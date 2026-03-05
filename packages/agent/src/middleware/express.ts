/**
 * @santh/agent/middleware/express
 *
 * Drop-in Express middleware. One line to add INVARIANT defense:
 *
 *   import { invariantMiddleware } from '@santh/agent/middleware/express'
 *   app.use(invariantMiddleware())
 *
 * Analyzes every incoming request against all invariant classes.
 * Writes signals to local SQLite. Blocks or monitors based on mode.
 */

import { InvariantAgent } from '../index.js'
import type { DefenseMode } from '../db.js'
import { checkDeserInvariants } from '../rasp/deser.js'

// ── Types ────────────────────────────────────────────────────────

interface ExpressRequest {
    method: string
    url: string
    path: string
    originalUrl: string
    headers: Record<string, string | string[] | undefined>
    body?: unknown
}

interface ExpressResponse {
    status: (code: number) => ExpressResponse
    json: (body: unknown) => void
    setHeader: (name: string, value: string) => void
}

type NextFunction = (err?: unknown) => void

export interface MiddlewareOptions {
    /** Defense mode */
    mode?: DefenseMode
    /** Project directory (for finding package-lock.json, etc.) */
    projectDir?: string
    /** Database path */
    dbPath?: string
    /** Paths to skip */
    allowlist?: string[]
    /** Run scans on startup */
    scanOnStart?: boolean
    /** Verbose logging */
    verbose?: boolean
}

// ── Defaults ─────────────────────────────────────────────────────

const DEFAULT_ALLOWLIST = [
    '/favicon.ico', '/robots.txt', '/sitemap.xml',
    '/health', '/healthz', '/ready', '/readyz',
    '/.well-known/',
]

// ── Dynamic import of the invariant engine ───────────────────────

// We lazily load the engine to avoid hard dependency on the engine package
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let engineModule: Record<string, any> | null = null

async function getEngine(): Promise<typeof engineModule> {
    if (engineModule) return engineModule
    try {
        // Use variable to prevent TS from resolving this at compile time
        const pkg = '@santh/invariant-engine'
        engineModule = await import(pkg)
    } catch {
        // Engine not installed — middleware will passthrough
        return null
    }
    return engineModule
}

// ── Middleware ────────────────────────────────────────────────────

export function invariantMiddleware(options: MiddlewareOptions = {}) {
    const {
        mode = 'observe',
        projectDir = process.cwd(),
        dbPath,
        allowlist = [],
        scanOnStart = true,
        verbose = false,
    } = options

    const agent = new InvariantAgent({
        projectDir,
        dbPath,
        mode,
        scanOnStart,
        auditOnStart: true,
        verbose,
    })

    const allPatterns = [...DEFAULT_ALLOWLIST, ...allowlist]

    // Start agent (async, non-blocking)
    agent.start().catch(() => { /* startup failure is not fatal */ })

    // Load engine (async, non-blocking)
    let engine: Awaited<ReturnType<typeof getEngine>> = null
    getEngine().then(e => { engine = e }).catch(() => { /* */ })

    return function invariant(req: ExpressRequest, res: ExpressResponse, next: NextFunction) {
        // Skip allowlisted paths
        const path = req.path || req.url
        if (allPatterns.some(p => p.endsWith('/') ? path.startsWith(p) : path === p)) {
            return next()
        }

        // Security response headers (always add, even if engine isn't loaded)
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.setHeader('X-Frame-Options', 'DENY')

        // If engine isn't loaded yet, pass through
        if (!engine) return next()

        try {
            const eng = new engine.InvariantEngine()
            const db = agent.getDB()
            const now = new Date().toISOString()

            // Collect all inputs to analyze
            const inputs: string[] = []

            // URL path + query string
            const fullUrl = req.originalUrl || req.url || ''
            if (fullUrl) inputs.push(fullUrl)

            // Request body (JSON or form-urlencoded)
            if (req.body) {
                if (typeof req.body === 'string') {
                    inputs.push(req.body)
                } else if (typeof req.body === 'object') {
                    const bodyStr = JSON.stringify(req.body)
                    inputs.push(bodyStr)
                    // Deep inspection: check individual values for injection
                    extractValues(req.body, inputs)
                }
            }

            // Run detection on all inputs
            const allMatches: Array<{ category: string; class: string; severity: string; confidence: number; source: string }> = []

            for (const input of inputs) {
                const matches = eng.detect(input, [])
                for (const m of matches) {
                    allMatches.push({
                        category: m.category,
                        class: m.class,
                        severity: m.severity,
                        confidence: m.confidence,
                        source: input === fullUrl ? 'url' : 'body',
                    })
                }
            }

            // Check for deserialization attacks in body
            if (req.body && typeof req.body === 'string') {
                const deserViolations = checkDeserInvariants(req.body)
                for (const v of deserViolations) {
                    allMatches.push({
                        category: 'deserialization',
                        class: v.id,
                        severity: v.severity,
                        confidence: 0.9,
                        source: 'body',
                    })
                }
            }

            if (allMatches.length === 0) return next()

            const shouldBlock = mode !== 'observe' && eng.shouldBlock(allMatches)

            // Record signal
            db.insertSignal({
                type: allMatches[0].category,
                subtype: allMatches[0].class,
                severity: allMatches[0].severity as 'critical' | 'high' | 'medium' | 'low' | 'info',
                action: shouldBlock ? 'blocked' : 'monitored',
                path,
                method: req.method,
                source_hash: null,
                invariant_classes: JSON.stringify(allMatches.map(m => m.class)),
                is_novel: false,
                timestamp: now,
            })

            // Record finding
            db.insertFinding({
                type: 'runtime_invariant_violation',
                category: allMatches[0].category,
                severity: allMatches[0].severity as 'critical' | 'high' | 'medium' | 'low' | 'info',
                status: 'open',
                title: `${allMatches[0].category}: ${allMatches[0].class} in ${req.method} ${path}`,
                description: `Detected ${allMatches.map(m => m.class).join(', ')} in ${allMatches[0].source}`,
                location: `${req.method} ${path}`,
                evidence: JSON.stringify({
                    classes: allMatches.map(m => m.class),
                    sources: [...new Set(allMatches.map(m => m.source))],
                }),
                remediation: 'Validate and sanitize user input before processing. Use parameterized queries for SQL, context-aware encoding for XSS.',
                cve_id: null,
                confidence: allMatches[0].confidence,
                first_seen: now,
                last_seen: now,
                rasp_active: shouldBlock,
            })

            if (shouldBlock) {
                return res.status(403).json({
                    blocked: true,
                    reason: 'invariant_defense',
                    classes: allMatches.map(m => m.class),
                })
            }

            return next()
        } catch {
            // NEVER break the application
            return next()
        }
    }
}

/**
 * Recursively extract string values from an object for deep inspection.
 * Caps at depth 5 and 50 values to prevent DoS.
 */
function extractValues(obj: unknown, out: string[], depth = 0): void {
    if (depth > 5 || out.length > 50) return
    if (!obj || typeof obj !== 'object') {
        if (typeof obj === 'string' && obj.length > 2 && obj.length < 10000) {
            out.push(obj)
        }
        return
    }
    if (Array.isArray(obj)) {
        for (const item of obj) extractValues(item, out, depth + 1)
        return
    }
    for (const value of Object.values(obj as Record<string, unknown>)) {
        extractValues(value, out, depth + 1)
    }
}
