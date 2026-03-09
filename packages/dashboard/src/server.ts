/**
 * @santh/dashboard — Localhost Dashboard Server
 *
 * Pure Node.js HTTP server. No Express. No frameworks.
 * Reads from invariant.db and serves a dashboard UI on localhost:4444.
 *
 * Zero external attack surface. Localhost only.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { InvariantDB, type FindingStatus, type Signal } from '../../agent/src/db.js'
import { ALL_CLASS_MODULES } from '../../engine/src/classes/index.js'
import { resolve, join, extname } from 'node:path'
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import dashboardPackage from '../package.json' with { type: 'json' }

const __dirname = fileURLToPath(new URL('.', import.meta.url))

// ── API Routes ───────────────────────────────────────────────────

interface ApiHandler {
    (ctx: ApiContext): unknown
}

interface ApiContext {
    db: InvariantDB
    params: URLSearchParams
    body?: string
    method: string
    pathParams: Record<string, string>
    classMetadata: ClassMetadata[]
    classCategoryById: Map<string, string>
    startedAtMs: number
}

interface ClassMetadata {
    id: string
    category: string
    severity: string
    description: string
}

interface RawApiResponse {
    raw: true
    statusCode: number
    contentType: string
    body: string
}

class ApiHttpError extends Error {
    statusCode: number

    constructor(statusCode: number, message: string) {
        super(message)
        this.statusCode = statusCode
    }
}

function isRawApiResponse(value: unknown): value is RawApiResponse {
    if (!value || typeof value !== 'object') return false
    const obj = value as Record<string, unknown>
    return obj.raw === true
        && typeof obj.statusCode === 'number'
        && typeof obj.contentType === 'string'
        && typeof obj.body === 'string'
}

function ensureMethod(method: string, allowed: string[]): void {
    if (!allowed.includes(method)) {
        throw new ApiHttpError(400, `Unsupported method: ${method}`)
    }
}

function parsePositiveInt(value: string | null, field: string, defaultValue: number, maxValue = 1000): number {
    if (value === null || value.trim() === '') return defaultValue
    const parsed = Number.parseInt(value, 10)
    if (!Number.isFinite(parsed) || parsed <= 0) {
        throw new ApiHttpError(400, `Invalid ${field}: ${value}`)
    }
    if (parsed > maxValue) {
        throw new ApiHttpError(400, `${field} too large: ${parsed} > ${maxValue}`)
    }
    return parsed
}

function parseFindingId(value: string | undefined): number {
    const id = Number.parseInt(value ?? '', 10)
    if (!Number.isFinite(id) || id <= 0) {
        throw new ApiHttpError(400, `Invalid finding id: ${value ?? ''}`)
    }
    return id
}

function toUtcHourIso(input: string): string | null {
    const date = new Date(input)
    if (Number.isNaN(date.getTime())) return null
    date.setUTCMinutes(0, 0, 0)
    return date.toISOString()
}

function getSignalCategory(signal: Signal, classCategoryById: Map<string, string>): string {
    const invariantIds = parseInvariantClassIds(signal.invariant_classes)
    for (const classId of invariantIds) {
        const category = classCategoryById.get(classId)
        if (category) return category
    }
    const typeCategory = classCategoryById.get(signal.type)
    if (typeCategory) return typeCategory
    return signal.type
}

function parseInvariantClassIds(raw: string): string[] {
    try {
        const parsed = safeParseJson(raw)
        if (!Array.isArray(parsed)) return []
        return parsed.filter((item): item is string => typeof item === 'string')
    } catch {
        return []
    }
}

function buildTimeline(signals: Signal[], hours: number, classCategoryById: Map<string, string>): Array<{
    hour: string
    count: number
    byCategory: Record<string, number>
}> {
    const hourMs = 60 * 60 * 1000
    const now = Date.now()
    const currentHourStart = Math.floor(now / hourMs) * hourMs
    const firstHourStart = currentHourStart - ((hours - 1) * hourMs)

    const buckets = new Map<string, { hour: string; count: number; byCategory: Record<string, number> }>()
    for (let i = 0; i < hours; i += 1) {
        const hour = new Date(firstHourStart + i * hourMs).toISOString()
        buckets.set(hour, { hour, count: 0, byCategory: {} })
    }

    for (const signal of signals) {
        const hour = toUtcHourIso(signal.timestamp)
        if (!hour) continue
        const bucket = buckets.get(hour)
        if (!bucket) continue
        bucket.count += 1
        const category = getSignalCategory(signal, classCategoryById)
        bucket.byCategory[category] = (bucket.byCategory[category] ?? 0) + 1
    }

    return Array.from(buckets.values())
}

function csvEscape(value: unknown): string {
    if (value === null || value === undefined) return ''
    const stringValue = typeof value === 'string' ? value : JSON.stringify(value)
    const escaped = stringValue.replace(/"/g, '""')
    return /[",\n]/.test(escaped) ? `"${escaped}"` : escaped
}

function findingsToCsv(findings: ReturnType<InvariantDB['getFindings']>): string {
    const header = [
        'id',
        'type',
        'category',
        'severity',
        'status',
        'title',
        'description',
        'location',
        'evidence',
        'remediation',
        'cve_id',
        'confidence',
        'first_seen',
        'last_seen',
        'rasp_active',
        'resolved_at',
        'resolved_by',
        'resolution_notes',
    ]
    const lines = [header.join(',')]
    for (const finding of findings) {
        const row = header.map((column) => csvEscape((finding as unknown as Record<string, unknown>)[column]))
        lines.push(row.join(','))
    }
    return `${lines.join('\n')}\n`
}

function matchApiRoute(pathname: string): { handler: ApiHandler; pathParams: Record<string, string> } | null {
    for (const [pattern, handler] of Object.entries(API_ROUTES)) {
        if (!pattern.includes(':')) {
            if (pattern === pathname) return { handler, pathParams: {} }
            continue
        }
        const patternParts = pattern.split('/').filter(Boolean)
        const pathParts = pathname.split('/').filter(Boolean)
        if (patternParts.length !== pathParts.length) continue
        const pathParams: Record<string, string> = {}
        let matched = true
        for (let i = 0; i < patternParts.length; i += 1) {
            const part = patternParts[i]
            const value = pathParts[i]
            if (part.startsWith(':')) {
                pathParams[part.slice(1)] = value
                continue
            }
            if (part !== value) {
                matched = false
                break
            }
        }
        if (matched) return { handler, pathParams }
    }
    return null
}

const DASHBOARD_VERSION = typeof dashboardPackage.version === 'string' ? dashboardPackage.version : 'unknown'

const DEFENSE_MODES = ['observe', 'sanitize', 'defend', 'lockdown'] as const
const DEFENSE_MODE_SET = new Set<string>(DEFENSE_MODES)

function parseConfigPatch(body: string | undefined): { mode?: string; thresholds?: Record<string, number> } {
    if (!body) throw new ApiHttpError(400, 'Missing body')
    const parsed = safeParseJson(body)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new ApiHttpError(400, 'Config patch body must be an object')
    }
    const obj = parsed as Record<string, unknown>
    const updates: { mode?: string; thresholds?: Record<string, number> } = {}

    if ('mode' in obj) {
        const mode = obj.mode
        if (typeof mode !== 'string' || !DEFENSE_MODE_SET.has(mode)) {
            throw new ApiHttpError(400, `Invalid mode: ${String(mode)}`)
        }
        updates.mode = mode
    }

    if ('thresholds' in obj) {
        const thresholds = obj.thresholds
        if (!thresholds || typeof thresholds !== 'object' || Array.isArray(thresholds)) {
            throw new ApiHttpError(400, 'thresholds must be an object')
        }
        const normalized: Record<string, number> = {}
        for (const [key, value] of Object.entries(thresholds as Record<string, unknown>)) {
            if (typeof value !== 'number' || !Number.isFinite(value)) {
                throw new ApiHttpError(400, `thresholds.${key} must be a finite number`)
            }
            normalized[key] = value
        }
        updates.thresholds = normalized
    }

    if (!('mode' in obj) && !('thresholds' in obj)) {
        throw new ApiHttpError(400, 'No supported config keys provided (mode, thresholds)')
    }

    return updates
}

const API_ROUTES: Record<string, ApiHandler> = {
    '/api/status': ({ db, method }) => {
        ensureMethod(method, ['GET'])
        const findingStats = db.getFindingStats()
        const signalStats = db.getSignalStats()
        const posture = db.getLatestPosture()
        const assets = db.getAllAssets()
        const mode = db.getConfig('mode') ?? 'observe'
        return {
            mode,
            posture: posture ? { grade: posture.grade, score: posture.score, breakdown: JSON.parse(posture.breakdown) } : null,
            findings: findingStats,
            signals: signalStats,
            assets,
        }
    },

    '/api/findings': ({ db, method }) => {
        ensureMethod(method, ['GET'])
        return db.getFindings()
    },

    '/api/findings/detail': ({ db, params, method }) => {
        ensureMethod(method, ['GET'])
        const id = parseInt(params.get('id') ?? '0')
        if (!id) throw new ApiHttpError(400, 'Missing id parameter')
        const finding = db.getFinding(id)
        if (!finding) throw new ApiHttpError(404, 'Finding not found')
        const log = db.getRemediationLog(id)
        return { finding, remediationLog: log }
    },

    '/api/findings/resolve': ({ db, params, body, method }) => {
        ensureMethod(method, ['POST'])
        const id = parseInt(params.get('id') ?? '0')
        if (!id) throw new ApiHttpError(400, 'Missing id parameter')
        const parsed = body ? safeParseJson(body) as Record<string, unknown> : {}
        const status = isFindingStatus(parsed.status) ? parsed.status : 'resolved'
        const notes = typeof parsed.notes === 'string' ? parsed.notes : undefined
        const finding = db.getFinding(id)
        if (!finding) throw new ApiHttpError(404, 'Finding not found')
        db.updateFindingStatus(id, status, notes)
        return { success: true, id, status }
    },

    '/api/signals': ({ db, params, method }) => {
        ensureMethod(method, ['GET'])
        const limit = parseInt(params.get('limit') ?? '50')
        if (!Number.isFinite(limit) || limit <= 0) throw new ApiHttpError(400, `Invalid limit: ${params.get('limit') ?? ''}`)
        return db.getSignals(limit)
    },

    '/api/signals/timeline': ({ db, params, method }) => {
        ensureMethod(method, ['GET'])
        const hours = parseInt(params.get('hours') ?? '24')
        if (!Number.isFinite(hours) || hours <= 0) throw new ApiHttpError(400, `Invalid hours: ${params.get('hours') ?? ''}`)
        return db.getSignalTimeline(hours)
    },

    '/api/signals/top-paths': ({ db, params, method }) => {
        ensureMethod(method, ['GET'])
        const limit = parseInt(params.get('limit') ?? '20')
        if (!Number.isFinite(limit) || limit <= 0) throw new ApiHttpError(400, `Invalid limit: ${params.get('limit') ?? ''}`)
        return db.getTopAttackedPaths(limit)
    },

    '/api/signals/distribution': ({ db, method }) => {
        ensureMethod(method, ['GET'])
        return db.getInvariantClassDistribution()
    },

    '/api/posture': ({ db, params, method }) => {
        ensureMethod(method, ['GET'])
        const limit = parseInt(params.get('limit') ?? '30')
        if (!Number.isFinite(limit) || limit <= 0) throw new ApiHttpError(400, `Invalid limit: ${params.get('limit') ?? ''}`)
        return db.getPostureHistory(limit)
    },

    '/api/posture/history': ({ db, params, method }) => {
        ensureMethod(method, ['GET'])
        const limit = parseInt(params.get('limit') ?? '30')
        if (!Number.isFinite(limit) || limit <= 0) throw new ApiHttpError(400, `Invalid limit: ${params.get('limit') ?? ''}`)
        return db.getPostureHistory(limit)
    },

    '/api/config': ({ db, body, method }) => {
        if (method === 'GET') {
            const thresholdsRaw = db.getConfig('thresholds')
            let thresholds: Record<string, number> = {}
            if (thresholdsRaw) {
                const parsed = safeParseJson(thresholdsRaw)
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                    thresholds = parsed as Record<string, number>
                }
            }
            return {
                mode: db.getConfig('mode') ?? 'observe',
                thresholds,
                project_dir: db.getConfig('project_dir') ?? process.cwd(),
            }
        }
        if (method === 'PATCH') {
            const updates = parseConfigPatch(body)
            if (updates.mode) db.setConfig('mode', updates.mode)
            if (updates.thresholds) db.setConfig('thresholds', JSON.stringify(updates.thresholds))
            const thresholdsRaw = db.getConfig('thresholds')
            let thresholds: Record<string, number> = {}
            if (thresholdsRaw) {
                const parsed = safeParseJson(thresholdsRaw)
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                    thresholds = parsed as Record<string, number>
                }
            }
            return {
                success: true,
                mode: db.getConfig('mode') ?? 'observe',
                thresholds,
            }
        }
        throw new ApiHttpError(400, `Unsupported method: ${method}`)
    },

    '/api/config/mode': ({ db, body, method }) => {
        ensureMethod(method, ['POST'])
        if (!body) throw new ApiHttpError(400, 'Missing body')
        const parsed = safeParseJson(body) as Record<string, unknown>
        const mode = parsed.mode
        if (typeof mode !== 'string' || !DEFENSE_MODE_SET.has(mode)) {
            throw new ApiHttpError(400, `Invalid mode: ${mode}`)
        }
        db.setConfig('mode', mode)
        return { success: true, mode }
    },

    '/api/classes': ({ method, classMetadata }) => {
        ensureMethod(method, ['GET'])
        return classMetadata
    },

    '/api/timeline': ({ db, params, method, classCategoryById }) => {
        ensureMethod(method, ['GET'])
        const hours = parsePositiveInt(params.get('hours'), 'hours', 24, 24 * 30)
        const since = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString()
        const now = new Date().toISOString()
        const signals = db.getSignalsByTimeRange(since, now)
        return buildTimeline(signals, hours, classCategoryById)
    },

    '/api/top-attackers': ({ db, params, method }) => {
        ensureMethod(method, ['GET'])
        const limit = parsePositiveInt(params.get('limit'), 'limit', 10, 100)
        return db.getTopSourceIps(limit).map(row => ({ sourceIp: row.source_ip, count: row.count }))
    },

    '/api/findings/:id/suppress': ({ db, method, pathParams, body }) => {
        ensureMethod(method, ['POST'])
        const id = parseFindingId(pathParams.id)
        const finding = db.getFinding(id)
        if (!finding) throw new ApiHttpError(404, 'Finding not found')
        const parsed = body ? safeParseJson(body) as Record<string, unknown> : {}
        const notes = typeof parsed.notes === 'string' ? parsed.notes : 'Suppressed via dashboard API'
        db.updateFindingStatus(id, 'suppressed', notes)
        return { success: true, id, status: 'suppressed' }
    },

    '/api/export/json': ({ db, method }) => {
        ensureMethod(method, ['GET'])
        return {
            exportedAt: new Date().toISOString(),
            findings: db.getFindings(),
        }
    },

    '/api/export/csv': ({ db, method }) => {
        ensureMethod(method, ['GET'])
        const findings = db.getFindings()
        const csv = findingsToCsv(findings)
        return {
            raw: true,
            statusCode: 200,
            contentType: 'text/csv; charset=utf-8',
            body: csv,
        } satisfies RawApiResponse
    },

    '/api/health': ({ method, startedAtMs, classMetadata }) => {
        ensureMethod(method, ['GET'])
        return {
            status: 'ok',
            uptime: Math.floor((Date.now() - startedAtMs) / 1000),
            version: DASHBOARD_VERSION,
            classCount: classMetadata.length,
        }
    },
}

// ── MIME Types ────────────────────────────────────────────────────

const MIME_TYPES: Record<string, string> = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
    '.woff': 'font/woff',
}

// ── Body Parser ──────────────────────────────────────────────────

function readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
        let data = ''
        req.on('data', (chunk: Buffer) => { data += chunk.toString() })
        req.on('end', () => resolve(data))
        req.on('error', reject)
    })
}

/** Strip __proto__ and constructor to prevent prototype pollution when parsing untrusted JSON. */
function stripPrototypePollution(value: unknown): unknown {
    if (value === null || typeof value !== 'object') return value
    if (Array.isArray(value)) return value.map(stripPrototypePollution)
    const obj = value as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(obj)) {
        if (key === '__proto__' || key === 'constructor') continue
        out[key] = stripPrototypePollution(obj[key])
    }
    return out
}

function safeParseJson(str: string): unknown {
    try {
        return stripPrototypePollution(JSON.parse(str))
    } catch {
        throw new ApiHttpError(400, 'Invalid JSON body')
    }
}

function isFindingStatus(value: unknown): value is FindingStatus {
    return value === 'open'
        || value === 'acknowledged'
        || value === 'resolved'
        || value === 'false_positive'
        || value === 'risk_accepted'
        || value === 'suppressed'
}

// ── Server ───────────────────────────────────────────────────────

export function startDashboard(dbPath: string, port = 4444): { close: () => void } {
    const db = new InvariantDB(dbPath)
    const viewsDir = join(__dirname, 'views')
    const startedAtMs = Date.now()
    const classMetadata = ALL_CLASS_MODULES.map((module) => ({
        id: module.id,
        category: module.category,
        severity: module.severity,
        description: module.description,
    })).sort((a, b) => a.id.localeCompare(b.id))
    const classCategoryById = new Map<string, string>(classMetadata.map((meta) => [meta.id, meta.category]))

    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
        const url = new URL(req.url ?? '/', `http://localhost:${port}`)
        const pathname = url.pathname

        // Security headers
        res.setHeader('X-Content-Type-Options', 'nosniff')
        res.setHeader('X-Frame-Options', 'DENY')
        res.setHeader('Referrer-Policy', 'no-referrer')

        // CORS for localhost only
        const origin = req.headers.origin ?? ''
        if (origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1')) {
            res.setHeader('Access-Control-Allow-Origin', origin)
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS')
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
        }

        // Preflight
        if (req.method === 'OPTIONS') {
            res.writeHead(204)
            res.end()
            return
        }

        // API routes
        if (pathname.startsWith('/api/')) {
            const matchedRoute = matchApiRoute(pathname)
            if (matchedRoute) {
                try {
                    const body = (req.method === 'POST' || req.method === 'PATCH') ? await readBody(req) : undefined
                    const data = matchedRoute.handler({
                        db,
                        params: url.searchParams,
                        body,
                        method: req.method ?? 'GET',
                        pathParams: matchedRoute.pathParams,
                        classMetadata,
                        classCategoryById,
                        startedAtMs,
                    })
                    if (isRawApiResponse(data)) {
                        res.writeHead(data.statusCode, { 'Content-Type': data.contentType })
                        res.end(data.body)
                    } else {
                        res.writeHead(200, { 'Content-Type': 'application/json' })
                        res.end(JSON.stringify(data))
                    }
                } catch (err) {
                    if (err instanceof ApiHttpError) {
                        res.writeHead(err.statusCode, { 'Content-Type': 'application/json' })
                        res.end(JSON.stringify({ error: err.message }))
                    } else {
                        res.writeHead(500, { 'Content-Type': 'application/json' })
                        res.end(JSON.stringify({ error: String(err) }))
                    }
                }
            } else {
                res.writeHead(404, { 'Content-Type': 'application/json' })
                res.end(JSON.stringify({ error: 'Not found' }))
            }
            return
        }

        // Static file serving
        let filePath = pathname === '/' ? '/index.html' : pathname
        filePath = join(viewsDir, filePath)

        // Security: prevent directory traversal
        const resolved = resolve(filePath)
        if (!resolved.startsWith(resolve(viewsDir))) {
            res.writeHead(403)
            res.end('Forbidden')
            return
        }

        if (!existsSync(resolved)) {
            // SPA fallback
            filePath = join(viewsDir, 'index.html')
        }

        try {
            const content = readFileSync(filePath)
            const ext = extname(filePath)
            const contentType = MIME_TYPES[ext] ?? 'application/octet-stream'
            res.writeHead(200, {
                'Content-Type': contentType,
                'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=86400',
            })
            res.end(content)
        } catch {
            res.writeHead(404)
            res.end('Not found')
        }
    })

    server.listen(port, '127.0.0.1', () => {
        console.log(`\n  ┌──────────────────────────────────────────────┐`)
        console.log(`  │                                              │`)
        console.log(`  │   ██ INVARIANT Dashboard                     │`)
        console.log(`  │                                              │`)
        console.log(`  │   http://localhost:${port}                     │`)
        console.log(`  │                                              │`)
        console.log(`  │   Mode: ${(db.getConfig('mode') ?? 'observe').padEnd(36)}│`)
        console.log(`  │   DB:   ${dbPath.slice(-35).padEnd(36)}│`)
        console.log(`  │                                              │`)
        console.log(`  │   Press Ctrl+C to stop                       │`)
        console.log(`  │                                              │`)
        console.log(`  └──────────────────────────────────────────────┘\n`)
    })

    return {
        close: () => {
            server.close()
            db.close()
        },
    }
}
