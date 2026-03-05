/**
 * @santh/dashboard — Localhost Dashboard Server
 *
 * Pure Node.js HTTP server. No Express. No frameworks.
 * Reads from invariant.db and serves a dashboard UI on localhost:4444.
 *
 * Zero external attack surface. Localhost only.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { InvariantDB } from '../../agent/src/db.js'
import { resolve, join, extname } from 'node:path'
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const __dirname = fileURLToPath(new URL('.', import.meta.url))

// ── API Routes ───────────────────────────────────────────────────

interface ApiHandler {
    (db: InvariantDB, params: URLSearchParams, body?: string): unknown
}

const API_ROUTES: Record<string, ApiHandler> = {
    '/api/status': (db) => {
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

    '/api/findings': (db, params) => {
        const severity = params.get('severity') as 'critical' | 'high' | 'medium' | 'low' | undefined
        const status = params.get('status') as 'open' | 'resolved' | undefined
        const type = params.get('type') ?? undefined
        const limit = parseInt(params.get('limit') ?? '100')
        return db.getFindings({ severity: severity || undefined, status: status || undefined, type: type || undefined, limit })
    },

    '/api/findings/detail': (db, params) => {
        const id = parseInt(params.get('id') ?? '0')
        if (!id) return { error: 'Missing id parameter' }
        const finding = db.getFinding(id)
        if (!finding) return { error: 'Finding not found' }
        const log = db.getRemediationLog(id)
        return { finding, remediationLog: log }
    },

    '/api/findings/resolve': (db, params, body) => {
        const id = parseInt(params.get('id') ?? '0')
        if (!id) return { error: 'Missing id parameter' }
        const parsed = body ? JSON.parse(body) : {}
        const status = parsed.status ?? 'resolved'
        const notes = parsed.notes ?? null
        db.updateFindingStatus(id, status, notes)
        return { success: true, id, status }
    },

    '/api/signals': (db, params) => {
        const limit = parseInt(params.get('limit') ?? '100')
        return db.getSignals(limit)
    },

    '/api/signals/timeline': (db, params) => {
        const hours = parseInt(params.get('hours') ?? '24')
        return db.getSignalTimeline(hours)
    },

    '/api/signals/top-paths': (db, params) => {
        const limit = parseInt(params.get('limit') ?? '20')
        return db.getTopAttackedPaths(limit)
    },

    '/api/signals/distribution': (db) => {
        return db.getInvariantClassDistribution()
    },

    '/api/posture': (db) => {
        return db.getLatestPosture()
    },

    '/api/posture/history': (db, params) => {
        const limit = parseInt(params.get('limit') ?? '30')
        return db.getPostureHistory(limit)
    },

    '/api/config': (db) => {
        return {
            mode: db.getConfig('mode') ?? 'observe',
            project_dir: db.getConfig('project_dir') ?? process.cwd(),
        }
    },

    '/api/config/mode': (db, _params, body) => {
        if (!body) return { error: 'Missing body' }
        const parsed = JSON.parse(body)
        const mode = parsed.mode
        if (!['observe', 'sanitize', 'defend', 'lockdown'].includes(mode)) {
            return { error: `Invalid mode: ${mode}` }
        }
        db.setConfig('mode', mode)
        return { success: true, mode }
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

// ── Server ───────────────────────────────────────────────────────

export function startDashboard(dbPath: string, port = 4444): { close: () => void } {
    const db = new InvariantDB(dbPath)
    const uiDir = join(__dirname, 'ui')

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
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
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
            const handler = API_ROUTES[pathname]
            if (handler) {
                try {
                    const body = req.method === 'POST' ? await readBody(req) : undefined
                    const data = handler(db, url.searchParams, body)
                    res.writeHead(200, { 'Content-Type': 'application/json' })
                    res.end(JSON.stringify(data))
                } catch (err) {
                    res.writeHead(500, { 'Content-Type': 'application/json' })
                    res.end(JSON.stringify({ error: String(err) }))
                }
            } else {
                res.writeHead(404, { 'Content-Type': 'application/json' })
                res.end(JSON.stringify({ error: 'Not found' }))
            }
            return
        }

        // Static file serving
        let filePath = pathname === '/' ? '/index.html' : pathname
        filePath = join(uiDir, filePath)

        // Security: prevent directory traversal
        const resolved = resolve(filePath)
        if (!resolved.startsWith(resolve(uiDir))) {
            res.writeHead(403)
            res.end('Forbidden')
            return
        }

        if (!existsSync(resolved)) {
            // SPA fallback
            filePath = join(uiDir, 'index.html')
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
