import type { ApplicationModel } from './application-model.js'

export interface DeceptionConfig {
    enabled: boolean
    trackingTtlSeconds: number
    minConfidenceToDecept: number
}

export const DEFAULT_DECEPTION_CONFIG: DeceptionConfig = {
    enabled: true,
    trackingTtlSeconds: 3600,
    minConfidenceToDecept: 0.65,
}

export interface TrackingToken {
    tokenId: string
    sessionId: string
    attackClass: string
    issuedAt: number
    payload: string
}

export interface AttackerAction {
    tokenId: string
    timestamp: number
    method: string
    path: string
    headers: Record<string, string>
    body: string
    ipAddress: string
}

export interface AttackerDossier {
    tokenId: string
    sessionId: string
    attackClass: string
    firstSeen: number
    lastSeen: number
    actions: AttackerAction[]
    ipAddresses: string[]
    userAgents: string[]
    toolSignatures: string[]
    confidence: number
}

const FAKE_SIGNING_KEY = 'santh_edge_fake_signing_key_v1'
const MAX_RECORDED_ACTIONS = 250

export class DeceptionLayer {
    private readonly config: DeceptionConfig
    private readonly trackedTokens = new Map<string, TrackingToken>()
    private readonly dossiers = new Map<string, AttackerDossier>()

    constructor(config: Partial<DeceptionConfig> = {}) {
        this.config = {
            ...DEFAULT_DECEPTION_CONFIG,
            ...config,
        }
    }

    async generateTrackingToken(attackClass: string, sessionId: string): Promise<TrackingToken> {
        this.pruneExpiredTokens()

        const issuedAtMs = Date.now()
        const issuedAtSec = Math.floor(issuedAtMs / 1000)
        const exp = issuedAtSec + this.config.trackingTtlSeconds
        const tokenId = crypto.randomUUID()

        const header = {
            alg: 'HS256',
            typ: 'JWT',
            kid: 'prod-auth-2026-rotation',
        }

        const payload = {
            sub: sessionId,
            iat: issuedAtSec,
            exp,
            role: 'admin',
            jti: tokenId,
            scope: 'read:all write:limited',
            iss: 'auth.edge.santh.internal',
        }

        const encodedHeader = encodeBase64Url(JSON.stringify(header))
        const encodedPayload = encodeBase64Url(JSON.stringify(payload))
        const signingInput = `${encodedHeader}.${encodedPayload}`
        const signature = await signJwtHs256(signingInput, FAKE_SIGNING_KEY)
        const jwt = `${signingInput}.${signature}`

        const token: TrackingToken = {
            tokenId,
            sessionId,
            attackClass,
            issuedAt: issuedAtMs,
            payload: jwt,
        }

        this.trackedTokens.set(tokenId, token)
        if (!this.dossiers.has(tokenId)) {
            this.dossiers.set(tokenId, {
                tokenId,
                sessionId,
                attackClass,
                firstSeen: issuedAtMs,
                lastSeen: issuedAtMs,
                actions: [],
                ipAddresses: [],
                userAgents: [],
                toolSignatures: [],
                confidence: 0,
            })
        }

        return token
    }

    async generateFakeResponse(
        request: Request,
        attackClass: string,
        appModel: ApplicationModel,
        token: TrackingToken,
    ): Promise<Response> {
        const url = new URL(request.url)
        const path = url.pathname.toLowerCase()

        const endpointModel = appModel.getEndpoint(url.pathname)
        await delay(this.calculateDelay(endpointModel?.avgResponseSize ?? 0))

        let body: Record<string, unknown>

        if (isAuthPath(path)) {
            body = this.buildAuthSuccessBody(token, appModel)
        } else if (isAdminPath(path)) {
            body = this.buildAdminSuccessBody(token)
        } else if (path.startsWith('/api/')) {
            body = this.buildApiSuccessBody(path, token)
        } else {
            body = {
                success: true,
                requestId: crypto.randomUUID(),
                message: 'Operation completed successfully',
                data: this.buildResourceItems(path, 1),
                trace: {
                    token: token.payload,
                },
            }
        }

        const responseText = JSON.stringify(body)
        const headers = new Headers({
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store',
            'x-request-id': crypto.randomUUID(),
            'content-length': String(responseText.length),
        })

        return new Response(responseText, {
            status: 200,
            headers,
        })
    }

    async isTrackingToken(request: Request): Promise<TrackingToken | null> {
        this.pruneExpiredTokens()

        const candidates: string[] = []
        const auth = request.headers.get('authorization')
        if (auth && auth.toLowerCase().startsWith('bearer ')) {
            candidates.push(auth.slice(7).trim())
        }

        const cookie = request.headers.get('cookie')
        if (cookie) {
            for (const chunk of cookie.split(';')) {
                const trimmed = chunk.trim()
                const separator = trimmed.indexOf('=')
                if (separator < 1) continue
                const name = trimmed.slice(0, separator).toLowerCase()
                if (name === 'token' || name === 'auth' || name === 'session' || name === 'jwt' || name === 'access_token') {
                    candidates.push(trimmed.slice(separator + 1))
                }
            }
        }

        const bodyCandidate = await extractTokenFromBody(request)
        if (bodyCandidate) {
            candidates.push(bodyCandidate)
        }

        for (const candidate of candidates) {
            const decoded = decodeJwtPayload(candidate)
            if (!decoded) continue
            const jti = typeof decoded.jti === 'string' ? decoded.jti : null
            if (!jti) continue
            const tracked = this.trackedTokens.get(jti)
            if (tracked && tracked.payload === candidate) {
                return tracked
            }
        }

        return null
    }

    async recordAttackerAction(token: TrackingToken, request: Request): Promise<AttackerAction> {
        const url = new URL(request.url)
        const body = await safeReadBody(request)
        const headers = headersToRecord(request.headers)
        const timestamp = Date.now()
        const ipAddress = request.headers.get('cf-connecting-ip') ?? request.headers.get('x-forwarded-for') ?? '0.0.0.0'

        const action: AttackerAction = {
            tokenId: token.tokenId,
            timestamp,
            method: request.method,
            path: `${url.pathname}${url.search}`,
            headers,
            body,
            ipAddress,
        }

        const existing = this.dossiers.get(token.tokenId) ?? {
            tokenId: token.tokenId,
            sessionId: token.sessionId,
            attackClass: token.attackClass,
            firstSeen: token.issuedAt,
            lastSeen: timestamp,
            actions: [],
            ipAddresses: [],
            userAgents: [],
            toolSignatures: [],
            confidence: 0,
        }

        existing.lastSeen = timestamp
        existing.actions.push(action)
        if (existing.actions.length > MAX_RECORDED_ACTIONS) {
            existing.actions.splice(0, existing.actions.length - MAX_RECORDED_ACTIONS)
        }

        if (!existing.ipAddresses.includes(ipAddress)) {
            existing.ipAddresses.push(ipAddress)
        }

        const ua = headers['user-agent'] ?? ''
        if (ua && !existing.userAgents.includes(ua)) {
            existing.userAgents.push(ua)
        }

        existing.toolSignatures = this.identifyToolSignatures(existing.actions)
        existing.confidence = Math.min(1, 0.4 + existing.actions.length * 0.03 + existing.toolSignatures.length * 0.1)

        this.dossiers.set(token.tokenId, existing)
        return action
    }

    identifyToolSignatures(actions: AttackerAction[]): string[] {
        const signatures = new Set<string>()

        const uas = actions
            .map(a => (a.headers['user-agent'] ?? '').toLowerCase())
            .filter(Boolean)

        const pathList = actions.map(a => a.path.toLowerCase())

        if (uas.some(ua => ua.includes('sqlmap'))) signatures.add('sqlmap')
        if (uas.some(ua => ua.includes('burpsuite') || ua.includes('burp'))) signatures.add('burpsuite')
        if (uas.some(ua => ua.includes('metasploit'))) signatures.add('metasploit')
        if (uas.some(ua => ua.includes('nuclei'))) signatures.add('nuclei')
        if (uas.some(ua => ua.includes('ffuf'))) signatures.add('ffuf')
        if (uas.some(ua => ua.includes('gobuster'))) signatures.add('gobuster')
        if (uas.some(ua => ua.includes('hydra'))) signatures.add('hydra')

        if (pathList.some(p => /\b(union|select|sleep\(|benchmark\()/.test(p))) signatures.add('sqlmap')
        if (pathList.some(p => p.includes('/wp-admin') || p.includes('/.env') || p.includes('/actuator'))) signatures.add('nuclei')
        if (pathList.some(p => p.includes('/admin') || p.includes('/login')) && actions.filter(a => a.method === 'POST').length >= 4) {
            signatures.add('hydra')
        }

        const fastBursts = countFastBursts(actions)
        const distinctPaths = new Set(pathList).size
        if (fastBursts >= 3 && distinctPaths >= 6) {
            if (!signatures.has('ffuf') && !signatures.has('gobuster')) {
                signatures.add('custom-script')
            }
        }

        if (signatures.size === 0 && actions.length >= 3) {
            signatures.add('custom-script')
        }

        return [...signatures]
    }

    assembleDossier(tokenId: string, actions: AttackerAction[]): AttackerDossier {
        const knownToken = this.trackedTokens.get(tokenId)
        const firstActionAt = actions.length > 0 ? Math.min(...actions.map(a => a.timestamp)) : Date.now()
        const lastActionAt = actions.length > 0 ? Math.max(...actions.map(a => a.timestamp)) : firstActionAt

        const ipAddresses = unique(actions.map(a => a.ipAddress))
        const userAgents = unique(actions.map(a => a.headers['user-agent'] ?? '').filter(Boolean))
        const toolSignatures = this.identifyToolSignatures(actions)

        const confidence = Math.min(
            1,
            0.35
            + Math.min(actions.length / 30, 0.35)
            + Math.min(toolSignatures.length * 0.1, 0.3),
        )

        const dossier: AttackerDossier = {
            tokenId,
            sessionId: knownToken?.sessionId ?? 'unknown-session',
            attackClass: knownToken?.attackClass ?? 'unknown_attack',
            firstSeen: Math.min(knownToken?.issuedAt ?? firstActionAt, firstActionAt),
            lastSeen: lastActionAt,
            actions,
            ipAddresses,
            userAgents,
            toolSignatures,
            confidence,
        }

        this.dossiers.set(tokenId, dossier)
        return dossier
    }

    shouldDecept(confidence: number, attackClass: string, config: DeceptionConfig = this.config): boolean {
        if (!config.enabled) return false
        if (confidence < config.minConfidenceToDecept) return false

        const lower = attackClass.toLowerCase()
        const highRiskClass =
            lower.includes('sql')
            || lower.includes('cmd')
            || lower.includes('rce')
            || lower.includes('ssrf')
            || lower.includes('deser')
            || lower.includes('path_traversal')
            || lower.includes('auth')
            || lower.includes('injection')

        return highRiskClass
    }

    getDossier(tokenId: string): AttackerDossier | null {
        return this.dossiers.get(tokenId) ?? null
    }

    private buildAuthSuccessBody(token: TrackingToken, appModel: ApplicationModel): Record<string, unknown> {
        const nowIso = new Date().toISOString()
        const sessionType = appModel.snapshot('deception-sensor').sessionType

        return {
            success: true,
            message: 'Login successful',
            token: token.payload,
            accessToken: token.payload,
            tokenType: 'Bearer',
            expiresIn: this.config.trackingTtlSeconds,
            user: {
                id: crypto.randomUUID(),
                email: 'ops.admin@company.example',
                username: 'ops-admin',
                role: 'admin',
                roles: ['admin', 'security'],
                lastLoginAt: nowIso,
                mfaEnabled: true,
            },
            session: {
                id: token.sessionId,
                type: sessionType,
                issuedAt: nowIso,
            },
            meta: {
                authContext: {
                    traceToken: token.payload,
                },
            },
        }
    }

    private buildApiSuccessBody(path: string, token: TrackingToken): Record<string, unknown> {
        return {
            success: true,
            count: 3,
            data: this.buildResourceItems(path, 3),
            paging: {
                page: 1,
                pageSize: 25,
                total: 3,
            },
            links: {
                self: path,
                next: null,
            },
            auth: {
                accessToken: token.payload,
                tokenType: 'Bearer',
            },
        }
    }

    private buildAdminSuccessBody(token: TrackingToken): Record<string, unknown> {
        return {
            success: true,
            panel: {
                environment: 'production',
                stats: {
                    activeUsers: 284,
                    requests24h: 18342,
                    errorRate: 0.011,
                    avgLatencyMs: 87,
                },
                services: [
                    { name: 'api-gateway', status: 'healthy' },
                    { name: 'auth-service', status: 'healthy' },
                    { name: 'billing-worker', status: 'degraded' },
                ],
                recentAlerts: [
                    { id: 'ALT-1029', severity: 'low', state: 'open' },
                    { id: 'ALT-1034', severity: 'medium', state: 'investigating' },
                ],
            },
            operator: {
                role: 'admin',
                accessToken: token.payload,
            },
        }
    }

    private buildResourceItems(path: string, count: number): Array<Record<string, unknown>> {
        const resource = resourceNameFromPath(path)
        const now = Date.now()

        return Array.from({ length: count }, (_, index) => {
            const id = crypto.randomUUID()
            const base: Record<string, unknown> = {
                id,
                createdAt: new Date(now - (index + 1) * 3600_000).toISOString(),
                updatedAt: new Date(now - index * 600_000).toISOString(),
                status: index % 2 === 0 ? 'active' : 'pending',
            }

            if (resource === 'user') {
                base.email = `user${index + 1}@example.com`
                base.name = `User ${index + 1}`
                base.role = index === 0 ? 'admin' : 'member'
                return base
            }

            if (resource === 'order') {
                base.orderNumber = `ORD-${4300 + index}`
                base.amount = 149 + index * 20
                base.currency = 'USD'
                return base
            }

            if (resource === 'invoice') {
                base.invoiceNumber = `INV-${9200 + index}`
                base.total = 240 + index * 35
                base.dueDate = new Date(now + (index + 2) * 86400_000).toISOString()
                return base
            }

            if (resource === 'payment') {
                base.amount = 79 + index * 11
                base.currency = 'USD'
                base.method = index % 2 === 0 ? 'card' : 'bank_transfer'
                return base
            }

            base.name = `${resource}-${index + 1}`
            base.slug = `${resource}-${(index + 1).toString().padStart(2, '0')}`
            return base
        })
    }

    private calculateDelay(avgResponseSize: number): number {
        const sizeAdjust = avgResponseSize > 0 ? Math.min(Math.floor(avgResponseSize / 2048), 40) : 0
        const min = Math.min(120, 50 + sizeAdjust)
        const max = Math.min(200, 160 + sizeAdjust)
        return min + Math.floor(Math.random() * (max - min + 1))
    }

    private pruneExpiredTokens(): void {
        const now = Date.now()
        const ttlMs = this.config.trackingTtlSeconds * 1000

        for (const [tokenId, token] of this.trackedTokens) {
            if (now - token.issuedAt > ttlMs) {
                this.trackedTokens.delete(tokenId)
                this.dossiers.delete(tokenId)
            }
        }
    }
}

function isAuthPath(path: string): boolean {
    return path.includes('/login') || path.includes('/auth') || path.includes('/token')
}

function isAdminPath(path: string): boolean {
    return /\/(admin|dashboard|manage|internal)\b/.test(path)
}

function resourceNameFromPath(path: string): string {
    const clean = path
        .replace(/\?.*$/, '')
        .split('/')
        .filter(Boolean)

    const candidates = clean.filter(segment => segment !== 'api' && !segment.startsWith('v'))
    const last = candidates[candidates.length - 1] ?? 'resource'

    if (last.endsWith('ies')) return `${last.slice(0, -3)}y`
    if (last.endsWith('s') && last.length > 1) return last.slice(0, -1)
    return last
}

function unique(values: string[]): string[] {
    return [...new Set(values)]
}

function countFastBursts(actions: AttackerAction[]): number {
    if (actions.length < 3) return 0

    const sorted = [...actions].sort((a, b) => a.timestamp - b.timestamp)
    let bursts = 0

    for (let i = 1; i < sorted.length; i++) {
        if (sorted[i].timestamp - sorted[i - 1].timestamp < 400) {
            bursts++
        }
    }

    return bursts
}

function headersToRecord(headers: Headers): Record<string, string> {
    const out: Record<string, string> = {}
    for (const [key, value] of headers.entries()) {
        out[key.toLowerCase()] = value
    }
    return out
}

function encodeBase64Url(value: string): string {
    const b64 = btoa(value)
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function decodeBase64Url(value: string): string | null {
    try {
        const padded = value + '='.repeat((4 - (value.length % 4 || 4)) % 4)
        const b64 = padded.replace(/-/g, '+').replace(/_/g, '/')
        return atob(b64)
    } catch {
        return null
    }
}

function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
    const parts = jwt.split('.')
    if (parts.length !== 3) return null

    const payloadJson = decodeBase64Url(parts[1])
    if (!payloadJson) return null

    try {
        const parsed = JSON.parse(payloadJson)
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null
        return parsed as Record<string, unknown>
    } catch {
        return null
    }
}

async function extractTokenFromBody(request: Request): Promise<string | null> {
    if (request.method === 'GET' || request.method === 'HEAD' || request.method === 'OPTIONS') {
        return null
    }

    const contentType = (request.headers.get('content-type') ?? '').toLowerCase()
    if (!contentType.includes('json') && !contentType.includes('x-www-form-urlencoded') && !contentType.includes('text/plain')) {
        return null
    }

    try {
        const body = await request.clone().text()
        if (!body) return null

        if (contentType.includes('json')) {
            const parsed = JSON.parse(body) as unknown
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null
            const record = parsed as Record<string, unknown>
            const candidate = record.token ?? record.accessToken ?? record.jwt
            return typeof candidate === 'string' ? candidate : null
        }

        if (contentType.includes('x-www-form-urlencoded')) {
            const params = new URLSearchParams(body)
            return params.get('token') ?? params.get('access_token') ?? params.get('jwt')
        }

        const match = body.match(/(?:token|access_token|jwt)\s*[:=]\s*([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)/i)
        return match ? match[1] : null
    } catch {
        return null
    }
}

async function safeReadBody(request: Request): Promise<string> {
    if (request.method === 'GET' || request.method === 'HEAD' || request.method === 'OPTIONS') {
        return ''
    }

    try {
        return await request.clone().text()
    } catch {
        return ''
    }
}

function delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
}

async function signJwtHs256(signingInput: string, key: string): Promise<string> {
    const encoder = new TextEncoder()
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(key),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    )
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(signingInput))
    return bytesToBase64Url(new Uint8Array(signature))
}

function bytesToBase64Url(bytes: Uint8Array): string {
    let binary = ''
    for (const byte of bytes) {
        binary += String.fromCharCode(byte)
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}
