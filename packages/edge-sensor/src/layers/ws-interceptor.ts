import { InvariantEngine, type InvariantMatch } from '../../../engine/src/invariant-engine.js'
import type { Env } from './types.js'

const engine = new InvariantEngine()

export interface WebSocketUpgradeAnalysisResult {
    isWebSocketUpgrade: boolean
    shouldBlock: boolean
    reasons: string[]
    matches: InvariantMatch[]
}

export interface WebSocketMessageAnalysisResult {
    parsedJson: boolean
    matches: InvariantMatch[]
}

function isWebSocketUpgradeRequest(request: Request): boolean {
    const upgrade = request.headers.get('upgrade')
    return typeof upgrade === 'string' && upgrade.toLowerCase() === 'websocket'
}

function parseAllowedOrigins(request: Request, env: Env): Set<string> {
    const allowed = new Set<string>()
    allowed.add(new URL(request.url).origin)

    const configured = env.WS_ALLOWED_ORIGINS ?? ''
    for (const value of configured.split(',')) {
        const trimmed = value.trim()
        if (trimmed.length > 0) allowed.add(trimmed)
    }

    return allowed
}

function isValidWebSocketKey(key: string | null): boolean {
    if (!key) return false
    // RFC 6455: base64-encoded 16-byte nonce.
    if (!/^[A-Za-z0-9+/]+=*$/.test(key)) return false
    try {
        const decoded = atob(key)
        return decoded.length === 16
    } catch {
        return false
    }
}

function collectStringValues(value: unknown, bucket: string[]): void {
    if (typeof value === 'string') {
        bucket.push(value)
        return
    }

    if (Array.isArray(value)) {
        for (const item of value) collectStringValues(item, bucket)
        return
    }

    if (value && typeof value === 'object') {
        for (const nested of Object.values(value as Record<string, unknown>)) {
            collectStringValues(nested, bucket)
        }
    }
}

export function analyzeWebSocketUpgrade(request: Request, env: Env): WebSocketUpgradeAnalysisResult {
    if (!isWebSocketUpgradeRequest(request)) {
        return {
            isWebSocketUpgrade: false,
            shouldBlock: false,
            reasons: [],
            matches: [],
        }
    }

    const reasons: string[] = []
    const allowedOrigins = parseAllowedOrigins(request, env)
    const origin = request.headers.get('origin')
    const protocol = request.headers.get('sec-websocket-protocol') ?? ''
    const wsKey = request.headers.get('sec-websocket-key')

    if (!origin) {
        reasons.push('missing_origin')
    } else if (!allowedOrigins.has(origin)) {
        reasons.push('origin_mismatch')
    }

    if (!isValidWebSocketKey(wsKey)) {
        reasons.push('invalid_sec_websocket_key')
    }

    const headerPayload = [
        'Upgrade: websocket',
        `Origin: ${origin ?? ''}`,
        `Sec-WebSocket-Protocol: ${protocol}`,
        `Sec-WebSocket-Key: ${wsKey ?? ''}`,
    ].join('\n')

    const rawMatches = engine.detect(headerPayload, [])
    const protocolMatches = protocol.length > 0 ? engine.detect(protocol, []) : []

    const deduped = new Map<string, InvariantMatch>()
    for (const match of [...rawMatches, ...protocolMatches]) {
        const existing = deduped.get(match.class)
        if (!existing || match.confidence > existing.confidence) {
            deduped.set(match.class, match)
        }
    }

    const matches = [...deduped.values()]
    if (matches.some(m => m.class === 'ws_hijack')) {
        reasons.push('ws_hijack_detected')
    }
    if (matches.some(m => m.class === 'ws_injection')) {
        reasons.push('ws_protocol_injection')
    }

    return {
        isWebSocketUpgrade: true,
        shouldBlock: reasons.length > 0,
        reasons,
        matches,
    }
}

export function analyzeWebSocketMessage(data: string): WebSocketMessageAnalysisResult {
    let parsed: unknown

    try {
        parsed = JSON.parse(data)
    } catch {
        return {
            parsedJson: false,
            matches: [],
        }
    }

    const strings: string[] = []
    collectStringValues(parsed, strings)

    const deduped = new Map<string, InvariantMatch>()
    for (const value of strings) {
        const matches = engine.detect(value, [])
        for (const match of matches) {
            const existing = deduped.get(match.class)
            if (!existing || match.confidence > existing.confidence) {
                deduped.set(match.class, match)
            }
        }
    }

    return {
        parsedJson: true,
        matches: [...deduped.values()],
    }
}

export function analyzeWebSocketFrameBody(body: string, engine: InvariantEngine): InvariantMatch[] {
    return engine.detect(body, [])
}
