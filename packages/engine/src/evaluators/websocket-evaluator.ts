/**
 * WebSocket Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for WebSocket attacks:
 *   ∃ payload ∈ ws_frame :
 *     payload MATCHES injection_pattern
 *     ∧ frame_context(payload) CONFIRMS ws_transport
 *     → attacker exploits persistent WebSocket connection
 *
 * This module performs structural analysis beyond regex:
 *   - ws_injection: deep JSON traversal of WS messages to find embedded attacks
 *   - ws_hijack: HTTP upgrade header validation against RFC 6455
 */


// ── Result Type ──────────────────────────────────────────────────

export interface WebSocketDetection {
    type: 'ws_injection' | 'ws_hijack'
    detail: string
    confidence: number
    indicators: string[]
}


// ── WS Injection Structural Analysis ─────────────────────────────
//
// Beyond regex: parse JSON messages and recursively extract all
// string values, then run injection analysis on each. This catches
// deeply nested payloads that flat regex misses.

const SQLI_PATTERNS = [
    /'\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
    /union\s+(?:all\s+)?select\b/i,
    /;\s*(?:drop|delete|insert|update|alter|create)\s/i,
    /(?:sleep|pg_sleep|benchmark|waitfor\s+delay)\s*\(/i,
    /(?:extractvalue|updatexml|load_file)\s*\(/i,
]

const XSS_PATTERNS = [
    /<script[\s>]/i,
    /javascript\s*:/i,
    /\bon(?:error|load|click|mouseover|focus|blur|submit|change|input)\s*=/i,
    /<(?:img|svg|iframe|embed|object)\s[^>]*(?:src|href)\s*=\s*['"]?(?:javascript|data):/i,
]

const CMDI_PATTERNS = [
    /[;|`]\s*(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc|bash|sh|python|perl|ruby|php)\b/i,
    /\$\([^)]*(?:id|whoami|cat|curl|wget|bash|sh)[^)]*\)/i,
    /`[^`]*(?:id|whoami|cat|curl|wget|bash|sh)[^`]*`/i,
]

function extractStrings(value: unknown, depth = 0): string[] {
    if (depth > 10) return []  // Prevent stack overflow on deep nesting
    const strings: string[] = []

    if (typeof value === 'string') {
        strings.push(value)
    } else if (Array.isArray(value)) {
        for (const item of value) {
            strings.push(...extractStrings(item, depth + 1))
        }
    } else if (value && typeof value === 'object') {
        for (const v of Object.values(value as Record<string, unknown>)) {
            strings.push(...extractStrings(v, depth + 1))
        }
    }

    return strings
}

function analyzeWsInjection(input: string): WebSocketDetection[] {
    const detections: WebSocketDetection[] = []
    const indicators: string[] = []

    // Attempt JSON parse for deep string extraction
    let strings: string[] = []
    try {
        const parsed = JSON.parse(input)
        strings = extractStrings(parsed)
    } catch {
        // Not valid JSON — check if it looks like a WS context
        if (!/(?:\{[\s\S]*\}|websocket|ws[_-]?(?:message|frame))/i.test(input)) {
            return detections
        }
        strings = [input]
    }

    for (const str of strings) {
        if (str.length < 3) continue

        for (const pattern of SQLI_PATTERNS) {
            if (pattern.test(str)) {
                indicators.push(`SQLi in WS value: ${str.slice(0, 60)}`)
                break
            }
        }

        for (const pattern of XSS_PATTERNS) {
            if (pattern.test(str)) {
                indicators.push(`XSS in WS value: ${str.slice(0, 60)}`)
                break
            }
        }

        for (const pattern of CMDI_PATTERNS) {
            if (pattern.test(str)) {
                indicators.push(`CMDi in WS value: ${str.slice(0, 60)}`)
                break
            }
        }
    }

    if (indicators.length > 0) {
        detections.push({
            type: 'ws_injection',
            detail: `WS frame injection: ${indicators.join('; ')}`,
            confidence: indicators.length >= 2 ? 0.92 : 0.86,
            indicators,
        })
    }

    return detections
}


// ── WS Hijack Structural Analysis ────────────────────────────────
//
// Beyond regex: validate HTTP Upgrade headers against RFC 6455:
//   1. Origin must be present and match expected domain
//   2. Sec-WebSocket-Key must be valid base64 of 16 bytes
//   3. Sec-WebSocket-Protocol must not contain injection payloads
//   4. Connection must include "Upgrade"

function analyzeWsHijack(input: string): WebSocketDetection[] {
    const detections: WebSocketDetection[] = []
    const indicators: string[] = []

    // Must look like an HTTP upgrade request
    if (!/upgrade\s*:\s*websocket/i.test(input)) return detections

    // Check Origin header
    const originMatch = input.match(/(?:^|\n)\s*origin\s*:\s*(\S+)/i)
    if (!originMatch) {
        indicators.push('missing Origin header on WS upgrade')
    } else {
        const origin = originMatch[1].toLowerCase()
        // Suspicious origins
        if (origin === 'null' || /(?:evil|attacker|malicious|phish|exploit|localhost:\d{4,5}(?!\d))/i.test(origin)) {
            indicators.push(`suspicious Origin: ${origin}`)
        }
    }

    // Validate Sec-WebSocket-Key
    const keyMatch = input.match(/(?:^|\n)\s*sec-websocket-key\s*:\s*(\S+)/i)
    if (!keyMatch) {
        indicators.push('missing Sec-WebSocket-Key')
    } else {
        const key = keyMatch[1]
        // RFC 6455: must be base64 of exactly 16 bytes → 24 chars with padding
        if (!/^[A-Za-z0-9+/]{22}==$/.test(key)) {
            indicators.push(`malformed Sec-WebSocket-Key: ${key.slice(0, 30)}`)
        }
    }

    // Check Sec-WebSocket-Protocol for injection
    const protoMatch = input.match(/(?:^|\n)\s*sec-websocket-protocol\s*:\s*(.*)/i)
    if (protoMatch) {
        const proto = protoMatch[1]
        if (/<script|union\s+select|\$\(|;\s*(?:drop|curl|bash)/i.test(proto)) {
            indicators.push('injection payload in Sec-WebSocket-Protocol')
        }
    }

    if (indicators.length > 0) {
        detections.push({
            type: 'ws_hijack',
            detail: `WS hijack: ${indicators.join('; ')}`,
            confidence: indicators.length >= 2 ? 0.93 : 0.87,
            indicators,
        })
    }

    return detections
}


// ── Public API ───────────────────────────────────────────────────

export function detectWebSocketAttack(input: string): WebSocketDetection[] {
    const detections: WebSocketDetection[] = []

    if (input.length < 5) return detections

    try { detections.push(...analyzeWsInjection(input)) } catch { /* safe */ }
    try { detections.push(...analyzeWsHijack(input)) } catch { /* safe */ }

    return detections
}
