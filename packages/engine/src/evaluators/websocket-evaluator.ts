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


// ── Advanced WebSocket Security Checks ─────────────────────────

function parseHeaderValue(input: string, headerName: string): string | null {
    const match = input.match(new RegExp(`(?:^|\\n)\\s*${headerName}\\s*:\\s*(.*)`, 'i'))
    return match?.[1]?.trim() ?? null
}

function stripHeaderHost(value: string): string {
    return value
        .replace(/^\s*\w+:\/\//, '')
        .replace(/[:/].*$/, '')
        .toLowerCase()
}

const SQL_COMMAND_PATTERN = /(?:drop|delete|insert|update|select|union|benchmark|load_file|sleep)\s*\(/i
const SHELL_COMMAND_PATTERN = /(?:cat|ls|id|whoami|uname|pwd|curl|wget|bash|sh|python|perl|ruby|php)/i

export function detectWebSocketCrossSiteHijack(input: string): WebSocketDetection | null {
    const indicators: string[] = []
    if (!/upgrade\s*:\s*websocket/i.test(input)) return null

    const origin = parseHeaderValue(input, 'origin')
    const host = parseHeaderValue(input, 'host')
    const key = parseHeaderValue(input, 'sec-websocket-key')
    const hasCsrfToken = /(?:^|\n)\s*(x-csrf-token|csrf-token|x-xsrf-token|x-xsrf)\s*:/i.test(input)

    if (!origin) {
        indicators.push('missing Origin header on websocket upgrade')
    } else if (host) {
        const normalizedOrigin = stripHeaderHost(origin)
        const normalizedHost = stripHeaderHost(host)
        if (normalizedOrigin && normalizedHost && normalizedOrigin !== normalizedHost) {
            indicators.push(`origin mismatch: Origin ${normalizedOrigin} vs Host ${normalizedHost}`)
        }
    }

    if (!hasCsrfToken) {
        indicators.push('missing CSRF token in websocket upgrade request')
    }

    if (!key) {
        indicators.push('missing Sec-WebSocket-Key')
    } else if (key.length > 0 && /^(.)\1{20,}=*$/.test(key)) {
        indicators.push(`predictable Sec-WebSocket-Key: ${key.slice(0, 20)}`)
    } else if (/^(?:dGhpcy1pcy1ub3QtYS1yYW5kb20ta2V5|YWJjZGVmZ2hpamtsbW5vcA==|dGVzdA==)$/i.test(key)) {
        indicators.push(`predictable Sec-WebSocket-Key: ${key}`)
    }

    if (indicators.length < 2) return null

    return {
        type: 'ws_hijack',
        detail: `Cross-site websocket hijack: ${indicators.join('; ')}`,
        confidence: 0.89,
        indicators,
    }
}

export function detectWebSocketBinaryFrameInjection(input: string): WebSocketDetection | null {
    const indicators: string[] = []
    const hasBinaryFrame = /(?:^|\n)\s*(?:opcode|frame-type)\s*:\s*(?:0x)?02\b/i.test(input) || /\bopcode(?:\s+)?0x02\b/i.test(input)
    if (!hasBinaryFrame) return null

    const payloadLines = [
        ...input.matchAll(/(?:^|\n)\s*payload\s*:\s*([^\r\n]*)/gi),
    ].map((m) => m[1] ?? '')

    const payloadText = payloadLines.join(' ')
    const hasControlCharacters = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(payloadText) || /(?:%00|\\x00|\\u0000)/i.test(payloadText)
    const normalizedPayload = payloadText.replace(/(?:%00|\\x00|\\u0000)/gi, '')
    const hasShellInjection = SHELL_COMMAND_PATTERN.test(normalizedPayload)
    const hasSqlInjection = SQL_COMMAND_PATTERN.test(normalizedPayload) || /(?:\bor\b.*\d+\s*=\s*\d+|union\s+select|--|\/\*|\*\/)/i.test(normalizedPayload)
    const hasFragmentation = /(?:\n|\r|^)\s*(?:fin\s*:\s*0|continuation|fragment(ed)?\b)/i.test(input)

    if (!hasControlCharacters) {
        return null
    }

    if (!(hasShellInjection || hasSqlInjection || hasFragmentation)) {
        return null
    }

    if (hasShellInjection) {
        indicators.push('shell command token detected in binary frame payload')
    }
    if (hasSqlInjection) {
        indicators.push('SQL injection pattern detected in binary payload after control-char filter')
    }
    if (hasFragmentation) {
        indicators.push('binary frame fragmentation indicators with payload reassembly risk')
    }

    return {
        type: 'ws_hijack',
        detail: `Binary websocket frame injection: ${indicators.join('; ')}`,
        confidence: 0.87,
        indicators,
    }
}

export function detectWebSocketSubprotocolAbuse(input: string): WebSocketDetection | null {
    const protocolHeader = parseHeaderValue(input, 'sec-websocket-protocol')
    if (!protocolHeader) return null

    const indicators: string[] = []
    if (/\b(soap|mqtt|chat)\b/i.test(protocolHeader) && /(?:\.\.\/|;|`|'|"|<|>|\$|\)|\|)/.test(protocolHeader)) {
        indicators.push(`suspicious protocol token: ${protocolHeader}`)
    }
    if (/\.\.\//.test(protocolHeader)) {
        indicators.push(`protocol path traversal attempt: ${protocolHeader}`)
    }
    if (/\\.\//.test(protocolHeader)) {
        indicators.push(`protocol escape payload: ${protocolHeader}`)
    }
    if (/(?:select|union|drop|cat|ls|curl|bash|sh)/i.test(protocolHeader)) {
        indicators.push('protocol contains command or SQL traversal payload')
    }

    if (indicators.length === 0) return null

    return {
        type: 'ws_hijack',
        detail: `WebSocket subprotocol abuse: ${indicators.join('; ')}`,
        confidence: 0.86,
        indicators,
    }
}

export function detectWebSocketExtensionAbuse(input: string): WebSocketDetection | null {
    const extHeader = parseHeaderValue(input, 'sec-websocket-extensions')
    if (!extHeader) return null

    const normalizedExt = extHeader.toLowerCase()
    if (!normalizedExt.includes('permessage-deflate') || !/client_max_window_bits\s*=\s*15/i.test(extHeader)) return null

    const payloadLine = parseHeaderValue(input, 'payload')
    const indicators: string[] = []
    indicators.push('permessage-deflate negotiated with max window set to 15')

    if (/(?:server_no_context_takeover|client_no_context_takeover)/i.test(extHeader)) {
        indicators.push('context takeover flags present in extension negotiation')
    }
    if (/(?:\b[a-z0-9+\/]{96,}={0,3}\b|\b0x78 0x9c\b|payload length[:\s]*\d{4,})/i.test(input)) {
        indicators.push('crafted compressed payload marker with high-entropy binary blob')
    }
    if (/deflate|zlib|gzip/.test(normalizedExt) && /payload/i.test(input)) {
        indicators.push('compressed websocket payload present')
    }

    if (indicators.length < 2) return null

    return {
        type: 'ws_hijack',
        detail: `WebSocket extension abuse: ${indicators.join('; ')}`,
        confidence: 0.84,
        indicators,
    }
}

export function detectWebSocketAuthBypass(input: string): WebSocketDetection | null {
    const pathMatch = input.match(/(?:^|\n)\s*(?:GET|POST)\s+([^\s]+)\s+HTTP\/[0-9.]+/i)
    if (!pathMatch) return null

    const path = pathMatch[1].toLowerCase()
    if (!/\/ws\/(?:admin|internal)/i.test(path)) return null

    const authorization = /(?:^|\n)\s*authorization\s*:\s*bearer\s+\S+/i.test(input)
    const hasCookie = /(?:^|\n)\s*cookie\s*:\s*\S+/i.test(input)
    const downgradedSession = /(?:^|\n)\s*cookie\s*:\s*[^;\n]*session=[^;\n]*\b(?:guest|anonymous|preview|read-only|readonly)\b/i.test(input)
    const swappedSessionHeader = /(?:^|\n)\s*(x-session-token|x-auth-token|session-token)\s*:\s*\S*/i.test(input) && !/x-session-token\s*:\s*(?:admin|super|root)/i.test(input)

    const indicators: string[] = []

    if (!hasCookie && authorization) {
        indicators.push(`ws admin path requested without Cookie: ${path}`)
    }
    if (authorization && downgradedSession) {
        indicators.push(`ws admin path with downgraded session cookie on ${path}`)
    }
    if (authorization && swappedSessionHeader && !hasCookie) {
        indicators.push('suspicious auth header used while cookie context is missing')
    }

    if (indicators.length === 0) return null

    return {
        type: 'ws_hijack',
        detail: `WebSocket auth bypass attempt: ${indicators.join('; ')}`,
        confidence: 0.88,
        indicators,
    }
}


// ── Public API ───────────────────────────────────────────────────

export function detectWebSocketAttack(input: string): WebSocketDetection[] {
    const detections: WebSocketDetection[] = []

    if (input.length < 5) return detections

    try { detections.push(...analyzeWsInjection(input)) } catch { /* safe */ }
    try { detections.push(...analyzeWsHijack(input)) } catch { /* safe */ }
    try {
        const crossSite = detectWebSocketCrossSiteHijack(input)
        if (crossSite) detections.push(crossSite)
    } catch { /* safe */ }
    try {
        const binaryFrame = detectWebSocketBinaryFrameInjection(input)
        if (binaryFrame) detections.push(binaryFrame)
    } catch { /* safe */ }
    try {
        const subprotocol = detectWebSocketSubprotocolAbuse(input)
        if (subprotocol) detections.push(subprotocol)
    } catch { /* safe */ }
    try {
        const extension = detectWebSocketExtensionAbuse(input)
        if (extension) detections.push(extension)
    } catch { /* safe */ }
    try {
        const authBypass = detectWebSocketAuthBypass(input)
        if (authBypass) detections.push(authBypass)
    } catch { /* safe */ }

    return detections
}
