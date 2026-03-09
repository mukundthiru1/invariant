/**
 * HTTP Smuggling Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for HTTP request smuggling is:
 *   ∃ header_set ∈ parse(input, HTTP_HEADER_GRAMMAR) :
 *     header_set CONTAINS 'Transfer-Encoding'
 *     ∧ header_set CONTAINS 'Content-Length'
 *     → CL/TE desync between front-end and back-end
 *
 *   ∨ header_set CONTAINS multiple 'Transfer-Encoding' headers
 *     → TE/TE desync via obfuscation
 *
 *   ∨ header CONTAINS CRLF within pseudo-header value
 *     → H2-to-H1 downgrade smuggling
 *
 * Covers:
 *   - http_smuggle_cl_te: CL/TE and TE/CL desync attacks
 *   - http_smuggle_h2:    HTTP/2 pseudo-header CRLF injection
 */


// ── Result Type ──────────────────────────────────────────────────

export interface HTTPSmuggleDetection {
    type: 'cl_te_desync' | 'te_te_desync' | 'te_obfuscation' | 'h2_pseudo_header' | 'h2_crlf' | 'chunked_body' | 'h2c_upgrade_smuggling' | 'chunked_trailer_injection' | 'obfuscated_content_length' | 'request_tunneling_abuse' | 'pipelined_request_poisoning'
    detail: string
    confidence: number
}


// ── Header Parser ────────────────────────────────────────────────

interface ParsedHeader {
    name: string
    value: string
    position: number
    rawLine: string
}

function parseHeaders(input: string): ParsedHeader[] {
    const headers: ParsedHeader[] = []

    // Split on CRLF and \n
    const lines = input.split(/\r?\n/)

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        const colonIdx = line.indexOf(':')
        if (colonIdx <= 0) continue

        const name = line.substring(0, colonIdx).trim()
        const value = line.substring(colonIdx + 1).trim()

        // Valid HTTP header name: [A-Za-z0-9-]+
        if (/^[A-Za-z0-9-]+$/.test(name)) {
            headers.push({
                name: name.toLowerCase(),
                value,
                position: i,
                rawLine: line,
            })
        }
    }

    return headers
}


// ── TE Obfuscation Patterns ──────────────────────────────────────
//
// Various ways to obfuscate Transfer-Encoding to trigger desync:
//   Transfer-Encoding: chunked
//   Transfer-Encoding : chunked        (space before colon)
//   Transfer-Encoding: chunked, identity
//   Transfer-Encoding: xchunked
//   Transfer-Encoding: chunk           (truncated)
//   Transfer-encoding: cow             (different casing)
//   Transfer-Encoding:
//    chunked                            (line continuation)

const TE_OBFUSCATION_PATTERNS = [
    { pattern: /transfer-encoding\s+:\s*chunked/i, name: 'space before colon' },
    { pattern: /transfer-encoding:\s*chunked\s*,\s*\w+/i, name: 'multiple TE values' },
    { pattern: /transfer-encoding:\s*x?chunk/i, name: 'chunked variant' },
    { pattern: /transfer-encoding:\s*$/im, name: 'empty TE value' },
    { pattern: /transfer-encoding:\s*identity/i, name: 'identity encoding' },
    { pattern: /transfer-encoding:(?:\s|\r?\n\s+)+chunked/i, name: 'multiline header continuation' },
    { pattern: /transfer-encoding:\s*chunked;boundary=/i, name: 'chunked with boundary extension' }
]


// ── Detection Functions ──────────────────────────────────────────

function detectCLTEDesync(headers: ParsedHeader[]): HTTPSmuggleDetection[] {
    const detections: HTTPSmuggleDetection[] = []

    const hasCL = headers.some(h => h.name === 'content-length')
    const hasTE = headers.some(h => h.name === 'transfer-encoding')

    if (hasCL && hasTE) {
        // CL + TE in same request = desync
        const teHeader = headers.find(h => h.name === 'transfer-encoding')
        const clHeader = headers.find(h => h.name === 'content-length')

        detections.push({
            type: 'cl_te_desync',
            detail: `CL/TE desync: Content-Length: ${clHeader?.value} + Transfer-Encoding: ${teHeader?.value}`,
            confidence: 0.96,
        })
    }

    // Multiple TE headers (TE/TE)
    const teHeaders = headers.filter(h => h.name === 'transfer-encoding')
    if (teHeaders.length > 1) {
        detections.push({
            type: 'te_te_desync',
            detail: `TE/TE desync: ${teHeaders.length} Transfer-Encoding headers`,
            confidence: 0.94,
        })
    }

    return detections
}

function detectTEObfuscation(input: string): HTTPSmuggleDetection[] {
    const detections: HTTPSmuggleDetection[] = []

    for (const obf of TE_OBFUSCATION_PATTERNS) {
        if (obf.pattern.test(input)) {
            detections.push({
                type: 'te_obfuscation',
                detail: `Transfer-Encoding obfuscation: ${obf.name}`,
                confidence: 0.90,
            })
        }
    }

    return detections
}

function detectH2Smuggle(input: string): HTTPSmuggleDetection[] {
    const detections: HTTPSmuggleDetection[] = []

    // HTTP/2 pseudo-headers in input
    const pseudoHeaders = [':method', ':path', ':authority', ':scheme', ':status']
    for (const ph of pseudoHeaders) {
        if (input.includes(ph)) {
            // Check for CRLF within the pseudo-header value
            const phIdx = input.indexOf(ph)
            const afterPh = input.substring(phIdx + ph.length, phIdx + ph.length + 200)
            if (/[\r\n]/.test(afterPh) || afterPh.includes('\\r\\n')) {
                detections.push({
                    type: 'h2_crlf',
                    detail: `H2 CRLF injection in ${ph} pseudo-header — H2-to-H1 smuggle`,
                    confidence: 0.94,
                })
            } else {
                detections.push({
                    type: 'h2_pseudo_header',
                    detail: `H2 pseudo-header in request body: ${ph} — potential H2 smuggle`,
                    confidence: 0.80,
                })
            }
        }
    }

    return detections
}

function detectChunkedBody(input: string): HTTPSmuggleDetection[] {
    const detections: HTTPSmuggleDetection[] = []

    // Detect chunked transfer encoding in body (embedded request)
    // Pattern: 0\r\n\r\n (end of chunks) followed by another HTTP request
    const chunkedEnd = /0\r?\n\r?\n(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s/
    if (chunkedEnd.test(input)) {
        detections.push({
            type: 'chunked_body',
            detail: 'Embedded HTTP request after chunked body terminator — request smuggling',
            confidence: 0.96,
        })
    }

    return detections
}


export function detectH2cUpgradeSmuggling(input: string): HTTPSmuggleDetection | null {
    const hasUpgrade = /(?:^|\r?\n)upgrade\s*:\s*[^\r\n]*\bh2c\b/i.test(input)
    const hasConnectionUpgrade = /(?:^|\r?\n)connection\s*:\s*[^\r\n]*\bupgrade\b/i.test(input)

    if (!hasUpgrade || !hasConnectionUpgrade) {
        return null
    }

    return {
        type: 'h2c_upgrade_smuggling',
        detail: 'HTTP/2 cleartext upgrade smuggling: Upgrade: h2c with Connection: Upgrade',
        confidence: 0.91,
    }
}

export function detectChunkedTrailerInjection(input: string): HTTPSmuggleDetection | null {
    const hasChunkedTransfer = /transfer-encoding\s*:\s*[^\r\n]*\bchunked\b/i.test(input)
    const trailerHeaderPayload = /\r\n0\r?\n(?:(?:[A-Za-z0-9-]+\s*:\s*[^\r\n]*\r?\n)+)\r?\n/i

    if (!hasChunkedTransfer || !trailerHeaderPayload.test(input)) {
        return null
    }

    return {
        type: 'chunked_trailer_injection',
        detail: 'Chunked trailer header injection after 0-terminator before final CRLF',
        confidence: 0.90,
    }
}

export function detectObfuscatedContentLength(input: string): HTTPSmuggleDetection | null {
    const clMatches = [...input.matchAll(/(?:^|\r?\n)content-length\s*:\s*([^\r\n]*)/gi)]
    if (clMatches.length < 1) {
        return null
    }

    const values: string[] = []
    const issues: string[] = []

    for (const match of clMatches) {
        const rawValue = match[1] ?? ''
        const normalized = rawValue.trim().toLowerCase()

        values.push(normalized)

        if (/^\s{2,}\S/.test(rawValue)) {
            issues.push('leading spaces before value')
        }
        if (/^0x[0-9a-f]+$/i.test(normalized)) {
            issues.push('hexadecimal value')
        }
        if (/^\d+\.\d+$/.test(normalized)) {
            issues.push('non-integer decimal value')
        }
    }

    const normalizedValues = new Set(values)
    if (values.length > 1 && normalizedValues.size > 1) {
        issues.push('duplicate Content-Length headers with potentially conflicting values')
    }

    if (issues.length === 0) {
        return null
    }

    return {
        type: 'obfuscated_content_length',
        detail: `Obfuscated Content-Length: ${[...new Set(issues)].join('; ')}`,
        confidence: 0.92,
    }
}

export function detectRequestTunnelingAbuse(input: string): HTTPSmuggleDetection | null {
    const hostWithEmbeddedRequest = /(?:^|\r?\n)host\s*:\s*[^\r\n]+\r?\n[\s\S]{0,300}?(?:(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[^\r\n]+\s+HTTP\/1\.[01]|CONNECT\s+[^\r\n]+\s+HTTP\/1\.[01])/i.test(input)
    const connectAbuse = /(?:^|\r?\n)host\s*:\s*[^\r\n]+\r?\n(?:[\s\S]{0,300}?)(?:\r?\n|^)connect\s+[^\s]+:\d+\s+HTTP\/1\.[01]/i.test(input)

    if (!hostWithEmbeddedRequest && !connectAbuse) {
        return null
    }

    return {
        type: 'request_tunneling_abuse',
        detail: 'HTTP/2 request tunneling abuse: Host header with embedded HTTP/1 request or CONNECT tunneling',
        confidence: 0.89,
    }
}

export function detectPipelinedRequestPoisoning(input: string): HTTPSmuggleDetection | null {
    const requestLinePattern = /(?:^|[\r\n])(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[^\r\n]+\s+HTTP\/1\.[01]/g
    const matches = [...input.matchAll(requestLinePattern)]

    if (matches.length < 2) {
        return null
    }

    for (let i = 1; i < matches.length; i++) {
        const prev = matches[i - 1]
        const curr = matches[i]

        const prevStart = prev.index ?? 0
        const prevMatch = prev[0]
        const prevLineEnd = prevStart + prevMatch.length

        const currStart = (curr.index ?? 0) + ((curr[0][0] === '\r' || curr[0][0] === '\n') ? 1 : 0)
        const boundary = input.slice(prevLineEnd, currStart)

        const hasCanonicalBoundary = /\r\n\r\n/.test(boundary)
        const hasAnyBoundary = /\r?\n\r?\n/.test(boundary)

        if (!hasAnyBoundary || (!hasCanonicalBoundary && /\n\n/.test(boundary))) {
            return {
                type: 'pipelined_request_poisoning',
                detail: 'Malformed pipelined request boundary detected in single TCP stream',
                confidence: 0.87,
            }
        }
    }

    return null
}


// ── Public API ───────────────────────────────────────────────────

export function detectHTTPSmuggling(input: string): HTTPSmuggleDetection[] {
    const detections: HTTPSmuggleDetection[] = []

    if (input.length < 10) return detections

    // Quick bail
    const lower = input.toLowerCase()
    if (!lower.includes('transfer') && !lower.includes('content-length') &&
        !lower.includes(':method') && !lower.includes(':path') &&
        !lower.includes('chunked') &&
        !/0\r?\n\r?\n/.test(input) &&
        !lower.includes('upgrade') &&
        !lower.includes('host:') &&
        !lower.includes('http/1.1')) {
        return detections
    }

    try {
        const headers = parseHeaders(input)
        detections.push(...detectCLTEDesync(headers))
    } catch { /* safe */ }

    try { detections.push(...detectTEObfuscation(input)) } catch { /* safe */ }
    try { detections.push(...detectH2Smuggle(input)) } catch { /* safe */ }
    try { detections.push(...detectChunkedBody(input)) } catch { /* safe */ }
    try {
        const h2cUpgrade = detectH2cUpgradeSmuggling(input)
        if (h2cUpgrade) detections.push(h2cUpgrade)
    } catch { /* safe */ }
    try {
        const chunkedTrailer = detectChunkedTrailerInjection(input)
        if (chunkedTrailer) detections.push(chunkedTrailer)
    } catch { /* safe */ }
    try {
        const obfContentLength = detectObfuscatedContentLength(input)
        if (obfContentLength) detections.push(obfContentLength)
    } catch { /* safe */ }
    try {
        const requestTunneling = detectRequestTunnelingAbuse(input)
        if (requestTunneling) detections.push(requestTunneling)
    } catch { /* safe */ }
    try {
        const pipelinedPoison = detectPipelinedRequestPoisoning(input)
        if (pipelinedPoison) detections.push(pipelinedPoison)
    } catch { /* safe */ }

    return detections
}

export function detectHttpSmuggle(input: string): HTTPSmuggleDetection[] {
    return detectHTTPSmuggling(input)
}
