import type { DetectionLevelResult, InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

const REQUEST_LINE_RE = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP\/(?:1\.0|1\.1|2(?:\.0)?)$/im
const CONTENT_LENGTH_HEADER_RE = /^content-length\s*:\s*(\d+)\s*$/gim
const TRANSFER_ENCODING_HEADER_RE = /^transfer-encoding\s*:\s*([^\r\n]+)\s*$/gim
const CONTENT_LENGTH_PRESENT_RE = /^content-length\s*:\s*\d+\s*$/im
const TRANSFER_ENCODING_PRESENT_RE = /^transfer-encoding\s*:\s*[^\r\n]+\s*$/im
const CHUNK_TERMINATOR_MIDBODY_RE = /\r?\n0\r?\n\r?\n[A-Za-z0-9-]{1,64}\s*:[^\r\n]{0,200}\r?\n/i
const H2_ESCAPED_CRLF_SMUGGLING_RE = /^:(?:path|method)\s*:\s*[^\r\n]{0,512}(?:\\r\\n|%0d%0a|%0a%0d|\\x0d\\x0a)/im
const H2_ACTUAL_CRLF_HEADER_INJECT_RE = /^:(?:path|method)\s*:\s*[^\r\n]{0,512}\r?\n(?!:)[A-Za-z0-9-]{1,64}\s*:[^\r\n]{0,256}\r?\n/im
const TE_OBFUSCATED_RE = /^transfer-encoding\s*:\s*(?:chunked\t|chunked\s{1,8}|\['chunked'\]|\["chunked"\])\s*$/im

function parseContentLengths(input: string): number[] {
    return Array.from(input.matchAll(CONTENT_LENGTH_HEADER_RE)).map((m) => parseInt(m[1], 10)).filter((n) => Number.isFinite(n))
}

function parseTransferEncodingValues(input: string): string[] {
    return Array.from(input.matchAll(TRANSFER_ENCODING_HEADER_RE)).map((m) => m[1].trim().toLowerCase())
}

function hasBothClAndTe(input: string): boolean {
    return CONTENT_LENGTH_PRESENT_RE.test(input) && TRANSFER_ENCODING_PRESENT_RE.test(input)
}

function hasClTeConflict(input: string): boolean {
    const cls = parseContentLengths(input)
    const tes = parseTransferEncodingValues(input)
    const hasChunked = tes.some((v) => /\bchunked\b/.test(v))
    if (!cls.length || !hasChunked) return false

    const uniqueCl = new Set(cls)
    if (uniqueCl.size > 1) return true

    const hasChunkFrame = /\r?\n[0-9a-f]{1,8}\r?\n/i.test(input)
    return cls.some((v) => v > 0) || hasChunkFrame
}

function hasTeClObfuscation(input: string): boolean {
    if (!CONTENT_LENGTH_PRESENT_RE.test(input)) return false
    const teValues = parseTransferEncodingValues(input)
    const hasObfuscatedHeader = TE_OBFUSCATED_RE.test(input)
    const hasBracketedChunked = teValues.some((v) => v.includes("['chunked']") || v.includes('["chunked"]'))
    const hasChunkedWithTabOrSpace = teValues.some((v) => /chunked(?:\t|\s{1,8})$/.test(v))

    return hasObfuscatedHeader || hasBracketedChunked || hasChunkedWithTabOrSpace
}

function hasHttp2PseudoHeaderCrlf(input: string): boolean {
    return H2_ESCAPED_CRLF_SMUGGLING_RE.test(input) || H2_ACTUAL_CRLF_HEADER_INJECT_RE.test(input)
}

function hasMidBodyChunkTerminator(input: string): boolean {
    return CHUNK_TERMINATOR_MIDBODY_RE.test(input)
}

function hasGetAdminTunneling(input: string): boolean {
    const reqLine = input.match(REQUEST_LINE_RE)
    if (!reqLine) return false
    const method = reqLine[1].toUpperCase()
    const path = reqLine[2].toLowerCase()
    if (method !== 'GET' || !path.startsWith('/admin')) return false

    const cls = parseContentLengths(input)
    return cls.some((v) => v > 0)
}

export const requestSmuggling: InvariantClassModule = {
    id: 'request_smuggling_desync',
    description: 'HTTP request desynchronization/smuggling via CL.TE conflicts, TE obfuscation, pseudo-header CRLF injection, and request tunneling',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.91, minInputLength: 20 },
    mitre: ['T1071.001'],
    cwe: 'CWE-444',
    knownPayloads: [
        'POST / HTTP/1.1\r\nHost: app.local\r\nContent-Length: 44\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: app.local\r\n\r\n',
        'POST /login HTTP/1.1\r\nHost: app.local\r\nTransfer-Encoding: chunked\t\r\nContent-Length: 6\r\n\r\n0\r\n\r\n',
        'POST /api HTTP/1.1\r\nHost: api.local\r\nTransfer-Encoding: [\'chunked\']\r\nContent-Length: 12\r\n\r\n0\r\n\r\n',
        ':method: GET\\r\\nX-Injected: yes\r\n:path: /admin\r\n:authority: edge.local\r\n',
        'POST /upload HTTP/1.1\r\nHost: files.local\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nX-Ignore: 1\r\nGET /admin HTTP/1.1\r\nHost: files.local\r\n\r\n',
        'GET /admin HTTP/1.1\r\nHost: app.local\r\nContent-Length: 9\r\n\r\ncmd=pwned',
    ],
    knownBenign: [
        'GET /health HTTP/1.1\r\nHost: app.local\r\n\r\n',
        'POST /api/items HTTP/1.1\r\nHost: app.local\r\nContent-Length: 15\r\nContent-Type: application/json\r\n\r\n{"id":1,"q":2}',
        'POST /chunk HTTP/1.1\r\nHost: app.local\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n',
        ':method: GET\r\n:path: /v1/users\r\n:authority: api.local\r\n',
    ],
    detect: (input: string): boolean => {
        if (input.length < 20) return false
        const d = deepDecode(input)

        if (hasClTeConflict(d)) return true
        if (hasTeClObfuscation(d)) return true
        if (hasHttp2PseudoHeaderCrlf(d)) return true
        if (hasMidBodyChunkTerminator(d)) return true
        if (hasGetAdminTunneling(d)) return true

        return false
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)

        const hasBoth = hasBothClAndTe(d)
        if (hasBoth) {
            return {
                detected: true,
                confidence: 0.93,
                explanation: 'L2 parser found both Content-Length and Transfer-Encoding headers in one request, indicating desync risk',
                evidence: 'content-length + transfer-encoding present',
            }
        }

        if (hasTeClObfuscation(d)) {
            return {
                detected: true,
                confidence: 0.91,
                explanation: 'L2 parser found obfuscated Transfer-Encoding chunked value combined with Content-Length',
                evidence: 'obfuscated transfer-encoding + content-length',
            }
        }

        return null
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'POST / HTTP/1.1\r\nHost: edge.local\r\nContent-Length: 31\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: edge.local\r\n\r\n',
            'POST /pay HTTP/1.1\r\nHost: app.local\r\nTransfer-Encoding: chunked \r\nContent-Length: 4\r\n\r\n0\r\n\r\n',
            ':path: /v1\\r\\nX-Shadow: injected\r\n:method: POST\r\n:authority: api.local\r\n',
            'GET /admin HTTP/1.1\r\nHost: app.local\r\nContent-Length: 5\r\n\r\na=1\r\n',
        ]
        return variants.slice(0, count)
    },
}
