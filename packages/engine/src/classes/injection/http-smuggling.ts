/**
 * HTTP Request Smuggling invariant classes
 *
 * HTTP smuggling exploits disagreements between front-end proxies and
 * back-end servers about where one request ends and another begins.
 *
 * INVARIANT PROPERTY:
 *   ∃ interpretation_1, interpretation_2 ∈ parse(request, HTTP_GRAMMAR) :
 *     boundaries(interpretation_1) ≠ boundaries(interpretation_2)
 *     → different servers see different request boundaries → desync
 *
 * Coverage (mapped to Kettle 2022-2025 research):
 *   - CL.TE desync: Content-Length + Transfer-Encoding disagree
 *   - TE.TE desync: Multiple/obfuscated Transfer-Encoding
 *   - H2 downgrade: HTTP/2 pseudo-header CRLF injection during H2→H1 translation
 *   - 0.CL desync: Content-Length: 0 with non-empty body (Kettle 2025)
 *   - Chunk extension exploits: Malicious chunk extensions (Kettle 2025)
 *   - Expect-based desync: Expect: 100-continue protocol abuse (Kettle 2025)
 *   - Browser-powered desync: Cross-domain connection pool poisoning (Kettle 2022)
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2HttpSmuggling, l2HttpRequestSmuggling } from '../../evaluators/l2-adapters.js'


// ── Shared Utilities ─────────────────────────────────────────────

/**
 * Semantic mutation operators for HTTP smuggling variant generation.
 *
 * WAF-A-MoLE integration: These mutations preserve the semantic meaning
 * (the desync property) while varying the syntactic representation.
 * Every variant generated will trigger a REAL desync on a vulnerable
 * server, not just match a regex pattern.
 */
const WHITESPACE_MUTATIONS: ReadonlyArray<(s: string) => string> = [
    s => s,
    s => s.replace(/\r\n/g, '\n'),                         // bare LF
    s => s.replace(/Transfer-Encoding/g, 'Transfer-encoding'),  // case variation
    s => s.replace(/Transfer-Encoding/g, 'Transfer-Encoding '), // trailing space
]

const CL_TE_TEMPLATES: readonly string[] = [
    'Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1',
    'Transfer-Encoding: chunked\r\nTransfer-Encoding: x',
    'Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST /login',
    'Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n5\r\nPOST\r\n0\r\n\r\n',
    'Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nDELETE /users HTTP/1.1',
    'Transfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n0\r\n\r\nPATCH /api/v1/config HTTP/1.1',
    'Transfer-Encoding:\tchunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\nGET /internal HTTP/1.1',
    'Content-Length: 5\r\n Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /secret HTTP/1.1',
]

const H2_TEMPLATES: readonly string[] = [
    'GET / HTTP/1.1\r\nHost: victim.com\r\n\r\nGET /admin HTTP/1.1\r\nHost: victim.com',
    ':method GET\r\n:path /\r\nTransfer-Encoding: chunked',
    'POST / HTTP/1.1\r\nHost: x\r\n\r\nDELETE /users HTTP/1.1\r\nHost: x',
    ':method POST\r\n:path /api\r\nHost: internal\r\n\r\nGET /admin HTTP/1.1',
    ':authority target.com\r\nfoo: bar\r\nHost: attacker.com',
]
const HTTP_SMUGGLE_CONTENT_LENGTH_HEADER_RE = /Content-Length\s*:/i
const HTTP_SMUGGLE_TRANSFER_ENCODING_HEADER_RE = /Transfer-Encoding\s*:/i
const HTTP_SMUGGLE_CHUNK_EXTENSION_RE = /([0-9a-fA-F]+)\s*;+([^\r\n]+)\r?\n/g
const HTTP_SMUGGLE_CL_ZERO_LINE_RE = /Content-Length:\s*0\s*\r?\n/i
const HTTP_SMUGGLE_EMBEDDED_REQUEST_LINE_RE = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\/[^\s]*)\s+HTTP\/[\d.]+/m
const HTTP_SMUGGLE_CL_ZERO_RE = /Content-Length:\s*0/i
const HTTP_SMUGGLE_CL_ANY_RE = /Content-Length/i
const HTTP_SMUGGLE_TE_ANY_RE = /Transfer-Encoding/i


// ── CL.TE / TE.TE / TE Obfuscation ──────────────────────────────

export const httpSmuggleClTe: InvariantClassModule = {
    id: 'http_smuggle_cl_te',
    description: 'HTTP request smuggling via Content-Length / Transfer-Encoding desync',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.92 },

    formalProperty: `∃ headers ∈ parse(request, HTTP_HEADER_GRAMMAR) :
        ('Content-Length' ∈ keys(headers) ∧ 'Transfer-Encoding' ∈ keys(headers))
        ∨ count(headers, 'Transfer-Encoding') ≥ 2
        ∨ obfuscated('Transfer-Encoding', headers)
        → boundary_disagreement(frontend, backend)`,

    composableWith: ['http_smuggle_h2', 'http_smuggle_chunk_ext', 'http_smuggle_zero_cl'],

    mitre: ['T1190'],
    cwe: 'CWE-444',

    knownPayloads: [
        'Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1',
        'Transfer-Encoding: chunked\r\nTransfer-Encoding: x',
        'Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX',
        'Transfer-Encoding:\tchunked\r\nContent-Length: 0',
        ' Transfer-Encoding: chunked\r\nContent-Length: 5',
        'Transfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n0\r\n\r\nPATCH /api HTTP/1.1',
        'CONTENT-LENGTH: 0\r\nTRANSFER-ENCODING: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1',
        'Content-Length: 0\r\nTransfer-Encoding:\tchunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1',
        'Content-Length: 0\r\nTransfer-Encoding:\r\n chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1',
        'Content-Length: 0\r\nTransfer-Encoding: chunked;boundary=X\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1',
        'POST / HTTP/1.0\r\nHost: target.com\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\nGET /admin HTTP/1.1',
        'POST / HTTP/1.0\r\nHost: target.com\r\nContent-Length: 0\r\nProxy-Connection: keep-alive\r\n\r\nGET /admin HTTP/1.1',
        'Transfer-Encoding: chunked\r\n\r\n0\r\nX-Injected: true\r\nAnother-Header: value\r\n\r\nGET /admin HTTP/1.1',
        'Transfer-Encoding: chunked\r\nTrailer: X-Auth-Token\r\n\r\n5\r\nHello\r\n0\r\nX-Auth-Token: admin-token\r\n\r\nGET /admin HTTP/1.1',
    ],

    knownBenign: [
        'Content-Length: 100',
        'Transfer-Encoding: gzip',
        'normal HTTP request body',
        'GET / HTTP/1.1\r\nHost: example.com',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // Both CL and TE in same payload
        const hasCL = HTTP_SMUGGLE_CONTENT_LENGTH_HEADER_RE.test(d)
        const hasTE = HTTP_SMUGGLE_TRANSFER_ENCODING_HEADER_RE.test(d)
        if (hasCL && hasTE) return true
        // Duplicate TE headers
        const teMatches = d.match(/Transfer-Encoding\s*:/gi)
        if (teMatches && teMatches.length >= 2) return true
        // Obfuscated TE (tab, space, newline in header name area)
        if (/Transfer[\s-]*Encoding\s*:(?:\s|\r?\n\s+)*(?:x?chunked|identity|cHuNkEd|CHUNKED)/i.test(d) && /\r?\n\r?\n.*(?:GET|POST|PUT|DELETE|PATCH)\s+\//i.test(d)) return true
        // TE with extension-like suffix
        if (/Transfer-Encoding\s*:\s*chunked;boundary=/i.test(d)) return true
        // HTTP/1.0 keep-alive CL:0 desync
        if (/HTTP\/1\.0/i.test(d) && /(?:Proxy-)?Connection:\s*keep-alive/i.test(d) && /Content-Length:\s*0/i.test(d) && /(?:GET|POST|PUT|DELETE|PATCH)\s+\//.test(d)) return true
        // Trailer chunk injection
        if (/\r?\n0(?:\s*;+[^\r\n]*)?\r?\n(?:[A-Za-z0-9-]+:[^\r\n]+\r?\n)+\r?\n(?:GET|POST|PUT|DELETE|PATCH)\s+\//i.test(d)) return true
        if (/Trailer:\s*[A-Za-z0-9-]+/i.test(d) && /\r?\n0(?:\s*;+[^\r\n]*)?\r?\n[A-Za-z0-9-]+:[^\r\n]+\r?\n/i.test(d) && /(?:GET|POST|PUT|DELETE|PATCH)\s+\//i.test(d)) return true

        return false
    },
    detectL2: l2HttpSmuggling,
    generateVariants: (count: number): string[] => {
        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            const tpl = CL_TE_TEMPLATES[i % CL_TE_TEMPLATES.length]
            const mutate = WHITESPACE_MUTATIONS[Math.floor(i / CL_TE_TEMPLATES.length) % WHITESPACE_MUTATIONS.length]
            variants.push(mutate(tpl))
        }
        return variants
    },
}


// ── H2 Downgrade Smuggling ──────────────────────────────────────

export const httpSmuggleH2: InvariantClassModule = {
    id: 'http_smuggle_h2',
    description: 'HTTP/2 downgrade smuggling — exploit H2→H1 translation to inject requests',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.90 },

    formalProperty: `∃ pseudoHeader ∈ {':method', ':path', ':authority', ':scheme'} :
        CRLF ∈ value(pseudoHeader)
        → H2_to_H1_translation INJECTS_HEADER(value)
        ∨ count(parse(request, HTTP_REQUEST_LINE_GRAMMAR)) ≥ 2
        → response_queue_desync`,

    composableWith: ['http_smuggle_cl_te', 'http_smuggle_chunk_ext'],

    mitre: ['T1190'],
    cwe: 'CWE-444',

    knownPayloads: [
        'GET / HTTP/1.1\r\nHost: victim.com\r\n\r\nGET /admin HTTP/1.1\r\nHost: victim.com',
        ':method GET\r\n:path /\r\nTransfer-Encoding: chunked',
        ':authority target.com\r\nfoo: bar\r\nHost: evil.com',
        ':path /\\r\\nHost: internal\\r\\n\\r\\nGET /admin HTTP/1.1',
    ],

    knownBenign: [
        'GET / HTTP/1.1',
        'Host: example.com',
        'normal request',
        ':root { color: red }',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // H2 pseudo-headers combined with CL/TE smuggling
        if (/:method\s|:path\s|:authority\s|:scheme\s/i.test(d) && /Transfer-Encoding|Content-Length/i.test(d)) return true
        // Multiple HTTP request lines in a single input (H2 downgrade desync)
        const requestCount = (d.match(/(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+\/[^\s]*\s+HTTP\/\d/gi) || []).length
        if (requestCount >= 2) return true
        // H2 :authority + Host header override — H2→H1 translation injects a Host
        // header disagreement. :authority is an H2 pseudo-header; Host: in the same
        // payload means the attacker is exploiting the translation layer.
        if (/:authority\s/i.test(d) && /\bHost\s*:/i.test(d)) return true
        // CRLF injection in H2 pseudo-header values — attacker encodes \r\n as
        // literal characters to survive WAF text scanning. The backend translator
        // interprets the escaped sequence and injects a header boundary.
        // Matches both actual CRLF (real attack) and the literal 4-char \r\n (evasion).
        if (/:(?:path|method|authority|scheme)\s[^\r\n]*(?:\r\n|\\r\\n)/i.test(d)) return true
        return false
    },
    detectL2: l2HttpSmuggling,
    generateVariants: (count: number): string[] => {
        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            const tpl = H2_TEMPLATES[i % H2_TEMPLATES.length]
            const mutate = WHITESPACE_MUTATIONS[Math.floor(i / H2_TEMPLATES.length) % WHITESPACE_MUTATIONS.length]
            variants.push(mutate(tpl))
        }
        return variants
    },
}


// ── Chunk Extension Exploit (Kettle 2025) ────────────────────────
//
// The property: chunk extensions (RFC 7230 §4.1.1) are allowed after
// the chunk size. Most proxies ignore them. Some backends parse them.
// If a proxy treats `0;ext=val\r\n` as end-of-chunks but the backend
// doesn't, desync occurs. Or vice versa.
//
// This is a NEW class added from Black Hat 2025 research.

export const httpSmuggleChunkExt: InvariantClassModule = {
    id: 'http_smuggle_chunk_ext',
    description: 'HTTP chunk extension exploit — desync via RFC 7230 §4.1.1 chunk extensions',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.88 },

    formalProperty: `∃ chunk ∈ parse(body, CHUNKED_ENCODING_GRAMMAR) :
        chunk.extensions.length > 0
        ∧ (chunk.size = 0 → terminates_message)
        ∧ proxy.interprets(chunk.extensions) ≠ backend.interprets(chunk.extensions)
        → boundary_disagreement`,

    composableWith: ['http_smuggle_cl_te', 'http_smuggle_h2'],

    mitre: ['T1190'],
    cwe: 'CWE-444',

    knownPayloads: [
        '0;ext=bar\r\n\r\nGET /admin HTTP/1.1',
        '0;malicious-extension\r\n\r\n',
        '5;ext=val\r\nhello\r\n0;ext=val\r\n\r\n',
        '0 ;ext=val\r\n\r\n',
        '0;ext=val\r\nX-Injected: true\r\n\r\n',
        '0 ;ext=foo\r\n\r\nGET /admin HTTP/1.1',
        '0;;ext=foo\r\n\r\nGET /admin HTTP/1.1',
        '0;ext="value\r\nX-Injected: true"\r\n\r\nGET /admin HTTP/1.1',
        '00000000000\r\n\r\nGET /admin HTTP/1.1',
        '+0\r\n\r\nGET /admin HTTP/1.1',
        'A;ext=foo\r\n0123456789\r\n0;ext=bar\r\n\r\nGET /admin HTTP/1.1',
    ],

    knownBenign: [
        'Transfer-Encoding: chunked',
        '5\r\nhello\r\n0\r\n\r\n',
        'no chunks here',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        
        // 1. Terminal chunk with extension
        if (/(?:^|\r?\n)[\t ]*0+\s*;+[^\r\n]+\r?\n/.test(d)) return true
        
        // 2. Terminal chunk size obfuscated (multiple zeros or plus prefix)
        if (/(?:^|\r?\n)[\t ]*(?:\+0+|00+)\s*\r?\n/.test(d)) return true

        // 3. Non-terminal chunk with extension
        if (/(?:^|\r?\n)[\t ]*[1-9a-fA-F][0-9a-fA-F]*\s*;+[^\r\n]+\r?\n/.test(d)) {
            // Only flag if there's also a smuggled request or terminator or multiple chunks
            if (/(?:GET|POST|PUT|DELETE|PATCH)\s+\//.test(d) || /(?:^|\r?\n)[\t ]*\+?0+\s*;/.test(d) || /(?:[\t ]*\+?[1-9a-fA-F][0-9a-fA-F]*\s*;+[^\r\n]+\r?\n.*){2,}/s.test(d)) return true
        }
        
        return false
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        // Parse for chunk extension patterns with structural analysis
        let match
        const extensions: Array<{ size: number; ext: string }> = []

        HTTP_SMUGGLE_CHUNK_EXTENSION_RE.lastIndex = 0
        while ((match = HTTP_SMUGGLE_CHUNK_EXTENSION_RE.exec(d)) !== null) {
            extensions.push({
                size: parseInt(match[1], 16),
                ext: match[2].trim(),
            })
        }

        if (extensions.length === 0) return null

        // Terminal chunk with extension = definitive smuggle signal
        const terminalWithExt = extensions.find(e => e.size === 0)
        if (terminalWithExt) {
            return {
                detected: true,
                confidence: 0.94,
                explanation: `Chunk extension on terminating chunk: 0;${terminalWithExt.ext} — creates parsing differential between proxy and backend`,
                evidence: `0;${terminalWithExt.ext}`,
            }
        }

        // Non-terminal chunk with extension and embedded request
        if (extensions.length > 0 && /(?:GET|POST|PUT|DELETE|PATCH)\s+\/[^\s]*\s+HTTP/i.test(d)) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: `Chunk extension with embedded HTTP request — potential desync`,
                evidence: extensions.map(e => `${e.size.toString(16)};${e.ext}`).join(', '),
            }
        }

        return null
    },

    generateVariants: (count: number): string[] => {
        const templates = [
            '0;ext=bar\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal',
            '0;malicious-extension\r\n\r\n',
            '0 ;ext=val\r\n\r\nPOST /api/keys HTTP/1.1',
            '0;ext=val\r\nX-Injected: true\r\n\r\n',
            '5;ext=val\r\nhello\r\n0;ext=val\r\n\r\nGET /admin HTTP/1.1',
            '0;x=\r\n\r\nGET / HTTP/1.1\r\nHost: evil',
        ]
        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            variants.push(templates[i % templates.length])
        }
        return variants
    },
}


// ── Zero Content-Length Desync (Kettle 2025) ─────────────────────
//
// The property: Content-Length: 0 but body is present.
// Some servers honor CL:0 (ignore body). Others read body anyway.
// When chained with connection reuse, creates a desync.

export const httpSmuggleZeroCl: InvariantClassModule = {
    id: 'http_smuggle_zero_cl',
    description: '0.CL desync — Content-Length: 0 with non-empty body exploits connection reuse disagreement',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.90 },

    formalProperty: `∃ request ∈ parse(input, HTTP_GRAMMAR) :
        header(request, 'Content-Length') = '0'
        ∧ body(request).length > 0
        → server_A ignores body (honors CL:0)
        ∧ server_B reads body (connection reuse)
        → desync`,

    composableWith: ['http_smuggle_cl_te', 'http_smuggle_chunk_ext'],

    mitre: ['T1190'],
    cwe: 'CWE-444',

    knownPayloads: [
        'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com',
        'Content-Length: 0\r\n\r\nPOST /api/transfer HTTP/1.1',
        'Content-Length: 0\r\n\r\nDELETE /users/1 HTTP/1.1',
    ],

    knownBenign: [
        'Content-Length: 0\r\n\r\n',
        'Content-Length: 0',
        'POST / HTTP/1.1\r\nContent-Length: 42',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // CL:0 followed by body containing another HTTP request
        if (/Content-Length:\s*0\s*\r?\n/i.test(d)) {
            // Check if there's an HTTP request after the empty body
            const clZeroIdx = d.search(/Content-Length:\s*0/i)
            const afterHeaders = d.indexOf('\r\n\r\n', clZeroIdx)
            if (afterHeaders >= 0) {
                const body = d.substring(afterHeaders + 4)
                if (body.length > 0 && /(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\//.test(body)) {
                    return true
                }
            }
            // Also check \n\n for bare LF
            const afterHeadersLF = d.indexOf('\n\n', clZeroIdx)
            if (afterHeadersLF >= 0) {
                const body = d.substring(afterHeadersLF + 2)
                if (body.length > 0 && /(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\//.test(body)) {
                    return true
                }
            }
        }
        return false
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const clZeroMatch = HTTP_SMUGGLE_CL_ZERO_LINE_RE.exec(d)
        if (!clZeroMatch) return null

        // Find the body boundary
        const searchFrom = clZeroMatch.index
        const headerEnd = d.indexOf('\r\n\r\n', searchFrom)
        const headerEndLF = d.indexOf('\n\n', searchFrom)
        const boundary = headerEnd >= 0 ? headerEnd + 4 : (headerEndLF >= 0 ? headerEndLF + 2 : -1)

        if (boundary < 0) return null
        const body = d.substring(boundary)
        if (body.length === 0) return null

        // Structural check: is there a valid HTTP request line in the body?
        const embeddedRequest = HTTP_SMUGGLE_EMBEDDED_REQUEST_LINE_RE.exec(body)
        if (embeddedRequest) {
            return {
                detected: true,
                confidence: 0.95,
                explanation: `0.CL desync: Content-Length: 0 but body contains embedded ${embeddedRequest[1]} ${embeddedRequest[2]} request. Connection reuse will process this as a separate request on the backend.`,
                evidence: `CL:0 + body: ${embeddedRequest[0]}`,
            }
        }

        // Body exists but no embedded request — could still be a desync probe
        if (body.trim().length > 0) {
            return {
                detected: true,
                confidence: 0.70,
                explanation: `0.CL anomaly: Content-Length: 0 with ${body.length}-byte body — potential desync probe`,
                evidence: `CL:0 + body_length:${body.length}`,
            }
        }

        return null
    },

    generateVariants: (count: number): string[] => {
        const templates = [
            'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com',
            'POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\nPOST /api/transfer HTTP/1.1',
            'GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\nDELETE /users/1 HTTP/1.1',
            'POST / HTTP/1.1\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\nGET /internal/config HTTP/1.1',
        ]
        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            variants.push(templates[i % templates.length])
        }
        return variants
    },
}


// ── Expect-Based Desync (Kettle 2025) ────────────────────────────
//
// The property: Expect: 100-continue triggers CL0 desyncs on many
// servers. The server sends 100 Continue, the client sends body.
// If the proxy doesn't wait for 100 Continue but the backend does,
// the proxy forwards the body as a new request → desync.
//
// This enables response queue poisoning across entire CDNs.

export const httpSmuggleExpect: InvariantClassModule = {
    id: 'http_smuggle_expect',
    description: 'Expect-based desync — Expect: 100-continue protocol abuse for response queue poisoning',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.85 },

    formalProperty: `∃ request ∈ parse(input, HTTP_GRAMMAR) :
        header(request, 'Expect') = '100-continue'
        ∧ body(request) contains HTTP_REQUEST_LINE
        → proxy.forwards_immediately ≠ backend.waits_for_100
        → response_queue_poisoning`,

    composableWith: ['http_smuggle_cl_te', 'http_smuggle_zero_cl'],

    mitre: ['T1190'],
    cwe: 'CWE-444',

    knownPayloads: [
        'POST / HTTP/1.1\r\nHost: target.com\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1',
        'Expect: 100-continue\r\nContent-Length: 50\r\nTransfer-Encoding: chunked',
        'Expect: 100-continue\r\nContent-Length: 0\r\n\r\nGET /internal HTTP/1.1\r\nHost: internal',
    ],

    knownBenign: [
        'Expect: 100-continue',
        'Expect: 100-continue\r\nContent-Length: 1024',
        'normal file upload with Expect header',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (!/Expect:\s*100-continue/i.test(d)) return false
        // Expect header + embedded HTTP request = desync
        const expectIdx = d.search(/Expect:\s*100-continue/i)
        const rest = d.substring(expectIdx)
        if (/(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\/[^\s]*\s+HTTP/i.test(rest)) {
            // Check it's not just the original request line
            const requestLines = (d.match(/(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\/[^\s]*\s+HTTP\/\d/gi) || [])
            if (requestLines.length >= 2) return true
        }
        // Expect + CL:0 is suspicious
        if (/Content-Length:\s*0/i.test(d)) return true
        // Expect + both CL and TE
        if (/Content-Length/i.test(d) && /Transfer-Encoding/i.test(d)) return true
        return false
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        if (!/Expect:\s*100-continue/i.test(d)) return null

        const hasCLZero = HTTP_SMUGGLE_CL_ZERO_RE.test(d)
        const hasCLTE = HTTP_SMUGGLE_CL_ANY_RE.test(d) && HTTP_SMUGGLE_TE_ANY_RE.test(d)
        const embeddedRequests = (d.match(/(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\/[^\s]*\s+HTTP\/[\d.]+/gi) || [])

        if (embeddedRequests.length >= 2) {
            return {
                detected: true,
                confidence: 0.92,
                explanation: `Expect-based desync: Expect: 100-continue with ${embeddedRequests.length} embedded HTTP requests — response queue poisoning`,
                evidence: embeddedRequests.join(' | '),
            }
        }

        if (hasCLZero) {
            return {
                detected: true,
                confidence: 0.85,
                explanation: 'Expect-based CL0 desync: Expect: 100-continue + Content-Length: 0 — proxy/backend disagreement on body handling',
                evidence: 'Expect: 100-continue + CL:0',
            }
        }

        if (hasCLTE) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'Expect header combined with CL/TE ambiguity — compound desync',
                evidence: 'Expect + CL + TE',
            }
        }

        return null
    },

    generateVariants: (count: number): string[] => {
        const templates = [
            'POST / HTTP/1.1\r\nHost: target\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target',
            'POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 50\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
            'POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\nDELETE /api/users HTTP/1.1',
            'POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\nPOST /api/transfer HTTP/1.1\r\nContent-Type: application/json',
        ]
        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            variants.push(templates[i % templates.length])
        }
        return variants
    },
}

export const http_request_smuggling: InvariantClassModule = {
    id: 'http_request_smuggling',
    description: 'HTTP request smuggling via CL.TE, TE.CL, transfer-encoding ambiguity, and invalid chunk framing',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.94 },

    mitre: ['T1190'],
    cwe: 'CWE-444',

    knownPayloads: [
        'POST / HTTP/1.1\r\nHost: victim\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: victim\r\n\r\n',
        'POST / HTTP/1.1\r\nHost: victim\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nPOST /internal HTTP/1.1\r\nHost: victim\r\n\r\n',
        'POST / HTTP/1.1\r\nHost: victim\r\nTransfer-Encoding: chunked, gzip\r\nContent-Length: 12\r\n\r\nz\r\ninvalid\r\n0\r\n\r\n',
        'POST / HTTP/1.1\r\nHost: victim\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nbody\r\n0\r\n\r\n',
    ],

    knownBenign: [
        'POST /upload HTTP/1.1\r\nHost: victim\r\nContent-Length: 10\r\n\r\n0123456789',
        'POST /upload HTTP/1.1\r\nHost: victim\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n',
        'GET /health HTTP/1.1\r\nHost: victim\r\nConnection: keep-alive\r\n\r\n',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const hasCL = /\bcontent-length\s*:\s*\d+/i.test(d)
        const teMatch = d.match(/\btransfer-encoding\s*:\s*([^\r\n]+)/i)
        const hasTE = Boolean(teMatch)
        const teValue = teMatch?.[1]?.toLowerCase() ?? ''
        const hasChunked = /\bchunked\b/.test(teValue)

        const clte = hasCL && hasTE && hasChunked
        const tecl = /transfer-encoding\s*:[^\r\n]*\r?\n[^\r\n]*content-length\s*:/i.test(d) && hasChunked
        const chunkedGzipCombo = /\btransfer-encoding\s*:\s*[^\r\n]*chunked[^\r\n]*gzip/i.test(d) || (hasChunked && /\bcontent-encoding\s*:\s*gzip\b/i.test(d))
        const invalidChunkSize = /\r?\n(?:ZZ|GG|INVALID|NOTHEX|0x[0-9a-f]+)\r?\n/i.test(d) && hasChunked

        return clte || tecl || chunkedGzipCombo || invalidChunkSize
    },

    detectL2: l2HttpRequestSmuggling,

    generateVariants: (count: number): string[] => {
        const variants = [
            'POST / HTTP/1.1\r\nHost: victim\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: victim\r\n\r\n',
            'POST / HTTP/1.1\r\nHost: victim\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nPOST /internal HTTP/1.1\r\nHost: victim\r\n\r\n',
            'POST / HTTP/1.1\r\nHost: victim\r\nTransfer-Encoding: chunked, gzip\r\nContent-Length: 11\r\n\r\n0\r\n\r\n',
            'POST / HTTP/1.1\r\nHost: victim\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nAAAA\r\n0\r\n\r\n',
            'POST / HTTP/1.1\r\nHost: victim\r\nTransfer-Encoding:\tchunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\nGET /x HTTP/1.1',
            'POST / HTTP/1.1\r\nHost: victim\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nContent-Length: 8\r\n\r\n1\r\na\r\n0\r\n\r\n',
        ]
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}
