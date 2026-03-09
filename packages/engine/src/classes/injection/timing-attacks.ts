import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { safeRegexMatchAll, safeRegexTest } from './regex-safety.js'

const SECURITY_SENSITIVE_PARAMS = new Set(['action', 'role', 'admin', 'id'])
const LOCK_BYPASS_RE = /\block\s*=\s*bypass\b/i
const CONCURRENCY_BYPASS_RE = /\bconcurrent\s*=\s*true\b/i
const TRANSFER_POST_RE = /POST\s+\/transfer\b/gi
const CONCURRENCY_SIGNAL_RE = /\b(?:parallel|concurrent|simultaneous(?:ly)?|burst|high[-_\s]?frequency|rapid)\b/i
const TRANSFER_ENCODING_CHUNKED_RE = /(?:^|\r?\n)\s*Transfer-Encoding\s*:\s*chunked\b/i
const HEADER_CRLF_INJECTION_RE = /(?:^|\r?\n)\s*[A-Za-z0-9-]+\s*:\s*[^\r\n]*(?:%0d%0a|\\r\\n|%5cr%5cn)\s*[A-Za-z0-9-]+\s*:/i
const STATIC_PATH_RE = /^\/(?:static|assets|images|img|fonts)\//i
const SENSITIVE_PATH_RE = /\/(?:api|account|admin|dashboard|profile|settings|user|auth|my-?account)\//i
const NESTED_QUANTIFIER_RE = /\([^()\\]*[+*](?:[?+])?\)(?:\+|\*|\{\d+(?:,\d*)?\})/
const X_REQUEST_ID_HEADER_RE = /(?:^|\r?\n)\s*X-Request-ID\s*:\s*([^\r\n]+)/gi
const X_IDEMPOTENCY_KEY_HEADER_RE = /(?:^|\r?\n)\s*X-Idempotency-Key\s*:\s*([^\r\n]+)/gi
const VALID_CHUNK_SIZE_RE = /^[0-9a-fA-F]+(?:;[^\r\n]+)?$/
const CONTENT_LENGTH_HEADER_RE = /(?:^|\r?\n)\s*Content-Length\s*:/i
const STATIC_ASSET_EXTENSION_RE = /\.(?:css|js|png|jpg|jpeg|ico)(?:[?#]|%23|\s|$)/i

function findDuplicateHeaderValues(decoded: string, pattern: RegExp): boolean {
    pattern.lastIndex = 0
    const values = new Map<string, number>()
    let match: RegExpExecArray | null

    while ((match = pattern.exec(decoded)) !== null) {
        const normalized = match[1].trim().toLowerCase()
        values.set(normalized, (values.get(normalized) ?? 0) + 1)
        if ((values.get(normalized) ?? 0) >= 2) return true
    }

    return false
}

function extractQueryLike(decoded: string): string {
    const qIdx = decoded.indexOf('?')
    if (qIdx >= 0) return decoded.slice(qIdx + 1)
    return decoded
}

function parseQueryParams(decoded: string): Map<string, { count: number; scalar: boolean; array: boolean; values: Set<string> }> {
    const params = new Map<string, { count: number; scalar: boolean; array: boolean; values: Set<string> }>()
    const query = extractQueryLike(decoded)
    const pairPattern = /(?:^|[?&\s])([A-Za-z0-9_.-]+(?:\[\])?)=([^&#\s]*)/g

    const pairMatches = safeRegexMatchAll(pairPattern, query)
    if (pairMatches === null) return params

    for (const pair of pairMatches) {
        const key = pair[1]
        const rawValue = pair[2]
        const baseKey = key.endsWith('[]') ? key.slice(0, -2) : key
        const entry = params.get(baseKey) ?? { count: 0, scalar: false, array: false, values: new Set<string>() }

        entry.count += 1
        if (key.endsWith('[]')) entry.array = true
        else entry.scalar = true

        try {
            entry.values.add(decodeURIComponent(rawValue))
        } catch {
            entry.values.add(rawValue)
        }

        params.set(baseKey, entry)
    }

    return params
}

function hasInvalidChunkSize(decoded: string): boolean {
    if (!safeRegexTest(TRANSFER_ENCODING_CHUNKED_RE, decoded)) return false

    const headerEndCrlf = decoded.indexOf('\r\n\r\n')
    const headerEndLf = decoded.indexOf('\n\n')
    const bodyStart = headerEndCrlf >= 0 ? headerEndCrlf + 4 : (headerEndLf >= 0 ? headerEndLf + 2 : -1)
    if (bodyStart < 0 || bodyStart >= decoded.length) return false

    const body = decoded.slice(bodyStart)
    const lines = body.split(/\r?\n/).map(l => l.trim()).filter(Boolean)
    if (lines.length === 0) return false

    const candidate = lines[0]
    return !safeRegexTest(VALID_CHUNK_SIZE_RE, candidate)
}

export const raceConditionProbe: InvariantClassModule = {
    id: 'race_condition_probe',
    description: 'Concurrent request race-condition probing via duplicated request identifiers and burst transfer operations',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.86 },
    mitre: ['T1190', 'T1499'],
    cwe: 'CWE-362',
    knownPayloads: [
        'POST /api/pay HTTP/1.1\r\nX-Request-ID: race-123\r\n\r\nPOST /api/pay HTTP/1.1\r\nX-Request-ID: race-123',
        'POST /transfer HTTP/1.1\r\nX-Idempotency-Key: pay-777\r\n\r\nPOST /transfer HTTP/1.1\r\nX-Idempotency-Key: pay-777\r\nX-Retry-Count: 9',
        '/api/lock?lock=bypass&concurrent=true',
    ],
    knownBenign: [
        'POST /transfer HTTP/1.1\r\nX-Idempotency-Key: pay-1',
        'GET /status?lock=normal',
        'POST /api/pay HTTP/1.1\r\nX-Request-ID: req-1',
    ],
    detect: (input: string): boolean => {
        const raw = input
        let d = raw
        try {
            d = deepDecode(input)
        } catch {
            d = raw
        }

        if (safeRegexTest(LOCK_BYPASS_RE, d) && safeRegexTest(CONCURRENCY_BYPASS_RE, d)) return true

        if (findDuplicateHeaderValues(d, X_REQUEST_ID_HEADER_RE)) return true
        if (findDuplicateHeaderValues(d, X_IDEMPOTENCY_KEY_HEADER_RE)) return true

        const transferPosts = safeRegexMatchAll(TRANSFER_POST_RE, d)?.length ?? 0
        const hasConcurrencySignal = safeRegexTest(CONCURRENCY_SIGNAL_RE, d)
        if (transferPosts >= 2 && hasConcurrencySignal) return true

        return false
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'POST /api/pay HTTP/1.1\r\nX-Request-ID: race-123\r\n\r\nPOST /api/pay HTTP/1.1\r\nX-Request-ID: race-123',
            'POST /transfer HTTP/1.1\r\nX-Idempotency-Key: pay-777\r\nX-Mode: parallel\r\n\r\nPOST /transfer HTTP/1.1\r\nX-Idempotency-Key: pay-777',
            '/api/lock?lock=bypass&concurrent=true',
            'POST /transfer HTTP/1.1\r\nX-Idempotency-Key: dup-1\r\nX-Request-Mode: burst\r\n\r\nPOST /transfer HTTP/1.1\r\nX-Idempotency-Key: dup-1',
        ]
        return variants.slice(0, count)
    },
}

export const redosPayload: InvariantClassModule = {
    id: 'redos_payload',
    description: 'Regular-expression DoS payloads including catastrophic backtracking run patterns and nested quantifiers',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.84 },
    mitre: ['T1499'],
    cwe: 'CWE-1333',
    knownPayloads: [
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!',
        'user_regex=(a+)+$',
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbX',
    ],
    knownBenign: [
        'hello world',
        'aaabbbccc',
        'normal text',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)

        for (let i = 0; i < d.length;) {
            let j = i + 1
            while (j < d.length && d[j] === d[i]) j++
            const run = j - i
            if (run >= 30 && j < d.length && d[j] !== d[i]) return true
            i = j
        }

        // Nested quantified groups like (a+)+ or (.+)* in user-supplied regex text.
        if (safeRegexTest(NESTED_QUANTIFIER_RE, d)) return true

        return false
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!',
            'user_regex=(a+)+$',
            '((((a+)+)+)+)$',
            'cccccccccccccccccccccccccccccccccccccccccccccccccc!',
        ]
        return variants.slice(0, count)
    },
}

export const httpDesyncAttack: InvariantClassModule = {
    id: 'http_desync_attack',
    description: 'HTTP desynchronization via header confusion, malformed chunk framing, and CRLF header value injection',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.91 },
    mitre: ['T1557', 'T1190'],
    cwe: 'CWE-444',
    knownPayloads: [
        'POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1',
        'POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\nabc\r\n0\r\n\r\n',
        'GET / HTTP/1.1\r\nHost: victim\r\nX-Api-Name: trusted%0d%0aX-Injected: yes\r\n\r\n',
    ],
    knownBenign: [
        'POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\nhello=world',
        'POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n',
        'GET /home HTTP/1.1\r\nHost: example.com\r\nX-Api-Name: trusted\r\n\r\n',
    ],
    detect: (input: string): boolean => {
        const raw = input
        let d = raw
        try {
            d = deepDecode(input)
        } catch {
            d = raw
        }

        const hasCL = safeRegexTest(CONTENT_LENGTH_HEADER_RE, d)
        const hasTEChunked = safeRegexTest(TRANSFER_ENCODING_CHUNKED_RE, d)
        if (hasCL && hasTEChunked) return true

        if (hasInvalidChunkSize(d)) return true

        // Header value contains injected CRLF in encoded/escaped form (not normal header delimiters).
        if (safeRegexTest(HEADER_CRLF_INJECTION_RE, raw)) return true
        if (safeRegexTest(HEADER_CRLF_INJECTION_RE, d)) return true

        return false
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1',
            'POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\nabc\r\n0\r\n\r\n',
            'GET / HTTP/1.1\r\nHost: victim\r\nX-Api-Name: trusted%0d%0aX-Injected: yes\r\n\r\n',
            'GET / HTTP/1.1\r\nHost: victim\r\nX-Route: one\\r\\nX-Split: two\r\n\r\n',
        ]
        return variants.slice(0, count)
    },
}

export const cacheDeceptionAttack: InvariantClassModule = {
    id: 'cache_deception_attack',
    description: 'Web cache deception on sensitive/authenticated routes masquerading as static assets',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.83 },
    mitre: ['T1539', 'T1557'],
    cwe: 'CWE-525',
    knownPayloads: [
        '/api/user/profile/nonexistent.css',
        '/account/settings/x.jpg',
        '/admin/dashboard/fake.js',
    ],
    knownBenign: [
        '/static/style.css',
        '/images/logo.png',
        '/assets/app.js',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)

        if (safeRegexTest(STATIC_PATH_RE, d)) return false

        if (!safeRegexTest(SENSITIVE_PATH_RE, d)) return false

        return safeRegexTest(STATIC_ASSET_EXTENSION_RE, d)
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            '/api/user/profile/nonexistent.css',
            '/account/settings/x.jpg',
            '/admin/dashboard/fake.js',
            '/api/private/orders/123.png?cache=1',
        ]
        return variants.slice(0, count)
    },
}

export const parameterPollutionAdvanced: InvariantClassModule = {
    id: 'parameter_pollution_advanced',
    description: 'Advanced HTTP parameter pollution with repeated keys, scalar/array ambiguity, and conflicting sensitive values',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.82 },
    mitre: ['T1190'],
    cwe: 'CWE-235',
    knownPayloads: [
        '?id=1&id=2&id[]=3',
        '?user=admin&user=guest&user=ops',
        '?action=view&action=delete',
    ],
    knownBenign: [
        '?page=1&sort=name',
        '?tags[]=a&tags[]=b',
        '?q=normal&lang=en',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const params = parseQueryParams(d)

        for (const [name, detail] of params) {
            if (detail.count >= 3) return true
            if (detail.scalar && detail.array) return true
            if (SECURITY_SENSITIVE_PARAMS.has(name.toLowerCase()) && detail.values.size >= 2) return true
        }

        return false
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            '?id=1&id=2&id[]=3',
            '?user=admin&user=guest&user=ops',
            '?action=view&action=delete',
            '?role=user&role=admin',
        ]
        return variants.slice(0, count)
    },
}

export const TIMING_ATTACK_CLASSES: InvariantClassModule[] = [
    raceConditionProbe,
    redosPayload,
    httpDesyncAttack,
    cacheDeceptionAttack,
    parameterPollutionAdvanced,
]
