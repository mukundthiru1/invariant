/**
 * HTTP Request Smuggling invariant classes
 *
 * HTTP smuggling exploits disagreements between front-end proxies and
 * back-end servers about where one request ends and another begins.
 * Two major variants: CL-TE desync and H2 downgrade smuggling.
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

export const httpSmuggleClTe: InvariantClassModule = {
    id: 'http_smuggle_cl_te',
    description: 'HTTP request smuggling via Content-Length / Transfer-Encoding desync',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.92 },

    mitre: ['T1190'],
    cwe: 'CWE-444',

    knownPayloads: [
        'Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1',
        'Transfer-Encoding: chunked\r\nTransfer-Encoding: x',
        'Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX',
    ],

    knownBenign: [
        'Content-Length: 100',
        'Transfer-Encoding: gzip',
        'normal HTTP request body',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // Both CL and TE in same payload
        const hasCL = /Content-Length\s*:/i.test(d)
        const hasTE = /Transfer-Encoding\s*:/i.test(d)
        if (hasCL && hasTE) return true
        // Duplicate TE headers
        const teMatches = d.match(/Transfer-Encoding\s*:/gi)
        if (teMatches && teMatches.length >= 2) return true
        // Obfuscated TE (tab, space, newline in header name)
        if (/Transfer[\s-]*Encoding\s*:\s*chunked/i.test(d) && /\r?\n\r?\n.*(?:GET|POST|PUT|DELETE|PATCH)\s+\//i.test(d)) return true
        return false
    },
    generateVariants: (count: number): string[] => {
        const v = [
            'Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1',
            'Transfer-Encoding: chunked\r\nTransfer-Encoding: x',
            'Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST /login',
            'Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n5\r\nPOST\r\n0\r\n\r\n',
        ]
        return v.slice(0, count)
    },
}

export const httpSmuggleH2: InvariantClassModule = {
    id: 'http_smuggle_h2',
    description: 'HTTP/2 downgrade smuggling — exploit H2→H1 translation to inject requests',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.90 },

    mitre: ['T1190'],
    cwe: 'CWE-444',

    knownPayloads: [
        'GET / HTTP/1.1\r\nHost: victim.com\r\n\r\nGET /admin HTTP/1.1\r\nHost: victim.com',
        ':method GET\r\n:path /\r\nTransfer-Encoding: chunked',
    ],

    knownBenign: [
        'GET / HTTP/1.1',
        'Host: example.com',
        'normal request',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // H2 pseudo-headers in raw input suggest smuggling attempt
        if (/:method\s|:path\s|:authority\s/i.test(d) && /Transfer-Encoding|Content-Length/i.test(d)) return true
        // Multiple HTTP request lines in a single input
        const requestCount = (d.match(/(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+\/[^\s]*\s+HTTP\/\d/gi) || []).length
        if (requestCount >= 2) return true
        return false
    },
    generateVariants: (count: number): string[] => {
        const v = [
            'GET / HTTP/1.1\r\nHost: x\r\n\r\nGET /admin HTTP/1.1\r\nHost: x',
            ':method GET\r\n:path /\r\nTransfer-Encoding: chunked\r\n0\r\n\r\nPOST /admin',
            'POST / HTTP/1.1\r\nHost: x\r\n\r\nDELETE /users HTTP/1.1\r\nHost: x',
        ]
        return v.slice(0, count)
    },
}
