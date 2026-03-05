/**
 * CORS origin abuse — Detecting manipulation of Origin headers and
 * misconfiguration exploitation patterns.
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

export const corsOriginAbuse: InvariantClassModule = {
    id: 'cors_origin_abuse',
    description: 'CORS origin abuse — crafted Origin headers to steal data cross-origin from misconfigured APIs',
    category: 'auth',
    severity: 'medium',
    calibration: { baseConfidence: 0.75 },

    mitre: ['T1557'],
    cwe: 'CWE-346',

    knownPayloads: [
        'Origin: https://evil.com',
        'Origin: null',
        'Origin: https://target.com.evil.com',
        'Origin: https://target.com%60.evil.com',
    ],

    knownBenign: [
        'Origin: https://example.com',
        'origin story',
        'the origin of species',
        'https://api.internal.com',
    ],

    // This is primarily a header-level check — input-level detection
    // catches Origin header values embedded in request bodies (e.g., CSRF probing)
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // Origin header with null value (classical CORS bypass)
        if (/Origin\s*:\s*null/i.test(d)) return true
        // Origin header with suspicious subdomain patterns (target.com.evil.com)
        if (/Origin\s*:\s*https?:\/\/[^.\s]+\.[^.\s]+\.[^.\s]+\.[^.\s]+/i.test(d)) return true
        // Encoded characters in Origin (backtick bypass, underscore bypass)
        if (/Origin\s*:.*(?:%60|%00|%0[dD]|%0[aA])/i.test(d)) return true
        return false
    },
    generateVariants: (count: number): string[] => {
        const v = [
            'Origin: null',
            'Origin: https://target.com.evil.com',
            'Origin: https://target.com%60.evil.com',
            'Origin: https://evil.com',
        ]
        return v.slice(0, count)
    },
}
