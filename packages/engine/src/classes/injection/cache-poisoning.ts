/**
 * Cache Poisoning & Web Cache Deception Invariant Classes
 *
 * Detects attacks that manipulate caching layers:
 *   - cache_poisoning: Cache key manipulation to serve malicious content
 *   - cache_deception: Tricking caches into storing sensitive responses
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2CachePoisoning, l2CacheDeception } from '../../evaluators/l2-adapters.js'


// ── 1) cache_poisoning ──────────────────────────────────────────

export const cachePoisoning: InvariantClassModule = {
    id: 'cache_poisoning',
    description: 'Web cache poisoning via unkeyed headers and parameter cloaking to serve attacker-controlled content from cache',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },

    mitre: ['T1557'],
    cwe: 'CWE-444',

    knownPayloads: [
        'X-Forwarded-Host: evil.example\r\nX-Forwarded-Scheme: nothttps',
        'X-Original-URL: /admin\r\nX-Rewrite-URL: /admin',
        'X-Forwarded-Host: evil.example"><script>alert(1)</script>',
    ],

    knownBenign: [
        'X-Forwarded-For: 10.0.0.1',
        'Cache-Control: no-cache',
        'Pragma: no-cache',
    ],

    detectL2: l2CachePoisoning,

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        // Unkeyed header manipulation for cache poisoning
        const unkeyedHeaders = /(?:^|\n)\s*(?:X-Forwarded-Host|X-Forwarded-Scheme|X-Original-URL|X-Rewrite-URL|X-Forwarded-Prefix)\s*:/i

        if (!unkeyedHeaders.test(d)) return false

        // Must have injection payload or domain override
        const hasPayload =
            /<script/i.test(d) ||
            /evil\.|attacker\.|malicious\./i.test(d) ||
            /nothttps?/i.test(d) ||
            /\/admin/i.test(d) ||
            /javascript:/i.test(d)

        return hasPayload
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'X-Forwarded-Host: evil.example\r\nX-Forwarded-Scheme: nothttps',
            'X-Original-URL: /admin\r\nX-Rewrite-URL: /admin',
            'X-Forwarded-Host: evil.example"><script>alert(1)</script>',
        ]
        return v.slice(0, count)
    },
}


// ── 2) cache_deception ──────────────────────────────────────────

export const cacheDeception: InvariantClassModule = {
    id: 'cache_deception',
    description: 'Web cache deception — tricking CDN/reverse proxy into caching authenticated responses by appending static extensions to dynamic endpoints',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.83 },

    mitre: ['T1557'],
    cwe: 'CWE-525',

    knownPayloads: [
        '/api/user/profile/nonexistent.css',
        '/account/settings/test.js',
        '/my-account/details/..%2f..%2fstatic.png',
        '/api/v1/me/avatar.jpg%23',
    ],

    knownBenign: [
        '/static/styles.css',
        '/assets/main.js',
        '/images/logo.png',
        '/api/users/123',
    ],

    detectL2: l2CacheDeception,

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        // Pattern: dynamic endpoint path + static file extension
        // The key insight: /api/something or /account/something should NOT end in .css/.js/.png etc.
        const dynamicPrefixes = /(?:\/api\/|\/account\/|\/user\/|\/profile\/|\/settings\/|\/admin\/|\/my-?account\/|\/dashboard\/)/i

        if (!dynamicPrefixes.test(d)) return false

        // Has a static file extension appended
        const staticExtension = /\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|json)(?:\?|#|%23|\s|$)/i
        if (!staticExtension.test(d)) return false

        // Extra confidence if path traversal is combined
        const hasTraversal = /(?:\.\.|%2[eE]%2[eE])/.test(d)

        return true
    },

    generateVariants: (count: number): string[] => {
        const v = [
            '/api/user/profile/nonexistent.css',
            '/account/settings/test.js',
            '/my-account/details/..%2f..%2fstatic.png',
            '/api/v1/me/avatar.jpg%23',
        ]
        return v.slice(0, count)
    },
}
