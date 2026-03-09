/**
 * web-cache-deception — targeted cache deception checks for sensitive endpoints
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { safeRegexMatchAll, safeRegexTest } from './regex-safety.js'

const SENSITIVE_STATIC_PATH_RE =
    /(?:^|[\s'"\t])(?:\/account|\/dashboard|\/admin|\/user|\/profile|\/settings|\/api\/user|\/api)\/[^\s'"?#]*\.(?:css|js|png|jpg|jpeg|gif|svg|ico|map|webp)(?:[?#][^\s'"#?]*)?/i

const CACHE_CONTROL_HEADER_RE = /(?:^|\r?\n)\s*Cache-Control\s*:\s*[^\r\n]*/gi
const VARY_HEADER_RE = /(?:^|\r?\n)\s*Vary\s*:\s*([^\r\n]*)/gi
const X_CACHE_KEY_RE = /(?:^|\r?\n)\s*X-Cache-Key\s*:\s*[^\r\n]*/i

const hasCacheControlNoStoreBypass = (decoded: string): boolean => {
    const matches = safeRegexMatchAll(CACHE_CONTROL_HEADER_RE, decoded) ?? []
    for (const match of matches) {
        const rawHeader = match[0]?.toLowerCase() ?? ''
        if (!/\bmax-age\s*=\s*\d+/.test(rawHeader)) continue
        if (/\bno-store\b/.test(rawHeader)) continue
        if (/\bno-cache\b/.test(rawHeader)) continue
        return true
    }

    return false
}

const hasVaryHeaderWithoutAccept = (decoded: string): boolean => {
    const matches = safeRegexMatchAll(VARY_HEADER_RE, decoded) ?? []
    for (const match of matches) {
        const value = (match[1] ?? '').toLowerCase().trim()
        if (!value) continue
        if (!/\baccept\b/.test(value)) return true
    }

    return false
}

export const webCacheDeception: InvariantClassModule = {
    id: 'web_cache_deception',
    description: 'Web cache deception via extension-masked sensitive routes and cache-key manipulation',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.87 },

    mitre: ['T1557'],
    cwe: 'CWE-524',

    knownPayloads: [
        '/api/user/profile.css',
        '/account/settings.jpg?cb=1',
        '/dashboard/profile.png',
        '/user/data.gif?v=2',
        '/admin/config.js',
        'Cache-Control: max-age=3600',
    ],

    knownBenign: [
        '/static/app.css',
        '/assets/logo.png',
        'Cache-Control: no-store, no-cache',
        '/api/data',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        const hasDynamicStaticPath = safeRegexTest(SENSITIVE_STATIC_PATH_RE, d)
        const hasCacheControlBypass = hasCacheControlNoStoreBypass(d)
        const hasVaryManipulation = hasVaryHeaderWithoutAccept(d)
        const hasCacheKeyInjection = safeRegexTest(X_CACHE_KEY_RE, d)

        return hasDynamicStaticPath || hasCacheControlBypass || hasVaryManipulation || hasCacheKeyInjection
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            '/api/user/profile.css',
            '/account/settings.jpg?cb=1',
            '/dashboard/profile.png',
            '/user/data.gif?v=2',
            '/admin/config.js',
            'Cache-Control: max-age=3600',
        ]

        return variants.slice(0, count)
    },
}
