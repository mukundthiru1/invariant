/**
 * Cache Attack Evaluator — Level 2 Invariant Detection
 *
 * Structural analysis of cache poisoning and deception attacks:
 *   - cache_poisoning:  Parse HTTP headers, identify unkeyed headers with injection payloads
 *   - cache_deception:  Analyze URL structure for static extension appended to dynamic paths
 *
 * Goes beyond regex by:
 *   - Parsing multi-line headers and validating header names against known unkeyed sets
 *   - Analyzing URL path segments to detect dynamic→static extension confusion
 *   - Checking for combined header manipulation (multiple unkeyed headers = higher confidence)
 */


// ── Result Type ──────────────────────────────────────────────────

export interface CacheDetection {
    type: 'cache_poisoning' | 'cache_deception'
    detail: string
    confidence: number
}


// ── Cache Poisoning Analysis ─────────────────────────────────────

const UNKEYED_HEADERS = new Set([
    'x-forwarded-host',
    'x-forwarded-scheme',
    'x-forwarded-proto',
    'x-forwarded-prefix',
    'x-original-url',
    'x-rewrite-url',
    'x-host',
    'x-forwarded-server',
    'x-http-method-override',
    'x-method-override',
])

const POISON_INDICATORS = [
    /<script/i,
    /javascript:/i,
    /on(?:error|load|click|mouse)\s*=/i,
    /evil\.|attacker\.|malicious\./i,
    /nothttps?/i,
    /\/admin/i,
    /\balert\s*\(/i,
    /\bdocument\./i,
]

function analyzeCachePoisoning(input: string): CacheDetection | null {
    // Parse header lines
    const lines = input.split(/\r?\n/)
    const unkeyedFound: string[] = []
    const payloadLines: string[] = []

    for (const line of lines) {
        const headerMatch = line.match(/^\s*([A-Za-z0-9-]+)\s*:\s*(.*)$/)
        if (!headerMatch) continue

        const headerName = headerMatch[1].toLowerCase()
        const headerValue = headerMatch[2].trim()

        if (UNKEYED_HEADERS.has(headerName)) {
            unkeyedFound.push(headerName)

            // Check if the value contains injection payloads
            for (const indicator of POISON_INDICATORS) {
                if (indicator.test(headerValue)) {
                    payloadLines.push(`${headerName}: ${headerValue.slice(0, 60)}`)
                    break
                }
            }

            // Domain override (any domain that isn't clearly internal)
            if (/^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$/i.test(headerValue)) {
                payloadLines.push(`${headerName} domain override: ${headerValue}`)
            }
        }
    }

    if (unkeyedFound.length === 0 || payloadLines.length === 0) return null

    return {
        type: 'cache_poisoning',
        detail: `Unkeyed header manipulation: ${payloadLines.join('; ')}`,
        confidence: unkeyedFound.length >= 2 ? 0.94 : 0.87,
    }
}


// ── Cache Deception Analysis ─────────────────────────────────────

const DYNAMIC_PATH_SEGMENTS = new Set([
    'api', 'account', 'user', 'profile', 'settings', 'admin',
    'dashboard', 'my-account', 'myaccount', 'me', 'session',
    'auth', 'login', 'private', 'internal',
])

const STATIC_EXTENSIONS = new Set([
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map',
    '.json', '.xml', '.pdf', '.txt', '.html', '.htm',
])

function analyzeCacheDeception(input: string): CacheDetection | null {
    // Extract URL path from input
    const pathMatch = input.match(/(?:^|\s)(\/[^\s?#]+)/m)
    if (!pathMatch) return null

    const path = pathMatch[1]
    const segments = path.split('/').filter(Boolean)

    if (segments.length < 2) return null

    // Check if early segments are dynamic
    const hasDynamic = segments.some(s => DYNAMIC_PATH_SEGMENTS.has(s.toLowerCase()))
    if (!hasDynamic) return null

    // Check if the path ends with a static extension
    const lastSegment = segments[segments.length - 1]
    const extMatch = lastSegment.match(/(\.[a-z0-9]+)(?:%23|#|\?|$)/i)
    if (!extMatch) return null

    const ext = extMatch[1].toLowerCase()
    if (!STATIC_EXTENSIONS.has(ext)) return null

    // Higher confidence if path traversal is combined
    const hasTraversal = /(?:\.\.|%2[eE]%2[eE])/.test(path)
    // Higher confidence if URL fragment/hash trick is used
    const hasHashTrick = /%23|#/.test(lastSegment)

    const signals: string[] = [`dynamic path + ${ext} extension`]
    if (hasTraversal) signals.push('path traversal')
    if (hasHashTrick) signals.push('fragment bypass')

    return {
        type: 'cache_deception',
        detail: `Cache deception: ${signals.join(' + ')} in "${path.slice(0, 80)}"`,
        confidence: hasTraversal || hasHashTrick ? 0.92 : 0.85,
    }
}


// ── Public API ───────────────────────────────────────────────────

export function detectCacheAttack(input: string): CacheDetection[] {
    const detections: CacheDetection[] = []

    if (input.length < 10) return detections

    try {
        const poison = analyzeCachePoisoning(input)
        if (poison) detections.push(poison)
    } catch { /* safe */ }

    try {
        const deception = analyzeCacheDeception(input)
        if (deception) detections.push(deception)
    } catch { /* safe */ }

    return detections
}
