/**
 * Open Redirect Evaluator — Level 2 Invariant Detection
 */

export interface OpenRedirectDetection {
    type: 'protocol_relative' | 'backslash' | 'javascript_uri' | 'data_uri' | 'scheme_bypass' | 'host_bypass'
    detail: string
    extractedHost: string
    confidence: number
}


const REDIRECT_PARAM_KEYS = new Set([
    'redirect',
    'url',
    'next',
    'return',
    'goto',
    'to',
    'target',
    'return_to',
    'dest',
    'continue',
    'callback',
    'returnUrl',
])

const REDIRECT_PARAM_RE = /(?:^|[?&])([a-zA-Z][a-zA-Z0-9_-]*)\s*=\s*([^&\s#]*)/g
const EXTERNAL_HOST_RE = /^(?:[a-z0-9.-]+\.)+[a-z]{2,}(?::\d+)?(?:[/?#].*)?$/i
const TRUSTED_HOSTS = new Set([
    'localhost',
    '127.0.0.1',
    '[::1]',
    '::1',
    'localhost.localdomain',
    '::ffff:127.0.0.1',
])

function stripWrappingQuotes(value: string): string {
    return value.replace(/^\s+|\s+$/g, '').replace(/^['"`]+|['"`]+$/g, '')
}

function decodeLayered(value: string, maxIterations = 4): string {
    let current = value

    for (let i = 0; i < maxIterations; i++) {
        const unicodeDecoded = current.replace(/%u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        let next = unicodeDecoded

        try {
            next = decodeURIComponent(unicodeDecoded)
        } catch {
            next = unicodeDecoded.replace(/%([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        }

        if (next === current) return current
        current = next
    }

    return current
}

function dedupeStrings(values: string[]): string[] {
    const seen = new Set<string>()
    const out: string[] = []

    for (const value of values) {
        const normalized = stripWrappingQuotes(value)
        if (!normalized || seen.has(normalized)) continue
        seen.add(normalized)
        out.push(normalized)
    }

    return out
}

function dedupe<T extends { type: string; extractedHost: string; detail: string }>(values: T[]): T[] {
    const seen = new Set<string>()
    const out: T[] = []

    for (const value of values) {
        const key = `${value.type}|${value.extractedHost}|${value.detail}`
        if (seen.has(key)) continue
        seen.add(key)
        out.push(value)
    }

    return out
}

function collectCandidateValues(input: string): string[] {
    const decoded = decodeLayered(input, 3)
    const values = dedupeStrings([input, decoded])

    const addParam = (match: RegExpMatchArray | null) => {
        if (!match) return
        const key = match[1].toLowerCase()
        if (!REDIRECT_PARAM_KEYS.has(key)) return

        const rawValue = stripWrappingQuotes(match[2] ?? '')
        if (!rawValue) return
        values.push(rawValue)
        values.push(decodeLayered(rawValue, 4))
    }

    let m = REDIRECT_PARAM_RE.exec(input)
    while (m !== null) {
        addParam(m)
        m = REDIRECT_PARAM_RE.exec(input)
    }

    m = REDIRECT_PARAM_RE.exec(decoded)
    while (m !== null) {
        addParam(m)
        m = REDIRECT_PARAM_RE.exec(decoded)
    }

    return dedupeStrings(values)
}

function extractHostFromValue(value: string): string | null {
    const trimmed = stripWrappingQuotes(value)
    if (!trimmed) return null

    if (trimmed.startsWith('//')) {
        try {
            return new URL(`https:${trimmed}`).hostname
        } catch {
            return null
        }
    }

    if (/^\\+/.test(trimmed)) {
        const host = trimmed.replace(/^\\+/, '').split(/[\\/?#]/, 2)[0]
        return host || null
    }

    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
        try {
            return new URL(trimmed).hostname
        } catch {
            return null
        }
    }

    const colonBypass = trimmed.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:([^/\\\s][^\s]*)/)
    if (colonBypass) {
        const host = colonBypass[1].split(/[/?#]/, 2)[0]
        if (host) return host
    }

    const authMatch = trimmed.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^@\s]+@([^/?#]+)(?:[/?#]|$)/i)
    if (authMatch) return authMatch[1]

    if (EXTERNAL_HOST_RE.test(trimmed)) {
        return trimmed.replace(/:[0-9]+(?:[/?#].*)?$/, '').split(/[/?#]/, 2)[0]
    }

    return null
}

function isLocalHost(host: string): boolean {
    const lower = host.toLowerCase()
    return TRUSTED_HOSTS.has(lower)
        || lower.startsWith('127.')
        || lower.endsWith('.localhost')
        || lower.endsWith('.local')
}

function isHostBypass(host: string): boolean {
    return !isLocalHost(host)
}

function hasHostConfusion(host: string): boolean {
    const lower = host.toLowerCase()
    return /(^|\.)whitelisted-domain\.evil\.com$/i.test(lower)
        || /(^|\.)evil\.(?:com|net|org|io|co|dev)$/i.test(lower)
        || /trusted\.|allowed\.|auth\./i.test(lower)
}

function encodedSchemeToken(value: string): boolean {
    const lower = value.toLowerCase()
    return /^%(?:68|48)(?:%74){2}%70/.test(lower)
        || /\bhttps?$/.test(lower)
        || /^%?https?$/.test(lower)
}

function detectOpenRedirectSchemeBypassForCandidate(candidate: string): OpenRedirectDetection[] {
    const candidates = dedupeStrings([candidate, decodeLayered(candidate), decodeLayered(candidate, 2)])
    const detections: OpenRedirectDetection[] = []

    for (const value of candidates) {
        const lower = value.toLowerCase()

        if (value.startsWith('//')) {
            detections.push({
                type: 'protocol_relative',
                detail: `Protocol-relative redirect target: ${value}`,
                extractedHost: extractHostFromValue(value) || value,
                confidence: 0.92,
            })
            continue
        }

        if (/^\\+/.test(value)) {
            const host = value.replace(/^\\+/, '').split(/[\\/?#]/, 2)[0]
            detections.push({
                type: 'backslash',
                detail: `Backslash-escaped redirect target: ${value}`,
                extractedHost: host || value,
                confidence: 0.90,
            })
            continue
        }

        if (/^(javascript|vbscript):/i.test(lower)) {
            detections.push({
                type: 'javascript_uri',
                detail: `Script URI redirect payload: ${value}`,
                extractedHost: `${value.split(':', 1)[0]}:`,
                confidence: 0.95,
            })
            continue
        }

        if (/^data:/i.test(lower)) {
            detections.push({
                type: 'data_uri',
                detail: `Data URI redirect payload: ${value}`,
                extractedHost: 'data:',
                confidence: 0.88,
            })
            continue
        }

        if (/^[a-zA-Z][a-zA-Z0-9+.-]*:(?!\/\/).+/.test(value)) {
            const afterScheme = value.split(':', 2)[1] ?? ''
            if (afterScheme.length > 0) {
                detections.push({
                    type: 'scheme_bypass',
                    detail: `Scheme-bypass redirect form: ${value}`,
                    extractedHost: afterScheme.split(/[/?#]/, 2)[0] || afterScheme,
                    confidence: 0.89,
                })
            }
        }

        if (encodedSchemeToken(value)) {
            detections.push({
                type: 'scheme_bypass',
                detail: `Encoded scheme token detected in redirect value: ${value}`,
                extractedHost: extractHostFromValue(value) || value,
                confidence: 0.86,
            })
        }
    }

    return detections
}

function detectOpenRedirectHostBypassForCandidate(candidate: string): OpenRedirectDetection[] {
    const candidates = dedupeStrings([candidate, decodeLayered(candidate)])
    const detections: OpenRedirectDetection[] = []

    for (const value of candidates) {
        const host = extractHostFromValue(value)
        if (!host || !isHostBypass(host)) continue

        const confidence = hasHostConfusion(host) ? 0.94 : 0.83
        detections.push({
            type: 'host_bypass',
            detail: hasHostConfusion(host)
                ? `Redirect host confusion candidate: ${host}`
                : `Redirect to external host: ${host}`,
            extractedHost: host,
            confidence,
        })
    }

    return detections
}

export function detectOpenRedirectSchemeBypass(input: string): OpenRedirectDetection[] {
    const candidates = collectCandidateValues(input)
    return dedupe(candidates.flatMap(detectOpenRedirectSchemeBypassForCandidate))
}

export function detectOpenRedirectHostBypass(input: string): OpenRedirectDetection[] {
    const candidates = collectCandidateValues(input)
    return dedupe(candidates.flatMap(detectOpenRedirectHostBypassForCandidate))
}

export function detectOpenRedirect(input: string): OpenRedirectDetection[] {
    return dedupe([
        ...detectOpenRedirectSchemeBypass(input),
        ...detectOpenRedirectHostBypass(input),
    ])
}
