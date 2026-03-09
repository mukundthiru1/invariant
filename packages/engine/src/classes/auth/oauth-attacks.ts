import type { InvariantClass, InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

const REDIRECT_URI_PATTERN = /(?:^|[?&\s])redirect_uri=([^&\s]+)/gi
const STATE_PATTERN = /(?:^|[?&\s])state=([^&\s]*)/gi

function safeDecode(value: string): string {
    try {
        return decodeURIComponent(value)
    } catch {
        return value
    }
}

function extractParamValues(input: string, pattern: RegExp): string[] {
    const values: string[] = []
    pattern.lastIndex = 0

    let match: RegExpExecArray | null
    while ((match = pattern.exec(input)) !== null) {
        values.push(safeDecode(match[1]))
    }

    return values
}

function isSequentialNumber(value: string): boolean {
    if (!/^\d+$/.test(value) || value.length < 2) return false

    let ascending = true
    let descending = true
    for (let i = 1; i < value.length; i++) {
        const prev = Number(value[i - 1])
        const curr = Number(value[i])
        if (curr !== prev + 1) ascending = false
        if (curr !== prev - 1) descending = false
    }

    return ascending || descending
}

export const oauthRedirectManipulation: InvariantClassModule = {
    id: 'oauth_redirect_manipulation' as InvariantClass,
    description: 'OAuth redirect_uri manipulation toward attacker-controlled or unsafe redirect targets',
    category: 'auth',
    severity: 'critical',
    calibration: { baseConfidence: 0.95 },
    mitre: ['T1190'],

    knownPayloads: [
        'redirect_uri=https://evil.com',
        'redirect_uri=https://trusted.com/../evil',
        '?redirect_uri=https://evil.example.com/oauth',
    ],

    knownBenign: [
        'redirect_uri=https://app.example.com/callback',
        'redirect_uri=/oauth/callback',
        'state=xyz&code=abc',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const redirectUris = extractParamValues(d, REDIRECT_URI_PATTERN)
        if (redirectUris.length === 0) return false

        return redirectUris.some((uriRaw) => {
            const uri = safeDecode(uriRaw.trim())
            if (!uri) return false

            if (/(?:[?&](?:next|url|target|dest|destination|redirect)=)/i.test(uri)) return true
            if (/(?:\/|%2f)\.\.(?:\/|\\\\|%2f|%5c)/i.test(uri) || /\/\.\.\//.test(uri)) return true
            if (/^\/\//.test(uri)) return true

            if (/^https?:\/\//i.test(uri)) {
                try {
                    const host = new URL(uri).hostname.toLowerCase()
                    if (host === 'localhost' || host === '127.0.0.1') return false
                    // Path traversal in redirect URI host or path
                    if (/\.\.|%2e%2e/i.test(uri)) return true
                    // Open redirect indicators: suspicious TLDs or IP addresses used as redirect targets
                    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) return true
                    // Hosts with common attacker keywords
                    if (/(?:evil|attacker|burp|ngrok|c2|exfil|steal|hook)/i.test(host)) return true
                    // URL contains another URL (open redirect chaining)
                    if (/https?:\/\//i.test(uri.replace(/^https?:\/\/[^/]+/, ''))) return true
                    // Bare domain with no recognised path — only flag if no path (bare root redirects are suspicious)
                    const { pathname } = new URL(uri)
                    return pathname === '/' && !uri.includes('callback') && !uri.includes('oauth') && !uri.includes('auth') && !uri.includes('return') && !uri.includes('redirect')
                } catch {
                    return true
                }
            }

            return false
        })
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            'redirect_uri=https://evil.com',
            'redirect_uri=https://trusted.com/../evil',
            '?redirect_uri=https://evil.example.com/oauth',
            'redirect_uri=//attacker.example.com/callback',
        ]
        return Array.from({ length: count }, (_, i) => variants[i % variants.length])
    },
}

export const oauthStateBypass: InvariantClassModule = {
    id: 'oauth_state_bypass' as InvariantClass,
    description: 'OAuth state parameter bypass via missing, empty, or predictable state values',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.92 },
    mitre: ['T1190'],

    knownPayloads: [
        'code=auth_code_here',
        'code=abc123&state=',
        '?code=xyz&state=1',
    ],

    knownBenign: [
        'code=abc&state=cryptorandomstring64chars',
        'state=8f7d6c5b4a3e2f1d0c9b8a7e6d5c4f3e',
        'error=access_denied&state=random123',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const hasCode = /(?:^|[?&\s])code=[^&\s]+/i.test(d)
        const states = extractParamValues(d, STATE_PATTERN).map((s) => s.trim())

        if (hasCode && states.length === 0) return true

        for (const state of states) {
            if (state.length === 0) return true
            if (hasCode && state.length < 8) return true
            if (/^\d+$/.test(state) && (state.length <= 6 || isSequentialNumber(state))) return true
            // Flag clearly non-random states: dictionary words ONLY (not words embedded in long entropy strings)
            if (hasCode && state.length < 20 && /^(?:null|undefined|none|empty|skip|bypass|csrf|xsrf|test|example|sample|static|fixed)$/i.test(state)) return true
        }

        return false
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            'code=auth_code_here',
            'code=abc123&state=',
            '?code=xyz&state=1',
            'code=abc&state=12',
        ]
        return Array.from({ length: count }, (_, i) => variants[i % variants.length])
    },
}

export const pkceDowngrade: InvariantClassModule = {
    id: 'pkce_downgrade',
    description: 'PKCE downgrade or bypass where code challenge/verifier protections are weak or missing',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.93 },

    knownPayloads: [
        'response_type=code&client_id=app',
        'code_challenge_method=plain&code_challenge=abc',
        'grant_type=authorization_code&code=xyz&redirect_uri=https://app.com',
    ],

    knownBenign: [
        'code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256',
        'response_type=code&code_challenge_method=S256&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        'grant_type=authorization_code&code=xyz&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&redirect_uri=https://app.com',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        if (/(?:^|[?&\s])code_challenge_method=plain(?:[&\s]|$)/i.test(d)) return true

        const isAuthCodeRequest = /(?:^|[?&\s])response_type=code(?:[&\s]|$)/i.test(d)
        const hasCodeChallenge = /(?:^|[?&\s])code_challenge=[^&\s]+/i.test(d)
        if (isAuthCodeRequest && !hasCodeChallenge) return true

        const isTokenExchange = /(?:^|[?&\s])grant_type=authorization_code(?:[&\s]|$)/i.test(d)
            && /(?:^|[?&\s])code=[^&\s]+/i.test(d)
        const hasCodeVerifier = /(?:^|[?&\s])code_verifier=[^&\s]+/i.test(d)
        if (isTokenExchange && !hasCodeVerifier) return true

        return false
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            'response_type=code&client_id=app',
            'code_challenge_method=plain&code_challenge=abc',
            'grant_type=authorization_code&code=xyz&redirect_uri=https://app.com',
            'grant_type=authorization_code&code=xyz&redirect_uri=https://evil.com',
        ]
        return Array.from({ length: count }, (_, i) => variants[i % variants.length])
    },
}
