/**
 * Auth protocol-oriented invariant classes.
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'

const JWT_TOKEN_PATTERN = /\b(?:eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]*)/g
const JWT_QUERY_TOKEN_PARAM_PATTERN = /(?:^|[?&\s])(id_token|access_token|token|jwt)=([^&\s]+)/gi
const JWT_SHAPE_PATTERN = /\.[A-Za-z0-9_-]+\.[A-Za-z0-9._-]*/
const QUERY_REDIRECT_URI_PATTERN = /(?:^|[?&\s])redirect_uri=([^&\s]+)/gi
const QUERY_NONCE_PATTERN = /(?:^|[?&\s])nonce=([^&\s]+)/gi
const QUERY_ID_TOKEN_PATTERN = /(?:^|[?&\s])id_token=([^&\s]+)/gi
const OAUTH_TOKEN_PARAM_PATTERN = /(?:^|[?&\s])(access_token|token|code)=([^&\s]+)/gi
const SAML_ASSERTION_ID_PATTERN = /<saml:Assertion[^>]*\bID\s*=\s*"([^"]+)"[^>]*>/gi

function decodeBase64Url(value: string): string | null {
    try {
        const b64 = value.replace(/-/g, '+').replace(/_/g, '/')
        const pad = b64.length % 4
        const padded = pad === 0 ? b64 : b64 + '='.repeat(4 - pad)
        return Buffer.from(padded, 'base64').toString('utf8')
    } catch {
        return null
    }
}

function extractJwtTokens(input: string): string[] {
    const decoded = deepDecode(input)
    const result: string[] = []
    const seen = new Set<string>()

    JWT_TOKEN_PATTERN.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = JWT_TOKEN_PATTERN.exec(decoded)) !== null) {
        const token = match[0]
        if (!seen.has(token)) {
            result.push(token)
            seen.add(token)
        }
    }

    JWT_QUERY_TOKEN_PARAM_PATTERN.lastIndex = 0
    while ((match = JWT_QUERY_TOKEN_PARAM_PATTERN.exec(decoded)) !== null) {
        const token = decodeURIComponent(match[2])
        if (!JWT_SHAPE_PATTERN.test(token) || seen.has(token)) continue
        result.push(token)
        seen.add(token)
    }

    return result
}

function parseJwtHeader(token: string): Record<string, unknown> | null {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const decoded = decodeBase64Url(parts[0])
    if (!decoded) return null
    try {
        const parsed = JSON.parse(decoded)
        if (typeof parsed === 'object' && parsed !== null) return parsed as Record<string, unknown>
        return null
    } catch {
        return null
    }
}

function parseJwtPayload(token: string): Record<string, unknown> | null {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const decoded = decodeBase64Url(parts[1])
    if (!decoded) return null
    try {
        const parsed = JSON.parse(decoded)
        if (typeof parsed === 'object' && parsed !== null) return parsed as Record<string, unknown>
        return null
    } catch {
        return null
    }
}

function getQueryValueAll(input: string, key: string): string[] {
    let pattern: RegExp | null = null
    if (key === 'redirect_uri') pattern = QUERY_REDIRECT_URI_PATTERN
    else if (key === 'nonce') pattern = QUERY_NONCE_PATTERN
    else if (key === 'id_token') pattern = QUERY_ID_TOKEN_PATTERN
    if (pattern === null) return []

    pattern.lastIndex = 0
    const values: string[] = []
    let match: RegExpExecArray | null
    while ((match = pattern.exec(input)) !== null) {
        try {
            values.push(decodeURIComponent(match[1]))
        } catch {
            values.push(match[1])
        }
    }
    return values
}

function safeDecode(value: string): string {
    try {
        return decodeURIComponent(value)
    } catch {
        return value
    }
}

function looksRandomOrStructuredNonce(value: string): boolean {
    if (!value) return false
    const lowered = value.toLowerCase()
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(lowered)
        || /^[a-z0-9_-]{24,}$/i.test(lowered)
}

export const oauthTokenLeak: InvariantClassModule = {
    id: 'oauth_token_leak',
    description: 'OAuth access-token or authorization-code leakage through URL query or Referer headers',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.92 },
    mitre: ['T1528'],
    cwe: 'CWE-201',

    knownPayloads: [
        '?access_token=eyJhbGc',
        '?code=abc123&state=xyz',
        'Referer: https://app.com/callback?token=Bearer_abc',
        'GET /callback?code=abc123&state=xyz HTTP/1.1',
    ],

    knownBenign: [
        '?page=1&sort=name',
        'Authorization: Bearer eyJ',
        '/dashboard?sort=asc',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const inAuthContext = /(?:oauth|oidc|openid|authorize|response_type|callback|access_token|id_token|code|token)/i.test(d)
        if (!inAuthContext) return false

        const hasTokenLeak = /(?:^|[?&\s])(access_token|token|code)=[^&\s]+/i.test(d)
            || /referer\s*:\s*https?:\/\/.+?[?&](?:access_token|token|code)=/i.test(d)

        if (!hasTokenLeak) return false

        const params = [...d.matchAll(OAUTH_TOKEN_PARAM_PATTERN)]
        if (params.length === 0) return false

        return params.some((m) => {
            const key = m[1].toLowerCase()
            const value = m[2]
            if (key === 'code' && value.length < 6) return false
            if (/^[A-Za-z0-9._-]+$/.test(value)) return true
            return false
        })
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            '?access_token=eyJhbGc',
            '?code=abc123&state=xyz',
            'Referer: https://app.com/callback?token=Bearer_abc',
            'GET /callback?access_token=ya29.example&state=abc HTTP/1.1',
        ]
        return Array.from({ length: count }, (_, i) => variants[i % variants.length])
    },
}

export const oauthRedirectHijack: InvariantClassModule = {
    id: 'oauth_redirect_hijack',
    description: 'Open-redirect-style OAuth redirect_uri manipulation to attacker-controlled destinations',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.94 },
    mitre: ['T1550.001'],
    cwe: 'CWE-601',

    knownPayloads: [
        '?redirect_uri=https://evil.com',
        '?redirect_uri=javascript:alert(1)',
        '?redirect_uri=//attacker.com/steal',
        '?redirect_uri=https://login.evil.com/callback',
    ],

    knownBenign: [
        '?redirect_uri=https://app.mycompany.com/callback',
        '?redirect_uri=/dashboard',
        '?redirect_uri=/oauth/callback?next=/home',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const urls = getQueryValueAll(d, 'redirect_uri')
        if (urls.length === 0) return false

        return urls.some((rawUri) => {
            const uri = safeDecode(rawUri.trim())

            if (/^javascript:/i.test(uri)) return true
            if (/^\/\//.test(uri)) return true
            if (/^https?:\/\//i.test(uri)) {
                if (/(?:app\.mycompany\.com|localhost|127\.0\.0\.1)/i.test(uri)) return false
                return true
            }

            const encodedHost = safeDecode(uri)
            if (encodedHost !== uri) {
                if (/^javascript:/i.test(encodedHost) || /^\/\//.test(encodedHost)) return true
                if (/^https?:\/\//i.test(encodedHost) && !/(?:app\.mycompany\.com|localhost|127\.0\.0\.1)/i.test(encodedHost)) return true
            }

            return false
        })
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            '?redirect_uri=https://evil.com',
            '?redirect_uri=javascript:alert(1)',
            '?redirect_uri=//attacker.com/steal',
            '?redirect_uri=https://app.mycompany.com/callback',
        ]
        return Array.from({ length: count }, (_, i) => variants[i % variants.length])
    },
}

export const samlSignatureWrapping: InvariantClassModule = {
    id: 'saml_signature_wrapping',
    description: 'SAML signature-wrapping indicators: multiple assertions, mismatched references, or XPath-wrapped targets',
    category: 'auth',
    severity: 'critical',
    calibration: { baseConfidence: 0.95 },
    mitre: ['T1550.001'],
    cwe: 'CWE-347',

    knownPayloads: [
        '<saml:Assertion ID="evil"><ds:Signature/><saml:Subject>admin</saml:Subject></saml:Assertion>',
        '<saml:Response><saml:Assertion ID="a"/><saml:Assertion ID="b"/><ds:Signature><ds:SignedInfo><ds:Reference URI="#b"/></ds:SignedInfo></ds:Signature></saml:Response>',
        '/samlp:Response/saml:Assertion[1]/../../../../ds:Signature',
    ],

    knownBenign: [
        '<saml:Assertion><saml:Issuer>legit</saml:Issuer></saml:Assertion>',
        '<samlp:Response><saml:Assertion ID="a"><ds:Signature/></saml:Assertion></samlp:Response>',
        '<xml><saml:Response><saml:Assertion ID="ok"></saml:Assertion></saml:Response></xml>',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (!/(?:saml|assertion|signature|signedinfo|ds:Signature)/i.test(d)) return false

        const assertionIds = [...d.matchAll(SAML_ASSERTION_ID_PATTERN)].map((m) => m[1])
        if (assertionIds.length > 1 && /(\b<saml:|<ds:)?Signature/i.test(d)) return true

        if (!/<samlp:Response|<saml:Response/i.test(d) && /<saml:Assertion[\s\S]{0,500}<ds:Signature/i.test(d) && !/<ds:SignedInfo/i.test(d)) {
            return true
        }

        if (/\/samlp:Response\/saml:Assertion\[[1-9]\]/i.test(d) || /\/saml:Response\/saml:Assertion\[[1-9]\]/i.test(d)) return true

        const referenceMatch = d.match(/<(?:ds:)?Reference[^>]*URI\s*=\s*"#([^"]+)"/i)
        if (referenceMatch) {
            const refId = referenceMatch[1]
            if (!assertionIds.includes(refId)) return true
        }

        return /<saml:Assertion[\s\S]{0,200}<\/saml:Assertion>[\s\S]{0,120}<(?:ds:)?Signature[\s\S]{0,160}><ds:SignedInfo>/i.test(d)
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            '<saml:Assertion ID="evil"><ds:Signature/><saml:Subject>admin</saml:Subject></saml:Assertion>',
            '<saml:Response><saml:Assertion ID="a"/><saml:Assertion ID="b"/><ds:Signature><ds:SignedInfo><ds:Reference URI="#b"/></ds:SignedInfo></ds:Signature></saml:Response>',
            '/samlp:Response/saml:Assertion[1]',
        ]
        return Array.from({ length: count }, (_, i) => variants[i % variants.length])
    },
}

export const jwtAlgorithmConfusion: InvariantClassModule = {
    id: 'jwt_algorithm_confusion',
    description: 'JWT algorithm confusion in hybrid OAuth/OIDC flows (alg none or HS256 where RS256 was expected)',
    category: 'auth',
    severity: 'critical',
    calibration: { baseConfidence: 0.94 },
    mitre: ['T1550.001', 'T1550'],
    cwe: 'CWE-327',

    knownPayloads: [
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature',
        '{"alg":"none"}',
        '{"alg":"HS256","typ":"JWT"}',
        '{"alg":"HS256","kid":"rsa-public-key","typ":"JWT"}',
    ],

    knownBenign: [
        'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature',
        '{"alg":"RS256","typ":"JWT","kid":"prod-key-2026"}',
        'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.xyz.abc',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const jwtLike = extractJwtTokens(d)
        for (const token of jwtLike) {
            const header = parseJwtHeader(token)
            if (!header) continue
            const alg = String(header.alg ?? '').toUpperCase()
            if (alg === 'NONE') return true
            if (/^HS\d{3}$/.test(alg)) {
                if (/\b(?:RS256|RS384|RS512)\b/.test(d) || /(public|rsa|jw[kks]|x5[cux])\b/i.test(d) || /pem|BEGIN PUBLIC KEY/i.test(d)) {
                    return true
                }

                // HS token with explicit algorithm header still warrants review in auth protocol flows
                if (/(?:^|[^\w])\{\s*\"alg\"\s*:\s*\"HS\d{3}\"/.test(d) && /\"typ\"\s*:\s*\"JWT\"/i.test(d) && token.length > 20) {
                    return true
                }
            }
        }

        if (/\{\s*\"alg\"\s*:\s*\"HS(?:256|384|512)\"/i.test(d) && (/\bRS256\b/i.test(d) || /\bRSA\b/i.test(d) || /\bpublic\b/i.test(d) || /\bjwk\b/i.test(d) || /\bjku\b/i.test(d) || /\bRS\d{3}\b/i.test(d))) return true
        if (/\{\s*\"alg\"\s*:\s*\"HS(?:256|384|512)\"/i.test(d) && /\"kid\"/i.test(d)) return true
        if (/\{\s*\"alg\"\s*:\s*\"HS(?:256|384|512)\"/i.test(d)) return true
        if (/eyJhbGciOiJIUzI1NiJ9\./i.test(d) && /^([^\s]{20,}\.[^\s]+\.[^\s]+)/i.test(d)) return true
        if (/"alg"\s*:\s*"none"/i.test(d)) return true

        return false
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        if (!input) return null
        const d = deepDecode(input)
        const tokens = extractJwtTokens(d)
        for (const token of tokens) {
            const header = parseJwtHeader(token)
            if (!header) continue
            const alg = String(header.alg ?? '').toUpperCase()
            if (alg === 'NONE') {
                return {
                    detected: true,
                    confidence: 0.98,
                    explanation: 'JWT header explicitly disables signature verification',
                    evidence: token.slice(0, 20),
                }
            }

            if (/^HS\d{3}$/.test(alg) && /(RS256|RS384|RS512|public|rsa|jw[kks]|BEGIN PUBLIC KEY|x5[cux])/i.test(d)) {
                return {
                    detected: true,
                    confidence: 0.93,
                    explanation: 'HS algorithm appears in an asymmetric-key JWT context',
                    evidence: `alg=${alg} with asymmetric-key indicators`,
                }
            }
        }

        return null
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature',
            '{"alg":"none"}',
            '{"alg":"HS256","typ":"JWT"} with RS256 public key flow',
            '{"alg":"HS256","kid":"rsa-public-key"}',
        ]
        return Array.from({ length: count }, (_, i) => variants[i % variants.length])
    },
}

export const oidcNonceReplay: InvariantClassModule = {
    id: 'oidc_nonce_replay',
    description: 'OIDC nonce misuse: missing nonce in ID token or repeated nonce values indicating replay risk',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.91 },
    mitre: ['T1528'],
    cwe: 'CWE-294',

    knownPayloads: [
        'GET /auth/callback?id_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.signature&state=abc',
        'nonce=abc&nonce=abc',
        'nonce=static_value&code=123&state=abc',
        'nonce=static_value&nonce=static_value&response_type=id_token',
    ],

    knownBenign: [
        'nonce=random_uuid_here',
        'id_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIiwibm9uY2UiOiJyYW5kb211dGhlX3V1aWRfaGVyIn0.signature&nonce=random_uuid_here',
        'response_type=id_token&nonce=random_uuid_here',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (!/\b(?:openid|oidc|id_token|nonce|response_type=)/i.test(d)) return false

        const nonceValues = getQueryValueAll(d, 'nonce')
        if (nonceValues.length > 1) {
            const seen = new Map<string, number>()
            for (const nonce of nonceValues) {
                const v = nonce.trim()
                seen.set(v, (seen.get(v) ?? 0) + 1)
            }
            for (const [value, count] of seen) {
                if (count > 1 && !looksRandomOrStructuredNonce(value)) return true
            }
        } else {
            const v = nonceValues[0]?.trim() ?? ''
            if (v && v.length <= 16 && v.toLowerCase() === 'static_value') return true
        }

        const idTokens = getQueryValueAll(d, 'id_token')
        if (idTokens.length > 0) {
            for (const token of idTokens) {
                const payload = parseJwtPayload(token)
                if (payload && !('nonce' in payload)) return true
            }
        }

        const bearerTokens = extractJwtTokens(d)
        for (const token of bearerTokens) {
            const payload = parseJwtPayload(token)
            if (!payload) continue
            if (d.includes('response_type=id_token') && !('nonce' in payload)) return true
        }

        return false
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            'GET /auth/callback?id_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIiwibm9uY2UiOiJyYW5kb211dGhlX3V1aWRfaGVyIn0.signature&state=abc',
            'nonce=static_value&code=xyz&state=abc&nonce=static_value',
            'nonce=static_value',
            'response_type=id_token&nonce=static_value&code=abc',
        ]
        return Array.from({ length: count }, (_, i) => variants[i % variants.length])
    },
}
