import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

interface ParsedJwtToken {
    raw: string
    headerB64: string
    payloadB64: string
    signature: string
}

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

function extractJwtTokens(input: string): ParsedJwtToken[] {
    const tokens: ParsedJwtToken[] = []
    const seen = new Set<string>()
    const decoded = deepDecode(input)

    const jwtPattern = /\b(?:Bearer\s+)?(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9._-]*)/gi
    let match: RegExpExecArray | null
    while ((match = jwtPattern.exec(decoded)) !== null) {
        const raw = match[1]
        if (seen.has(raw)) continue
        const parts = raw.split('.')
        if (parts.length !== 3) continue

        tokens.push({
            raw,
            headerB64: parts[0],
            payloadB64: parts[1],
            signature: parts[2],
        })
        seen.add(raw)
    }

    const queryPattern = /[?&](?:token|jwt|auth)=([^&\s]+)/gi
    while ((match = queryPattern.exec(decoded)) !== null) {
        const value = decodeURIComponent(match[1])
        if (seen.has(value)) continue
        const parts = value.split('.')
        if (parts.length !== 3 || !parts[0].startsWith('eyJ')) continue

        tokens.push({
            raw: value,
            headerB64: parts[0],
            payloadB64: parts[1],
            signature: parts[2],
        })
        seen.add(value)
    }

    return tokens
}

function extractJwtLikeHeaders(input: string): Record<string, unknown>[] {
    const headers: Record<string, unknown>[] = []
    const decoded = deepDecode(input)

    for (const token of extractJwtTokens(decoded)) {
        const parsed = decodeBase64Url(token.headerB64)
        if (!parsed) continue
        try {
            const obj = JSON.parse(parsed)
            if (typeof obj === 'object' && obj !== null) {
                headers.push(obj as Record<string, unknown>)
            }
        } catch {
            continue
        }
    }

    const headerPattern = /\{\s*"(?:alg|kid|jwk|jku|typ)"[\s\S]{0,600}?\}/g
    let headerMatch: RegExpExecArray | null
    while ((headerMatch = headerPattern.exec(decoded)) !== null) {
        try {
            const obj = JSON.parse(headerMatch[0])
            if (typeof obj === 'object' && obj !== null) {
                headers.push(obj as Record<string, unknown>)
            }
        } catch {
            continue
        }
    }

    const standaloneHeaderPattern = /\b(eyJ[A-Za-z0-9_-]{16,})\b/g
    let standaloneMatch: RegExpExecArray | null
    while ((standaloneMatch = standaloneHeaderPattern.exec(decoded)) !== null) {
        const parsed = decodeBase64Url(standaloneMatch[1])
        if (!parsed || !/^\s*\{/.test(parsed)) continue
        try {
            const obj = JSON.parse(parsed)
            if (typeof obj === 'object' && obj !== null) {
                headers.push(obj as Record<string, unknown>)
            }
        } catch {
            continue
        }
    }

    return headers
}

function isKidSuspicious(kid: string): boolean {
    if (/\.\.[\\/]/.test(kid)) return true
    if (/(?:'\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?|union\s+select|select\s+.+--|--\s*$)/i.test(kid)) return true
    if (/^\s*\|[^\s]+\b/i.test(kid)) return true
    if (/[$][(][^)]+[)]/.test(kid)) return true
    if (/\bhttps?:\/\//i.test(kid) || /^\s*\/\//.test(kid)) return true
    return false
}

function isWeakSignature(signature: string): boolean {
    if (!signature) return true
    if (signature.length < 16) return true
    if (/^(?:invalid|test|debug|none|null)$/i.test(signature)) return true
    if (/^(?:secret|password|admin|123456|qwerty)[A-Za-z0-9_-]*$/i.test(signature)) return true
    if (/^(?:[A-Za-z0-9_-])\1{7,}$/.test(signature)) return true
    return false
}

export const jwtKidInjection: InvariantClassModule = {
    id: 'jwt_kid_injection',
    description: 'JWT kid header injection (SQL/path/URL) can force key lookup against attacker-controlled resources',
    category: 'auth',
    severity: 'critical',
    calibration: { baseConfidence: 0.92 },
    mitre: ['T1550.001'],
    cwe: 'CWE-20',

    knownPayloads: [
        'eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uL2Rldi9udWxsIn0...',
        'kid=../../../dev/null',
        'kid=1 UNION SELECT password FROM users--',
        '{"alg":"HS256","kid":"http://evil.com/key"}',
    ],

    knownBenign: [
        '{"alg":"RS256","kid":"prod-2026-rot-01"}',
        'kid=rotation_key_2026_q1',
        'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456ghi789',
    ],

    detect: (input: string): boolean => {
        const decoded = deepDecode(input)

        for (const header of extractJwtLikeHeaders(decoded)) {
            const kidValue = header.kid
            if (typeof kidValue === 'string' && isKidSuspicious(kidValue)) {
                return true
            }
        }

        const rawKid = decoded.match(/\bkid\s*(?:=|:)\s*['"]?([^'"\r\n&]+)['"]?/i)
        if (!rawKid) return false

        return isKidSuspicious(rawKid[1])
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            'kid=../../../dev/null',
            'kid=1 UNION SELECT password FROM users--',
            '{"alg":"HS256","kid":"http://evil.com/key"}',
            '{"alg":"HS256","kid":"\' OR 1=1--"}',
        ]
        return Array.from({ length: count }, (_, i) => variants[i % variants.length])
    },
}

export const jwtJwkEmbedding: InvariantClassModule = {
    id: 'jwt_jwk_embedding',
    description: 'JWT header includes embedded JWK/JKU and can trust attacker-supplied signing keys',
    category: 'auth',
    severity: 'critical',
    calibration: { baseConfidence: 0.93 },
    mitre: ['T1550.001'],
    cwe: 'CWE-347',

    knownPayloads: [
        'eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiYXR0YWNrZXIiLCJlIjoiQVFBQiJ9fQ...',
        '{"alg":"RS256","jwk":{"kty":"RSA","n":"attacker","e":"AQAB"}}',
        '{"alg":"RS256","jku":"https://evil.com/key"}',
        '{"alg":"ES256","jku":"http://evil.com/jwks.json"}',
    ],

    knownBenign: [
        '{"alg":"RS256","kid":"main-key"}',
        '{"keys":[{"kty":"RSA","kid":"1"}]}',
        'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.zHh5eHh4eXl5eXh4',
    ],

    detect: (input: string): boolean => {
        const decoded = deepDecode(input)

        for (const header of extractJwtLikeHeaders(decoded)) {
            const hasAlg = typeof header.alg === 'string'
            if (!hasAlg) continue

            if (header.jwk && typeof header.jwk === 'object') return true
            if (typeof header.jku === 'string' && /^(?:https?:)?\/\//i.test(header.jku)) return true
        }

        if (/"alg"\s*:\s*"(?:RS|ES|PS)\d+"[\s\S]{0,160}"jwk"\s*:\s*\{/i.test(decoded)) return true
        if (/\bjku\s*(?:=|:)\s*['"]?(?:https?:)?\/\//i.test(decoded)) return true

        return false
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            '{"alg":"RS256","jwk":{"kty":"RSA","n":"attacker","e":"AQAB"}}',
            '{"alg":"RS256","jku":"https://evil.com/key"}',
            '{"alg":"ES256","jku":"http://evil.com/jwks.json"}',
            '{"alg":"RS256","x5u":"https://evil.com/cert.pem"}',
        ]
        return Array.from({ length: count }, (_, i) => variants[i % variants.length])
    },
}

export const jwtWeakSecret: InvariantClassModule = {
    id: 'jwt_weak_secret',
    description: 'JWT with HS* algorithm and weak/invalid signature material suggests brute-forceable or forged tokens',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1552.004'],
    cwe: 'CWE-321',

    knownPayloads: [
        '?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.invalid',
        'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
        '?jwt=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.secret123',
        '?auth=eyJhbGciOiJIUzM4NCJ9.eyJ1c2VyIjoidGVzdCJ9.1234567890',
    ],

    knownBenign: [
        'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.fj3K9n3rXy9eZ3Q2m4Y8k1aC0pQ9vT6x',
        '?token=abc123&next=/home',
        'jwt.sign(payload, process.env.JWT_SECRET, { algorithm: "HS256" })',
    ],

    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        const queryJwt = /[?&](?:token|jwt|auth)=eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9._-]*/i.test(decoded)

        for (const token of extractJwtTokens(decoded)) {
            const decodedHeader = decodeBase64Url(token.headerB64)
            if (!decodedHeader) continue

            let header: Record<string, unknown>
            try {
                const parsed = JSON.parse(decodedHeader)
                if (typeof parsed !== 'object' || parsed === null) continue
                header = parsed as Record<string, unknown>
            } catch {
                continue
            }

            const alg = String(header.alg ?? '').toUpperCase()
            if (!/^HS(?:256|384|512)$/.test(alg)) continue

            if (queryJwt) return true
            if (isWeakSignature(token.signature)) return true
        }

        const standaloneHeader = decoded.match(/\b(?:Authorization\s*:\s*)?(eyJ[A-Za-z0-9_-]{16,})\b/i)
        if (!standaloneHeader) return false

        const parsed = decodeBase64Url(standaloneHeader[1])
        if (!parsed) return false
        return /"alg"\s*:\s*"HS(?:256|384|512)"/i.test(parsed)
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            '?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.invalid',
            '?jwt=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.secret123',
            '?auth=eyJhbGciOiJIUzM4NCJ9.eyJ1c2VyIjoidGVzdCJ9.1234567890',
            'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
        ]
        return Array.from({ length: count }, (_, i) => variants[i % variants.length])
    },
}
