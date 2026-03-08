/**
 * JWT Abuse Invariant Classes
 *
 * Beyond alg:none — detects structural JWT manipulation:
 *   - jwt_kid_injection: Key ID header injection (SQLi/path traversal in kid)
 *   - jwt_jwk_embedding: Attacker embeds their own JWK in the header
 *   - jwt_confusion: Algorithm confusion (RSA→HMAC key confusion)
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2JwtKidInjection, l2JwtJwkEmbedding, l2JwtConfusion } from '../../evaluators/l2-adapters.js'


// ── Helpers ──────────────────────────────────────────────────────

function extractJwtHeader(input: string): string | null {
    // JWT format: header.payload.signature (base64url encoded)
    const jwtPattern = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/
    const match = input.match(jwtPattern)
    if (!match) return null

    const headerB64 = match[0].split('.')[0]
    try {
        // base64url → base64
        const b64 = headerB64.replace(/-/g, '+').replace(/_/g, '/')
        const pad = b64.length % 4
        const padded = pad === 0 ? b64 : b64 + '='.repeat(4 - pad)
        return Buffer.from(padded, 'base64').toString('utf8')
    } catch {
        return null
    }
}

function looksLikeJwtContext(input: string): boolean {
    return /\beyJ[A-Za-z0-9_-]{10,}\./i.test(input) ||
        /\b(?:jwt|bearer|authorization|token)\b/i.test(input) ||
        /\{"(?:alg|typ|kid|jwk|jku|x5[cu])"/i.test(input)
}


// ── 1) jwt_kid_injection ─────────────────────────────────────────

export const jwtKidInjection: InvariantClassModule = {
    id: 'jwt_kid_injection',
    description: 'JWT Key ID (kid) header injection — SQLi or path traversal via the kid claim to retrieve attacker-controlled signing key',
    category: 'auth',
    severity: 'critical',
    calibration: { baseConfidence: 0.91 },

    mitre: ['T1550.001'],
    cwe: 'CWE-347',

    knownPayloads: [
        '{"alg":"HS256","kid":"../../dev/null"}',
        '{"alg":"HS256","kid":"\' UNION SELECT \'secret\' --"}',
        '{"alg":"HS256","kid":"| cat /etc/passwd"}',
    ],

    knownBenign: [
        '{"alg":"RS256","kid":"2024-key-rotation-01"}',
        '{"alg":"ES256","typ":"JWT","kid":"prod-key-id"}',
        'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.test.test',
    ],

    detectL2: l2JwtKidInjection,

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (!looksLikeJwtContext(d)) return false

        // Check for injection in kid field
        const kidMatch = d.match(/"kid"\s*:\s*"((?:[^"\\]|\\.)*)"/i)
        if (!kidMatch) return false

        const kid = kidMatch[1]

        // Path traversal in kid
        if (/\.\.[\\/]/.test(kid)) return true
        // SQLi in kid
        if (/(?:union\s+select|'\s*(?:or|and)\s+|;\s*(?:drop|select|insert)|--\s*$)/i.test(kid)) return true
        // Command injection in kid
        if (/[|;`$]/.test(kid) && /\b(?:cat|curl|wget|bash|sh|id|whoami)\b/i.test(kid)) return true
        // Null byte
        if (/\\x00|%00|\x00/.test(kid)) return true

        return false
    },

    generateVariants: (count: number): string[] => {
        const v = [
            '{"alg":"HS256","kid":"../../dev/null"}',
            '{"alg":"HS256","kid":"\' UNION SELECT \'secret\' --"}',
            '{"alg":"HS256","kid":"| cat /etc/passwd"}',
        ]
        return v.slice(0, count)
    },
}


// ── 2) jwt_jwk_embedding ────────────────────────────────────────

export const jwtJwkEmbedding: InvariantClassModule = {
    id: 'jwt_jwk_embedding',
    description: 'JWT self-signed key injection — attacker embeds their own JWK or JKU in the token header to forge signatures',
    category: 'auth',
    severity: 'critical',
    calibration: { baseConfidence: 0.93 },

    mitre: ['T1550.001'],
    cwe: 'CWE-347',

    knownPayloads: [
        '{"alg":"RS256","jwk":{"kty":"RSA","n":"0vx7agoebGcQ","e":"AQAB"}}',
        '{"alg":"RS256","jku":"https://evil.example/.well-known/jwks.json"}',
        '{"alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"f83O","y":"x_FE"}}',
    ],

    knownBenign: [
        '{"alg":"RS256","typ":"JWT"}',
        '{"alg":"ES256","kid":"prod-key-01"}',
        '{"keys":[{"kty":"RSA","use":"sig","kid":"1"}]}',
    ],

    detectL2: l2JwtJwkEmbedding,

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (!looksLikeJwtContext(d)) return false

        // JWK embedded directly in header
        if (/"jwk"\s*:\s*\{/.test(d) && /"kty"\s*:\s*"/.test(d)) {
            // Only suspicious if it's in a JWT header context (has alg)
            if (/"alg"\s*:\s*"/.test(d)) return true
        }

        // JKU pointing to external URL
        if (/"jku"\s*:\s*"https?:\/\//.test(d) && /"alg"\s*:\s*"/.test(d)) {
            return true
        }

        // x5u pointing to external URL (X.509 certificate chain)
        if (/"x5u"\s*:\s*"https?:\/\//.test(d) && /"alg"\s*:\s*"/.test(d)) {
            return true
        }

        return false
    },

    generateVariants: (count: number): string[] => {
        const v = [
            '{"alg":"RS256","jwk":{"kty":"RSA","n":"0vx7agoebGcQ","e":"AQAB"}}',
            '{"alg":"RS256","jku":"https://evil.example/.well-known/jwks.json"}',
            '{"alg":"ES256","x5u":"https://evil.example/cert.pem"}',
        ]
        return v.slice(0, count)
    },
}


// ── 3) jwt_confusion ────────────────────────────────────────────

export const jwtConfusion: InvariantClassModule = {
    id: 'jwt_confusion',
    description: 'JWT algorithm confusion — switching from asymmetric (RS/ES/PS) to symmetric (HS) to sign with the public key',
    category: 'auth',
    severity: 'critical',
    calibration: { baseConfidence: 0.88 },

    mitre: ['T1550.001'],
    cwe: 'CWE-327',

    knownPayloads: [
        '{"alg":"HS256","typ":"JWT"} RSA public key as HMAC secret',
        '{"alg":"HS384","typ":"JWT","kid":"rsa-pub-key"}',
        '{"alg":"HS512"} -----BEGIN PUBLIC KEY-----',
    ],

    knownBenign: [
        '{"alg":"HS256","typ":"JWT"}',
        '{"alg":"RS256","typ":"JWT"}',
        '{"alg":"ES256","typ":"JWT"}',
    ],

    detectL2: l2JwtConfusion,

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (!looksLikeJwtContext(d)) return false

        // Look for HMAC algorithm combined with RSA key references
        const hmacAlg = /"alg"\s*:\s*"HS(?:256|384|512)"/i.test(d)
        if (!hmacAlg) return false

        // Indicators of confusion attack:
        // - kid referencing RSA key
        const rsaKid = /"kid"\s*:\s*"[^"]*(?:rsa|public|pub[_-]?key|asymmetric)/i.test(d)
        // - explicit mention of RSA public key being used as HMAC secret
        const rsaAsHmac = /(?:rsa\s+)?public\s+key\s+(?:as|for|used\s+as)\s+(?:hmac|secret|symmetric)/i.test(d)
        // - PEM-format key material in the input alongside HS alg
        const pemKey = /-----BEGIN\s+(?:RSA\s+)?PUBLIC\s+KEY-----/i.test(d)

        return rsaKid || rsaAsHmac || pemKey
    },

    generateVariants: (count: number): string[] => {
        const v = [
            '{"alg":"HS256","typ":"JWT","kid":"rsa-pub-key"}',
            '{"alg":"HS256"} RSA public key as HMAC secret',
            '{"alg":"HS384"} -----BEGIN PUBLIC KEY-----',
        ]
        return v.slice(0, count)
    },
}
