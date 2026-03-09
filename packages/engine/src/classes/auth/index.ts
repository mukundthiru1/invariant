/**
 * Auth Bypass Invariant Classes
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { jwtKidInjection, jwtJwkEmbedding, jwtWeakSecret, jwtClaimConfusion } from './jwt-attacks.js'
import { jwtConfusion } from './jwt-abuse.js'
import { oauthRedirectManipulation, oauthStateBypass, pkceDowngrade } from './oauth-attacks.js'
import { oauthRedirectHijack, oauthTokenLeak, jwtAlgorithmConfusion, oidcNonceReplay, samlSignatureWrapping } from './protocol-attacks.js'

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

function findJwtToken(input: string): string | null {
    const decoded = deepDecode(input)
    const jwtMatch = decoded.match(/\b(?:Bearer\s+)?(eyJ[A-Za-z0-9_\-+\/=]{8,}\.[A-Za-z0-9_\-+\/=]{8,}\.[A-Za-z0-9_\-+\/=]*)/i)
    return jwtMatch?.[1] ?? null
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

function looksLikeJwtContext(input: string): boolean {
    return /\b(?:jwt|bearer|authorization|token|claim)\b/i.test(input) ||
        /\beyJ[A-Za-z0-9_\-+\/=]{8,}\.[A-Za-z0-9_\-+\/=]{8,}\.[A-Za-z0-9_\-+\/=]*/.test(input)
}

export const authNoneAlgorithm: InvariantClassModule = {
    id: 'auth_none_algorithm',
    description: 'JWT alg:none attack to bypass signature verification entirely',
    category: 'auth',
    severity: 'critical',
    calibration: { baseConfidence: 0.95 },

    mitre: ['T1550.001'],
    cwe: 'CWE-347',

    knownPayloads: [
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.',
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ.',
        // C-010: Whitespace-padded "none" bypass (many JWT libraries trim)
        'eyJhbGciOiIgbm9uZSAiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJhZG1pbiJ9.',
        // C-010: Tab/newline padding
        'eyJhbGciOiJcdG5vbmVcbiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.',
    ],

    knownBenign: [
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
        'not.a.jwt.token',
        'hello world',
    ],

    detect: (input: string): boolean => {
        const token = findJwtToken(input)
        if (!token) return false
        const header = parseJwtHeader(token)
        if (!header) return false
        // C-010: Trim whitespace/control chars — many JWT libraries normalize the alg field
        // so {"alg":" none "} (with spaces) is treated as alg=none at the library level.
        return /^none$/i.test(String(header.alg ?? '').trim())
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const token = findJwtToken(input)
        if (!token) return null
        const header = parseJwtHeader(token)
        if (!header) return null
        if (/^none$/i.test(String(header.alg ?? '').trim())) {
            return {
                detected: true,
                confidence: 0.97,
                explanation: 'JWT algorithm set to none',
                evidence: String(header.alg),
            }
        }
        return null
    },
    generateVariants: (count: number): string[] => {
        const v = [
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const authHeaderSpoof: InvariantClassModule = {
    id: 'auth_header_spoof',
    description: 'Spoof proxy/forwarding headers to bypass IP-based access controls',
    category: 'auth',
    severity: 'medium',
    calibration: { baseConfidence: 0.80 },

    mitre: ['T1090'],
    cwe: 'CWE-290',

    knownPayloads: [
        'X-Forwarded-For: 127.0.0.1',
        'X-Original-URL: /admin',
        'X-Rewrite-URL: /admin',
        'X-Custom-IP-Authorization: 127.0.0.1',
        'X-Real-IP: 127.0.0.1',
        'X-Client-IP: 10.0.0.1',
    ],

    knownBenign: [
        'normal header value',
        '192.168.1.1',
        '/api/users',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const i = d.toLowerCase()
        if (i.includes('x-forwarded-for:') || i.includes('x-original-url:') || i.includes('x-rewrite-url:')) return true
        if (i.includes('x-real-ip:') || i.includes('x-client-ip:') || i.includes('x-cluster-client-ip:')) return true
        if (/x-[a-z-]*(?:ip|authorization)[a-z-]*:\s*(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|localhost)/i.test(d)) return true
        return false
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        try {
            const lowerInput = deepDecode(input).toLowerCase()
            const forwardedMatches = lowerInput.match(/x-forwarded-[a-z-]+:/g) || []
            if (forwardedMatches.length >= 3) {
                return { detected: true, confidence: 0.82, explanation: 'Multiple X-Forwarded headers detected, likely spoofing attempt' }
            }
            if (lowerInput.includes('x-original-url:') || lowerInput.includes('x-rewrite-url:')) {
                return { detected: true, confidence: 0.87, explanation: 'URL rewrite header spoofing detected' }
            }
            return null
        } catch { return null }
    },
    generateVariants: (count: number): string[] => {
        const v = [
            'X-Forwarded-For: 127.0.0.1', 'X-Original-URL: /admin',
            'X-Rewrite-URL: /admin', 'X-Custom-IP-Authorization: 127.0.0.1',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const jwtWeakHmacSecret: InvariantClassModule = {
    id: 'jwt_weak_hmac_secret',
    description: 'JWT weak HMAC secret detection — hardcoded trivial keys like secret/password/123456 enable token forgery',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.90 },

    mitre: ['T1550.001'],
    cwe: 'CWE-798',

    knownPayloads: [
        'jwt.sign(payload, "secret", { algorithm: "HS256" })',
        'Authorization: Bearer token using HS256 with HMAC secret=123456',
        '{"alg":"HS512","typ":"JWT"} signed with password as key',
    ],

    knownBenign: [
        'jwt.sign(payload, process.env.JWT_SECRET, { algorithm: "HS256", expiresIn: "1h" })',
        '{"alg":"RS256","typ":"JWT"}',
        'HMAC key loaded from KMS and rotated daily',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const hasJwtHmacContext = /\b(?:jwt\.sign|jsonwebtoken\.sign|hmac|hs(?:256|384|512)|bearer|token)\b/i.test(d)
        if (!hasJwtHmacContext) return false

        if (/jwt\.sign\s*\([^)]*,\s*["'](?:secret|password|123456|qwerty|letmein|changeme|admin|test|default)["']/i.test(d)) {
            return true
        }

        if (/(?:hmac(?:[_-]?secret)?|secret|key)\s*[:=]\s*["']?(?:secret|password|123456|qwerty|letmein|changeme|admin|test|default)["']?/i.test(d)) {
            return true
        }

        return /signed\s+with\s+(?:password|secret|123456)\s+as\s+key/i.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        if (!/\b(?:jwt|hmac|hs(?:256|384|512)|token)\b/i.test(d)) return null

        const weakMatch = d.match(/(?:hmac(?:[_-]?secret)?|secret|key)\s*[:=]\s*["']?([A-Za-z0-9!@#$%^&*._-]{3,32})["']?/i)
        if (weakMatch && /^(?:secret|password|123456|qwerty|letmein|changeme|admin|test|default)$/i.test(weakMatch[1])) {
            return {
                detected: true,
                confidence: 0.94,
                explanation: 'JWT HMAC secret appears weak or default',
                evidence: weakMatch[0],
            }
        }

        const hardcoded = d.match(/jwt\.sign\s*\([^)]*,\s*["'](secret|password|123456|qwerty|letmein|changeme|admin|test|default)["']/i)
        if (hardcoded) {
            return {
                detected: true,
                confidence: 0.95,
                explanation: 'JWT signing uses a hardcoded weak secret',
                evidence: hardcoded[0],
            }
        }

        return null
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'jwt.sign(payload, "secret", { algorithm: "HS256" })',
            'Authorization: Bearer token using HS256 with HMAC secret=123456',
            '{"alg":"HS512","typ":"JWT"} signed with password as key',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const jwtMissingExpiry: InvariantClassModule = {
    id: 'jwt_missing_expiry',
    description: 'JWT replay risk — token has no exp claim or signing code omits token expiry controls',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.86 },

    mitre: ['T1550.001'],
    cwe: 'CWE-613',

    knownPayloads: [
        'jwt.sign({ sub: "123", role: "user", iat: 1710000000 }, secret, { algorithm: "HS256" })',
        '{"sub":"123","role":"user","iat":1710000000} // JWT payload with no exp',
        'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJpYXQiOjE3MTAwMDAwMDB9.signature',
    ],

    knownBenign: [
        'jwt.sign({ sub: "123" }, secret, { algorithm: "HS256", expiresIn: "15m" })',
        '{"sub":"123","iat":1710000000,"exp":1710003600}',
        'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJleHAiOjE3MTAwMDM2MDB9.signature',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        const token = findJwtToken(d)
        if (token) {
            const payload = parseJwtPayload(token)
            if (payload && ('iat' in payload || 'sub' in payload || 'nbf' in payload) && !('exp' in payload)) {
                return true
            }
        }

        if (/jwt\.sign\s*\(/i.test(d) && !/\bexpiresIn\b/i.test(d)) {
            return true
        }

        if (looksLikeJwtContext(d) && /"iat"\s*:/.test(d) && !/"exp"\s*:/.test(d)) {
            return true
        }

        return false
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const token = findJwtToken(d)
        if (token) {
            const payload = parseJwtPayload(token)
            if (payload && ('iat' in payload || 'sub' in payload || 'nbf' in payload) && !('exp' in payload)) {
                return {
                    detected: true,
                    confidence: 0.91,
                    explanation: 'JWT payload is missing exp claim, enabling replay windows',
                    evidence: JSON.stringify(payload).slice(0, 140),
                }
            }
        }

        if (/jwt\.sign\s*\(/i.test(d) && !/\bexpiresIn\b/i.test(d)) {
            return {
                detected: true,
                confidence: 0.87,
                explanation: 'JWT signing code omits expiration configuration',
                evidence: 'jwt.sign(...) without expiresIn',
            }
        }

        return null
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'jwt.sign({ sub: "123", role: "user", iat: 1710000000 }, secret, { algorithm: "HS256" })',
            '{"sub":"123","role":"user","iat":1710000000} // JWT payload with no exp',
            'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJpYXQiOjE3MTAwMDAwMDB9.signature',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const jwtPrivilegeEscalation: InvariantClassModule = {
    id: 'jwt_privilege_escalation',
    description: 'JWT claim manipulation for privilege escalation (role=admin, is_admin=true, wildcard scopes)',
    category: 'auth',
    severity: 'critical',
    calibration: { baseConfidence: 0.89 },

    mitre: ['T1078', 'T1550.001'],
    cwe: 'CWE-639',

    knownPayloads: [
        'tamper JWT payload: {"sub":"42","role":"admin"}',
        '{"is_admin":true,"user":"guest"} // forged token claims',
        'Authorization: Bearer token with scope="*" and role="admin"',
    ],

    knownBenign: [
        'Admin dashboard is available for role-based access control docs',
        '{"role":"user","scope":"read:profile"}',
        'authorization token claims include tenant and locale only',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (!looksLikeJwtContext(d)) return false

        const adminClaims = /"(?:role|roles|scope|permissions?)"\s*:\s*"(?:admin|root|superuser|\*|all)"/i.test(d) ||
            /"(?:is_admin|isAdmin|admin)"\s*:\s*true/i.test(d) ||
            /\b(?:scope|permissions?)\s*=\s*["']?\*/i.test(d)

        if (!adminClaims) return false

        return /\b(?:tamper|forge|modify|escalat|bypass|privilege|claim)\w*/i.test(d) || /bearer\s+token/i.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        if (!looksLikeJwtContext(d)) return null

        const matches = d.match(/"(?:role|roles|scope|permissions?|is_admin|isAdmin|admin)"\s*:\s*(?:"(?:admin|root|superuser|\*|all)"|true)/ig)
        if (matches && matches.length > 0) {
            const suspiciousContext = /\b(?:tamper|forge|modify|escalat|bypass|privilege|claim)\w*/i.test(d) || /bearer\s+token/i.test(d)
            if (suspiciousContext) {
                return {
                    detected: true,
                    confidence: 0.92,
                    explanation: 'JWT claims contain elevated privileges in a likely manipulation context',
                    evidence: matches.slice(0, 2).join(' | '),
                }
            }
        }

        return null
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'tamper JWT payload: {"sub":"42","role":"admin"}',
            '{"is_admin":true,"user":"guest"} // forged token claims',
            'Authorization: Bearer token with scope="*" and role="admin"',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const oauthStateMissing: InvariantClassModule = {
    id: 'oauth_state_missing',
    description: 'OAuth CSRF risk — authorization request missing state parameter',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.90 },

    mitre: ['T1078'],
    cwe: 'CWE-352',

    knownPayloads: [
        'https://accounts.example.com/oauth/authorize?response_type=code&client_id=abc123&redirect_uri=https://app.example/callback',
        '/oauth/authorize?client_id=app123&response_type=token&redirect_uri=https://example.com/cb',
        'response_type=code&client_id=my-client&redirect_uri=https://app/callback // no state',
    ],

    knownBenign: [
        'https://accounts.example.com/oauth/authorize?response_type=code&client_id=abc123&redirect_uri=https://app.example/callback&state=xyz987',
        'response_type=code&client_id=my-client&redirect_uri=https://app/callback&state=random',
        'OAuth docs: Always require state parameter',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const isOauthAuthFlow = /\b(?:oauth|authorize|response_type=code|response_type=token)\b/i.test(d) &&
            /\bclient_id=/.test(d) &&
            /\bredirect_uri=/.test(d)
        if (!isOauthAuthFlow) return false
        return !/\bstate=/.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const isOauthAuthFlow = /\b(?:oauth|authorize|response_type=code|response_type=token)\b/i.test(d) &&
            /\bclient_id=/.test(d) &&
            /\bredirect_uri=/.test(d)
        if (!isOauthAuthFlow) return null
        if (/\bstate=/.test(d)) return null
        return {
            detected: true,
            confidence: 0.93,
            explanation: 'OAuth authorization request appears to omit state parameter',
            evidence: d.slice(0, 180),
        }
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'https://accounts.example.com/oauth/authorize?response_type=code&client_id=abc123&redirect_uri=https://app.example/callback',
            '/oauth/authorize?client_id=app123&response_type=token&redirect_uri=https://example.com/cb',
            'response_type=code&client_id=my-client&redirect_uri=https://app/callback // no state',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const sessionFixation: InvariantClassModule = {
    id: 'session_fixation',
    description: 'Session fixation indicator — attacker-provided session identifiers in URL/auth flow or weak sequential IDs',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },

    mitre: ['T1550.004'],
    cwe: 'CWE-384',

    knownPayloads: [
        '?PHPSESSID=attacker_controlled_session',
        '?sid=1234567890',
        '?session_id=abc123',
        '/login?JSESSIONID=1111111111111111&next=/dashboard',
    ],

    knownBenign: [
        'Set-Cookie: sessionid=cf1f8b723c6f4f4bb991fa9a3905ac72; HttpOnly; Secure; SameSite=Lax',
        '/login?next=/dashboard',
        '/profile?view=security',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const sessionInUrl = d.match(/[?&](?:PHPSESSID|JSESSIONID|sid|session_id|sessionid)=([^&\s]+)/i)
        if (!sessionInUrl) return false

        const token = sessionInUrl[1]
        const hasAuthFlow = /\b(?:login|signin|authenticate|oauth|callback)\b/i.test(d)
        const numeric = /^\d+$/.test(token)
        const sequential = /^(?:0123456789|1234567890|9876543210)$/.test(token)
        const tooShort = token.length < 16

        if (sessionInUrl) return true
        if (numeric || sequential || tooShort) return true

        return false
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const sessionRef = d.match(/[?&](?:PHPSESSID|JSESSIONID|sid|session_id|sessionid)=([^&\s]+)/i)
        if (sessionRef) {
            return {
                detected: true,
                confidence: 0.9,
                explanation: 'Session identifier is supplied via URL parameter, enabling fixation attacks',
                evidence: sessionRef[0],
            }
        }

        return null
    },

    generateVariants: (count: number): string[] => {
        const v = [
            '?PHPSESSID=attacker_controlled_session',
            '?sid=1234567890',
            '?session_id=abc123',
            '/login?JSESSIONID=1111111111111111&next=/dashboard',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const credentialStuffing: InvariantClassModule = {
    id: 'credential_stuffing',
    description: 'Credential stuffing signals — repeated automated login attempts using credential lists',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.83 },

    mitre: ['T1110.004'],
    cwe: 'CWE-307',

    knownPayloads: [
        'login failed 25 attempts for user admin from 10.0.0.5',
        'POST /login username=admin&password=admin username=root&password=toor username=test&password=test',
        'credential stuffing run with combo list admin:admin root:toor user:password',
    ],

    knownBenign: [
        'user login success for account alice',
        'password reset requested by user',
        'single failed login attempt',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const hasAuthContext = /\b(?:login|signin|authenticate|password|username|credential)\b/i.test(d)
        if (!hasAuthContext) return false

        const repeatedAttempts = /\b(?:[1-9]\d)\s*(?:failed\s+)?(?:login\s+)?attempts?\b/i.test(d) ||
            /\b(?:failed\s+login|invalid\s+password)\b[\s\S]{0,120}\b(?:failed\s+login|invalid\s+password)\b/i.test(d)

        const comboList = /\b(?:admin:admin|root:toor|test:test|user:password|administrator:password)\b/i.test(d) ||
            /(?:username=[^&\s]{1,40}&password=[^&\s]{1,40})[\s\S]{0,120}(?:username=[^&\s]{1,40}&password=[^&\s]{1,40})/i.test(d)

        return repeatedAttempts || comboList
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const authEvents = (d.match(/\b(?:failed\s+login|invalid\s+password|login\s+attempt)\b/ig) ?? []).length
        const comboEvents = (d.match(/\b(?:[a-z0-9_.-]{2,32}:[^,\s]{2,32})\b/ig) ?? []).length

        if (authEvents >= 2 || comboEvents >= 3) {
            return {
                detected: true,
                confidence: Math.min(0.93, 0.80 + authEvents * 0.04 + comboEvents * 0.03),
                explanation: 'Multiple authentication failures or credential pairs suggest credential stuffing',
                evidence: `auth_events=${authEvents}, combo_events=${comboEvents}`,
            }
        }

        return null
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'login failed 25 attempts for user admin from 10.0.0.5',
            'POST /login username=admin&password=admin username=root&password=toor username=test&password=test',
            'credential stuffing run with combo list admin:admin root:toor user:password',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const oauthRedirectUriBypass: InvariantClassModule = {
    id: 'oauth_redirect_uri_bypass',
    description: 'OAuth redirect_uri bypass via subdomain confusion, traversal, wildcard, or nested open redirect',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.91 },
    mitre: ['T1550.001'],
    cwe: 'CWE-601',

    knownPayloads: [
        'redirect_uri=https://legit.com.evil.com/callback',
        'redirect_uri=https://legit.com/../../../evil.com',
        'redirect_uri=https://legit.com/callback?next=//evil.com',
        'redirect_uri=https://*.legit.com/callback',
    ],

    knownBenign: [
        'redirect_uri=https://legit.com/callback',
        'redirect_uri=https://login.legit.com/oauth/callback',
        'client_id=app&response_type=code&state=abc123',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const match = d.match(/(?:^|[?&\s])redirect_uri=([^\s&]+)/i)
        if (!match) return false

        const uri = decodeURIComponent(match[1])
        if (/\.{2}[\\/]/.test(uri)) return true
        if (/(?:https?:\/\/[^/?#]*\.(?:com|net|org|io|co)\.[^/?#]+)/i.test(uri)) return true
        if (/[?&](?:next|url|redirect|return_to)=\/\//i.test(uri)) return true
        if (/\*/.test(uri)) return true
        return false
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'redirect_uri=https://legit.com.evil.com/callback',
            'redirect_uri=https://legit.com/../../../evil.com',
            'redirect_uri=https://legit.com/callback?next=//evil.com',
            'redirect_uri=https://*.legit.com/callback',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const mfaBypassIndicator: InvariantClassModule = {
    id: 'mfa_bypass_indicator',
    description: 'MFA bypass indicators including trivial OTP values and backup code abuse patterns',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.88 },
    mitre: ['T1110.001'],
    cwe: 'CWE-307',

    knownPayloads: [
        'otp=000000',
        'totp=123456&retry=true',
        'backup_code=00000000',
        'mfa_code=111111',
    ],

    knownBenign: [
        'otp=849275',
        'totp=927461&remember_device=true',
        'backup_code=A7K9-M4P2',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // Direct fast-path: all-zero backup codes are clear attack signals
        if (/backup_code=0{6,}/i.test(d)) return true
        const paramPattern = /(?:^|[?&\s])(otp|totp|mfa_code|mfacode|backup_code)=([^&\s]+)/gi
        let match: RegExpExecArray | null
        let backupCount = 0

        while ((match = paramPattern.exec(d)) !== null) {
            const key = match[1].toLowerCase()
            const rawValue = decodeURIComponent(match[2])
            const digits = rawValue.replace(/\D/g, '')

            if (key === 'backup_code') {
                backupCount += 1
                if (digits.length >= 6 && /^0+$/.test(digits)) return true
                continue
            }

            if (digits.length > 0 && digits.length < 6) return true
            if (/^0{6,}$/.test(digits)) return true
            if (/^(\d)\1{5,}$/.test(digits)) return true
            if (/^(?:012345|123456|234567|345678|456789|567890|654321|987654)$/.test(digits)) return true
        }

        if (backupCount >= 2 && /(?:retry=true|attempt=\d+|rapid|burst)/i.test(d)) return true
        return false
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'otp=000000',
            'totp=123456&retry=true',
            'backup_code=00000000',
            'mfa_code=111111',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

const pkceDowngradeLegacy: InvariantClassModule = {
    id: 'pkce_downgrade',
    description: 'PKCE downgrade when code_challenge_method=plain or code flow is initiated without code_challenge',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1550.001'],
    cwe: 'CWE-757',

    knownPayloads: [
        'response_type=code&code_challenge=abc&code_challenge_method=plain',
        'response_type=code&client_id=app',
        'oauth/authorize?response_type=code&client_id=mobile-app&redirect_uri=https://app/cb',
    ],

    knownBenign: [
        'response_type=code&code_challenge=abc123&code_challenge_method=S256&client_id=app',
        'response_type=token&client_id=app',
        'response_type=code&client_id=app&code_challenge=abc123&code_challenge_method=s256',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (!/\bresponse_type=code\b/i.test(d)) return false
        if (/\bcode_challenge_method=plain\b/i.test(d)) return true
        if (!/\bcode_challenge=/i.test(d)) return true
        return false
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'response_type=code&code_challenge=abc&code_challenge_method=plain',
            'response_type=code&client_id=app',
            'oauth/authorize?response_type=code&client_id=mobile-app&redirect_uri=https://app/cb',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const bearerTokenExposure: InvariantClassModule = {
    id: 'bearer_token_exposure',
    description: 'Bearer/access token exposure in URLs, Referer headers, request bodies, or forwarded logs',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.89 },
    mitre: ['T1528'],
    cwe: 'CWE-200',

    knownPayloads: [
        'GET /api/data?access_token=ya29.xxx HTTP/1.1',
        'Referer: https://app.com/page?token=eyJhbGc...',
        'access_token=ya29.longtoken&action=transfer&amount=100',
        'X-Forwarded-For: 203.0.113.10 bearer eyJhbGciOiJIUzI1NiJ9.abc.def',
    ],

    knownBenign: [
        'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.abc.def',
        'GET /api/data?page=2 HTTP/1.1',
        'Referer: https://app.com/dashboard',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (/[?&](?:access_token|token|jwt|auth)=([^&\s]+)/i.test(d)) return true
        if (/referer\s*:\s*https?:\/\/\S*[?&](?:access_token|token|jwt|auth)=/i.test(d)) return true
        if (/(?:access_token|token)=([^&\s]+)&(?:[a-z_][a-z0-9_]*)=/i.test(d)) return true
        if (/x-forwarded-for\s*:[^\n]*\bbearer\s+[A-Za-z0-9._-]+/i.test(d)) return true
        return false
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'GET /api/data?access_token=ya29.xxx HTTP/1.1',
            'Referer: https://app.com/page?token=eyJhbGc...',
            'access_token=ya29.longtoken&action=transfer&amount=100',
            'X-Forwarded-For: 203.0.113.10 bearer eyJhbGciOiJIUzI1NiJ9.abc.def',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const passwordSprayIndicator: InvariantClassModule = {
    id: 'password_spray_indicator',
    description: 'Password spray indicators where common breached passwords are reused across login attempts',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1110.003'],
    cwe: 'CWE-307',

    knownPayloads: [
        'username=admin&password=password123',
        'email=ceo@corp.com&password=Summer2024!',
        'login=admin&pass=qwerty123',
        'username=password123&password=qwerty',
    ],

    knownBenign: [
        'username=alice&password=V3ryStrong!Pass',
        'email=user@corp.com&password=H7$kLm2!qP9',
        'login=service-user&pass=machine-token',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (!/\b(?:login|signin|auth|username|email|password|pass)\b/i.test(d)) return false

        const weakPw = /^(?:password|password1|password123|qwerty|qwerty123|admin|123456|12345678|letmein|welcome|iloveyou|monkey|dragon|sunshine|princess|football|summer2024!?|summer2024!)$/i
        const pairPattern = /(?:^|[?&\s])(username|email|login|password|pass)=([^&\s]+)/gi
        let match: RegExpExecArray | null
        const values: Record<string, string[]> = { username: [], email: [], login: [], password: [], pass: [] }

        while ((match = pairPattern.exec(d)) !== null) {
            const key = match[1].toLowerCase()
            const value = decodeURIComponent(match[2])
                .replace(/\\([!@#$%^&*])/g, '$1')
                .replace(/['"]/g, '')
            values[key].push(value)
        }

        for (const pw of [...values.password, ...values.pass]) {
            if (weakPw.test(pw)) return true
        }

        for (const idValue of [...values.username, ...values.email, ...values.login]) {
            if (weakPw.test(idValue)) return true
        }

        return false
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'username=admin&password=password123',
        'email=ceo@corp.com&password=Summer2024!',
            'login=admin&pass=qwerty123',
            'username=password123&password=qwerty',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export { jwtKidInjection, jwtJwkEmbedding, jwtWeakSecret, jwtClaimConfusion } from './jwt-attacks.js'
export { jwtConfusion } from './jwt-abuse.js'
export { oauthRedirectManipulation, oauthStateBypass, pkceDowngrade } from './oauth-attacks.js'

export const AUTH_CLASSES: InvariantClassModule[] = [
    authNoneAlgorithm,
    authHeaderSpoof,
    jwtWeakHmacSecret,
    jwtMissingExpiry,
    jwtPrivilegeEscalation,
    oauthRedirectManipulation,
    oauthStateBypass,
    pkceDowngrade,
    oauthStateMissing,
    sessionFixation,
    oauthTokenLeak,
    oauthRedirectHijack,
    samlSignatureWrapping,
    oauthRedirectUriBypass,
    mfaBypassIndicator,
    bearerTokenExposure,
    passwordSprayIndicator,
    jwtAlgorithmConfusion,
    oidcNonceReplay,
    jwtWeakSecret,
    jwtKidInjection,
    jwtJwkEmbedding,
    jwtConfusion,
    jwtClaimConfusion,
]
