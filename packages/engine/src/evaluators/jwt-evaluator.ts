/**
 * JWT Abuse Evaluator — Level 2 Invariant Detection
 *
 * Structural analysis of JWT tokens beyond regex:
 *   - jwt_kid_injection:  Parse JWT header, extract kid, analyze for injection payloads
 *   - jwt_jwk_embedding:  Detect self-signed key material in JWT header
 *   - jwt_confusion:      Detect algorithm confusion (asymmetric → symmetric swap)
 *
 * The evaluator actually parses the JWT header (base64url decode) and inspects
 * the decoded JSON structure, rather than relying on regex over the raw string.
 */


// ── Result Type ──────────────────────────────────────────────────

export interface JWTDetection {
    type: 'jwt_kid_injection' | 'jwt_jwk_embedding' | 'jwt_confusion'
    detail: string
    confidence: number
    headerFields: string[]
}


// ── Helpers ──────────────────────────────────────────────────────

interface JWTHeader {
    alg?: string
    typ?: string
    kid?: string
    jwk?: Record<string, unknown>
    jku?: string
    x5u?: string
    x5c?: unknown[]
    [key: string]: unknown
}

function extractAndParseJwtHeaders(input: string): JWTHeader[] {
    const headers: JWTHeader[] = []

    // Try to find JWT tokens in the input
    const jwtPattern = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g
    let match: RegExpExecArray | null
    while ((match = jwtPattern.exec(input)) !== null) {
        const headerB64 = match[0].split('.')[0]
        try {
            const b64 = headerB64.replace(/-/g, '+').replace(/_/g, '/')
            const pad = b64.length % 4
            const padded = pad === 0 ? b64 : b64 + '='.repeat(4 - pad)
            const decoded = Buffer.from(padded, 'base64').toString('utf8')
            const parsed = JSON.parse(decoded)
            if (typeof parsed === 'object' && parsed !== null) {
                headers.push(parsed as JWTHeader)
            }
        } catch { /* skip malformed */ }
    }

    // Also try to parse raw JSON that looks like a JWT header
    const jsonHeaderPattern = /\{"(?:alg|typ|kid|jwk|jku|x5[cu])"\s*:/g
    let jsonMatch: RegExpExecArray | null
    while ((jsonMatch = jsonHeaderPattern.exec(input)) !== null) {
        // Find the matching closing brace
        let depth = 0
        let end = jsonMatch.index
        for (let i = jsonMatch.index; i < input.length && i < jsonMatch.index + 2000; i++) {
            if (input[i] === '{') depth++
            else if (input[i] === '}') {
                depth--
                if (depth === 0) { end = i + 1; break }
            }
        }
        if (depth === 0 && end > jsonMatch.index) {
            try {
                const parsed = JSON.parse(input.slice(jsonMatch.index, end))
                if (typeof parsed === 'object' && parsed !== null) {
                    headers.push(parsed as JWTHeader)
                }
            } catch { /* skip */ }
        }
    }

    return headers
}


// ── kid Injection Analysis ───────────────────────────────────────

function analyzeKidInjection(header: JWTHeader): JWTDetection | null {
    if (!header.kid || typeof header.kid !== 'string') return null

    const kid = header.kid
    const signals: string[] = []

    // Path traversal in kid
    if (/\.\.[\\/]/.test(kid)) {
        signals.push('path traversal')
    }

    // SQL injection in kid
    if (/(?:union\s+select|'\s*(?:or|and)\s+|;\s*(?:drop|select|insert|update|delete)|--\s*$)/i.test(kid)) {
        signals.push('SQL injection')
    }

    // Command injection in kid
    if (/[|;`$]/.test(kid) && /\b(?:cat|curl|wget|bash|sh|id|whoami|ls|rm|nc)\b/i.test(kid)) {
        signals.push('command injection')
    }

    // Null byte injection
    if (/(?:\\x00|%00|\0)/.test(kid)) {
        signals.push('null byte')
    }

    // LDAP injection in kid
    if (/[*()\\]/.test(kid) && /\|/.test(kid)) {
        signals.push('LDAP injection')
    }

    if (signals.length === 0) return null

    return {
        type: 'jwt_kid_injection',
        detail: `JWT kid field contains ${signals.join(' + ')}: "${kid.slice(0, 80)}"`,
        confidence: signals.length >= 2 ? 0.96 : 0.91,
        headerFields: Object.keys(header),
    }
}


// ── JWK/JKU Embedding Analysis ───────────────────────────────────

function analyzeJwkEmbedding(header: JWTHeader): JWTDetection | null {
    const signals: string[] = []

    // JWK embedded in header — the key material itself is in the token
    if (header.jwk && typeof header.jwk === 'object') {
        const jwk = header.jwk as Record<string, unknown>
        if (jwk.kty && typeof jwk.kty === 'string') {
            signals.push(`embedded ${jwk.kty} JWK`)

            // Extra suspicious: RSA key with n and e params
            if (jwk.kty === 'RSA' && jwk.n && jwk.e) {
                signals.push('complete RSA public key')
            }
            // EC key with full coordinates
            if (jwk.kty === 'EC' && jwk.x && jwk.y) {
                signals.push('complete EC public key')
            }
        }
    }

    // JKU pointing to external URL — server would fetch attacker's JWKS
    if (header.jku && typeof header.jku === 'string') {
        signals.push(`external JKU: ${header.jku.slice(0, 60)}`)
    }

    // x5u — external X.509 cert URL
    if (header.x5u && typeof header.x5u === 'string') {
        signals.push(`external x5u: ${header.x5u.slice(0, 60)}`)
    }

    if (signals.length === 0) return null

    // Only suspicious if combined with an algorithm declaration
    if (!header.alg) return null

    return {
        type: 'jwt_jwk_embedding',
        detail: `JWT header self-signed key: ${signals.join(', ')}`,
        confidence: signals.length >= 2 ? 0.96 : 0.93,
        headerFields: Object.keys(header),
    }
}


// ── Algorithm Confusion Analysis ─────────────────────────────────

function analyzeAlgConfusion(header: JWTHeader, fullInput: string): JWTDetection | null {
    if (!header.alg || typeof header.alg !== 'string') return null

    const alg = header.alg.toUpperCase()

    // Must be an HMAC algorithm
    if (!alg.startsWith('HS')) return null

    const signals: string[] = []

    // kid references RSA/public key
    if (header.kid && typeof header.kid === 'string') {
        if (/(?:rsa|public|pub[_-]?key|asymmetric)/i.test(header.kid)) {
            signals.push(`kid references asymmetric key: "${header.kid}"`)
        }
    }

    // PEM key material in the broader input
    if (/-----BEGIN\s+(?:RSA\s+)?(?:PUBLIC\s+)?KEY-----/i.test(fullInput)) {
        signals.push('PEM key material present')
    }

    // Explicit confusion context
    if (/(?:rsa|public)\s+key\s+(?:as|for|used\s+as)\s+(?:hmac|secret|symmetric)/i.test(fullInput)) {
        signals.push('explicit confusion context')
    }

    if (signals.length === 0) return null

    return {
        type: 'jwt_confusion',
        detail: `JWT algorithm confusion (${header.alg} with ${signals.join(', ')})`,
        confidence: signals.length >= 2 ? 0.96 : 0.88,
        headerFields: Object.keys(header),
    }
}


// ── Public API ───────────────────────────────────────────────────

export function detectJWTAbuse(input: string): JWTDetection[] {
    const detections: JWTDetection[] = []

    if (input.length < 10) return detections

    const headers = extractAndParseJwtHeaders(input)
    if (headers.length === 0) return detections

    for (const header of headers) {
        try {
            const kid = analyzeKidInjection(header)
            if (kid) detections.push(kid)
        } catch { /* safe */ }

        try {
            const jwk = analyzeJwkEmbedding(header)
            if (jwk) detections.push(jwk)
        } catch { /* safe */ }

        try {
            const confusion = analyzeAlgConfusion(header, input)
            if (confusion) detections.push(confusion)
        } catch { /* safe */ }
    }

    return detections
}
