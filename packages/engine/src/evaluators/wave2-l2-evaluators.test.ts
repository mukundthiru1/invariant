/**
 * Tests for Wave 2 L2 Evaluators: JWT, Cache, API Abuse
 *
 * Tests:
 *   1. JWT kid injection — path traversal, SQLi, command injection in kid
 *   2. JWT JWK embedding — embedded key material, JKU, x5u
 *   3. JWT algorithm confusion — HS256 with RSA key references
 *   4. Cache poisoning — unkeyed headers with injection payloads
 *   5. Cache deception — static extensions on dynamic paths
 *   6. BOLA/IDOR — API path with auth mismatch, path traversal to admin
 *   7. API mass enumeration — sequential IDs, range queries, large limits
 *   8. Negative: benign inputs should not trigger
 *   9. Edge cases: empty input, very short input, malformed JWT
 */

import { describe, it, expect } from 'vitest'
import { detectJWTAbuse } from './jwt-evaluator.js'
import { detectCacheAttack } from './cache-evaluator.js'
import { detectAPIAbuse } from './api-abuse-evaluator.js'

describe('JWT Abuse Evaluator', () => {
    it('detects path traversal in kid field', () => {
        const input = '{"alg":"HS256","kid":"../../dev/null"}'
        const results = detectJWTAbuse(input)
        const kid = results.find(r => r.type === 'jwt_kid_injection')
        expect(kid).toBeDefined()
        expect(kid!.confidence).toBeGreaterThanOrEqual(0.88)
    })

    it('detects SQL injection in kid field', () => {
        const input = '{"alg":"HS256","kid":"\' UNION SELECT \'secret\' --"}'
        const results = detectJWTAbuse(input)
        const kid = results.find(r => r.type === 'jwt_kid_injection')
        expect(kid).toBeDefined()
    })

    it('detects command injection in kid field', () => {
        const input = '{"alg":"HS256","kid":"| cat /etc/passwd"}'
        const results = detectJWTAbuse(input)
        const kid = results.find(r => r.type === 'jwt_kid_injection')
        expect(kid).toBeDefined()
    })

    it('detects embedded JWK in header', () => {
        const input = '{"alg":"RS256","jwk":{"kty":"RSA","n":"0vx7agoebGcQ","e":"AQAB"}}'
        const results = detectJWTAbuse(input)
        const jwk = results.find(r => r.type === 'jwt_jwk_embedding')
        expect(jwk).toBeDefined()
        expect(jwk!.confidence).toBeGreaterThanOrEqual(0.90)
    })

    it('detects external JKU URL', () => {
        const input = '{"alg":"RS256","jku":"https://evil.example/.well-known/jwks.json"}'
        const results = detectJWTAbuse(input)
        const jwk = results.find(r => r.type === 'jwt_jwk_embedding')
        expect(jwk).toBeDefined()
    })

    it('detects algorithm confusion (HS with RSA kid)', () => {
        const input = '{"alg":"HS256","typ":"JWT","kid":"rsa-pub-key"}'
        const results = detectJWTAbuse(input)
        const confusion = results.find(r => r.type === 'jwt_confusion')
        expect(confusion).toBeDefined()
    })

    it('detects algorithm confusion with PEM key', () => {
        const input = '{"alg":"HS512"} -----BEGIN PUBLIC KEY-----'
        const results = detectJWTAbuse(input)
        const confusion = results.find(r => r.type === 'jwt_confusion')
        expect(confusion).toBeDefined()
    })

    it('does not trigger on normal JWT header', () => {
        const input = '{"alg":"RS256","typ":"JWT"}'
        const results = detectJWTAbuse(input)
        expect(results.length).toBe(0)
    })

    it('does not trigger on normal JWT with safe kid', () => {
        const input = '{"alg":"RS256","kid":"2024-key-rotation-01"}'
        const results = detectJWTAbuse(input)
        expect(results.length).toBe(0)
    })

    it('returns empty for very short input', () => {
        expect(detectJWTAbuse('hi')).toEqual([])
    })

    it('returns empty for empty input', () => {
        expect(detectJWTAbuse('')).toEqual([])
    })
})

describe('Cache Attack Evaluator', () => {
    it('detects cache poisoning via X-Forwarded-Host', () => {
        const input = 'X-Forwarded-Host: evil.example\r\nX-Forwarded-Scheme: nothttps'
        const results = detectCacheAttack(input)
        const poison = results.find(r => r.type === 'cache_poisoning')
        expect(poison).toBeDefined()
    })

    it('detects cache poisoning with XSS payload', () => {
        const input = 'X-Forwarded-Host: evil.example"><script>alert(1)</script>'
        const results = detectCacheAttack(input)
        const poison = results.find(r => r.type === 'cache_poisoning')
        expect(poison).toBeDefined()
    })

    it('detects cache deception on API path', () => {
        const input = '/api/user/profile/nonexistent.css'
        const results = detectCacheAttack(input)
        const deception = results.find(r => r.type === 'cache_deception')
        expect(deception).toBeDefined()
    })

    it('detects cache deception with path traversal', () => {
        const input = '/my-account/details/..%2f..%2fstatic.png'
        const results = detectCacheAttack(input)
        const deception = results.find(r => r.type === 'cache_deception')
        expect(deception).toBeDefined()
        expect(deception!.confidence).toBeGreaterThanOrEqual(0.90)
    })

    it('detects cache deception with fragment bypass', () => {
        const input = '/api/v1/me/avatar.jpg%23'
        const results = detectCacheAttack(input)
        const deception = results.find(r => r.type === 'cache_deception')
        expect(deception).toBeDefined()
    })

    it('does not trigger on static asset paths', () => {
        const input = '/static/styles.css'
        const results = detectCacheAttack(input)
        expect(results.length).toBe(0)
    })

    it('does not trigger on normal headers', () => {
        const input = 'Cache-Control: no-cache\r\nPragma: no-cache'
        const results = detectCacheAttack(input)
        expect(results.length).toBe(0)
    })

    it('returns empty for short input', () => {
        expect(detectCacheAttack('short')).toEqual([])
    })
})

describe('API Abuse Evaluator', () => {
    it('detects BOLA/IDOR with auth mismatch', () => {
        const input = '/api/users/2/profile with Authorization: Bearer <token_for_user_1>'
        const results = detectAPIAbuse(input)
        const bola = results.find(r => r.type === 'bola_idor')
        expect(bola).toBeDefined()
    })

    it('detects BOLA/IDOR with path traversal to admin', () => {
        const input = '/api/v1/documents/../../admin/config'
        const results = detectAPIAbuse(input)
        const bola = results.find(r => r.type === 'bola_idor')
        expect(bola).toBeDefined()
    })

    it('detects mass enumeration via sequential IDs', () => {
        const input = 'GET /api/users/1 GET /api/users/2 GET /api/users/3 GET /api/users/4 GET /api/users/5'
        const results = detectAPIAbuse(input)
        const mass = results.find(r => r.type === 'api_mass_enum')
        expect(mass).toBeDefined()
    })

    it('detects mass enumeration via range operators', () => {
        const input = '/api/invoices?id[gte]=1&id[lte]=99999'
        const results = detectAPIAbuse(input)
        const mass = results.find(r => r.type === 'api_mass_enum')
        expect(mass).toBeDefined()
    })

    it('detects mass enumeration via large limit', () => {
        const input = '/api/v1/records?filter=id>0&limit=999999'
        const results = detectAPIAbuse(input)
        const mass = results.find(r => r.type === 'api_mass_enum')
        expect(mass).toBeDefined()
    })

    it('does not trigger on normal API usage', () => {
        const input = '/api/users?page=1&limit=20'
        const results = detectAPIAbuse(input)
        expect(results.length).toBe(0)
    })

    it('does not trigger on non-API paths', () => {
        const input = '/static/main.js'
        const results = detectAPIAbuse(input)
        expect(results.length).toBe(0)
    })

    it('returns empty for short input', () => {
        expect(detectAPIAbuse('short')).toEqual([])
    })
})
