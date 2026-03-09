import { describe, expect, it } from 'vitest'
import { detectJWTAbuse } from './jwt-evaluator.js'

describe('jwt-evaluator', () => {
    it('detects kid injection in JWT-like header JSON', () => {
        const input = '{"alg":"HS256","kid":"../../etc/passwd"}'
        const detections = detectJWTAbuse(input)
        expect(detections.some((d) => d.type === 'jwt_kid_injection')).toBe(true)
    })

    it('detects embedded JWK material', () => {
        const input = '{"alg":"RS256","jwk":{"kty":"RSA","n":"abc","e":"AQAB"}}'
        const detections = detectJWTAbuse(input)
        expect(detections.some((d) => d.type === 'jwt_jwk_embedding')).toBe(true)
    })

    it('detects algorithm confusion signal', () => {
        const input = '{"alg":"HS256","kid":"rsa-public-key"} -----BEGIN PUBLIC KEY-----'
        const detections = detectJWTAbuse(input)
        expect(detections.some((d) => d.type === 'jwt_confusion')).toBe(true)
    })

    it('returns no detections for benign short text', () => {
        expect(detectJWTAbuse('hello')).toHaveLength(0)
    })
})
