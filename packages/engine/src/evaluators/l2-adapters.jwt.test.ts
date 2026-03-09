import { describe, expect, it } from 'vitest'
import { l2JwtAlgConfusion } from './l2-adapters.js'

describe('l2JwtAlgConfusion', () => {
    it('detects alg:none in JWT header', () => {
        const token = 'eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.'
        const result = l2JwtAlgConfusion(token, token)
        expect(result).not.toBeNull()
        expect(result!.detected).toBe(true)
        expect(result!.confidence).toBe(0.95)
    })

    it('detects external jku injection', () => {
        const input = '{"alg":"RS256","typ":"JWT","jku":"https://evil.example/.well-known/jwks.json"}'
        const result = l2JwtAlgConfusion(input, input)
        expect(result).not.toBeNull()
        expect(result!.detected).toBe(true)
        expect(result!.confidence).toBe(0.90)
    })

    it('detects kid SQL injection pattern', () => {
        const input = '{"alg":"RS256","typ":"JWT","kid":"1 UNION SELECT password FROM users--"}'
        const result = l2JwtAlgConfusion(input, input)
        expect(result).not.toBeNull()
        expect(result!.detected).toBe(true)
        expect(result!.confidence).toBe(0.90)
    })

    it('detects kid path traversal pattern', () => {
        const input = '{"alg":"RS256","typ":"JWT","kid":"../../../etc/passwd"}'
        const result = l2JwtAlgConfusion(input, input)
        expect(result).not.toBeNull()
        expect(result!.detected).toBe(true)
        expect(result!.confidence).toBe(0.90)
    })

    it('does not detect a valid RS256 JWT header', () => {
        const token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.fj3K9n3rXy9eZ3Q2m4Y8k1aC0pQ9vT6x'
        const result = l2JwtAlgConfusion(token, token)
        expect(result).toBeNull()
    })
})
