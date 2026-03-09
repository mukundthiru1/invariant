import { describe, it, expect } from 'vitest'
import {
    detectAuthCodeInterception,
    detectPkceDowngradeAttack,
    detectOAuthMixupAttack,
    detectTokenLeakageViaReferrer,
    detectImplicitFlowAbuse,
    detectOAuthTheft,
} from './oauth-theft-evaluator.js'

describe('oauth-theft-evaluator', () => {
    it('detectAuthCodeInterception: detects HTTP redirect_uri to external host', () => {
        const input = 'https://auth.example.com/oauth/authorize?response_type=code&client_id=app&redirect_uri=http://evil.com/callback'
        const r = detectAuthCodeInterception(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('auth_code_interception')
        expect(r!.confidence).toBe(0.93)
    })

    it('detectAuthCodeInterception: detects redirect_uri to IP address', () => {
        const input = 'oauth/authorize?response_type=code&client_id=x&redirect_uri=http://192.168.1.1/cb'
        const r = detectAuthCodeInterception(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('auth_code_interception')
    })

    it('detectPkceDowngradeAttack: detects missing code_challenge with response_type=code', () => {
        const input = 'response_type=code&client_id=app&redirect_uri=https://app.example/callback'
        const r = detectPkceDowngradeAttack(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('pkce_downgrade')
        expect(r!.confidence).toBe(0.91)
    })

    it('detectPkceDowngradeAttack: detects code_challenge_method=plain', () => {
        const input = 'response_type=code&client_id=app&redirect_uri=https://app/cb&code_challenge=abc&code_challenge_method=plain'
        const r = detectPkceDowngradeAttack(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('pkce_downgrade')
    })

    it('detectOAuthMixupAttack: detects missing state in auth request', () => {
        const input = 'https://idp.example/oauth/authorize?response_type=code&client_id=app&redirect_uri=https://app/cb'
        const r = detectOAuthMixupAttack(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('oauth_mixup')
    })

    it('detectTokenLeakageViaReferrer: detects access_token in query', () => {
        const input = 'https://app.example/callback?access_token=ya29.abcdefghijklmnopqrstuvwxyz123456'
        const r = detectTokenLeakageViaReferrer(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('token_leakage_referrer')
        expect(r!.confidence).toBe(0.92)
    })

    it('detectImplicitFlowAbuse: detects response_type=token', () => {
        const input = 'oauth/authorize?response_type=token&client_id=app&redirect_uri=https://app/cb'
        const r = detectImplicitFlowAbuse(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('implicit_flow_abuse')
        expect(r!.confidence).toBe(0.87)
    })

    it('detectOAuthTheft aggregates all detectors and returns array', () => {
        const input = 'https://auth.example/oauth/authorize?response_type=code&client_id=app&redirect_uri=http://evil.com/cb'
        const all = detectOAuthTheft(input)
        expect(Array.isArray(all)).toBe(true)
        expect(all.length).toBeGreaterThanOrEqual(1)
        expect(new Set(all.map(a => a.type)).has('auth_code_interception')).toBe(true)
    })
})
