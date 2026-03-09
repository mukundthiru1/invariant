/**
 * OAuth Theft & PKCE Bypass Evaluator — Level 2 Invariant Detection
 *
 * Advanced detection for:
 *   - Auth code interception (redirect_uri mismatch, open redirect in redirect_uri)
 *   - PKCE downgrade (missing code_challenge, code_challenge_method=plain)
 *   - OAuth mix-up (missing/predictable state, missing iss in token response)
 *   - Token leakage via Referer (access_token in URL query/fragment)
 *   - Implicit flow abuse (response_type=token, token in fragment without PKCE)
 *
 * All functions perform real pattern and structural analysis; no stubs.
 */

import { describe, it, expect } from 'vitest'

// ── Result Type ──────────────────────────────────────────────────

export interface OAuthDetection {
    type: 'auth_code_interception' | 'pkce_downgrade' | 'oauth_mixup' | 'token_leakage_referrer' | 'implicit_flow_abuse'
    confidence: number
    detail: string
}

// ── Helpers ──────────────────────────────────────────────────────

function normalizedSearchParams(input: string): string {
    return input.replace(/\s+/g, ' ').trim()
}

// ── Auth Code Interception ────────────────────────────────────────

/**
 * OAuth authorization code interception: redirect_uri mismatch, open redirect
 * in redirect_uri. Detects redirect_uri pointing to external/evil domain or
 * use of http (insecure) in OAuth flow.
 */
export function detectAuthCodeInterception(input: string): OAuthDetection | null {
    const d = normalizedSearchParams(input)
    const redirectUriMatch = d.match(/(?:^|[?&\s])redirect_uri=([^\s&]+)/i)
    if (!redirectUriMatch) return null

    const uri = decodeURIComponent(redirectUriMatch[1]).replace(/\+/g, ' ')
    const isOAuthFlow = /\b(?:oauth|authorize|response_type=code)\b/i.test(d) && /\bclient_id=/.test(d)

    if (!isOAuthFlow) return null

    const signals: string[] = []

    if (/^http:\/\//i.test(uri) && !/^http:\/\/localhost(?::\d+)?(\/|$)/i.test(uri)) {
        signals.push('redirect_uri uses HTTP (insecure, code can be intercepted)')
    }

    const hostMatch = uri.match(/^(?:https?):\/\/([^/?#]+)/i)
    if (hostMatch) {
        const host = hostMatch[1].toLowerCase()
        if (/\.(tk|ml|ga|cf|gq)$/.test(host)) signals.push('redirect_uri to free/typosquat TLD')
        if (/\b(?:evil|attacker|malicious|phish|steal)\./i.test(host)) signals.push('redirect_uri to suspicious host')
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?$/.test(host)) {
            signals.push('redirect_uri to IP address (common in code interception)')
        }
    }

    if (/(?:\.\.\/|%2e%2e%2f|%2e%2e\/)/i.test(uri)) {
        signals.push('redirect_uri contains path traversal')
    }

    if (signals.length === 0) return null

    return {
        type: 'auth_code_interception',
        confidence: 0.93,
        detail: `OAuth auth code interception risk: ${signals.join('; ')}`,
    }
}

// ── PKCE Downgrade ────────────────────────────────────────────────

/**
 * PKCE downgrade: missing code_challenge in PKCE flow, or
 * code_challenge_method=plain with weak verifier.
 */
export function detectPkceDowngradeAttack(input: string): OAuthDetection | null {
    const d = normalizedSearchParams(input)
    if (!/\bresponse_type=code\b/i.test(d)) return null

    const hasClientId = /\bclient_id=/.test(d)
    const hasRedirectUri = /\bredirect_uri=/.test(d)
    if (!hasClientId || !hasRedirectUri) return null

    const hasCodeChallenge = /\bcode_challenge=/.test(d)
    const plainMethod = /\bcode_challenge_method=plain\b/i.test(d)
    const s256Method = /\bcode_challenge_method=(?:S256|s256)\b/i.test(d)

    if (plainMethod) {
        const shortVerifier = /\bcode_challenge=([A-Za-z0-9_-]{1,20})(?:&|$)/i.exec(d)
        return {
            type: 'pkce_downgrade',
            confidence: 0.91,
            detail: 'PKCE downgrade: code_challenge_method=plain (verifier sent in clear; weak verifier if short)',
        }
    }

    if (!hasCodeChallenge && (hasClientId && hasRedirectUri)) {
        return {
            type: 'pkce_downgrade',
            confidence: 0.91,
            detail: 'PKCE downgrade: authorization request with response_type=code but no code_challenge',
        }
    }

    return null
}

// ── OAuth Mix-up ──────────────────────────────────────────────────

/**
 * OAuth mix-up: state parameter missing or predictable; iss missing in token response.
 */
export function detectOAuthMixupAttack(input: string): OAuthDetection | null {
    const d = normalizedSearchParams(input)
    const isAuthRequest = /\b(?:oauth|authorize)\b/i.test(d) && /\b(?:response_type=code|response_type=token)\b/i.test(d) &&
        /\bredirect_uri=/.test(d)
    const isTokenResponse = /\b(?:access_token|id_token)=/.test(d) || /"access_token"\s*:/.test(d)

    const signals: string[] = []

    if (isAuthRequest) {
        const stateMatch = d.match(/\bstate=([^&\s]+)/i)
        if (!stateMatch) {
            signals.push('state parameter missing (CSRF/mix-up risk)')
        } else {
            const stateVal = decodeURIComponent(stateMatch[1])
            if (/^\d{1,6}$/.test(stateVal)) signals.push('predictable state (sequential or short numeric)')
            if (/^(?:1234|0000|test|abc)$/i.test(stateVal)) signals.push('trivial state value')
        }
    }

    if (isTokenResponse) {
        if (!/["']?iss["']?\s*[:=]/.test(d) && /\b(?:access_token|id_token)=/.test(d)) {
            signals.push('iss missing in token response (mix-up between providers)')
        }
        const issMatches = d.match(/["']?iss["']?\s*[:=]\s*["']?([^"'\s&,}]+)/gi)
        if (issMatches && issMatches.length > 1) {
            signals.push('multiple iss values in token response')
        }
    }

    if (signals.length === 0) return null

    return {
        type: 'oauth_mixup',
        confidence: 0.88,
        detail: `OAuth mix-up indicators: ${signals.join('; ')}`,
    }
}

// ── Token Leakage via Referrer ──────────────────────────────────────

/**
 * Access token in URL (leaked via Referer header): ?access_token=, #access_token=, ?token=
 */
export function detectTokenLeakageViaReferrer(input: string): OAuthDetection | null {
    const d = normalizedSearchParams(input)

    const patterns = [
        { re: /[?#&]access_token=([^&\s#]+)/i, label: 'access_token in URL' },
        { re: /#(?:[^#]*&)?access_token=([^&\s]+)/i, label: 'access_token in fragment (Referer leak)' },
        { re: /[?#&]token=([A-Za-z0-9_.-]{20,})/i, label: 'bearer-like token in query/fragment' },
    ]

    for (const { re, label } of patterns) {
        const match = d.match(re)
        if (match) {
            const value = match[1]
            if (value.length >= 10) {
                return {
                    type: 'token_leakage_referrer',
                    confidence: 0.92,
                    detail: `Token leakage via Referer: ${label}`,
                }
            }
        }
    }

    return null
}

// ── Implicit Flow Abuse ────────────────────────────────────────────

/**
 * Implicit flow (deprecated, insecure): response_type=token; token in fragment without PKCE.
 */
export function detectImplicitFlowAbuse(input: string): OAuthDetection | null {
    const d = normalizedSearchParams(input)
    const hasResponseTypeToken = /\bresponse_type=token\b/i.test(d)
    const hasResponseTypeCode = /\bresponse_type=code\b/i.test(d)
    const hasFragmentToken = /#(?:[^#]*&)?access_token=/.test(d) || /#(?:[^#]*&)?token=/.test(d)
    const isOAuth = /\b(?:oauth|authorize)\b/i.test(d) && /\bclient_id=/.test(d)

    if (!isOAuth) return null

    if (hasResponseTypeToken) {
        return {
            type: 'implicit_flow_abuse',
            confidence: 0.87,
            detail: 'Implicit flow: response_type=token (deprecated; token in fragment without PKCE)',
        }
    }

    if (hasFragmentToken && !hasResponseTypeCode) {
        return {
            type: 'implicit_flow_abuse',
            confidence: 0.87,
            detail: 'Token delivered in URL fragment without authorization code flow (implicit-like)',
        }
    }

    return null
}

// ── Public API ──────────────────────────────────────────────────────

/**
 * Run all OAuth theft / PKCE bypass detectors on input.
 * Returns array of detections for registry consumption.
 */
export function detectOAuthTheft(input: string): OAuthDetection[] {
    const out: OAuthDetection[] = []
    if (typeof input !== 'string' || input.length < 5) return out

    const fns: Array<() => OAuthDetection | null> = [
        () => detectAuthCodeInterception(input),
        () => detectPkceDowngradeAttack(input),
        () => detectOAuthMixupAttack(input),
        () => detectTokenLeakageViaReferrer(input),
        () => detectImplicitFlowAbuse(input),
    ]
    for (const fn of fns) {
        try {
            const r = fn()
            if (r) out.push(r)
        } catch { /* per-detector isolation */ }
    }
    return out
}

// ── Unit Tests ────────────────────────────────────────────────────

describe('oauth-theft-evaluator', () => {
    it('detectAuthCodeInterception: detects HTTP redirect_uri to external host', () => {
        const input = 'https://auth.example.com/oauth/authorize?response_type=code&client_id=app&redirect_uri=http://evil.com/callback'
        const r = detectAuthCodeInterception(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('auth_code_interception')
        expect(r!.confidence).toBe(0.93)
        expect(r!.detail).toMatch(/HTTP|interception|redirect_uri/i)
    })

    it('detectAuthCodeInterception: detects redirect_uri to IP address', () => {
        const input = 'oauth/authorize?response_type=code&client_id=x&redirect_uri=http://192.168.1.1/cb'
        const r = detectAuthCodeInterception(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('auth_code_interception')
        expect(r!.detail).toMatch(/IP|interception/i)
    })

    it('detectPkceDowngradeAttack: detects missing code_challenge with response_type=code', () => {
        const input = 'response_type=code&client_id=app&redirect_uri=https://app.example/callback'
        const r = detectPkceDowngradeAttack(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('pkce_downgrade')
        expect(r!.confidence).toBe(0.91)
        expect(r!.detail).toMatch(/code_challenge|downgrade/i)
    })

    it('detectPkceDowngradeAttack: detects code_challenge_method=plain', () => {
        const input = 'response_type=code&client_id=app&redirect_uri=https://app/cb&code_challenge=abc&code_challenge_method=plain'
        const r = detectPkceDowngradeAttack(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('pkce_downgrade')
        expect(r!.detail).toMatch(/plain|downgrade/i)
    })

    it('detectOAuthMixupAttack: detects missing state in auth request', () => {
        const input = 'https://idp.example/oauth/authorize?response_type=code&client_id=app&redirect_uri=https://app/cb'
        const r = detectOAuthMixupAttack(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('oauth_mixup')
        expect(r!.detail).toMatch(/state|missing|mix-up/i)
    })

    it('detectOAuthMixupAttack: detects predictable state value', () => {
        const input = 'oauth/authorize?response_type=code&client_id=app&redirect_uri=https://app/cb&state=1234'
        const r = detectOAuthMixupAttack(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('oauth_mixup')
        expect(r!.detail).toMatch(/predictable|trivial|state|mix-up/i)
    })

    it('detectTokenLeakageViaReferrer: detects access_token in query', () => {
        const input = 'https://app.example/callback?access_token=ya29.abcdefghijklmnopqrstuvwxyz123456'
        const r = detectTokenLeakageViaReferrer(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('token_leakage_referrer')
        expect(r!.confidence).toBe(0.92)
        expect(r!.detail).toMatch(/Referer|access_token|leakage/i)
    })

    it('detectTokenLeakageViaReferrer: detects access_token in fragment', () => {
        const input = 'https://app.example/cb#access_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.xxx&token_type=Bearer'
        const r = detectTokenLeakageViaReferrer(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('token_leakage_referrer')
        expect(r!.detail).toMatch(/fragment|Referer|leakage/i)
    })

    it('detectImplicitFlowAbuse: detects response_type=token', () => {
        const input = 'oauth/authorize?response_type=token&client_id=app&redirect_uri=https://app/cb'
        const r = detectImplicitFlowAbuse(input)
        expect(r).not.toBeNull()
        expect(r!.type).toBe('implicit_flow_abuse')
        expect(r!.confidence).toBe(0.87)
        expect(r!.detail).toMatch(/implicit|token|fragment|deprecated/i)
    })

    it('detectOAuthTheft aggregates all detectors and returns array', () => {
        const input = 'https://auth.example/oauth/authorize?response_type=code&client_id=app&redirect_uri=http://evil.com/cb'
        const all = detectOAuthTheft(input)
        expect(Array.isArray(all)).toBe(true)
        expect(all.length).toBeGreaterThanOrEqual(1)
        const types = new Set(all.map(a => a.type))
        expect(types.has('auth_code_interception')).toBe(true)
    })
})
