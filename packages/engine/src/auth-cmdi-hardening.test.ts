import { describe, it, expect } from 'vitest'

import {
    authNoneAlgorithm,
    jwtWeakHmacSecret,
    jwtMissingExpiry,
    jwtPrivilegeEscalation,
    oauthStateMissing,
    sessionFixation,
} from './classes/auth/index.js'
import { cmdSeparator, cmdSubstitution, cmdArgumentInjection } from './classes/cmdi/index.js'
import { detectCmdInjection } from './evaluators/cmd-injection-evaluator.js'


describe('Auth hardening coverage', () => {
    it('detects alg=none in bearer token context', () => {
        const payload = 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ.'
        expect(authNoneAlgorithm.detect(payload)).toBe(true)
        expect(authNoneAlgorithm.detectL2?.(payload)?.detected).toBe(true)
    })

    it('detects weak JWT HMAC secret usage', () => {
        const payload = 'jwt.sign(payload, "secret", { algorithm: "HS256" })'
        expect(jwtWeakHmacSecret.detect(payload)).toBe(true)
        expect(jwtWeakHmacSecret.detectL2?.(payload)?.detected).toBe(true)
    })

    it('detects replayable JWTs with missing exp', () => {
        const payload = 'jwt.sign({ sub: "123", iat: 1710000000 }, secret, { algorithm: "HS256" })'
        expect(jwtMissingExpiry.detect(payload)).toBe(true)
        expect(jwtMissingExpiry.detectL2?.(payload)?.detected).toBe(true)
    })

    it('detects privilege escalation claim tampering', () => {
        const payload = 'tamper JWT payload: {"sub":"42","role":"admin"}'
        expect(jwtPrivilegeEscalation.detect(payload)).toBe(true)
        expect(jwtPrivilegeEscalation.detectL2?.(payload)?.detected).toBe(true)
    })

    it('detects OAuth auth flow without state parameter', () => {
        const payload = 'https://accounts.example.com/oauth/authorize?response_type=code&client_id=abc123&redirect_uri=https://app.example/callback'
        expect(oauthStateMissing.detect(payload)).toBe(true)
        expect(oauthStateMissing.detectL2?.(payload)?.detected).toBe(true)
    })

    it('detects session fixation patterns in auth flow URLs', () => {
        const payload = '/login?sessionid=attackerfixed12345&next=/dashboard'
        expect(sessionFixation.detect(payload)).toBe(true)
        expect(sessionFixation.detectL2?.(payload)?.detected).toBe(true)
    })
})


describe('CMDi hardening coverage', () => {
    it('detects separator chain with tab-separated arguments', () => {
        expect(cmdSeparator.detect('; ls \t-la')).toBe(true)
    })

    it('detects backtick execution payloads', () => {
        expect(cmdSubstitution.detect('`whoami`')).toBe(true)
    })

    it('detects newline command chaining', () => {
        expect(cmdSeparator.detect('\n whoami')).toBe(true)
    })

    it('detects separator operators ; | && ||', () => {
        expect(cmdSeparator.detect('; id')).toBe(true)
        expect(cmdSeparator.detect('| cat /etc/passwd')).toBe(true)
        expect(cmdSeparator.detect('&& whoami')).toBe(true)
        expect(cmdSeparator.detect('|| uname -a')).toBe(true)
    })

    it('detects environment mutation injection payloads', () => {
        expect(cmdSubstitution.detect('PATH=/tmp/evil:$PATH whoami')).toBe(true)
        const l2 = detectCmdInjection('PATH=/tmp/evil:$PATH whoami')
        expect(l2.some(d => d.type === 'structural' && d.separator === 'env-assign')).toBe(true)
    })

    it('detects null-byte bypass payloads in shell context', () => {
        expect(cmdSeparator.detect('; id\\x00')).toBe(true)
        const l2 = detectCmdInjection('; id\\x00')
        expect(l2.some(d => d.type === 'structural' && d.separator === 'null-byte')).toBe(true)
    })

    it('detects glob wildcard path execution obfuscation', () => {
        const l2 = detectCmdInjection('/???/??t /etc/passwd')
        expect(l2.some(d => d.type === 'glob_path')).toBe(true)
    })

    it('detects dangerous argument injection forms', () => {
        expect(cmdArgumentInjection.detect('--option=evil')).toBe(true)
        expect(cmdArgumentInjection.detect('--config=../../tmp/evil.conf')).toBe(true)
    })
})
