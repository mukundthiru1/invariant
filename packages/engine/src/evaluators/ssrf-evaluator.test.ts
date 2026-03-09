import { describe, it, expect } from 'vitest'
import {
    detectSSRF,
    parseIPRepresentation,
    detectSsrfViaFileScheme,
    detectSsrfViaGopher,
    detectSsrfViaDict,
    detectSsrfViaLdapScheme,
} from './ssrf-evaluator.js'

describe('SSRF evaluator regressions', () => {
    it('parses shorthand IPv4 representations', () => {
        expect(parseIPRepresentation('127.1')).toBe(0x7f000001)
        expect(parseIPRepresentation('127.0.1')).toBe(0x7f000001)
        expect(parseIPRepresentation('10.1')).toBe(0x0a000001)
    })

    it('detects known DNS rebinding domains and aliases', () => {
        const payloads = [
            'http://localtest.me',
            'http://lvh.me',
            'http://yurets.dev',
            'http://1u.ms',
            'http://127-0-0-1.nip.io',
        ]

        for (const payload of payloads) {
            const detections = detectSSRF(payload)
            expect(detections.some(d => d.type === 'internal_reach')).toBe(true)
        }
    })

    it('detects full IPv6 loopback and mapped unspecified forms', () => {
        const payloads = [
            'http://[0000:0000:0000:0000:0000:0000:0000:0001]',
            'http://[::ffff:0:0]',
        ]

        for (const payload of payloads) {
            const detections = detectSSRF(payload)
            expect(detections.some(d => d.type === 'internal_reach')).toBe(true)
        }
    })

    it('detects missing wrapper protocols', () => {
        const payloads = [
            'php://filter/read=convert.base64-encode/resource=/etc/passwd',
            'expect://ls',
        ]

        for (const payload of payloads) {
            const detections = detectSSRF(payload)
            expect(detections.some(d => d.type === 'protocol_smuggle')).toBe(true)
        }
    })

    it('does not false-positive on benign URLs', () => {
        const benign = [
            'https://example.com',
            'https://api.github.com/repos',
            'https://localtest.media',
            'https://docs.php.net',
        ]

        for (const payload of benign) {
            expect(detectSSRF(payload)).toEqual([])
        }
    })

    it('detects file:// scheme SSRF for sensitive paths', () => {
        const r1 = detectSsrfViaFileScheme('file:///etc/passwd')
        expect(r1).not.toBeNull()
        expect(r1!.confidence).toBe(0.96)
        expect(r1!.detail).toContain('file://')
        const r2 = detectSsrfViaFileScheme('file:///proc/self/environ')
        expect(r2).not.toBeNull()
        expect(r2!.confidence).toBe(0.96)
        expect(detectSSRF('file:///etc/passwd').some(d => d.confidence === 0.96)).toBe(true)
    })

    it('detects gopher:// protocol SSRF', () => {
        const r = detectSsrfViaGopher('gopher://127.0.0.1:6379/_')
        expect(r).not.toBeNull()
        expect(r!.confidence).toBe(0.95)
        expect(r!.detail).toContain('Gopher')
        expect(detectSSRF('gopher://localhost:25/').some(d => d.type === 'protocol_smuggle')).toBe(true)
    })

    it('detects dict:// protocol SSRF', () => {
        const r = detectSsrfViaDict('dict://127.0.0.1:6379/info')
        expect(r).not.toBeNull()
        expect(r!.confidence).toBe(0.93)
        expect(r!.detail).toContain('dict')
        expect(detectSSRF('dict://localhost/').some(d => d.type === 'protocol_smuggle')).toBe(true)
    })

    it('detects ldap/ldaps scheme SSRF', () => {
        const r = detectSsrfViaLdapScheme('ldap://attacker.com/a')
        expect(r).not.toBeNull()
        expect(r!.confidence).toBe(0.91)
        expect(r!.detail).toContain('LDAP')
        const r2 = detectSsrfViaLdapScheme('ldaps://evil.com/')
        expect(r2).not.toBeNull()
        expect(r2!.confidence).toBe(0.91)
    })
})
