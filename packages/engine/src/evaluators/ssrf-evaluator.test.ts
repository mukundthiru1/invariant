import { describe, it, expect } from 'vitest'
import { detectSSRF, parseIPRepresentation } from './ssrf-evaluator.js'

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
})
