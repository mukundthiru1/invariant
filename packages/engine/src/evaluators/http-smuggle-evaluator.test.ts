import { describe, it, expect } from 'vitest'
import {
    detectChunkedTrailerInjection,
    detectHttpSmuggle,
    detectObfuscatedContentLength,
    detectPipelinedRequestPoisoning,
    detectRequestTunnelingAbuse,
} from './http-smuggle-evaluator.js'

describe('HTTP smuggling advanced detections', () => {
    it('flags h2c upgrade smuggling via Upgrade and Connection headers', () => {
        const payload = [
            'GET /chat HTTP/1.1',
            'Host: example.com',
            'Upgrade: h2c',
            'Connection: Upgrade',
            '',
            '',
        ].join('\r\n')

        const detections = detectHttpSmuggle(payload)
        expect(detections.some(d => d.type === 'h2c_upgrade_smuggling')).toBe(true)
        expect(detections.find(d => d.type === 'h2c_upgrade_smuggling')?.confidence).toBe(0.91)
    })

    it('does not flag unrelated Upgrade headers as h2c smuggling', () => {
        const payload = [
            'GET /chat HTTP/1.1',
            'Host: example.com',
            'Upgrade: websocket',
            'Connection: keep-alive',
            '',
            '',
        ].join('\r\n')

        expect(detectHttpSmuggle(payload).some(d => d.type === 'h2c_upgrade_smuggling')).toBe(false)
    })

    it('detects chunked trailer header injection', () => {
        const payload = [
            'POST /upload HTTP/1.1',
            'Host: example.com',
            'Transfer-Encoding: chunked',
            '',
            '4',
            'test',
            '0',
            'X-Injected: 1',
            'X-Extra: smuggled',
            '',
            '',
        ].join('\r\n')

        expect(detectHttpSmuggle(payload).some(d => d.type === 'chunked_trailer_injection')).toBe(true)
        expect(detectChunkedTrailerInjection(payload)?.type).toBe('chunked_trailer_injection')
    })

    it('does not flag valid chunked terminator without injected trailer headers', () => {
        const payload = [
            'POST /upload HTTP/1.1',
            'Host: example.com',
            'Transfer-Encoding: chunked',
            '',
            '4',
            'test',
            '0',
            '',
            '',
        ].join('\r\n')

        expect(detectHttpSmuggle(payload).some(d => d.type === 'chunked_trailer_injection')).toBe(false)
        expect(detectChunkedTrailerInjection(payload)).toBe(null)
    })

    it('detects obfuscated hex Content-Length values', () => {
        const payload = [
            'POST /admin HTTP/1.1',
            'Host: example.com',
            'Content-Length: 0x10',
            '',
            '',
        ].join('\r\n')

        expect(detectHttpSmuggle(payload).some(d => d.type === 'obfuscated_content_length')).toBe(true)
        expect(detectObfuscatedContentLength(payload)?.confidence).toBe(0.92)
    })

    it('detects non-integer decimal Content-Length obfuscation', () => {
        const payload = [
            'POST /admin HTTP/1.1',
            'Host: example.com',
            'Content-Length: 16.0',
            '',
            '',
        ].join('\r\n')

        expect(detectHttpSmuggle(payload).some(d => d.type === 'obfuscated_content_length')).toBe(true)
        expect(detectObfuscatedContentLength(payload)?.type).toBe('obfuscated_content_length')
    })

    it('detects duplicate Content-Length headers with conflicting values', () => {
        const payload = [
            'POST /admin HTTP/1.1',
            'Host: example.com',
            'Content-Length: 16',
            'Content-Length: 17',
            '',
            '',
        ].join('\r\n')

        expect(detectHttpSmuggle(payload).some(d => d.type === 'obfuscated_content_length')).toBe(true)
        expect(detectObfuscatedContentLength(payload)?.detail.includes('duplicate')).toBe(true)
    })

    it('detects request tunneling abuse from Host header embedded HTTP/1 payload', () => {
        const payload = [
            'GET /index HTTP/2',
            'Host: safe.internal',
            'X-Proxy: enabled',
            'GET /admin HTTP/1.1',
            'Host: shadow.internal',
            '',
            '',
        ].join('\r\n')

        expect(detectHttpSmuggle(payload).some(d => d.type === 'request_tunneling_abuse')).toBe(true)
        expect(detectRequestTunnelingAbuse(payload)?.confidence).toBe(0.89)
    })

    it('detects CONNECT tunneling abuse for request smuggling', () => {
        const payload = [
            'GET / HTTP/2',
            'Host: safe.internal',
            'X-Trace: on',
            'CONNECT tunnel.internal:443 HTTP/1.1',
            'Host: secure.internal',
            '',
            '',
        ].join('\r\n')

        expect(detectHttpSmuggle(payload).some(d => d.type === 'request_tunneling_abuse')).toBe(true)
        expect(detectRequestTunnelingAbuse(payload)?.type).toBe('request_tunneling_abuse')
    })

    it('detects pipelined request poisoning with malformed boundaries', () => {
        const payload = [
            'GET /a HTTP/1.1',
            'Host: a.internal',
            '',
            'POST /b HTTP/1.1',
            'Host: b.internal',
            '',
        ].join('\n')

        expect(detectHttpSmuggle(payload).some(d => d.type === 'pipelined_request_poisoning')).toBe(true)
        expect(detectPipelinedRequestPoisoning(payload)?.type).toBe('pipelined_request_poisoning')
    })

    it('flags legacy chunked-body abuse still present', () => {
        const payload = [
            'POST /chunks HTTP/1.1',
            'Host: example.com',
            'Transfer-Encoding: chunked',
            '',
            '0',
            '',
            'GET /admin HTTP/1.1',
            'Host: example.com',
            '',
            '',
        ].join('\r\n')

        expect(detectHttpSmuggle(payload).some(d => d.type === 'chunked_body')).toBe(true)
    })
})
