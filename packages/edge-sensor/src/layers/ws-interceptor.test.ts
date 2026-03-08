import { describe, expect, it } from 'vitest'
import { analyzeWebSocketMessage, analyzeWebSocketUpgrade } from './ws-interceptor.js'
import type { Env } from './types.js'

function makeEnv(overrides: Partial<Env> = {}): Env {
    return {
        SANTH_INGEST_URL: 'https://ingest.example.com',
        SIGNAL_BATCH_SIZE: '50',
        DEFENSE_MODE: 'monitor',
        SENSOR_STATE: {} as KVNamespace,
        SENSOR_ID: 'sensor-1',
        PROBE_ENABLED: 'false',
        SENSOR_API_KEY: 'test-api-key',
        ...overrides,
    }
}

describe('analyzeWebSocketUpgrade', () => {
    it('does not flag normal HTTP requests', () => {
        const request = new Request('https://app.example.com/api/users')
        const result = analyzeWebSocketUpgrade(request, makeEnv())

        expect(result.isWebSocketUpgrade).toBe(false)
        expect(result.shouldBlock).toBe(false)
        expect(result.matches).toEqual([])
    })

    it('blocks mismatched origin on websocket upgrade', () => {
        const request = new Request('https://app.example.com/socket', {
            headers: {
                Upgrade: 'websocket',
                Connection: 'Upgrade',
                Origin: 'https://evil.example',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            },
        })

        const result = analyzeWebSocketUpgrade(request, makeEnv())

        expect(result.isWebSocketUpgrade).toBe(true)
        expect(result.shouldBlock).toBe(true)
        expect(result.reasons).toContain('origin_mismatch')
        expect(result.matches.some(m => m.class === 'ws_hijack')).toBe(true)
    })

    it('blocks missing websocket key', () => {
        const request = new Request('https://app.example.com/socket', {
            headers: {
                Upgrade: 'websocket',
                Connection: 'Upgrade',
                Origin: 'https://app.example.com',
            },
        })

        const result = analyzeWebSocketUpgrade(request, makeEnv())

        expect(result.shouldBlock).toBe(true)
        expect(result.reasons).toContain('invalid_sec_websocket_key')
    })

    it('allows valid origin and valid websocket key', () => {
        const request = new Request('https://app.example.com/socket', {
            headers: {
                Upgrade: 'websocket',
                Connection: 'Upgrade',
                Origin: 'https://app.example.com',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Protocol': 'chat',
            },
        })

        const result = analyzeWebSocketUpgrade(request, makeEnv())

        expect(result.isWebSocketUpgrade).toBe(true)
        expect(result.shouldBlock).toBe(false)
        expect(result.matches.some(m => m.class === 'ws_hijack')).toBe(false)
    })

    it('allows configured alternate origin', () => {
        const request = new Request('https://app.example.com/socket', {
            headers: {
                Upgrade: 'websocket',
                Connection: 'Upgrade',
                Origin: 'https://chat.example.com',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            },
        })

        const result = analyzeWebSocketUpgrade(
            request,
            makeEnv({ WS_ALLOWED_ORIGINS: 'https://chat.example.com' }),
        )

        expect(result.shouldBlock).toBe(false)
    })

    it('blocks protocol injection attempts', () => {
        const request = new Request('https://app.example.com/socket', {
            headers: {
                Upgrade: 'websocket',
                Connection: 'Upgrade',
                Origin: 'https://app.example.com',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Protocol': 'chat,<script>alert(1)</script>',
            },
        })

        const result = analyzeWebSocketUpgrade(request, makeEnv())

        expect(result.shouldBlock).toBe(true)
        expect(result.reasons).toContain('ws_protocol_injection')
    })
})

describe('analyzeWebSocketMessage', () => {
    it('detects SQL injection payloads in JSON message fields', () => {
        const payload = JSON.stringify({ event: 'chat', message: "' OR 1=1--" })
        const result = analyzeWebSocketMessage(payload)

        expect(result.parsedJson).toBe(true)
        expect(result.matches.some(m => m.class === 'sql_tautology')).toBe(true)
    })

    it('detects XSS payloads in JSON message fields', () => {
        const payload = JSON.stringify({ action: 'update_profile', bio: '<script>alert(1)</script>' })
        const result = analyzeWebSocketMessage(payload)

        expect(result.parsedJson).toBe(true)
        expect(result.matches.some(m => m.class === 'xss_tag_injection')).toBe(true)
    })

    it('returns no matches for benign JSON payloads', () => {
        const payload = JSON.stringify({ jsonrpc: '2.0', method: 'ping', params: { room: 'general' }, id: 1 })
        const result = analyzeWebSocketMessage(payload)

        expect(result.parsedJson).toBe(true)
        expect(result.matches).toEqual([])
    })

    it('returns parsedJson=false for non-JSON payloads', () => {
        const result = analyzeWebSocketMessage('ping')
        expect(result.parsedJson).toBe(false)
        expect(result.matches).toEqual([])
    })
})
