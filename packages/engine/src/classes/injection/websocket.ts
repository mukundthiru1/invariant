/**
 * WebSocket-specific threat classes:
 * - Injection payloads inside WS message frames
 * - WebSocket hijacking (CSWSH) via unsafe upgrade requests
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2WsInjection, l2WsHijack } from '../../evaluators/l2-adapters.js'

const SQLI_IN_WS = /(?:'\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|union\s+(?:all\s+)?select|;\s*(?:drop|delete|insert|update|alter|create|exec|execute)|(?:sleep|pg_sleep|benchmark)\s*\()/i
const XSS_IN_WS = /(?:<script[\s>]|javascript\s*:|\bon(?:error|load|click|mouseover|focus|blur|submit|change|input)\s*=)/i
const CMDI_IN_WS = /(?:[;|`]\s*(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc|ncat|bash|sh|python|perl|ruby|php)\b|\$\([^)]*(?:id|whoami|cat|curl|wget|bash|sh|python)[^)]*\))/i

export const ws_injection: InvariantClassModule = {
    id: 'ws_injection',
    description: 'WebSocket frame injection — SQL/XSS/command payloads hidden inside JSON WS messages over persistent connections',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.84 },

    mitre: ['T1190'],
    cwe: 'CWE-20',

    knownPayloads: [
        '{"event":"chat","message":"\' OR 1=1--"}',
        '{"type":"update","bio":"<script>alert(1)</script>"}',
    ],

    knownBenign: [
        '{"event":"chat","message":"hello team"}',
        '{"jsonrpc":"2.0","method":"ping","params":{"room":"general"},"id":1}',
        'plain websocket heartbeat',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const looksLikeWsMessage = /\{[\s\S]*\}/.test(d) || /(?:websocket|ws[_-]?(?:message|frame))/i.test(d)
        if (!looksLikeWsMessage) return false
        return SQLI_IN_WS.test(d) || XSS_IN_WS.test(d) || CMDI_IN_WS.test(d)
    },

    detectL2: l2WsInjection,

    generateVariants: (count: number): string[] => {
        const variants = [
            '{"event":"chat","message":"\' OR 1=1--"}',
            '{"event":"search","query":"UNION SELECT username,password FROM users"}',
            '{"type":"profile","bio":"<img src=x onerror=alert(1)>"}',
            '{"action":"run","cmd":"$(id)"}',
        ]
        return variants.slice(0, count)
    },
}

export const ws_hijack: InvariantClassModule = {
    id: 'ws_hijack',
    description: 'WebSocket hijacking (CSWSH) — unsafe upgrade handling with missing Origin validation or malformed key exchange',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },

    mitre: ['T1539'],
    cwe: 'CWE-1385',

    knownPayloads: [
        'GET /socket HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://evil.example\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n',
        'GET /socket HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://evil.example\r\n',
    ],

    knownBenign: [
        'GET /socket HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://app.example.com\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n',
        'GET /chat HTTP/1.1\r\nHost: app.example.com\r\nConnection: keep-alive\r\n',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const hasWsUpgrade = /(?:^|\n)\s*upgrade\s*:\s*websocket\b/i.test(d)
        if (!hasWsUpgrade) return false

        const suspiciousOrigin = /(?:^|\n)\s*origin\s*:\s*(?:null|https?:\/\/(?:evil|attacker|malicious|phish|exploit)[^\s\r\n]*)/i.test(d)
        const missingKey = !/(?:^|\n)\s*sec-websocket-key\s*:/i.test(d)
        const injectedProtocol = /(?:^|\n)\s*sec-websocket-protocol\s*:.*(?:<script|union\s+select|\$\(|;\s*(?:drop|curl|bash))/i.test(d)

        return suspiciousOrigin || missingKey || injectedProtocol
    },

    detectL2: l2WsHijack,

    generateVariants: (count: number): string[] => {
        const variants = [
            'GET /socket HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nOrigin: https://evil.example\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n',
            'GET /socket HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nOrigin: https://evil.example\r\n',
            'GET /socket HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nOrigin: null\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n',
            'GET /socket HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nOrigin: https://app.example.com\r\nSec-WebSocket-Protocol: chat,<script>alert(1)</script>\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n',
        ]
        return variants.slice(0, count)
    },
}
