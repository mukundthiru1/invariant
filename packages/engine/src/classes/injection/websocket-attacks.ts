import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import {
    l2WebsocketOriginBypass,
    l2WebsocketMessageInjection,
    l2WebsocketDos,
} from '../../evaluators/l2-adapters.js'

const WS_UPGRADE_RE = /(?:^|\r?\n)\s*upgrade\s*:\s*websocket\b/i
const WS_HOST_RE = /(?:^|\r?\n)\s*host\s*:\s*([^\r\n]+)/i
const WS_ORIGIN_RE = /(?:^|\r?\n)\s*origin\s*:\s*([^\r\n]+)/i
const WS_ALLOW_ORIGIN_RE = /(?:^|\r?\n)\s*access-control-allow-origin\s*:\s*([^\r\n]+)/i
const WS_PROTO_POLLUTION_RE = /(?:"(?:__proto__|__defineGetter__|constructor|prototype)"\s*:\s*|\b(?:__proto__|__defineGetter__)\s*[:=]|\bconstructor\s*\.\s*prototype\b)/i
const WS_FRAME_SIZE_RE = /\b(?:payload(?:_|\s)?size|frame(?:_|\s)?size|frame(?:_|\s)?length|message(?:_|\s)?size|bytes|len)\s*[:=]\s*(\d{6,})\b/i
const WS_CONTENT_LEN_RE = /(?:^|\r?\n)\s*content-length\s*:\s*(\d{6,})\b/i

function countMaxDepth(input: string): number {
    let depth = 0
    let maxDepth = 0
    for (const ch of input) {
        if (ch === '{' || ch === '[') {
            depth++
            if (depth > maxDepth) maxDepth = depth
        } else if (ch === '}' || ch === ']') {
            depth = Math.max(0, depth - 1)
        }
    }
    return maxDepth
}

function isCrossOrigin(originHeader: string, hostHeader: string): boolean {
    const origin = originHeader.trim().toLowerCase()
    const host = hostHeader.trim().toLowerCase().replace(/^https?:\/\//, '')
    if (!origin.startsWith('http://') && !origin.startsWith('https://')) return false
    const originHost = origin.replace(/^https?:\/\//, '').split('/')[0]
    return originHost !== host
}

export const websocket_origin_bypass: InvariantClassModule = {
    id: 'websocket_origin_bypass',
    description: 'WebSocket Origin validation bypass via missing/wildcard Origin header or cross-origin upgrade without explicit CORS allowlist',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },

    mitre: ['T1190'],
    cwe: 'CWE-346',

    knownPayloads: [
        'GET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n',
        'GET /socket HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: *\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
        'GET /chat HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://evil.example\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
    ],

    knownBenign: [
        'GET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://app.example.com\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
        'GET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://api.example.com\r\nAccess-Control-Allow-Origin: https://api.example.com\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
        'GET /health HTTP/1.1\r\nHost: app.example.com\r\nConnection: keep-alive\r\n\r\n',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (!WS_UPGRADE_RE.test(d)) return false

        const originMatch = d.match(WS_ORIGIN_RE)
        const hostMatch = d.match(WS_HOST_RE)

        if (!originMatch) return true

        const originValue = originMatch[1].trim().toLowerCase()
        if (originValue === '*' || originValue === 'null') return true

        if (hostMatch && isCrossOrigin(originValue, hostMatch[1])) {
            const allowOrigin = d.match(WS_ALLOW_ORIGIN_RE)?.[1]?.trim().toLowerCase()
            if (!allowOrigin) return true
            if (!(allowOrigin === '*' || allowOrigin === originValue)) return true
        }

        return false
    },

    detectL2: l2WebsocketOriginBypass,

    generateVariants: (count: number): string[] => {
        const variants = [
            'GET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n',
            'GET /socket HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: *\r\n\r\n',
            'GET /chat HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://evil.example\r\n\r\n',
            'GET /stream HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: null\r\n\r\n',
            'GET /live HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://attacker.example\r\n\r\n',
        ]
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}

export const websocket_message_injection: InvariantClassModule = {
    id: 'websocket_message_injection',
    description: 'WebSocket message injection with JSON prototype pollution primitives such as __proto__ and __defineGetter__',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.94 },

    mitre: ['T1190'],
    cwe: 'CWE-1321',

    knownPayloads: [
        '{"type":"ws_message","payload":{"__proto__":{"isAdmin":true}}}',
        '{"event":"sync","patch":{"__defineGetter__":"toString","value":"pwn"}}',
        '{"ws":true,"payload":"constructor.prototype.pwned=true"}',
    ],

    knownBenign: [
        '{"type":"ws_message","payload":{"text":"hello"}}',
        '{"event":"chat","payload":{"user":"alice","message":"prototype discussion"}}',
        '{"jsonrpc":"2.0","method":"ping","params":{"room":"general"},"id":1}',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const wsLike = /(?:websocket|ws[_-]?(?:message|frame)|"type"\s*:\s*"ws_message"|"event"\s*:)/i.test(d) || /\{[\s\S]*\}/.test(d)
        if (!wsLike) return false

        if (WS_PROTO_POLLUTION_RE.test(d)) return true

        if (/\\u005f\\u005fproto\\u005f\\u005f/i.test(d) || /\\x5f\\x5fproto\\x5f\\x5f/i.test(d)) return true

        return false
    },

    detectL2: l2WebsocketMessageInjection,

    generateVariants: (count: number): string[] => {
        const variants = [
            '{"type":"ws_message","payload":{"__proto__":{"isAdmin":true}}}',
            '{"type":"ws_message","payload":{"constructor":{"prototype":{"polluted":1}}}}',
            '{"event":"sync","patch":{"__defineGetter__":"toString","value":"evil"}}',
            '{"ws":true,"payload":"constructor.prototype.pwned=true"}',
            '{"ws":true,"payload":{"nested":[{"__proto__":{"debug":true}}]}}',
            '{"ws":true,"payload":"\\u005f\\u005fproto\\u005f\\u005f": {"admin": true}',
        ]
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}

export const websocket_dos: InvariantClassModule = {
    id: 'websocket_dos',
    description: 'WebSocket denial-of-service via extremely large frames, rapid reconnect loops, or ping flood traffic',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.82 },

    mitre: ['T1499'],
    cwe: 'CWE-400',

    knownPayloads: [
        'websocket frame_size=2097152 opcode=text payload=' + 'A'.repeat(128),
        'GET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nGET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nGET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nGET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n',
        'ping ping ping ping ping ping ping ping ping ping ping ping ping ping ping ping ping ping ping ping ping ping ping ping ping',
    ],

    knownBenign: [
        'GET /ws HTTP/1.1\r\nHost: app.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n',
        'websocket frame_size=2048 opcode=text payload=hello',
        'ping\npong\nping\npong',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        const sizeMatch = d.match(WS_FRAME_SIZE_RE) ?? d.match(WS_CONTENT_LEN_RE)
        if (sizeMatch && Number.parseInt(sizeMatch[1], 10) >= 1_000_000) return true

        const reconnectCount = (d.match(/(?:GET\s+\/[^\r\n\s]*\s+HTTP\/1\.1[\s\S]{0,180}?Upgrade\s*:\s*websocket)/gi) || []).length
        if (reconnectCount >= 4) return true

        const pingCount = (d.match(/\bping\b/gi) || []).length
        if (pingCount >= 20) return true

        const depth = countMaxDepth(d)
        if (depth > 40 && /websocket|ws[_-]?(?:message|frame)/i.test(d)) return true

        return false
    },

    detectL2: l2WebsocketDos,

    generateVariants: (count: number): string[] => {
        const variants = [
            'websocket frame_size=2097152 opcode=text payload=' + 'A'.repeat(64),
            'websocket payload_size=3145728 compressed=false',
            'GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nGET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nGET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nGET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n',
            'ping '.repeat(25).trim(),
            'websocket frame_length=5000000 opcode=binary',
            'websocket bytes=2500000 reconnect=true reconnect=true reconnect=true reconnect=true',
        ]
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}
