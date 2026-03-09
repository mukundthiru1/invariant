import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

const PRIVILEGED_FIELDS = [
    'role',
    'admin',
    'isadmin',
    '_isadmin',
    'isowner',
    'issuperuser',
    'privilege',
    'candelete',
]

const SAFE_WS_PROTOCOLS = new Set(['chat', 'json', 'graphql-ws', 'wamp', 'mqtt'])

function collectFieldKeys(decoded: string): string[] {
    const keys: string[] = []

    for (const match of decoded.matchAll(/"([^"\\]{1,64})"\s*:/g)) {
        keys.push(match[1].toLowerCase())
    }

    for (const match of decoded.matchAll(/(?:^|[?&,\s])([A-Za-z_][A-Za-z0-9_\-]{0,63})\s*=/g)) {
        keys.push(match[1].toLowerCase())
    }

    return keys
}

function hasPrivilegedField(keys: string[]): boolean {
    return keys.some((key) => {
        const normalized = key.replace(/[^a-z]/g, '')
        return PRIVILEGED_FIELDS.includes(normalized)
    })
}

function hasCompanionBusinessField(keys: string[]): boolean {
    return keys.some((key) => {
        const normalized = key.toLowerCase()
        return !PRIVILEGED_FIELDS.includes(normalized.replace(/[^a-z]/g, ''))
            && /(name|email|user(id)?|quantity|qty|color|title|phone|address|profile|amount|price|total)/i.test(normalized)
    })
}

function extractNumericAssignments(decoded: string): Array<{ key: string; value: number }> {
    const out: Array<{ key: string; value: number }> = []

    for (const m of decoded.matchAll(/"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*(-?\d+(?:\.\d+)?)/g)) {
        const value = Number.parseFloat(m[2])
        if (!Number.isNaN(value)) out.push({ key: m[1].toLowerCase(), value })
    }

    for (const m of decoded.matchAll(/(?:^|[?&\s,])([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?\d+(?:\.\d+)?)/g)) {
        const value = Number.parseFloat(m[2])
        if (!Number.isNaN(value)) out.push({ key: m[1].toLowerCase(), value })
    }

    return out
}

function hasSequentialRun(values: number[]): boolean {
    if (values.length < 2) return false
    for (let i = 1; i < values.length; i++) {
        if (values[i] === values[i - 1] + 1) return true
    }
    return false
}

export const massAssignment: InvariantClassModule = {
    id: 'mass_assignment',
    description: 'Over-posting / mass assignment via privileged fields mixed into otherwise normal input objects',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.87 },
    mitre: ['T1068'],
    cwe: 'CWE-915',
    knownPayloads: [
        '{"isAdmin":true,"role":"admin","__proto__":{"admin":true}}',
        '{"userId":1,"_isAdmin":1}',
        '{"name":"alice","email":"a@b.com","isOwner":true,"privilege":"all"}',
    ],
    knownBenign: [
        '{"name":"John","email":"j@j.com"}',
        '{"quantity":2,"color":"red"}',
        '{"title":"profile update","phone":"555-0100"}',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        const keys = collectFieldKeys(decoded)
        if (keys.length === 0) return false

        if (/"__proto__"\s*:\s*\{[^}]*"admin"\s*:\s*(?:true|1)/i.test(decoded)) return true

        const privileged = hasPrivilegedField(keys)
        if (!privileged) return false

        return hasCompanionBusinessField(keys)
            || /"(?:role|admin|privilege|isAdmin|isOwner|isSuperuser|canDelete)"\s*:/i.test(decoded)
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            '{"isAdmin":true,"role":"admin","__proto__":{"admin":true}}',
            '{"userId":1,"_isAdmin":1}',
            '{"name":"alice","email":"a@b.com","isOwner":true,"privilege":"all"}',
            'name=alice&email=a%40b.com&canDelete=true',
        ]
        return variants.slice(0, count)
    },
}

export const priceManipulation: InvariantClassModule = {
    id: 'price_manipulation',
    description: 'Business-logic price tampering using negative/zero/tiny monetary values or invalid discount amplification',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1565'],
    cwe: 'CWE-840',
    knownPayloads: [
        'price=-1&quantity=1',
        '{"price":0.001,"total":-99.99}',
        'price=0&discount=100',
        '{"amount":-1000}',
        'price=1&discount=250',
    ],
    knownBenign: [
        '{"price":29.99,"qty":2}',
        'price=49.99',
        '{"amount":19.95,"fee":2.5}',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        const assignments = extractNumericAssignments(decoded)
        if (assignments.length === 0) return false

        for (const a of assignments) {
            if (/(price|amount|total|cost|fee)/.test(a.key) && (a.value <= 0 || (a.value > 0 && a.value < 0.01))) {
                return true
            }
            if (a.key === 'discount' && a.value > 100) {
                return true
            }
        }

        return false
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'price=-1&quantity=1',
            '{"price":0.001,"total":-99.99}',
            'price=0&discount=100',
            '{"amount":-1000}',
            'price=1&discount=250',
        ]
        return variants.slice(0, count)
    },
}

export const idorParameterProbe: InvariantClassModule = {
    id: 'idor_parameter_probe',
    description: 'IDOR probing through sequential identifier guessing, ID parameter traversal, and dangerous endpoint targeting',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.88 },
    mitre: ['T1087', 'T1190'],
    cwe: 'CWE-639',
    knownPayloads: [
        '/api/users/1,/api/users/2',
        '?userId=../admin',
        '/account/1337/delete',
        '?id=0&id=1&id=2',
    ],
    knownBenign: [
        '/api/users/me',
        '/api/profile',
        '/api/orders',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)

        if (/[?&](?:id|userId|accountId|profileId)\s*=\s*\.\.\/(?:admin|root|delete|export)/i.test(decoded)) {
            return true
        }

        if (/\/(?:account|user|users|admin)\/\d+\/(?:delete|export|admin)\b/i.test(decoded)) {
            return true
        }

        const repeatedIdParams = Array.from(decoded.matchAll(/[?&](id|userId|accountId)=(-?\d+)/gi))
        if (repeatedIdParams.length >= 2) {
            const nums = repeatedIdParams
                .map((m) => Number.parseInt(m[2], 10))
                .filter((n) => !Number.isNaN(n))
                .sort((a, b) => a - b)
            if (hasSequentialRun(nums)) return true
        }

        const pathIds = Array.from(decoded.matchAll(/\/(?:api\/)?(?:users?|accounts?|orders?|profiles?|records?|items?)\/(\d+)\b/gi))
            .map((m) => Number.parseInt(m[1], 10))
            .filter((n) => !Number.isNaN(n))
            .sort((a, b) => a - b)
        if (hasSequentialRun(pathIds)) return true

        return false
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            '/api/users/1,/api/users/2',
            '?userId=../admin',
            '/account/1337/delete',
            '?id=0&id=1&id=2',
        ]
        return variants.slice(0, count)
    },
}

export const http2HeaderInjection: InvariantClassModule = {
    id: 'http2_header_injection',
    description: 'HTTP/2 pseudo-header injection and smuggling via duplicate pseudo-headers, null bytes, or injected authority values',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.89 },
    mitre: ['T1557'],
    cwe: 'CWE-444',
    knownPayloads: [
        ':method=CONNECT :path=/admin%0d%0ax-injected:1',
        ':path=/api\x00/users',
        ':authority=example.com\r\nX-Evil: 1',
        ':path=/a :path=/b',
    ],
    knownBenign: [
        ':method=GET :path=/api/v1/users',
        ':scheme=https :authority=api.example.com :path=/health',
        ':method=POST :path=/api/orders',
    ],
    detect: (input: string): boolean => {
        const raw = input
        const decoded = deepDecode(input)

        if (raw.includes('\u0000') || /\\x00|\\u0000|%00/i.test(raw)) return true
        if (/:path\s*[=:][^\r\n]*(?:%0d|%0a|\\r|\\n)/i.test(raw)) return true

        if (decoded.includes('\u0000') || /\x00|\u0000/.test(decoded)) return true
        if (/:[a-z]+\s*[=:][^\r\n]*(?:\\x00|%00)/i.test(decoded)) return true
        if (/:path\s*[=:][^\r\n]*(?:\r|\n)/i.test(decoded)) return true

        const pseudoMatches = Array.from(decoded.matchAll(/(^|\s|\r|\n)(:path|:method|:scheme|:authority)\s*[=:]/gi))
        const seen = new Map<string, number>()
        for (const m of pseudoMatches) {
            const key = m[2].toLowerCase()
            seen.set(key, (seen.get(key) ?? 0) + 1)
            if ((seen.get(key) ?? 0) > 1) return true
        }

        if (/:authority\s*[=:]\s*[^\r\n]*(?:\r|\n|%0d|%0a|[<>])/i.test(decoded)) return true

        return false
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            ':method=CONNECT :path=/admin%0d%0ax-injected:1',
            ':path=/api\\x00/users',
            ':authority=example.com\\r\\nX-Evil: 1',
            ':path=/a :path=/b',
        ]
        return variants.slice(0, count)
    },
}

export const websocketProtocolConfusion: InvariantClassModule = {
    id: 'websocket_protocol_confusion',
    description: 'WebSocket protocol confusion via subprotocol smuggling, prototype-bearing messages, or credential-injected ws URLs',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.86 },
    mitre: ['T1185', 'T1557'],
    cwe: 'CWE-436',
    knownPayloads: [
        'Upgrade: websocket\r\nSec-WebSocket-Protocol: chat, http',
        '{"type":"__proto__","payload":{"admin":true}}',
        'ws://admin:secret@victim.internal/socket',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
    ],
    knownBenign: [
        'Upgrade: websocket',
        '{"type":"message","text":"hello"}',
        'wss://example.com/realtime',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)

        const protocolHeader = decoded.match(/Sec-WebSocket-Protocol\s*:\s*([^\r\n]+)/i)
        if (protocolHeader) {
            const protocols = protocolHeader[1].split(',').map((p) => p.trim().toLowerCase()).filter(Boolean)
            if (protocols.length > 1 && protocols.some((p) => p.startsWith('http') || p.includes('/') || !SAFE_WS_PROTOCOLS.has(p))) {
                return true
            }
        }

        if (/"(?:__proto__|constructor)"\s*:/i.test(decoded)) return true
        if (/"(?:type|event|action)"\s*:\s*"__proto__"/i.test(decoded)) return true
        if (/\"__proto__\"/i.test(decoded) && /\"payload\"|\"prototype\"/i.test(decoded)) return true
        if (/\bws:\/\/[^\s/@]+(?::[^\s/@]+)?@[^\s/]+/i.test(decoded)) return true

        return false
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'Upgrade: websocket\\r\\nSec-WebSocket-Protocol: chat, http',
            '{"type":"__proto__","payload":{"admin":true}}',
            'ws://admin:secret@victim.internal/socket',
            '{"constructor":{"prototype":{"isAdmin":true}}}',
        ]
        return variants.slice(0, count)
    },
}
