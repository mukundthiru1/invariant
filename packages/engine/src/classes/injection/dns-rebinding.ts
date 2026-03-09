/**
 * dns-rebinding — DNS rebinding indicators in network policy and request context
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { safeRegexMatchAll, safeRegexTest } from './regex-safety.js'

const TTL_REBIND_RE = /\b(?:TTL|time-to-live)\s*[:=]\s*(?:0|1)\b/i
const PRIVATE_IP_RE =
    /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)\b/g
const LOCAL_TARGET_RE = /(?:fetch|XMLHttpRequest|XHR|axios\.(?:get|post)|request\(|HttpWebRequest|curl|wget)\b[^\n\r]{0,180}?(?:https?:\/\/)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})/i
const REBIND_SERVICE_RE = /(?:1u\.ms|rbndr\.us|nip\.io)/i
const HOSTNAME_A_RECORD_RE = /([A-Za-z0-9.-]+(?:\.[A-Za-z0-9.-]+)*)\s+(?:\d+\s+)?IN\s+A\s+(\b(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\b)/gi
const DNS_CONTEXT_RE = /\b(?:dns|dig|nslookup|lookup|A\s+record|ttl|1u\.ms|rbndr\.us|nip\.io)\b/i
const LOCAL_ORIGIN_RE = /(?:^|\r?\n)\s*Origin\s*:\s*https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)/i

const ipToIntOctets = (ip: string): number[] => ip.split('.').map((part) => Number.parseInt(part, 10))

const isPrivateIp = (ip: string): boolean => {
    const [a, b] = ipToIntOctets(ip)
    if (![a, b].every(Number.isFinite)) return false

    if (a === 127 || a === 10) return true
    if (a === 192 && b === 168) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 0 && b === 0) return true

    return false
}

const isPublicIPv4 = (ip: string): boolean => {
    const parts = ipToIntOctets(ip)
    return parts.length === 4 && parts.every((part) => Number.isFinite(part)) && !isPrivateIp(ip)
}

const hasLowTTLValue = (decoded: string): boolean => safeRegexTest(TTL_REBIND_RE, decoded)

const hasMixedARecordTargetsForHostname = (decoded: string): boolean => {
    const state = new Map<string, { private: boolean; public: boolean }>()
    const matches = safeRegexMatchAll(HOSTNAME_A_RECORD_RE, decoded) ?? []

    for (const match of matches) {
        const hostname = (match[1] ?? '').toLowerCase()
        const ip = match[2] ?? ''
        if (!hostname || !ip) continue

        const entry = state.get(hostname) ?? { private: false, public: false }
        if (isPrivateIp(ip)) entry.private = true
        if (isPublicIPv4(ip)) entry.public = true
        state.set(hostname, entry)
    }

    for (const { private: hasPrivate, public: hasPublic } of state.values()) {
        if (hasPrivate && hasPublic) return true
    }

    return false
}

const hasLocalIpInExternalDnsContext = (decoded: string): boolean => {
    const hasLocalIp = safeRegexTest(PRIVATE_IP_RE, decoded)
    return hasLocalIp && safeRegexTest(DNS_CONTEXT_RE, decoded)
}

const hasRebindingServiceDomain = (decoded: string): boolean => {
    if (!safeRegexTest(REBIND_SERVICE_RE, decoded)) return false
    return /(?:\/(?:127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)|\s|$)/i.test(decoded) || /\brebind\b/i.test(decoded)
}

const hasLocalHostnameRequestFromRemoteOrigin = (decoded: string): boolean => {
    const nonLocalOrigin = !safeRegexTest(LOCAL_ORIGIN_RE, decoded)
    if (!nonLocalOrigin) return false

    const localTarget = safeRegexTest(LOCAL_TARGET_RE, decoded)
    const hasPrivateIpTarget = safeRegexTest(PRIVATE_IP_RE, decoded)
    return localTarget || hasPrivateIpTarget
}

export const dnsRebinding: InvariantClassModule = {
    id: 'dns_rebinding',
    description: 'DNS rebinding indicators: low TTL records, mixed A records, and private-target fetch/XHR patterns',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.9 },

    mitre: ['T1557.002'],
    cwe: 'CWE-350',

    knownPayloads: [
        'TTL: 1\n192.168.1.1',
        'fetch("http://192.168.0.1")',
        '1u.ms/127.0.0.1',
        'rbndr.us local rebind',
        '0.0.0.0:8080',
        'TTL=0 A 10.0.0.1',
    ],

    knownBenign: [
        'TTL: 3600',
        'fetch("https://api.example.com")',
        'A record: 203.0.113.5',
        'DNS lookup timeout',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        if (hasLowTTLValue(d)) return true
        if (hasMixedARecordTargetsForHostname(d)) return true
        if (hasLocalIpInExternalDnsContext(d)) return true
        if (hasRebindingServiceDomain(d)) return true
        if (hasLocalHostnameRequestFromRemoteOrigin(d)) return true

        return false
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            'TTL: 1',
            'TTL: 0\n192.168.1.1',
            'fetch("http://192.168.0.1")',
            '1u.ms/127.0.0.1',
            'rbndr.us/local',
            '0.0.0.0:8080',
            'TTL=0 A 10.0.0.1',
        ]

        return variants.slice(0, count)
    },
}
