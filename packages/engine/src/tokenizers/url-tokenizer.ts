/**
 * URL Tokenizer — SSRF Detection
 *
 * Tokenizes input as a URL to detect SSRF patterns:
 *   - Scheme identification (http, https, ftp, gopher, file, data)
 *   - Authority parsing (host, port, userinfo)
 *   - Internal/private IP detection (127.0.0.1, 169.254.169.254, 10.x, etc.)
 *   - Cloud metadata endpoint detection (metadata.google, 169.254.169.254)
 *   - IP obfuscation (hex, octal, decimal, IPv6 mapped)
 *   - DNS rebinding indicators (0.0.0.0, [::])
 *
 * SSRF detection becomes: "does the token stream contain a SCHEME token
 * followed by an INTERNAL_HOST or METADATA_HOST?" rather than matching
 * regex patterns against known IP addresses.
 */

import type { Token, Tokenizer, TokenStream } from './types.js'
import { MAX_TOKENIZER_INPUT, MAX_TOKEN_COUNT } from './types.js'
import { TokenStream as TS } from './types.js'


// ── URL Token Types ─────────────────────────────────────────────

export type UrlTokenType =
    | 'SCHEME'              // http://, https://, ftp://, gopher://, file://, data:
    | 'AUTHORITY_SEP'       // //
    | 'USERINFO'            // user:pass@ (before host)
    | 'HOST_INTERNAL'       // 127.0.0.1, localhost, 0.0.0.0, ::1, etc.
    | 'HOST_METADATA'       // 169.254.169.254, metadata.google.internal
    | 'HOST_EXTERNAL'       // Any non-internal hostname
    | 'HOST_OBFUSCATED'     // Hex IP (0x7f000001), octal (0177.0.0.1), decimal (2130706433)
    | 'PORT'                // :8080
    | 'PATH_SEGMENT'        // /path/segment
    | 'QUERY'               // ?key=value
    | 'FRAGMENT'            // #anchor
    | 'IPV6'                // [::1], [::ffff:127.0.0.1]
    | 'WHITESPACE'          // Spaces
    | 'UNKNOWN'             // Malformed content


// ── Internal Network Patterns ───────────────────────────────────

const PRIVATE_IPV4_PATTERNS = [
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,            // 127.0.0.0/8 loopback
    /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,              // 10.0.0.0/8 private
    /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,  // 172.16.0.0/12 private
    /^192\.168\.\d{1,3}\.\d{1,3}$/,                  // 192.168.0.0/16 private
    /^0\.0\.0\.0$/,                                   // Unspecified (binds all)
]

const METADATA_HOSTS = new Set([
    '169.254.169.254',         // AWS/GCP/Azure metadata
    'metadata.google.internal', // GCP metadata
    'metadata.google',          // GCP metadata short
    '100.100.100.200',         // Alibaba Cloud metadata
    'fd00:ec2::254',           // AWS IPv6 metadata
])

const INTERNAL_HOSTNAMES = new Set([
    'localhost',
    'localhost.localdomain',
    'ip6-localhost',
    'ip6-loopback',
])

function isPrivateIPv4(host: string): boolean {
    return PRIVATE_IPV4_PATTERNS.some(re => re.test(host))
}

function isIPv6Internal(host: string): boolean {
    const stripped = host.replace(/^\[|\]$/g, '').toLowerCase()
    if (stripped === '::1' || stripped === '::') return true
    if (stripped === '0000:0000:0000:0000:0000:0000:0000:0001') return true
    // IPv6-mapped IPv4: ::ffff:127.0.0.1
    const mapped = stripped.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i)
    if (mapped && isPrivateIPv4(mapped[1])) return true
    return false
}

function isObfuscatedIP(host: string): boolean {
    // Hex: 0x7f000001 or 0x7f.0x00.0x00.0x01
    if (/^0x[0-9a-f]+$/i.test(host)) {
        const num = parseInt(host, 16)
        return isPrivateIPv4(numToIPv4(num)) || num === 2852039166 // 169.254.169.254
    }
    // Decimal: 2130706433 (127.0.0.1)
    if (/^\d{8,10}$/.test(host)) {
        const num = parseInt(host, 10)
        if (num >= 0 && num <= 4294967295) {
            return isPrivateIPv4(numToIPv4(num)) || num === 2852039166
        }
    }
    // Octal: 0177.0.0.1
    if (/^0\d+\./.test(host)) {
        const octets = host.split('.')
        if (octets.length === 4) {
            const nums = octets.map(o => parseInt(o, 8))
            if (nums.every(n => !isNaN(n) && n >= 0 && n <= 255)) {
                const ip = nums.join('.')
                return isPrivateIPv4(ip)
            }
        }
    }
    return false
}

function numToIPv4(num: number): string {
    return [
        (num >>> 24) & 0xff,
        (num >>> 16) & 0xff,
        (num >>> 8) & 0xff,
        num & 0xff,
    ].join('.')
}


// ── URL Tokenizer ───────────────────────────────────────────────

export class UrlTokenizer implements Tokenizer<UrlTokenType> {
    readonly language = 'url'

    tokenize(input: string): TokenStream<UrlTokenType> {
        const bounded = input.length > MAX_TOKENIZER_INPUT
            ? input.slice(0, MAX_TOKENIZER_INPUT)
            : input
        const tokens: Token<UrlTokenType>[] = []
        let i = 0

        // Skip leading whitespace
        while (i < bounded.length && /\s/.test(bounded[i])) {
            const start = i
            while (i < bounded.length && /\s/.test(bounded[i])) i++
            tokens.push({ type: 'WHITESPACE', value: bounded.slice(start, i), start, end: i })
        }

        // Try to parse scheme
        const schemeMatch = bounded.slice(i).match(/^([a-zA-Z][a-zA-Z0-9+.-]*):(?:\/\/)?/)
        if (schemeMatch) {
            const scheme = schemeMatch[1].toLowerCase()
            const hasDblSlash = schemeMatch[0].includes('//')
            tokens.push({ type: 'SCHEME', value: schemeMatch[1] + ':', start: i, end: i + schemeMatch[1].length + 1 })
            i += schemeMatch[1].length + 1

            if (hasDblSlash) {
                tokens.push({ type: 'AUTHORITY_SEP', value: '//', start: i, end: i + 2 })
                i += 2
            }

            // Parse authority (host[:port])
            if (scheme !== 'data') {
                i = this.parseAuthority(bounded, i, tokens)
            }
        } else if (bounded.slice(i).startsWith('//')) {
            // Protocol-relative URL
            tokens.push({ type: 'AUTHORITY_SEP', value: '//', start: i, end: i + 2 })
            i += 2
            i = this.parseAuthority(bounded, i, tokens)
        }

        // Parse path
        while (i < bounded.length && tokens.length < MAX_TOKEN_COUNT) {
            if (bounded[i] === '/') {
                const start = i
                i++
                while (i < bounded.length && bounded[i] !== '/' && bounded[i] !== '?' && bounded[i] !== '#' && !/\s/.test(bounded[i])) i++
                tokens.push({ type: 'PATH_SEGMENT', value: bounded.slice(start, i), start, end: i })
            } else if (bounded[i] === '?') {
                const start = i
                i++
                while (i < bounded.length && bounded[i] !== '#' && !/\s/.test(bounded[i])) i++
                tokens.push({ type: 'QUERY', value: bounded.slice(start, i), start, end: i })
            } else if (bounded[i] === '#') {
                const start = i
                while (i < bounded.length && !/\s/.test(bounded[i])) i++
                tokens.push({ type: 'FRAGMENT', value: bounded.slice(start, i), start, end: i })
            } else if (/\s/.test(bounded[i])) {
                const start = i
                while (i < bounded.length && /\s/.test(bounded[i])) i++
                tokens.push({ type: 'WHITESPACE', value: bounded.slice(start, i), start, end: i })
            } else {
                // Consume remaining as unknown
                const start = i
                while (i < bounded.length && !/[\s\/?#]/.test(bounded[i])) i++
                if (i > start) {
                    tokens.push({ type: 'UNKNOWN', value: bounded.slice(start, i), start, end: i })
                }
            }
        }

        return new TS(tokens)
    }

    private parseAuthority(input: string, pos: number, tokens: Token<UrlTokenType>[]): number {
        let i = pos

        // Check for userinfo (user:pass@)
        const remaining = input.slice(i)
        const atIdx = remaining.indexOf('@')
        if (atIdx !== -1 && atIdx < remaining.indexOf('/') || (atIdx !== -1 && !remaining.includes('/'))) {
            const userinfo = remaining.slice(0, atIdx + 1)
            if (!/[\s]/.test(userinfo)) {
                tokens.push({ type: 'USERINFO', value: userinfo, start: i, end: i + userinfo.length })
                i += userinfo.length
            }
        }

        // Parse host
        const hostStart = i
        if (i < input.length && input[i] === '[') {
            // IPv6 address
            const closeBracket = input.indexOf(']', i)
            if (closeBracket !== -1) {
                const ipv6 = input.slice(i, closeBracket + 1)
                const hostType = isIPv6Internal(ipv6) ? 'HOST_INTERNAL' : 'HOST_EXTERNAL'
                tokens.push({ type: hostType, value: ipv6, start: i, end: closeBracket + 1 })
                i = closeBracket + 1
            }
        } else {
            // Hostname or IPv4
            while (i < input.length && !/[\s\/:?#]/.test(input[i])) i++
            if (i > hostStart) {
                const host = input.slice(hostStart, i).toLowerCase()
                const hostType = this.classifyHost(host)
                tokens.push({ type: hostType, value: input.slice(hostStart, i), start: hostStart, end: i })
            }
        }

        // Parse port
        if (i < input.length && input[i] === ':') {
            const portStart = i
            i++
            while (i < input.length && /\d/.test(input[i])) i++
            tokens.push({ type: 'PORT', value: input.slice(portStart, i), start: portStart, end: i })
        }

        return i
    }

    private classifyHost(host: string): UrlTokenType {
        if (METADATA_HOSTS.has(host)) return 'HOST_METADATA'
        if (INTERNAL_HOSTNAMES.has(host)) return 'HOST_INTERNAL'
        if (isPrivateIPv4(host)) return 'HOST_INTERNAL'
        if (isIPv6Internal(host)) return 'HOST_INTERNAL'
        if (isObfuscatedIP(host)) return 'HOST_OBFUSCATED'
        return 'HOST_EXTERNAL'
    }
}

export function urlTokenize(input: string): readonly Token<UrlTokenType>[] {
    return new UrlTokenizer().tokenize(input).all()
}

export const urlTokenizer = new UrlTokenizer()
