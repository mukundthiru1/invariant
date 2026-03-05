/**
 * SSRF Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for SSRF is:
 *   resolve(parse(input, URL_GRAMMAR)).host ∈ INTERNAL_RANGES
 *   ∨ resolve(input).host = CLOUD_METADATA_IP
 *   ∨ parse(input).protocol ∈ NON_HTTP_PROTOCOLS
 *
 * This module evaluates the actual resolved host, not the string
 * representation. Key advantage: it resolves ALL numeric IP
 * representations to a canonical form:
 *
 *   127.0.0.1       (dotted decimal — standard)
 *   0x7f000001      (hex integer)
 *   2130706433      (decimal integer)
 *   017700000001    (octal integer)
 *   0177.0.0.1      (octal octets)
 *   127.1           (compressed — 127.0.0.1)
 *   [::1]           (IPv6 loopback)
 *   [::ffff:127.0.0.1] (IPv4-mapped IPv6)
 *   0x7f.0.0.1      (hex octets)
 *
 * ALL of these resolve to 127.0.0.1. A regex can enumerate some.
 * This evaluator resolves ALL of them via numeric normalization.
 *
 * Covers:
 *   - ssrf_internal_reach:    request targets internal/private IP
 *   - ssrf_cloud_metadata:    request targets cloud metadata endpoint
 *   - ssrf_protocol_smuggle:  request uses non-HTTP protocol (file://, gopher://)
 */


// ── Result Type ──────────────────────────────────────────────────

export interface SSRFDetection {
    type: 'internal_reach' | 'cloud_metadata' | 'protocol_smuggle'
    detail: string
    resolvedHost: string
    resolvedIP: string | null
    confidence: number
}


// ── Cloud Metadata Endpoints ─────────────────────────────────────

const CLOUD_METADATA_IPS = [
    '169.254.169.254',   // AWS, GCP, Azure, DigitalOcean, Oracle
    '100.100.100.200',   // Alibaba Cloud
    '169.254.170.2',     // AWS ECS task metadata
]

const CLOUD_METADATA_HOSTNAMES = new Set([
    'metadata.google.internal',
    'metadata.goog',
    'metadata',
    'instance-data',
])


// ── Dangerous Protocols ──────────────────────────────────────────

const DANGEROUS_PROTOCOLS = new Set([
    'file:', 'gopher:', 'dict:', 'ftp:', 'ldap:', 'ldaps:',
    'tftp:', 'sftp:', 'jar:', 'netdoc:', 'phar:',
    'expect:', 'glob:', 'data:', 'php:',
])


// ── Internal IP Range Definitions ────────────────────────────────
//
// RFC 1918 + RFC 5735 + RFC 6890:
//   10.0.0.0/8        → 10.0.0.0 – 10.255.255.255
//   172.16.0.0/12     → 172.16.0.0 – 172.31.255.255
//   192.168.0.0/16    → 192.168.0.0 – 192.168.255.255
//   127.0.0.0/8       → 127.0.0.0 – 127.255.255.255  (loopback)
//   0.0.0.0/8         → 0.0.0.0 – 0.255.255.255      (this network)
//   169.254.0.0/16    → link-local
//   ::1               → IPv6 loopback
//   fc00::/7          → IPv6 ULA

interface IPRange {
    start: number
    end: number
    label: string
}

const INTERNAL_RANGES: IPRange[] = [
    { start: ip4ToNum(10, 0, 0, 0), end: ip4ToNum(10, 255, 255, 255), label: 'RFC1918 10/8' },
    { start: ip4ToNum(172, 16, 0, 0), end: ip4ToNum(172, 31, 255, 255), label: 'RFC1918 172.16/12' },
    { start: ip4ToNum(192, 168, 0, 0), end: ip4ToNum(192, 168, 255, 255), label: 'RFC1918 192.168/16' },
    { start: ip4ToNum(127, 0, 0, 0), end: ip4ToNum(127, 255, 255, 255), label: 'Loopback 127/8' },
    { start: ip4ToNum(0, 0, 0, 0), end: ip4ToNum(0, 255, 255, 255), label: 'This network 0/8' },
    { start: ip4ToNum(169, 254, 0, 0), end: ip4ToNum(169, 254, 255, 255), label: 'Link-local 169.254/16' },
]

function ip4ToNum(a: number, b: number, c: number, d: number): number {
    // Use >>> 0 to force unsigned 32-bit. Without this, IPs with first
    // octet > 127 produce negative numbers from bitwise shift.
    return (((a & 0xFF) << 24) | ((b & 0xFF) << 16) | ((c & 0xFF) << 8) | (d & 0xFF)) >>> 0
}

export function isInternalIP(ipNum: number): string | null {
    // Ensure unsigned comparison
    const unsigned = ipNum >>> 0
    for (const range of INTERNAL_RANGES) {
        if (unsigned >= range.start && unsigned <= range.end) {
            return range.label
        }
    }
    return null
}


// ── IP Representation Parser ─────────────────────────────────────
//
// This is the core strength over regex. We resolve any numeric
// representation of an IP address to a canonical 32-bit integer.

export function parseIPRepresentation(host: string): number | null {
    // Strip brackets from IPv6
    let h = host.replace(/^\[|\]$/g, '').trim()

    // IPv6 loopback
    if (h === '::1') return ip4ToNum(127, 0, 0, 1)

    // IPv4-mapped IPv6: ::ffff:127.0.0.1
    const v4mapped = h.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i)
    if (v4mapped) h = v4mapped[1]

    // IPv4-mapped IPv6 hex: ::ffff:7f00:0001
    const v4hex = h.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i)
    if (v4hex) {
        const high = parseInt(v4hex[1], 16)
        const low = parseInt(v4hex[2], 16)
        return ((high << 16) | low) >>> 0
    }

    // Single integer representation
    // Hex: 0x7f000001
    if (/^0x[0-9a-f]+$/i.test(h)) {
        const val = parseInt(h, 16)
        if (val >= 0 && val <= 0xFFFFFFFF) return val >>> 0
    }

    // Octal integer: 017700000001
    if (/^0[0-7]+$/.test(h) && h.length > 1) {
        const val = parseInt(h, 8)
        if (val >= 0 && val <= 0xFFFFFFFF) return val >>> 0
    }

    // Decimal integer: 2130706433
    if (/^\d+$/.test(h)) {
        const val = parseInt(h, 10)
        // Only treat as IP integer if it's large enough (> 255 rules out single octets)
        if (val > 255 && val <= 0xFFFFFFFF) return val >>> 0
    }

    // Dotted representation (handles mixed radix: 0x7f.0.0.1, 0177.0.0.01)
    const parts = h.split('.')
    if (parts.length >= 1 && parts.length <= 4) {
        const octets: number[] = []
        let valid = true

        for (const part of parts) {
            let val: number
            if (/^0x[0-9a-f]+$/i.test(part)) {
                val = parseInt(part, 16)
            } else if (/^0[0-7]+$/.test(part) && part.length > 1) {
                val = parseInt(part, 8)
            } else if (/^\d+$/.test(part)) {
                val = parseInt(part, 10)
            } else {
                valid = false
                break
            }
            octets.push(val)
        }

        if (valid && octets.length > 0) {
            // Handle compressed forms:
            //   127.1       → 127.0.0.1
            //   127.0.1     → 127.0.0.1
            //   10.1.1      → 10.1.0.1
            switch (octets.length) {
                case 4:
                    if (octets.every(o => o >= 0 && o <= 255)) {
                        return ip4ToNum(octets[0], octets[1], octets[2], octets[3])
                    }
                    break
                case 3:
                    if (octets[0] >= 0 && octets[0] <= 255 &&
                        octets[1] >= 0 && octets[1] <= 255 &&
                        octets[2] >= 0 && octets[2] <= 65535) {
                        return ip4ToNum(octets[0], octets[1], (octets[2] >> 8) & 0xFF, octets[2] & 0xFF)
                    }
                    break
                case 2:
                    if (octets[0] >= 0 && octets[0] <= 255 &&
                        octets[1] >= 0 && octets[1] <= 16777215) {
                        return ip4ToNum(
                            octets[0],
                            (octets[1] >> 16) & 0xFF,
                            (octets[1] >> 8) & 0xFF,
                            octets[1] & 0xFF,
                        )
                    }
                    break
                case 1:
                    if (octets[0] >= 0 && octets[0] <= 0xFFFFFFFF) {
                        return octets[0] >>> 0
                    }
                    break
            }
        }
    }

    return null
}

function ipNumToString(num: number): string {
    return `${(num >>> 24) & 0xFF}.${(num >>> 16) & 0xFF}.${(num >>> 8) & 0xFF}.${num & 0xFF}`
}


// ── URL Parser ───────────────────────────────────────────────────

interface ParsedURL {
    protocol: string
    hostname: string
    port: number | null
    path: string
}

function parseURL(input: string): ParsedURL | null {
    // Trim and normalize
    let url = input.trim()

    // Handle protocol-relative URLs
    if (url.startsWith('//')) {
        url = 'http:' + url
    }

    // Extract protocol
    const protoMatch = url.match(/^([a-z][a-z0-9+.-]*):\/\//i)
    if (!protoMatch) return null

    const protocol = protoMatch[1].toLowerCase() + ':'
    let remainder = url.substring(protoMatch[0].length)

    // Handle @ for user:pass@host
    const atIndex = remainder.indexOf('@')
    if (atIndex !== -1) {
        remainder = remainder.substring(atIndex + 1)
    }

    // Extract host:port and path
    const pathIndex = remainder.indexOf('/')
    const hostPort = pathIndex >= 0 ? remainder.substring(0, pathIndex) : remainder
    const path = pathIndex >= 0 ? remainder.substring(pathIndex) : '/'

    // Extract hostname and port
    let hostname: string
    let port: number | null = null

    // IPv6 address: [::1]:8080
    const ipv6Match = hostPort.match(/^\[([^\]]+)\](?::(\d+))?$/)
    if (ipv6Match) {
        hostname = ipv6Match[1]
        port = ipv6Match[2] ? parseInt(ipv6Match[2], 10) : null
    } else {
        const colonIndex = hostPort.lastIndexOf(':')
        if (colonIndex > 0) {
            const portStr = hostPort.substring(colonIndex + 1)
            if (/^\d+$/.test(portStr)) {
                hostname = hostPort.substring(0, colonIndex)
                port = parseInt(portStr, 10)
            } else {
                hostname = hostPort
            }
        } else {
            hostname = hostPort
        }
    }

    return { protocol, hostname: hostname.toLowerCase(), port, path }
}


// ── Detection Functions ──────────────────────────────────────────

function detectInternalReach(parsed: ParsedURL): SSRFDetection | null {
    const ipNum = parseIPRepresentation(parsed.hostname)

    if (ipNum !== null) {
        const range = isInternalIP(ipNum)
        if (range) {
            const resolvedIP = ipNumToString(ipNum)
            return {
                type: 'internal_reach',
                detail: `Internal IP (${range}): ${parsed.hostname} → ${resolvedIP}`,
                resolvedHost: parsed.hostname,
                resolvedIP,
                confidence: 0.92,
            }
        }
    }

    // Check hostnames that resolve to internal
    const h = parsed.hostname
    if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h === '0') {
        return {
            type: 'internal_reach',
            detail: `Localhost hostname: ${h}`,
            resolvedHost: h,
            resolvedIP: '127.0.0.1',
            confidence: 0.90,
        }
    }

    // DNS rebinding services — hostnames that resolve to internal IPs
    // e.g., 127.0.0.1.nip.io, 10.0.0.1.xip.io, 192.168.1.1.sslip.io
    const rebindServices = ['.nip.io', '.xip.io', '.sslip.io']
    for (const suffix of rebindServices) {
        if (h.endsWith(suffix)) {
            const ipPart = h.slice(0, -suffix.length)
            const rebindIP = parseIPRepresentation(ipPart)
            if (rebindIP !== null) {
                const range = isInternalIP(rebindIP)
                if (range) {
                    return {
                        type: 'internal_reach',
                        detail: `DNS rebinding via ${suffix}: ${h} → ${ipNumToString(rebindIP)}`,
                        resolvedHost: h,
                        resolvedIP: ipNumToString(rebindIP),
                        confidence: 0.92,
                    }
                }
            }
        }
    }

    return null
}

function detectCloudMetadata(parsed: ParsedURL): SSRFDetection | null {
    const ipNum = parseIPRepresentation(parsed.hostname)

    if (ipNum !== null) {
        const resolvedIP = ipNumToString(ipNum)
        if (CLOUD_METADATA_IPS.includes(resolvedIP)) {
            return {
                type: 'cloud_metadata',
                detail: `Cloud metadata endpoint: ${parsed.hostname} → ${resolvedIP}${parsed.path}`,
                resolvedHost: parsed.hostname,
                resolvedIP,
                confidence: 0.95,
            }
        }
    }

    if (CLOUD_METADATA_HOSTNAMES.has(parsed.hostname)) {
        return {
            type: 'cloud_metadata',
            detail: `Cloud metadata hostname: ${parsed.hostname}`,
            resolvedHost: parsed.hostname,
            resolvedIP: null,
            confidence: 0.92,
        }
    }

    return null
}

function detectProtocolSmuggle(parsed: ParsedURL): SSRFDetection | null {
    if (DANGEROUS_PROTOCOLS.has(parsed.protocol)) {
        return {
            type: 'protocol_smuggle',
            detail: `Non-HTTP protocol: ${parsed.protocol}//${parsed.hostname}`,
            resolvedHost: parsed.hostname,
            resolvedIP: null,
            confidence: 0.88,
        }
    }
    return null
}


// ── Public API ───────────────────────────────────────────────────

/**
 * Detect SSRF vectors by parsing the URL and evaluating the
 * resolved host against internal ranges and metadata endpoints.
 */
export function detectSSRF(input: string): SSRFDetection[] {
    const detections: SSRFDetection[] = []

    // Don't waste time on very short inputs
    if (input.length < 4) return detections

    // Multi-layer decode to handle encoding bypass
    let decoded = input
    try {
        let prev = ''
        for (let i = 0; i < 3 && decoded !== prev; i++) {
            prev = decoded
            try { decoded = decodeURIComponent(decoded) } catch { break }
        }
    } catch { /* use original */ }

    const parsed = parseURL(decoded)
    if (!parsed) return detections

    const detectorFns: Array<(parsed: ParsedURL) => SSRFDetection | null> = [
        detectCloudMetadata,   // Check metadata first (highest severity)
        detectInternalReach,
        detectProtocolSmuggle,
    ]

    for (const detector of detectorFns) {
        try {
            const result = detector(parsed)
            if (result) detections.push(result)
        } catch { /* never crash the pipeline */ }
    }

    return detections
}

// ── Exports for Testing ──────────────────────────────────────────

export { ipNumToString, parseURL }
