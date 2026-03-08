/**
 * INVARIANT Crypto — Base64URL + Binary Utilities
 *
 * Zero-dependency encoding utilities required by all crypto operations.
 * Pure functions, synchronous, no platform APIs needed.
 *
 * base64url (RFC 4648 §5): uses '-' and '_' instead of '+' and '/',
 * no padding. Standard for JWK, JWE, and Santh wire formats.
 */


// ── Base64URL ─────────────────────────────────────────────────────

const B64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

/** Encode a Uint8Array to base64url string (no padding). */
export function toBase64Url(bytes: Uint8Array): string {
    let result = ''
    const len = bytes.length
    for (let i = 0; i < len; i += 3) {
        const b0 = bytes[i]
        const b1 = i + 1 < len ? bytes[i + 1] : 0
        const b2 = i + 2 < len ? bytes[i + 2] : 0
        result += B64URL_CHARS[b0 >> 2]
        result += B64URL_CHARS[((b0 & 0x3) << 4) | (b1 >> 4)]
        if (i + 1 < len) result += B64URL_CHARS[((b1 & 0xf) << 2) | (b2 >> 6)]
        if (i + 2 < len) result += B64URL_CHARS[b2 & 0x3f]
    }
    return result
}

/** Decode a base64url string (with or without padding) to Uint8Array. */
export function fromBase64Url(str: string): Uint8Array {
    // Normalize: remove padding, convert base64 → base64url chars
    const s = str.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
    const len = s.length
    const outputLen = Math.floor((len * 3) / 4)
    const out = new Uint8Array(outputLen)

    const lookup = buildLookup()
    let outIdx = 0

    for (let i = 0; i < len; i += 4) {
        const c0 = lookup[s.charCodeAt(i)] ?? 0
        const c1 = lookup[s.charCodeAt(i + 1)] ?? 0
        const c2 = i + 2 < len ? (lookup[s.charCodeAt(i + 2)] ?? 0) : 0
        const c3 = i + 3 < len ? (lookup[s.charCodeAt(i + 3)] ?? 0) : 0

        out[outIdx++] = (c0 << 2) | (c1 >> 4)
        if (i + 2 < len) out[outIdx++] = ((c1 & 0xf) << 4) | (c2 >> 2)
        if (i + 3 < len) out[outIdx++] = ((c2 & 0x3) << 6) | c3
    }

    return out.subarray(0, outIdx)
}

let _lookup: Uint8Array | null = null
function buildLookup(): Uint8Array {
    if (_lookup) return _lookup
    _lookup = new Uint8Array(128)
    for (let i = 0; i < B64URL_CHARS.length; i++) {
        _lookup[B64URL_CHARS.charCodeAt(i)] = i
    }
    return _lookup
}


// ── Binary Utilities ──────────────────────────────────────────────

/** Concatenate multiple Uint8Arrays into one. */
export function concat(...arrays: Uint8Array[]): Uint8Array {
    const totalLen = arrays.reduce((sum, a) => sum + a.length, 0)
    const out = new Uint8Array(totalLen)
    let offset = 0
    for (const arr of arrays) {
        out.set(arr, offset)
        offset += arr.length
    }
    return out
}

/** Encode a 32-bit unsigned integer as 4 big-endian bytes. */
export function uint32BE(n: number): Uint8Array {
    const buf = new Uint8Array(4)
    new DataView(buf.buffer).setUint32(0, n >>> 0, false)
    return buf
}

/** Encode a 64-bit unsigned integer as 8 big-endian bytes (safe for timestamps). */
export function uint64BE(n: number): Uint8Array {
    const buf = new Uint8Array(8)
    const view = new DataView(buf.buffer)
    // JS numbers are safe integers up to 2^53, sufficient for unix ms timestamps
    view.setUint32(0, Math.floor(n / 0x100000000) >>> 0, false)
    view.setUint32(4, n >>> 0, false)
    return buf
}

/** UTF-8 encode a string. */
export const encode = (s: string): Uint8Array => new TextEncoder().encode(s)

/** UTF-8 decode bytes. */
export const decode = (b: Uint8Array): string => new TextDecoder().decode(b)

/**
 * Constant-time comparison of two Uint8Arrays.
 * Prevents timing attacks when comparing MACs or signatures.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    let diff = 0
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i]
    }
    return diff === 0
}
