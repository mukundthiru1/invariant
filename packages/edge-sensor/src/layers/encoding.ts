/**
 * Edge Sensor — Encoding Helpers
 *
 * Multi-layer decoding to normalize attacker evasion techniques.
 * Unified with the engine's deepDecode implementation.
 * SECURITY: Bounded input size to prevent DoS via huge path/query.
 */

const MAX_DECODE_DEPTH = 6
const MAX_INPUT_SIZE = 8192

/** Valid Unicode code point is 0–0x10FFFF excluding surrogates 0xD800–0xDFFF. */
function safeFromCodePoint(cp: number): string {
    if (Number.isNaN(cp) || cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '\uFFFD'
    return cp <= 0xffff ? String.fromCharCode(cp) : String.fromCodePoint(cp)
}

export function safeDecode(input: string): string {
    try { return decodeURIComponent(input) }
    catch { return input }
}

export function deepDecode(input: string, depth = 0): string {
    if (depth > MAX_DECODE_DEPTH) return input
    if (input.length > MAX_INPUT_SIZE) input = input.slice(0, MAX_INPUT_SIZE)

    let decoded = input

    // URL decode
    try {
        const urlDecoded = decodeURIComponent(decoded)
        if (urlDecoded !== decoded) {
            decoded = deepDecode(urlDecoded, depth + 1)
        }
    } catch { /* invalid encoding, keep original */ }

    // HTML entity decode (numeric + named). Clamp to valid Unicode (0–0x10FFFF) to avoid surrogates/invalid.
    decoded = decoded
        .replace(/&#x([0-9a-f]+);?/gi, (_, hex: string) => safeFromCodePoint(parseInt(hex, 16)))
        .replace(/&#(\d+);?/g, (_, dec: string) => safeFromCodePoint(parseInt(dec, 10)))
        .replace(/&quot;/gi, '"')
        .replace(/&apos;/gi, "'")
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
        .replace(/&amp;/gi, '&')

    // Unicode escapes (4 hex = BMP; clamp for safety)
    decoded = decoded.replace(/\\u([0-9a-f]{4})/gi, (_, hex: string) =>
        safeFromCodePoint(parseInt(hex, 16)))

    // Hex escapes
    decoded = decoded.replace(/\\x([0-9a-f]{2})/gi, (_, hex: string) =>
        safeFromCodePoint(parseInt(hex, 16)))

    // C-style escape sequences: \r → CR, \n → LF, \t → TAB
    decoded = decoded.replace(/\\r/g, '\r').replace(/\\n/g, '\n').replace(/\\t/g, '\t')

    // Collapse SQL comment-space bypass: /**/  →  space
    decoded = decoded.replace(/\/\*.*?\*\//g, ' ')

    // SAA-058: Protocol keyword normalization — MUST match engine's deepDecode.
    // Without this, "j\ta\tv\ta\ts\tc\tr\ti\tp\tt:" evades L1 XSS detection
    // because L1 checks ctx.decodedQuery which uses THIS decoder.
    // L5 invariant engine's decoder normalizes it → catches it → but at
    // lower confidence (0.88) which may not trigger blocking.
    decoded = normalizeProtocolKeyword(decoded, 'javascript')
    decoded = normalizeProtocolKeyword(decoded, 'vbscript')

    // Strip null bytes — used to bypass path traversal and string termination filters
    // e.g. "../../../etc/passwd%00.png" passes extension checks but reads /etc/passwd
    decoded = decoded.replace(/\0/g, '')

    return decoded
}


/**
 * O(n) protocol keyword normalization.
 * Finds "j a v a s c r i p t :" (with whitespace/control chars between letters)
 * and normalizes to "javascript:".
 * Bounded to 10 normalizations per input to prevent stack overflow.
 */
function normalizeProtocolKeyword(input: string, keyword: string, depth = 0): string {
    if (depth > 10) return input

    const lower = input.toLowerCase()
    const keyLower = keyword.toLowerCase()

    if (lower.indexOf(keyLower[0]) === -1) return input

    let result = input
    let i = 0
    while (i < lower.length) {
        if (lower[i] !== keyLower[0]) { i++; continue }

        let ki = 0
        let j = i
        const startPos = i
        while (j < lower.length && ki < keyLower.length) {
            if (lower[j] === keyLower[ki]) {
                ki++
                j++
            } else if (lower.charCodeAt(j) <= 0x20) {
                j++
            } else {
                break
            }
        }

        if (ki === keyLower.length && j < lower.length && lower[j] === ':') {
            if (j - startPos > keyword.length + 1) {
                result = result.slice(0, startPos) + keyword + ':' + result.slice(j + 1)
                return normalizeProtocolKeyword(result, keyword, depth + 1)
            }
        }
        i++
    }
    return result
}
