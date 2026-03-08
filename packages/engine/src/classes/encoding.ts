/**
 * Encoding Normalizer — Shared Decoding Infrastructure
 *
 * Attackers stack encodings to bypass filters:
 *   %27%20OR%201%3D1--           (URL encoded)
 *   %2527%2520OR%25201%253D1--   (double URL encoded)
 *   &#39; OR 1=1--               (HTML entity)
 *   \u0027 OR 1=1--              (Unicode escape)
 *
 * This module normalizes all encoding layers to plain text before
 * invariant matching. It is shared across all class modules.
 *
 * SECURITY INVARIANT: The decoder is bounded to prevent DoS.
 * Maximum recursion depth is 6. Maximum input size is 8192 bytes.
 */

const MAX_DECODE_DEPTH = 6
const MAX_INPUT_SIZE = 8192

/** Valid Unicode 0–0x10FFFF excluding surrogates; avoids invalid chars from entity abuse. */
function safeFromCodePoint(cp: number): string {
    if (Number.isNaN(cp) || cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '\uFFFD'
    return cp <= 0xffff ? String.fromCharCode(cp) : String.fromCodePoint(cp)
}

/**
 * Recursively decode a string through common encoding layers.
 * Returns the fully decoded form.
 */
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

    // HTML entity decode (numeric + named). Clamp to valid Unicode.
    decoded = decoded
        .replace(/&#x([0-9a-f]+);?/gi, (_, hex) => safeFromCodePoint(parseInt(hex, 16)))
        .replace(/&#(\d+);?/g, (_, dec) => safeFromCodePoint(parseInt(dec, 10)))
        .replace(/&quot;/gi, '"')
        .replace(/&apos;/gi, "'")
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
        .replace(/&amp;/gi, '&')

    // Unicode escapes
    decoded = decoded.replace(/\\u([0-9a-f]{4})/gi, (_, hex) =>
        safeFromCodePoint(parseInt(hex, 16)))

    // Hex escapes
    decoded = decoded.replace(/\\x([0-9a-f]{2})/gi, (_, hex) =>
        safeFromCodePoint(parseInt(hex, 16)))

    // C-style escape sequences: \r → CR, \n → LF, \t → TAB
    decoded = decoded.replace(/\\r/g, '\r').replace(/\\n/g, '\n').replace(/\\t/g, '\t')

    // Collapse SQL comment-space bypass: /**/  →  space
    decoded = decoded.replace(/\/\*.*?\*\//g, ' ')

    // Normalize whitespace/control chars inside protocol keywords
    // java\tscript: → javascript:,  vb\nscript: → vbscript:
    // O(n) approach: check stripped version, then do simple replacement
    decoded = normalizeProtocolKeyword(decoded, 'javascript')
    decoded = normalizeProtocolKeyword(decoded, 'vbscript')

    // Decode base64 data URIs: data:text/html;base64,XXXX
    decoded = decoded.replace(/data:[^;,]*;base64,([A-Za-z0-9+/=]+)/gi, (full, b64) => {
        try {
            const plain = atob(b64)
            return `data:text/html,${plain}`
        } catch {
            return full
        }
    })

    return decoded
}

/**
 * O(n) protocol keyword normalization.
 * Finds "j a v a s c r i p t :" (with whitespace/control chars between letters)
 * and normalizes to "javascript:".
 *
 * SECURITY (SAA-046): Bounded recursion — max 10 normalizations per input.
 * Without this, hundreds of obfuscated sequences cause stack overflow.
 */
function normalizeProtocolKeyword(input: string, keyword: string, depth = 0): string {
    // Recursion depth limit to prevent stack overflow
    if (depth > 10) return input

    const lower = input.toLowerCase()
    const keyLower = keyword.toLowerCase()

    // Fast path: no first character of keyword found
    if (lower.indexOf(keyLower[0]) === -1) return input

    // Scan through input looking for keyword letters with optional whitespace between
    let result = input
    let i = 0
    while (i < lower.length) {
        if (lower[i] !== keyLower[0]) { i++; continue }

        // Try to match keyword starting here
        let ki = 0
        let j = i
        const startPos = i
        while (j < lower.length && ki < keyLower.length) {
            if (lower[j] === keyLower[ki]) {
                ki++
                j++
            } else if (lower.charCodeAt(j) <= 0x20) {
                // Whitespace or control char — skip
                j++
            } else {
                break
            }
        }

        // Check if we matched the full keyword AND the next char is ':'
        if (ki === keyLower.length && j < lower.length && lower[j] === ':') {
            // Only normalize if there was actually whitespace inserted
            if (j - startPos > keyword.length + 1) {
                result = result.slice(0, startPos) + keyword + ':' + result.slice(j + 1)
                return normalizeProtocolKeyword(result, keyword, depth + 1)
            }
        }
        i++
    }
    return result
}
