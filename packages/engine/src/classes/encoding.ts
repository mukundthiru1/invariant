/**
 * Encoding Normalizer — Shared Decoding Infrastructure
 *
 * Attackers stack encodings to bypass filters:
 *   %27%20OR%201%3D1--           (URL encoded)
 *   %2527%2520OR%25201%253D1--   (double URL encoded)
 *   &#39; OR 1=1--               (HTML entity)
 *   \u0027 OR 1=1--              (Unicode escape)
 *
 * SAA-104: Unicode homoglyph and invisible character bypass:
 *   sel\u00adect → select         (soft hyphen U+00AD — invisible, splits keywords)
 *   OR\u202e1=1 → OR1=1          (BIDI RTL override — reorders displayed text)
 *   A\u{E0041}B → AB             (Tags block invisible char U+E0041)
 *   Ο R → OR                     (Greek Omicron U+039F homoglyph for Latin O)
 *   О R → OR                     (Cyrillic O U+041E homoglyph for Latin O)
 *
 * BYP-001: SQL comment injection bypass:
 *   MySQL conditional comments (e.g. /*! 50000SELECT * /) must be unwrapped
 *   BEFORE generic block comment stripping to preserve injected SQL keywords.
 *
 * This module normalizes all encoding layers to plain text before
 * invariant matching. It is shared across all class modules.
 *
 * SECURITY INVARIANT: The decoder is bounded to prevent DoS.
 * Maximum recursion depth is 6. Maximum input size is 8192 bytes.
 */

const MAX_DECODE_DEPTH = 6
const MAX_INPUT_SIZE = 8192
const NULL_BYTE_RE = /\u0000/g

// SAA-104: Invisible/zero-width character stripping
// U+00AD = soft hyphen (splits keywords invisibly, e.g. sel\u00adect → select)
// U+200B-U+200D = zero-width space/non-joiner/joiner
// U+FEFF = zero-width no-break space (BOM)
const ZERO_WIDTH_CHARS = /[\u200B-\u200D\uFEFF\u00AD]/g

// SAA-104: BIDI control characters (RTL/LTR override, isolate marks)
// These can reorder displayed text without changing byte stream order,
// allowing attackers to visually hide injection payloads from reviewers.
const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069]/g

// SAA-104: Unicode Tags block (U+E0000–U+E007F) — tag characters invisible in UI.
// CRITICAL: MUST use /u flag. Without it, \uE000 parses as U+E000 + literal '0',
// creating range 0x30-0xE007 that covers ALL printable ASCII. Catastrophic.
const TAGS_BLOCK = /[\u{E0000}-\u{E007F}]/gu

// SAA-104: Unicode combining marks — diacritics visually fused to base chars.
// Attackers layer combining marks over letters to bypass character-level checks.
const COMBINING_MARKS_RE = /\p{M}+/gu

// ASCII control characters (except tab U+0009, LF U+000A, CR U+000D which are valid)
const ASCII_CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g

const HTML_NAMED_ENTITIES: Record<string, string> = {
    quot: '"',
    apos: "'",
    lt: '<',
    gt: '>',
    amp: '&',
    sol: '/',
    bsol: '\\',
    lpar: '(',
    rpar: ')',
    semi: ';',
    colon: ':',
    period: '.',
}

const BASE32_CANDIDATE_RE = /\b[A-Z2-7]{8,}={1,}(?![A-Z2-7])/gi
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const BASE32_LOOKUP: Record<string, number> = (() => {
    const map: Record<string, number> = {}
    for (let i = 0; i < BASE32_ALPHABET.length; i++) {
        map[BASE32_ALPHABET[i]] = i
    }
    return map
})()
const BASE32_DECODER = new TextDecoder('utf-8')
const OVERLONG_SLASH_RE = /%c0%af|%e0%80%af/gi
const ATTACK_HINT_RE = /\b(?:select|union|insert|update|delete|drop|or|and|script|javascript|vbscript|alert|from|where)\b|<\s*script|<\s*on\w+\s*=|\/\*/i

/**
 * SAA-104: Homoglyph normalization map.
 * Cyrillic and Greek characters visually identical to Latin letters.
 * Attackers spell SQL keywords (OR, SELECT, UNION) using these to bypass
 * ASCII-only detection regex while remaining semantically equivalent when
 * processed by case-folding database engines.
 */
const HOMOGLYPH_MAP: Record<string, string> = {
    // Cyrillic → Latin
    '\u0410': 'A', // А (Cyrillic Capital A)
    '\u0430': 'a', // а (Cyrillic Small A)
    '\u0412': 'B', // В (Cyrillic Capital Ve)
    '\u0421': 'C', // С (Cyrillic Capital Es)
    '\u0441': 'c', // с (Cyrillic Small Es)
    '\u0415': 'E', // Е (Cyrillic Capital Ie)
    '\u0435': 'e', // е (Cyrillic Small Ie)
    '\u0405': 'S', // Ѕ (Cyrillic Capital Dze)
    '\u0455': 's', // ѕ (Cyrillic Small Dze)
    '\u0406': 'I', // І (Cyrillic Capital I)
    '\u0456': 'i', // і (Cyrillic Small I)
    '\u0408': 'J', // Ј (Cyrillic Capital Je)
    '\u0458': 'j', // ј (Cyrillic Small Je)
    '\u041A': 'K', // К (Cyrillic Capital Ka)
    '\u041C': 'M', // М (Cyrillic Capital Em)
    '\u041D': 'H', // Н (Cyrillic Capital En)
    '\u041E': 'O', // О (Cyrillic Capital O)
    '\u043E': 'o', // о (Cyrillic Small O)
    '\u0420': 'P', // Р (Cyrillic Capital Er)
    '\u0440': 'p', // р (Cyrillic Small Er)
    '\u0422': 'T', // Т (Cyrillic Capital Te)
    '\u0443': 'y', // у (Cyrillic Small U)
    '\u0425': 'X', // Х (Cyrillic Capital Ha)
    '\u0445': 'x', // х (Cyrillic Small Ha)

    // Greek → Latin
    '\u039F': 'O', // Ο (Greek Capital Omicron)
    '\u03BF': 'o', // ο (Greek Small Omicron)
    '\u0391': 'A', // Α (Greek Capital Alpha)
    '\u03B1': 'a', // α (Greek Small Alpha)
    '\u0392': 'B', // Β (Greek Capital Beta)
    '\u0395': 'E', // Ε (Greek Capital Epsilon)
    '\u03B5': 'e', // ε (Greek Small Epsilon)
    '\u0397': 'H', // Η (Greek Capital Eta)
    '\u0399': 'I', // Ι (Greek Capital Iota)
    '\u03B9': 'i', // ι (Greek Small Iota)
    '\u039A': 'K', // Κ (Greek Capital Kappa)
    '\u039C': 'M', // Μ (Greek Capital Mu)
    '\u039D': 'N', // Ν (Greek Capital Nu)
    '\u03A1': 'P', // Ρ (Greek Capital Rho)
    '\u03A4': 'T', // Τ (Greek Capital Tau)
    '\u03A7': 'X', // Χ (Greek Capital Chi)
    '\u03C7': 'x', // χ (Greek Small Chi)
}

/** Build homoglyph replacement regex once at module load */
const HOMOGLYPH_RE = new RegExp(
    Object.keys(HOMOGLYPH_MAP).map(c => c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'),
    'g'
)

/** Valid Unicode 0–0x10FFFF excluding surrogates; avoids invalid chars from entity abuse. */
function safeFromCodePoint(cp: number): string {
    if (Number.isNaN(cp) || cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '\uFFFD'
    return cp <= 0xffff ? String.fromCharCode(cp) : String.fromCodePoint(cp)
}

function decodeBase32Token(token: string): string | null {
    const encoded = token.toUpperCase().replace(/=+$/g, '')
    if (encoded.length < 8) return null

    let bitBuffer = 0
    let bitCount = 0
    const bytes: number[] = []

    for (let i = 0; i < encoded.length; i++) {
        const value = BASE32_LOOKUP[encoded[i]]
        if (value === undefined) return null
        bitBuffer = (bitBuffer << 5) | value
        bitCount += 5
        while (bitCount >= 8) {
            bitCount -= 8
            bytes.push((bitBuffer >> bitCount) & 0xff)
        }
    }

    if (bytes.length === 0) return null
    try {
        return BASE32_DECODER.decode(Uint8Array.from(bytes))
    } catch {
        return null
    }
}

function looksLikeAttackPayload(input: string): boolean {
    return ATTACK_HINT_RE.test(input)
}

function decodeBase32IfSuspicious(input: string): string {
    return input.replace(BASE32_CANDIDATE_RE, token => {
        const decoded = decodeBase32Token(token)
        if (!decoded || !looksLikeAttackPayload(decoded)) return token
        return decoded
    })
}

function decodeRot13(input: string): string {
    return input.replace(/[a-zA-Z]/g, c => {
        const code = c.charCodeAt(0)
        const base = code <= 90 ? 65 : 97
        return String.fromCharCode(((code - base + 13) % 26) + base)
    })
}

function normalizeNamedEntity(input: string): string {
    return input.replace(/&([a-zA-Z0-9]+);?/gi, (match, name) => {
        const decoded = HTML_NAMED_ENTITIES[name.toLowerCase()]
        return decoded ?? match
    })
}

function normalizeOverlongUtf8(input: string): string {
    return input.replace(OVERLONG_SLASH_RE, '%2F')
}

function decodeBase64Loose(input: string): string | null {
    const decodeCandidate = (candidate: string): string | null => {
        const padded = candidate + '='.repeat((4 - (candidate.length % 4)) % 4)
        try {
            return atob(padded)
        } catch {
            return null
        }
    }

    // Non-standard URL-safe payloads may substitute trailing padding with '-' or '_'.
    if (!input.includes('=') && /[-_]$/.test(input)) {
        const paddingCandidate = input
            .replace(/[-_]+$/g, m => '='.repeat(m.length))
            .replace(/-/g, '+')
            .replace(/_/g, '/')
        const decodedPaddingCandidate = decodeCandidate(paddingCandidate)
        if (decodedPaddingCandidate !== null) return decodedPaddingCandidate
    }

    const normalized = input.replace(/-/g, '+').replace(/_/g, '/')
    const decodedNormalized = decodeCandidate(normalized)
    if (decodedNormalized !== null) return decodedNormalized

    return null
}

function isStandaloneBase64Candidate(input: string): boolean {
    // Restrict standalone decoding to URL-safe alphabet to avoid mutating normal text
    // (paths, API keys, and identifiers that include slash-like separators).
    return /^[A-Za-z0-9_-]{8,4096}={0,2}$/.test(input)
}

function shouldUseDecodedStandaloneBase64(decoded: string): boolean {
    if (!decoded) return false
    let printable = 0
    for (let i = 0; i < decoded.length; i++) {
        const code = decoded.charCodeAt(i)
        if (code === 9 || code === 10 || code === 13 || (code >= 32 && code <= 126)) printable++
    }
    const printableRatio = printable / decoded.length
    return printableRatio >= 0.9
}

/**
 * RFC 3492 Punycode decoder — zero external dependencies.
 * Handles domain labels like xn--invariant-1m4c.io → homoglyph-encoded domain.
 * Without this, attackers use punycode-encoded domains for SSRF homoglyph bypass.
 */
function decodePunycodeLabel(label: string): string {
    if (!/^xn--/i.test(label)) return label
    const encoded = label.slice(4).toLowerCase()
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, initialBias = 72
    const basic = encoded.lastIndexOf('-')
    const output: number[] = []
    if (basic > 0) {
        for (let i = 0; i < basic; i++) output.push(encoded.charCodeAt(i))
    }
    const digitOf = (c: number) =>
        c - 48 < 10 ? c - 48 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base
    const adapt = (delta: number, numPoints: number, firstTime: boolean) => {
        delta = firstTime ? Math.floor(delta / damp) : delta >> 1
        delta += Math.floor(delta / numPoints)
        let k = 0
        while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base }
        return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew))
    }
    let n = 128, i = 0, bias = initialBias
    let ptr = basic > 0 ? basic + 1 : 0
    while (ptr < encoded.length) {
        const oldi = i
        let w = 1
        for (let k = base; ; k += base) {
            if (ptr >= encoded.length) return label
            const digit = digitOf(encoded.charCodeAt(ptr++))
            if (digit >= base) return label
            i += digit * w
            const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias
            if (digit < t) break
            w *= base - t
        }
        bias = adapt(i - oldi, output.length + 1, oldi === 0)
        n += Math.floor(i / (output.length + 1))
        i %= output.length + 1
        output.splice(i, 0, n)
        i++
    }
    try { return output.map(cp => safeFromCodePoint(cp)).join('') } catch { return label }
}

/** Decode punycode labels in domains and URL path segments. */
function decodePunycodeDomains(input: string): string {
    return input.replace(/\bxn--[a-z0-9-]+\b/gi, match => {
        const decoded = decodePunycodeLabel(match)
        return decoded !== match ? decoded : match
    })
}

/**
 * Recursively decode a string through common encoding layers.
 * Returns the fully decoded, normalized form with all bypass techniques stripped.
 */
export function deepDecode(input: string, depth = 0): string {
    if (typeof input !== 'string') return ''
    if (input.includes('\u0000')) input = input.replace(NULL_BYTE_RE, '')
    if (depth > MAX_DECODE_DEPTH) return input
    if (input.length > MAX_INPUT_SIZE) input = input.slice(0, MAX_INPUT_SIZE)

    function normalizeFullwidth(s: string): string {
        return s.replace(/[\uFF01-\uFF5E]/g, c => String.fromCharCode(c.charCodeAt(0) - 0xFF00 + 0x20))
    }

    // SAA-104: Strip invisible/control chars FIRST before any other processing.
    // Order matters: Tags block → BIDI → zero-width → combining marks → control chars.
    // These must come before URL/entity decoding or attackers can encode them.
    let decoded = normalizeFullwidth(input)
        .replace(TAGS_BLOCK, '')
        .replace(BIDI_CONTROLS, '')
        .replace(ZERO_WIDTH_CHARS, '')
        .replace(COMBINING_MARKS_RE, '')
        .replace(ASCII_CONTROL_RE, '')

    // SAA-104: Normalize homoglyphs (Cyrillic/Greek lookalikes → Latin)
    // Must run after invisible char stripping so homoglyphs aren't hidden by zero-width chars.
    decoded = decoded.replace(HOMOGLYPH_RE, c => HOMOGLYPH_MAP[c] ?? c)

    // SAA-104: Normalize compatibility/fullwidth forms before further decoding.
    decoded = decoded.normalize('NFKC')

    // Security critical: normalize known overlong UTF-8 slash encodings.
    decoded = normalizeOverlongUtf8(decoded)

    // URL decode
    // IIS %uXXXX encoding: %u003C -> <
    decoded = decoded.replace(/%u([0-9A-Fa-f]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
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
        .replace(/&[a-z0-9]+;?/gi, match => normalizeNamedEntity(match))

    // Unicode escapes
    decoded = decoded.replace(/\\u([0-9a-f]{4})/gi, (_, hex) =>
        safeFromCodePoint(parseInt(hex, 16)))

    // %5Cu0027 → \u0027 → '
    decoded = decoded.replace(/%5[Cc]u([0-9A-Fa-f]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))

    // IIS-style Unicode escapes: %u003C -> <
    decoded = decoded.replace(/%u([0-9a-f]{4})/gi, (_, hex) =>
        safeFromCodePoint(parseInt(hex, 16)))

    // Hex escapes
    decoded = decoded.replace(/\\x([0-9a-f]{2})/gi, (_, hex) =>
        safeFromCodePoint(parseInt(hex, 16)))

    // C-style escape sequences: \r → CR, \n → LF, \t → TAB
    decoded = decoded.replace(/\\r/g, '\r').replace(/\\n/g, '\n').replace(/\\t/g, '\t')

    const base32Decoded = decodeBase32IfSuspicious(decoded)
    if (base32Decoded !== decoded) {
        return deepDecode(base32Decoded, depth + 1)
    }

    const rot13Decoded = decodeRot13(decoded)
    if (
        rot13Decoded !== decoded &&
        looksLikeAttackPayload(rot13Decoded) &&
        !looksLikeAttackPayload(decoded)
    ) {
        return deepDecode(rot13Decoded, depth + 1)
    }

    // BYP-001: MySQL conditional comments MUST be unwrapped BEFORE generic block comment
    // stripping. /*!50000SELECT*/ → ' SELECT ' preserves the keyword. If the generic
    // /*.*?\*/ runs first, conditional comments collapse to spaces and the keyword is lost.
    decoded = decoded.replace(/\/\*!\d*\s*([\s\S]*?)\*\//g, (_, inner) => ' ' + inner + ' ')

    // Collapse SQL comment-space bypass: /**/ → space
    decoded = decoded.replace(/\/\*[\s\S]*?\*\//g, ' ')

    // Normalize whitespace/control chars inside protocol keywords:
    // java\tscript: → javascript:,  vb\nscript: → vbscript:
    decoded = normalizeProtocolKeyword(decoded, 'javascript')
    decoded = normalizeProtocolKeyword(decoded, 'vbscript')

    // Decode base64 data URIs: data:text/html;base64,XXXX
    // Cap at 4096 chars to prevent DoS via huge base64 payloads.
    decoded = decoded.replace(/data:[^;,]*;base64,([A-Za-z0-9+/_=-]{1,4096})/gi, (full, b64) => {
        const plain = decodeBase64Loose(b64)
        return plain === null ? full : `data:text/html,${plain}`
    })

    // URL-safe base64: replace - → + and _ → / then decode
    decoded = decoded.replace(/data:[^;,]*;base64,([A-Za-z0-9_\-]{1,4096})/gi, (full, b64) => {
        if (!b64.includes('-') && !b64.includes('_')) return full
        try {
            return `data:text/html,${atob(b64.replace(/-/g, '+').replace(/_/g, '/'))}`
        } catch {
            return full
        }
    })

    // Standalone/base token base64 decode (including URL-safe alphabet).
    if (isStandaloneBase64Candidate(decoded)) {
        const plain = decodeBase64Loose(decoded)
        if (plain !== null && shouldUseDecodedStandaloneBase64(plain)) {
            decoded = plain
        }
    }

    // Standalone URL-safe base64 payloads that look like attack payloads after decode.
    if (isStandaloneBase64Candidate(decoded) && /[-_]/.test(decoded)) {
        const plain = decodeBase64Loose(decoded)
        if (plain !== null && shouldUseDecodedStandaloneBase64(plain) && looksLikeAttackPayload(plain)) {
            decoded = plain
        }
    }

    // SAA-104: Punycode domain decoding (SSRF homoglyph bypass via IDN)
    decoded = decodePunycodeDomains(decoded)

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
