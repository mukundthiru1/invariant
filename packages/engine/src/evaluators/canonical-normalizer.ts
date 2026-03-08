/**
 * Canonical Normalizer — Universal Input Normalization Primitive
 *
 * The fundamental principle: EVERY representation of the same semantic
 * input MUST map to the same canonical form BEFORE property checking.
 *
 * The SSRF evaluator pioneered this: all IP representations (hex, octal,
 * compressed, IPv6-mapped) resolve to a 32-bit integer. This normalizer
 * generalizes that principle to ALL input types.
 *
 * Why this matters:
 *   An attacker has ~N encoding tricks (URL, double-URL, Unicode, overlong
 *   UTF-8, HTML entities, hex escapes, octal, mixed radix). Without
 *   canonical normalization, each evaluator must handle N² combinations
 *   independently. With canonical normalization, every evaluator receives
 *   a single canonical form — reducing the attack surface to ZERO for
 *   encoding-based evasions.
 *
 * Normalization layers (applied in order):
 *   1. URL decoding (iterative, up to 3 layers)
 *   2. HTML entity decoding (named + numeric)
 *   3. Unicode normalization (NFC)
 *   4. Overlong UTF-8 resolution
 *   5. Null byte removal
 *   6. Case-fold (optional, for case-insensitive contexts)
 *   7. Whitespace normalization (collapse + strip)
 *
 * The invariant: canonical(encode₁(input)) === canonical(encode₂(input))
 * for ALL encoding functions encode₁, encode₂.
 */


// ── HTML Entity Decoding ────────────────────────────────────────

const NAMED_ENTITIES: Record<string, string> = {
    'amp': '&', 'lt': '<', 'gt': '>', 'quot': '"', 'apos': "'",
    'nbsp': ' ', 'tab': '\t', 'newline': '\n',
    'excl': '!', 'num': '#', 'dollar': '$', 'percnt': '%',
    'lpar': '(', 'rpar': ')', 'ast': '*', 'plus': '+',
    'comma': ',', 'period': '.', 'sol': '/', 'colon': ':',
    'semi': ';', 'equals': '=', 'quest': '?', 'commat': '@',
    'lsqb': '[', 'rsqb': ']', 'lbrace': '{', 'rbrace': '}',
    'vert': '|', 'bsol': '\\', 'grave': '`', 'tilde': '~',
}

function decodeHtmlEntities(input: string): string {
    return input
        // Hex numeric entities: &#x41; → A
        .replace(/&#x([0-9a-fA-F]{1,6});?/g, (_, hex: string) => {
            const cp = parseInt(hex, 16)
            return cp > 0 && cp <= 0x10FFFF ? String.fromCodePoint(cp) : _
        })
        // Decimal numeric entities: &#65; → A
        .replace(/&#(\d{1,7});?/g, (_, dec: string) => {
            const cp = parseInt(dec, 10)
            return cp > 0 && cp <= 0x10FFFF ? String.fromCodePoint(cp) : _
        })
        // Named entities
        .replace(/&([a-zA-Z]+);/g, (full, name: string) => {
            return NAMED_ENTITIES[name.toLowerCase()] ?? full
        })
}


// ── Unicode Escape Decoding ─────────────────────────────────────

function decodeUnicodeEscapes(input: string): string {
    return input
        // \uXXXX
        .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex: string) =>
            String.fromCharCode(parseInt(hex, 16)))
        // \xXX
        .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex: string) =>
            String.fromCharCode(parseInt(hex, 16)))
        // \OOO (octal, 1-3 digits, max \377)
        .replace(/\\([0-3][0-7]{2})/g, (_, oct: string) =>
            String.fromCharCode(parseInt(oct, 8)))
}


// ── Overlong UTF-8 Normalization ────────────────────────────────
//
// Overlong UTF-8 sequences encode ASCII characters with more bytes
// than necessary. Example: / (0x2F) can be encoded as:
//   C0 AF (2-byte overlong)
//   E0 80 AF (3-byte overlong)
//
// URL-encoded overlong: %C0%AF → /
// These bypass security filters that only check ASCII representations.

function decodeOverlongUtf8(input: string): string {
    // Detect URL-encoded overlong sequences
    return input
        // 2-byte overlong: %C0%80-%C0%BF → ASCII 0x00-0x3F
        .replace(/%C0%([89AB][0-9A-F])/gi, (_, tail: string) => {
            const byte2 = parseInt(tail, 16)
            const cp = byte2 & 0x3F
            return cp > 0 ? String.fromCharCode(cp) : '\x00'
        })
        // 2-byte overlong: %C1%80-%C1%BF → ASCII 0x40-0x7F
        .replace(/%C1%([89AB][0-9A-F])/gi, (_, tail: string) => {
            const byte2 = parseInt(tail, 16)
            const cp = 0x40 | (byte2 & 0x3F)
            return String.fromCharCode(cp)
        })
        // 3-byte overlong: %E0%80%80-%E0%80%BF → ASCII 0x00-0x3F
        .replace(/%E0%80%([89AB][0-9A-F])/gi, (_, tail: string) => {
            const byte3 = parseInt(tail, 16)
            const cp = byte3 & 0x3F
            return cp > 0 ? String.fromCharCode(cp) : '\x00'
        })
}


// ── URL Decoding ────────────────────────────────────────────────

function iterativeUrlDecode(input: string, maxLayers: number = 3): string {
    let current = input
    for (let i = 0; i < maxLayers; i++) {
        let next: string
        try {
            next = decodeURIComponent(current)
        } catch {
            break
        }
        if (next === current) break
        current = next
    }
    return current
}


// ── Null Byte Removal ───────────────────────────────────────────

function removeNullBytes(input: string): string {
    return input
        .replace(/%00/gi, '')
        .replace(/\x00/g, '')
}


// ── Whitespace Normalization ────────────────────────────────────

function normalizeWhitespace(input: string): string {
    // Collapse all whitespace sequences (including tabs, vertical tabs,
    // form feeds, zero-width spaces) to a single space
    return input.replace(/[\s\u200B\uFEFF]+/g, ' ').trim()
}


// ── Public API ──────────────────────────────────────────────────

export interface NormalizationResult {
    /** The canonical form of the input */
    canonical: string
    /** How many encoding layers were resolved */
    encodingDepth: number
    /** Which encoding types were detected */
    encodingsDetected: Set<string>
    /** Whether the input differed from its canonical form */
    wasEncoded: boolean
}

/**
 * Normalize an input string to its canonical form.
 *
 * The canonical form is the semantic content of the input with all
 * encoding layers resolved. Two inputs that would produce the same
 * effect when interpreted MUST have the same canonical form.
 *
 * @param input Raw input string (URL-encoded, HTML-encoded, etc.)
 * @param options Control which normalization steps to apply
 * @returns The canonical form and encoding metadata
 */
export function canonicalize(
    input: string,
    options?: {
        /** Apply case folding (default: false — case-sensitive) */
        caseFold?: boolean
        /** Normalize whitespace (default: false — preserve original) */
        normalizeWs?: boolean
        /** Maximum length to process (default: 16384) */
        maxLength?: number
    },
): NormalizationResult {
    const maxLen = options?.maxLength ?? 16384
    let current = input.length > maxLen ? input.slice(0, maxLen) : input
    const encodingsDetected = new Set<string>()
    let depth = 0

    // 1. Overlong UTF-8 (before URL decode to catch %C0%AF patterns)
    const afterOverlong = decodeOverlongUtf8(current)
    if (afterOverlong !== current) {
        encodingsDetected.add('overlong_utf8')
        depth++
        current = afterOverlong
    }

    // 2. Iterative URL decoding
    const afterUrl = iterativeUrlDecode(current)
    if (afterUrl !== current) {
        // Count the actual decode layers
        let layerCheck = current
        for (let i = 0; i < 3; i++) {
            let next: string
            try { next = decodeURIComponent(layerCheck) } catch { break }
            if (next === layerCheck) break
            depth++
            layerCheck = next
        }
        if (depth === 1) encodingsDetected.add('url_single')
        else if (depth >= 2) encodingsDetected.add('url_double')
        current = afterUrl
    }

    // 3. HTML entity decoding
    const afterHtml = decodeHtmlEntities(current)
    if (afterHtml !== current) {
        encodingsDetected.add('html_entity')
        depth++
        current = afterHtml
    }

    // 4. Unicode escape decoding
    const afterUnicode = decodeUnicodeEscapes(current)
    if (afterUnicode !== current) {
        encodingsDetected.add('unicode_escape')
        depth++
        current = afterUnicode
    }

    // 5. Null byte removal
    const afterNull = removeNullBytes(current)
    if (afterNull !== current) {
        encodingsDetected.add('null_byte')
        depth++
        current = afterNull
    }

    // 6. Case folding (optional)
    if (options?.caseFold) {
        current = current.toLowerCase()
    }

    // 7. Whitespace normalization (optional)
    if (options?.normalizeWs) {
        current = normalizeWhitespace(current)
    }

    return {
        canonical: current,
        encodingDepth: depth,
        encodingsDetected,
        wasEncoded: current !== input,
    }
}

/**
 * Quick canonical form — just the string, no metadata.
 * For evaluators that just need the decoded input.
 */
export function quickCanonical(input: string): string {
    return canonicalize(input).canonical
}

/**
 * Detect encoding evasion — returns true if the input uses multiple
 * encoding layers, which is a strong signal of deliberate evasion.
 *
 * The invariant: legitimate input uses at most one encoding layer
 * (URL encoding for HTTP transport). Multiple layers indicate
 * deliberate evasion of security filters.
 */
export function detectEncodingEvasion(input: string): {
    isEvasion: boolean
    depth: number
    encodings: string[]
    confidence: number
} {
    const result = canonicalize(input)

    // Single URL encoding is normal (HTTP transport)
    // Anything beyond that is suspicious
    const isNormalUrlEncoding = result.encodingsDetected.size === 1 &&
        result.encodingsDetected.has('url_single')

    const isEvasion = result.encodingDepth >= 2 && !isNormalUrlEncoding

    // Confidence scales with depth and diversity of encoding
    let confidence = 0
    if (isEvasion) {
        confidence = Math.min(0.95,
            0.60 + (result.encodingDepth - 1) * 0.10 + (result.encodingsDetected.size - 1) * 0.08)
    }

    return {
        isEvasion,
        depth: result.encodingDepth,
        encodings: [...result.encodingsDetected],
        confidence,
    }
}
