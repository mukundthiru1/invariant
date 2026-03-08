import { describe, it, expect } from 'vitest'
import {
    canonicalize,
    quickCanonical,
    detectEncodingEvasion,
} from './canonical-normalizer.js'

describe('Canonical Normalizer', () => {

    describe('URL decoding', () => {
        it('decodes single-layer URL encoding', () => {
            const result = canonicalize('%3Cscript%3Ealert(1)%3C%2Fscript%3E')
            expect(result.canonical).toBe('<script>alert(1)</script>')
            expect(result.encodingsDetected.has('url_single')).toBe(true)
        })

        it('decodes double-layer URL encoding', () => {
            const result = canonicalize('%253Cscript%253E')
            expect(result.canonical).toBe('<script>')
            expect(result.encodingsDetected.has('url_double')).toBe(true)
        })

        it('decodes triple-layer URL encoding', () => {
            const result = canonicalize('%25253Cscript%25253E')
            expect(result.canonical).toBe('<script>')
            expect(result.encodingDepth).toBeGreaterThanOrEqual(2)
        })
    })

    describe('HTML entity decoding', () => {
        it('decodes hex numeric entities', () => {
            expect(quickCanonical('&#x3C;script&#x3E;')).toBe('<script>')
        })

        it('decodes decimal numeric entities', () => {
            expect(quickCanonical('&#60;script&#62;')).toBe('<script>')
        })

        it('decodes named entities', () => {
            expect(quickCanonical('&lt;script&gt;')).toBe('<script>')
        })

        it('handles mixed entity types', () => {
            expect(quickCanonical('&lt;img src&#x3D;x onerror&#61;alert(1)&gt;'))
                .toBe('<img src=x onerror=alert(1)>')
        })
    })

    describe('Unicode escape decoding', () => {
        it('decodes \\uXXXX', () => {
            expect(quickCanonical('\\u003Cscript\\u003E')).toBe('<script>')
        })

        it('decodes \\xXX', () => {
            expect(quickCanonical('\\x3Cscript\\x3E')).toBe('<script>')
        })
    })

    describe('Overlong UTF-8', () => {
        it('decodes 2-byte overlong slash', () => {
            // %C0%AF is overlong encoding of / (0x2F)
            const result = canonicalize('..%C0%AF..%C0%AFetc/passwd')
            expect(result.canonical).toContain('/')
            expect(result.encodingsDetected.has('overlong_utf8')).toBe(true)
        })
    })

    describe('Null byte removal', () => {
        it('removes URL-encoded null bytes', () => {
            expect(quickCanonical('file.php%00.jpg')).toBe('file.php.jpg')
        })

        it('removes raw null bytes', () => {
            expect(quickCanonical('file.php\x00.jpg')).toBe('file.php.jpg')
        })
    })

    describe('Combined encoding layers', () => {
        it('resolves URL + HTML entities', () => {
            // URL-encoded HTML entity
            const result = canonicalize('%26lt%3Bscript%26gt%3B')
            expect(result.canonical).toBe('<script>')
            expect(result.encodingDepth).toBeGreaterThanOrEqual(2)
        })

        it('resolves URL + Unicode escapes', () => {
            const result = canonicalize('%5Cu003Cscript%5Cu003E')
            expect(result.canonical).toBe('<script>')
        })
    })

    describe('Options', () => {
        it('case folds when requested', () => {
            const result = canonicalize('SELECT * FROM Users', { caseFold: true })
            expect(result.canonical).toBe('select * from users')
        })

        it('normalizes whitespace when requested', () => {
            const result = canonicalize('  hello   world  ', { normalizeWs: true })
            expect(result.canonical).toBe('hello world')
        })

        it('respects maxLength', () => {
            const long = 'A'.repeat(50000)
            const result = canonicalize(long, { maxLength: 100 })
            expect(result.canonical.length).toBeLessThanOrEqual(100)
        })
    })

    describe('quickCanonical', () => {
        it('returns just the string', () => {
            expect(typeof quickCanonical('hello')).toBe('string')
            expect(quickCanonical('hello')).toBe('hello')
        })

        it('decodes transparently', () => {
            expect(quickCanonical('%27%20OR%201%3D1--')).toBe("' OR 1=1--")
        })
    })
})


describe('Canonical Normalizer — Real Attack Evasion Patterns', () => {
    // These are encoding evasion techniques from real-world attacks.
    // The normalizer must resolve ALL of them to the same canonical form.

    it('resolves all representations of <script> to the same form', () => {
        const variants = [
            '<script>',                          // plain
            '%3Cscript%3E',                      // URL encoded
            '%253Cscript%253E',                  // double URL encoded
            '&#x3C;script&#x3E;',                // hex HTML entity
            '&#60;script&#62;',                  // decimal HTML entity
            '&lt;script&gt;',                    // named HTML entity
            '\\u003Cscript\\u003E',              // Unicode escape
            '\\x3Cscript\\x3E',                  // hex escape
        ]

        const canonicals = variants.map(v => quickCanonical(v))
        // All should resolve to the same thing
        for (const c of canonicals) {
            expect(c).toBe('<script>')
        }
    })

    it('resolves path traversal encoding variants', () => {
        const variants = [
            '../../../etc/passwd',               // plain
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',  // URL encoded
            '..%252f..%252f..%252fetc%252fpasswd',        // double encoded slash
        ]

        const canonicals = variants.map(v => quickCanonical(v))
        for (const c of canonicals) {
            expect(c).toContain('../')
            expect(c).toContain('etc/passwd')
        }
    })

    it('resolves SQL injection encoding variants', () => {
        const variants = [
            "' OR 1=1--",                        // plain
            "%27%20OR%201%3D1--",                 // URL encoded
        ]

        const canonicals = variants.map(v => quickCanonical(v))
        for (const c of canonicals) {
            expect(c).toContain("' OR 1=1--")
        }
    })
})


describe('Encoding Evasion Detection', () => {
    it('does not flag single URL encoding', () => {
        const result = detectEncodingEvasion('%2Fpath%2Fto%2Ffile')
        expect(result.isEvasion).toBe(false)
    })

    it('flags double URL encoding', () => {
        const result = detectEncodingEvasion('%252e%252e%252fetc%252fpasswd')
        expect(result.isEvasion).toBe(true)
        expect(result.depth).toBeGreaterThanOrEqual(2)
        expect(result.confidence).toBeGreaterThan(0.6)
    })

    it('flags URL + overlong UTF-8 combination', () => {
        const result = detectEncodingEvasion('..%C0%AF..%C0%AFetc%2Fpasswd')
        expect(result.isEvasion).toBe(true)
        expect(result.encodings).toContain('overlong_utf8')
    })

    it('does not flag plain text', () => {
        const result = detectEncodingEvasion('hello world this is a normal input')
        expect(result.isEvasion).toBe(false)
        expect(result.confidence).toBe(0)
    })

    it('does not flag short inputs', () => {
        const result = detectEncodingEvasion('abc')
        expect(result.isEvasion).toBe(false)
    })
})
