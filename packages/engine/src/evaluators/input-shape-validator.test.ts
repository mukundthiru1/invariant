import { describe, it, expect } from 'vitest'
import { validateShape, inferFieldType, autoValidateShape } from './input-shape-validator.js'

describe('Input Shape Validator', () => {

    describe('username shape', () => {
        it('accepts valid usernames', () => {
            expect(validateShape('john_doe', 'username').matches).toBe(true)
            expect(validateShape('user123', 'username').matches).toBe(true)
            expect(validateShape('a.b-c@d', 'username').matches).toBe(true)
        })

        it('rejects SQL injection in username', () => {
            const result = validateShape("admin' OR 1=1--", 'username')
            expect(result.matches).toBe(false)
            expect(result.deviation).toBeGreaterThan(0.3)
            expect(result.violations.some(v => v.constraint === 'charset')).toBe(true)
            expect(result.violations.some(v => v.constraint === 'whitespace')).toBe(true)
        })

        it('rejects XSS in username', () => {
            const result = validateShape('<script>alert(1)</script>', 'username')
            expect(result.matches).toBe(false)
            expect(result.violations.some(v => v.constraint === 'charset')).toBe(true)
        })

        it('rejects very long input', () => {
            const result = validateShape('a'.repeat(200), 'username')
            expect(result.matches).toBe(false)
            expect(result.violations.some(v => v.constraint === 'length')).toBe(true)
        })
    })

    describe('email shape', () => {
        it('accepts valid emails', () => {
            expect(validateShape('user@example.com', 'email').matches).toBe(true)
            expect(validateShape('a.b+c@sub.domain.org', 'email').matches).toBe(true)
        })

        it('rejects missing @', () => {
            const result = validateShape('not-an-email', 'email')
            expect(result.matches).toBe(false)
            expect(result.deviation).toBeGreaterThan(0.5)
        })

        it('rejects SQL injection in email', () => {
            const result = validateShape("admin@x.com' OR 1=1--", 'email')
            expect(result.matches).toBe(false)
        })
    })

    describe('integer shape', () => {
        it('accepts valid integers', () => {
            expect(validateShape('42', 'integer').matches).toBe(true)
            expect(validateShape('-7', 'integer').matches).toBe(true)
            expect(validateShape('0', 'integer').matches).toBe(true)
        })

        it('rejects SQL injection in integer field', () => {
            const result = validateShape("1 OR 1=1", 'integer')
            expect(result.matches).toBe(false)
            expect(result.deviation).toBeGreaterThan(0.8)
        })

        it('rejects path traversal in integer field', () => {
            const result = validateShape("../../etc/passwd", 'integer')
            expect(result.matches).toBe(false)
        })
    })

    describe('uuid shape', () => {
        it('accepts valid UUIDs', () => {
            expect(validateShape('550e8400-e29b-41d4-a716-446655440000', 'uuid').matches).toBe(true)
        })

        it('rejects anything that is not a UUID', () => {
            expect(validateShape("' OR 1=1--", 'uuid').matches).toBe(false)
            expect(validateShape('not-a-uuid', 'uuid').matches).toBe(false)
        })
    })

    describe('filename shape', () => {
        it('accepts valid filenames', () => {
            expect(validateShape('report.pdf', 'filename').matches).toBe(true)
            expect(validateShape('my-document_v2.docx', 'filename').matches).toBe(true)
        })

        it('rejects path traversal', () => {
            const result = validateShape('../../etc/passwd', 'filename')
            expect(result.matches).toBe(false)
            expect(result.violations.some(v => v.constraint === 'path_separator')).toBe(true)
            expect(result.violations.some(v => v.constraint === 'dotdot')).toBe(true)
        })

        it('rejects null byte injection', () => {
            const result = validateShape('image.jpg\0.php', 'filename')
            expect(result.matches).toBe(false)
            expect(result.violations.some(v => v.constraint === 'null_byte')).toBe(true)
        })
    })

    describe('search shape', () => {
        it('accepts natural language queries', () => {
            expect(validateShape('best restaurants in NYC', 'search').matches).toBe(true)
            expect(validateShape('how to cook pasta', 'search').matches).toBe(true)
        })

        it('flags high metacharacter ratio', () => {
            const result = validateShape("'; DROP TABLE users; --", 'search')
            expect(result.matches).toBe(false)
            expect(result.violations.some(v => v.constraint === 'metachar_ratio')).toBe(true)
        })

        it('accepts short queries without alpha check', () => {
            // Short queries (≤5 chars) skip alpha ratio check
            expect(validateShape('42', 'search').matches).toBe(true)
        })
    })

    describe('url shape', () => {
        it('accepts valid URLs', () => {
            expect(validateShape('https://example.com/path?q=1', 'url').matches).toBe(true)
            expect(validateShape('/api/v1/users', 'url').matches).toBe(true)
        })

        it('flags control characters in URL', () => {
            const result = validateShape('https://example.com/\r\nX-Injected: true', 'url')
            expect(result.matches).toBe(false)
            expect(result.violations.some(v => v.constraint === 'control_chars')).toBe(true)
        })
    })

    describe('freetext shape', () => {
        it('accepts normal text', () => {
            expect(validateShape('Hello, this is a normal comment.', 'freetext').matches).toBe(true)
        })

        it('flags extreme metacharacter density', () => {
            const result = validateShape("{{{{[[[[]]]]}}}}<<<>>>'''", 'freetext')
            expect(result.matches).toBe(false)
            expect(result.violations.some(v => v.constraint === 'metachar_density')).toBe(true)
        })

        it('flags control characters', () => {
            const result = validateShape('text\x00with\x01control\x02chars', 'freetext')
            expect(result.matches).toBe(false)
        })
    })

    describe('phone shape', () => {
        it('accepts valid phone numbers', () => {
            expect(validateShape('+1 (555) 123-4567', 'phone').matches).toBe(true)
            expect(validateShape('555-0100', 'phone').matches).toBe(true)
        })

        it('rejects injection in phone field', () => {
            const result = validateShape("555; cat /etc/passwd", 'phone')
            expect(result.matches).toBe(false)
        })
    })

    describe('slug shape', () => {
        it('accepts valid slugs', () => {
            expect(validateShape('hello-world', 'slug').matches).toBe(true)
            expect(validateShape('post123', 'slug').matches).toBe(true)
        })

        it('rejects injection in slug', () => {
            expect(validateShape("hello-world'; DROP TABLE--", 'slug').matches).toBe(false)
        })
    })

    describe('ipv4 shape', () => {
        it('accepts valid IPs', () => {
            expect(validateShape('192.168.1.1', 'ipv4').matches).toBe(true)
            expect(validateShape('10.0.0.1', 'ipv4').matches).toBe(true)
        })

        it('rejects SSRF payloads', () => {
            expect(validateShape('169.254.169.254/latest/meta-data', 'ipv4').matches).toBe(false)
        })
    })

    describe('confidence boost scaling', () => {
        it('high deviation gives 0.10 boost', () => {
            const result = validateShape("' OR 1=1--", 'integer')
            expect(result.deviation).toBeGreaterThanOrEqual(0.7)
            expect(result.confidenceBoost).toBe(0.10)
        })

        it('medium deviation gives 0.05 boost', () => {
            const result = validateShape('a'.repeat(200), 'username')
            // Length violation alone is severity 0.3 → deviation ~0.3
            expect(result.confidenceBoost).toBeLessThanOrEqual(0.05)
        })

        it('no violations gives 0 boost', () => {
            const result = validateShape('john_doe', 'username')
            expect(result.confidenceBoost).toBe(0)
        })
    })

    describe('inferFieldType', () => {
        it('infers common field types from parameter names', () => {
            expect(inferFieldType('email')).toBe('email')
            expect(inferFieldType('user_email')).toBe('email')
            expect(inferFieldType('username')).toBe('username')
            expect(inferFieldType('phone')).toBe('phone')
            expect(inferFieldType('q')).toBe('search')
            expect(inferFieldType('search')).toBe('search')
            expect(inferFieldType('query')).toBe('search')
            expect(inferFieldType('filename')).toBe('filename')
            expect(inferFieldType('page')).toBe('integer')
            expect(inferFieldType('limit')).toBe('integer')
            expect(inferFieldType('redirect_url')).toBe('url')
            expect(inferFieldType('callback')).toBe('url')
            expect(inferFieldType('slug')).toBe('slug')
            expect(inferFieldType('ip_address')).toBe('ipv4')
            expect(inferFieldType('price')).toBe('float')
            expect(inferFieldType('created_at')).toBe('date')
        })

        it('returns null for ambiguous names', () => {
            expect(inferFieldType('data')).toBe(null)
            expect(inferFieldType('value')).toBe(null)
            expect(inferFieldType('content')).toBe(null)
        })

        it('detects id fields', () => {
            expect(inferFieldType('id')).toBe('uuid')
            expect(inferFieldType('user_id')).toBe('uuid')
            expect(inferFieldType('userId')).toBe('uuid')
        })
    })

    describe('autoValidateShape', () => {
        it('auto-validates with inferred type', () => {
            const result = autoValidateShape("' OR 1=1--", 'email')
            expect(result).not.toBeNull()
            expect(result!.matches).toBe(false)
        })

        it('returns null for unknown param names', () => {
            expect(autoValidateShape('anything', 'data')).toBe(null)
        })

        it('validates SQL injection in integer id field', () => {
            const result = autoValidateShape("1 UNION SELECT * FROM users", 'page')
            expect(result).not.toBeNull()
            expect(result!.matches).toBe(false)
            expect(result!.deviation).toBeGreaterThan(0.8)
        })
    })
})
