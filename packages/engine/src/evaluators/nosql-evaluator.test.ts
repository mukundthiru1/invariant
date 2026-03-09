import { describe, expect, it } from 'vitest'
import { detectNoSQLInjection } from './nosql-evaluator.js'

describe('nosql-evaluator bypass regressions', () => {
    it('detects Function constructor JS injection in $where', () => {
        const input = '{"$where":"Function(\'return this.admin\')()"}'
        const results = detectNoSQLInjection(input)
        expect(results.some(r => r.type === 'js_injection')).toBe(true)
    })

    it('detects eval() JS injection in $where', () => {
        const input = '{"$where":"eval(\'this.password.length>0\')"}'
        const results = detectNoSQLInjection(input)
        expect(results.some(r => r.type === 'js_injection')).toBe(true)
    })

    it('detects constructor escape in $where', () => {
        const input = '{"$where":"this[\'constructor\'][\'constructor\'](\'return process\')()"}'
        const results = detectNoSQLInjection(input)
        expect(results.some(r => r.type === 'js_injection')).toBe(true)
    })

    it('detects URL parameter operator injection with nested field paths', () => {
        const input = 'query[user.name][$ne]=null'
        const results = detectNoSQLInjection(input)
        expect(results.some(r => r.type === 'operator_injection' && r.operator.toLowerCase() === '$ne')).toBe(true)
    })

    it('detects dot-notation operator injection', () => {
        const input = 'username.$ne=admin'
        const results = detectNoSQLInjection(input)
        expect(results.some(r => r.type === 'operator_injection' && r.operator.toLowerCase() === '$ne')).toBe(true)
    })

    it('detects BSON extended JSON wrappers used as operators', () => {
        const input = '{"_id":{"$oid":"507f1f77bcf86cd799439011"}}'
        const results = detectNoSQLInjection(input)
        expect(results.some(r => r.type === 'operator_injection' && r.operator.toLowerCase() === '$oid')).toBe(true)
    })

    it('does not trigger on benign dollar usage', () => {
        const input = 'price is $50 and $HOME is env var'
        expect(detectNoSQLInjection(input)).toEqual([])
    })

    it('detects MongoDB regex injection with options', () => {
        const input = '{"email":{"$regex":"^admin","$options":"i"}}'
        const results = detectNoSQLInjection(input)
        expect(results.some(r => r.type === 'operator_injection' && r.operator.toLowerCase() === '$regex')).toBe(true)
        expect(results.some(r => r.type === 'operator_injection' && r.operator.toLowerCase() === '$options')).toBe(true)
    })

    it('detects MongoDB array operator bypasses', () => {
        const input = '{"role":{"$in":["admin","user"]},"disabled":{"$nin":[""]}}'
        const results = detectNoSQLInjection(input)
        expect(results.some(r => r.type === 'operator_injection' && r.operator.toLowerCase() === '$in')).toBe(true)
        expect(results.some(r => r.type === 'operator_injection' && r.operator.toLowerCase() === '$nin')).toBe(true)
    })

    it('detects MongoDB $where function javascript injection', () => {
        const input = '{"$where":"function() { return true; }"}'
        const results = detectNoSQLInjection(input)
        expect(results.some(r => r.type === 'js_injection')).toBe(true)
    })

    it('detects CouchDB selector operator injection', () => {
        const input = '{"selector":{"$or":[{"type":"admin"}]}}'
        const results = detectNoSQLInjection(input)
        expect(results.some(r => r.type === 'operator_injection' && r.detail.includes('CouchDB'))).toBe(true)
    })

    it('detects Elasticsearch match_all and script injection payloads', () => {
        const matchAll = '{"query":{"match_all":{}}}'
        const script = '{"query":{"script":{"script":{"source":"ctx._source.isAdmin=true","lang":"painless"}}}}'

        const matchAllResults = detectNoSQLInjection(matchAll)
        const scriptResults = detectNoSQLInjection(script)

        expect(matchAllResults.some(r => r.type === 'operator_injection' && r.operator === 'match_all')).toBe(true)
        expect(scriptResults.some(r => r.type === 'operator_injection' && r.operator === 'script')).toBe(true)
    })

    it('detects Redis command injection delivered over SSRF transport', () => {
        const input = 'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a*3%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$4%0d%0adir%0d%0a'
        const results = detectNoSQLInjection(input)
        expect(results.some(r => r.type === 'operator_injection' && r.operator.startsWith('redis:FLUSHALL'))).toBe(true)
        expect(results.some(r => r.type === 'operator_injection' && r.operator.startsWith('redis:CONFIG SET'))).toBe(true)
    })

    it('does not flag benign Elasticsearch term query', () => {
        const input = '{"query":{"term":{"status":"active"}}}'
        expect(detectNoSQLInjection(input)).toEqual([])
    })
})
