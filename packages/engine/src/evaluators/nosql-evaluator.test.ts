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
})
