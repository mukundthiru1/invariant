import { describe, it, expect } from 'vitest'
import {
    detectTautologies,
    parseCaseWhen,
    sqlTokenize,
} from './sql-expression-evaluator.js'

function has(expressionText: string, contains: string) {
    return expressionText.includes(contains)
}

function expectTautology(input: string) {
    const detections = detectTautologies(input)
    expect(detections.length).toBeGreaterThan(0)
    return detections
}

describe('sql-expression-evaluator bypasses', () => {
    it('detects Oracle/SQLite || string concatenation tautology', () => {
        const detections = expectTautology("' ||UPPER('A')='A'")
        const expression = detections[0]?.expression
        expect(has(expression ?? '', "UPPER('A')")).toBe(true)
        expect(has(expression ?? '', '||')).toBe(true)
    })

    it('detects tautological CASE WHEN branches', () => {
        const detections = expectTautology('CASE WHEN 1=1 THEN 1 ELSE 0 END')
        expect(detections.some(d => has(d.expression, 'TAUTOLOGY'))).toBe(true)

        const stringy = expectTautology("CASE WHEN 'a'='a' THEN TRUE ELSE FALSE END")
        expect(stringy.some(d => has(d.expression, 'TAUTOLOGY'))).toBe(true)
    })

    it('returns tautology node for tautological CASE WHEN conditions', () => {
        const tokens = sqlTokenize('CASE WHEN 1=1 THEN 1 ELSE 0 END').filter(
            t => t.type !== 'WHITESPACE' && t.type !== 'SEPARATOR',
        )
        const parsed = parseCaseWhen(tokens, 0)

        expect(parsed.node).toMatchObject({
            kind: 'tautology',
            confidence: 0.85,
        })
    })

    it('flags CASE with tautological WHEN even if THEN expression is malformed', () => {
        const detections = detectTautologies('CASE WHEN 1=1 THEN END')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('flags CASE as tautology even when tautological WHEN returns falsey value', () => {
        const detections = detectTautologies('CASE WHEN NULL IS NULL THEN 0 ELSE 0 END')
        expect(detections.length).toBeGreaterThan(0)
    })

    it('detects bitwise tautologies and shifts', () => {
        const andBitwiseAnd = expectTautology('1 OR 1&1')
        expect(andBitwiseAnd.some(d => has(d.expression, '1 & 1'))).toBe(true)

        const unaryNot = expectTautology('1 OR ~0')
        expect(unaryNot.some(d => has(d.expression, '~0'))).toBe(true)

        const bitwiseOr = expectTautology('1 OR 1|0')
        expect(bitwiseOr.some(d => has(d.expression, '1 | 0'))).toBe(true)

        const bitwiseXor = expectTautology('1 OR 2^1')
        expect(bitwiseXor.some(d => has(d.expression, '2 ^ 1'))).toBe(true)

        const bitwiseShift = expectTautology('1 OR 1<<1')
        expect(bitwiseShift.some(d => has(d.expression, '1 << 1'))).toBe(true)

        const shiftEq = expectTautology('1 OR 1<<0=1')
        expect(shiftEq.some(d => has(d.expression, '1 << 0 = 1'))).toBe(true)

        const rightShiftEq = expectTautology('1 OR 8>>3=1')
        expect(rightShiftEq.some(d => has(d.expression, '8 >> 3 = 1'))).toBe(true)

        const andEq = expectTautology('1 OR 1&1=1')
        expect(andEq.some(d => has(d.expression, '1 & 1 = 1'))).toBe(true)

        const orEq = expectTautology('1 OR 255|0=255')
        expect(orEq.some(d => has(d.expression, '255 | 0 = 255'))).toBe(true)

        const hexEquals = expectTautology('1 OR 0xFF = 255')
        expect(hexEquals.some(d => has(d.expression, '255 = 255'))).toBe(true)
    })

    it('detects NULL, NULL/NOT NULL tautologies', () => {
        const nullIsNull = detectTautologies("1 OR NULL IS NULL")
        expect(nullIsNull.length).toBeGreaterThan(0)
        expect(nullIsNull.some(d => has(d.expression, 'NULL IS NULL'))).toBe(true)

        const nullNotNull = detectTautologies("1 OR NULL IS NOT NULL")
        expect(nullNotNull.length).toBe(0)

        const oneIsNotNull = detectTautologies("1 OR 1 IS NOT NULL")
        expect(oneIsNotNull.length).toBeGreaterThan(0)
        expect(oneIsNotNull.some(d => has(d.expression, '1 IS NOT NULL'))).toBe(true)
    })

    it('evaluates previously missing SQL functions', () => {
        expectTautology("1 OR UPPER('a')='A'")
        expectTautology("1 OR LOWER('A')='a'")
        expectTautology("1 OR LENGTH('abc')=3")
        expectTautology("1 OR ASCII('A')=65")
        expectTautology("1 OR CHAR(65)='A'")
        expectTautology("1 OR SUBSTR('abc',2,2)='bc'")
        expectTautology("1 OR SUBSTRING('abcd',2,2)='bc'")
        expectTautology("1 OR TRIM(' a ')='a'")
        expectTautology("1 OR LTRIM('  a')='a'")
        expectTautology("1 OR RTRIM('a  ')='a'")
        expectTautology("1 OR COALESCE(NULL,'x')='x'")
        expectTautology("1 OR IFNULL(NULL,'x')='x'")
        expectTautology("1 OR ISNULL(NULL,'x')='x'")
        expectTautology("1 OR NULLIF(1,1) IS NULL")
    })
})
