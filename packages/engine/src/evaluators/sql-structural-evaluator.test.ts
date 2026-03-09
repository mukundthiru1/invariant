import { describe, expect, it } from 'vitest'
import {
    detectSqlStrikeZone,
    detectTimeBasedBlindSqli,
} from './sql-structural-evaluator.js'

describe('sql-structural-evaluator time-based blind SQLi detection', () => {
    it('detects SLEEP(5)', () => {
        expect(detectTimeBasedBlindSqli('SLEEP(5)')).toBe(true)
    })

    it('detects BENCHMARK(10000000,SHA1(1))', () => {
        expect(detectTimeBasedBlindSqli('BENCHMARK(10000000,SHA1(1))')).toBe(true)
    })

    it('detects pg_sleep(3)', () => {
        expect(detectTimeBasedBlindSqli('pg_sleep(3)')).toBe(true)
    })

    it('detects WAITFOR DELAY 0:0:5', () => {
        expect(detectTimeBasedBlindSqli('WAITFOR DELAY 0:0:5')).toBe(true)
    })

    it('detects OR SLEEP(5)', () => {
        expect(detectTimeBasedBlindSqli('OR SLEEP(5)')).toBe(true)
    })

    it('detects SELECT pg_sleep(5)', () => {
        expect(detectTimeBasedBlindSqli('SELECT pg_sleep(5)')).toBe(true)
    })

    it('does not detect SELECT * FROM users', () => {
        expect(detectTimeBasedBlindSqli('SELECT * FROM users')).toBe(false)
    })

    it('does not detect sleep tight', () => {
        expect(detectTimeBasedBlindSqli('sleep tight')).toBe(false)
    })
})

describe('sql-structural-evaluator strike-zone detection', () => {
    it('detects stacked query with IF EXISTS pattern', () => {
        const detection = detectSqlStrikeZone('; IF EXISTS(SELECT * FROM users) WAITFOR DELAY \'0:0:5\'--')
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('stacked_execution')
        expect(detection?.confidence).toBe(0.92)
        expect(detection?.detail).toContain('IF EXISTS')
    })

    it('detects stacked query with CASE WHEN pattern', () => {
        const detection = detectSqlStrikeZone('; CASE WHEN 1=1 THEN SLEEP(1) ELSE WAITFOR DELAY \'0:0:1\' END--')
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('stacked_execution')
    })

    it('detects stacked query with WAITFOR conditional pattern', () => {
        const detection = detectSqlStrikeZone('; EXECUTE IMMEDIATE \'clean\'; WAITFOR DELAY \'0:0:5\'')
        expect(detection).not.toBeNull()
        expect(detection?.type).toBe('stacked_execution')
    })

    it('does not detect stacked query without conditional blind marker', () => {
        const detection = detectSqlStrikeZone('; UPDATE accounts SET active=0 WHERE id=1--')
        expect(detection).toBeNull()
    })
})
