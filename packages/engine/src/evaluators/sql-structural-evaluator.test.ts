import { describe, expect, it } from 'vitest'
import { detectTimeBasedBlindSqli } from './sql-structural-evaluator.js'

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
