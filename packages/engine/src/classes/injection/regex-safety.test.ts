import { describe, expect, it } from 'vitest'
import { safeRegexMatchAll, safeRegexMatch, safeRegexTest } from './regex-safety.js'

const ADVERSARIAL_INPUT = 'a'.repeat(10_000) + '!'

function elapsedMs(action: () => void): number {
    const start = performance.now()
    action()
    return performance.now() - start
}

describe('regex safety helpers', () => {
    it('keeps known-safe ReDoS-replacement patterns under 10ms', () => {
        const fixedPatterns = [
            /[\w\s]+/,
            /[^\n]+/,
            /a(?:ba)*/,
        ]

        for (const pattern of fixedPatterns) {
            const elapsed = elapsedMs(() => {
                expect(safeRegexTest(pattern, ADVERSARIAL_INPUT)).toBe(true)
            })
            expect(elapsed).toBeLessThan(10)
        }
    })

    it('keeps timed matching APIs deterministic on user input', () => {
        const input = 'a=1&b=2&c=3'
        const match = safeRegexMatch(/([A-Za-z]+)=(\d+)/, input)

        expect(match?.[0]).toBe('a=1')
        expect(match?.[1]).toBe('a')

        const matches = safeRegexMatchAll(/\w+ = /g, 'a = 1, b = 2')
        expect(matches).not.toBeNull()
    })

    it('regex timeout wrapper completes on potentially dangerous input', () => {
        const elapsed = elapsedMs(() => {
            safeRegexTest(/(a+)+!/, ADVERSARIAL_INPUT, { timeoutMs: 10 })
        })
        expect(elapsed).toBeLessThan(10)
    })
})
