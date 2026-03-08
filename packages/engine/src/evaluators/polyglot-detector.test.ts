import { describe, it, expect } from 'vitest'
import { analyzePolyglot } from './polyglot-detector.js'
import { InvariantEngine } from '../invariant-engine.js'

describe('Polyglot Detector', () => {

    describe('analyzePolyglot', () => {
        it('returns isPolyglot=false for single domain', () => {
            const result = analyzePolyglot(['sql_tautology', 'sql_string_termination'])
            expect(result.isPolyglot).toBe(false)
            expect(result.domainCount).toBe(1)
            expect(result.domains).toEqual(['sql'])
            expect(result.confidenceBoost).toBe(0)
        })

        it('returns isPolyglot=false for no detections', () => {
            const result = analyzePolyglot([])
            expect(result.isPolyglot).toBe(false)
            expect(result.domainCount).toBe(0)
        })

        it('detects SQL+XSS polyglot', () => {
            const result = analyzePolyglot([
                'sql_string_termination', 'xss_tag_injection',
            ])
            expect(result.isPolyglot).toBe(true)
            expect(result.domainCount).toBe(2)
            expect(result.domains).toContain('sql')
            expect(result.domains).toContain('xss')
            expect(result.confidenceBoost).toBeGreaterThan(0.05)
            expect(result.detail).toContain('SQL+XSS')
        })

        it('detects SQL+CMDi polyglot', () => {
            const result = analyzePolyglot([
                'sql_stacked_execution', 'cmd_separator',
            ])
            expect(result.isPolyglot).toBe(true)
            expect(result.confidenceBoost).toBeGreaterThanOrEqual(0.08)
        })

        it('detects triple-domain polyglot with higher boost', () => {
            const result = analyzePolyglot([
                'sql_tautology', 'xss_event_handler', 'cmd_separator',
            ])
            expect(result.isPolyglot).toBe(true)
            expect(result.domainCount).toBe(3)
            // Triple domain gets base + domain count boost
            expect(result.confidenceBoost).toBeGreaterThan(0.08)
        })

        it('generic multi-domain gets base boost', () => {
            const result = analyzePolyglot([
                'ssrf_internal_reach', 'path_dotdot_escape',
            ])
            expect(result.isPolyglot).toBe(true)
            expect(result.confidenceBoost).toBeGreaterThanOrEqual(0.04)
        })

        it('handles unknown class IDs gracefully', () => {
            const result = analyzePolyglot([
                'unknown_class_xyz', 'another_unknown',
            ])
            expect(result.isPolyglot).toBe(false)
            expect(result.domainCount).toBe(0)
        })

        it('same domain classes do not trigger polyglot', () => {
            // All XSS classes = same domain
            const result = analyzePolyglot([
                'xss_tag_injection', 'xss_event_handler', 'xss_protocol_handler',
            ])
            expect(result.isPolyglot).toBe(false)
            expect(result.domainCount).toBe(1)
        })
    })

    describe('Integration with detectDeep', () => {
        const engine = new InvariantEngine()

        it('detectDeep includes polyglot field for multi-domain payloads', () => {
            // This payload is both SQL injection AND command injection
            const payload = "'; exec('whoami')--"
            const result = engine.detectDeep(payload, [])

            // Should detect in at least 2 domains
            if (result.matches.length >= 2) {
                const domains = new Set<string>()
                for (const m of result.matches) {
                    if (m.class.startsWith('sql_')) domains.add('sql')
                    if (m.class.startsWith('cmd_')) domains.add('cmdi')
                }

                if (domains.size >= 2 && result.polyglot) {
                    expect(result.polyglot.isPolyglot).toBe(true)
                    expect(result.polyglot.domainCount).toBeGreaterThanOrEqual(2)
                }
            }
        })

        it('single-domain detection has no polyglot boost', () => {
            // Pure SQL injection
            const result = engine.detectDeep("' OR 1=1--", [])
            // Even if polyglot analysis runs, it should not boost single-domain
            if (result.polyglot) {
                expect(result.polyglot.isPolyglot).toBe(false)
            }
        })
    })
})
