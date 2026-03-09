import { describe, it, expect } from 'vitest'

import { ALL_CLASS_MODULES } from './index.js'
import { InvariantRegistry, RegistryError, sanitizeConfidence } from './registry.js'
import type { InvariantClassModule, InvariantMatch } from './types.js'

function makeMatch(overrides: Partial<InvariantMatch> & Pick<InvariantMatch, 'class' | 'confidence' | 'severity'>): InvariantMatch {
    return {
        class: overrides.class,
        confidence: overrides.confidence,
        severity: overrides.severity,
        category: overrides.category ?? 'sqli',
        isNovelVariant: overrides.isNovelVariant ?? false,
        description: overrides.description ?? 'test match',
        detectionLevels: overrides.detectionLevels ?? { l1: true, l2: false, convergent: false },
        l2Evidence: overrides.l2Evidence,
    }
}

describe('formal contract verification', () => {
    it('registering a module where knownPayloads are all detected succeeds without error', () => {
        const registry = new InvariantRegistry()
        const module: InvariantClassModule = {
            id: 'sql_tautology',
            description: 'contract pass module',
            category: 'sqli',
            severity: 'high',
            detect: (input: string) => input.includes('attack-marker'),
            generateVariants: (count: number) => Array.from({ length: count }, () => 'attack-marker'),
            knownPayloads: ['attack-marker', 'prefix-attack-marker-suffix'],
            knownBenign: ['hello', 'world'],
        }

        expect(() => registry.register(module)).not.toThrow()
        expect(registry.size).toBe(1)
    })

    it('registering a module where detect() misses a knownPayload throws RegistryError with payload details', () => {
        const registry = new InvariantRegistry()
        const module: InvariantClassModule = {
            id: 'sql_tautology',
            description: 'contract miss payload',
            category: 'sqli',
            severity: 'high',
            detect: () => false,
            generateVariants: () => [],
            knownPayloads: ['must-detect-payload'],
            knownBenign: ['benign'],
        }

        expect(() => registry.register(module)).toThrow(RegistryError)
        expect(() => registry.register(module)).toThrow(/misses knownPayloads: must-detect-payload/)
    })

    it('registering a module where detect() false-positives on a knownBenign throws RegistryError with benign details', () => {
        const registry = new InvariantRegistry()
        const module: InvariantClassModule = {
            id: 'sql_tautology',
            description: 'contract false positive',
            category: 'sqli',
            severity: 'high',
            detect: () => true,
            generateVariants: () => [],
            knownPayloads: ['attack-ok'],
            knownBenign: ['should-not-detect-benign'],
        }

        expect(() => registry.register(module)).toThrow(RegistryError)
        expect(() => registry.register(module)).toThrow(/false-positives on knownBenign: should-not-detect-benign/)
    })

    it('all pre-registered ALL_CLASS_MODULES pass their own knownPayloads/knownBenign contracts', () => {
        const failures: string[] = []

        for (const module of ALL_CLASS_MODULES) {
            for (const payload of module.knownPayloads) {
                let detected = false
                try {
                    detected = module.detect(payload)
                } catch {
                    failures.push(`${module.id}: knownPayload threw: ${payload.slice(0, 80)}`)
                    continue
                }

                if (!detected) {
                    failures.push(`${module.id}: knownPayload missed: ${payload.slice(0, 80)}`)
                }
            }

            for (const benign of module.knownBenign) {
                let detected = false
                try {
                    detected = module.detect(benign)
                } catch {
                    continue
                }

                if (detected) {
                    failures.push(`${module.id}: knownBenign false-positive: ${benign.slice(0, 80)}`)
                }
            }
        }

        expect(ALL_CLASS_MODULES.length).toBeGreaterThanOrEqual(94)
        expect(
            failures,
            failures.length === 0 ? '' : `Contract failures:\n${failures.join('\n')}`,
        ).toEqual([])

        const registry = new InvariantRegistry()
        expect(() => registry.registerAll(ALL_CLASS_MODULES)).not.toThrow()
        expect(registry.size).toBe(ALL_CLASS_MODULES.length)
    })

    it('computeCorrelations() returns empty array for single-class input', () => {
        const registry = new InvariantRegistry()
        registry.registerAll(ALL_CLASS_MODULES)

        const correlations = registry.computeCorrelations([
            makeMatch({ class: 'sql_tautology', confidence: 0.88, severity: 'high' }),
        ])

        expect(correlations).toEqual([])
    })

    it('computeCorrelations() returns CompoundConfidence >= 0.99 for SQL triad (string_termination + union_extraction + comment_truncation)', () => {
        const registry = new InvariantRegistry()
        registry.registerAll(ALL_CLASS_MODULES)

        const correlations = registry.computeCorrelations([
            makeMatch({ class: 'sql_string_termination', confidence: 0.85, severity: 'high' }),
            makeMatch({ class: 'sql_union_extraction', confidence: 0.86, severity: 'high' }),
            makeMatch({ class: 'sql_comment_truncation', confidence: 0.84, severity: 'high' }),
        ])

        expect(correlations.length).toBeGreaterThanOrEqual(1)
        expect(correlations.some(c => c.compoundConfidence >= 0.99)).toBe(true)
    })

    it('setCalibrationOverride() changes confidence output of computeConfidence() in the expected direction', () => {
        const registry = new InvariantRegistry()
        registry.registerAll(ALL_CLASS_MODULES)

        const input = "' OR 1=1--"
        const baseline = registry.computeConfidence('sql_tautology', input)

        registry.setCalibrationOverride('sql_tautology', { baseConfidence: 0.20 })
        const lowered = registry.computeConfidence('sql_tautology', input)

        registry.setCalibrationOverride('sql_tautology', { baseConfidence: 0.95 })
        const raised = registry.computeConfidence('sql_tautology', input)

        expect(lowered).toBeLessThan(baseline)
        expect(raised).toBeGreaterThan(lowered)
    })
})

describe('sanitizeConfidence helper', () => {
    it('returns fallback for NaN', () => {
        expect(sanitizeConfidence(Number.NaN)).toBe(0.5)
    })

    it('returns 0.99 for +Infinity', () => {
        expect(sanitizeConfidence(Number.POSITIVE_INFINITY)).toBe(0.99)
    })

    it('clamps values below 0 to 0', () => {
        expect(sanitizeConfidence(-1)).toBe(0)
    })
})
