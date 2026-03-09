import { describe, expect, it } from 'vitest'
import { HYGIENE_CLASSES } from './index.js'

describe('Hygiene Classes', () => {
    it('registers all hygiene classes', () => {
        expect(HYGIENE_CLASSES.length).toBeGreaterThanOrEqual(12)
    })

    for (const mod of HYGIENE_CLASSES) {
        describe(mod.id, () => {
            it('has required metadata and vectors', () => {
                expect(mod.calibration?.baseConfidence).toBeGreaterThan(0)
                expect(mod.mitre && mod.mitre.length).toBeGreaterThan(0)
                expect(mod.cwe).toMatch(/^CWE-\d+$/)
                expect(mod.knownPayloads.length).toBeGreaterThanOrEqual(3)
                expect(mod.knownBenign.length).toBeGreaterThanOrEqual(3)
            })

            it('detects known payloads', () => {
                for (const payload of mod.knownPayloads) {
                    expect(mod.detect(payload), `${mod.id} should detect: ${payload}`).toBe(true)
                }
            })

            it('does not detect known benign samples', () => {
                for (const sample of mod.knownBenign) {
                    expect(mod.detect(sample), `${mod.id} should not detect: ${sample}`).toBe(false)
                }
            })
        })
    }
})
