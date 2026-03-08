/**
 * Tests for @santh/agent — Adaptive Calibration System
 *
 * Tests:
 *   1. recordOutcome(true) increases alpha and estimatedPrecision
 *   2. recordOutcome(false) increases beta and decreases estimatedPrecision
 *   3. After 10 TP and 0 FP, estimatedPrecision > 0.9
 *   4. After 5 TP and 5 FP, estimatedPrecision is close to 0.5
 *   5. getCalibrationMultiplier returns 1.0 for unknown classes
 *   6. applyToConfidence clamps to [0.01, 0.99]
 *   7. detectCalibrationDrift returns false when observations match prior
 *   8. getCalibrationReport returns all tracked classes with correct fields
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { InvariantDB } from './db.js'
import { AdaptiveCalibrator, type ClassCalibrationState } from './calibration.js'

describe('AdaptiveCalibrator', () => {
    let db: InvariantDB
    let calibrator: AdaptiveCalibrator

    beforeEach(() => {
        // In-memory database for testing
        db = new InvariantDB(':memory:')
        // Use default priors: alpha=2, beta=1 (prior mean = 0.667)
        calibrator = new AdaptiveCalibrator(db, 2.0, 1.0)
    })

    afterEach(() => {
        db.close()
    })

    // ── Test 1: recordOutcome(true) increases alpha and estimatedPrecision ─────

    it('recordOutcome(true) increases alpha and estimatedPrecision', () => {
        const classId = 'test_sqli_union'

        // Initial state with priors
        const initialState = calibrator.getState(classId)
        expect(initialState).toBeUndefined()  // Not loaded yet

        // Record a true positive
        calibrator.recordOutcome(classId, true)

        const state = calibrator.getState(classId)!
        expect(state.alpha).toBe(3.0)  // prior 2.0 + 1 TP
        expect(state.beta).toBe(1.0)   // prior 1.0 + 0 FP
        expect(state.estimatedPrecision).toBe(3.0 / 4.0)  // 0.75
        expect(state.totalObservations).toBe(1)
    })

    // ── Test 2: recordOutcome(false) increases beta and decreases estimatedPrecision ─

    it('recordOutcome(false) increases beta and decreases estimatedPrecision', () => {
        const classId = 'test_xss_reflected'

        // Record some TPs first to establish baseline
        calibrator.recordOutcome(classId, true)
        calibrator.recordOutcome(classId, true)
        const stateBefore = calibrator.getState(classId)!
        const precisionBefore = stateBefore.estimatedPrecision

        // Now record a false positive
        calibrator.recordOutcome(classId, false)

        const state = calibrator.getState(classId)!
        expect(state.alpha).toBe(4.0)  // prior 2.0 + 2 TP
        expect(state.beta).toBe(2.0)   // prior 1.0 + 1 FP
        expect(state.estimatedPrecision).toBeLessThan(precisionBefore)
        expect(state.estimatedPrecision).toBe(4.0 / 6.0)  // ~0.667
    })

    // ── Test 3: After 10 TP and 0 FP, estimatedPrecision > 0.9 ─────────────────

    it('after 10 TP and 0 FP, estimatedPrecision > 0.9', () => {
        const classId = 'test_high_precision_class'

        // Record 10 true positives
        for (let i = 0; i < 10; i++) {
            calibrator.recordOutcome(classId, true)
        }

        const state = calibrator.getState(classId)!
        // alpha = 2 + 10 = 12, beta = 1 + 0 = 1
        // estimatedPrecision = 12 / 13 ≈ 0.923
        expect(state.alpha).toBe(12.0)
        expect(state.beta).toBe(1.0)
        expect(state.estimatedPrecision).toBeGreaterThan(0.9)
        expect(state.totalObservations).toBe(10)
    })

    // ── Test 4: After 5 TP and 5 FP, estimatedPrecision is close to 0.5 ────────

    it('after 5 TP and 5 FP, estimatedPrecision is close to 0.5', () => {
        const classId = 'test_mixed_class'

        // Record 5 true positives and 5 false positives
        for (let i = 0; i < 5; i++) {
            calibrator.recordOutcome(classId, true)
        }
        for (let i = 0; i < 5; i++) {
            calibrator.recordOutcome(classId, false)
        }

        const state = calibrator.getState(classId)!
        // alpha = 2 + 5 = 7, beta = 1 + 5 = 6
        // estimatedPrecision = 7 / 13 ≈ 0.538
        expect(state.alpha).toBe(7.0)
        expect(state.beta).toBe(6.0)
        expect(state.estimatedPrecision).toBeCloseTo(7 / 13, 3)
        // Should be in the range [0.45, 0.55] (close to 0.5)
        expect(state.estimatedPrecision).toBeGreaterThan(0.45)
        expect(state.estimatedPrecision).toBeLessThan(0.6)
        expect(state.totalObservations).toBe(10)
    })

    // ── Test 5: getCalibrationMultiplier returns 1.0 for unknown classes ───────

    it('getCalibrationMultiplier returns 1.0 for unknown classes', () => {
        const unknownClassId = 'unknown_class_never_seen'

        const multiplier = calibrator.getCalibrationMultiplier(unknownClassId)

        expect(multiplier).toBe(1.0)
    })

    // ── Test 6: applyToConfidence clamps to [0.01, 0.99] ───────────────────────

    it('applyToConfidence clamps to [0.01, 0.99]', () => {
        const highPrecisionClass = 'test_high_precision'
        const lowPrecisionClass = 'test_low_precision'

        // Create a high-precision class (multiplier > 1.0, capped at 1.5)
        for (let i = 0; i < 20; i++) {
            calibrator.recordOutcome(highPrecisionClass, true)
        }

        // Create a low-precision class (multiplier < 1.0, potentially 0.5)
        for (let i = 0; i < 10; i++) {
            calibrator.recordOutcome(lowPrecisionClass, false)
        }

        // Test high precision: raw 0.8 * ~1.35 should cap at 0.99
        const highCalibrated = calibrator.applyToConfidence(highPrecisionClass, 0.8)
        expect(highCalibrated).toBeLessThanOrEqual(0.99)

        // Test low precision with high raw confidence that gets reduced
        // With many FPs, multiplier drops below 1.0
        const lowCalibrated = calibrator.applyToConfidence(lowPrecisionClass, 0.8)
        expect(lowCalibrated).toBeGreaterThanOrEqual(0.01)

        // Test extreme low raw confidence
        const extremeLow = calibrator.applyToConfidence(lowPrecisionClass, 0.001)
        expect(extremeLow).toBe(0.01)  // clamped to minimum

        // Test extreme high raw confidence
        const extremeHigh = calibrator.applyToConfidence(highPrecisionClass, 0.999)
        expect(extremeHigh).toBe(0.99)  // clamped to maximum
    })

    // ── Test 7: detectCalibrationDrift returns false when observations match prior

    it('detectCalibrationDrift returns false when observations match prior', () => {
        const classId = 'test_no_drift'

        // Prior mean is 2 / (2 + 1) ≈ 0.667
        // We need observations that keep precision close to 0.667

        // Add observations maintaining roughly 2:1 TP:FP ratio
        // After 4 TP and 2 FP: alpha=6, beta=3, precision = 6/9 = 0.667
        for (let i = 0; i < 4; i++) {
            calibrator.recordOutcome(classId, true)
        }
        for (let i = 0; i < 2; i++) {
            calibrator.recordOutcome(classId, false)
        }

        const state = calibrator.getState(classId)!
        // alpha = 2 + 4 = 6, beta = 1 + 2 = 3
        // precision = 6 / 9 = 0.667, same as prior
        expect(state.estimatedPrecision).toBe(6 / 9)

        // Drift threshold is 0.15, so |0.667 - 0.667| = 0 < 0.15
        const hasDrift = calibrator.detectCalibrationDrift(classId)
        expect(hasDrift).toBe(false)
    })

    it('detectCalibrationDrift returns true when observations diverge from prior', () => {
        const classId = 'test_with_drift'

        // Prior mean is 0.667
        // Add many FPs to drop precision significantly
        for (let i = 0; i < 10; i++) {
            calibrator.recordOutcome(classId, false)
        }

        // alpha = 2 + 0 = 2, beta = 1 + 10 = 11
        // precision = 2 / 13 ≈ 0.154
        const state = calibrator.getState(classId)!
        expect(state.estimatedPrecision).toBeCloseTo(2 / 13, 3)

        // |0.154 - 0.667| ≈ 0.513 > 0.15, so drift detected
        const hasDrift = calibrator.detectCalibrationDrift(classId)
        expect(hasDrift).toBe(true)
    })

    // ── Test 8: getCalibrationReport returns all tracked classes with correct fields

    it('getCalibrationReport returns all tracked classes with correct fields', () => {
        // Create multiple classes with different precisions
        const classA = 'test_class_a'  // Will have lower precision
        const classB = 'test_class_b'  // Will have higher precision
        const classC = 'test_class_c'  // Insufficient data

        // Class A: 2 TP, 8 FP (low precision)
        for (let i = 0; i < 2; i++) {
            calibrator.recordOutcome(classA, true)
        }
        for (let i = 0; i < 8; i++) {
            calibrator.recordOutcome(classA, false)
        }

        // Class B: 8 TP, 2 FP (high precision)
        for (let i = 0; i < 8; i++) {
            calibrator.recordOutcome(classB, true)
        }
        for (let i = 0; i < 2; i++) {
            calibrator.recordOutcome(classB, false)
        }

        // Class C: 2 TP (insufficient data - less than 5 observations)
        for (let i = 0; i < 2; i++) {
            calibrator.recordOutcome(classC, true)
        }

        const report = calibrator.getCalibrationReport()

        // Check report structure
        expect(report.classes).toHaveLength(3)
        expect(report.highUncertainty).toContain(classC)
        expect(report.highUncertainty).not.toContain(classA)
        expect(report.highUncertainty).not.toContain(classB)

        // Verify classes are sorted by estimatedPrecision ascending
        const precisions = report.classes.map(c => c.estimatedPrecision)
        expect(precisions[0]).toBeLessThan(precisions[1])  // A < B

        // Verify each class has required fields
        for (const cls of report.classes) {
            expect(cls).toHaveProperty('classId')
            expect(cls).toHaveProperty('alpha')
            expect(cls).toHaveProperty('beta')
            expect(cls).toHaveProperty('totalObservations')
            expect(cls).toHaveProperty('lastUpdated')
            expect(cls).toHaveProperty('estimatedPrecision')
            expect(cls).toHaveProperty('confidenceInterval')
            expect(Array.isArray(cls.confidenceInterval)).toBe(true)
            expect(cls.confidenceInterval).toHaveLength(2)
            expect(cls.confidenceInterval[0]).toBeLessThanOrEqual(cls.confidenceInterval[1])
        }

        // Verify specific class data
        const stateA = report.classes.find(c => c.classId === classA)!
        expect(stateA.alpha).toBe(4)  // 2 + 2
        expect(stateA.beta).toBe(9)   // 1 + 8
        expect(stateA.totalObservations).toBe(10)

        const stateB = report.classes.find(c => c.classId === classB)!
        expect(stateB.alpha).toBe(10)  // 2 + 8
        expect(stateB.beta).toBe(3)    // 1 + 2
        expect(stateB.totalObservations).toBe(10)

        // Verify overall precision is computed
        expect(typeof report.overallPrecision).toBe('number')
        expect(report.overallPrecision).toBeGreaterThan(0)
        expect(report.overallPrecision).toBeLessThan(1)
    })

    // ── Additional Tests ──────────────────────────────────────────────────────

    it('resetClass removes state and resets to prior', () => {
        const classId = 'test_reset'

        // Add some observations
        calibrator.recordOutcome(classId, true)
        calibrator.recordOutcome(classId, true)

        const stateBefore = calibrator.getState(classId)!
        expect(stateBefore.totalObservations).toBe(2)

        // Reset the class
        calibrator.resetClass(classId)

        // State should be undefined (removed from memory)
        const stateAfter = calibrator.getState(classId)
        expect(stateAfter).toBeUndefined()

        // Multiplier should return to neutral
        const multiplier = calibrator.getCalibrationMultiplier(classId)
        expect(multiplier).toBe(1.0)
    })

    it('persists state to database and reloads on access', () => {
        const classId = 'test_persistence'

        // Create a new calibrator and record some outcomes
        // Use outcomes that produce a different precision than the prior
        // Prior: alpha=2, beta=1, precision=0.667
        // After 5 TP: alpha=7, beta=1, precision=0.875 (different from prior)
        for (let i = 0; i < 5; i++) {
            calibrator.recordOutcome(classId, true)
        }

        const stateBefore = calibrator.getState(classId)!
        expect(stateBefore.alpha).toBe(7)  // 2 + 5
        expect(stateBefore.beta).toBe(1)   // 1 + 0
        expect(stateBefore.estimatedPrecision).toBe(7 / 8)  // 0.875

        // Create a new calibrator instance with same database
        const calibrator2 = new AdaptiveCalibrator(db, 2.0, 1.0)

        // Accessing the class should load from DB
        // Prior mean is 0.667, estimated is 0.875, multiplier = 0.875/0.667 ≈ 1.31
        const multiplier = calibrator2.getCalibrationMultiplier(classId)
        expect(multiplier).not.toBe(1.0)  // Should have loaded the actual data
        expect(multiplier).toBeGreaterThan(1.0)  // Higher precision than prior

        const stateAfter = calibrator2.getState(classId)!
        expect(stateAfter.alpha).toBe(7)
        expect(stateAfter.beta).toBe(1)
        expect(stateAfter.totalObservations).toBe(5)
    })

    it('confidenceInterval is computed correctly', () => {
        const classId = 'test_ci'

        // With no observations, CI should be based on prior
        calibrator.recordOutcome(classId, true)
        const state = calibrator.getState(classId)!

        // With alpha=3, beta=1: mean = 0.75
        expect(state.estimatedPrecision).toBe(0.75)
        // CI should be a valid interval containing the mean
        expect(state.confidenceInterval[0]).toBeLessThan(state.estimatedPrecision)
        expect(state.confidenceInterval[1]).toBeGreaterThan(state.estimatedPrecision)
    })

    it('calibrationMultiplier respects clamp bounds', () => {
        const highClass = 'test_very_high_precision'
        const lowClass = 'test_very_low_precision'

        // Create extreme high precision (many TPs, no FPs)
        for (let i = 0; i < 100; i++) {
            calibrator.recordOutcome(highClass, true)
        }

        // Create extreme low precision (no TPs, many FPs)
        for (let i = 0; i < 50; i++) {
            calibrator.recordOutcome(lowClass, false)
        }

        const highMultiplier = calibrator.getCalibrationMultiplier(highClass)
        const lowMultiplier = calibrator.getCalibrationMultiplier(lowClass)

        // Should be clamped to [0.5, 1.5]
        expect(highMultiplier).toBeLessThanOrEqual(1.5)
        expect(lowMultiplier).toBeGreaterThanOrEqual(0.5)
    })
})
