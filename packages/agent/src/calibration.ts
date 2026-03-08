/**
 * @santh/agent — Adaptive Calibration System
 *
 * Online Bayesian calibration for invariant class confidence scores.
 * Instead of static baseConfidence values per class, the system tracks
 * observed true positives (TP) and false positives (FP) in production
 * and updates calibration dynamically using a Beta distribution.
 *
 * The Beta distribution is conjugate prior for Bernoulli/binomial likelihood,
 * making it ideal for modeling precision (P(attack | detected)).
 *
 * Key properties:
 *   - priorAlpha=2, priorBeta=1 biases toward attackers being real (conservative)
 *   - estimatedPrecision = alpha / (alpha + beta) = posterior mean
 *   - 95% CI computed via normal approximation for efficiency
 *   - Calibration multiplier adjusts base confidence based on observed performance
 */

import type { InvariantDB } from './db.js'

// ── Types ─────────────────────────────────────────────────────────

/**
 * Per-invariant-class calibration state using Beta distribution.
 * Alpha represents (prior + confirmed attacks), beta represents (prior + false positives).
 */
export interface ClassCalibrationState {
    /** The invariant class identifier */
    classId: string
    /** Beta distribution alpha parameter (TP count + prior) */
    alpha: number
    /** Beta distribution beta parameter (FP count + prior) */
    beta: number
    /** Total number of observations recorded */
    totalObservations: number
    /** Last update timestamp (epoch ms) */
    lastUpdated: number
    /** Estimated precision: P(attack | detected) = alpha / (alpha + beta) */
    estimatedPrecision: number
    /** 95% confidence interval for estimatedPrecision */
    confidenceInterval: [number, number]
}

/**
 * Complete calibration report for all tracked classes.
 */
export interface CalibrationReport {
    /** All tracked classes with their calibration states, sorted by estimatedPrecision ascending */
    classes: ClassCalibrationState[]
    /** Class IDs with insufficient data (totalObservations < 5) */
    highUncertainty: string[]
    /** Overall precision across all classes (weighted average by observations) */
    overallPrecision: number
}

// ── Constants ──────────────────────────────────────────────────────

/** Minimum observations before we consider data reliable */
const MIN_CONFIDENCE_OBSERVATIONS = 5

/** Z-score for 95% confidence interval */
const Z_95 = 1.96

/** Clamp multiplier to prevent extreme drift */
const MULTIPLIER_MIN = 0.5
const MULTIPLIER_MAX = 1.5

/** Confidence clamping bounds */
const CONFIDENCE_MIN = 0.01
const CONFIDENCE_MAX = 0.99

/** Config key prefix for persistence */
const CONFIG_KEY_PREFIX = 'calibration_'

// ── AdaptiveCalibrator ─────────────────────────────────────────────

/**
 * Online Bayesian calibrator for invariant class confidence scores.
 *
 * Tracks true positives and false positives per class using a Beta(α, β)
 * distribution. The posterior mean (α / (α + β)) estimates precision,
 * which drives a dynamic calibration multiplier.
 *
 * Usage:
 *   const calibrator = new AdaptiveCalibrator(db, 2.0, 1.0)
 *   calibrator.loadFromDb()  // Restore state
 *   calibrator.recordOutcome('sqli_union', true)   // Confirmed attack
 *   calibrator.recordOutcome('sqli_union', false)  // False positive
 *   const multiplier = calibrator.getCalibrationMultiplier('sqli_union')
 */
export class AdaptiveCalibrator {
    private readonly db: InvariantDB
    private readonly priorAlpha: number
    private readonly priorBeta: number
    private readonly priorMean: number
    private states: Map<string, ClassCalibrationState> = new Map()

    /**
     * Create a new AdaptiveCalibrator.
     *
     * @param db - InvariantDB instance for persistence
     * @param priorAlpha - Beta distribution alpha prior (default 2.0, biases toward attacks being real)
     * @param priorBeta - Beta distribution beta prior (default 1.0)
     */
    constructor(db: InvariantDB, priorAlpha = 2.0, priorBeta = 1.0) {
        this.db = db
        this.priorAlpha = priorAlpha
        this.priorBeta = priorBeta
        this.priorMean = priorAlpha / (priorAlpha + priorBeta)
    }

    // ── Core Operations ──────────────────────────────────────────────

    /**
     * Record an outcome for a class.
     *
     * @param classId - The invariant class identifier
     * @param wasAttack - true if confirmed attack (TP), false if false positive (FP)
     */
    recordOutcome(classId: string, wasAttack: boolean): void {
        let state = this.states.get(classId)

        if (!state) {
            state = this.createInitialState(classId)
            this.states.set(classId, state)
        }

        // Update Beta parameters
        if (wasAttack) {
            state.alpha += 1
        } else {
            state.beta += 1
        }

        state.totalObservations += 1
        state.lastUpdated = Date.now()

        // Recompute derived statistics
        this.recomputeState(state)

        // Persist to database
        this.persistState(state)
    }

    /**
     * Load all calibration states from database on startup.
     * Should be called once after construction.
     */
    loadFromDb(): void {
        // We need to find all config keys starting with 'calibration_'
        // Since there's no direct method, we try common class patterns
        // In practice, this would be called with known class IDs or
        // we'd need to extend InvariantDB with a method to list config keys
        // For now, we load on-demand in getCalibrationMultiplier
    }

    /**
     * Get calibration multiplier for a class.
     * Returns multiplier to apply to base confidence from registry.
     *
     * multiplier = estimatedPrecision / priorMean
     * - If precision > prior: multiplier > 1.0 (boost)
     * - If precision < prior: multiplier < 1.0 (reduce)
     * - Clamped to [0.5, 1.5] to prevent extreme drift
     *
     * @param classId - The invariant class identifier
     * @returns Calibration multiplier (default 1.0 if no data)
     */
    getCalibrationMultiplier(classId: string): number {
        // Try to load from DB if not in memory
        this.maybeLoadState(classId)

        const state = this.states.get(classId)
        if (!state || state.totalObservations === 0) {
            return 1.0  // Neutral for unknown classes
        }

        const multiplier = state.estimatedPrecision / this.priorMean
        return Math.max(MULTIPLIER_MIN, Math.min(MULTIPLIER_MAX, multiplier))
    }

    /**
     * Apply calibration to a raw confidence score.
     *
     * @param classId - The invariant class identifier
     * @param rawConfidence - The raw confidence from the registry
     * @returns Calibrated confidence, clamped to [0.01, 0.99]
     */
    applyToConfidence(classId: string, rawConfidence: number): number {
        const multiplier = this.getCalibrationMultiplier(classId)
        const calibrated = rawConfidence * multiplier
        return Math.min(CONFIDENCE_MAX, Math.max(CONFIDENCE_MIN, calibrated))
    }

    /**
     * Get a comprehensive calibration report.
     *
     * @returns CalibrationReport with all tracked classes
     */
    getCalibrationReport(): CalibrationReport {
        const classes = Array.from(this.states.values())

        // Sort by estimatedPrecision ascending (worst performers first)
        classes.sort((a, b) => a.estimatedPrecision - b.estimatedPrecision)

        // Identify high uncertainty classes
        const highUncertainty = classes
            .filter(c => c.totalObservations < MIN_CONFIDENCE_OBSERVATIONS)
            .map(c => c.classId)

        // Compute overall precision (weighted by observations)
        const totalObservations = classes.reduce((sum, c) => sum + c.totalObservations, 0)
        const overallPrecision = totalObservations > 0
            ? classes.reduce((sum, c) => sum + c.estimatedPrecision * c.totalObservations, 0) / totalObservations
            : this.priorMean

        return {
            classes,
            highUncertainty,
            overallPrecision,
        }
    }

    /**
     * Detect if a class has drifted significantly from prior expectations.
     *
     * Returns true if |estimatedPrecision - priorMean| > 0.15,
     * indicating the class is performing much better or worse than expected.
     *
     * @param classId - The invariant class identifier
     * @returns true if significant drift detected
     */
    detectCalibrationDrift(classId: string): boolean {
        this.maybeLoadState(classId)

        const state = this.states.get(classId)
        if (!state || state.totalObservations === 0) {
            return false  // No data, no drift
        }

        const drift = Math.abs(state.estimatedPrecision - this.priorMean)
        return drift > 0.15
    }

    /**
     * Reset a class back to prior values.
     * Useful when a deployment change fixes FP rate.
     *
     * @param classId - The invariant class identifier
     */
    resetClass(classId: string): void {
        // Remove from memory
        this.states.delete(classId)

        // Reset to prior in database (empty string to indicate reset/no data)
        this.db.setConfig(`${CONFIG_KEY_PREFIX}${classId}`, '')
    }

    /**
     * Get the current state for a class (for testing/debugging).
     *
     * @param classId - The invariant class identifier
     * @returns The calibration state or undefined if not tracked
     */
    getState(classId: string): ClassCalibrationState | undefined {
        // Return in-memory state only; don't auto-load from DB
        // This ensures tests see only what's been recorded in this session
        return this.states.get(classId)
    }

    // ── Private Helpers ──────────────────────────────────────────────

    private createInitialState(classId: string): ClassCalibrationState {
        return {
            classId,
            alpha: this.priorAlpha,
            beta: this.priorBeta,
            totalObservations: 0,
            lastUpdated: Date.now(),
            estimatedPrecision: this.priorMean,
            confidenceInterval: this.computeConfidenceInterval(this.priorMean, this.priorAlpha + this.priorBeta),
        }
    }

    private recomputeState(state: ClassCalibrationState): void {
        const total = state.alpha + state.beta
        state.estimatedPrecision = state.alpha / total
        state.confidenceInterval = this.computeConfidenceInterval(state.estimatedPrecision, total)
    }

    private computeConfidenceInterval(mean: number, total: number): [number, number] {
        // Normal approximation to Beta: std = sqrt(mean * (1 - mean) / (alpha + beta))
        // This is equivalent to sqrt(alpha * beta / ((alpha + beta)^2 * (alpha + beta + 1)))
        // But using mean*(1-mean)/(alpha+beta) is more numerically stable

        const variance = mean * (1 - mean) / (total + 1)  // +1 for stability with small samples
        const std = Math.sqrt(variance)
        const margin = Z_95 * std

        const lower = Math.max(0, mean - margin)
        const upper = Math.min(1, mean + margin)

        return [lower, upper]
    }

    private persistState(state: ClassCalibrationState): void {
        const key = `${CONFIG_KEY_PREFIX}${state.classId}`
        this.db.setConfig(key, JSON.stringify(state))
    }

    private maybeLoadState(classId: string): void {
        if (this.states.has(classId)) {
            return
        }

        const key = `${CONFIG_KEY_PREFIX}${classId}`
        const stored = this.db.getConfig(key)

        if (stored) {
            try {
                const parsed = JSON.parse(stored) as ClassCalibrationState
                this.states.set(classId, parsed)
            } catch {
                // Invalid stored data, ignore
            }
        }
    }

    /**
     * Load a specific class state from database.
     * Used internally for loading state without risking overwrite of in-memory updates.
     */
    private loadStateFromDb(classId: string): ClassCalibrationState | undefined {
        const key = `${CONFIG_KEY_PREFIX}${classId}`
        const stored = this.db.getConfig(key)

        if (stored) {
            try {
                return JSON.parse(stored) as ClassCalibrationState
            } catch {
                // Invalid stored data, ignore
            }
        }
        return undefined
    }
}
