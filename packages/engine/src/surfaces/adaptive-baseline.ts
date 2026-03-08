/**
 * INVARIANT — Adaptive Endpoint Baseline Engine
 *
 * Learns what "normal" looks like for every endpoint in the application.
 * Detects deviations from the established baseline using statistical methods.
 *
 * Why APTs fear this: Nation-state attackers craft requests that pass static
 * rules. They CANNOT craft requests that look normal to a deployment-specific
 * statistical baseline — because they don't know what normal IS.
 *
 * Core algorithm:
 *   1. Every request is profiled: parameter types, value distributions,
 *      entropy, metacharacter rates, timing, sizes.
 *   2. Profiles accumulate over time using exponential moving averages
 *      (bounded memory, recency-weighted).
 *   3. New requests are scored against the profile using σ-distance.
 *   4. Anomaly score feeds into the unified runtime as a confidence multiplier.
 *
 * Memory model:
 *   Each endpoint profile is ~4KB (HyperLogLog + reservoir sampling + EMA stats).
 *   1,000 endpoints = 4MB. Bounded at MAX_ENDPOINTS.
 *   Oldest unused profiles are evicted via LRU.
 */

import type { Surface } from './request-decomposer.js'


// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

/**
 * Rolling statistics computed via exponential moving average.
 * Bounded memory, recency-weighted, no raw storage required.
 */
export interface RollingStats {
    mean: number
    variance: number
    min: number
    max: number
    count: number
}

/**
 * Profile for a single parameter at a single endpoint.
 * Captures the statistical characteristics of normal values.
 */
export interface ParameterProfile {
    /** Parameter name */
    name: string
    /** Where this parameter appears */
    location: string
    /** Value type distribution (ratios, sum to 1.0) */
    typeDistribution: {
        numeric: number
        alpha: number
        alphanumeric: number
        email: number
        uuid: number
        special: number  // Contains metacharacters
    }
    /** Length distribution */
    lengthStats: RollingStats
    /** Entropy distribution */
    entropyStats: RollingStats
    /** Metacharacter density in normal traffic */
    metacharStats: RollingStats
    /** Has this parameter EVER contained metacharacters in normal use? */
    hasEverHadMetachars: boolean
    /** Historical metachar rate (ratio of metachar-containing requests) */
    normalMetacharRate: number
    /** Cardinality estimate (distinct values seen) */
    cardinalityEstimate: number
    /** Reservoir sample of recent values (bounded) */
    valueSample: string[]
    /** Total observations */
    observations: number
}

/**
 * Timing profile for an endpoint.
 */
export interface TimingProfile {
    /** Requests per minute (rolling average) */
    requestRatePerMinute: RollingStats
    /** Response time in milliseconds */
    responseTimeMs: RollingStats
    /** Last seen timestamp */
    lastSeen: number
}

/**
 * Full baseline for a single endpoint.
 */
export interface EndpointBaseline {
    /** Endpoint identity — normalized method + path pattern */
    endpointKey: string
    /** Parameter profiles */
    parameterProfiles: Map<string, ParameterProfile>
    /** Timing profile */
    timing: TimingProfile
    /** Request body size distribution */
    bodySizeStats: RollingStats
    /** Response body size distribution (if tracked) */
    responseSizeStats: RollingStats
    /** Ratio of authenticated requests */
    authRatio: number
    /** Total observations */
    observations: number
    /** Baseline confidence (0-1, based on sample size) */
    baselineConfidence: number
    /** First observed */
    firstSeen: number
    /** Last observed */
    lastSeen: number
}

/**
 * Anomaly assessment for a single request against its endpoint baseline.
 */
export interface AnomalyAssessment {
    /** Overall anomaly score (0-1, higher = more anomalous) */
    overallScore: number
    /** Per-parameter anomaly scores */
    parameterAnomalies: {
        name: string
        score: number
        reason: string
    }[]
    /** Whether the baseline has enough data to be reliable */
    baselineReliable: boolean
    /** Number of observations the baseline is trained on */
    baselineObservations: number
}


// ═══════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════

/** Maximum endpoints to track (LRU eviction beyond this) */
const MAX_ENDPOINTS = 2_000
/** Minimum observations before baseline is considered reliable */
const MIN_OBSERVATIONS = 50
/** EMA smoothing factor (higher = more weight on recent data) */
const EMA_ALPHA = 0.05
/** Reservoir sample size for value tracking */
const RESERVOIR_SIZE = 100
/** Sigma threshold for anomaly detection */
const ANOMALY_SIGMA = 3.0
/** Maximum parameters to track per endpoint */
const MAX_PARAMS_PER_ENDPOINT = 50


// ═══════════════════════════════════════════════════════════════════
// BASELINE ENGINE
// ═══════════════════════════════════════════════════════════════════

export class AdaptiveBaselineEngine {
    private baselines: Map<string, EndpointBaseline> = new Map()
    /** LRU ordering for eviction */
    private lruOrder: string[] = []

    /**
     * Record an observation for a request.
     * Updates the endpoint baseline with the new data.
     */
    recordObservation(
        method: string,
        path: string,
        surfaces: Surface[],
        responseTimeMs?: number,
        bodySize?: number,
        responseSize?: number,
        isAuthenticated?: boolean,
    ): void {
        const key = this.normalizeEndpointKey(method, path)
        let baseline = this.baselines.get(key)

        if (!baseline) {
            if (this.baselines.size >= MAX_ENDPOINTS) {
                this.evictLru()
            }
            baseline = this.createBaseline(key)
            this.baselines.set(key, baseline)
        }

        // Update LRU
        this.touchLru(key)

        // Update parameter profiles
        for (const surface of surfaces) {
            if (surface.location === 'path_segment') continue // Path segments are part of the key
            this.updateParameterProfile(baseline, surface)
        }

        // Update timing
        const now = Date.now()
        if (baseline.timing.lastSeen > 0) {
            const intervalMinutes = (now - baseline.timing.lastSeen) / 60_000
            if (intervalMinutes > 0 && intervalMinutes < 60) {
                const rate = 1 / intervalMinutes
                updateRollingStats(baseline.timing.requestRatePerMinute, rate)
            }
        }
        baseline.timing.lastSeen = now

        if (responseTimeMs !== undefined) {
            updateRollingStats(baseline.timing.responseTimeMs, responseTimeMs)
        }

        if (bodySize !== undefined) {
            updateRollingStats(baseline.bodySizeStats, bodySize)
        }

        if (responseSize !== undefined) {
            updateRollingStats(baseline.responseSizeStats, responseSize)
        }

        // Update auth ratio
        if (isAuthenticated !== undefined) {
            const oldWeight = baseline.observations / (baseline.observations + 1)
            baseline.authRatio = baseline.authRatio * oldWeight + (isAuthenticated ? 1 : 0) * (1 - oldWeight)
        }

        baseline.observations++
        baseline.lastSeen = now
        baseline.baselineConfidence = Math.min(1.0, baseline.observations / MIN_OBSERVATIONS)
    }

    /**
     * Assess how anomalous a request is compared to the endpoint baseline.
     *
     * Score interpretation:
     *   0.0-0.2: Normal traffic
     *   0.2-0.4: Slightly unusual
     *   0.4-0.6: Moderately anomalous
     *   0.6-0.8: Highly anomalous
     *   0.8-1.0: Extreme deviation
     */
    assessAnomaly(
        method: string,
        path: string,
        surfaces: Surface[],
    ): AnomalyAssessment {
        const key = this.normalizeEndpointKey(method, path)
        const baseline = this.baselines.get(key)

        if (!baseline || baseline.observations < MIN_OBSERVATIONS) {
            return {
                overallScore: 0,
                parameterAnomalies: [],
                baselineReliable: false,
                baselineObservations: baseline?.observations ?? 0,
            }
        }

        const anomalies: { name: string; score: number; reason: string }[] = []

        for (const surface of surfaces) {
            if (surface.location === 'path_segment') continue

            const profileKey = `${surface.location}:${surface.name}`
            const profile = baseline.parameterProfiles.get(profileKey)

            if (!profile) {
                // Unknown parameter — moderately suspicious if baseline is mature
                if (baseline.observations >= MIN_OBSERVATIONS * 2) {
                    anomalies.push({
                        name: surface.name,
                        score: 0.5,
                        reason: 'unknown_parameter',
                    })
                }
                continue
            }

            // ── Length anomaly ──
            const lengthSigma = sigmaDistance(surface.raw.length, profile.lengthStats)
            if (lengthSigma > ANOMALY_SIGMA) {
                anomalies.push({
                    name: surface.name,
                    score: Math.min(1.0, lengthSigma / 10.0),
                    reason: `length_anomaly:${lengthSigma.toFixed(1)}σ`,
                })
            }

            // ── Entropy anomaly ──
            const entropySigma = sigmaDistance(surface.entropy, profile.entropyStats)
            if (entropySigma > ANOMALY_SIGMA) {
                anomalies.push({
                    name: surface.name,
                    score: Math.min(1.0, entropySigma / 8.0),
                    reason: `entropy_anomaly:${entropySigma.toFixed(1)}σ`,
                })
            }

            // ── Metacharacter anomaly ──
            // This is the key signal: if an endpoint parameter NEVER has metacharacters
            // in normal traffic, and suddenly it does, that's extremely suspicious.
            if (surface.hasMetachars && profile.normalMetacharRate < 0.05) {
                const intensity = surface.metacharDensity / Math.max(0.001, profile.metacharStats.mean + profile.metacharStats.variance * 2)
                anomalies.push({
                    name: surface.name,
                    score: Math.min(1.0, 0.7 + intensity * 0.3),
                    reason: `metachar_anomaly:rate=${profile.normalMetacharRate.toFixed(3)}`,
                })
            }

            // ── Type anomaly ──
            const valueType = classifyValueType(surface.normalized)
            const typeRate = profile.typeDistribution[valueType] ?? 0
            if (typeRate < 0.02 && profile.observations >= MIN_OBSERVATIONS) {
                anomalies.push({
                    name: surface.name,
                    score: Math.min(1.0, 0.6 + (1 - typeRate) * 0.4),
                    reason: `type_anomaly:${valueType}_rate=${typeRate.toFixed(3)}`,
                })
            }
        }

        // Compute overall score — max of individual anomalies, weighted by baselineConfidence
        const maxAnomaly = anomalies.length > 0
            ? Math.max(...anomalies.map(a => a.score))
            : 0
        const overallScore = maxAnomaly * baseline.baselineConfidence

        return {
            overallScore,
            parameterAnomalies: anomalies,
            baselineReliable: baseline.baselineConfidence >= 1.0,
            baselineObservations: baseline.observations,
        }
    }

    /**
     * Get the baseline for a specific endpoint (for introspection/debugging).
     */
    getBaseline(method: string, path: string): EndpointBaseline | undefined {
        return this.baselines.get(this.normalizeEndpointKey(method, path))
    }

    /**
     * Get all tracked endpoints.
     */
    get endpointCount(): number {
        return this.baselines.size
    }

    /**
     * Get stats.
     */
    getStats(): {
        endpoints: number
        totalObservations: number
        reliableEndpoints: number
        avgObservationsPerEndpoint: number
    } {
        let totalObs = 0
        let reliable = 0
        for (const b of this.baselines.values()) {
            totalObs += b.observations
            if (b.baselineConfidence >= 1.0) reliable++
        }
        return {
            endpoints: this.baselines.size,
            totalObservations: totalObs,
            reliableEndpoints: reliable,
            avgObservationsPerEndpoint: this.baselines.size > 0
                ? totalObs / this.baselines.size : 0,
        }
    }

    // ── Internal ─────────────────────────────────────────────────────

    /**
     * Normalize endpoint keys to handle path parameters.
     * /api/users/123 → GET:/api/users/{id}
     * /api/posts/abc-def-123/comments → GET:/api/posts/{id}/comments
     */
    private normalizeEndpointKey(method: string, path: string): string {
        // Strip query string
        const pathOnly = path.split('?')[0]
        const segments = pathOnly.split('/').filter(Boolean)
        const normalized = segments.map(s => {
            // Pure numeric → {id}
            if (/^\d+$/.test(s)) return '{id}'
            // UUID → {id}
            if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return '{id}'
            // Long alphanumeric (likely a slug or ID) → {slug}
            if (s.length > 20 && /^[a-zA-Z0-9_-]+$/.test(s)) return '{slug}'
            return s
        })
        return `${method.toUpperCase()}:/${normalized.join('/')}`
    }

    private createBaseline(key: string): EndpointBaseline {
        const now = Date.now()
        return {
            endpointKey: key,
            parameterProfiles: new Map(),
            timing: {
                requestRatePerMinute: createRollingStats(),
                responseTimeMs: createRollingStats(),
                lastSeen: 0,
            },
            bodySizeStats: createRollingStats(),
            responseSizeStats: createRollingStats(),
            authRatio: 0,
            observations: 0,
            baselineConfidence: 0,
            firstSeen: now,
            lastSeen: now,
        }
    }

    private updateParameterProfile(baseline: EndpointBaseline, surface: Surface): void {
        const profileKey = `${surface.location}:${surface.name}`
        let profile = baseline.parameterProfiles.get(profileKey)

        if (!profile) {
            if (baseline.parameterProfiles.size >= MAX_PARAMS_PER_ENDPOINT) return
            profile = this.createParameterProfile(surface.name, surface.location)
            baseline.parameterProfiles.set(profileKey, profile)
        }

        // Update value type distribution
        const valueType = classifyValueType(surface.normalized)
        const typeWeight = 1 / (profile.observations + 1)
        const oldWeight = 1 - typeWeight
        for (const key of Object.keys(profile.typeDistribution) as Array<keyof typeof profile.typeDistribution>) {
            profile.typeDistribution[key] = profile.typeDistribution[key] * oldWeight +
                (key === valueType ? 1 : 0) * typeWeight
        }

        // Update length stats
        updateRollingStats(profile.lengthStats, surface.raw.length)

        // Update entropy stats
        updateRollingStats(profile.entropyStats, surface.entropy)

        // Update metachar stats
        updateRollingStats(profile.metacharStats, surface.metacharDensity)
        if (surface.hasMetachars) {
            profile.hasEverHadMetachars = true
        }
        profile.normalMetacharRate = profile.normalMetacharRate * (1 - EMA_ALPHA) +
            (surface.hasMetachars ? 1 : 0) * EMA_ALPHA

        // Update cardinality estimate (simple counter with cap)
        profile.cardinalityEstimate = Math.min(
            profile.cardinalityEstimate + 1,
            profile.observations * 0.8, // Cap at 80% cardinality
        )

        // Reservoir sampling for value recording
        if (profile.valueSample.length < RESERVOIR_SIZE) {
            profile.valueSample.push(surface.raw)
        } else {
            const replaceIdx = Math.floor(Math.random() * profile.observations)
            if (replaceIdx < RESERVOIR_SIZE) {
                profile.valueSample[replaceIdx] = surface.raw
            }
        }

        profile.observations++
    }

    private createParameterProfile(name: string, location: string): ParameterProfile {
        return {
            name,
            location,
            typeDistribution: {
                numeric: 0,
                alpha: 0,
                alphanumeric: 0,
                email: 0,
                uuid: 0,
                special: 0,
            },
            lengthStats: createRollingStats(),
            entropyStats: createRollingStats(),
            metacharStats: createRollingStats(),
            hasEverHadMetachars: false,
            normalMetacharRate: 0,
            cardinalityEstimate: 0,
            valueSample: [],
            observations: 0,
        }
    }

    private touchLru(key: string): void {
        const idx = this.lruOrder.indexOf(key)
        if (idx >= 0) this.lruOrder.splice(idx, 1)
        this.lruOrder.push(key)
    }

    private evictLru(): void {
        if (this.lruOrder.length === 0) return
        const evictKey = this.lruOrder.shift()!
        this.baselines.delete(evictKey)
    }
}


// ═══════════════════════════════════════════════════════════════════
// STATISTICAL HELPERS
// ═══════════════════════════════════════════════════════════════════

function createRollingStats(): RollingStats {
    return { mean: 0, variance: 0, min: Infinity, max: -Infinity, count: 0 }
}

/**
 * Welford's online algorithm for mean and variance, combined with EMA.
 * Bounded memory, numerically stable.
 */
function updateRollingStats(stats: RollingStats, value: number): void {
    stats.count++
    if (stats.count === 1) {
        stats.mean = value
        stats.variance = 0
        stats.min = value
        stats.max = value
        return
    }

    // EMA update
    const alpha = Math.max(EMA_ALPHA, 1 / stats.count) // Use higher alpha early
    const delta = value - stats.mean
    stats.mean += alpha * delta
    stats.variance = (1 - alpha) * (stats.variance + alpha * delta * delta)
    stats.min = Math.min(stats.min, value)
    stats.max = Math.max(stats.max, value)
}

/**
 * Compute σ-distance (number of standard deviations from mean).
 */
function sigmaDistance(value: number, stats: RollingStats): number {
    if (stats.count < 5) return 0 // Not enough data
    const stddev = Math.sqrt(stats.variance)
    if (stddev < 0.001) return Math.abs(value - stats.mean) > 0.001 ? 10.0 : 0
    return Math.abs(value - stats.mean) / stddev
}

/**
 * Classify a value into a simple type.
 */
function classifyValueType(value: string): 'numeric' | 'alpha' | 'alphanumeric' | 'email' | 'uuid' | 'special' {
    if (/^\d+(\.\d+)?$/.test(value)) return 'numeric'
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return 'uuid'
    if (/^[^@]+@[^@]+\.[^@]+$/.test(value)) return 'email'
    if (/^[a-zA-Z]+$/.test(value)) return 'alpha'
    if (/^[a-zA-Z0-9_-]+$/.test(value)) return 'alphanumeric'
    return 'special'
}
