/**
 * @santh/agent — Autonomous Defense Controller
 *
 * Makes real-time defense decisions based on:
 *   1. Individual invariant signals (single payload analysis)
 *   2. Attack chain correlation (multi-step pattern detection)
 *   3. Source reputation tracking (historical behavior per source)
 *   4. Temporal analysis (rate anomalies, burst detection)
 *
 * The key insight: defense mode should not be static.
 * An attacker probing with SQLi error-based should trigger
 * automatic escalation from observe → defend for that source,
 * BEFORE they reach UNION-based extraction.
 *
 * Defense is PREEMPTIVE, not reactive.
 *
 * Invariants:
 *   - Never breaks the application (all decisions are fail-open for non-attackers)
 *   - Source-specific: one attacker escalates for THEIR source only
 *   - Time-decaying: escalations decay back to baseline over time
 *   - Auditable: every decision with rationale is logged
 */

import {
    ChainCorrelator,
    type ChainSignal,
    type ChainMatch,
} from '../../engine/src/chain-detector.js'
import type { InvariantDB, DefenseAction, Severity } from './db.js'

// ── Types ────────────────────────────────────────────────────────

export type DefenseLevel = 'baseline' | 'elevated' | 'high' | 'critical' | 'lockdown'

export interface SourceReputation {
    /** Hashed source identifier */
    sourceHash: string
    /** Current defense level for this source */
    level: DefenseLevel
    /** Total signals from this source */
    totalSignals: number
    /** Signals that triggered chain matches */
    chainSignals: number
    /** Highest severity seen from this source */
    highestSeverity: Severity
    /** Active chain matches for this source */
    activeChains: string[]
    /** When this source was first seen */
    firstSeen: number
    /** When this source was last seen */
    lastSeen: number
    /** When escalation happened (0 = never escalated) */
    escalatedAt: number
    /** Escalation reason */
    escalationReason: string | null
}

export interface DefenseDecision {
    /** What action to take */
    action: DefenseAction
    /** Why this decision was made */
    reason: string
    /** Defense level for this source */
    sourceLevel: DefenseLevel
    /** Confidence in this decision */
    confidence: number
    /** Active chain IDs */
    activeChains: string[]
    /** Should we serve a challenge (CAPTCHA) instead of blocking? */
    challenge: boolean
    /** Recommended response delay (ms) for throttling */
    throttleMs: number
}

// ── Constants ────────────────────────────────────────────────────

/**
 * Escalation thresholds.
 * These are based on the compounding nature of attack chains.
 *
 * A source at 'baseline' sees 3 low-severity signals → elevated.
 * A source at 'elevated' sees 1 high-severity signal → high.
 * A source at 'high' sees any chain match → critical.
 * A source at 'critical' with completed chain → lockdown.
 */
const ESCALATION_THRESHOLDS = {
    baseline: {
        signalsToElevate: 3,      // 3 signals of any severity → elevated
        highToElevate: 1,         // 1 high-sev signal → elevated
        criticalToElevate: 1,     // 1 critical-sev signal → high (skip elevated)
    },
    elevated: {
        signalsToHigh: 5,
        highToHigh: 2,
        criticalToHigh: 1,
        chainToHigh: 1,           // Any partial chain match → high
    },
    high: {
        signalsToCritical: 10,
        chainToCritical: 1,       // Any chain match → critical
        criticalToCritical: 2,
    },
    critical: {
        completedChainToLockdown: 1, // Completed chain → lockdown
    },
}

/**
 * Decay rates: how quickly escalation levels decay back to baseline.
 * In seconds of inactivity.
 */
const DECAY_RATES: Record<DefenseLevel, number> = {
    baseline: Infinity,
    elevated: 300,     // 5 minutes of silence → baseline
    high: 600,         // 10 minutes → elevated
    critical: 1800,    // 30 minutes → high
    lockdown: 3600,    // 1 hour → critical
}

// ── Autonomous Defense Controller ────────────────────────────────

export class AutonomousDefenseController {
    private readonly correlator: ChainCorrelator
    private readonly sources: Map<string, SourceReputation> = new Map()
    private readonly db: InvariantDB | null
    private globalMode: 'observe' | 'sanitize' | 'defend' | 'lockdown'
    private lastDecayCheck: number = Date.now()

    constructor(
        globalMode: 'observe' | 'sanitize' | 'defend' | 'lockdown' = 'observe',
        db: InvariantDB | null = null,
    ) {
        this.correlator = new ChainCorrelator()
        this.db = db
        this.globalMode = globalMode
    }

    /**
     * Process a new invariant detection and make a defense decision.
     *
     * This is the main entry point. Called by RASP wrappers and middleware
     * whenever an invariant match is detected.
     *
     * Returns a DefenseDecision that the caller should enforce.
     */
    processSignal(
        sourceHash: string,
        classes: string[],
        behaviors: string[],
        confidence: number,
        severity: Severity,
        path: string,
        method: string,
    ): DefenseDecision {
        const now = Date.now()

        // 1. Get or create source reputation
        const source = this.getOrCreateSource(sourceHash, now)
        source.lastSeen = now
        source.totalSignals++

        // Update highest severity
        if (severityRank(severity) > severityRank(source.highestSeverity)) {
            source.highestSeverity = severity
        }

        // 2. Feed into chain correlator
        const chainSignal: ChainSignal = {
            sourceHash,
            classes: classes as ChainSignal['classes'],
            behaviors,
            confidence,
            path,
            method,
            timestamp: now,
        }

        const chainMatches = this.correlator.ingest(chainSignal)

        // 3. Update source with chain results
        if (chainMatches.length > 0) {
            source.chainSignals++
            source.activeChains = chainMatches.map(m => m.chainId)
        }

        // 4. Check for decay (periodic, not every request)
        if (now - this.lastDecayCheck > 10_000) {
            this.decayAllSources(now)
            this.lastDecayCheck = now
        }

        // 5. Evaluate escalation
        this.evaluateEscalation(source, severity, chainMatches, now)

        // 6. Make defense decision
        const decision = this.makeDecision(source, chainMatches, severity, confidence)

        // 7. Log the decision
        this.logDecision(source, decision, classes, path, method, now)

        return decision
    }

    /**
     * Evaluate whether a source should be escalated based on accumulated signals.
     */
    private evaluateEscalation(
        source: SourceReputation,
        severity: Severity,
        chainMatches: ChainMatch[],
        now: number,
    ): void {
        const sevRank = severityRank(severity)
        const prevLevel = source.level

        switch (source.level) {
            case 'baseline': {
                const t = ESCALATION_THRESHOLDS.baseline
                if (sevRank >= 4) {
                    // Critical severity → skip to high
                    source.level = 'high'
                    source.escalationReason = `Critical severity signal detected`
                } else if (sevRank >= 3 || source.totalSignals >= t.signalsToElevate) {
                    source.level = 'elevated'
                    source.escalationReason = sevRank >= 3
                        ? `High severity signal detected`
                        : `${source.totalSignals} signals from this source`
                }
                break
            }

            case 'elevated': {
                const t = ESCALATION_THRESHOLDS.elevated
                if (chainMatches.length >= t.chainToHigh) {
                    source.level = 'high'
                    source.escalationReason = `Chain detected: ${chainMatches[0].name}`
                } else if (sevRank >= 4) {
                    source.level = 'high'
                    source.escalationReason = `Critical severity signal`
                } else if (sevRank >= 3 && source.totalSignals >= t.highToHigh) {
                    source.level = 'high'
                    source.escalationReason = `${source.totalSignals} signals with high severity`
                }
                break
            }

            case 'high': {
                const t = ESCALATION_THRESHOLDS.high
                const completedChains = chainMatches.filter(m => m.completion >= 0.66)
                if (completedChains.length > 0) {
                    source.level = 'critical'
                    source.escalationReason = `Chain ${completedChains[0].name} at ${Math.round(completedChains[0].completion * 100)}% completion`
                } else if (sevRank >= 4 && source.totalSignals >= t.criticalToCritical) {
                    source.level = 'critical'
                    source.escalationReason = `${source.totalSignals} critical signals`
                }
                break
            }

            case 'critical': {
                const t = ESCALATION_THRESHOLDS.critical
                const fullyCompleted = chainMatches.filter(m => m.completion >= 1.0)
                if (fullyCompleted.length >= t.completedChainToLockdown) {
                    source.level = 'lockdown'
                    source.escalationReason = `Completed attack chain: ${fullyCompleted[0].name}`
                }
                break
            }
        }

        if (source.level !== prevLevel) {
            source.escalatedAt = now
        }
    }

    /**
     * Make a defense decision based on source reputation and current signal.
     */
    private makeDecision(
        source: SourceReputation,
        chainMatches: ChainMatch[],
        severity: Severity,
        confidence: number,
    ): DefenseDecision {
        // In observe mode, never block
        if (this.globalMode === 'observe') {
            return {
                action: 'monitored',
                reason: `Global mode: observe. Source level: ${source.level}`,
                sourceLevel: source.level,
                confidence,
                activeChains: source.activeChains,
                challenge: false,
                throttleMs: 0,
            }
        }

        // Source-level decisions
        switch (source.level) {
            case 'lockdown':
                return {
                    action: 'blocked',
                    reason: `Source locked down: ${source.escalationReason}`,
                    sourceLevel: source.level,
                    confidence: Math.min(0.99, confidence + 0.3),
                    activeChains: source.activeChains,
                    challenge: false,
                    throttleMs: 0,
                }

            case 'critical':
                return {
                    action: 'blocked',
                    reason: `Source at critical level: ${source.escalationReason}`,
                    sourceLevel: source.level,
                    confidence: Math.min(0.99, confidence + 0.2),
                    activeChains: source.activeChains,
                    challenge: false,
                    throttleMs: 0,
                }

            case 'high': {
                const sevRank = severityRank(severity)
                if (sevRank >= 3 || confidence >= 0.7) {
                    return {
                        action: 'blocked',
                        reason: `Source at high level with ${severity} severity signal`,
                        sourceLevel: source.level,
                        confidence: Math.min(0.99, confidence + 0.15),
                        activeChains: source.activeChains,
                        challenge: false,
                        throttleMs: 0,
                    }
                }
                // High level but low severity individual signal → challenge
                return {
                    action: 'monitored',
                    reason: `Source at high level, but individual signal is ${severity}`,
                    sourceLevel: source.level,
                    confidence,
                    activeChains: source.activeChains,
                    challenge: true,
                    throttleMs: 500,
                }
            }

            case 'elevated': {
                // Chain recommendation overrides
                const strongestChain = chainMatches.reduce((best, m) =>
                    !best || m.confidence > best.confidence ? m : best, null as ChainMatch | null)

                if (strongestChain && strongestChain.recommendedAction === 'block') {
                    return {
                        action: 'blocked',
                        reason: `Chain ${strongestChain.name} recommends block`,
                        sourceLevel: source.level,
                        confidence: strongestChain.confidence,
                        activeChains: source.activeChains,
                        challenge: false,
                        throttleMs: 0,
                    }
                }

                // In defend/lockdown mode: high+ severity with good confidence → block
                if ((this.globalMode === 'defend' || this.globalMode === 'lockdown')
                    && severityRank(severity) >= 3 && confidence >= 0.7) {
                    return {
                        action: 'blocked',
                        reason: `Elevated source with ${severity} severity in ${this.globalMode} mode`,
                        sourceLevel: source.level,
                        confidence: Math.min(0.99, confidence + 0.1),
                        activeChains: source.activeChains,
                        challenge: false,
                        throttleMs: 0,
                    }
                }

                if (severityRank(severity) >= 4) {
                    return {
                        action: this.globalMode === 'lockdown' ? 'blocked' : 'monitored',
                        reason: `Source elevated with critical signal`,
                        sourceLevel: source.level,
                        confidence,
                        activeChains: source.activeChains,
                        challenge: true,
                        throttleMs: 200,
                    }
                }

                return {
                    action: 'monitored',
                    reason: `Source elevated, monitoring`,
                    sourceLevel: source.level,
                    confidence,
                    activeChains: source.activeChains,
                    challenge: false,
                    throttleMs: 100,
                }
            }

            default: {
                // Baseline — use global mode logic
                const sevRank = severityRank(severity)
                if (this.globalMode === 'lockdown') {
                    return {
                        action: sevRank >= 2 ? 'blocked' : 'monitored',
                        reason: `Global lockdown mode`,
                        sourceLevel: source.level,
                        confidence,
                        activeChains: source.activeChains,
                        challenge: false,
                        throttleMs: 0,
                    }
                }
                if (this.globalMode === 'defend' && sevRank >= 3 && confidence >= 0.7) {
                    return {
                        action: 'blocked',
                        reason: `Defend mode: ${severity} severity with ${Math.round(confidence * 100)}% confidence`,
                        sourceLevel: source.level,
                        confidence,
                        activeChains: source.activeChains,
                        challenge: false,
                        throttleMs: 0,
                    }
                }
                return {
                    action: 'monitored',
                    reason: `Baseline source, ${this.globalMode} mode`,
                    sourceLevel: source.level,
                    confidence,
                    activeChains: source.activeChains,
                    challenge: false,
                    throttleMs: 0,
                }
            }
        }
    }

    /**
     * Decay all source levels that haven't been seen recently.
     */
    private decayAllSources(now: number): void {
        for (const [hash, source] of this.sources.entries()) {
            const silenceDuration = now - source.lastSeen
            const decayThreshold = DECAY_RATES[source.level] * 1000

            if (silenceDuration > decayThreshold) {
                const levels: DefenseLevel[] = ['baseline', 'elevated', 'high', 'critical', 'lockdown']
                const currentIdx = levels.indexOf(source.level)
                if (currentIdx > 0) {
                    source.level = levels[currentIdx - 1]
                    source.escalationReason = `Decayed from ${levels[currentIdx]} after ${Math.round(silenceDuration / 1000)}s silence`
                }
            }

            // Remove sources that have fully decayed and are old
            if (source.level === 'baseline' && silenceDuration > 7200_000) {
                this.sources.delete(hash)
            }
        }
    }

    private getOrCreateSource(sourceHash: string, now: number): SourceReputation {
        let source = this.sources.get(sourceHash)
        if (!source) {
            source = {
                sourceHash,
                level: 'baseline',
                totalSignals: 0,
                chainSignals: 0,
                highestSeverity: 'info',
                activeChains: [],
                firstSeen: now,
                lastSeen: now,
                escalatedAt: 0,
                escalationReason: null,
            }
            this.sources.set(sourceHash, source)
        }
        return source
    }

    private logDecision(
        source: SourceReputation,
        decision: DefenseDecision,
        classes: string[],
        path: string,
        method: string,
        now: number,
    ): void {
        if (!this.db) return
        try {
            this.db.insertSignal({
                type: 'autonomous_defense',
                subtype: decision.action,
                severity: decision.action === 'blocked' ? 'high' : 'medium',
                action: decision.action,
                path,
                method,
                source_hash: source.sourceHash,
                invariant_classes: JSON.stringify(classes),
                is_novel: false,
                timestamp: new Date(now).toISOString(),
            })
        } catch { /* Never break on logging */ }
    }

    // ── Public API ───────────────────────────────────────────────

    /** Get reputation for a specific source */
    getSourceReputation(sourceHash: string): SourceReputation | null {
        return this.sources.get(sourceHash) ?? null
    }

    /** Get all escalated sources */
    getEscalatedSources(): SourceReputation[] {
        return [...this.sources.values()].filter(s => s.level !== 'baseline')
    }

    /** Update global defense mode */
    setGlobalMode(mode: 'observe' | 'sanitize' | 'defend' | 'lockdown'): void {
        this.globalMode = mode
    }

    /** Get correlator for direct chain queries */
    getCorrelator(): ChainCorrelator {
        return this.correlator
    }

    /** Stats */
    get stats(): {
        activeSources: number
        escalatedSources: number
        totalChainMatches: number
        globalMode: string
    } {
        const escalated = this.getEscalatedSources()
        return {
            activeSources: this.sources.size,
            escalatedSources: escalated.length,
            totalChainMatches: this.correlator.getAllActiveChains().length,
            globalMode: this.globalMode,
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────

function severityRank(severity: Severity | string): number {
    switch (severity) {
        case 'critical': return 4
        case 'high': return 3
        case 'medium': return 2
        case 'low': return 1
        default: return 0
    }
}
