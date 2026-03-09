/**
 * INVARIANT — Threat Scoring Engine
 *
 * Transforms raw detection signals into a composite threat score.
 * Unlike simple threshold-based blocking, this engine synthesizes
 * multiple weak signals into a strong conviction — catching
 * multi-vector attacks that no single detector would flag.
 *
 * Architecture:
 *   Multiple independent signals → calibrated weights →
 *   temporal decay → IP reputation overlay → composite score →
 *   threat classification (clear / suspect / hostile)
 *
 * Why this matters:
 *   A single SQLi attempt at 0.5 confidence → benign fuzzing.
 *   The same IP sending 0.5 SQLi, 0.3 path traversal, and
 *   3 prior signals → high-confidence attack chain.
 *   CrowdStrike calls this "indicator composition."
 */
import {
    detectH2PseudoHeaderAbuse,
    detectHttpVerbTunneling,
    detectTrailerInjection,
    detectWebSocketUpgradeAbuse,
} from './header-analysis.js'
import type { BodyAnalysisResult } from './body-analysis.js'


// ── Signal Input ─────────────────────────────────────────────────

export interface ThreatSignal {
    /** Detection layer that produced this signal */
    source: 'invariant' | 'static' | 'dynamic' | 'behavioral' | 'header' | 'ai' | 'ioc_feed'
    /** Signal type (e.g., 'sql_injection', 'path_traversal') */
    type: string
    /** Subtype (e.g., 'union_based') */
    subtype: string | null
    /** Individual confidence [0, 1] */
    confidence: number
    /** Severity tier */
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
    /** Linked CVEs from intel rules */
    linkedCves: string[]
    /** MITRE ATT&CK techniques */
    linkedTechniques: string[]
    /** Is this a novel variant (no static match)? */
    isNovel: boolean
}


// ── Threat Score Output ──────────────────────────────────────────

export interface ThreatScore {
    /** Composite threat score [0, 100] */
    score: number
    /** Classification */
    classification: 'clear' | 'suspect' | 'hostile'
    /** Should the request be blocked? */
    shouldBlock: boolean
    /** Human-readable threat summary */
    summary: string
    /** Individual signal contributions */
    contributions: SignalContribution[]
    /** Aggregate attack chain indicators */
    chainIndicators: ChainIndicator[]
    /** Time-to-verdict in ms */
    verdictMs: number
    /** Per-application anomaly score from application model */
    anomalyScore?: number
    /** Evidence strings from application invariant checks */
    anomalyEvidence: string[]
    /** Whether anomaly-based confidence boost was applied */
    anomalyBoostApplied: boolean
}

export interface SignalContribution {
    source: string
    type: string
    rawConfidence: number
    weightedScore: number
    weight: number
}

export interface ChainIndicator {
    type: string
    description: string
    multiplier: number
}


// ── Weight Configuration ─────────────────────────────────────────

/**
 * Signal weights calibrated against real-world attack distributions.
 *
 * Rationale:
 *   - Invariant engine signals are the strongest — they detect
 *     attack CLASSES, not specific payloads
 *   - Static rules have known false-positive rates
 *   - Dynamic (intel) rules are externally validated
 *   - Behavioral signals are probabilistic
 *   - AI classification is a secondary opinion
 */
const SOURCE_WEIGHTS: Record<string, number> = {
    invariant: 1.0,
    dynamic: 0.9,        // Intel-validated rules
    ioc_feed: 0.95,      // Threat intelligence feed matches
    static: 0.7,         // Known signature patterns
    behavioral: 0.5,     // Rate/pattern based
    header: 0.6,         // Header anomalies
    ai: 0.8,             // AI secondary verdict
}

/**
 * Severity multipliers determine how much each severity tier
 * amplifies the composite score.
 */
const SEVERITY_MULTIPLIERS: Record<string, number> = {
    critical: 2.0,
    high: 1.5,
    medium: 1.0,
    low: 0.6,
    info: 0.3,
}

/**
 * Attack type multipliers based on real-world exploitation frequency.
 * SQL injection remains the #1 attack vector in OWASP Top 10.
 */
const ATTACK_TYPE_MULTIPLIERS: Record<string, number> = {
    sql_injection: 1.3,
    sqli: 1.3,
    xss: 1.1,
    path_traversal: 1.2,
    cmdi: 1.4,           // Command injection = instant RCE
    ssrf: 1.3,
    deser: 1.4,          // Deserialization = instant RCE
    injection: 1.2,
    auth: 1.1,
    h2_pseudo_header_abuse: 1.2,
    trailer_header_injection: 1.2,
    websocket_upgrade_abuse: 1.2,
    http_verb_tunneling: 1.15,
}

export function buildHeaderThreatSignals(
    request: Request,
    bodyResult: Pick<BodyAnalysisResult, 'contentType' | 'combinedText'>,
): ThreatSignal[] {
    const signals: ThreatSignal[] = []

    if (detectH2PseudoHeaderAbuse(request.headers)) {
        signals.push({
            source: 'header',
            type: 'h2_pseudo_header_abuse',
            subtype: null,
            confidence: 0.8,
            severity: 'high',
            linkedCves: [],
            linkedTechniques: [],
            isNovel: false,
        })
    }

    if (detectTrailerInjection(request)) {
        signals.push({
            source: 'header',
            type: 'trailer_header_injection',
            subtype: null,
            confidence: 0.75,
            severity: 'high',
            linkedCves: [],
            linkedTechniques: [],
            isNovel: false,
        })
    }

    if (detectWebSocketUpgradeAbuse(request)) {
        signals.push({
            source: 'header',
            type: 'websocket_upgrade_abuse',
            subtype: null,
            confidence: 0.7,
            severity: 'medium',
            linkedCves: [],
            linkedTechniques: [],
            isNovel: false,
        })
    }

    const tunnelingHits = detectHttpVerbTunneling(request, {
        contentType: bodyResult.contentType,
        combinedText: bodyResult.combinedText,
    })
    for (const hit of tunnelingHits) {
        signals.push({
            source: 'header',
            type: 'http_verb_tunneling',
            subtype: hit,
            confidence: hit === 'x_method_override_unusual_verb' ? 0.65 : 0.8,
            severity: hit === 'x_method_override_unusual_verb' ? 'medium' : 'high',
            linkedCves: [],
            linkedTechniques: [],
            isNovel: false,
        })
    }

    return signals
}


// ═══════════════════════════════════════════════════════════════════
// SCORING ENGINE
// ═══════════════════════════════════════════════════════════════════

export class ThreatScoringEngine {
    private recentScores: { timestamp: number; score: number; sourceHash: string }[] = []

    /**
     * Compute composite threat score from raw detection signals.
     *
     * Algorithm:
     *   1. Weight each signal by source reliability
     *   2. Apply severity multiplier
     *   3. Apply attack-type frequency multiplier
     *   4. Detect attack chains (multi-vector compound attacks)
     *   5. Apply chain amplification
     *   6. Apply IP reputation overlay
     *   7. Normalize to 0-100 scale
     *   8. Classify and determine verdict
     */
    score(
        signals: ThreatSignal[],
        context: {
            sourceHash: string
            knownAttacker: boolean
            priorSignalCount: number
            requestsInWindow: number
            anomalyScore?: number
            anomalyEvidence?: string[]
        },
    ): ThreatScore {
        const start = performance.now()

        if (signals.length === 0) {
            return {
                score: 0,
                classification: 'clear',
                shouldBlock: false,
                summary: 'No threats detected',
                contributions: [],
                chainIndicators: [],
                verdictMs: performance.now() - start,
                anomalyScore: context.anomalyScore,
                anomalyEvidence: context.anomalyEvidence ?? [],
                anomalyBoostApplied: false,
            }
        }

        // ── Step 1-3: Weight individual signals ──────────────────
        const contributions: SignalContribution[] = []
        let rawAggregate = 0

        for (const signal of signals) {
            const sourceWeight = SOURCE_WEIGHTS[signal.source] ?? 0.5
            const severityMult = SEVERITY_MULTIPLIERS[signal.severity] ?? 1.0
            const attackMult = ATTACK_TYPE_MULTIPLIERS[signal.type] ?? 1.0

            const weighted = signal.confidence * sourceWeight * severityMult * attackMult

            contributions.push({
                source: signal.source,
                type: signal.type,
                rawConfidence: signal.confidence,
                weightedScore: weighted,
                weight: sourceWeight,
            })

            rawAggregate += weighted
        }

        // ── Step 4: Detect attack chains ─────────────────────────
        const chainIndicators: ChainIndicator[] = []
        let chainMultiplier = 1.0

        // Multi-vector: different attack types from same source
        const uniqueTypes = new Set(signals.map(s => s.type))
        if (uniqueTypes.size >= 2) {
            const multiVectorBoost = 1.0 + (uniqueTypes.size - 1) * 0.15
            chainMultiplier *= multiVectorBoost
            chainIndicators.push({
                type: 'multi_vector',
                description: `${uniqueTypes.size} distinct attack types detected — coordinated multi-vector attack`,
                multiplier: multiVectorBoost,
            })
        }

        // Multi-layer: signals from different detection layers
        const uniqueSources = new Set(signals.map(s => s.source))
        if (uniqueSources.size >= 3) {
            chainMultiplier *= 1.2
            chainIndicators.push({
                type: 'multi_layer_corroboration',
                description: `${uniqueSources.size} independent detection layers corroborate — high conviction`,
                multiplier: 1.2,
            })
        }

        // Novel variant: invariant engine caught something no signature knows
        const novelSignals = signals.filter(s => s.isNovel)
        if (novelSignals.length > 0) {
            chainMultiplier *= 1.1
            chainIndicators.push({
                type: 'novel_variant',
                description: `${novelSignals.length} novel variant(s) — zero-day or evasion technique`,
                multiplier: 1.1,
            })
        }

        // CVE-linked: signals tied to known vulnerabilities
        const linkedCves = [...new Set(signals.flatMap(s => s.linkedCves))]
        if (linkedCves.length > 0) {
            chainMultiplier *= 1.25
            chainIndicators.push({
                type: 'cve_linked',
                description: `Attack matches ${linkedCves.length} known CVE(s): ${linkedCves.slice(0, 3).join(', ')}`,
                multiplier: 1.25,
            })
        }

        // ── Step 5: Apply chain amplification ────────────────────
        let amplified = rawAggregate * chainMultiplier

        // ── Step 6: IP reputation overlay ────────────────────────
        if (context.knownAttacker) {
            const reputationBoost = 1.0 + Math.min(context.priorSignalCount * 0.05, 0.5)
            amplified *= reputationBoost
            chainIndicators.push({
                type: 'repeat_offender',
                description: `Known attacker with ${context.priorSignalCount} prior signals`,
                multiplier: reputationBoost,
            })
        }

        // Rate-based amplification: many requests in window = scanning
        if (context.requestsInWindow > 50) {
            const rateBoost = 1.0 + Math.min((context.requestsInWindow - 50) * 0.01, 0.3)
            amplified *= rateBoost
            chainIndicators.push({
                type: 'high_rate',
                description: `${context.requestsInWindow} requests in window — automated scanning detected`,
                multiplier: rateBoost,
            })
        }

        // ── Step 7: Normalize to 0-100 ──────────────────────────
        // Sigmoid normalization prevents extreme scores while preserving discrimination
        const baselineScore = Math.min(100, Math.round(sigmoid(amplified) * 100))
        let normalizedScore = baselineScore
        let anomalyBoostApplied = false

        const anomalyScore = context.anomalyScore ?? 0
        if (anomalyScore > 0.8 && baselineScore / 100 > 0.3) {
            normalizedScore = Math.min(100, Math.round((baselineScore / 100 + 0.15) * 100))
            anomalyBoostApplied = true
            chainIndicators.push({
                type: 'application_invariant_anomaly',
                description: `High application-model anomaly (${anomalyScore.toFixed(2)}) corroborates active threat`,
                multiplier: 1.15,
            })
        }

        // ── Step 8: Classify ─────────────────────────────────────
        const classification = normalizedScore >= 70 ? 'hostile'
            : normalizedScore >= 30 ? 'suspect'
                : 'clear'

        const shouldBlock = normalizedScore >= 65

        // ── Build summary ────────────────────────────────────────
        const topSignal = contributions.sort((a, b) => b.weightedScore - a.weightedScore)[0]
        const summary = buildSummary(
            normalizedScore,
            classification,
            signals,
            linkedCves,
            topSignal,
            context.anomalyEvidence ?? [],
        )

        // Record for temporal analysis
        this.recentScores.push({
            timestamp: Date.now(),
            score: normalizedScore,
            sourceHash: context.sourceHash,
        })
        // Keep only last 1000 scores
        if (this.recentScores.length > 1000) {
            this.recentScores = this.recentScores.slice(-1000)
        }

        return {
            score: normalizedScore,
            classification,
            shouldBlock,
            summary,
            contributions,
            chainIndicators,
            verdictMs: performance.now() - start,
            anomalyScore: context.anomalyScore,
            anomalyEvidence: context.anomalyEvidence ?? [],
            anomalyBoostApplied,
        }
    }

    /**
     * Get threat trend for a specific source over time.
     */
    getTrend(sourceHash: string, windowMs: number = 3600000): {
        scoreCount: number
        avgScore: number
        maxScore: number
        escalating: boolean
    } {
        const cutoff = Date.now() - windowMs
        const recent = this.recentScores.filter(
            s => s.sourceHash === sourceHash && s.timestamp >= cutoff,
        )

        if (recent.length === 0) {
            return { scoreCount: 0, avgScore: 0, maxScore: 0, escalating: false }
        }

        const avgScore = recent.reduce((sum, s) => sum + s.score, 0) / recent.length
        const maxScore = Math.max(...recent.map(s => s.score))

        // Escalating = recent scores are higher than earlier ones
        const mid = Math.floor(recent.length / 2)
        const firstHalf = recent.slice(0, mid)
        const secondHalf = recent.slice(mid)
        const firstAvg = firstHalf.reduce((s, x) => s + x.score, 0) / (firstHalf.length || 1)
        const secondAvg = secondHalf.reduce((s, x) => s + x.score, 0) / (secondHalf.length || 1)

        return {
            scoreCount: recent.length,
            avgScore: Math.round(avgScore),
            maxScore,
            escalating: secondAvg > firstAvg + 5,
        }
    }
}


// ── Helpers ──────────────────────────────────────────────────────

function sigmoid(x: number): number {
    // Adjusted sigmoid: values above 2.5 approach 1.0, below 0.5 approach 0.0
    return 1 / (1 + Math.exp(-2 * (x - 1.5)))
}

function buildSummary(
    score: number,
    classification: string,
    signals: ThreatSignal[],
    linkedCves: string[],
    topSignal: SignalContribution | undefined,
    anomalyEvidence: string[],
): string {
    const parts: string[] = []

    parts.push(`Threat score ${score}/100 (${classification})`)

    if (topSignal) {
        parts.push(`Primary: ${topSignal.type} (${topSignal.source}, confidence ${topSignal.rawConfidence.toFixed(2)})`)
    }

    if (signals.length > 1) {
        parts.push(`${signals.length} signals from ${new Set(signals.map(s => s.source)).size} detection layers`)
    }

    if (linkedCves.length > 0) {
        parts.push(`Linked CVEs: ${linkedCves.join(', ')}`)
    }

    const novelCount = signals.filter(s => s.isNovel).length
    if (novelCount > 0) {
        parts.push(`${novelCount} novel variant(s)`)
    }

    if (anomalyEvidence.length > 0) {
        parts.push(`Anomaly evidence: ${anomalyEvidence.slice(0, 2).join('; ')}`)
    }

    return parts.join(' | ')
}
