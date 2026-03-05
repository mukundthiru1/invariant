/**
 * @santh/edge-sensor — Multi-Dimensional Risk Surface
 *
 * Replaces 1D threat scoring with a 4-axis risk surface:
 *   - Security:    exploitation signals, chain correlation, CVE linkage
 *   - Privacy:     tracker detection, data exposure, body inspection patterns
 *   - Compliance:  header violations, posture drift, missing security controls
 *   - Operational: availability signals, error rates, resource exhaustion
 *
 * Concept from Axiom Drift's RiskScorer with 4-axis breakdown,
 * adapted for real-time request analysis instead of snapshot-based drift.
 *
 * Why a surface instead of a number:
 *   Score 75 from a SQLi chain is very different from score 75 from
 *   missing security headers + tracker detection + DDoS signals.
 *   One requires incident response. The other requires policy review.
 *   Same number, opposite playbooks.
 */

// ── Types ─────────────────────────────────────────────────────────

export interface RiskSurface {
    /** Security risk: exploitation, injection, authentication bypass */
    security: number
    /** Privacy risk: tracking, data exposure, PII handling */
    privacy: number
    /** Compliance risk: missing headers, posture violations, config gaps */
    compliance: number
    /** Operational risk: availability threats, resource exhaustion */
    operational: number
    /** Composite score (weighted combination) */
    composite: number
    /** Which axis dominates? Determines playbook. */
    dominantAxis: 'security' | 'privacy' | 'compliance' | 'operational'
    /** Risk classification based on composite */
    classification: 'clear' | 'noise' | 'suspicious' | 'hostile' | 'critical'
    /** Factor breakdown for explainability */
    factors: RiskFactor[]
}

export interface RiskFactor {
    source: string
    axis: 'security' | 'privacy' | 'compliance' | 'operational'
    contribution: number
    description: string
}

// ── Weights ───────────────────────────────────────────────────────

const AXIS_WEIGHTS = {
    security: 0.40,
    privacy: 0.20,
    compliance: 0.25,
    operational: 0.15,
} as const

// Map signal types to risk axes
const SIGNAL_AXIS_MAP: Record<string, 'security' | 'privacy' | 'compliance' | 'operational'> = {
    // Security
    sql_injection: 'security',
    xss: 'security',
    command_injection: 'security',
    path_traversal: 'security',
    ssrf: 'security',
    ssti: 'security',
    deserialization: 'security',
    xxe: 'security',
    nosql_injection: 'security',
    ldap_injection: 'security',
    exploit_payload: 'security',
    http_smuggling: 'security',
    auth_bypass: 'security',

    // Privacy
    tracker_added: 'privacy',
    tracker_detected: 'privacy',
    data_exposure: 'privacy',
    sensitive_public: 'privacy',
    privilege_observation: 'privacy',

    // Compliance
    header_anomaly: 'compliance',
    version_leak: 'compliance',
    missing_header: 'compliance',
    posture_finding: 'compliance',
    probe_finding: 'compliance',

    // Operational
    rate_anomaly: 'operational',
    path_enumeration: 'operational',
    method_probing: 'operational',
    unusual_method: 'operational',
    high_error_rate: 'operational',
    scanner: 'operational',

    // Hybrid defaults
    open_redirect: 'security',
    header_injection: 'security',
    information_disclosure: 'compliance',
}


// ── Risk Surface Calculator ──────────────────────────────────────

export class RiskSurfaceCalculator {
    /**
     * Calculate the full risk surface from detection signals.
     */
    calculate(
        signalTypes: string[],
        signalConfidences: number[],
        signalSeverities: string[],
        postureIssues: number,
        knownAttacker: boolean,
    ): RiskSurface {
        const factors: RiskFactor[] = []
        let security = 0
        let privacy = 0
        let compliance = 0
        let operational = 0

        // Process each signal
        for (let i = 0; i < signalTypes.length; i++) {
            const type = signalTypes[i]
            const confidence = signalConfidences[i] ?? 0.5
            const severity = signalSeverities[i] ?? 'medium'
            const axis = SIGNAL_AXIS_MAP[type] ?? 'security'

            const severityMultiplier = severity === 'critical' ? 30
                : severity === 'high' ? 20
                    : severity === 'medium' ? 10
                        : severity === 'low' ? 5 : 2

            const contribution = severityMultiplier * confidence

            switch (axis) {
                case 'security': security += contribution; break
                case 'privacy': privacy += contribution; break
                case 'compliance': compliance += contribution; break
                case 'operational': operational += contribution; break
            }

            factors.push({
                source: type,
                axis,
                contribution,
                description: `${type} at ${(confidence * 100).toFixed(0)}% confidence (${severity})`,
            })
        }

        // Compliance penalty for posture issues
        if (postureIssues > 0) {
            const postureContribution = Math.min(postureIssues * 3, 30)
            compliance += postureContribution
            factors.push({
                source: 'posture_deficit',
                axis: 'compliance',
                contribution: postureContribution,
                description: `${postureIssues} posture issues detected`,
            })
        }

        // Known attacker multiplier (affects security axis)
        if (knownAttacker) {
            const boost = security * 0.3
            security += boost
            factors.push({
                source: 'known_attacker_boost',
                axis: 'security',
                contribution: boost,
                description: 'Source has prior attack history',
            })
        }

        // Normalize each axis to 0-100
        security = Math.min(100, security)
        privacy = Math.min(100, privacy)
        compliance = Math.min(100, compliance)
        operational = Math.min(100, operational)

        // Weighted composite
        const composite = Math.min(100, Math.round(
            security * AXIS_WEIGHTS.security +
            privacy * AXIS_WEIGHTS.privacy +
            compliance * AXIS_WEIGHTS.compliance +
            operational * AXIS_WEIGHTS.operational,
        ))

        // Dominant axis
        const axes = { security, privacy, compliance, operational }
        const dominantAxis = (Object.entries(axes) as [keyof typeof axes, number][])
            .sort((a, b) => b[1] - a[1])[0][0]

        // Classification
        const classification = composite >= 70 ? 'critical'
            : composite >= 50 ? 'hostile'
                : composite >= 30 ? 'suspicious'
                    : composite > 0 ? 'noise'
                        : 'clear'

        return {
            security,
            privacy,
            compliance,
            operational,
            composite,
            dominantAxis,
            classification,
            factors,
        }
    }
}
