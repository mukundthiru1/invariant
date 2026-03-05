/**
 * INVARIANT v4 — Blast Radius (Phase 5)
 *
 * Given a compromised endpoint, compute the TOTAL DAMAGE:
 * what data is reachable, what actions are possible, and
 * how far the compromise cascades through the application.
 *
 * This is the capstone of the INVARIANT v4 architecture.
 * It synthesizes all previous phases:
 *   - Phase 1 (Application Model): endpoint inventory
 *   - Phase 2 (Privilege Graph): access relationships
 *   - Phase 3 (CVE-Stack): tech-specific vulnerabilities
 *   - Phase 4 (Path Enumeration): alternative access paths
 *   - Phase 6 (Reactivation): misconfiguration amplifiers
 *
 * Output: A structured blast radius report that tells the
 * subscriber exactly what's at risk if a specific endpoint
 * or privilege level is compromised.
 *
 * This powers:
 *   - Advisory "Impact" sections
 *   - Risk scoring for vulnerability prioritization
 *   - "What's the worst case?" analysis for decision makers
 */


import type { PrivilegeGraphSnapshot, EndpointPrivilege, PrivilegeLevel, PrivilegeObservation } from './privilege-graph'
import type { PathEnumerationReport, AlternativePath } from './path-enumeration'
import type { VulnerabilityProfile } from './cve-stack-correlation'
import type { ReactivationMatch } from './reactivation-engine'


// ═══════════════════════════════════════════════════════════════════
// BLAST RADIUS SCOPE
//
// What an attacker can do from a compromised position.
// ═══════════════════════════════════════════════════════════════════

export interface BlastRadiusScope {
    /** Endpoints directly reachable from the compromised position */
    directlyReachable: EndpointImpact[]
    /** Endpoints reachable through privilege escalation */
    escalationReachable: EndpointImpact[]
    /** Endpoints reachable through reactivation vectors */
    reactivationReachable: EndpointImpact[]
    /** Total unique endpoints at risk */
    totalEndpointsAtRisk: number
    /** Sensitive endpoints at risk */
    sensitiveEndpointsAtRisk: number
}


export interface EndpointImpact {
    /** Endpoint pattern */
    pattern: string
    /** Privilege level required */
    level: PrivilegeLevel | string
    /** Whether it handles sensitive data */
    sensitive: boolean
    /** Methods available */
    methods: string[]
    /** How the attacker reaches this endpoint */
    accessMethod: 'direct' | 'same_auth' | 'escalation' | 'reactivation' | 'api_version'
    /** Impact if this endpoint is abused */
    impact: string
}


// ═══════════════════════════════════════════════════════════════════
// DATA IMPACT ASSESSMENT
// ═══════════════════════════════════════════════════════════════════

export interface DataImpact {
    /** Can the attacker read user data? */
    canReadUserData: boolean
    /** Can the attacker modify data? */
    canModifyData: boolean
    /** Can the attacker delete data? */
    canDeleteData: boolean
    /** Can the attacker access admin functions? */
    canAccessAdmin: boolean
    /** Can the attacker perform financial transactions? */
    canPerformTransactions: boolean
    /** Can the attacker escalate to higher privileges? */
    canEscalatePrivileges: boolean
    /** Evidence for each assertion */
    evidence: string[]
}


// ═══════════════════════════════════════════════════════════════════
// BLAST RADIUS REPORT
// ═══════════════════════════════════════════════════════════════════

export interface BlastRadiusReport {
    /** Sensor identifier */
    sensorId: string
    /** The compromised starting point */
    compromisePoint: {
        endpoint: string
        level: string
    }
    /** Overall risk score (0-100) */
    riskScore: number
    /** Risk grade (A-F) */
    riskGrade: string
    /** Blast radius scope */
    scope: BlastRadiusScope
    /** Data impact assessment */
    dataImpact: DataImpact
    /** CWE classes that amplify the blast radius */
    amplifyingCWEs: string[]
    /** Reactivation vectors that extend reach */
    amplifyingReactivations: string[]
    /** Security observations that affect blast radius */
    relevantObservations: PrivilegeObservation[]
    /** Human-readable executive summary */
    summary: string
    /** Timestamp */
    timestamp: string
}

// ═══════════════════════════════════════════════════════════════════
// FULL BLAST RADIUS ANALYSIS
//
// Analyzes every privilege level and sensitive endpoint.
// ═══════════════════════════════════════════════════════════════════

export interface BlastRadiusAnalysis {
    /** Sensor identifier */
    sensorId: string
    /** Individual blast radius reports for key compromise points */
    reports: BlastRadiusReport[]
    /** Global statistics */
    stats: {
        totalCompromisePoints: number
        highestRiskScore: number
        averageRiskScore: number
        totalEndpointsAtRisk: number
    }
    /** Overall application risk assessment */
    overallRisk: 'critical' | 'high' | 'medium' | 'low'
    /** Timestamp */
    timestamp: string
}


// ═══════════════════════════════════════════════════════════════════
// IMPACT PATTERNS
//
// Heuristic endpoint impact classification based on path patterns.
// ═══════════════════════════════════════════════════════════════════

const FINANCIAL_PATTERNS = /\/(payment|billing|invoice|charge|transfer|refund|subscription|checkout|order|purchase)/i
const USER_DATA_PATTERNS = /\/(user|profile|account|me|settings|preference|personal|contact|address)/i
const ADMIN_PATTERNS = /\/(admin|manage|dashboard|management|backoffice|control|moderator)/i
const AUTH_PATTERNS = /\/(auth|login|token|session|password|credential|key|secret|oauth|sso)/i
const DESTRUCTIVE_METHODS = new Set(['DELETE', 'PUT', 'PATCH'])
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])


function classifyEndpointImpact(ep: EndpointPrivilege): string {
    const p = ep.pattern
    if (FINANCIAL_PATTERNS.test(p)) return 'Financial operations — potential monetary loss'
    if (AUTH_PATTERNS.test(p)) return 'Authentication/authorization — credential access or session manipulation'
    if (ADMIN_PATTERNS.test(p)) return 'Administrative functions — full application control'
    if (USER_DATA_PATTERNS.test(p)) return 'User data access — PII exposure, privacy violation'
    if (ep.sensitive) return 'Sensitive data endpoint — data exposure risk'
    if (ep.methods.some(m => DESTRUCTIVE_METHODS.has(m))) return 'Destructive operations — data integrity risk'
    if (ep.methods.some(m => WRITE_METHODS.has(m))) return 'State-changing operations — data modification risk'
    return 'Data access — information disclosure'
}


// ═══════════════════════════════════════════════════════════════════
// BLAST RADIUS ENGINE
// ═══════════════════════════════════════════════════════════════════

export class BlastRadiusEngine {
    /**
     * Compute the blast radius for a specific compromise point.
     *
     * @param compromiseEndpoint - The endpoint that was compromised
     * @param privilegeGraph - Current privilege graph
     * @param pathEnum - Path enumeration report
     * @param reactivations - Active reactivation matches
     * @param vulnProfile - Vulnerability profile (Phase 3)
     */
    computeBlastRadius(
        compromiseEndpoint: string,
        privilegeGraph: PrivilegeGraphSnapshot,
        pathEnum: PathEnumerationReport,
        reactivations: ReactivationMatch[] = [],
        vulnProfile: VulnerabilityProfile | null = null,
    ): BlastRadiusReport {
        const compromiseEp = privilegeGraph.endpoints.find(
            ep => ep.pattern === compromiseEndpoint,
        )

        if (!compromiseEp) {
            return this.emptyReport(compromiseEndpoint, privilegeGraph.sensorId)
        }

        // Phase 1: Compute directly reachable endpoints (same auth)
        const directlyReachable = this.findDirectlyReachable(compromiseEp, privilegeGraph)

        // Phase 2: Compute escalation reachable (privilege edges)
        const escalationReachable = this.findEscalationReachable(compromiseEp, privilegeGraph)

        // Phase 3: Compute reactivation-extended reach
        const reactivationReachable = this.findReactivationReachable(
            compromiseEp, privilegeGraph, reactivations,
        )

        // Combine and deduplicate
        const allReachable = new Map<string, EndpointImpact>()
        for (const ep of directlyReachable) allReachable.set(ep.pattern, ep)
        for (const ep of escalationReachable) {
            if (!allReachable.has(ep.pattern)) allReachable.set(ep.pattern, ep)
        }
        for (const ep of reactivationReachable) {
            if (!allReachable.has(ep.pattern)) allReachable.set(ep.pattern, ep)
        }

        const sensitiveCount = [...allReachable.values()].filter(ep => ep.sensitive).length

        const scope: BlastRadiusScope = {
            directlyReachable,
            escalationReachable,
            reactivationReachable,
            totalEndpointsAtRisk: allReachable.size,
            sensitiveEndpointsAtRisk: sensitiveCount,
        }

        // Assess data impact
        const dataImpact = this.assessDataImpact([...allReachable.values()])

        // Identify amplifying factors
        const amplifyingCWEs = vulnProfile?.aggregateCWEs ?? []
        const amplifyingReactivations = reactivations.map(r => r.rule_id)

        // Relevant observations
        const relevantObservations = privilegeGraph.observations.filter(obs =>
            obs.endpoints.some(ep => allReachable.has(ep)),
        )

        // Compute risk score
        const riskScore = this.computeRiskScore(scope, dataImpact, reactivations, relevantObservations)
        const riskGrade = this.scoreToGrade(riskScore)

        return {
            sensorId: privilegeGraph.sensorId,
            compromisePoint: {
                endpoint: compromiseEndpoint,
                level: compromiseEp.level,
            },
            riskScore,
            riskGrade,
            scope,
            dataImpact,
            amplifyingCWEs,
            amplifyingReactivations,
            relevantObservations,
            summary: this.buildSummary(compromiseEp, scope, dataImpact, riskScore, riskGrade),
            timestamp: new Date().toISOString(),
        }
    }

    /**
     * Analyze blast radius for all compromise-worthy endpoints.
     * Targets: authenticated, elevated, and sensitive endpoints.
     */
    analyzeAll(
        privilegeGraph: PrivilegeGraphSnapshot,
        pathEnum: PathEnumerationReport,
        reactivations: ReactivationMatch[] = [],
        vulnProfile: VulnerabilityProfile | null = null,
    ): BlastRadiusAnalysis {
        // Select key compromise points
        const targets = privilegeGraph.endpoints.filter(
            ep => ep.level === 'authenticated' || ep.level === 'elevated' || ep.sensitive,
        )

        const reports: BlastRadiusReport[] = []
        for (const target of targets) {
            const report = this.computeBlastRadius(
                target.pattern, privilegeGraph, pathEnum, reactivations, vulnProfile,
            )
            reports.push(report)
        }

        const riskScores = reports.map(r => r.riskScore)
        const highestRisk = Math.max(0, ...riskScores)
        const avgRisk = riskScores.length > 0
            ? Math.round(riskScores.reduce((a, b) => a + b, 0) / riskScores.length)
            : 0

        const totalAtRisk = new Set(
            reports.flatMap(r => [
                ...r.scope.directlyReachable.map(e => e.pattern),
                ...r.scope.escalationReachable.map(e => e.pattern),
                ...r.scope.reactivationReachable.map(e => e.pattern),
            ]),
        ).size

        let overallRisk: BlastRadiusAnalysis['overallRisk']
        if (highestRisk >= 80) overallRisk = 'critical'
        else if (highestRisk >= 60) overallRisk = 'high'
        else if (highestRisk >= 30) overallRisk = 'medium'
        else overallRisk = 'low'

        return {
            sensorId: privilegeGraph.sensorId,
            reports,
            stats: {
                totalCompromisePoints: reports.length,
                highestRiskScore: highestRisk,
                averageRiskScore: avgRisk,
                totalEndpointsAtRisk: totalAtRisk,
            },
            overallRisk,
            timestamp: new Date().toISOString(),
        }
    }

    // ── Internal: Reach computation ──────────────────────────────

    private findDirectlyReachable(
        compromise: EndpointPrivilege,
        graph: PrivilegeGraphSnapshot,
    ): EndpointImpact[] {
        const results: EndpointImpact[] = []

        // Find all endpoints at same or lower privilege level
        // that share an auth type with the compromised endpoint
        const compromiseAuthTypes = Object.entries(compromise.authDistribution)
            .filter(([, count]) => count > 0)
            .map(([type]) => type)
            .filter(type => type !== 'anonymous')

        for (const ep of graph.endpoints) {
            if (ep.pattern === compromise.pattern) continue

            const epAuthTypes = Object.entries(ep.authDistribution)
                .filter(([, count]) => count > 0)
                .map(([type]) => type)

            const shared = compromiseAuthTypes.filter(a => epAuthTypes.includes(a))
            if (shared.length > 0) {
                results.push({
                    pattern: ep.pattern,
                    level: ep.level,
                    sensitive: ep.sensitive,
                    methods: ep.methods,
                    accessMethod: 'same_auth',
                    impact: classifyEndpointImpact(ep),
                })
            }
        }

        return results
    }

    private findEscalationReachable(
        compromise: EndpointPrivilege,
        graph: PrivilegeGraphSnapshot,
    ): EndpointImpact[] {
        const results: EndpointImpact[] = []

        // Find escalation edges from the compromised endpoint
        const escalationEdges = graph.edges.filter(
            e => (e.from === compromise.pattern || e.to === compromise.pattern)
                && e.type === 'escalation',
        )

        for (const edge of escalationEdges) {
            const targetPattern = edge.from === compromise.pattern ? edge.to : edge.from
            const targetEp = graph.endpoints.find(ep => ep.pattern === targetPattern)
            if (!targetEp) continue

            results.push({
                pattern: targetEp.pattern,
                level: targetEp.level,
                sensitive: targetEp.sensitive,
                methods: targetEp.methods,
                accessMethod: 'escalation',
                impact: classifyEndpointImpact(targetEp),
            })
        }

        return results
    }

    private findReactivationReachable(
        compromise: EndpointPrivilege,
        graph: PrivilegeGraphSnapshot,
        reactivations: ReactivationMatch[],
    ): EndpointImpact[] {
        if (reactivations.length === 0) return []

        const results: EndpointImpact[] = []

        // XSS/session hijack reactivations make ALL authenticated endpoints reachable
        const hasXSSReactivation = reactivations.some(r =>
            r.reactivated_categories.includes('xss') ||
            r.reactivated_categories.includes('session_hijack'),
        )

        if (hasXSSReactivation) {
            for (const ep of graph.endpoints) {
                if (ep.pattern === compromise.pattern) continue
                if (ep.level === 'public' || ep.level === 'system') continue

                results.push({
                    pattern: ep.pattern,
                    level: ep.level,
                    sensitive: ep.sensitive,
                    methods: ep.methods,
                    accessMethod: 'reactivation',
                    impact: classifyEndpointImpact(ep) + ' (via XSS session theft)',
                })
            }
        }

        return results
    }

    // ── Internal: Data impact assessment ─────────────────────────

    private assessDataImpact(endpoints: EndpointImpact[]): DataImpact {
        const evidence: string[] = []

        const canReadUserData = endpoints.some(ep => {
            if (USER_DATA_PATTERNS.test(ep.pattern)) {
                evidence.push(`User data: ${ep.pattern} is reachable`)
                return true
            }
            return false
        })

        const canModifyData = endpoints.some(ep => {
            const hasWrite = ep.methods.some(m => WRITE_METHODS.has(m))
            if (hasWrite && ep.sensitive) {
                evidence.push(`Data modification: ${ep.pattern} accepts ${ep.methods.filter(m => WRITE_METHODS.has(m)).join(', ')}`)
                return true
            }
            return false
        })

        const canDeleteData = endpoints.some(ep => {
            if (ep.methods.includes('DELETE')) {
                evidence.push(`Data deletion: ${ep.pattern} accepts DELETE`)
                return true
            }
            return false
        })

        const canAccessAdmin = endpoints.some(ep => {
            if (ep.level === 'elevated' || ADMIN_PATTERNS.test(ep.pattern)) {
                evidence.push(`Admin access: ${ep.pattern} (${ep.level})`)
                return true
            }
            return false
        })

        const canPerformTransactions = endpoints.some(ep => {
            if (FINANCIAL_PATTERNS.test(ep.pattern)) {
                evidence.push(`Financial: ${ep.pattern}`)
                return true
            }
            return false
        })

        const canEscalatePrivileges = endpoints.some(ep => {
            if (ep.accessMethod === 'escalation') {
                evidence.push(`Privilege escalation to ${ep.level} via ${ep.pattern}`)
                return true
            }
            return false
        })

        return {
            canReadUserData,
            canModifyData,
            canDeleteData,
            canAccessAdmin,
            canPerformTransactions,
            canEscalatePrivileges,
            evidence,
        }
    }

    // ── Internal: Risk scoring ───────────────────────────────────

    private computeRiskScore(
        scope: BlastRadiusScope,
        dataImpact: DataImpact,
        reactivations: ReactivationMatch[],
        observations: PrivilegeObservation[],
    ): number {
        let score = 0

        // Base: endpoints at risk (0-30 points)
        score += Math.min(30, scope.totalEndpointsAtRisk * 3)

        // Sensitive endpoints (0-20 points)
        score += Math.min(20, scope.sensitiveEndpointsAtRisk * 5)

        // Data impact (0-30 points)
        if (dataImpact.canAccessAdmin) score += 10
        if (dataImpact.canPerformTransactions) score += 8
        if (dataImpact.canDeleteData) score += 5
        if (dataImpact.canModifyData) score += 4
        if (dataImpact.canReadUserData) score += 3

        // Reactivation amplification (0-10 points)
        const criticalReactivations = reactivations.filter(r =>
            r.severity_boost === 'critical_upgrade',
        )
        score += Math.min(10, criticalReactivations.length * 3)

        // Security observations (0-10 points)
        const criticalObs = observations.filter(o => o.severity === 'critical')
        score += Math.min(10, criticalObs.length * 5)

        return Math.min(100, score)
    }

    private scoreToGrade(score: number): string {
        // Lower score = better security posture
        // The score represents RISK, not security quality
        if (score <= 10) return 'A'
        if (score <= 25) return 'B'
        if (score <= 45) return 'C'
        if (score <= 65) return 'D'
        return 'F'
    }

    private buildSummary(
        compromise: EndpointPrivilege,
        scope: BlastRadiusScope,
        dataImpact: DataImpact,
        riskScore: number,
        riskGrade: string,
    ): string {
        const parts: string[] = [
            `Blast radius from ${compromise.pattern} (${compromise.level}): ` +
            `${scope.totalEndpointsAtRisk} endpoint(s) at risk, risk score ${riskScore}/100 (${riskGrade}).`,
        ]

        if (scope.sensitiveEndpointsAtRisk > 0) {
            parts.push(`${scope.sensitiveEndpointsAtRisk} sensitive endpoint(s) exposed.`)
        }

        const impacts: string[] = []
        if (dataImpact.canAccessAdmin) impacts.push('admin access')
        if (dataImpact.canPerformTransactions) impacts.push('financial operations')
        if (dataImpact.canDeleteData) impacts.push('data destruction')
        if (dataImpact.canModifyData) impacts.push('data modification')
        if (dataImpact.canReadUserData) impacts.push('user data exposure')
        if (dataImpact.canEscalatePrivileges) impacts.push('privilege escalation')

        if (impacts.length > 0) {
            parts.push(`Potential impact: ${impacts.join(', ')}.`)
        }

        if (scope.reactivationReachable.length > 0) {
            parts.push(
                `${scope.reactivationReachable.length} additional endpoint(s) reachable ` +
                'through misconfiguration reactivation vectors.',
            )
        }

        return parts.join(' ')
    }

    private emptyReport(endpoint: string, sensorId: string): BlastRadiusReport {
        return {
            sensorId,
            compromisePoint: { endpoint, level: 'unknown' },
            riskScore: 0,
            riskGrade: 'A',
            scope: {
                directlyReachable: [],
                escalationReachable: [],
                reactivationReachable: [],
                totalEndpointsAtRisk: 0,
                sensitiveEndpointsAtRisk: 0,
            },
            dataImpact: {
                canReadUserData: false,
                canModifyData: false,
                canDeleteData: false,
                canAccessAdmin: false,
                canPerformTransactions: false,
                canEscalatePrivileges: false,
                evidence: [],
            },
            amplifyingCWEs: [],
            amplifyingReactivations: [],
            relevantObservations: [],
            summary: `Endpoint ${endpoint} not found in privilege graph. No blast radius computed.`,
            timestamp: new Date().toISOString(),
        }
    }
}
