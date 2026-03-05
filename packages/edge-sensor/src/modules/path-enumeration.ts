/**
 * INVARIANT v4 — Path Enumeration (Phase 4)
 *
 * Given a vulnerability at a specific endpoint, enumerate ALL
 * alternative paths an attacker could use to exploit it.
 *
 * Core insight from the user's lockdown bypass experience:
 *   "Even the best security engineers patch the delivery mechanism
 *    or the privilege instead of the exploit."
 *
 * This module asks three questions for every vulnerability:
 *   1. What other endpoints share the same auth requirement?
 *      → Same credential = same access
 *   2. What lower-privilege paths lead to the same data?
 *      → IDOR, rate limit bypass, API versioning
 *   3. What misconfigurations broaden the attack surface?
 *      → Reactivation vectors from Phase 6
 *
 * This is the RULE-BASED component. The AI-assisted component
 * (Phase 4b, future) will use LLMs to reason about novel
 * delivery mechanisms not captured in rules.
 *
 * Privacy: No request bodies, no credentials, no user data.
 * Only endpoint patterns and privilege metadata.
 */


import type { EndpointPrivilege, PrivilegeEdge, PrivilegeGraphSnapshot } from './privilege-graph'
import type { ReactivationMatch } from './reactivation-engine'
import type { VulnerabilityProfile } from './cve-stack-correlation'


// ═══════════════════════════════════════════════════════════════════
// ALTERNATIVE PATH
// ═══════════════════════════════════════════════════════════════════

export interface AlternativePath {
    /** How the alternative path was discovered */
    discovery: 'same_auth' | 'privilege_edge' | 'api_version' | 'method_override' | 'reactivation'
    /** The alternative endpoint pattern */
    endpoint: string
    /** Privilege level of the alternative path */
    privilegeLevel: string
    /** Why this is an alternative path */
    reasoning: string
    /** Confidence in this being a valid alternative (0.0 - 1.0) */
    confidence: number
}


// ═══════════════════════════════════════════════════════════════════
// PATH ENUMERATION RESULT
// ═══════════════════════════════════════════════════════════════════

export interface PathEnumerationResult {
    /** The target endpoint being analyzed */
    targetEndpoint: string
    /** The target endpoint's privilege level */
    targetPrivilege: string
    /** All alternative paths discovered */
    alternativePaths: AlternativePath[]
    /** Summary statistics */
    stats: {
        totalAlternatives: number
        sameAuthPaths: number
        lowerPrivilegePaths: number
        reactivationPaths: number
        apiVersionPaths: number
    }
    /** Human-readable summary */
    summary: string
}


// ═══════════════════════════════════════════════════════════════════
// FULL ENUMERATION REPORT
// ═══════════════════════════════════════════════════════════════════

export interface PathEnumerationReport {
    /** Sensor identifier */
    sensorId: string
    /** All target endpoints analyzed */
    enumerations: PathEnumerationResult[]
    /** Global statistics */
    stats: {
        totalEndpointsAnalyzed: number
        totalAlternativePaths: number
        endpointsWithAlternatives: number
        highestAlternativeCount: number
    }
    /** Timestamp */
    timestamp: string
}


// ═══════════════════════════════════════════════════════════════════
// API VERSION PATTERNS
//
// Detects versioned APIs and generates alternative version paths.
// /api/v1/users → try /api/v2/users, /api/users
// ═══════════════════════════════════════════════════════════════════

const VERSION_PATTERN = /\/(v\d+)\//

function generateVersionAlternatives(pattern: string): string[] {
    const match = pattern.match(VERSION_PATTERN)
    if (!match) return []

    const currentVersion = match[1]
    const versionNum = parseInt(currentVersion.slice(1))
    const alternatives: string[] = []

    // Try previous versions (often less restricted)
    for (let v = versionNum - 1; v >= 1; v--) {
        alternatives.push(pattern.replace(VERSION_PATTERN, `/v${v}/`))
    }

    // Try next version (sometimes deployed without auth)
    if (versionNum < 10) {
        alternatives.push(pattern.replace(VERSION_PATTERN, `/v${versionNum + 1}/`))
    }

    // Try unversioned path
    alternatives.push(pattern.replace(VERSION_PATTERN, '/'))

    return alternatives
}


// ═══════════════════════════════════════════════════════════════════
// METHOD OVERRIDE PATTERNS
//
// Some frameworks allow HTTP method override via headers or parameters.
// A POST /api/users can become GET /api/users?_method=POST
// ═══════════════════════════════════════════════════════════════════

const METHOD_OVERRIDE_FRAMEWORKS = [
    'rails',       // _method parameter
    'laravel',     // _method parameter
    'django',      // X-HTTP-Method-Override
    'express',     // methodOverride middleware
    'spring',      // HiddenHttpMethodFilter
]


// ═══════════════════════════════════════════════════════════════════
// PATH ENUMERATOR
// ═══════════════════════════════════════════════════════════════════

export class PathEnumerator {
    /**
     * Enumerate alternative paths for a specific endpoint.
     *
     * @param targetPattern - The endpoint to find alternatives for
     * @param privilegeGraph - Current privilege graph snapshot
     * @param reactivations - Current reactivation matches (Phase 6)
     * @param techStack - Detected technology stack
     */
    enumeratePaths(
        targetPattern: string,
        privilegeGraph: PrivilegeGraphSnapshot,
        reactivations: ReactivationMatch[] = [],
        techStack: string[] = [],
    ): PathEnumerationResult {
        const targetEndpoint = privilegeGraph.endpoints.find(
            ep => ep.pattern === targetPattern,
        )

        if (!targetEndpoint) {
            return {
                targetEndpoint: targetPattern,
                targetPrivilege: 'unknown',
                alternativePaths: [],
                stats: { totalAlternatives: 0, sameAuthPaths: 0, lowerPrivilegePaths: 0, reactivationPaths: 0, apiVersionPaths: 0 },
                summary: `Endpoint ${targetPattern} not found in privilege graph.`,
            }
        }

        const alternatives: AlternativePath[] = []

        // Strategy 1: Same auth type → same credential = same access
        this.findSameAuthPaths(targetEndpoint, privilegeGraph, alternatives)

        // Strategy 2: Privilege edges → can reach from lower privilege
        this.findPrivilegeEdgePaths(targetPattern, privilegeGraph, alternatives)

        // Strategy 3: API version alternatives
        this.findApiVersionPaths(targetPattern, privilegeGraph, alternatives)

        // Strategy 4: Method override potential
        this.findMethodOverridePaths(targetEndpoint, techStack, alternatives)

        // Strategy 5: Reactivation-enabled paths
        this.findReactivationPaths(targetEndpoint, reactivations, alternatives)

        // Deduplicate by (endpoint, discovery, reasoning) — same endpoint can appear
        // with different discovery types or different reactivation conditions,
        // each representing a distinct insight
        const seen = new Set<string>()
        const deduped = alternatives.filter(a => {
            const key = `${a.endpoint}::${a.discovery}::${a.reasoning.slice(0, 40)}`
            if (seen.has(key)) return false
            seen.add(key)
            return true
        })

        const sameAuth = deduped.filter(a => a.discovery === 'same_auth').length
        const lowerPriv = deduped.filter(a => a.discovery === 'privilege_edge').length
        const reactivation = deduped.filter(a => a.discovery === 'reactivation').length
        const apiVersion = deduped.filter(a => a.discovery === 'api_version').length

        return {
            targetEndpoint: targetPattern,
            targetPrivilege: targetEndpoint.level,
            alternativePaths: deduped,
            stats: {
                totalAlternatives: deduped.length,
                sameAuthPaths: sameAuth,
                lowerPrivilegePaths: lowerPriv,
                reactivationPaths: reactivation,
                apiVersionPaths: apiVersion,
            },
            summary: this.buildSummary(targetPattern, targetEndpoint.level, deduped),
        }
    }

    /**
     * Enumerate paths for ALL sensitive/elevated endpoints.
     * Used for comprehensive posture analysis.
     */
    enumerateAll(
        privilegeGraph: PrivilegeGraphSnapshot,
        reactivations: ReactivationMatch[] = [],
        techStack: string[] = [],
    ): PathEnumerationReport {
        // Only enumerate for authenticated, elevated, and sensitive endpoints
        const targets = privilegeGraph.endpoints.filter(
            ep => ep.level === 'authenticated' || ep.level === 'elevated' || ep.sensitive,
        )

        const enumerations: PathEnumerationResult[] = []
        for (const target of targets) {
            const result = this.enumeratePaths(target.pattern, privilegeGraph, reactivations, techStack)
            enumerations.push(result)
        }

        const totalAlternatives = enumerations.reduce((sum, e) => sum + e.stats.totalAlternatives, 0)
        const withAlternatives = enumerations.filter(e => e.stats.totalAlternatives > 0).length
        const highestCount = enumerations.reduce((max, e) => Math.max(max, e.stats.totalAlternatives), 0)

        return {
            sensorId: privilegeGraph.sensorId,
            enumerations,
            stats: {
                totalEndpointsAnalyzed: enumerations.length,
                totalAlternativePaths: totalAlternatives,
                endpointsWithAlternatives: withAlternatives,
                highestAlternativeCount: highestCount,
            },
            timestamp: new Date().toISOString(),
        }
    }

    // ── Strategy implementations ──────────────────────────────────

    private findSameAuthPaths(
        target: EndpointPrivilege,
        graph: PrivilegeGraphSnapshot,
        alternatives: AlternativePath[],
    ): void {
        const targetAuthTypes = Object.entries(target.authDistribution)
            .filter(([, count]) => count > 0)
            .map(([type]) => type)
            .filter(type => type !== 'anonymous')

        if (targetAuthTypes.length === 0) return

        for (const ep of graph.endpoints) {
            if (ep.pattern === target.pattern) continue

            const epAuthTypes = Object.entries(ep.authDistribution)
                .filter(([, count]) => count > 0)
                .map(([type]) => type)

            const shared = targetAuthTypes.filter(a => epAuthTypes.includes(a))
            if (shared.length > 0) {
                alternatives.push({
                    discovery: 'same_auth',
                    endpoint: ep.pattern,
                    privilegeLevel: ep.level,
                    reasoning:
                        `Shares ${shared.join(', ')} authentication with ${target.pattern}. ` +
                        'Same credential grants access to both endpoints.',
                    confidence: 0.7,
                })
            }
        }
    }

    private findPrivilegeEdgePaths(
        targetPattern: string,
        graph: PrivilegeGraphSnapshot,
        alternatives: AlternativePath[],
    ): void {
        // Find edges where target is the destination (can be reached from source)
        const inboundEdges = graph.edges.filter(e => e.to === targetPattern || e.from === targetPattern)

        for (const edge of inboundEdges) {
            const otherPattern = edge.from === targetPattern ? edge.to : edge.from
            const otherEndpoint = graph.endpoints.find(ep => ep.pattern === otherPattern)
            if (!otherEndpoint) continue

            if (edge.type === 'escalation' || edge.type === 'same_level') {
                alternatives.push({
                    discovery: 'privilege_edge',
                    endpoint: otherPattern,
                    privilegeLevel: otherEndpoint.level,
                    reasoning:
                        edge.type === 'escalation'
                            ? `Privilege edge: access to ${otherPattern} (${otherEndpoint.level}) can escalate to ${targetPattern} via shared ${edge.sharedAuth.join(', ')} auth.`
                            : `Same privilege level: ${otherPattern} shares ${edge.sharedAuth.join(', ')} auth.`,
                    confidence: edge.type === 'escalation' ? 0.6 : 0.5,
                })
            }
        }
    }

    private findApiVersionPaths(
        targetPattern: string,
        graph: PrivilegeGraphSnapshot,
        alternatives: AlternativePath[],
    ): void {
        const versionAlts = generateVersionAlternatives(targetPattern)

        for (const altPattern of versionAlts) {
            // Check if this alternative exists in the graph
            const existing = graph.endpoints.find(ep => ep.pattern === altPattern)
            if (existing) {
                alternatives.push({
                    discovery: 'api_version',
                    endpoint: existing.pattern,
                    privilegeLevel: existing.level,
                    reasoning:
                        `API version alternative: ${altPattern} exists and may have different auth requirements.`,
                    confidence: 0.5,
                })
            } else {
                // Hypothetical — the endpoint might exist but wasn't observed
                alternatives.push({
                    discovery: 'api_version',
                    endpoint: altPattern,
                    privilegeLevel: 'unknown',
                    reasoning:
                        `Hypothetical API version: ${altPattern} may exist (not yet observed in traffic). ` +
                        'Older API versions often have weaker authentication.',
                    confidence: 0.2,
                })
            }
        }
    }

    private findMethodOverridePaths(
        target: EndpointPrivilege,
        techStack: string[],
        alternatives: AlternativePath[],
    ): void {
        const hasOverrideFramework = techStack.some(t =>
            METHOD_OVERRIDE_FRAMEWORKS.includes(t),
        )

        if (!hasOverrideFramework) return

        // Only relevant for endpoints that accept specific methods
        const writeMethods = target.methods.filter(m =>
            ['POST', 'PUT', 'PATCH', 'DELETE'].includes(m),
        )

        if (writeMethods.length > 0) {
            const frameworks = techStack.filter(t => METHOD_OVERRIDE_FRAMEWORKS.includes(t))
            alternatives.push({
                discovery: 'method_override',
                endpoint: target.pattern,
                privilegeLevel: target.level,
                reasoning:
                    `${frameworks.join(', ')} detected — supports HTTP method override. ` +
                    `${writeMethods.join(', ')} operations on ${target.pattern} may be accessible ` +
                    'via GET with _method parameter or X-HTTP-Method-Override header, ' +
                    'potentially bypassing method-based access controls.',
                confidence: 0.4,
            })
        }
    }

    private findReactivationPaths(
        target: EndpointPrivilege,
        reactivations: ReactivationMatch[],
        alternatives: AlternativePath[],
    ): void {
        if (reactivations.length === 0) return

        // XSS reactivations affect all authenticated endpoints
        // (attacker can steal session and access the endpoint)
        const xssReactivations = reactivations.filter(r =>
            r.reactivated_categories.includes('xss') ||
            r.reactivated_categories.includes('session_hijack'),
        )

        if (xssReactivations.length > 0 && target.level !== 'public') {
            for (const react of xssReactivations) {
                alternatives.push({
                    discovery: 'reactivation',
                    endpoint: target.pattern,
                    privilegeLevel: 'public',
                    reasoning:
                        `Reactivation vector: ${react.condition} enables ${react.reactivated_categories.join(', ')}. ` +
                        `An attacker can steal ${target.level}-level credentials via XSS/session hijacking ` +
                        `and access ${target.pattern} without direct authentication.`,
                    confidence: react.severity_boost === 'critical_upgrade' ? 0.8 : 0.5,
                })
            }
        }

        // CSRF reactivations affect state-changing endpoints
        const csrfReactivations = reactivations.filter(r =>
            r.reactivated_categories.includes('csrf'),
        )

        const hasWriteMethods = target.methods.some(m =>
            ['POST', 'PUT', 'PATCH', 'DELETE'].includes(m),
        )

        if (csrfReactivations.length > 0 && hasWriteMethods && target.level !== 'public') {
            for (const react of csrfReactivations) {
                alternatives.push({
                    discovery: 'reactivation',
                    endpoint: target.pattern,
                    privilegeLevel: 'public',
                    reasoning:
                        `CSRF reactivation: ${react.condition} enables cross-site request forgery. ` +
                        `State-changing operations on ${target.pattern} can be triggered from any website ` +
                        'the authenticated user visits.',
                    confidence: react.severity_boost === 'critical_upgrade' ? 0.8 : 0.5,
                })
            }
        }
    }

    private buildSummary(
        targetPattern: string,
        targetPrivilege: string,
        alternatives: AlternativePath[],
    ): string {
        if (alternatives.length === 0) {
            return `No alternative paths found for ${targetPattern} (${targetPrivilege}).`
        }

        const parts: string[] = [
            `${alternatives.length} alternative path(s) to ${targetPattern} (${targetPrivilege}):`,
        ]

        const byDiscovery = new Map<string, number>()
        for (const alt of alternatives) {
            byDiscovery.set(alt.discovery, (byDiscovery.get(alt.discovery) ?? 0) + 1)
        }

        for (const [discovery, count] of byDiscovery) {
            switch (discovery) {
                case 'same_auth':
                    parts.push(`  ${count} via shared authentication credentials`)
                    break
                case 'privilege_edge':
                    parts.push(`  ${count} via privilege escalation edges`)
                    break
                case 'api_version':
                    parts.push(`  ${count} via API version alternatives`)
                    break
                case 'method_override':
                    parts.push(`  ${count} via HTTP method override`)
                    break
                case 'reactivation':
                    parts.push(`  ${count} via misconfiguration reactivation`)
                    break
            }
        }

        return parts.join('\n')
    }
}
