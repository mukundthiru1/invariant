/**
 * INVARIANT v4 — Privilege Graph (Phase 2)
 *
 * Infers the privilege structure of an application from
 * observed traffic patterns. No credentials inspected,
 * no body parsing — only metadata and behavioral patterns.
 *
 * Core idea: endpoints that require authentication form a
 * directed graph of privilege levels. By observing which
 * endpoints are accessed with which auth types, we can infer:
 *
 *   1. Which endpoints are public (anonymous access)
 *   2. Which require authentication (any auth type)
 *   3. Which require elevated privileges (admin paths, 403 responses)
 *   4. Which endpoints are related (shared auth requirements)
 *
 * This enables:
 *   - Phase 4: "What privilege do I need to reach this endpoint?"
 *   - Phase 5: "If I compromise endpoint X, what else can I reach?"
 *   - Advisories: "This endpoint is admin-only but has no rate limiting"
 *
 * The graph is built incrementally from ApplicationModel data.
 * It does NOT store credentials, tokens, or user data.
 */


// ═══════════════════════════════════════════════════════════════════
// PRIVILEGE LEVELS
//
// Ordered from least to most privilege.
// Each endpoint is assigned the MINIMUM privilege level
// observed in traffic, with heuristic adjustments.
// ═══════════════════════════════════════════════════════════════════

export type PrivilegeLevel =
    | 'public'          // No auth required — accessible by anyone
    | 'authenticated'   // Requires any form of authentication
    | 'elevated'        // Requires elevated privileges (admin, manager)
    | 'system'          // Internal/system endpoints (health checks, metrics)

const PRIVILEGE_ORDER: Record<PrivilegeLevel, number> = {
    public: 0,
    authenticated: 1,
    elevated: 2,
    system: 3,
}


// ═══════════════════════════════════════════════════════════════════
// ENDPOINT PRIVILEGE ASSIGNMENT
// ═══════════════════════════════════════════════════════════════════

export interface EndpointPrivilege {
    /** Normalized endpoint pattern */
    pattern: string
    /** Inferred minimum privilege level */
    level: PrivilegeLevel
    /** How confident we are in this assignment (0.0 - 1.0) */
    confidence: number
    /** Why this level was assigned */
    reason: string
    /** Whether this endpoint handles sensitive data */
    sensitive: boolean
    /** HTTP methods observed */
    methods: string[]
    /** Auth types observed with distribution */
    authDistribution: Record<string, number>
    /** Total requests used for inference */
    sampleSize: number
}


// ═══════════════════════════════════════════════════════════════════
// PRIVILEGE EDGE
//
// Represents a relationship between two endpoints
// at different privilege levels. Used for blast radius
// computation and path enumeration.
// ═══════════════════════════════════════════════════════════════════

export interface PrivilegeEdge {
    /** Source endpoint */
    from: string
    /** Target endpoint */
    to: string
    /** Privilege transition type */
    type: 'escalation' | 'same_level' | 'de_escalation'
    /** The auth type that connects them */
    sharedAuth: string[]
}


// ═══════════════════════════════════════════════════════════════════
// PRIVILEGE GRAPH SNAPSHOT
// ═══════════════════════════════════════════════════════════════════

export interface PrivilegeGraphSnapshot {
    /** Unique sensor identifier */
    sensorId: string
    /** Total endpoints classified */
    totalEndpoints: number
    /** Distribution by privilege level */
    levelDistribution: Record<PrivilegeLevel, number>
    /** Endpoints with privilege assignments */
    endpoints: EndpointPrivilege[]
    /** Privilege edges (relationships between endpoints) */
    edges: PrivilegeEdge[]
    /** Security observations */
    observations: PrivilegeObservation[]
    /** Snapshot timestamp */
    timestamp: string
}


// ═══════════════════════════════════════════════════════════════════
// PRIVILEGE OBSERVATIONS
//
// Security-relevant patterns detected in the privilege structure.
// These feed directly into advisories.
// ═══════════════════════════════════════════════════════════════════

export interface PrivilegeObservation {
    /** Type of observation */
    type:
    | 'mixed_auth'              // Endpoint accepts both anon and auth (potential IDOR)
    | 'admin_no_mfa_indicator'  // Admin endpoint with no step-up auth observed
    | 'sensitive_public'        // Sensitive data endpoint accessible anonymously
    | 'write_public'            // State-changing endpoint accessible anonymously
    | 'privilege_boundary_thin' // Very few endpoints separate public from elevated
    /** Affected endpoints */
    endpoints: string[]
    /** Human-readable description */
    description: string
    /** Severity of the observation */
    severity: 'info' | 'warning' | 'critical'
}


// ═══════════════════════════════════════════════════════════════════
// PATH HEURISTICS
//
// Well-known path patterns that indicate privilege levels.
// Used as a strong prior when traffic volume is low.
// ═══════════════════════════════════════════════════════════════════

const ADMIN_PATTERNS = /\/(admin|manage|dashboard|management|backoffice|control|moderator)/i
const SYSTEM_PATTERNS = /\/(__invariant|_internal|actuator|metrics|healthz?|readyz?|livez?|debug|\.well-known)/i
const AUTH_PATTERNS = /\/(login|logout|signin|signup|register|forgot|reset|verify|callback|oauth|sso|auth)/i
const SENSITIVE_PATHS = /\/(user|profile|account|settings|me|billing|payment|token|secret|credential|password|key)/i
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])


// ═══════════════════════════════════════════════════════════════════
// PRIVILEGE GRAPH ENGINE
// ═══════════════════════════════════════════════════════════════════

export class PrivilegeGraph {
    /**
     * Minimum requests before assigning privilege with high confidence.
     */
    private static readonly HIGH_CONFIDENCE_THRESHOLD = 10

    /**
     * Minimum requests before assigning privilege with medium confidence.
     */
    private static readonly MEDIUM_CONFIDENCE_THRESHOLD = 3

    /**
     * Build a privilege graph from application model endpoint data.
     *
     * This is a PURE function — no state mutation, no side effects.
     * Called on-demand (not per-request) for health/posture endpoints.
     *
     * @param endpoints - Endpoint snapshots from ApplicationModel.snapshot()
     * @param sensorId - Sensor identifier for the snapshot
     */
    buildGraph(
        endpoints: Array<{
            pattern: string
            methods: Record<string, number>
            auth: Record<string, number>
            sensitive: boolean
            requestCount: number
        }>,
        sensorId: string,
    ): PrivilegeGraphSnapshot {
        // Phase 1: Assign privilege levels to each endpoint
        const privilegeEndpoints = endpoints.map(ep => this.classifyEndpoint(ep))

        // Phase 2: Build edges between endpoints
        const edges = this.buildEdges(privilegeEndpoints)

        // Phase 3: Detect security observations
        const observations = this.detectObservations(privilegeEndpoints)

        // Phase 4: Compute level distribution
        const levelDistribution: Record<PrivilegeLevel, number> = {
            public: 0,
            authenticated: 0,
            elevated: 0,
            system: 0,
        }
        for (const ep of privilegeEndpoints) {
            levelDistribution[ep.level]++
        }

        return {
            sensorId,
            totalEndpoints: privilegeEndpoints.length,
            levelDistribution,
            endpoints: privilegeEndpoints,
            edges,
            observations,
            timestamp: new Date().toISOString(),
        }
    }

    private classifyEndpoint(ep: {
        pattern: string
        methods: Record<string, number>
        auth: Record<string, number>
        sensitive: boolean
        requestCount: number
    }): EndpointPrivilege {
        const pattern = ep.pattern
        const totalRequests = ep.requestCount
        const methods = Object.keys(ep.methods)

        // Auth distribution analysis
        const anonCount = ep.auth['anonymous'] ?? 0
        const bearerCount = ep.auth['bearer'] ?? 0
        const cookieCount = ep.auth['cookie'] ?? 0
        const apiKeyCount = ep.auth['api_key'] ?? 0
        const basicCount = ep.auth['basic'] ?? 0
        const authCount = bearerCount + cookieCount + apiKeyCount + basicCount
        const anonRatio = totalRequests > 0 ? anonCount / totalRequests : 1

        // Calculate confidence based on sample size
        let confidence: number
        if (totalRequests >= PrivilegeGraph.HIGH_CONFIDENCE_THRESHOLD) {
            confidence = 0.9
        } else if (totalRequests >= PrivilegeGraph.MEDIUM_CONFIDENCE_THRESHOLD) {
            confidence = 0.6
        } else {
            confidence = 0.3
        }

        // ── SYSTEM endpoints (path heuristics) ────────────────────
        if (SYSTEM_PATTERNS.test(pattern)) {
            return {
                pattern,
                level: 'system',
                confidence: Math.max(confidence, 0.8), // Path heuristic is strong
                reason: 'System/internal path pattern detected',
                sensitive: false,
                methods,
                authDistribution: ep.auth,
                sampleSize: totalRequests,
            }
        }

        // ── ELEVATED endpoints (admin path + auth required) ──────
        if (ADMIN_PATTERNS.test(pattern) && authCount > 0) {
            return {
                pattern,
                level: 'elevated',
                confidence: Math.max(confidence, 0.7),
                reason: `Admin path with ${authCount}/${totalRequests} authenticated requests`,
                sensitive: true,
                methods,
                authDistribution: ep.auth,
                sampleSize: totalRequests,
            }
        }

        // ── ELEVATED (admin path even without auth — suspicious) ──
        if (ADMIN_PATTERNS.test(pattern) && anonRatio > 0.8) {
            return {
                pattern,
                level: 'elevated',
                confidence: 0.4, // Low confidence — admin path but mostly anonymous
                reason: 'Admin path accessed anonymously — possible misconfiguration',
                sensitive: true,
                methods,
                authDistribution: ep.auth,
                sampleSize: totalRequests,
            }
        }

        // ── AUTHENTICATED (mostly auth traffic) ──────────────────
        if (anonRatio < 0.2 && totalRequests >= PrivilegeGraph.MEDIUM_CONFIDENCE_THRESHOLD) {
            return {
                pattern,
                level: 'authenticated',
                confidence,
                reason: `${Math.round((1 - anonRatio) * 100)}% authenticated traffic (${authCount}/${totalRequests})`,
                sensitive: ep.sensitive || SENSITIVE_PATHS.test(pattern),
                methods,
                authDistribution: ep.auth,
                sampleSize: totalRequests,
            }
        }

        // ── AUTHENTICATED (sensitive path heuristic) ──────────────
        if (SENSITIVE_PATHS.test(pattern) && authCount > 0) {
            return {
                pattern,
                level: 'authenticated',
                confidence: Math.max(confidence, 0.5),
                reason: 'Sensitive path pattern with some authenticated access',
                sensitive: true,
                methods,
                authDistribution: ep.auth,
                sampleSize: totalRequests,
            }
        }

        // ── PUBLIC (default — mostly anonymous) ──────────────────
        return {
            pattern,
            level: 'public',
            confidence,
            reason: anonRatio > 0.8
                ? `${Math.round(anonRatio * 100)}% anonymous traffic`
                : `Mixed traffic (${Math.round(anonRatio * 100)}% anonymous) — defaulting to public`,
            sensitive: ep.sensitive,
            methods,
            authDistribution: ep.auth,
            sampleSize: totalRequests,
        }
    }

    /**
     * Build edges between endpoints based on shared auth patterns.
     * An edge represents: "if you can access A, you can access B"
     * (same auth mechanism required).
     */
    private buildEdges(endpoints: EndpointPrivilege[]): PrivilegeEdge[] {
        const edges: PrivilegeEdge[] = []

        // Group endpoints by auth types used
        for (let i = 0; i < endpoints.length; i++) {
            const from = endpoints[i]
            const fromAuthTypes = Object.keys(from.authDistribution).filter(
                k => from.authDistribution[k] > 0
            )

            for (let j = i + 1; j < endpoints.length; j++) {
                const to = endpoints[j]
                const toAuthTypes = Object.keys(to.authDistribution).filter(
                    k => to.authDistribution[k] > 0
                )

                // Find shared auth types
                const shared = fromAuthTypes.filter(a => toAuthTypes.includes(a))
                if (shared.length === 0) continue
                // Skip if both are purely anonymous
                if (shared.length === 1 && shared[0] === 'anonymous') continue

                const fromOrder = PRIVILEGE_ORDER[from.level]
                const toOrder = PRIVILEGE_ORDER[to.level]

                let type: PrivilegeEdge['type']
                if (fromOrder < toOrder) type = 'escalation'
                else if (fromOrder > toOrder) type = 'de_escalation'
                else type = 'same_level'

                edges.push({
                    from: from.pattern,
                    to: to.pattern,
                    type,
                    sharedAuth: shared,
                })
            }
        }

        return edges
    }

    /**
     * Detect security-relevant observations in the privilege structure.
     */
    private detectObservations(endpoints: EndpointPrivilege[]): PrivilegeObservation[] {
        const observations: PrivilegeObservation[] = []

        for (const ep of endpoints) {
            const anonCount = ep.authDistribution['anonymous'] ?? 0
            const authTotal = ep.sampleSize - anonCount
            const anonRatio = ep.sampleSize > 0 ? anonCount / ep.sampleSize : 0

            // Mixed auth — endpoint accepts both anonymous and authenticated
            if (anonCount > 0 && authTotal > 0 && ep.sampleSize >= PrivilegeGraph.MEDIUM_CONFIDENCE_THRESHOLD) {
                const anonPct = Math.round(anonRatio * 100)
                const authPct = 100 - anonPct
                if (anonPct > 10 && authPct > 10) { // Not just noise
                    observations.push({
                        type: 'mixed_auth',
                        endpoints: [ep.pattern],
                        description:
                            `${ep.pattern} accepts both anonymous (${anonPct}%) and authenticated (${authPct}%) ` +
                            'requests. If this returns user-specific data, it may be vulnerable to IDOR.',
                        severity: ep.sensitive ? 'warning' : 'info',
                    })
                }
            }

            // Sensitive endpoint accessible publicly
            if (ep.sensitive && ep.level === 'public' && ep.sampleSize >= PrivilegeGraph.MEDIUM_CONFIDENCE_THRESHOLD) {
                observations.push({
                    type: 'sensitive_public',
                    endpoints: [ep.pattern],
                    description:
                        `${ep.pattern} appears to return sensitive data but is publicly accessible. ` +
                        'Verify that authentication is enforced and data is properly scoped.',
                    severity: 'critical',
                })
            }

            // Write operations on public endpoints
            const hasWriteMethods = ep.methods.some(m => WRITE_METHODS.has(m))
            if (hasWriteMethods && ep.level === 'public' && anonRatio > 0.5) {
                observations.push({
                    type: 'write_public',
                    endpoints: [ep.pattern],
                    description:
                        `${ep.pattern} accepts state-changing methods (${ep.methods.filter(m => WRITE_METHODS.has(m)).join(', ')}) ` +
                        'and is primarily accessed anonymously. Ensure proper authorization checks.',
                    severity: 'warning',
                })
            }
        }

        // Thin privilege boundary — very few endpoints between public and elevated
        const publicCount = endpoints.filter(ep => ep.level === 'public').length
        const elevatedCount = endpoints.filter(ep => ep.level === 'elevated').length
        const authCount = endpoints.filter(ep => ep.level === 'authenticated').length

        if (elevatedCount > 0 && authCount === 0 && publicCount > 0) {
            observations.push({
                type: 'privilege_boundary_thin',
                endpoints: endpoints.filter(ep => ep.level === 'elevated').map(ep => ep.pattern),
                description:
                    'No intermediate authenticated endpoints detected between public and elevated. ' +
                    'The privilege boundary may be thin — a single auth bypass could expose admin functionality.',
                severity: 'warning',
            })
        }

        return observations
    }
}
