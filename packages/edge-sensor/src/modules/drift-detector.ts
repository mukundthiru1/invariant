/**
 * @santh/edge-sensor — Drift Detection Layer
 *
 * Core concept from Axiom Drift: the delta matters more than the snapshot.
 *
 * INVARIANT already takes snapshots of security posture (response headers,
 * tech stack, application model, privilege graph). This module compares
 * them over time to detect security-relevant changes:
 *
 *   - Header regressions: HSTS removed, CSP weakened, X-Frame-Options dropped
 *   - Auth degradation: endpoint that required auth now serves anonymously
 *   - Surface expansion: new endpoints, new tech detected
 *   - Privilege changes: public endpoint becoming admin, or admin going public
 *   - Tech stack changes: new framework version, new server detected
 *
 * Why this is transformative:
 *   A WAF tells you "this request is bad."
 *   INVARIANT tells you "this request violates an invariant."
 *   Drift detection tells you "your security posture is regressing
 *   in ways that will make you vulnerable." It's predictive.
 *
 * Runs during cron (scheduled), comparing current state against
 * the previous snapshot stored in KV.
 */


// ── Drift Types ──────────────────────────────────────────────────

export type DriftType =
    | 'header_regression'       // Security header was present, now gone
    | 'header_weakened'         // Security header value degraded
    | 'auth_degradation'        // Endpoint lost authentication requirement
    | 'auth_escalation'         // Endpoint gained authentication (positive)
    | 'endpoint_added'          // New endpoint appeared
    | 'endpoint_removed'        // Endpoint disappeared
    | 'tech_added'              // New technology detected
    | 'tech_removed'            // Technology no longer detected
    | 'privilege_escalation'    // Endpoint became more privileged
    | 'privilege_degradation'   // Endpoint became less privileged (concern)
    | 'surface_expansion'       // Attack surface grew
    | 'endpoint_enumeration_suspected' // Sudden burst of new endpoints
    | 'unusual_method_detected' // Known endpoint observed with new HTTP method
    | 'new_parameter_detected'  // New request parameter names appeared
    | 'posture_improvement'     // Security posture improved

export type DriftSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface DriftEvent {
    type: DriftType
    severity: DriftSeverity
    path: string
    description: string
    previousValue: string | null
    currentValue: string | null
    riskDelta: number  // Positive = more risk, negative = less risk
    detectedAt: string
}


// ── Posture Snapshot ─────────────────────────────────────────────

export interface PostureSnapshot {
    /** ISO timestamp of the snapshot */
    timestamp: string
    /** Security headers observed across responses */
    securityHeaders: Record<string, string | null>
    /** Detected technology stack */
    techStack: string[]
    /** Endpoint patterns and their auth characteristics */
    endpoints: EndpointSnapshot[]
    /** Total request count at snapshot time */
    totalRequests: number
}

export interface EndpointSnapshot {
    pattern: string
    methods: string[]
    authTypes: Record<string, number>
    sensitive: boolean
    requestCount: number
    parameterNames?: string[]
}


// ── Drift Detector ───────────────────────────────────────────────

export class DriftDetector {
    /**
     * Compare two posture snapshots and return all detected drifts.
     */
    detect(previous: PostureSnapshot, current: PostureSnapshot): DriftEvent[] {
        const events: DriftEvent[] = []
        const ts = current.timestamp

        // 1. Security header drift
        events.push(...this.detectHeaderDrift(previous, current, ts))

        // 2. Auth degradation
        events.push(...this.detectAuthDrift(previous, current, ts))

        // 3. Surface changes (endpoints)
        events.push(...this.detectSurfaceDrift(previous, current, ts))
        events.push(...this.detectMethodDrift(previous, current, ts))
        events.push(...this.detectParameterDrift(previous, current, ts))

        // 4. Tech stack changes
        events.push(...this.detectTechDrift(previous, current, ts))

        return events
    }

    // ── Header Drift ─────────────────────────────────────────────

    private detectHeaderDrift(
        prev: PostureSnapshot,
        curr: PostureSnapshot,
        ts: string,
    ): DriftEvent[] {
        const events: DriftEvent[] = []
        const criticalHeaders = [
            'strict-transport-security',
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options',
            'referrer-policy',
            'permissions-policy',
        ]

        for (const header of criticalHeaders) {
            const prevVal = prev.securityHeaders[header]
            const currVal = curr.securityHeaders[header]

            // Header was present, now removed
            if (prevVal && !currVal) {
                events.push({
                    type: 'header_regression',
                    severity: header === 'strict-transport-security' ? 'critical'
                        : header === 'content-security-policy' ? 'high'
                            : 'medium',
                    path: '/',
                    description: `Security header ${header} was present but is now missing`,
                    previousValue: prevVal,
                    currentValue: null,
                    riskDelta: header === 'strict-transport-security' ? 30
                        : header === 'content-security-policy' ? 25 : 10,
                    detectedAt: ts,
                })
            }

            // Header value weakened (e.g., CSP became more permissive)
            if (prevVal && currVal && prevVal !== currVal) {
                const weakened = this.isHeaderWeakened(header, prevVal, currVal)
                if (weakened) {
                    events.push({
                        type: 'header_weakened',
                        severity: 'medium',
                        path: '/',
                        description: `Security header ${header} value was weakened`,
                        previousValue: prevVal,
                        currentValue: currVal,
                        riskDelta: 10,
                        detectedAt: ts,
                    })
                }
            }
        }

        return events
    }

    private isHeaderWeakened(header: string, prev: string, curr: string): boolean {
        if (header === 'content-security-policy') {
            // CSP weakened if it gains 'unsafe-inline' or 'unsafe-eval' or wildcard
            const prevHasUnsafe = /unsafe-inline|unsafe-eval|\*/.test(prev)
            const currHasUnsafe = /unsafe-inline|unsafe-eval|\*/.test(curr)
            return !prevHasUnsafe && currHasUnsafe
        }
        if (header === 'strict-transport-security') {
            // HSTS weakened if max-age decreased
            const prevAge = parseInt(prev.match(/max-age=(\d+)/)?.[1] ?? '0')
            const currAge = parseInt(curr.match(/max-age=(\d+)/)?.[1] ?? '0')
            return currAge < prevAge
        }
        if (header === 'x-frame-options') {
            // Weakened if went from DENY to SAMEORIGIN or removed
            return prev.toUpperCase() === 'DENY' && curr.toUpperCase() !== 'DENY'
        }
        return false
    }

    // ── Auth Drift ───────────────────────────────────────────────

    private detectAuthDrift(
        prev: PostureSnapshot,
        curr: PostureSnapshot,
        ts: string,
    ): DriftEvent[] {
        const events: DriftEvent[] = []
        const prevMap = new Map(prev.endpoints.map(e => [e.pattern, e]))

        for (const endpoint of curr.endpoints) {
            const prevEndpoint = prevMap.get(endpoint.pattern)
            if (!prevEndpoint) continue

            // Was authenticated, now anonymous
            const prevAnonymousRatio = (prevEndpoint.authTypes['anonymous'] ?? 0) / Math.max(1, prevEndpoint.requestCount)
            const currAnonymousRatio = (endpoint.authTypes['anonymous'] ?? 0) / Math.max(1, endpoint.requestCount)

            // Threshold: if anonymous access grew from <20% to >80%, auth degraded
            if (prevAnonymousRatio < 0.2 && currAnonymousRatio > 0.8) {
                events.push({
                    type: 'auth_degradation',
                    severity: endpoint.sensitive ? 'critical' : 'high',
                    path: endpoint.pattern,
                    description: `Endpoint ${endpoint.pattern} was primarily authenticated (${(prevAnonymousRatio * 100).toFixed(0)}% anonymous) but is now primarily anonymous (${(currAnonymousRatio * 100).toFixed(0)}% anonymous)`,
                    previousValue: `${(prevAnonymousRatio * 100).toFixed(0)}% anonymous`,
                    currentValue: `${(currAnonymousRatio * 100).toFixed(0)}% anonymous`,
                    riskDelta: endpoint.sensitive ? 40 : 20,
                    detectedAt: ts,
                })
            }

            // Opposite: was anonymous, now authenticated (positive)
            if (prevAnonymousRatio > 0.8 && currAnonymousRatio < 0.2) {
                events.push({
                    type: 'auth_escalation',
                    severity: 'info',
                    path: endpoint.pattern,
                    description: `Endpoint ${endpoint.pattern} gained authentication requirement`,
                    previousValue: `${(prevAnonymousRatio * 100).toFixed(0)}% anonymous`,
                    currentValue: `${(currAnonymousRatio * 100).toFixed(0)}% anonymous`,
                    riskDelta: -15,
                    detectedAt: ts,
                })
            }
        }

        return events
    }

    // ── Surface Drift ────────────────────────────────────────────

    private detectSurfaceDrift(
        prev: PostureSnapshot,
        curr: PostureSnapshot,
        ts: string,
    ): DriftEvent[] {
        const events: DriftEvent[] = []
        const prevPatterns = new Set(prev.endpoints.map(e => e.pattern))
        const currPatterns = new Set(curr.endpoints.map(e => e.pattern))

        // New endpoints
        for (const pattern of currPatterns) {
            if (!prevPatterns.has(pattern)) {
                const endpoint = curr.endpoints.find(e => e.pattern === pattern)!
                events.push({
                    type: 'endpoint_added',
                    severity: endpoint.sensitive ? 'high' : 'medium',
                    path: pattern,
                    description: `New endpoint discovered: ${pattern} (${endpoint.methods.join(', ')})`,
                    previousValue: null,
                    currentValue: pattern,
                    riskDelta: endpoint.sensitive ? 15 : 5,
                    detectedAt: ts,
                })
            }
        }

        // Removed endpoints (less concerning but notable)
        for (const pattern of prevPatterns) {
            if (!currPatterns.has(pattern)) {
                events.push({
                    type: 'endpoint_removed',
                    severity: 'info',
                    path: pattern,
                    description: `Endpoint no longer observed: ${pattern}`,
                    previousValue: pattern,
                    currentValue: null,
                    riskDelta: -2,
                    detectedAt: ts,
                })
            }
        }

        // Surface expansion metric
        const surfaceGrowth = currPatterns.size - prevPatterns.size
        if (surfaceGrowth > 5) {
            events.push({
                type: 'surface_expansion',
                severity: 'medium',
                path: '/',
                description: `Attack surface grew by ${surfaceGrowth} endpoints (${prevPatterns.size} → ${currPatterns.size})`,
                previousValue: `${prevPatterns.size} endpoints`,
                currentValue: `${currPatterns.size} endpoints`,
                riskDelta: surfaceGrowth * 2,
                detectedAt: ts,
            })
        }

        // Sudden endpoint burst can indicate path enumeration/scanning
        const growthRatio = prevPatterns.size > 0 ? surfaceGrowth / prevPatterns.size : 0
        if (surfaceGrowth >= 10 || (surfaceGrowth >= 5 && growthRatio >= 0.5)) {
            events.push({
                type: 'endpoint_enumeration_suspected',
                severity: 'high',
                path: '/',
                description: `Sudden endpoint growth suggests path enumeration (${prevPatterns.size} → ${currPatterns.size})`,
                previousValue: `${prevPatterns.size} endpoints`,
                currentValue: `${currPatterns.size} endpoints`,
                riskDelta: Math.max(15, surfaceGrowth * 2),
                detectedAt: ts,
            })
        }

        return events
    }

    // ── Tech Drift ───────────────────────────────────────────────

    private detectMethodDrift(
        prev: PostureSnapshot,
        curr: PostureSnapshot,
        ts: string,
    ): DriftEvent[] {
        const events: DriftEvent[] = []
        const prevMap = new Map(prev.endpoints.map(e => [e.pattern, e]))

        for (const endpoint of curr.endpoints) {
            const prevEndpoint = prevMap.get(endpoint.pattern)
            if (!prevEndpoint) continue

            const prevMethods = new Set(prevEndpoint.methods.map(m => m.toUpperCase()))
            for (const method of endpoint.methods) {
                const normalized = method.toUpperCase()
                if (prevMethods.has(normalized)) continue

                events.push({
                    type: 'unusual_method_detected',
                    severity: endpoint.sensitive ? 'high' : 'medium',
                    path: endpoint.pattern,
                    description: `Known endpoint ${endpoint.pattern} now serves unusual method ${normalized}`,
                    previousValue: [...prevMethods].join(', ') || null,
                    currentValue: normalized,
                    riskDelta: endpoint.sensitive ? 18 : 10,
                    detectedAt: ts,
                })
            }
        }

        return events
    }

    private detectParameterDrift(
        prev: PostureSnapshot,
        curr: PostureSnapshot,
        ts: string,
    ): DriftEvent[] {
        const events: DriftEvent[] = []
        const prevMap = new Map(prev.endpoints.map(e => [e.pattern, e]))

        for (const endpoint of curr.endpoints) {
            const prevEndpoint = prevMap.get(endpoint.pattern)
            if (!prevEndpoint) continue

            const prevParams = new Set((prevEndpoint.parameterNames ?? []).map(p => p.toLowerCase()))
            const currParams = endpoint.parameterNames ?? []
            for (const name of currParams) {
                const normalized = name.toLowerCase()
                if (prevParams.has(normalized)) continue

                events.push({
                    type: 'new_parameter_detected',
                    severity: endpoint.sensitive ? 'high' : 'medium',
                    path: endpoint.pattern,
                    description: `Endpoint ${endpoint.pattern} has new parameter name "${name}" not seen in training window`,
                    previousValue: [...prevParams].join(', ') || null,
                    currentValue: name,
                    riskDelta: endpoint.sensitive ? 14 : 8,
                    detectedAt: ts,
                })
            }
        }

        return events
    }

    private detectTechDrift(
        prev: PostureSnapshot,
        curr: PostureSnapshot,
        ts: string,
    ): DriftEvent[] {
        const events: DriftEvent[] = []
        const prevTech = new Set(prev.techStack)
        const currTech = new Set(curr.techStack)

        for (const tech of currTech) {
            if (!prevTech.has(tech)) {
                events.push({
                    type: 'tech_added',
                    severity: 'medium',
                    path: '/',
                    description: `New technology detected: ${tech}`,
                    previousValue: null,
                    currentValue: tech,
                    riskDelta: 10,
                    detectedAt: ts,
                })
            }
        }

        for (const tech of prevTech) {
            if (!currTech.has(tech)) {
                events.push({
                    type: 'tech_removed',
                    severity: 'low',
                    path: '/',
                    description: `Technology no longer observed: ${tech}`,
                    previousValue: tech,
                    currentValue: null,
                    riskDelta: -3,
                    detectedAt: ts,
                })
            }
        }

        return events
    }
}
