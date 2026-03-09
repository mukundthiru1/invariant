/**
 * INVARIANT v4 — Application Model (Phase 1)
 *
 * Passively learns the application's structure from observed traffic.
 * Runs on every request with minimal overhead — counter increments
 * and map lookups only. No allocations in the hot path beyond
 * the initial endpoint registration.
 *
 * What it learns:
 *   - Endpoint inventory (paths, methods)
 *   - Authentication patterns per endpoint
 *   - Response characteristics (status codes, content types)
 *   - Data sensitivity indicators
 *   - Traffic volume distribution
 *
 * This is the foundation for:
 *   - Phase 2: Privilege Graph (which endpoints require auth?)
 *   - Phase 3: CVE-Stack Correlation (which tech serves which endpoints?)
 *   - Phase 4: Path Enumeration (alternative routes to same data)
 *
 * Design constraints:
 *   - Memory bounded: MAX_ENDPOINTS cap prevents unbounded growth
 *   - No body inspection: only headers and metadata
 *   - Deterministic path normalization: collapses dynamic segments
 *   - Privacy-preserving: no actual values stored, only patterns
 */


// ═══════════════════════════════════════════════════════════════════
// PATH NORMALIZATION
//
// Collapses dynamic path segments into typed placeholders.
// /api/users/123/profile  →  /api/users/{id}/profile
// /orders/a1b2c3d4-e5f6   →  /orders/{uuid}
// /files/report.pdf       →  /files/{file}
//
// This is critical for grouping requests to the same logical
// endpoint regardless of parameter values.
// ═══════════════════════════════════════════════════════════════════

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NUMERIC_ID_PATTERN = /^\d+$/
const HEX_ID_PATTERN = /^[0-9a-f]{16,}$/i
const HASH_PATTERN = /^[0-9a-f]{32,128}$/i
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/
const FILE_PATTERN = /^.+\.[a-z0-9]{1,10}$/i
const BASE64_SLUG_PATTERN = /^[A-Za-z0-9_-]{20,}$/
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const BOOLEAN_PATTERN = /^(true|false|0|1)$/i
const SQL_KEYWORD_PATTERN = /\b(select|union|insert|update|delete|drop|alter|create|truncate|where|or|and)\b|--|\/\*|\*\/|;/i

/**
 * Normalize a URL path into a canonical pattern.
 *
 * Examples:
 *   /api/users/42/posts     → /api/users/{id}/posts
 *   /api/v2/orders/abc-def  → /api/v2/orders/{uuid}
 *   /blog/2024-01-15/hello  → /blog/{date}/hello
 *   /files/report.pdf       → /files/{file}
 *   /api/tokens/a1b2c3...   → /api/tokens/{hash}
 */
export function normalizePathPattern(path: string): string {
    const segments = path.split('/')

    const normalized = segments.map((segment, index) => {
        if (segment === '') return segment

        // Preserve well-known path prefixes
        if (index === 1 && ['api', 'v1', 'v2', 'v3', 'admin', 'auth', 'public', 'static', 'assets'].includes(segment.toLowerCase())) {
            return segment
        }

        // UUID
        if (UUID_PATTERN.test(segment)) return '{uuid}'

        // Pure numeric ID
        if (NUMERIC_ID_PATTERN.test(segment)) return '{id}'

        // Long hex string (hash, token)
        if (HASH_PATTERN.test(segment)) return '{hash}'

        // Hex ID (shorter hex strings)
        if (HEX_ID_PATTERN.test(segment)) return '{hex}'

        // Date
        if (DATE_PATTERN.test(segment)) return '{date}'

        // File with extension
        if (FILE_PATTERN.test(segment) && segment.includes('.')) return '{file}'

        // Base64-encoded or long random slugs
        if (BASE64_SLUG_PATTERN.test(segment) && segment.length > 24) return '{token}'

        return segment
    })

    return normalized.join('/')
}


// ═══════════════════════════════════════════════════════════════════
// AUTH PATTERN DETECTION
//
// Classifies the authentication mechanism used in a request
// from header inspection only. No token validation.
// ═══════════════════════════════════════════════════════════════════

export type AuthType = 'anonymous' | 'bearer' | 'cookie' | 'api_key' | 'basic'

/**
 * Detect authentication type from request headers.
 * Returns the most specific auth type found.
 */
export function detectAuthType(headers: Headers): AuthType {
    const authHeader = headers.get('authorization')

    if (authHeader) {
        const lower = authHeader.toLowerCase()
        if (lower.startsWith('bearer ')) return 'bearer'
        if (lower.startsWith('basic ')) return 'basic'
        // Non-standard auth header — treat as API key
        return 'api_key'
    }

    // Check for API key headers (common patterns)
    if (
        headers.has('x-api-key') ||
        headers.has('api-key') ||
        headers.has('x-auth-token') ||
        headers.has('x-access-token')
    ) {
        return 'api_key'
    }

    // PRIVACY (SAA-072): Cookie header is inspected for auth type CLASSIFICATION only.
    // Only cookie NAMES are regex-tested — no values are extracted, stored, or transmitted.
    // This backs the Principles page claim: "cookie names and flags inspected [...] 
    // cookie values never read, stored, or transmitted."
    const cookie = headers.get('cookie')
    if (cookie) {
        // Look for common session cookie names (name pattern only, values ignored)
        if (/(?:^|;\s*)(sess|session|sid|token|auth|jwt|connect\.sid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId)/i.test(cookie)) {
            return 'cookie'
        }
    }

    return 'anonymous'
}


// ═══════════════════════════════════════════════════════════════════
// SENSITIVE RESPONSE DETECTION
//
// Quick heuristic check on response headers to detect endpoints
// that likely return sensitive data. No body inspection.
// ═══════════════════════════════════════════════════════════════════

/**
 * Check response headers for indicators of sensitive data.
 * This is a heuristic — not definitive, but useful for
 * privilege graph construction.
 */
export function detectSensitiveResponse(path: string, responseHeaders: Headers, statusCode: number): boolean {
    // Endpoints that typically return user-specific data
    const sensitivePaths = /\/(user|profile|account|settings|me|admin|billing|payment|token|secret|credential|password|key)/i

    if (sensitivePaths.test(path)) return true

    // Responses with auth-related headers
    if (responseHeaders.has('set-cookie')) return true

    // JSON responses from API endpoints with non-public cache
    const cacheControl = responseHeaders.get('cache-control') ?? ''
    const isPrivate = cacheControl.includes('private') || cacheControl.includes('no-store')
    const isApi = (responseHeaders.get('content-type') ?? '').includes('application/json')
    if (isApi && isPrivate) return true

    // 401/403 responses indicate auth-protected endpoints
    if (statusCode === 401 || statusCode === 403) return true

    return false
}


// ═══════════════════════════════════════════════════════════════════
// ENDPOINT MODEL
// ═══════════════════════════════════════════════════════════════════

export interface EndpointSnapshot {
    /** Normalized path pattern */
    pattern: string
    /** HTTP methods observed → request count */
    methods: Record<string, number>
    /** Auth type distribution */
    auth: Record<AuthType, number>
    /** Response status code distribution (top 5) */
    responseCodes: Record<number, number>
    /** Content types observed */
    responseTypes: string[]
    /** Average response size in bytes */
    avgResponseSize: number
    /** Whether this endpoint likely returns sensitive data */
    sensitive: boolean
    /** First seen timestamp (epoch ms) */
    firstSeen: number
    /** Last seen timestamp (epoch ms) */
    lastSeen: number
    /** Total requests observed */
    requestCount: number
    /** Learned parameter value distribution for this endpoint */
    parameterDistribution: Record<string, ParameterStats>
}

export interface ParameterStats {
    type: 'numeric' | 'string' | 'email' | 'uuid' | 'boolean'
    minLength: number
    maxLength: number
    pattern?: string
    entropy: number
}

export interface EndpointProfile {
    pattern: string
    parameterDistribution: Map<string, ParameterStats>
}

interface ParameterState {
    stats: ParameterStats
    observations: number
    typeCounts: Map<ParameterStats['type'], number>
}

interface EndpointState {
    pattern: string
    methods: Map<string, number>
    auth: Map<AuthType, number>
    responseCodes: Map<number, number>
    responseTypes: Set<string>
    totalResponseSize: number
    responseCount: number      // responses measured (may differ from requestCount if some blocked)
    sensitive: boolean
    firstSeen: number
    lastSeen: number
    requestCount: number
    parameterDistribution: Map<string, ParameterState>
}


// ═══════════════════════════════════════════════════════════════════
// APPLICATION MODEL SNAPSHOT
// ═══════════════════════════════════════════════════════════════════

export interface ApplicationModelSnapshot {
    /** Unique identifier for this sensor */
    sensorId: string
    /** Model schema version */
    modelVersion: number
    /** Technology stack detected (from L4) */
    techStack: string[]
    /** Authentication mechanisms observed */
    authMechanisms: AuthType[]
    /** Primary session mechanism */
    sessionType: 'cookie' | 'bearer' | 'api_key' | 'none'
    /** Estimated number of distinct privilege levels */
    estimatedPrivilegeLevels: number
    /** Total unique endpoint patterns */
    totalEndpoints: number
    /** Total requests observed */
    totalRequests: number
    /** Endpoint inventory */
    endpoints: EndpointSnapshot[]
    /** Snapshot timestamp */
    timestamp: string
}


// ═══════════════════════════════════════════════════════════════════
// APPLICATION MODEL
// ═══════════════════════════════════════════════════════════════════

export class ApplicationModel {
    /**
     * Maximum endpoints to track. Prevents unbounded memory growth.
     * Most web applications have 50-200 unique endpoint patterns.
     * 500 gives generous headroom for complex applications.
     */
    private static readonly MAX_ENDPOINTS = 500

    /**
     * Maximum response codes to track per endpoint.
     * Prevents memory bloat from random status codes.
     */
    private static readonly MAX_RESPONSE_CODES = 10

    /**
     * Maximum response types to track per endpoint.
     */
    private static readonly MAX_RESPONSE_TYPES = 10

    /**
     * Endpoint stale threshold (7 days in ms).
     * Endpoints not seen in 7 days are pruned on snapshot.
     */
    private static readonly STALE_THRESHOLD_MS = 7 * 24 * 60 * 60 * 1000

    private endpoints = new Map<string, EndpointState>()
    private totalRequests = 0
    private lastAnomalyEvidence: string[] = []

    /**
     * Record a request observation.
     * Called on every request in the main pipeline — must be fast.
     *
     * @param path - Raw request path (will be normalized)
     * @param method - HTTP method
     * @param authType - Detected auth type
     */
    recordRequest(path: string, method: string, authType: AuthType, request?: Request): void {
        this.totalRequests++
        const pattern = normalizePathPattern(path)
        const now = Date.now()

        let endpoint = this.endpoints.get(pattern)
        if (!endpoint) {
            // Check capacity
            if (this.endpoints.size >= ApplicationModel.MAX_ENDPOINTS) {
                // Evict least recently seen endpoint
                this.evictLeastRecent()
            }

            endpoint = {
                pattern,
                methods: new Map(),
                auth: new Map(),
                responseCodes: new Map(),
                responseTypes: new Set(),
                totalResponseSize: 0,
                responseCount: 0,
                sensitive: false,
                firstSeen: now,
                lastSeen: now,
                requestCount: 0,
                parameterDistribution: new Map(),
            }
            this.endpoints.set(pattern, endpoint)
        }

        endpoint.lastSeen = now
        endpoint.requestCount++
        endpoint.methods.set(method, (endpoint.methods.get(method) ?? 0) + 1)
        endpoint.auth.set(authType, (endpoint.auth.get(authType) ?? 0) + 1)
        if (request) {
            this.updateParameterDistribution(endpoint, request)
        }
    }

    /**
     * Record response characteristics for an endpoint.
     * Called after origin fetch — separate from recordRequest
     * because blocked requests never reach origin.
     *
     * @param path - Raw request path (will be normalized)
     * @param statusCode - Response HTTP status code
     * @param contentType - Response content type
     * @param contentLength - Response content length (from header, may be null)
     * @param sensitive - Whether response indicates sensitive data
     */
    recordResponse(
        path: string,
        statusCode: number,
        contentType: string | null,
        contentLength: number | null,
        sensitive: boolean,
    ): void {
        const pattern = normalizePathPattern(path)
        const endpoint = this.endpoints.get(pattern)
        if (!endpoint) return // Endpoint not tracked (shouldn't happen)

        // Response codes
        if (endpoint.responseCodes.size < ApplicationModel.MAX_RESPONSE_CODES) {
            endpoint.responseCodes.set(statusCode, (endpoint.responseCodes.get(statusCode) ?? 0) + 1)
        } else if (endpoint.responseCodes.has(statusCode)) {
            endpoint.responseCodes.set(statusCode, endpoint.responseCodes.get(statusCode)! + 1)
        }

        // Content type
        if (contentType && endpoint.responseTypes.size < ApplicationModel.MAX_RESPONSE_TYPES) {
            // Normalize content type (strip charset etc.)
            const normalized = contentType.split(';')[0].trim().toLowerCase()
            endpoint.responseTypes.add(normalized)
        }

        // Response size tracking
        if (contentLength !== null && contentLength > 0) {
            endpoint.totalResponseSize += contentLength
            endpoint.responseCount++
        }

        // Sensitive flag is sticky — once detected, stays true
        if (sensitive) {
            endpoint.sensitive = true
        }
    }

    /**
     * Generate a compact snapshot of the application model.
     * Called on cron tick for upstream reporting.
     *
     * @param sensorId - Unique sensor identifier
     * @param techStack - Technology stack from L4
     * @returns Compact model snapshot (~2-5KB typical)
     */
    snapshot(sensorId: string, techStack: string[] = []): ApplicationModelSnapshot {
        const now = Date.now()

        // Prune stale endpoints
        for (const [pattern, endpoint] of this.endpoints) {
            if (now - endpoint.lastSeen > ApplicationModel.STALE_THRESHOLD_MS) {
                this.endpoints.delete(pattern)
            }
        }

        // Build endpoint snapshots
        const endpointSnapshots: EndpointSnapshot[] = []
        for (const endpoint of this.endpoints.values()) {
            endpointSnapshots.push(this.snapshotEndpoint(endpoint))
        }

        // Sort by request count (most trafficked first)
        endpointSnapshots.sort((a, b) => b.requestCount - a.requestCount)

        // Determine auth mechanisms
        const authMechanisms = this.detectAuthMechanisms()
        const sessionType = this.detectSessionType(authMechanisms)
        const privilegeLevels = this.estimatePrivilegeLevels()

        return {
            sensorId,
            modelVersion: 1,
            techStack,
            authMechanisms,
            sessionType,
            estimatedPrivilegeLevels: privilegeLevels,
            totalEndpoints: endpointSnapshots.length,
            totalRequests: this.totalRequests,
            endpoints: endpointSnapshots,
            timestamp: new Date().toISOString(),
        }
    }

    private snapshotEndpoint(endpoint: EndpointState): EndpointSnapshot {
        const avgResponseSize = endpoint.responseCount > 0
            ? Math.round(endpoint.totalResponseSize / endpoint.responseCount)
            : 0

        return {
            pattern: endpoint.pattern,
            methods: Object.fromEntries(endpoint.methods),
            auth: Object.fromEntries(endpoint.auth) as Record<AuthType, number>,
            responseCodes: Object.fromEntries(endpoint.responseCodes),
            responseTypes: [...endpoint.responseTypes],
            avgResponseSize,
            sensitive: endpoint.sensitive,
            firstSeen: endpoint.firstSeen,
            lastSeen: endpoint.lastSeen,
            requestCount: endpoint.requestCount,
            parameterDistribution: Object.fromEntries(
                [...endpoint.parameterDistribution.entries()].map(([name, value]) => [name, value.stats]),
            ),
        }
    }

    /**
     * Detect which auth mechanisms are in use across the application.
     */
    private detectAuthMechanisms(): AuthType[] {
        const mechanisms = new Set<AuthType>()
        for (const endpoint of this.endpoints.values()) {
            for (const [authType, count] of endpoint.auth) {
                // Only count auth types seen in >5% of requests for this endpoint
                if (count / endpoint.requestCount > 0.05) {
                    mechanisms.add(authType)
                }
            }
        }
        return [...mechanisms].sort()
    }

    /**
     * Determine the primary session mechanism.
     * Used for Phase 2 privilege graph construction.
     */
    private detectSessionType(mechanisms: AuthType[]): ApplicationModelSnapshot['sessionType'] {
        // Priority: cookie > bearer > api_key > none
        if (mechanisms.includes('cookie')) return 'cookie'
        if (mechanisms.includes('bearer')) return 'bearer'
        if (mechanisms.includes('api_key')) return 'api_key'
        return 'none'
    }

    /**
     * Estimate the number of distinct privilege levels.
     *
     * Heuristic: count distinct auth requirement patterns across endpoints.
     * - All anonymous → 1 level
     * - Mixed anonymous + authenticated → 2 levels
     * - Has admin-path endpoints with different auth → 3 levels
     * - Has internal/system endpoints → 4 levels
     */
    private estimatePrivilegeLevels(): number {
        let hasAnonymous = false
        let hasAuthenticated = false
        let hasAdmin = false

        for (const endpoint of this.endpoints.values()) {
            const anonCount = endpoint.auth.get('anonymous') ?? 0
            const totalAuth = endpoint.requestCount - anonCount
            const anonRatio = anonCount / (endpoint.requestCount || 1)

            if (anonRatio > 0.8) {
                hasAnonymous = true
            }
            if (totalAuth > 0 && anonRatio < 0.5) {
                hasAuthenticated = true
            }
            if (/\/(admin|manage|dashboard|internal|system)/i.test(endpoint.pattern)) {
                if (totalAuth > 0) {
                    hasAdmin = true
                }
            }
        }

        let levels = 0
        if (hasAnonymous) levels++
        if (hasAuthenticated) levels++
        if (hasAdmin) levels++
        return Math.max(1, levels)
    }

    /**
     * Compute anomaly score for request parameters against learned endpoint baseline.
     * Score range: 0 (normal) to 1 (highly anomalous).
     */
    computeAnomalyScore(endpoint: string, request: Request): number {
        this.lastAnomalyEvidence = []

        const pattern = normalizePathPattern(endpoint)
        const endpointState = this.endpoints.get(pattern)
        if (!endpointState || endpointState.parameterDistribution.size === 0) {
            return 0
        }

        const paramValues = this.extractParameters(request)
        if (paramValues.size === 0) return 0

        let aggregate = 0
        let compared = 0

        for (const [name, value] of paramValues) {
            const learned = endpointState.parameterDistribution.get(name)
            if (!learned) {
                continue
            }

            compared++
            const score = this.computeParameterAnomaly(name, value, learned.stats)
            aggregate += score
        }

        if (compared === 0) return 0
        return Math.max(0, Math.min(1, aggregate / compared))
    }

    /**
     * Retrieve anomaly evidence emitted by the most recent anomaly scoring call.
     */
    getLastAnomalyEvidence(): string[] {
        return [...this.lastAnomalyEvidence]
    }

    private computeParameterAnomaly(name: string, value: string, stats: ParameterStats): number {
        const valueType = classifyParameterType(value)
        const valueLength = value.length
        let score = 0

        if (valueLength > 0 && stats.maxLength > 0 && valueLength > stats.maxLength * 3) {
            score = Math.max(score, 0.95)
            this.lastAnomalyEvidence.push(
                `Parameter "${name}" length ${valueLength} exceeds learned max ${stats.maxLength} by >3x`,
            )
        }

        if (stats.type === 'numeric' && SQL_KEYWORD_PATTERN.test(value)) {
            score = Math.max(score, 1)
            this.lastAnomalyEvidence.push(
                `Parameter "${name}" is learned numeric but contains SQL-like keywords`,
            )
        }

        if (stats.type !== valueType) {
            score = Math.max(score, 0.55)
            this.lastAnomalyEvidence.push(
                `Parameter "${name}" expected ${stats.type} but observed ${valueType}`,
            )
        }

        if (stats.type === 'uuid' && !UUID_PATTERN.test(value)) {
            score = Math.max(score, 0.7)
            this.lastAnomalyEvidence.push(`Parameter "${name}" violates learned UUID format`)
        }

        if (stats.type === 'email' && !EMAIL_PATTERN.test(value)) {
            score = Math.max(score, 0.7)
            this.lastAnomalyEvidence.push(`Parameter "${name}" violates learned email format`)
        }

        if (stats.type === 'boolean' && !BOOLEAN_PATTERN.test(value)) {
            score = Math.max(score, 0.7)
            this.lastAnomalyEvidence.push(`Parameter "${name}" violates learned boolean format`)
        }

        const currentEntropy = computeEntropy(value)
        if (stats.entropy > 0.3 && currentEntropy > stats.entropy * 1.8 && valueLength >= 8) {
            score = Math.max(score, 0.45)
            this.lastAnomalyEvidence.push(
                `Parameter "${name}" entropy ${currentEntropy.toFixed(2)} deviates from baseline ${stats.entropy.toFixed(2)}`,
            )
        }

        return Math.min(1, score)
    }

    private updateParameterDistribution(endpoint: EndpointState, request: Request): void {
        const values = this.extractParameters(request)
        for (const [name, value] of values) {
            const type = classifyParameterType(value)
            const length = value.length
            const entropy = computeEntropy(value)

            let state = endpoint.parameterDistribution.get(name)
            if (!state) {
                state = {
                    stats: {
                        type,
                        minLength: length,
                        maxLength: length,
                        pattern: inferPattern(value, type),
                        entropy,
                    },
                    observations: 0,
                    typeCounts: new Map(),
                }
                endpoint.parameterDistribution.set(name, state)
            }

            state.observations++
            state.typeCounts.set(type, (state.typeCounts.get(type) ?? 0) + 1)
            state.stats.type = dominantParameterType(state.typeCounts)
            state.stats.minLength = Math.min(state.stats.minLength, length)
            state.stats.maxLength = Math.max(state.stats.maxLength, length)
            state.stats.pattern = mergePattern(state.stats.pattern, inferPattern(value, type))
            // Exponential moving average keeps the signal stable.
            state.stats.entropy = state.observations === 1
                ? entropy
                : state.stats.entropy * 0.9 + entropy * 0.1
        }
    }

    private extractParameters(request: Request): Map<string, string> {
        const params = new Map<string, string>()
        let parsed: URL

        try {
            parsed = new URL(request.url)
        } catch {
            return params
        }

        for (const [name, value] of parsed.searchParams.entries()) {
            if (!name) continue
            const existing = params.get(name)
            params.set(name, existing ? `${existing},${value}` : value)
        }

        return params
    }

    /**
     * Evict the least recently seen endpoint when at capacity.
     */
    private evictLeastRecent(): void {
        let oldestPattern: string | null = null
        let oldestTime = Infinity

        for (const [pattern, endpoint] of this.endpoints) {
            if (endpoint.lastSeen < oldestTime) {
                oldestTime = endpoint.lastSeen
                oldestPattern = pattern
            }
        }

        if (oldestPattern) {
            this.endpoints.delete(oldestPattern)
        }
    }

    /** Number of tracked endpoints */
    get endpointCount(): number {
        return this.endpoints.size
    }

    /** Total requests observed */
    get requestsObserved(): number {
        return this.totalRequests
    }

    /**
     * Get the endpoint model for a specific pattern (for testing/inspection).
     */
    getEndpoint(path: string): EndpointSnapshot | null {
        const pattern = normalizePathPattern(path)
        const endpoint = this.endpoints.get(pattern)
        if (!endpoint) return null
        return this.snapshotEndpoint(endpoint)
    }
}

function classifyParameterType(value: string): ParameterStats['type'] {
    if (NUMERIC_ID_PATTERN.test(value)) return 'numeric'
    if (BOOLEAN_PATTERN.test(value)) return 'boolean'
    if (UUID_PATTERN.test(value)) return 'uuid'
    if (EMAIL_PATTERN.test(value)) return 'email'
    return 'string'
}

function dominantParameterType(
    counts: Map<ParameterStats['type'], number>,
): ParameterStats['type'] {
    let dominant: ParameterStats['type'] = 'string'
    let max = -1
    for (const [type, count] of counts) {
        if (count > max) {
            dominant = type
            max = count
        }
    }
    return dominant
}

function inferPattern(value: string, type: ParameterStats['type']): string | undefined {
    if (type !== 'string') return undefined
    if (SQL_KEYWORD_PATTERN.test(value)) return 'contains_sql_keyword'
    if (/^[a-z]+$/i.test(value)) return 'alpha'
    if (/^[a-z0-9_-]+$/i.test(value)) return 'alnum_symbol'
    if (/^[^a-z0-9]+$/i.test(value)) return 'symbolic'
    return 'mixed'
}

function mergePattern(current: string | undefined, next: string | undefined): string | undefined {
    if (!current) return next
    if (!next) return current
    return current === next ? current : 'mixed'
}

function computeEntropy(value: string): number {
    if (!value) return 0
    const counts = new Map<string, number>()
    for (const ch of value) {
        counts.set(ch, (counts.get(ch) ?? 0) + 1)
    }

    let entropy = 0
    for (const count of counts.values()) {
        const p = count / value.length
        entropy -= p * Math.log2(p)
    }
    return entropy
}
