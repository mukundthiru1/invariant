/**
 * Edge Sensor — Type Definitions
 */

// ── Environment ───────────────────────────────────────────────────

export interface Env {
    SANTH_INGEST_URL: string
    SIGNAL_BATCH_SIZE: string
    DEFENSE_MODE: string           // "monitor" | "enforce" | "off"
    SENSOR_STATE: KVNamespace      // KV binding for persistent state
    SENSOR_ID: string              // Unique sensor identifier
    PROBE_ENABLED: string          // "true" | "false"
    AI?: Ai                        // Optional Workers AI binding
    SENSOR_API_KEY: string         // API key for authenticated signal flush
    INTROSPECTION_KEY?: string     // Key for /__invariant/* endpoint access
    SEAL_SECRET?: string           // Cryptographic key for evidence sealing
}

// ── Signal ────────────────────────────────────────────────────────

export interface Signal {
    type: string
    subtype: string | null
    confidence: number
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
    path: string
    method: string
    sourceHash: string
    country: string | null
    matchedRules: string[]
    invariantClasses: string[]
    isNovelVariant: boolean
    targetTech: string | null
    clientClass: string
    requestSize: number | null
    headerAnomaly: boolean
    defenseAction: 'blocked' | 'monitored' | 'passed'
    threatScore: number
    chainIndicators: string[]
    timestamp: string
    // MITRE ATT&CK enrichment
    mitreTechniques?: string[]
    mitreKillChainPhase?: string
    // Multi-dimensional risk surface
    riskSurface?: {
        security: number
        privacy: number
        compliance: number
        operational: number
        dominantAxis: string
    }
}

// ── Signature Rule ────────────────────────────────────────────────

export interface SignatureRule {
    id: string
    type: string
    subtype: string | null
    severity: Signal['severity']
    confidence: number
    check: (ctx: RequestContext) => boolean
}

// ── Request Context ───────────────────────────────────────────────

export interface RequestContext {
    url: URL
    path: string
    query: string
    decodedPath: string
    decodedQuery: string
    fullDecoded: string
    method: string
    headers: Headers
    ua: string
    contentType: string
    bodyText: string | null
    bodyValues: string[]
}

// ── Client Classification ─────────────────────────────────────────

export type ClientClass =
    | 'browser'
    | 'mobile_browser'
    | 'bot'
    | 'crawler'
    | 'scanner'
    | 'api_client'
    | 'cli_tool'
    | 'empty'
    | 'suspicious'
