/**
 * Edge Sensor — Type Definitions
 */

// ── Environment ───────────────────────────────────────────────────

export interface Env {
    SANTH_INGEST_URL: string
    SANTH_INTEL_URL?: string
    SIGNAL_BATCH_SIZE: string
    DEFENSE_MODE: string           // "monitor" | "enforce" | "off"
    SENSOR_STATE: KVNamespace      // KV binding for persistent state
    SENSOR_ID: string              // Unique sensor identifier
    PROBE_ENABLED: string          // "true" | "false"
    AI?: Ai                        // Optional Workers AI binding
    SENSOR_API_KEY: string         // API key for authenticated signal flush
    WS_ALLOWED_ORIGINS?: string    // Comma-separated allowed WS Origin values
    INTROSPECTION_KEY?: string     // Key for /__invariant/* endpoint access
    SEAL_SECRET?: string           // Cryptographic key for evidence sealing

    // ── Encrypted Architecture (set via wrangler secret put) ─────
    // These three secrets enable the collective intelligence network.
    // Without them the worker runs in standalone mode — full detection,
    // no encrypted signal upload, no dispatched rule bundles applied.

    /** Subscriber's X25519 private key (32 bytes, base64url). Decrypts
     *  rule bundles dispatched by Santh central. Generate with: npx @santh/invariant init */
    SUBSCRIBER_PRIVATE_KEY?: string

    /** Santh central's Ed25519 verify key (32 bytes, base64url).
     *  Validates rule bundle signatures — prevents rule injection attacks. */
    SANTH_RULE_VERIFY_KEY?: string

    /** Santh central's X25519 public key (32 bytes, base64url).
     *  Encrypts novel-variant signals before upload to central ingest. */
    SANTH_SIGNAL_ENCRYPT_KEY?: string

    /** AES-256-GCM key (32 bytes, base64url) for encrypting local KV state.
     *  At-rest encryption for everything written to SENSOR_STATE KV. */
    INVARIANT_STORAGE_KEY?: string

    /** Product category from `invariant init`. Drives collective intelligence segmentation.
     *  Set automatically by `invariant deploy` from invariant.config.json. */
    INVARIANT_CATEGORY?: string
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
