/**
 * INVARIANT Crypto — Shared Type Contracts
 *
 * These types define the wire format for all encrypted communication:
 *   - Signal upload:   Worker → Santh Central (encrypted with Santh pubkey)
 *   - Rule dispatch:   Santh Central → Worker KV (encrypted with subscriber pubkey)
 *   - Local storage:   Worker KV + Agent SQLite (encrypted with subscriber storage key)
 *
 * BACKWARDS COMPAT: Every field here is additive-only after v1.0.0.
 * Central accepts all historical bundle versions simultaneously.
 * Workers accept bundles from newer central versions (ignore unknown fields).
 *
 * Requires: Web Crypto API (globalThis.crypto.subtle)
 * Supported runtimes: Cloudflare Workers, Node.js ≥ 20, modern browsers.
 */


// ── Signal Bundle (Worker → Central) ─────────────────────────────
//
// What the worker collects from a novel detection and encrypts before upload.
// Central decrypts this to extract attack pattern intelligence.
//
// Privacy guarantee: no raw request content, no PII, no IP addresses.
// The IP is hashed separately with a daily-rotating salt before this bundle
// is assembled. Central only learns the statistical pattern, not the actor.

export interface SignalBundle {
    /** Which invariant class fired */
    invariantClass: string

    /** Detection level: L1 regex, L2 structural evaluator, L3 decomposer */
    detectionLevel: 'l1' | 'l2' | 'l3'

    /** Detection confidence (0–1) */
    confidence: number

    /** How many encoding layers were peeled (0 = plain, 3+ = deeply obfuscated) */
    encodingDepth: number

    /** HTTP method */
    method: string

    /**
     * Injection surface — WHERE in the request the payload was found.
     * Reveals attack technique placement without leaking endpoint structure.
     */
    surface: 'query_param' | 'body_param' | 'header' | 'cookie' | 'path' | 'fragment' | 'unknown'

    /**
     * Raw sanitized payload — the actual attack technique.
     * sanitizePayload() strips: internal hostnames, email addresses, API keys,
     * domain names, app-specific paths. Keeps: SQL syntax, XSS vectors, shell
     * operators, encoding layers, traversal sequences — pure technique.
     */
    payload?: string

    /**
     * Product category selected at `invariant init`.
     * Used for industry-level threat distribution analysis.
     * No identifying information — just a vertical label.
     */
    category?: SignalProductCategory

    /** Auto-detected framework (express, next, django, etc.) */
    framework?: string

    /** Unix timestamp ms — rounded to nearest hour for anonymity */
    timestamp: number

    /** Evidence string from L2/L3 evaluator (no raw values — pattern description only) */
    evidence?: string

    /** Schema version for forwards compat */
    v: 1 | 2
}

/** Product category — one question at `invariant init` */
export type SignalProductCategory =
    | 'saas'
    | 'api'
    | 'ecommerce'
    | 'fintech'
    | 'healthcare'
    | 'content'
    | 'devtools'
    | 'gaming'
    | 'education'
    | 'government'
    | 'other'

/** Encrypted signal bundle as sent over the wire */
export interface EncryptedSignalBundle {
    /** Worker's ephemeral X25519 public key (32 bytes, base64url) */
    ephemeralPublicKey: string

    /** AES-256-GCM ciphertext (base64url) */
    ciphertext: string

    /** AES-256-GCM nonce / IV (12 bytes, base64url) */
    iv: string

    /**
     * Anonymous sensor token — rotates daily, not linkable across days.
     * hash(sensorId + daily_salt). Used as AAD for encryption binding
     * and same-day deduplication. Central cannot build a profile over time.
     */
    anonToken: string

    /** Bundle schema version */
    v: 1 | 2
}

/** Batch of encrypted signals sent to central ingest endpoint */
export interface SignalUploadBatch {
    signals: EncryptedSignalBundle[]
    batchId: string      // random UUID, for dedup
    sentAt: number       // unix timestamp ms
    campaignFingerprint: string // deterministic campaign correlation key
    /** Anonymous daily token for batch-level routing (not a subscriber ID) */
    anonToken: string
    v: 1 | 2
}


// ── Rule Bundle (Central → Worker KV) ────────────────────────────
//
// What Santh central generates and dispatches per subscriber per cycle.
// Contains: new L1 rules (from collective intelligence), threshold overrides
// (EPSS-weighted), class priorities (tech-stack-aware), blocklist deltas.
//
// Encrypted with subscriber's X25519 public key + signed with Santh's Ed25519 key.
// Worker decrypts in-memory only — plaintext NEVER written to KV.

export interface PatternRule {
    /** Stable unique ID — never reused even after rule retirement */
    id: string

    /** Which invariant class this pattern augments */
    invariantClass: string

    /** Regex source string */
    pattern: string

    /** Regex flags ('i', 'gi', or '') */
    flags: string

    /** Minimum input confidence required to fire this rule */
    minConfidence: number

    /** Who generated this rule */
    source: 'central_analyst' | 'sensor_collective' | 'research_pipeline'

    /** When this rule was synthesized (unix timestamp ms) */
    addedAt: number

    /** When this rule expires — undefined means permanent */
    expiresAt?: number
}

export interface ThresholdOverride {
    /** The invariant class whose block threshold is being adjusted */
    invariantClass: string

    /** EPSS score of the linked CVE (0–1) */
    epss: number

    /** Adjusted threshold: base_threshold × (1 − epss × 0.30) */
    adjustedThreshold: number

    /** The CVE driving this adjustment */
    linkedCve: string

    /** When this override expires (unix timestamp ms) */
    validUntil: number
}

export interface ClassPriority {
    /** The invariant class being reprioritized */
    invariantClass: string

    /**
     * Priority multiplier applied to this class's confidence scores.
     * 0.0 = skip entirely (stack doesn't support this attack surface)
     * 1.0 = unchanged (default)
     * 2.0 = high priority (stack is highly susceptible)
     */
    priorityMultiplier: number

    /** Human-readable reason (e.g., 'tech_stack:wordpress') */
    reason: string
}

export interface RuleBundle {
    /** Monotonically increasing version number — worker rejects if ≤ current version */
    version: number

    /** When this bundle expires and must be replaced (unix timestamp ms) */
    expiresAt: number

    /** New L1 patterns to add (from collective intelligence, analyst, or research) */
    l1Additions: PatternRule[]

    /** Rule IDs to retire (pattern no longer needed) */
    l1Removals: string[]

    /** EPSS-weighted threshold adjustments */
    thresholdOverrides: ThresholdOverride[]

    /** Tech-stack-aware class prioritization */
    classPriorities: ClassPriority[]

    /** Hashed IP addresses to add to the blocklist */
    blocklistAdditions: string[]

    /** Hashed IP addresses to remove from the blocklist */
    blocklistRemovals: string[]

    /** Schema version */
    v: 1
}

/** Encrypted rule bundle as written to subscriber's Workers KV */
export interface EncryptedRuleBundle {
    /**
     * The bundle_key encrypted to the subscriber's X25519 public key.
     * Format: X25519 ephemeral pubkey (32 bytes) || AES-256-GCM ciphertext of bundle_key.
     * Subscriber decrypts with their private key (stored in CF Worker Secrets).
     * (base64url)
     */
    encBundleKey: string

    /**
     * The rule bundle encrypted with bundle_key using AES-256-GCM.
     * AAD: UTF-8(`${subscriberId}:${bundleVersion}`) — colon-separated,
     *      collision-free because subscriberIds are UUIDs (no colons).
     * (base64url: iv[12] || ciphertext)
     */
    encRules: string

    /** Monotonically increasing bundle version */
    bundleVersion: number

    /** Expiry timestamp — worker rejects stale bundles (unix timestamp ms) */
    expiresAt: number

    /**
     * Ed25519 signature over:
     *   encBundleKey_bytes || encRules_bytes || bundleVersion (8-byte BE) || expiresAt (8-byte BE)
     * Signed by Santh's static Ed25519 signing key.
     * Worker verifies with Santh's static verify key (embedded in worker).
     * (base64url)
     */
    signature: string

    /** Schema version */
    v: 1
}


// ── Storage Encryption (Local KV / SQLite) ────────────────────────
//
// All writes to Workers KV and agent SQLite are encrypted before storage.
// Key: INVARIANT_STORAGE_KEY environment variable / CF Worker Secret.
// Format: base64url(iv[12] || ciphertext) — self-contained, no separate IV storage.

export interface StorageEncryptionConfig {
    /** Base64url-encoded 32-byte AES-256-GCM key */
    keyB64: string
}

/** Result of encrypting a storage value */
export interface EncryptedStorageValue {
    /** base64url(iv[12] || ciphertext || ghash[16]) — single opaque blob */
    blob: string
}


// ── Key Material ──────────────────────────────────────────────────

/** Subscriber's X25519 keypair (generated at init, private key in CF Secrets) */
export interface SubscriberKeyPair {
    /** X25519 public key — registered with Santh central (base64url, 32 bytes) */
    publicKey: string
    /** X25519 private key — stored ONLY in CF Worker Secrets, never committed (base64url, 32 bytes) */
    privateKey: string
}

/**
 * Santh's static public keys embedded in the worker.
 * These are rotated via rule bundle dispatch — never hardcoded in perpetuity.
 * The worker trusts bundles signed with the key active at dispatch time.
 */
export interface SanthPublicKeys {
    /** X25519 public key for signal upload encryption (base64url, 32 bytes) */
    signalEncryptionKey: string
    /** Ed25519 public key for rule bundle signature verification (base64url, 32 bytes) */
    ruleVerifyKey: string
    /** Key version — allows Santh to rotate keys without breaking in-flight bundles */
    keyVersion: number
}
