/**
 * INVARIANT — Sensor State Persistence
 *
 * Solves the fundamental problem: Cloudflare Workers are ephemeral.
 * Every cold start resets all in-memory state. Without persistence,
 * the application model, privilege graph, IP reputation, and detection
 * history evaporate — making the sensor analytically blind.
 *
 * Architecture:
 *   KV Store (Cloudflare Workers KV) provides:
 *     - Sub-millisecond reads (eventually consistent)
 *     - Durable writes with TTL support
 *     - 25MB max value size (more than enough)
 *     - Global edge distribution
 *
 * Storage design:
 *   sensor:{sensorId}:model       → Serialized ApplicationModel endpoints
 *   sensor:{sensorId}:posture     → Last posture findings
 *   sensor:{sensorId}:reputation  → IP reputation table
 *   sensor:{sensorId}:rules       → Dynamic detection rules from intel
 *   sensor:{sensorId}:rules:ver   → Rule version hash
 *   sensor:{sensorId}:stats       → Cumulative statistics
 *   sensor:{sensorId}:heartbeat   → Last heartbeat timestamp
 *
 * Write strategy:
 *   - Writes are batched and deferred to ctx.waitUntil()
 *   - Model state persisted every N requests (configurable)
 *   - Posture findings persisted on every response audit
 *   - Rules persisted on fetch from intel pipeline
 *
 * Read strategy:
 *   - State loaded ONCE on cold start
 *   - Cached in module-level variables for hot path
 *   - No KV reads on the hot path after initialization
 */


// ── KV Key Schema ────────────────────────────────────────────────

const KEY_PREFIX = 'sensor'

function key(sensorId: string, segment: string): string {
    return `${KEY_PREFIX}:${sensorId}:${segment}`
}

export const KV_KEYS = {
    model: (id: string) => key(id, 'model'),
    posture: (id: string) => key(id, 'posture'),
    reputation: (id: string) => key(id, 'reputation'),
    rules: (id: string) => key(id, 'rules'),
    rulesVersion: (id: string) => key(id, 'rules:ver'),
    stats: (id: string) => key(id, 'stats'),
    heartbeat: (id: string) => key(id, 'heartbeat'),
    config: (id: string) => key(id, 'config'),
} as const


// ── Persisted Model State ────────────────────────────────────────

export interface PersistedEndpoint {
    pattern: string
    methods: Record<string, number>
    auth: Record<string, number>
    sensitive: boolean
    requestCount: number
    lastSeen: number
}

export interface PersistedModelState {
    endpoints: PersistedEndpoint[]
    totalRequests: number
    persistedAt: number
    version: number
}


// ── Persisted Posture State ──────────────────────────────────────

export interface PersistedPosture {
    findings: PersistedPostureFinding[]
    reactivationCount: number
    persistedAt: number
}

export interface PersistedPostureFinding {
    invariant: string
    severity: string
    header?: string
    detail: string
    firstSeen: number
    count: number
}


// ── Persisted IP Reputation ──────────────────────────────────────

export interface IPReputationEntry {
    ipHash: string
    signals: number
    lastSeen: number
    categories: string[]
    blocked: boolean
}

export interface PersistedReputation {
    entries: IPReputationEntry[]
    totalAttackers: number
    persistedAt: number
}


// ── Persisted Detection Rules (from Intel) ───────────────────────

export interface DynamicRule {
    ruleId: string
    name: string
    signalType: string
    signalSubtype: string | null
    matchType: 'regex' | 'exact' | 'contains' | 'header' | 'path' | 'combo'
    patterns: DynamicRulePattern[]
    baseConfidence: number
    linkedCves: string[]
    linkedTechniques: string[]
    enabled: boolean
}

export interface DynamicRulePattern {
    field: 'path' | 'query' | 'header' | 'user_agent' | 'method'
    operator: 'regex' | 'exact' | 'contains' | 'starts_with' | 'not_contains'
    value: string
    headerName?: string
}

export interface PersistedRules {
    rules: DynamicRule[]
    version: string
    fetchedAt: number
    source: string
}


// ── Persisted Statistics ─────────────────────────────────────────

export interface PersistedStats {
    totalRequests: number
    totalBlocked: number
    totalSignals: number
    signalsByType: Record<string, number>
    uniqueAttackerIPs: number
    coldStarts: number
    lastColdStart: number
    upSince: number
    persistedAt: number
}


// ── Sensor Configuration (from Intel) ────────────────────────────

export interface SensorConfig {
    defenseMode: 'monitor' | 'enforce' | 'off'
    signalBatchSize: number
    probeEnabled: boolean
    rulesFetchUrl: string
    rulesFetchInterval: number
    modelPersistInterval: number
    reputationTTL: number
    maxTrackedIPs: number
}

const DEFAULT_CONFIG: SensorConfig = {
    defenseMode: 'monitor',
    signalBatchSize: 50,
    probeEnabled: true,
    rulesFetchUrl: 'https://santh-intel.contactmukundthiru.workers.dev/v1/rules/sensor',
    rulesFetchInterval: 300,
    modelPersistInterval: 100,
    reputationTTL: 86400,
    maxTrackedIPs: 10000,
}


// ═══════════════════════════════════════════════════════════════════
// SENSOR STATE MANAGER
//
// The central persistence coordinator.
// Handles all KV reads/writes with batching and error resilience.
// ═══════════════════════════════════════════════════════════════════

export class SensorStateManager {
    private kv: KVNamespace
    private sensorId: string
    private initialized = false
    private dirty = false
    private requestsSinceLastPersist = 0

    // Cached state
    private _model: PersistedModelState | null = null
    private _posture: PersistedPosture | null = null
    private _reputation: PersistedReputation | null = null
    private _rules: PersistedRules | null = null
    private _stats: PersistedStats | null = null
    private _config: SensorConfig = DEFAULT_CONFIG

    constructor(kv: KVNamespace, sensorId: string) {
        this.kv = kv
        this.sensorId = sensorId
    }

    /**
     * Initialize state from KV on cold start.
     * Called ONCE per Worker lifecycle.
     * All reads happen here — hot path never touches KV.
     */
    async initialize(): Promise<{
        coldStart: boolean
        modelEndpoints: number
        reputation: number
        rules: number
        statsRestored: boolean
    }> {
        if (this.initialized) {
            return {
                coldStart: false,
                modelEndpoints: this._model?.endpoints.length ?? 0,
                reputation: this._reputation?.entries.length ?? 0,
                rules: this._rules?.rules.length ?? 0,
                statsRestored: this._stats !== null,
            }
        }

        // Parallel KV reads — all at once for minimum latency
        const [modelRaw, postureRaw, reputationRaw, rulesRaw, statsRaw, configRaw] =
            await Promise.all([
                this.kv.get(KV_KEYS.model(this.sensorId)),
                this.kv.get(KV_KEYS.posture(this.sensorId)),
                this.kv.get(KV_KEYS.reputation(this.sensorId)),
                this.kv.get(KV_KEYS.rules(this.sensorId)),
                this.kv.get(KV_KEYS.stats(this.sensorId)),
                this.kv.get(KV_KEYS.config(this.sensorId)),
            ])

        // Parse safely — corrupted KV should not crash the sensor
        this._model = safeParse<PersistedModelState>(modelRaw)
        this._posture = safeParse<PersistedPosture>(postureRaw)
        this._reputation = safeParse<PersistedReputation>(reputationRaw)
        this._rules = safeParse<PersistedRules>(rulesRaw)
        this._stats = safeParse<PersistedStats>(statsRaw)

        const configParsed = safeParse<SensorConfig>(configRaw)
        if (configParsed) this._config = { ...DEFAULT_CONFIG, ...configParsed }

        // Update cold start stats
        if (this._stats) {
            this._stats.coldStarts++
            this._stats.lastColdStart = Date.now()
        } else {
            this._stats = {
                totalRequests: 0,
                totalBlocked: 0,
                totalSignals: 0,
                signalsByType: {},
                uniqueAttackerIPs: 0,
                coldStarts: 1,
                lastColdStart: Date.now(),
                upSince: Date.now(),
                persistedAt: 0,
            }
        }

        const statsWereRestored = safeParse<PersistedStats>(statsRaw) !== null

        this.initialized = true

        return {
            coldStart: true,
            modelEndpoints: this._model?.endpoints.length ?? 0,
            reputation: this._reputation?.entries.length ?? 0,
            rules: this._rules?.rules.length ?? 0,
            statsRestored: statsWereRestored,
        }
    }

    // ── Accessors ────────────────────────────────────────────────

    get model(): PersistedModelState | null { return this._model }
    get posture(): PersistedPosture | null { return this._posture }
    get reputation(): PersistedReputation | null { return this._reputation }
    get rules(): PersistedRules | null { return this._rules }
    get stats(): PersistedStats | null { return this._stats }
    get config(): SensorConfig { return this._config }

    // ── Model Updates ────────────────────────────────────────────

    updateModel(endpoints: PersistedEndpoint[], totalRequests: number): void {
        this._model = {
            endpoints,
            totalRequests,
            persistedAt: Date.now(),
            version: (this._model?.version ?? 0) + 1,
        }
        this.requestsSinceLastPersist++
        this.dirty = true
    }

    // ── Posture Updates ──────────────────────────────────────────

    updatePosture(findings: PersistedPostureFinding[], reactivationCount: number): void {
        this._posture = {
            findings,
            reactivationCount,
            persistedAt: Date.now(),
        }
        this.dirty = true
    }

    // ── Reputation Updates ───────────────────────────────────────

    recordAttacker(ipHash: string, categories: string[]): void {
        if (!this._reputation) {
            this._reputation = {
                entries: [],
                totalAttackers: 0,
                persistedAt: 0,
            }
        }

        const existing = this._reputation.entries.find(e => e.ipHash === ipHash)
        if (existing) {
            existing.signals++
            existing.lastSeen = Date.now()
            for (const cat of categories) {
                if (!existing.categories.includes(cat)) {
                    existing.categories.push(cat)
                }
            }
        } else {
            // Enforce memory bound
            if (this._reputation.entries.length >= this._config.maxTrackedIPs) {
                // Evict oldest entry
                this._reputation.entries.sort((a, b) => a.lastSeen - b.lastSeen)
                this._reputation.entries.shift()
            }
            this._reputation.entries.push({
                ipHash,
                signals: 1,
                lastSeen: Date.now(),
                categories,
                blocked: false,
            })
            this._reputation.totalAttackers++
        }
        this.dirty = true
    }

    /**
     * Check if an IP hash has known bad reputation.
     * Returns the entry if found, null otherwise.
     * This is called on the HOT PATH — must be O(1) or fast O(n).
     */
    checkReputation(ipHash: string): IPReputationEntry | null {
        if (!this._reputation) return null
        return this._reputation.entries.find(e => e.ipHash === ipHash) ?? null
    }

    // ── Dynamic Rules ────────────────────────────────────────────

    updateRules(rules: DynamicRule[], version: string, source: string): void {
        this._rules = {
            rules,
            version,
            fetchedAt: Date.now(),
            source,
        }
        this.dirty = true
    }

    // ── Stats Updates ────────────────────────────────────────────

    recordRequest(): void {
        if (this._stats) {
            this._stats.totalRequests++
            this.requestsSinceLastPersist++
        }
    }

    recordBlock(): void {
        if (this._stats) this._stats.totalBlocked++
    }

    recordSignal(signalType: string): void {
        if (this._stats) {
            this._stats.totalSignals++
            this._stats.signalsByType[signalType] =
                (this._stats.signalsByType[signalType] ?? 0) + 1
        }
    }

    // ── Persistence ──────────────────────────────────────────────

    /**
     * Persist all dirty state to KV.
     * Called in ctx.waitUntil() — NEVER on the hot path.
     *
     * Write strategy:
     *   - Model: every N requests (configurable)
     *   - Reputation: every persist cycle if dirty
     *   - Rules: on fetch from intel
     *   - Stats: every persist cycle
     *   - Posture: every persist cycle if dirty
     *   - Heartbeat: every persist cycle
     */
    async persist(): Promise<{ written: string[]; errors: string[] }> {
        if (!this.dirty && this.requestsSinceLastPersist < this._config.modelPersistInterval) {
            return { written: [], errors: [] }
        }

        const written: string[] = []
        const errors: string[] = []

        const writes: Promise<void>[] = []

        // Model — only if enough requests accumulated
        if (this._model && this.requestsSinceLastPersist >= this._config.modelPersistInterval) {
            writes.push(
                this.safeWrite(KV_KEYS.model(this.sensorId), this._model, 86400 * 7)
                    .then(() => { written.push('model') })
                    .catch(e => { errors.push(`model: ${e}`) }),
            )
            this.requestsSinceLastPersist = 0
        }

        // Posture
        if (this._posture) {
            writes.push(
                this.safeWrite(KV_KEYS.posture(this.sensorId), this._posture, 86400 * 7)
                    .then(() => { written.push('posture') })
                    .catch(e => { errors.push(`posture: ${e}`) }),
            )
        }

        // Reputation
        if (this._reputation && this._reputation.entries.length > 0) {
            writes.push(
                this.safeWrite(KV_KEYS.reputation(this.sensorId), this._reputation, this._config.reputationTTL)
                    .then(() => { written.push('reputation') })
                    .catch(e => { errors.push(`reputation: ${e}`) }),
            )
        }

        // Rules
        if (this._rules) {
            writes.push(
                this.safeWrite(KV_KEYS.rules(this.sensorId), this._rules, 86400)
                    .then(() => { written.push('rules') })
                    .catch(e => { errors.push(`rules: ${e}`) }),
            )
        }

        // Stats
        if (this._stats) {
            this._stats.persistedAt = Date.now()
            writes.push(
                this.safeWrite(KV_KEYS.stats(this.sensorId), this._stats, 86400 * 30)
                    .then(() => { written.push('stats') })
                    .catch(e => { errors.push(`stats: ${e}`) }),
            )
        }

        // Heartbeat — always write
        writes.push(
            this.kv.put(
                KV_KEYS.heartbeat(this.sensorId),
                new Date().toISOString(),
                { expirationTtl: 600 },
            )
                .then(() => { written.push('heartbeat') })
                .catch(e => { errors.push(`heartbeat: ${e}`) }),
        )

        await Promise.allSettled(writes)
        this.dirty = false

        return { written, errors }
    }

    // ── Internal ─────────────────────────────────────────────────

    private async safeWrite(kvKey: string, value: unknown, ttl: number): Promise<void> {
        const json = JSON.stringify(value)

        // KV has a 25MB limit — enforce a safe margin
        if (json.length > 20_000_000) {
            throw new Error(`Value too large: ${json.length} bytes`)
        }

        await this.kv.put(kvKey, json, { expirationTtl: ttl })
    }
}


// ── Safe JSON Parser ─────────────────────────────────────────────

function safeParse<T>(raw: string | null): T | null {
    if (!raw) return null
    try {
        return JSON.parse(raw) as T
    } catch {
        return null
    }
}
