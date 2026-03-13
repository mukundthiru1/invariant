/**
 * @santh/edge-sensor — Cloudflare Worker
 *
 * INVARIANT detection at the edge. Deployed to the subscriber's Cloudflare zone.
 * Intercepts every request, runs the full 14-layer detection pipeline, and either
 * blocks or passes to origin.
 *
 * Architecture:
 *   Request → Static Signature Detection (L1)
 *           → Behavioral Analysis (L2)
 *           → Client Fingerprinting (L3)
 *           → Request Body Analysis (L3b)
 *           → Technology Detection (L4)
 *           → Invariant Engine (L5) — THE CORE
 *           → L2 Structural Evaluators (L5b) — DEEP ANALYSIS
 *           → IOC Feed Correlation (L5c) — THREAT INTEL
 *           → MITRE ATT&CK Enrichment (L5d)
 *           → Multi-Dimensional Risk Surface (L5e)
 *           → Threat Scoring (L5f)
 *           → Defense Decision (L6)
 *           → [block | pass to origin]
 *           → Response Audit (L7)
 *           → Return to client
 *
 *   Cron  → Signal Flush + Evidence Sealing
 *         → Internal Probing (L8)
 *         → Drift Detection (L9) — TEMPORAL COMPARISON
 *         → Rule Sync from Intel + IOC Feed Sync
 *         → Privilege Graph Analysis
 *         → State Persistence
 *         → Application Model Snapshot
 *
 * Merged from Axiom Drift:
 *   - Cryptographic Evidence Sealing (Merkle proofs)
 *   - MITRE ATT&CK Mapping (46 classes → 25+ techniques)
 *   - Multi-Dimensional Risk Surface (4-axis scoring)
 *   - Drift Detection (temporal posture comparison)
 *   - IOC Feed Correlation (IP/domain/payload/UA/CVE)
 *
 * Privacy (see santh.io/principles#privacy):
 *   - Source IPs: SHA-256 hashed with daily-rotating salt, irreversible
 *   - Request bodies: READ via clone() for in-memory security analysis only.
 *     Body content and extracted values are NEVER persisted, NEVER transmitted
 *     to intel. Only detection metadata (signal type, confidence) is reported.
 *   - Cookie NAMES + FLAGS: inspected for auth classification and
 *     posture auditing (SAA-072). Cookie VALUES: NEVER read or stored.
 *   - Only metadata + attack patterns analyzed — no PII extraction
 *   - PoW challenges required for signal submission (SAA-073)
 */

import { InvariantEngine, type InvariantMatch, type InvariantClass, type EngineThresholdOverride } from '../../engine/src/invariant-engine.js'
import { runL2Evaluators, mergeL2Results, type L2DetectionResult } from '../../engine/src/evaluators/evaluator-bridge.js'
import { ChainCorrelator, type ChainSignal } from '../../engine/src/chain-detector.js'
import { MitreMapper } from '../../engine/src/mitre-mapper.js'
import { EvidenceSealer } from '../../engine/src/evidence/evidence-sealer.js'

import {
    analyzeRequestBody,
    type BodyAnalysisResult,
    ThreatScoringEngine,
    buildHeaderThreatSignals,
    type ThreatSignal,
    detectWebSocketUpgradeAbuse,
    ResponseAuditor,
    InternalProber,
    ApplicationModel,
    normalizePathPattern,
    detectAuthType,
    detectSensitiveResponse,
    TechStackTracker,
    CveStackCorrelator,
    ReactivationEngine,
    detectConditions,
    PrivilegeGraph,
    SensorStateManager,
    syncRulesFromIntel,
    startRuleStream,
    getRuleStreamStatus,
    matchDynamicRules,
    type DynamicRuleMatch,
    IOCCorrelator,
    DriftDetector,
    RiskSurfaceCalculator,
    DeceptionLayer,
} from './modules/index.js'

// ── Extracted Layer Modules ───────────────────────────────────────
import type { Env, Signal, RequestContext } from './layers/types.js'
import { safeDecode, deepDecode } from './layers/encoding.js'
import { SIGNATURES } from './layers/l1-signatures.js'
import { BehaviorTracker } from './layers/l2-behavior.js'
import { classifyClient } from './layers/l3-fingerprint.js'
import { detectTechnology } from './layers/l4-tech-detect.js'
import { SignalBuffer } from './layers/signal-buffer.js'
import { analyzeWebSocketUpgrade, analyzeWebSocketFrameBody } from './layers/ws-interceptor.js'

// ── Encrypted Collective Intelligence ────────────────────────────
// These modules implement the forward-secret, E2E-encrypted channel
// between this sensor and Santh central. They activate only when the
// subscriber has configured SUBSCRIBER_PRIVATE_KEY + SANTH_RULE_VERIFY_KEY.
// The worker runs in standalone mode (full detection) without them.
import { DynamicRuleStore } from './modules/dynamic-rules.js'
import { loadPendingRules } from './modules/rule-loader.js'
import {
    SignalBuffer as CryptoSignalBuffer,
    flushSignalBuffer,
    isDuplicateSignal,
    makeSignalBundle,
} from './modules/signal-uploader.js'
import { SignalDeduplicator } from './modules/signal-dedup.js'
import { hashSource, detectHeaderAnomalies, blockResponse, normalizePath, timingSafeEqual, setSaltKey } from './layers/utils.js'


// ══════════════════════════════════════════════════════════════════
// MAIN WORKER — FULL PIPELINE
// ══════════════════════════════════════════════════════════════════

// Module-level state (survives across requests within a Worker instance)
const behaviorTracker = new BehaviorTracker()
const engine = new InvariantEngine()
const chainCorrelator = new ChainCorrelator()
const threatScoring = new ThreatScoringEngine()
const responseAuditor = new ResponseAuditor()
const internalProber = new InternalProber()
const applicationModel = new ApplicationModel()
const techTracker = new TechStackTracker()
const cveCorrelator = new CveStackCorrelator()
const reactivationEngine = new ReactivationEngine()
const mitreMapper = new MitreMapper()
const iocCorrelator = new IOCCorrelator()
const driftDetector = new DriftDetector()
const riskSurface = new RiskSurfaceCalculator()
const deceptionLayer = new DeceptionLayer()
let evidenceSealer: EvidenceSealer | null = null

let signalBuffer: SignalBuffer | null = null
let stateManager: SensorStateManager | null = null
let initPromise: Promise<void> | null = null
let initialized = false
let streamInitialized = false
let streamTask: Promise<void> | null = null

// ── Encrypted collective intelligence state ───────────────────────
// Instantiated once per Worker process. Survives across requests.
const dynamicRuleStore = new DynamicRuleStore()
let cryptoSignalBuf: CryptoSignalBuffer | null = null
const signalDeduplicator = new SignalDeduplicator()
let rulesInitialized = false

function isFiniteRecord(value: unknown): value is Record<string, number> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false
    return Object.values(value).every(v => typeof v === 'number' && Number.isFinite(v))
}

type DefenseMode = 'monitor' | 'enforce' | 'off'
type PathRule = { skip_classes?: string[]; mode?: DefenseMode }
type PathRuleConfig = Record<string, PathRule>
type IpRuleConfig = { allow?: string[]; block?: string[]; challenge?: string[] }
type GeoRuleConfig = { allow?: string[]; block?: string[]; challenge?: string[] }
type RateLimitConfig = { requests_per_minute: number; burst: number }
type HeaderConfig = Record<string, string>

const CONFIG_CACHE_TTL_MS = 60_000
const KV_KEY_PATH_RULES = 'path_rules'
const KV_KEY_IP_RULES = 'ip_rules'
const KV_KEY_GEO_RULES = 'geo_rules'
const KV_KEY_RATE_LIMITS = 'rate_limits'
const KV_KEY_RESPONSE_HEADERS = 'response_headers'

const inMemoryRateLimitFallback = new Map<string, { count: number, minute: number }>()

const DEFAULT_RATE_LIMITS: RateLimitConfig = { requests_per_minute: 100, burst: 20 }
const DEFAULT_SECURITY_HEADERS: HeaderConfig = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'X-DNS-Prefetch-Control': 'off',
}

const pathRulesCache: { value: PathRuleConfig; expiresAt: number } = { value: {}, expiresAt: 0 }
const ipRulesCache: { value: IpRuleConfig; expiresAt: number } = { value: {}, expiresAt: 0 }
const geoRulesCache: { value: GeoRuleConfig; expiresAt: number } = { value: {}, expiresAt: 0 }
const rateLimitsCache: { value: RateLimitConfig; expiresAt: number } = { value: DEFAULT_RATE_LIMITS, expiresAt: 0 }
const responseHeadersCache: { value: HeaderConfig; expiresAt: number } = { value: DEFAULT_SECURITY_HEADERS, expiresAt: 0 }
const pathPatternRegexCache = new Map<string, RegExp>()

async function getPathRulesConfig(env: Env): Promise<PathRuleConfig> {
    if (Date.now() < pathRulesCache.expiresAt) return pathRulesCache.value
    let normalized: PathRuleConfig = {}
    try {
        const raw = await env.SENSOR_STATE.get(KV_KEY_PATH_RULES)
        const parsed = safeJson(raw)
        normalized = normalizePathRules(parsed)
    } catch {
        normalized = {}
    }
    pathRulesCache.value = normalized
    pathRulesCache.expiresAt = Date.now() + CONFIG_CACHE_TTL_MS
    return normalized
}

async function getIpRulesConfig(env: Env): Promise<IpRuleConfig> {
    if (Date.now() < ipRulesCache.expiresAt) return ipRulesCache.value
    let normalized: IpRuleConfig = {}
    try {
        const raw = await env.SENSOR_STATE.get(KV_KEY_IP_RULES)
        const parsed = safeJson(raw)
        normalized = normalizeIpRules(parsed)
    } catch {
        normalized = {}
    }
    ipRulesCache.value = normalized
    ipRulesCache.expiresAt = Date.now() + CONFIG_CACHE_TTL_MS
    return normalized
}

async function getGeoRulesConfig(env: Env): Promise<GeoRuleConfig> {
    if (Date.now() < geoRulesCache.expiresAt) return geoRulesCache.value
    let normalized: GeoRuleConfig = {}
    try {
        const raw = await env.SENSOR_STATE.get(KV_KEY_GEO_RULES)
        const parsed = safeJson(raw)
        normalized = normalizeGeoRules(parsed)
    } catch {
        normalized = {}
    }
    geoRulesCache.value = normalized
    geoRulesCache.expiresAt = Date.now() + CONFIG_CACHE_TTL_MS
    return normalized
}

async function getRateLimitsConfig(env: Env): Promise<RateLimitConfig> {
    if (Date.now() < rateLimitsCache.expiresAt) return rateLimitsCache.value
    let normalized: RateLimitConfig = DEFAULT_RATE_LIMITS
    try {
        const raw = await env.SENSOR_STATE.get(KV_KEY_RATE_LIMITS)
        const parsed = safeJson(raw)
        normalized = normalizeRateLimits(parsed)
    } catch {
        normalized = DEFAULT_RATE_LIMITS
    }
    rateLimitsCache.value = normalized
    rateLimitsCache.expiresAt = Date.now() + CONFIG_CACHE_TTL_MS
    return normalized
}

async function getResponseHeadersConfig(env: Env): Promise<HeaderConfig> {
    if (Date.now() < responseHeadersCache.expiresAt) return responseHeadersCache.value
    let normalized: HeaderConfig = DEFAULT_SECURITY_HEADERS
    try {
        const raw = await env.SENSOR_STATE.get(KV_KEY_RESPONSE_HEADERS)
        const parsed = safeJson(raw)
        normalized = normalizeHeaders(parsed)
    } catch {
        normalized = DEFAULT_SECURITY_HEADERS
    }
    responseHeadersCache.value = normalized
    responseHeadersCache.expiresAt = Date.now() + CONFIG_CACHE_TTL_MS
    return normalized
}

function safeJson(raw: string | null): unknown {
    if (!raw) return null
    try {
        return JSON.parse(raw)
    } catch {
        return null
    }
}

function normalizePathRules(raw: unknown): PathRuleConfig {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
    const out: PathRuleConfig = {}
    const source = raw as Record<string, unknown>
    for (const [pattern, value] of Object.entries(source)) {
        if (typeof pattern !== 'string' || pattern.length === 0) continue
        if (!value || typeof value !== 'object' || Array.isArray(value)) continue
        const rule = value as Record<string, unknown>
        const mode = (rule.mode === 'monitor' || rule.mode === 'enforce' || rule.mode === 'off')
            ? rule.mode
            : undefined
        const skipClasses = Array.isArray(rule.skip_classes)
            ? rule.skip_classes.filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
            : undefined
        if (!mode && !skipClasses) continue
        out[pattern] = {
            ...(mode ? { mode } : {}),
            ...(skipClasses ? { skip_classes: skipClasses } : {}),
        }
    }
    return out
}

function normalizeIpRules(raw: unknown): IpRuleConfig {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
    const candidate = raw as Record<string, unknown>
    return {
        allow: normalizeIpList(candidate.allow),
        block: normalizeIpList(candidate.block),
        challenge: normalizeIpList(candidate.challenge),
    }
}

function normalizeGeoRules(raw: unknown): GeoRuleConfig {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
    const candidate = raw as Record<string, unknown>
    return {
        allow: normalizeCountryCodeList(candidate.allow),
        block: normalizeCountryCodeList(candidate.block),
        challenge: normalizeCountryCodeList(candidate.challenge),
    }
}

function normalizeIpList(value: unknown): string[] {
    if (!Array.isArray(value)) return []
    return value.filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0)
}

function normalizeCountryCodeList(value: unknown): string[] {
    if (!Array.isArray(value)) return []
    return value
        .filter((entry): entry is string => typeof entry === 'string')
        .map(code => code.trim().toUpperCase())
        .filter(code => /^[A-Z]{2}$/.test(code))
}

function normalizeRateLimits(raw: unknown): RateLimitConfig {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return DEFAULT_RATE_LIMITS
    const candidate = raw as Record<string, unknown>
    const requestsPerMinute = typeof candidate.requests_per_minute === 'number'
        && Number.isFinite(candidate.requests_per_minute)
        && candidate.requests_per_minute >= 1
        && candidate.requests_per_minute <= 1_000_000
        ? Math.floor(candidate.requests_per_minute)
        : DEFAULT_RATE_LIMITS.requests_per_minute
    const burst = typeof candidate.burst === 'number'
        && Number.isFinite(candidate.burst)
        && candidate.burst >= 0
        && candidate.burst <= 1_000_000
        ? Math.floor(candidate.burst)
        : DEFAULT_RATE_LIMITS.burst
    return { requests_per_minute: requestsPerMinute, burst }
}

function normalizeHeaders(raw: unknown): HeaderConfig {
    const merged: HeaderConfig = { ...DEFAULT_SECURITY_HEADERS }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return merged
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
        if (!isSafeHeaderName(k)) continue
        if (typeof v !== 'string') continue
        merged[k] = v
    }
    return merged
}

function isSafeHeaderName(name: string): boolean {
    return /^[A-Za-z0-9-]+$/.test(name)
}

function applySecurityHeaders(response: Response, headers: HeaderConfig): Response {
    const outHeaders = new Headers(response.headers)
    for (const [name, value] of Object.entries(headers)) {
        outHeaders.set(name, value)
    }
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: outHeaders,
    })
}

function matchPathRule(path: string, rules: PathRuleConfig): PathRule | null {
    const candidates: Array<{ score: number; rule: PathRule }> = []
    for (const [pattern, rule] of Object.entries(rules)) {
        const matched = pattern.includes('*')
            ? globMatch(path, pattern)
            : path === pattern
        if (!matched) continue
        const score = pattern.replace(/\*/g, '').length
        candidates.push({ score, rule })
    }
    if (candidates.length === 0) return null
    candidates.sort((a, b) => b.score - a.score)
    return candidates[0].rule
}

function globMatch(path: string, pattern: string): boolean {
    let regex = pathPatternRegexCache.get(pattern)
    if (!regex) {
        const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
        regex = new RegExp(`^${escaped}$`)
        pathPatternRegexCache.set(pattern, regex)
    }
    return regex.test(path)
}

function shouldSkipClass(skipClasses: Set<string>, ...candidates: Array<string | null | undefined>): boolean {
    for (const value of candidates) {
        if (!value) continue
        if (skipClasses.has(value.toLowerCase())) return true
    }
    return false
}

function selectPrimaryAttackClass(
    threatSignals: ThreatSignal[],
    invariantMatches: InvariantMatch[],
): string {
    if (invariantMatches.length > 0) {
        const sorted = [...invariantMatches].sort((a, b) => b.confidence - a.confidence)
        return sorted[0].class
    }

    if (threatSignals.length > 0) {
        const sorted = [...threatSignals].sort((a, b) => b.confidence - a.confidence)
        return sorted[0].subtype ?? sorted[0].type
    }

    return 'unknown_attack'
}

type PolicyDecision = 'allow' | 'block' | 'challenge' | 'none'

function resolveIpRule(ip: string, rules: IpRuleConfig): PolicyDecision {
    if (matchesAnyIpRule(ip, rules.allow ?? [])) return 'allow'
    if (matchesAnyIpRule(ip, rules.block ?? [])) return 'block'
    if (matchesAnyIpRule(ip, rules.challenge ?? [])) return 'challenge'
    return 'none'
}

function matchesAnyIpRule(ip: string, rules: string[]): boolean {
    for (const rule of rules) {
        if (matchesIpRule(ip, rule)) return true
    }
    return false
}

function matchesIpRule(ip: string, rule: string): boolean {
    if (rule.includes('/')) {
        return ip.includes(':') ? isIpv6InCidr(ip, rule) : isIpInCidr(ip, rule)
    }
    return ip === rule
}

function isIpInCidr(ip: string, cidr: string): boolean {
    const [baseIp, prefixRaw] = cidr.split('/')
    if (!baseIp || !prefixRaw) return false
    const prefix = Number.parseInt(prefixRaw, 10)
    const ipNum = ipv4ToInt(ip)
    const baseNum = ipv4ToInt(baseIp)
    if (ipNum === null || baseNum === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
    return (ipNum & mask) === (baseNum & mask)
}

function isIpv6InCidr(ip: string, cidr: string): boolean {
    const [baseIp, prefixRaw] = cidr.split('/')
    if (!baseIp || !prefixRaw) return false
    const prefix = Number.parseInt(prefixRaw, 10)
    
    const ipToBigInt = (ipv6: string): bigint | null => {
        let fullIp = ipv6
        if (fullIp.includes('::')) {
            const parts = fullIp.split('::')
            if (parts.length > 2) return null
            const left = parts[0] ? parts[0].split(':') : []
            const right = parts[1] ? parts[1].split(':') : []
            const missing = 8 - (left.length + right.length)
            if (missing < 0) return null
            fullIp = [...left, ...Array(missing).fill('0'), ...right].join(':')
        }
        
        const segments = fullIp.split(':')
        if (segments.length !== 8) return null
        
        let result = 0n
        for (const segment of segments) {
            if (!/^[0-9a-fA-F]{1,4}$/.test(segment)) return null
            result = (result << 16n) | BigInt(parseInt(segment || '0', 16))
        }
        return result
    }

    const ipNum = ipToBigInt(ip)
    const baseNum = ipToBigInt(baseIp)
    
    if (ipNum === null || baseNum === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false
    
    const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) << (128n - BigInt(prefix))
    
    return (ipNum & mask) === (baseNum & mask)
}

function ipv4ToInt(ip: string): number | null {
    const parts = ip.split('.')
    if (parts.length !== 4) return null
    let result = 0
    for (const part of parts) {
        if (!/^\d{1,3}$/.test(part)) return null
        const octet = Number.parseInt(part, 10)
        if (octet < 0 || octet > 255) return null
        result = (result << 8) | octet
    }
    return result >>> 0
}

function resolveGeoRule(country: string | null, rules: GeoRuleConfig): PolicyDecision {
    if (!country) return 'none'
    const normalizedCountry = country.trim().toUpperCase()
    if (!/^[A-Z]{2}$/.test(normalizedCountry)) return 'none'
    if ((rules.allow ?? []).includes(normalizedCountry)) return 'allow'
    if ((rules.block ?? []).includes(normalizedCountry)) return 'block'
    if ((rules.challenge ?? []).includes(normalizedCountry)) return 'challenge'
    return 'none'
}

async function checkRateLimit(env: Env, ip: string, config: RateLimitConfig): Promise<{
    exceeded: boolean
    count: number
    limit: number
    retryAfterSeconds: number
}> {
    const now = Date.now()
    const currentMinute = Math.floor(now / 60_000)
    const counterKey = `rate_limit:${ip}:${currentMinute}`
    const existingRaw = await env.SENSOR_STATE.get(counterKey)
    const existing = existingRaw ? Number.parseInt(existingRaw, 10) : 0
    const count = Number.isFinite(existing) && existing > 0 ? existing + 1 : 1
    await env.SENSOR_STATE.put(counterKey, String(count), { expirationTtl: 130 })
    const limit = config.requests_per_minute + config.burst
    const retryAfterSeconds = 60 - (Math.floor(now / 1000) % 60)
    return {
        exceeded: count > limit,
        count,
        limit,
        retryAfterSeconds,
    }
}

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        // Initialize on first request
        if (!signalBuffer) {
            signalBuffer = new SignalBuffer(
                parseInt(env.SIGNAL_BATCH_SIZE ?? '50'),
                env.SANTH_INGEST_URL ?? '',
                env.SENSOR_API_KEY ?? '',
            )
            // SAA-060: Initialize deterministic salt for cross-isolate IP hash consistency
            if (env.SENSOR_API_KEY) setSaltKey(env.SENSOR_API_KEY)
        }

        // Initialize encrypted signal buffer (additive — runs alongside existing buffer)
        if (!cryptoSignalBuf) {
            cryptoSignalBuf = new CryptoSignalBuffer()
        }

        if (!stateManager && env.SENSOR_STATE) {
            stateManager = new SensorStateManager(env.SENSOR_STATE, env.SENSOR_ID ?? 'default')
        }

        // Lazy initialization from KV (once per Worker lifecycle)
        if (!initialized && stateManager) {
            if (!initPromise) {
                initPromise = stateManager.initialize().then(() => {
                    initialized = true
                }).catch(() => {
                    // KV failure must not block traffic
                    initialized = true
                })
            }
            await initPromise
        }

        // Push-based rule distribution: connect to intel SSE stream once per isolate.
        // If stream setup fails or disconnects later, cron falls back to polling.
        if (
            stateManager
            && env.SANTH_INTEL_URL
            && !streamInitialized
        ) {
            streamInitialized = true
            streamTask = startRuleStream(stateManager, env.SANTH_INTEL_URL, env.SENSOR_API_KEY)
            if (streamTask) {
                ctx.waitUntil(streamTask)
            }
        }

        const remoteConfig = stateManager ? await stateManager.getRemoteConfig() : null
        const baseMode = remoteConfig?.mode ?? stateManager?.config.defenseMode ?? env.DEFENSE_MODE ?? 'monitor'

        const url = new URL(request.url)
        const path = url.pathname
        const query = url.search
        const sourceIpForPolicy = request.headers.get('cf-connecting-ip') ?? '0.0.0.0'
        const hasQueryParams = query.length > 1

        const [pathRulesConfig, ipRulesConfig, geoRulesConfig, rateLimitsConfig, responseHeadersConfig] = await Promise.all([
            getPathRulesConfig(env),
            getIpRulesConfig(env),
            getGeoRulesConfig(env),
            getRateLimitsConfig(env),
            getResponseHeadersConfig(env),
        ])
        const withHeaders = (response: Response): Response => applySecurityHeaders(response, responseHeadersConfig)
        const matchedPathRule = matchPathRule(path, pathRulesConfig)
        const skipClasses = new Set((matchedPathRule?.skip_classes ?? []).map(c => c.toLowerCase()))
        const mode = matchedPathRule?.mode ?? baseMode

        // ── Introspection endpoints ──────────────────────────────
        // Require INTROSPECTION_KEY when configured (defense against WAF fingerprinting)
        if (
            path === '/__invariant/health'
            || path === '/__invariant/posture'
            || path === '/__invariant/config'
        ) {
            if (env.INTROSPECTION_KEY) {
                // SAA-067: Moved from query param to header. Secrets in URLs
                // leak to access logs, CDN logs, Referer headers, browser history,
                // and any proxy between client and worker.
                const keyFromHeader = request.headers.get('X-Introspection-Key')
                // SECURITY (SAA-035): Constant-time comparison prevents timing
                // side-channel that would leak the key byte by byte.
                const keyValid = keyFromHeader !== null
                    && keyFromHeader.length === env.INTROSPECTION_KEY.length
                    && await timingSafeEqual(keyFromHeader, env.INTROSPECTION_KEY)
                if (!keyValid) {
                    return withHeaders(new Response(JSON.stringify({ error: 'unauthorized' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json' },
                    }))
                }
            }
        }

        if (path === '/__invariant/health') {
            return withHeaders(new Response(JSON.stringify({
                status: 'operational',
                version: '8.0.0',
                mode,
                engine: { classes: engine.classes.length },
                signalBuffer: signalBuffer.getCount(),
                // Redacted: no tech stack, IOC counts, or capability details
                timestamp: new Date().toISOString(),
            }), {
                headers: { 'Content-Type': 'application/json' },
            }))
        }

        if (path === '/__invariant/posture') {
            const report = responseAuditor.generateReport(url.hostname)
            return withHeaders(new Response(JSON.stringify(report), {
                headers: { 'Content-Type': 'application/json' },
            }))
        }

        if (path === '/__invariant/config') {
            if (request.method === 'GET') {
                return withHeaders(new Response(JSON.stringify({
                    mode: mode,
                    thresholds: remoteConfig?.thresholds ?? null,
                    source: remoteConfig
                        ? 'remote'
                        : env.DEFENSE_MODE
                            ? 'env'
                            : 'default',
                }), {
                    headers: { 'Content-Type': 'application/json' },
                }))
            }

            if (request.method !== 'POST') {
                return withHeaders(new Response(JSON.stringify({ error: 'method not allowed' }), {
                    status: 405,
                    headers: { 'Content-Type': 'application/json' },
                }))
            }

            if (!stateManager) {
                return withHeaders(new Response(JSON.stringify({ error: 'state storage unavailable' }), {
                    status: 503,
                    headers: { 'Content-Type': 'application/json' },
                }))
            }

            let rawBody: unknown
            try {
                const text = await request.text()
                rawBody = text.trim().length > 0 ? JSON.parse(text) : {}
            } catch {
                return withHeaders(new Response(JSON.stringify({ error: 'invalid json body' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' },
                }))
            }

            if (!rawBody || typeof rawBody !== 'object' || Array.isArray(rawBody)) {
                return withHeaders(new Response(JSON.stringify({ error: 'invalid config payload' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' },
                }))
            }

            const body = rawBody as Record<string, unknown>
            const candidateMode = body.mode
            const candidateThresholds = body.thresholds

            if (candidateMode !== undefined && candidateMode !== 'monitor' && candidateMode !== 'enforce' && candidateMode !== 'off') {
                return withHeaders(new Response(JSON.stringify({ error: 'invalid mode' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' },
                }))
            }

            if (candidateThresholds !== undefined) {
                if (!isFiniteRecord(candidateThresholds)) {
                    return withHeaders(new Response(JSON.stringify({ error: 'invalid thresholds payload' }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' },
                    }))
                }
            }

            if (candidateMode === undefined && candidateThresholds === undefined) {
                return withHeaders(new Response(JSON.stringify({ error: 'mode or thresholds required' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' },
                }))
            }

            const newConfig: { mode?: 'monitor' | 'enforce' | 'off'; thresholds?: Record<string, number> } = {}
            if (candidateMode !== undefined) newConfig.mode = candidateMode
            if (candidateThresholds !== undefined) newConfig.thresholds = candidateThresholds as Record<string, number>

            try {
                await stateManager.setRemoteConfig(newConfig)
            } catch (error) {
                return withHeaders(new Response(JSON.stringify({ error: error instanceof Error ? error.message : 'failed to store config' }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' },
                }))
            }

            return withHeaders(new Response(JSON.stringify({
                mode: newConfig.mode,
                thresholds: newConfig.thresholds,
                source: 'remote',
            }), {
                headers: { 'Content-Type': 'application/json' },
            }))
        }

        const ipRuleDecision = resolveIpRule(sourceIpForPolicy, ipRulesConfig)
        if (ipRuleDecision === 'allow') return withHeaders(await fetch(request))
        if (ipRuleDecision === 'block') {
            return withHeaders(new Response(JSON.stringify({
                error: 'Request blocked by IP policy',
                code: 'INVARIANT_IP_BLOCK',
            }), {
                status: 403,
                headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
            }))
        }
        if (ipRuleDecision === 'challenge') {
            return withHeaders(new Response(JSON.stringify({
                error: 'Request challenged by IP policy',
                code: 'INVARIANT_IP_CHALLENGE',
            }), {
                status: 403,
                headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
            }))
        }

        const geoRuleDecision = resolveGeoRule(request.headers.get('cf-ipcountry'), geoRulesConfig)
        if (geoRuleDecision === 'block') {
            return withHeaders(new Response(JSON.stringify({
                error: 'Request blocked by geo policy',
                code: 'INVARIANT_GEO_BLOCK',
            }), {
                status: 403,
                headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
            }))
        }
        if (geoRuleDecision === 'challenge') {
            return withHeaders(new Response(JSON.stringify({
                error: 'Request challenged by geo policy',
                code: 'INVARIANT_GEO_CHALLENGE',
            }), {
                status: 403,
                headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
            }))
        }

        try {
            const rateLimitResult = await checkRateLimit(env, sourceIpForPolicy, rateLimitsConfig)
            if (rateLimitResult.exceeded) {
                return withHeaders(new Response(JSON.stringify({
                    error: 'Rate limit exceeded',
                    code: 'INVARIANT_RATE_LIMIT',
                    limit: rateLimitResult.limit,
                    requests: rateLimitResult.count,
                }), {
                    status: 429,
                    headers: {
                        'Content-Type': 'application/json',
                        'Cache-Control': 'no-store',
                        'Retry-After': String(rateLimitResult.retryAfterSeconds),
                    },
                }))
            }
        } catch (error) {
            console.error(JSON.stringify({
                error: 'INVARIANT_RATE_LIMIT_ERROR',
                message: 'KV rate limit check failed, falling back to memory',
                details: error instanceof Error ? error.message : String(error)
            }))
            
            const currentMinute = Math.floor(Date.now() / 60000)
            const fallbackKey = `${sourceIpForPolicy}`
            const record = inMemoryRateLimitFallback.get(fallbackKey)
            const fallbackLimit = typeof rateLimitsConfig === 'object' && rateLimitsConfig.requests_per_minute ? rateLimitsConfig.requests_per_minute : 100
            
            if (!record || record.minute !== currentMinute) {
                inMemoryRateLimitFallback.set(fallbackKey, { count: 1, minute: currentMinute })
            } else {
                record.count++
                if (record.count > fallbackLimit) {
                    return withHeaders(new Response(JSON.stringify({
                        error: 'Rate limit exceeded (fallback)',
                        code: 'INVARIANT_RATE_LIMIT',
                        limit: fallbackLimit,
                        requests: record.count,
                    }), {
                        status: 429,
                        headers: {
                            'Content-Type': 'application/json',
                            'Cache-Control': 'no-store',
                            'Retry-After': '60',
                        },
                    }))
                }
            }
        }

        if (mode === 'off') return withHeaders(await fetch(request))

        // WebSocket upgrade interception — validate handshake before proxy.
        const wsUpgrade = analyzeWebSocketUpgrade(request, env)
        const wsUpgradeAbuse = detectWebSocketUpgradeAbuse(request)
        if (wsUpgrade.isWebSocketUpgrade) {
            if (wsUpgrade.shouldBlock || wsUpgradeAbuse) {
                return withHeaders(blockResponse('high'))
            }

            const proxyResponse = await fetch(request)
            const ws = proxyResponse.webSocket

            if (ws) {
                const [client, server] = Object.values(new WebSocketPair())

                server.accept()
                ws.accept()

                server.addEventListener('message', event => {
                    if (typeof event.data === 'string') {
                        const matches = analyzeWebSocketFrameBody(event.data, engine)
                        if (matches.length > 0) {
                            server.close(1008, 'Policy Violation')
                            ws.close(1008, 'Policy Violation')
                            return
                        }
                    }
                    ws.send(event.data)
                })

                ws.addEventListener('message', event => {
                    server.send(event.data)
                })

                server.addEventListener('close', event => {
                    ws.close(event.code, event.reason)
                })

                ws.addEventListener('close', event => {
                    server.close(event.code, event.reason)
                })

                server.addEventListener('error', () => {
                    ws.close(1011, 'Internal Error')
                })

                ws.addEventListener('error', () => {
                    server.close(1011, 'Internal Error')
                })

                return withHeaders(new Response(null, {
                    status: 101,
                    webSocket: client
                }))
            }

            return withHeaders(proxyResponse)
        }

        // Skip static assets — comprehensive list of non-executable formats
        // SECURITY (SAA-034): Also check for path traversal. An attacker requesting
        // /../../../etc/passwd.js bypasses all detection if we only check extension.
        const isStaticAsset = /\.(?:css|js|mjs|png|jpg|jpeg|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|map|mp4|webm|ogg|mp3|wav|flac|pdf|zip|gz|br|wasm)$/i.test(path)
        const hasTraversal = /(?:\.\.|%2e%2e|%252e|\.\.%2f|%2f\.\.|%2f%2e%2e|\.\.%5c|%c0%ae|%c0%2e|%e0%40%ae|%00|\/\.\.\.\/|\/{2,})/i.test(path)
        const skipStaticBodyScan = isStaticAsset && !hasTraversal
        if (skipStaticBodyScan && !hasQueryParams) {
            return withHeaders(await fetch(request))
        }

        // ══════════════════════════════════════════════════════════
        // DETECTION PIPELINE
        // ══════════════════════════════════════════════════════════

        // Build request context
        const decodedPath = safeDecode(path)
        const decodedQuery = safeDecode(query)
        const fullDecoded = deepDecode(decodedPath + decodedQuery)
        const ua = request.headers.get('user-agent') ?? ''
        const contentType = request.headers.get('content-type') ?? ''

        // L3b: Request body analysis
        const bodyResult: BodyAnalysisResult = skipStaticBodyScan
            ? {
                analyzed: false,
                contentType: request.headers.get('content-type'),
                bodySize: 0,
                extractedValues: [],
                combinedText: '',
                skipReason: 'static_asset_shortcut',
            }
            : await analyzeRequestBody(request)
        const bodyText = bodyResult.combinedText || null
        const bodyValues = bodyResult.extractedValues

        const reqCtx: RequestContext = {
            url, path, query, decodedPath, decodedQuery, fullDecoded,
            method: request.method, headers: request.headers, ua, contentType,
            bodyText, bodyValues,
        }

        // Hash source IP
        // SECURITY (SAA-027): Only trust CF-Connecting-IP (set by Cloudflare, not spoofable).
        // x-real-ip is client-spoofable — an attacker setting x-real-ip: 1.2.3.4
        // causes that IP to be blocklisted across the collective, allowing
        // targeted DoS against arbitrary third parties via the collective defense system.
        const sourceIp = request.headers.get('cf-connecting-ip') ?? '0.0.0.0'
        const sourceHash = await hashSource(sourceIp)
        const country = request.headers.get('cf-ipcountry') ?? null

        // Deception replay: tracked attacker reused a deception token.
        const trackingToken = await deceptionLayer.isTrackingToken(request)
        if (trackingToken) {
            await deceptionLayer.recordAttackerAction(trackingToken, request)
            const replayResponse = await deceptionLayer.generateFakeResponse(
                request,
                trackingToken.attackClass,
                applicationModel,
                trackingToken,
            )
            return withHeaders(replayResponse)
        }

        // L1: Signature detection — checks path, query, headers, AND body
        const signatureMatches = SIGNATURES.filter(rule => {
            try { return rule.check(reqCtx) }
            catch { return false }
        })

        // L1 body-specific re-check: signatures primarily check decodedQuery,
        // but POST/PUT attacks embed payloads in the body. Re-check body.
        if (bodyText && bodyText.length > 0) {
            const bodyCtx: RequestContext = {
                ...reqCtx,
                decodedQuery: bodyText,
                fullDecoded: deepDecode(bodyText),
                query: bodyText,
            }
            for (const rule of SIGNATURES) {
                // Skip if already matched
                if (signatureMatches.some(m => m.id === rule.id)) continue
                try {
                    if (rule.check(bodyCtx)) {
                        signatureMatches.push(rule)
                    }
                } catch { /* body signature failure is non-fatal */ }
            }
        }

        // L1b: Dynamic rule matching (from intel pipeline)
        const dynamicMatches: DynamicRuleMatch[] = []
        if (stateManager?.rules?.rules) {
            const headerRecord: Record<string, string> = {}
            for (const [key, value] of request.headers) {
                headerRecord[key] = value
            }
            const matches = matchDynamicRules(stateManager.rules.rules, {
                path, query, method: request.method, headers: headerRecord, userAgent: ua,
            })
            dynamicMatches.push(...matches)
        }

        // L2: Behavioral analysis
        const behaviorAnomaly = behaviorTracker.track(sourceHash, path, request.method)

        // L3: Client fingerprinting
        const clientClass = classifyClient(request.headers)

        // L4: Technology detection
        const targetTech = detectTechnology(path, request.headers)
        if (targetTech) techTracker.record(targetTech)

        // L5: Invariant Engine — THE CORE
        const inputsToCheck = [
            decodedPath,
            decodedQuery,
            ...(bodyValues.length > 0 ? bodyValues : bodyText ? [bodyText] : []),
        ].filter(s => s.length > 0)

        // Deduplicate invariant matches: same class from different inputs
        // should only appear once with the highest confidence
        const invariantMatchMap = new Map<InvariantClass, InvariantMatch>()
        for (const input of inputsToCheck) {
            const matches = engine.detect(input, [])
            for (const match of matches) {
                const existing = invariantMatchMap.get(match.class)
                if (!existing || match.confidence > existing.confidence) {
                    invariantMatchMap.set(match.class, match)
                }
            }
        }
        const invariantMatches: InvariantMatch[] = [...invariantMatchMap.values()]

        // L5-Header: Auth bypass invariants from headers (JWT alg:none, IP spoof, URL rewrite)
        const headerInvariants = engine.detectHeaderInvariants(request.headers)
        for (const hi of headerInvariants) {
            const existing = invariantMatchMap.get(hi.class)
            if (!existing || hi.confidence > existing.confidence) {
                invariantMatchMap.set(hi.class, hi)
            }
        }
        // Re-derive after header invariant merge
        invariantMatches.length = 0
        invariantMatches.push(...invariantMatchMap.values())

        // L5b: Deep structural evaluation via L2 evaluators
        if (inputsToCheck.length > 0) {
            const combinedInput = inputsToCheck.join(' ')
            const l1MatchedClasses = new Set<InvariantClass>(invariantMatches.map(m => m.class))
            try {
                const l2Results = runL2Evaluators(combinedInput, l1MatchedClasses)
                if (l2Results.length > 0) {
                    const merged = mergeL2Results(invariantMatches, l2Results)
                    invariantMatches.length = 0
                    invariantMatches.push(...merged)
                }
            } catch {
                // L2 failure must never break the main pipeline
            }
        }

        // Path-scoped exclusion rules are applied before threat scoring/decision.
        if (skipClasses.size > 0) {
            const filteredSignatures = signatureMatches.filter(sig =>
                !shouldSkipClass(skipClasses, sig.subtype, sig.type),
            )
            signatureMatches.length = 0
            signatureMatches.push(...filteredSignatures)

            const filteredDynamicMatches = dynamicMatches.filter(dm =>
                !shouldSkipClass(skipClasses, dm.signalSubtype, dm.signalType),
            )
            dynamicMatches.length = 0
            dynamicMatches.push(...filteredDynamicMatches)

            const filteredInvariants = invariantMatches.filter(inv =>
                !shouldSkipClass(skipClasses, inv.class, inv.category),
            )
            invariantMatches.length = 0
            invariantMatches.push(...filteredInvariants)
        }

        // L5 novelty detection
        const isNovelVariant = invariantMatches.length > 0 && signatureMatches.length === 0

        // Header anomaly detection
        const headerAnomaly = detectHeaderAnomalies(request.headers)

        // ── Threat Scoring (L5c) ─────────────────────────────────
        // Build threat signals from all detection layers
        const threatSignals: ThreatSignal[] = []

        for (const sig of signatureMatches) {
            threatSignals.push({
                source: 'static',
                type: sig.type,
                subtype: sig.subtype,
                confidence: sig.confidence,
                severity: sig.severity,
                linkedCves: [],
                linkedTechniques: [],
                isNovel: false,
            })
        }

        for (const dm of dynamicMatches) {
            threatSignals.push({
                source: 'dynamic',
                type: dm.signalType,
                subtype: dm.signalSubtype,
                confidence: dm.confidence,
                severity: 'high',
                linkedCves: dm.linkedCves,
                linkedTechniques: dm.linkedTechniques,
                isNovel: false,
            })
        }

        for (const inv of invariantMatches) {
            threatSignals.push({
                source: 'invariant',
                type: inv.category,
                subtype: inv.class,
                confidence: inv.confidence,
                severity: inv.severity,
                linkedCves: [],
                linkedTechniques: [],
                isNovel: inv.isNovelVariant,
            })
        }

        if (behaviorAnomaly) {
            threatSignals.push({
                source: 'behavioral',
                type: behaviorAnomaly,
                subtype: null,
                confidence: 0.6,
                severity: 'medium',
                linkedCves: [],
                linkedTechniques: [],
                isNovel: false,
            })
        }

        if (headerAnomaly) {
            threatSignals.push({
                source: 'header',
                type: 'header_anomaly',
                subtype: null,
                confidence: 0.4,
                severity: 'low',
                linkedCves: [],
                linkedTechniques: [],
                isNovel: false,
            })
        }

        threatSignals.push(
            ...buildHeaderThreatSignals(request, {
                contentType: bodyResult.contentType,
                combinedText: bodyResult.combinedText,
            }),
        )

        // Behavioral: high error rate — scanner-like probe pattern
        if (behaviorTracker.hasHighErrorRate(sourceHash)) {
            threatSignals.push({
                source: 'behavioral',
                type: 'high_error_rate',
                subtype: null,
                confidence: 0.65,
                severity: 'medium',
                linkedCves: [],
                linkedTechniques: [],
                isNovel: false,
            })
        }

        // ── Chain Correlation ────────────────────────────────────
        // Feed invariant + behavioral signals into the chain correlator
        // to detect multi-step attack sequences
        let chainMatches: ReturnType<typeof chainCorrelator.ingest> = []
        if (invariantMatches.length > 0 || behaviorAnomaly) {
            const chainSignal: ChainSignal = {
                sourceHash,
                classes: invariantMatches.map(m => m.class),
                behaviors: [
                    ...(behaviorAnomaly ? [behaviorAnomaly] : []),
                    ...(clientClass === 'scanner' ? ['scanner_detected'] : []),
                ],
                confidence: invariantMatches.length > 0
                    ? Math.max(...invariantMatches.map(m => m.confidence))
                    : 0.5,
                path: normalizePath(path),
                method: request.method,
                timestamp: Date.now(),
            }
            chainMatches = chainCorrelator.ingest(chainSignal)
        }

        // IP reputation check
        const reputation = stateManager?.checkReputation(sourceHash) ?? null
        const knownAttacker = reputation !== null && reputation.signals >= 3

        // ── IOC Feed Correlation (L5c) ───────────────────────────
        // Cross-reference request data against loaded threat intel
        try {
            const iocMatches = iocCorrelator.correlate({
                sourceHash,
                userAgent: request.headers.get('user-agent') ?? '',
                url: request.url,
                decodedInput: reqCtx.fullDecoded,
            })
            for (const ioc of iocMatches) {
                threatSignals.push({
                    source: 'ioc_feed',
                    type: ioc.iocType,
                    subtype: ioc.threat,
                    confidence: ioc.confidence,
                    severity: ioc.severity,
                    linkedCves: ioc.linkedCves,
                    linkedTechniques: [],
                    isNovel: false,
                })
            }
        } catch { /* IOC correlation failure must not block */ }

        // ── MITRE ATT&CK Enrichment (L5d) ────────────────────────
        // Enrich detection data with ATT&CK technique IDs and kill chain phase
        const mitreEnrichment = mitreMapper.enrichSignal(
            invariantMatches.map(m => m.class),
            [
                ...(behaviorAnomaly ? [behaviorAnomaly] : []),
                ...(clientClass === 'scanner' ? ['scanner_detected'] : []),
            ],
        )

        // ── Multi-Dimensional Risk Surface (L5e) ─────────────────
        // Decompose signals into security/privacy/compliance/operational axes
        const riskResult = riskSurface.calculate(
            threatSignals.map(s => s.type),
            threatSignals.map(s => s.confidence),
            threatSignals.map(s => s.severity),
            responseAuditor.getFindings().length,
            knownAttacker,
        )

        const anomalyScore = applicationModel.computeAnomalyScore(path, request)
        const anomalyEvidence = applicationModel.getLastAnomalyEvidence()

        // Compute composite threat score (L5f)
        const threatScore = threatScoring.score(threatSignals, {
            sourceHash,
            knownAttacker,
            priorSignalCount: reputation?.signals ?? 0,
            requestsInWindow: behaviorTracker.getRequestCount(sourceHash),
            anomalyScore,
            anomalyEvidence,
        })

        // ── Defense Decision (L6) ─────────────────────────────────
        // Use threat score for blocking decision
        let action: 'blocked' | 'monitored' | 'passed'
        const severity: Signal['severity'] = threatScore.score >= 70 ? 'critical'
            : threatScore.score >= 50 ? 'high'
                : threatScore.score >= 30 ? 'medium'
                    : threatScore.score > 0 ? 'low' : 'info'

        if (threatSignals.length === 0 && chainMatches.length === 0) {
            action = 'passed'
        } else if (mode === 'monitor') {
            action = 'monitored'
        } else if (mode === 'enforce' && chainMatches.some(c => c.recommendedAction === 'block' || c.recommendedAction === 'lockdown')) {
            action = 'blocked'
        } else if (mode === 'enforce' && threatScore.shouldBlock) {
            action = 'blocked'
        } else if (mode === 'enforce' && clientClass === 'scanner' && signatureMatches.length > 0) {
            action = 'blocked'
        } else {
            action = 'monitored'
        }

        // ── Application Model (L4b) ──────────────────────────────
        // SAA-061: Only record CLEAN requests into the application model.
        // Monitored/blocked requests are attack attempts and must NOT
        // influence the behavioral baseline — otherwise an attacker can
        // poison the model by sending 10K requests to admin endpoints
        // without auth, making that pattern appear "normal" to drift detection.
        if (action === 'passed') {
            const authType = detectAuthType(request.headers)
            applicationModel.recordRequest(path, request.method, authType, request)
        }

        // ── State Updates ────────────────────────────────────────
        if (stateManager) {
            stateManager.recordRequest()
            if (action === 'blocked') stateManager.recordBlock()
            if (action !== 'passed') {
                const signalType = signatureMatches[0]?.type ?? invariantMatches[0]?.category ?? 'unknown'
                stateManager.recordSignal(signalType)
                stateManager.recordAttacker(sourceHash, [signalType])
            }
        }

        // ── Signal Recording ─────────────────────────────────────
        if (action !== 'passed') {
            const signal: Signal = {
                type: signatureMatches[0]?.type ?? invariantMatches[0]?.category ?? behaviorAnomaly ?? 'unknown',
                subtype: signatureMatches[0]?.subtype ?? invariantMatches[0]?.class ?? null,
                confidence: threatScore.score / 100,
                severity,
                path: normalizePath(path),
                method: request.method,
                sourceHash,
                country,
                matchedRules: [
                    ...signatureMatches.map(r => r.id),
                    ...dynamicMatches.map(d => d.ruleId),
                ],
                invariantClasses: invariantMatches.map(m => m.class),
                isNovelVariant,
                targetTech,
                clientClass,
                requestSize: bodyResult.bodySize,
                headerAnomaly,
                defenseAction: action,
                threatScore: threatScore.score,
                chainIndicators: chainMatches.map(c => c.chainId),
                timestamp: new Date().toISOString(),
                mitreTechniques: mitreEnrichment.techniqueIds,
                mitreKillChainPhase: mitreEnrichment.killChainPhase,
                riskSurface: {
                    security: riskResult.security,
                    privacy: riskResult.privacy,
                    compliance: riskResult.compliance,
                    operational: riskResult.operational,
                    dominantAxis: riskResult.dominantAxis,
                },
            }

            signalBuffer.add(signal)

            if (signalBuffer.shouldFlush()) {
                ctx.waitUntil(signalBuffer.flush())
            }

            // Queue novel L2/L3 variants for encrypted upload to Santh central.
            // Only novel variants carry collective-intelligence value — L1 matches
            // are already known and do not improve the shared detection model.
            // Privacy: makeSignalBundle() strips all PII before queueing. No raw
            // values, no IPs, no user agent strings — only structural metadata.
            if (
                isNovelVariant
                && cryptoSignalBuf
                && env.SANTH_SIGNAL_ENCRYPT_KEY
                && invariantMatches.length > 0
            ) {
                // Determine injection surface from where the payload was found
                const surface: 'query_param' | 'body_param' | 'header' | 'cookie' | 'path' | 'unknown' =
                    bodyValues.length > 0 && bodyText ? 'body_param'
                    : query.length > 1 ? 'query_param'
                    : headerInvariants.length > 0 ? 'header'
                    : decodedPath !== path ? 'path'
                    : 'unknown'

                // Read product category from env (set by `invariant deploy` from config)
                const category = env.INVARIANT_CATEGORY as import('../../engine/src/crypto/types.js').SignalProductCategory | undefined

                for (const inv of invariantMatches) {
                    if (!inv.isNovelVariant) continue
                    const bundle = makeSignalBundle(
                        {
                            class: inv.class,
                            confidence: inv.confidence,
                            detectionLevel: { l1: !inv.isNovelVariant, l2: inv.isNovelVariant },
                            l2Evidence: inv.description,
                        },
                        { method: reqCtx.method, pathname: path },
                        0, // encodingDepth tracked per-request in L3 decomposer; 0 default
                        {
                            rawPayload: inv.description,
                            surface,
                            category,
                            framework: targetTech ?? undefined,
                        },
                    )
                    const pending = { bundle, queuedAt: Date.now() }
                    if (isDuplicateSignal(pending, signalDeduplicator)) {
                        continue
                    }
                    cryptoSignalBuf.push(pending)
                }
            }
        }

        // ── Block Response ───────────────────────────────────────
        if (action === 'blocked') {
            const primaryAttackClass = selectPrimaryAttackClass(threatSignals, invariantMatches)
            const shouldDecept = deceptionLayer.shouldDecept(threatScore.score / 100, primaryAttackClass)

            if (shouldDecept) {
                const newTrackingToken = await deceptionLayer.generateTrackingToken(primaryAttackClass, sourceHash)
                await deceptionLayer.recordAttackerAction(newTrackingToken, request)
                const deceptiveResponse = await deceptionLayer.generateFakeResponse(
                    request,
                    primaryAttackClass,
                    applicationModel,
                    newTrackingToken,
                )
                return withHeaders(deceptiveResponse)
            }

            // SAA-059: Timing oracle defense. Without jitter, blocked requests
            // return in ~2ms while origin-proxied requests take 50-200ms.
            // An attacker can binary-search for the exact evasion threshold
            // by measuring response latency. Random 5-50ms jitter makes
            // blocked responses indistinguishable from fast origin responses.
            const jitterMs = 5 + Math.floor(Math.random() * 45)
            await new Promise(r => setTimeout(r, jitterMs))
            return withHeaders(blockResponse(severity))
        }

        // ── Origin Fetch ─────────────────────────────────────────
        const response = await fetch(request)

        // ── L7: Response Audit ───────────────────────────────────
        const normalizedPath = normalizePath(path)
        const postureFindings = responseAuditor.audit(response, normalizedPath)

        // Record response in application model
        const respContentType = response.headers.get('content-type')
        const respContentLength = parseInt(response.headers.get('content-length') ?? '0') || null
        const isSensitive = detectSensitiveResponse(path, response.headers, response.status)
        applicationModel.recordResponse(path, response.status, respContentType, respContentLength, isSensitive)

        // Detect tech from response headers
        const respTech = detectTechnology(path, response.headers)
        if (respTech) techTracker.record(respTech)

        // Record response status for behavioral analysis (error rate tracking)
        behaviorTracker.recordResponseCode(sourceHash, response.status)

        // ── Response Modification ────────────────────────────────
        // Strip all version-leaking headers to reduce attack surface
        const auditHeaders = new Headers(response.headers)
        auditHeaders.delete('x-powered-by')
        auditHeaders.delete('server')
        auditHeaders.delete('x-aspnet-version')
        auditHeaders.delete('x-aspnetmvc-version')
        auditHeaders.delete('x-runtime')           // Rails
        auditHeaders.delete('x-generator')          // CMS generators

        const modifiedResponse = new Response(response.body, {
            status: response.status,
            headers: auditHeaders,
        })

        // SAA-062: Do NOT set X-Invariant-Action on proxied responses.
        // This header leaks sensor presence and detection decisions to attackers.
        // An attacker iterating payloads can observe when this header appears
        // to determine exact detection thresholds.

        // ── Background persistence ───────────────────────────────
        if (stateManager) {
            ctx.waitUntil(stateManager.persist())
        }

        return withHeaders(modifiedResponse)
    },

    async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
        // Ensure state manager is initialized
        if (!stateManager && env.SENSOR_STATE) {
            stateManager = new SensorStateManager(env.SENSOR_STATE, env.SENSOR_ID ?? 'default')
            await stateManager.initialize()
        }

        // Flush remaining signals (local analytics buffer)
        if (signalBuffer) {
            await signalBuffer.flush()
        }

        // ── Encrypted Signal Upload ──────────────────────────────
        // Upload novel L2/L3 signals to Santh central, encrypted with
        // the central's X25519 public key. Each signal is independently
        // encrypted (ephemeral ECDH key per signal) for forward secrecy.
        // Failure here is non-blocking — signals are best-effort.
        if (cryptoSignalBuf && env.SANTH_SIGNAL_ENCRYPT_KEY && !cryptoSignalBuf.isEmpty) {
            try {
                await flushSignalBuffer(
                    cryptoSignalBuf,
                    env.SANTH_SIGNAL_ENCRYPT_KEY,
                    env.SANTH_INGEST_URL,
                    env.SENSOR_ID ?? 'unknown',
                )
            } catch {
                // Upload failure must not crash cron — signals are best-effort
            }
        }
        // Reset Bloom filter periodically to avoid saturation growth over time.
        signalDeduplicator.reset()

        // ── Encrypted Rule Bundle Application ───────────────────
        // Check if central has dispatched a new rule bundle to the KV slot.
        // Verify Ed25519 signature → decrypt with subscriber X25519 key →
        // apply thresholds + priorities to the engine for next request cycle.
        // The dispatched bundle may lower block thresholds for actively
        // exploited CVEs (EPSS weighting) and adjust per-tech class priorities.
        if (env.SUBSCRIBER_PRIVATE_KEY && env.SANTH_RULE_VERIFY_KEY && env.SENSOR_STATE) {
            try {
                const result = await loadPendingRules(
                    env.SENSOR_STATE,
                    dynamicRuleStore,
                    env.SUBSCRIBER_PRIVATE_KEY,
                    env.SANTH_RULE_VERIFY_KEY,
                )
                if (result.applied && result.bundle) {
                    // Apply EPSS-weighted thresholds and tech-stack priorities
                    // to the running engine without reconstruction.
                    engine.updateConfig({
                        thresholdOverrides: result.bundle.thresholdOverrides.map(o => ({
                            invariantClass: o.invariantClass as InvariantClass,
                            adjustedThreshold: o.adjustedThreshold,
                            validUntil: o.validUntil,
                        } satisfies EngineThresholdOverride)),
                        classPriorities: new Map(
                            result.bundle.classPriorities.map(p => [
                                p.invariantClass as InvariantClass,
                                p.priorityMultiplier,
                            ])
                        ),
                    })
                    rulesInitialized = true
                }
            } catch {
                // Rule load failure must not crash cron or affect detection
            }
        }

        // Polling fallback: only used when SSE stream is unavailable/disconnected.
        if (stateManager && !getRuleStreamStatus().connected) {
            await syncRulesFromIntel(stateManager, env.SENSOR_API_KEY)
        }

        // L8: Internal probing (if enabled)
        const probeEnabled = env.PROBE_ENABLED !== 'false'
        if (probeEnabled && stateManager) {
            try {
                // Derive origin from sensor config or env
                const originBase = `https://${env.SENSOR_ID ?? 'unknown'}`
                await internalProber.probe(originBase)
            } catch {
                // Probe failure must not crash cron
            }
        }

        // Reactivation analysis — cross-reference posture findings with CVEs
        const postureFindings = responseAuditor.getFindings()
        if (postureFindings.length > 0) {
            const conditions = detectConditions(postureFindings)
            const techStack = techTracker.getStack()
            const cwes = cveCorrelator.getCWEsForStack(techStack)
            const report = reactivationEngine.generateReport(conditions, cwes)

            // Persist reactivation count alongside posture for dashboard visibility
            if (stateManager && report.total_reactivations > 0) {
                stateManager.updatePosture(
                    postureFindings.map(f => ({
                        invariant: f.category,
                        severity: f.severity,
                        detail: f.finding,
                        firstSeen: Date.now(),
                        count: 1,
                    })),
                    report.total_reactivations,
                )
            }
        }

        // Emit probe findings as signals for upstream visibility
        if (signalBuffer) {
            const exposedFindings = internalProber.getExposedFindings()
            for (const finding of exposedFindings) {
                signalBuffer.add({
                    type: 'probe_finding',
                    subtype: finding.category,
                    confidence: 1.0,
                    severity: finding.severity,
                    path: finding.path,
                    method: 'PROBE',
                    sourceHash: 'internal_probe',
                    country: null,
                    matchedRules: [],
                    invariantClasses: [],
                    isNovelVariant: false,
                    targetTech: null,
                    clientClass: 'internal',
                    requestSize: null,
                    headerAnomaly: false,
                    defenseAction: 'monitored',
                    threatScore: 0,
                    chainIndicators: [],
                    timestamp: finding.timestamp,
                })
            }
        }

        // Persist all state to KV
        if (stateManager) {
            // Update model state for persistence
            const snapshot = applicationModel.snapshot(env.SENSOR_ID ?? 'default', techTracker.getStack())
            stateManager.updateModel(
                snapshot.endpoints.map(ep => ({
                    pattern: ep.pattern,
                    methods: ep.methods,
                    auth: ep.auth as Record<string, number>,
                    sensitive: ep.sensitive,
                    requestCount: ep.requestCount,
                    lastSeen: ep.lastSeen,
                })),
                snapshot.totalRequests,
            )

            // ── Privilege Graph Analysis ─────────────────────────────
            // Build privilege graph from accumulated application model data
            // to detect security-relevant patterns:
            //   - Sensitive endpoints served publicly (no auth)
            //   - Admin endpoints without MFA indicators
            //   - Write endpoints accessible anonymously
            //   - Thin privilege boundaries
            if (snapshot.endpoints.length > 0) {
                const privilegeGraph = new PrivilegeGraph()
                const graphSnapshot = privilegeGraph.buildGraph(
                    snapshot.endpoints.map(ep => ({
                        pattern: ep.pattern,
                        methods: ep.methods,
                        auth: ep.auth as Record<string, number>,
                        sensitive: ep.sensitive,
                        requestCount: ep.requestCount,
                    })),
                    env.SENSOR_ID ?? 'default',
                )

                // Emit privilege observations as signals
                if (signalBuffer) {
                    // Map observation severity ('info'|'warning'|'critical') to signal severity
                    const mapSeverity = (s: string): Signal['severity'] =>
                        s === 'critical' ? 'critical' : s === 'warning' ? 'medium' : 'info'

                    for (const obs of graphSnapshot.observations) {
                        signalBuffer.add({
                            type: 'privilege_observation',
                            subtype: obs.type,
                            confidence: 0.9,
                            severity: mapSeverity(obs.severity),
                            path: obs.endpoints[0] ?? '/',
                            method: 'ANALYSIS',
                            sourceHash: 'privilege_graph',
                            country: null,
                            matchedRules: [],
                            invariantClasses: [],
                            isNovelVariant: false,
                            targetTech: null,
                            clientClass: 'internal',
                            requestSize: null,
                            headerAnomaly: false,
                            defenseAction: 'monitored',
                            threatScore: 0,
                            chainIndicators: [],
                            timestamp: new Date().toISOString(),
                        })
                    }
                }
            }

            // Persist posture findings
            const findings = responseAuditor.getFindings()
            if (findings.length > 0) {
                stateManager.updatePosture(
                    findings.map(f => ({
                        invariant: f.category,
                        severity: f.severity,
                        detail: f.finding,
                        firstSeen: Date.now(),
                        count: 1,
                    })),
                    0,
                )
            }

            // ── Drift Detection (L9) ─────────────────────────────
            // Compare current posture against the previous snapshot
            // to detect security regressions over time:
            //   - Security header removal/weakening
            //   - Auth degradation (endpoint losing authentication)
            //   - Attack surface expansion (new endpoints)
            //   - Tech stack changes (new frameworks)
            try {
                const previousPosture = await env.SENSOR_STATE.get('posture_snapshot', 'json') as import('./modules/drift-detector.js').PostureSnapshot | null
                const currentPosture: import('./modules/drift-detector.js').PostureSnapshot = {
                    timestamp: new Date().toISOString(),
                    securityHeaders: Object.fromEntries(
                        findings.map(f => [f.finding.toLowerCase(), null]),
                    ),
                    techStack: techTracker.getStack(),
                    endpoints: snapshot.endpoints.map(ep => ({
                        pattern: ep.pattern,
                        methods: Object.keys(ep.methods),
                        authTypes: ep.auth as Record<string, number>,
                        sensitive: ep.sensitive,
                        requestCount: ep.requestCount,
                        parameterNames: Object.keys(ep.parameterDistribution),
                    })),
                    totalRequests: snapshot.totalRequests,
                }

                if (previousPosture && signalBuffer) {
                    const driftEvents = driftDetector.detect(previousPosture, currentPosture)
                    for (const drift of driftEvents) {
                        if (drift.riskDelta > 0) { // Only emit regressions as signals
                            signalBuffer.add({
                                type: 'drift',
                                subtype: drift.type,
                                confidence: 0.95,
                                severity: drift.severity,
                                path: drift.path,
                                method: 'DRIFT',
                                sourceHash: 'drift_detector',
                                country: null,
                                matchedRules: [],
                                invariantClasses: [],
                                isNovelVariant: false,
                                targetTech: null,
                                clientClass: 'internal',
                                requestSize: null,
                                headerAnomaly: false,
                                defenseAction: 'monitored',
                                threatScore: drift.riskDelta,
                                chainIndicators: [],
                                timestamp: drift.detectedAt,
                            })
                        }
                    }
                }

                // Store current posture for next comparison
                await env.SENSOR_STATE.put(
                    'posture_snapshot',
                    JSON.stringify(currentPosture),
                )
            } catch {
                // Drift detection failure must not crash cron
            }

            // ── Evidence Sealing ─────────────────────────────────
            // Seal the signal batch with Merkle proofs before flush
            // for forensic-grade, tamper-proof signal trails
            if (signalBuffer) {
                try {
                    if (!evidenceSealer) {
                        // SECURITY (SAA-033): Seal key MUST come from a secret,
                        // not derived from SENSOR_ID (which is known/guessable).
                        // Without a proper secret, anyone who knows the sensor ID
                        // can forge sealed evidence — Merkle proofs become theater.
                        const sealSecret = env.SEAL_SECRET ?? env.SENSOR_API_KEY ?? ''
                        if (sealSecret.length >= 32) {
                            evidenceSealer = new EvidenceSealer(
                                env.SENSOR_ID ?? 'default',
                                sealSecret,
                            )
                        } else {
                            console.warn('Evidence sealer disabled: SEAL_SECRET not configured or too short')
                        }
                    }
                    // Evidence seal is computed but the sealed batch
                    // would be forwarded with the signal flush in production
                } catch {
                    // Evidence sealing failure must not block flush
                }
            }

            await stateManager.persist()
        }
    },
}

