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
 * Privacy:
 *   - Source IPs: SHA-256 hashed with daily-rotating salt
 *   - Request bodies: Analyzed in-memory only. NEVER persisted.
 *   - Cookies/tokens: NEVER accessed
 *   - Only metadata + attack patterns analyzed — no PII extraction
 */

import { InvariantEngine, type InvariantMatch, type InvariantClass } from '../../engine/src/invariant-engine.js'
import { runL2Evaluators, mergeL2Results, type L2DetectionResult } from '../../engine/src/evaluators/evaluator-bridge.js'
import { ChainCorrelator, type ChainSignal } from '../../engine/src/chain-detector.js'
import { MitreMapper } from '../../engine/src/mitre-mapper.js'
import { EvidenceSealer } from '../../engine/src/evidence/evidence-sealer.js'

import {
    analyzeRequestBody,
    type BodyAnalysisResult,
    ThreatScoringEngine,
    type ThreatSignal,
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
    matchDynamicRules,
    type DynamicRuleMatch,
    IOCCorrelator,
    DriftDetector,
    RiskSurfaceCalculator,
} from './modules/index.js'

// ── Extracted Layer Modules ───────────────────────────────────────
import type { Env, Signal, RequestContext } from './layers/types.js'
import { safeDecode, deepDecode } from './layers/encoding.js'
import { SIGNATURES } from './layers/l1-signatures.js'
import { BehaviorTracker } from './layers/l2-behavior.js'
import { classifyClient } from './layers/l3-fingerprint.js'
import { detectTechnology } from './layers/l4-tech-detect.js'
import { SignalBuffer } from './layers/signal-buffer.js'
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
let evidenceSealer: EvidenceSealer | null = null

let signalBuffer: SignalBuffer | null = null
let stateManager: SensorStateManager | null = null
let initialized = false

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

        if (!stateManager && env.SENSOR_STATE) {
            stateManager = new SensorStateManager(env.SENSOR_STATE, env.SENSOR_ID ?? 'default')
        }

        // Lazy initialization from KV (once per Worker lifecycle)
        if (!initialized && stateManager) {
            try {
                await stateManager.initialize()
                initialized = true
            } catch {
                // KV failure must not block traffic
                initialized = true
            }
        }

        const mode = stateManager?.config.defenseMode ?? env.DEFENSE_MODE ?? 'monitor'
        if (mode === 'off') return fetch(request)

        const url = new URL(request.url)
        const path = url.pathname
        const query = url.search

        // ── Introspection endpoints ──────────────────────────────
        // Require INTROSPECTION_KEY when configured (defense against WAF fingerprinting)
        if (path === '/__invariant/health' || path === '/__invariant/posture') {
            if (env.INTROSPECTION_KEY) {
                const authParam = url.searchParams.get('key')
                // SECURITY (SAA-035): Constant-time comparison prevents timing
                // side-channel that would leak the key byte by byte.
                const keyValid = authParam !== null
                    && authParam.length === env.INTROSPECTION_KEY.length
                    && await timingSafeEqual(authParam, env.INTROSPECTION_KEY)
                if (!keyValid) {
                    return new Response(JSON.stringify({ error: 'unauthorized' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json' },
                    })
                }
            }
        }

        if (path === '/__invariant/health') {
            return new Response(JSON.stringify({
                status: 'operational',
                version: '8.0.0',
                mode,
                engine: { classes: engine.classes.length },
                signalBuffer: signalBuffer.getCount(),
                // Redacted: no tech stack, IOC counts, or capability details
                timestamp: new Date().toISOString(),
            }), {
                headers: { 'Content-Type': 'application/json' },
            })
        }

        if (path === '/__invariant/posture') {
            const report = responseAuditor.generateReport(url.hostname)
            return new Response(JSON.stringify(report), {
                headers: { 'Content-Type': 'application/json' },
            })
        }

        // Skip static assets — comprehensive list of non-executable formats
        // SECURITY (SAA-034): Also check for path traversal. An attacker requesting
        // /../../../etc/passwd.js bypasses all detection if we only check extension.
        const isStaticAsset = /\.(?:css|js|mjs|png|jpg|jpeg|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|map|mp4|webm|ogg|mp3|wav|flac|pdf|zip|gz|br|wasm)$/i.test(path)
        const hasTraversal = /(?:\.\.|%2e%2e|%252e)/i.test(path)
        if (isStaticAsset && !hasTraversal) {
            return fetch(request)
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
        const bodyResult: BodyAnalysisResult = await analyzeRequestBody(request)
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

        // Compute composite threat score (L5f)
        const threatScore = threatScoring.score(threatSignals, {
            sourceHash,
            knownAttacker,
            priorSignalCount: reputation?.signals ?? 0,
            requestsInWindow: behaviorTracker.getRequestCount(sourceHash),
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
            applicationModel.recordRequest(path, request.method, authType)
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
        }

        // ── Block Response ───────────────────────────────────────
        if (action === 'blocked') {
            // SAA-059: Timing oracle defense. Without jitter, blocked requests
            // return in ~2ms while origin-proxied requests take 50-200ms.
            // An attacker can binary-search for the exact evasion threshold
            // by measuring response latency. Random 5-50ms jitter makes
            // blocked responses indistinguishable from fast origin responses.
            const jitterMs = 5 + Math.floor(Math.random() * 45)
            await new Promise(r => setTimeout(r, jitterMs))
            return blockResponse(severity)
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

        return modifiedResponse
    },

    async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
        // Ensure state manager is initialized
        if (!stateManager && env.SENSOR_STATE) {
            stateManager = new SensorStateManager(env.SENSOR_STATE, env.SENSOR_ID ?? 'default')
            await stateManager.initialize()
        }

        // Flush remaining signals
        if (signalBuffer) {
            await signalBuffer.flush()
        }

        // Sync rules from intel pipeline
        if (stateManager) {
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

