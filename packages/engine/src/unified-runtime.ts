/**
 * INVARIANT — Unified Detection Runtime
 *
 * The closed-loop orchestrator that connects ALL subsystems into a single
 * coherent pipeline. This is what turns INVARIANT from a collection of
 * detection modules into a unified defense system.
 *
 * Pipeline:
 *   1. INPUT → InvariantEngine.analyze() → matches, compositions, block recommendation
 *   2. MATCHES → ChainCorrelator.ingest() → attack chain detection
 *   3. MATCHES → CampaignIntelligence.recordSignal() → behavioral fingerprinting
 *   4. CHAIN + CAMPAIGN → threat level calculation → defense decision
 *   5. MATCHES → ExploitKnowledgeGraph.enrichDetection() → CVE correlation
 *   6. ALL SIGNALS → EvidenceSealer.seal() → forensic evidence
 *   7. HIGH-CONFIDENCE → ExploitVerifier.verify() → confirmation (async, optional)
 *   8. FEEDBACK → learning loop → calibration updates
 *
 * This is the system a nation-state attacker faces.
 * Not a regex. Not a WAF. A coordinated defense intelligence platform.
 *
 * Memory model:
 *   - ChainCorrelator: 5,000 source windows × 200 signals = bounded
 *   - CampaignIntelligence: 10,000 sessions × behavioral fingerprints = bounded
 *   - EvidenceSealer: batched, written to disk, not retained
 *   - Knowledge graph: static, shared, read-only after init
 */

import { InvariantEngine, type DeepDetectionResult } from './invariant-engine.js'
import { ChainCorrelator, type ChainSignal, type ChainMatch } from './chain-detector.js'
import { CampaignIntelligence, type CampaignSignal, type Campaign } from './decomposition/campaign-intelligence.js'
import { ExploitKnowledgeGraph } from './decomposition/exploit-knowledge-graph.js'
import { ExploitVerifier, type VerificationResult } from './decomposition/exploit-verifier.js'
import { EvidenceSealer, type SealedBatch } from './evidence/index.js'
import { MitreMapper } from './mitre-mapper.js'
import {
    simulateSqlEffect,
    simulateCmdEffect,
    simulateXssEffect,
    simulatePathEffect,
    simulateSsrfEffect,
    fingerprintAdversary,
    type ExploitEffect,
    type AdversaryFingerprint,
} from './evaluators/effect-simulator.js'
import { autoValidateShape, type ShapeValidation } from './evaluators/input-shape-validator.js'
import { generateResponsePlan, type ResponsePlan } from './evaluators/response-recommender.js'
import type {
    InvariantClass,
    InvariantMatch,
    AnalysisRequest,
    AnalysisResult,
    BlockRecommendation,
    PropertyProof,
} from './classes/types.js'


// ═══════════════════════════════════════════════════════════════════
// UNIFIED TYPES
// ═══════════════════════════════════════════════════════════════════

/**
 * A request to the unified runtime. Extends AnalysisRequest with
 * source attribution, request metadata, and optional verification control.
 */
export interface UnifiedRequest {
    /** The input string to analyze (URL-decoded body, query parameter, etc.) */
    input: string
    /** Source identifier — hashed IP, session ID, API key hash */
    sourceHash: string
    /** Request metadata for context-aware detection */
    request: {
        method: string
        path: string
        contentType?: string
        headers?: Headers
    }
    /** Known execution context (if determinable from application layer) */
    knownContext?: string
    /** Source reputation score (0 = unknown, 1 = known hostile) */
    sourceReputation?: number
    /** Detected technology stack (from fingerprinting or config) */
    detectedTech?: { vendor: string; product: string; framework?: string; version?: string }
    /** Parameter name (for input shape validation, e.g., "email", "username", "page") */
    paramName?: string
    /** Whether to attempt exploit verification (requires fetch function) */
    verify?: boolean
    /** Timestamp override (default: Date.now()) */
    timestamp?: number
}

/**
 * The unified response from the runtime. Contains everything
 * the defense layer needs to make a decision AND everything
 * the forensics layer needs for evidence.
 */
export interface UnifiedResponse {
    // ── Detection ──
    /** Raw analysis from the detection engine */
    analysis: AnalysisResult
    /** Highest severity match */
    highestSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info'

    // ── Temporal Correlation ──
    /** Attack chain matches from this signal */
    chainMatches: ChainMatch[]
    /** Active campaigns this source is part of */
    activeCampaign: Campaign | null
    /** Attack phase of this source (recon → weaponize → deliver → exploit → etc.) */
    attackPhase: string | null
    /** Campaign-level threat score for this source (0-10) */
    threatLevel: number

    // ── CVE Intelligence ──
    /** Total CVEs linked to detected classes */
    linkedCveCount: number
    /** Actively exploited CVEs among detections */
    activelyExploitedCves: string[]
    /** Highest EPSS score among linked CVEs */
    highestEpss: number

    // ── Defense Decision ──
    /** The unified defense decision (supersedes per-match recommendations) */
    decision: DefenseDecision
    /** MITRE ATT&CK techniques mapped from all detections */
    mitreTechniques: string[]

    // ── Forensics ──
    /** Sealed evidence batch (null if no matches) */
    sealedEvidence: SealedBatch | null

    // ── Verification ──
    /** Exploit verification result (null if not requested or not applicable) */
    verification: VerificationResult | null

    // ── Effect Simulation ──
    /** Simulated exploit effect (what would happen if the attack succeeded) */
    effectSimulation: ExploitEffect | null
    /** Adversary fingerprint (tool, skill level, automation) */
    adversaryFingerprint: AdversaryFingerprint | null
    /** Input shape validation result (null if param name not provided) */
    shapeValidation: ShapeValidation | null
    /** Incident response plan with containment/investigation/remediation recommendations */
    responsePlan: ResponsePlan | null

    // ── Performance ──
    /** Total pipeline processing time in microseconds */
    totalProcessingTimeUs: number
}

/**
 * The unified defense decision. This is the single output the
 * application layer consumes to decide how to handle the request.
 */
export interface DefenseDecision {
    /** What to do */
    action: 'allow' | 'monitor' | 'throttle' | 'challenge' | 'block' | 'lockdown'
    /** Why */
    reason: string
    /** Confidence in this decision (0-1) */
    confidence: number
    /** Which signals contributed to this decision */
    contributors: string[]
    /** Urgency — should this trigger an immediate alert? */
    alert: boolean
    /** Suggested response headers */
    responseHeaders?: Record<string, string>
    /** Proof summary from the highest-confidence detection (if available) */
    proofSummary?: {
        domain: string
        isComplete: boolean
        stepCount: number
        proofConfidence: number
    }
}

export interface UnifiedRuntimeErrorLogEntry {
    timestamp: number
    source: string
    error: string
}

export class UnifiedRuntimeError extends Error {
    readonly code: string

    constructor(code: string, message: string) {
        super(message)
        this.name = 'UnifiedRuntimeError'
        this.code = code
    }
}


// ═══════════════════════════════════════════════════════════════════
// DATA-DRIVEN ROUTING TABLES
// ═══════════════════════════════════════════════════════════════════

// ── Effect Simulation Routes ─────────────────────────────────────
//
// Maps invariant classes to exploit effect simulators.
// First matching route wins (ordered by severity/priority).
// Adding a new simulator = adding one entry here.

interface EffectRoute {
    classes: InvariantClass[]
    simulate: (input: string, proof?: PropertyProof | null) => ExploitEffect
}

const EFFECT_ROUTES: readonly EffectRoute[] = [
    // SQL injection — covers all SQL classes
    {
        classes: [
            'sql_tautology', 'sql_union_extraction', 'sql_stacked_execution',
            'sql_time_oracle', 'sql_error_oracle', 'sql_string_termination',
            'sql_comment_truncation', 'json_sql_bypass',
        ] as InvariantClass[],
        simulate: (input, proof) => simulateSqlEffect(input, undefined, proof ?? undefined),
    },
    // Command injection
    {
        classes: ['cmd_separator', 'cmd_substitution', 'cmd_argument_injection'] as InvariantClass[],
        simulate: (input, proof) => simulateCmdEffect(input, proof ?? undefined),
    },
    // XSS
    {
        classes: [
            'xss_tag_injection', 'xss_event_handler', 'xss_protocol_handler',
            'xss_attribute_escape', 'xss_template_expression',
        ] as InvariantClass[],
        simulate: (input, proof) => simulateXssEffect(input, proof ?? undefined),
    },
    // Path traversal
    {
        classes: [
            'path_dotdot_escape', 'path_encoding_bypass',
            'path_null_terminate', 'path_normalization_bypass',
        ] as InvariantClass[],
        simulate: (input, proof) => simulatePathEffect(input, proof ?? undefined),
    },
    // SSRF
    {
        classes: [
            'ssrf_internal_reach', 'ssrf_cloud_metadata', 'ssrf_protocol_smuggle',
        ] as InvariantClass[],
        simulate: (input, proof) => simulateSsrfEffect(input, proof ?? undefined),
    },
]

// ── Behavior Derivation Rules ────────────────────────────────────
//
// Data-driven behavior signal derivation.
// Three rule types:
//   1. CLASS_BEHAVIORS: class match → emit behaviors (unconditional)
//   2. CONTENT_BEHAVIORS: class match + input content → emit behaviors
//   3. PATH_BEHAVIORS: path match → emit behaviors (no class required)
//
// Adding a new behavior signal = adding one entry.
// Zero changes to deriveBehaviors().

interface ClassBehaviorRule {
    /** At least one of these classes must be detected (OR) */
    classes: string[]
    /** Behaviors to emit */
    behaviors: string[]
}

interface ContentBehaviorRule {
    /** At least one of these classes must be detected (OR) */
    classes: string[]
    /** Input must contain at least one of these strings (case-insensitive) */
    patterns: string[]
    /** Behaviors to emit when both class and content match */
    behaviors: string[]
}

interface PathBehaviorRule {
    /** Path must start with one of these prefixes */
    pathPrefixes: string[]
    /** Behaviors to emit when path matches */
    behaviors: string[]
}

const CLASS_BEHAVIORS: readonly ClassBehaviorRule[] = [
    // Privilege escalation
    { classes: ['mass_assignment', 'auth_none_algorithm'], behaviors: ['privilege_escalation'] },
    // Property injection
    { classes: ['proto_pollution', 'proto_pollution_gadget'], behaviors: ['property_injection'] },
    // Cloud credential extraction
    { classes: ['ssrf_cloud_metadata'], behaviors: ['credential_extraction'] },
    // JNDI class loading
    { classes: ['log_jndi_lookup'], behaviors: ['outbound_connection', 'class_loading'] },
    // JWT / auth bypass
    { classes: ['jwt_kid_injection', 'jwt_jwk_embedding', 'jwt_confusion', 'auth_none_algorithm'], behaviors: ['auth_bypass', 'token_forgery'] },
    // Credential stuffing / auth automation
    { classes: ['credential_stuffing'], behaviors: ['auth_bypass', 'brute_force'] },
    // Cache manipulation
    { classes: ['cache_poisoning', 'cache_deception'], behaviors: ['cache_manipulation'] },
    // Authorization bypass
    { classes: ['bola_idor'], behaviors: ['authorization_bypass'] },
    // Data exfiltration / enumeration
    { classes: ['api_mass_enum'], behaviors: ['data_exfiltration', 'enumeration'] },
    // LLM instruction override
    { classes: ['llm_prompt_injection', 'llm_jailbreak'], behaviors: ['instruction_override'] },
    // LLM data exfiltration
    { classes: ['llm_data_exfiltration'], behaviors: ['data_exfiltration'] },
    // Supply chain compromise
    { classes: ['dependency_confusion', 'postinstall_injection'], behaviors: ['supply_chain_compromise'] },
    // Env credential extraction
    { classes: ['env_exfiltration'], behaviors: ['credential_extraction', 'data_exfiltration'] },
    // WebSocket abuse
    { classes: ['ws_injection', 'ws_hijack'], behaviors: ['websocket_abuse'] },
    // HTTP smuggling
    { classes: ['http_smuggle_cl_te', 'http_smuggle_h2', 'http_smuggle_chunk_ext', 'http_smuggle_zero_cl', 'http_smuggle_expect'], behaviors: ['request_smuggling'] },
    // Deserialization
    { classes: ['deser_java_gadget', 'deser_php_object', 'deser_python_pickle'], behaviors: ['code_execution'] },
]

const CONTENT_BEHAVIORS: readonly ContentBehaviorRule[] = [
    // Credential file targeting via path traversal
    {
        classes: ['path_dotdot_escape', 'path_encoding_bypass', 'path_null_terminate', 'path_normalization_bypass'],
        patterns: [
            '.env', 'passwd', 'shadow', 'id_rsa', 'id_ed25519',
            '.ssh', '.git/config', '.aws/credentials', '.docker/config',
            'wp-config.php', 'database.yml', 'application.properties',
            '.htpasswd', 'web.config', 'appsettings.json',
        ],
        behaviors: ['credential_extraction', 'path_sensitive_file'],
    },
    // Cookie / session exfiltration via XSS
    {
        classes: ['xss_tag_injection', 'xss_event_handler', 'xss_protocol_handler', 'xss_attribute_escape'],
        patterns: ['document.cookie', 'localstorage', 'sessionstorage'],
        behaviors: ['cookie_exfil'],
    },
    // Reverse shell indicators via command injection
    {
        classes: ['cmd_separator', 'cmd_substitution', 'cmd_argument_injection'],
        patterns: [
            '/bin/bash', '/bin/sh', 'nc ', 'ncat ', 'netcat',
            'mkfifo', '/dev/tcp', 'python -c', 'perl -e',
            'php -r', 'ruby -e', 'socat', 'curl|sh', 'wget -q',
        ],
        behaviors: ['reverse_shell', 'outbound_connection'],
    },
    // SSTI class traversal
    {
        classes: ['ssti_jinja_twig', 'ssti_el_expression', 'template_injection_generic'],
        patterns: ['__class__', '__mro__', '__subclasses__', '__globals__'],
        behaviors: ['class_traversal'],
    },
    // SSTI code execution
    {
        classes: ['ssti_jinja_twig', 'ssti_el_expression', 'template_injection_generic'],
        patterns: ['.exec(', 'popen(', 'getruntime(', 'processbuilder(', 'runtime.exec('],
        behaviors: ['code_execution'],
    },
    // XXE out-of-band
    {
        classes: ['xxe_entity_expansion'],
        patterns: ['http://', 'https://', 'ftp://', 'gopher://'],
        behaviors: ['outbound_connection'],
    },
]

const PATH_BEHAVIORS: readonly PathBehaviorRule[] = [
    {
        pathPrefixes: ['/admin', '/wp-admin', '/dashboard', '/manager', '/console', '/actuator', '/phpmyadmin'],
        behaviors: ['admin_access'],
    },
    {
        pathPrefixes: ['/api/v1/', '/api/v2/', '/graphql', '/rest/'],
        behaviors: ['api_targeting'],
    },
]


// ═══════════════════════════════════════════════════════════════════
// UNIFIED RUNTIME
// ═══════════════════════════════════════════════════════════════════

export class UnifiedRuntime {
    readonly engine: InvariantEngine
    readonly chains: ChainCorrelator
    readonly campaigns: CampaignIntelligence
    readonly knowledgeGraph: ExploitKnowledgeGraph
    readonly verifier: ExploitVerifier
    readonly mitre: MitreMapper
    private sealer: EvidenceSealer | null = null
    private readonly errorLog: UnifiedRuntimeErrorLogEntry[] = []

    constructor(options?: {
        sensorId?: string
        signingKey?: string
        probeLevel?: 'off' | 'passive' | 'active' | 'aggressive'
    }) {
        this.engine = new InvariantEngine()
        this.chains = new ChainCorrelator()
        this.campaigns = new CampaignIntelligence()
        this.knowledgeGraph = this.engine.knowledgeGraph
        this.verifier = new ExploitVerifier(options?.probeLevel ?? 'off')
        this.mitre = new MitreMapper()

        if (options?.sensorId && options?.signingKey) {
            this.sealer = new EvidenceSealer(options.sensorId, options.signingKey)
        }
    }

    getErrorLog(): readonly UnifiedRuntimeErrorLogEntry[] {
        return this.errorLog
    }

    private recordError(source: string, error: unknown): void {
        const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error)
        this.errorLog.push({ timestamp: Date.now(), source, error: message })
        if (this.errorLog.length > 100) this.errorLog.shift()
    }

    /**
     * Process a request through the full unified pipeline.
     *
     * This is the single entry point for ALL detection, correlation,
     * intelligence, and defense decision-making.
     *
     * Latency budget:
     *   - L1+L2+L3 detection: <5ms
     *   - Chain correlation: <1ms
     *   - Campaign intelligence: <1ms  
     *   - CVE enrichment: <1ms
     *   - Evidence sealing: <2ms (async, non-blocking)
     *   - Total synchronous path: <10ms
     *
     * Verification is async and NOT on the hot path.
     */
    async process(request: UnifiedRequest): Promise<UnifiedResponse> {
        try {
            const pipelineStart = performance.now()
            const core = this.runCorePipeline(request)
            const timestamp = request.timestamp ?? Date.now()

            // ── Evidence Sealing (async, non-blocking) ──
            let sealedEvidence: SealedBatch | null = null
            if (this.sealer && core.analysis.matches.length > 0) {
                try {
                    const evidencePayload = core.analysis.matches.map(m => ({
                        timestamp: new Date(timestamp).toISOString(),
                        class: m.class,
                        confidence: m.confidence,
                        severity: m.severity,
                        sourceHash: request.sourceHash,
                        path: request.request.path,
                        method: request.request.method,
                        l2Evidence: m.l2Evidence ?? null,
                        chainContext: core.chainMatches.length > 0
                            ? core.chainMatches[0].chainId : null,
                        decision: core.decision.action,
                    }))
                    sealedEvidence = await this.sealer.seal(evidencePayload)
                } catch (error) {
                    // Evidence sealing failure MUST NOT block the pipeline
                    this.recordError('process.seal', error)
                }
            }

            // Verification is intentionally NOT wired here because it requires
            // a fetch function and origin URL from the caller.

            return {
                ...core,
                sealedEvidence,
                verification: null,
                totalProcessingTimeUs: (performance.now() - pipelineStart) * 1000,
            }
        } catch (error) {
            this.recordError('process.boundary', error)
            throw new UnifiedRuntimeError('UNIFIED_RUNTIME_PROCESS_FAILED', 'Unified runtime processing failed')
        }
    }

    /**
     * Synchronous fast path for hot-loop detection without async overhead.
     * Runs L1+L2+L3 + chain correlation + campaign tracking + defense decision.
     * No evidence sealing, no verification.
     */
    processSync(request: UnifiedRequest): Omit<UnifiedResponse, 'sealedEvidence' | 'verification'> & { sealedEvidence: null; verification: null } {
        try {
            const pipelineStart = performance.now()
            const core = this.runCorePipeline(request)

            return {
                ...core,
                sealedEvidence: null,
                verification: null,
                totalProcessingTimeUs: (performance.now() - pipelineStart) * 1000,
            }
        } catch (error) {
            this.recordError('processSync.boundary', error)
            throw new UnifiedRuntimeError('UNIFIED_RUNTIME_PROCESS_SYNC_FAILED', 'Unified runtime processing failed')
        }
    }

    /**
     * Core pipeline shared between process() and processSync().
     * Contains ALL detection, correlation, intelligence, and decision logic.
     * Evidence sealing and verification are handled by callers.
     */
    private runCorePipeline(request: UnifiedRequest): Omit<UnifiedResponse, 'sealedEvidence' | 'verification' | 'totalProcessingTimeUs'> {
        // ── Step 1: Core Detection (L1 + L2 + L3 + compositions + correlations) ──
        const analysis = this.engine.analyze({
            input: request.input,
            knownContext: request.knownContext,
            sourceReputation: request.sourceReputation,
            requestMeta: {
                method: request.request.method,
                path: request.request.path,
                contentType: request.request.contentType,
            },
        })

        let headerMatches: InvariantMatch[] = []
        if (request.request.headers) {
            headerMatches = this.engine.detectHeaderInvariants(request.request.headers)
        }
        const allMatches = [...analysis.matches, ...headerMatches]

        const timestamp = request.timestamp ?? Date.now()

        // ── Step 2: Temporal Correlation — Chain Detection ──
        const chainSignal: ChainSignal = {
            sourceHash: request.sourceHash,
            classes: allMatches.map(m => m.class),
            behaviors: this.deriveBehaviors(allMatches, request, analysis),
            confidence: allMatches.length > 0
                ? Math.max(...allMatches.map(m => m.confidence))
                : 0,
            path: request.request.path,
            method: request.request.method,
            timestamp,
        }

        let chainMatches: ChainMatch[] = []
        if (allMatches.length > 0 || chainSignal.behaviors.length > 0) {
            chainMatches = this.chains.ingest(chainSignal)
        }

        // ── Step 3: Campaign Intelligence — Behavioral Fingerprinting ──
        if (allMatches.length > 0) {
            const campaignSignal: CampaignSignal = {
                type: allMatches[0].class,
                timestamp,
                confidence: allMatches[0].confidence,
                path: request.request.path,
                sourceHash: request.sourceHash,
                encoding: this.detectEncoding(request.input),
            }
            this.campaigns.recordSignal(campaignSignal)
        }

        const threatLevel = this.campaigns.getThreatLevel(request.sourceHash)
        const attackPhase = this.campaigns.getAttackPhase(request.sourceHash)
        const activeCampaign = this.campaigns.isPartOfCampaign(request.sourceHash)

        // ── Step 4: CVE Intelligence ──
        const allLinkedCves: string[] = []
        const activelyExploitedCves: string[] = []
        let highestEpss = 0
        for (const match of allMatches) {
            if (match.cveEnrichment) {
                allLinkedCves.push(...match.cveEnrichment.linkedCves)
                if (match.cveEnrichment.activelyExploited) {
                    activelyExploitedCves.push(...match.cveEnrichment.linkedCves)
                }
                if (match.cveEnrichment.highestEpss > highestEpss) {
                    highestEpss = match.cveEnrichment.highestEpss
                }
            }
        }

        // ── Step 5: MITRE ATT&CK Mapping ──
        const mitreTechniques = this.mitre.mapDetections(allMatches)

        // ── Step 6: Effect Simulation ──
        // Simulate what the attack would DO if it succeeded.
        // Routes to the simulator whose matching class has the HIGHEST
        // confidence — the most certain detection drives the simulation.
        // Uses data-driven EFFECT_ROUTES — adding a new simulator = one table entry.
        let effectSimulation: ExploitEffect | null = null
        if (allMatches.length > 0) {
            const topMatch = allMatches.reduce((best, current) =>
                current.confidence > best.confidence ? current : best,
            allMatches[0])
            const topProof = topMatch?.proof ?? null
            const classSet = new Set(allMatches.map(m => m.class))
            let bestRoute: EffectRoute | null = null
            let bestConfidence = 0
            try {
                for (const route of EFFECT_ROUTES) {
                    for (const cls of route.classes) {
                        if (classSet.has(cls)) {
                            const match = allMatches.find(m => m.class === cls)
                            if (match && match.confidence > bestConfidence) {
                                bestRoute = route
                                bestConfidence = match.confidence
                            }
                        }
                    }
                }
                if (bestRoute) {
                    effectSimulation = bestRoute.simulate(request.input, topProof)
                }
            } catch (error) {
                this.recordError('runCorePipeline.effectSimulation', error)
            }
        }

        // ── Step 6b: Adversary Fingerprinting ──
        let adversaryFingerprint: AdversaryFingerprint | null = null
        if (allMatches.length > 0) {
            try {
                adversaryFingerprint = fingerprintAdversary(
                    request.input,
                    allMatches.map(m => m.class),
                )
            } catch (error) {
                this.recordError('runCorePipeline.fingerprinting', error)
            }
        }

        // ── Step 6c: Input Shape Validation ──
        let shapeValidation: ShapeValidation | null = null
        if (request.paramName) {
            try {
                shapeValidation = autoValidateShape(request.input, request.paramName)
            } catch (error) {
                this.recordError('runCorePipeline.shapeValidation', error)
            }
        }

        // ── Step 7: Unified Defense Decision ──
        const decision = this.makeDefenseDecision(
            analysis,
            allMatches,
            chainMatches,
            threatLevel,
            activeCampaign,
            activelyExploitedCves,
        )

        // ── Proof enrichment — attach proof evidence to ANY block/lockdown decision ──
        if ((decision.action === 'block' || decision.action === 'lockdown') && allMatches.length > 0) {
            const topProofMatch = allMatches
                .filter(m => m.proof && m.proof.steps.length > 0)
                .sort((a, b) => b.confidence - a.confidence)[0]
            if (topProofMatch?.proof) {
                const proofSummary = topProofMatch.proof.steps
                    .map(s => `${s.operation}(${s.input.slice(0, 30)} @${s.offset})`)
                    .join(' → ')
                if (!decision.reason.includes('PROOF')) {
                    decision.reason = `${decision.reason} [PROOF: ${proofSummary}]`
                }
                if (!decision.contributors.some(c => c.startsWith('proof:'))) {
                    decision.contributors.push(`proof:${topProofMatch.proof.domain}:${topProofMatch.proof.isComplete ? 'complete' : 'partial'}`)
                }
                if (!decision.proofSummary) {
                    decision.proofSummary = {
                        domain: topProofMatch.proof.domain,
                        isComplete: topProofMatch.proof.isComplete,
                        stepCount: topProofMatch.proof.steps.length,
                        proofConfidence: topProofMatch.proof.proofConfidence,
                    }
                }
            }
        }

        // Escalate based on effect simulation — high-impact effects force alert
        if (effectSimulation && effectSimulation.impact.baseScore >= 9.0 && !decision.alert) {
            decision.alert = true
            decision.contributors.push(`effect:${effectSimulation.operation}:impact_${effectSimulation.impact.baseScore.toFixed(1)}`)
        }

        // Shape violation can tighten the decision
        if (shapeValidation && !shapeValidation.matches && shapeValidation.confidenceBoost > 0) {
            decision.confidence = Math.min(0.99, decision.confidence + shapeValidation.confidenceBoost)
            decision.contributors.push(`shape_violation:${request.paramName}:deviation_${shapeValidation.deviation.toFixed(2)}`)
        }

        // ── Step 8: Incident Response Plan ──
        let responsePlan: ResponsePlan | null = null
        if (allMatches.length > 0) {
            try {
                responsePlan = generateResponsePlan(
                    allMatches,
                    effectSimulation,
                    adversaryFingerprint,
                    chainMatches,
                    {
                        method: request.request.method,
                        path: request.request.path,
                        sourceHash: request.sourceHash,
                    },
                )
            } catch (error) {
                this.recordError('runCorePipeline.responsePlan', error)
            }
        }

        return {
            analysis: { ...analysis, matches: allMatches },
            highestSeverity: this.engine.highestSeverity(allMatches),
            chainMatches,
            activeCampaign,
            attackPhase: attackPhase ? String(attackPhase) : null,
            threatLevel,
            linkedCveCount: new Set(allLinkedCves).size,
            activelyExploitedCves: [...new Set(activelyExploitedCves)],
            highestEpss,
            decision,
            mitreTechniques,
            effectSimulation,
            adversaryFingerprint,
            shapeValidation,
            responsePlan,
        }
    }

    // ── Defense Decision Engine ───────────────────────────────────────

    /**
     * Make the unified defense decision by considering ALL intelligence
     * sources simultaneously. This is NOT a simple threshold check.
     *
     * Decision hierarchy:
     *   1. Completed critical chain → lockdown (always)
     *   2. Actively exploited CVE + high confidence match → block
     *   3. Campaign member + detection → escalate (block if medium→high)
     *   4. High threat level source + any detection → block
     *   5. Chain in progress (≥66%) → block
     *   6. Chain in progress (≥50%) → challenge
     *   7. Polyglot attack (multi-context) → block/challenge
     *   7b. Encoding evasion + detection → block
     *   8. Analysis block recommendation → block
     *   9. Low confidence / no chains / new source → standard threshold
     */
    private makeDefenseDecision(
        analysis: AnalysisResult,
        matches: InvariantMatch[],
        chainMatches: ChainMatch[],
        threatLevel: number,
        activeCampaign: Campaign | null,
        activelyExploitedCves: string[],
    ): DefenseDecision {
        const contributors: string[] = []

        // ── 1. Completed critical chain → instant lockdown ──
        const completedCritical = chainMatches.find(
            c => c.completion >= 1.0 && c.severity === 'critical'
        )
        if (completedCritical) {
            contributors.push(`chain:${completedCritical.chainId}:complete`)
            return {
                action: 'lockdown',
                reason: `Complete critical attack chain: ${completedCritical.name}`,
                confidence: completedCritical.confidence,
                contributors,
                alert: true,
                responseHeaders: { 'X-Invariant-Action': 'lockdown' },
            }
        }

        // ── 2. Actively exploited CVE + high confidence ──
        if (activelyExploitedCves.length > 0) {
            const highConfMatch = matches.find(m =>
                m.cveEnrichment?.activelyExploited && m.confidence >= 0.75
            )
            if (highConfMatch) {
                contributors.push(`cve:${activelyExploitedCves[0]}:active`)
                contributors.push(`match:${highConfMatch.class}:${highConfMatch.confidence.toFixed(2)}`)
                return {
                    action: 'block',
                    reason: `Actively exploited CVE pattern detected: ${highConfMatch.class}`,
                    confidence: highConfMatch.confidence,
                    contributors,
                    alert: true,
                    responseHeaders: { 'X-Invariant-Action': 'block' },
                }
            }
        }

        // ── 3. Known campaign member ──
        if (activeCampaign && activeCampaign.severity !== 'low') {
            contributors.push(`campaign:${activeCampaign.id}`)
            if (matches.length > 0) {
                return {
                    action: 'block',
                    reason: `Source is part of active campaign: ${activeCampaign.description}`,
                    confidence: Math.max(...matches.map(m => m.confidence)),
                    contributors,
                    alert: activeCampaign.severity === 'critical',
                    responseHeaders: { 'X-Invariant-Action': 'block' },
                }
            }
        }

        // ── 4. High threat level source ──
        if (threatLevel >= 7.0 && matches.length > 0) {
            contributors.push(`threat_level:${threatLevel.toFixed(1)}`)
            return {
                action: 'block',
                reason: `High threat source (level ${threatLevel.toFixed(1)}) with active detection`,
                confidence: Math.max(...matches.map(m => m.confidence)),
                contributors,
                alert: true,
                responseHeaders: { 'X-Invariant-Action': 'block' },
            }
        }

        // ── 5. Chain in progress (high completion) ──
        const highCompletionChain = chainMatches.find(c => c.completion >= 0.66)
        if (highCompletionChain) {
            contributors.push(`chain:${highCompletionChain.chainId}:${(highCompletionChain.completion * 100).toFixed(0)}%`)
            return {
                action: highCompletionChain.recommendedAction === 'lockdown' ? 'lockdown' : 'block',
                reason: `Attack chain ${highCompletionChain.name} at ${(highCompletionChain.completion * 100).toFixed(0)}% completion`,
                confidence: highCompletionChain.confidence,
                contributors,
                alert: highCompletionChain.severity === 'critical',
                responseHeaders: { 'X-Invariant-Action': 'block' },
            }
        }

        // ── 6. Chain in progress (medium completion) ──
        const medCompletionChain = chainMatches.find(c => c.completion >= 0.5)
        if (medCompletionChain) {
            contributors.push(`chain:${medCompletionChain.chainId}:${(medCompletionChain.completion * 100).toFixed(0)}%`)
            return {
                action: 'challenge',
                reason: `Attack chain ${medCompletionChain.name} at ${(medCompletionChain.completion * 100).toFixed(0)}% completion`,
                confidence: medCompletionChain.confidence,
                contributors,
                alert: false,
                responseHeaders: { 'X-Invariant-Action': 'challenge' },
            }
        }

        // ── 7. Polyglot escalation — multi-context attack ──
        if (analysis.polyglot?.isPolyglot && matches.length >= 2) {
            const topConf = Math.max(...matches.map(m => m.confidence))
            contributors.push(`polyglot:${analysis.polyglot.domains.join('+')}`)
            contributors.push(...matches.map(m => `match:${m.class}:${m.confidence.toFixed(2)}`))
            // Polyglot with medium+ confidence → block (multi-context validity is adversarial)
            if (topConf >= 0.50) {
                return {
                    action: 'block',
                    reason: `Polyglot attack: ${analysis.polyglot.detail}`,
                    confidence: Math.min(0.99, topConf + analysis.polyglot.confidenceBoost),
                    contributors,
                    alert: analysis.polyglot.domainCount >= 3,
                    responseHeaders: { 'X-Invariant-Action': 'block' },
                }
            }
            // Lower confidence polyglot → challenge
            return {
                action: 'challenge',
                reason: `Suspected polyglot: ${analysis.polyglot.detail}`,
                confidence: Math.min(0.99, topConf + analysis.polyglot.confidenceBoost),
                contributors,
                alert: false,
                responseHeaders: { 'X-Invariant-Action': 'challenge' },
            }
        }

        // ── 7b. Encoding evasion escalation ──
        if (analysis.encodingEvasion && matches.length > 0) {
            const topConf = Math.max(...matches.map(m => m.confidence))
            contributors.push('encoding_evasion')
            contributors.push(...matches.map(m => `match:${m.class}:${m.confidence.toFixed(2)}`))
            if (topConf >= 0.45) {
                return {
                    action: 'block',
                    reason: 'Attack detected with encoding evasion — multi-layer obfuscation',
                    confidence: Math.min(0.99, topConf + 0.05),
                    contributors,
                    alert: false,
                    responseHeaders: { 'X-Invariant-Action': 'block' },
                }
            }
        }

        // ── 8. Standard analysis recommendation (enriched with intent) ──
        if (analysis.recommendation.block) {
            const topMatch = matches.reduce((a, b) => a.confidence > b.confidence ? a : b, matches[0])
            if (topMatch) {
                contributors.push(`match:${topMatch.class}:${topMatch.confidence.toFixed(2)}`)
            }

            // Enrich with intent classification
            const intent = analysis.intent
            if (intent) {
                contributors.push(`intent:${intent.primaryIntent}`)
                for (const t of intent.targets) {
                    contributors.push(`target:${t}`)
                }
            }

            // High-severity intents force alert regardless of severity level
            const HIGH_SEVERITY_INTENTS = new Set([
                'exfiltrate_credentials', 'destroy_data', 'code_execution', 'establish_persistence',
            ])
            const forceAlert = intent ? HIGH_SEVERITY_INTENTS.has(intent.primaryIntent) : false

            const reason = intent && intent.primaryIntent !== 'unknown'
                ? `${analysis.recommendation.reason} [intent: ${intent.detail}]`
                : analysis.recommendation.reason

            return {
                action: 'block',
                reason,
                confidence: analysis.recommendation.confidence,
                contributors,
                alert: forceAlert || this.engine.highestSeverity(matches) === 'critical',
                responseHeaders: { 'X-Invariant-Action': 'block' },
            }
        }

        // ── 9. Below threshold — monitor or allow ──
        if (matches.length > 0) {
            return {
                action: threatLevel >= 3.0 ? 'monitor' : 'allow',
                reason: 'detections_below_threshold',
                confidence: Math.max(...matches.map(m => m.confidence)),
                contributors: matches.map(m => `match:${m.class}:${m.confidence.toFixed(2)}`),
                alert: false,
            }
        }

        return {
            action: 'allow',
            reason: 'no_detections',
            confidence: 0,
            contributors: [],
            alert: false,
        }
    }

    // ── Behavior Derivation (Data-Driven) ────────────────────────────

    /**
     * Derive behavioral signals using data-driven rule tables.
     *
     * Three rule types (defined above):
     *   CLASS_BEHAVIORS:   class match → emit behaviors
     *   CONTENT_BEHAVIORS: class match + input content → emit behaviors
     *   PATH_BEHAVIORS:    path prefix match → emit behaviors
     *
     * Adding a new behavioral signal = adding one table entry.
     * Zero changes to this method.
     */
    private deriveBehaviors(matches: InvariantMatch[], request: UnifiedRequest, analysis?: AnalysisResult): string[] {
        const behaviors: string[] = []
        const classSet = new Set(matches.map(m => m.class))
        const path = request.request.path.toLowerCase()
        const inputLower = request.input.toLowerCase()

        // ── Analysis-level signals (not class-dependent) ──
        if (analysis?.polyglot?.isPolyglot) behaviors.push('polyglot_attack')
        if (analysis?.encodingEvasion) behaviors.push('encoding_evasion')

        // ── Class → behavior (unconditional) ──
        for (const rule of CLASS_BEHAVIORS) {
            if (rule.classes.some(c => classSet.has(c as InvariantClass))) {
                for (const b of rule.behaviors) behaviors.push(b)
            }
        }

        // ── Class + content → behavior (conditional) ──
        for (const rule of CONTENT_BEHAVIORS) {
            if (!rule.classes.some(c => classSet.has(c as InvariantClass))) continue
            if (rule.patterns.some(p => inputLower.includes(p.toLowerCase()) || path.includes(p.toLowerCase()))) {
                for (const b of rule.behaviors) behaviors.push(b)
            }
        }

        // ── Path → behavior (no class required) ──
        for (const rule of PATH_BEHAVIORS) {
            if (rule.pathPrefixes.some(prefix => path.startsWith(prefix))) {
                for (const b of rule.behaviors) behaviors.push(b)
            }
        }

        return behaviors
    }

    // ── Encoding Detection ───────────────────────────────────────────

    /**
     * Detect encoding preferences of the attacker.
     * This feeds the campaign intelligence behavioral fingerprint.
     */
    private detectEncoding(input: string): 'plain' | 'url_single' | 'url_double' | 'base64' | 'unicode' | 'mixed' | 'hex' {
        const hasUrl = /%[0-9a-fA-F]{2}/.test(input)
        const hasDoubleUrl = /%25[0-9a-fA-F]{2}/.test(input)
        const hasBase64 = /^[A-Za-z0-9+/]{20,}={0,2}$/.test(input)
        const hasUnicode = /\\u[0-9a-fA-F]{4}/.test(input)
        const hasHex = /0x[0-9a-fA-F]{2,}/.test(input) || /\\x[0-9a-fA-F]{2}/.test(input)

        const encodingCount = [hasUrl, hasDoubleUrl, hasBase64, hasUnicode, hasHex].filter(Boolean).length
        if (encodingCount >= 2) return 'mixed'
        if (hasDoubleUrl) return 'url_double'
        if (hasBase64) return 'base64'
        if (hasUrl) return 'url_single'
        if (hasUnicode) return 'unicode'
        if (hasHex) return 'hex'
        return 'plain'
    }

    // ── Stats ────────────────────────────────────────────────────────

    getStats(): {
        classCount: number
        l2Coverage: number
        chainDefinitions: number
        activeSources: number
        activeCampaigns: number
        knowledgeGraphEntries: number
    } {
        const all = this.engine.registry.all()
        const withL2 = all.filter(c => c.detectL2)
        return {
            classCount: all.length,
            l2Coverage: withL2.length / all.length,
            chainDefinitions: this.chains.chainCount,
            activeSources: this.chains.activeSourceCount,
            activeCampaigns: this.campaigns.getActiveCampaigns().length,
            knowledgeGraphEntries: this.knowledgeGraph.getStats().totalCves,
        }
    }
}
