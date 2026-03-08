/**
 * INVARIANT Engine — Core Detection Engine (v3, Multi-Level)
 *
 * v3 PARADIGM:
 *   Level 1: Regex fast-path (class module detect())
 *   Level 2: Deep structural evaluators (class module detectL2())
 *   Level 3: Input decomposition pipeline (context-aware property extraction)
 *
 * Detection Flow:
 *   1. L1 runs on ALL classes (fast, sub-millisecond total)
 *   2. L2 runs on classes that have detectL2 (deeper, still fast)
 *   3. If L1+L2 both fire → convergent evidence → boost confidence
 *   4. If only L2 fires → novel variant that bypassed regex
 *   5. If only L1 fires → known pattern, standard confidence
 *
 * The key insight: regex catches known patterns fast.
 * Expression evaluators catch unknown patterns that preserve the PROPERTY.
 * Running both catches everything and rates confidence correctly.
 *
 * MIGRATION:
 *   The v2 API (InvariantEngine.detect()) is fully backward compatible.
 *   v3 adds .detectDeep() for full multi-level analysis.
 */

import {
    InvariantRegistry,
    ALL_CLASS_MODULES,
    deepDecode,
} from './classes/index.js'

import { decomposeInput, type DecompositionResult, type ExtractedProperty } from './decomposition/input-decomposer.js'
import { ExploitKnowledgeGraph } from './decomposition/exploit-knowledge-graph.js'
import { anomalyConfidenceMultiplier, computeAnomalyProfile, type AnomalyProfile } from './evaluators/entropy-analyzer.js'
import { detectEncodingEvasion } from './evaluators/canonical-normalizer.js'
import { analyzePolyglot, type PolyglotDetection } from './evaluators/polyglot-detector.js'
import { classifyIntent } from './evaluators/intent-classifier.js'
import { constructProof } from './proof-constructor.js'

import type {
    InvariantClass,
    InvariantClassModule,
    InvariantMatch,
    Severity,
    DetectionLevelResult,
    AnalysisRequest,
    AnalysisResult,
    EscapeOperation,
    PayloadOperation,
    RepairOperation,
    InputContext,
    AlgebraicComposition,
    InterClassCorrelation,
    BlockRecommendation,
} from './classes/types.js'

// ── Backward Compatibility ────────────────────────────────────────
export type InvariantDefinition = InvariantClassModule
export type { InvariantClass, InvariantMatch }
export { deepDecode }


// ── Dynamic Threshold Overrides (from dispatched rule bundles) ────
//
// Injected by the edge sensor after decrypting a rule bundle.
// The engine uses these to apply EPSS-weighted block thresholds.
// The static SEVERITY_THRESHOLDS (below) remain as fallback — callers
// that don't inject overrides get identical behavior to previous versions.

export interface EngineThresholdOverride {
    /** The invariant class whose block threshold is adjusted */
    invariantClass: InvariantClass
    /** Adjusted threshold: base_threshold × (1 − epss × 0.30) */
    adjustedThreshold: number
    /** Unix timestamp ms — override ignored after this time */
    validUntil: number
}

export interface EngineConfig {
    /**
     * EPSS-weighted threshold overrides from the last dispatched rule bundle.
     * Optional — if omitted, static per-severity thresholds apply.
     * Overrides that have passed validUntil are silently ignored.
     */
    thresholdOverrides?: EngineThresholdOverride[]
    /**
     * Priority multipliers per invariant class (from tech-stack-aware dispatch).
     * Applied to detection confidence before threshold comparison.
     * Optional — if omitted, all classes run at default priority (1.0).
     */
    classPriorities?: Map<InvariantClass, number>
}


// ── Deep Detection Result ─────────────────────────────────────────

export interface DeepDetectionResult {
    /** All matches (L1 + L2 + L3 merged, deduplicated) */
    matches: InvariantMatch[]
    /** How many L2-only detections (novel variants) */
    novelByL2: number
    /** How many L3-only detections (deep structural novel variants) */
    novelByL3: number
    /** How many convergent detections (L1+L2 agreed) */
    convergent: number
    /** Total processing time in microseconds */
    processingTimeUs: number
    /** Detected input contexts from decomposition */
    contexts?: string[]
    /** Encoding analysis from decomposition */
    encodingDepth?: number
    /** Statistical anomaly profile of the input */
    anomalyProfile?: AnomalyProfile
    /** Whether encoding evasion was detected */
    encodingEvasion?: boolean
    /** Polyglot analysis (multi-context attack detection) */
    polyglot?: PolyglotDetection
}


// ── Context-Dependent Relevance Maps ─────────────────────────────
//
// Maps class ID prefixes to abstract "context domains", then maps
// knownContext values to which domains are primary/secondary.
// Primary = the input flows directly into this interpreter.
// Secondary = commonly chained with this context (e.g., SQL→CMDi via xp_cmdshell).

const CLASS_PREFIX_TO_CONTEXT_DOMAIN: Record<string, string> = {
    sql: 'sql', json: 'sql',
    xss: 'html',
    cmd: 'shell',
    ssrf: 'url', redirect: 'url',
    path: 'path',
    ssti: 'template',
    xxe: 'xml',
    deser: 'deser',
    auth: 'auth', jwt: 'auth',
    nosql: 'nosql',
    proto: 'proto',
    log: 'log4j',
    ldap: 'ldap',
    crlf: 'http', http: 'http', cache: 'http',
    llm: 'llm',
    graphql: 'graphql',
    ws: 'ws',
    mass: 'api', bola: 'api', api: 'api',
    dependency: 'supply', postinstall: 'supply', env: 'supply',
}

const CONTEXT_RELEVANCE: Record<string, { primary: Set<string>; secondary: Set<string> }> = {
    sql:      { primary: new Set(['sql']),      secondary: new Set(['shell', 'nosql']) },
    html:     { primary: new Set(['html']),     secondary: new Set(['template', 'url']) },
    shell:    { primary: new Set(['shell']),    secondary: new Set(['path', 'url']) },
    xml:      { primary: new Set(['xml']),      secondary: new Set(['html']) },
    json:     { primary: new Set(['sql', 'nosql', 'proto']), secondary: new Set(['api']) },
    ldap:     { primary: new Set(['ldap']),     secondary: new Set(['auth']) },
    template: { primary: new Set(['template']), secondary: new Set(['html', 'shell']) },
    graphql:  { primary: new Set(['graphql']),  secondary: new Set(['sql', 'nosql']) },
    url:      { primary: new Set(['url']),      secondary: new Set(['path', 'http']) },
}


// ── Data-Driven Algebraic Composition Rules ─────────────────────
//
// Each rule describes a structural composition: two classes that
// together form a higher-level attack pattern (escape + payload).
// An optional "completer" class makes the composition structurally
// complete (escape + payload + repair = confirmed injection).
//
// Adding a new composition = adding ONE entry here.
// Zero changes to detectCompositions().

interface CompositionRule {
    a: InvariantClass
    b: InvariantClass
    completer?: InvariantClass
    escape: EscapeOperation | null
    payload: PayloadOperation
    repair: RepairOperation
    repairComplete?: RepairOperation
    context: InputContext
    confidence: number
    confidenceComplete?: number
    derivedClass: InvariantClass
    alwaysComplete?: boolean
}

const COMPOSITION_RULES: readonly CompositionRule[] = [
    // SQL: string termination + union extraction
    {
        a: 'sql_string_termination', b: 'sql_union_extraction',
        completer: 'sql_comment_truncation',
        escape: 'string_terminate', payload: 'union_extract',
        repair: 'none', repairComplete: 'comment_close',
        context: 'sql', confidence: 0.93, confidenceComplete: 0.99,
        derivedClass: 'sql_union_extraction',
    },
    // SQL: string termination + tautology
    {
        a: 'sql_string_termination', b: 'sql_tautology',
        completer: 'sql_comment_truncation',
        escape: 'string_terminate', payload: 'tautology',
        repair: 'none', repairComplete: 'comment_close',
        context: 'sql', confidence: 0.92, confidenceComplete: 0.99,
        derivedClass: 'sql_tautology',
    },
    // SQL: string termination + time oracle
    {
        a: 'sql_string_termination', b: 'sql_time_oracle',
        completer: 'sql_comment_truncation',
        escape: 'string_terminate', payload: 'time_oracle',
        repair: 'none', repairComplete: 'comment_close',
        context: 'sql', confidence: 0.91,
        derivedClass: 'sql_time_oracle',
    },
    // SQL: string termination + stacked execution (always complete — ; is self-terminating)
    {
        a: 'sql_string_termination', b: 'sql_stacked_execution',
        escape: 'string_terminate', payload: 'stacked_exec',
        repair: 'natural_end', context: 'sql', confidence: 0.95,
        derivedClass: 'sql_stacked_execution', alwaysComplete: true,
    },
    // XSS: attribute escape + event handler
    {
        a: 'xss_attribute_escape', b: 'xss_event_handler',
        escape: 'context_break', payload: 'event_handler',
        repair: 'tag_close', context: 'html', confidence: 0.96,
        derivedClass: 'xss_event_handler', alwaysComplete: true,
    },
    // XSS: tag injection + protocol handler
    {
        a: 'xss_tag_injection', b: 'xss_protocol_handler',
        escape: 'context_break', payload: 'tag_inject',
        repair: 'tag_close', context: 'html', confidence: 0.94,
        derivedClass: 'xss_protocol_handler', alwaysComplete: true,
    },
    // Path: dotdot + encoding bypass (incomplete — needs target validation)
    {
        a: 'path_dotdot_escape', b: 'path_encoding_bypass',
        escape: 'encoding_bypass', payload: 'path_escape',
        repair: 'none', context: 'url', confidence: 0.93,
        derivedClass: 'path_dotdot_escape',
    },
    // Path: dotdot + null terminate (complete — null byte truncates extension check)
    {
        a: 'path_dotdot_escape', b: 'path_null_terminate',
        escape: 'null_terminate', payload: 'path_escape',
        repair: 'natural_end', context: 'url', confidence: 0.95,
        derivedClass: 'path_null_terminate', alwaysComplete: true,
    },
    // SSRF: internal reach + protocol smuggle
    {
        a: 'ssrf_internal_reach', b: 'ssrf_protocol_smuggle',
        escape: 'encoding_bypass', payload: 'proto_pollute',
        repair: 'none', context: 'url', confidence: 0.94,
        derivedClass: 'ssrf_protocol_smuggle', alwaysComplete: true,
    },
    // CMDi: separator + substitution
    {
        a: 'cmd_separator', b: 'cmd_substitution',
        escape: 'context_break', payload: 'cmd_substitute',
        repair: 'natural_end', context: 'shell', confidence: 0.96,
        derivedClass: 'cmd_substitution', alwaysComplete: true,
    },
    // SSTI: template expression + command separator → server RCE
    {
        a: 'ssti_jinja_twig', b: 'cmd_separator',
        escape: 'context_break', payload: 'cmd_substitute',
        repair: 'natural_end', context: 'template', confidence: 0.97,
        derivedClass: 'ssti_jinja_twig', alwaysComplete: true,
    },
    // XXE + SSRF internal reach → blind XXE via out-of-band
    {
        a: 'xxe_entity_expansion', b: 'ssrf_internal_reach',
        escape: 'context_break', payload: 'entity_expand',
        repair: 'none', context: 'xml', confidence: 0.95,
        derivedClass: 'xxe_entity_expansion', alwaysComplete: true,
    },
]


// ── Engine ────────────────────────────────────────────────────────

export class InvariantEngine {
    readonly registry: InvariantRegistry
    readonly knowledgeGraph: ExploitKnowledgeGraph
    private readonly thresholdOverrides: Map<InvariantClass, number>
    private readonly classPriorities: Map<InvariantClass, number>

    /**
     * Create an InvariantEngine.
     *
     * @param config Optional runtime config injected by the edge sensor after
     *               decrypting the latest rule bundle. Callers that omit config
     *               get the same static behavior as engine v3 — fully backwards
     *               compatible.
     */
    constructor(config?: EngineConfig) {
        this.registry = new InvariantRegistry()
        this.registry.registerAll(ALL_CLASS_MODULES)
        this.knowledgeGraph = new ExploitKnowledgeGraph()

        // Build effective threshold override map (skip expired entries)
        this.thresholdOverrides = new Map()
        if (config?.thresholdOverrides) {
            const now = Date.now()
            for (const override of config.thresholdOverrides) {
                if (override.validUntil > now) {
                    this.thresholdOverrides.set(override.invariantClass, override.adjustedThreshold)
                }
            }
        }

        this.classPriorities = config?.classPriorities ?? new Map()
    }

    /**
     * Update threshold overrides at runtime (called when a new rule bundle is applied).
     * Does not require engine reconstruction — overrides take effect on the next detect call.
     * Backwards compatible: engines constructed without config still work.
     */
    updateConfig(config: EngineConfig): void {
        this.thresholdOverrides.clear()
        if (config.thresholdOverrides) {
            const now = Date.now()
            for (const override of config.thresholdOverrides) {
                if (override.validUntil > now) {
                    this.thresholdOverrides.set(override.invariantClass, override.adjustedThreshold)
                }
            }
        }
        if (config.classPriorities) {
            this.classPriorities.clear()
            for (const [cls, priority] of config.classPriorities) {
                this.classPriorities.set(cls, priority)
            }
        }
    }

    /**
     * v2-compatible detection: L1 regex only.
     * Fast path, backward compatible.
     */
    detect(input: string, staticRuleIds: string[], environment?: string): InvariantMatch[] {
        const matches: InvariantMatch[] = []

        for (const module of this.registry.all()) {
            try {
                if (module.detect(input)) {
                    const isNovel = staticRuleIds.length === 0
                    const confidence = this.registry.computeConfidence(
                        module.id,
                        input,
                        environment,
                        !isNovel,
                    )

                    matches.push({
                        class: module.id,
                        confidence,
                        category: module.category,
                        severity: module.severity,
                        isNovelVariant: isNovel,
                        description: module.description,
                        detectionLevels: { l1: true, l2: false, convergent: false },
                    })
                }
            } catch {
                // Never let a detection failure break the engine
            }
        }

        return matches
    }

    /**
     * v3: Full multi-level detection pipeline.
     *
     * Runs L1 (regex) and L2 (structural evaluator) for every class.
     * Merges results with convergent evidence boosting.
     *
     * Use this when you want maximum detection capability.
     * The additional latency is typically <1ms for L2 evaluators.
     */
    detectDeep(input: string, staticRuleIds: string[], environment?: string): DeepDetectionResult {
        const start = performance.now()
        const matchMap = new Map<InvariantClass, InvariantMatch>()
        let novelByL2 = 0
        let novelByL3 = 0
        let convergent = 0

        for (const module of this.registry.all()) {
            let l1Detected = false
            let l2Detected = false
            let l1Confidence = 0
            let l2Result: DetectionLevelResult | null = null

            // ── Level 1: Regex fast-path ──
            try {
                l1Detected = module.detect(input)
                if (l1Detected) {
                    l1Confidence = this.registry.computeConfidence(
                        module.id,
                        input,
                        environment,
                        staticRuleIds.length > 0,
                    )
                }
            } catch { /* never break */ }

            // ── Level 2: Structural evaluator ──
            if (module.detectL2) {
                try {
                    l2Result = module.detectL2(input)
                    if (l2Result?.detected) {
                        l2Detected = true
                    }
                } catch { /* never break */ }
            }

            // ── Merge (L2-Primary Confidence Model) ──
            //
            // The core architectural principle: PROPERTY VERIFICATION is the
            // confidence authority, not pattern matching.
            //
            // - Convergent (L1+L2): very high confidence — both agree
            // - L2-only: L2 confidence stands — structural verification is authoritative
            // - L1-only: attenuated — regex matched but property wasn't verified
            //
            // This is what makes INVARIANT fundamentally different from
            // signature-based systems: confidence tracks mathematical certainty.
            if (!l1Detected && !l2Detected) continue

            const isNovel = staticRuleIds.length === 0

            if (l1Detected && l2Detected) {
                // CONVERGENT: both agree → strongest confidence signal.
                // The regex caught the pattern AND the structural evaluator
                // verified the mathematical property holds. Near-certain.
                convergent++
                const boostedConfidence = Math.min(0.99,
                    Math.max(l1Confidence, l2Result!.confidence) + 0.05)
                const convergentMatch: InvariantMatch = {
                    class: module.id,
                    confidence: boostedConfidence,
                    category: module.category,
                    severity: module.severity,
                    isNovelVariant: isNovel,
                    description: module.description,
                    detectionLevels: { l1: true, l2: true, convergent: true },
                    l2Evidence: l2Result!.explanation,
                }
                const convergentProof = constructProof(module, input, l2Result)
                if (convergentProof) convergentMatch.proof = convergentProof
                matchMap.set(module.id, convergentMatch)
            } else if (l2Detected && !l1Detected) {
                // NOVEL by L2: structural evaluator caught what regex missed.
                // L2 IS the authority — its confidence stands unmodified.
                // This is the invariant-detection paradigm: the PROPERTY holds
                // even though the PATTERN is novel.
                novelByL2++
                const novelMatch: InvariantMatch = {
                    class: module.id,
                    confidence: l2Result!.confidence,
                    category: module.category,
                    severity: module.severity,
                    isNovelVariant: true,
                    description: module.description,
                    detectionLevels: { l1: false, l2: true, convergent: false },
                    l2Evidence: l2Result!.explanation,
                }
                const novelProof = constructProof(module, input, l2Result)
                if (novelProof) novelMatch.proof = novelProof
                matchMap.set(module.id, novelMatch)
            } else {
                // L1 only: regex matched but structural evaluator is SILENT.
                // The property wasn't independently verified. Attenuate confidence.
                //
                // If the class has an L2 evaluator (all 66 do) but L2 didn't fire,
                // that's evidence the regex may be matching coincidental syntax
                // rather than a true invariant violation. Reduce confidence by 18%.
                //
                // This creates a natural incentive: classes with strong L2 evaluators
                // that fire on real attacks get full convergent confidence (0.99),
                // while regex-only noise gets attenuated to ~0.70.
                const hasL2 = !!module.detectL2
                const attenuatedConfidence = hasL2
                    ? l1Confidence * 0.82
                    : l1Confidence
                const l1Match: InvariantMatch = {
                    class: module.id,
                    confidence: attenuatedConfidence,
                    category: module.category,
                    severity: module.severity,
                    isNovelVariant: isNovel,
                    description: module.description,
                    detectionLevels: { l1: true, l2: false, convergent: false },
                }
                // L1-only still gets structural proof (no L2 semantic step)
                const l1Proof = constructProof(module, input, null)
                if (l1Proof) l1Match.proof = l1Proof
                matchMap.set(module.id, l1Match)
            }
        }

        // ── Level 3: Input Decomposition Pipeline ──
        // Run the full decomposer to extract structural properties.
        // Any property that maps to a class NOT already detected by L1/L2
        // is a deep novel variant — the input's structure implies a class
        // that neither regex nor evaluator caught.
        let decomposition: DecompositionResult | null = null
        try {
            decomposition = decomposeInput(input)
            for (const prop of decomposition.properties) {
                if (!matchMap.has(prop.invariantClass)) {
                    // L3-only detection: structural decomposition found a property
                    novelByL3++
                    matchMap.set(prop.invariantClass, {
                        class: prop.invariantClass,
                        confidence: prop.confidence,
                        category: this.registry.get(prop.invariantClass)?.category ?? 'unknown',
                        severity: this.registry.get(prop.invariantClass)?.severity ?? 'medium',
                        isNovelVariant: true, // ALWAYS novel if L3-only
                        description: this.registry.get(prop.invariantClass)?.description
                            ?? `Decomposition-detected: ${prop.evidence}`,
                        detectionLevels: { l1: false, l2: false, convergent: false },
                        l2Evidence: `L3 decomposition [${prop.context}]: ${prop.evidence}`,
                    })
                }
            }
        } catch { /* never break the pipeline */ }

        // ── Step 3a: Proof-Based Confidence Augmentation ──
        // A complete PropertyProof (all 3 algebraic phases: escape + payload + repair)
        // is independent structural evidence of exploitation. Use proofConfidence
        // as a confidence FLOOR — if the proof is stronger than heuristic confidence,
        // elevate the detection. This prevents complete proofs from being attenuated
        // below their structural certainty by L1-only attenuation or context weighting.
        for (const [cls, match] of matchMap) {
            if (match.proof?.isComplete && match.proof.proofConfidence > match.confidence) {
                matchMap.set(cls, {
                    ...match,
                    confidence: Math.min(0.99, match.proof.proofConfidence),
                })
            }
        }

        // ── Step 3b: Context-Dependent Confidence Weighting ──
        // When the caller tells us WHERE this input flows (sql, html, shell, etc.),
        // boost detections matching that context and attenuate others.
        // The invariant: if you KNOW the input goes into a SQL query,
        // SQL detection confidence is near-certain while XSS is background noise.
        if (environment && matchMap.size > 0) {
            const contextBoost = CONTEXT_RELEVANCE[environment]
            if (contextBoost) {
                for (const [cls, match] of matchMap) {
                    const prefix = cls.split('_')[0]
                    const domain = CLASS_PREFIX_TO_CONTEXT_DOMAIN[prefix]
                    if (domain && contextBoost.primary.has(domain)) {
                        // Primary context match — boost
                        matchMap.set(cls, {
                            ...match,
                            confidence: Math.min(0.99, match.confidence + 0.10),
                        })
                    } else if (domain && contextBoost.secondary.has(domain)) {
                        // Related context — mild boost
                        matchMap.set(cls, {
                            ...match,
                            confidence: Math.min(0.99, match.confidence + 0.04),
                        })
                    } else if (domain) {
                        // Unrelated context — attenuate (don't remove; polyglots are real)
                        matchMap.set(cls, {
                            ...match,
                            confidence: match.confidence * 0.85,
                        })
                    }
                }
            }
        }

        // ── Step 4: Statistical Anomaly Analysis ──
        // Apply cross-cutting entropy/structural anomaly signal.
        // This adjusts confidence based on universal statistical properties
        // of the input — works for ALL attack classes simultaneously.
        const anomalyMultiplier = anomalyConfidenceMultiplier(input)
        let anomalyProfile: AnomalyProfile | undefined
        let encodingEvasion = false

        if (matchMap.size > 0 || input.length > 20) {
            anomalyProfile = computeAnomalyProfile(input)

            // Apply anomaly multiplier to all detections
            if (anomalyMultiplier !== 1.0) {
                for (const [cls, match] of matchMap) {
                    matchMap.set(cls, {
                        ...match,
                        confidence: Math.min(0.99, match.confidence * anomalyMultiplier),
                    })
                }
            }

            // Check for encoding evasion
            const evasion = detectEncodingEvasion(input)
            encodingEvasion = evasion.isEvasion
        }

        // ── Step 5: Polyglot Detection ──
        // Analyze whether the input triggers detections in multiple
        // DISTINCT attack domains. Multi-context validity is a hallmark
        // of adversarial construction — legitimate input is meaningful
        // in exactly one context.
        let polyglot: PolyglotDetection | undefined
        if (matchMap.size >= 2) {
            polyglot = analyzePolyglot([...matchMap.keys()])
            if (polyglot.isPolyglot && polyglot.confidenceBoost > 0) {
                // Apply polyglot confidence boost to all detections
                for (const [cls, match] of matchMap) {
                    matchMap.set(cls, {
                        ...match,
                        confidence: Math.min(0.99, match.confidence + polyglot.confidenceBoost),
                    })
                }
            }
        }

        return {
            matches: Array.from(matchMap.values()),
            novelByL2,
            novelByL3,
            convergent,
            processingTimeUs: (performance.now() - start) * 1000,
            contexts: decomposition?.contexts?.map(c => String(c)) ?? [],
            encodingDepth: decomposition?.encoding?.encodingDepth ?? 0,
            anomalyProfile,
            encodingEvasion,
            polyglot,
        }
    }

    analyze(request: AnalysisRequest): AnalysisResult {
        const start = performance.now()

        // Step 1: Run full deep detection
        const deep = this.detectDeep(request.input, [], request.knownContext as string | undefined)

        // Step 2: Apply source reputation prior — boost confidence if source is known hostile
        let matches = deep.matches
        if (request.sourceReputation && request.sourceReputation > 0.6) {
            const boost = (request.sourceReputation - 0.6) * 0.4  // 0–0.16 boost
            matches = matches.map(m => ({
                ...m,
                confidence: Math.min(0.99, m.confidence + boost),
            }))
        }

        // Step 3: Compute inter-class correlations
        const correlations = this.registry.computeCorrelations(matches)

        // Step 4: Apply correlation boosts — find the highest compoundConfidence and apply to matching classes
        if (correlations.length > 0) {
            const maxCorrelation = correlations.reduce((a, b) => a.compoundConfidence > b.compoundConfidence ? a : b)
            if (maxCorrelation.compoundConfidence > 0) {
                matches = matches.map(m =>
                    maxCorrelation.classes.includes(m.class)
                        ? { ...m, confidence: Math.min(0.99, Math.max(m.confidence, maxCorrelation.compoundConfidence)) }
                        : m
                )
            }
        }

        // Step 5: Detect algebraic compositions
        const compositions = this.detectCompositions(matches, request.knownContext)

        // Step 6: Compute block recommendation with per-severity thresholds
        const recommendation = this.computeBlockRecommendation(matches, compositions)

        // Step 7: CVE enrichment via exploit knowledge graph
        const activelyExploitedClasses: string[] = []
        let highestEpss = 0
        let totalLinkedCves = 0
        try {
            matches = matches.map(m => {
                const enrichment = this.knowledgeGraph.enrichDetection(m.class)
                if (enrichment.linkedCves.length > 0) {
                    totalLinkedCves += enrichment.linkedCves.length
                    if (enrichment.activelyExploited) {
                        activelyExploitedClasses.push(m.class)
                    }
                    if (enrichment.highestEpss > highestEpss) {
                        highestEpss = enrichment.highestEpss
                    }
                    // Boost confidence for actively exploited CVEs
                    const boostedConfidence = enrichment.activelyExploited
                        ? Math.min(0.99, m.confidence + 0.05)
                        : m.confidence
                    return {
                        ...m,
                        confidence: boostedConfidence,
                        cveEnrichment: {
                            linkedCves: enrichment.linkedCves,
                            activelyExploited: enrichment.activelyExploited,
                            highestEpss: enrichment.highestEpss,
                            verificationAvailable: enrichment.verificationAvailable,
                        },
                    }
                }
                return m
            })
        } catch { /* knowledge graph is optional */ }

        // Step 8: Intent classification — what would the attack DO if it succeeded?
        const intent = matches.length > 0
            ? classifyIntent(matches.map(m => m.class), request.input, request.requestMeta?.path)
            : undefined

        return {
            matches,
            compositions,
            correlations,
            recommendation,
            novelByL2: deep.novelByL2,
            novelByL3: deep.novelByL3,
            convergent: deep.convergent,
            processingTimeUs: (performance.now() - start) * 1000,
            contexts: deep.contexts,
            cveEnrichment: {
                totalLinkedCves,
                activelyExploitedClasses,
                highestEpss,
            },
            polyglot: deep.polyglot,
            anomalyScore: (deep.anomalyProfile as any)?.score,
            encodingEvasion: deep.encodingEvasion,
            intent,
        }
    }

    /**
     * Detect algebraic compositions using data-driven COMPOSITION_RULES.
     *
     * Each rule declares two required classes and an optional completer.
     * Adding a new composition = adding one table entry above.
     * Zero changes to this method.
     */
    private detectCompositions(matches: InvariantMatch[], _knownContext?: string): AlgebraicComposition[] {
        const classSet = new Set(matches.map(m => m.class))
        const compositions: AlgebraicComposition[] = []

        for (const rule of COMPOSITION_RULES) {
            if (!classSet.has(rule.a) || !classSet.has(rule.b)) continue

            const hasCompleter = rule.completer ? classSet.has(rule.completer) : false
            const isComplete = rule.alwaysComplete ?? hasCompleter

            compositions.push({
                escape: rule.escape,
                payload: rule.payload,
                repair: (isComplete && rule.repairComplete) ? rule.repairComplete : rule.repair,
                context: rule.context,
                confidence: (isComplete && rule.confidenceComplete) ? rule.confidenceComplete : rule.confidence,
                derivedClass: rule.derivedClass,
                isComplete,
            })
        }

        return compositions
    }

    private computeBlockRecommendation(matches: InvariantMatch[], compositions: AlgebraicComposition[]): BlockRecommendation {
        if (matches.length === 0 && compositions.length === 0) {
            return { block: false, confidence: 0, reason: 'no_detections', threshold: 0 }
        }

        // Per-severity static thresholds — fallback when no EPSS override is present.
        // EPSS-weighted overrides are injected by the edge sensor after decrypting
        // the rule bundle (see EngineConfig). Callers with no config get these values
        // unchanged — full backwards compatibility.
        const SEVERITY_THRESHOLDS: Record<string, number> = {
            critical: 0.45,  // deser, rce-class attacks — block early
            high: 0.65,  // sqli, xss, ssrf
            medium: 0.80,  // path traversal, redirect
            low: 0.92,  // info-class signals
        }

        // Check compositions first — a structurally complete injection always blocks,
        // regardless of thresholds. A complete SQL injection is a complete SQL injection.
        const completeComposition = compositions.find(c => c.isComplete && c.confidence >= 0.90)
        if (completeComposition) {
            return {
                block: true, confidence: completeComposition.confidence,
                reason: `complete_injection_structure:${completeComposition.payload}`,
                threshold: 0.90,
            }
        }

        // Check individual matches against per-severity thresholds.
        //
        // Two dynamic adjustments are applied per match:
        //
        // 1. CLASS PRIORITY MULTIPLIER (tech-stack-aware, from dispatched bundle)
        //    effectiveConfidence = confidence × priorityMultiplier
        //    - 0.0 = skip class entirely (stack doesn't support this attack surface)
        //    - 1.0 = default (no change)
        //    - 1.5+ = high-risk for this stack (e.g., php_object on WordPress)
        //    If effectiveConfidence drops below 0.05 the match is not actionable.
        //
        // 2. EPSS-WEIGHTED THRESHOLD OVERRIDE (from dispatched bundle)
        //    threshold = min(override, SEVERITY_THRESHOLDS[severity])
        //    We take the MIN so EPSS can only lower the threshold (tighten detection)
        //    and never accidentally raise it above the severity floor — a dispatched
        //    bundle must not be able to soften blocking of critical-severity classes.
        for (const match of matches) {
            const priorityMultiplier = this.classPriorities.get(match.class as InvariantClass) ?? 1.0
            // A zero multiplier means the tech stack cannot be affected by this class —
            // skip without penalizing the overall confidence picture.
            if (priorityMultiplier < 0.05) continue

            const effectiveConfidence = Math.min(match.confidence * priorityMultiplier, 1.0)

            const severityFloor = SEVERITY_THRESHOLDS[match.severity] ?? 0.75
            const epssOverride = this.thresholdOverrides.get(match.class as InvariantClass)
            // EPSS can only tighten (lower) the threshold, never relax it.
            const threshold = epssOverride !== undefined
                ? Math.min(epssOverride, severityFloor)
                : severityFloor

            if (effectiveConfidence >= threshold) {
                return {
                    block: true,
                    // Report original confidence, not the priority-adjusted value.
                    // Consumers can recover effectiveConfidence from the match + config.
                    confidence: match.confidence,
                    reason: epssOverride !== undefined
                        ? `${match.class}_epss_override_${match.severity}_threshold`
                        : `${match.class}_exceeds_${match.severity}_threshold`,
                    threshold,
                }
            }
        }

        // No match exceeded its threshold. Report advisory state.
        const maxConfidence = matches.length > 0 ? Math.max(...matches.map(m => m.confidence)) : 0
        return {
            block: false, confidence: maxConfidence,
            reason: 'below_severity_thresholds',
            threshold: SEVERITY_THRESHOLDS[this.highestSeverity(matches)] ?? 0.75,
        }
    }

    /**
     * Check headers specifically for auth bypass invariants.
     */
    detectHeaderInvariants(headers: Headers): InvariantMatch[] {
        const matches: InvariantMatch[] = []

        const forwardHeaders = [
            'x-forwarded-for', 'x-real-ip', 'x-originating-ip',
            'x-remote-ip', 'x-client-ip', 'x-custom-ip-authorization',
        ]
        const forwardCount = forwardHeaders.filter(h => headers.has(h)).length
        if (forwardCount >= 3) {
            const authSpoof = this.registry.get('auth_header_spoof')
            matches.push({
                class: 'auth_header_spoof',
                confidence: 0.8,
                category: 'auth',
                severity: 'medium',
                isNovelVariant: false,
                description: authSpoof?.description ?? 'Spoof proxy/forwarding headers to bypass IP-based access controls',
            })
        }

        if (headers.has('x-original-url') || headers.has('x-rewrite-url')) {
            matches.push({
                class: 'auth_header_spoof',
                confidence: 0.85,
                category: 'auth',
                severity: 'high',
                isNovelVariant: false,
                description: 'URL rewrite header used to bypass path-based access controls',
            })
        }

        const auth = headers.get('authorization') ?? ''
        if (auth.startsWith('Bearer ')) {
            const jwtModule = this.registry.get('auth_none_algorithm')
            if (jwtModule?.detect(auth.slice(7))) {
                matches.push({
                    class: 'auth_none_algorithm',
                    confidence: 0.95,
                    category: 'auth',
                    severity: 'critical',
                    isNovelVariant: false,
                    description: jwtModule.description,
                })
            }
        }

        return matches
    }

    shouldBlock(matches: InvariantMatch[]): boolean {
        return this.computeBlockRecommendation(matches, []).block
    }

    highestSeverity(matches: InvariantMatch[]): 'critical' | 'high' | 'medium' | 'low' | 'info' {
        const order = ['info', 'low', 'medium', 'high', 'critical'] as const
        let max = 0
        for (const m of matches) {
            const idx = order.indexOf(m.severity)
            if (idx > max) max = idx
        }
        return order[max] ?? 'info'
    }

    generateVariants(cls: InvariantClass, count: number): string[] {
        const module = this.registry.get(cls)
        if (!module) return []
        return module.generateVariants(count)
    }

    get classCount(): number {
        return this.registry.size
    }

    get classes(): InvariantClass[] {
        return this.registry.classIds()
    }
}
