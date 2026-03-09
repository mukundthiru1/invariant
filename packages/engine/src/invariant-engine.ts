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
import { InvariantError } from './invariant-error.js'

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
// The static SEVERITY_BLOCK_THRESHOLDS (below) remain as fallback — callers
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
    ssti: 'template', template: 'template',
    xxe: 'xml',
    deser: 'deser',
    auth: 'auth', jwt: 'auth', credential: 'auth',
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


export interface EngineErrorLogEntry {
    timestamp: number
    source: string
    error: string
}

function sanitizeConf(v: number): number {
    if (!isFinite(v) || isNaN(v)) return 0
    return Math.max(0, Math.min(1, v))
}

export function sanitizeConfidence(value: number, fallback: number = 0.5): number {
    if (!Number.isFinite(value) || Number.isNaN(value)) return sanitizeConf(fallback)
    return sanitizeConf(value)
}

export const MAX_INPUT_LENGTH = 1_000_000
const NULL_BYTE_RE = /\u0000/g

function sanitizeInputBoundary(input: unknown): string | null {
    if (typeof input !== 'string') return null
    let sanitized = input
    if (sanitized.includes('\u0000')) sanitized = sanitized.replace(NULL_BYTE_RE, '')
    if (sanitized.length > MAX_INPUT_LENGTH) sanitized = sanitized.slice(0, MAX_INPUT_LENGTH)
    return sanitized
}

function sanitizeStaticRuleIds(staticRuleIds: unknown): string[] {
    if (!Array.isArray(staticRuleIds)) return []
    return staticRuleIds.filter((ruleId): ruleId is string => typeof ruleId === 'string')
}

function sanitizeEnvironment(environment: unknown): string | undefined {
    if (typeof environment !== 'string') return undefined
    const trimmed = environment.trim()
    return trimmed.length > 0 ? trimmed : undefined
}

function createEmptyDeepDetectionResult(): DeepDetectionResult {
    return {
        matches: [],
        novelByL2: 0,
        novelByL3: 0,
        convergent: 0,
        processingTimeUs: 0,
        contexts: [],
        encodingDepth: 0,
        encodingEvasion: false,
    }
}

function createEmptyAnalysisResult(processingTimeUs: number): AnalysisResult {
    return {
        matches: [],
        compositions: [],
        correlations: [],
        recommendation: { block: false, confidence: 0, reason: 'invalid_input', threshold: 0 },
        novelByL2: 0,
        novelByL3: 0,
        convergent: 0,
        processingTimeUs,
        contexts: [],
        cveEnrichment: {
            totalLinkedCves: 0,
            activelyExploitedClasses: [],
            highestEpss: 0,
        },
        encodingEvasion: false,
    }
}

const SEVERITY_BLOCK_THRESHOLDS: Record<string, number> = {
    critical: 0.45, // deser, rce-class attacks — block early
    high: 0.65, // sqli, xss, ssrf
    medium: 0.80, // path traversal, redirect
    low: 0.92, // info-class signals
}
const COMPLETE_COMPOSITION_THRESHOLD = 0.90
const DEFAULT_BLOCK_THRESHOLD = 0.75
const COMPLETE_SKIP_PRIORITY_FLOOR = 0.05
const DEFAULT_CLASS_PRIORITY_MULTIPLIER = 1.0
const MAX_CONCURRENT = 10

const AUTH_PATH_HINTS = ['/login', '/signin', '/auth', '/session', '/token', '/oauth']
const TEMPLATE_PATH_HINTS = ['/template', '/render', '/preview', '/email', '/view']


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
    private readonly errorLog: EngineErrorLogEntry[] = []

    private applyConfig(config: unknown): void {
        if (!config || typeof config !== 'object') return

        const now = Date.now()
        const candidate = config as {
            thresholdOverrides?: unknown
            classPriorities?: unknown
        }

        if (Array.isArray(candidate.thresholdOverrides)) {
            for (const override of candidate.thresholdOverrides) {
                if (!override || typeof override !== 'object') continue
                const o = override as {
                    invariantClass?: unknown
                    adjustedThreshold?: unknown
                    validUntil?: unknown
                }
                if (typeof o.invariantClass !== 'string') continue
                if (typeof o.adjustedThreshold !== 'number' || !Number.isFinite(o.adjustedThreshold)) continue
                if (typeof o.validUntil !== 'number' || !Number.isFinite(o.validUntil) || o.validUntil <= now) continue
                this.thresholdOverrides.set(o.invariantClass as InvariantClass, sanitizeConf(o.adjustedThreshold))
            }
        }

        if (candidate.classPriorities instanceof Map) {
            for (const [cls, priority] of candidate.classPriorities) {
                if (typeof cls !== 'string') continue
                if (typeof priority !== 'number' || !Number.isFinite(priority)) continue
                this.classPriorities.set(cls as InvariantClass, priority)
            }
        }
    }

    private recordError(source: string, error: unknown): void {
        const errorString = error instanceof Error
            ? `${error.name}: ${error.message}`
            : String(error)

        this.errorLog.push({
            timestamp: Date.now(),
            source,
            error: errorString,
        })

        if (this.errorLog.length > 100) {
            this.errorLog.shift()
        }
    }

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

        this.thresholdOverrides = new Map()
        this.classPriorities = new Map()
        this.applyConfig(config)
    }

    getErrorLog(): readonly EngineErrorLogEntry[] {
        return this.errorLog
    }

    /**
     * Update threshold overrides at runtime (called when a new rule bundle is applied).
     * Does not require engine reconstruction — overrides take effect on the next detect call.
     * Backwards compatible: engines constructed without config still work.
     */
    updateConfig(config: EngineConfig): void {
        this.thresholdOverrides.clear()
        this.classPriorities.clear()
        this.applyConfig(config)
    }

    /**
     * v2-compatible detection: L1 regex only.
     * Fast path, backward compatible.
     */
    detect(input: string, staticRuleIds: string[], environment?: string): InvariantMatch[] {
        const safeInput = sanitizeInputBoundary(input)
        if (safeInput === null) return []
        const safeStaticRuleIds = sanitizeStaticRuleIds(staticRuleIds)
        const safeEnvironment = sanitizeEnvironment(environment)

        return this.registry.runInConfidenceScope((scope) => {
            const matches: InvariantMatch[] = []

            for (const module of this.registry.all()) {
                try {
                    if (module.detect(safeInput)) {
                        const isNovel = safeStaticRuleIds.length === 0
                        const confidence = sanitizeConf(this.registry.computeConfidence(
                            module.id,
                            safeInput,
                            safeEnvironment,
                            !isNovel,
                            scope,
                        ))

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
                } catch (error) {
                    this.recordError(`detect:${module.id}`, error)
                }
            }

            return matches
        })
    }

    async detectBatch(inputs: string[], staticRuleIds: string[] = [], environment?: string): Promise<InvariantMatch[][]> {
        if (!Array.isArray(inputs)) {
            throw new InvariantError('detectBatch inputs must be an array of strings', {
                code: 'INVALID_BATCH_INPUT',
                phase: 'l1',
            })
        }

        const results: InvariantMatch[][] = new Array(inputs.length)
        const workerCount = Math.min(MAX_CONCURRENT, inputs.length)
        let cursor = 0

        const runWorker = async (): Promise<void> => {
            while (true) {
                const index = cursor++
                if (index >= inputs.length) return

                const batchInput = inputs[index]
                if (typeof batchInput !== 'string') {
                    throw new InvariantError(`detectBatch input at index ${index} must be a string`, {
                        code: 'INVALID_BATCH_ITEM',
                        phase: 'l1',
                    })
                }

                results[index] = this.detect(batchInput, staticRuleIds, environment)
            }
        }

        await Promise.all(Array.from({ length: workerCount }, () => runWorker()))
        return results
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
        const safeInput = sanitizeInputBoundary(input)
        if (safeInput === null) return createEmptyDeepDetectionResult()
        const safeStaticRuleIds = sanitizeStaticRuleIds(staticRuleIds)
        const safeEnvironment = sanitizeEnvironment(environment)

        return this.registry.runInConfidenceScope((scope) => {
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
                l1Detected = module.detect(safeInput)
                if (l1Detected) {
                    l1Confidence = sanitizeConf(this.registry.computeConfidence(
                        module.id,
                        safeInput,
                        safeEnvironment,
                        safeStaticRuleIds.length > 0,
                        scope,
                    ))
                }
            } catch (error) {
                this.recordError(`detectDeep.l1:${module.id}`, error)
            }

            // ── Level 2: Structural evaluator ──
            if (module.detectL2) {
                try {
                    l2Result = module.detectL2(safeInput)
                    if (l2Result?.detected) {
                        l2Detected = true
                    }
                } catch (error) {
                    this.recordError(`detectDeep.l2:${module.id}`, error)
                }
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

            const isNovel = safeStaticRuleIds.length === 0

            if (l1Detected && l2Detected) {
                // CONVERGENT: both agree → strongest confidence signal.
                // The regex caught the pattern AND the structural evaluator
                // verified the mathematical property holds. Near-certain.
                convergent++
                const boostedConfidence = sanitizeConf(
                    Math.max(sanitizeConf(l1Confidence), sanitizeConf(l2Result!.confidence)) + 0.05,
                )
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
                const convergentProof = constructProof(module, safeInput, l2Result)
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
                    confidence: sanitizeConf(l2Result!.confidence),
                    category: module.category,
                    severity: module.severity,
                    isNovelVariant: true,
                    description: module.description,
                    detectionLevels: { l1: false, l2: true, convergent: false },
                    l2Evidence: l2Result!.explanation,
                }
                const novelProof = constructProof(module, safeInput, l2Result)
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
                    ? sanitizeConf(l1Confidence * 0.82)
                    : l1Confidence
                const l1Match: InvariantMatch = {
                    class: module.id,
                    confidence: sanitizeConf(attenuatedConfidence),
                    category: module.category,
                    severity: module.severity,
                    isNovelVariant: isNovel,
                    description: module.description,
                    detectionLevels: { l1: true, l2: false, convergent: false },
                }
                // L1-only still gets structural proof (no L2 semantic step)
                const l1Proof = constructProof(module, safeInput, null)
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
            decomposition = decomposeInput(safeInput)
            for (const prop of decomposition.properties) {
                if (!matchMap.has(prop.invariantClass)) {
                    // L3-only detection: structural decomposition found a property
                    novelByL3++
                        matchMap.set(prop.invariantClass, {
                            class: prop.invariantClass,
                        confidence: sanitizeConf(prop.confidence),
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
        } catch (error) {
            this.recordError('detectDeep.decompose', error)
        }

        // ── Step 3a: Proof-Based Confidence Augmentation ──
        // A complete PropertyProof (all 3 algebraic phases: escape + payload + repair)
        // is independent structural evidence of exploitation. Use proofConfidence
        // as a confidence FLOOR — if the proof is stronger than heuristic confidence,
        // elevate the detection. This prevents complete proofs from being attenuated
        // below their structural certainty by L1-only attenuation or context weighting.
        for (const [cls, match] of matchMap) {
            const currentConfidence = sanitizeConf(match.confidence)
            if (match.proof?.isComplete && sanitizeConf(match.proof.proofConfidence) > currentConfidence) {
                matchMap.set(cls, {
                    ...match,
                    confidence: sanitizeConf(match.proof.proofConfidence),
                })
            }
        }

        // ── Step 3b: Context-Dependent Confidence Weighting ──
        // When the caller tells us WHERE this input flows (sql, html, shell, etc.),
        // boost detections matching that context and attenuate others.
        // The invariant: if you KNOW the input goes into a SQL query,
        // SQL detection confidence is near-certain while XSS is background noise.
        if (safeEnvironment && matchMap.size > 0) {
            const contextBoost = CONTEXT_RELEVANCE[safeEnvironment]
            if (contextBoost) {
                for (const [cls, match] of matchMap) {
                    const prefix = cls.split('_')[0]
                    const domain = CLASS_PREFIX_TO_CONTEXT_DOMAIN[prefix]
                    if (domain && contextBoost.primary.has(domain)) {
                        // Primary context match — boost
                        const safeConfidence = sanitizeConf(match.confidence)
                        matchMap.set(cls, {
                            ...match,
                            confidence: sanitizeConf(safeConfidence + 0.10),
                        })
                    } else if (domain && contextBoost.secondary.has(domain)) {
                        // Related context — mild boost
                        const safeConfidence = sanitizeConf(match.confidence)
                        matchMap.set(cls, {
                            ...match,
                            confidence: sanitizeConf(safeConfidence + 0.04),
                        })
                    } else if (domain) {
                        // Unrelated context — attenuate (don't remove; polyglots are real)
                        const safeConfidence = sanitizeConf(match.confidence)
                        matchMap.set(cls, {
                            ...match,
                            confidence: sanitizeConf(safeConfidence * 0.85),
                        })
                    }
                }
            }
        }

        // ── Step 4: Statistical Anomaly Analysis ──
        // Apply cross-cutting entropy/structural anomaly signal.
        // This adjusts confidence based on universal statistical properties
        // of the input — works for ALL attack classes simultaneously.
        const anomalyMultiplier = sanitizeConf(anomalyConfidenceMultiplier(safeInput))
        let anomalyProfile: AnomalyProfile | undefined
        let encodingEvasion = false

        if (matchMap.size > 0 || safeInput.length > 20) {
            anomalyProfile = computeAnomalyProfile(safeInput)

            // Apply anomaly multiplier to all detections
            if (anomalyMultiplier !== 1.0) {
                for (const [cls, match] of matchMap) {
                    matchMap.set(cls, {
                        ...match,
                        confidence: sanitizeConf(sanitizeConf(match.confidence) * anomalyMultiplier),
                    })
                }
            }

            // Check for encoding evasion
            const evasion = detectEncodingEvasion(safeInput)
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
                        confidence: sanitizeConf(
                            sanitizeConf(match.confidence) + sanitizeConf(polyglot.confidenceBoost),
                        ),
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
        })
    }

    analyze(request: AnalysisRequest): AnalysisResult {
        const start = performance.now()
        if (!request || typeof request !== 'object') {
            return createEmptyAnalysisResult((performance.now() - start) * 1000)
        }

        const safeInput = sanitizeInputBoundary((request as { input?: unknown }).input)
        if (safeInput === null) {
            return createEmptyAnalysisResult((performance.now() - start) * 1000)
        }

        const safeKnownContext = typeof request.knownContext === 'string' ? request.knownContext : undefined
        const safeSourceReputation = (
            typeof request.sourceReputation === 'number' && Number.isFinite(request.sourceReputation)
        ) ? request.sourceReputation : undefined
        const safeRequestMeta = request.requestMeta && typeof request.requestMeta === 'object'
            ? {
                method: typeof request.requestMeta.method === 'string' ? request.requestMeta.method : undefined,
                path: typeof request.requestMeta.path === 'string' ? request.requestMeta.path : undefined,
                contentType: typeof request.requestMeta.contentType === 'string' ? request.requestMeta.contentType : undefined,
            }
            : undefined
        const safeRequest: AnalysisRequest = {
            input: safeInput,
            knownContext: safeKnownContext,
            sourceReputation: safeSourceReputation,
            requestMeta: safeRequestMeta,
        }

        // Step 1: Run full deep detection
        const deep = this.detectDeep(safeInput, [], safeKnownContext as string | undefined)

        // Step 2: Apply source reputation prior — boost confidence if source is known hostile
        let matches = deep.matches
        if (safeSourceReputation && safeSourceReputation > 0.6) {
            const boost = sanitizeConf((safeSourceReputation - 0.6) * 0.4)
            matches = matches.map(m => ({
                ...m,
                confidence: sanitizeConf(m.confidence + boost),
            }))
        }

        // Step 2b: Contextual risk scoring from request metadata
        matches = this.applyContextualRiskScoring(matches, safeRequest)

        // Step 3: Compute inter-class correlations
        const correlations = this.registry.computeCorrelations(matches)

        // Step 4: Apply correlation boosts — find the highest compoundConfidence and apply to matching classes
        if (correlations.length > 0) {
            const maxCorrelation = correlations.reduce((a, b) => a.compoundConfidence > b.compoundConfidence ? a : b)
            if (maxCorrelation.compoundConfidence > 0) {
                matches = matches.map(m =>
                    maxCorrelation.classes.includes(m.class)
                        ? {
                            ...m,
                            confidence: sanitizeConf(
                                Math.max(sanitizeConf(m.confidence), sanitizeConf(maxCorrelation.compoundConfidence)),
                            ),
                        }
                        : m
                )
            }
        }

        // Step 5: Detect algebraic compositions
        const compositions = this.detectCompositions(matches, safeKnownContext)

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
                        ? sanitizeConf(m.confidence + 0.05)
                        : sanitizeConf(m.confidence)
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
        } catch (error) {
            this.recordError('analyze.kg', error)
        }

        // Step 8: Intent classification — what would the attack DO if it succeeded?
        const intent = matches.length > 0
            ? classifyIntent(matches.map(m => m.class), safeInput, safeRequestMeta?.path)
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

    private applyContextualRiskScoring(matches: InvariantMatch[], request: AnalysisRequest): InvariantMatch[] {
        if (matches.length === 0) return matches

        const path = (request.requestMeta?.path ?? '').toLowerCase()
        const method = (request.requestMeta?.method ?? '').toUpperCase()
        const contentType = (request.requestMeta?.contentType ?? '').toLowerCase()
        const knownContext = String(request.knownContext ?? '').toLowerCase()

        return matches.map(match => {
            let confidence = sanitizeConf(match.confidence)

            if (match.class === 'credential_stuffing') {
                if (AUTH_PATH_HINTS.some(p => path.includes(p))) {
                    confidence = sanitizeConf(confidence + 0.08)
                }
                if (method === 'POST') {
                    confidence = sanitizeConf(confidence + 0.04)
                }
                if (contentType.includes('application/json') || contentType.includes('application/x-www-form-urlencoded')) {
                    confidence = sanitizeConf(confidence + 0.03)
                }
                if (!AUTH_PATH_HINTS.some(p => path.includes(p)) && method === 'GET') {
                    confidence = sanitizeConf(confidence * 0.90)
                }
            }

            if (match.class === 'template_injection_generic') {
                if (knownContext === 'template' || knownContext === 'html') {
                    confidence = sanitizeConf(confidence + 0.07)
                }
                if (TEMPLATE_PATH_HINTS.some(p => path.includes(p))) {
                    confidence = sanitizeConf(confidence + 0.05)
                }
                if (contentType.includes('text/html') || contentType.includes('application/xhtml+xml')) {
                    confidence = sanitizeConf(confidence + 0.03)
                }
                if (!TEMPLATE_PATH_HINTS.some(p => path.includes(p)) && contentType.startsWith('image/')) {
                    confidence = sanitizeConf(confidence * 0.92)
                }
            }

            return { ...match, confidence: sanitizeConf(confidence) }
        })
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

        // Check compositions first — a structurally complete injection always blocks,
        // regardless of thresholds. A complete SQL injection is a complete SQL injection.
        const completeComposition = compositions.find(c => c.isComplete && c.confidence >= COMPLETE_COMPOSITION_THRESHOLD)
        if (completeComposition) {
            return {
                block: true,
                confidence: sanitizeConf(completeComposition.confidence),
                reason: `complete_injection_structure:${completeComposition.payload}`,
                threshold: COMPLETE_COMPOSITION_THRESHOLD,
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
        //    threshold = min(override, SEVERITY_BLOCK_THRESHOLDS[severity])
        //    We take the MIN so EPSS can only lower the threshold (tighten detection)
        //    and never accidentally raise it above the severity floor — a dispatched
        //    bundle must not be able to soften blocking of critical-severity classes.
        for (const match of matches) {
            const priorityMultiplier = this.classPriorities.get(match.class as InvariantClass) ?? DEFAULT_CLASS_PRIORITY_MULTIPLIER
            // A zero multiplier means the tech stack cannot be affected by this class —
            // skip without penalizing the overall confidence picture.
            if (priorityMultiplier < COMPLETE_SKIP_PRIORITY_FLOOR) continue

            const effectiveConfidence = sanitizeConf(match.confidence * priorityMultiplier)

            const severityFloor = SEVERITY_BLOCK_THRESHOLDS[match.severity] ?? DEFAULT_BLOCK_THRESHOLD
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
        const maxConfidence = matches.length > 0 ? Math.max(...matches.map(m => sanitizeConf(m.confidence))) : 0
        return {
            block: false, confidence: sanitizeConf(maxConfidence),
            reason: 'below_severity_thresholds',
            threshold: SEVERITY_BLOCK_THRESHOLDS[this.highestSeverity(matches)] ?? DEFAULT_BLOCK_THRESHOLD,
        }
    }

    /**
     * Check headers specifically for auth bypass invariants.
     */
    detectHeaderInvariants(headers: Headers): InvariantMatch[] {
        if (!(headers instanceof Headers)) return []
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
        if (!Array.isArray(matches)) return false
        return this.computeBlockRecommendation(matches, []).block
    }

    highestSeverity(matches: InvariantMatch[]): 'critical' | 'high' | 'medium' | 'low' | 'info' {
        if (!Array.isArray(matches)) return 'info'
        const order = ['info', 'low', 'medium', 'high', 'critical'] as const
        let max = 0
        for (const m of matches) {
            const idx = order.indexOf(m.severity)
            if (idx > max) max = idx
        }
        return order[max] ?? 'info'
    }

    generateVariants(cls: InvariantClass, count: number): string[] {
        if (typeof cls !== 'string') return []
        if (typeof count !== 'number' || !Number.isFinite(count)) return []
        const safeCount = Math.max(0, Math.floor(count))
        const module = this.registry.get(cls)
        if (!module) return []
        return module.generateVariants(safeCount)
    }

    get classCount(): number {
        return this.registry.size
    }

    get classes(): InvariantClass[] {
        return this.registry.classIds()
    }
}
