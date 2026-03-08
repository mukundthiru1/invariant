/**
 * @santh/invariant-engine
 *
 * The detection engine that powers INVARIANT.
 * Matches invariant PROPERTIES, not signatures.
 * Zero dependencies. Runs in Workers, Node.js, Bun, Deno — anywhere JS runs.
 *
 * Usage:
 *   import { InvariantEngine } from '@santh/invariant-engine'
 *   const engine = new InvariantEngine()
 *   const matches = engine.detect(userInput, [])
 *   if (engine.shouldBlock(matches)) { // block }
 *
 * Modular usage (v2):
 *   import { InvariantRegistry, ALL_CLASS_MODULES } from '@santh/invariant-engine'
 *   const registry = new InvariantRegistry()
 *   registry.registerAll(ALL_CLASS_MODULES)
 *   // Or register individual categories:
 *   import { SQL_CLASSES } from '@santh/invariant-engine'
 *   registry.registerAll(SQL_CLASSES)
 */

// ── Core Engine ──────────────────────────────────────────────────
export {
    InvariantEngine,
    type InvariantClass,
    type InvariantDefinition,
    type InvariantMatch,
    type EngineThresholdOverride,
    type EngineConfig,
    type DeepDetectionResult,
} from './invariant-engine.js'

// ── Crypto Types & Utilities ─────────────────────────────────────
export type {
    SignalBundle,
    EncryptedSignalBundle,
    SignalUploadBatch,
    PatternRule,
    ThresholdOverride,
    ClassPriority,
    RuleBundle,
    EncryptedRuleBundle,
    StorageEncryptionConfig,
    EncryptedStorageValue,
    SubscriberKeyPair,
    SanthPublicKeys,
} from './crypto/types.js'

export {
    toBase64Url,
    fromBase64Url,
    concat,
    uint32BE,
    uint64BE,
    encode,
    decode,
    timingSafeEqual,
} from './crypto/encoding.js'

// ── Modular Class System (v2) ────────────────────────────────────
export {
    InvariantRegistry,
    RegistryError,
    type RegistryStats,
    ALL_CLASS_MODULES,
    SQL_CLASSES,
    XSS_CLASSES,
    PATH_CLASSES,
    CMD_CLASSES,
    SSRF_CLASSES,
    DESER_CLASSES,
    AUTH_CLASSES,
    INJECTION_CLASSES,
    type InvariantClassModule,
    type AttackCategory,
    type Severity,
    type CalibrationConfig,
    deepDecode,
} from './classes/index.js'

export {
    PluginRegistry,
    PluginError,
    defineClass,
    type InvariantPlugin,
} from './plugin.js'

// ── Property Proof System ────────────────────────────────────
export {
    constructProof,
} from './proof-constructor.js'

export type {
    PropertyProof,
    ProofStep,
} from './classes/types.js'

// ── Chain Detection ──────────────────────────────────────────────
export {
    ChainCorrelator,
    ATTACK_CHAINS,
    type ChainDefinition,
    type ChainStep,
    type ChainSignal,
    type ChainMatch,
} from './chain-detector.js'

// ── Defense Validation ───────────────────────────────────────────
export {
    DefenseValidator,
    type ValidationResult,
    type FullValidationReport,
} from './defense-validator.js'

// ── Level 2 Evaluator Bridge ─────────────────────────────────────
export {
    runL2Evaluators,
    mergeL2Results,
    type L2DetectionResult,
    type L2Stats,
} from './evaluators/evaluator-bridge.js'

// ── L2 Evaluator Registry (data-driven module system) ───────────
export {
    L2_EVALUATOR_DESCRIPTORS,
    lookupCategory,
    lookupSeverity,
    CLASS_CATEGORY,
    CLASS_SEVERITY,
    type L2EvaluatorDescriptor,
    type L2Detection,
} from './evaluators/l2-evaluator-registry.js'

// ── Decomposition Pipeline ───────────────────────────────────────
export {
    decomposeInput,
    multiLayerDecode,
    detectContexts,
    type ExtractedProperty,
    type DecompositionResult,
    type DecodedForms,
    type InputContext,
} from './decomposition/input-decomposer.js'

export {
    ExploitKnowledgeGraph,
} from './decomposition/exploit-knowledge-graph.js'

export {
    ExploitVerifier,
} from './decomposition/exploit-verifier.js'

export {
    CampaignIntelligence,
} from './decomposition/campaign-intelligence.js'

// ── Evidence Sealing ─────────────────────────────────────────────
export {
    EvidenceSealer,
    type EvidenceSeal,
    type SignalWithProof,
    type SealedBatch,
} from './evidence/index.js'

// ── MITRE ATT&CK Mapping ────────────────────────────────────────
export {
    MitreMapper,
    type MitreTechnique,
    type MitreTactic,
    type MitreMapping,
    type KillChainPhase,
} from './mitre-mapper.js'

// ── Unified Runtime ──────────────────────────────────────────────
export {
    UnifiedRuntime,
    type UnifiedRequest,
    type UnifiedResponse,
    type DefenseDecision,
} from './unified-runtime.js'

// ── Cross-Cutting Analysis Primitives ────────────────────────────
export {
    canonicalize,
    quickCanonical,
    detectEncodingEvasion,
    type NormalizationResult,
} from './evaluators/canonical-normalizer.js'

export {
    shannonEntropy,
    charClassDistribution,
    repetitionIndex,
    structuralDensity,
    computeAnomalyProfile,
    anomalyConfidenceMultiplier,
    isLikelyEncoded,
    type CharClassDistribution,
    type AnomalyProfile,
} from './evaluators/entropy-analyzer.js'

export {
    analyzePolyglot,
    type PolyglotDetection,
} from './evaluators/polyglot-detector.js'

export {
    classifyIntent,
    intentSeverity,
    type AttackIntent,
    type IntentClassification,
} from './evaluators/intent-classifier.js'

export {
    validateShape,
    inferFieldType,
    autoValidateShape,
    type FieldType,
    type ShapeViolation,
    type ShapeValidation,
} from './evaluators/input-shape-validator.js'

// ── Effect Simulation & Adversary Fingerprinting ────────────────
export {
    simulateSqlEffect,
    simulateCmdEffect,
    simulateXssEffect,
    simulatePathEffect,
    simulateSsrfEffect,
    fingerprintAdversary,
    type ExploitEffect,
    type ExploitOperation,
    type ExploitProof,
    type ImpactAssessment,
    type ExploitStep,
    type AdversaryFingerprint,
} from './evaluators/effect-simulator.js'

// ── Incident Response Recommender ───────────────────────────────
export {
    generateResponsePlan,
    type IncidentRecommendation,
    type ResponsePlan,
} from './evaluators/response-recommender.js'

// ── Shared Configuration ────────────────────────────────────────
export {
    validateConfig,
    isValidCategory,
    ConfigError,
    DEFAULT_CONFIG,
    type InvariantConfig,
} from './config.js'

// ── Static Codebase Scanner ─────────────────────────────────────
export {
    CodebaseScanner,
    formatReport,
    toSarif,
    toJunitXml,
    SINK_PATTERNS,
    CLASSES_BY_CATEGORY,
    type ScanFinding,
    type ScanResult,
} from './codebase-scanner.js'

export {
    AutoFixer,
    type FixResult,
    type FixReport,
} from './auto-fixer.js'
