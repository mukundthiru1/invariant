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
} from './invariant-engine.js'

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
