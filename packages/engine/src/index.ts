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
 */

export {
    InvariantEngine,
    type InvariantClass,
    type InvariantDefinition,
    type InvariantMatch,
} from './invariant-engine.js'

export {
    ChainCorrelator,
    ATTACK_CHAINS,
    type ChainDefinition,
    type ChainStep,
    type ChainSignal,
    type ChainMatch,
} from './chain-detector.js'

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
    InputDecomposer,
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

// ── Evidence Sealing (from Axiom Drift merge) ────────────────────
export {
    EvidenceSealer,
    type EvidenceSeal,
    type SignalWithProof,
    type SealedBatch,
} from './evidence/index.js'

// ── MITRE ATT&CK Mapping (from Axiom Drift merge) ───────────────
export {
    MitreMapper,
    type MitreTechnique,
    type MitreTactic,
    type MitreMapping,
    type KillChainPhase,
} from './mitre-mapper.js'

