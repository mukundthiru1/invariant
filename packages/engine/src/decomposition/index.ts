/**
 * INVARIANT — Decomposition Pipeline Integration
 *
 * The master orchestrator that connects all decomposition components:
 *   1. Input Decomposer: multi-layer decode → context detect → property extract
 *   2. Exploit Knowledge Graph: CVE → invariant property → defense rule mapping
 *   3. Exploit Verifier: zero-damage probes to confirm detections
 *   4. Campaign Intelligence: behavioral fingerprinting + campaign detection
 *
 * This module provides the unified API that the main worker uses.
 */

export { multiLayerDecode, detectContexts, decomposeInput } from './input-decomposer'
export type {
    InputContext,
    ExtractedProperty,
    DecompositionResult,
    DecodedForms,
} from './input-decomposer'

export {
    ExploitKnowledgeGraph,
    FRAMEWORK_PROFILES,
} from './exploit-knowledge-graph'
export type {
    ExploitKnowledgeEntry,
    TechProduct,
    TechCategory,
    VersionRange,
    InvariantPropertyMapping,
    DefenseRule,
    VerificationStep,
    VerificationTechnique,
    FrameworkProfile,
    FrameworkProbe,
    AttackVector,
    ExploitSource,
} from './exploit-knowledge-graph'

export { ExploitVerifier } from './exploit-verifier'
export type {
    ProbeLevel,
    VerificationRequest,
    VerificationResult,
    ProbeEvidence,
    ProbeAuditEntry,
} from './exploit-verifier'

export { CampaignIntelligence } from './campaign-intelligence'
export type {
    BehavioralFingerprint,
    EncodingPreference,
    AttackPhase,
    AttackerSession,
    CampaignSignal,
    Campaign,
    CampaignType,
} from './campaign-intelligence'
