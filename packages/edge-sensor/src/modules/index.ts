/**
 * @santh/edge-sensor — Module Barrel Export
 *
 * All sensor-specific modules exported from a single entry point.
 * These modules handle the layers beyond pure detection:
 * state persistence, application modeling, privilege analysis,
 * response auditing, internal probing, and threat scoring.
 */

// ── Core Detection Layers ────────────────────────────────────────
export { analyzeRequestBody, extractFromJson, extractFromFormEncoded, extractFromMultipart } from './body-analysis.js'
export type { BodyAnalysisResult } from './body-analysis.js'

export { ThreatScoringEngine } from './threat-scoring.js'
export type { ThreatSignal, ThreatScore, SignalContribution, ChainIndicator } from './threat-scoring.js'

export { DeceptionLayer, DEFAULT_DECEPTION_CONFIG } from './deception-layer.js'
export type { DeceptionConfig, TrackingToken, AttackerAction, AttackerDossier } from './deception-layer.js'

// ── Response Audit (L7) ──────────────────────────────────────────
export { ResponseAuditor } from './response-audit.js'
export type { PostureFinding, PostureReport } from './response-audit.js'

// ── Internal Probing (L8) ────────────────────────────────────────
export { InternalProber } from './internal-probe.js'
export type { ProbeTarget, ProbeResult } from './internal-probe.js'

// ── Application Intelligence ─────────────────────────────────────
export { ApplicationModel, normalizePathPattern, detectAuthType, detectSensitiveResponse } from './application-model.js'
export type { EndpointSnapshot, ApplicationModelSnapshot, AuthType, ParameterStats, EndpointProfile } from './application-model.js'

export { PrivilegeGraph } from './privilege-graph.js'
export type { PrivilegeLevel, EndpointPrivilege, PrivilegeEdge, PrivilegeGraphSnapshot, PrivilegeObservation } from './privilege-graph.js'

export { PathEnumerator } from './path-enumeration.js'
export type { AlternativePath, PathEnumerationResult, PathEnumerationReport } from './path-enumeration.js'

export { BlastRadiusEngine } from './blast-radius.js'
export type { BlastRadiusScope, EndpointImpact, DataImpact, BlastRadiusReport, BlastRadiusAnalysis } from './blast-radius.js'

// ── CVE-Stack Correlation ────────────────────────────────────────
export { CveStackCorrelator, TechStackTracker } from './cve-stack-correlation.js'
export type { CpeMapping, VulnerabilityProfile } from './cve-stack-correlation.js'

// ── Reactivation Engine ──────────────────────────────────────────
export { ReactivationEngine, detectConditions } from './reactivation-engine.js'
export type { ReactivationMatch, ReactivationRule, ReactivationReport } from './reactivation-engine.js'

// ── State Persistence ────────────────────────────────────────────
export { SensorStateManager, KV_KEYS } from './sensor-state.js'
export type {
    SensorConfig,
    PersistedModelState, PersistedEndpoint,
    PersistedPosture, PersistedPostureFinding,
    PersistedReputation, IPReputationEntry,
    PersistedRules, DynamicRule, DynamicRulePattern,
    PersistedStats,
} from './sensor-state.js'

// ── Rule Sync ────────────────────────────────────────────────────
export { syncRulesFromIntel, matchDynamicRules } from './rule-sync.js'
export type { RuleSyncResult, DynamicRuleMatch } from './rule-sync.js'
export { startRuleStream, stopRuleStream, getRuleStreamStatus } from './rule-stream.js'
export type { RuleStreamStatus, RuleStreamOptions } from './rule-stream.js'

// ── Drift Detection (from Axiom Drift merge) ─────────────────────
export { DriftDetector } from './drift-detector.js'
export type { DriftEvent, DriftType, DriftSeverity, PostureSnapshot, EndpointSnapshot as DriftEndpointSnapshot } from './drift-detector.js'

// ── IOC Feed Correlation (from Axiom Drift merge) ────────────────
export { IOCCorrelator } from './ioc-correlator.js'
export type { IOCEntry, IOCMatch, IOCType } from './ioc-correlator.js'

// ── Multi-Dimensional Risk Surface (from Axiom Drift merge) ──────
export { RiskSurfaceCalculator } from './risk-dimensions.js'
export type { RiskSurface, RiskFactor as RiskDimensionFactor } from './risk-dimensions.js'

