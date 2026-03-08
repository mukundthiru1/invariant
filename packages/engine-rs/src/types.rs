//! Core types for the INVARIANT detection engine.
//!
//! Every module in the engine depends on these types. They define the
//! vocabulary of invariant classes, detection results, proof structures,
//! and analysis outputs.
//!
//! Design principles:
//!   - Enums over strings: InvariantClass is a closed enum, not a string union.
//!     Adding a new class is a compile-time change that forces handling everywhere.
//!   - Copy-on-write strings: We use `Cow<'_, str>` at boundaries, owned `String`
//!     in stored results, and `&str` in hot-path analysis.
//!   - No Option abuse: fields are required unless genuinely optional.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Invariant Class Taxonomy ────────────────────────────────────────

/// Every attack class the engine can detect.
///
/// This is a closed enum — adding a new class requires updating this enum,
/// which produces compile errors everywhere the class must be handled
/// (match arms, serialization, MITRE mapping, chain definitions).
///
/// 66 classes across 17 categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InvariantClass {
    // SQL Injection (7)
    SqlStringTermination,
    SqlTautology,
    SqlUnionExtraction,
    SqlStackedExecution,
    SqlTimeOracle,
    SqlErrorOracle,
    SqlCommentTruncation,

    // XSS (5)
    XssTagInjection,
    XssAttributeEscape,
    XssEventHandler,
    XssProtocolHandler,
    XssTemplateExpression,

    // Path Traversal (4)
    PathDotdotEscape,
    PathNullTerminate,
    PathEncodingBypass,
    PathNormalizationBypass,

    // Command Injection (3)
    CmdSeparator,
    CmdSubstitution,
    CmdArgumentInjection,

    // SSRF (3)
    SsrfInternalReach,
    SsrfCloudMetadata,
    SsrfProtocolSmuggle,

    // Deserialization (3)
    DeserJavaGadget,
    DeserPhpObject,
    DeserPythonPickle,

    // Auth Bypass (3)
    AuthNoneAlgorithm,
    AuthHeaderSpoof,
    CorsOriginAbuse,

    // Prototype Pollution (2)
    ProtoPollution,
    ProtoPollutionGadget,

    // Log Injection (1)
    LogJndiLookup,

    // SSTI (2)
    SstiJinjaTwig,
    SstiElExpression,

    // NoSQL Injection (2)
    NosqlOperatorInjection,
    NosqlJsInjection,

    // LDAP Injection (1)
    LdapFilterInjection,

    // XXE (2)
    XxeEntityExpansion,
    XmlInjection,

    // CRLF (2)
    CrlfHeaderInjection,
    CrlfLogInjection,

    // GraphQL (2)
    GraphqlIntrospection,
    GraphqlBatchAbuse,

    // Open Redirect (1)
    OpenRedirectBypass,

    // Mass Assignment (1)
    MassAssignment,

    // ReDoS (1)
    RegexDos,

    // HTTP Smuggling (5)
    HttpSmuggleClTe,
    HttpSmuggleH2,
    HttpSmuggleChunkExt,
    HttpSmuggleZeroCl,
    HttpSmuggleExpect,

    // JSON-SQL Bypass (1)
    JsonSqlBypass,

    // Supply Chain (3)
    DependencyConfusion,
    PostinstallInjection,
    EnvExfiltration,

    // LLM (3)
    LlmPromptInjection,
    LlmDataExfiltration,
    LlmJailbreak,

    // WebSocket (2)
    WsInjection,
    WsHijack,

    // JWT (3)
    JwtKidInjection,
    JwtJwkEmbedding,
    JwtConfusion,

    // Cache (2)
    CachePoisoning,
    CacheDeception,

    // API Abuse (2)
    BolaIdor,
    ApiMassEnum,

    // OAST (1)
    OastInteraction,
}

impl InvariantClass {
    /// Attack category for grouping related classes.
    pub fn category(self) -> AttackCategory {
        use InvariantClass::*;
        match self {
            SqlStringTermination | SqlTautology | SqlUnionExtraction | SqlStackedExecution
            | SqlTimeOracle | SqlErrorOracle | SqlCommentTruncation | JsonSqlBypass => {
                AttackCategory::Sqli
            }

            XssTagInjection
            | XssAttributeEscape
            | XssEventHandler
            | XssProtocolHandler
            | XssTemplateExpression => AttackCategory::Xss,

            PathDotdotEscape | PathNullTerminate | PathEncodingBypass | PathNormalizationBypass => {
                AttackCategory::PathTraversal
            }

            CmdSeparator | CmdSubstitution | CmdArgumentInjection => AttackCategory::Cmdi,

            SsrfInternalReach | SsrfCloudMetadata | SsrfProtocolSmuggle => AttackCategory::Ssrf,

            DeserJavaGadget | DeserPhpObject | DeserPythonPickle => AttackCategory::Deser,

            AuthNoneAlgorithm | AuthHeaderSpoof | CorsOriginAbuse | JwtKidInjection
            | JwtJwkEmbedding | JwtConfusion => AttackCategory::Auth,

            HttpSmuggleClTe | HttpSmuggleH2 | HttpSmuggleChunkExt | HttpSmuggleZeroCl
            | HttpSmuggleExpect => AttackCategory::Smuggling,

            _ => AttackCategory::Injection,
        }
    }

    /// Default severity when this class is detected.
    pub fn default_severity(self) -> Severity {
        use InvariantClass::*;
        match self {
            // Critical: RCE, full data extraction, credential theft
            SqlUnionExtraction | SqlStackedExecution | CmdSeparator | CmdSubstitution
            | DeserJavaGadget | DeserPythonPickle | LogJndiLookup | SstiJinjaTwig
            | SstiElExpression | SsrfCloudMetadata | XxeEntityExpansion | LlmDataExfiltration
            | ProtoPollutionGadget | OastInteraction => Severity::Critical,

            // High: significant data access or code execution potential
            SqlStringTermination
            | SqlTautology
            | SqlTimeOracle
            | SqlErrorOracle
            | SqlCommentTruncation
            | JsonSqlBypass
            | XssTagInjection
            | XssEventHandler
            | XssProtocolHandler
            | PathDotdotEscape
            | PathEncodingBypass
            | SsrfInternalReach
            | SsrfProtocolSmuggle
            | DeserPhpObject
            | AuthNoneAlgorithm
            | AuthHeaderSpoof
            | ProtoPollution
            | NosqlOperatorInjection
            | NosqlJsInjection
            | CrlfHeaderInjection
            | HttpSmuggleClTe
            | HttpSmuggleH2
            | LlmPromptInjection
            | LlmJailbreak
            | JwtKidInjection
            | JwtJwkEmbedding
            | JwtConfusion
            | CachePoisoning
            | WsInjection
            | WsHijack
            | DependencyConfusion
            | PostinstallInjection
            | EnvExfiltration
            | CmdArgumentInjection => Severity::High,

            // Medium: information disclosure, limited impact
            XssAttributeEscape
            | XssTemplateExpression
            | PathNullTerminate
            | PathNormalizationBypass
            | CorsOriginAbuse
            | LdapFilterInjection
            | XmlInjection
            | CrlfLogInjection
            | GraphqlIntrospection
            | GraphqlBatchAbuse
            | OpenRedirectBypass
            | MassAssignment
            | RegexDos
            | HttpSmuggleChunkExt
            | HttpSmuggleZeroCl
            | HttpSmuggleExpect
            | CacheDeception
            | BolaIdor
            | ApiMassEnum => Severity::Medium,
        }
    }

    /// The proof domain this class maps to for proof construction.
    pub fn proof_domain(self) -> &'static str {
        use InvariantClass::*;
        match self {
            SqlStringTermination | SqlTautology | SqlUnionExtraction | SqlStackedExecution
            | SqlTimeOracle | SqlErrorOracle | SqlCommentTruncation | JsonSqlBypass => "sqli",

            XssTagInjection
            | XssAttributeEscape
            | XssEventHandler
            | XssProtocolHandler
            | XssTemplateExpression => "xss",

            CmdSeparator | CmdSubstitution | CmdArgumentInjection => "cmdi",

            PathDotdotEscape | PathNullTerminate | PathEncodingBypass | PathNormalizationBypass => {
                "path_traversal"
            }

            SsrfInternalReach | SsrfCloudMetadata | SsrfProtocolSmuggle => "ssrf",

            XxeEntityExpansion | XmlInjection => "xxe",

            SstiJinjaTwig | SstiElExpression => "ssti",

            _ => "generic",
        }
    }
}

// ── Attack Category ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Broad attack family used for aggregation and policy tuning.
pub enum AttackCategory {
    Sqli,
    Xss,
    PathTraversal,
    Cmdi,
    Ssrf,
    Deser,
    Auth,
    Injection,
    Smuggling,
}

// ── Severity ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Severity ladder used by block-threshold policy.
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Block confidence threshold for this severity level.
    /// Lower threshold = easier to block = more aggressive defense.
    pub fn block_threshold(self) -> f64 {
        match self {
            Severity::Critical => 0.45,
            Severity::High => 0.65,
            Severity::Medium => 0.80,
            Severity::Low => 0.92,
        }
    }
}

// ── Proof Step ──────────────────────────────────────────────────────

/// Phase of the exploitation algebra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofOperation {
    ContextEscape,
    PayloadInject,
    SyntaxRepair,
    EncodingDecode,
    TypeCoerce,
    SemanticEval,
}

/// A single step in a property violation proof.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofStep {
    /// Phase of the exploitation algebra.
    pub operation: ProofOperation,
    /// The exact substring being analyzed.
    pub input: String,
    /// What it becomes when interpreted in the target context.
    pub output: String,
    /// Which formal property this step violates.
    pub property: String,
    /// Byte offset in the original input where this step begins.
    pub offset: usize,
    /// Confidence that this step is correctly identified (0.0–1.0).
    pub confidence: f64,
    /// Whether this step has been computationally verified.
    pub verified: bool,
    /// Verification method used.
    pub verification_method: Option<String>,
}

// ── Proof Verification Level ────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Verification confidence tier for an assembled [`PropertyProof`].
pub enum ProofVerificationLevel {
    None,
    Structural,
    Verified,
    FormallyVerified,
}

// ── Property Proof ──────────────────────────────────────────────────

/// A constructive proof that an input violates a mathematical property.
///
/// Each proof step is independently verifiable. The complete proof shows
/// the full exploitation chain: context escape → payload injection → syntax repair.
///
/// This is what SOC analysts read instead of "confidence: 0.92."
/// It is machine-checkable and forensically admissible.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropertyProof {
    /// The formal property statement that was violated.
    pub property: String,
    /// The exact witness substring demonstrating the violation.
    pub witness: String,
    /// Ordered steps showing how the violation works.
    pub steps: Vec<ProofStep>,
    /// Whether all three phases (escape + payload + repair) are present.
    pub is_complete: bool,
    /// The interpretation domain (sqli, xss, cmdi, etc.).
    pub domain: String,
    /// What the attack would accomplish if it succeeded.
    pub impact: String,
    /// Confidence derived from proof structure (independent of heuristics).
    pub proof_confidence: f64,
    /// Number of steps that are computationally verified.
    pub verified_steps: u32,
    /// Verification coverage: verified_steps / steps.len().
    pub verification_coverage: f64,
    /// Aggregate verification level.
    pub verification_level: ProofVerificationLevel,
}

impl PropertyProof {
    /// Recompute verification metrics from step data.
    pub fn recompute_verification(&mut self) {
        let total = self.steps.len() as u32;
        let verified = self.steps.iter().filter(|s| s.verified).count() as u32;
        self.verified_steps = verified;
        self.verification_coverage = if total > 0 {
            verified as f64 / total as f64
        } else {
            0.0
        };
        self.verification_level = match self.verification_coverage {
            c if c >= 1.0 => ProofVerificationLevel::Verified,
            c if c >= 0.5 => ProofVerificationLevel::Structural,
            _ => ProofVerificationLevel::None,
        };
    }
}

impl Default for PropertyProof {
    fn default() -> Self {
        Self {
            property: String::new(),
            witness: String::new(),
            steps: Vec::new(),
            is_complete: false,
            domain: String::new(),
            impact: String::new(),
            proof_confidence: 0.0,
            verified_steps: 0,
            verification_coverage: 0.0,
            verification_level: ProofVerificationLevel::None,
        }
    }
}

// ── Detection Level Result ──────────────────────────────────────────

/// Structured evidence from an L2 evaluator proof step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructuredEvidence {
    /// Algebraic proof operation represented by this evidence.
    pub operation: ProofOperation,
    /// Raw input substring matched by the evaluator.
    pub matched_input: String,
    /// Evaluator interpretation of the matched input.
    pub interpretation: String,
    /// Byte offset in the original payload.
    pub offset: usize,
    /// Property statement tied to this evidence node.
    pub property: String,
}

/// Detection result from a single level (L1 or L2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Whether this level detected a violation.
    pub detected: bool,
    /// Confidence in the detection (0.0–1.0).
    pub confidence: f64,
    /// Human-readable explanation.
    pub explanation: String,
    /// Raw evidence string.
    pub evidence: Option<String>,
    /// Structured proof evidence from L2 evaluators.
    pub structured_evidence: Vec<StructuredEvidence>,
}

impl DetectionResult {
    /// A negative detection result.
    pub fn none() -> Self {
        Self {
            detected: false,
            confidence: 0.0,
            explanation: String::new(),
            evidence: None,
            structured_evidence: Vec::new(),
        }
    }

    /// A positive detection with confidence and explanation.
    pub fn detected(confidence: f64, explanation: impl Into<String>) -> Self {
        Self {
            detected: true,
            confidence,
            explanation: explanation.into(),
            evidence: None,
            structured_evidence: Vec::new(),
        }
    }
}

impl Default for DetectionResult {
    fn default() -> Self {
        Self::none()
    }
}

// ── Invariant Match ─────────────────────────────────────────────────

/// A single detection from the analysis pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvariantMatch {
    /// Which invariant class was matched.
    pub class: InvariantClass,
    /// Detection confidence (0.0–1.0).
    pub confidence: f64,
    /// Attack category.
    pub category: AttackCategory,
    /// Severity.
    pub severity: Severity,
    /// Was this caught by L2 but NOT by L1?
    pub is_novel_variant: bool,
    /// Description.
    pub description: String,
    /// Which detection levels fired.
    pub detection_levels: DetectionLevels,
    /// L2 evidence detail.
    pub l2_evidence: Option<String>,
    /// Constructive proof of property violation.
    pub proof: Option<PropertyProof>,
    /// CVE enrichment from exploit knowledge graph.
    pub cve_enrichment: Option<CveEnrichment>,
}

/// Which detection levels contributed to a final match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionLevels {
    /// Regex fast-path detector fired.
    pub l1: bool,
    /// Structural evaluator fired.
    pub l2: bool,
    /// L1 and L2 both fired for the same class.
    pub convergent: bool,
}

impl Default for DetectionLevels {
    fn default() -> Self {
        Self {
            l1: false,
            l2: false,
            convergent: false,
        }
    }
}

/// CVE intelligence attached to a specific class match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveEnrichment {
    /// CVE identifiers mapped to the match.
    pub linked_cves: Vec<String>,
    /// Whether any linked CVE is currently exploited in the wild.
    pub actively_exploited: bool,
    /// Maximum EPSS score observed among linked CVEs.
    pub highest_epss: f64,
    /// Whether independent verification artifacts are available.
    pub verification_available: bool,
}

// ── Algebraic Composition ───────────────────────────────────────────

/// The exploitation algebra: escape ∘ payload ∘ repair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlgebraicComposition {
    /// Escape operation if one is explicitly observed.
    pub escape: Option<EscapeOperation>,
    /// Payload operation introduced by attacker-controlled input.
    pub payload: PayloadOperation,
    /// Syntax repair operation making the payload parseable.
    pub repair: RepairOperation,
    /// Input interpretation context.
    pub context: InputContext,
    /// Confidence of the composed chain.
    pub confidence: f64,
    /// Class represented by this composition.
    pub derived_class: InvariantClass,
    /// True when composition has all required phases.
    pub is_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// How attacker-controlled input exits the original parsing boundary.
pub enum EscapeOperation {
    StringTerminate,
    ContextBreak,
    EncodingBypass,
    CommentBypass,
    NullTerminate,
    WhitespaceBypass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Payload semantics introduced after context escape.
pub enum PayloadOperation {
    Tautology,
    UnionExtract,
    TimeOracle,
    ErrorOracle,
    StackedExec,
    TagInject,
    EventHandler,
    CmdSubstitute,
    PathEscape,
    EntityExpand,
    ProtoPollute,
    NosqlOperator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Operation that restores syntactic validity after payload insertion.
pub enum RepairOperation {
    CommentClose,
    StringClose,
    TagClose,
    NaturalEnd,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Parser/runtime context used to interpret the input stream.
pub enum InputContext {
    Sql,
    Html,
    Shell,
    Xml,
    Json,
    Ldap,
    Template,
    Graphql,
    Url,
    Header,
    Unknown,
}

// ── Inter-Class Correlation ─────────────────────────────────────────

/// Correlation generated when multiple related classes co-occur.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterClassCorrelation {
    /// Correlated classes in this cluster.
    pub classes: Vec<InvariantClass>,
    /// Aggregate confidence for the cluster.
    pub compound_confidence: f64,
    /// Machine-readable reason string.
    pub reason: String,
}

// ── Block Recommendation ────────────────────────────────────────────

/// Final blocking recommendation derived from matches and compositions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockRecommendation {
    /// Whether the request should be blocked.
    pub block: bool,
    /// Confidence of the recommendation.
    pub confidence: f64,
    /// Explanation for downstream logging and SOC review.
    pub reason: String,
    /// Confidence threshold used for this decision.
    pub threshold: f64,
}

// ── Analysis Request / Result ───────────────────────────────────────

/// Request payload for deep engine analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisRequest {
    /// Untrusted input to analyze.
    pub input: String,
    /// Optional caller-supplied context.
    pub known_context: Option<InputContext>,
    /// Optional source reputation score in `[0.0, 1.0]`.
    pub source_reputation: Option<f64>,
    /// Optional HTTP metadata.
    pub request_meta: Option<RequestMeta>,
}

/// Additional request metadata for context-aware detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestMeta {
    /// HTTP method, when available.
    pub method: Option<String>,
    /// Request path, when available.
    pub path: Option<String>,
    /// Content type header, when available.
    pub content_type: Option<String>,
}

/// Exception rule used to suppress specific detections after they are generated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionRule {
    /// Optional path glob pattern (for example: `/api/search/*`).
    pub path_pattern: Option<String>,
    /// Optional class scope. When omitted, applies to any class.
    pub class: Option<InvariantClass>,
    /// Optional source IP glob pattern.
    pub source_ip_pattern: Option<String>,
    /// Human-readable reason for the exception.
    pub reason: String,
    /// User or service that created the exception.
    pub created_by: String,
}

impl ExceptionRule {
    /// Return true when this rule matches all configured dimensions.
    pub fn matches(&self, path: &str, class: InvariantClass, source_ip: &str) -> bool {
        if let Some(pattern) = self.path_pattern.as_deref() {
            if !glob_matches(pattern, path) {
                return false;
            }
        }
        if let Some(rule_class) = self.class {
            if rule_class != class {
                return false;
            }
        }
        if let Some(pattern) = self.source_ip_pattern.as_deref() {
            if !glob_matches(pattern, source_ip) {
                return false;
            }
        }
        true
    }
}

/// Runtime exception config controlling post-detection suppression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ExceptionConfig {
    /// Ordered exception rules. First match wins for logging, but any match suppresses.
    pub rules: Vec<ExceptionRule>,
    /// Master toggle for exception processing.
    pub enabled: bool,
}

impl ExceptionConfig {
    /// Return true when a detection should be suppressed for this request context.
    pub fn should_skip(&self, path: &str, class: InvariantClass, source_ip: &str) -> bool {
        self.find_matching_rule(path, class, source_ip).is_some()
    }

    /// Return the first matching rule when exceptions are enabled.
    pub fn find_matching_rule(
        &self,
        path: &str,
        class: InvariantClass,
        source_ip: &str,
    ) -> Option<&ExceptionRule> {
        if !self.enabled || self.rules.is_empty() {
            return None;
        }
        self.rules
            .iter()
            .find(|rule| rule.matches(path, class, source_ip))
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let p = pattern.as_bytes();
    let v = value.as_bytes();
    let mut pi = 0usize;
    let mut vi = 0usize;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0usize;

    while vi < v.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_idx = Some(pi);
            match_idx = vi;
            pi += 1;
        } else if let Some(star) = star_idx {
            pi = star + 1;
            match_idx += 1;
            vi = match_idx;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }

    pi == p.len()
}

/// Multi-domain interpretation output for polyglot payloads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolyglotAnalysis {
    /// True when multiple domains were simultaneously detected.
    pub is_polyglot: bool,
    /// Domains detected in the payload.
    pub domains: Vec<String>,
    /// Number of domains detected.
    pub domain_count: usize,
    /// Confidence boost derived from polyglot evidence.
    pub confidence_boost: f64,
    /// Human-readable detection detail.
    pub detail: String,
}

/// Intent classifier output serialized for API response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntentClassification {
    /// Highest-confidence intent category.
    pub primary_intent: String,
    /// Candidate intents considered.
    pub intents: Vec<String>,
    /// Confidence of intent classification.
    pub confidence: f64,
    /// Human-readable classification detail.
    pub detail: String,
    /// Severity multiplier derived from intent.
    pub severity_multiplier: f64,
    /// Targets inferred from payload semantics.
    pub targets: Vec<String>,
}

/// Full analysis output returned by the detection engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Detected invariant matches.
    pub matches: Vec<InvariantMatch>,
    /// Composed exploitation algebra relations.
    pub compositions: Vec<AlgebraicComposition>,
    /// Cross-class correlation outputs.
    pub correlations: Vec<InterClassCorrelation>,
    /// Final block recommendation.
    pub recommendation: BlockRecommendation,
    /// Count of L2-only novel detections.
    pub novel_by_l2: u32,
    /// Reserved for future L3 novel detections.
    pub novel_by_l3: u32,
    /// Number of convergent (L1+L2) detections.
    pub convergent: u32,
    /// Processing time in microseconds.
    pub processing_time_us: f64,
    /// Contexts involved in this analysis.
    pub contexts: Vec<InputContext>,
    /// Optional aggregate CVE enrichment.
    pub cve_enrichment: Option<CveEnrichmentSummary>,
    /// Optional polyglot analysis output.
    pub polyglot: Option<PolyglotAnalysis>,
    /// Optional anomaly score from entropy model.
    pub anomaly_score: Option<f64>,
    /// Whether encoding evasion was detected.
    pub encoding_evasion: bool,
    /// Optional intent classification.
    pub intent: Option<IntentClassification>,
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self {
            matches: Vec::new(),
            compositions: Vec::new(),
            correlations: Vec::new(),
            recommendation: BlockRecommendation::default(),
            novel_by_l2: 0,
            novel_by_l3: 0,
            convergent: 0,
            processing_time_us: 0.0,
            contexts: Vec::new(),
            cve_enrichment: None,
            polyglot: None,
            anomaly_score: None,
            encoding_evasion: false,
            intent: None,
        }
    }
}

/// Summary of CVE enrichment across all matches in an analysis result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveEnrichmentSummary {
    /// Number of unique linked CVEs across all matches.
    pub total_linked_cves: u32,
    /// Identifiers of classes with active exploitation indicators.
    pub actively_exploited_classes: Vec<String>,
    /// Highest EPSS score observed across linked CVEs.
    pub highest_epss: f64,
}

impl Default for BlockRecommendation {
    fn default() -> Self {
        Self {
            block: false,
            confidence: 0.0,
            reason: "no_detections".to_owned(),
            threshold: 0.0,
        }
    }
}

impl Default for AnalysisRequest {
    fn default() -> Self {
        Self {
            input: String::new(),
            known_context: None,
            source_reputation: None,
            request_meta: None,
        }
    }
}

impl Default for RequestMeta {
    fn default() -> Self {
        Self {
            method: None,
            path: None,
            content_type: None,
        }
    }
}

impl Default for PolyglotAnalysis {
    fn default() -> Self {
        Self {
            is_polyglot: false,
            domains: Vec::new(),
            domain_count: 0,
            confidence_boost: 0.0,
            detail: String::new(),
        }
    }
}

impl Default for IntentClassification {
    fn default() -> Self {
        Self {
            primary_intent: "Unknown".to_owned(),
            intents: Vec::new(),
            confidence: 0.0,
            detail: String::new(),
            severity_multiplier: 1.0,
            targets: Vec::new(),
        }
    }
}

impl Default for CveEnrichmentSummary {
    fn default() -> Self {
        Self {
            total_linked_cves: 0,
            actively_exploited_classes: Vec::new(),
            highest_epss: 0.0,
        }
    }
}

// ── Unified Errors ──────────────────────────────────────────────────

/// Unified error type for engine and runtime fallible APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantError {
    /// The caller provided an invalid or missing input value.
    InvalidInput(String),
    /// Internal processing failed with a non-recoverable condition.
    Internal(String),
}

impl InvariantError {
    /// Build an invalid-input error.
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput(message.into())
    }

    /// Build an internal processing error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

impl fmt::Display for InvariantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid_input:{message}"),
            Self::Internal(message) => write!(f, "internal_error:{message}"),
        }
    }
}

impl std::error::Error for InvariantError {}

/// Unified `Result` alias used by additive fallible APIs.
pub type InvariantResult<T> = Result<T, InvariantError>;

// ── Confidence Model Constants ──────────────────────────────────────

/// The L2-primary confidence model.
///
/// When L1 and L2 agree (convergent), confidence is boosted.
/// When only L1 fires, confidence is attenuated.
/// When only L2 fires, the detection is flagged as a novel variant.
pub mod confidence {
    /// Confidence when both L1 and L2 agree.
    pub const CONVERGENT: f64 = 0.97;
    /// Confidence for L2-only detection (novel variant).
    pub const L2_ONLY: f64 = 0.92;
    /// Base L1-only confidence.
    pub const L1_BASE: f64 = 0.85;
    /// Attenuation factor when L2 is silent (L1-only).
    pub const L1_ATTENUATION: f64 = 0.82;
    /// Convergent confidence boost.
    pub const CONVERGENT_BOOST: f64 = 0.05;
}

// ── Tokenizer Limits ────────────────────────────────────────────────

/// Maximum input size any tokenizer will process (16 KiB).
pub const MAX_TOKENIZER_INPUT: usize = 16_384;
/// Maximum tokens any tokenizer will emit.
pub const MAX_TOKEN_COUNT: usize = 4_096;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rule() -> ExceptionRule {
        ExceptionRule {
            path_pattern: Some("/api/search/*".to_owned()),
            class: Some(InvariantClass::SqlTautology),
            source_ip_pattern: Some("10.0.*".to_owned()),
            reason: "test".to_owned(),
            created_by: "unit-test".to_owned(),
        }
    }

    #[test]
    fn exception_rule_matches_with_globs() {
        let rule = sample_rule();
        assert!(rule.matches("/api/search/foo", InvariantClass::SqlTautology, "10.0.1.42"));
    }

    #[test]
    fn exception_rule_rejects_non_matching_class() {
        let rule = sample_rule();
        assert!(!rule.matches(
            "/api/search/foo",
            InvariantClass::XssTagInjection,
            "10.0.1.42"
        ));
    }

    #[test]
    fn exception_config_disabled_never_skips() {
        let cfg = ExceptionConfig {
            rules: vec![sample_rule()],
            enabled: false,
        };
        assert!(!cfg.should_skip("/api/search/foo", InvariantClass::SqlTautology, "10.0.1.42"));
    }

    #[test]
    fn exception_config_empty_rules_never_skips() {
        let cfg = ExceptionConfig {
            rules: Vec::new(),
            enabled: true,
        };
        assert!(!cfg.should_skip("/api/search/foo", InvariantClass::SqlTautology, "10.0.1.42"));
    }

    #[test]
    fn exception_config_finds_first_matching_rule() {
        let first = ExceptionRule {
            path_pattern: Some("/api/search/*".to_owned()),
            class: Some(InvariantClass::SqlTautology),
            source_ip_pattern: None,
            reason: "first".to_owned(),
            created_by: "unit-test".to_owned(),
        };
        let second = ExceptionRule {
            path_pattern: Some("/api/search/*".to_owned()),
            class: Some(InvariantClass::SqlTautology),
            source_ip_pattern: None,
            reason: "second".to_owned(),
            created_by: "unit-test".to_owned(),
        };
        let cfg = ExceptionConfig {
            rules: vec![first, second],
            enabled: true,
        };
        let matched =
            cfg.find_matching_rule("/api/search/foo", InvariantClass::SqlTautology, "1.2.3.4");
        assert_eq!(matched.map(|r| r.reason.as_str()), Some("first"));
    }

    #[test]
    fn exception_rule_with_no_constraints_matches_any_context() {
        let rule = ExceptionRule {
            path_pattern: None,
            class: None,
            source_ip_pattern: None,
            reason: "all".to_owned(),
            created_by: "unit-test".to_owned(),
        };
        assert!(rule.matches("/any", InvariantClass::SqlTautology, "127.0.0.1"));
    }
}
