//! Attack Chain Detection
//!
//! Detects multi-step attack sequences by correlating individual invariant
//! signals over time from the same source. Individual payloads may be
//! low-confidence. Chains compound confidence.
//!
//! The fundamental insight:
//!   A single `path_dotdot_escape` at 0.6 confidence is ambiguous.
//!   `path_dotdot_escape` → `path_sensitive_file` → `credential_extraction`
//!   from the same source within 60 seconds is a confirmed LFI attack chain.

use crate::types::InvariantClass;
use std::collections::{HashMap, HashSet};

// ── Chain Types ──────────────────────────────────────────────────

/// One stage in a chain definition.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainStep {
    /// Classes that can satisfy this step.
    pub classes: Vec<InvariantClass>,
    /// Behavior markers that can satisfy this step.
    pub behaviors: Vec<String>,
    /// Minimum signal confidence required for this step.
    pub min_confidence: f64,
    /// Human-readable step description.
    pub description: String,
    /// Optional defense action recommendation at this stage.
    pub defense: Option<DefenseAction>,
}

/// Recommended defense action at a chain step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefenseAction {
    Alert,
    Throttle,
    Challenge,
    Block,
}

/// Attack chain definition.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainDefinition {
    /// Stable chain identifier.
    pub id: &'static str,
    /// Human-readable chain name.
    pub name: &'static str,
    /// Chain description.
    pub description: &'static str,
    /// ATT&CK techniques associated with the chain.
    pub mitre: Vec<&'static str>,
    /// Severity classification.
    pub severity: ChainSeverity,
    /// Ordered chain steps.
    pub steps: Vec<ChainStep>,
    /// Matching window in seconds.
    pub window_seconds: u64,
    /// Minimum matched steps needed for a chain match.
    pub minimum_steps: Option<usize>,
    /// Confidence offset applied by chain completion.
    pub confidence_boost: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSeverity {
    Critical,
    High,
    Medium,
}

impl ChainSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
        }
    }
}

/// Signal ingested by the chain correlator.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainSignal {
    /// Source identifier.
    pub source_hash: String,
    /// Detected classes for this event.
    pub classes: Vec<InvariantClass>,
    /// Derived behavior markers for this event.
    pub behaviors: Vec<String>,
    /// Event confidence.
    pub confidence: f64,
    /// Request path.
    pub path: String,
    /// HTTP method.
    pub method: String,
    /// Event timestamp in milliseconds.
    pub timestamp: u64,
}

/// Correlator output for a matched chain instance.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainMatch {
    /// Matched chain identifier.
    pub chain_id: String,
    /// Matched chain name.
    pub name: String,
    /// Number of steps currently matched.
    pub steps_matched: usize,
    /// Total steps in the chain definition.
    pub total_steps: usize,
    /// Completion ratio in `[0.0, 1.0]`.
    pub completion: f64,
    /// Aggregate chain confidence.
    pub confidence: f64,
    /// Chain severity.
    pub severity: ChainSeverity,
    /// Chain description.
    pub description: String,
    /// Recommended runtime action.
    pub recommended_action: RecommendedAction,
    /// Per-step matching evidence.
    pub step_matches: Vec<StepMatch>,
    /// Duration from first to latest matched step in seconds.
    pub duration_seconds: u64,
    /// Primary source hash for this chain state.
    pub source_hash: String,
    /// All associated sources participating in the chain.
    pub associated_sources: Vec<String>,
}

/// Evidence for one satisfied step in a chain match.
#[derive(Debug, Clone, PartialEq)]
pub struct StepMatch {
    /// Step index in chain definition.
    pub step_index: usize,
    /// Step description.
    pub description: String,
    /// Matched class label.
    pub matched_class: String,
    /// Confidence for this step.
    pub confidence: f64,
    /// Event timestamp.
    pub timestamp: u64,
    /// Event path.
    pub path: String,
    /// Event source hash.
    pub source_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendedAction {
    Monitor,
    Throttle,
    Challenge,
    Block,
    Lockdown,
}

impl RecommendedAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monitor => "monitor",
            Self::Throttle => "throttle",
            Self::Challenge => "challenge",
            Self::Block => "block",
            Self::Lockdown => "lockdown",
        }
    }
}

// ── Chain State Store ────────────────────────────────────────────

struct SatisfiedStep {
    signal: ChainSignal,
    confidence: f64,
}

struct ChainStateNode {
    chain_id: String,
    source_hash: String,
    sources: HashSet<String>,
    satisfied_steps: HashMap<usize, SatisfiedStep>,
    noise_events: usize,
    start_time: u64,
    last_update: u64,
    status: ChainStatus,
    steps_matched: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChainStatus {
    InProgress,
    Completed,
    Expired,
}

struct ChainStateStore {
    states: HashMap<String, HashMap<String, ChainStateNode>>,
    max_sources: usize,
}

impl ChainStateStore {
    fn new(max_sources: usize) -> Self {
        Self {
            states: HashMap::new(),
            max_sources,
        }
    }

    fn get_or_create(
        &mut self,
        actor_key: &str,
        chain_id: &str,
        source_hash: &str,
        _window_seconds: u64,
    ) -> &mut ChainStateNode {
        let by_source = self.states.entry(actor_key.to_owned()).or_default();

        by_source
            .entry(chain_id.to_owned())
            .or_insert_with(|| ChainStateNode {
                chain_id: chain_id.to_owned(),
                source_hash: source_hash.to_owned(),
                sources: {
                    let mut sources = HashSet::new();
                    sources.insert(source_hash.to_owned());
                    sources
                },
                noise_events: 0,
                satisfied_steps: HashMap::new(),
                start_time: 0,
                last_update: 0,
                status: ChainStatus::InProgress,
                steps_matched: 0,
            });

        by_source.get_mut(chain_id).unwrap()
    }

    fn advance(
        &mut self,
        actor_key: &str,
        source_hash: &str,
        chain_id: &str,
        step_index: usize,
        signal: &ChainSignal,
        window_seconds: u64,
    ) {
        let state = self.get_or_create(actor_key, chain_id, source_hash, window_seconds);
        if state.status != ChainStatus::InProgress {
            return;
        }

        if state.satisfied_steps.is_empty() {
            state.start_time = signal.timestamp;
        } else if signal.timestamp.saturating_sub(state.start_time) > window_seconds * 1000 {
            state.status = ChainStatus::Expired;
            return;
        }

        if state.satisfied_steps.contains_key(&step_index) {
            return;
        }
        state.sources.insert(source_hash.to_owned());
        if signal.confidence < 0.35 {
            state.noise_events += 1;
        }
        state.satisfied_steps.insert(
            step_index,
            SatisfiedStep {
                signal: signal.clone(),
                confidence: signal.confidence,
            },
        );
        state.steps_matched = state.satisfied_steps.len();
        state.last_update = signal.timestamp;
    }

    fn complete(&mut self, source_hash: &str, chain_id: &str) {
        if let Some(by_source) = self.states.get_mut(source_hash) {
            if let Some(state) = by_source.get_mut(chain_id) {
                state.status = ChainStatus::Completed;
                state.last_update = current_time_ms();
            }
        }
    }

    fn get_state(&self, source_hash: &str, chain_id: &str) -> Option<&ChainStateNode> {
        self.states.get(source_hash)?.get(chain_id)
    }

    fn get_all_for_source(&self, source_hash: &str) -> Vec<&ChainStateNode> {
        self.states
            .get(source_hash)
            .map(|m| m.values().collect())
            .unwrap_or_default()
    }

    fn all_sources(&self) -> Vec<&str> {
        self.states.keys().map(|s| s.as_str()).collect()
    }

    fn remove_source(&mut self, source_hash: &str) {
        self.states.remove(source_hash);
    }

    fn prune_expired(&mut self, max_window_seconds: u64) {
        let cutoff = current_time_ms().saturating_sub(max_window_seconds * 1000 * 2);
        let sources: Vec<String> = self.states.keys().cloned().collect();
        for source_hash in sources {
            if let Some(by_chain) = self.states.get_mut(&source_hash) {
                let expired_chains: Vec<String> = by_chain
                    .iter()
                    .filter(|(_, state)| state.last_update < cutoff)
                    .map(|(id, _)| id.clone())
                    .collect();
                for chain_id in expired_chains {
                    by_chain.remove(&chain_id);
                }
                if by_chain.is_empty() {
                    self.states.remove(&source_hash);
                }
            }
        }

        if self.states.len() > self.max_sources {
            let mut entries: Vec<(String, u64)> = self
                .states
                .iter()
                .map(|(k, v)| {
                    let latest = v.values().map(|s| s.last_update).max().unwrap_or(0);
                    (k.clone(), latest)
                })
                .collect();
            entries.sort_by_key(|e| e.1);
            let evict = self.states.len() - self.max_sources;
            for i in 0..evict {
                self.states.remove(&entries[i].0);
            }
        }
    }

    fn source_count(&self) -> usize {
        self.states.len()
    }
}

fn current_time_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        0
    } // In WASM, caller provides timestamps
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

// ── Temporal + behavioral fingerprints ───────────────────────────

fn source_fingerprint_domains(signals: &[ChainSignal]) -> usize {
    let mut domains = std::collections::HashSet::new();
    for signal in signals {
        for class in &signal.classes {
            domains.insert(class.proof_domain());
        }
    }
    domains.len().max(1)
}

fn source_fingerprint_classes(signals: &[ChainSignal]) -> usize {
    let mut classes = std::collections::HashSet::new();
    for signal in signals {
        for class in &signal.classes {
            classes.insert(*class);
        }
    }
    classes.len().max(1)
}

fn continuation_key(signal: &ChainSignal) -> Option<String> {
    if signal.classes.is_empty() && signal.behaviors.is_empty() {
        return None;
    }

    let mut classes: Vec<String> = signal.classes.iter().map(|c| format!("{:?}", c)).collect();
    classes.sort_unstable();
    let class_signal = if classes.is_empty() {
        "behavioral".to_owned()
    } else {
        classes.into_iter().take(2).collect::<Vec<_>>().join("|")
    };

    let bucket = {
        let clean = signal.path.trim_end_matches('/');
        let first = clean
            .trim_start_matches('/')
            .split('/')
            .find(|s| !s.is_empty())
            .unwrap_or("");
        if first.is_empty() {
            "root".to_owned()
        } else {
            first.to_owned()
        }
    };

    if signal.confidence < 0.35 {
        None
    } else {
        Some(format!(
            "continuity|{}|{}|{}|{}",
            signal.method.to_lowercase(),
            bucket,
            class_signal,
            signal.path.len().min(64)
        ))
    }
}

fn pivot_seed_key(chain_id: &str, target_step: usize, signal: &ChainSignal) -> Option<String> {
    if signal.classes.is_empty() && signal.behaviors.is_empty() {
        return None;
    }

    if signal.confidence < 0.85 {
        return None;
    }

    let clean = signal.path.trim_end_matches('/');
    let first = clean
        .trim_start_matches('/')
        .split('/')
        .find(|s| !s.is_empty())
        .unwrap_or("");
    if first.is_empty() {
        return None;
    }

    Some(format!(
        "pivot|{}|{}|{}|{}",
        chain_id,
        target_step,
        signal.method.to_lowercase(),
        first
    ))
}

fn chain_behavior_overlap(boost_signal: &[ChainSignal], chain: &ChainDefinition) -> f64 {
    if chain.steps.is_empty() {
        return 1.0;
    }
    let mut chain_behaviors = std::collections::HashSet::new();
    for step in &chain.steps {
        for behavior in &step.behaviors {
            chain_behaviors.insert(behavior.as_str());
        }
    }
    if chain_behaviors.is_empty() {
        return 1.0;
    }
    let mut chain_domains = std::collections::HashSet::new();
    for step in &chain.steps {
        for class in &step.classes {
            chain_domains.insert(class.proof_domain());
        }
    }

    let mut overlap = 0.0;
    for signal in boost_signal {
        for behavior in &signal.behaviors {
            if chain_behaviors.contains(behavior.as_str()) {
                overlap += 1.0;
            }
        }
        for class in &signal.classes {
            if chain_domains.contains(&class.proof_domain()) {
                overlap += 1.0;
            }
        }
    }
    let normalized = (overlap / 2.0_f64).min(1.0);
    1.0 + (normalized * 0.08)
}

fn cross_class_fingerprint_boost(signals: &[ChainSignal]) -> f64 {
    let unique_domains = source_fingerprint_domains(signals) as f64;
    let unique_classes = source_fingerprint_classes(signals) as f64;
    let domain_boost = ((unique_domains - 1.0).max(0.0)) * 0.035;
    let class_boost = ((unique_classes - 1.0).max(0.0)) * 0.015;
    (1.0 + domain_boost + class_boost).min(1.24)
}

fn temporal_slow_factor(step_timestamps: &[u64], window_seconds: u64) -> f64 {
    if step_timestamps.len() < 2 {
        return 1.0;
    }

    let mut stamps = step_timestamps.to_vec();
    stamps.sort_unstable();
    let first = stamps.first().copied().unwrap_or(0);
    let last = stamps.last().copied().unwrap_or(0);
    let elapsed_ms = last.saturating_sub(first) as f64;
    let _elapsed = elapsed_ms / 1000.0;
    let spread = elapsed_ms / ((window_seconds as f64) * 1000.0);
    let avg_gap_ms = if step_timestamps.len() > 1 {
        elapsed_ms / ((stamps.len() - 1) as f64)
    } else {
        0.0
    };
    let avg_gap_seconds = avg_gap_ms / 1000.0;

    let mut factor = 1.0;

    // Kill-chain acceleration: rapid progression of all chain steps in a short time
    // is a stronger signal of automation than spread-out reconnaissance.
    if spread <= 0.1 {
        factor += 0.06 + ((0.1 - spread) * 0.02);
    } else if spread <= 0.35 {
        factor += ((0.35 - spread) / 0.25) * 0.02;
    }

    // Slow-chain persistence: long chains, large delays, and repeated probing
    // are still suspicious but weaker than fast chain acceleration.
    if spread > 0.35 {
        factor += ((spread - 0.35) * 0.2).min(0.08);
    }
    if spread > 0.6 {
        factor += 0.04;
    }
    factor += ((avg_gap_seconds - 30.0).max(0.0) / 6000.0 * 0.02).min(0.04);

    factor.min(1.30)
}

// ── Attack Chain Definitions ─────────────────────────────────────

fn step(
    classes: &[InvariantClass],
    behaviors: &[&str],
    desc: &str,
    defense: Option<DefenseAction>,
) -> ChainStep {
    ChainStep {
        classes: classes.to_vec(),
        behaviors: behaviors.iter().map(|b| b.to_string()).collect(),
        min_confidence: 0.3,
        description: desc.to_owned(),
        defense,
    }
}

fn step_with_conf(
    classes: &[InvariantClass],
    behaviors: &[&str],
    min_conf: f64,
    desc: &str,
    defense: Option<DefenseAction>,
) -> ChainStep {
    ChainStep {
        classes: classes.to_vec(),
        behaviors: behaviors.iter().map(|b| b.to_string()).collect(),
        min_confidence: min_conf,
        description: desc.to_owned(),
        defense,
    }
}

use InvariantClass::*;

pub fn attack_chains() -> Vec<ChainDefinition> {
    vec![
        // 1. LFI → Credential Extraction
        ChainDefinition {
            id: "lfi_credential_theft",
            name: "LFI → Credential Extraction",
            description: "Path traversal to read sensitive files, extract credentials, then access protected resources.",
            mitre: vec!["T1083", "T1552.001"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[PathDotdotEscape, PathEncodingBypass],
                    &[],
                    "Probe for path traversal vulnerability",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[PathDotdotEscape, PathNullTerminate, PathEncodingBypass],
                    &["path_sensitive_file"],
                    "Read sensitive files (.env, /etc/passwd)",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[AuthHeaderSpoof],
                    &["auth_change", "privilege_escalation"],
                    "Use extracted credentials",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 300,
            minimum_steps: Some(2),
            confidence_boost: 0.3,
        },
        // 2. SQLi → Data Exfiltration
        ChainDefinition {
            id: "sqli_data_exfil",
            name: "SQLi → Data Exfiltration",
            description: "SQL injection to extract data, enumerate schema, dump tables, escalate privileges.",
            mitre: vec!["T1190", "T1005"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[SqlStringTermination, SqlErrorOracle, SqlTimeOracle],
                    &[],
                    "Probe for SQL injection (error/time-based)",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[SqlTautology, SqlUnionExtraction],
                    &[],
                    "Extract data via UNION/boolean-based blind SQLi",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[SqlStackedExecution],
                    &[],
                    "Execute additional SQL statements",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 600,
            minimum_steps: Some(2),
            confidence_boost: 0.25,
        },
        // 3. SSRF → Cloud Credential Theft
        ChainDefinition {
            id: "ssrf_cloud_credential_theft",
            name: "SSRF → Cloud Credential Theft",
            description: "SSRF to reach cloud metadata, extract IAM credentials, pivot to cloud infrastructure.",
            mitre: vec!["T1552.005", "T1078.004"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[SsrfInternalReach],
                    &[],
                    "Probe for SSRF via internal IPs",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[SsrfCloudMetadata],
                    &[],
                    "Reach cloud metadata endpoint",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[SsrfProtocolSmuggle],
                    &["credential_extraction"],
                    "Use extracted credentials or smuggle to internal services",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 300,
            minimum_steps: Some(2),
            confidence_boost: 0.35,
        },
        // 4. XSS → Session Hijack → Admin Takeover
        ChainDefinition {
            id: "xss_session_hijack",
            name: "XSS → Session Hijack → Admin Takeover",
            description: "XSS to steal session cookies, then access admin endpoints.",
            mitre: vec!["T1189", "T1539"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[
                        XssTagInjection,
                        XssEventHandler,
                        XssAttributeEscape,
                        XssProtocolHandler,
                    ],
                    &[],
                    "Inject XSS payload",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[XssTemplateExpression],
                    &["cookie_exfil", "dom_manipulation"],
                    "Escalate to cookie exfiltration",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[AuthHeaderSpoof],
                    &["privilege_escalation", "admin_access"],
                    "Use stolen session for admin access",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 1800,
            minimum_steps: Some(2),
            confidence_boost: 0.25,
        },
        // 5. Deserialization → RCE
        ChainDefinition {
            id: "deser_rce",
            name: "Deserialization → RCE",
            description: "Untrusted deserialization leading to gadget chain execution and RCE.",
            mitre: vec!["T1059", "T1203"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[DeserJavaGadget, DeserPhpObject, DeserPythonPickle],
                    &[],
                    "Inject serialized object with gadget chain",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSeparator, CmdSubstitution],
                    &["reverse_shell", "outbound_connection"],
                    "Execute system commands",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 60,
            minimum_steps: Some(1),
            confidence_boost: 0.4,
        },
        // 6. Prototype Pollution → RCE
        ChainDefinition {
            id: "proto_pollution_rce",
            name: "Prototype Pollution → RCE",
            description: "Pollute Object.prototype to inject properties that achieve RCE.",
            mitre: vec!["T1059.007"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[ProtoPollution],
                    &[],
                    "Inject __proto__ or constructor.prototype",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSeparator, CmdSubstitution, CmdArgumentInjection],
                    &["property_injection"],
                    "Polluted properties trigger command execution",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 30,
            minimum_steps: Some(1),
            confidence_boost: 0.35,
        },
        // 7. Log4Shell → JNDI → RCE
        ChainDefinition {
            id: "log4shell_rce",
            name: "Log4Shell → JNDI Lookup → RCE",
            description: "Exploit Log4j JNDI lookup to fetch and execute malicious code.",
            mitre: vec!["T1190", "T1059"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[LogJndiLookup],
                    &[],
                    "Inject JNDI lookup string",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[SsrfInternalReach, SsrfProtocolSmuggle],
                    &["outbound_connection", "class_loading"],
                    "Log4j resolves JNDI and fetches remote class",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 30,
            minimum_steps: Some(1),
            confidence_boost: 0.4,
        },
        // 8. Scanner → Targeted Exploit
        ChainDefinition {
            id: "automated_attack_pipeline",
            name: "Automated Scanner → Targeted Exploit",
            description: "Automated scanner probing, then switching to targeted exploitation.",
            mitre: vec!["T1595.002", "T1190"],
            severity: ChainSeverity::High,
            steps: vec![
                step(
                    &[],
                    &["scanner_detected", "path_spray", "rate_anomaly"],
                    "Automated scanner fingerprinting",
                    Some(DefenseAction::Throttle),
                ),
                step(
                    &[
                        SqlStringTermination,
                        XssTagInjection,
                        PathDotdotEscape,
                        CmdSeparator,
                        SsrfInternalReach,
                        LogJndiLookup,
                    ],
                    &[],
                    "Targeted payload after recon",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 3600,
            minimum_steps: Some(2),
            confidence_boost: 0.2,
        },
        // 9. Multi-Vector SQLi
        ChainDefinition {
            id: "sqli_multi_vector",
            name: "Multi-Vector SQL Injection Campaign",
            description: "Systematic multi-technique SQLi: error-based detection, UNION extraction, stacked modification.",
            mitre: vec!["T1190"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[SqlErrorOracle, SqlTimeOracle],
                    &[],
                    "Blind SQLi probing via errors/timing",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[SqlTautology, SqlCommentTruncation, SqlStringTermination],
                    &[],
                    "Confirm injection — bypass auth or extract booleans",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[SqlUnionExtraction],
                    &[],
                    "UNION-based data exfiltration",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[SqlStackedExecution],
                    &[],
                    "Execute additional statements (INSERT/UPDATE/DROP)",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 1800,
            minimum_steps: Some(2),
            confidence_boost: 0.3,
        },
        // 10. SSTI → Template RCE
        ChainDefinition {
            id: "ssti_rce",
            name: "SSTI → Template Engine RCE",
            description: "Server-side template injection escalating to code execution.",
            mitre: vec!["T1059"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[SstiJinjaTwig, SstiElExpression, XssTemplateExpression],
                    &[],
                    "Inject template expression to test for SSTI",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[SstiJinjaTwig, SstiElExpression],
                    &["class_traversal", "code_execution"],
                    "Escalate to code execution via class hierarchy",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 300,
            minimum_steps: Some(1),
            confidence_boost: 0.3,
        },
        // 11. XXE → SSRF → Internal Pivot
        ChainDefinition {
            id: "xxe_ssrf_chain",
            name: "XXE → SSRF → Internal Pivot",
            description: "XML external entity injection to make server-side requests and exfiltrate data.",
            mitre: vec!["T1190", "T1018"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[XxeEntityExpansion, XmlInjection],
                    &[],
                    "Inject XML with external entity references",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[SsrfInternalReach, SsrfProtocolSmuggle],
                    &[],
                    "Entity resolution triggers SSRF to internal network",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 120,
            minimum_steps: Some(1),
            confidence_boost: 0.3,
        },
        // 12. Auth Bypass → Privilege Escalation
        ChainDefinition {
            id: "auth_bypass_privesc",
            name: "Auth Bypass → Privilege Escalation",
            description: "Bypass authentication then escalate privileges.",
            mitre: vec!["T1078", "T1548"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[AuthNoneAlgorithm, AuthHeaderSpoof],
                    &[],
                    "Bypass authentication",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[MassAssignment, ProtoPollution],
                    &["privilege_escalation", "role_change"],
                    "Escalate privileges",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 300,
            minimum_steps: Some(1),
            confidence_boost: 0.3,
        },
        // 13. Supply Chain → Cloud Pivot
        ChainDefinition {
            id: "supply_chain_pivot",
            name: "Supply Chain Exploit → Cloud Pivot",
            description: "Exploit deserialization in a dependency to gain access, SSRF to cloud metadata, extract IAM credentials.",
            mitre: vec!["T1195.002", "T1190", "T1552.005"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[
                        DeserJavaGadget,
                        DeserPhpObject,
                        DeserPythonPickle,
                        LogJndiLookup,
                    ],
                    &[],
                    "Initial access via deser/JNDI",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSeparator, CmdSubstitution],
                    &["outbound_connection", "class_loading"],
                    "Establish execution",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[SsrfCloudMetadata, SsrfInternalReach],
                    &["credential_extraction"],
                    "Cloud metadata credential extraction",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 600,
            minimum_steps: Some(2),
            confidence_boost: 0.4,
        },
        // 14. DNS Rebinding → SSRF → Internal Access
        ChainDefinition {
            id: "dns_rebinding_ssrf",
            name: "DNS Rebinding → SSRF → Internal Access",
            description: "DNS rebinding to bypass SSRF filters, reach internal IPs.",
            mitre: vec!["T1557", "T1210"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[SsrfInternalReach],
                    &[],
                    "Probe SSRF with external URL",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[SsrfCloudMetadata, SsrfProtocolSmuggle],
                    &[],
                    "Rebinding resolves to internal target",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[AuthHeaderSpoof],
                    &["credential_extraction", "admin_access"],
                    "Use extracted credentials for internal access",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 120,
            minimum_steps: Some(2),
            confidence_boost: 0.35,
        },
        // 15. HTTP Desync → Auth Bypass
        ChainDefinition {
            id: "http_desync_auth_bypass",
            name: "HTTP Desync → Request Smuggling → Auth Bypass",
            description: "CL.TE or H2 desync to smuggle requests, bypass proxy auth.",
            mitre: vec!["T1557", "T1190", "T1078"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[HttpSmuggleClTe, HttpSmuggleH2],
                    &[],
                    "Exploit CL.TE or H2 desync",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[AuthHeaderSpoof, AuthNoneAlgorithm],
                    &["admin_access", "privilege_escalation"],
                    "Smuggled request bypasses auth",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 60,
            minimum_steps: Some(1),
            confidence_boost: 0.4,
        },
        // 16. SSRF → Cloud IAM → Cross-Account
        ChainDefinition {
            id: "cloud_iam_escalation",
            name: "SSRF → Cloud IAM → Cross-Account Escalation",
            description: "SSRF to extract IAM credentials, then assume roles across accounts.",
            mitre: vec!["T1552.005", "T1078.004", "T1550.001"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[SsrfCloudMetadata],
                    &[],
                    "Extract IAM credentials from metadata",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[SsrfInternalReach, SsrfProtocolSmuggle],
                    &["credential_extraction"],
                    "Access internal cloud services",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[],
                    &["outbound_connection", "admin_access"],
                    "Pivot to additional cloud accounts",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 900,
            minimum_steps: Some(2),
            confidence_boost: 0.4,
        },
        // 17. Web Shell Deployment
        ChainDefinition {
            id: "webshell_deployment",
            name: "Vuln Exploit → File Write → Web Shell → C2",
            description: "Exploit RCE to write web shell for persistent command execution.",
            mitre: vec!["T1190", "T1505.003", "T1059"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[
                        SqlStackedExecution,
                        SstiJinjaTwig,
                        SstiElExpression,
                        DeserJavaGadget,
                        DeserPhpObject,
                        LogJndiLookup,
                    ],
                    &[],
                    "Exploit RCE-class vuln",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSeparator, CmdSubstitution, CmdArgumentInjection],
                    &["code_execution", "reverse_shell"],
                    "Write web shell",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[PathDotdotEscape, PathEncodingBypass],
                    &["outbound_connection"],
                    "Verify web shell and establish C2",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 1800,
            minimum_steps: Some(2),
            confidence_boost: 0.35,
        },
        // 18. OOB Data Exfiltration
        ChainDefinition {
            id: "oob_data_exfil",
            name: "Blind Injection → OOB Exfiltration",
            description: "Blind injection with out-of-band exfiltration via DNS/HTTP.",
            mitre: vec!["T1190", "T1048"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[SqlTimeOracle, SqlErrorOracle, XxeEntityExpansion],
                    &[],
                    "Detect blind injection point",
                    Some(DefenseAction::Alert),
                ),
                step_with_conf(
                    &[SsrfInternalReach, SsrfProtocolSmuggle],
                    &["outbound_connection"],
                    0.4,
                    "Outbound connection to attacker callback",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[SqlUnionExtraction, SqlStackedExecution],
                    &[],
                    "Full data exfiltration via OOB",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 1200,
            minimum_steps: Some(2),
            confidence_boost: 0.3,
        },
        // 19. CORS → XSS → Credential Theft
        ChainDefinition {
            id: "cors_credential_theft",
            name: "CORS Abuse → XSS → Credential Harvest",
            description: "Exploit permissive CORS to enable cross-origin XSS for credential theft.",
            mitre: vec!["T1189", "T1539", "T1557"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[CorsOriginAbuse],
                    &[],
                    "Detect permissive CORS policy",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[XssTagInjection, XssEventHandler, XssProtocolHandler],
                    &[],
                    "Inject XSS in permissive CORS context",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[AuthHeaderSpoof],
                    &["cookie_exfil", "privilege_escalation"],
                    "Stolen credentials used for access",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 3600,
            minimum_steps: Some(2),
            confidence_boost: 0.25,
        },
        // 20. Slow SQLi Recon
        ChainDefinition {
            id: "slow_sqli_recon",
            name: "Low-and-Slow SQLi Reconnaissance",
            description: "Patient, distributed SQL injection reconnaissance across many parameters.",
            mitre: vec!["T1190", "T1595.002"],
            severity: ChainSeverity::High,
            steps: vec![
                step_with_conf(
                    &[SqlStringTermination],
                    &[],
                    0.3,
                    "Single-quote probing",
                    Some(DefenseAction::Alert),
                ),
                step_with_conf(
                    &[SqlErrorOracle, SqlTimeOracle],
                    &[],
                    0.3,
                    "Error/timing detection",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[SqlTautology, SqlCommentTruncation],
                    &[],
                    "Confirm injection",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[SqlUnionExtraction],
                    &[],
                    "Begin data extraction",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 7200,
            minimum_steps: Some(3),
            confidence_boost: 0.25,
        },
        // 21. JWT Forgery Pipeline
        ChainDefinition {
            id: "jwt_forgery_pipeline",
            name: "JWT Forgery Pipeline",
            description: "Multi-step JWT attack: alg:none → kid injection → JWK embedding.",
            mitre: vec!["T1550.001"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[AuthNoneAlgorithm],
                    &[],
                    "alg:none probing",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[JwtKidInjection],
                    &[],
                    "kid header injection",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[JwtJwkEmbedding, JwtConfusion],
                    &[],
                    "Self-signed key injection or alg confusion",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 300,
            minimum_steps: Some(2),
            confidence_boost: 0.20,
        },
        // 22. Supply Chain Full Compromise
        ChainDefinition {
            id: "supply_chain_full_compromise",
            name: "Supply Chain Full Compromise",
            description: "Dependency confusion → malicious postinstall → credential exfiltration.",
            mitre: vec!["T1195.001", "T1059.006", "T1114"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[DependencyConfusion],
                    &[],
                    "Dependency confusion/typosquat planted",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[PostinstallInjection],
                    &[],
                    "Malicious lifecycle script executes",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[EnvExfiltration],
                    &[],
                    "Environment variables exfiltrated",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 600,
            minimum_steps: Some(2),
            confidence_boost: 0.25,
        },
        // 23. LLM Jailbreak Escalation
        ChainDefinition {
            id: "llm_jailbreak_escalation",
            name: "LLM Jailbreak Escalation",
            description: "Progressive LLM jailbreak: prompt injection → role override → data exfiltration.",
            mitre: vec!["T1059.003"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[LlmPromptInjection],
                    &[],
                    "Prompt boundary crossing",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[LlmJailbreak],
                    &[],
                    "Known jailbreak framework applied",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[LlmDataExfiltration],
                    &[],
                    "Confidential data extraction",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 300,
            minimum_steps: Some(2),
            confidence_boost: 0.20,
        },
        // 24. Cache Poisoning to XSS
        ChainDefinition {
            id: "cache_poison_xss",
            name: "Cache Poisoning to Stored XSS",
            description: "Manipulate unkeyed headers to inject XSS, serve poisoned response from cache.",
            mitre: vec!["T1557", "T1189"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[CachePoisoning],
                    &[],
                    "Unkeyed header manipulation",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[XssTagInjection, XssEventHandler, XssProtocolHandler],
                    &[],
                    "XSS payload via poisoned cache",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 120,
            minimum_steps: Some(2),
            confidence_boost: 0.20,
        },
        // 25. API IDOR to Mass Exfiltration
        ChainDefinition {
            id: "api_idor_mass_exfil",
            name: "API IDOR to Mass Data Exfiltration",
            description: "BOLA/IDOR exploitation followed by mass enumeration.",
            mitre: vec!["T1078", "T1087", "T1530"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(&[BolaIdor], &[], "IDOR probing", Some(DefenseAction::Alert)),
                step(
                    &[ApiMassEnum],
                    &[],
                    "Mass enumeration after IDOR confirmed",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 300,
            minimum_steps: Some(2),
            confidence_boost: 0.20,
        },
        // 26. JWT Forgery to IDOR Escalation
        ChainDefinition {
            id: "jwt_idor_escalation",
            name: "JWT Forgery to IDOR Privilege Escalation",
            description: "Forge JWT token then exploit IDOR with forged identity.",
            mitre: vec!["T1550.001", "T1078"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[
                        JwtKidInjection,
                        JwtJwkEmbedding,
                        JwtConfusion,
                        AuthNoneAlgorithm,
                    ],
                    &[],
                    "JWT manipulation",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[BolaIdor],
                    &[],
                    "IDOR exploitation using forged identity",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 300,
            minimum_steps: Some(2),
            confidence_boost: 0.25,
        },
        // 27. Cache Deception to Session Theft
        ChainDefinition {
            id: "cache_deception_session_theft",
            name: "Cache Deception to Session Theft",
            description: "Trick CDN into caching authenticated response, steal session tokens.",
            mitre: vec!["T1557", "T1539"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[CacheDeception],
                    &[],
                    "Cache deception: append static extension",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[CachePoisoning],
                    &[],
                    "Cache poisoning to serve stolen content",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 180,
            minimum_steps: Some(1),
            confidence_boost: 0.15,
        },
        // 28. LLM to Supply Chain Pivot
        ChainDefinition {
            id: "llm_supply_chain_pivot",
            name: "LLM Jailbreak to Supply Chain Compromise",
            description: "Jailbreak AI coding assistant to inject malicious dependencies.",
            mitre: vec!["T1059.003", "T1195.001"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[LlmJailbreak, LlmPromptInjection],
                    &[],
                    "Jailbreak/prompt injection targeting AI assistant",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[DependencyConfusion, PostinstallInjection],
                    &[],
                    "Malicious dependency in generated output",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 600,
            minimum_steps: Some(2),
            confidence_boost: 0.20,
        },
        // 29. SSRF to API Mass Enumeration
        ChainDefinition {
            id: "ssrf_api_exfil",
            name: "SSRF to Internal API Mass Exfiltration",
            description: "SSRF to reach internal APIs, then mass-enumerate endpoints.",
            mitre: vec!["T1090", "T1087", "T1530"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[SsrfInternalReach],
                    &[],
                    "SSRF to reach internal network",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[ApiMassEnum, BolaIdor],
                    &[],
                    "Mass enumeration on internal APIs",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 300,
            minimum_steps: Some(2),
            confidence_boost: 0.20,
        },
        // 30. SQLi Probe to LFI to Credential Exfil
        ChainDefinition {
            id: "sqli_lfi_credential_theft",
            name: "SQLi Probe to LFI Credential Extraction",
            description: "Probe SQLi to map the app, discover path traversal, extract credential files.",
            mitre: vec!["T1190", "T1005", "T1552.001"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[SqlErrorOracle, SqlTautology, SqlStringTermination],
                    &[],
                    "SQL injection probing",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[PathDotdotEscape, PathEncodingBypass],
                    &[],
                    "Path traversal to access server files",
                    Some(DefenseAction::Throttle),
                ),
                step(
                    &[PathDotdotEscape, PathEncodingBypass],
                    &["path_sensitive_file"],
                    "Credential file extraction via LFI",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 600,
            minimum_steps: Some(2),
            confidence_boost: 0.25,
        },
        // 31. JWT Forgery → Privilege Escalation
        ChainDefinition {
            id: "jwt_forgery_to_privilege_escalation",
            name: "JWT Forgery to Privilege Escalation",
            description: "Forge JWT headers and keys, then access protected resources through role confusion.",
            mitre: vec!["T1550.001", "T1078"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[JwtKidInjection, JwtJwkEmbedding],
                    &[],
                    "Forge JWT key/header path",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[JwtConfusion, JwtJwkEmbedding],
                    &["role_change", "privilege_escalation"],
                    "Bypass role checks with confused token validation",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[AuthHeaderSpoof],
                    &["admin_access"],
                    "Use forged token for privilege escalation",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 240,
            minimum_steps: Some(2),
            confidence_boost: 0.20,
        },
        // 32. Deserialization → Command to File Path Pivot
        ChainDefinition {
            id: "deser_to_path_pivot",
            name: "Deserialization → Command Injection → Path Pivot",
            description: "Deserialize malicious object, execute command, then pivot to file-system exposure.",
            mitre: vec!["T1203", "T1090"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[DeserJavaGadget, DeserPhpObject, DeserPythonPickle],
                    &[],
                    "Initial code execution via deserialization",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSeparator, CmdSubstitution, CmdArgumentInjection],
                    &["code_execution", "file_system_write"],
                    "Command execution and file write primitives",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[PathDotdotEscape, PathEncodingBypass],
                    &["path_sensitive_file"],
                    "Pivot to sensitive file access",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 900,
            minimum_steps: Some(2),
            confidence_boost: 0.25,
        },
        // 33. Open Redirect to Credential Abuse Pivot
        ChainDefinition {
            id: "open_redirect_credential_pivot",
            name: "Open Redirect to Credential Abuse",
            description: "Open redirect abuse to move through auth boundaries then probe credentials.",
            mitre: vec!["T1189", "T1550.001"],
            severity: ChainSeverity::High,
            steps: vec![
                step(
                    &[OpenRedirectBypass],
                    &[],
                    "Abuse redirect trust boundary",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[AuthHeaderSpoof, CorsOriginAbuse],
                    &["session_hijack", "token_steal"],
                    "Abuse authenticated redirects and origin trust",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[BolaIdor, ApiMassEnum],
                    &["credential_exposure"],
                    "Cross-account / credential targeting via redirects",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 1800,
            minimum_steps: Some(2),
            confidence_boost: 0.22,
        },
        // 34. Supply Chain Compromise
        ChainDefinition {
            id: "supply_chain_compromise",
            name: "Supply Chain → Code Injection → Command Injection",
            description: "Dependency hijack leads to injected package code, then command execution on host.",
            mitre: vec!["T1195.001", "T1059"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[DependencyConfusion],
                    &[],
                    "Dependency hijack / typosquat stage",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[PostinstallInjection],
                    &["code_execution"],
                    "Injected package lifecycle code executes",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSeparator, CmdSubstitution, CmdArgumentInjection],
                    &["reverse_shell", "outbound_connection"],
                    "Escalate to system command execution",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 900,
            minimum_steps: Some(3),
            confidence_boost: 0.28,
        },
        // 35. API Key Exfiltration
        ChainDefinition {
            id: "api_key_exfiltration",
            name: "Path Traversal → Information Disclosure → SSRF Exfiltration",
            description: "Traverse to secrets, disclose API keys, then exfiltrate through SSRF pivot.",
            mitre: vec!["T1005", "T1048"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[
                        PathDotdotEscape,
                        PathEncodingBypass,
                        PathNormalizationBypass,
                    ],
                    &[],
                    "Path traversal to sensitive config",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[],
                    &["path_sensitive_file", "credential_extraction"],
                    "Read and expose API keys from config files",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[SsrfInternalReach, SsrfProtocolSmuggle],
                    &["outbound_connection"],
                    "Exfiltrate key material via SSRF channel",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 600,
            minimum_steps: Some(3),
            confidence_boost: 0.27,
        },
        // 36. Cloud Metadata Pivot
        ChainDefinition {
            id: "cloud_metadata_pivot",
            name: "SSRF → Metadata Credential Theft → Auth Bypass",
            description: "SSRF reaches metadata service, extracts cloud creds, then bypasses auth controls.",
            mitre: vec!["T1552.005", "T1078"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[SsrfInternalReach, SsrfCloudMetadata],
                    &[],
                    "SSRF toward metadata/internal endpoints",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[],
                    &["credential_extraction"],
                    "Steal IAM/session credentials from metadata",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[AuthHeaderSpoof, AuthNoneAlgorithm, CorsOriginAbuse],
                    &["admin_access", "privilege_escalation"],
                    "Use stolen credentials to bypass authentication",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 420,
            minimum_steps: Some(3),
            confidence_boost: 0.30,
        },
        // 37. GraphQL Abuse Chain
        ChainDefinition {
            id: "graphql_abuse_chain",
            name: "GraphQL Injection → Schema Discovery → SQL Injection",
            description: "GraphQL abuse via introspection enables schema discovery and targeted SQLi.",
            mitre: vec!["T1190", "T1592"],
            severity: ChainSeverity::High,
            steps: vec![
                step(
                    &[GraphqlIntrospection, GraphqlBatchAbuse],
                    &[],
                    "GraphQL probing and injection primitives",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[],
                    &["schema_discovery", "path_sensitive_file"],
                    "Schema and resolver discovery for backend targeting",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[
                        SqlStringTermination,
                        SqlTautology,
                        SqlUnionExtraction,
                        SqlErrorOracle,
                    ],
                    &[],
                    "Targeted SQL injection against discovered backend paths",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 900,
            minimum_steps: Some(3),
            confidence_boost: 0.24,
        },
        // 38. WebSocket Takeover
        ChainDefinition {
            id: "websocket_takeover",
            name: "WebSocket Hijack → Auth Bypass → Command Injection",
            description: "WebSocket takeover pivots into session abuse and command execution.",
            mitre: vec!["T1189", "T1078", "T1059"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[WsHijack, WsInjection],
                    &[],
                    "Hijack or inject WebSocket channel",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[AuthHeaderSpoof, AuthNoneAlgorithm],
                    &["session_hijack", "admin_access"],
                    "Bypass auth with stolen WS/session context",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSeparator, CmdSubstitution, CmdArgumentInjection],
                    &["code_execution", "reverse_shell"],
                    "Drive command execution through privileged channel",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 480,
            minimum_steps: Some(3),
            confidence_boost: 0.29,
        },
        // 39. JWT to Account Takeover
        ChainDefinition {
            id: "jwt_to_account_takeover",
            name: "JWT Forgery → Auth Bypass → Account Takeover",
            description: "Forged JWT bypasses auth and escalates account privileges via mass assignment.",
            mitre: vec!["T1550.001", "T1078", "T1098"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[JwtKidInjection, JwtJwkEmbedding, JwtConfusion],
                    &[],
                    "Forge or confuse JWT trust chain",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[AuthNoneAlgorithm, AuthHeaderSpoof],
                    &["privilege_escalation"],
                    "Bypass authentication with forged token",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[MassAssignment],
                    &["role_change", "admin_access"],
                    "Escalate to account takeover via writable privilege fields",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 360,
            minimum_steps: Some(3),
            confidence_boost: 0.26,
        },
        // 40. OAuth Redirect Theft
        ChainDefinition {
            id: "oauth_redirect_theft",
            name: "OAuth Redirect Theft",
            description: "Abuse open redirects in OAuth callbacks to steal tokens and assume victim sessions.",
            mitre: vec!["T1189", "T1539", "T1550.001"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[OpenRedirectBypass],
                    &["oauth_flow", "open_redirect"],
                    "Abuse OAuth redirect allowlist",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[AuthHeaderSpoof],
                    &["token_steal", "oauth_token_theft"],
                    "Steal OAuth token through redirected callback",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[AuthNoneAlgorithm, JwtKidInjection, JwtJwkEmbedding],
                    &["account_takeover", "admin_access"],
                    "Forge token state to take over account",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 1800,
            minimum_steps: Some(3),
            confidence_boost: 0.28,
        },
        // 41. Cache Deception to Stored XSS
        ChainDefinition {
            id: "cache_poisoning_to_xss",
            name: "Cache Deception → Stored XSS",
            description: "Cache deception primes key poisoning, then stored XSS is delivered from cached content.",
            mitre: vec!["T1557", "T1189"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[CacheDeception],
                    &["cache_key_poisoning", "cache_poisoning"],
                    "Abuse cache key and key derivation logic",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[CachePoisoning, XssTagInjection],
                    &["stored_xss", "path_sensitive_file"],
                    "Persist XSS in poisoned cache response",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 180,
            minimum_steps: Some(2),
            confidence_boost: 0.24,
        },
        // 42. SSRF to RCE via Cloud Metadata
        ChainDefinition {
            id: "ssrf_to_rce",
            name: "SSRF to Cloud Metadata → RCE",
            description: "SSRF reaches metadata, extracts credentials, then drives command execution.",
            mitre: vec!["T1552.005", "T1059", "T1059.001"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[SsrfInternalReach],
                    &["internal_recon"],
                    "Probe internal/metadata endpoints via SSRF",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[SsrfCloudMetadata],
                    &["credential_extraction"],
                    "Pull cloud credentials from metadata service",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSeparator, CmdSubstitution, CmdArgumentInjection],
                    &["code_execution", "reverse_shell"],
                    "Use stolen credentials to execute commands",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 600,
            minimum_steps: Some(3),
            confidence_boost: 0.34,
        },
        // 43. Prototype Pollution to RCE
        ChainDefinition {
            id: "prototype_pollution_to_rce",
            name: "Prototype Pollution → RCE",
            description: "Prototype pollution injects executable gadgets and is followed by command execution.",
            mitre: vec!["T1059.007"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[ProtoPollution],
                    &["property_injection"],
                    "Pollute prototype chain",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[ProtoPollutionGadget],
                    &["code_execution"],
                    "Pollution gadget enables dynamic code execution",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSeparator, CmdSubstitution, CmdArgumentInjection],
                    &["reverse_shell", "outbound_connection"],
                    "Remote shell launch from polluted environment",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 180,
            minimum_steps: Some(3),
            confidence_boost: 0.32,
        },
        // 44. Deserialization to Reverse Shell
        ChainDefinition {
            id: "deserialization_chain",
            name: "Deserialization → Command Execution → Reverse Shell",
            description: "Untrusted payload deserialization leads to command execution and reverse-shell delivery.",
            mitre: vec!["T1059", "T1203"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[DeserJavaGadget, DeserPhpObject, DeserPythonPickle],
                    &["deserialization_gadget"],
                    "Inject gadgetized object",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[CmdSeparator, CmdSubstitution, CmdArgumentInjection],
                    &["code_execution"],
                    "Reach command execution context",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSubstitution],
                    &["reverse_shell", "outbound_connection"],
                    "Launch reverse-shell callback",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 300,
            minimum_steps: Some(3),
            confidence_boost: 0.30,
        },
        // 45. Log4Shell to Lateral Movement
        ChainDefinition {
            id: "log4shell_to_lateral",
            name: "Log4Shell → Internal Pivot",
            description: "JNDI lookup is used to load attacker code and pivot into internal lateral movement.",
            mitre: vec!["T1059", "T1210"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[LogJndiLookup],
                    &["jndi_lookup", "class_loading"],
                    "Inject JNDI lookup in log input",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[SsrfProtocolSmuggle],
                    &["outbound_connection", "class_loading"],
                    "Server-side class fetch / callback path",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[AuthHeaderSpoof, AuthNoneAlgorithm],
                    &["lateral_movement", "admin_access"],
                    "Pivot credentials through compromised runtime",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 120,
            minimum_steps: Some(3),
            confidence_boost: 0.35,
        },
        // 46. SSRF → Cloud Metadata → Credential Theft → Lateral Movement
        ChainDefinition {
            id: "ssrf_cloud_metadata_lateral",
            name: "SSRF → Cloud Metadata → Credential Theft → Lateral Movement",
            description: "Reach metadata services via SSRF, harvest credentials, and use them to pivot into lateral movement.",
            mitre: vec!["T1552.005", "T1078", "T1210"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step_with_conf(
                    &[SsrfInternalReach],
                    &["internal_recon"],
                    0.4,
                    "Probe internal services and metadata endpoints",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[SsrfCloudMetadata],
                    &["metadata_probe"],
                    "Enumerate metadata surface",
                    Some(DefenseAction::Alert),
                ),
                step_with_conf(
                    &[SsrfProtocolSmuggle],
                    &["credential_extraction", "cloud_token_theft"],
                    0.4,
                    "Extract IAM or cloud runtime credentials",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[AuthHeaderSpoof, AuthNoneAlgorithm],
                    &["admin_access", "lateral_movement"],
                    "Pivot with stolen credentials",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 420,
            minimum_steps: Some(4),
            confidence_boost: 0.38,
        },
        // 47. XXE → SSRF → Data Exfiltration
        ChainDefinition {
            id: "xxe_to_ssrf_to_exfiltration",
            name: "XXE → SSRF → Data Exfiltration",
            description: "Exploit XXE entity expansion to trigger SSRF and exfiltrate discovered data.",
            mitre: vec!["T1190", "T1048"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[XxeEntityExpansion, XmlInjection],
                    &["external_entity", "xml_entity_injection"],
                    "Inject external entity expansion payload",
                    Some(DefenseAction::Alert),
                ),
                step_with_conf(
                    &[SsrfInternalReach, SsrfProtocolSmuggle],
                    &["internal_request"],
                    0.42,
                    "Resolve external entity to internal network",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[],
                    &["data_exfiltration", "outbound_connection"],
                    "Send extracted data from internal service to attacker infrastructure",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 180,
            minimum_steps: Some(3),
            confidence_boost: 0.31,
        },
        // 48. SQLi → File Write → Webshell Upload → Command Execution
        ChainDefinition {
            id: "sqli_to_webshell_rce",
            name: "SQLi → File Write → Webshell Upload → RCE",
            description: "Use SQL injection to write webshell payload then execute commands through uploaded shell.",
            mitre: vec!["T1190", "T1059.003", "T1505.003"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[SqlStringTermination, SqlErrorOracle, SqlUnionExtraction],
                    &["sqli_probe", "database_exfil"],
                    "Identify and abuse SQLi sink",
                    Some(DefenseAction::Alert),
                ),
                step_with_conf(
                    &[SqlStackedExecution],
                    &["file_system_write", "webshell_upload"],
                    0.4,
                    "Write shell-like payload into web root",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSubstitution, CmdArgumentInjection],
                    &["code_execution", "webshell"],
                    "Execute shell commands via uploaded webshell",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 600,
            minimum_steps: Some(3),
            confidence_boost: 0.33,
        },
        // 49. Auth Bypass → Admin Access → Sensitive Data Access
        ChainDefinition {
            id: "auth_bypass_to_admin_sensitive_data",
            name: "Auth Bypass → Admin Access → Sensitive Data Access",
            description: "Bypass authentication, obtain administrative context, then extract sensitive data.",
            mitre: vec!["T1078", "T1134", "T1552.001"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step_with_conf(
                    &[AuthNoneAlgorithm, AuthHeaderSpoof],
                    &["auth_bypass"],
                    0.45,
                    "Skip or forge authentication checks",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[AuthNoneAlgorithm, CorsOriginAbuse, AuthHeaderSpoof],
                    &["admin_access", "role_change"],
                    "Obtain administrative session context",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[],
                    &["sensitive_data_access", "credential_extraction"],
                    "Access protected data stores under admin context",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 300,
            minimum_steps: Some(3),
            confidence_boost: 0.36,
        },
        // 50. Deserialization → RCE → Persistence
        ChainDefinition {
            id: "deserialization_to_rce_persistence",
            name: "Deserialization → RCE → Persistence",
            description: "Unsafe deserialization leads to command execution and long-term persistence.",
            mitre: vec!["T1203", "T1053.005", "T1055"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[DeserJavaGadget, DeserPhpObject, DeserPythonPickle],
                    &["deserialization_gadget"],
                    "Inject a serialized gadget chain",
                    Some(DefenseAction::Alert),
                ),
                step_with_conf(
                    &[CmdSubstitution, CmdArgumentInjection],
                    &["code_execution"],
                    0.45,
                    "Achieve command execution",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSeparator, CmdArgumentInjection],
                    &["persistence", "persistence_install"],
                    "Install persistent artifact",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 900,
            minimum_steps: Some(3),
            confidence_boost: 0.34,
        },
        // 51. CORS Misconfiguration → Session/Token Theft
        ChainDefinition {
            id: "cors_to_session_theft",
            name: "CORS Misconfiguration → Session Theft",
            description: "Exploit permissive CORS to bypass origin checks, then exfiltrate session material.",
            mitre: vec!["T1557", "T1539", "T1110"],
            severity: ChainSeverity::High,
            steps: vec![
                step(
                    &[CorsOriginAbuse],
                    &["cors_policy_bypass", "cross_origin_read"],
                    "Bypass origin restrictions and trust boundaries",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[XssProtocolHandler, XssAttributeEscape],
                    &["cross_origin_read", "token_steal"],
                    "Read victim session/API data across origin",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[AuthHeaderSpoof, AuthNoneAlgorithm],
                    &["session_theft", "token_steal"],
                    "Use stolen cookies/tokens to hijack session",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 1800,
            minimum_steps: Some(3),
            confidence_boost: 0.27,
        },
        // 52. LLM Prompt Injection → System Prompt Extraction → API Key Exfiltration
        ChainDefinition {
            id: "llm_prompt_to_api_key_exfil",
            name: "LLM Prompt Injection → System Prompt Extraction → API Key Exfiltration",
            description: "LLM jailbreak over prompt injection to extract system prompt and leak API credentials.",
            mitre: vec!["T1059.003", "T1005", "T1048"],
            severity: ChainSeverity::High,
            steps: vec![
                step(
                    &[LlmPromptInjection],
                    &["prompt_escape"],
                    "Inject prompt injection payload",
                    Some(DefenseAction::Alert),
                ),
                step_with_conf(
                    &[LlmJailbreak],
                    &["system_prompt_extraction", "system_prompt_readback"],
                    0.45,
                    "Extract hidden prompt or internal context",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[LlmDataExfiltration],
                    &["api_key_exfiltration", "credential_extraction"],
                    "Exfiltrate API keys and model credentials",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 300,
            minimum_steps: Some(3),
            confidence_boost: 0.30,
        },
        // 53. Supply Chain Compromise → Backdoor → Environment Exfiltration → C2 Beacon
        ChainDefinition {
            id: "supply_chain_to_backdoor_c2",
            name: "Supply-Chain Compromise → Backdoor → Environment Exfiltration → C2 Beacon",
            description: "Dependency confusion injects a backdoor package, exfiltrates runtime environment, and phones home.",
            mitre: vec!["T1195.002", "T1041", "T1552.001"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[DependencyConfusion],
                    &["dependency_confusion"],
                    "Resolve dependency from attacker-controlled namespace",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[PostinstallInjection],
                    &["backdoor_payload", "package_install"],
                    "Execute malicious package lifecycle logic",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[EnvExfiltration],
                    &["environment_variable_access"],
                    "Read secrets from environment and runtime",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSeparator, CmdArgumentInjection],
                    &["c2_beacon", "outbound_connection"],
                    "Beacon compromised host to attacker infrastructure",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 1200,
            minimum_steps: Some(4),
            confidence_boost: 0.4,
        },
        // 54. Log4Shell → JNDI → Remote Class Loading → RCE
        ChainDefinition {
            id: "log4shell_to_jndi_rce",
            name: "Log4Shell → JNDI → RCE",
            description: "Use Log4Shell log injection to trigger JNDI and execute arbitrary payloads.",
            mitre: vec!["T1190", "T1059"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step(
                    &[LogJndiLookup],
                    &["jndi_lookup", "log_injection"],
                    "Inject JNDI lookup string in log event",
                    Some(DefenseAction::Alert),
                ),
                step_with_conf(
                    &[SsrfProtocolSmuggle, SsrfCloudMetadata],
                    &["class_loading", "remote_class_load"],
                    0.43,
                    "Reach remote class endpoint via JNDI protocol smuggling",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[CmdSubstitution, CmdArgumentInjection],
                    &["code_execution", "rce"],
                    "Execute attacker-controlled payload",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 180,
            minimum_steps: Some(3),
            confidence_boost: 0.39,
        },
        // 55. HTTP Smuggling → Cache Poisoning → Reflected XSS Delivery
        ChainDefinition {
            id: "http_smuggling_to_cache_poison_xss",
            name: "HTTP Smuggling → Cache Poisoning → Reflected XSS Delivery",
            description: "Request smuggling manipulates cache keys, enabling reflected XSS served from poisoned cache state.",
            mitre: vec!["T1557", "T1189", "T1595.002"],
            severity: ChainSeverity::Critical,
            steps: vec![
                step_with_conf(
                    &[
                        HttpSmuggleClTe,
                        HttpSmuggleH2,
                        HttpSmuggleChunkExt,
                        HttpSmuggleZeroCl,
                        HttpSmuggleExpect,
                    ],
                    &["cache_deception"],
                    0.4,
                    "Perform request smuggling to desync cache interpretation",
                    Some(DefenseAction::Alert),
                ),
                step(
                    &[CachePoisoning, CacheDeception],
                    &["cache_key_poisoning", "stored_xss"],
                    "Poison cache response for cross-user consumption",
                    Some(DefenseAction::Block),
                ),
                step(
                    &[XssTagInjection, XssEventHandler, XssProtocolHandler],
                    &["reflected_xss", "script_execution"],
                    "Deliver reflected XSS payload via poisoned cache object",
                    Some(DefenseAction::Block),
                ),
            ],
            window_seconds: 240,
            minimum_steps: Some(3),
            confidence_boost: 0.35,
        },
    ]
}

// ── Chain Correlator ─────────────────────────────────────────────

/// Stateful correlator that converts event streams into attack-chain matches.
pub struct ChainCorrelator {
    source_windows: HashMap<String, Vec<ChainSignal>>,
    max_signals_per_source: usize,
    chain_defs: Vec<ChainDefinition>,
    chain_by_id: HashMap<String, usize>,
    state_store: ChainStateStore,
    pivot_store: ChainStateStore,
    last_prune: u64,
    max_sources: usize,
}

impl ChainCorrelator {
    /// Build a correlator with built-in chain definitions and default limits.
    pub fn new() -> Self {
        Self::with_chains(attack_chains(), 200, 5_000)
    }

    /// Build a correlator with caller-provided definitions and storage limits.
    pub fn with_chains(
        chains: Vec<ChainDefinition>,
        max_signals_per_source: usize,
        max_sources: usize,
    ) -> Self {
        let chain_by_id: HashMap<String, usize> = chains
            .iter()
            .enumerate()
            .map(|(i, c)| (c.id.to_owned(), i))
            .collect();

        Self {
            source_windows: HashMap::new(),
            max_signals_per_source,
            chain_defs: chains,
            chain_by_id,
            state_store: ChainStateStore::new(max_sources),
            pivot_store: ChainStateStore::new(max_sources),
            last_prune: current_time_ms(),
            max_sources,
        }
    }

    pub fn ingest(&mut self, signal: ChainSignal) -> Vec<ChainMatch> {
        // Store signal in window
        let window = self
            .source_windows
            .entry(signal.source_hash.clone())
            .or_default();
        window.push(signal.clone());
        if window.len() > self.max_signals_per_source {
            let remove = window.len() - self.max_signals_per_source;
            window.drain(..remove);
        }

        // Periodic prune
        let now = current_time_ms();
        if now.saturating_sub(self.last_prune) > 60_000 {
            self.prune_stale_windows();
        }

        // Hard cap on sources
        if self.source_windows.len() > self.max_sources {
            self.prune_stale_windows();
            if self.source_windows.len() > self.max_sources {
                let mut entries: Vec<(String, u64)> = self
                    .source_windows
                    .iter()
                    .map(|(k, sigs)| {
                        let latest = sigs.last().map(|s| s.timestamp).unwrap_or(0);
                        (k.clone(), latest)
                    })
                    .collect();
                entries.sort_by_key(|e| e.1);
                let evict = self.source_windows.len() - self.max_sources;
                for i in 0..evict {
                    self.source_windows.remove(&entries[i].0);
                    self.state_store.remove_source(&entries[i].0);
                }
            }
        }

        let mut touched_states: HashSet<(String, String)> = HashSet::new();
        let continuity_key = continuation_key(&signal);

        // Match signal against all chain/step pairs
        for chain_idx in 0..self.chain_defs.len() {
            let chain = &self.chain_defs[chain_idx];
            for step_index in 0..chain.steps.len() {
                let step = &chain.steps[step_index];
                let min_conf = step.min_confidence;

                let class_satisfied = step.classes.is_empty()
                    || step.classes.iter().any(|c| signal.classes.contains(c));
                let behavior_satisfied =
                    step.behaviors.iter().any(|b| signal.behaviors.contains(b));

                if (class_satisfied || behavior_satisfied) && signal.confidence >= min_conf {
                    let chain_id = chain.id;
                    let window_seconds = chain.window_seconds;
                    self.state_store.advance(
                        &signal.source_hash,
                        &signal.source_hash,
                        chain_id,
                        step_index,
                        &signal,
                        window_seconds,
                    );
                    touched_states.insert((signal.source_hash.clone(), chain_id.to_owned()));

                    if let Some(match_key) = pivot_seed_key(chain_id, step_index, &signal) {
                        self.pivot_store.advance(
                            &match_key,
                            &signal.source_hash,
                            chain_id,
                            step_index,
                            &signal,
                            window_seconds,
                        );
                        touched_states.insert((match_key.clone(), chain_id.to_owned()));
                    }

                    if let Some(next_key) = pivot_seed_key(chain_id, step_index + 1, &signal) {
                        self.pivot_store.advance(
                            &next_key,
                            &signal.source_hash,
                            chain_id,
                            step_index,
                            &signal,
                            window_seconds,
                        );
                        touched_states.insert((next_key, chain_id.to_owned()));
                    }
                    if let Some(key) = continuity_key.as_ref() {
                        self.pivot_store.advance(
                            key,
                            &signal.source_hash,
                            chain_id,
                            step_index,
                            &signal,
                            window_seconds,
                        );
                        touched_states.insert((key.to_string(), chain_id.to_owned()));
                    }

                    let state = self
                        .state_store
                        .get_state(&signal.source_hash, chain_id)
                        .or_else(|| {
                            pivot_seed_key(chain_id, step_index, &signal).and_then(|match_key| {
                                self.pivot_store.get_state(&match_key, chain_id)
                            })
                        })
                        .or_else(|| {
                            continuity_key
                                .as_ref()
                                .and_then(|key| self.pivot_store.get_state(key, chain_id))
                        })
                        .or_else(|| self.pivot_store.get_state(&signal.source_hash, chain_id));
                    if let Some(state) = state {
                        if state.status == ChainStatus::Expired {
                            continue;
                        }

                        let min_steps = self.chain_defs[chain_idx]
                            .minimum_steps
                            .unwrap_or(self.chain_defs[chain_idx].steps.len());

                        if state.status == ChainStatus::InProgress
                            && state.steps_matched >= min_steps
                        {
                            self.state_store.complete(&signal.source_hash, chain_id);
                        }
                    }
                }
            }
        }

        // Build matches for touched chains only
        let mut matches = Vec::new();
        for (actor, chain_id) in touched_states {
            if let Some(&chain_idx) = self.chain_by_id.get(chain_id.as_str()) {
                let chain = &self.chain_defs[chain_idx];
                let state = self
                    .state_store
                    .get_state(&actor, &chain_id)
                    .or_else(|| self.pivot_store.get_state(&actor, &chain_id));
                if let Some(state) = state {
                    if let Some(m) = self.state_to_chain_match(state, chain) {
                        matches.push(m);
                        continue;
                    }
                }
            }

            if let Some(&chain_idx) = self.chain_by_id.get(chain_id.as_str()) {
                let chain = &self.chain_defs[chain_idx];
                if let Some(state) = self.pivot_store.get_state(&actor, &chain_id) {
                    if let Some(m) = self.state_to_chain_match(state, chain) {
                        matches.push(m);
                    }
                }
            }
        }
        matches
    }

    fn state_to_chain_match(
        &self,
        state: &ChainStateNode,
        chain: &ChainDefinition,
    ) -> Option<ChainMatch> {
        if state.status == ChainStatus::Expired {
            return None;
        }
        if state.steps_matched < 1 {
            return None;
        }

        let min_steps = chain.minimum_steps.unwrap_or(chain.steps.len());
        if state.steps_matched < min_steps {
            return None;
        }

        let mut step_matches: Vec<StepMatch> = state
            .satisfied_steps
            .iter()
            .map(|(&step_index, satisfied)| StepMatch {
                step_index,
                description: chain
                    .steps
                    .get(step_index)
                    .map(|s| s.description.clone())
                    .unwrap_or_default(),
                matched_class: satisfied
                    .signal
                    .classes
                    .first()
                    .map(|c| format!("{:?}", c))
                    .unwrap_or_else(|| "behavioral".to_owned()),
                confidence: satisfied.confidence,
                timestamp: satisfied.signal.timestamp,
                path: satisfied.signal.path.clone(),
                source_hash: satisfied.signal.source_hash.clone(),
            })
            .collect();
        step_matches.sort_by_key(|m| m.step_index);

        let satisfied_signals: Vec<ChainSignal> = state
            .satisfied_steps
            .iter()
            .map(|(_, satisfied)| satisfied.signal.clone())
            .collect();
        let timestamps: Vec<u64> = satisfied_signals.iter().map(|s| s.timestamp).collect();

        let temporal_factor = temporal_slow_factor(&timestamps, chain.window_seconds);
        let cross_class_factor = cross_class_fingerprint_boost(&satisfied_signals);
        let behavior_factor = chain_behavior_overlap(&satisfied_signals, chain);

        let base_confidence =
            step_matches.iter().map(|s| s.confidence).sum::<f64>() / step_matches.len() as f64;
        let completion_ratio = state.steps_matched as f64 / chain.steps.len() as f64;
        let noise_factor = if state.steps_matched == 0 {
            1.0
        } else {
            (1.0 - ((state.noise_events as f64 / state.steps_matched as f64) * 0.4)).max(0.6)
        };
        let pivot_boost = if state.sources.len() > 1 { 1.08 } else { 1.0 };
        let mut sources: Vec<String> = state.sources.iter().cloned().collect();
        sources.sort_unstable();

        let compounded = (base_confidence
            * temporal_factor
            * cross_class_factor
            * behavior_factor
            * noise_factor
            * pivot_boost
            + chain.confidence_boost * completion_ratio)
            .min(0.99);

        let mut action =
            self.determine_action(chain, completion_ratio, compounded, state.sources.len());
        if state.status == ChainStatus::Completed
            && matches!(
                action,
                RecommendedAction::Monitor
                    | RecommendedAction::Throttle
                    | RecommendedAction::Challenge
            )
        {
            action = RecommendedAction::Block;
        }
        let first = timestamps.iter().copied().min().unwrap_or(0);
        let last = timestamps.iter().copied().max().unwrap_or(0);
        let duration_seconds = last.saturating_sub(first) / 1000;

        Some(ChainMatch {
            chain_id: chain.id.to_owned(),
            name: chain.name.to_owned(),
            steps_matched: state.steps_matched,
            total_steps: chain.steps.len(),
            completion: completion_ratio,
            confidence: compounded,
            severity: chain.severity,
            description: chain.description.to_owned(),
            recommended_action: action,
            step_matches,
            duration_seconds,
            associated_sources: sources,
            source_hash: state.source_hash.clone(),
        })
    }

    fn determine_action(
        &self,
        chain: &ChainDefinition,
        completion: f64,
        confidence: f64,
        source_count: usize,
    ) -> RecommendedAction {
        if completion >= 1.0 && chain.severity == ChainSeverity::Critical {
            return RecommendedAction::Lockdown;
        }
        if completion >= 1.0 {
            return RecommendedAction::Block;
        }
        if source_count >= 2 && completion >= 0.66 {
            return RecommendedAction::Block;
        }
        if completion >= 0.66 && chain.severity == ChainSeverity::Critical {
            return RecommendedAction::Block;
        }
        if completion >= 0.66 && confidence >= 0.8 {
            return RecommendedAction::Block;
        }
        if completion >= 0.5 {
            return RecommendedAction::Challenge;
        }
        if chain.severity == ChainSeverity::Critical {
            return RecommendedAction::Throttle;
        }
        RecommendedAction::Monitor
    }

    fn prune_stale_windows(&mut self) {
        let max_window = self
            .chain_defs
            .iter()
            .map(|c| c.window_seconds)
            .max()
            .unwrap_or(3600);
        let cutoff = current_time_ms().saturating_sub(max_window * 1000 * 2);
        self.state_store.prune_expired(max_window);
        self.pivot_store.prune_expired(max_window);

        let stale: Vec<String> = self
            .source_windows
            .iter()
            .filter(|(_, sigs)| sigs.last().map(|s| s.timestamp).unwrap_or(0) < cutoff)
            .map(|(k, _)| k.clone())
            .collect();
        for source in stale {
            self.source_windows.remove(&source);
        }
        self.last_prune = current_time_ms();
    }

    pub fn get_active_chains(&self, source_hash: &str) -> Vec<ChainMatch> {
        let states = self.state_store.get_all_for_source(source_hash);
        let mut matches = Vec::new();
        for state in states {
            if let Some(&chain_idx) = self.chain_by_id.get(&state.chain_id) {
                let chain = &self.chain_defs[chain_idx];
                if let Some(m) = self.state_to_chain_match(state, chain) {
                    matches.push(m);
                }
            }
        }
        matches
    }

    pub fn get_all_active_chains(&self) -> Vec<ChainMatch> {
        let mut all_matches = Vec::new();
        for source_hash in self.state_store.all_sources() {
            all_matches.extend(self.get_active_chains(source_hash));
        }
        all_matches
    }

    pub fn active_source_count(&self) -> usize {
        self.state_store.source_count()
    }

    pub fn total_signals(&self) -> usize {
        self.source_windows.values().map(|v| v.len()).sum()
    }

    pub fn chain_count(&self) -> usize {
        self.chain_defs.len()
    }

    pub fn get_attack_graph_inference(
        &self,
        classes: &[InvariantClass],
        behaviors: &[&str],
    ) -> Vec<AttackGraphInference> {
        let mut scored: Vec<AttackGraphInference> = self
            .chain_defs
            .iter()
            .filter_map(|chain| {
                let mut satisfied = 0;
                for step in &chain.steps {
                    let class_overlap = step.classes.iter().any(|c| classes.contains(c));
                    let behavior_overlap = step
                        .behaviors
                        .iter()
                        .any(|b| behaviors.contains(&b.as_str()));
                    if class_overlap || behavior_overlap {
                        satisfied += 1;
                    }
                }
                let probability = satisfied as f64 / chain.steps.len() as f64;
                if probability > 0.1 {
                    Some(AttackGraphInference {
                        chain_id: chain.id.to_owned(),
                        name: chain.name.to_owned(),
                        probability,
                        description: chain.description.to_owned(),
                    })
                } else {
                    None
                }
            })
            .collect();
        scored.sort_by(|a, b| {
            b.probability
                .partial_cmp(&a.probability)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(5);
        scored
    }

    pub fn get_chain_velocity(&self, source_hash: &str) -> Vec<ChainVelocity> {
        let now = current_time_ms();
        let states = self.state_store.get_all_for_source(source_hash);
        let mut velocities: Vec<ChainVelocity> = states
            .iter()
            .filter(|s| s.status == ChainStatus::InProgress && s.steps_matched > 0)
            .filter_map(|state| {
                let elapsed_minutes =
                    (now.saturating_sub(state.start_time) as f64 / 60_000.0).max(1.0 / 60.0);
                let spm = state.steps_matched as f64 / elapsed_minutes;
                if spm > 2.0 {
                    Some(ChainVelocity {
                        chain_id: state.chain_id.clone(),
                        steps_per_minute: spm,
                        latest_step: state.steps_matched,
                    })
                } else {
                    None
                }
            })
            .collect();
        velocities.sort_by(|a, b| {
            b.steps_per_minute
                .partial_cmp(&a.steps_per_minute)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        velocities
    }
}

impl Default for ChainCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

/// Probabilistic projection of likely chain trajectories.
#[derive(Debug, Clone, PartialEq)]
pub struct AttackGraphInference {
    /// Chain identifier.
    pub chain_id: String,
    /// Chain display name.
    pub name: String,
    /// Estimated probability for observed evidence.
    pub probability: f64,
    /// Chain description.
    pub description: String,
}

/// Estimated chain progression velocity for a source.
#[derive(Debug, Clone, PartialEq)]
pub struct ChainVelocity {
    /// Chain identifier.
    pub chain_id: String,
    /// Matched step rate.
    pub steps_per_minute: f64,
    /// Latest step index reached.
    pub latest_step: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signal(
        source: &str,
        classes: &[InvariantClass],
        behaviors: &[&str],
        confidence: f64,
        timestamp: u64,
    ) -> ChainSignal {
        ChainSignal {
            source_hash: source.to_owned(),
            classes: classes.to_vec(),
            behaviors: behaviors.iter().map(|b| b.to_string()).collect(),
            confidence,
            path: "/test".to_owned(),
            method: "GET".to_owned(),
            timestamp,
        }
    }

    fn chain_definition_expect(
        id: &str,
        expected_steps: usize,
        expected_minimum_steps: Option<usize>,
    ) {
        let chains = attack_chains();
        let chain = chains
            .into_iter()
            .find(|c| c.id == id)
            .expect("chain must exist");
        assert_eq!(chain.steps.len(), expected_steps);
        assert_eq!(chain.minimum_steps, expected_minimum_steps);
    }

    #[test]
    fn chain_definitions_load() {
        let chains = attack_chains();
        assert_eq!(chains.len(), 55);
    }

    #[test]
    fn multi_source_pivot_chain_match() {
        let mut correlator = ChainCorrelator::new();

        let s1 = make_signal("src_a", &[SqlErrorOracle], &[], 0.9, 1000);
        correlator.ingest(s1);

        let s2 = make_signal(
            "src_b",
            &[SqlUnionExtraction],
            &["path_sensitive_file"],
            0.9,
            2000,
        );
        let matches = correlator.ingest(s2);

        let match_entry = matches.iter().find(|m| m.chain_id == "sqli_data_exfil");
        assert!(match_entry.is_some());

        let mm = match_entry.unwrap();
        assert!(mm.associated_sources.len() >= 2);
        assert!(mm.steps_matched >= 2);
    }

    #[test]
    fn single_step_detection() {
        let mut correlator = ChainCorrelator::new();
        let signal = make_signal("src1", &[SqlStringTermination], &[], 0.8, 1000);
        let matches = correlator.ingest(signal);
        // Should match at least one chain step
        assert!(!matches.is_empty() || correlator.active_source_count() > 0);
    }

    #[test]
    fn sqli_chain_two_steps() {
        let mut correlator = ChainCorrelator::new();
        // Step 1: probe
        let s1 = make_signal("attacker1", &[SqlStringTermination], &[], 0.7, 1000);
        correlator.ingest(s1);
        // Step 2: extract
        let s2 = make_signal("attacker1", &[SqlUnionExtraction], &[], 0.85, 2000);
        let matches = correlator.ingest(s2);

        let sqli_match = matches.iter().find(|m| m.chain_id == "sqli_data_exfil");
        assert!(sqli_match.is_some(), "Should detect SQLi data exfil chain");
        let sqli = sqli_match.unwrap();
        assert!(sqli.steps_matched >= 2);
        assert!(sqli.confidence > 0.7);
    }

    #[test]
    fn chain_expiry() {
        let mut correlator = ChainCorrelator::new();
        // Step 1 at time 0
        let s1 = make_signal("attacker2", &[SsrfInternalReach], &[], 0.8, 0);
        correlator.ingest(s1);
        // Step 2 at time way beyond window (300s = 300_000ms)
        let s2 = make_signal("attacker2", &[SsrfCloudMetadata], &[], 0.9, 1_000_000);
        let matches = correlator.ingest(s2);
        // The chain should be expired for the SSRF cloud credential theft chain
        let ssrf_match = matches
            .iter()
            .find(|m| m.chain_id == "ssrf_cloud_credential_theft");
        // Either no match or expired (no match because expired state returns None)
        assert!(
            ssrf_match.is_none() || ssrf_match.unwrap().steps_matched < 2,
            "Chain should expire beyond window"
        );
    }

    #[test]
    fn lfi_credential_theft_chain() {
        let mut correlator = ChainCorrelator::new();
        let s1 = make_signal("apt1", &[PathDotdotEscape], &[], 0.6, 1000);
        correlator.ingest(s1);
        let s2 = make_signal(
            "apt1",
            &[PathDotdotEscape],
            &["path_sensitive_file"],
            0.75,
            5000,
        );
        let matches = correlator.ingest(s2);

        let lfi_match = matches
            .iter()
            .find(|m| m.chain_id == "lfi_credential_theft");
        assert!(
            lfi_match.is_some(),
            "Should detect LFI credential theft chain"
        );
    }

    #[test]
    fn attack_graph_inference() {
        let correlator = ChainCorrelator::new();
        let inferences =
            correlator.get_attack_graph_inference(&[SqlStringTermination, SqlUnionExtraction], &[]);
        assert!(!inferences.is_empty());
        assert!(inferences[0].probability > 0.1);
    }

    #[test]
    fn chain_temporal_factor_identifies_slow_timing() {
        let samples = vec![0u64, 2_700_000, 4_600_000, 5_200_000];
        let factor = temporal_slow_factor(&samples, 7_200);
        assert!(factor > 1.0);
    }

    #[test]
    fn chain_fingerprint_boost_functional() {
        let signals = vec![
            make_signal("fp1", &[SqlStringTermination], &[], 0.7, 0),
            make_signal("fp1", &[PathDotdotEscape], &[], 0.7, 100),
        ];

        assert!(cross_class_fingerprint_boost(&signals) > 1.0);

        let chain = attack_chains()
            .into_iter()
            .find(|c| c.id == "lfi_credential_theft")
            .expect("chain exists");
        assert!(chain_behavior_overlap(&signals, &chain) > 1.0);
    }

    #[test]
    fn slow_and_fast_chain_timing_adjustment() {
        let mut fast = ChainCorrelator::new();
        let mut slow = ChainCorrelator::new();

        for signal in [
            make_signal("dual", &[SqlStringTermination], &[], 0.35, 0),
            make_signal("dual", &[SqlErrorOracle], &[], 0.35, 1_000),
            make_signal("dual", &[SqlTautology], &[], 0.35, 2_000),
            make_signal("dual", &[SqlUnionExtraction], &[], 0.35, 3_000),
        ] {
            let _ = fast.ingest(signal);
        }

        for signal in [
            make_signal("dual", &[SqlStringTermination], &[], 0.35, 0),
            make_signal("dual", &[SqlErrorOracle], &[], 0.35, 2_700_000),
            make_signal("dual", &[SqlTautology], &[], 0.35, 5_400_000),
            make_signal("dual", &[SqlUnionExtraction], &[], 0.35, 5_900_000),
        ] {
            let _ = slow.ingest(signal);
        }

        let fast_match = fast
            .get_all_active_chains()
            .into_iter()
            .find(|m| m.chain_id == "slow_sqli_recon")
            .expect("fast slow_recon chain should exist");
        let slow_match = slow
            .get_all_active_chains()
            .into_iter()
            .find(|m| m.chain_id == "slow_sqli_recon")
            .expect("slow slow_recon chain should exist");

        assert!(slow_match.confidence > fast_match.confidence);
    }

    #[test]
    fn different_sources_independent() {
        let mut correlator = ChainCorrelator::new();
        let s1 = make_signal("src_a", &[SqlStringTermination], &[], 0.7, 1000);
        correlator.ingest(s1);
        let s2 = make_signal("src_b", &[SqlUnionExtraction], &[], 0.85, 2000);
        let matches = correlator.ingest(s2);
        // src_b's signal should not complete src_a's chain
        let cross_match = matches
            .iter()
            .find(|m| m.chain_id == "sqli_data_exfil" && m.steps_matched >= 2);
        assert!(
            cross_match.is_none(),
            "Different sources should not cross-correlate"
        );
    }

    #[test]
    fn supply_chain_compromise_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal("sc1", &[DependencyConfusion], &[], 0.72, 1_000));
        correlator.ingest(make_signal(
            "sc1",
            &[PostinstallInjection],
            &["code_execution"],
            0.74,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "sc1",
            &[CmdSeparator],
            &["reverse_shell"],
            0.76,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "supply_chain_compromise")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.76);
    }

    #[test]
    fn api_key_exfiltration_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal("api1", &[PathDotdotEscape], &[], 0.71, 1_000));
        correlator.ingest(make_signal(
            "api1",
            &[],
            &["path_sensitive_file", "credential_extraction"],
            0.73,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "api1",
            &[SsrfInternalReach],
            &["outbound_connection"],
            0.75,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "api_key_exfiltration")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.75);
    }

    #[test]
    fn cloud_metadata_pivot_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "cloud1",
            &[SsrfCloudMetadata],
            &[],
            0.70,
            1_000,
        ));
        correlator.ingest(make_signal(
            "cloud1",
            &[],
            &["credential_extraction"],
            0.74,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "cloud1",
            &[AuthHeaderSpoof],
            &["admin_access"],
            0.77,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "cloud_metadata_pivot")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.77);
    }

    #[test]
    fn graphql_abuse_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "gql1",
            &[GraphqlIntrospection],
            &[],
            0.70,
            1_000,
        ));
        correlator.ingest(make_signal("gql1", &[], &["schema_discovery"], 0.73, 2_000));
        let matches =
            correlator.ingest(make_signal("gql1", &[SqlUnionExtraction], &[], 0.78, 3_000));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "graphql_abuse_chain")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.78);
    }

    #[test]
    fn websocket_takeover_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal("ws1", &[WsHijack], &[], 0.72, 1_000));
        correlator.ingest(make_signal(
            "ws1",
            &[AuthHeaderSpoof],
            &["session_hijack"],
            0.74,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "ws1",
            &[CmdSubstitution],
            &["code_execution"],
            0.77,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "websocket_takeover")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.77);
    }

    #[test]
    fn jwt_to_account_takeover_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal("jwt1", &[JwtKidInjection], &[], 0.71, 1_000));
        correlator.ingest(make_signal(
            "jwt1",
            &[AuthNoneAlgorithm],
            &["privilege_escalation"],
            0.74,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "jwt1",
            &[MassAssignment],
            &["role_change"],
            0.79,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "jwt_to_account_takeover")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.79);
    }

    #[test]
    fn oauth_redirect_theft_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "oauth1",
            &[OpenRedirectBypass],
            &["oauth_flow"],
            0.72,
            1_000,
        ));
        correlator.ingest(make_signal(
            "oauth1",
            &[AuthHeaderSpoof],
            &["token_steal"],
            0.74,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "oauth1",
            &[JwtKidInjection],
            &["account_takeover"],
            0.79,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "oauth_redirect_theft")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.79);
    }

    #[test]
    fn cache_poisoning_to_xss_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "cache1",
            &[CacheDeception],
            &["cache_key_poisoning"],
            0.72,
            1_000,
        ));
        let matches = correlator.ingest(make_signal(
            "cache1",
            &[XssTagInjection],
            &["stored_xss"],
            0.78,
            2_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "cache_poisoning_to_xss")
            .expect("chain exists");
        assert!(chain.steps_matched >= 2);
        assert!(chain.confidence > 0.78);
    }

    #[test]
    fn ssrf_to_rce_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "ssrf1",
            &[SsrfInternalReach],
            &["internal_recon"],
            0.72,
            1_000,
        ));
        correlator.ingest(make_signal(
            "ssrf1",
            &[SsrfCloudMetadata],
            &["credential_extraction"],
            0.74,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "ssrf1",
            &[CmdSubstitution],
            &["reverse_shell"],
            0.8,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "ssrf_to_rce")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.8);
    }

    #[test]
    fn prototype_pollution_to_rce_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "pp1",
            &[ProtoPollution],
            &["property_injection"],
            0.72,
            1_000,
        ));
        correlator.ingest(make_signal(
            "pp1",
            &[ProtoPollutionGadget],
            &["code_execution"],
            0.74,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "pp1",
            &[CmdSubstitution],
            &["reverse_shell"],
            0.81,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "prototype_pollution_to_rce")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.81);
    }

    #[test]
    fn deserialization_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal("deser1", &[DeserJavaGadget], &[], 0.72, 1_000));
        correlator.ingest(make_signal(
            "deser1",
            &[CmdSeparator],
            &["code_execution"],
            0.75,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "deser1",
            &[CmdSubstitution],
            &["reverse_shell"],
            0.84,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "deserialization_chain")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.84);
    }

    #[test]
    fn log4shell_to_lateral_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "log4j1",
            &[LogJndiLookup],
            &["class_loading"],
            0.72,
            1_000,
        ));
        correlator.ingest(make_signal(
            "log4j1",
            &[SsrfProtocolSmuggle],
            &["outbound_connection"],
            0.74,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "log4j1",
            &[AuthNoneAlgorithm],
            &["lateral_movement"],
            0.83,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "log4shell_to_lateral")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.83);
    }

    #[test]
    fn ssrf_cloud_metadata_lateral_chain_defined() {
        chain_definition_expect("ssrf_cloud_metadata_lateral", 4, Some(4));
    }

    #[test]
    fn ssrf_cloud_metadata_lateral_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "meta1",
            &[SsrfInternalReach],
            &["internal_recon"],
            0.7,
            1_000,
        ));
        correlator.ingest(make_signal(
            "meta1",
            &[SsrfCloudMetadata],
            &["metadata_probe"],
            0.74,
            2_000,
        ));
        correlator.ingest(make_signal(
            "meta1",
            &[SsrfProtocolSmuggle],
            &["credential_extraction"],
            0.79,
            3_000,
        ));
        let matches = correlator.ingest(make_signal(
            "meta1",
            &[AuthHeaderSpoof],
            &["lateral_movement"],
            0.84,
            4_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "ssrf_cloud_metadata_lateral")
            .expect("chain exists");
        assert!(chain.steps_matched >= 4);
        assert!(chain.confidence > 0.84);
    }

    #[test]
    fn xxe_to_ssrf_to_exfiltration_chain_defined() {
        chain_definition_expect("xxe_to_ssrf_to_exfiltration", 3, Some(3));
    }

    #[test]
    fn xxe_to_ssrf_to_exfiltration_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "xxe1",
            &[XxeEntityExpansion],
            &["external_entity"],
            0.7,
            1_000,
        ));
        correlator.ingest(make_signal(
            "xxe1",
            &[SsrfProtocolSmuggle],
            &["internal_request"],
            0.76,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "xxe1",
            &[],
            &["data_exfiltration", "outbound_connection"],
            0.81,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "xxe_to_ssrf_to_exfiltration")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.81);
    }

    #[test]
    fn sqli_to_webshell_rce_chain_defined() {
        chain_definition_expect("sqli_to_webshell_rce", 3, Some(3));
    }

    #[test]
    fn sqli_to_webshell_rce_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "sqli2",
            &[SqlStringTermination],
            &["sqli_probe"],
            0.73,
            1_000,
        ));
        correlator.ingest(make_signal(
            "sqli2",
            &[SqlStackedExecution],
            &["file_system_write", "webshell_upload"],
            0.77,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "sqli2",
            &[CmdSubstitution],
            &["code_execution", "webshell"],
            0.86,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "sqli_to_webshell_rce")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.86);
    }

    #[test]
    fn auth_bypass_to_admin_sensitive_data_chain_defined() {
        chain_definition_expect("auth_bypass_to_admin_sensitive_data", 3, Some(3));
    }

    #[test]
    fn auth_bypass_to_admin_sensitive_data_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "auth1",
            &[AuthNoneAlgorithm],
            &["auth_bypass"],
            0.75,
            1_000,
        ));
        correlator.ingest(make_signal(
            "auth1",
            &[AuthHeaderSpoof],
            &["admin_access"],
            0.78,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "auth1",
            &[],
            &["sensitive_data_access", "credential_extraction"],
            0.83,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "auth_bypass_to_admin_sensitive_data")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.83);
    }

    #[test]
    fn deserialization_to_rce_persistence_chain_defined() {
        chain_definition_expect("deserialization_to_rce_persistence", 3, Some(3));
    }

    #[test]
    fn deserialization_to_rce_persistence_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "des1",
            &[DeserPythonPickle],
            &["deserialization_gadget"],
            0.76,
            1_000,
        ));
        correlator.ingest(make_signal(
            "des1",
            &[CmdSubstitution],
            &["code_execution"],
            0.79,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "des1",
            &[CmdSeparator],
            &["persistence", "persistence_install"],
            0.87,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "deserialization_to_rce_persistence")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.87);
    }

    #[test]
    fn cors_to_session_theft_chain_defined() {
        chain_definition_expect("cors_to_session_theft", 3, Some(3));
    }

    #[test]
    fn cors_to_session_theft_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "cors1",
            &[CorsOriginAbuse],
            &["cors_policy_bypass"],
            0.72,
            1_000,
        ));
        correlator.ingest(make_signal(
            "cors1",
            &[XssProtocolHandler],
            &["token_steal"],
            0.76,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "cors1",
            &[AuthHeaderSpoof],
            &["session_theft"],
            0.84,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "cors_to_session_theft")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.84);
    }

    #[test]
    fn llm_prompt_to_api_key_exfil_chain_defined() {
        chain_definition_expect("llm_prompt_to_api_key_exfil", 3, Some(3));
    }

    #[test]
    fn llm_prompt_to_api_key_exfil_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "llm1",
            &[LlmPromptInjection],
            &["prompt_escape"],
            0.72,
            1_000,
        ));
        correlator.ingest(make_signal(
            "llm1",
            &[LlmJailbreak],
            &["system_prompt_extraction"],
            0.77,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "llm1",
            &[LlmDataExfiltration],
            &["api_key_exfiltration"],
            0.89,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "llm_prompt_to_api_key_exfil")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.89);
    }

    #[test]
    fn supply_chain_to_backdoor_c2_chain_defined() {
        chain_definition_expect("supply_chain_to_backdoor_c2", 4, Some(4));
    }

    #[test]
    fn supply_chain_to_backdoor_c2_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "sc2",
            &[DependencyConfusion],
            &["dependency_confusion"],
            0.75,
            1_000,
        ));
        correlator.ingest(make_signal(
            "sc2",
            &[PostinstallInjection],
            &["backdoor_payload"],
            0.78,
            2_000,
        ));
        correlator.ingest(make_signal(
            "sc2",
            &[EnvExfiltration],
            &["environment_variable_access"],
            0.81,
            3_000,
        ));
        let matches = correlator.ingest(make_signal(
            "sc2",
            &[CmdSeparator],
            &["c2_beacon"],
            0.88,
            4_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "supply_chain_to_backdoor_c2")
            .expect("chain exists");
        assert!(chain.steps_matched >= 4);
        assert!(chain.confidence > 0.88);
    }

    #[test]
    fn log4shell_to_jndi_rce_chain_defined() {
        chain_definition_expect("log4shell_to_jndi_rce", 3, Some(3));
    }

    #[test]
    fn log4shell_to_jndi_rce_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "l4j1",
            &[LogJndiLookup],
            &["jndi_lookup"],
            0.75,
            1_000,
        ));
        correlator.ingest(make_signal(
            "l4j1",
            &[SsrfProtocolSmuggle],
            &["class_loading"],
            0.79,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "l4j1",
            &[CmdSubstitution],
            &["code_execution"],
            0.9,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "log4shell_to_jndi_rce")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.9);
    }

    #[test]
    fn http_smuggling_to_cache_poison_xss_chain_defined() {
        chain_definition_expect("http_smuggling_to_cache_poison_xss", 3, Some(3));
    }

    #[test]
    fn http_smuggling_to_cache_poison_xss_chain_detects_with_confidence_boost() {
        let mut correlator = ChainCorrelator::new();
        correlator.ingest(make_signal(
            "http1",
            &[HttpSmuggleClTe],
            &["cache_deception"],
            0.71,
            1_000,
        ));
        correlator.ingest(make_signal(
            "http1",
            &[CachePoisoning],
            &["cache_key_poisoning"],
            0.77,
            2_000,
        ));
        let matches = correlator.ingest(make_signal(
            "http1",
            &[XssTagInjection],
            &["reflected_xss"],
            0.85,
            3_000,
        ));

        let chain = matches
            .iter()
            .find(|m| m.chain_id == "http_smuggling_to_cache_poison_xss")
            .expect("chain exists");
        assert!(chain.steps_matched >= 3);
        assert!(chain.confidence > 0.85);
    }
}
