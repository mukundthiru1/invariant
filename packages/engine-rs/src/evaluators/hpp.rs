//! HTTP Parameter Pollution (HPP) Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

pub type L2EvalResult = L2Detection;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ParamSource {
    Query,
    Form,
    Json,
    Multipart,
}

impl ParamSource {
    fn as_str(self) -> &'static str {
        match self {
            ParamSource::Query => "query",
            ParamSource::Form => "form",
            ParamSource::Json => "json",
            ParamSource::Multipart => "multipart",
        }
    }
}

#[derive(Debug, Clone)]
struct ParamEntry {
    raw_key: String,
    canonical_key: String,
    value: String,
    source: ParamSource,
    encoded_key: bool,
    array_style: bool,
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(((hi << 4) as u8 | lo as u8) as char);
                i += 3;
                continue;
            }
        }

        let b = bytes[i];
        if b == b'+' {
            out.push(' ');
        } else {
            out.push(b as char);
        }
        i += 1;
    }

    out
}

fn canonicalize_key(raw_key: &str) -> (String, bool, bool) {
    let decoded = percent_decode(raw_key);
    let lowered = decoded.trim().to_ascii_lowercase();
    let array_style = lowered.ends_with("[]");
    let canonical = lowered.trim_end_matches("[]").to_string();
    let encoded = raw_key.contains('%') && !decoded.eq_ignore_ascii_case(raw_key);
    (canonical, encoded, array_style)
}

fn parse_pairs(input: &str, source: ParamSource) -> Vec<ParamEntry> {
    let mut out = Vec::new();

    for pair in input.split(['&', ';']) {
        if pair.is_empty() {
            continue;
        }
        let mut parts = pair.splitn(2, '=');
        let raw_key = parts.next().unwrap_or_default().trim();
        if raw_key.is_empty() {
            continue;
        }
        let raw_value = parts.next().unwrap_or_default().trim();
        let (canonical_key, encoded_key, array_style) = canonicalize_key(raw_key);
        if canonical_key.is_empty() {
            continue;
        }

        out.push(ParamEntry {
            raw_key: raw_key.to_string(),
            canonical_key,
            value: percent_decode(raw_value),
            source,
            encoded_key,
            array_style,
        });
    }

    out
}

fn parse_http_sections(input: &str) -> (String, HashMap<String, String>, String) {
    if let Some((head, body)) = input.split_once("\r\n\r\n") {
        return parse_head_body(head, body);
    }
    if let Some((head, body)) = input.split_once("\n\n") {
        return parse_head_body(head, body);
    }
    (String::new(), HashMap::new(), String::new())
}

fn parse_head_body(head: &str, body: &str) -> (String, HashMap<String, String>, String) {
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut query = String::new();

    if let Some(path) = request_line.split_whitespace().nth(1) {
        if let Some((_, q)) = path.split_once('?') {
            query = q.to_string();
        }
    }

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    (query, headers, body.to_string())
}

fn parse_json_keys(body: &str) -> Vec<ParamEntry> {
    let mut out = Vec::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return out;
    };

    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            let (canonical_key, encoded_key, array_style) = canonicalize_key(k);
            if canonical_key.is_empty() {
                continue;
            }
            let value_str = if let Some(s) = v.as_str() {
                s.to_string()
            } else {
                v.to_string()
            };

            out.push(ParamEntry {
                raw_key: k.clone(),
                canonical_key,
                value: value_str,
                source: ParamSource::Json,
                encoded_key,
                array_style,
            });
        }
    }

    out
}

fn parse_multipart_names(body: &str) -> Vec<ParamEntry> {
    let mut out = Vec::new();

    for line in body.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("content-disposition") || !lower.contains("name=") {
            continue;
        }

        if let Some(name_idx) = lower.find("name=") {
            let tail = &line[name_idx + 5..].trim();
            let raw_name = if let Some(rest) = tail.strip_prefix('"') {
                rest.split('"').next().unwrap_or_default()
            } else {
                tail.split(';').next().unwrap_or_default().trim()
            };

            if raw_name.is_empty() {
                continue;
            }

            let (canonical_key, encoded_key, array_style) = canonicalize_key(raw_name);
            if canonical_key.is_empty() {
                continue;
            }

            out.push(ParamEntry {
                raw_key: raw_name.to_string(),
                canonical_key,
                value: String::new(),
                source: ParamSource::Multipart,
                encoded_key,
                array_style,
            });
        }
    }

    out
}

fn has_mixed_semicolon_ampersand(input: &str, query: &str, body: &str) -> bool {
    let candidate = if !query.is_empty() {
        query
    } else if !body.is_empty() {
        body
    } else {
        input
    };

    candidate.contains(';') && candidate.contains('&')
}

fn detect_boundary_manipulation(headers: &HashMap<String, String>, body: &str) -> bool {
    let Some(content_type) = headers.get("content-type") else {
        return false;
    };
    let ct_lower = content_type.to_ascii_lowercase();
    if !ct_lower.contains("multipart/form-data") {
        return false;
    }

    let mut boundaries = Vec::new();
    for part in content_type.split(';').map(|p| p.trim()) {
        let lower = part.to_ascii_lowercase();
        if let Some((_, b)) = lower.split_once("boundary=") {
            boundaries.push(b.trim_matches('"').to_string());
        }
    }

    if boundaries.is_empty() {
        return true;
    }

    let unique: HashSet<_> = boundaries.iter().collect();
    if unique.len() > 1 {
        return true;
    }

    let boundary = boundaries[0].trim_matches('"');
    if boundary.is_empty() {
        return true;
    }

    // Body must use the declared boundary marker.
    let declared_marker = format!("--{}", boundary);
    if body.contains("--") && !body.contains(&declared_marker) {
        return true;
    }

    false
}

fn find_conflicts(entries: &[ParamEntry]) -> (usize, usize, bool, bool, bool, bool) {
    let mut by_key: HashMap<&str, Vec<&ParamEntry>> = HashMap::new();
    for entry in entries {
        by_key
            .entry(entry.canonical_key.as_str())
            .or_default()
            .push(entry);
    }

    let mut duplicate_conflicts = 0usize;
    let mut duplicate_total = 0usize;
    let mut encoded_duplicate = false;
    let mut array_injection = false;
    let mut cross_format_collision = false;
    let mut precedence_collision = false;

    for group in by_key.values() {
        if group.len() < 2 {
            continue;
        }

        duplicate_total += 1;

        let distinct_values: HashSet<&str> = group.iter().map(|e| e.value.as_str()).collect();
        if distinct_values.len() > 1 {
            duplicate_conflicts += 1;
        }

        if group.iter().any(|e| e.encoded_key) && group.iter().any(|e| !e.encoded_key) {
            encoded_duplicate = true;
        }

        if group.iter().filter(|e| e.array_style).count() >= 2 {
            array_injection = true;
        }

        let sources: HashSet<ParamSource> = group.iter().map(|e| e.source).collect();
        if sources.contains(&ParamSource::Query) && sources.contains(&ParamSource::Json) {
            cross_format_collision = true;
        }
        if sources.contains(&ParamSource::Query) && sources.contains(&ParamSource::Form) {
            precedence_collision = true;
        }
    }

    (
        duplicate_conflicts,
        duplicate_total,
        encoded_duplicate,
        array_injection,
        cross_format_collision,
        precedence_collision,
    )
}

static DOT_NOTATION_POLLUTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[?&;])([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)=([^&;]+)")
        .expect("valid dot-notation pollution regex")
});

static DOUBLE_ENCODED_KEY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[?&;]([^=]*%25[0-9a-f]{2}[^=]*)=").expect("valid regex"));

static NESTED_JSON_ADMIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\{[^{}]*"[^"]+"\s*:\s*\{[^{}]*"(?:role|admin|permission)""#)
        .expect("valid nested json regex")
});

fn extract_query_candidates(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (query, _, _) = parse_http_sections(input);
    if !query.is_empty() {
        out.push(query);
    }

    for line in input.lines() {
        let mut parts = line.split_whitespace();
        let _method = parts.next().unwrap_or_default();
        let path = parts.next().unwrap_or_default();
        if let Some((_, q)) = path.split_once('?') {
            let query = q.trim();
            if !query.is_empty() {
                out.push(query.to_string());
            }
        }
    }

    if out.is_empty() {
        if let Some((_, q)) = input.split_once('?') {
            let query = q
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_matches('?')
                .trim();
            if !query.is_empty() {
                out.push(query.to_string());
            }
        }
    }

    let mut seen = HashSet::new();
    out.into_iter()
        .filter(|q| !q.is_empty())
        .filter(|q| seen.insert(q.clone()))
        .collect()
}

fn extract_cookie_header_values(input: &str, headers: &HashMap<String, String>) -> Vec<String> {
    let mut values = Vec::new();
    if let Some(cookie) = headers.get("cookie") {
        values.push(cookie.clone());
    }

    for line in input.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("cookie") {
                values.push(v.trim().to_string());
            }
        }
    }

    values
}

fn detect_cookie_query_collision(input: &str) -> Vec<L2Detection> {
    let (_, headers, _) = parse_http_sections(input);
    let query_candidates = extract_query_candidates(input);
    let mut query_keys = HashSet::new();
    for query in query_candidates {
        for entry in parse_pairs(&query, ParamSource::Query) {
            query_keys.insert(entry.canonical_key);
        }
    }

    let mut cookie_keys = HashSet::new();
    for cookie_line in extract_cookie_header_values(input, &headers) {
        for token in cookie_line.split(';') {
            let raw = token.trim();
            if raw.is_empty() {
                continue;
            }
            let Some((k, _)) = raw.split_once('=') else {
                continue;
            };
            let (canonical, _, _) = canonicalize_key(k.trim());
            if !canonical.is_empty() {
                cookie_keys.insert(canonical);
            }
        }
    }

    query_keys
        .intersection(&cookie_keys)
        .map(|key| L2Detection {
            detection_type: "hpp_cookie_query_collision".into(),
            confidence: 0.88,
            detail: format!("Cookie/query key collision detected for parameter '{}'", key),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: format!("collision_key={}", key),
                interpretation:
                    "Same canonical key is present in Cookie and query parameter channels".into(),
                offset: 0,
                property: "Same parameter must not appear in both Cookie and query string — server may merge them in undefined order".into(),
            }],
        })
        .collect()
}

fn detect_dot_notation_pollution(input: &str) -> Vec<L2Detection> {
    let mut dets = Vec::new();
    let query_candidates = extract_query_candidates(input);
    let privileged_values = ["admin", "true", "1", "root", "superuser", "enabled"];

    for query in query_candidates {
        let with_prefix = format!("?{}", query);
        for caps in DOT_NOTATION_POLLUTION_RE.captures_iter(&with_prefix) {
            let raw_key = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let raw_value = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            let value = percent_decode(raw_value).to_ascii_lowercase();

            if privileged_values.iter().any(|p| value == *p) {
                dets.push(L2Detection {
                    detection_type: "hpp_dot_notation_pollution".into(),
                    confidence: 0.84,
                    detail: format!(
                        "Dot-notation parameter '{}' carries privileged value '{}'",
                        raw_key, raw_value
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::TypeCoerce,
                        matched_input: format!("{}={}", raw_key, raw_value),
                        interpretation:
                            "Dot-notation keys can be expanded into nested objects by some frameworks".into(),
                        offset: 0,
                        property: "Dot-notation keys may be parsed as nested object properties by some frameworks, enabling privilege escalation".into(),
                    }],
                });
            }
        }
    }

    dets
}

fn normalize_key_for_collision(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn detect_double_encoded_key(input: &str) -> Vec<L2Detection> {
    let mut dets = Vec::new();
    let query_candidates = extract_query_candidates(input);

    for query in query_candidates {
        let entries = parse_pairs(&query, ParamSource::Query);
        let existing: HashSet<String> = entries
            .iter()
            .map(|e| normalize_key_for_collision(&e.canonical_key))
            .collect();
        let with_prefix = format!("?{}", query);

        for caps in DOUBLE_ENCODED_KEY_RE.captures_iter(&with_prefix) {
            let raw_key = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let once_decoded = percent_decode(raw_key);
            let twice_decoded = percent_decode(&once_decoded);
            let normalized_twice = normalize_key_for_collision(&twice_decoded);

            if !normalized_twice.is_empty() && existing.contains(&normalized_twice) {
                dets.push(L2Detection {
                    detection_type: "hpp_double_encoded_key".into(),
                    confidence: 0.86,
                    detail: format!(
                        "Double-encoded key '{}' resolves to '{}' after two decodes",
                        raw_key, twice_decoded
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::EncodingDecode,
                        matched_input: format!(
                            "raw_key={} once={} twice={}",
                            raw_key, once_decoded, twice_decoded
                        ),
                        interpretation:
                            "Double decoding collapses a disguised key into an existing parameter namespace".into(),
                        offset: 0,
                        property: "Double-encoded parameter keys bypass WAF/middleware canonicalization, creating duplicate parameter confusion".into(),
                    }],
                });
            }
        }
    }

    dets
}

fn key_depths(input: &str, key: &str) -> Vec<usize> {
    let needle = format!("\"{}\"", key);
    let mut depths = Vec::new();
    let bytes = input.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut depth = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth = depth.saturating_add(1),
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if i + needle_bytes.len() <= bytes.len() && &bytes[i..i + needle_bytes.len()] == needle_bytes
        {
            depths.push(depth);
        }
        i += 1;
    }
    depths
}

fn detect_nested_json_hpp(input: &str) -> Vec<L2Detection> {
    let role_depths = key_depths(input, "role");
    let unique_depths: HashSet<usize> = role_depths.iter().copied().collect();
    let has_multi_depth_role = role_depths.len() >= 2 && unique_depths.len() >= 2;
    let has_nested_admin_pattern = NESTED_JSON_ADMIN_RE.is_match(input);
    let has_privileged_terms = input.contains("\"admin\"")
        || input.contains("\"permissions\"")
        || input.contains("\"permission\"");

    if has_multi_depth_role || (has_nested_admin_pattern && has_privileged_terms) {
        return vec![L2Detection {
            detection_type: "hpp_nested_json".into(),
            confidence: 0.83,
            detail: "Nested JSON key duplication indicates potential merge-order confusion".into(),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: input.chars().take(220).collect(),
                interpretation:
                    "Privileged JSON keys appear across multiple nesting levels in the same payload".into(),
                offset: 0,
                property: "JSON parameter pollution via nested key duplication can confuse server-side object merge logic".into(),
            }],
        }];
    }

    Vec::new()
}

pub fn evaluate_hpp(input: &str) -> Option<L2EvalResult> {
    let decoded_input = crate::encoding::multi_layer_decode(input).fully_decoded;
    let (mut query, headers, body) = parse_http_sections(input);

    if query.is_empty() {
        if let Some((_, q)) = input.split_once('?') {
            query = q.split_whitespace().next().unwrap_or_default().to_string();
        } else if input.contains('=') {
            query = input.to_string();
        }
    }

    let mut entries = Vec::new();
    if !query.is_empty() {
        entries.extend(parse_pairs(&query, ParamSource::Query));
    }

    let content_type = headers
        .get("content-type")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    if content_type.contains("application/x-www-form-urlencoded") {
        entries.extend(parse_pairs(&body, ParamSource::Form));
    }
    if content_type.contains("application/json") {
        entries.extend(parse_json_keys(&body));
    }
    if content_type.contains("multipart/form-data") {
        entries.extend(parse_multipart_names(&body));
    }

    let (
        duplicate_conflicts,
        duplicate_total,
        encoded_duplicate,
        array_injection,
        cross_format_collision,
        precedence_collision,
    ) = find_conflicts(&entries);

    let mixed_delimiters = has_mixed_semicolon_ampersand(input, &query, &body);
    let boundary_manipulation = detect_boundary_manipulation(&headers, &body);

    let is_detected = duplicate_conflicts > 0
        || array_injection
        || (mixed_delimiters && duplicate_total > 0)
        || encoded_duplicate
        || precedence_collision
        || boundary_manipulation
        || cross_format_collision;

    if !is_detected {
        return None;
    }

    let confidence = if cross_format_collision {
        0.90
    } else if encoded_duplicate {
        0.85
    } else if duplicate_conflicts > 1
        || array_injection
        || precedence_collision
        || boundary_manipulation
    {
        0.75
    } else {
        0.65
    };

    let mut patterns = Vec::new();
    if duplicate_conflicts > 0 {
        patterns.push(format!(
            "{} conflicting duplicate key(s)",
            duplicate_conflicts
        ));
    }
    if array_injection {
        patterns.push("array-style key[] duplication".to_string());
    }
    if mixed_delimiters && duplicate_total > 0 {
        patterns.push("mixed ';' and '&' delimiter pollution".to_string());
    }
    if encoded_duplicate {
        patterns.push("encoded/plain key collision".to_string());
    }
    if precedence_collision {
        patterns.push("query/form precedence collision".to_string());
    }
    if boundary_manipulation {
        patterns.push("multipart boundary manipulation".to_string());
    }
    if cross_format_collision {
        patterns.push("query/json key collision".to_string());
    }

    let matched = entries
        .iter()
        .take(6)
        .map(|e| {
            format!(
                "{}={} [{}:{}]",
                e.raw_key,
                e.value,
                e.source.as_str(),
                e.canonical_key
            )
        })
        .collect::<Vec<_>>()
        .join("; ");

    Some(L2Detection {
        detection_type: "http_parameter_pollution".into(),
        confidence,
        detail: format!("HPP pattern(s): {}", patterns.join(", ")),
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: if matched.is_empty() {
                decoded_input.chars().take(180).collect()
            } else {
                matched
            },
            interpretation: "Conflicting parameter semantics can create parser/precedence divergence across HTTP layers".into(),
            offset: 0,
            property: "Each logical parameter key should resolve to a single unambiguous value after canonicalization".into(),
        }],
    })
}

pub struct HppEvaluator;

impl L2Evaluator for HppEvaluator {
    fn id(&self) -> &'static str {
        "hpp"
    }
    fn prefix(&self) -> &'static str {
        "L2 HPP"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets: Vec<L2Detection> = evaluate_hpp(input).into_iter().collect();
        dets.extend(detect_cookie_query_collision(input));
        dets.extend(detect_dot_notation_pollution(input));
        dets.extend(detect_double_encoded_key(input));
        dets.extend(detect_nested_json_hpp(input));
        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "http_parameter_pollution" => Some(InvariantClass::HttpParameterPollution),
            "hpp_cookie_query_collision" => Some(InvariantClass::HttpParameterPollution),
            "hpp_dot_notation_pollution" => Some(InvariantClass::HttpParameterPollution),
            "hpp_double_encoded_key" => Some(InvariantClass::HttpParameterPollution),
            "hpp_nested_json" => Some(InvariantClass::HttpParameterPollution),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_decodes_hex() {
        assert_eq!(percent_decode("%6b%65%79"), "key");
    }

    #[test]
    fn canonicalize_key_normalizes_arrays_and_encoding() {
        let (key, encoded, array) = canonicalize_key("%75ser[]");
        assert_eq!(key, "user");
        assert!(encoded);
        assert!(array);
    }

    #[test]
    fn parse_pairs_handles_ampersand_and_semicolon() {
        let entries = parse_pairs("a=1;b=2&c=3", ParamSource::Query);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn parse_http_sections_extracts_query_headers_and_body() {
        let raw =
            "POST /a?x=1 HTTP/1.1\r\nHost: e\r\nContent-Type: application/json\r\n\r\n{\"x\":2}";
        let (query, headers, body) = parse_http_sections(raw);
        assert_eq!(query, "x=1");
        assert_eq!(
            headers.get("content-type").map(|s| s.as_str()),
            Some("application/json")
        );
        assert_eq!(body, "{\"x\":2}");
    }

    #[test]
    fn parse_json_keys_extracts_top_level_object() {
        let entries = parse_json_keys("{\"id\":1,\"name\":\"a\"}");
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.canonical_key == "id"));
    }

    #[test]
    fn parse_multipart_names_extracts_form_field_names() {
        let body = "--x\r\nContent-Disposition: form-data; name=\"role\"\r\n\r\nuser\r\n--x--";
        let entries = parse_multipart_names(body);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].canonical_key, "role");
    }

    #[test]
    fn boundary_manipulation_detects_multiple_boundaries() {
        let mut headers = HashMap::new();
        headers.insert(
            "content-type".to_string(),
            "multipart/form-data; boundary=abc; boundary=def".to_string(),
        );
        assert!(detect_boundary_manipulation(&headers, "--abc\r\n"));
    }

    #[test]
    fn boundary_manipulation_detects_mismatched_body_boundary() {
        let mut headers = HashMap::new();
        headers.insert(
            "content-type".to_string(),
            "multipart/form-data; boundary=abc".to_string(),
        );
        assert!(detect_boundary_manipulation(&headers, "--def\r\n"));
    }

    #[test]
    fn no_detection_single_param() {
        assert!(evaluate_hpp("id=1").is_none());
    }

    #[test]
    fn no_detection_no_duplicates() {
        assert!(evaluate_hpp("a=1&b=2&c=3").is_none());
    }

    #[test]
    fn detects_single_duplicate_conflict_with_score() {
        let res = evaluate_hpp("id=1&id=2").expect("expected HPP detection");
        assert_eq!(res.confidence, 0.65);
        assert!(res.detail.contains("conflicting duplicate"));
    }

    #[test]
    fn detects_multiple_duplicate_conflicts_with_score() {
        let res = evaluate_hpp("id=1&id=2&role=user&role=admin").expect("expected HPP detection");
        assert_eq!(res.confidence, 0.75);
    }

    #[test]
    fn detects_array_injection() {
        let res = evaluate_hpp("key[]=1&key[]=2").expect("expected HPP detection");
        assert!(res.detail.contains("array-style"));
    }

    #[test]
    fn detects_mixed_semicolon_and_ampersand_pattern() {
        let res = evaluate_hpp("key=1;key=2&key=3").expect("expected HPP detection");
        assert!(res.detail.contains("mixed ';' and '&'"));
    }

    #[test]
    fn detects_encoded_duplicate_with_score() {
        let res = evaluate_hpp("%6b%65%79=1&key=2").expect("expected HPP detection");
        assert_eq!(res.confidence, 0.85);
        assert!(res.detail.contains("encoded/plain"));
    }

    #[test]
    fn detects_query_form_precedence_collision() {
        let req = "POST /p?role=user HTTP/1.1\r\nHost: ex\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nrole=admin";
        let res = evaluate_hpp(req).expect("expected HPP detection");
        assert!(res.detail.contains("query/form precedence collision"));
    }

    #[test]
    fn detects_multipart_boundary_manipulation() {
        let req = "POST /upload HTTP/1.1\r\nHost: ex\r\nContent-Type: multipart/form-data; boundary=abc; boundary=def\r\n\r\n--abc\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n1\r\n--abc--";
        let res = evaluate_hpp(req).expect("expected HPP detection");
        assert!(res.detail.contains("multipart boundary manipulation"));
    }

    #[test]
    fn detects_query_json_collision_with_score() {
        let req = "POST /api?user=guest HTTP/1.1\r\nHost: ex\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}";
        let res = evaluate_hpp(req).expect("expected HPP detection");
        assert_eq!(res.confidence, 0.90);
        assert!(res.detail.contains("query/json key collision"));
    }

    #[test]
    fn no_detection_body_only_json_without_collision() {
        let req = "POST /api HTTP/1.1\r\nHost: ex\r\nContent-Type: application/json\r\n\r\n{\"a\":1,\"b\":2}";
        assert!(evaluate_hpp(req).is_none());
    }

    #[test]
    fn no_detection_url_only_without_duplicates() {
        let req = "GET /x?a=1&b=2 HTTP/1.1\r\nHost: ex\r\n\r\n";
        assert!(evaluate_hpp(req).is_none());
    }

    #[test]
    fn evaluator_wrapper_returns_detection() {
        let eval = HppEvaluator;
        let dets = eval.detect("id=1&id=2");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].detection_type, "http_parameter_pollution");
    }

    #[test]
    fn evaluator_maps_class() {
        let eval = HppEvaluator;
        assert_eq!(
            eval.map_class("http_parameter_pollution"),
            Some(InvariantClass::HttpParameterPollution)
        );
    }

    #[test]
    fn test_cookie_query_collision() {
        let eval = HppEvaluator;
        let input = "GET /?user_id=1 HTTP/1.1\r\nHost: ex\r\nCookie: user_id=admin\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "hpp_cookie_query_collision")
        );
    }

    #[test]
    fn test_dot_notation_admin() {
        let eval = HppEvaluator;
        let dets = eval.detect("GET /?user.role=admin HTTP/1.1\r\nHost: ex\r\n\r\n");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "hpp_dot_notation_pollution")
        );
    }

    #[test]
    fn test_double_encoded_key() {
        let eval = HppEvaluator;
        let dets = eval.detect("GET /?user%2525id=1&user_id=admin HTTP/1.1\r\nHost: ex\r\n\r\n");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "hpp_double_encoded_key")
        );
    }

    #[test]
    fn test_nested_json_hpp() {
        let eval = HppEvaluator;
        let input = "POST /api HTTP/1.1\r\nHost: ex\r\nContent-Type: application/json\r\n\r\n{\"role\":\"user\",\"user\":{\"role\":\"admin\"}}";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "hpp_nested_json"));
    }
}
