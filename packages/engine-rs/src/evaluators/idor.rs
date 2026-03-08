//! Insecure Direct Object Reference (IDOR / BOLA) Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

pub type L2EvalResult = L2Detection;

const EVIDENCE_PREVIEW_LIMIT: usize = 180;
const CONF_SINGLE_ID: f64 = 0.50;
const CONF_MULTIPLE_IDS: f64 = 0.65;
const CONF_SEQUENTIAL_IDS: f64 = 0.80;
const CONF_ENCODED_ID: f64 = 0.70;

const ID_KEY_PREFIXES: &[&str] = &[
    "user",
    "account",
    "order",
    "product",
    "file",
    "profile",
    "tenant",
    "org",
    "project",
    "member",
    "customer",
    "invoice",
    "ticket",
    "team",
    "subscription",
    "message",
    "payment",
    "node",
    "resource",
];

const RESOURCE_SEGMENTS: &[&str] = &[
    "user",
    "users",
    "account",
    "accounts",
    "order",
    "orders",
    "product",
    "products",
    "file",
    "files",
    "profile",
    "profiles",
    "tenant",
    "tenants",
    "customer",
    "customers",
    "member",
    "members",
    "project",
    "projects",
    "invoice",
    "invoices",
    "ticket",
    "tickets",
    "team",
    "teams",
    "subscription",
    "subscriptions",
    "message",
    "messages",
    "payment",
    "payments",
    "node",
    "nodes",
    "upload",
    "uploads",
    "document",
    "documents",
];

const ACTOR_KEYS: &[&str] = &[
    "acting_user_id",
    "requesting_user_id",
    "current_user_id",
    "session_user_id",
    "actor_id",
    "subject_id",
    "caller_id",
    "from_user_id",
    "auth_user_id",
    "principal_id",
    "owner_id",
];

const TARGET_KEYS: &[&str] = &[
    "target_user_id",
    "victim_id",
    "target_id",
    "owner_id",
    "impersonated_user_id",
    "impersonate_user_id",
    "resource_owner_id",
    "for_user_id",
    "target_account_id",
    "object_owner_id",
];

#[derive(Clone)]
struct IdCandidate {
    key: String,
    value: String,
    kind: &'static str,
    position: usize,
}

#[derive(Clone)]
struct EncodedCandidate {
    key: String,
    raw: String,
    decoded: String,
    position: usize,
}

#[inline]
fn preview(input: &str, start: usize) -> String {
    let start = start.min(input.len());
    let end = (start + EVIDENCE_PREVIEW_LIMIT).min(input.len());
    String::from_utf8_lossy(&input.as_bytes()[start..end]).into_owned()
}

#[inline]
fn normalize_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace('-', "_")
}

#[inline]
fn sanitize_token(value: &str) -> &str {
    value.trim_matches(|c: char| {
        c == '"'
            || c == '\''
            || c == ')'
            || c == '}'
            || c == ']'
            || c == '>'
            || c == ';'
            || c == ','
    })
}

#[inline]
fn trim_graphql_escape(value: &str) -> &str {
    value
        .trim()
        .trim_matches('\\')
        .trim_matches('"')
        .trim_matches('\'')
}

#[inline]
fn is_numeric(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_digit())
}

#[inline]
fn is_uuid_like(value: &str) -> bool {
    static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            .unwrap()
    });
    UUID_RE.is_match(value)
}

#[inline]
fn is_version_segment(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    v.starts_with('v') && v.len() > 1 && v[1..].chars().all(|c| c.is_ascii_digit())
}

fn is_resource_segment(segment: &str) -> bool {
    let segment = sanitize_token(segment).trim().to_ascii_lowercase();
    if segment.len() < 2 {
        return false;
    }
    if !segment
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return false;
    }
    if segment == "api" || segment == "v1" || segment == "v2" || segment == "v3" {
        return false;
    }
    if RESOURCE_SEGMENTS.contains(&segment.as_str()) {
        return true;
    }
    if segment.ends_with('s') {
        return RESOURCE_SEGMENTS.contains(&segment.trim_end_matches('s'));
    }
    false
}

fn contextual_resource(segments: &[&str], index: usize) -> Option<String> {
    if index == 0 || segments.is_empty() {
        return None;
    }

    let prev = segments[index - 1];
    if is_resource_segment(prev) {
        return Some(normalize_key(prev));
    }

    if index >= 2 {
        if is_version_segment(prev) && is_resource_segment(segments[index - 2]) {
            return Some(normalize_key(segments[index - 2]));
        }
        if segments[index - 2].eq_ignore_ascii_case("api") && is_resource_segment(prev) {
            return Some(normalize_key(prev));
        }
    }

    None
}

fn is_id_key(raw_key: &str) -> bool {
    let key = normalize_key(raw_key);
    if key == "id" || key == "ids" || key == "node_id" {
        return true;
    }

    let base = if key.ends_with("_ids") {
        key.trim_end_matches("_ids")
    } else if key.ends_with("_id") {
        key.trim_end_matches("_id")
    } else {
        return false;
    };

    ID_KEY_PREFIXES.iter().any(|p| base.ends_with(p))
}

fn is_actor_key(key: &str) -> bool {
    ACTOR_KEYS.iter().any(|k| k == &normalize_key(key))
}

fn is_target_key(key: &str) -> bool {
    TARGET_KEYS.iter().any(|k| k == &normalize_key(key))
}

fn is_batch_key(key: &str) -> bool {
    let key = normalize_key(key);
    key == "ids" || key.ends_with("_ids")
}

fn decode_base64_token(input: &str) -> Option<String> {
    static BASE64_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/=_-]+$").unwrap());
    let compact: String = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect::<String>();
    if compact.len() < 8 || !BASE64_RE.is_match(&compact) {
        return None;
    }

    let mut padded = compact.replace('-', "+").replace('_', "/");
    let rem = padded.len() % 4;
    if rem != 0 {
        padded.push_str(&"=".repeat(4 - rem));
    }

    fn b64_value(ch: u8) -> Option<u8> {
        match ch {
            b'A'..=b'Z' => Some(ch - b'A'),
            b'a'..=b'z' => Some(ch - b'a' + 26),
            b'0'..=b'9' => Some(ch - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }

    let bytes = padded.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }

    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let a = b64_value(chunk[0])?;
        let b = b64_value(chunk[1])?;
        let c = b64_value(chunk[2])?;
        let d = b64_value(chunk[3])?;

        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            out.push((c << 6) | d);
        }
    }

    String::from_utf8(out).ok()
}

fn extract_numeric_id(decoded: &str) -> Option<String> {
    let cleaned = decoded.trim();
    if cleaned.chars().all(|c| c.is_ascii_digit()) {
        return Some(cleaned.to_string());
    }

    for fragment in cleaned
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|f| !f.is_empty())
    {
        if fragment.chars().all(|c| c.is_ascii_digit()) {
            return Some(fragment.to_string());
        }
    }

    None
}

fn split_multi_value(raw: &str) -> Vec<String> {
    let inner = raw
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    inner
        .split(',')
        .map(|part| {
            part.trim()
                .trim_matches('\"')
                .trim_matches('\'')
                .to_string()
        })
        .filter(|p| !p.is_empty())
        .collect()
}

fn add_id_candidate(
    key: &str,
    raw_value: &str,
    position: usize,
    ids: &mut Vec<IdCandidate>,
    encoded: &mut Vec<EncodedCandidate>,
) {
    for value in split_multi_value(raw_value) {
        let value = sanitize_token(value.as_str()).to_string();
        if value.is_empty() {
            continue;
        }

        if is_numeric(&value) {
            ids.push(IdCandidate {
                key: normalize_key(key),
                value,
                kind: "numeric",
                position,
            });
            continue;
        }

        if is_uuid_like(&value) {
            ids.push(IdCandidate {
                key: normalize_key(key),
                value,
                kind: "uuid",
                position,
            });
            continue;
        }

        if value.len() > 7 {
            if let Some(decoded) = decode_base64_token(&value) {
                if let Some(extracted) = extract_numeric_id(&decoded) {
                    encoded.push(EncodedCandidate {
                        key: normalize_key(key),
                        raw: value,
                        decoded: extracted,
                        position,
                    });
                }
            }
        }
    }
}

fn collect_path_references(decoded: &str) -> (Vec<IdCandidate>, Vec<EncodedCandidate>) {
    static PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)(?:https?://[^\s"']+|/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]+)"#).unwrap()
    });

    let mut ids = Vec::new();
    let mut encoded = Vec::new();

    for m in PATH_RE.find_iter(decoded) {
        let mut path = m.as_str();
        if let Some((_, tail)) = path.split_once("://") {
            let Some(slash) = tail.find('/') else {
                continue;
            };
            path = &tail[slash..];
        }

        if !path.contains('/') {
            continue;
        }
        let path_only = if let Some((p, _)) = path.split_once('?') {
            p
        } else {
            path
        };

        let segments: Vec<&str> = path_only.split('/').filter(|seg| !seg.is_empty()).collect();
        if segments.len() < 2 {
            continue;
        }

        for (idx, raw_segment) in segments.iter().enumerate() {
            let segment = sanitize_token(raw_segment);
            let Some(resource) = contextual_resource(&segments, idx) else {
                continue;
            };

            if is_numeric(segment) {
                ids.push(IdCandidate {
                    key: resource,
                    value: segment.to_string(),
                    kind: "numeric",
                    position: m.start(),
                });
                continue;
            }

            if is_uuid_like(segment) {
                ids.push(IdCandidate {
                    key: resource,
                    value: segment.to_string(),
                    kind: "uuid",
                    position: m.start(),
                });
                continue;
            }

            if let Some(decoded) = decode_base64_token(segment) {
                if let Some(extracted) = extract_numeric_id(&decoded) {
                    encoded.push(EncodedCandidate {
                        key: resource,
                        raw: segment.to_string(),
                        decoded: extracted,
                        position: m.start(),
                    });
                }
            }
        }
    }

    (ids, encoded)
}

fn collect_param_references(decoded: &str) -> (Vec<IdCandidate>, Vec<EncodedCandidate>) {
    static PARAM_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)(?:^|[&?\s])([a-z0-9_][a-z0-9._-]{0,48})=([^\s&]+)"#).unwrap()
    });
    static JSON_STRING_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)"([a-z0-9_][a-z0-9._-]{0,48})"\s*:\s*"([^"]+)""#).unwrap()
    });
    static JSON_NUM_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)"([a-z0-9_][a-z0-9._-]{0,48})"\s*:\s*([0-9]{1,40})"#).unwrap()
    });
    static JSON_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)"([a-z0-9_][a-z0-9._-]{0,48})"\s*:\s*\[([^\]]+)\]"#).unwrap()
    });

    let mut ids = Vec::new();
    let mut encoded = Vec::new();

    for capture in PARAM_RE.captures_iter(decoded) {
        let Some(raw_key) = capture.get(1) else {
            continue;
        };
        let Some(raw_value) = capture.get(2) else {
            continue;
        };
        let key = raw_key.as_str();
        if !is_id_key(key) {
            continue;
        }

        add_id_candidate(
            key,
            raw_value.as_str(),
            capture.get(2).unwrap().start(),
            &mut ids,
            &mut encoded,
        );
    }

    for capture in JSON_STRING_RE.captures_iter(decoded) {
        let Some(raw_key) = capture.get(1) else {
            continue;
        };
        let Some(raw_value) = capture.get(2) else {
            continue;
        };
        let key = raw_key.as_str();
        if !is_id_key(key) {
            continue;
        }

        add_id_candidate(
            key,
            raw_value.as_str(),
            raw_value.start(),
            &mut ids,
            &mut encoded,
        );
    }

    for capture in JSON_NUM_RE.captures_iter(decoded) {
        let Some(raw_key) = capture.get(1) else {
            continue;
        };
        let Some(raw_value) = capture.get(2) else {
            continue;
        };
        let key = raw_key.as_str();
        if !is_id_key(key) {
            continue;
        }

        add_id_candidate(
            key,
            raw_value.as_str(),
            raw_value.start(),
            &mut ids,
            &mut encoded,
        );
    }

    for capture in JSON_ARRAY_RE.captures_iter(decoded) {
        let Some(raw_key) = capture.get(1) else {
            continue;
        };
        let Some(raw_values) = capture.get(2) else {
            continue;
        };
        let key = raw_key.as_str();
        if !is_batch_key(key) {
            continue;
        }
        add_id_candidate(
            key,
            raw_values.as_str(),
            raw_values.start(),
            &mut ids,
            &mut encoded,
        );
    }

    (ids, encoded)
}

fn detect_sequential_path_ids(decoded: &str, path_ids: &[IdCandidate]) -> Option<L2EvalResult> {
    let mut grouped: HashMap<String, Vec<(u64, usize)>> = HashMap::new();
    for c in path_ids {
        if c.kind != "numeric" {
            continue;
        }
        if let Ok(id) = c.value.parse::<u64>() {
            grouped
                .entry(c.key.clone())
                .or_default()
                .push((id, c.position));
        }
    }

    let mut best: Option<(usize, String, usize)> = None;
    for (resource, mut entries) in grouped {
        entries.sort_by_key(|(id, _)| *id);
        entries.dedup_by_key(|(id, _)| *id);

        if entries.len() < 3 {
            continue;
        }

        let mut run_start = 0usize;
        let mut run_len = 1usize;
        let mut longest_len = 1usize;

        for i in 1..entries.len() {
            if entries[i].0 == entries[i - 1].0 + 1 {
                run_len += 1;
                if run_len > longest_len {
                    longest_len = run_len;
                }
            } else {
                run_len = 1;
                run_start = i;
            }
        }

        if longest_len >= 3 {
            let run_position = entries[run_start].1;
            let is_better = match &best {
                Some((score, _, _)) => longest_len > *score,
                None => true,
            };
            if is_better {
                best = Some((longest_len, resource, run_position));
            }
        }
    }

    let Some((seq_len, resource, position)) = best else {
        return None;
    };

    Some(L2Detection {
        detection_type: "idor_path_id_sequential".into(),
        confidence: CONF_SEQUENTIAL_IDS,
        detail: format!(
            "Sequential ID access on resource '{}' ({} IDs)",
            resource, seq_len
        ),
        position,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: preview(decoded, position),
            interpretation: "Consecutive object IDs in API-style paths indicate enumeration".into(),
            offset: position,
            property: "APIs must enforce object-level authorization checks for every ID".into(),
        }],
    })
}

fn detect_path_single_reference(decoded: &str, path_ids: &[IdCandidate]) -> Option<L2EvalResult> {
    if path_ids.iter().any(|c| c.kind == "numeric") {
        let first = path_ids.iter().find(|c| c.kind == "numeric").unwrap();
        return Some(L2Detection {
            detection_type: "idor_path_id_reference".into(),
            confidence: CONF_SINGLE_ID,
            detail: format!(
                "Object-style path uses ID '{}' for resource '{}'",
                first.value, first.key
            ),
            position: first.position,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: preview(decoded, first.position),
                interpretation: "Direct object ID appears in a context-aware API path".into(),
                offset: first.position,
                property: "Object references should be authorized per principal and resource"
                    .into(),
            }],
        });
    }

    if path_ids.iter().any(|c| c.kind == "uuid") {
        let first = path_ids.iter().find(|c| c.kind == "uuid").unwrap();
        return Some(L2Detection {
            detection_type: "idor_uuid_reference".into(),
            confidence: CONF_SINGLE_ID,
            detail: format!(
                "UUID-based object reference '{}' for resource '{}'",
                first.value, first.key
            ),
            position: first.position,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: preview(decoded, first.position),
                interpretation:
                    "UUID identifiers in object paths should still be authorization-checked".into(),
                offset: first.position,
                property: "Do not trust UUID opacity as sufficient object-level authorization"
                    .into(),
            }],
        });
    }

    None
}

fn detect_param_id_reference(decoded: &str, param_ids: &[IdCandidate]) -> Option<L2EvalResult> {
    if param_ids.is_empty() {
        return None;
    }

    let mut unique: HashSet<String> = HashSet::new();
    for c in param_ids {
        unique.insert(format!("{}:{}", c.key, c.value));
    }
    if unique.len() > 1 {
        let first = &param_ids[0];
        Some(L2Detection {
            detection_type: "idor_param_id_batch".into(),
            confidence: CONF_MULTIPLE_IDS,
            detail:
                "Multiple object identifiers in parameters indicates bulk/iterator-style access"
                    .into(),
            position: first.position,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: preview(decoded, first.position),
                interpretation:
                    "Requests with multiple object IDs can be abused for bulk enumeration".into(),
                offset: first.position,
                property:
                    "Bulk ID access must enforce per-id authorization and anti-enumeration controls"
                        .into(),
            }],
        })
    } else {
        let first = &param_ids[0];
        Some(L2Detection {
            detection_type: "idor_param_id_tamper".into(),
            confidence: CONF_SINGLE_ID,
            detail: format!(
                "Single parameter '{}' contains object identifier '{}'",
                first.key, first.value
            ),
            position: first.position,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: preview(decoded, first.position),
                interpretation:
                    "Changing parameterized object identifiers may expose other resources".into(),
                offset: first.position,
                property: "Validate caller authorization against explicit object identifiers"
                    .into(),
            }],
        })
    }
}

fn detect_graphql_node_ids(decoded: &str) -> Option<L2EvalResult> {
    if !(decoded.contains("/graphql") || decoded.to_lowercase().contains("graphql")) {
        return None;
    }

    let normalized = decoded.replace("\\\"", "\"").replace("\\'", "'");

    static GRAPHQL_NODE_ID_ARG_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?is)\bnode\s*\([^)]*?\bid\s*:\s*(?:"([A-Za-z0-9_+/\-=]{1,})"|'([A-Za-z0-9_+/\-=]{1,})'|([A-Za-z0-9_+/\-=]{1,}))"#).unwrap()
    });
    static GRAPHQL_NODE_ID_FIELD_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)"(?:node_id|nodeid|nodeId)"\s*:\s*\"([A-Za-z0-9_+/\-=]{1,})\""#).unwrap()
    });
    static GRAPHQL_NODE_ARRAY_FIELD_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?i)"(?:nodes|node_ids)"\s*:\s*\[([^\]]+)\]"#).unwrap());
    static GRAPHQL_NODE_ARRAY_ARG_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?is)\bnodes\s*:\s*\[([^\]]+)\]"#).unwrap());

    let mut ids = Vec::new();
    let mut min_pos = None::<usize>;

    for cap in GRAPHQL_NODE_ID_ARG_RE.captures_iter(&normalized) {
        let Some(v) = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)) else {
            continue;
        };
        let raw = trim_graphql_escape(v.as_str());
        if raw.is_empty() {
            continue;
        }
        if min_pos.is_none() {
            min_pos = Some(v.start());
        }
        ids.push(raw.to_string());
    }

    for cap in GRAPHQL_NODE_ID_FIELD_RE.captures_iter(&normalized) {
        let Some(v) = cap.get(1) else {
            continue;
        };
        let raw = sanitize_token(v.as_str());
        if raw.is_empty() {
            continue;
        }
        if min_pos.is_none() {
            min_pos = Some(v.start());
        }
        ids.push(raw.to_string());
    }

    for cap in GRAPHQL_NODE_ARRAY_FIELD_RE.captures_iter(&normalized) {
        let Some(v) = cap.get(1) else {
            continue;
        };
        if min_pos.is_none() {
            min_pos = Some(v.start());
        }
        let list = v.as_str().replace("\\\"", "\"");
        for part in split_multi_value(&list) {
            let raw = sanitize_token(&part).to_string();
            if !raw.is_empty() {
                ids.push(raw);
            }
        }
    }

    for cap in GRAPHQL_NODE_ARRAY_ARG_RE.captures_iter(&normalized) {
        let Some(v) = cap.get(1) else {
            continue;
        };
        if min_pos.is_none() {
            min_pos = Some(v.start());
        }
        let list = v.as_str().replace("\\\"", "\"");
        for part in split_multi_value(&list) {
            let raw = sanitize_token(&part).to_string();
            if !raw.is_empty() {
                ids.push(raw);
            }
        }
    }

    if ids.is_empty() {
        return None;
    }

    let ids = ids
        .into_iter()
        .filter(|id| !id.is_empty())
        .collect::<Vec<_>>();
    if ids.len() >= 2 {
        Some(L2Detection {
            detection_type: "idor_graphql_node_id_batch".into(),
            confidence: CONF_MULTIPLE_IDS,
            detail: format!("GraphQL node manipulation with {} IDs", ids.len()),
            position: min_pos.unwrap_or(0),
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: preview(decoded, min_pos.unwrap_or(0)),
                interpretation: "GraphQL node queries using multiple IDs can enumerate objects"
                    .into(),
                offset: min_pos.unwrap_or(0),
                property: "GraphQL node IDs should be authorization-scoped".into(),
            }],
        })
    } else {
        Some(L2Detection {
            detection_type: "idor_graphql_node_id".into(),
            confidence: CONF_SINGLE_ID,
            detail: "GraphQL node query references direct object identifier".into(),
            position: min_pos.unwrap_or(0),
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: preview(decoded, min_pos.unwrap_or(0)),
                interpretation: "Direct node ID manipulation can traverse object boundaries".into(),
                offset: min_pos.unwrap_or(0),
                property:
                    "Validate caller ownership for every GraphQL node before returning object"
                        .into(),
            }],
        })
    }
}

fn detect_predictable_resource_path(decoded: &str) -> Option<L2EvalResult> {
    static PREDICTABLE_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?i)(?:^|[\s\"'])/(?:uploads|media|files|documents|assets|avatars|upload)/(?:user|account|tenant|customer|member|team)[0-9]+(?:-[a-z0-9_]+)?/(?:[^\s\"']+)"#,
        )
        .unwrap()
    });

    let Some(m) = PREDICTABLE_PATH_RE.find(decoded) else {
        return None;
    };
    let matched = m.as_str();
    let value = matched
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>();

    Some(L2Detection {
        detection_type: "idor_predictable_path".into(),
        confidence: CONF_SINGLE_ID,
        detail: format!("Predictable resource path includes identifier-like segment '{}'", value),
        position: m.start(),
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: preview(decoded, m.start()),
            interpretation: "Predictable filesystem-like identifiers enable path-based horizontal access attempts".into(),
            offset: m.start(),
            property: "Use opaque, authorization-bound storage keys instead of incrementing path names".into(),
        }],
    })
}

fn detect_horizontal_privilege(
    path_ids: &[IdCandidate],
    param_ids: &[IdCandidate],
) -> Option<L2EvalResult> {
    let mut actor_ids: HashSet<String> = HashSet::new();
    let mut target_ids: HashSet<String> = HashSet::new();

    for c in param_ids {
        if is_actor_key(&c.key) {
            actor_ids.insert(c.value.clone());
        } else if is_target_key(&c.key) || c.key == "target" || c.key == "user" || c.key == "users"
        {
            target_ids.insert(c.value.clone());
        }
    }

    for c in path_ids {
        if (c.key == "user" || c.key == "users") && c.kind == "numeric" {
            target_ids.insert(c.value.clone());
        }
    }

    if actor_ids.is_empty() || target_ids.is_empty() {
        return None;
    }

    for actor in &actor_ids {
        for target in &target_ids {
            if actor != target {
                return Some(L2Detection {
                    detection_type: "idor_horizontal_privilege".into(),
                    confidence: CONF_SEQUENTIAL_IDS,
                    detail: format!("Actor identifier '{}' differs from target identifier '{}'", actor, target),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: "actor/target identifier mismatch".into(),
                        interpretation: "Different actor and target object IDs indicate possible horizontal privilege escalation".into(),
                        offset: 0,
                        property: "Enforce authorization so callers can only access objects owned by them".into(),
                    }],
                });
            }
        }
    }

    None
}

fn detect_wildcard_bulk_id_abuse(decoded: &str) -> Option<L2EvalResult> {
    static WILDCARD_ID_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)/(?:api/)?v\d+/[a-z]+/(?:\*|all|_all|__all__|bulk|everyone|any|me|self|current|default)(?:/|$|\?)").unwrap()
    });

    let Some(m) = WILDCARD_ID_RE.find(decoded) else {
        return None;
    };

    Some(L2Detection {
        detection_type: "idor_wildcard_id".into(),
        confidence: 0.82,
        detail: "Wildcard/bulk resource identifier suggests horizontal privilege escalation probe"
            .into(),
        position: m.start(),
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: preview(decoded, m.start()),
            interpretation: "Special resource selectors like '*' or 'all' can bypass per-object checks when authorization is weak".into(),
            offset: m.start(),
            property: "Bulk selectors must enforce the same object-level authorization as single-resource access".into(),
        }],
    })
}

fn uuid_v1_components(value: &str) -> Option<(u64, String, String)> {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() != 5 {
        return None;
    }
    if parts[2].len() != 4 || !parts[2].starts_with('1') {
        return None;
    }

    let time_low = u64::from_str_radix(parts[0], 16).ok()?;
    let time_mid = u64::from_str_radix(parts[1], 16).ok()?;
    let time_hi_and_version = u64::from_str_radix(parts[2], 16).ok()?;
    let timestamp = ((time_hi_and_version & 0x0FFF) << 48) | (time_mid << 32) | time_low;

    Some((
        timestamp,
        parts[3].to_ascii_lowercase(),
        parts[4].to_ascii_lowercase(),
    ))
}

fn detect_uuidv1_prediction(decoded: &str) -> Option<L2EvalResult> {
    static UUIDV1_PAIR_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)([0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})[\s,&]{1,5}([0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})").unwrap()
    });

    for caps in UUIDV1_PAIR_RE.captures_iter(decoded) {
        let Some(left) = caps.get(1) else {
            continue;
        };
        let Some(right) = caps.get(2) else {
            continue;
        };

        let left_uuid = left.as_str().to_ascii_lowercase();
        let right_uuid = right.as_str().to_ascii_lowercase();
        let Some((left_ts, left_clock, left_node)) = uuid_v1_components(&left_uuid) else {
            continue;
        };
        let Some((right_ts, right_clock, right_node)) = uuid_v1_components(&right_uuid) else {
            continue;
        };

        if left_clock == right_clock && left_node == right_node && left_ts != right_ts {
            return Some(L2Detection {
                detection_type: "idor_uuidv1_prediction".into(),
                confidence: 0.79,
                detail: "Multiple UUIDv1 identifiers differ primarily by timestamp bits, suggesting prediction".into(),
                position: left.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: format!("{},{}", left_uuid, right_uuid),
                    interpretation: "Near-related UUIDv1 values with identical node/clock components indicate timestamp-driven ID prediction attempts".into(),
                    offset: left.start(),
                    property: "Object identifiers should be non-predictable and authorization-checked independently of ID entropy".into(),
                }],
            });
        }
    }

    None
}

fn detect_encoded_reference(
    path_encoded: &[EncodedCandidate],
    param_encoded: &[EncodedCandidate],
) -> Option<L2EvalResult> {
    let mut all = Vec::new();
    all.extend(path_encoded.iter().cloned());
    all.extend(param_encoded.iter().cloned());

    if all.is_empty() {
        return None;
    }

    all.sort_by_key(|c| c.position);
    if let Some(c) = all.first() {
        Some(L2Detection {
            detection_type: "idor_encoded_reference".into(),
            confidence: CONF_ENCODED_ID,
            detail: format!(
                "Encoded object identifier '{}' in '{}' resolves to numeric id {}",
                c.raw, c.key, c.decoded
            ),
            position: c.position,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::TypeCoerce,
                matched_input: format!("{} -> {}", c.raw, c.decoded),
                interpretation:
                    "Base64-style identifier can often be swapped to access adjacent resources"
                        .into(),
                offset: c.position,
                property: "Treat indirect encodings as security-sensitive object references".into(),
            }],
        })
    } else {
        None
    }
}

fn detect_mongodb_objectid(decoded: &str) -> Option<L2EvalResult> {
    static MONGO_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)[?&/](?:[a-z_-]+[=:/])?([0-9a-f]{24})(?:[?&/"'\s]|$)"#).unwrap()
    });
    
    if let Some(m) = MONGO_RE.captures(decoded) {
        if let Some(id_match) = m.get(1) {
            return Some(L2Detection {
                detection_type: "idor_mongodb_objectid".into(),
                confidence: 0.79,
                detail: "MongoDB ObjectId (24 hex chars) found in path/parameter".into(),
                position: id_match.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: preview(decoded, id_match.start()),
                    interpretation: "MongoDB ObjectId (24 hex chars) encodes creation timestamp in the first 4 bytes. Sequential ObjectIds from the same server/process are predictable, enabling IDOR by guessing adjacent IDs.".into(),
                    offset: id_match.start(),
                    property: "MongoDB ObjectIds should be treated as predictable and require authorization checks.".into(),
                }],
            });
        }
    }
    None
}

fn detect_snowflake_id(decoded: &str) -> Option<L2EvalResult> {
    static SNOWFLAKE_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)[?&/](?:[a-z_-]+[=:/])?([0-9]{17,19})(?:[?&/"'\s]|$)"#).unwrap()
    });
    
    if let Some(m) = SNOWFLAKE_RE.captures(decoded) {
        if let Some(id_match) = m.get(1) {
            return Some(L2Detection {
                detection_type: "idor_snowflake_id".into(),
                confidence: 0.77,
                detail: "Snowflake ID (17-19 digit number) found in path/parameter".into(),
                position: id_match.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: preview(decoded, id_match.start()),
                    interpretation: "Snowflake IDs (17-19 digit numbers used by Twitter, Discord, Instagram) encode a millisecond timestamp in the upper bits. Adjacent IDs are predictable, enabling temporal IDOR attacks by guessing IDs created within the same time window.".into(),
                    offset: id_match.start(),
                    property: "Snowflake IDs should be treated as predictable and require authorization checks.".into(),
                }],
            });
        }
    }
    None
}

fn detect_ulid(decoded: &str) -> Option<L2EvalResult> {
    static ULID_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)[?&/](?:[a-z_-]+[=:/])?([0-9A-HJKMNP-TV-Z]{26})(?:[?&/"'\s]|$)"#).unwrap()
    });
    
    if let Some(m) = ULID_RE.captures(decoded) {
        if let Some(id_match) = m.get(1) {
            return Some(L2Detection {
                detection_type: "idor_ulid".into(),
                confidence: 0.77,
                detail: "ULID (26-char Crockford base32 string) found in path/parameter".into(),
                position: id_match.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: preview(decoded, id_match.start()),
                    interpretation: "ULID (Universally Unique Lexicographically Sortable Identifier) encodes a millisecond timestamp prefix. ULIDs generated in close time proximity are nearly sequential, making IDOR attacks feasible by incrementing the timestamp portion.".into(),
                    offset: id_match.start(),
                    property: "ULIDs should be treated as predictable and require authorization checks.".into(),
                }],
            });
        }
    }
    None
}

fn detect_cookie_id(decoded: &str) -> Option<L2EvalResult> {
    static COOKIE_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?im)^cookie\s*:[^\r\n]*(?:user_id|account_id|customer_id|uid|user-id|userid)\s*=\s*([0-9]{1,15}|[0-9a-f-]{36})").unwrap()
    });
    
    if let Some(m) = COOKIE_RE.captures(decoded) {
        if let Some(id_match) = m.get(1) {
            return Some(L2Detection {
                detection_type: "idor_cookie_id".into(),
                confidence: 0.78,
                detail: "Cookie header contains an ID-like field (numeric or UUID)".into(),
                position: id_match.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: preview(decoded, id_match.start()),
                    interpretation: "Numeric or UUID-format object references in Cookie headers indicate server-side access control decisions based on user-controlled cookies. Cookie values can be trivially modified, enabling IDOR by changing the identifier to another user account.".into(),
                    offset: id_match.start(),
                    property: "Server-side state should not rely on user-controlled identifiers in cookies for access control.".into(),
                }],
            });
        }
    }
    None
}

pub fn evaluate_idor(input: &str) -> Option<L2EvalResult> {
    let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

    let (path_ids, path_encoded) = collect_path_references(&decoded);
    let (param_ids, param_encoded) = collect_param_references(&decoded);

    let mut detections: Vec<L2Detection> = Vec::new();

    if let Some(d) = detect_sequential_path_ids(&decoded, &path_ids) {
        detections.push(d);
    }
    if let Some(d) = detect_path_single_reference(&decoded, &path_ids) {
        detections.push(d);
    }
    if let Some(d) = detect_param_id_reference(&decoded, &param_ids) {
        detections.push(d);
    }
    if let Some(d) = detect_graphql_node_ids(&decoded) {
        detections.push(d);
    }
    if let Some(d) = detect_predictable_resource_path(&decoded) {
        detections.push(d);
    }
    if let Some(d) = detect_horizontal_privilege(&path_ids, &param_ids) {
        detections.push(d);
    }
    if let Some(d) = detect_wildcard_bulk_id_abuse(&decoded) {
        detections.push(d);
    }
    if let Some(d) = detect_uuidv1_prediction(&decoded) {
        detections.push(d);
    }
    if let Some(d) = detect_encoded_reference(&path_encoded, &param_encoded) {
        detections.push(d);
    }

    if detections.is_empty() {
        return None;
    }

    detections.sort_by(|a, b| {
        b.confidence
            .total_cmp(&a.confidence)
            .then(a.position.cmp(&b.position))
    });

    detections.into_iter().next()
}

pub struct IdorEvaluator;

impl L2Evaluator for IdorEvaluator {
    fn id(&self) -> &'static str {
        "idor"
    }

    fn prefix(&self) -> &'static str {
        "L2 IDOR"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        let (path_ids, path_encoded) = collect_path_references(&decoded);
        let (param_ids, param_encoded) = collect_param_references(&decoded);

        if let Some(d) = detect_sequential_path_ids(&decoded, &path_ids) { detections.push(d); }
        if let Some(d) = detect_path_single_reference(&decoded, &path_ids) { detections.push(d); }
        if let Some(d) = detect_param_id_reference(&decoded, &param_ids) { detections.push(d); }
        if let Some(d) = detect_graphql_node_ids(&decoded) { detections.push(d); }
        if let Some(d) = detect_predictable_resource_path(&decoded) { detections.push(d); }
        if let Some(d) = detect_horizontal_privilege(&path_ids, &param_ids) { detections.push(d); }
        if let Some(d) = detect_wildcard_bulk_id_abuse(&decoded) { detections.push(d); }
        if let Some(d) = detect_uuidv1_prediction(&decoded) { detections.push(d); }
        if let Some(d) = detect_encoded_reference(&path_encoded, &param_encoded) { detections.push(d); }

        if let Some(d) = detect_mongodb_objectid(&decoded) { detections.push(d); }
        if let Some(d) = detect_snowflake_id(&decoded) { detections.push(d); }
        if let Some(d) = detect_ulid(&decoded) { detections.push(d); }
        if let Some(d) = detect_cookie_id(&decoded) { detections.push(d); }

        detections
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "idor_param_id_batch" | "idor_graphql_node_id_batch" | "idor_encoded_reference" => {
                Some(InvariantClass::ApiMassEnum)
            }
            "idor_path_id_sequential"
            | "idor_path_id_reference"
            | "idor_uuid_reference"
            | "idor_param_id_tamper"
            | "idor_predictable_path"
            | "idor_horizontal_privilege"
            | "idor_graphql_node_id"
            | "idor_wildcard_id"
            | "idor_uuidv1_prediction"
            | "idor_mongodb_objectid"
            | "idor_snowflake_id"
            | "idor_ulid"
            | "idor_cookie_id" => Some(InvariantClass::BolaIdor),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sequential_path_ids_in_api_style_urls() {
        let input = "/api/users/1001 /api/users/1002 /api/users/1003";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_path_id_sequential");
        assert!((result.confidence - 0.80).abs() < f64::EPSILON);
    }

    #[test]
    fn detects_single_api_path_id_reference() {
        let input = "/api/users/123";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_path_id_reference");
    }

    #[test]
    fn detects_uuid_path_reference() {
        let input = "/api/orders/550e8400-e29b-41d4-a716-446655440000";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_uuid_reference");
    }

    #[test]
    fn detects_single_object_id_parameter_tampering() {
        let input = "/api/transfer?user_id=123&amount=100";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_param_id_tamper");
    }

    #[test]
    fn detects_multiple_object_id_parameters() {
        let input = "/api/transfer?user_id=123&target_user_id=456";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_param_id_batch");
        assert!((result.confidence - 0.65).abs() < f64::EPSILON);
    }

    #[test]
    fn detects_horizontal_privilege_with_actor_and_target_ids() {
        let input = "/api/users/100?acting_user_id=100&target_user_id=101";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_horizontal_privilege");
    }

    #[test]
    fn detects_predictable_upload_path_pattern() {
        let input = "/uploads/user1/file.pdf";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_predictable_path");
    }

    #[test]
    fn detects_graphql_single_node_id() {
        let input = r#"POST /graphql HTTP/1.1
{"query":"{ node(id:\"123\") { id title } }"}"#;
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_graphql_node_id");
    }

    #[test]
    fn detects_graphql_multiple_node_ids() {
        let input = r#"POST /graphql
{"query":"{ nodes:[\"101\", \"102\"] }"}"#;
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_graphql_node_id_batch");
    }

    #[test]
    fn detects_query_list_bulk_ids() {
        let input = "/api/products?ids=101,102,103,104";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_param_id_batch");
    }

    #[test]
    fn detects_repeated_id_parameters_as_bulk_access() {
        let input = "/api/items?ids=201&ids=202&ids=203";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_param_id_batch");
    }

    #[test]
    fn detects_json_array_of_ids() {
        let input = r#"POST /api/items {"ids":[301,302,303]}"#;
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_param_id_batch");
    }

    #[test]
    fn detects_encoded_user_id_in_api_path() {
        let input = "/api/users/dXNlcjox";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_encoded_reference");
        assert!((result.confidence - 0.70).abs() < f64::EPSILON);
    }

    #[test]
    fn detects_encoded_user_id_in_query_parameter() {
        let input = "/api/users?user_id=dXNlcjox";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_encoded_reference");
    }

    #[test]
    fn ignores_benign_non_resource_numeric_paths() {
        let input = "/api/status/200";
        assert!(evaluate_idor(input).is_none());
    }

    #[test]
    fn ignores_benign_non_id_api_queries() {
        let input = "/api/search?q=books&sort=desc";
        assert!(evaluate_idor(input).is_none());
    }

    #[test]
    fn maps_idor_detection_type_to_class() {
        let eval = IdorEvaluator;
        let input = "/api/users/1001";
        let det = eval.detect(input);
        assert_eq!(
            eval.map_class(det[0].detection_type.as_str()),
            Some(InvariantClass::BolaIdor)
        );
        let batch = eval.detect("/api/products?ids=10,11");
        assert_eq!(
            eval.map_class(batch[0].detection_type.as_str()),
            Some(InvariantClass::ApiMassEnum)
        );
    }

    #[test]
    fn detects_wildcard_bulk_id_abuse() {
        let input = "GET /api/v2/users/all?active=true HTTP/1.1";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_wildcard_id");
        assert!((result.confidence - 0.82).abs() < f64::EPSILON);
    }

    #[test]
    fn detects_uuidv1_prediction_attempt() {
        let input =
            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6, f81d4faf-7dec-11d0-a765-00a0c91e6bf6";
        let result = evaluate_idor(input).unwrap();
        assert_eq!(result.detection_type, "idor_uuidv1_prediction");
        assert!((result.confidence - 0.79).abs() < f64::EPSILON);
    }

    #[test]
    fn detects_mongodb_objectid() {
        let eval = IdorEvaluator;
        let det = eval.detect("/api/users/507f1f77bcf86cd799439011");
        assert!(det.iter().any(|d| d.detection_type == "idor_mongodb_objectid"));
    }

    #[test]
    fn detects_snowflake_id() {
        let eval = IdorEvaluator;
        let det = eval.detect("/api/tweets/1234567890123456789");
        assert!(det.iter().any(|d| d.detection_type == "idor_snowflake_id"));
    }

    #[test]
    fn detects_ulid() {
        let eval = IdorEvaluator;
        let det = eval.detect("/api/events/01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert!(det.iter().any(|d| d.detection_type == "idor_ulid"));
    }

    #[test]
    fn detects_cookie_id() {
        let eval = IdorEvaluator;
        let det = eval.detect("Cookie: session=abc; user_id=12345\r\n");
        assert!(det.iter().any(|d| d.detection_type == "idor_cookie_id"));
    }
}
