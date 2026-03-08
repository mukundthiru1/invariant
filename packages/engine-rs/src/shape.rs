//! Input Shape Validator — Negative-Space Detection
//!
//! Traditional detection: "Does this look like an attack?"
//! Shape validation: "Does this look like what it SHOULD be?"
//!
//! This inverts the detection problem. Instead of enumerating attacks,
//! we define what LEGITIMATE input looks like. Any deviation is suspicious.
//! Catches zero-day attacks: the input violates the SHAPE of legitimate
//! data, even if we've never seen this exploit before.
//!
//! This is NOT a detection mechanism — it's a CONTEXTUAL SIGNAL
//! that amplifies or attenuates detection confidence.

use serde_json::Value;

const MAX_JSON_PAYLOAD_BYTES: usize = 65_536;
const FILENAME_DECODING_LAYERS: usize = 3;
const VIOLATION_PREVIEW_CHARS: usize = 32;

fn violation_preview(input: &str) -> String {
    input.chars().take(VIOLATION_PREVIEW_CHARS).collect()
}

fn has_encoded_path_traversal(input: &str) -> bool {
    for current in percent_decode_layers(input, FILENAME_DECODING_LAYERS) {
        if current.contains('/') || current.contains('\\') || current.contains("..") {
            return true;
        }
    }
    false
}

fn percent_decode_layers(input: &str, depth: usize) -> Vec<String> {
    let mut layers = Vec::with_capacity(depth + 1);
    let mut current = input.to_string();
    layers.push(current.clone());
    for _ in 0..depth {
        let next = percent_decode_once(&current);
        if next == current {
            break;
        }
        current = next.clone();
        layers.push(next);
    }
    layers
}

// ── Field Types ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldType {
    Username,
    Email,
    Url,
    Integer,
    Float,
    Uuid,
    Phone,
    Date,
    Search,
    Filename,
    JsonValue,
    Freetext,
    Slug,
    Hex,
    Base64,
    Ipv4,
}

// ── Violations ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ShapeViolation {
    pub constraint: String,
    pub expected: String,
    pub found: String,
    pub severity: f64,
}

#[derive(Debug, Clone)]
pub struct ShapeValidation {
    pub matches: bool,
    pub deviation: f64,
    pub violations: Vec<ShapeViolation>,
    pub confidence_boost: f64,
    pub detail: String,
}

// ── Validators ────────────────────────────────────────────────────

fn validate_username(input: &str) -> Vec<ShapeViolation> {
    let mut v = Vec::new();
    if input.len() > 128 {
        v.push(ShapeViolation { constraint: "length".into(), expected: "≤128".into(), found: format!("{}", input.len()), severity: 0.3 });
    }
    if input.is_empty() {
        v.push(ShapeViolation { constraint: "length".into(), expected: "≥1".into(), found: "0".into(), severity: 0.2 });
    }
    let illegal: String = input.chars().filter(|c| !c.is_ascii_alphanumeric() && !"_.@-".contains(*c)).collect();
    if !illegal.is_empty() {
        let ratio = illegal.len() as f64 / input.len() as f64;
        v.push(ShapeViolation {
            constraint: "charset".into(),
            expected: "alphanumeric + _.@-".into(),
            found: format!("illegal chars: {:?}", violation_preview(&illegal)),
            severity: (ratio * 2.0).min(1.0),
        });
    }
    if input.chars().any(|c| c.is_whitespace()) {
        v.push(ShapeViolation { constraint: "whitespace".into(), expected: "none".into(), found: "contains whitespace".into(), severity: 0.5 });
    }
    v
}

fn validate_email(input: &str) -> Vec<ShapeViolation> {
    let mut v = Vec::new();
    if !input.contains('@') {
        v.push(ShapeViolation { constraint: "format".into(), expected: "local@domain".into(), found: "no @ sign".into(), severity: 0.8 });
        return v;
    }
    let at_idx = input.rfind('@').unwrap();
    let local = &input[..at_idx];
    let domain = &input[at_idx + 1..];
    if local.is_empty() || local.len() > 64 {
        v.push(ShapeViolation { constraint: "local_part".into(), expected: "1-64 chars".into(), found: format!("{}", local.len()), severity: 0.4 });
    }
    if domain.is_empty() || !domain.contains('.') || domain.len() < 4 {
        v.push(ShapeViolation { constraint: "domain".into(), expected: "valid domain".into(), found: domain.to_string(), severity: 0.5 });
    }
    let illegal_domain: String = domain.chars().filter(|c| !c.is_ascii_alphanumeric() && !".-".contains(*c)).collect();
    if !illegal_domain.is_empty() {
        v.push(ShapeViolation { constraint: "domain_charset".into(), expected: "alphanumeric + .- only".into(), found: format!("illegal: {:?}", violation_preview(&illegal_domain)), severity: 0.7 });
    }
    v
}

fn validate_url(input: &str) -> Vec<ShapeViolation> {
    let mut v = Vec::new();
    let scheme_ok = input
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
        || input
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
        || input.starts_with('/');
    if !scheme_ok {
        v.push(ShapeViolation { constraint: "scheme".into(), expected: "http(s):// or /".into(), found: violation_preview(input), severity: 0.3 });
    }
    if input.bytes().any(|b| b < 0x20 || b == 0x7F) {
        v.push(ShapeViolation { constraint: "control_chars".into(), expected: "none".into(), found: "contains control chars".into(), severity: 0.8 });
    }
    let suspicious: String = input.chars().filter(|c| !c.is_ascii_alphanumeric() && !":/_~?&=#%+@!$'()*,;.-".contains(*c)).collect();
    if !suspicious.is_empty() {
        let ratio = suspicious.len() as f64 / input.len().max(1) as f64;
        v.push(ShapeViolation {
            constraint: "url_charset".into(),
            expected: "URL-safe characters".into(),
            found: format!("suspicious: {:?}", violation_preview(&suspicious)),
            severity: (ratio * 3.0).min(1.0),
        });
    }
    v
}

fn validate_integer(input: &str) -> Vec<ShapeViolation> {
    let trimmed = input.trim();
    let valid = if trimmed.starts_with('-') {
        trimmed[1..].chars().all(|c| c.is_ascii_digit())
    } else {
        trimmed.chars().all(|c| c.is_ascii_digit())
    };
    if !valid || trimmed.is_empty() || (trimmed.starts_with('-') && trimmed.len() == 1) {
        vec![ShapeViolation { constraint: "format".into(), expected: "integer".into(), found: violation_preview(trimmed), severity: 0.9 }]
    } else {
        vec![]
    }
}

fn validate_float(input: &str) -> Vec<ShapeViolation> {
    let trimmed = input.trim();
    if trimmed.parse::<f64>().is_err() {
        vec![ShapeViolation { constraint: "format".into(), expected: "float".into(), found: violation_preview(trimmed), severity: 0.9 }]
    } else {
        vec![]
    }
}

fn validate_uuid(input: &str) -> Vec<ShapeViolation> {
    let trimmed = input.trim();
    let parts: Vec<&str> = trimmed.split('-').collect();
    let valid = parts.len() == 5
        && parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()));
    if !valid {
        vec![ShapeViolation { constraint: "format".into(), expected: "UUID v4".into(), found: violation_preview(trimmed), severity: 0.9 }]
    } else {
        vec![]
    }
}

fn validate_phone(input: &str) -> Vec<ShapeViolation> {
    let mut v = Vec::new();
    let digits: String = input.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 7 || digits.len() > 15 {
        v.push(ShapeViolation { constraint: "digit_count".into(), expected: "7-15 digits".into(), found: format!("{}", digits.len()), severity: 0.5 });
    }
    let illegal: String = input.chars().filter(|c| !c.is_ascii_digit() && !"+() .-".contains(*c)).collect();
    if !illegal.is_empty() {
        v.push(ShapeViolation { constraint: "charset".into(), expected: "digits + +()-. space".into(), found: format!("illegal: {:?}", violation_preview(&illegal)), severity: 0.7 });
    }
    v
}

fn validate_date(input: &str) -> Vec<ShapeViolation> {
    let trimmed = input.trim();
    let trimmed_chars: Vec<char> = trimmed.chars().collect();
    let iso_date = if trimmed_chars.len() == 10 {
        matches!(trimmed_chars[4], '-')
            && matches!(trimmed_chars[7], '-')
            && trimmed_chars[0..4].iter().all(|c| c.is_ascii_digit())
            && trimmed_chars[5..7].iter().all(|c| c.is_ascii_digit())
            && trimmed_chars[8..10].iter().all(|c| c.is_ascii_digit())
    } else {
        false
    };
    let iso_datetime = trimmed_chars.len() >= 16 && trimmed.contains('T') && iso_date;
    let us_date = if trimmed_chars.len() == 10 {
        matches!(trimmed_chars[2], '/')
            && matches!(trimmed_chars[5], '/')
    } else {
        false
    };

    if iso_date || iso_datetime || us_date {
        vec![]
    } else {
        vec![ShapeViolation { constraint: "format".into(), expected: "date format".into(), found: violation_preview(trimmed), severity: 0.8 }]
    }
}

fn validate_search(input: &str) -> Vec<ShapeViolation> {
    let mut v = Vec::new();
    let alpha_count = input.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let ratio = if input.is_empty() { 0.0 } else { alpha_count as f64 / input.len() as f64 };
    if ratio < 0.4 && input.len() > 5 {
        v.push(ShapeViolation {
            constraint: "alpha_ratio".into(),
            expected: "≥40% alphabetic".into(),
            found: format!("{}%", (ratio * 100.0) as u32),
            severity: ((0.4 - ratio) * 3.0).min(1.0),
        });
    }
    if input.len() > 500 {
        v.push(ShapeViolation { constraint: "length".into(), expected: "≤500".into(), found: format!("{}", input.len()), severity: 0.4 });
    }
    let meta_count = input.chars().filter(|c| "<>'\"`;\t|&${}()[]\\".contains(*c)).count();
    let meta_ratio = if input.is_empty() { 0.0 } else { meta_count as f64 / input.len() as f64 };
    if meta_ratio > 0.10 && input.len() > 5 {
        v.push(ShapeViolation {
            constraint: "metachar_ratio".into(),
            expected: "≤10% metacharacters".into(),
            found: format!("{}%", (meta_ratio * 100.0) as u32),
            severity: (meta_ratio * 5.0).min(1.0),
        });
    }
    v
}

fn validate_filename(input: &str) -> Vec<ShapeViolation> {
    let mut v = Vec::new();
    if has_encoded_path_traversal(input) {
        v.push(ShapeViolation { constraint: "path_traversal".into(), expected: "no traversal sequences".into(), found: "encoded traversal attempt".into(), severity: 1.0 });
    }
    if input.contains('/') || input.contains('\\') {
        v.push(ShapeViolation { constraint: "path_separator".into(), expected: "none".into(), found: "contains / or \\".into(), severity: 0.9 });
    }
    if input.contains('\0') {
        v.push(ShapeViolation { constraint: "null_byte".into(), expected: "none".into(), found: "contains null byte".into(), severity: 1.0 });
    }
    if input.contains("..") {
        v.push(ShapeViolation { constraint: "dotdot".into(), expected: "no ..".into(), found: "contains ..".into(), severity: 0.9 });
    }
    if input.len() > 255 {
        v.push(ShapeViolation { constraint: "length".into(), expected: "≤255".into(), found: format!("{}", input.len()), severity: 0.3 });
    }
    v
}

fn json_depth(v: &Value) -> usize {
    match v {
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        Value::Array(arr) => 1 + arr.iter().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn json_key_stats(v: &Value, keys: &mut usize, suspicious: &mut usize) {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                *keys += 1;
                if k.starts_with('$')
                    || k == "__proto__"
                    || k == "constructor"
                    || k == "prototype"
                    || k == "$where"
                    || k == "$ne"
                    || k == "$gt"
                {
                    *suspicious += 1;
                }
                json_key_stats(child, keys, suspicious);
            }
        }
        Value::Array(arr) => {
            for child in arr {
                json_key_stats(child, keys, suspicious);
            }
        }
        _ => {}
    }
}

fn has_xml_like_markers(input: &str) -> bool {
    let lower = input.to_lowercase();
    lower.contains("<?xml") || lower.contains("<!doctype") || (lower.contains('<') && lower.contains("</"))
}

fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 2 < bytes.len()
            && bytes[i] == b'%'
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hi = (bytes[i + 1] as char).to_digit(16).unwrap_or(0);
            let lo = (bytes[i + 2] as char).to_digit(16).unwrap_or(0);
            let b = ((hi << 4) + lo) as u8;
            out.push(char::from(b));
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn nested_encoding_depth(input: &str, max_layers: usize) -> usize {
    let mut depth = 0usize;
    let mut current = input.to_string();
    while depth < max_layers {
        let bytes = current.as_bytes();
        let mut pct_sequences = 0usize;
        let mut i = 0usize;
        while i + 2 < bytes.len() {
            if bytes[i] == b'%' && bytes[i + 1].is_ascii_hexdigit() && bytes[i + 2].is_ascii_hexdigit() {
                pct_sequences += 1;
                i += 3;
            } else {
                i += 1;
            }
        }
        if pct_sequences < 2 {
            break;
        }
        current = percent_decode_once(&current);
        depth += 1;
    }
    depth
}

fn validate_json_value(input: &str) -> Vec<ShapeViolation> {
    let trimmed = input.trim();
    let mut violations = Vec::new();

    if trimmed.len() > MAX_JSON_PAYLOAD_BYTES {
        violations.push(ShapeViolation {
            constraint: "payload_size".into(),
            expected: format!("≤{} bytes", MAX_JSON_PAYLOAD_BYTES),
            found: trimmed.len().to_string(),
            severity: 0.9,
        });
        return violations;
    }

    if has_xml_like_markers(trimmed) {
        violations.push(ShapeViolation {
            constraint: "content_mismatch".into(),
            expected: "JSON payload".into(),
            found: "XML/HTML-like markers".into(),
            severity: 0.9,
        });
    }

    let parsed: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => {
            violations.push(ShapeViolation {
                constraint: "valid_json".into(),
                expected: "parseable JSON".into(),
                found: "invalid".into(),
                severity: 0.8,
            });
            return violations;
        }
    };

    let depth = json_depth(&parsed);
    if depth > 16 {
        violations.push(ShapeViolation {
            constraint: "json_depth".into(),
            expected: "depth <= 16".into(),
            found: depth.to_string(),
            severity: 0.8,
        });
    }

    let mut total_keys = 0usize;
    let mut suspicious_keys = 0usize;
    json_key_stats(&parsed, &mut total_keys, &mut suspicious_keys);
    if total_keys > 256 {
        violations.push(ShapeViolation {
            constraint: "key_count".into(),
            expected: "keys <= 256".into(),
            found: total_keys.to_string(),
            severity: 0.6,
        });
    }
    if suspicious_keys > 0 {
        violations.push(ShapeViolation {
            constraint: "suspicious_keys".into(),
            expected: "application-domain field names".into(),
            found: format!("{} suspicious keys", suspicious_keys),
            severity: (0.4 + (suspicious_keys as f64 * 0.06)).min(0.9),
        });
    }

    let enc_depth = nested_encoding_depth(trimmed, 6);
    if enc_depth > 3 {
        violations.push(ShapeViolation {
            constraint: "encoding_layers".into(),
            expected: "nested encoding <= 3".into(),
            found: enc_depth.to_string(),
            severity: 0.7,
        });
    }

    violations
}

fn validate_freetext(input: &str) -> Vec<ShapeViolation> {
    let mut v = Vec::new();
    if input.bytes().any(|b| matches!(b, 0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F)) {
        v.push(ShapeViolation { constraint: "control_chars".into(), expected: "no control chars".into(), found: "contains control chars".into(), severity: 0.6 });
    }
    let meta_count = input.chars().filter(|c| "<>'\"`;\t|&${}()[]\\".contains(*c)).count();
    let meta_ratio = if input.is_empty() { 0.0 } else { meta_count as f64 / input.len() as f64 };
    if meta_ratio > 0.25 && input.len() > 10 {
        v.push(ShapeViolation {
            constraint: "metachar_density".into(),
            expected: "≤25% metacharacters".into(),
            found: format!("{}%", (meta_ratio * 100.0) as u32),
            severity: ((meta_ratio - 0.25) * 4.0).min(1.0),
        });
    }
    v
}

fn validate_slug(input: &str) -> Vec<ShapeViolation> {
    let mut v = Vec::new();
    let valid = !input.is_empty()
        && input.split('-').all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric()));
    if !valid {
        v.push(ShapeViolation { constraint: "format".into(), expected: "url-slug".into(), found: violation_preview(input), severity: 0.7 });
    }
    if input.len() > 200 {
        v.push(ShapeViolation { constraint: "length".into(), expected: "≤200".into(), found: format!("{}", input.len()), severity: 0.3 });
    }
    v
}

fn validate_hex(input: &str) -> Vec<ShapeViolation> {
    let trimmed = input.trim();
    let s = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        vec![ShapeViolation { constraint: "format".into(), expected: "hex string".into(), found: violation_preview(trimmed), severity: 0.8 }]
    } else {
        vec![]
    }
}

fn validate_base64(input: &str) -> Vec<ShapeViolation> {
    let trimmed = input.trim();
    let valid = trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && trimmed.chars().filter(|&c| c == '=').count() <= 2;
    if !valid || trimmed.is_empty() {
        vec![ShapeViolation { constraint: "format".into(), expected: "base64".into(), found: violation_preview(trimmed), severity: 0.8 }]
    } else {
        vec![]
    }
}

fn validate_ipv4(input: &str) -> Vec<ShapeViolation> {
    let trimmed = input.trim();
    let parts: Vec<&str> = trimmed.split('.').collect();
    let valid = parts.len() == 4 && parts.iter().all(|p| {
        !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()) && p.parse::<u16>().map_or(false, |n| n <= 255)
    });
    if !valid {
        vec![ShapeViolation { constraint: "format".into(), expected: "IPv4 address".into(), found: violation_preview(trimmed), severity: 0.9 }]
    } else {
        vec![]
    }
}

fn extract_content_type_token(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_lowercase()
}

fn xml_structure_violations(input: &str) -> Vec<ShapeViolation> {
    let mut v = Vec::new();
    let lower = input.to_lowercase();
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        v.push(ShapeViolation {
            constraint: "xml_dtd_entity".into(),
            expected: "no DTD/entity declarations".into(),
            found: "contains <!DOCTYPE/<!ENTITY>".into(),
            severity: 0.9,
        });
    }

    let open_tags = input.matches('<').count();
    let close_tags = input.matches('>').count();
    if open_tags != close_tags {
        v.push(ShapeViolation {
            constraint: "xml_delimiters".into(),
            expected: "balanced < and >".into(),
            found: format!("{} opens, {} closes", open_tags, close_tags),
            severity: 0.7,
        });
    }

    let closing = lower.matches("</").count();
    let non_closing = lower
        .matches('<')
        .count()
        .saturating_sub(closing)
        .saturating_sub(lower.matches("<?").count())
        .saturating_sub(lower.matches("<!").count())
        .saturating_sub(lower.matches("/>").count());
    if non_closing > 0 && closing == 0 {
        v.push(ShapeViolation {
            constraint: "xml_closing_tags".into(),
            expected: "closing tags present".into(),
            found: "missing closing tags".into(),
            severity: 0.8,
        });
    }

    v
}

fn multipart_boundary_violations(input: &str, content_type: &str) -> Vec<ShapeViolation> {
    let mut v = Vec::new();
    let boundary = content_type
        .split(';')
        .find_map(|part| {
            let p = part.trim();
            p.strip_prefix("boundary=").map(|b| b.trim_matches('"').to_string())
        });

    let Some(boundary) = boundary else {
        v.push(ShapeViolation {
            constraint: "multipart_boundary".into(),
            expected: "boundary parameter present".into(),
            found: "missing boundary".into(),
            severity: 0.9,
        });
        return v;
    };

    if boundary.len() < 6 || boundary.chars().any(|c| c.is_whitespace()) {
        v.push(ShapeViolation {
            constraint: "boundary_format".into(),
            expected: "6+ chars, no whitespace".into(),
            found: boundary.clone(),
            severity: 0.7,
        });
    }

    let marker = format!("--{}", boundary);
    let start_count = input.matches(&marker).count();
    if start_count == 0 {
        v.push(ShapeViolation {
            constraint: "boundary_presence".into(),
            expected: "multipart boundaries in body".into(),
            found: "no boundary markers".into(),
            severity: 0.9,
        });
    }

    let closing_marker = format!("{}--", marker);
    if !input.contains(&closing_marker) {
        v.push(ShapeViolation {
            constraint: "boundary_closure".into(),
            expected: "closing boundary marker".into(),
            found: "missing closing boundary".into(),
            severity: 0.8,
        });
    }
    v
}

// ── Public API ────────────────────────────────────────────────────

/// Validate input against an expected field shape.
pub fn validate_shape(input: &str, expected_type: FieldType) -> ShapeValidation {
    let violations = match expected_type {
        FieldType::Username => validate_username(input),
        FieldType::Email => validate_email(input),
        FieldType::Url => validate_url(input),
        FieldType::Integer => validate_integer(input),
        FieldType::Float => validate_float(input),
        FieldType::Uuid => validate_uuid(input),
        FieldType::Phone => validate_phone(input),
        FieldType::Date => validate_date(input),
        FieldType::Search => validate_search(input),
        FieldType::Filename => validate_filename(input),
        FieldType::JsonValue => validate_json_value(input),
        FieldType::Freetext => validate_freetext(input),
        FieldType::Slug => validate_slug(input),
        FieldType::Hex => validate_hex(input),
        FieldType::Base64 => validate_base64(input),
        FieldType::Ipv4 => validate_ipv4(input),
    };

    if violations.is_empty() {
        return ShapeValidation {
            matches: true,
            deviation: 0.0,
            violations: vec![],
            confidence_boost: 0.0,
            detail: format!("Input matches expected {:?} shape", expected_type),
        };
    }

    let total_severity: f64 = violations.iter().map(|v| v.severity).sum();
    let deviation = (total_severity / violations.len() as f64).min(1.0);

    let confidence_boost = if deviation >= 0.7 {
        0.10
    } else if deviation >= 0.4 {
        0.05
    } else {
        0.02
    };

    let summary: Vec<String> = violations.iter()
        .map(|v| format!("{}: expected {}, got {}", v.constraint, v.expected, v.found))
        .collect();

    ShapeValidation {
        matches: false,
        deviation,
        violations,
        confidence_boost,
        detail: format!("Input violates {:?} shape: {}", expected_type, summary.join("; ")),
    }
}

/// Auto-detect the most likely field type from a parameter name.
pub fn infer_field_type(param_name: &str) -> Option<FieldType> {
    let lower = param_name.to_lowercase();

    if lower == "id" || lower.ends_with("_id") {
        return Some(FieldType::Uuid);
    }
    if lower.contains("email") || lower.contains("mail") { return Some(FieldType::Email); }
    if lower.contains("username") || lower.contains("user_name") || lower.contains("login") || lower.contains("handle") { return Some(FieldType::Username); }
    if lower.contains("phone") || lower.contains("tel") || lower.contains("mobile") { return Some(FieldType::Phone); }
    if lower == "url" || lower.contains("website") || lower.contains("homepage") || lower.contains("link") || lower.contains("redirect") || lower.contains("callback") || lower.contains("return_url") || lower.contains("next") || lower.contains("goto") { return Some(FieldType::Url); }
    if lower == "q" || lower.contains("query") || lower.contains("search") || lower.contains("keyword") || lower.contains("term") { return Some(FieldType::Search); }
    if lower.contains("date") || lower.contains("time") || lower.contains("created") || lower.contains("updated") || lower.contains("expires") || lower.contains("birthday") { return Some(FieldType::Date); }
    if lower.contains("file") || lower.contains("filename") || lower.contains("attachment") { return Some(FieldType::Filename); }
    if lower == "page" || lower == "limit" || lower == "offset" || lower == "count" || lower == "size" || lower == "port" || lower == "age" || lower == "amount" || lower.starts_with("num") { return Some(FieldType::Integer); }
    if lower == "price" || lower == "rate" || lower == "score" || lower == "weight" || lower == "lat" || lower == "lng" { return Some(FieldType::Float); }
    if lower.contains("slug") || lower.contains("permalink") { return Some(FieldType::Slug); }
    if lower == "ip" || lower.contains("ip_address") || lower.contains("remote_addr") { return Some(FieldType::Ipv4); }

    None
}

/// Validate input against its auto-inferred shape.
/// Returns None if the parameter name doesn't indicate a clear field type.
pub fn auto_validate_shape(input: &str, param_name: &str) -> Option<ShapeValidation> {
    let field_type = infer_field_type(param_name)?;
    Some(validate_shape(input, field_type))
}

/// Validate expected required keys for a JSON object.
/// Missing required fields are a negative-space signal.
pub fn validate_json_required_fields(input: &str, required_fields: &[&str]) -> Vec<ShapeViolation> {
    let mut violations = Vec::new();
    if input.len() > MAX_JSON_PAYLOAD_BYTES {
        violations.push(ShapeViolation {
            constraint: "payload_size".into(),
            expected: format!("≤{} bytes", MAX_JSON_PAYLOAD_BYTES),
            found: input.len().to_string(),
            severity: 0.9,
        });
        return violations;
    }
    let parsed: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => {
            violations.push(ShapeViolation {
                constraint: "valid_json".into(),
                expected: "parseable JSON object".into(),
                found: "invalid".into(),
                severity: 0.8,
            });
            return violations;
        }
    };

    let Value::Object(map) = parsed else {
        violations.push(ShapeViolation {
            constraint: "json_top_level".into(),
            expected: "object".into(),
            found: "non-object".into(),
            severity: 0.6,
        });
        return violations;
    };

    for key in required_fields {
        if !map.contains_key(*key) {
            violations.push(ShapeViolation {
                constraint: "required_field".into(),
                expected: format!("field '{}' present", key),
                found: format!("field '{}' missing", key),
                severity: 0.5,
            });
        }
    }
    violations
}

/// Validate body structure against declared content type.
pub fn validate_content_type_consistency(input: &str, content_type: Option<&str>) -> Option<ShapeValidation> {
    let content_type = content_type?;
    if input.len() > MAX_JSON_PAYLOAD_BYTES {
        let violation = ShapeValidation {
            matches: false,
            deviation: 1.0,
            violations: vec![ShapeViolation {
                constraint: "payload_size".into(),
                expected: format!("≤{} bytes", MAX_JSON_PAYLOAD_BYTES),
                found: input.len().to_string(),
                severity: 0.95,
            }],
            confidence_boost: 0.10,
            detail: "Input too large for content-type consistency checks".into(),
        };
        return Some(violation);
    }

    let token = extract_content_type_token(content_type);
    let mut violations = Vec::new();
    let trimmed = input.trim();

    if token.contains("application/json") {
        violations.extend(validate_json_value(trimmed));
    } else if token.contains("xml") {
        if !trimmed.starts_with('<') {
            violations.push(ShapeViolation {
                constraint: "content_type_mismatch".into(),
                expected: "XML body".into(),
                found: "non-XML payload".into(),
                severity: 0.8,
            });
        }
        violations.extend(xml_structure_violations(trimmed));
    } else if token.contains("multipart/form-data") {
        violations.extend(multipart_boundary_violations(input, content_type));
    } else if token.contains("application/x-www-form-urlencoded") {
        if !trimmed.contains('=') {
            violations.push(ShapeViolation {
                constraint: "form_structure".into(),
                expected: "key=value pairs".into(),
                found: "missing assignment".into(),
                severity: 0.7,
            });
        }
        if trimmed.starts_with('{') || trimmed.starts_with('<') {
            violations.push(ShapeViolation {
                constraint: "content_type_mismatch".into(),
                expected: "urlencoded form body".into(),
                found: "JSON/XML-like body".into(),
                severity: 0.7,
            });
        }
    }

    if violations.is_empty() {
        return Some(ShapeValidation {
            matches: true,
            deviation: 0.0,
            violations: vec![],
            confidence_boost: 0.0,
            detail: format!("Input is consistent with {}", token),
        });
    }

    let deviation = (violations.iter().map(|v| v.severity).sum::<f64>() / violations.len() as f64).min(1.0);
    let confidence_boost = if deviation > 0.75 { 0.10 } else if deviation > 0.4 { 0.05 } else { 0.02 };

    Some(ShapeValidation {
        matches: false,
        deviation,
        confidence_boost,
        detail: format!("Input inconsistent with {}: {} issues", token, violations.len()),
        violations,
    })
}

fn fnv1a_hash(hash: u64, byte: u8) -> u64 {
    const FNV_PRIME: u64 = 0x00000100000001B3;
    (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
}

fn fnv1a_hash_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        hash = fnv1a_hash(hash, b);
    }
    hash
}

fn fnv1a_hash_u64(mut hash: u64, value: u64) -> u64 {
    let bytes = value.to_le_bytes();
    hash = fnv1a_hash_bytes(hash, &bytes);
    hash
}

fn fnv1a_hash_str(mut hash: u64, s: &str) -> u64 {
    hash = fnv1a_hash_bytes(hash, s.as_bytes());
    hash
}

/// Deterministic shape fingerprint for collision-resistant comparisons.
/// Includes both validation outcome and canonicalized violation descriptors.
pub fn shape_fingerprint(input: &str, expected_type: FieldType) -> u64 {
    let shape = validate_shape(input, expected_type);
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    let mut hash = FNV_OFFSET;
    hash = fnv1a_hash_u64(hash, expected_type as u64);
    hash = fnv1a_hash_u64(hash, shape.deviation.to_bits());
    hash = fnv1a_hash_u64(hash, shape.matches as u8 as u64);
    hash = fnv1a_hash_u64(hash, shape.confidence_boost.to_bits());
    hash = fnv1a_hash_u64(hash, shape.violations.len() as u64);
    hash = fnv1a_hash_u64(hash, input.len() as u64);
    hash = fnv1a_hash_bytes(hash, input.as_bytes());

    let mut entries: Vec<(&str, &str, &str, u64)> = shape
        .violations
        .iter()
        .map(|v| {
            (
                v.constraint.as_str(),
                v.expected.as_str(),
                v.found.as_str(),
                v.severity.to_bits(),
            )
        })
        .collect();
    entries.sort_unstable();
    for (constraint, expected, found, severity_bits) in entries {
        hash = fnv1a_hash_str(hash, constraint);
        hash = fnv1a_hash_str(hash, expected);
        hash = fnv1a_hash_str(hash, found);
        hash = fnv1a_hash_u64(hash, severity_bits);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_username() {
        let r = validate_shape("john_doe", FieldType::Username);
        assert!(r.matches);
        assert_eq!(r.deviation, 0.0);
    }

    #[test]
    fn invalid_username_sqli() {
        let r = validate_shape("' OR 1=1 --", FieldType::Username);
        assert!(!r.matches);
        assert!(r.deviation > 0.3);
        assert!(r.confidence_boost > 0.0);
    }

    #[test]
    fn valid_email() {
        let r = validate_shape("user@example.com", FieldType::Email);
        assert!(r.matches);
    }

    #[test]
    fn invalid_email() {
        let r = validate_shape("<script>alert(1)</script>", FieldType::Email);
        assert!(!r.matches);
    }

    #[test]
    fn valid_uuid() {
        let r = validate_shape("550e8400-e29b-41d4-a716-446655440000", FieldType::Uuid);
        assert!(r.matches);
    }

    #[test]
    fn invalid_uuid_sqli() {
        let r = validate_shape("' UNION SELECT 1--", FieldType::Uuid);
        assert!(!r.matches);
        assert!(r.deviation >= 0.7);
    }

    #[test]
    fn valid_integer() {
        let r = validate_shape("42", FieldType::Integer);
        assert!(r.matches);
    }

    #[test]
    fn invalid_integer() {
        let r = validate_shape("1; DROP TABLE users", FieldType::Integer);
        assert!(!r.matches);
    }

    #[test]
    fn valid_ipv4() {
        let r = validate_shape("192.168.1.1", FieldType::Ipv4);
        assert!(r.matches);
    }

    #[test]
    fn filename_traversal() {
        let r = validate_shape("../../etc/passwd", FieldType::Filename);
        assert!(!r.matches);
        assert!(r.violations.iter().any(|v| v.constraint == "path_separator" || v.constraint == "dotdot"));
    }

    #[test]
    fn infer_email_field() {
        assert_eq!(infer_field_type("email"), Some(FieldType::Email));
        assert_eq!(infer_field_type("user_email"), Some(FieldType::Email));
    }

    #[test]
    fn infer_search_field() {
        assert_eq!(infer_field_type("q"), Some(FieldType::Search));
        assert_eq!(infer_field_type("search_query"), Some(FieldType::Search));
    }

    #[test]
    fn infer_unknown_field() {
        assert_eq!(infer_field_type("foobar"), None);
    }

    #[test]
    fn auto_validate_sqli_in_id() {
        let r = auto_validate_shape("' OR 1=1 --", "user_id").unwrap();
        assert!(!r.matches);
        assert!(r.confidence_boost >= 0.05);
    }

    #[test]
    fn search_with_metachar() {
        let r = validate_shape("'; DROP TABLE--", FieldType::Search);
        assert!(!r.matches);
    }

    #[test]
    fn empty_username_rejected() {
        let r = validate_shape("", FieldType::Username);
        assert!(!r.matches);
        assert!(r.violations.iter().any(|v| v.constraint == "length"));
    }

    #[test]
    fn repeated_char_username_rejected_10k() {
        let payload = "a".repeat(10_000);
        let r = validate_shape(&payload, FieldType::Username);
        assert!(!r.matches);
        assert!(r.deviation > 0.2);
        assert!(r.violations.iter().any(|v| v.constraint == "length"));
    }

    #[test]
    fn printable_ascii_search_remains_textual() {
        let payload: String = (0x20u8..=0x7E).map(char::from).collect();
        let r = validate_shape(&payload, FieldType::Search);
        assert!(!r.matches);
        assert!(r.violations.iter().any(|v| v.constraint == "metachar_ratio"));
    }

    #[test]
    fn binary_input_without_utf8_crash() {
        let bytes = [0x00u8, 0xFF, 0x7F, b'[' as u8, b']', b'a'];
        let payload = String::from_utf8_lossy(&bytes).to_string();
        let r = validate_shape(&payload, FieldType::Username);
        assert!(!r.matches);
        assert!(r.violations.iter().any(|v| v.constraint == "charset" || v.constraint == "control_chars"));
    }

    #[test]
    fn unicode_heavy_input_detected_as_invalid_for_integer() {
        let payload = "火山火山火山".repeat(200);
        let r = validate_shape(&payload, FieldType::Integer);
        assert!(!r.matches);
        assert!(r.violations.iter().any(|v| v.constraint == "format"));
    }

    #[test]
    fn alternating_entropy_segments_in_filename_looks_suspicious() {
        let payload = format!("safe_name_{}{}_{}", "A".repeat(300), "%2e%2e%2f", "/tmp");
        let r = validate_shape(&payload, FieldType::Filename);
        assert!(!r.matches);
        assert!(r.violations.iter().any(|v| v.constraint == "path_traversal"));
    }

    #[test]
    fn shape_fingerprint_is_deterministic() {
        let p1 = shape_fingerprint("john_doe", FieldType::Username);
        let p2 = shape_fingerprint("john_doe", FieldType::Username);
        assert_eq!(p1, p2);
    }

    #[test]
    fn shape_fingerprint_distinguishes_payload_variants() {
        let p1 = shape_fingerprint("john_doe", FieldType::Username);
        let p2 = shape_fingerprint("john_d0e", FieldType::Username);
        assert_ne!(p1, p2);
    }

    #[test]
    fn shape_fingerprint_detects_path_traversal_collision_resistance() {
        let plain = shape_fingerprint("../../etc/passwd", FieldType::Filename);
        let encoded = shape_fingerprint("%2e%2e%2f%2e%2e%2fetc%2fpasswd", FieldType::Filename);
        assert_ne!(plain, encoded);
    }

    #[test]
    fn json_value_detects_suspicious_operator_keys() {
        let r = validate_shape(r#"{"username":"a","$ne":"x"}"#, FieldType::JsonValue);
        assert!(!r.matches);
        assert!(r.violations.iter().any(|v| v.constraint == "suspicious_keys"));
    }

    #[test]
    fn json_required_fields_negative_space() {
        let violations = validate_json_required_fields(r#"{"username":"alice"}"#, &["username", "password"]);
        assert!(violations.iter().any(|v| v.constraint == "required_field"));
    }

    #[test]
    fn shape_json_required_fields_blocks_large_payloads() {
        let payload = "a".repeat(MAX_JSON_PAYLOAD_BYTES + 1);
        let violations = validate_json_required_fields(&payload, &["x"]);
        assert!(violations.iter().any(|v| v.constraint == "payload_size"));
    }

    #[test]
    fn content_type_json_mismatch() {
        let r = validate_content_type_consistency("<xml></xml>", Some("application/json")).unwrap();
        assert!(!r.matches);
        assert!(r.violations.iter().any(|v| v.constraint == "valid_json" || v.constraint == "content_mismatch"));
    }

    #[test]
    fn multipart_boundary_manipulation_detected() {
        let body = "--abc\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nhello";
        let r = validate_content_type_consistency(body, Some("multipart/form-data; boundary=abc")).unwrap();
        assert!(!r.matches);
        assert!(r.violations.iter().any(|v| v.constraint == "boundary_format" || v.constraint == "boundary_closure"));
    }

    #[test]
    fn xml_entity_abuse_detected() {
        let body = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>";
        let r = validate_content_type_consistency(body, Some("application/xml")).unwrap();
        assert!(!r.matches);
        assert!(r.violations.iter().any(|v| v.constraint == "xml_dtd_entity"));
    }

    #[test]
    fn json_nested_encoding_depth_detected() {
        let deep = r#""%25252525253Cscript%25252525253Ealert(1)%25252525253C%25252525252Fscript%25252525253E""#;
        let r = validate_shape(deep, FieldType::JsonValue);
        assert!(!r.matches);
        assert!(r.violations.iter().any(|v| v.constraint == "encoding_layers"));
    }

    #[test]
    fn content_type_large_payload_rejected_early() {
        let payload = "a".repeat(MAX_JSON_PAYLOAD_BYTES + 1);
        let r = validate_content_type_consistency(&payload, Some("application/json")).unwrap();
        assert!(!r.matches);
        assert!(r.violations.iter().any(|v| v.constraint == "payload_size"));
    }
}
