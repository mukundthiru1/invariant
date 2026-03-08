use crate::types::InvariantClass;
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use std::time::Instant;

const MAX_JSON_ITEMS: usize = 100;
const MAX_XML_ATTRS: usize = 200;
const MAX_XML_TEXTS: usize = 200;
const MAX_XML_CDATA: usize = 50;
const MAX_SUSPICIOUS_SURFACES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SurfaceLocation {
    PathSegment,
    QueryKey,
    QueryValue,
    HeaderValue,
    CookieValue,
    JsonKey,
    JsonValue,
    FormField,
    MultipartField,
    XmlElement,
    XmlAttribute,
    Fragment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingKind {
    Plain,
    UrlEncoded,
    DoubleUrlEncoded,
    HtmlEntity,
    UnicodeEscape,
    Base64Like,
    HexLike,
    Mixed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EntropyProfile {
    pub shannon_bits: f64,
    pub length: usize,
    pub unique_char_ratio: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CharClassAnalysis {
    pub alphabetic: usize,
    pub numeric: usize,
    pub whitespace: usize,
    pub punctuation: usize,
    pub control: usize,
    pub non_ascii: usize,
    pub metacharacters: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Surface {
    pub location: SurfaceLocation,
    pub name: String,
    pub raw: String,
    pub normalized: String,
    pub entropy: f64,
    pub has_metachars: bool,
    pub metachar_density: f64,
    pub entropy_profile: EntropyProfile,
    pub char_analysis: CharClassAnalysis,
    pub encoding: EncodingKind,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PayloadCarrier {
    pub index: usize,
    pub location: SurfaceLocation,
    pub name: String,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssembledPayloadSource {
    pub location: SurfaceLocation,
    pub name: String,
    pub fragment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssemblyMethod {
    Concatenation,
    KeyValueMerge,
    NestedInjection,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssembledPayload {
    pub payload: String,
    pub sources: Vec<AssembledPayloadSource>,
    pub matched_class: Option<InvariantClass>,
    pub assembly_method: AssemblyMethod,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestSurfaces {
    pub surfaces: Vec<Surface>,
    pub cross_surface_payloads: Vec<AssembledPayload>,
    pub payload_carrier: Option<PayloadCarrier>,
    pub surface_count: usize,
    pub highest_entropy: f64,
    pub total_metachar_density: f64,
    pub processing_time_us: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHttpRequest {
    pub method: String,
    pub path: String,
    pub query_string: Option<String>,
    pub headers: HashMap<String, String>,
    pub cookies: Option<HashMap<String, String>>,
    pub body: Option<String>,
    pub content_type: Option<String>,
}

static SQL_META: &[char] = &[
    '\'', '"', ';', '-', '/', '*', '(', ')', '=', '<', '>', '!', '|', '&', '~', '^', '%', '+', '@',
];
static SHELL_META: &[char] = &[
    '|', '&', ';', '`', '$', '(', ')', '{', '}', '<', '>', '!', '\\', '\n', '\r',
];
static HTML_META: &[char] = &['<', '>', '"', '\'', '&', '/', '='];

fn all_meta_set() -> HashSet<char> {
    SQL_META
        .iter()
        .chain(SHELL_META.iter())
        .chain(HTML_META.iter())
        .copied()
        .collect()
}

fn security_headers() -> &'static [&'static str] {
    &[
        "authorization",
        "cookie",
        "x-forwarded-for",
        "x-real-ip",
        "x-originating-ip",
        "x-remote-ip",
        "x-client-ip",
        "x-custom-ip-authorization",
        "x-original-url",
        "x-rewrite-url",
        "referer",
        "origin",
        "content-type",
        "content-disposition",
        "transfer-encoding",
        "x-middleware-subrequest",
        "x-forwarded-host",
        "x-forwarded-proto",
        "accept",
        "user-agent",
        "host",
    ]
}

pub fn decompose_request(request: &RawHttpRequest) -> RequestSurfaces {
    let start = Instant::now();
    let mut surfaces = Vec::new();

    let path_without_query = request.path.split('?').next().unwrap_or(&request.path);
    let path_parts: Vec<&str> = path_without_query
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    for (idx, raw) in path_parts.iter().enumerate() {
        surfaces.push(make_surface(
            SurfaceLocation::PathSegment,
            &format!("path[{idx}]"),
            raw,
        ));
    }

    let query_str = request
        .query_string
        .clone()
        .unwrap_or_else(|| extract_query_string(&request.path));
    if !query_str.is_empty() {
        for (key, value) in parse_query_string(&query_str) {
            surfaces.push(make_surface(SurfaceLocation::QueryKey, &key, &key));
            surfaces.push(make_surface(SurfaceLocation::QueryValue, &key, &value));
        }
    }

    let sec_headers: HashSet<&str> = security_headers().iter().copied().collect();
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if sec_headers.contains(lower.as_str()) {
            surfaces.push(make_surface(SurfaceLocation::HeaderValue, &lower, value));
        }
    }

    if let Some(cookies) = &request.cookies {
        for (name, value) in cookies {
            surfaces.push(make_surface(SurfaceLocation::CookieValue, name, value));
        }
    } else {
        let cookie_header = request
            .headers
            .get("cookie")
            .or_else(|| request.headers.get("Cookie"))
            .map(|s| s.as_str())
            .unwrap_or("");
        if !cookie_header.is_empty() {
            for (name, value) in parse_cookies(cookie_header) {
                surfaces.push(make_surface(SurfaceLocation::CookieValue, &name, &value));
            }
        }
    }

    if let Some(body) = &request.body {
        if !body.is_empty() {
            let ct = request
                .content_type
                .as_deref()
                .or_else(|| request.headers.get("content-type").map(|s| s.as_str()))
                .unwrap_or("")
                .to_ascii_lowercase();

            if ct.contains("application/json") {
                extract_json_surfaces(body, &mut surfaces);
            } else if ct.contains("application/x-www-form-urlencoded") {
                for (key, value) in parse_query_string(body) {
                    surfaces.push(make_surface(SurfaceLocation::FormField, &key, &value));
                }
            } else if ct.contains("multipart/form-data") {
                extract_multipart_surfaces(body, &mut surfaces);
            } else if ct.contains("text/xml") || ct.contains("application/xml") {
                extract_xml_surfaces(body, &mut surfaces);
            } else {
                surfaces.push(make_surface(SurfaceLocation::FormField, "_body", body));
            }
        }
    }

    let cross_surface_payloads = detect_cross_surface_payloads(&surfaces);
    let payload_carrier = identify_payload_carrier(&surfaces);

    let surface_count = surfaces.len();
    let highest_entropy = surfaces.iter().map(|s| s.entropy).fold(0.0_f64, f64::max);
    let total_metachar_density = if surfaces.is_empty() {
        0.0
    } else {
        surfaces.iter().map(|s| s.metachar_density).sum::<f64>() / surfaces.len() as f64
    };

    RequestSurfaces {
        surfaces,
        cross_surface_payloads,
        payload_carrier,
        surface_count,
        highest_entropy,
        total_metachar_density,
        processing_time_us: start.elapsed().as_secs_f64() * 1_000_000.0,
    }
}

fn make_surface(location: SurfaceLocation, name: &str, raw: &str) -> Surface {
    let normalized = normalize(raw);
    let entropy = shannon_entropy(&normalized);
    let meta = analyze_metachars(&normalized);
    let char_analysis = char_class_analysis(&normalized);
    let encoding = detect_encoding(raw);

    let unique = normalized.chars().collect::<HashSet<char>>().len();
    let profile = EntropyProfile {
        shannon_bits: entropy,
        length: normalized.chars().count(),
        unique_char_ratio: if normalized.is_empty() {
            0.0
        } else {
            unique as f64 / normalized.chars().count() as f64
        },
    };

    Surface {
        location,
        name: name.to_owned(),
        raw: raw.to_owned(),
        normalized,
        entropy,
        has_metachars: meta.0,
        metachar_density: meta.1,
        entropy_profile: profile,
        char_analysis,
        encoding,
    }
}

fn normalize(raw: &str) -> String {
    let mut out = raw.to_owned();
    for _ in 0..3 {
        let decoded = safe_url_decode(&out);
        if decoded == out {
            break;
        }
        out = decoded;
    }
    out = decode_html_entities(&out);
    collapse_spaces(&out)
}

fn collapse_spaces(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_space = false;
    for ch in input.chars() {
        if ch == ' ' || ch == '\t' {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            out.push(ch);
            last_space = false;
        }
    }
    out
}

fn safe_url_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let a = bytes[i + 1] as char;
            let b = bytes[i + 2] as char;
            if a.is_ascii_hexdigit() && b.is_ascii_hexdigit() {
                let hex = &input[i + 1..i + 3];
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v as char);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn decode_html_entities(input: &str) -> String {
    static HEX_ENTITY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"&#x([0-9a-fA-F]+);").expect("valid regex"));
    static DEC_ENTITY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"&#(\d+);").expect("valid regex"));

    let mut out = input
        .replace("&lt;", "<")
        .replace("&LT;", "<")
        .replace("&gt;", ">")
        .replace("&GT;", ">")
        .replace("&amp;", "&")
        .replace("&AMP;", "&")
        .replace("&quot;", "\"")
        .replace("&QUOT;", "\"");

    out = HEX_ENTITY
        .replace_all(&out, |caps: &regex::Captures| {
            let code = u32::from_str_radix(&caps[1], 16).ok();
            code.and_then(char::from_u32)
                .map(|c| c.to_string())
                .unwrap_or_else(|| caps[0].to_owned())
        })
        .to_string();

    DEC_ENTITY
        .replace_all(&out, |caps: &regex::Captures| {
            let code = caps[1].parse::<u32>().ok();
            code.and_then(char::from_u32)
                .map(|c| c.to_string())
                .unwrap_or_else(|| caps[0].to_owned())
        })
        .to_string()
}

fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for ch in input.chars() {
        *freq.entry(ch).or_insert(0) += 1;
    }
    let len = input.chars().count() as f64;
    let mut entropy = 0.0;
    for count in freq.values() {
        let p = *count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn analyze_metachars(input: &str) -> (bool, f64) {
    if input.is_empty() {
        return (false, 0.0);
    }
    let all_meta = all_meta_set();
    let mut count = 0usize;
    for ch in input.chars() {
        if all_meta.contains(&ch) {
            count += 1;
        }
    }
    (count > 0, count as f64 / input.chars().count() as f64)
}

fn char_class_analysis(input: &str) -> CharClassAnalysis {
    let all_meta = all_meta_set();
    let mut out = CharClassAnalysis {
        alphabetic: 0,
        numeric: 0,
        whitespace: 0,
        punctuation: 0,
        control: 0,
        non_ascii: 0,
        metacharacters: 0,
    };

    for ch in input.chars() {
        if ch.is_alphabetic() {
            out.alphabetic += 1;
        }
        if ch.is_ascii_digit() {
            out.numeric += 1;
        }
        if ch.is_whitespace() {
            out.whitespace += 1;
        }
        if ch.is_ascii_punctuation() {
            out.punctuation += 1;
        }
        if ch.is_control() {
            out.control += 1;
        }
        if !ch.is_ascii() {
            out.non_ascii += 1;
        }
        if all_meta.contains(&ch) {
            out.metacharacters += 1;
        }
    }

    out
}

fn detect_encoding(input: &str) -> EncodingKind {
    let has_pct = input.contains('%');
    let pct_triplets = input
        .match_indices('%')
        .filter(|(idx, _)| *idx + 2 < input.len())
        .count();
    let has_html = input.contains("&lt;")
        || input.contains("&gt;")
        || input.contains("&#")
        || input.contains("&amp;");
    let has_unicode_escape = input.contains("\\u") || input.contains("\\x");

    let lower = input.to_ascii_lowercase();
    let is_hex_like = lower.starts_with("0x")
        || (lower.len() >= 8 && lower.chars().all(|c| c.is_ascii_hexdigit()));
    let base64_charset = input
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    let is_base64_like = input.len() >= 12 && input.len() % 4 == 0 && base64_charset;

    let mut hits = 0usize;
    if has_pct && pct_triplets > 0 {
        hits += 1;
    }
    if has_html {
        hits += 1;
    }
    if has_unicode_escape {
        hits += 1;
    }
    if is_base64_like {
        hits += 1;
    }
    if is_hex_like {
        hits += 1;
    }

    if hits > 1 {
        return EncodingKind::Mixed;
    }

    if has_pct && input.contains("%25") {
        return EncodingKind::DoubleUrlEncoded;
    }
    if has_pct && pct_triplets > 0 {
        return EncodingKind::UrlEncoded;
    }
    if has_html {
        return EncodingKind::HtmlEntity;
    }
    if has_unicode_escape {
        return EncodingKind::UnicodeEscape;
    }
    if is_base64_like {
        return EncodingKind::Base64Like;
    }
    if is_hex_like {
        return EncodingKind::HexLike;
    }

    EncodingKind::Plain
}

fn extract_query_string(path: &str) -> String {
    path.split_once('?')
        .map(|(_, q)| q.to_owned())
        .unwrap_or_default()
}

fn parse_query_string(qs: &str) -> Vec<(String, String)> {
    if qs.is_empty() {
        return Vec::new();
    }
    qs.split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            if let Some((k, v)) = part.split_once('=') {
                (safe_url_decode(k), safe_url_decode(v))
            } else {
                (safe_url_decode(part), String::new())
            }
        })
        .collect()
}

fn parse_cookies(header: &str) -> Vec<(String, String)> {
    header
        .split(';')
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                return None;
            }
            let (k, v) = trimmed.split_once('=')?;
            Some((k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect()
}

fn extract_json_surfaces(body: &str, surfaces: &mut Vec<Surface>) {
    match serde_json::from_str::<Value>(body) {
        Ok(parsed) => walk_json(&parsed, "", surfaces),
        Err(_) => surfaces.push(make_surface(SurfaceLocation::JsonValue, "_body", body)),
    }
}

fn walk_json(value: &Value, path: &str, surfaces: &mut Vec<Surface>) {
    match value {
        Value::Null => {}
        Value::Bool(v) => surfaces.push(make_surface(
            SurfaceLocation::JsonValue,
            if path.is_empty() { "_root" } else { path },
            &v.to_string(),
        )),
        Value::Number(v) => surfaces.push(make_surface(
            SurfaceLocation::JsonValue,
            if path.is_empty() { "_root" } else { path },
            &v.to_string(),
        )),
        Value::String(v) => surfaces.push(make_surface(
            SurfaceLocation::JsonValue,
            if path.is_empty() { "_root" } else { path },
            v,
        )),
        Value::Array(items) => {
            for (idx, item) in items.iter().take(MAX_JSON_ITEMS).enumerate() {
                walk_json(item, &format!("{path}[{idx}]"), surfaces);
            }
        }
        Value::Object(map) => {
            for (key, val) in map.iter().take(MAX_JSON_ITEMS) {
                let full = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                surfaces.push(make_surface(SurfaceLocation::JsonKey, &full, key));
                walk_json(val, &full, surfaces);
            }
        }
    }
}

fn extract_multipart_surfaces(body: &str, surfaces: &mut Vec<Surface>) {
    let first_line = body.lines().next().unwrap_or_default().trim().to_owned();
    if !first_line.starts_with("--") {
        surfaces.push(make_surface(SurfaceLocation::FormField, "_body", body));
        return;
    }

    for part in body.split(&first_line) {
        if part.is_empty() || part == "--" || part == "--\r\n" {
            continue;
        }
        let name = if let Some(idx) = part.find("name=\"") {
            let rest = &part[idx + 6..];
            rest.split('"').next().unwrap_or_default().to_owned()
        } else {
            continue;
        };

        let Some(value_start) = part.find("\r\n\r\n") else {
            continue;
        };
        let value = part[value_start + 4..]
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_owned();
        surfaces.push(make_surface(SurfaceLocation::MultipartField, &name, &value));
    }
}

fn extract_xml_surfaces(body: &str, surfaces: &mut Vec<Surface>) {
    static ATTR_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(\w+)=[\"']([^\"']*?)[\"']"#).expect("valid regex"));
    static TEXT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r">([^<]+)<").expect("valid regex"));
    static CDATA_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?s)<!\[CDATA\[(.*?)\]\]>").expect("valid regex"));
    static DOCTYPE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)<!DOCTYPE|<!ENTITY").expect("valid regex"));

    for (idx, cap) in ATTR_RE.captures_iter(body).take(MAX_XML_ATTRS).enumerate() {
        let _ = idx;
        surfaces.push(make_surface(
            SurfaceLocation::XmlAttribute,
            &cap[1],
            &cap[2],
        ));
    }

    for (idx, cap) in TEXT_RE.captures_iter(body).take(MAX_XML_TEXTS).enumerate() {
        let text = cap[1].trim();
        if !text.is_empty() {
            surfaces.push(make_surface(
                SurfaceLocation::XmlElement,
                &format!("_text[{idx}]"),
                text,
            ));
        }
    }

    for (idx, cap) in CDATA_RE.captures_iter(body).take(MAX_XML_CDATA).enumerate() {
        surfaces.push(make_surface(
            SurfaceLocation::XmlElement,
            &format!("_cdata[{idx}]"),
            &cap[1],
        ));
    }

    if DOCTYPE_RE.is_match(body) {
        let head: String = body.chars().take(500).collect();
        surfaces.push(make_surface(SurfaceLocation::XmlElement, "_doctype", &head));
    }
}

fn detect_cross_surface_payloads(surfaces: &[Surface]) -> Vec<AssembledPayload> {
    let mut payloads = Vec::new();

    for key in surfaces
        .iter()
        .filter(|s| s.location == SurfaceLocation::JsonKey)
    {
        if is_injection_key(&key.normalized) {
            payloads.push(AssembledPayload {
                payload: key.normalized.clone(),
                sources: vec![AssembledPayloadSource {
                    location: key.location,
                    name: key.name.clone(),
                    fragment: key.normalized.clone(),
                }],
                matched_class: guess_class_from_key(&key.normalized),
                assembly_method: AssemblyMethod::NestedInjection,
                confidence: 0.85,
            });
        }
    }

    let suspicious: Vec<&Surface> = surfaces
        .iter()
        .filter(|s| s.has_metachars && !s.normalized.is_empty())
        .take(MAX_SUSPICIOUS_SURFACES)
        .collect();

    let query_values: Vec<&Surface> = suspicious
        .iter()
        .copied()
        .filter(|s| {
            matches!(
                s.location,
                SurfaceLocation::QueryValue | SurfaceLocation::FormField
            )
        })
        .collect();
    if suspicious.len() >= 2 && query_values.len() >= 2 {
        let combined = query_values
            .iter()
            .map(|s| s.normalized.as_str())
            .collect::<Vec<&str>>()
            .join(" ");
        if looks_like_split_sql(&combined, &query_values) {
            payloads.push(AssembledPayload {
                payload: combined,
                sources: query_values
                    .iter()
                    .map(|s| AssembledPayloadSource {
                        location: s.location,
                        name: s.name.clone(),
                        fragment: s.normalized.clone(),
                    })
                    .collect(),
                matched_class: None,
                assembly_method: AssemblyMethod::Concatenation,
                confidence: compute_assembly_confidence(&query_values),
            });
        }
    }

    for i in 0..suspicious.len() {
        for j in (i + 1)..suspicious.len() {
            if suspicious[i].location == suspicious[j].location
                && suspicious[i].name == suspicious[j].name
            {
                continue;
            }
            let pair = format!("{}{}", suspicious[i].normalized, suspicious[j].normalized);
            if looks_like_split_payload(&pair) {
                payloads.push(AssembledPayload {
                    payload: pair,
                    sources: vec![
                        AssembledPayloadSource {
                            location: suspicious[i].location,
                            name: suspicious[i].name.clone(),
                            fragment: suspicious[i].normalized.clone(),
                        },
                        AssembledPayloadSource {
                            location: suspicious[j].location,
                            name: suspicious[j].name.clone(),
                            fragment: suspicious[j].normalized.clone(),
                        },
                    ],
                    matched_class: None,
                    assembly_method: AssemblyMethod::Concatenation,
                    confidence: (0.6
                        + (suspicious[i].metachar_density + suspicious[j].metachar_density) * 0.2)
                        .clamp(0.0, 0.95),
                });
            }
        }
    }

    for key in surfaces
        .iter()
        .filter(|s| s.location == SurfaceLocation::JsonKey)
    {
        if is_injection_key(&key.normalized) {
            payloads.push(AssembledPayload {
                payload: key.normalized.clone(),
                sources: vec![AssembledPayloadSource {
                    location: key.location,
                    name: key.name.clone(),
                    fragment: key.normalized.clone(),
                }],
                matched_class: guess_class_from_key(&key.normalized),
                assembly_method: AssemblyMethod::NestedInjection,
                confidence: 0.85,
            });
        }
    }

    payloads
}

fn looks_like_split_sql(combined: &str, surfaces: &[&Surface]) -> bool {
    let lower = combined.to_ascii_lowercase();
    let sql_keywords = [
        "select", "union", "insert", "update", "delete", "drop", "having", "group by", "order by",
        "where", "from",
    ];

    let found_keywords = sql_keywords
        .iter()
        .filter(|kw| lower.contains(**kw))
        .count();
    if found_keywords < 2 {
        return false;
    }

    let contributions = surfaces
        .iter()
        .filter(|s| {
            let v = s.normalized.to_ascii_lowercase();
            sql_keywords.iter().any(|kw| v.contains(kw))
        })
        .count();

    contributions >= 2
}

fn looks_like_split_payload(combined: &str) -> bool {
    static SQL_ESCAPE_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)['\"].*\b(or|and|union|select|drop|insert|delete|update)\b"#)
            .expect("valid regex")
    });
    static XSS_TAG_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)<\w+.*>.*</\w+>").expect("valid regex"));
    static XSS_EVENT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)on\w+\s*=|javascript:").expect("valid regex"));
    static XSS_PRIM_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)<script|<img|<svg|<iframe").expect("valid regex"));
    static CMD_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"[|;&`$].*\b(cat|ls|id|whoami|curl|wget|nc|ncat)\b").expect("valid regex")
    });
    static PATH_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\.\..*[/\\]").expect("valid regex"));

    let lower = combined.to_ascii_lowercase();

    if SQL_ESCAPE_RE.is_match(combined) {
        return true;
    }
    if XSS_TAG_RE.is_match(combined) {
        return true;
    }
    if XSS_PRIM_RE.is_match(combined) && XSS_EVENT_RE.is_match(combined) {
        return true;
    }
    if CMD_RE.is_match(combined) {
        return true;
    }
    if PATH_RE.is_match(combined)
        && ["etc", "passwd", "shadow", "config", "env"]
            .iter()
            .any(|kw| lower.contains(kw))
    {
        return true;
    }

    false
}

fn is_injection_key(key: &str) -> bool {
    if key == "__proto__" || key == "constructor" || key == "prototype" {
        return true;
    }
    static MASS_ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)^(is_?admin|role|permission|privilege|access_level|admin|superuser)$")
            .expect("valid regex")
    });
    MASS_ASSIGN_RE.is_match(key)
}

fn guess_class_from_key(key: &str) -> Option<InvariantClass> {
    if key == "__proto__" || key == "constructor" || key == "prototype" {
        return Some(InvariantClass::ProtoPollution);
    }
    if key.to_ascii_lowercase().contains("admin")
        || key.to_ascii_lowercase().contains("role")
        || key.to_ascii_lowercase().contains("permission")
    {
        return Some(InvariantClass::MassAssignment);
    }
    None
}

fn compute_assembly_confidence(surfaces: &[&Surface]) -> f64 {
    let meta_surfaces = surfaces.iter().filter(|s| s.has_metachars).count();
    let avg_density =
        surfaces.iter().map(|s| s.metachar_density).sum::<f64>() / surfaces.len() as f64;
    (0.5 + (meta_surfaces as f64 / surfaces.len() as f64) * 0.2 + avg_density * 0.3)
        .clamp(0.0, 0.95)
}

fn identify_payload_carrier(surfaces: &[Surface]) -> Option<PayloadCarrier> {
    let mut best: Option<PayloadCarrier> = None;

    for (idx, s) in surfaces.iter().enumerate() {
        let encoding_boost = match s.encoding {
            EncodingKind::DoubleUrlEncoded | EncodingKind::Mixed => 0.25,
            EncodingKind::UrlEncoded | EncodingKind::HtmlEntity | EncodingKind::UnicodeEscape => {
                0.15
            }
            EncodingKind::Base64Like | EncodingKind::HexLike => 0.2,
            EncodingKind::Plain => 0.0,
        };
        let score = (s.metachar_density * 0.6)
            + (if s.has_metachars { 0.15 } else { 0.0 })
            + ((s.entropy / 8.0).clamp(0.0, 1.0) * 0.25)
            + encoding_boost;

        if score < 0.15 {
            continue;
        }

        let candidate = PayloadCarrier {
            index: idx,
            location: s.location,
            name: s.name.clone(),
            score,
        };

        if best
            .as_ref()
            .map(|b| candidate.score > b.score)
            .unwrap_or(true)
        {
            best = Some(candidate);
        }
    }

    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(path: &str) -> RawHttpRequest {
        RawHttpRequest {
            method: "GET".into(),
            path: path.into(),
            query_string: None,
            headers: HashMap::new(),
            cookies: None,
            body: None,
            content_type: None,
        }
    }

    #[test]
    fn path_segments_are_extracted() {
        let r = req("/api/v1/users");
        let out = decompose_request(&r);
        assert!(
            out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::PathSegment
                    && s.name == "path[0]"
                    && s.raw == "api")
        );
    }

    #[test]
    fn query_keys_and_values_are_extracted() {
        let r = req("/search?q=test&sort=asc");
        let out = decompose_request(&r);
        assert!(
            out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::QueryKey && s.raw == "q")
        );
        assert!(
            out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::QueryValue
                    && s.name == "q"
                    && s.raw == "test")
        );
    }

    #[test]
    fn security_headers_are_extracted() {
        let mut r = req("/");
        r.headers.insert("Authorization".into(), "Bearer x".into());
        r.headers.insert("X-Other".into(), "skip".into());
        let out = decompose_request(&r);
        assert!(
            out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::HeaderValue && s.name == "authorization")
        );
        assert!(
            !out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::HeaderValue && s.name == "x-other")
        );
    }

    #[test]
    fn cookies_parse_from_header_when_missing_cookie_map() {
        let mut r = req("/");
        r.headers
            .insert("Cookie".into(), "sid=abc; role=user".into());
        let out = decompose_request(&r);
        assert!(
            out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::CookieValue
                    && s.name == "sid"
                    && s.raw == "abc")
        );
    }

    #[test]
    fn json_body_walk_extracts_keys_and_values() {
        let mut r = req("/");
        r.content_type = Some("application/json".into());
        r.body = Some(r#"{"profile":{"name":"alice","age":42}}"#.into());
        let out = decompose_request(&r);
        assert!(
            out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::JsonKey && s.raw == "profile")
        );
        assert!(
            out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::JsonValue
                    && s.name.ends_with("name")
                    && s.raw == "alice")
        );
    }

    #[test]
    fn malformed_json_falls_back_to_body_surface() {
        let mut r = req("/");
        r.content_type = Some("application/json".into());
        r.body = Some("{bad".into());
        let out = decompose_request(&r);
        assert!(
            out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::JsonValue && s.name == "_body")
        );
    }

    #[test]
    fn form_urlencoded_fields_extracted() {
        let mut r = req("/");
        r.content_type = Some("application/x-www-form-urlencoded".into());
        r.body = Some("email=a%40b.com&message=hello".into());
        let out = decompose_request(&r);
        assert!(
            out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::FormField
                    && s.name == "email"
                    && s.raw == "a@b.com")
        );
    }

    #[test]
    fn multipart_fields_extracted() {
        let mut r = req("/");
        r.content_type = Some("multipart/form-data; boundary=abc".into());
        r.body = Some(
            "--abc\r\nContent-Disposition: form-data; name=\"cmd\"\r\n\r\nwhoami\r\n--abc--\r\n"
                .into(),
        );
        let out = decompose_request(&r);
        assert!(
            out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::MultipartField
                    && s.name == "cmd"
                    && s.raw == "whoami")
        );
    }

    #[test]
    fn xml_surfaces_extracted_including_doctype() {
        let mut r = req("/");
        r.content_type = Some("application/xml".into());
        r.body = Some("<!DOCTYPE foo [<!ENTITY xxe \"x\">]><a k=\"v\">text</a>".into());
        let out = decompose_request(&r);
        assert!(
            out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::XmlAttribute
                    && s.name == "k"
                    && s.raw == "v")
        );
        assert!(
            out.surfaces
                .iter()
                .any(|s| s.location == SurfaceLocation::XmlElement && s.name == "_doctype")
        );
    }

    #[test]
    fn encoding_detection_identifies_double_url() {
        let s = make_surface(SurfaceLocation::FormField, "a", "%2527%2520OR%25201%253D1");
        assert_eq!(s.encoding, EncodingKind::DoubleUrlEncoded);
    }

    #[test]
    fn char_analysis_and_entropy_are_populated() {
        let s = make_surface(SurfaceLocation::FormField, "x", "abc123<>");
        assert!(s.entropy > 0.0);
        assert!(s.char_analysis.alphabetic >= 3);
        assert!(s.char_analysis.numeric >= 3);
        assert!(s.char_analysis.metacharacters >= 2);
    }

    #[test]
    fn split_sql_assembly_detected() {
        let r = RawHttpRequest {
            method: "GET".into(),
            path: "/?id=1'&sort=OR%201=1--".into(),
            query_string: None,
            headers: HashMap::new(),
            cookies: None,
            body: None,
            content_type: None,
        };
        let out = decompose_request(&r);
        assert!(!out.cross_surface_payloads.is_empty());
    }

    #[test]
    fn nested_injection_key_detected() {
        let mut r = req("/");
        r.content_type = Some("application/json".into());
        r.body = Some(r#"{"__proto__":"x"}"#.into());
        let out = decompose_request(&r);
        assert!(
            out.cross_surface_payloads
                .iter()
                .any(|p| p.assembly_method == AssemblyMethod::NestedInjection
                    && p.matched_class == Some(InvariantClass::ProtoPollution))
        );
    }

    #[test]
    fn payload_carrier_points_to_suspicious_surface() {
        let r = RawHttpRequest {
            method: "GET".into(),
            path: "/api".into(),
            query_string: Some("a=ok&b=%27%20OR%201%3D1--".into()),
            headers: HashMap::new(),
            cookies: None,
            body: None,
            content_type: None,
        };
        let out = decompose_request(&r);
        let carrier = out.payload_carrier.expect("payload carrier expected");
        assert_eq!(carrier.name, "b");
    }

    #[test]
    fn metrics_are_computed() {
        let r = req("/a/b?x=1");
        let out = decompose_request(&r);
        assert!(out.surface_count >= 3);
        assert!(out.processing_time_us >= 0.0);
        assert!(out.highest_entropy >= 0.0);
    }
}
