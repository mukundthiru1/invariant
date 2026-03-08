use serde_json::Value;
use std::collections::{HashMap, HashSet};

const MAX_JSON_DEPTH: usize = 128;
const MAX_JSON_KEY_LEN: usize = 256;
const MAX_JSON_VALUE_LEN: usize = 4096;
const MAX_FORM_FIELDS: usize = 512;
const MAX_FORM_FIELD_NAME_LEN: usize = 256;
const MAX_FORM_FIELD_VALUE_LEN: usize = 4096;
const MAX_MULTIPART_FIELD_NAME_LEN: usize = 128;
const MAX_MULTIPART_FIELD_VALUE_LEN: usize = 4096;
const MAX_MULTIPART_FILENAME_LEN: usize = 255;
const MAX_MULTIPART_BOUNDARY_LEN: usize = 70;

#[derive(Debug, Clone, PartialEq)]
pub enum ParsedBody {
    Json(JsonBody),
    FormUrlEncoded(Vec<(String, String)>),
    Multipart(Vec<MultipartField>),
    Xml(XmlBody),
    Raw(String),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct JsonBody {
    pub fields: Vec<(String, String)>,
    pub max_depth: usize,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct XmlBody {
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MultipartField {
    pub name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldType {
    Email,
    Url,
    Id,
    FreeText,
    Numeric,
    Boolean,
    Date,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldContext {
    pub field_name: String,
    pub field_path: String,
    pub expected_type: FieldType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldAnomaly {
    pub field_name: String,
    pub field_path: String,
    pub message: String,
}

pub fn parse_body(content_type: Option<&str>, body: &str) -> ParsedBody {
    let ct = content_type.unwrap_or_default().to_ascii_lowercase();

    if ct.contains("application/json") || ct.contains("+json") {
        return match parse_json_body(body) {
            Some(json) => ParsedBody::Json(json),
            None => ParsedBody::Raw(body.to_owned()),
        };
    }

    if ct.contains("application/x-www-form-urlencoded") {
        return ParsedBody::FormUrlEncoded(parse_form_urlencoded(body));
    }

    if ct.contains("multipart/form-data") {
        if let Some(boundary) = extract_boundary(&ct) {
            return ParsedBody::Multipart(parse_multipart(body, &boundary));
        }
        return ParsedBody::Raw(body.to_owned());
    }

    if ct.contains("xml") || looks_like_xml(body) {
        return match parse_xml_body(body) {
            Some(xml) => ParsedBody::Xml(xml),
            None => ParsedBody::Raw(body.to_owned()),
        };
    }

    if body.trim_start().starts_with('{') || body.trim_start().starts_with('[') {
        if let Some(json) = parse_json_body(body) {
            return ParsedBody::Json(json);
        }
    }

    ParsedBody::Raw(body.to_owned())
}

pub fn infer_field_type(field_name: &str) -> FieldType {
    let name = field_name.to_ascii_lowercase();
    if name.contains("email") {
        return FieldType::Email;
    }
    if name.contains("url") || name.contains("uri") || name.contains("link") || name.contains("website") {
        return FieldType::Url;
    }
    if name.ends_with("id") || name == "id" || name.contains("_id") || name.contains("uuid") {
        return FieldType::Id;
    }
    if name.contains("count")
        || name.contains("amount")
        || name.contains("price")
        || name.contains("total")
        || name.contains("qty")
        || name.contains("number")
        || name.contains("age")
    {
        return FieldType::Numeric;
    }
    if name.starts_with("is_")
        || name.starts_with("has_")
        || name.starts_with("can_")
        || name.ends_with("enabled")
        || name.ends_with("active")
        || name == "enabled"
        || name == "active"
    {
        return FieldType::Boolean;
    }
    if name.contains("date")
        || name.contains("time")
        || name.contains("at")
        || name.contains("dob")
        || name.contains("expires")
        || name.contains("expiry")
    {
        return FieldType::Date;
    }
    if name.contains("name")
        || name.contains("title")
        || name.contains("description")
        || name.contains("comment")
        || name.contains("message")
        || name.contains("content")
        || name.contains("text")
    {
        return FieldType::FreeText;
    }
    FieldType::Unknown
}

pub fn analyze_field(field_name: &str, value: &str, field_type: FieldType) -> Vec<FieldAnomaly> {
    let mut anomalies = Vec::new();
    let path = field_name.to_owned();
    let v = value.trim();
    let lower = v.to_ascii_lowercase();

    let sql = looks_like_sql_injection(&lower);
    let xss = looks_like_xss(&lower);
    let cmd = looks_like_cmd_injection(&lower);

    match field_type {
        FieldType::Email => {
            if !looks_like_email(v) {
                anomalies.push(anomaly(field_name, &path, "invalid email shape"));
            }
            if sql {
                anomalies.push(anomaly(field_name, &path, "unexpected SQL-like payload in email field"));
            }
            if xss {
                anomalies.push(anomaly(field_name, &path, "unexpected HTML/JS payload in email field"));
            }
        }
        FieldType::Numeric => {
            if !looks_like_numeric(v) {
                anomalies.push(anomaly(field_name, &path, "non-numeric data in numeric field"));
            }
            if xss {
                anomalies.push(anomaly(field_name, &path, "XSS-like payload in numeric field"));
            }
            if sql {
                anomalies.push(anomaly(field_name, &path, "SQL-like payload in numeric field"));
            }
        }
        FieldType::Boolean => {
            if !looks_like_boolean(v) {
                anomalies.push(anomaly(field_name, &path, "non-boolean data in boolean field"));
            }
            if xss || sql {
                anomalies.push(anomaly(field_name, &path, "injection-like payload in boolean field"));
            }
        }
        FieldType::Date => {
            if !looks_like_date(v) {
                anomalies.push(anomaly(field_name, &path, "unexpected date format"));
            }
            if sql || xss {
                anomalies.push(anomaly(field_name, &path, "injection-like payload in date field"));
            }
        }
        FieldType::Id => {
            if !looks_like_id(v) {
                anomalies.push(anomaly(field_name, &path, "unexpected ID format"));
            }
            if lower.contains("../") || lower.contains("..\\") {
                anomalies.push(anomaly(field_name, &path, "path traversal-like sequence in ID field"));
            }
        }
        FieldType::Url => {
            if !looks_like_url(v) {
                anomalies.push(anomaly(field_name, &path, "invalid URL format"));
            }
            if lower.contains("javascript:") || lower.contains("data:text/html") {
                anomalies.push(anomaly(field_name, &path, "executable URL scheme in URL field"));
            }
        }
        FieldType::FreeText | FieldType::Unknown => {
            if cmd {
                anomalies.push(anomaly(field_name, &path, "command injection-like payload"));
            }
        }
    }

    anomalies
}

pub fn detect_json_injection(body: &str) -> Vec<FieldAnomaly> {
    let mut anomalies = Vec::new();
    let preflight_depth_exceeded = json_depth_exceeds(body, MAX_JSON_DEPTH);
    if preflight_depth_exceeded {
        anomalies.push(anomaly(
            "$",
            "$",
            "excessive JSON nesting depth while analyzing payload",
        ));
    }

    let value = match serde_json::from_str::<Value>(body) {
        Ok(v) => v,
        Err(_) => return anomalies,
    };

    let mut max_depth_overflow = false;
    let mut type_map: HashMap<String, HashSet<&'static str>> = HashMap::new();
    let mut max_depth = 0usize;
    walk_json_for_anomalies(
        &value,
        "",
        0,
        &mut max_depth,
        &mut anomalies,
        &mut type_map,
        &mut max_depth_overflow,
    );

    if max_depth > 14 {
        anomalies.push(anomaly(
            "$",
            "$",
            "excessive JSON nesting depth may indicate parser abuse",
        ));
    }

    for (path, kinds) in &type_map {
        if kinds.len() > 1 {
            anomalies.push(anomaly(
                path,
                path,
                "JSON type confusion detected for same logical field",
            ));
        }
    }

    let mut logical_type_map: HashMap<String, HashSet<&'static str>> = HashMap::new();
    for (path, kinds) in &type_map {
        let logical = canonical_json_field(path);
        if logical.is_empty() {
            continue;
        }
        logical_type_map
            .entry(logical)
            .or_default()
            .extend(kinds.iter().copied());
    }
    for (logical, kinds) in logical_type_map {
        if kinds.len() > 1 {
            anomalies.push(anomaly(
                &logical,
                &logical,
                "JSON type confusion detected for same logical field",
            ));
        }
    }

    if max_depth_overflow {
        anomalies.push(anomaly(
            "$",
            "$",
            "excessive JSON nesting depth while analyzing payload",
        ));
    }

    for issue in detect_duplicate_json_keys_with_conflicts(body) {
        anomalies.push(issue);
    }

    anomalies
}

pub fn extract_all_string_values(json: &str) -> Vec<(String, String)> {
    if json_depth_exceeds(json, MAX_JSON_DEPTH) {
        return vec![("$".to_owned(), "<max-json-depth-exceeded>".to_owned())];
    }

    let value = match serde_json::from_str::<Value>(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut fields = Vec::new();
    let mut max_depth = 0usize;
    let mut depth_exceeded = false;
    walk_json_strings(&value, "", 0, &mut max_depth, &mut depth_exceeded, &mut fields);
    if depth_exceeded {
        fields.push(("$".to_owned(), "<max-json-depth-exceeded>".to_owned()));
    }
    fields
}

pub fn detect_multipart_abuse(fields: &[MultipartField]) -> Vec<FieldAnomaly> {
    let mut anomalies = Vec::new();
    for field in fields {
        let path = if field.name.is_empty() {
            "$multipart".to_owned()
        } else {
            field.name.clone()
        };

        if field.name.trim().is_empty() {
            anomalies.push(anomaly("multipart", &path, "multipart field with missing name"));
        }

        if field.body.contains("\r\n--") || field.body.contains("\n--") {
            anomalies.push(anomaly(
                &field.name,
                &path,
                "embedded boundary marker inside multipart body",
            ));
        }

        if field.body.to_ascii_lowercase().contains("content-disposition:") {
            anomalies.push(anomaly(
                &field.name,
                &path,
                "nested multipart headers inside field body",
            ));
        }

        if let Some(filename) = &field.filename {
            let lower = filename.to_ascii_lowercase();
            if lower.contains("../") || lower.contains("..\\") {
                anomalies.push(anomaly(
                    &field.name,
                    &path,
                    "filename path traversal sequence detected",
                ));
            }
            if has_double_extension(&lower) {
                anomalies.push(anomaly(
                    &field.name,
                    &path,
                    "double-extension filename may bypass filters",
                ));
            }
            if let Some(ct) = &field.content_type {
                if extension_content_type_mismatch(&lower, ct) {
                    anomalies.push(anomaly(
                        &field.name,
                        &path,
                        "filename extension and content-type mismatch",
                    ));
                }
            }
        }
    }
    anomalies
}

fn parse_json_body(body: &str) -> Option<JsonBody> {
    if json_depth_exceeds(body, MAX_JSON_DEPTH) {
        return Some(JsonBody {
            fields: vec![("$".to_owned(), "<max-json-depth-exceeded>".to_owned())],
            max_depth: MAX_JSON_DEPTH,
        });
    }

    let value = serde_json::from_str::<Value>(body).ok()?;
    let mut fields = Vec::new();
    let mut max_depth = 0usize;
    let mut max_depth_overflow = false;
    walk_json_fields(
        &value,
        "",
        0,
        &mut max_depth,
        &mut fields,
        &mut max_depth_overflow,
    );
    if max_depth_overflow {
        fields.push(("$".to_owned(), "<max-json-depth-exceeded>".to_owned()));
    }
    Some(JsonBody { fields, max_depth })
}

fn parse_form_urlencoded(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .take(MAX_FORM_FIELDS)
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let mut split = pair.splitn(2, '=');
            let key = truncate_string(
                &percent_decode(split.next().unwrap_or_default()),
                MAX_FORM_FIELD_NAME_LEN,
            );
            let val = truncate_string(
                &percent_decode(split.next().unwrap_or_default()),
                MAX_FORM_FIELD_VALUE_LEN,
            );
            (key, val)
        })
        .collect()
}

fn extract_boundary(content_type: &str) -> Option<String> {
    for part in content_type.split(';').map(str::trim) {
        if let Some(v) = part.strip_prefix("boundary=") {
            let trimmed = v.trim_matches('"').trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }
    None
}

fn parse_multipart(body: &str, boundary: &str) -> Vec<MultipartField> {
    let marker = format!("--{boundary}");
    let mut out = Vec::new();

    for part in body.split(&marker) {
        let p = part.trim_matches('\r').trim_matches('\n').trim();
        if p.is_empty() || p == "--" {
            continue;
        }
        let p = p.trim_end_matches("--").trim();

        let (headers, content) = if let Some((h, c)) = p.split_once("\r\n\r\n") {
            (h, c)
        } else if let Some((h, c)) = p.split_once("\n\n") {
            (h, c)
        } else {
            continue;
        };

        let mut field = MultipartField::default();
        field.body = content.trim_matches('\r').trim_matches('\n').to_owned();

        for line in headers.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-disposition:") {
                for token in line.split(';').map(str::trim) {
                    if let Some(name) = token.strip_prefix("name=") {
                        field.name = truncate_string(
                            name.trim_matches('"'),
                            MAX_MULTIPART_FIELD_NAME_LEN,
                        );
                    } else if let Some(fname) = token.strip_prefix("filename=") {
                        field.filename = Some(truncate_string(
                            fname.trim_matches('"'),
                            MAX_MULTIPART_FILENAME_LEN,
                        ));
                    }
                }
            } else if lower.starts_with("content-type:") {
                if let Some((_, v)) = line.split_once(':') {
                    field.content_type = Some(v.trim().to_owned());
                }
            }
        }
        if field.body.len() > MAX_MULTIPART_FIELD_VALUE_LEN {
            field.body = truncate_string(&field.body, MAX_MULTIPART_FIELD_VALUE_LEN);
        }
        out.push(field);
    }

    out
}

pub fn detect_multipart_boundary_confusion(body: &str, boundary: Option<&str>) -> Vec<FieldAnomaly> {
    let mut anomalies = Vec::new();
    let boundary = match boundary {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            anomalies.push(anomaly("multipart", "$", "multipart body has missing boundary"));
            return anomalies;
        }
    };

    if boundary.len() > MAX_MULTIPART_BOUNDARY_LEN {
        anomalies.push(anomaly("multipart", "$", "multipart boundary length exceeds safe threshold"));
    }

    if boundary.contains(' ') || boundary.contains('\r') || boundary.contains('\n') {
        anomalies.push(anomaly("multipart", "$", "multipart boundary contains invalid control/spacing characters"));
    }

    let marker = format!("--{boundary}");
    let final_marker = format!("--{boundary}--");
    let mut saw_boundary_marker = false;
    for line in body.lines() {
        let trimmed = line.trim();

        if trimmed == marker || trimmed == final_marker {
            saw_boundary_marker = true;
            continue;
        }

        if trimmed.starts_with(&marker) {
            anomalies.push(anomaly(
                "multipart",
                "$",
                "multipart boundary marker malformed in body framing",
            ));
            saw_boundary_marker = true;
            continue;
        }

        if line.contains(&marker) {
            anomalies.push(anomaly(
                "multipart",
                "$",
                "multipart boundary marker appears in body content",
            ));
            break;
        }
    }

    if !saw_boundary_marker {
        anomalies.push(anomaly("multipart", "$", "multipart boundary marker missing"));
    }

    if anomalies.is_empty() {
        anomalies
    } else {
        anomalies
    }
}

pub fn detect_chunked_encoding_abuse(body: &str) -> Vec<FieldAnomaly> {
    let mut anomalies = Vec::new();
    let mut idx = 0usize;
    let bytes = body.as_bytes();
    let mut chunks = 0usize;
    let mut had_chunked = false;
    let mut saw_zero_chunk = false;

    while idx < bytes.len() {
        let rest = &bytes[idx..];
        let Some((line_end, consume_len)) = next_line_ending(rest) else {
            if had_chunked {
                anomalies.push(anomaly("body", "$", "truncated chunked body"));
            }
            break;
        };

        let size_line = &body[idx..idx + line_end];
        let size_token = size_line.split(';').next().unwrap_or_default().trim();
        idx += line_end + consume_len;

        if size_token.is_empty() {
            anomalies.push(anomaly("body", "$", "invalid chunk size line"));
            break;
        }

        if !size_token.chars().all(|c| c.is_ascii_hexdigit()) {
            anomalies.push(anomaly("body", "$", "invalid chunk size token"));
            break;
        }

        let size = usize::from_str_radix(size_token, 16).unwrap_or(0);
        had_chunked = true;
        chunks += 1;

        if chunks > 64 {
            anomalies.push(anomaly("body", "$", "excessive chunk count detected"));
            break;
        }

        if size == 0 {
            saw_zero_chunk = true;
        }

        if idx + size > bytes.len() {
            anomalies.push(anomaly("body", "$", "chunked transfer length mismatch"));
            break;
        }
        idx += size;

        if idx + consume_len > bytes.len() {
            anomalies.push(anomaly("body", "$", "chunked transfer malformed terminator"));
            break;
        }

        if &bytes[idx..idx + consume_len] != b"\r\n" && &bytes[idx..idx + consume_len] != b"\n" {
            anomalies.push(anomaly("body", "$", "chunked transfer malformed terminator"));
            break;
        }
        idx += consume_len;

        if size == 0 && consume_len == 2 && idx + 1 < bytes.len() {
            if bytes[idx] == b'\r' && idx + 1 < bytes.len() && bytes[idx + 1] == b'\n' {
                idx += 2;
            }
        }

        if size == 0 {
            saw_zero_chunk = true;
            break;
        }
    }

    if had_chunked && !saw_zero_chunk && anomalies.is_empty() {
        anomalies.push(anomaly("body", "$", "missing terminal zero-length chunk"));
    }

    if had_chunked && anomalies.is_empty() {
        anomalies.push(anomaly("body", "$", "chunked transfer encoding-like body detected"));
    }
    anomalies
}

fn next_line_ending(rest: &[u8]) -> Option<(usize, usize)> {
    if rest.is_empty() {
        return None;
    }

    if let Some(offset) = rest.windows(2).position(|w| w == b"\r\n") {
        return Some((offset, 2));
    }

    if let Some(offset) = rest.windows(1).position(|w| w == b"\n") {
        return Some((offset, 1));
    }

    None
}

fn looks_like_xml(body: &str) -> bool {
    let trimmed = body.trim();
    trimmed.starts_with('<') && trimmed.ends_with('>')
}

fn parse_xml_body(body: &str) -> Option<XmlBody> {
    let bytes = body.as_bytes();
    let mut i = 0usize;
    let mut stack: Vec<String> = Vec::new();
    let mut fields = Vec::new();

    while i < bytes.len() {
        if bytes[i] == b'<' {
            if i > 0 {
                let text = body[..i]
                    .rsplit_once('>')
                    .map(|(_, t)| t)
                    .unwrap_or_default()
                    .trim();
                if !text.is_empty() && !stack.is_empty() {
                    let path = format!("/{}", stack.join("/"));
                    fields.push((path, text.to_owned()));
                }
            }

            let close = body[i..].find('>')?;
            let end = i + close;
            let raw = body[i + 1..end].trim();

            if raw.starts_with('?') || raw.starts_with('!') {
                i = end + 1;
                continue;
            }
            if let Some(name) = raw.strip_prefix('/') {
                if stack.last().map(|s| s.as_str()) == Some(name.trim()) {
                    stack.pop();
                }
                i = end + 1;
                continue;
            }

            let self_closing = raw.ends_with('/');
            let content = raw.trim_end_matches('/').trim();
            let tag_name = content.split_whitespace().next().unwrap_or_default();
            if tag_name.is_empty() {
                i = end + 1;
                continue;
            }
            stack.push(tag_name.to_owned());
            let base_path = format!("/{}", stack.join("/"));

            for (attr, val) in extract_xml_attributes(content) {
                fields.push((format!("{base_path}/@{attr}"), val));
            }

            if self_closing {
                stack.pop();
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }

    if fields.is_empty() && stack.is_empty() && !looks_like_xml(body) {
        return None;
    }
    Some(XmlBody { fields })
}

fn extract_xml_attributes(tag_content: &str) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    let mut rest = tag_content.split_whitespace();
    let _tag = rest.next();
    for token in rest {
        if let Some((k, v)) = token.split_once('=') {
            attrs.push((k.to_owned(), v.trim_matches('"').trim_matches('\'').to_owned()));
        }
    }
    attrs
}

fn walk_json_fields(
    value: &Value,
    path: &str,
    depth: usize,
    max_depth: &mut usize,
    out: &mut Vec<(String, String)>,
    depth_exceeded: &mut bool,
) {
    *max_depth = (*max_depth).max(depth);
    if depth >= MAX_JSON_DEPTH {
        *depth_exceeded = true;
        return;
    }

    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let next = if path.is_empty() {
                    k.to_owned()
                } else {
                    format!("{path}.{k}")
                };
                walk_json_fields(v, &next, depth + 1, max_depth, out, depth_exceeded);
            }
        }
        Value::Array(arr) => {
            for (idx, v) in arr.iter().enumerate() {
                let next = if path.is_empty() {
                    format!("[{idx}]")
                } else {
                    format!("{path}[{idx}]")
                };
                walk_json_fields(v, &next, depth + 1, max_depth, out, depth_exceeded);
            }
        }
        Value::Null => {
            let key = truncate_string(path, MAX_JSON_KEY_LEN);
            out.push((key, "null".to_owned()));
        }
        Value::Bool(v) => {
            let key = truncate_string(path, MAX_JSON_KEY_LEN);
            out.push((key, truncate_string(&v.to_string(), MAX_JSON_VALUE_LEN)));
        }
        Value::Number(v) => {
            let key = truncate_string(path, MAX_JSON_KEY_LEN);
            out.push((key, truncate_string(&v.to_string(), MAX_JSON_VALUE_LEN)));
        }
        Value::String(v) => {
            let key = truncate_string(path, MAX_JSON_KEY_LEN);
            out.push((key, truncate_string(v, MAX_JSON_VALUE_LEN)));
        }
    }
}

fn walk_json_strings(
    value: &Value,
    path: &str,
    depth: usize,
    max_depth: &mut usize,
    depth_exceeded: &mut bool,
    out: &mut Vec<(String, String)>,
) {
    *max_depth = (*max_depth).max(depth);
    if depth >= MAX_JSON_DEPTH {
        *depth_exceeded = true;
        return;
    }

    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let next = if path.is_empty() {
                    k.to_owned()
                } else {
                    format!("{path}.{k}")
                };
                walk_json_strings(v, &next, depth + 1, max_depth, depth_exceeded, out);
            }
        }
        Value::Array(arr) => {
            for (idx, v) in arr.iter().enumerate() {
                let next = if path.is_empty() {
                    format!("[{idx}]")
                } else {
                    format!("{path}[{idx}]")
                };
                walk_json_strings(v, &next, depth + 1, max_depth, depth_exceeded, out);
            }
        }
        Value::String(v) => {
            let path = truncate_string(path, MAX_JSON_KEY_LEN);
            out.push((path, truncate_string(v, MAX_JSON_VALUE_LEN)));
        }
        _ => {}
    }
}

fn walk_json_for_anomalies(
    value: &Value,
    path: &str,
    depth: usize,
    max_depth: &mut usize,
    anomalies: &mut Vec<FieldAnomaly>,
    type_map: &mut HashMap<String, HashSet<&'static str>>,
    depth_exceeded: &mut bool,
) {
    *max_depth = (*max_depth).max(depth);
    if depth >= MAX_JSON_DEPTH {
        *depth_exceeded = true;
        return;
    }

    let kind = json_kind(value);
    if !path.is_empty() {
        type_map.entry(canonicalize_json_path(path)).or_default().insert(kind);
    }

    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let lower = k.to_ascii_lowercase();
                if lower == "__proto__" || lower == "constructor" || lower == "prototype" {
                    let kp = if path.is_empty() {
                        k.to_owned()
                    } else {
                        format!("{path}.{k}")
                    };
                    anomalies.push(anomaly(
                        k,
                        &kp,
                        "prototype-pollution key in JSON payload",
                    ));
                }
                let next = if path.is_empty() {
                    k.to_owned()
                } else {
                    format!("{path}.{k}")
                };
                walk_json_for_anomalies(
                    v,
                    &next,
                    depth + 1,
                    max_depth,
                    anomalies,
                    type_map,
                    depth_exceeded,
                );
            }
        }
        Value::Array(arr) => {
            for (idx, v) in arr.iter().enumerate() {
                let next = if path.is_empty() {
                    format!("[{idx}]")
                } else {
                    format!("{path}[{idx}]")
                };
                walk_json_for_anomalies(
                    v,
                    &next,
                    depth + 1,
                    max_depth,
                    anomalies,
                    type_map,
                    depth_exceeded,
                );
            }
        }
        _ => {}
    }
}

fn canonicalize_json_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut chars = path.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '[' {
            while let Some(next) = chars.peek() {
                if *next == ']' {
                    chars.next();
                    break;
                }
                chars.next();
            }
            continue;
        }
        out.push(ch);
    }

    out
}

fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn canonical_json_field(path: &str) -> String {
    let no_index = path
        .split('.')
        .last()
        .unwrap_or(path)
        .chars()
        .take_while(|c| *c != '[')
        .collect::<String>();
    no_index
}

fn extension_content_type_mismatch(filename: &str, content_type: &str) -> bool {
    let content_type = content_type.to_ascii_lowercase();
    let ext = filename.rsplit('.').next().unwrap_or_default();
    match ext {
        "png" | "jpg" | "jpeg" | "gif" => !content_type.starts_with("image/"),
        "json" => !content_type.contains("json"),
        "xml" => !content_type.contains("xml"),
        "txt" | "md" => !content_type.starts_with("text/"),
        "html" | "htm" => !content_type.contains("html"),
        "js" => !content_type.contains("javascript") && !content_type.contains("ecmascript"),
        "pdf" => !content_type.contains("pdf"),
        _ => false,
    }
}

fn has_double_extension(filename: &str) -> bool {
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() < 3 {
        return false;
    }
    let dangerous = ["php", "jsp", "aspx", "exe", "js", "sh", "bat"];
    parts.iter().skip(1).any(|ext| dangerous.contains(ext))
}

fn looks_like_sql_injection(lower: &str) -> bool {
    lower.contains(" or 1=1")
        || lower.contains(" union select")
        || lower.contains("'--")
        || lower.contains("';")
        || lower.contains(" drop table")
}

fn looks_like_xss(lower: &str) -> bool {
    lower.contains("<script")
        || lower.contains("javascript:")
        || lower.contains("onerror=")
        || lower.contains("onload=")
        || lower.contains("<img")
}

fn looks_like_cmd_injection(lower: &str) -> bool {
    lower.contains("&&")
        || lower.contains("||")
        || lower.contains("`")
        || lower.contains("$( ")
        || lower.contains("$(")
        || lower.contains(";cat ")
        || lower.contains(";wget ")
        || lower.contains(";curl ")
}

fn looks_like_email(v: &str) -> bool {
    let mut parts = v.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    parts.next().is_none() && !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
}

fn looks_like_numeric(v: &str) -> bool {
    let trimmed = v.trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed.parse::<f64>().is_ok()
}

fn looks_like_boolean(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "true" | "false" | "1" | "0" | "yes" | "no"
    )
}

fn looks_like_date(v: &str) -> bool {
    let lower = v.trim().to_ascii_lowercase();
    if lower.len() >= 10 && lower.chars().filter(|c| *c == '-').count() == 2 {
        return true;
    }
    if lower.contains('t') && lower.contains(':') {
        return true;
    }
    false
}

fn looks_like_id(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':' | '.'))
}

fn looks_like_url(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with('/')
}

fn anomaly(field_name: &str, path: &str, message: &str) -> FieldAnomaly {
    FieldAnomaly {
        field_name: field_name.to_owned(),
        field_path: path.to_owned(),
        message: message.to_owned(),
    }
}

fn percent_decode(s: &str) -> String {
    let s = s.replace('+', " ");
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn truncate_string(input: &str, max_len: usize) -> String {
    if input.len() <= max_len {
        input.to_owned()
    } else {
        input.chars().take(max_len).collect()
    }
}

fn detect_duplicate_json_keys_with_conflicts(body: &str) -> Vec<FieldAnomaly> {
    let bytes = body.as_bytes();
    let mut idx = 0usize;
    let mut max_depth = 0usize;
    let mut depth_overflow = false;
    let mut anomalies = Vec::new();

    skip_json_ws(bytes, &mut idx);
    if idx >= bytes.len() {
        return anomalies;
    }

    match bytes[idx] {
        b'{' => {
            let _ = scan_duplicate_json_object(
                body,
                &mut idx,
                "",
                0,
                &mut max_depth,
                &mut depth_overflow,
                &mut anomalies,
            );
        }
        b'[' => {
            let _ = scan_duplicate_json_array(
                body,
                &mut idx,
                "",
                0,
                &mut max_depth,
                &mut depth_overflow,
                &mut anomalies,
            );
        }
        _ => {}
    }

    if depth_overflow {
        anomalies.push(anomaly(
            "$",
            "$",
            "excessive JSON nesting depth while checking duplicate keys",
        ));
    }

    anomalies
}

fn scan_duplicate_json_object(
    body: &str,
    idx: &mut usize,
    path: &str,
    depth: usize,
    max_depth: &mut usize,
    depth_overflow: &mut bool,
    anomalies: &mut Vec<FieldAnomaly>,
) -> Option<usize> {
    let bytes = body.as_bytes();
    if *idx >= bytes.len() || bytes[*idx] != b'{' {
        return None;
    }

    *max_depth = (*max_depth).max(depth);
    if depth >= MAX_JSON_DEPTH {
        *depth_overflow = true;
        return None;
    }

    *idx += 1;
    skip_json_ws(bytes, idx);

    if *idx >= bytes.len() {
        return None;
    }

    if bytes[*idx] == b'}' {
        *idx += 1;
        return Some(*idx);
    }

    let mut seen = HashMap::new();

    loop {
    let key = parse_json_string(body, idx)?;

        skip_json_ws(bytes, idx);
        if *idx >= bytes.len() || bytes[*idx] != b':' {
            return None;
        }
        *idx += 1;

        skip_json_ws(bytes, idx);
        if *idx >= bytes.len() {
            return None;
        }

        let child_path = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };

        let value_start = *idx;
        let value_end = match bytes[*idx] {
            b'{' => scan_duplicate_json_object(
                body,
                idx,
                &child_path,
                depth + 1,
                max_depth,
                depth_overflow,
                anomalies,
            )?,
            b'[' => scan_duplicate_json_array(
                body,
                idx,
                &child_path,
                depth + 1,
                max_depth,
                depth_overflow,
                anomalies,
            )?,
            _ => {
                parse_json_primitive_end(body, idx)?;
                *idx
            }
        };

        let canonical_key = truncate_string(&key, MAX_JSON_KEY_LEN);
        let value = normalize_json_fragment(body, value_start, value_end);

        if let Some(prev) = seen.get(&canonical_key) {
            if prev != &value {
                anomalies.push(anomaly(
                    &canonical_key,
                    &truncate_string(&child_path, MAX_JSON_KEY_LEN),
                    "duplicate JSON key with conflicting values",
                ));
            }
        } else {
            seen.insert(canonical_key.clone(), value);
        }

        skip_json_ws(bytes, idx);
        if *idx >= bytes.len() {
            return None;
        }
        if bytes[*idx] == b',' {
            *idx += 1;
            skip_json_ws(bytes, idx);
            continue;
        }
        if bytes[*idx] == b'}' {
            *idx += 1;
            return Some(*idx);
        }
        return None;
    }
}

fn scan_duplicate_json_array(
    body: &str,
    idx: &mut usize,
    path: &str,
    depth: usize,
    max_depth: &mut usize,
    depth_overflow: &mut bool,
    anomalies: &mut Vec<FieldAnomaly>,
) -> Option<usize> {
    let bytes = body.as_bytes();
    if *idx >= bytes.len() || bytes[*idx] != b'[' {
        return None;
    }

    *max_depth = (*max_depth).max(depth);
    if depth >= MAX_JSON_DEPTH {
        *depth_overflow = true;
        return None;
    }

    *idx += 1;
    skip_json_ws(bytes, idx);

    if *idx >= bytes.len() {
        return None;
    }

    if bytes[*idx] == b']' {
        *idx += 1;
        return Some(*idx);
    }

    let mut item = 0usize;
    loop {
        skip_json_ws(bytes, idx);
        if *idx >= bytes.len() {
            return None;
        }

        let item_path = if path.is_empty() {
            format!("[{item}]")
        } else {
            format!("{path}[{item}]")
        };

        match bytes[*idx] {
            b'{' => {
                let _ = scan_duplicate_json_object(
                    body,
                    idx,
                    &item_path,
                    depth + 1,
                    max_depth,
                    depth_overflow,
                    anomalies,
                )?;
            }
            b'[' => {
                let _ = scan_duplicate_json_array(
                    body,
                    idx,
                    &item_path,
                    depth + 1,
                    max_depth,
                    depth_overflow,
                    anomalies,
                )?;
            }
            _ => {
                parse_json_primitive_end(body, idx)?;
            }
        }

        skip_json_ws(bytes, idx);
        if *idx >= bytes.len() {
            return None;
        }
        if bytes[*idx] == b',' {
            item += 1;
            *idx += 1;
            continue;
        }
        if bytes[*idx] == b']' {
            *idx += 1;
            return Some(*idx);
        }
        return None;
    }
}

fn parse_json_primitive_end(body: &str, idx: &mut usize) -> Option<usize> {
    let bytes = body.as_bytes();
    if *idx >= bytes.len() {
        return None;
    }

    match bytes[*idx] {
        b'"' => {
            parse_json_string(body, idx)?;
            Some(*idx)
        }
        b'-' | b'0'..=b'9' => {
            let start = *idx;
            *idx += 1;
            while *idx < bytes.len() {
                let b = bytes[*idx];
                if !(b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-')) {
                    break;
                }
                *idx += 1;
            }
            if *idx == start {
                None
            } else {
                Some(*idx)
            }
        }
        _ => {
            let s = &body[*idx..];
            if s.starts_with("true") {
                *idx += 4;
                return Some(*idx);
            }
            if s.starts_with("false") {
                *idx += 5;
                return Some(*idx);
            }
            if s.starts_with("null") {
                *idx += 4;
                return Some(*idx);
            }
            None
        }
    }
}

fn parse_json_string(body: &str, idx: &mut usize) -> Option<String> {
    let bytes = body.as_bytes();
    if *idx >= bytes.len() || bytes[*idx] != b'"' {
        return None;
    }

    let start = *idx;
    *idx += 1;
    let mut escaped = false;

    while *idx < body.len() {
        let b = bytes[*idx];
        if escaped {
            *idx += 1;
            escaped = false;
            continue;
        }
        if b == b'\\' {
            escaped = true;
            *idx += 1;
            continue;
        }
        if b == b'"' {
            *idx += 1;
            break;
        }
        if b < 0x80 {
            *idx += 1;
            continue;
        }
        let ch = body[*idx..].chars().next()?;
        *idx += ch.len_utf8();
    }

    let raw = body.get(start..*idx)?;
    let parsed: Value = serde_json::from_str(raw).ok()?;
    if let Value::String(decoded) = parsed {
        Some(decoded)
    } else {
        None
    }
}

fn json_depth_exceeds(body: &str, max_depth: usize) -> bool {
    let bytes = body.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
                i += 1;
                continue;
            }
            if b == b'\\' {
                escaped = true;
                i += 1;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        match b {
            b'"' => {
                in_string = true;
            }
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > max_depth {
                    return true;
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
        i += 1;
    }

    false
}

fn skip_json_ws(bytes: &[u8], idx: &mut usize) {
    while *idx < bytes.len() && bytes[*idx].is_ascii_whitespace() {
        *idx += 1;
    }
}

fn normalize_json_fragment(body: &str, start: usize, end: usize) -> String {
    let raw = body.get(start..end).unwrap_or_default().trim();
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        serde_json::to_string(&value).unwrap_or_else(|_| raw.to_string())
    } else {
        raw.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_body_extracts_nested_paths() {
        let body = r#"{"user":{"email":"a@b.com"},"items":[{"name":"pen"}]}"#;
        let parsed = parse_body(Some("application/json"), body);
        match parsed {
            ParsedBody::Json(json) => {
                assert!(json.fields.contains(&("user.email".into(), "a@b.com".into())));
                assert!(json.fields.contains(&("items[0].name".into(), "pen".into())));
            }
            _ => panic!("expected json"),
        }
    }

    #[test]
    fn parse_form_urlencoded_decodes_values() {
        let parsed = parse_body(
            Some("application/x-www-form-urlencoded"),
            "email=test%40example.com&name=John+Doe",
        );
        match parsed {
            ParsedBody::FormUrlEncoded(fields) => {
                assert!(fields.contains(&("email".into(), "test@example.com".into())));
                assert!(fields.contains(&("name".into(), "John Doe".into())));
            }
            _ => panic!("expected form"),
        }
    }

    #[test]
    fn parse_multipart_extracts_field_metadata() {
        let body = "--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--abc--";
        let parsed = parse_body(
            Some("multipart/form-data; boundary=abc"),
            body,
        );
        match parsed {
            ParsedBody::Multipart(fields) => {
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].name, "file");
                assert_eq!(fields[0].filename.as_deref(), Some("a.txt"));
                assert_eq!(fields[0].content_type.as_deref(), Some("text/plain"));
                assert_eq!(fields[0].body, "hello");
            }
            _ => panic!("expected multipart"),
        }
    }

    #[test]
    fn detect_json_injection_depth_guard_for_nested_payloads() {
        let mut nested = String::from("{\"x\":");
        for _ in 0..180 {
            nested.push_str("{\"x\":");
        }
        nested.push('"');
        nested.push('x');
        nested.push('"');
        for _ in 0..181 {
            nested.push('}');
        }
        let anomalies = detect_json_injection(&nested);
        assert!(anomalies.iter().any(|a| a.message.contains("excessive JSON nesting")));
    }

    #[test]
    fn extract_all_string_values_depth_guarded() {
        let mut nested = String::from("[");
        for _ in 0..180 {
            nested.push_str("[{\"x\":\"y\"},");
        }
        nested.push_str("{\"x\":\"y\"}");
        for _ in 0..181 {
            nested.push(']');
        }
        let fields = extract_all_string_values(&nested);
        assert_eq!(fields.len(), 1);
        assert!(fields.contains(&("$".to_owned(), "<max-json-depth-exceeded>".to_owned())));
    }

    #[test]
    fn detect_duplicate_json_keys_with_conflicting_values() {
        let anomalies =
            detect_json_injection(r#"{"profile":{"role":"admin","role":"user"},"role":"guest"}"#);
        assert!(anomalies.iter().any(|a| a.message.contains("duplicate JSON key with conflicting values")));
    }

    #[test]
    fn detect_multipart_boundary_confusion_with_embedded_marker_and_missing_boundary() {
        let body = "line1\n--abc-attack\nvalue--abc--\n--abc\n";
        let anomalies = detect_multipart_boundary_confusion(body, Some("abc"));
        assert!(anomalies.iter().any(|a| a.message.contains("appears in body content")));

        let missing = detect_multipart_boundary_confusion("just text", None);
        assert!(missing.iter().any(|a| a.message.contains("missing boundary")));
    }

    #[test]
    fn detect_chunked_encoding_abuse_invalid_size_or_truncated_body() {
        let invalid_size = "G\r\nabc\r\n0\r\n\r\n";
        let invalid_size_anomalies = detect_chunked_encoding_abuse(invalid_size);
        assert!(invalid_size_anomalies
            .iter()
            .any(|a| a.message.contains("invalid chunk size token")));

        let truncated = "4\r\nabc";
        let truncated_anomalies = detect_chunked_encoding_abuse(truncated);
        assert!(truncated_anomalies
            .iter()
            .any(|a| a.message.contains("truncated chunked body") || a.message.contains("length mismatch")));
    }

    #[test]
    fn detect_chunked_encoding_abuse_excessive_chunk_count() {
        let mut body = String::new();
        for _ in 0..70 {
            body.push_str("1\r\na\r\n");
        }
        body.push_str("0\r\n\r\n");
        let anomalies = detect_chunked_encoding_abuse(&body);
        assert!(anomalies.iter().any(|a| a.message.contains("excessive chunk count")));
    }

    #[test]
    fn parse_form_urlencoded_truncates_oversized_field_name_and_value() {
        let long_name = "n".repeat(1024);
        let long_value = "v".repeat(5000);
        let parsed = parse_form_urlencoded(&format!("{long_name}={long_value}"));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.len(), MAX_FORM_FIELD_NAME_LEN);
        assert!(parsed[0].1.len() <= MAX_FORM_FIELD_VALUE_LEN);
        assert_eq!(parsed[0].1.len(), MAX_FORM_FIELD_VALUE_LEN);
    }

    #[test]
    fn parse_multipart_truncates_oversized_parts() {
        let long_name = "n".repeat(1024);
        let long_value = "v".repeat(5000);
        let long_filename = "f".repeat(1024);
        let body = format!(
            "--abc\r\nContent-Disposition: form-data; name=\"{long_name}\"; filename=\"{long_filename}\"\r\n\r\n{long_value}\r\n--abc--"
        );
        let fields = parse_multipart(&body, "abc");
        assert_eq!(fields.len(), 1);
        assert!(fields[0].name.len() <= MAX_MULTIPART_FIELD_NAME_LEN);
        assert!(fields[0].filename.as_ref().is_some_and(|name| name.len() <= MAX_MULTIPART_FILENAME_LEN));
        assert!(fields[0].body.len() <= MAX_MULTIPART_FIELD_VALUE_LEN);
    }

    #[test]
    fn parse_xml_extracts_elements_and_attributes() {
        let body = r#"<root><user id="42"><email>x@y.com</email></user></root>"#;
        let parsed = parse_body(Some("application/xml"), body);
        match parsed {
            ParsedBody::Xml(xml) => {
                assert!(xml.fields.contains(&("/root/user/@id".into(), "42".into())));
                assert!(xml.fields.contains(&("/root/user/email".into(), "x@y.com".into())));
            }
            _ => panic!("expected xml"),
        }
    }

    #[test]
    fn infer_field_type_by_name_heuristics() {
        assert_eq!(infer_field_type("emailAddress"), FieldType::Email);
        assert_eq!(infer_field_type("profile_url"), FieldType::Url);
        assert_eq!(infer_field_type("user_id"), FieldType::Id);
        assert_eq!(infer_field_type("total_amount"), FieldType::Numeric);
        assert_eq!(infer_field_type("is_active"), FieldType::Boolean);
        assert_eq!(infer_field_type("created_at"), FieldType::Date);
    }

    #[test]
    fn analyze_field_detects_sql_in_email() {
        let anomalies = analyze_field("email", "a' OR 1=1--@x.com", FieldType::Email);
        assert!(!anomalies.is_empty());
        assert!(anomalies.iter().any(|a| a.message.contains("SQL")));
    }

    #[test]
    fn analyze_field_detects_xss_in_numeric() {
        let anomalies = analyze_field("amount", "<script>alert(1)</script>", FieldType::Numeric);
        assert!(anomalies.iter().any(|a| a.message.contains("XSS")));
    }

    #[test]
    fn detect_json_injection_finds_proto_pollution_keys() {
        let anomalies = detect_json_injection(r#"{"user":{"__proto__":{"admin":true}}}"#);
        assert!(anomalies.iter().any(|a| a.message.contains("prototype-pollution")));
    }

    #[test]
    fn detect_json_injection_finds_type_confusion() {
        let anomalies = detect_json_injection(r#"{"x":"1","arr":[{"x":1},{"x":"2"}]}"#);
        assert!(anomalies.iter().any(|a| a.message.contains("type confusion")));
    }

    #[test]
    fn extract_all_string_values_returns_only_strings() {
        let fields = extract_all_string_values(r#"{"a":"x","b":1,"c":[{"d":"y"}]}"#);
        assert_eq!(fields.len(), 2);
        assert!(fields.contains(&("a".into(), "x".into())));
        assert!(fields.contains(&("c[0].d".into(), "y".into())));
    }

    #[test]
    fn detect_multipart_abuse_filename_traversal_and_double_ext() {
        let fields = vec![MultipartField {
            name: "upload".into(),
            filename: Some("../shell.php.jpg".into()),
            content_type: Some("image/jpeg".into()),
            body: "x".into(),
        }];
        let anomalies = detect_multipart_abuse(&fields);
        assert!(anomalies.iter().any(|a| a.message.contains("traversal")));
        assert!(anomalies.iter().any(|a| a.message.contains("double-extension")));
    }

    #[test]
    fn detect_multipart_abuse_content_type_mismatch() {
        let fields = vec![MultipartField {
            name: "upload".into(),
            filename: Some("script.js".into()),
            content_type: Some("image/png".into()),
            body: "alert(1)".into(),
        }];
        let anomalies = detect_multipart_abuse(&fields);
        assert!(anomalies.iter().any(|a| a.message.contains("mismatch")));
    }

    #[test]
    fn parse_unknown_is_raw() {
        let parsed = parse_body(Some("text/plain"), "hello");
        assert_eq!(parsed, ParsedBody::Raw("hello".into()));
    }

    #[test]
    fn json_detection_handles_invalid_json_gracefully() {
        assert!(detect_json_injection("{bad json").is_empty());
        assert!(extract_all_string_values("{bad json").is_empty());
    }
}
