use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    MissingHeader,
    WeakHeader,
    HeaderBypassRisk,
    ContentTypeMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefenseFinding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub message: String,
    pub header: Option<String>,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DefenseValidationInput {
    pub request_headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DefenseValidationReport {
    pub findings: Vec<DefenseFinding>,
    pub passed: bool,
    pub missing_security_headers: usize,
    pub weak_security_headers: usize,
    pub bypass_risks: usize,
    pub content_type_matches: bool,
}

pub fn validate_defense(input: &DefenseValidationInput) -> DefenseValidationReport {
    let headers = normalized_headers(&input.response_headers);
    let req_headers = normalized_headers(&input.request_headers);
    let mut findings = Vec::new();

    findings.extend(validate_core_security_headers(&headers));
    findings.extend(validate_csp(&headers));
    findings.extend(validate_cors(&headers, &req_headers));
    findings.extend(validate_x_frame_options(&headers));
    findings.extend(validate_nosniff_bypass_risk(
        &headers,
        input.body.as_deref(),
    ));
    findings.extend(validate_content_type_alignment(
        &headers,
        input.body.as_deref(),
    ));

    let missing_security_headers = findings
        .iter()
        .filter(|f| f.kind == FindingKind::MissingHeader)
        .count();
    let weak_security_headers = findings
        .iter()
        .filter(|f| f.kind == FindingKind::WeakHeader)
        .count();
    let bypass_risks = findings
        .iter()
        .filter(|f| f.kind == FindingKind::HeaderBypassRisk)
        .count();
    let content_type_matches = findings
        .iter()
        .all(|f| f.kind != FindingKind::ContentTypeMismatch);

    DefenseValidationReport {
        passed: findings.is_empty(),
        findings,
        missing_security_headers,
        weak_security_headers,
        bypass_risks,
        content_type_matches,
    }
}

fn normalized_headers(headers: &[(String, String)]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (k, v) in headers {
        map.insert(k.to_ascii_lowercase(), v.trim().to_ascii_lowercase());
    }
    map
}

fn validate_core_security_headers(headers: &HashMap<String, String>) -> Vec<DefenseFinding> {
    let mut findings = Vec::new();
    let required = [
        ("content-security-policy", Severity::High),
        ("x-frame-options", Severity::Medium),
        ("x-content-type-options", Severity::Medium),
        ("access-control-allow-origin", Severity::Medium),
    ];

    for (header, severity) in required {
        if !headers.contains_key(header) {
            findings.push(DefenseFinding {
                kind: FindingKind::MissingHeader,
                severity,
                message: format!("missing security header `{header}`"),
                header: Some(header.to_owned()),
                evidence: None,
            });
        }
    }
    findings
}

fn validate_csp(headers: &HashMap<String, String>) -> Vec<DefenseFinding> {
    let mut findings = Vec::new();
    let Some(csp) = headers.get("content-security-policy") else {
        return findings;
    };

    if !csp.contains("default-src") {
        findings.push(DefenseFinding {
            kind: FindingKind::WeakHeader,
            severity: Severity::Medium,
            message: "content-security-policy is missing `default-src`".to_owned(),
            header: Some("content-security-policy".to_owned()),
            evidence: Some(csp.clone()),
        });
    }

    if csp.contains("'unsafe-inline'") || csp.contains("'unsafe-eval'") {
        findings.push(DefenseFinding {
            kind: FindingKind::WeakHeader,
            severity: Severity::High,
            message: "content-security-policy allows unsafe script execution".to_owned(),
            header: Some("content-security-policy".to_owned()),
            evidence: Some(csp.clone()),
        });
    }

    findings
}

fn validate_cors(
    headers: &HashMap<String, String>,
    request_headers: &HashMap<String, String>,
) -> Vec<DefenseFinding> {
    let mut findings = Vec::new();

    let origin = request_headers.get("origin").cloned();
    let acao = headers.get("access-control-allow-origin").cloned();
    let acc = headers
        .get("access-control-allow-credentials")
        .map(|v| v == "true")
        .unwrap_or(false);

    if let Some(acao) = acao {
        if acao == "*" && acc {
            findings.push(DefenseFinding {
                kind: FindingKind::WeakHeader,
                severity: Severity::High,
                message: "CORS allows wildcard origin with credentials".to_owned(),
                header: Some("access-control-allow-origin".to_owned()),
                evidence: Some("acao=* with access-control-allow-credentials=true".to_owned()),
            });
        }

        if acao == "null" {
            findings.push(DefenseFinding {
                kind: FindingKind::WeakHeader,
                severity: Severity::Medium,
                message: "CORS allows `null` origin".to_owned(),
                header: Some("access-control-allow-origin".to_owned()),
                evidence: Some(acao.clone()),
            });
        }

        if let Some(origin) = origin {
            if acao == origin && !is_trusted_origin(&origin) {
                findings.push(DefenseFinding {
                    kind: FindingKind::HeaderBypassRisk,
                    severity: Severity::High,
                    message: "CORS appears to reflect arbitrary Origin header".to_owned(),
                    header: Some("access-control-allow-origin".to_owned()),
                    evidence: Some(format!("origin reflected: {origin}")),
                });
            }
        }
    }

    findings
}

fn validate_x_frame_options(headers: &HashMap<String, String>) -> Vec<DefenseFinding> {
    let mut findings = Vec::new();

    if let Some(xfo) = headers.get("x-frame-options") {
        let v = xfo.trim();
        if v != "deny" && v != "sameorigin" {
            findings.push(DefenseFinding {
                kind: FindingKind::WeakHeader,
                severity: Severity::Medium,
                message: "x-frame-options should be `DENY` or `SAMEORIGIN`".to_owned(),
                header: Some("x-frame-options".to_owned()),
                evidence: Some(v.to_owned()),
            });
        }
    }

    findings
}

fn validate_nosniff_bypass_risk(
    headers: &HashMap<String, String>,
    body: Option<&str>,
) -> Vec<DefenseFinding> {
    let mut findings = Vec::new();

    let nosniff = headers
        .get("x-content-type-options")
        .map(|v| v.trim() == "nosniff")
        .unwrap_or(false);

    if !nosniff {
        findings.push(DefenseFinding {
            kind: FindingKind::HeaderBypassRisk,
            severity: Severity::Medium,
            message: "x-content-type-options missing or not `nosniff`".to_owned(),
            header: Some("x-content-type-options".to_owned()),
            evidence: headers.get("x-content-type-options").cloned(),
        });
    }

    if let Some(body) = body {
        if looks_like_active_content(body) && !nosniff {
            findings.push(DefenseFinding {
                kind: FindingKind::HeaderBypassRisk,
                severity: Severity::High,
                message: "active content served without nosniff allows MIME sniffing bypass"
                    .to_owned(),
                header: Some("x-content-type-options".to_owned()),
                evidence: Some(snippet(body, 120)),
            });
        }
    }

    findings
}

fn validate_content_type_alignment(
    headers: &HashMap<String, String>,
    body: Option<&str>,
) -> Vec<DefenseFinding> {
    let mut findings = Vec::new();
    let Some(body) = body else {
        return findings;
    };

    let actual = infer_content_type(body);
    let declared = headers
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| "".to_owned());

    if declared.is_empty() {
        findings.push(DefenseFinding {
            kind: FindingKind::MissingHeader,
            severity: Severity::Medium,
            message: "missing content-type header".to_owned(),
            header: Some("content-type".to_owned()),
            evidence: None,
        });
        return findings;
    }

    if !content_type_matches(&declared, actual) {
        findings.push(DefenseFinding {
            kind: FindingKind::ContentTypeMismatch,
            severity: Severity::High,
            message: "declared content-type does not match response body".to_owned(),
            header: Some("content-type".to_owned()),
            evidence: Some(format!("declared={declared}, inferred={actual}")),
        });
    }

    findings
}

fn infer_content_type(body: &str) -> &'static str {
    let trimmed = body.trim_start();

    if trimmed.starts_with("{") || trimmed.starts_with("[") {
        return "json";
    }
    if trimmed.starts_with("<") {
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("<html") || lower.contains("<!doctype html") {
            return "html";
        }
        return "xml";
    }

    static JS_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b(function|const|let|var)\b|=>|document\.|window\.").expect("valid regex")
    });
    if JS_RE.is_match(trimmed) {
        return "javascript";
    }

    "text"
}

fn content_type_matches(declared: &str, inferred: &str) -> bool {
    match inferred {
        "json" => declared.contains("json"),
        "html" => declared.contains("html"),
        "xml" => declared.contains("xml"),
        "javascript" => {
            declared.contains("javascript")
                || declared.contains("ecmascript")
                || declared.contains("text/plain")
        }
        _ => declared.contains("text") || declared.contains("octet-stream"),
    }
}

fn looks_like_active_content(body: &str) -> bool {
    static ACTIVE_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?is)<script|on\w+\s*=|javascript:|<iframe|<svg").expect("valid regex")
    });
    ACTIVE_RE.is_match(body)
}

fn is_trusted_origin(origin: &str) -> bool {
    origin.starts_with("https://")
        && (origin.ends_with(".example.com") || origin.contains("localhost"))
}

fn snippet(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> DefenseValidationInput {
        DefenseValidationInput {
            request_headers: vec![("Origin".into(), "https://evil.tld".into())],
            response_headers: vec![
                (
                    "Content-Security-Policy".into(),
                    "default-src 'self'".into(),
                ),
                ("X-Frame-Options".into(), "DENY".into()),
                ("X-Content-Type-Options".into(), "nosniff".into()),
                (
                    "Access-Control-Allow-Origin".into(),
                    "https://app.example.com".into(),
                ),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: Some("{\"ok\":true}".into()),
        }
    }

    #[test]
    fn passes_with_strong_headers_and_matching_content_type() {
        let report = validate_defense(&base_input());
        assert!(report.passed);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn detects_missing_core_headers() {
        let mut input = base_input();
        input.response_headers.clear();
        let report = validate_defense(&input);
        assert!(report.missing_security_headers >= 4);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("content-security-policy"))
        );
    }

    #[test]
    fn detects_weak_csp_unsafe_inline() {
        let mut input = base_input();
        input
            .response_headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("Content-Security-Policy"));
        input.response_headers.push((
            "Content-Security-Policy".into(),
            "default-src 'self'; script-src 'unsafe-inline'".into(),
        ));
        let report = validate_defense(&input);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("unsafe script execution"))
        );
    }

    #[test]
    fn detects_cors_wildcard_with_credentials() {
        let mut input = base_input();
        input
            .response_headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("Access-Control-Allow-Origin"));
        input
            .response_headers
            .push(("Access-Control-Allow-Origin".into(), "*".into()));
        input
            .response_headers
            .push(("Access-Control-Allow-Credentials".into(), "true".into()));
        let report = validate_defense(&input);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("wildcard origin"))
        );
    }

    #[test]
    fn detects_reflected_origin_bypass_risk() {
        let mut input = base_input();
        input
            .response_headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("Access-Control-Allow-Origin"));
        input.response_headers.push((
            "Access-Control-Allow-Origin".into(),
            "https://evil.tld".into(),
        ));
        let report = validate_defense(&input);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == FindingKind::HeaderBypassRisk && f.message.contains("reflect"))
        );
    }

    #[test]
    fn detects_invalid_x_frame_options() {
        let mut input = base_input();
        input
            .response_headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("X-Frame-Options"));
        input
            .response_headers
            .push(("X-Frame-Options".into(), "ALLOWALL".into()));
        let report = validate_defense(&input);
        assert!(report.findings.iter().any(|f| f.message.contains("DENY")));
    }

    #[test]
    fn detects_missing_nosniff_bypass_risk() {
        let mut input = base_input();
        input
            .response_headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("X-Content-Type-Options"));
        let report = validate_defense(&input);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("nosniff"))
        );
        assert!(report.bypass_risks >= 1);
    }

    #[test]
    fn detects_active_content_without_nosniff() {
        let mut input = base_input();
        input
            .response_headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("X-Content-Type-Options"));
        input.body = Some("<html><script>alert(1)</script></html>".into());
        input
            .response_headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("Content-Type"));
        input
            .response_headers
            .push(("Content-Type".into(), "text/html".into()));
        let report = validate_defense(&input);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("MIME sniffing bypass"))
        );
    }

    #[test]
    fn detects_content_type_mismatch() {
        let mut input = base_input();
        input.body = Some("<html><body>x</body></html>".into());
        input
            .response_headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("Content-Type"));
        input
            .response_headers
            .push(("Content-Type".into(), "application/json".into()));
        let report = validate_defense(&input);
        assert!(!report.content_type_matches);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == FindingKind::ContentTypeMismatch)
        );
    }

    #[test]
    fn detects_missing_content_type_header() {
        let mut input = base_input();
        input
            .response_headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("Content-Type"));
        let report = validate_defense(&input);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == FindingKind::MissingHeader
                    && f.header.as_deref() == Some("content-type"))
        );
    }

    #[test]
    fn allows_null_body_without_content_type_check() {
        let mut input = base_input();
        input.body = None;
        input
            .response_headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("Content-Type"));
        let report = validate_defense(&input);
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.kind != FindingKind::ContentTypeMismatch)
        );
    }
}
