//! Response-side security analysis for exploitation confirmation and data leakage.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::types::{InvariantClass, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFindingType {
    SqlErrorLeak,
    StackTraceLeak,
    SensitiveDataLeak,
    DirectoryListing,
    VersionDisclosure,
    MissingSecurityHeader,
    MisconfiguredSecurityHeader,
    ExploitConfirmation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseFinding {
    pub finding_type: ResponseFindingType,
    pub severity: Severity,
    pub detail: String,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ResponseAnalysis {
    pub findings: Vec<ResponseFinding>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExploitConfirmation {
    pub exploit_type: String,
    pub confidence: f64,
    pub detail: String,
    pub evidence: String,
}

pub fn analyze_response(
    status: u16,
    headers: &[(String, String)],
    body: &str,
    request_classes: &[InvariantClass],
) -> ResponseAnalysis {
    let mut findings = Vec::new();
    findings.extend(detect_sql_error_leak(body));
    findings.extend(detect_stack_trace_leak(body));
    findings.extend(detect_sensitive_data_leak(body));
    findings.extend(detect_directory_listing(body));
    findings.extend(detect_version_disclosure(body, headers));
    findings.extend(audit_security_headers(headers));

    if request_classes.iter().any(|c| {
        matches!(
            c,
            InvariantClass::SsrfInternalReach
                | InvariantClass::SsrfCloudMetadata
                | InvariantClass::SsrfProtocolSmuggle
        )
    }) {
        if let Some(confirm) = confirm_ssrf_success(status, body) {
            findings.push(confirmation_to_finding(confirm, Severity::Critical));
        }
    }

    dedupe_findings(findings)
}

pub fn detect_sql_error_leak(body: &str) -> Vec<ResponseFinding> {
    let patterns = [
        (
            "mysql",
            r"(?i)(you have an error in your sql syntax|warning:\s*mysql_|mysqli?_[a-z_]+\(|mysql server version for the right syntax)",
        ),
        (
            "postgresql",
            r"(?i)(pg::\w+error|postgresql.*error|org\.postgresql\.util\.psqlexception|error:\s*syntax error at or near)",
        ),
        (
            "mssql",
            r"(?i)(sqlserverexception|unclosed quotation mark after the character string|microsoft ole db provider for sql server|incorrect syntax near)",
        ),
        (
            "oracle",
            r"(?i)(ora-\d{5}|oracle error|quoted string not properly terminated)",
        ),
        (
            "sqlite",
            r#"(?i)(sqlite\.exception|sqlite/jdbcdriver|sqlite_error|near ".*": syntax error)"#,
        ),
    ];

    let mut findings = Vec::new();
    for (engine, pattern) in patterns {
        if let Some(ev) = first_regex_match(body, pattern) {
            findings.push(ResponseFinding {
                finding_type: ResponseFindingType::SqlErrorLeak,
                severity: Severity::High,
                detail: format!("{engine} error details disclosed in response"),
                evidence: ev,
            });
        }
    }
    findings
}

pub fn detect_stack_trace_leak(body: &str) -> Vec<ResponseFinding> {
    let patterns = [
        (
            "java",
            r"(?mi)(exception in thread|java\.lang\.\w+exception|^\s+at [\w.$_]+\(.*:\d+\))",
        ),
        (
            "python",
            r#"(?mi)(traceback \(most recent call last\):|^\s*file ".*", line \d+)"#,
        ),
        (
            "php",
            r"(?mi)(php fatal error|uncaught .*exception|stack trace:)",
        ),
        (
            ".net",
            r"(?mi)(system\.[\w.]+exception| at [\w.]+\(.*\) in .*:line \d+)",
        ),
        (
            "node.js",
            r"(?mi)(node:internal|^\s+at (?:new )?[\w.$<>\[\]]+\s+\(.*:\d+:\d+\)|referenceerror:|typeerror:)",
        ),
    ];

    let mut findings = Vec::new();
    for (runtime, pattern) in patterns {
        if let Some(ev) = first_regex_match(body, pattern) {
            findings.push(ResponseFinding {
                finding_type: ResponseFindingType::StackTraceLeak,
                severity: Severity::High,
                detail: format!("{runtime} stack trace leaked in response"),
                evidence: ev,
            });
        }
    }
    findings
}

pub fn detect_sensitive_data_leak(body: &str) -> Vec<ResponseFinding> {
    let mut findings = Vec::new();

    if let Some(ev) = first_regex_match(body, r"\b\d{3}-\d{2}-\d{4}\b") {
        findings.push(ResponseFinding {
            finding_type: ResponseFindingType::SensitiveDataLeak,
            severity: Severity::Critical,
            detail: "possible SSN exposed in response".to_owned(),
            evidence: ev,
        });
    }

    if let Some(card) = find_likely_credit_card(body) {
        findings.push(ResponseFinding {
            finding_type: ResponseFindingType::SensitiveDataLeak,
            severity: Severity::Critical,
            detail: "possible payment card number exposed in response".to_owned(),
            evidence: card,
        });
    }

    let key_patterns = [
        ("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b"),
        ("github_pat", r"\bghp_[A-Za-z0-9]{36}\b"),
        (
            "generic_api_key",
            r#"(?i)\b(api[_-]?key|access[_-]?token)\b\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']"#,
        ),
    ];
    for (kind, pattern) in key_patterns {
        if let Some(ev) = first_regex_match(body, pattern) {
            findings.push(ResponseFinding {
                finding_type: ResponseFindingType::SensitiveDataLeak,
                severity: Severity::Critical,
                detail: format!("{kind} exposed in response"),
                evidence: ev,
            });
        }
    }

    if let Some(ev) = first_regex_match(
        body,
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    ) {
        findings.push(ResponseFinding {
            finding_type: ResponseFindingType::SensitiveDataLeak,
            severity: Severity::Critical,
            detail: "private key material exposed in response".to_owned(),
            evidence: ev,
        });
    }

    if let Some(ev) = first_regex_match(
        body,
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    ) {
        findings.push(ResponseFinding {
            finding_type: ResponseFindingType::SensitiveDataLeak,
            severity: Severity::High,
            detail: "JWT token exposed in response".to_owned(),
            evidence: ev,
        });
    }

    findings
}

pub fn detect_directory_listing(body: &str) -> Vec<ResponseFinding> {
    let patterns = [
        r"(?i)<title>\s*index of /",
        r"(?i)<h1>\s*index of /",
        r"(?i)directory listing for /",
        r"(?i)parent directory</a>",
    ];

    let mut findings = Vec::new();
    for pattern in patterns {
        if let Some(ev) = first_regex_match(body, pattern) {
            findings.push(ResponseFinding {
                finding_type: ResponseFindingType::DirectoryListing,
                severity: Severity::Medium,
                detail: "directory listing appears exposed".to_owned(),
                evidence: ev,
            });
            break;
        }
    }
    findings
}

pub fn detect_version_disclosure(body: &str, headers: &[(String, String)]) -> Vec<ResponseFinding> {
    let mut findings = Vec::new();

    let interesting_headers = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-runtime",
        "x-generator",
    ];
    let version_re = Regex::new(r"(?i)\b(?:\d+\.){1,3}\d+\b").expect("valid version regex");

    for (name, value) in headers {
        if interesting_headers
            .iter()
            .any(|h| name.eq_ignore_ascii_case(h))
            && version_re.is_match(value)
        {
            findings.push(ResponseFinding {
                finding_type: ResponseFindingType::VersionDisclosure,
                severity: Severity::Low,
                detail: format!("version disclosed in response header `{name}`"),
                evidence: truncate(value, 120),
            });
        }
    }

    if let Some(ev) = first_regex_match(
        body,
        r"(?i)\b(apache|nginx|express|django|laravel|rails|spring|wordpress|tomcat|php)\s*/?\s*v?(?:\d+\.){1,3}\d+\b",
    ) {
        findings.push(ResponseFinding {
            finding_type: ResponseFindingType::VersionDisclosure,
            severity: Severity::Low,
            detail: "framework/server version appears in response body".to_owned(),
            evidence: ev,
        });
    }

    findings
}

pub fn confirm_sqli_success(
    request_input: &str,
    response_body: &str,
) -> Option<ExploitConfirmation> {
    if request_input.trim().is_empty() || response_body.is_empty() {
        return None;
    }
    let lower_body = response_body.to_ascii_lowercase();
    let reflected = response_body.contains(request_input);
    let has_error = !detect_sql_error_leak(response_body).is_empty();
    let extraction_markers = [
        "information_schema",
        "table_name",
        "column_name",
        "username",
        "password",
        "email",
        "rows in set",
    ];
    let extracted = extraction_markers.iter().any(|m| lower_body.contains(m));

    if reflected && has_error {
        return Some(ExploitConfirmation {
            exploit_type: "sqli".to_owned(),
            confidence: 0.95,
            detail: "request payload reflected alongside SQL parser error".to_owned(),
            evidence: truncate(request_input, 120),
        });
    }
    if extracted && request_input.to_ascii_lowercase().contains("select") {
        return Some(ExploitConfirmation {
            exploit_type: "sqli".to_owned(),
            confidence: 0.92,
            detail: "response contains SQL data extraction indicators".to_owned(),
            evidence: "information_schema/credential-like fields observed".to_owned(),
        });
    }
    None
}

pub fn confirm_xss_reflection(
    request_input: &str,
    response_body: &str,
) -> Option<ExploitConfirmation> {
    if request_input.trim().is_empty() || response_body.is_empty() {
        return None;
    }
    if response_body.contains(request_input) {
        return Some(ExploitConfirmation {
            exploit_type: "xss".to_owned(),
            confidence: 0.99,
            detail: "exact unencoded request payload reflected in response".to_owned(),
            evidence: truncate(request_input, 120),
        });
    }
    None
}

pub fn confirm_ssrf_success(
    response_status: u16,
    response_body: &str,
) -> Option<ExploitConfirmation> {
    if response_body.is_empty() {
        return None;
    }
    if !(200..=399).contains(&response_status) {
        return None;
    }

    let lower_body = response_body.to_ascii_lowercase();
    let cloud_markers = [
        "latest/meta-data",
        "iam/security-credentials",
        "instance-id",
        "ami-id",
        "metadata.google.internal",
        "computemetadata/v1",
    ];
    if cloud_markers.iter().any(|m| lower_body.contains(m)) {
        return Some(ExploitConfirmation {
            exploit_type: "ssrf".to_owned(),
            confidence: 0.98,
            detail: "response matches cloud metadata endpoint content".to_owned(),
            evidence: "cloud_metadata_indicator".to_owned(),
        });
    }

    let internal_markers = [
        "jenkins",
        "grafana",
        "prometheus",
        "elasticsearch",
        "kubernetes",
        "consul",
    ];
    if internal_markers.iter().any(|m| lower_body.contains(m)) {
        return Some(ExploitConfirmation {
            exploit_type: "ssrf".to_owned(),
            confidence: 0.86,
            detail: "response resembles internal service/admin content".to_owned(),
            evidence: "internal_service_indicator".to_owned(),
        });
    }
    None
}

pub fn audit_security_headers(headers: &[(String, String)]) -> Vec<ResponseFinding> {
    let mut normalized = HashMap::new();
    for (k, v) in headers {
        normalized.insert(k.to_ascii_lowercase(), v.to_ascii_lowercase());
    }

    let mut findings = Vec::new();
    let required = [
        ("content-security-policy", Severity::High),
        ("strict-transport-security", Severity::Medium),
        ("x-frame-options", Severity::Medium),
        ("x-content-type-options", Severity::Medium),
        ("referrer-policy", Severity::Low),
        ("permissions-policy", Severity::Low),
    ];

    for (name, severity) in required {
        if !normalized.contains_key(name) {
            findings.push(ResponseFinding {
                finding_type: ResponseFindingType::MissingSecurityHeader,
                severity,
                detail: format!("missing required security header `{name}`"),
                evidence: "header_absent".to_owned(),
            });
        }
    }

    if let Some(value) = normalized.get("x-content-type-options") {
        if value.trim() != "nosniff" {
            findings.push(ResponseFinding {
                finding_type: ResponseFindingType::MisconfiguredSecurityHeader,
                severity: Severity::Medium,
                detail: "x-content-type-options should be `nosniff`".to_owned(),
                evidence: truncate(value, 80),
            });
        }
    }

    if let Some(value) = normalized.get("x-frame-options") {
        if value.trim() != "deny" && value.trim() != "sameorigin" {
            findings.push(ResponseFinding {
                finding_type: ResponseFindingType::MisconfiguredSecurityHeader,
                severity: Severity::Medium,
                detail: "x-frame-options should be `DENY` or `SAMEORIGIN`".to_owned(),
                evidence: truncate(value, 80),
            });
        }
    }

    findings
}

pub fn confirmation_to_finding(
    confirm: ExploitConfirmation,
    severity: Severity,
) -> ResponseFinding {
    ResponseFinding {
        finding_type: ResponseFindingType::ExploitConfirmation,
        severity,
        detail: format!(
            "{} exploit confirmed: {}",
            confirm.exploit_type, confirm.detail
        ),
        evidence: confirm.evidence,
    }
}

fn dedupe_findings(findings: Vec<ResponseFinding>) -> ResponseAnalysis {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for finding in findings {
        let key = (
            finding.finding_type,
            finding.severity,
            finding.detail.clone(),
            finding.evidence.clone(),
        );
        if seen.insert(key) {
            deduped.push(finding);
        }
    }
    ResponseAnalysis { findings: deduped }
}

fn first_regex_match(haystack: &str, pattern: &str) -> Option<String> {
    let re = Regex::new(pattern).ok()?;
    let m = re.find(haystack)?;
    Some(truncate(m.as_str(), 160))
}

fn find_likely_credit_card(body: &str) -> Option<String> {
    let re = Regex::new(r"\b(?:\d[ -]*?){13,19}\b").ok()?;
    for candidate in re.find_iter(body) {
        let digits: String = candidate
            .as_str()
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
            return Some(digits);
        }
    }
    None
}

fn luhn_valid(number: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for ch in number.chars().rev() {
        let mut n = match ch.to_digit(10) {
            Some(v) => v,
            None => return false,
        };
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    sum % 10 == 0
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_error_detection_mysql() {
        let findings = detect_sql_error_leak("You have an error in your SQL syntax near '1=1'");
        assert!(!findings.is_empty());
    }

    #[test]
    fn sql_error_detection_oracle() {
        let findings = detect_sql_error_leak("ORA-00933: SQL command not properly ended");
        assert!(findings.iter().any(|f| f.detail.contains("oracle")));
    }

    #[test]
    fn stack_trace_detection_python() {
        let body = "Traceback (most recent call last):\n  File \"app.py\", line 10, in <module>";
        let findings = detect_stack_trace_leak(body);
        assert!(findings.iter().any(|f| f.detail.contains("python")));
    }

    #[test]
    fn stack_trace_detection_java() {
        let body = "Exception in thread \"main\" java.lang.NullPointerException\n at com.app.Main.main(Main.java:12)";
        let findings = detect_stack_trace_leak(body);
        assert!(findings.iter().any(|f| f.detail.contains("java")));
    }

    #[test]
    fn sensitive_data_detection_ssn() {
        let findings = detect_sensitive_data_leak("customer_ssn=123-45-6789");
        assert!(findings.iter().any(|f| f.detail.contains("SSN")));
    }

    #[test]
    fn sensitive_data_detection_credit_card_luhn() {
        let findings = detect_sensitive_data_leak("card=4111 1111 1111 1111");
        assert!(findings.iter().any(|f| f.detail.contains("card")));
    }

    #[test]
    fn sensitive_data_detection_private_key() {
        let findings = detect_sensitive_data_leak("-----BEGIN PRIVATE KEY-----\nabc");
        assert!(findings.iter().any(|f| f.detail.contains("private key")));
    }

    #[test]
    fn directory_listing_detection() {
        let body =
            "<html><title>Index of /backups</title><a href=\"../\">Parent Directory</a></html>";
        let findings = detect_directory_listing(body);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn version_disclosure_from_header() {
        let headers = vec![("Server".to_owned(), "nginx/1.24.0".to_owned())];
        let findings = detect_version_disclosure("", &headers);
        assert!(findings.iter().any(|f| f.detail.contains("header")));
    }

    #[test]
    fn confirm_sqli_on_reflected_error() {
        let req = "' OR 1=1--";
        let body = "error: You have an error in your SQL syntax near '' OR 1=1--'";
        let confirm = confirm_sqli_success(req, body);
        assert!(confirm.is_some());
    }

    #[test]
    fn confirm_xss_on_exact_reflection() {
        let payload = "<script>alert(1)</script>";
        let body = format!("<html>{payload}</html>");
        let confirm = confirm_xss_reflection(payload, &body);
        assert!(confirm.is_some());
    }

    #[test]
    fn confirm_ssrf_metadata() {
        let body = "ami-id\ninstance-id\niam/security-credentials/";
        let confirm = confirm_ssrf_success(200, body);
        assert!(confirm.is_some());
    }

    #[test]
    fn audit_security_headers_reports_missing() {
        let findings = audit_security_headers(&[]);
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("content-security-policy"))
        );
    }

    #[test]
    fn analyze_response_aggregates_findings() {
        let headers = vec![("Server".to_owned(), "Apache/2.4.58".to_owned())];
        let body = "You have an error in your SQL syntax\nTraceback (most recent call last):";
        let analysis = analyze_response(
            500,
            &headers,
            body,
            &[
                InvariantClass::SqlErrorOracle,
                InvariantClass::SsrfCloudMetadata,
            ],
        );
        assert!(analysis.findings.len() >= 3);
    }
}
