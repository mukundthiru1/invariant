//! CORS Misconfiguration Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::sync::LazyLock;

static DNS_REBINDING_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Origin\s*:\s*https?://[a-z0-9.-]*(?:\d{1,3}\.){3}\d{1,3}\.(?:xip\.io|nip\.io|sslip\.io|localtest\.me|lvh\.me)").unwrap());
static MULTI_ORIGIN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^Origin\s*:.*\r?\n(?:[^\r\n]*\r?\n)*?^Origin\s*:").unwrap());
static ACAO_WILDCARD_CREDS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^Access-Control-Allow-Credentials\s*:\s*true[^\r\n]*\r?\n(?:[^\r\n]*\r?\n)*?^Access-Control-Allow-Origin\s*:\s*\*").unwrap());


pub type L2EvalResult = L2Detection;

#[derive(Debug, Clone)]
struct CorsPatternHit {
    name: &'static str,
    confidence: f64,
    snippet: String,
}

fn header_values(input: &str, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in input.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                out.push(v.trim().to_string());
            }
        }
    }
    out
}

fn first_header(input: &str, name: &str) -> Option<String> {
    header_values(input, name).into_iter().next()
}

fn origin_host(origin: &str) -> Option<String> {
    let mut value = origin.trim().to_ascii_lowercase();
    if value == "null" {
        return None;
    }
    if let Some(rest) = value.strip_prefix("http://") {
        value = rest.to_string();
    } else if let Some(rest) = value.strip_prefix("https://") {
        value = rest.to_string();
    }

    let host_port = value.split('/').next().unwrap_or_default();
    if host_port.is_empty() {
        return None;
    }

    let host = host_port.split('@').next_back().unwrap_or(host_port);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn request_method(input: &str) -> Option<String> {
    let line = input.lines().next()?.trim();
    let token = line.split_whitespace().next()?.to_ascii_uppercase();
    if token.chars().all(|c| c.is_ascii_uppercase()) {
        Some(token)
    } else {
        None
    }
}

fn detect_cors_patterns(input: &str) -> Vec<CorsPatternHit> {
    let mut hits = Vec::new();

    let origin = first_header(input, "Origin");
    let acao = first_header(input, "Access-Control-Allow-Origin");
    let acac = first_header(input, "Access-Control-Allow-Credentials");
    let acam = first_header(input, "Access-Control-Allow-Methods");
    let acrh = first_header(input, "Access-Control-Request-Headers");

    if let (Some(origin), Some(acao)) = (origin.as_deref(), acao.as_deref()) {
        if origin.eq_ignore_ascii_case("null") && acao.eq_ignore_ascii_case("null") {
            hits.push(CorsPatternHit {
                name: "null origin reflection",
                confidence: 0.85,
                snippet: "Origin: null / Access-Control-Allow-Origin: null".to_string(),
            });
        }

        if origin.eq_ignore_ascii_case("https://evil.com")
            && acao.eq_ignore_ascii_case("https://evil.com")
        {
            hits.push(CorsPatternHit {
                name: "attacker origin reflection",
                confidence: 0.82,
                snippet: "Origin: https://evil.com reflected in ACAO".to_string(),
            });
        }

        let origin_l = origin.to_ascii_lowercase();
        let acao_l = acao.to_ascii_lowercase();

        if origin_l == acao_l && origin_l.contains("evil.legitimate.com") {
            hits.push(CorsPatternHit {
                name: "subdomain origin validation bypass",
                confidence: 0.75,
                snippet: format!("Reflected subdomain origin: {origin}"),
            });
        }

        if origin_l == acao_l && origin_l.contains("evil.com.attacker.com") {
            hits.push(CorsPatternHit {
                name: "regex-based origin matching bypass",
                confidence: 0.80,
                snippet: format!("Reflected regex-bypass origin: {origin}"),
            });
        }

        if origin_l.starts_with("https://")
            && acao_l.starts_with("http://")
            && origin_host(&origin_l).is_some()
            && origin_host(&origin_l) == origin_host(&acao_l)
        {
            hits.push(CorsPatternHit {
                name: "protocol downgrade reflection",
                confidence: 0.78,
                snippet: format!("Origin {origin} downgraded to {acao}"),
            });
        }

        let has_creds_true_local = acac
            .as_deref()
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if origin_l == acao_l && origin_l != "null" && !origin_l.is_empty() && hits.is_empty() && has_creds_true_local {
            hits.push(CorsPatternHit {
                name: "arbitrary origin reflected",
                confidence: 0.85,
                snippet: format!("Origin {origin} reflected in ACAO with credentials"),
            });
        }
    }

    let acao_values = header_values(input, "Access-Control-Allow-Origin");
    if acao_values.len() >= 2 {
        hits.push(CorsPatternHit {
            name: "duplicate ACAO headers",
            confidence: 0.83,
            snippet: format!("Found {} Access-Control-Allow-Origin headers", acao_values.len()),
        });
    }

    let has_wildcard_acao = acao.as_deref().map(|v| v.trim() == "*").unwrap_or(false);
    let has_creds_true = acac
        .as_deref()
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if has_wildcard_acao && has_creds_true {
        hits.push(CorsPatternHit {
            name: "wildcard ACAO with credentials",
            confidence: 0.90,
            snippet: "Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true"
                .to_string(),
        });
    }
    let any_wildcard_acao = header_values(input, "Access-Control-Allow-Origin")
        .iter()
        .any(|v| v.trim() == "*");
    let any_creds_true = header_values(input, "Access-Control-Allow-Credentials")
        .iter()
        .any(|v| v.eq_ignore_ascii_case("true"));
    if any_wildcard_acao
        && any_creds_true
        && !hits
            .iter()
            .any(|h| h.name == "wildcard ACAO with credentials")
    {
        hits.push(CorsPatternHit {
            name: "wildcard ACAO with credentials",
            confidence: 0.90,
            snippet: "Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true"
                .to_string(),
        });
    }

    if let Some(acam) = acam.as_deref() {
        if acam.trim() == "*" {
            hits.push(CorsPatternHit {
                name: "overbroad Access-Control-Allow-Methods",
                confidence: 0.72,
                snippet: "Access-Control-Allow-Methods: *".to_string(),
            });
        }
    }

    if request_method(input).as_deref() == Some("OPTIONS")
        && acrh
            .as_deref()
            .map(|v| {
                let l = v.to_ascii_lowercase();
                l.contains("x-") || l.contains("authorization") || l.contains("cookie")
            })
            .unwrap_or(false)
    {
        hits.push(CorsPatternHit {
            name: "pre-flight request manipulation",
            confidence: 0.70,
            snippet: format!(
                "OPTIONS preflight with custom headers: {}",
                acrh.unwrap_or_default()
            ),
        });
    }

    hits
}

pub fn evaluate_cors(input: &str) -> Option<L2EvalResult> {
    let hits = detect_cors_patterns(input);
    if hits.is_empty() {
        return None;
    }

    let confidence = hits.iter().map(|h| h.confidence).fold(0.0, f64::max);
    let detail = format!(
        "CORS misconfiguration pattern(s): {}",
        hits.iter().map(|h| h.name).collect::<Vec<_>>().join(", ")
    );
    let snippet = hits
        .iter()
        .map(|h| h.snippet.as_str())
        .collect::<Vec<_>>()
        .join("; ");

    Some(L2Detection {
        detection_type: "cors_misconfiguration".into(),
        confidence,
        detail,
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: snippet,
            interpretation:
                "Cross-origin policy appears to trust attacker-controlled origin or overbroad methods/credentials"
                    .into(),
            offset: 0,
            property:
                "CORS allowlist must not reflect untrusted origins and must avoid wildcard credentials/methods"
                    .into(),
        }],
    })
}

pub struct CorsEvaluator;

impl L2Evaluator for CorsEvaluator {
    fn id(&self) -> &'static str {
        "cors"
    }

    fn prefix(&self) -> &'static str {
        "L2 CORS"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut results: Vec<L2Detection> = evaluate_cors(input).into_iter().collect();

        if let Some(m) = DNS_REBINDING_RE.find(input) {
            results.push(L2Detection {
                detection_type: "cors_dns_rebinding_origin".into(),
                confidence: 0.90,
                detail: "DNS rebinding origin detected in CORS".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_string(),
                    interpretation: "xip.io and nip.io domains resolve to the embedded IP address. Origin: http://192.168.1.1.xip.io resolves to 192.168.1.1, enabling DNS rebinding to bypass same-origin policy by getting CORS headers accepted for an internal IP.".into(),
                    offset: m.start(),
                    property: "CORS origin validation must reject wildcard DNS services (xip.io, nip.io, sslip.io). Validate origins against an explicit allowlist of exact domain+port combinations.".into(),
                }],
            });
        }

        if let Some(m) = MULTI_ORIGIN_RE.find(input) {
            results.push(L2Detection {
                detection_type: "cors_multiple_origin_headers".into(),
                confidence: 0.87,
                detail: "Multiple Origin headers detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Multiple Origin headers in a single HTTP request exploit inconsistency in how intermediaries vs. application servers handle duplicate headers. The first may be trusted while the second (attacker-controlled) is echoed in ACAO.".into(),
                    offset: m.start(),
                    property: "Reject requests with multiple Origin headers. CORS origin validation must use exactly one Origin value and reject ambiguous multi-header Origin.".into(),
                }],
            });
        }

        if let Some(m) = ACAO_WILDCARD_CREDS_RE.find(input) {
            results.push(L2Detection {
                detection_type: "cors_acao_wildcard_credentials".into(),
                confidence: 0.88,
                detail: "CORS allow-credentials wildcard bypass".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true violates CORS spec but some server misconfiguration still allows it. Malicious intermediaries may forward credentials with wildcard ACAO.".into(),
                    offset: m.start(),
                    property: "When Allow-Credentials: true is set, Allow-Origin must be a specific origin, never *. Reject this combination at middleware level.".into(),
                }],
            });
        }

        results
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "cors_misconfiguration" | "cors_dns_rebinding_origin" | "cors_multiple_origin_headers" | "cors_acao_wildcard_credentials" => Some(InvariantClass::CorsOriginAbuse),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_null_origin_reflection_with_required_confidence() {
        let input = "Origin: null\nAccess-Control-Allow-Origin: null";
        let result = evaluate_cors(input).unwrap();
        assert!(result.detail.contains("null origin reflection"));
        assert!((result.confidence - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn detects_evil_origin_reflection() {
        let input = "Origin: https://evil.com\nAccess-Control-Allow-Origin: https://evil.com";
        let result = evaluate_cors(input).unwrap();
        assert!(result.detail.contains("attacker origin reflection"));
    }

    #[test]
    fn detects_wildcard_and_credentials_true_with_required_confidence() {
        let input = "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true";
        let result = evaluate_cors(input).unwrap();
        assert!(result.detail.contains("wildcard ACAO with credentials"));
        assert!((result.confidence - 0.90).abs() < f64::EPSILON);
    }

    #[test]
    fn detects_subdomain_bypass_with_required_confidence() {
        let input = "Origin: https://evil.legitimate.com\nAccess-Control-Allow-Origin: https://evil.legitimate.com";
        let result = evaluate_cors(input).unwrap();
        assert!(result.detail.contains("subdomain origin validation bypass"));
        assert!((result.confidence - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn detects_preflight_request_manipulation() {
        let input = "OPTIONS /api HTTP/1.1\nOrigin: https://site.com\nAccess-Control-Request-Headers: X-Evil, Authorization";
        let result = evaluate_cors(input).unwrap();
        assert!(result.detail.contains("pre-flight request manipulation"));
    }

    #[test]
    fn detects_allow_methods_star() {
        let input = "Access-Control-Allow-Methods: *";
        let result = evaluate_cors(input).unwrap();
        assert!(
            result
                .detail
                .contains("overbroad Access-Control-Allow-Methods")
        );
    }

    #[test]
    fn detects_regex_origin_bypass_with_required_confidence() {
        let input = "Origin: https://evil.com.attacker.com\nAccess-Control-Allow-Origin: https://evil.com.attacker.com";
        let result = evaluate_cors(input).unwrap();
        assert!(result.detail.contains("regex-based origin matching bypass"));
        assert!((result.confidence - 0.80).abs() < f64::EPSILON);
    }

    #[test]
    fn detects_protocol_downgrade_reflection() {
        let input =
            "Origin: https://app.example.com\nAccess-Control-Allow-Origin: http://app.example.com";
        let result = evaluate_cors(input).unwrap();
        assert!(result.detail.contains("protocol downgrade reflection"));
    }

    #[test]
    fn combines_multiple_hits_uses_max_confidence() {
        let input = "Origin: null\nAccess-Control-Allow-Origin: null\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true";
        let result = evaluate_cors(input).unwrap();
        assert!(result.confidence >= 0.90);
    }

    #[test]
    fn map_class_routes_to_cors_origin_abuse() {
        let eval = CorsEvaluator;
        assert_eq!(
            eval.map_class("cors_misconfiguration"),
            Some(InvariantClass::CorsOriginAbuse)
        );
    }

    #[test]
    fn no_detection_for_specific_allowlist_origin() {
        let input = "Origin: https://app.example.com\nAccess-Control-Allow-Origin: https://app.example.com\nAccess-Control-Allow-Credentials: false";
        assert!(evaluate_cors(input).is_none());
    }

    #[test]
    fn no_detection_for_wildcard_without_credentials() {
        let input = "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: false";
        assert!(evaluate_cors(input).is_none());
    }

    #[test]
    fn no_detection_for_non_options_custom_header_probe() {
        let input = "GET /api HTTP/1.1\nAccess-Control-Request-Headers: X-Test";
        assert!(evaluate_cors(input).is_none());
    }

    #[test]
    fn no_detection_when_origin_not_reflected() {
        let input =
            "Origin: https://evil.com\nAccess-Control-Allow-Origin: https://api.example.com";
        assert!(evaluate_cors(input).is_none());
    }

    #[test]
    fn no_detection_for_https_to_https_same_host() {
        let input =
            "Origin: https://app.example.com\nAccess-Control-Allow-Origin: https://app.example.com";
        assert!(evaluate_cors(input).is_none());
    }

    #[test]
    fn header_values_are_case_insensitive() {
        let input = "origin: null\naccess-control-allow-origin: null";
        assert!(evaluate_cors(input).is_some());
    }

    #[test]
    fn request_method_parser_handles_missing_request_line() {
        assert_eq!(request_method("Origin: a"), None);
    }

    #[test]
    fn origin_host_parses_host_without_port() {
        assert_eq!(
            origin_host("https://app.example.com:443/path"),
            Some("app.example.com".to_string())
        );
    }

    #[test]
    fn test_general_arbitrary_origin_reflection() {
        let input = "Origin: https://attacker.com\nAccess-Control-Allow-Origin: https://attacker.com\nAccess-Control-Allow-Credentials: true";
        let result = evaluate_cors(input).unwrap();
        assert!(result.detail.contains("arbitrary origin reflected"));
    }

    #[test]
    fn test_no_false_positive_when_origin_not_reflected() {
        let input = "Origin: https://evil.com\nAccess-Control-Allow-Origin: https://legit.example.com";
        assert!(evaluate_cors(input).is_none());
    }

    #[test]
    fn test_duplicate_acao_headers() {
        let input = "Access-Control-Allow-Origin: https://site1.com\nAccess-Control-Allow-Origin: https://site2.com";
        let result = evaluate_cors(input).unwrap();
        assert!(result.detail.contains("duplicate ACAO headers"));
    }

    #[test]
    fn test_dns_rebinding() {
        let eval = CorsEvaluator;
        let dets = eval.detect("Origin: http://127.0.0.1.xip.io");
        assert!(dets.iter().any(|d| d.detection_type == "cors_dns_rebinding_origin"));
    }

    #[test]
    fn test_multiple_origin() {
        let eval = CorsEvaluator;
        let dets = eval.detect("Origin: https://site1.com\nOrigin: https://site2.com");
        assert!(dets.iter().any(|d| d.detection_type == "cors_multiple_origin_headers"));
    }

    #[test]
    fn test_acao_wildcard_credentials() {
        let eval = CorsEvaluator;
        let dets = eval.detect("Access-Control-Allow-Credentials: true\nAccess-Control-Allow-Origin: *");
        assert!(dets.iter().any(|d| d.detection_type == "cors_acao_wildcard_credentials"));
    }
}
