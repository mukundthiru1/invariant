//! Auth Header Spoof Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;

fn parse_headers(input: &str) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for line in input.lines() {
        if line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    headers
}

fn header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            if k.eq_ignore_ascii_case(name) {
                Some(v.as_str())
            } else {
                None
            }
        })
        .collect()
}

fn first_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|(k, v)| {
        if k.eq_ignore_ascii_case(name) {
            Some(v.as_str())
        } else {
            None
        }
    })
}

fn strip_host_port(candidate: &str) -> &str {
    if candidate.starts_with('[') && candidate.ends_with(']') {
        return candidate;
    }

    if candidate.matches(':').count() == 1 && candidate.contains('.') {
        return candidate.split(':').next().unwrap_or(candidate);
    }

    candidate
}

fn looks_internal_ip(value: &str) -> bool {
    for raw in value.split(',') {
        let mut candidate = raw.trim().trim_matches('"').trim();
        if candidate.is_empty() {
            continue;
        }

        if candidate.starts_with("::ffff:") {
            candidate = &candidate[7..];
        }
        candidate = strip_host_port(candidate);

        if candidate == "::1" || candidate == "[::1]" {
            return true;
        }
        if candidate.starts_with("10.")
            || candidate.starts_with("192.168.")
            || candidate.starts_with("127.")
        {
            return true;
        }
        if let Some(rest) = candidate.strip_prefix("172.") {
            let octet = rest.split('.').next().unwrap_or_default();
            if let Ok(o) = octet.parse::<u8>() {
                if (16..=31).contains(&o) {
                    return true;
                }
            }
        }
    }

    false
}

fn normalized_host(value: &str) -> String {
    value
        .trim()
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

fn host_only(value: &str) -> String {
    let mut host = value.trim().to_ascii_lowercase();
    if let Some((_, right)) = host.rsplit_once('@') {
        host = right.to_string();
    }
    let host = strip_host_port(&host);
    normalized_host(host)
}

fn request_line_expected_host(input: &str) -> Option<String> {
    let line = input.lines().next()?.trim();
    let path = line.split_whitespace().nth(1)?;

    let rest = if let Some(v) = path.strip_prefix("http://") {
        v
    } else if let Some(v) = path.strip_prefix("https://") {
        v
    } else {
        return None;
    };

    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        None
    } else {
        Some(host_only(authority))
    }
}

fn origin_expected_host(headers: &[(String, String)]) -> Option<String> {
    let origin = first_header(headers, "Origin")?;
    let value = origin.trim();
    let rest = if let Some(v) = value.strip_prefix("http://") {
        v
    } else if let Some(v) = value.strip_prefix("https://") {
        v
    } else {
        return None;
    };

    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        None
    } else {
        Some(host_only(authority))
    }
}

fn expected_host(input: &str, headers: &[(String, String)]) -> Option<String> {
    request_line_expected_host(input)
        .or_else(|| origin_expected_host(headers))
        .or_else(|| first_header(headers, "X-Forwarded-Host").map(host_only))
        .or_else(|| first_header(headers, ":authority").map(host_only))
}

fn has_multiple_colons(host: &str) -> bool {
    let value = host.trim();
    value.matches(':').count() > 1 && !(value.starts_with('[') && value.ends_with(']'))
}

fn looks_user_host_format(host: &str) -> bool {
    let value = host.trim();
    value.contains('@') && value.split('@').count() == 2 && !value.contains("//")
}

pub struct AuthHeaderSpoofEvaluator;

impl L2Evaluator for AuthHeaderSpoofEvaluator {
    fn id(&self) -> &'static str {
        "auth_header_spoof"
    }

    fn prefix(&self) -> &'static str {
        "L2 AuthHeaderSpoof"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let headers = parse_headers(input);
        let mut detections = Vec::new();

        let spoof_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Client-IP",
            "X-Originating-IP",
        ];

        let mut spoof_hits = Vec::new();
        for name in spoof_headers {
            for value in header_values(&headers, name) {
                if looks_internal_ip(value) {
                    spoof_hits.push(format!("{}: {}", name, value));
                }
            }
        }

        if !spoof_hits.is_empty() {
            detections.push(L2Detection {
                detection_type: "auth_header_ip_spoofing".into(),
                confidence: 0.85,
                detail: format!(
                    "Internal IP observed in spoofable forwarding headers: {}",
                    spoof_hits.join("; ")
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: spoof_hits.join("; "),
                    interpretation: "Forwarding headers contain internal/loopback IPs commonly used to bypass IP-based trust gates".into(),
                    offset: 0,
                    property: "Authentication and authorization decisions must not trust user-supplied forwarding headers".into(),
                }],
            });
        }

        if let Some(host_value) = first_header(&headers, "Host") {
            let mut reasons = Vec::new();
            if host_value.contains('@') {
                reasons.push("contains '@' character");
            }
            if looks_user_host_format(host_value) {
                reasons.push("uses user@host authority form");
            }
            if has_multiple_colons(host_value) {
                reasons.push("contains multiple ':' delimiters");
            }
            if let Some(expected) = expected_host(input, &headers) {
                let actual = host_only(host_value);
                if !actual.is_empty() && actual != expected {
                    reasons.push("does not match expected domain context");
                }
            }

            if !reasons.is_empty() {
                detections.push(L2Detection {
                    detection_type: "auth_header_host_injection".into(),
                    confidence: 0.82,
                    detail: format!(
                        "Host header injection indicators ({}): {}",
                        host_value,
                        reasons.join(", ")
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: format!("Host: {}", host_value),
                        interpretation: "Manipulated Host headers can confuse upstream routing and bypass host-based access controls".into(),
                        offset: 0,
                        property: "Host header must match expected authority and reject ambiguous authority syntax".into(),
                    }],
                });
            }
        }

        let mut bypass_headers = Vec::new();
        for name in ["X-Original-URL", "X-Rewrite-URL"] {
            for value in header_values(&headers, name) {
                bypass_headers.push(format!("{}: {}", name, value));
            }
        }
        if !bypass_headers.is_empty() {
            detections.push(L2Detection {
                detection_type: "auth_header_rewrite_override".into(),
                confidence: 0.80,
                detail: format!(
                    "Auth bypass rewrite headers present: {}",
                    bypass_headers.join("; ")
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: bypass_headers.join("; "),
                    interpretation: "Proxy rewrite headers may trigger alternate internal routing paths that skip authentication checks".into(),
                    offset: 0,
                    property: "Security boundaries must ignore or strictly sanitize X-Original-URL and X-Rewrite-URL from untrusted clients".into(),
                }],
            });
        }

        detections
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "auth_header_ip_spoofing"
            | "auth_header_host_injection"
            | "auth_header_rewrite_override" => Some(InvariantClass::AuthHeaderSpoof),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ip_spoofing_headers_with_internal_ip() {
        let eval = AuthHeaderSpoofEvaluator;
        let input = "GET /admin HTTP/1.1\r\nHost: app.example.com\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n";
        let dets = eval.detect(input);
        let det = dets
            .iter()
            .find(|d| d.detection_type == "auth_header_ip_spoofing")
            .expect("expected IP spoofing detection");
        assert_eq!(det.confidence, 0.85);
        assert_eq!(
            eval.map_class("auth_header_ip_spoofing"),
            Some(InvariantClass::AuthHeaderSpoof)
        );
    }

    #[test]
    fn detects_host_header_injection_user_host_format() {
        let eval = AuthHeaderSpoofEvaluator;
        let input = "GET / HTTP/1.1\r\nHost: admin@evil.example\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "auth_header_host_injection")
        );
    }

    #[test]
    fn detects_host_header_expected_domain_mismatch() {
        let eval = AuthHeaderSpoofEvaluator;
        let input = "GET /profile HTTP/1.1\r\nHost: attacker.example\r\nOrigin: https://api.example.com\r\n\r\n";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| {
            d.detection_type == "auth_header_host_injection"
                && d.detail.contains("does not match expected domain context")
        }));
    }

    #[test]
    fn detects_rewrite_override_headers() {
        let eval = AuthHeaderSpoofEvaluator;
        let input = "GET / HTTP/1.1\r\nHost: app.example.com\r\nX-Original-URL: /internal/admin\r\n\r\n";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "auth_header_rewrite_override")
        );
    }

    #[test]
    fn no_detection_for_benign_headers() {
        let eval = AuthHeaderSpoofEvaluator;
        let input = "GET / HTTP/1.1\r\nHost: app.example.com\r\nX-Forwarded-For: 203.0.113.5\r\n\r\n";
        assert!(eval.detect(input).is_empty());
    }
}
