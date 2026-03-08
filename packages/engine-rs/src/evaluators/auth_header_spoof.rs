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

        let mut forwarded_hits = Vec::new();
        for value in header_values(&headers, "Forwarded") {
            let lower = value.to_ascii_lowercase();
            if lower.contains("for=127.")
                || lower.contains("for=10.")
                || lower.contains("for=192.168.")
                || lower.contains("for=::1")
                || lower.contains("for=localhost")
            {
                forwarded_hits.push(format!("Forwarded: {}", value));
            }
        }
        if !forwarded_hits.is_empty() {
            detections.push(L2Detection {
                detection_type: "auth_forwarded_header_spoof".into(),
                confidence: 0.86,
                detail: format!(
                    "RFC 7239 Forwarded header includes internal/loopback for= values: {}",
                    forwarded_hits.join("; ")
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: forwarded_hits.join("; "),
                    interpretation: "RFC 7239 Forwarded header contains an internal/loopback IP in the for= parameter. This structured proxy header is increasingly supported by modern frameworks and can be used to bypass IP-based access controls in the same way as X-Forwarded-For.".into(),
                    offset: 0,
                    property: "RFC 7239 Forwarded header must not be trusted from untrusted clients. Only accept forwarding headers from verified proxy endpoints.".into(),
                }],
            });
        }

        let method_override_headers = [
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-HTTP-Method",
        ];
        let dangerous_methods = ["DELETE", "PUT", "PATCH", "CONNECT", "TRACE", "OPTIONS", "HEAD"];
        let mut method_override_hits = Vec::new();
        for name in method_override_headers {
            for value in header_values(&headers, name) {
                let upper = value.trim().to_ascii_uppercase();
                if dangerous_methods.contains(&upper.as_str()) {
                    method_override_hits.push(format!("{}: {}", name, value));
                }
            }
        }
        if !method_override_hits.is_empty() {
            detections.push(L2Detection {
                detection_type: "auth_method_override".into(),
                confidence: 0.84,
                detail: format!(
                    "HTTP method override headers indicate unsafe method tunneling: {}",
                    method_override_hits.join("; ")
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: method_override_hits.join("; "),
                    interpretation: "HTTP method override headers (X-HTTP-Method-Override) allow changing the HTTP method on a request. Some frameworks honor these headers to work around firewall restrictions. Attackers can use them to invoke DELETE/PUT/PATCH endpoints through GET-only attack vectors or bypass method-based access controls.".into(),
                    offset: 0,
                    property: "Method override headers must not be accepted from untrusted clients. Method-based access controls must use the actual HTTP method, not override headers.".into(),
                }],
            });
        }

        let proxy_values = header_values(&headers, "Proxy");
        if proxy_values.iter().any(|v| !v.trim().is_empty()) {
            let proxy_hits: Vec<String> = proxy_values
                .iter()
                .map(|v| format!("Proxy: {}", v))
                .collect();
            detections.push(L2Detection {
                detection_type: "auth_httpoxy".into(),
                confidence: 0.90,
                detail: format!(
                    "Proxy header present (httpoxy risk): {}",
                    proxy_hits.join("; ")
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: proxy_hits.join("; "),
                    interpretation: "The Proxy: request header maps to the HTTP_PROXY environment variable in CGI/PHP environments (httpoxy, CVE-2016-5385). If the backend application uses HTTP_PROXY for outbound requests, an attacker can redirect all backend HTTP traffic through an attacker-controlled proxy, enabling MITM of outbound API calls, credential theft, and SSRF.".into(),
                    offset: 0,
                    property: "The Proxy: request header must be stripped at the gateway/load balancer before reaching CGI applications. Applications must not read HTTP_PROXY from the environment without explicit configuration.".into(),
                }],
            });
        }

        let extended_spoof_headers = [
            "True-Client-IP",
            "CF-Connecting-IP",
            "X-Cluster-Client-IP",
            "X-ProxyUser-Ip",
            "X-Forwarded-User",
            "X-Remote-User",
            "Fastly-Client-IP",
        ];
        let mut extended_spoof_hits = Vec::new();
        for name in extended_spoof_headers {
            for value in header_values(&headers, name) {
                if looks_internal_ip(value) {
                    extended_spoof_hits.push(format!("{}: {}", name, value));
                }
            }
        }
        if !extended_spoof_hits.is_empty() {
            detections.push(L2Detection {
                detection_type: "auth_extended_ip_spoof".into(),
                confidence: 0.83,
                detail: format!(
                    "Additional forwarding headers contain internal IPs: {}",
                    extended_spoof_hits.join("; ")
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: extended_spoof_hits.join("; "),
                    interpretation: "CDN/proxy-specific IP forwarding headers (True-Client-IP, CF-Connecting-IP, X-Cluster-Client-IP) contain internal IPs. These headers are trusted by some frameworks without validation, enabling IP-based access control bypass in the same manner as X-Forwarded-For spoofing.".into(),
                    offset: 0,
                    property: "CDN and cluster IP headers must only be trusted when originating from verified CDN/load balancer infrastructure, not from untrusted client requests.".into(),
                }],
            });
        }

        detections
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "auth_header_ip_spoofing"
            | "auth_header_host_injection"
            | "auth_header_rewrite_override"
            | "auth_forwarded_header_spoof"
            | "auth_method_override"
            | "auth_httpoxy"
            | "auth_extended_ip_spoof" => Some(InvariantClass::AuthHeaderSpoof),
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
    fn detects_forwarded_header_spoofing() {
        let eval = AuthHeaderSpoofEvaluator;
        let input = "GET / HTTP/1.1\r\nHost: app.example.com\r\nForwarded: for=127.0.0.1;proto=http;by=proxy\r\n\r\n";
        let dets = eval.detect(input);
        let det = dets
            .iter()
            .find(|d| d.detection_type == "auth_forwarded_header_spoof")
            .expect("expected Forwarded spoofing detection");
        assert_eq!(det.confidence, 0.86);
        assert_eq!(
            eval.map_class("auth_forwarded_header_spoof"),
            Some(InvariantClass::AuthHeaderSpoof)
        );
    }

    #[test]
    fn detects_method_override_header() {
        let eval = AuthHeaderSpoofEvaluator;
        let input = "GET /resource HTTP/1.1\r\nHost: app.example.com\r\nX-HTTP-Method-Override: delete\r\n\r\n";
        let dets = eval.detect(input);
        let det = dets
            .iter()
            .find(|d| d.detection_type == "auth_method_override")
            .expect("expected method override detection");
        assert_eq!(det.confidence, 0.84);
        assert_eq!(
            eval.map_class("auth_method_override"),
            Some(InvariantClass::AuthHeaderSpoof)
        );
    }

    #[test]
    fn detects_httpoxy_proxy_header() {
        let eval = AuthHeaderSpoofEvaluator;
        let input = "GET /api HTTP/1.1\r\nHost: app.example.com\r\nProxy: http://attacker-proxy.example:8080\r\n\r\n";
        let dets = eval.detect(input);
        let det = dets
            .iter()
            .find(|d| d.detection_type == "auth_httpoxy")
            .expect("expected httpoxy detection");
        assert_eq!(det.confidence, 0.90);
        assert_eq!(
            eval.map_class("auth_httpoxy"),
            Some(InvariantClass::AuthHeaderSpoof)
        );
    }

    #[test]
    fn detects_extended_ip_spoofing_headers() {
        let eval = AuthHeaderSpoofEvaluator;
        let input =
            "GET /admin HTTP/1.1\r\nHost: app.example.com\r\nTrue-Client-IP: 192.168.1.55\r\n\r\n";
        let dets = eval.detect(input);
        let det = dets
            .iter()
            .find(|d| d.detection_type == "auth_extended_ip_spoof")
            .expect("expected extended spoofing detection");
        assert_eq!(det.confidence, 0.83);
        assert_eq!(
            eval.map_class("auth_extended_ip_spoof"),
            Some(InvariantClass::AuthHeaderSpoof)
        );
    }

    #[test]
    fn no_detection_for_benign_headers() {
        let eval = AuthHeaderSpoofEvaluator;
        let input = "GET / HTTP/1.1\r\nHost: app.example.com\r\nX-Forwarded-For: 203.0.113.5\r\n\r\n";
        assert!(eval.detect(input).is_empty());
    }
}
