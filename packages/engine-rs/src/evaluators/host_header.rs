//! Host Header Injection Evaluator — Level 2
//!
//! Detects host header manipulation attacks including:
//!   - Password reset poisoning via Host header override
//!   - Cache poisoning through X-Forwarded-Host abuse
//!   - SSRF/routing manipulation via crafted Host headers
//!   - Virtual host confusion attacks
//!
//! Host header injection is critical because many frameworks trust the Host header
//! for URL generation (password reset links, email confirmation, OAuth callbacks).

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::sync::LazyLock;

static X_FORWARDED_HOST_SPOOF_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^X-Forwarded-Host\s*:\s*([^\r\n]+)").unwrap());
static HOST_IPV6_INJECTION_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?im)^Host\s*:\s*\[[0-9a-fA-F:]+(?:%[^\]]+)?\]").unwrap());

fn extract_header<'a>(input: &'a str, name: &str) -> Option<&'a str> {
    for line in input.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

fn is_suspicious_host(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    // Known attacker patterns
    v.contains("evil") ||
    v.contains("attacker") ||
    v.contains("burp") ||
    v.contains("collaborator") ||
    v.contains("oast") ||
    v.contains("interact.sh") ||
    v.contains("webhook.site") ||
    v.contains("ngrok") ||
    v.contains("localhost") ||
    v.contains("127.0.0.1") ||
    v.contains("0.0.0.0") ||
    v.contains("[::1]") ||
    v.contains("169.254")
}

fn has_port_override(value: &str) -> bool {
    // attacker.com:443 or legitimate.com:8443
    if let Some((_host, port)) = value.rsplit_once(':') {
        if let Ok(p) = port.parse::<u16>() {
            // Non-standard ports in Host header are suspicious
            return p != 80 && p != 443;
        }
    }
    false
}

pub struct HostHeaderEvaluator;

impl L2Evaluator for HostHeaderEvaluator {
    fn id(&self) -> &'static str {
        "host_header"
    }
    fn prefix(&self) -> &'static str {
        "L2 HostHeader"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let lower = input.to_ascii_lowercase();

        if let Some(m) = X_FORWARDED_HOST_SPOOF_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "host_xforwarded_host_spoof".into(),
                confidence: 0.88,
                detail: "X-Forwarded-Host header overrides Host routing in many frameworks".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "X-Forwarded-Host header is used by many frameworks (Django, Rails, Laravel) to generate absolute URLs in password resets and emails. Spoofing this header redirects password reset links to attacker domains, enabling account takeover".into(),
                    offset: m.start(),
                    property: "X-Forwarded-Host must be validated against an allowlist of trusted hosts. Accept only from trusted reverse proxy IPs".into(),
                }],
            });
        }

        if let Some(m) = HOST_IPV6_INJECTION_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "host_ipv6_injection".into(),
                confidence: 0.86,
                detail: "IPv6 Host headers with zone IDs can bypass hostname validation".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "IPv6 Host headers with zone IDs ([fe80::1%25eth0]) bypass hostname validation that only checks for domain format. Some parsers strip zone IDs inconsistently, enabling Host header SSRF to internal IPv6 addresses".into(),
                    offset: m.start(),
                    property: "Host headers with IPv6 zone IDs must be rejected. Only validate against expected IPv6 addresses without zone ID suffixes".into(),
                }],
            });
        }

        // 1. X-Forwarded-Host with suspicious value
        if let Some(xfh) = extract_header(input, "X-Forwarded-Host") {
            if is_suspicious_host(xfh) {
                dets.push(L2Detection {
                    detection_type: "host_header_xfh_injection".into(),
                    confidence: 0.88,
                    detail: format!(
                        "X-Forwarded-Host header contains suspicious value: {}",
                        xfh
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: format!("X-Forwarded-Host: {}", xfh),
                        interpretation: "X-Forwarded-Host header overrides the Host header in many reverse proxy configurations. Frameworks using this for URL generation (password resets, OAuth callbacks) will construct URLs pointing to attacker-controlled domains.".into(),
                        offset: 0,
                        property: "X-Forwarded-Host must not contain untrusted domains. Applications must validate or ignore this header.".into(),
                    }],
                });
            }
        }

        // 2. Multiple Host headers (request smuggling vector)
        let host_count = input
            .lines()
            .filter(|l| {
                l.split_once(':')
                    .map(|(k, _)| k.trim().eq_ignore_ascii_case("Host"))
                    .unwrap_or(false)
            })
            .count();

        if host_count > 1 {
            dets.push(L2Detection {
                detection_type: "host_header_duplicate".into(),
                confidence: 0.92,
                detail: format!("Multiple Host headers detected ({}). This is a request smuggling or routing confusion vector.", host_count),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: format!("{} Host headers", host_count),
                    interpretation: "Duplicate Host headers cause inconsistent behavior between proxies and backends. The first proxy may route based on the first Host, while the backend uses the second, enabling request smuggling.".into(),
                    offset: 0,
                    property: "HTTP/1.1 requests must contain exactly one Host header (RFC 7230 Section 5.4).".into(),
                }],
            });
        }

        // 3. Host header with @ sign (URL authority confusion)
        if let Some(host) = extract_header(input, "Host") {
            if host.contains('@') {
                dets.push(L2Detection {
                    detection_type: "host_header_authority_confusion".into(),
                    confidence: 0.90,
                    detail: format!(
                        "Host header contains '@' sign (URL authority confusion): {}",
                        host
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: format!("Host: {}", host),
                        interpretation: "@ in the Host header exploits URL parser confusion. Some parsers interpret user@host as basic auth credentials, while others treat the entire string as a hostname, enabling routing to attacker infrastructure.".into(),
                        offset: 0,
                        property: "Host header must not contain URL authority syntax (user:password@).".into(),
                    }],
                });
            }

            // 4. Host override via internal headers
            if is_suspicious_host(host) {
                dets.push(L2Detection {
                    detection_type: "host_header_suspicious".into(),
                    confidence: 0.85,
                    detail: format!("Host header contains suspicious domain: {}", host),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: format!("Host: {}", host),
                        interpretation: "The Host header contains a domain associated with security testing tools or internal/loopback addresses. Many frameworks trust Host for generating absolute URLs in password resets, email verification, and OAuth callbacks.".into(),
                        offset: 0,
                        property: "Host header must match the expected application domain. Applications must not blindly trust Host for URL generation.".into(),
                    }],
                });
            }

            if has_port_override(host) {
                dets.push(L2Detection {
                    detection_type: "host_header_port_override".into(),
                    confidence: 0.79,
                    detail: format!("Host header contains non-standard port: {}", host),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: format!("Host: {}", host),
                        interpretation: "Non-standard port in Host header can bypass WAF rules that match only standard ports, and may indicate host header manipulation to redirect password reset/OAuth links to attacker-controlled endpoints on custom ports.".into(),
                        offset: 0,
                        property: "Host header port must match the application service port.".into(),
                    }],
                });
            }
        }

        // 5. X-Host, X-Original-Host, X-Rewrite-URL (proxy override headers)
        for header_name in &[
            "X-Host",
            "X-Original-Host",
            "X-Rewrite-URL",
            "X-Original-URL",
            "X-Forwarded-Server",
            "X-Forwarded-For-Original",
        ] {
            if let Some(val) = extract_header(input, header_name) {
                if is_suspicious_host(val) || val.contains('/') {
                    dets.push(L2Detection {
                        detection_type: "host_header_proxy_override".into(),
                        confidence: 0.83,
                        detail: format!(
                            "{} header used to override routing: {}",
                            header_name, val
                        ),
                        position: 0,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: format!("{}: {}", header_name, val),
                            interpretation: format!("The {} header is used by some reverse proxies to override request routing. An attacker can inject this header to redirect requests to their infrastructure or access restricted paths.", header_name),
                            offset: 0,
                            property: format!("{} must be stripped by the reverse proxy before reaching the application.", header_name),
                        }],
                    });
                    break; // one proxy override detection is sufficient
                }
            }
        }

        // 6. Absolute URL in request line with mismatched Host
        if let Some(first_line) = lower.lines().next() {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                let path = parts[1];
                if path.starts_with("http://") || path.starts_with("https://") {
                    if let Some(host) = extract_header(input, "Host") {
                        let host_lower = host.to_ascii_lowercase();
                        if !path.contains(&host_lower) {
                            dets.push(L2Detection {
                                detection_type: "host_header_absolute_url_mismatch".into(),
                                confidence: 0.87,
                                detail: format!(
                                    "Absolute URL in request line ({}) does not match Host header ({})",
                                    &path[..path.len().min(80)], host
                                ),
                                position: 0,
                                evidence: vec![ProofEvidence {
                                    operation: EvidenceOperation::ContextEscape,
                                    matched_input: format!("{} vs Host: {}", path, host),
                                    interpretation: "When the request line contains an absolute URL that differs from the Host header, proxies and backends may disagree on the target. This enables request smuggling and routing confusion.".into(),
                                    offset: 0,
                                    property: "Request line absolute URL host must match the Host header.".into(),
                                }],
                            });
                        }
                    }
                }
            }
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "host_header_xfh_injection"
            | "host_header_duplicate"
            | "host_header_authority_confusion"
            | "host_header_suspicious"
            | "host_header_port_override"
            | "host_header_proxy_override"
            | "host_header_absolute_url_mismatch"
            | "host_xforwarded_host_spoof"
            | "host_ipv6_injection" => Some(InvariantClass::HostHeaderInjection),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_port_override() {
        let eval = HostHeaderEvaluator;
        let dets = eval.detect("GET / HTTP/1.1\r\nHost: legit.com:8888\r\n\r\n");
        assert!(dets.iter().any(|d| d.detection_type == "host_header_port_override"));
    }

    #[test]
    fn detects_xfh_injection() {
        let eval = HostHeaderEvaluator;
        let dets = eval.detect("GET / HTTP/1.1\r\nHost: legit.com\r\nX-Forwarded-Host: evil.com\r\n\r\n");
        assert!(dets.iter().any(|d| d.detection_type == "host_header_xfh_injection"));
    }

    #[test]
    fn detects_duplicate_host() {
        let eval = HostHeaderEvaluator;
        let dets = eval.detect("GET / HTTP/1.1\r\nHost: legit.com\r\nHost: evil.com\r\n\r\n");
        assert!(dets.iter().any(|d| d.detection_type == "host_header_duplicate"));
    }

    #[test]
    fn detects_authority_confusion() {
        let eval = HostHeaderEvaluator;
        let dets = eval.detect("GET / HTTP/1.1\r\nHost: admin@evil.com\r\n\r\n");
        assert!(dets.iter().any(|d| d.detection_type == "host_header_authority_confusion"));
    }

    #[test]
    fn detects_proxy_override() {
        let eval = HostHeaderEvaluator;
        let dets = eval.detect("GET / HTTP/1.1\r\nHost: legit.com\r\nX-Original-URL: /admin\r\n\r\n");
        assert!(dets.iter().any(|d| d.detection_type == "host_header_proxy_override"));
    }

    #[test]
    fn detects_suspicious_host() {
        let eval = HostHeaderEvaluator;
        let dets = eval.detect("GET / HTTP/1.1\r\nHost: evil.attacker.com\r\n\r\n");
        assert!(dets.iter().any(|d| d.detection_type == "host_header_suspicious"));
    }

    #[test]
    fn no_detection_for_normal_host() {
        let eval = HostHeaderEvaluator;
        let dets = eval.detect("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
        assert!(dets.is_empty());
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = HostHeaderEvaluator;
        assert_eq!(
            eval.map_class("host_header_xfh_injection"),
            Some(InvariantClass::HostHeaderInjection)
        );
    }

    #[test]
    fn detects_host_xforwarded_host_spoof() {
        let eval = HostHeaderEvaluator;
        let dets = eval.detect("GET / HTTP/1.1\r\nX-Forwarded-Host: attacker.com\r\n\r\n");
        assert!(dets.iter().any(|d| d.detection_type == "host_xforwarded_host_spoof"));
    }

    #[test]
    fn detects_host_ipv6_injection() {
        let eval = HostHeaderEvaluator;
        let dets = eval.detect("GET / HTTP/1.1\r\nHost: [fe80::1%25eth0]\r\n\r\n");
        assert!(dets.iter().any(|d| d.detection_type == "host_ipv6_injection"));
    }
}
