//! DNS Rebinding & Exfiltration Evaluator — Level 2
//!
//! Detects DNS-based attack signals in HTTP input:
//!   - DNS rebinding (attacker domain resolving to internal IP)
//!   - DNS exfiltration (data encoded in subdomain labels)
//!   - Suspicious DNS record references in input
//!
//! This evaluator catches signals that other evaluators miss because
//! the payload is in DNS labels rather than traditional injection vectors.

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;

/// Known DNS rebinding services.
const REBINDING_DOMAINS: &[&str] = &[
    "rbndr.us",
    "rbnd.io",
    "nip.io",
    "sslip.io",
    "xip.io",
    "1u.ms",
    "lock.cmpxchg8b.com",
    "rebind.network",
];

pub struct DnsEvaluator;

impl L2Evaluator for DnsEvaluator {
    fn id(&self) -> &'static str {
        "dns"
    }
    fn prefix(&self) -> &'static str {
        "L2 DNS"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
        let lower = decoded.to_ascii_lowercase();

        // 1. DNS rebinding service domains
        for &domain in REBINDING_DOMAINS {
            if lower.contains(domain) {
                let pos = lower.find(domain).unwrap_or(0);
                dets.push(L2Detection {
                    detection_type: "dns_rebinding_service".into(),
                    confidence: 0.91,
                    detail: format!("DNS rebinding service detected: {}", domain),
                    position: pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded[pos.saturating_sub(20)..decoded.len().min(pos + 40)].to_string(),
                        interpretation: format!(
                            "Input contains domain '{}' which is a DNS rebinding service. These services alternate DNS responses between an external IP and an internal IP (e.g., 127.0.0.1, 169.254.169.254), bypassing same-origin policy and SSRF protections.",
                            domain
                        ),
                        offset: pos,
                        property: "URLs containing known DNS rebinding service domains must be rejected. DNS resolution results must be validated against internal IP ranges.".into(),
                    }],
                });
                break;
            }
        }

        // 2. IP-in-subdomain patterns (DNS rebinding / SSRF bypass)
        // Patterns: 127.0.0.1.nip.io, 10-0-0-1.example.com, A.B.C.D.domain
        let ip_in_domain_patterns = [
            // Decimal octets as subdomain labels
            ("127.0.0.1.", "loopback IP embedded in domain"),
            ("10.0.0.", "private network IP (10.x) embedded in domain"),
            ("192.168.", "private network IP (192.168.x) embedded in domain"),
            ("172.16.", "private network IP (172.16.x) embedded in domain"),
            ("169.254.169.254", "cloud metadata IP embedded in domain"),
        ];

        for &(pattern, desc) in &ip_in_domain_patterns {
            if lower.contains(pattern) {
                // Check if it's part of a domain name (followed by more labels)
                if let Some(pos) = lower.find(pattern) {
                    let after = &lower[pos + pattern.len()..];
                    if after.contains('.') || after.contains('/') {
                        dets.push(L2Detection {
                            detection_type: "dns_ip_subdomain".into(),
                            confidence: 0.85,
                            detail: format!("{} — potential DNS rebinding or SSRF bypass", desc),
                            position: pos,
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::PayloadInject,
                                matched_input: decoded[pos..decoded.len().min(pos + 60)].to_string(),
                                interpretation: format!(
                                    "Input contains a {} as part of a domain name. Services like nip.io and sslip.io resolve these domains to the embedded IP, bypassing SSRF protections that block direct IP access.",
                                    desc
                                ),
                                offset: pos,
                                property: "DNS resolution results must be validated against internal IP ranges regardless of the domain name used. IP addresses must not be extracted from domain labels.".into(),
                            }],
                        });
                        break;
                    }
                }
            }
        }

        // 3. DNS exfiltration patterns (data encoded in subdomain labels)
        // Pattern: base64/hex data as subdomain labels, very long subdomains
        // Example: dGVzdCBkYXRh.evil.com (base64 of "test data")
        let dot_count = lower.matches('.').count();
        if dot_count >= 3 {
            // Check for unusually long subdomain labels (>20 chars of hex/base64)
            let labels: Vec<&str> = lower.split('.').collect();
            let long_labels = labels.iter().filter(|l| {
                l.len() > 20 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            }).count();

            if long_labels >= 2 {
                dets.push(L2Detection {
                    detection_type: "dns_exfiltration".into(),
                    confidence: 0.79,
                    detail: format!(
                        "Suspicious DNS pattern: {} labels, {} with encoded-looking data — potential DNS exfiltration",
                        dot_count + 1,
                        long_labels
                    ),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: decoded[..decoded.len().min(100)].to_string(),
                        interpretation: "Input contains a domain name with long subdomain labels containing encoded data. This pattern is used for DNS exfiltration where stolen data is encoded into subdomain labels and sent via DNS queries to an attacker-controlled nameserver.".into(),
                        offset: 0,
                        property: "Outbound DNS queries must not contain encoded data in subdomain labels. DNS monitoring should flag queries with unusually long or high-entropy subdomain labels.".into(),
                    }],
                });
            }
        }

        // 4. Dash-separated IP in domain (10-0-0-1.example.com, common cloud patterns)
        if lower.contains("10-0-0-") || lower.contains("192-168-") || lower.contains("172-16-") {
            dets.push(L2Detection {
                detection_type: "dns_dash_ip".into(),
                confidence: 0.82,
                detail: "Dash-separated private IP pattern in domain — potential DNS rebinding or internal routing bypass".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: lower[..lower.len().min(80)].to_string(),
                    interpretation: "Input contains a domain with dash-separated private IP address octets (e.g., 10-0-0-1.example.com). Some cloud services and DNS rebinding tools resolve these to the embedded IP. This bypasses URL-based SSRF protections.".into(),
                    offset: 0,
                    property: "DNS resolution results must be validated against internal IP ranges. Domain names with embedded IP patterns must be flagged.".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "dns_rebinding_service"
            | "dns_ip_subdomain"
            | "dns_exfiltration"
            | "dns_dash_ip" => Some(InvariantClass::DnsRebinding),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_rebinding_service() {
        let eval = DnsEvaluator;
        let dets = eval.detect("http://127.0.0.1.rbndr.us/admin");
        assert!(dets.iter().any(|d| d.detection_type == "dns_rebinding_service"));
    }

    #[test]
    fn detects_nip_io() {
        let eval = DnsEvaluator;
        let dets = eval.detect("http://10.0.0.1.nip.io/internal");
        assert!(dets.iter().any(|d| d.detection_type == "dns_rebinding_service"));
    }

    #[test]
    fn detects_metadata_ip_in_domain() {
        let eval = DnsEvaluator;
        let dets = eval.detect("http://169.254.169.254.evil.com/latest/meta-data");
        assert!(dets.iter().any(|d| d.detection_type == "dns_ip_subdomain"));
    }

    #[test]
    fn detects_dash_ip() {
        let eval = DnsEvaluator;
        let dets = eval.detect("http://10-0-0-1.internal.example.com/api");
        assert!(dets.iter().any(|d| d.detection_type == "dns_dash_ip"));
    }

    #[test]
    fn no_detection_for_normal_domain() {
        let eval = DnsEvaluator;
        let dets = eval.detect("http://www.google.com/search?q=hello");
        assert!(dets.is_empty());
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = DnsEvaluator;
        assert_eq!(
            eval.map_class("dns_rebinding_service"),
            Some(InvariantClass::DnsRebinding)
        );
    }
}
