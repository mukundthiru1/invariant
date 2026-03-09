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
use regex::Regex;
use std::sync::LazyLock;
type RustDetection = L2Detection;

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

const TAKEOVER_SUFFIXES: &[&str] = &[
    "amazonaws.com",
    "azurewebsites.net",
    "cloudapp.azure.com",
    "azurefd.net",
    "herokuapp.com",
    "herokudns.com",
    "fastly.net",
    "github.io",
    "githubusercontent.com",
    "netlify.app",
    "netlify.com",
    "vercel.app",
    "now.sh",
    "shopifypreview.com",
    "myshopify.com",
    "unbouncepages.com",
    "unbounce.com",
    "surge.sh",
    "bitbucket.io",
    "readme.io",
    "cargo.site",
];

static CNAME_TAKEOVER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bCNAME\b[^\n\r]{0,100}(?:amazonaws\.com|azurewebsites\.net|cloudapp\.azure\.com|azurefd\.net|herokuapp\.com|github\.io|netlify\.app|netlify\.com|vercel\.app|now\.sh|shopifypreview\.com|unbouncepages\.com|surge\.sh|bitbucket\.io|readme\.io|cargo\.site)").unwrap()
});

static CNAME_URL_PARAM_TAKEOVER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:\?|&)[^=\s&#]{1,64}\s*=\s*[^&#\s]{1,253}\.(?:amazonaws\.com|azurewebsites\.net|cloudapp\.azure\.com|azurefd\.net|herokuapp\.com|herokudns\.com|fastly\.net|github\.io|githubusercontent\.com|netlify\.app|netlify\.com|vercel\.app|now\.sh|shopifypreview\.com|myshopify\.com|unbouncepages\.com|unbounce\.com|surge\.sh|bitbucket\.io|readme\.io|cargo\.site)\b").unwrap()
});

static CNAME_FASTLY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bCNAME\b[^\n\r]{0,100}fastly\.net\b").unwrap());

static AXFR_INJECTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:AXFR|IXFR)\b|\btype\s*=\s*(?:AXFR|IXFR|255)\b|\bqtype\s*=\s*255\b|\bdig\s+\+AXFR\b|\bhost\s+-t\s+AXFR\b",
    )
    .unwrap()
});

static HEX_IP_REBINDING_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:0x[0-9a-f]{1,8}\.){3}0x[0-9a-f]{1,8}|(?:0[0-7]{3}\.){3}0[0-7]{3}").unwrap()
});

static ZONE_TRANSFER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:type\s*=\s*(?:axfr|ixfr|aXfR|iXfR)|qtype\s*=\s*252|qtype\s*=\s*251)").unwrap()
});

fn has_high_entropy_label(label: &str) -> bool {
    if label.len() < 12 {
        return false;
    }
    let valid = label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !valid {
        return false;
    }
    let unique = label
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len();
    let ratio = unique as f64 / label.len() as f64;
    let has_alpha = label.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = label.chars().any(|c| c.is_ascii_digit());
    if label.len() > 30 && label.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    ratio >= 0.55 && has_alpha && has_digit
}

fn detect_dns_cache_poisoning(input: &str) -> Option<RustDetection> {
    static QNAME_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?im)(?:qname|query|name)\s*[:=]\s*([a-z0-9.-]+\.[a-z]{2,})").unwrap()
    });
    static TTL_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?im)\bttl\s*[:=]\s*(\d{1,7})").unwrap());
    static RDATA_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?im)(?:rdata|answer|address|a-record)\s*[:=]\s*([a-z0-9.:_-]{3,128})")
            .unwrap()
    });

    let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
    let lower = decoded.to_ascii_lowercase();

    let mut qnames = Vec::new();
    for cap in QNAME_RE.captures_iter(&lower) {
        if let Some(m) = cap.get(1) {
            qnames.push(m.as_str().to_string());
        }
    }
    if qnames.len() < 2 {
        return None;
    }
    qnames.sort();
    let mut repeated_qname = None;
    for i in 0..(qnames.len() - 1) {
        if qnames[i] == qnames[i + 1] {
            repeated_qname = Some(qnames[i].clone());
            break;
        }
    }
    let Some(qname) = repeated_qname else {
        return None;
    };

    let mut ttls = Vec::new();
    for cap in TTL_RE.captures_iter(&lower) {
        if let Some(m) = cap.get(1) {
            ttls.push(m.as_str().to_string());
        }
    }
    ttls.sort();
    ttls.dedup();

    let mut rdata = Vec::new();
    for cap in RDATA_RE.captures_iter(&lower) {
        if let Some(m) = cap.get(1) {
            rdata.push(m.as_str().to_string());
        }
    }
    rdata.sort();
    rdata.dedup();

    let has_conflict = ttls.len() >= 2 || rdata.len() >= 2;
    if !has_conflict {
        return None;
    }

    let has_forged_authority = lower.contains("forged authority")
        || lower.contains("spoofed authority")
        || lower.contains("authority section");
    let has_txid_pattern = lower.contains("txid")
        && (lower.contains("predict")
            || lower.contains("sequential")
            || lower.contains("guessable"));
    if !has_forged_authority && !has_txid_pattern {
        return None;
    }

    let pos = lower.find(&qname).unwrap_or(0);
    Some(RustDetection {
        detection_type: "dns_cache_poisoning".into(),
        confidence: 0.90,
        detail: "Conflicting DNS response data for same QNAME with forged-authority/TXID cues indicates cache poisoning".into(),
        position: pos,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: decoded[..decoded.len().min(180)].to_string(),
            interpretation: "The same DNS name appears across multiple responses with conflicting TTL/RDATA and poisoning indicators, matching DNS cache poisoning behavior.".into(),
            offset: pos,
            property: "Resolvers should enforce source-port and TXID randomization, DNSSEC validation, and reject conflicting unsolicited authority data".into(),
        }],
    })
}

fn detect_dns_amplification_abuse(input: &str) -> Option<RustDetection> {
    static AMPLIFICATION_QUERY_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?im)\b(?:type|qtype)\s*[:=]\s*(?:any|dnskey|255|48)\b|\b(?:any|dnskey)\s+query\b")
            .unwrap()
    });

    let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
    let lower = decoded.to_ascii_lowercase();

    let query_match = AMPLIFICATION_QUERY_RE.find(&lower)?;
    let targets_open_resolver = lower.contains("8.8.8.8") || lower.contains("1.1.1.1");
    if !targets_open_resolver {
        return None;
    }

    let untrusted_context = lower.contains("spoof")
        || lower.contains("forged source")
        || lower.contains("source ip")
        || lower.contains("x-forwarded-for")
        || lower.contains("reflection")
        || lower.contains("amplification")
        || lower.contains("untrusted");
    if !untrusted_context {
        return None;
    }

    Some(RustDetection {
        detection_type: "dns_amplification_abuse".into(),
        confidence: 0.88,
        detail: "ANY/DNSKEY queries to open resolvers from spoofable context indicate DNS amplification abuse".into(),
        position: query_match.start(),
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: decoded[query_match.start()..decoded.len().min(query_match.end() + 120)]
                .to_string(),
            interpretation: "Large-response DNS query types (ANY/DNSKEY) sent toward open resolvers in spoofable context are characteristic of reflection/amplification DDoS traffic.".into(),
            offset: query_match.start(),
            property: "Reject spoofable DNS relay behavior, block amplification-prone query types, and restrict resolver usage to trusted sources".into(),
        }],
    })
}

fn detect_dns_tunnel_exfil(input: &str) -> Option<RustDetection> {
    static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62}){2,}\b").unwrap()
    });
    let known_good_tlds = [
        "com", "net", "org", "io", "co", "app", "dev", "cloud", "edu", "gov",
    ];

    let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
    let lower = decoded.to_ascii_lowercase();

    for m in DOMAIN_RE.find_iter(&lower) {
        let domain = m.as_str();
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() < 3 {
            continue;
        }
        let tld = labels[labels.len() - 1];
        if !known_good_tlds.contains(&tld) {
            continue;
        }
        let suspicious = labels[..labels.len() - 2]
            .iter()
            .any(|label| label.len() > 30 && has_high_entropy_label(label));
        if suspicious {
            return Some(RustDetection {
                detection_type: "dns_tunnel_exfil".into(),
                confidence: 0.91,
                detail: "Very long high-entropy subdomain label before common TLD indicates DNS tunnel exfiltration".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[m.start()..decoded.len().min(m.end() + 80)].to_string(),
                    interpretation: "Subdomain labels contain long high-entropy encoded-like data, consistent with DNS tunneling used for covert exfiltration.".into(),
                    offset: m.start(),
                    property: "Outbound DNS should enforce label-length/entropy anomaly detection and block encoded payload transfer via subdomains".into(),
                }],
            });
        }
    }

    None
}

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

        // 5. Dangling CNAME takeover indicators
        let takeover_pos = CNAME_TAKEOVER_RE
            .find(&decoded)
            .map(|m| m.start())
            .or_else(|| {
                CNAME_URL_PARAM_TAKEOVER_RE
                    .find(&decoded)
                    .map(|m| m.start())
            })
            .or_else(|| {
                if CNAME_FASTLY_RE.is_match(&decoded)
                    && (lower.contains("404")
                        || lower.contains("nxdomain")
                        || lower.contains("not found"))
                {
                    CNAME_FASTLY_RE.find(&decoded).map(|m| m.start())
                } else {
                    None
                }
            })
            .or_else(|| {
                if lower.contains("cname") {
                    TAKEOVER_SUFFIXES
                        .iter()
                        .find_map(|suffix| lower.find(suffix).filter(|_| lower.contains("cname")))
                } else {
                    None
                }
            });

        if let Some(pos) = takeover_pos {
            dets.push(L2Detection {
                detection_type: "dns_subdomain_takeover".into(),
                confidence: 0.87,
                detail: "Potential dangling CNAME to vulnerable SaaS/cloud takeover target".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[pos.saturating_sub(20)..decoded.len().min(pos + 120)]
                        .to_string(),
                    interpretation: "Input references a CNAME target that matches known subdomain takeover-prone SaaS/cloud domains. Unclaimed resources behind dangling CNAME records can be re-registered by attackers.".into(),
                    offset: pos,
                    property: "CNAME targets to third-party SaaS/cloud services must be continuously verified as claimed and returning expected ownership responses.".into(),
                }],
            });
        }

        // 6. DNS zone transfer (AXFR/IXFR) injection indicators
        if let Some(m) = AXFR_INJECTION_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "dns_axfr_injection".into(),
                confidence: 0.91,
                detail: "DNS zone transfer query type injection detected (AXFR/IXFR/ANY)".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[m.start()..decoded.len().min(m.end() + 80)].to_string(),
                    interpretation: "Input attempts to inject DNS transfer query types (AXFR/IXFR/ANY), which can be used to enumerate complete DNS zones when resolvers or authorities are misconfigured.".into(),
                    offset: m.start(),
                    property: "User-controlled DNS query parameters must not allow AXFR/IXFR/ANY transfer/zone-enumeration query types.".into(),
                }],
            });
        }

        // 7. Hex/Octal IP Rebinding
        if let Some(m) = HEX_IP_REBINDING_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "dns_hex_ip_rebinding".into(),
                confidence: 0.90,
                detail: "Hex/octal encoded IP address detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[m.start()..decoded.len().min(m.end() + 80)].to_string(),
                    interpretation: "Hex/octal encoded IP addresses (0x7f000001, 0177.0.0.01) bypass IP allowlist validation while resolving to the same address. Used for SSRF and DNS rebinding attacks".into(),
                    offset: m.start(),
                    property: "IP address validation must normalize all hex/octal/decimal formats before comparison to detect 127.0.0.1 variants".into(),
                }],
            });
        }

        // 8. Zone Transfer Attempt
        if let Some(m) = ZONE_TRANSFER_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "dns_zone_transfer_attempt".into(),
                confidence: 0.92,
                detail: "DNS zone transfer request type detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[m.start()..decoded.len().min(m.end() + 80)].to_string(),
                    interpretation: "AXFR and IXFR DNS query types request full zone transfers. If allowed, they expose the entire DNS zone including internal hostnames, IP addresses, and infrastructure topology".into(),
                    offset: m.start(),
                    property: "DNS zone transfers must be restricted to authorized secondary nameservers. AXFR/IXFR queries must be blocked from untrusted sources".into(),
                }],
            });
        }

        if let Some(det) = detect_dns_cache_poisoning(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_dns_amplification_abuse(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_dns_tunnel_exfil(&decoded) {
            dets.push(det);
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "dns_rebinding_service"
            | "dns_ip_subdomain"
            | "dns_exfiltration"
            | "dns_dash_ip"
            | "dns_axfr_injection"
            | "dns_hex_ip_rebinding"
            | "dns_zone_transfer_attempt"
            | "dns_cache_poisoning"
            | "dns_amplification_abuse"
            | "dns_tunnel_exfil" => Some(InvariantClass::DnsRebinding),
            "dns_subdomain_takeover" => Some(InvariantClass::SubdomainTakeover),
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

    #[test]
    fn test_cname_github_io_takeover() {
        let eval = DnsEvaluator;
        let dets = eval.detect("sub.example.com CNAME something.github.io");
        assert!(dets.iter().any(|d| d.detection_type == "dns_subdomain_takeover"));
    }

    #[test]
    fn test_cname_netlify_takeover() {
        let eval = DnsEvaluator;
        let dets = eval.detect("CNAME myapp.netlify.app");
        assert!(dets.iter().any(|d| d.detection_type == "dns_subdomain_takeover"));
    }

    #[test]
    fn test_axfr_query() {
        let eval = DnsEvaluator;
        let dets = eval.detect("type=AXFR");
        assert!(dets.iter().any(|d| d.detection_type == "dns_axfr_injection"));
    }

    #[test]
    fn test_ixfr_query() {
        let eval = DnsEvaluator;
        let dets = eval.detect("IXFR");
        assert!(dets.iter().any(|d| d.detection_type == "dns_axfr_injection"));
    }

    #[test]
    fn test_hex_ip_rebinding() {
        let eval = DnsEvaluator;
        let dets = eval.detect("http://0x7f.0x00.0x00.0x01/");
        assert!(dets.iter().any(|d| d.detection_type == "dns_hex_ip_rebinding"));
    }

    #[test]
    fn test_zone_transfer_attempt() {
        let eval = DnsEvaluator;
        let dets = eval.detect("qtype=252");
        assert!(dets.iter().any(|d| d.detection_type == "dns_zone_transfer_attempt"));
    }

    #[test]
    fn detects_dns_cache_poisoning_conflicting_responses() {
        let input = "dns response qname=api.example.com ttl=60 rdata=1.1.1.1\n\
dns response qname=api.example.com ttl=300 rdata=8.8.8.8 forged authority section txid predictable";
        let det = detect_dns_cache_poisoning(input).expect("expected cache poisoning detection");
        assert_eq!(det.detection_type, "dns_cache_poisoning");
        assert_eq!(det.confidence, 0.90);
    }

    #[test]
    fn no_dns_cache_poisoning_without_conflict() {
        let input = "dns response qname=api.example.com ttl=60 rdata=1.1.1.1 txid predictable";
        assert!(detect_dns_cache_poisoning(input).is_none());
    }

    #[test]
    fn detects_dns_amplification_abuse_any_query() {
        let input = "qtype=ANY resolver=8.8.8.8 source ip spoofed reflection attack";
        let det =
            detect_dns_amplification_abuse(input).expect("expected dns amplification abuse detection");
        assert_eq!(det.detection_type, "dns_amplification_abuse");
        assert_eq!(det.confidence, 0.88);
    }

    #[test]
    fn no_dns_amplification_abuse_for_trusted_context() {
        let input = "qtype=DNSKEY resolver=8.8.8.8 normal maintenance lookup";
        assert!(detect_dns_amplification_abuse(input).is_none());
    }

    #[test]
    fn detects_dns_tunnel_exfil_long_entropy_label() {
        let input = "lookup a9f0b7d4c1e2f3a4b5c6d7e8f9a0b1c2.data.example.com";
        let det = detect_dns_tunnel_exfil(input).expect("expected dns tunnel exfil detection");
        assert_eq!(det.detection_type, "dns_tunnel_exfil");
        assert_eq!(det.confidence, 0.91);
    }

    #[test]
    fn no_dns_tunnel_exfil_for_short_labels() {
        let input = "lookup api.dev.example.com";
        assert!(detect_dns_tunnel_exfil(input).is_none());
    }
}
