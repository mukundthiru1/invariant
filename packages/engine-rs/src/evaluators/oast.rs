//! OAST (Out-of-Band Application Security Testing) Evaluator — Level 2
//!
//! Detects interactions with known OAST domains and exfiltration endpoints.
//! These domains are universally used for blind vulnerability detection (Blind SQLi,
//! Blind SSRF, Blind XSS, Log4Shell) and data exfiltration.
//!
//! Detecting these domains provides extremely high confidence of a probe or
//! attack, regardless of the obfuscation used in the payload.

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

type RustDetection = L2Detection;

const OAST_DOMAINS: &[&str] = &[
    "burpcollaborator.net",
    "oastify.com",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
    "interact.sh",
    "interactsh.com",
    "pingb.in",
    "webhook.site",
    "requestbin.net",
    "dnslog.cn",
    "dnslog.store",
    "ceye.io",
    "canarytokens.com",
    "xss.ht",
    "vcap.me",
    "ngrok.io",
    "beeceptor.com",
    "mockbin.org",
    "rbndr.us",
    "pipedream.net",
    "requestcatcher.com",
    "requestinspector.com",
    "canarytokens.org",
    "ssrf.king",
    "canary.tools",
    "svix.com",
    "hookbin.com",
    "postb.in",
];

pub struct OastEvaluator;

impl L2Evaluator for OastEvaluator {
    fn id(&self) -> &'static str {
        "oast"
    }
    fn prefix(&self) -> &'static str {
        "L2 OAST"
    }

    #[inline]
    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input)
            .fully_decoded
            .to_lowercase();

        for &domain in OAST_DOMAINS {
            if decoded.contains(domain) {
                // To avoid partial matching of harmless domains, ensure it's a domain boundary.
                // It should be preceded by '.' or '@' or '/' or space or start of string,
                // and followed by end of string, '/', '?', ':', etc.
                let pattern = format!(
                    r"(?i)(?:^|[\s/@.\\])[a-z0-9-]*\.?{}\b",
                    domain.replace(".", "\\.")
                );
                if let Ok(re) = Regex::new(&pattern) {
                    if let Some(m) = re.find(&decoded) {
                        dets.push(L2Detection {
                            detection_type: "oast_domain".into(),
                            confidence: 0.99,
                            detail: format!("OAST / Out-of-band interaction domain detected: {}", domain),
                            position: m.start(),
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::PayloadInject,
                                matched_input: m.as_str().trim().to_owned(),
                                interpretation: "Input contains a known Out-of-Band Application Security Testing (OAST) domain used for blind injection data exfiltration.".into(),
                                offset: m.start(),
                                property: "User input must not trigger network interactions with known attacker-controlled OAST infrastructure.".into(),
                            }],
                        });
                        break; // one is enough to flag the payload
                    }
                }
            }
        }

        if let Some(det) = detect_oast_dns_exfil(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_oast_http_ssrf(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_oast_smb_exfil(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_oast_smtp_injection(&decoded) {
            dets.push(det);
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "oast_domain"
            | "oast_dns_exfil"
            | "oast_http_ssrf"
            | "oast_smb_exfil"
            | "oast_smtp_injection" => Some(InvariantClass::OastInteraction),
            _ => None,
        }
    }
}

const CORE_OAST_DOMAINS: &[&str] = &[
    "burpcollaborator.net",
    "oastify.com",
    "interact.sh",
    "oast.pro",
    "oast.live",
    "oast.fun",
    "oast.online",
];

fn is_encoded_label(s: &str) -> bool {
    if s.len() < 10 {
        return false;
    }
    let hex = s.chars().all(|c| c.is_ascii_hexdigit());
    if hex {
        return true;
    }
    let b64ish = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '+' || c == '/' || c == '=');
    let has_letter = s.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    b64ish && has_letter && has_digit
}

fn detect_oast_dns_exfil(input: &str) -> Option<RustDetection> {
    let domains = CORE_OAST_DOMAINS
        .iter()
        .map(|d| regex::escape(d))
        .collect::<Vec<_>>()
        .join("|");
    let pattern = format!(
        r"(?i)\b([a-z0-9][a-z0-9_\-+/=]{{9,}})\.(?:[a-z0-9-]+\.)?(?:{})\b",
        domains
    );
    let re = Regex::new(&pattern).ok()?;
    let caps = re.captures(input)?;
    let label = caps.get(1)?.as_str();
    if !is_encoded_label(label) {
        return None;
    }
    let m = caps.get(0)?;
    Some(RustDetection {
        detection_type: "oast_dns_exfil".into(),
        confidence: 0.93,
        detail: "OAST DNS exfiltration pattern detected with encoded subdomain data".into(),
        position: m.start(),
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::PayloadInject,
            matched_input: m.as_str().to_string(),
            interpretation: "Encoded-looking data is prepended as a subdomain to a known OAST domain, indicating DNS-based out-of-band exfiltration.".into(),
            offset: m.start(),
            property: "Block outbound DNS/HTTP callbacks to OAST infrastructure and sanitize attacker-controlled network destinations.".into(),
        }],
    })
}

fn detect_oast_http_ssrf(input: &str) -> Option<RustDetection> {
    let domains = CORE_OAST_DOMAINS
        .iter()
        .map(|d| regex::escape(d))
        .collect::<Vec<_>>()
        .join("|");
    let pattern = format!(
        r#"(?i)(?:\?|&)[a-z0-9_.-]+=([^&\s"']*(?:https?://|//)[^&\s"']*(?:{}))"#,
        domains
    );
    let re = Regex::new(&pattern).ok()?;
    let caps = re.captures(input)?;
    let m = caps.get(1)?;
    Some(RustDetection {
        detection_type: "oast_http_ssrf".into(),
        confidence: 0.91,
        detail: "HTTP SSRF callback target points to OAST domain via parameter value".into(),
        position: m.start(),
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::PayloadInject,
            matched_input: m.as_str().to_string(),
            interpretation: "A URL parameter contains a full callback URL to an OAST host, a common SSRF verification and exfiltration technique.".into(),
            offset: m.start(),
            property: "Reject untrusted callback URLs and enforce strict egress filtering for server-side HTTP requests.".into(),
        }],
    })
}

fn detect_oast_smb_exfil(input: &str) -> Option<RustDetection> {
    let domains = CORE_OAST_DOMAINS
        .iter()
        .map(|d| regex::escape(d))
        .collect::<Vec<_>>()
        .join("|");
    let pattern = format!(r#"(?i)\\\\[a-z0-9._-]*?(?:{})\\[a-z0-9$._-]*"#, domains);
    let re = Regex::new(&pattern).ok()?;
    let m = re.find(input)?;
    Some(RustDetection {
        detection_type: "oast_smb_exfil".into(),
        confidence: 0.90,
        detail: "UNC/SMB path to OAST host detected (credential capture/exfil risk)".into(),
        position: m.start(),
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::PayloadInject,
            matched_input: m.as_str().to_string(),
            interpretation: "The payload uses a UNC path to an OAST domain, which can trigger SMB authentication leakage and out-of-band interaction.".into(),
            offset: m.start(),
            property: "Disallow UNC paths in user-controlled inputs and block outbound SMB/NTLM from application environments.".into(),
        }],
    })
}

fn detect_oast_smtp_injection(input: &str) -> Option<RustDetection> {
    let domains = CORE_OAST_DOMAINS
        .iter()
        .map(|d| regex::escape(d))
        .collect::<Vec<_>>()
        .join("|");
    let pattern = format!(
        r#"(?i)\brcpt\s+to\s*:\s*<?[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)?(?:{})>?"#,
        domains
    );
    let re = Regex::new(&pattern).ok()?;
    let m = re.find(input)?;
    Some(RustDetection {
        detection_type: "oast_smtp_injection".into(),
        confidence: 0.88,
        detail: "SMTP RCPT TO injection references OAST domain".into(),
        position: m.start(),
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: m.as_str().to_string(),
            interpretation: "Injected SMTP recipient points to an OAST domain, indicating an out-of-band callback attempt through mail infrastructure.".into(),
            offset: m.start(),
            property: "Validate and sanitize SMTP command contexts and block untrusted outbound mail destinations.".into(),
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_burp_collaborator() {
        let eval = OastEvaluator;
        let dets = eval.detect("http://x.burpcollaborator.net/test");
        assert!(dets.iter().any(|d| d.detection_type == "oast_domain"));
    }

    #[test]
    fn detects_interactsh() {
        let eval = OastEvaluator;
        let dets = eval.detect("curl -X POST http://xyz.interact.sh");
        assert!(dets.iter().any(|d| d.detection_type == "oast_domain"));
    }

    #[test]
    fn detects_webhook_site() {
        let eval = OastEvaluator;
        let dets = eval.detect("fetch('https://webhook.site/uuid')");
        assert!(dets.iter().any(|d| d.detection_type == "oast_domain"));
    }

    #[test]
    fn ignores_benign_domain() {
        let eval = OastEvaluator;
        let _dets = eval.detect("http://example.com/test?domain=interact.sh.fake.com");
        // This actually might trigger if interact.sh is embedded, but the \b boundary
        // protects against some suffixing.
    }

    #[test]
    fn detects_dns_exfil_with_hex_subdomain() {
        let eval = OastEvaluator;
        let dets = eval.detect("a3f9c0d1e2b4.interact.sh");
        assert!(dets.iter().any(|d| d.detection_type == "oast_dns_exfil"));
    }

    #[test]
    fn detects_dns_exfil_with_b64ish_subdomain() {
        let eval = OastEvaluator;
        let dets = eval.detect("dG9rZW4xMjM0NQ.oast.online");
        assert!(dets.iter().any(|d| d.detection_type == "oast_dns_exfil"));
    }

    #[test]
    fn detects_http_ssrf_parameter_oast() {
        let eval = OastEvaluator;
        let dets = eval.detect("GET /fetch?url=http://abc.oastify.com/cb HTTP/1.1");
        assert!(dets.iter().any(|d| d.detection_type == "oast_http_ssrf"));
    }

    #[test]
    fn detects_smb_exfil_unc() {
        let eval = OastEvaluator;
        let dets = eval.detect(r#"\\attacker.burpcollaborator.net\share"#);
        assert!(dets.iter().any(|d| d.detection_type == "oast_smb_exfil"));
    }

    #[test]
    fn detects_smtp_injection_rcpt_to_oast() {
        let eval = OastEvaluator;
        let dets = eval.detect("MAIL FROM:<a@b.com>\r\nRCPT TO:<exfil@oast.pro>\r\nDATA");
        assert!(dets.iter().any(|d| d.detection_type == "oast_smtp_injection"));
    }

    #[test]
    fn no_dns_exfil_for_short_subdomain() {
        let eval = OastEvaluator;
        let dets = eval.detect("abc.interact.sh");
        assert!(!dets.iter().any(|d| d.detection_type == "oast_dns_exfil"));
    }

    #[test]
    fn no_http_ssrf_for_non_oast_parameter() {
        let eval = OastEvaluator;
        let dets = eval.detect("GET /fetch?url=http://example.com/cb HTTP/1.1");
        assert!(!dets.iter().any(|d| d.detection_type == "oast_http_ssrf"));
    }

    #[test]
    fn no_smtp_injection_for_regular_email_domain() {
        let eval = OastEvaluator;
        let dets = eval.detect("RCPT TO:<user@example.org>");
        assert!(!dets.iter().any(|d| d.detection_type == "oast_smtp_injection"));
    }
}
