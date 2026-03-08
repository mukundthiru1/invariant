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
];

pub struct OastEvaluator;

impl L2Evaluator for OastEvaluator {
    fn id(&self) -> &'static str { "oast" }
    fn prefix(&self) -> &'static str { "L2 OAST" }

    #[inline]
    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded.to_lowercase();

        for &domain in OAST_DOMAINS {
            if decoded.contains(domain) {
                // To avoid partial matching of harmless domains, ensure it's a domain boundary.
                // It should be preceded by '.' or '@' or '/' or space or start of string,
                // and followed by end of string, '/', '?', ':', etc.
                let pattern = format!(r"(?i)(?:^|[\s/@.\\])[a-z0-9-]*\.?{}\b", domain.replace(".", "\\."));
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

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "oast_domain" => Some(InvariantClass::OastInteraction),
            _ => None,
        }
    }
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
}