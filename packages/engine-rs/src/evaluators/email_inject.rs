//! Email Header Injection Evaluator — Level 2
//!
//! Detects SMTP header injection attacks through web application input.
//! Attackers inject CRLF sequences (or equivalent) into fields that are
//! used in email header construction (To, CC, BCC, Subject, etc.).
//!
//! Impact: spam relay, phishing via legitimate domain, data exfiltration.

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;

/// SMTP header names that attackers inject.
const SMTP_HEADERS: &[&str] = &[
    "to:", "cc:", "bcc:", "from:", "reply-to:",
    "subject:", "content-type:", "mime-version:",
    "x-mailer:", "return-path:", "sender:",
];

pub struct EmailInjectEvaluator;

impl L2Evaluator for EmailInjectEvaluator {
    fn id(&self) -> &'static str {
        "email_inject"
    }
    fn prefix(&self) -> &'static str {
        "L2 EmailInject"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
        let lower = decoded.to_ascii_lowercase();

        // 1. CRLF + SMTP header injection
        // The core attack: inject \r\n followed by an SMTP header
        let has_crlf = lower.contains("\r\n") || lower.contains("%0d%0a") || lower.contains("%0a");
        if has_crlf {
            for &header in SMTP_HEADERS {
                if lower.contains(header) {
                    let pos = lower.find(header).unwrap_or(0);
                    dets.push(L2Detection {
                        detection_type: "email_header_injection".into(),
                        confidence: 0.92,
                        detail: format!(
                            "CRLF sequence followed by SMTP header '{}' — email header injection",
                            header.trim_end_matches(':')
                        ),
                        position: pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::ContextEscape,
                            matched_input: decoded[pos..decoded.len().min(pos + 60)].to_string(),
                            interpretation: format!(
                                "Input contains CRLF (line break) followed by SMTP header '{}'. When used in email composition, this injects additional headers, allowing the attacker to add recipients (BCC for data theft), change the sender (phishing), or modify the body.",
                                header.trim_end_matches(':')
                            ),
                            offset: pos,
                            property: "User input incorporated into email headers must not contain newline characters or SMTP header syntax.".into(),
                        }],
                    });
                    break; // one detection is sufficient
                }
            }
        }

        // 2. Multiple email addresses in a single field (CC/BCC injection without CRLF)
        // Pattern: user@domain, user2@domain, user3@domain
        let email_count = lower
            .split(|c: char| c == ',' || c == ';' || c == ' ')
            .filter(|s| s.contains('@') && s.contains('.') && s.len() > 5)
            .count();

        if email_count >= 3 {
            dets.push(L2Detection {
                detection_type: "email_mass_recipient".into(),
                confidence: 0.78,
                detail: format!(
                    "{} email addresses detected in input — potential mass recipient injection",
                    email_count
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(100)].to_string(),
                    interpretation: "Input contains multiple email addresses separated by commas or semicolons. When this input is used as a recipient field, the attacker can send email to arbitrary recipients through the application's mail server.".into(),
                    offset: 0,
                    property: "Recipient fields must accept only the intended number of addresses. Multi-recipient input must be validated against an allowlist.".into(),
                }],
            });
        }

        // 3. MIME boundary injection
        if lower.contains("content-type:") && lower.contains("boundary=") {
            dets.push(L2Detection {
                detection_type: "email_mime_injection".into(),
                confidence: 0.88,
                detail: "MIME Content-Type with boundary parameter — multipart email body injection".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(120)].to_string(),
                    interpretation: "Input contains a MIME Content-Type header with a boundary parameter. This enables multipart email body injection, allowing the attacker to attach arbitrary files or replace the email body entirely.".into(),
                    offset: 0,
                    property: "User input must not contain MIME headers or boundary definitions.".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "email_header_injection" | "email_mass_recipient" | "email_mime_injection" => {
                Some(InvariantClass::EmailHeaderInjection)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_crlf_bcc_injection() {
        let eval = EmailInjectEvaluator;
        let dets = eval.detect("user@example.com\r\nBcc: attacker@evil.com");
        assert!(dets.iter().any(|d| d.detection_type == "email_header_injection"));
    }

    #[test]
    fn detects_encoded_crlf_injection() {
        let eval = EmailInjectEvaluator;
        let dets = eval.detect("user@example.com%0d%0aBcc: attacker@evil.com");
        assert!(dets.iter().any(|d| d.detection_type == "email_header_injection"));
    }

    #[test]
    fn detects_mass_recipient() {
        let eval = EmailInjectEvaluator;
        let dets = eval.detect("a@b.com, c@d.com, e@f.com, g@h.com");
        assert!(dets.iter().any(|d| d.detection_type == "email_mass_recipient"));
    }

    #[test]
    fn detects_mime_injection() {
        let eval = EmailInjectEvaluator;
        let dets = eval.detect("Subject: test\r\nContent-Type: multipart/mixed; boundary=evil\r\n\r\n");
        assert!(dets.iter().any(|d| d.detection_type == "email_mime_injection"));
    }

    #[test]
    fn no_detection_for_normal_email() {
        let eval = EmailInjectEvaluator;
        let dets = eval.detect("user@example.com");
        assert!(dets.is_empty());
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = EmailInjectEvaluator;
        assert_eq!(
            eval.map_class("email_header_injection"),
            Some(InvariantClass::EmailHeaderInjection)
        );
    }
}
