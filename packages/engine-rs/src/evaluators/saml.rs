//! SAML Authentication Bypass Evaluator — Level 2
//!
//! Detects attacks against SAML-based SSO:
//!   - Signature wrapping (XSW) attacks
//!   - Comment injection in NameID
//!   - XML signature exclusion
//!   - Assertion replay
//!   - Audience restriction bypass

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use base64::Engine as _;
use regex::Regex;

type RustDetection = L2Detection;

pub struct SamlEvaluator;

impl L2Evaluator for SamlEvaluator {
    fn id(&self) -> &'static str {
        "saml"
    }
    fn prefix(&self) -> &'static str {
        "L2 SAML"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
        let lower = decoded.to_ascii_lowercase();
        let attribute_injection_re = Regex::new(
            r"(?i)<(?:saml[p2]?:)?(?:AttributeStatement|Attribute)[^>]*>(?:[^<]{0,200})?(?:admin|root|superuser|administrator|role=|permission=|is_superuser|is_root|staff|is_staff|elevated|privileged|owner|isowner|is_owner)",
        )
        .expect("valid regex");
        let audience_bypass_re = Regex::new(
            r"(?i)<(?:saml[p2]?:)?(?:AudienceRestriction|Audience)\s*/>|<(?:saml[p2]?:)?Audience>\s*(?:ANY|\*|everyone|all)\s*</",
        )
        .expect("valid regex");
        let saml_response_re = Regex::new(r"SAMLResponse=[A-Za-z0-9+/%]{20,}").expect("valid regex");

        // Only run on SAML-like input
        if !lower.contains("saml")
            && !lower.contains("assertion")
            && !lower.contains("nameid")
            && !lower.contains("samlresponse=")
        {
            return dets;
        }

        // 1. Signature wrapping (XSW) — duplicate Assertion elements
        let assertion_count = lower.matches("<saml:assertion").count()
            + lower.matches("<assertion").count()
            + lower.matches("<saml2:assertion").count();

        if assertion_count >= 2 {
            dets.push(L2Detection {
                detection_type: "saml_signature_wrapping".into(),
                confidence: 0.93,
                detail: format!(
                    "{} SAML Assertion elements detected — XML Signature Wrapping (XSW) attack",
                    assertion_count
                ),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: decoded[..decoded.len().min(200)].to_string(),
                    interpretation: "Multiple SAML Assertion elements in a single response enable XML Signature Wrapping (XSW). The signature validates against one Assertion while the application processes a different (attacker-controlled) Assertion, allowing authentication bypass.".into(),
                    offset: 0,
                    property: "SAML responses must contain exactly one Assertion. The signed Assertion must be the one the application processes. Canonicalization must prevent document restructuring.".into(),
                }],
            });
        }

        // 2. Comment injection in NameID
        // <NameID>admin<!---->@evil.com</NameID>
        if lower.contains("nameid") && lower.contains("<!--") {
            dets.push(L2Detection {
                detection_type: "saml_nameid_comment".into(),
                confidence: 0.91,
                detail: "XML comment inside SAML NameID — comment truncation attack".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: decoded[..decoded.len().min(150)].to_string(),
                    interpretation: "XML comments inside NameID can cause identity truncation. Some SAML libraries parse the text content as 'admin' (first text node before comment) while the IdP signed 'admin@evil.com' (full element content). This enables impersonation.".into(),
                    offset: 0,
                    property: "SAML NameID parsing must use the complete text content of the element. XML comments must not truncate identity strings.".into(),
                }],
            });
        }

        // 3. Missing or manipulated signature
        if lower.contains("<samlp:response") || lower.contains("<saml:assertion") {
            if !lower.contains("<ds:signature") 
                && !lower.contains("<signature") 
                && !lower.contains("<saml:signature") 
                && !lower.contains("<xmldsig:signature") {
                dets.push(L2Detection {
                    detection_type: "saml_unsigned".into(),
                    confidence: 0.87,
                    detail: "SAML Assertion/Response without XML Signature — unsigned assertion acceptance".into(),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: "SAML response without ds:Signature".into(),
                        interpretation: "SAML Response or Assertion lacks an XML Signature (ds:Signature). If the Service Provider processes unsigned assertions, an attacker can forge arbitrary SAML responses and authenticate as any user.".into(),
                        offset: 0,
                        property: "SAML Service Providers must reject unsigned Assertions. Both the Response and the Assertion should be signed and verified.".into(),
                    }],
                });
            }
        }

        // 4. SAML NotBefore/NotOnOrAfter manipulation
        if lower.contains("notbefore=\"2000-01-01") || lower.contains("notonorafter=\"2099") || lower.contains("notonorafter=\"9999") {
            dets.push(L2Detection {
                detection_type: "saml_time_manipulation".into(),
                confidence: 0.84,
                detail: "SAML temporal condition has unreasonable value — assertion replay attack".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(200)].to_string(),
                    interpretation: "SAML assertion has temporal conditions (NotBefore/NotOnOrAfter) set to extreme values, creating an excessively long validity window. This enables assertion replay — a stolen assertion remains valid indefinitely.".into(),
                    offset: 0,
                    property: "SAML temporal conditions must use short validity windows (typically 5-10 minutes). Assertions with validity windows exceeding 1 hour should be rejected.".into(),
                }],
            });
        }

        // 5. DOCTYPE in SAML (XXE vector)
        if (lower.contains("saml") || lower.contains("assertion")) && lower.contains("<!doctype") {
            dets.push(L2Detection {
                detection_type: "saml_xxe".into(),
                confidence: 0.92,
                detail: "DOCTYPE declaration in SAML document — XXE via SAML".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(200)].to_string(),
                    interpretation: "DOCTYPE declaration in a SAML document enables XML External Entity (XXE) attacks. SAML parsers that process external entities can leak server files, perform SSRF, or cause denial of service.".into(),
                    offset: 0,
                    property: "SAML XML parsers must disable external entity processing. DOCTYPE declarations in SAML documents must be rejected.".into(),
                }],
            });
        }

        // 6. SAML attribute injection
        if let Some(m) = attribute_injection_re.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "saml_attribute_injection".into(),
                confidence: 0.85,
                detail: "Suspicious SAML Attribute/AttributeStatement contains elevated role or permission markers".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_string(),
                    interpretation: "SAML attribute block appears to inject privileged identity data (admin/role/permission fields), which can lead to authorization bypass if blindly trusted.".into(),
                    offset: m.start(),
                    property: "Service Providers must enforce strict attribute allowlists and validate authorization claims against trusted IdP policy.".into(),
                }],
            });
        }

        // 7. Audience restriction bypass
        if let Some(m) = audience_bypass_re.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "saml_audience_bypass".into(),
                confidence: 0.83,
                detail: "SAML audience restriction is missing, empty, or overly broad".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Audience restriction appears absent or wildcarded, allowing assertions intended for one relying party to be replayed against another.".into(),
                    offset: m.start(),
                    property: "SAML assertions must include a specific Audience matching the Service Provider entity ID.".into(),
                }],
            });
        }

        // 8. Compressed SAML deflate bypass signal: SAMLResponse query + deflate/zlib bytes
        if let Some(m) = saml_response_re.find(&decoded) {
            if let Some(value) = extract_saml_response_value(&decoded) {
                if has_deflate_header(value) {
                    dets.push(L2Detection {
                        detection_type: "saml_deflate_bypass".into(),
                        confidence: 0.81,
                        detail: "SAMLResponse appears base64-encoded and deflate-compressed (zlib header)".into(),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::SemanticEval,
                            matched_input: m.as_str().to_string(),
                            interpretation: "Compressed SAML payload with deflate header can be used to bypass fragile signature validation pipelines when decode/verify order is incorrect.".into(),
                            offset: m.start(),
                            property: "SAML signature verification must occur on the canonicalized XML after correct decode/inflate processing and strict binding checks.".into(),
                        }],
                    });
                }
            }
        }

        // 9. XML XInclude injection
        if (lower.contains("<xi:include") || lower.contains("xinclude")) && lower.contains("href=") {
            dets.push(L2Detection {
                detection_type: "saml_xinclude_injection".into(),
                confidence: 0.92,
                detail: "XInclude element detected in SAML document — external entity inclusion".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[..decoded.len().min(200)].to_string(),
                    interpretation: "XInclude (xi:include) allows embedding external XML content via href attributes. Unlike DOCTYPE-based XXE, XInclude processing can be enabled separately and bypasses DOCTYPE-disabled XXE protections. Attackers use xi:include to read local files or trigger SSRF in SAML assertions.".into(),
                    offset: 0,
                    property: "XInclude processing must be disabled in SAML parsers. Use a whitelist-based XML parser configuration that disables all external resource fetching.".into(),
                }],
            });
        }

        // 10. SubjectConfirmation manipulation
        if lower.contains("subjectconfirmationdata") && !lower.contains("recipient=") {
            dets.push(L2Detection {
                detection_type: "saml_subject_confirmation_abuse".into(),
                confidence: 0.88,
                detail: "SubjectConfirmationData missing Recipient attribute — assertion replay vulnerability".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(200)].to_string(),
                    interpretation: "SubjectConfirmationData without a Recipient attribute bypass the Recipient validation check. SAML assertions can then be replayed against any service provider, not just the intended recipient.".into(),
                    offset: 0,
                    property: "SAML Service Providers must verify that the Recipient attribute in SubjectConfirmationData exactly matches the expected endpoint URL.".into(),
                }],
            });
        }

        // 11. Multiple Audience bypass
        let audience_count = lower.matches("<audience>").count()
            + lower.matches("<saml:audience>").count()
            + lower.matches("<saml2:audience>").count();
        if audience_count >= 2 {
            dets.push(L2Detection {
                detection_type: "saml_multi_audience_bypass".into(),
                confidence: 0.85,
                detail: "Multiple Audience elements detected — audience restriction bypass".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(200)].to_string(),
                    interpretation: "SAML Conditions with multiple Audience elements — some IdPs accept SAML with any matching audience, while others require exact match. Attackers add the legitimate audience alongside an attacker-controlled audience to create assertions usable on multiple SPs simultaneously.".into(),
                    offset: 0,
                    property: "SAML assertions should typically contain a single Audience matching the intended Service Provider. If multiple are present, validation logic must strictly ensure the current SP is among them and not bypass checks.".into(),
                }],
            });
        }

        if let Some(det) = detect_saml_assertion_injection(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_saml_comment_injection(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_saml_xxe_in_assertion(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_saml_signature_exclusion(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_saml_attribute_manipulation(&decoded) {
            dets.push(det);
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "saml_signature_wrapping"
            | "saml_nameid_comment"
            | "saml_unsigned"
            | "saml_time_manipulation"
            | "saml_xxe"
            | "saml_attribute_injection"
            | "saml_audience_bypass"
            | "saml_deflate_bypass"
            | "saml_xinclude_injection"
            | "saml_subject_confirmation_abuse"
            | "saml_multi_audience_bypass"
            | "saml_assertion_injection"
            | "saml_comment_injection_advanced"
            | "saml_xxe_in_assertion"
            | "saml_signature_exclusion"
            | "saml_attribute_manipulation" => Some(InvariantClass::SamlBypass),
            _ => None,
        }
    }
}

fn detect_saml_assertion_injection(input: &str) -> Option<RustDetection> {
    let assertion_re = Regex::new(r"(?is)<(?:\w+:)?Assertion\b").expect("valid regex");
    let response_re = Regex::new(r"(?is)<(?:\w+:)?Response\b").expect("valid regex");
    let nameid_re =
        Regex::new(r#"(?is)<(?:\w+:)?NameID\b[^>]*>\s*([^<]+?)\s*</(?:\w+:)?NameID>"#)
            .expect("valid regex");

    let assertion_count = assertion_re.find_iter(input).count();
    let response_count = response_re.find_iter(input).count();
    if assertion_count + response_count < 2 {
        return None;
    }

    let mut nameids = std::collections::BTreeSet::new();
    for cap in nameid_re.captures_iter(input) {
        if let Some(nameid) = cap.get(1) {
            let normalized = nameid.as_str().trim().to_ascii_lowercase();
            if !normalized.is_empty() {
                nameids.insert(normalized);
            }
        }
    }

    if nameids.len() < 2 {
        return None;
    }

    Some(L2Detection {
        detection_type: "saml_assertion_injection".into(),
        confidence: 0.94,
        detail: "Multiple Assertion/Response elements with conflicting NameID values — assertion injection pattern".into(),
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::ContextEscape,
            matched_input: input[..input.len().min(220)].to_string(),
            interpretation: "SAML payload contains multiple Assertion/Response elements and different NameID identities, which is consistent with assertion injection where a signed element is paired with an attacker-controlled assertion.".into(),
            offset: 0,
            property: "SAML processing must enforce single-assertion semantics and bind signature verification to the exact assertion consumed for identity.".into(),
        }],
    })
}

fn detect_saml_comment_injection(input: &str) -> Option<RustDetection> {
    let comment_nameid_re = Regex::new(
        r#"(?is)<(?:\w+:)?NameID\b[^>]*>\s*[^<]*<!--[\s\S]*?-->[\s\S]*?</(?:\w+:)?NameID>"#,
    )
    .expect("valid regex");
    let m = comment_nameid_re.find(input)?;
    Some(L2Detection {
        detection_type: "saml_comment_injection_advanced".into(),
        confidence: 0.93,
        detail: "XML comment embedded inside NameID value — comment-splitting identity injection".into(),
        position: m.start(),
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::ContextEscape,
            matched_input: m.as_str().to_string(),
            interpretation: "A comment token appears inside NameID text content (e.g., adm<!---->in@corp.com), enabling parser discrepancies in identity reconstruction.".into(),
            offset: m.start(),
            property: "NameID values must be canonicalized as complete text nodes and reject XML comment-tokenized identities.".into(),
        }],
    })
}

fn detect_saml_xxe_in_assertion(input: &str) -> Option<RustDetection> {
    let doctype_entity_re =
        Regex::new(r#"(?is)<!DOCTYPE[\s\S]*?<!ENTITY[\s\S]*?SYSTEM\s*["'](?:file|https?)://"#)
            .expect("valid regex");
    let saml_context_re =
        Regex::new(r"(?is)(?:xmlns:(?:saml|samlp)\s*=|<\s*(?:saml|saml2|samlp):(?:Assertion|Response)\b)")
            .expect("valid regex");
    let m = doctype_entity_re.find(input)?;
    if !saml_context_re.is_match(input) {
        return None;
    }

    Some(L2Detection {
        detection_type: "saml_xxe_in_assertion".into(),
        confidence: 0.95,
        detail: "DOCTYPE + external ENTITY URI in SAML context — XXE within assertion".into(),
        position: m.start(),
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::PayloadInject,
            matched_input: input[..input.len().min(220)].to_string(),
            interpretation: "SAML payload includes a DOCTYPE with external entity resolution to file/http resources, indicating XXE injection in assertion processing.".into(),
            offset: m.start(),
            property: "SAML XML parsing must disable DTD/ENTITY expansion and reject DOCTYPE-bearing assertions/responses.".into(),
        }],
    })
}

fn detect_saml_signature_exclusion(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();
    let in_saml_context = lower.contains("<saml")
        || lower.contains("<samlp")
        || lower.contains("xmlns:saml")
        || lower.contains("assertion");
    if !in_saml_context {
        return None;
    }

    let has_signature = lower.contains("<ds:signature")
        || lower.contains("<signature")
        || lower.contains("<xmldsig:signature")
        || lower.contains("<saml:signature");
    if !has_signature {
        return Some(L2Detection {
            detection_type: "saml_signature_exclusion".into(),
            confidence: 0.91,
            detail: "SAML assertion/response missing Signature element — signature exclusion pattern".into(),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: input[..input.len().min(220)].to_string(),
                interpretation: "SAML-bearing payload is missing a signature node, which can indicate signature exclusion or stripped-signature acceptance.".into(),
                offset: 0,
                property: "Service Providers must require and validate XML signatures for all accepted assertions/responses.".into(),
            }],
        });
    }

    let assertion_id_re = Regex::new(r#"(?is)<(?:\w+:)?Assertion\b[^>]*\bID\s*=\s*["']([^"']+)["']"#)
        .expect("valid regex");
    let reference_re = Regex::new(r#"(?is)<(?:\w+:)?Reference\b[^>]*\bURI\s*=\s*["']#([^"']+)["']"#)
        .expect("valid regex");
    let assertion_id = assertion_id_re
        .captures(input)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_ascii_lowercase())?;
    let mut refs = Vec::new();
    for cap in reference_re.captures_iter(input) {
        if let Some(m) = cap.get(1) {
            refs.push(m.as_str().to_ascii_lowercase());
        }
    }
    if refs.is_empty() || refs.iter().all(|id| id != &assertion_id) {
        return Some(L2Detection {
            detection_type: "saml_signature_exclusion".into(),
            confidence: 0.91,
            detail: "SignedInfo Reference URI does not bind to Assertion ID — signature wrapping/exclusion risk".into(),
            position: 0,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::SemanticEval,
                matched_input: input[..input.len().min(220)].to_string(),
                interpretation: "Signature reference URI does not match the Assertion ID in the same payload, which can allow wrapping where a different assertion is processed than the one signed.".into(),
                offset: 0,
                property: "Signature Reference URI must resolve exactly to the consumed Assertion element ID.".into(),
            }],
        });
    }
    None
}

fn detect_saml_attribute_manipulation(input: &str) -> Option<RustDetection> {
    let saml_context_re = Regex::new(r"(?is)(?:<\s*(?:saml|saml2):Assertion\b|<\s*(?:saml|saml2):Attribute(?:Statement|Value)?\b|xmlns:saml)")
        .expect("valid regex");
    if !saml_context_re.is_match(input) {
        return None;
    }
    let escalation_re = Regex::new(
        r#"(?is)<(?:\w+:)?AttributeValue\b[^>]*>\s*(?:[^<]{0,120})\b(?:admin\s*=\s*(?:true|1)|is_admin\s*=\s*(?:true|1)|superuser|role\s*=\s*[a-z0-9_-]{1,32}|privilege(?:d)?|elevated|root)\b(?:[^<]{0,120})</(?:\w+:)?AttributeValue>"#,
    )
    .expect("valid regex");
    let m = escalation_re.find(input)?;

    Some(L2Detection {
        detection_type: "saml_attribute_manipulation".into(),
        confidence: 0.87,
        detail: "Privileged role/attribute value injected in SAML AttributeValue".into(),
        position: m.start(),
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::PayloadInject,
            matched_input: m.as_str().to_string(),
            interpretation: "SAML attribute statement includes privilege-escalation markers (admin/superuser/role/privilege), which can indicate attribute manipulation.".into(),
            offset: m.start(),
            property: "Authorization attributes from SAML must be schema-validated and constrained to trusted IdP-issued claims.".into(),
        }],
    })
}

fn extract_saml_response_value(input: &str) -> Option<&str> {
    let (_, tail) = input.split_once("SAMLResponse=")?;
    let end = tail
        .find('&')
        .or_else(|| tail.find(' '))
        .unwrap_or(tail.len());
    Some(&tail[..end])
}

fn has_deflate_header(value: &str) -> bool {
    let raw = value.replace("%2B", "+").replace("%2F", "/").replace("%3D", "=").replace("%25", "%");
    let candidate = raw.trim_matches(|c| c == '"' || c == '\'' || c == '#');
    let engines = [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];

    for engine in engines {
        if let Ok(bytes) = engine.decode(candidate) {
            if bytes.len() >= 2 && bytes[0] == 0x78 && (bytes[1] == 0x9c || bytes[1] == 0xda) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_signature_wrapping() {
        let eval = SamlEvaluator;
        let input = r#"<samlp:Response><saml:Assertion ID="legit">...</saml:Assertion><saml:Assertion ID="evil">...</saml:Assertion></samlp:Response>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "saml_signature_wrapping"));
    }

    #[test]
    fn detects_nameid_comment_injection() {
        let eval = SamlEvaluator;
        let input = r#"<saml:Assertion><saml:NameID>admin<!---->@evil.com</saml:NameID></saml:Assertion>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "saml_nameid_comment"));
    }

    #[test]
    fn detects_unsigned_assertion() {
        let eval = SamlEvaluator;
        let input = r#"<samlp:Response><saml:Assertion><saml:NameID>admin</saml:NameID></saml:Assertion></samlp:Response>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "saml_unsigned"));
    }

    #[test]
    fn detects_saml_xxe() {
        let eval = SamlEvaluator;
        let input = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><saml:Assertion>&xxe;</saml:Assertion>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "saml_xxe"));
    }

    #[test]
    fn detects_attribute_injection() {
        let eval = SamlEvaluator;
        let input = r#"<saml:Assertion><saml:AttributeStatement>role=admin</saml:AttributeStatement></saml:Assertion>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "saml_attribute_injection"));
    }

    #[test]
    fn detects_audience_bypass() {
        let eval = SamlEvaluator;
        let input = r#"<saml:Assertion><saml:Audience>ANY</saml:Audience></saml:Assertion>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "saml_audience_bypass"));
    }

    #[test]
    fn detects_deflate_bypass_pattern() {
        let eval = SamlEvaluator;
        let input = "GET /sso?SAMLResponse=eJxBQUFBQUFBQUFBQUFBQUFBQUFBQQ== HTTP/1.1";
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "saml_deflate_bypass"));
    }

    #[test]
    fn detects_xinclude_injection() {
        let eval = SamlEvaluator;
        let input = r#"<saml:Assertion><xi:include href="file:///etc/passwd"/></saml:Assertion>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "saml_xinclude_injection"));
    }

    #[test]
    fn detects_subject_confirmation_abuse() {
        let eval = SamlEvaluator;
        let input = r#"<saml:Assertion><saml:SubjectConfirmationData NotOnOrAfter="2024-01-01T00:00:00Z" /></saml:Assertion>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "saml_subject_confirmation_abuse"));
    }

    #[test]
    fn detects_multi_audience_bypass() {
        let eval = SamlEvaluator;
        let input = r#"<saml:Assertion><saml:Conditions><saml:AudienceRestriction><saml:Audience>https://legit.com</saml:Audience><saml:Audience>https://attacker.com</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "saml_multi_audience_bypass"));
    }

    #[test]
    fn no_detection_for_non_saml() {
        let eval = SamlEvaluator;
        let dets = eval.detect("just a regular string with no XML");
        assert!(dets.is_empty());
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = SamlEvaluator;
        assert_eq!(
            eval.map_class("saml_signature_wrapping"),
            Some(InvariantClass::SamlBypass)
        );
    }

    #[test]
    fn detects_saml_assertion_injection_positive() {
        let input = r#"<samlp:Response><saml:Assertion><saml:NameID>alice@corp.com</saml:NameID></saml:Assertion><saml:Assertion><saml:NameID>admin@corp.com</saml:NameID></saml:Assertion></samlp:Response>"#;
        assert!(detect_saml_assertion_injection(input).is_some());
    }

    #[test]
    fn detects_saml_assertion_injection_negative() {
        let input = r#"<samlp:Response><saml:Assertion><saml:NameID>alice@corp.com</saml:NameID></saml:Assertion></samlp:Response>"#;
        assert!(detect_saml_assertion_injection(input).is_none());
    }

    #[test]
    fn detects_saml_comment_injection_positive() {
        let input = r#"<saml:Assertion><saml:NameID>adm<!---->in@corp.com</saml:NameID></saml:Assertion>"#;
        assert!(detect_saml_comment_injection(input).is_some());
    }

    #[test]
    fn detects_saml_comment_injection_negative() {
        let input = r#"<saml:Assertion><saml:NameID>admin@corp.com</saml:NameID></saml:Assertion>"#;
        assert!(detect_saml_comment_injection(input).is_none());
    }

    #[test]
    fn detects_saml_xxe_in_assertion_positive() {
        let input = r#"<!DOCTYPE saml [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Assertion>"#;
        assert!(detect_saml_xxe_in_assertion(input).is_some());
    }

    #[test]
    fn detects_saml_xxe_in_assertion_negative() {
        let input = r#"<!DOCTYPE html><root>safe</root>"#;
        assert!(detect_saml_xxe_in_assertion(input).is_none());
    }

    #[test]
    fn detects_saml_signature_exclusion_positive() {
        let input = r##"<saml:Assertion ID="assert-123"><ds:Signature><ds:SignedInfo><ds:Reference URI="#other-999"/></ds:SignedInfo></ds:Signature></saml:Assertion>"##;
        assert!(detect_saml_signature_exclusion(input).is_some());
    }

    #[test]
    fn detects_saml_signature_exclusion_negative() {
        let input = r##"<saml:Assertion ID="assert-123"><ds:Signature><ds:SignedInfo><ds:Reference URI="#assert-123"/></ds:SignedInfo></ds:Signature></saml:Assertion>"##;
        assert!(detect_saml_signature_exclusion(input).is_none());
    }

    #[test]
    fn detects_saml_attribute_manipulation_positive() {
        let input = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Attribute Name="role"><saml:AttributeValue>role=superuser</saml:AttributeValue></saml:Attribute></saml:Assertion>"#;
        assert!(detect_saml_attribute_manipulation(input).is_some());
    }

    #[test]
    fn detects_saml_attribute_manipulation_negative() {
        let input = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Attribute Name="department"><saml:AttributeValue>engineering</saml:AttributeValue></saml:Attribute></saml:Assertion>"#;
        assert!(detect_saml_attribute_manipulation(input).is_none());
    }
}
