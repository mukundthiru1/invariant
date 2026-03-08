//! LDAP Injection Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::sync::LazyLock;

pub struct LdapEvaluator;

// Static regexes prevent repeated compile costs on every request.
static FILTER_INJECT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\)\s*\(\s*[a-zA-Z][\w-]*\s*[=~<>]").unwrap());
static WILDCARD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\(\s*[a-zA-Z][\w-]*\s*=\s*\*\s*\)").unwrap());
static BLIND_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:\(\||\(\&)\s*\(").unwrap());
static PRIV_USER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)password|admin|root").unwrap());
static ATTR_ENUM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\(\s*&\s*\(\s*objectClass\s*=\s*\*\s*\)\s*\(\s*attribute\s*=\s*\*\s*\)\s*\)")
        .unwrap()
});
static DN_INJECTION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\(\s*(?:ou|cn)\s*=[^)\r\n]*\)\s*[\(\|&]").unwrap());
static NULL_BASE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*\(\s*objectClass\s*=\s*\*\s*\)\s*$").unwrap());
static EXTENSIBLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\([^()]*:\s*(?:dn|[a-zA-Z][a-zA-Z0-9]*match)\s*:=[^)]*\)|\([^()]*:[0-9]+(?:\.[0-9]+)+\s*:[a-zA-Z][a-zA-Z0-9]*match\s*:=[^)]*\)").unwrap()
});
static REFERRAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\([^()]*\bldap://[^\s)"'<>]+"#).unwrap());
static NESTED_PAREN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)\(\s*[&|!]\s*(?:\([^()]{0,120}\)){3,}").unwrap());
static WILDCARD_VALUE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\(\s*[a-zA-Z][\w-]*\s*=\s*[^)]*\*[^)]*\)").unwrap());
static DN_SEPARATOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:cn|ou|dc|uid)\s*=\s*[^)\r\n,;]+(?:\s*[,;]\s*(?:cn|ou|dc|uid)\s*=|\s*[,;]\s*[|&()])").unwrap()
});
static ATTR_INJECT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\(\s*[|&]\s*\([^)]*\)\s*\(\s*(?:userPassword|unicodePwd|memberOf|shadowLastChange|pwdLastSet|loginShell|homeDirectory)\s*=").unwrap()
});
static LDAP_URL_SCHEME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bldaps?://[^\s"'<>]+"#).unwrap());
static LDAP_HOMOGLYPH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[\u{FF08}\u{FF09}\u{FF1D}\u{FF0A}\u{FE64}\u{FE65}\u{FE66}\u{2217}\u{204E}\u{02BC}\u{2018}\u{2019}]").unwrap()
});

impl L2Evaluator for LdapEvaluator {
    fn id(&self) -> &'static str {
        "ldap"
    }
    fn prefix(&self) -> &'static str {
        "L2 LDAP"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded_data = crate::encoding::multi_layer_decode(input);
        let decoded = decoded_data.fully_decoded;
        let all_forms = decoded_data.all_forms;

        // LDAP filter injection: )(uid=*)  or  *)(objectClass=*
        if let Some(m) = FILTER_INJECT_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ldap_filter".into(),
                confidence: 0.88,
                detail: format!("LDAP filter injection: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Closing paren + new filter modifies LDAP query logic".into(),
                    offset: m.start(),
                    property: "User input must not break LDAP filter boundaries".into(),
                }],
            });
        }

        // Wildcard enumeration: (uid=*)
        if let Some(m) = WILDCARD_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ldap_wildcard".into(),
                confidence: 0.80,
                detail: format!("LDAP wildcard enumeration: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Wildcard match returns all LDAP entries".into(),
                    offset: m.start(),
                    property: "LDAP queries must use exact matching, not wildcards from user input"
                        .into(),
                }],
            });
        }

        // Boolean blind: (&(uid=admin)(|... or (|(uid=*)(userPassword=*))
        if let Some(m) = BLIND_RE.find(&decoded) {
            if decoded.contains("*") || PRIV_USER_RE.is_match(&decoded) {
                dets.push(L2Detection {
                    detection_type: "ldap_blind".into(),
                    confidence: 0.85,
                    detail: "LDAP boolean-based blind injection".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Boolean LDAP operators used for enumeration".into(),
                        offset: m.start(),
                        property: "User input must not inject LDAP boolean operators".into(),
                    }],
                });
            }
        }

        // LDAP attribute enumeration for schema discovery / data exfiltration.
        if let Some(m) = ATTR_ENUM_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ldap_attr_enum".into(),
                confidence: 0.89,
                detail: format!("LDAP attribute enumeration: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Wildcard attribute selector attempts directory schema discovery".into(),
                    offset: m.start(),
                    property: "LDAP filters from user input should restrict returned attributes"
                        .into(),
                }],
            });
        }

        // LDAP DN injection via ou=/cn= with delimiter / special char escaping scope.
        if let Some(m) = DN_INJECTION_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ldap_dn_injection".into(),
                confidence: 0.87,
                detail: format!("LDAP DN injection attempt: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Terminator/special characters in DN attributes can rewrite LDAP scope"
                            .into(),
                    offset: m.start(),
                    property: "DN components must be escaped/validated before LDAP binding".into(),
                }],
            });
        }

        // LDAP null base search with (objectClass=*) can expose root naming context.
        if NULL_BASE_RE.is_match(&decoded) {
            dets.push(L2Detection {
                detection_type: "ldap_null_base".into(),
                confidence: 0.90,
                detail: "LDAP null base search with (objectClass=*)".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded.clone(),
                    interpretation:
                        "Unscoped base DN search can enumerate root directory information".into(),
                    offset: 0,
                    property: "LDAP base DN must be fixed and not user-controlled".into(),
                }],
            });
        }

        // LDAP extensible match (`:dn:=`, `:caseIgnoreMatch:=`, OID-based filters).
        if let Some(m) = all_forms.iter().find(|f| EXTENSIBLE_RE.is_match(f)) {
            let matched = m.as_str();
            dets.push(L2Detection {
                detection_type: "ldap_extensible_match".into(),
                confidence: 0.92,
                detail: format!("LDAP extensible match filter: {}", matched),
                position: decoded.find(matched).unwrap_or(0),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: matched.to_owned(),
                    interpretation: "Extensible match filters can bypass strict attribute matching".into(),
                    offset: decoded.find(matched).unwrap_or(0),
                    property: "LDAP filters should restrict to simple matching operators and known attributes".into(),
                }],
            });
        }

        // LDAP referral injection / external LDAP chaining through URL values.
        if let Some(m) = REFERRAL_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ldap_referral_injection".into(),
                confidence: 0.94,
                detail: format!("LDAP referral URI in filter context: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Filter value includes external LDAP URI for referral chaining"
                        .into(),
                    offset: m.start(),
                    property: "LDAP search filters must reject external referral targets".into(),
                }],
            });
        }

        // Nested boolean filter structures can alter intended query precedence.
        if let Some(m) = NESTED_PAREN_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ldap_nested_paren_abuse".into(),
                confidence: 0.91,
                detail: "LDAP nested parentheses abuse in boolean filter".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str()[..m.as_str().len().min(100)].to_owned(),
                    interpretation:
                        "Deeply nested filter terms can rebind boolean logic and bypass constraints"
                            .into(),
                    offset: m.start(),
                    property: "User input must not control LDAP filter structure depth/operators"
                        .into(),
                }],
            });
        }

        // Wildcard in attribute values enables broad LDAP enumeration.
        if let Some(m) = WILDCARD_VALUE_RE.find(&decoded) {
            if !WILDCARD_RE.is_match(m.as_str()) {
                dets.push(L2Detection {
                    detection_type: "ldap_wildcard_value".into(),
                    confidence: 0.84,
                    detail: format!("LDAP wildcard used inside value: {}", m.as_str()),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation:
                            "Wildcard in value broadens matching beyond exact identity checks"
                                .into(),
                        offset: m.start(),
                        property:
                            "LDAP attribute values from users should be escaped and exact-matched"
                                .into(),
                    }],
                });
            }
        }

        // DN injection via comma/semicolon separators can alter bind/search base.
        if let Some(m) = DN_SEPARATOR_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ldap_dn_separator_injection".into(),
                confidence: 0.90,
                detail: format!("LDAP DN separator injection: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Injected DN separators can append/replace directory components".into(),
                    offset: m.start(),
                    property:
                        "DN segments must be escaped and not directly composed from user input"
                            .into(),
                }],
            });
        }

        // Attribute injection of privileged/sensitive attributes.
        if let Some(m) = ATTR_INJECT_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ldap_attribute_injection".into(),
                confidence: 0.92,
                detail: "LDAP filter adds unauthorized sensitive attribute".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str()[..m.as_str().len().min(100)].to_owned(),
                    interpretation:
                        "Injected sensitive attribute can expose credentials/privilege metadata"
                            .into(),
                    offset: m.start(),
                    property:
                        "LDAP queries must enforce strict allow-lists for searchable attributes"
                            .into(),
                }],
            });
        }

        // Direct LDAP URL scheme payloads (ldap://, ldaps://) in input channels.
        if let Some(m) = LDAP_URL_SCHEME_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ldap_url_scheme_injection".into(),
                confidence: 0.93,
                detail: format!("LDAP URL scheme injection: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "LDAP URL can redirect lookups to attacker-controlled directory endpoints"
                            .into(),
                    offset: m.start(),
                    property: "User input must not supply LDAP/LDAPS scheme endpoints".into(),
                }],
            });
        }

        // Unicode homoglyph payloads to evade ASCII-centric LDAP sanitizers.
        if let Some(m) = LDAP_HOMOGLYPH_RE.find(&decoded) {
            if decoded.contains('(')
                || decoded.contains(')')
                || decoded.contains('=')
                || decoded.contains("cn")
                || decoded.contains("uid")
            {
                dets.push(L2Detection {
                    detection_type: "ldap_unicode_homoglyph".into(),
                    confidence: 0.86,
                    detail: "Unicode homoglyphs in LDAP filter-like input".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::EncodingDecode,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Homoglyph symbols can bypass filters expecting ASCII operators".into(),
                        offset: m.start(),
                        property: "LDAP sanitization must normalize Unicode and reject confusable operators".into(),
                    }],
                });
            }
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "ldap_filter"
            | "ldap_wildcard"
            | "ldap_blind"
            | "ldap_attr_enum"
            | "ldap_dn_injection"
            | "ldap_null_base"
            | "ldap_extensible_match"
            | "ldap_referral_injection"
            | "ldap_nested_paren_abuse"
            | "ldap_wildcard_value"
            | "ldap_dn_separator_injection"
            | "ldap_attribute_injection"
            | "ldap_url_scheme_injection"
            | "ldap_unicode_homoglyph" => Some(InvariantClass::LdapFilterInjection),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_attribute_enumeration() {
        let eval = LdapEvaluator;
        let dets = eval.detect("(&(objectClass=*)(attribute=*))");
        assert!(dets.iter().any(|d| d.detection_type == "ldap_attr_enum"));
    }

    #[test]
    fn detects_dn_injection() {
        let eval = LdapEvaluator;
        let dets = eval.detect("(cn=admin)| (uid=foo)");
        assert!(dets.iter().any(|d| d.detection_type == "ldap_dn_injection"));
    }
    #[test]
    fn detects_null_base_search() {
        let eval = LdapEvaluator;
        let dets = eval.detect("(objectClass=*)");
        assert!(dets.iter().any(|d| d.detection_type == "ldap_null_base"));
    }

    #[test]
    fn detects_extensible_match() {
        let eval = LdapEvaluator;
        let dets = eval.detect("(cn:dn:=admin)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ldap_extensible_match")
        );
        let dets = eval.detect("(cn:caseIgnoreMatch:=Admin)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ldap_extensible_match")
        );
    }

    #[test]
    fn detects_referral_injection() {
        let eval = LdapEvaluator;
        let dets = eval.detect("(member=ldap://attacker.example.com/ou=users,dc=evil,dc=com)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ldap_referral_injection")
        );
    }

    #[test]
    fn detects_nested_parentheses_abuse() {
        let eval = LdapEvaluator;
        let dets = eval.detect("(|(uid=foo)(mail=foo@example.com)(userPassword=*)(cn=admin))");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ldap_nested_paren_abuse")
        );
    }

    #[test]
    fn detects_wildcard_value_injection_suffix() {
        let eval = LdapEvaluator;
        let dets = eval.detect("(uid=adm*)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ldap_wildcard_value")
        );
    }

    #[test]
    fn detects_wildcard_value_injection_infix() {
        let eval = LdapEvaluator;
        let dets = eval.detect("(mail=*admin*@corp.local)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ldap_wildcard_value")
        );
    }

    #[test]
    fn detects_dn_separator_injection_comma() {
        let eval = LdapEvaluator;
        let dets = eval.detect("(cn=alice,ou=admins)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ldap_dn_separator_injection")
        );
    }

    #[test]
    fn detects_dn_separator_injection_semicolon() {
        let eval = LdapEvaluator;
        let dets = eval.detect("(uid=bob;dc=evil)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ldap_dn_separator_injection")
        );
    }

    #[test]
    fn detects_attribute_injection_for_sensitive_attr() {
        let eval = LdapEvaluator;
        let dets = eval.detect("(|(uid=alice)(userPassword=*))");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ldap_attribute_injection")
        );
    }

    #[test]
    fn detects_ldap_url_scheme_injection_ldap() {
        let eval = LdapEvaluator;
        let dets = eval.detect("cn=admin,dc=corp ldap://attacker.example.com/dc=evil,dc=com");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ldap_url_scheme_injection")
        );
    }

    #[test]
    fn detects_ldap_url_scheme_injection_ldaps() {
        let eval = LdapEvaluator;
        let dets = eval.detect("redirect=ldaps://evil.example.org/ou=ops,dc=evil,dc=org");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ldap_url_scheme_injection")
        );
    }

    #[test]
    fn detects_unicode_homoglyph_evasion() {
        let eval = LdapEvaluator;
        let dets = eval.detect("cn＝admin＊");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ldap_unicode_homoglyph")
        );
    }
}
