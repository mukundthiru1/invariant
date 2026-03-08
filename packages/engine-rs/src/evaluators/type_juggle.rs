//! Type Juggling / Type Confusion Evaluator — Level 2
//!
//! Detects attacks exploiting loose type comparison in PHP, JavaScript,
//! and other languages:
//!   - PHP loose comparison (== vs ===) with magic hashes
//!   - JSON type confusion (string "0" vs integer 0)
//!   - Boolean/null confusion in authentication
//!   - Mass assignment via unexpected types

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::sync::LazyLock;

static PHP_SCI_NOTATION_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\x22[0-9]+e[0-9]+\x22").unwrap());
static JSON_TYPE_COERCE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)"(?:password|token|secret|key|auth|role|admin|permission|access)"\s*:\s*(?:true|false|null|\[\]|\{\}|0|-1)"#).unwrap());
static PHP_HEX_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\x220x[0-9a-f]+\x22").unwrap());
static NUMERIC_OVERFLOW_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:9{15,}|2147483648|9223372036854775808|-2147483649|-9223372036854775809)").unwrap());

/// PHP magic hash prefixes (md5/sha1 values that start with "0e" and contain only digits).
/// These compare equal to 0 under PHP's loose comparison (0e123 == 0e456 == 0).
const MAGIC_HASHES: &[&str] = &[
    "0e215962017", // md5("240610708")
    "0e462097431", // md5("QNKCDZO")
    "0e830400451", // md5("aabg7XSs")
    "0e776015056", // md5("aabC9RqS")
    "0e1290633704", // sha1("aaroZmOk")
    "0e1137126905", // sha1("aaK1STfY")
];

pub struct TypeJuggleEvaluator;

impl L2Evaluator for TypeJuggleEvaluator {
    fn id(&self) -> &'static str {
        "type_juggle"
    }
    fn prefix(&self) -> &'static str {
        "L2 TypeJuggle"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
        let lower = decoded.to_ascii_lowercase();

        // 1. PHP magic hash values
        for &hash in MAGIC_HASHES {
            if lower.contains(hash) {
                let pos = lower.find(hash).unwrap_or(0);
                dets.push(L2Detection {
                    detection_type: "type_juggle_magic_hash".into(),
                    confidence: 0.92,
                    detail: format!("PHP magic hash value detected: {} — loose comparison bypass", hash),
                    position: pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::TypeCoerce,
                        matched_input: hash.to_string(),
                        interpretation: "Input contains a 'magic hash' value (starting with '0e' followed by digits). PHP's loose comparison (==) interprets this as scientific notation (0 × 10^n = 0). Two different passwords whose hashes both start with '0e' will compare as equal, bypassing authentication.".into(),
                        offset: pos,
                        property: "String comparisons must use strict equality (=== in PHP, .equals() in Java). Hash comparisons must use constant-time comparison functions.".into(),
                    }],
                });
                break;
            }
        }

        // 2. JSON type confusion — boolean/null where string expected
        let type_confusion_patterns = [
            (r#""password":true"#, "boolean true", "PHP 'true == any_nonempty_string' bypasses password checks"),
            (r#""password":false"#, "boolean false", "PHP 'false == empty_string' may bypass checks"),
            (r#""password":null"#, "null", "NULL comparison bypasses may skip authentication entirely"),
            (r#""password":0"#, "integer 0", "PHP '0 == string_not_starting_with_digit' is true"),
            (r#""password":[]"#, "empty array", "Array comparison with string produces unexpected results"),
            (r#""admin":true"#, "boolean true for privilege", "Type confusion to escalate privileges via boolean admin flag"),
            (r#""role":1"#, "integer for role", "Integer role value may bypass string-based role checks"),
            (r#""is_admin":1"#, "integer admin flag", "Numeric admin flag injection via type confusion"),
        ];

        for &(pattern, typename, desc) in &type_confusion_patterns {
            // Case-insensitive check, collapse spaces
            let normalized_input = lower.replace(' ', "");
            let normalized_pattern = pattern.to_ascii_lowercase().replace(' ', "");

            if normalized_input.contains(&normalized_pattern) {
                dets.push(L2Detection {
                    detection_type: "type_juggle_json_confusion".into(),
                    confidence: 0.85,
                    detail: format!("JSON type confusion: {} value where string expected — {}", typename, desc),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::TypeCoerce,
                        matched_input: pattern.to_string(),
                        interpretation: format!(
                            "Input contains a {} value in a field that typically expects a string. In PHP and loose-typed languages, comparing a {} with a string using == produces unexpected results, enabling authentication bypass or privilege escalation.",
                            typename, typename
                        ),
                        offset: 0,
                        property: "Server-side code must validate input types explicitly. JSON fields expecting strings must reject boolean, null, integer, and array values. Use strict comparison operators.".into(),
                    }],
                });
                break;
            }
        }

        // 3. PHP array parameter injection (?password[]=)
        if lower.contains("]=") || lower.contains("%5b%5d=") || lower.contains("[]=" ) {
            // Check it's in a parameter context
            if lower.contains("password[]") || lower.contains("token[]") || lower.contains("secret[]") || lower.contains("key[]") {
                dets.push(L2Detection {
                    detection_type: "type_juggle_array_param".into(),
                    confidence: 0.87,
                    detail: "Array parameter injection on sensitive field — PHP type juggling bypass".into(),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::TypeCoerce,
                        matched_input: decoded[..decoded.len().min(100)].to_string(),
                        interpretation: "Sensitive parameter (password, token, etc.) is passed as an array (param[]= syntax). PHP will type-cast this to an array, and comparisons like strcmp(array, string) return NULL rather than false, which evaluates to 0 (equal) in some contexts.".into(),
                        offset: 0,
                        property: "Server-side code must validate that parameters are scalar values (string/number) before comparison. Array-typed parameters on sensitive fields must be rejected.".into(),
                    }],
                });
            }
        }

        if let Some(m) = PHP_SCI_NOTATION_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "type_juggle_php_sci_notation".into(),
                confidence: 0.88,
                detail: "PHP scientific notation comparison bypass".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_string(),
                    interpretation: "PHP loose comparison converts scientific notation strings to floats: 1e5 == 100000 is true. This allows bypassing numeric comparisons and hash equality checks (magic hash: 0e prefix strings compare equal as both equal 0.0)".into(),
                    offset: m.start(),
                    property: "PHP comparisons must use === strict equality. Reject scientific notation in security-sensitive numeric inputs.".into(),
                }],
            });
        }

        if let Some(m) = JSON_TYPE_COERCE_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "type_juggle_json_type_coerce".into(),
                confidence: 0.85,
                detail: "JSON boolean/null type coercion bypass".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Security-sensitive JSON fields set to boolean/null/empty values exploit type juggling: PHP converts false to empty string, null to 0, true to 1. Frameworks may compare these loosely against expected string passwords.".into(),
                    offset: m.start(),
                    property: "Security-sensitive JSON fields must have type assertions before comparison. Never compare password/token fields without strict type checking.".into(),
                }],
            });
        }

        if let Some(m) = PHP_HEX_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "type_juggle_php_hex".into(),
                confidence: 0.82,
                detail: "PHP hex string comparison bypass".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_string(),
                    interpretation: "PHP loose comparison converts hex strings to integers: 0x1A == 26 is true in PHP <= 5.6. 0x0 == false is also true. Attackers can bypass numeric checks using hex-encoded values.".into(),
                    offset: m.start(),
                    property: "Reject hex-format strings in numeric fields. Always use strict equality and explicit type casting.".into(),
                }],
            });
        }

        if let Some(m) = NUMERIC_OVERFLOW_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "type_juggle_numeric_overflow".into(),
                confidence: 0.83,
                detail: "Numeric string overflow".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Numeric values exceeding 32-bit (2^31-1=2147483647) or 64-bit (2^63-1) integer bounds trigger overflow behavior: PHP silently converts to float, JavaScript loses precision, C/Go wraps around. This enables bypassing range checks.".into(),
                    offset: m.start(),
                    property: "Validate numeric bounds explicitly. Use arbitrary precision libraries for security-critical comparisons. Reject values exceeding expected ranges.".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "type_juggle_magic_hash" | "type_juggle_json_confusion" | "type_juggle_array_param"
            | "type_juggle_php_sci_notation" | "type_juggle_json_type_coerce" | "type_juggle_php_hex" | "type_juggle_numeric_overflow" => {
                Some(InvariantClass::TypeJuggling)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_magic_hash() {
        let eval = TypeJuggleEvaluator;
        let dets = eval.detect("password=0e215962017");
        assert!(dets.iter().any(|d| d.detection_type == "type_juggle_magic_hash"));
    }

    #[test]
    fn detects_json_type_confusion() {
        let eval = TypeJuggleEvaluator;
        let dets = eval.detect(r#"{"username":"admin","password":true}"#);
        assert!(dets.iter().any(|d| d.detection_type == "type_juggle_json_confusion"));
    }

    #[test]
    fn detects_array_param() {
        let eval = TypeJuggleEvaluator;
        let dets = eval.detect("username=admin&password[]=");
        assert!(dets.iter().any(|d| d.detection_type == "type_juggle_array_param"));
    }

    #[test]
    fn no_detection_for_normal_input() {
        let eval = TypeJuggleEvaluator;
        let dets = eval.detect(r#"{"username":"admin","password":"secret123"}"#);
        assert!(dets.is_empty());
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = TypeJuggleEvaluator;
        assert_eq!(
            eval.map_class("type_juggle_magic_hash"),
            Some(InvariantClass::TypeJuggling)
        );
    }

    #[test]
    fn test_php_sci_notation() {
        let eval = TypeJuggleEvaluator;
        let dets = eval.detect(r#"{"value": "0e12345"}"#);
        assert!(dets.iter().any(|d| d.detection_type == "type_juggle_php_sci_notation"));
    }

    #[test]
    fn test_json_bool_coerce() {
        let eval = TypeJuggleEvaluator;
        let dets = eval.detect(r#"{"password": false}"#);
        assert!(dets.iter().any(|d| d.detection_type == "type_juggle_json_type_coerce"));
    }

    #[test]
    fn test_php_hex() {
        let eval = TypeJuggleEvaluator;
        let dets = eval.detect(r#"{"value": "0x1A"}"#);
        assert!(dets.iter().any(|d| d.detection_type == "type_juggle_php_hex"));
    }

    #[test]
    fn test_numeric_overflow() {
        let eval = TypeJuggleEvaluator;
        let dets = eval.detect("id=9223372036854775808");
        assert!(dets.iter().any(|d| d.detection_type == "type_juggle_numeric_overflow"));
    }
}
