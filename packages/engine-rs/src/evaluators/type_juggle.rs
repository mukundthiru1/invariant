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

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "type_juggle_magic_hash" | "type_juggle_json_confusion" | "type_juggle_array_param" => {
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
}
