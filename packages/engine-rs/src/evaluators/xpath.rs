//! XPath Injection Evaluator — Level 2
//!
//! Detects XPath injection attacks where attacker-controlled input is interpolated
//! into XPath queries. Similar to SQL injection but targeting XML document stores.
//!
//! Impact: authentication bypass, data extraction from XML databases, blind
//! information disclosure via boolean/error-based oracles.

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;

/// XPath function names that indicate injection attempts.
const XPATH_FUNCTIONS: &[&str] = &[
    "string-length(", "substring(", "concat(", "contains(",
    "normalize-space(", "translate(", "starts-with(",
    "count(", "sum(", "position(", "last(",
    "name(", "local-name(", "namespace-uri(",
    "text()", "comment()", "node()",
    "processing-instruction(",
];

/// XPath axis names (attacker probing XML structure).
const XPATH_AXES: &[&str] = &[
    "child::", "parent::", "ancestor::", "descendant::",
    "following::", "preceding::", "following-sibling::",
    "preceding-sibling::", "self::", "attribute::",
    "namespace::", "ancestor-or-self::", "descendant-or-self::",
];

pub struct XPathEvaluator;

impl L2Evaluator for XPathEvaluator {
    fn id(&self) -> &'static str {
        "xpath"
    }
    fn prefix(&self) -> &'static str {
        "L2 XPath"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
        let lower = decoded.to_ascii_lowercase();

        // 1. XPath tautology — the classic auth bypass
        // ' or '1'='1 or ' or 1=1 or true()
        let tautology_patterns = [
            "' or '1'='1",
            "' or 1=1",
            "\" or \"1\"=\"1",
            "\" or 1=1",
            "' or true()",
            "\" or true()",
            "') or ('1'='1",
            "\") or (\"1\"=\"1",
            "' or ''='",
        ];

        for pattern in &tautology_patterns {
            if lower.contains(pattern) {
                let pos = lower.find(pattern).unwrap_or(0);
                dets.push(L2Detection {
                    detection_type: "xpath_tautology".into(),
                    confidence: 0.92,
                    detail: format!("XPath tautology injection: '{}'", pattern),
                    position: pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: pattern.to_string(),
                        interpretation: "Input contains an XPath tautology pattern that always evaluates to true. When injected into an XPath query like //user[name='INPUT'], it becomes //user[name='' or '1'='1'], returning all nodes and bypassing authentication.".into(),
                        offset: pos,
                        property: "XPath queries must use parameterized expressions. User input must not be interpolated into XPath query strings.".into(),
                    }],
                });
                break;
            }
        }

        // 2. XPath function injection
        for &func in XPATH_FUNCTIONS {
            if lower.contains(func) {
                let pos = lower.find(func).unwrap_or(0);
                dets.push(L2Detection {
                    detection_type: "xpath_function".into(),
                    confidence: 0.83,
                    detail: format!("XPath function detected in input: {}", func),
                    position: pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded[pos..decoded.len().min(pos + 40)].to_string(),
                        interpretation: format!(
                            "Input contains XPath function '{}' which, when injected into an XPath query, enables the attacker to extract data character-by-character (substring), enumerate node counts, or probe XML structure.",
                            func.trim_end_matches('(')
                        ),
                        offset: pos,
                        property: "User input must not contain XPath function syntax. Parameterized XPath queries must be used.".into(),
                    }],
                });
                break;
            }
        }

        // 3. XPath axis injection (navigating XML tree)
        for &axis in XPATH_AXES {
            if lower.contains(axis) {
                let pos = lower.find(axis).unwrap_or(0);
                dets.push(L2Detection {
                    detection_type: "xpath_axis".into(),
                    confidence: 0.80,
                    detail: format!("XPath axis navigation in input: {}", axis),
                    position: pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded[pos..decoded.len().min(pos + 40)].to_string(),
                        interpretation: format!(
                            "Input contains XPath axis '{}' which allows traversing the XML document tree. An attacker can navigate from the current node to parent, ancestor, or sibling nodes, accessing data outside the intended scope.",
                            axis.trim_end_matches("::")
                        ),
                        offset: pos,
                        property: "User input must not contain XPath axis selectors. XPath queries must be constructed server-side with parameterized values.".into(),
                    }],
                });
                break;
            }
        }

        // 4. Blind XPath injection (boolean extraction)
        if (lower.contains("and ") || lower.contains("or ")) &&
            (lower.contains("string-length(") || lower.contains("substring(") || lower.contains("count("))
        {
            dets.push(L2Detection {
                detection_type: "xpath_blind".into(),
                confidence: 0.87,
                detail: "Blind XPath injection pattern — boolean-based data extraction".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: decoded[..decoded.len().min(100)].to_string(),
                    interpretation: "Input combines boolean operators (and/or) with XPath functions (string-length, substring, count). This pattern is used for blind XPath injection where the attacker extracts data one character at a time by observing true/false responses.".into(),
                    offset: 0,
                    property: "XPath queries must be parameterized. Boolean logic combined with string functions in user input indicates a blind injection attack.".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "xpath_tautology" | "xpath_function" | "xpath_axis" | "xpath_blind" => {
                Some(InvariantClass::XpathInjection)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_xpath_tautology() {
        let eval = XPathEvaluator;
        let dets = eval.detect("username=admin' or '1'='1");
        assert!(dets.iter().any(|d| d.detection_type == "xpath_tautology"));
    }

    #[test]
    fn detects_xpath_function() {
        let eval = XPathEvaluator;
        let dets = eval.detect("' and string-length(//user/password)>5");
        assert!(dets.iter().any(|d| d.detection_type == "xpath_function"));
    }

    #[test]
    fn detects_xpath_axis() {
        let eval = XPathEvaluator;
        let dets = eval.detect("' or parent::*/child::password");
        assert!(dets.iter().any(|d| d.detection_type == "xpath_axis"));
    }

    #[test]
    fn detects_blind_xpath() {
        let eval = XPathEvaluator;
        let dets = eval.detect("' and substring(//user/pass,1,1)='a");
        assert!(dets.iter().any(|d| d.detection_type == "xpath_blind"));
    }

    #[test]
    fn no_detection_for_normal_input() {
        let eval = XPathEvaluator;
        let dets = eval.detect("username=admin");
        assert!(dets.is_empty());
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = XPathEvaluator;
        assert_eq!(
            eval.map_class("xpath_tautology"),
            Some(InvariantClass::XpathInjection)
        );
    }
}
