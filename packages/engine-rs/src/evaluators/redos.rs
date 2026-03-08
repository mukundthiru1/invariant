//! ReDoS (Regular Expression Denial of Service) Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;
use std::sync::LazyLock;

pub type L2EvalResult = L2Detection;

const EVIDENCE_PREVIEW_LIMIT: usize = 180;

#[inline]
fn preview(input: &str) -> String {
    input.chars().take(EVIDENCE_PREVIEW_LIMIT).collect()
}

#[inline]
fn has_regex_metacharacters(input: &str) -> bool {
    input.chars().any(|c| {
        matches!(
            c,
            '.' | '*' | '+' | '?' | '^' | '$' | '{' | '}' | '(' | ')' | '[' | ']' | '|' | '\\'
        )
    })
}

#[inline]
fn looks_like_user_controlled_arg(arg: &str) -> bool {
    let lowered = arg.to_ascii_lowercase();
    let user_markers = [
        "userinput",
        "user_input",
        "input",
        "pattern",
        "regex",
        "untrusted",
        "tainted",
        "req.",
        "query",
        "params",
        "body",
        "argv",
    ];

    user_markers.iter().any(|m| lowered.contains(m))
}

#[inline]
fn is_likely_string_literal(arg: &str) -> bool {
    let trimmed = arg.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('"') && trimmed.contains('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || trimmed.starts_with("r\"")
}

#[inline]
fn detect_regex_injection(decoded: &str) -> Option<(usize, &'static str, f64)> {
    static JS_NEW_REGEXP_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\bnew\s+regexp\s*\(\s*([^\),]+)").unwrap());
    static PY_RE_COMPILE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\bre\s*\.\s*compile\s*\(\s*([^\),]+)").unwrap());
    static RUST_REGEX_NEW_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\bregex\s*::\s*new\s*\(\s*([^\),]+)").unwrap());

    let constructor_checks = [
        (
            &*JS_NEW_REGEXP_RE,
            "dynamic new RegExp(user_input) constructor",
        ),
        (
            &*PY_RE_COMPILE_RE,
            "dynamic re.compile(user_input) constructor",
        ),
        (
            &*RUST_REGEX_NEW_RE,
            "dynamic Regex::new(user_input) constructor",
        ),
    ];

    for (re, label) in constructor_checks {
        for caps in re.captures_iter(decoded) {
            let Some(full) = caps.get(0) else {
                continue;
            };
            let Some(arg_match) = caps.get(1) else {
                continue;
            };
            let arg = arg_match.as_str().trim();

            if is_likely_string_literal(arg) {
                continue;
            }

            if looks_like_user_controlled_arg(arg) && has_regex_metacharacters(decoded) {
                return Some((full.start(), label, 0.80));
            }
        }
    }

    None
}

#[inline]
fn detect_nested_quantifier(decoded: &str) -> Option<(usize, &'static str, f64)> {
    static NESTED_QUANT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"\((?:[^()\\]|\\.)*(?:\+|\*|\{\d+,?\d*\})(?:[^()\\]|\\.)*\)\s*(?:\+|\*|\{\d+,?\d*\})",
        )
        .unwrap()
    });

    let m = NESTED_QUANT_RE.find(decoded)?;
    let segment = m.as_str();

    let complex = segment.contains("{")
        || segment.contains('|')
        || segment.contains(".*")
        || segment.contains(".+");
    let confidence = if complex { 0.85 } else { 0.70 };
    let label = if complex {
        "complex nested quantifier pattern"
    } else {
        "nested quantifier pattern"
    };

    Some((m.start(), label, confidence))
}

#[inline]
fn detect_overlapping_alternation(decoded: &str) -> Option<(usize, &'static str, f64)> {
    static ALT_GROUP_REPEAT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\(([^()]{1,120}\|[^()]{1,120})\)\s*(?:\*|\+|\{\d+,?\d*\})").unwrap()
    });

    for caps in ALT_GROUP_REPEAT_RE.captures_iter(decoded) {
        let Some(group) = caps.get(1) else {
            continue;
        };
        let Some(full) = caps.get(0) else {
            continue;
        };

        let branches = group
            .as_str()
            .split('|')
            .map(|b| b.trim().to_string())
            .filter(|b| !b.is_empty())
            .collect::<Vec<_>>();

        if branches.len() < 2 {
            continue;
        }

        for (i, a) in branches.iter().enumerate() {
            for b in branches.iter().skip(i + 1) {
                if a == b || a.starts_with(b) || b.starts_with(a) {
                    return Some((
                        full.start(),
                        "overlapping alternation under repetition",
                        0.85,
                    ));
                }
            }
        }
    }

    None
}

#[inline]
fn detect_catastrophic_charclass_overlap(decoded: &str) -> Option<(usize, &'static str, f64)> {
    static CHARCLASS_NESTED_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\(\[[^\]]+\]\s*(?:\+|\*)\)\s*(?:\+|\*|\{\d+,?\d*\})").unwrap()
    });

    let m = CHARCLASS_NESTED_RE.find(decoded)?;
    Some((m.start(), "nested character-class repetition", 0.85))
}

#[inline]
fn detect_exponential_trigger(decoded: &str) -> Option<(usize, &'static str, f64)> {
    static EXP_TRIGGER_INPUT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[a-zA-Z0-9]{8,}!").unwrap());
    static VULN_REGEX_SIGNATURE_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\([a-zA-Z0-9]\+\)\+\$|\(\.\+\)\+\$|\(\[\^?[^\]]+\]\+\)\+\$").unwrap()
    });

    let Some(input_match) = EXP_TRIGGER_INPUT_RE.find(decoded) else {
        return None;
    };
    if !VULN_REGEX_SIGNATURE_RE.is_match(decoded) {
        return None;
    }

    Some((
        input_match.start(),
        "exponential backtracking trigger pattern",
        0.85,
    ))
}

#[inline]
fn detect_evil_group_unbounded(decoded: &str) -> Option<(usize, &'static str, f64)> {
    static EVIL_GROUP_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\((?:[^()\\]|\\.)*(?:\.\*|\.\+|\[[^\]]+\]\+)(?:[^()\\]|\\.)*\)\s*(?:\*|\+|\{\d+,?\d*\})").unwrap()
    });

    let m = EVIL_GROUP_RE.find(decoded)?;
    Some((
        m.start(),
        "unbounded repetition inside repeated group",
        0.85,
    ))
}

pub fn evaluate_redos(input: &str) -> Option<L2EvalResult> {
    let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

    let mut signals: Vec<(&'static str, usize, f64, EvidenceOperation)> = Vec::new();
    let sources = if decoded == input {
        vec![input]
    } else {
        vec![input, decoded.as_str()]
    };

    for source in sources {
        if let Some((pos, label, confidence)) = detect_nested_quantifier(source) {
            signals.push((label, pos, confidence, EvidenceOperation::SemanticEval));
        }

        if let Some((pos, label, confidence)) = detect_overlapping_alternation(source) {
            signals.push((label, pos, confidence, EvidenceOperation::SemanticEval));
        }

        if let Some((pos, label, confidence)) = detect_exponential_trigger(source) {
            signals.push((label, pos, confidence, EvidenceOperation::SemanticEval));
        }

        if let Some((pos, label, confidence)) = detect_catastrophic_charclass_overlap(source) {
            signals.push((label, pos, confidence, EvidenceOperation::SemanticEval));
        }

        if let Some((pos, label, confidence)) = detect_evil_group_unbounded(source) {
            signals.push((label, pos, confidence, EvidenceOperation::SemanticEval));
        }

        if let Some((pos, label, confidence)) = detect_regex_injection(source) {
            signals.push((label, pos, confidence, EvidenceOperation::PayloadInject));
        }
    }

    if signals.is_empty() {
        return None;
    }

    signals.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| b.2.total_cmp(&a.2)));

    let has_injection = signals
        .iter()
        .any(|(_, _, _, op)| *op == EvidenceOperation::PayloadInject);
    let max_confidence = signals.iter().map(|(_, _, c, _)| *c).fold(0.0, f64::max);
    let confidence = if has_injection { 0.80 } else { max_confidence };
    let position = signals.first().map(|(_, pos, _, _)| *pos).unwrap_or(0);
    let operation = signals
        .iter()
        .find(|(_, _, _, op)| *op == EvidenceOperation::PayloadInject)
        .map(|(_, _, _, op)| *op)
        .unwrap_or(EvidenceOperation::SemanticEval);

    let detail = format!(
        "ReDoS/regex abuse indicators: {}",
        signals
            .iter()
            .map(|(label, _, _, _)| *label)
            .collect::<Vec<_>>()
            .join(", ")
    );

    Some(L2Detection {
        detection_type: "regex_dos".into(),
        confidence,
        detail,
        position,
        evidence: vec![ProofEvidence {
            operation,
            matched_input: preview(&decoded),
            interpretation: if operation == EvidenceOperation::PayloadInject {
                "User-controlled input appears to construct a regex with metacharacters, enabling regex injection and potential catastrophic backtracking".into()
            } else {
                "Regex structure suggests catastrophic backtracking potential under adversarial input".into()
            },
            offset: position,
            property: "Regex evaluation must avoid catastrophic backtracking and forbid untrusted dynamic pattern construction".into(),
        }],
    })
}

pub struct RedosEvaluator;

impl L2Evaluator for RedosEvaluator {
    fn id(&self) -> &'static str {
        "redos"
    }

    fn prefix(&self) -> &'static str {
        "L2 ReDoS"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = evaluate_redos(input).into_iter().collect::<Vec<_>>();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        static ALT_BOMB_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"\(([^|()]{1,20})\|([^|()]{1,20})\)\s*[*+]").unwrap()
        });
        for caps in ALT_BOMB_RE.captures_iter(&decoded) {
            let g1 = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let g2 = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if g1 == g2 && !g1.is_empty() {
                let m = caps.get(0).unwrap();
                dets.push(L2Detection {
                    detection_type: "redos_alternation_bomb".into(),
                    confidence: 0.89,
                    detail: "Catastrophic backtracking via overlapping/identical alternation branches".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Regex alternation with identical or near-identical branches causes exponential backtracking when the engine tries both paths. (a|a)+ has 2^n paths to explore for input of length n, causing catastrophic ReDoS on failure paths".into(),
                        offset: m.start(),
                        property: "Regex alternation must use mutually exclusive branches. Never use identical alternation branches. Use atomic groups or possessive quantifiers to prevent catastrophic backtracking".into(),
                    }],
                });
                break;
            }
        }

        static BACKREF_CATASTROPHIC_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"\\[1-9]\d*\s*[+*]|\\[1-9]\d*[^)]*[+*][^)]*\)").unwrap()
        });
        if let Some(m) = BACKREF_CATASTROPHIC_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "redos_backref_catastrophic".into(),
                confidence: 0.86,
                detail: "Catastrophic backtracking via backreference combined with quantifier".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Regex backreferences (\\1, \\2) combined with + or * quantifiers force the engine to re-match a previously captured group repeatedly. \\1+ with a complex capture group creates exponential backtracking on mismatch paths".into(),
                    offset: m.start(),
                    property: "Backreferences must not appear inside quantified groups or be combined with +/* quantifiers in security-critical regex patterns".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "regex_dos" | "redos_alternation_bomb" | "redos_backref_catastrophic" => Some(InvariantClass::RegexDos),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_simple_nested_plus_quantifier() {
        let det = evaluate_redos("(a+)+").expect("expected ReDoS detection");
        assert_eq!(det.confidence, 0.70);
        assert!(det.detail.contains("nested quantifier pattern"));
    }

    #[test]
    fn detects_simple_nested_star_quantifier() {
        let det = evaluate_redos("(a*)*").expect("expected ReDoS detection");
        assert_eq!(det.confidence, 0.70);
        assert!(det.detail.contains("nested quantifier pattern"));
    }

    #[test]
    fn detects_complex_nested_brace_quantifier() {
        let det = evaluate_redos("(a{1,})+").expect("expected ReDoS detection");
        assert_eq!(det.confidence, 0.85);
        assert!(det.detail.contains("complex nested quantifier pattern"));
    }

    #[test]
    fn detects_overlapping_alternation_equal_branch() {
        let det = evaluate_redos("(a|a)*").expect("expected overlap detection");
        assert_eq!(det.confidence, 0.85);
        assert!(det.detail.contains("overlapping alternation"));
    }

    #[test]
    fn detects_overlapping_alternation_prefix_branch() {
        let det = evaluate_redos("(ab|a)*").expect("expected overlap detection");
        assert_eq!(det.confidence, 0.85);
        assert!(det.detail.contains("overlapping alternation"));
    }

    #[test]
    fn detects_star_height_greater_than_one() {
        let det = evaluate_redos("([a-z]+)+").expect("expected star-height detection");
        assert_eq!(det.confidence, 0.85);
        assert!(det.detail.contains("nested character-class repetition"));
    }

    #[test]
    fn detects_exponential_backtracking_trigger() {
        let payload = r#"/(a+)+$/.test(\"aaaaaaaaaaaa!\")"#;
        let det = evaluate_redos(payload).expect("expected exponential trigger detection");
        assert_eq!(det.confidence, 0.85);
        assert!(
            det.detail
                .contains("exponential backtracking trigger pattern")
        );
    }

    #[test]
    fn detects_evil_unbounded_group_pattern() {
        let det = evaluate_redos("(.+)+$").expect("expected evil group detection");
        assert_eq!(det.confidence, 0.85);
        assert!(
            det.detail
                .contains("unbounded repetition inside repeated group")
        );
    }

    #[test]
    fn detects_regex_injection_new_regexp_user_input() {
        let payload = r#"const userInput = \"(a+)+$\"; new RegExp(userInput)"#;
        let det = evaluate_redos(payload).expect("expected regex injection detection");
        assert_eq!(det.confidence, 0.80);
        assert!(det.detail.contains("new RegExp(user_input)"));
    }

    #[test]
    fn detects_regex_injection_python_compile_user_input() {
        let payload = r#"user_input='(a+)+$'; re.compile(user_input)"#;
        let det = evaluate_redos(payload).expect("expected regex injection detection");
        assert_eq!(det.confidence, 0.80);
        assert!(det.detail.contains("re.compile(user_input)"));
    }

    #[test]
    fn detects_regex_injection_rust_regex_new_user_input() {
        let payload = r#"let user_input = \"(a+)+$\"; Regex::new(user_input).unwrap()"#;
        let det = evaluate_redos(payload).expect("expected regex injection detection");
        assert_eq!(det.confidence, 0.80);
        assert!(det.detail.contains("Regex::new(user_input)"));
    }

    #[test]
    fn no_detection_for_safe_anchored_pattern() {
        assert!(evaluate_redos(r"^[a-z0-9_-]{3,16}$").is_none());
    }

    #[test]
    fn no_detection_for_safe_literal_new_regexp() {
        assert!(evaluate_redos(r#"new RegExp(\"^[a-z]+$\")"#).is_none());
    }

    #[test]
    fn no_detection_for_safe_literal_re_compile() {
        assert!(evaluate_redos(r#"re.compile(r\"^\\d+$\")"#).is_none());
    }

    #[test]
    fn no_detection_for_benign_text() {
        assert!(evaluate_redos("hello world").is_none());
    }

    #[test]
    fn combines_multiple_redos_signals() {
        let det = evaluate_redos("(ab|a)* and (a+)+$").expect("expected combined detection");
        assert_eq!(det.confidence, 0.85);
        assert!(det.detail.contains("overlapping alternation"));
        assert!(det.detail.contains("nested quantifier pattern"));
    }

    #[test]
    fn evaluator_wrapper_returns_detection() {
        let eval = RedosEvaluator;
        let dets = eval.detect("(a+)+");
        assert_eq!(dets.len(), 1);
        assert_eq!(dets[0].detection_type, "regex_dos");
    }

    #[test]
    fn evaluator_maps_to_regex_dos_class() {
        let eval = RedosEvaluator;
        assert_eq!(eval.map_class("regex_dos"), Some(InvariantClass::RegexDos));
        assert_eq!(eval.map_class("unknown"), None);
    }

    #[test]
    fn detects_redos_alternation_bomb() {
        let eval = RedosEvaluator;
        let dets = eval.detect("(a|a)*");
        assert!(dets.iter().any(|d| d.detection_type == "redos_alternation_bomb"));
        assert_eq!(eval.map_class("redos_alternation_bomb"), Some(InvariantClass::RegexDos));
    }

    #[test]
    fn detects_redos_backref_catastrophic() {
        let eval = RedosEvaluator;
        let dets = eval.detect(r"\1*");
        assert!(dets.iter().any(|d| d.detection_type == "redos_backref_catastrophic"));
        assert_eq!(eval.map_class("redos_backref_catastrophic"), Some(InvariantClass::RegexDos));
    }
}
