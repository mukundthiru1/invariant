//! Clickjacking / UI Redressing Evaluator — Level 2
//!
//! Detects clickjacking attack signals by analyzing:
//!   - iframe embedding with attacker-controlled overlays
//!   - Missing frame protection headers in responses
//!   - CSS opacity/position tricks for UI redressing
//!   - Drag-and-drop jacking patterns

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;

pub struct ClickjackingEvaluator;

impl L2Evaluator for ClickjackingEvaluator {
    fn id(&self) -> &'static str {
        "clickjacking"
    }
    fn prefix(&self) -> &'static str {
        "L2 Clickjacking"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let lower = input.to_ascii_lowercase();

        // 1. iframe with opacity:0 or visibility:hidden (classic clickjacking)
        if lower.contains("<iframe") {
            let has_opacity_trick = lower.contains("opacity:0")
                || lower.contains("opacity: 0")
                || lower.contains("visibility:hidden")
                || lower.contains("visibility: hidden");

            let has_position_trick = lower.contains("position:absolute")
                || lower.contains("position: absolute")
                || lower.contains("position:fixed")
                || lower.contains("position: fixed");

            if has_opacity_trick || (lower.contains("<iframe") && has_position_trick) {
                dets.push(L2Detection {
                    detection_type: "clickjacking_iframe_overlay".into(),
                    confidence: 0.88,
                    detail: "Invisible iframe overlay detected — clickjacking attack setup".into(),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: lower[..lower.len().min(200)].to_string(),
                        interpretation: "Hidden iframe with CSS tricks (opacity:0, position:absolute) creates an invisible overlay. The victim sees the attacker's page but their clicks are intercepted by the invisible iframe, triggering actions on the target site (transfers, permission grants, etc.).".into(),
                        offset: 0,
                        property: "Applications must set X-Frame-Options or Content-Security-Policy frame-ancestors to prevent embedding in untrusted contexts.".into(),
                    }],
                });
            }

            // iframe with sandbox bypass or missing sandbox
            if lower.contains("<iframe") && lower.contains("sandbox=\"") {
                let allow_patterns = [
                    "allow-scripts allow-same-origin",
                    "allow-same-origin allow-scripts",
                ];
                for pattern in &allow_patterns {
                    if lower.contains(pattern) {
                        dets.push(L2Detection {
                            detection_type: "clickjacking_sandbox_bypass".into(),
                            confidence: 0.85,
                            detail: "iframe with sandbox='allow-scripts allow-same-origin' — sandbox is effectively disabled".into(),
                            position: 0,
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::SemanticEval,
                                matched_input: pattern.to_string(),
                                interpretation: "Combining 'allow-scripts' and 'allow-same-origin' in an iframe sandbox effectively disables the sandbox, as the embedded content can remove the sandbox attribute entirely via JavaScript.".into(),
                                offset: 0,
                                property: "iframe sandbox must never combine 'allow-scripts' and 'allow-same-origin'. These permissions together negate the sandbox.".into(),
                            }],
                        });
                        break;
                    }
                }
            }
        }

        // 2. Drag-and-drop jacking
        if lower.contains("draggable=\"true\"") && lower.contains("ondrop") {
            dets.push(L2Detection {
                detection_type: "clickjacking_drag_drop".into(),
                confidence: 0.80,
                detail: "Drag-and-drop jacking pattern — draggable elements with drop handlers".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: "draggable=true + ondrop handler".into(),
                    interpretation: "Draggable elements combined with drop handlers can trick users into dragging sensitive content (tokens, URLs) from a legitimate page into an attacker-controlled drop zone, exfiltrating data without requiring clicks.".into(),
                    offset: 0,
                    property: "Sensitive pages must use Content-Security-Policy frame-ancestors to prevent embedding. Drag-and-drop interactions with cross-origin content must be restricted.".into(),
                }],
            });
        }

        // 3. CSP/X-Frame-Options abuse indicators
        if lower.contains("x-frame-options") {
            if lower.contains("x-frame-options: allowall") || lower.contains("x-frame-options: allow-from") {
                dets.push(L2Detection {
                    detection_type: "clickjacking_xfo_bypass".into(),
                    confidence: 0.82,
                    detail: "X-Frame-Options set to overly permissive value — framing protection disabled".into(),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SemanticEval,
                        matched_input: "X-Frame-Options: ALLOWALL or ALLOW-FROM".into(),
                        interpretation: "X-Frame-Options is set to a permissive value that allows framing by any origin. This disables clickjacking protection.".into(),
                        offset: 0,
                        property: "X-Frame-Options must be set to DENY or SAMEORIGIN. ALLOW-FROM is deprecated and unsupported by most browsers.".into(),
                    }],
                });
            }
        }

        // 4. CSP frame-ancestors bypass
        for line in lower.lines() {
            if line.contains("content-security-policy:") && line.contains("frame-ancestors") {
                if line.contains("frame-ancestors *")
                    || line.contains("frame-ancestors http:")
                    || line.contains("frame-ancestors https:")
                {
                    dets.push(L2Detection {
                        detection_type: "clickjacking_csp_frameancestors_bypass".into(),
                        confidence: 0.87,
                        detail: "CSP frame-ancestors is overly permissive".into(),
                        position: 0,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::SemanticEval,
                            matched_input: line.to_string(),
                            interpretation: "CSP frame-ancestors directive uses a wildcard or permissive scheme (http/https), allowing the application to be framed by arbitrary domains, defeating clickjacking protections.".into(),
                            offset: 0,
                            property: "CSP frame-ancestors must be restricted to 'self' or specific trusted domains.".into(),
                        }],
                    });
                }
            }
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "clickjacking_iframe_overlay"
            | "clickjacking_sandbox_bypass"
            | "clickjacking_drag_drop"
            | "clickjacking_xfo_bypass"
            | "clickjacking_csp_frameancestors_bypass" => Some(InvariantClass::ClickjackingVuln),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_csp_frameancestors_wildcard() {
        let eval = ClickjackingEvaluator;
        let dets = eval.detect("Content-Security-Policy: default-src self; frame-ancestors *");
        assert!(dets.iter().any(|d| d.detection_type == "clickjacking_csp_frameancestors_bypass"));
    }

    #[test]
    fn no_detection_for_strict_frameancestors() {
        let eval = ClickjackingEvaluator;
        let dets = eval.detect("Content-Security-Policy: frame-ancestors none");
        assert!(dets.is_empty());
    }

    #[test]
    fn detects_invisible_iframe() {
        let eval = ClickjackingEvaluator;
        let input = r#"<iframe src="https://bank.com/transfer" style="opacity:0; position:absolute; width:100%;"></iframe>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "clickjacking_iframe_overlay"));
    }

    #[test]
    fn detects_sandbox_bypass() {
        let eval = ClickjackingEvaluator;
        let input = r#"<iframe sandbox="allow-scripts allow-same-origin" src="https://target.com"></iframe>"#;
        let dets = eval.detect(input);
        assert!(dets.iter().any(|d| d.detection_type == "clickjacking_sandbox_bypass"));
    }

    #[test]
    fn no_detection_for_safe_iframe() {
        let eval = ClickjackingEvaluator;
        let dets = eval.detect(r#"<iframe src="https://youtube.com/embed/abc"></iframe>"#);
        assert!(dets.is_empty());
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = ClickjackingEvaluator;
        assert_eq!(
            eval.map_class("clickjacking_iframe_overlay"),
            Some(InvariantClass::ClickjackingVuln)
        );
    }
}
