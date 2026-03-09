//! Clickjacking / UI Redressing Evaluator — Level 2
//!
//! Detects clickjacking attack signals by analyzing:
//!   - iframe embedding with attacker-controlled overlays
//!   - Missing frame protection headers in responses
//!   - CSS opacity/position tricks for UI redressing
//!   - Drag-and-drop jacking patterns

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

type RustDetection = L2Detection;

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

        if let Some(det) = detect_csp_frame_ancestors_bypass(input) {
            dets.push(det);
        }
        if let Some(det) = detect_double_framing_attack(input) {
            dets.push(det);
        }
        if let Some(det) = detect_drag_drop_clickjacking(input) {
            dets.push(det);
        }
        if let Some(det) = detect_touch_event_hijack(input) {
            dets.push(det);
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "clickjacking_iframe_overlay"
            | "clickjacking_sandbox_bypass"
            | "clickjacking_drag_drop"
            | "clickjacking_xfo_bypass"
            | "clickjacking_csp_frameancestors_bypass"
            | "clickjacking_csp_frame_ancestors_bypass"
            | "clickjacking_double_framing_attack"
            | "clickjacking_drag_drop_exfil"
            | "clickjacking_touch_event_hijack" => Some(InvariantClass::ClickjackingVuln),
            _ => None,
        }
    }
}

fn detect_csp_frame_ancestors_bypass(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();
    let has_csp = lower.contains("content-security-policy:");
    let missing_frame_ancestors = has_csp && !lower.contains("frame-ancestors");
    let has_none_and_wildcard_fallback = lower.contains("frame-ancestors 'none'")
        && (lower.contains("frame-ancestors *")
            || lower.contains("frame-ancestors http:")
            || lower.contains("frame-ancestors https:"));
    let allow_from_wildcard = lower.contains("x-frame-options: allow-from *")
        || lower.contains("x-frame-options: allowall");
    let contradictory_xfo = lower.contains("x-frame-options: deny")
        && (lower.contains("x-frame-options: allowall")
            || lower.contains("x-frame-options: allow-from"));

    if !(missing_frame_ancestors
        || has_none_and_wildcard_fallback
        || allow_from_wildcard
        || contradictory_xfo)
    {
        return None;
    }

    Some(RustDetection {
        detection_type: "clickjacking_csp_frame_ancestors_bypass".into(),
        confidence: 0.88,
        detail: "CSP/XFO frame-ancestor bypass pattern detected (missing or contradictory framing policy)"
            .into(),
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: lower[..lower.len().min(220)].to_string(),
            interpretation: "The framing policy is bypassable due to missing frame-ancestors, wildcard fallback, or permissive/contradictory X-Frame-Options directives.".into(),
            offset: 0,
            property: "Set CSP frame-ancestors to a strict allowlist and keep X-Frame-Options consistent (DENY or SAMEORIGIN only).".into(),
        }],
    })
}

fn extract_origin(src: &str) -> Option<String> {
    let trimmed = src.trim();
    if trimmed.starts_with("data:") {
        return Some("data:".to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("http://") {
        return Some(
            rest.split(&['/', '?', '#'][..])
                .next()
                .unwrap_or_default()
                .to_string(),
        );
    }
    if let Some(rest) = trimmed.strip_prefix("https://") {
        return Some(
            rest.split(&['/', '?', '#'][..])
                .next()
                .unwrap_or_default()
                .to_string(),
        );
    }
    if let Some(rest) = trimmed.strip_prefix("//") {
        return Some(
            rest.split(&['/', '?', '#'][..])
                .next()
                .unwrap_or_default()
                .to_string(),
        );
    }
    None
}

fn detect_double_framing_attack(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();
    let iframe_re = Regex::new(r#"(?is)<iframe[^>]*\bsrc\s*=\s*["']([^"']+)["']"#).ok()?;
    let mut srcs = Vec::new();
    for cap in iframe_re.captures_iter(&lower) {
        if let Some(m) = cap.get(1) {
            srcs.push(m.as_str().to_string());
        }
    }
    if srcs.len() < 2 {
        return None;
    }

    let mut has_different_origins = false;
    for i in 0..srcs.len() {
        for j in (i + 1)..srcs.len() {
            if let (Some(a), Some(b)) = (extract_origin(&srcs[i]), extract_origin(&srcs[j])) {
                if !a.is_empty() && !b.is_empty() && a != b {
                    has_different_origins = true;
                    break;
                }
            }
        }
        if has_different_origins {
            break;
        }
    }

    let frame_bust_bypass = (lower.contains("if(top") || lower.contains("if (top"))
        && lower.contains("self")
        && lower.contains("data:text/html");

    if !(has_different_origins && (lower.contains("<iframe") || frame_bust_bypass)) {
        return None;
    }

    Some(RustDetection {
        detection_type: "clickjacking_double_framing_attack".into(),
        confidence: 0.85,
        detail: "Potential double-framing attack: nested iframes with cross-origin chain".into(),
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: srcs.join(" -> "),
            interpretation: "Multiple iframe sources from different origins can be used to keep a trusted outer frame while an attacker-controlled inner frame bypasses frame-busting protections.".into(),
            offset: 0,
            property: "Block framing with strict CSP frame-ancestors and avoid relying on frame-busting JavaScript.".into(),
        }],
    })
}

fn detect_drag_drop_clickjacking(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();
    let has_draggable = lower.contains("draggable=\"true\"") || lower.contains("draggable=true");
    let has_drag_start = lower.contains("ondragstart")
        || lower.contains("addEventListener('dragstart'")
        || lower.contains("addeventlistener(\"dragstart\"");
    if !(has_draggable && has_drag_start && lower.contains("<iframe")) {
        return None;
    }

    let sensitive_terms = [
        "/admin",
        "/account",
        "/transfer",
        "/payment",
        "/billing",
        "/oauth",
        "/token",
        "/settings",
    ];
    if !sensitive_terms.iter().any(|t| lower.contains(t)) {
        return None;
    }

    Some(RustDetection {
        detection_type: "clickjacking_drag_drop_exfil".into(),
        confidence: 0.82,
        detail: "Drag-and-drop clickjacking with sensitive framed target detected".into(),
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::PayloadInject,
            matched_input: lower[..lower.len().min(220)].to_string(),
            interpretation: "A draggable UI element with dragstart logic over a sensitive iframe can trick users into dropping protected data into attacker-controlled controls.".into(),
            offset: 0,
            property: "Prevent framing of sensitive workflows and disable unsafe drag/drop handlers around embedded content.".into(),
        }],
    })
}

fn detect_touch_event_hijack(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();
    let has_hidden_iframe = lower.contains("<iframe")
        && (lower.contains("opacity:0")
            || lower.contains("opacity: 0")
            || lower.contains("visibility:hidden")
            || lower.contains("visibility: hidden"));
    let has_touch_hooks = lower.contains("ontouchstart")
        || lower.contains("ontouchend")
        || lower.contains("addEventListener('touchstart'")
        || lower.contains("addEventListener(\"touchstart\"")
        || lower.contains("addEventListener('touchend'")
        || lower.contains("addEventListener(\"touchend\"")
        || lower.contains("addeventlistener('touchstart'")
        || lower.contains("addeventlistener(\"touchstart\"")
        || lower.contains("addeventlistener('touchend'")
        || lower.contains("addeventlistener(\"touchend\"");
    let has_pointer_events = lower.contains("pointer-events:all") || lower.contains("pointer-events: all");
    if !(has_hidden_iframe && has_touch_hooks && has_pointer_events) {
        return None;
    }

    Some(RustDetection {
        detection_type: "clickjacking_touch_event_hijack".into(),
        confidence: 0.84,
        detail: "Mobile touch-event hijacking pattern over hidden iframe detected".into(),
        position: 0,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::SemanticEval,
            matched_input: lower[..lower.len().min(220)].to_string(),
            interpretation: "Touch handlers combined with a transparent iframe and pointer-events enabled can hijack taps on mobile browsers.".into(),
            offset: 0,
            property: "Disallow framing of sensitive views and avoid transparent interaction layers that intercept touch events.".into(),
        }],
    })
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

    #[test]
    fn detects_frame_ancestors_missing_in_csp() {
        let eval = ClickjackingEvaluator;
        let input = "Content-Security-Policy: default-src 'self'; script-src 'self'";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "clickjacking_csp_frame_ancestors_bypass")
        );
    }

    #[test]
    fn detects_frame_ancestors_none_with_wildcard_fallback() {
        let eval = ClickjackingEvaluator;
        let input = "Content-Security-Policy: frame-ancestors 'none'; Content-Security-Policy-Report-Only: frame-ancestors *";
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "clickjacking_csp_frame_ancestors_bypass")
        );
    }

    #[test]
    fn detects_double_framing_mixed_origins() {
        let eval = ClickjackingEvaluator;
        let input = r#"<iframe src="https://trusted.example/container"><iframe src="https://evil.example/pay"></iframe></iframe>"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "clickjacking_double_framing_attack")
        );
    }

    #[test]
    fn detects_drag_drop_sensitive_iframe() {
        let eval = ClickjackingEvaluator;
        let input = r#"<div draggable="true" ondragstart="x()">drag</div><iframe src="https://bank.example/transfer"></iframe>"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "clickjacking_drag_drop_exfil")
        );
    }

    #[test]
    fn detects_touch_hijack_pattern() {
        let eval = ClickjackingEvaluator;
        let input = r#"<iframe src="https://target.example/account" style="opacity:0;pointer-events:all"></iframe><script>document.addEventListener('touchstart', fn)</script>"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "clickjacking_touch_event_hijack")
        );
    }

    #[test]
    fn does_not_detect_drag_drop_without_sensitive_iframe() {
        let eval = ClickjackingEvaluator;
        let input = r#"<div draggable="true" ondragstart="x()">drag</div><iframe src="https://cdn.example/widget"></iframe>"#;
        let dets = eval.detect(input);
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "clickjacking_drag_drop_exfil")
        );
    }

    #[test]
    fn does_not_detect_touch_hijack_without_pointer_events() {
        let eval = ClickjackingEvaluator;
        let input = r#"<iframe src="https://target.example/account" style="opacity:0"></iframe><script>document.addEventListener('touchend', fn)</script>"#;
        let dets = eval.detect(input);
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "clickjacking_touch_event_hijack")
        );
    }

    #[test]
    fn does_not_detect_double_framing_same_origin_iframes() {
        let eval = ClickjackingEvaluator;
        let input = r#"<iframe src="https://same.example/a"></iframe><iframe src="https://same.example/b"></iframe>"#;
        let dets = eval.detect(input);
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "clickjacking_double_framing_attack")
        );
    }
}
