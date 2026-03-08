//! Server-Side Includes (SSI) Injection Evaluator — Level 2
//!
//! Detects SSI directive injection in user input. When a web server has
//! SSI processing enabled (.shtml, etc.), injected directives execute
//! server-side commands or include files.
//!
//! Impact: RCE via `<!--#exec cmd="..."-->`, file disclosure via
//! `<!--#include virtual="..."-->`.

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;

pub struct SsiEvaluator;

impl L2Evaluator for SsiEvaluator {
    fn id(&self) -> &'static str {
        "ssi"
    }
    fn prefix(&self) -> &'static str {
        "L2 SSI"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
        let lower = decoded.to_ascii_lowercase();

        // SSI directives: <!--#directive param="value" -->
        let ssi_directives = [
            ("<!--#exec", "exec", "Server-side command execution via SSI exec directive", 0.95),
            ("<!--#include", "include", "Server-side file inclusion via SSI include directive", 0.92),
            ("<!--#echo", "echo", "SSI echo directive — environment variable disclosure", 0.80),
            ("<!--#set", "set", "SSI set directive — variable manipulation", 0.78),
            ("<!--#config", "config", "SSI config directive — error message manipulation", 0.75),
            ("<!--#flastmod", "flastmod", "SSI flastmod directive — file metadata disclosure", 0.72),
            ("<!--#fsize", "fsize", "SSI fsize directive — file size disclosure", 0.72),
            ("<!--#printenv", "printenv", "SSI printenv directive — full environment dump", 0.90),
        ];

        for &(pattern, name, desc, confidence) in &ssi_directives {
            if lower.contains(pattern) {
                let pos = lower.find(pattern).unwrap_or(0);
                dets.push(L2Detection {
                    detection_type: format!("ssi_{}", name),
                    confidence,
                    detail: desc.into(),
                    position: pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded[pos..decoded.len().min(pos + 60)].to_string(),
                        interpretation: format!(
                            "Input contains SSI directive '<!--#{}'. When processed by a server with SSI enabled (Apache mod_include, Nginx ssi on), this directive executes server-side. The '{}' directive {}.",
                            name, name,
                            match name {
                                "exec" => "executes arbitrary OS commands",
                                "include" => "reads arbitrary files from the server filesystem",
                                "echo" => "discloses server environment variables",
                                "printenv" => "dumps all server environment variables",
                                _ => "manipulates server-side processing"
                            }
                        ),
                        offset: pos,
                        property: format!("User input must not contain SSI directives. The <!--#{} syntax must be escaped or rejected.", name),
                    }],
                });
            }
        }

        // ESI directives: <esi:* ...> and ESI variable expansions $(HTTP_*{...})
        if lower.contains("<esi:include") {
            let pattern = "<esi:include";
            let pos = lower.find(pattern).unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "ssi_esi_include".into(),
                confidence: 0.91,
                detail: "ESI include directive can trigger SSRF through CDN/reverse-proxy fetch".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[pos..decoded.len().min(pos + 60)].to_string(),
                    interpretation: "Input contains '<esi:include'. ESI processors (Varnish, Squid, Akamai, Cloudflare) may fetch attacker-controlled URLs server-side, enabling SSRF and internal network probing.".into(),
                    offset: pos,
                    property: "User input must not contain ESI include directives or untrusted ESI markup.".into(),
                }],
            });
        }

        if lower.contains("<esi:vars") || lower.contains("$(http_cookie{") || lower.contains("$(http_header{") {
            let pos = lower
                .find("<esi:vars")
                .or_else(|| lower.find("$(http_cookie{"))
                .or_else(|| lower.find("$(http_header{"))
                .unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "ssi_esi_vars".into(),
                confidence: 0.85,
                detail: "ESI variable expansion can disclose cookies and headers from edge context".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[pos..decoded.len().min(pos + 60)].to_string(),
                    interpretation: "Input contains ESI variable syntax (<esi:vars> or $(HTTP_COOKIE{...})/$(HTTP_HEADER{...})). This can exfiltrate sensitive header and cookie data via edge-side rendering.".into(),
                    offset: pos,
                    property: "User input must not contain ESI variable directives or HTTP_* variable expansions.".into(),
                }],
            });
        }

        if (lower.contains("<esi:remove>")
            && (lower.contains("<script")
                || lower.contains("javascript:")
                || lower.contains("onerror=")
                || lower.contains("onload=")))
            || lower.contains("<esi:comment")
        {
            let pos = lower
                .find("<esi:remove>")
                .or_else(|| lower.find("<esi:comment"))
                .unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "ssi_esi_remove".into(),
                confidence: 0.82,
                detail: "ESI remove/comment directives can be abused to bypass filters and enable XSS payload shaping".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[pos..decoded.len().min(pos + 60)].to_string(),
                    interpretation: "Input contains ESI remove/comment markup. Attackers can hide or reshape script content at the edge to bypass WAF/view-layer defenses.".into(),
                    offset: pos,
                    property: "User input must not contain ESI remove/comment directives or script-bearing ESI fragments.".into(),
                }],
            });
        }

        if lower.contains("<esi:choose") || lower.contains("<esi:when") || lower.contains("<esi:otherwise") {
            let pos = lower
                .find("<esi:choose")
                .or_else(|| lower.find("<esi:when"))
                .or_else(|| lower.find("<esi:otherwise"))
                .unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "ssi_esi_conditional".into(),
                confidence: 0.86,
                detail: "ESI conditional directives enable attacker-controlled conditional content injection".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[pos..decoded.len().min(pos + 60)].to_string(),
                    interpretation: "Input contains ESI conditional directives (<esi:choose>/<esi:when>/<esi:otherwise>). These can inject logic-driven payloads rendered by CDN/reverse-proxy ESI processors.".into(),
                    offset: pos,
                    property: "User input must not contain ESI conditional directives.".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        if detection_type.starts_with("ssi_") {
            Some(InvariantClass::SsiInjection)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ssi_exec() {
        let eval = SsiEvaluator;
        let dets = eval.detect(r#"<!--#exec cmd="cat /etc/passwd" -->"#);
        assert!(dets.iter().any(|d| d.detection_type == "ssi_exec"));
    }

    #[test]
    fn detects_ssi_include() {
        let eval = SsiEvaluator;
        let dets = eval.detect(r#"<!--#include virtual="/etc/passwd" -->"#);
        assert!(dets.iter().any(|d| d.detection_type == "ssi_include"));
    }

    #[test]
    fn detects_ssi_printenv() {
        let eval = SsiEvaluator;
        let dets = eval.detect("<!--#printenv -->");
        assert!(dets.iter().any(|d| d.detection_type == "ssi_printenv"));
    }

    #[test]
    fn no_detection_for_html_comment() {
        let eval = SsiEvaluator;
        let dets = eval.detect("<!-- this is a regular comment -->");
        assert!(dets.is_empty());
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = SsiEvaluator;
        assert_eq!(
            eval.map_class("ssi_exec"),
            Some(InvariantClass::SsiInjection)
        );
    }

    #[test]
    fn test_esi_include_ssrf() {
        let eval = SsiEvaluator;
        let dets = eval.detect(r#"<esi:include src="http://evil.com/secret" />"#);
        assert!(dets.iter().any(|d| d.detection_type == "ssi_esi_include"));
    }

    #[test]
    fn test_esi_vars_cookie_theft() {
        let eval = SsiEvaluator;
        let dets = eval.detect("$(HTTP_COOKIE{session})");
        assert!(dets.iter().any(|d| d.detection_type == "ssi_esi_vars"));
    }

    #[test]
    fn test_esi_conditional_injection() {
        let eval = SsiEvaluator;
        let dets = eval.detect(r#"<esi:choose><esi:when test="$(HTTP_COOKIE{admin})==1">"#);
        assert!(dets.iter().any(|d| d.detection_type == "ssi_esi_conditional"));
    }
}
