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
}
