//! File Upload Evaluator — Level 2
//!
//! Detects malicious file upload patterns:
//!   - Polyglot files (JPEG+PHP, GIF89a+PHP, PNG+PHP)
//!   - Double extensions (.php.jpg, .asp;.jpg)
//!   - Content-Type mismatch with extension
//!   - Null byte extension truncation
//!   - SVG with embedded script
//!   - Server-side executable extensions in non-executable contexts
//!
//! File upload is a top-10 web vulnerability (CWE-434). Unrestricted upload
//! enables RCE via webshell deployment.

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;

/// Extensions that execute server-side.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
    ".asp", ".aspx", ".ashx", ".asmx", ".cer",
    ".jsp", ".jspx", ".jsw", ".jsv",
    ".cgi", ".pl", ".py", ".rb",
    ".sh", ".bash",
    ".shtml", ".shtm",
    ".cfm", ".cfml",
    ".exe", ".dll", ".bat", ".cmd", ".com", ".msi",
    ".war", ".jar",
];

/// Image extensions used in polyglot attacks.
const IMAGE_EXTENSIONS: &[&str] = &[
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".webp", ".svg",
];

/// Polyglot file signature magic bytes (text representations).
const POLYGLOT_SIGNATURES: &[(&str, &str)] = &[
    ("GIF89a", "GIF polyglot"),
    ("GIF87a", "GIF polyglot"),
    ("\u{0089}PNG", "PNG polyglot"),
    ("\u{00ff}\u{00d8}\u{00ff}", "JPEG polyglot"),
];

pub struct UploadEvaluator;

impl L2Evaluator for UploadEvaluator {
    fn id(&self) -> &'static str {
        "upload"
    }
    fn prefix(&self) -> &'static str {
        "L2 Upload"
    }

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;
        let lower = decoded.to_ascii_lowercase();

        // 1. Double extension (file.php.jpg, file.asp;.jpg)
        for &exec in EXECUTABLE_EXTENSIONS {
            for &img in IMAGE_EXTENSIONS {
                let double = format!("{}{}", exec, img);
                if lower.contains(&double) {
                    let pos = lower.find(&double).unwrap_or(0);
                    dets.push(L2Detection {
                        detection_type: "upload_double_extension".into(),
                        confidence: 0.90,
                        detail: format!("Double extension polyglot: *{}{} — executable masquerading as image", exec, img),
                        position: pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: double.clone(),
                            interpretation: format!(
                                "File uses double extension {}{} to bypass extension-based upload filters. The server may process the first extension ({}) and execute the file, while the filter only checks the last extension ({}).",
                                exec, img, exec, img
                            ),
                            offset: pos,
                            property: "File upload validation must check the entire filename, not just the final extension. Executable extensions must be rejected regardless of position.".into(),
                        }],
                    });
                    return dets; // one double-extension detection is sufficient
                }
            }
        }

        // 2. Null byte extension truncation (%00, \x00)
        if (lower.contains("%00") || decoded.contains('\0')) {
            for &exec in EXECUTABLE_EXTENSIONS {
                if lower.contains(exec) {
                    let pos = lower.find(exec).unwrap_or(0);
                    dets.push(L2Detection {
                        detection_type: "upload_null_byte".into(),
                        confidence: 0.93,
                        detail: format!("Null byte extension truncation with executable extension '{}'", exec),
                        position: pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::ContextEscape,
                            matched_input: decoded[pos..decoded.len().min(pos + 40)].to_string(),
                            interpretation: format!(
                                "Null byte (\\x00 or %00) truncates the filename at the C/OS level, causing the file to be saved with the extension '{}' despite the visible extension appearing safe. This bypasses extension-based allowlists.",
                                exec
                            ),
                            offset: pos,
                            property: "Filenames must be stripped of null bytes before extension validation. The storage path must not contain null terminators.".into(),
                        }],
                    });
                    return dets;
                }
            }
        }

        // 3. Semicolon extension bypass (IIS: file.asp;.jpg)
        if lower.contains(';') {
            for &exec in EXECUTABLE_EXTENSIONS {
                let pattern = format!("{};", exec);
                if lower.contains(&pattern) {
                    let pos = lower.find(&pattern).unwrap_or(0);
                    dets.push(L2Detection {
                        detection_type: "upload_semicolon_bypass".into(),
                        confidence: 0.88,
                        detail: format!("IIS semicolon extension bypass: {}; — IIS treats ';' as a path parameter separator", exec),
                        position: pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::ContextEscape,
                            matched_input: decoded[pos..decoded.len().min(pos + 30)].to_string(),
                            interpretation: format!(
                                "IIS treats semicolons as path parameter separators. A file named 'shell.asp;.jpg' is processed as 'shell.asp' by IIS while the filter sees '.jpg'. This enables webshell upload on IIS servers.",
                            ),
                            offset: pos,
                            property: "Filenames must be sanitized before IIS-specific parsing. Semicolons in filenames must be rejected.".into(),
                        }],
                    });
                    return dets;
                }
            }
        }

        // 4. SVG with embedded script
        if lower.contains("<svg") && (lower.contains("<script") || lower.contains("onload=") || lower.contains("onerror=")) {
            dets.push(L2Detection {
                detection_type: "upload_svg_xss".into(),
                confidence: 0.91,
                detail: "SVG file with embedded script — stored XSS via file upload".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: lower[..lower.len().min(120)].to_string(),
                    interpretation: "SVG files are XML-based and can contain embedded JavaScript via <script> tags or event handlers (onload, onerror). When served with an SVG content type, browsers execute the embedded script in the context of the hosting domain.".into(),
                    offset: 0,
                    property: "SVG uploads must be sanitized to remove script elements and event handlers, or served with Content-Disposition: attachment.".into(),
                }],
            });
        }

        // 5. Polyglot file signature + executable content
        for &(sig, name) in POLYGLOT_SIGNATURES {
            if decoded.starts_with(sig) || lower.starts_with(&sig.to_ascii_lowercase()) {
                // Check if it also contains PHP/JSP/ASP code
                if lower.contains("<?php") || lower.contains("<%") || lower.contains("<script") {
                    dets.push(L2Detection {
                        detection_type: "upload_polyglot".into(),
                        confidence: 0.94,
                        detail: format!("{} — file starts with image signature but contains server-side code", name),
                        position: 0,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: decoded[..decoded.len().min(80)].to_string(),
                            interpretation: format!(
                                "File begins with a valid {} header/signature but contains embedded server-side code (PHP/JSP/ASP). Image validators accept the file, but the web server executes the embedded code when accessed with the correct URL.",
                                name
                            ),
                            offset: 0,
                            property: "File upload validation must verify content integrity beyond the magic bytes. Content-sniffing must not override the declared content type.".into(),
                        }],
                    });
                    break;
                }
            }
        }

        // 6. Webshell patterns in uploaded content
        let webshell_patterns = [
            ("<?php eval(", "PHP eval webshell"),
            ("<?php system(", "PHP system webshell"),
            ("<?php exec(", "PHP exec webshell"),
            ("<?php passthru(", "PHP passthru webshell"),
            ("<?php shell_exec(", "PHP shell_exec webshell"),
            ("runtime.getruntime().exec(", "Java Runtime exec webshell"),
            ("<%@ page", "JSP webshell page directive"),
            ("response.write", "ASP Response.Write webshell"),
        ];

        for &(pattern, desc) in &webshell_patterns {
            if lower.contains(pattern) {
                let pos = lower.find(pattern).unwrap_or(0);
                dets.push(L2Detection {
                    detection_type: "upload_webshell".into(),
                    confidence: 0.95,
                    detail: format!("Webshell pattern detected: {}", desc),
                    position: pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: decoded[pos..decoded.len().min(pos + 60)].to_string(),
                        interpretation: format!(
                            "Uploaded content contains '{}' — a known webshell pattern that provides remote code execution when accessed via the web server.",
                            desc
                        ),
                        offset: pos,
                        property: "Uploaded files must not contain server-side code execution constructs. File content must be validated against an allowlist of safe content types.".into(),
                    }],
                });
                break; // one webshell detection is sufficient
            }
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "upload_double_extension"
            | "upload_null_byte"
            | "upload_semicolon_bypass"
            | "upload_svg_xss"
            | "upload_polyglot"
            | "upload_webshell" => Some(InvariantClass::MaliciousUpload),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_double_extension() {
        let eval = UploadEvaluator;
        let dets = eval.detect("filename=shell.php.jpg");
        assert!(dets.iter().any(|d| d.detection_type == "upload_double_extension"));
    }

    #[test]
    fn detects_null_byte_truncation() {
        let eval = UploadEvaluator;
        let dets = eval.detect("filename=shell.php%00.jpg");
        assert!(dets.iter().any(|d| d.detection_type == "upload_null_byte"));
    }

    #[test]
    fn detects_iis_semicolon() {
        let eval = UploadEvaluator;
        let dets = eval.detect("filename=shell.asp;.jpg");
        assert!(dets.iter().any(|d| d.detection_type == "upload_semicolon_bypass"));
    }

    #[test]
    fn detects_svg_xss() {
        let eval = UploadEvaluator;
        let dets = eval.detect(r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#);
        assert!(dets.iter().any(|d| d.detection_type == "upload_svg_xss"));
    }

    #[test]
    fn detects_php_webshell() {
        let eval = UploadEvaluator;
        let dets = eval.detect("<?php eval($_POST['cmd']); ?>");
        assert!(dets.iter().any(|d| d.detection_type == "upload_webshell"));
    }

    #[test]
    fn no_detection_for_normal_filename() {
        let eval = UploadEvaluator;
        let dets = eval.detect("filename=photo.jpg");
        assert!(dets.is_empty());
    }

    #[test]
    fn maps_to_correct_class() {
        let eval = UploadEvaluator;
        assert_eq!(
            eval.map_class("upload_webshell"),
            Some(InvariantClass::MaliciousUpload)
        );
    }
}
