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

type RustDetection = L2Detection;

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

fn detect_polyglot_file_upload(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();
    let has_php = lower.contains("<?php");
    let has_html = lower.contains("<html");
    let has_script = lower.contains("<script");
    let has_gif = lower.contains("gif89a");
    let has_jpeg_magic = input.starts_with("\u{00ff}\u{00d8}\u{00ff}") || lower.contains("ff d8 ff");
    let has_pdf = lower.contains("%pdf-");

    if (has_gif && has_php) || (has_jpeg_magic && has_script) || (has_pdf && has_html) {
        let pos = if has_gif {
            lower.find("gif89a").unwrap_or(0)
        } else if has_jpeg_magic {
            lower.find("ff d8 ff").unwrap_or(0)
        } else {
            lower.find("%pdf-").unwrap_or(0)
        };
        return Some(RustDetection {
            detection_type: "upload_polyglot_file".into(),
            confidence: 0.90,
            detail: "Polyglot upload payload combines multiple file formats (image/document + executable markup/code)".into(),
            position: pos,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::PayloadInject,
                matched_input: input[pos..input.len().min(pos + 120)].to_string(),
                interpretation: "Payload appears valid under one file signature while containing executable or active content from another format (e.g., GIF+PHP, JPEG+script, PDF+HTML).".into(),
                offset: pos,
                property: "Upload validation must enforce strict single-format parsing and reject active-content polyglots.".into(),
            }],
        });
    }

    None
}

fn detect_zip_slip_in_upload(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();
    let pos = lower
        .find("../")
        .or_else(|| lower.find("..\\"))
        .or_else(|| lower.find("%2e%2e%2f"))
        .or_else(|| lower.find("%2e%2e%5c"))
        .or_else(|| lower.find("..%2f"))
        .or_else(|| lower.find("..%5c"));

    if let Some(idx) = pos {
        return Some(RustDetection {
            detection_type: "upload_zip_slip_in_archive".into(),
            confidence: 0.93,
            detail: "Archive member path traversal (zip slip) in uploaded content".into(),
            position: idx,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::ContextEscape,
                matched_input: input[idx..input.len().min(idx + 120)].to_string(),
                interpretation: "Archive member names include parent traversal segments and can write files outside extraction root.".into(),
                offset: idx,
                property: "Archive extraction must normalize and block entries resolving outside destination root.".into(),
            }],
        });
    }

    None
}

fn detect_svg_upload_xss(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();
    if !lower.contains("<svg") {
        return None;
    }
    if let Some(pos) = lower.find("<svg") {
        let has_event = lower.contains("onload=") || lower.contains("onerror=");
        let has_external_href = lower.contains("<image")
            && (lower.contains("href='http://")
                || lower.contains("href=\"http://")
                || lower.contains("href='https://")
                || lower.contains("href=\"https://"));
        if has_event || has_external_href {
            return Some(RustDetection {
                detection_type: "upload_svg_upload_xss".into(),
                confidence: 0.91,
                detail: "SVG upload contains scriptable event handlers or external URL reference".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input[pos..input.len().min(pos + 120)].to_string(),
                    interpretation: "SVG content can execute script via event handlers or trigger SSRF/XSS via external references in image href attributes.".into(),
                    offset: pos,
                    property: "SVG uploads must be sanitized and disallow scriptable attributes and external network references.".into(),
                }],
            });
        }
    }

    None
}

fn detect_archive_bomb_upload(input: &str) -> Option<RustDetection> {
    let lower = input.to_ascii_lowercase();

    if let Some(pos) = lower.find(".tar.gz.gz.gz") {
        return Some(RustDetection {
            detection_type: "upload_archive_bomb".into(),
            confidence: 0.85,
            detail: "Nested archive extension chain indicates possible archive bomb".into(),
            position: pos,
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::PayloadInject,
                matched_input: input[pos..input.len().min(pos + 120)].to_string(),
                interpretation: "Repeated nested compression layers are commonly used in archive bombs to exhaust decompression resources.".into(),
                offset: pos,
                property: "Upload processing must enforce archive depth limits and reject excessive nested compression.".into(),
            }],
        });
    }

    let parse_number = |s: &str| -> Option<u64> {
        let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
        digits.parse::<u64>().ok()
    };
    let uncompressed = lower
        .split("uncompressed")
        .nth(1)
        .and_then(parse_number);
    let compressed = lower
        .split("compressed")
        .nth(1)
        .and_then(parse_number);
    if let (Some(u), Some(c)) = (uncompressed, compressed) {
        if c > 0 && u / c >= 1000 {
            let pos = lower.find("uncompressed").unwrap_or(0);
            return Some(RustDetection {
                detection_type: "upload_archive_bomb".into(),
                confidence: 0.85,
                detail: "Extreme uncompressed/compressed ratio indicates archive bomb behavior".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input[pos..input.len().min(pos + 120)].to_string(),
                    interpretation: "The declared decompression ratio is abnormally high and can trigger disk/CPU exhaustion during extraction.".into(),
                    offset: pos,
                    property: "Archive handling must apply decompression ratio and total-expanded-size limits.".into(),
                }],
            });
        }
    }

    None
}

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

        // 7. Zip slip / archive path traversal
        if lower.contains("filename=") && (lower.contains("../") || lower.contains("..\\") || lower.contains("%2e%2e") || lower.contains("..%2f") || lower.contains("..%5c")) {
            let pos = lower.find("filename=").unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "upload_zip_slip".into(),
                confidence: 0.93,
                detail: "Archive entry filename contains path traversal (..). During extraction, files are written outside the target directory (zip slip). This enables writing webshells to executable directories, overwriting config files, or planting cron jobs.".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: decoded[pos..decoded.len().min(pos + 40)].to_string(),
                    interpretation: "Archive entry filename contains path traversal (..). During extraction, files are written outside the target directory (zip slip). This enables writing webshells to executable directories, overwriting config files, or planting cron jobs.".into(),
                    offset: pos,
                    property: "Archive extraction must validate that resolved paths remain within the target extraction directory.".into(),
                }],
            });
        }

        // 8. Malicious .htaccess / web.config upload
        if let Ok(re) = regex::Regex::new(r#"(?i)(?:^|/)(?:\.htaccess|web\.config|\.(user\.ini|htpasswd|htdigest|php\.ini|ini))(?:['"]|$|\s)"#) {
            if let Some(mat) = re.find(&decoded) {
                dets.push(L2Detection {
                    detection_type: "upload_config_override".into(),
                    confidence: 0.92,
                    detail: "Upload of server configuration file (.htaccess, web.config, .user.ini) can override PHP execution rules, enable directory listing, redirect requests, or cause the server to execute non-PHP files as PHP. This enables code execution without uploading a .php file.".into(),
                    position: mat.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: mat.as_str().to_string(),
                        interpretation: "Upload of server configuration file (.htaccess, web.config, .user.ini) can override PHP execution rules, enable directory listing, redirect requests, or cause the server to execute non-PHP files as PHP. This enables code execution without uploading a .php file.".into(),
                        offset: mat.start(),
                        property: "File uploads must reject server configuration files.".into(),
                    }],
                });
            }
        }

        // 9. Content-Type mismatch
        if let Ok(re_ct) = regex::Regex::new(r#"(?im)^content-type\s*:\s*(image/|text/plain)"#) {
            if re_ct.is_match(&decoded) {
                for &exec in EXECUTABLE_EXTENSIONS {
                    if lower.contains(exec) {
                        let pos = lower.find(exec).unwrap_or(0);
                        dets.push(L2Detection {
                            detection_type: "upload_content_type_mismatch".into(),
                            confidence: 0.87,
                            detail: "Content-Type header claims the file is an image or plain text, but the filename contains an executable extension. Servers that trust Content-Type over extension validation accept the dangerous file while believing it is safe.".into(),
                            position: pos,
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::ContextEscape,
                                matched_input: decoded[pos..decoded.len().min(pos + 40)].to_string(),
                                interpretation: "Content-Type header claims the file is an image or plain text, but the filename contains an executable extension. Servers that trust Content-Type over extension validation accept the dangerous file while believing it is safe.".into(),
                                offset: pos,
                                property: "File extension must match the declared Content-Type and its actual content.".into(),
                            }],
                        });
                        break;
                    }
                }
            }
        }

        // 10. XML/SVG XXE in upload
        if (lower.contains("<svg") || lower.contains("<?xml")) && lower.contains("<!doctype") && lower.contains("<!entity") {
            let pos = lower.find("<!entity").unwrap_or(0);
            dets.push(L2Detection {
                detection_type: "upload_xxe".into(),
                confidence: 0.91,
                detail: "Uploaded SVG or XML file contains a DOCTYPE with ENTITY declaration. When the server parses this file (for validation, resizing, or rendering), the XML parser fetches external entities, enabling SSRF and local file disclosure (/etc/passwd, internal service endpoints).".into(),
                position: pos,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: decoded[pos..decoded.len().min(pos + 40)].to_string(),
                    interpretation: "Uploaded SVG or XML file contains a DOCTYPE with ENTITY declaration. When the server parses this file (for validation, resizing, or rendering), the XML parser fetches external entities, enabling SSRF and local file disclosure (/etc/passwd, internal service endpoints).".into(),
                    offset: pos,
                    property: "XML parsers must disable external entity resolution (XXE) when processing untrusted SVG or XML uploads.".into(),
                }],
            });
        }

        if let Some(det) = detect_polyglot_file_upload(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_zip_slip_in_upload(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_svg_upload_xss(&decoded) {
            dets.push(det);
        }
        if let Some(det) = detect_archive_bomb_upload(&decoded) {
            dets.push(det);
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
            | "upload_webshell"
            | "upload_zip_slip"
            | "upload_config_override"
            | "upload_content_type_mismatch"
            | "upload_xxe"
            | "upload_polyglot_file"
            | "upload_zip_slip_in_archive"
            | "upload_svg_upload_xss"
            | "upload_archive_bomb" => Some(InvariantClass::MaliciousUpload),
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

    #[test]
    fn detects_zip_slip() {
        let eval = UploadEvaluator;
        let dets = eval.detect("filename=../../../etc/passwd");
        assert!(dets.iter().any(|d| d.detection_type == "upload_zip_slip"));
    }

    #[test]
    fn detects_config_override() {
        let eval = UploadEvaluator;
        let dets = eval.detect("filename=\"/.htaccess\"");
        assert!(dets.iter().any(|d| d.detection_type == "upload_config_override"));
    }

    #[test]
    fn detects_content_type_mismatch() {
        let eval = UploadEvaluator;
        let dets = eval.detect("Content-Type: image/jpeg\r\n\r\nfilename=\"shell.php\"");
        assert!(dets.iter().any(|d| d.detection_type == "upload_content_type_mismatch"));
    }

    #[test]
    fn detects_xxe_in_upload() {
        let eval = UploadEvaluator;
        let dets = eval.detect(r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>"#);
        assert!(dets.iter().any(|d| d.detection_type == "upload_xxe"));
    }

    #[test]
    fn detects_polyglot_gif_php_upload() {
        let eval = UploadEvaluator;
        let dets = eval.detect("GIF89a<?php echo 'owned'; ?>");
        assert!(dets.iter().any(|d| d.detection_type == "upload_polyglot_file"));
    }

    #[test]
    fn detects_polyglot_pdf_html_upload() {
        let eval = UploadEvaluator;
        let dets = eval.detect("%PDF-1.7\n<html><body>payload</body></html>");
        assert!(dets.iter().any(|d| d.detection_type == "upload_polyglot_file"));
    }

    #[test]
    fn detects_zip_slip_archive_member_relative() {
        let eval = UploadEvaluator;
        let dets = eval.detect("archive-entry=../../../etc/cron.d/evil");
        assert!(dets.iter().any(|d| d.detection_type == "upload_zip_slip_in_archive"));
    }

    #[test]
    fn detects_zip_slip_archive_member_backslash() {
        let eval = UploadEvaluator;
        let dets = eval.detect(r"archive-entry=..\..\Windows\System32\drivers\etc\hosts");
        assert!(dets.iter().any(|d| d.detection_type == "upload_zip_slip_in_archive"));
    }

    #[test]
    fn detects_svg_upload_onload_xss() {
        let eval = UploadEvaluator;
        let dets = eval.detect(r#"<svg onload=alert(1) xmlns="http://www.w3.org/2000/svg"></svg>"#);
        assert!(dets.iter().any(|d| d.detection_type == "upload_svg_upload_xss"));
    }

    #[test]
    fn detects_svg_upload_external_href() {
        let eval = UploadEvaluator;
        let dets = eval.detect(r#"<svg><image href='http://evil.example/x.png' /></svg>"#);
        assert!(dets.iter().any(|d| d.detection_type == "upload_svg_upload_xss"));
    }

    #[test]
    fn detects_archive_bomb_nested_extensions() {
        let eval = UploadEvaluator;
        let dets = eval.detect("filename=backup.tar.gz.gz.gz");
        assert!(dets.iter().any(|d| d.detection_type == "upload_archive_bomb"));
    }

    #[test]
    fn detects_archive_bomb_ratio_indicator() {
        let eval = UploadEvaluator;
        let dets = eval.detect("compressed size: 1024 bytes; uncompressed size: 2147483648 bytes");
        assert!(dets.iter().any(|d| d.detection_type == "upload_archive_bomb"));
    }
}
