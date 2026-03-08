//! Path Traversal Evaluator — L2 Detection
//!
//! Invariant: user input for filesystem paths must not contain directory
//! traversal sequences that escape the intended directory scope.

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::tokenizers::path::{PathTokenType, PathTokenizer};
use crate::types::InvariantClass;
use regex::Regex;
use std::sync::LazyLock;

const SENSITIVE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/ssh",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log",
    "/root/.ssh",
    "win.ini",
    "boot.ini",
    "SAM",
    "SYSTEM",
    "web.config",
    ".htaccess",
    ".env",
];

pub struct PathTraversalEvaluator;

// Hot-path regexes are compiled once to avoid repeated initialization overhead.
static WINDOWS_BYPASS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:\.\.[\\/]){2,}|%5c|/\.\.;/").unwrap());
static UNC_PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:\\\\|//)[a-z0-9._-]+[\\/][a-z0-9.$_-]+").unwrap());
static NORMALIZATION_BYPASS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)/\./(?:\.\./)+|(?:[\\/][^\\/\s]+)+[\\/]\.\.[\\/](?:\.\.[\\/])+|\.\.[\\/].*[\\/]\.\.",
    )
    .unwrap()
});
static SYMLINK_INDICATOR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)/proc/self/root|/dev/fd/\d+").unwrap());
static URL_IN_PATH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)file://|\\\\\?[a-z]:\\|/dev/stdin").unwrap());
static DOUBLE_ENCODED_TRAVERSAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)%252e%252e%252f|%252e%252e%255c").unwrap());
static ENCODED_TRAVERSAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:%2e%2e|%252e%252e|\.%2e|%2e\.|%c0%ae|%c1%9c|\.\.%c0%af)").unwrap()
});
static CASE_VARIATION_TRAVERSAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.\.[\\/]|%2e%2e(?:%2f|%5c)").unwrap());
static PATH_TRUNCATION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(?:^|[\\/])[^\\/\s]{260,}(?:[\\/]|$)"#).unwrap());
static PHP_FILTER_WRAPPER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)php://filter/(?:read|write|string|convert)=[^/]*/resource=").unwrap()
});
static PHP_STREAM_WRAPPER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)php://(?:input|output|memory|temp|stdin|stdout|stderr)").unwrap()
});
static DATA_URI_WRAPPER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)data://(?:text/plain|application/octet-stream)(?:;base64)?,[^&]*").unwrap()
});
static PHAR_WRAPPER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)phar://[^\s&?#]+\.(?:phar|zip|tar|gz|jpg|png|gif|pdf)").unwrap()
});
static ZIP_WRAPPER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)zip://[^#]*#").unwrap());
static EXPECT_WRAPPER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)expect://").unwrap());

impl L2Evaluator for PathTraversalEvaluator {
    fn id(&self) -> &'static str {
        "path_traversal"
    }
    fn prefix(&self) -> &'static str {
        "L2 Path"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let tokenizer = PathTokenizer;
        let stream = tokenizer.tokenize(input);
        let tokens = stream.all();

        // Windows traversal bypasses: ..\..\ , encoded backslashes, and Tomcat /..;/
        if let Some(m) = WINDOWS_BYPASS_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_windows_bypass".into(),
                confidence: 0.91,
                detail: format!("Windows/Tomcat traversal bypass sequence: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Mixed traversal separators bypass canonical directory checks"
                        .into(),
                    offset: m.start(),
                    property: "Path input must not include cross-platform traversal bypasses"
                        .into(),
                }],
            });
        }

        // UNC path injection can pivot to SMB/NTLM reachability
        if let Some(m) = UNC_PATH_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_unc_injection".into(),
                confidence: 0.90,
                detail: format!("UNC network path in user input: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "UNC path may trigger outbound SMB/NTLM resolution".into(),
                    offset: m.start(),
                    property: "User paths must not target remote UNC shares".into(),
                }],
            });
        }

        // Dot-segment and mixed-separator normalization bypasses
        if let Some(m) = NORMALIZATION_BYPASS_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_normalization_bypass".into(),
                confidence: 0.90,
                detail: format!("Path normalization bypass chain: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Dot-segment normalization can collapse to escaped parent paths".into(),
                    offset: m.start(),
                    property: "Path normalization must preserve sandbox boundaries".into(),
                }],
            });
        }

        // Case-variation and mixed separator traversal bypasses
        if let Some(m) = CASE_VARIATION_TRAVERSAL_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_case_variation_bypass".into(),
                confidence: 0.90,
                detail: format!("Case-variation traversal sequence: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Case/encoding variants of traversal can evade naive filters"
                        .into(),
                    offset: m.start(),
                    property: "Canonicalize before evaluating path traversal".into(),
                }],
            });
        }

        // Symlink/proc filesystem traversal indicators
        if let Some(m) = SYMLINK_INDICATOR_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_symlink_indicator".into(),
                confidence: 0.93,
                detail: format!("Symlink-style path escape indicator: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Process root/file-descriptor paths can bypass intended filesystem roots"
                            .into(),
                    offset: m.start(),
                    property: "User paths must not reference procfs or live file descriptors"
                        .into(),
                }],
            });
        }

        // URL-like or device-style paths passed where local file path is expected
        if let Some(m) = URL_IN_PATH_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_url_injection".into(),
                confidence: 0.92,
                detail: format!("Non-local path scheme/device indicator: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "URL/device path form bypasses local path-only assumptions"
                        .into(),
                    offset: m.start(),
                    property: "User input must resolve to a canonical local filesystem path".into(),
                }],
            });
        }

        // Double URL-encoded traversal bypass (%252e%252e%252f => %2e%2e%2f => ../)
        if let Some(m) = DOUBLE_ENCODED_TRAVERSAL_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_double_url_encoded".into(),
                confidence: 0.94,
                detail: format!("Double URL-encoded traversal sequence: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Double decoding reveals parent-directory traversal".into(),
                    offset: m.start(),
                    property: "Encoded path segments must not decode into traversal".into(),
                }],
            });
        }

        // Overlong components used in truncation-based traversal/lookup bypasses
        if PATH_TRUNCATION_RE.is_match(input) {
            dets.push(L2Detection {
                detection_type: "path_overlong_component".into(),
                confidence: 0.90,
                detail: "Overlong path component may enable path truncation attacks".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: input.to_owned(),
                    interpretation:
                        "Excessively long segments can collide with legacy path truncation behavior"
                            .into(),
                    offset: 0,
                    property: "Reject path segments beyond platform-safe limits".into(),
                }],
            });
        }

        // PHP stream/filter wrappers used in LFI exploitation chains
        if let Some(m) = PHP_FILTER_WRAPPER_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_php_filter_wrapper".into(),
                confidence: 0.91,
                detail: format!("PHP filter wrapper path in input: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "PHP filter wrapper can expose or transform local file contents".into(),
                    offset: m.start(),
                    property: "Path input must not include PHP wrappers in file path context"
                        .into(),
                }],
            });
        }

        if let Some(m) = PHP_STREAM_WRAPPER_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_php_stream_wrapper".into(),
                confidence: 0.89,
                detail: format!("PHP stream wrapper path in input: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "PHP stream wrappers can redirect reads/writes beyond intended files"
                            .into(),
                    offset: m.start(),
                    property:
                        "Path input must not use PHP input/output or memory stream wrappers".into(),
                }],
            });
        }

        if let Some(m) = DATA_URI_WRAPPER_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_data_uri_wrapper".into(),
                confidence: 0.88,
                detail: format!("Data URI wrapper in file path context: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Data URI wrappers can inject inline payloads where file paths are expected"
                            .into(),
                    offset: m.start(),
                    property: "Path input must resolve to local file paths, not data URIs".into(),
                }],
            });
        }

        if let Some(m) = PHAR_WRAPPER_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_phar_wrapper".into(),
                confidence: 0.93,
                detail: format!("PHAR wrapper path in input: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "PHAR wrappers can trigger deserialization side effects via file APIs".into(),
                    offset: m.start(),
                    property: "Path input must not include PHAR archive wrappers".into(),
                }],
            });
        }

        if let Some(m) = ZIP_WRAPPER_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_zip_wrapper".into(),
                confidence: 0.87,
                detail: format!("ZIP wrapper path in input: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "ZIP wrappers can access internal archive members through path parsing"
                            .into(),
                    offset: m.start(),
                    property: "Path input must not include archive wrapper schemes".into(),
                }],
            });
        }

        if let Some(m) = EXPECT_WRAPPER_RE.find(input) {
            dets.push(L2Detection {
                detection_type: "path_expect_wrapper".into(),
                confidence: 0.94,
                detail: format!("Expect wrapper in file path context: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Expect wrapper can execute commands when interpreted as a file path".into(),
                    offset: m.start(),
                    property: "Path input must not include command-executing wrapper schemes".into(),
                }],
            });
        }

        // Count traversal tokens
        let traversal_count = tokens
            .iter()
            .filter(|t| t.token_type == PathTokenType::Traversal)
            .count();
        let has_null_byte = input.contains('\0') || input.contains("%00");
        if has_null_byte {
            dets.push(L2Detection {
                detection_type: "null_byte".into(),
                confidence: 0.92,
                detail: "Null byte in path — extension bypass attempt".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: input.to_owned(),
                    interpretation: "Null byte truncates path extension check".into(),
                    offset: 0,
                    property: "Path input must not contain null bytes".into(),
                }],
            });
        }

        if traversal_count == 0 {
            return dets;
        }

        // Calculate confidence based on traversal depth and target sensitivity
        let mut confidence = 0.75 + (traversal_count as f64 * 0.04).min(0.20);

        // Check for sensitive file target
        let input_lower = input.to_lowercase();
        let targets_sensitive = SENSITIVE_PATHS
            .iter()
            .any(|p| input_lower.contains(&p.to_lowercase()));
        if targets_sensitive {
            confidence = confidence.max(0.92);
        }

        if has_null_byte {
            confidence = confidence.max(0.90);
        }

        // Look for encoded traversal patterns
        if ENCODED_TRAVERSAL_RE.is_match(input) {
            confidence = confidence.max(0.88);
        }

        // Main traversal detection
        for tok in tokens {
            if tok.token_type == PathTokenType::Traversal {
                dets.push(L2Detection {
                    detection_type: "directory_traversal".into(),
                    confidence,
                    detail: format!(
                        "Directory traversal: {} escapes intended directory scope (depth: {})",
                        tok.value, traversal_count
                    ),
                    position: tok.start,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::ContextEscape,
                        matched_input: tok.value.clone(),
                        interpretation: "Path traversal sequence escapes directory boundary".into(),
                        offset: tok.start,
                        property: "User-supplied path must remain within intended directory scope"
                            .into(),
                    }],
                });
                break; // One detection per input (traversal count already captured)
            }
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "directory_traversal" => Some(InvariantClass::PathDotdotEscape),
            "null_byte" => Some(InvariantClass::PathNullTerminate),
            "path_windows_bypass" => Some(InvariantClass::PathDotdotEscape),
            "path_unc_injection" => Some(InvariantClass::PathEncodingBypass),
            "path_normalization_bypass" | "path_symlink_indicator" => {
                Some(InvariantClass::PathNormalizationBypass)
            }
            "path_url_injection"
            | "path_double_url_encoded"
            | "path_case_variation_bypass"
            | "path_overlong_component"
            | "path_php_filter_wrapper"
            | "path_php_stream_wrapper"
            | "path_data_uri_wrapper"
            | "path_phar_wrapper"
            | "path_zip_wrapper"
            | "path_expect_wrapper" => Some(InvariantClass::PathEncodingBypass),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_traversal() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("../../etc/passwd");
        assert!(!dets.is_empty());
    }

    #[test]
    fn no_traversal() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("images/photo.jpg");
        assert!(dets.is_empty());
    }

    #[test]
    fn detects_windows_bypass_sequences() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect(r"..\..\windows\win.ini");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_windows_bypass")
        );
    }

    #[test]
    fn detects_unc_path_injection() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect(r"\\server\share\secret.txt");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_unc_injection")
        );
    }

    #[test]
    fn detects_normalization_bypass() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("/./../../etc/passwd");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_normalization_bypass")
        );
    }

    #[test]
    fn detects_symlink_escape_indicators() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("/proc/self/root/etc/shadow");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_symlink_indicator")
        );
    }

    #[test]
    fn detects_url_in_path_payloads() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("file:///etc/passwd");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_url_injection")
        );
    }

    #[test]
    fn detects_double_encoded_traversal() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("%252e%252e%252fetc%252fpasswd");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_double_url_encoded")
        );
    }

    #[test]
    fn detects_dot_inflation_traversal() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("....//....//etc/passwd");
        assert!(
            dets.iter().any(|d| {
                d.detection_type == "directory_traversal"
                    || d.detection_type == "path_normalization_bypass"
            }),
            "Dot inflation traversal should be detected"
        );
    }

    #[test]
    fn detects_single_encoded_traversal() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("%2e%2e%2fsecret.txt");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_case_variation_bypass")
                || dets
                    .iter()
                    .any(|d| d.detection_type == "directory_traversal")
        );
    }

    #[test]
    fn detects_null_byte_filename_injection() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("file.php%00.jpg");
        assert!(dets.iter().any(|d| d.detection_type == "null_byte"));
    }

    #[test]
    fn detects_case_variation_bypass_windows_separator_mix() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect(r"..\..%2Fadmin");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_case_variation_bypass")
                || dets
                    .iter()
                    .any(|d| d.detection_type == "path_windows_bypass")
        );
    }

    #[test]
    fn detects_path_truncation_component() {
        let eval = PathTraversalEvaluator;
        let long = "a".repeat(280);
        let input = format!("/tmp/{long}/index.html");
        let dets = eval.detect(&input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_overlong_component")
        );
    }

    #[test]
    fn detects_php_filter_wrapper_lfi_payload() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("php://filter/read=convert.base64-encode/resource=/etc/passwd");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_php_filter_wrapper")
        );
    }

    #[test]
    fn detects_php_stream_wrapper_lfi_payload() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("php://input");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_php_stream_wrapper")
        );
    }

    #[test]
    fn detects_data_uri_wrapper_lfi_payload() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_data_uri_wrapper")
        );
    }

    #[test]
    fn detects_phar_wrapper_deserialization_payload() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("phar://uploads/avatar.jpg");
        assert!(dets.iter().any(|d| d.detection_type == "path_phar_wrapper"));
    }

    #[test]
    fn detects_zip_wrapper_lfi_payload() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("zip://archive.zip#payload.php");
        assert!(dets.iter().any(|d| d.detection_type == "path_zip_wrapper"));
    }

    #[test]
    fn detects_expect_wrapper_lfi_payload() {
        let eval = PathTraversalEvaluator;
        let dets = eval.detect("expect://id");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "path_expect_wrapper")
        );
    }

    #[test]
    fn maps_path_case_variation_and_overlong_to_encoding_bypass_class() {
        let eval = PathTraversalEvaluator;
        assert_eq!(
            eval.map_class("path_case_variation_bypass"),
            Some(InvariantClass::PathEncodingBypass)
        );
        assert_eq!(
            eval.map_class("path_overlong_component"),
            Some(InvariantClass::PathEncodingBypass)
        );
        assert_eq!(
            eval.map_class("path_php_filter_wrapper"),
            Some(InvariantClass::PathEncodingBypass)
        );
        assert_eq!(
            eval.map_class("path_php_stream_wrapper"),
            Some(InvariantClass::PathEncodingBypass)
        );
        assert_eq!(
            eval.map_class("path_data_uri_wrapper"),
            Some(InvariantClass::PathEncodingBypass)
        );
        assert_eq!(
            eval.map_class("path_phar_wrapper"),
            Some(InvariantClass::PathEncodingBypass)
        );
        assert_eq!(
            eval.map_class("path_zip_wrapper"),
            Some(InvariantClass::PathEncodingBypass)
        );
        assert_eq!(
            eval.map_class("path_expect_wrapper"),
            Some(InvariantClass::PathEncodingBypass)
        );
    }
}
