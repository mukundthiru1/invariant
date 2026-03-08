use regex::Regex;
use std::sync::LazyLock;

use crate::classes::{ClassDefinition, decode};
use crate::types::InvariantClass;

static DOTDOT_DECODED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\.{2,}[\\/]+){2,}").unwrap());
static DOTDOT_RAW: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\.\.%2[fF]|%2[eE]%2[eE]%2[fF]|\.\.%5[cC]){2,}").unwrap());
static NULL_TERM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"%00|\\x00|\\0|\x00").unwrap());
static ENC_BYPASS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"%252[eE]%252[eE]|%25252|%c0%ae|%c0%af|%e0%80%ae|\.%00\.").unwrap()
});
static SENSITIVE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/etc/(?:passwd|shadow|hosts)|/proc/self/(?:environ|cmdline|maps)|/windows/(?:system32|win\.ini)").unwrap()
});
static TRAVERSAL_HINT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\.\.[\\/]|%2e|%252e)").unwrap());
static NORM_TRAILING_DOT_SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/[^/]+\.{1,}/").unwrap());
static NORM_SENSITIVE_DOT_SEGMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/(?:admin|config|internal|secret|private|\.env|\.git)/\.(?:/|$)").unwrap()
});
static NORM_SPACE_SEGMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/[^/]+\s+/").unwrap());
static NORM_SEMICOLON_SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/[^/]+;[^/]*/").unwrap());
static NORM_MIXED_SLASHES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^/.*\\.*\w").unwrap());
static NORM_SENSITIVE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/(?:admin|config|internal|secret|private|\.env|\.git)[\\/]").unwrap()
});

fn path_dotdot_escape(input: &str) -> bool {
    let d = decode(input);
    DOTDOT_DECODED.is_match(&d) || DOTDOT_RAW.is_match(input)
}

fn path_null_terminate(input: &str) -> bool {
    NULL_TERM.is_match(input)
}

fn path_encoding_bypass(input: &str) -> bool {
    if ENC_BYPASS.is_match(input) {
        return true;
    }
    let d = decode(input);
    if let Some(m) = SENSITIVE_PATH.find(&d) {
        let has_traversal = TRAVERSAL_HINT.is_match(input);
        let is_path_dominant = d.trim().len() < m.as_str().len() * 3;
        return has_traversal || is_path_dominant;
    }
    false
}

fn path_normalization_bypass(input: &str) -> bool {
    let d = decode(input);
    NORM_TRAILING_DOT_SEGMENT.is_match(&d)
        || NORM_SENSITIVE_DOT_SEGMENT.is_match(&d)
        || NORM_SPACE_SEGMENT.is_match(&d)
        || NORM_SEMICOLON_SEGMENT.is_match(&d)
        || (NORM_MIXED_SLASHES.is_match(&d) && NORM_SENSITIVE_PATH.is_match(&d))
}

pub const PATH_CLASSES: &[ClassDefinition] = &[
    ClassDefinition {
        id: InvariantClass::PathDotdotEscape,
        description: "Use ../ sequences to escape the webroot and access arbitrary files",
        detect: path_dotdot_escape,
        known_payloads: &[
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
        ],
        known_benign: &[
            "/home/user/documents",
            "file.txt",
            "./local-file.js",
            "../sibling-dir",
            "https://example.com/path",
        ],
        mitre: &["T1083"],
        cwe: Some("CWE-22"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::PathNullTerminate,
        description: "Null byte injection to truncate file extension checks",
        detect: path_null_terminate,
        known_payloads: &[
            "../../../etc/passwd%00.jpg",
            "shell.php%00.gif",
            "/etc/passwd\\x00.html",
        ],
        known_benign: &["image.jpg", "document.pdf", "style.css", "100% complete"],
        mitre: &["T1083"],
        cwe: Some("CWE-158"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::PathEncodingBypass,
        description: "Multi-layer encoding to bypass path traversal filters",
        detect: path_encoding_bypass,
        known_payloads: &[
            "%252e%252e%252fetc%252fpasswd",
            "..%c0%af..%c0%afetc/passwd",
            "..%e0%80%ae/etc/passwd",
        ],
        known_benign: &[
            "hello%20world",
            "/api/users",
            "filename.txt",
            "%E2%9C%93 check mark",
        ],
        mitre: &["T1083"],
        cwe: Some("CWE-22"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::PathNormalizationBypass,
        description: "Path normalization tricks (trailing dots, reserved names, backslash→slash) to bypass access controls",
        detect: path_normalization_bypass,
        known_payloads: &[
            "/admin/./",
            "/admin../",
            "/Admin%20/",
            "/admin;/secret",
            "/admin;jsessionid=x/secret",
            "/api/v1/admin\\secret",
        ],
        known_benign: &[
            "/api/users",
            "/home/page",
            "/about",
            "/contact-us",
            "/images/logo.png",
        ],
        mitre: &["T1083"],
        cwe: Some("CWE-22"),
        formal_property: None,
        composable_with: &[],
    },
];
