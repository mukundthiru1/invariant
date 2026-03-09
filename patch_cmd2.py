import re

with open("packages/engine-rs/src/evaluators/cmd.rs", "r") as f:
    content = f.read()

content = content.replace(
    "        self.detect_additional_evasion_patterns(&decoded, &mut dets);",
    "        self.detect_additional_evasion_patterns(&decoded, &mut dets);\n        self.detect_new_cmd_types(&decoded, &mut dets);"
)

new_func = """
    fn detect_new_cmd_types(&self, raw_input: &str, dets: &mut Vec<L2Detection>) {
        static ENV_VAR_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:\\$HOME|\\$PATH|\\$\\{USER\\}|\\$IFS)").unwrap());
        for m in ENV_VAR_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "cmd_env_variable_expansion".into(),
                confidence: 0.85,
                detail: "Shell env var expansion in command args".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: m.as_str().to_owned(), interpretation: "expansion".into(), offset: m.start(), property: "no".into() }]
            });
        }
        static PROCESS_SUB_EXACT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:<|>)\\([^)]+\\)").unwrap());
        for m in PROCESS_SUB_EXACT_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "cmd_process_substitution".into(),
                confidence: 0.90,
                detail: "Bash process substitution injected in args".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: m.as_str().to_owned(), interpretation: "proc sub".into(), offset: m.start(), property: "no".into() }]
            });
        }
        static HERE_STRING_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"<<<\\s*\\w+").unwrap());
        for m in HERE_STRING_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "cmd_here_string".into(),
                confidence: 0.87,
                detail: "Here-string injection".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: m.as_str().to_owned(), interpretation: "here string".into(), offset: m.start(), property: "no".into() }]
            });
        }
        static GLOB_EXPANSION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:^|\\s)(?:/\\w*)*[?*\\[\\]]+(?:/\\w*)*").unwrap());
        for m in GLOB_EXPANSION_RE.find_iter(raw_input) {
            if m.as_str().contains('*') || m.as_str().contains('?') || m.as_str().contains('[') {
                dets.push(L2Detection {
                    detection_type: "cmd_glob_expansion".into(),
                    confidence: 0.82,
                    detail: "Glob injection".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: m.as_str().to_owned(), interpretation: "glob".into(), offset: m.start(), property: "no".into() }]
                });
            }
        }
        static NEWLINE_INJ_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:\\n|%0a|\\r\\n)").unwrap());
        for m in NEWLINE_INJ_RE.find_iter(raw_input) {
            dets.push(L2Detection {
                detection_type: "cmd_newline_injection".into(),
                confidence: 0.91,
                detail: "Newline injection".into(),
                position: m.start(),
                evidence: vec![ProofEvidence { operation: EvidenceOperation::PayloadInject, matched_input: m.as_str().to_owned(), interpretation: "newline".into(), offset: m.start(), property: "no".into() }]
            });
        }
    }

    fn detect_additional_evasion_patterns"""

content = content.replace("    fn detect_additional_evasion_patterns", new_func)

content = content.replace(
    '"blind_timing_injection" | "here_string_injection" => {',
    '"cmd_env_variable_expansion" | "cmd_process_substitution" | "cmd_here_string" | "cmd_glob_expansion" | "cmd_newline_injection" | "blind_timing_injection" | "here_string_injection" => {'
)

tests_to_add = """

    #[test]
    fn test_cmd_env_variable_expansion() {
        let eval = CmdInjectionEvaluator;
        assert!(eval.detect("ls $HOME").iter().any(|d| d.detection_type == "cmd_env_variable_expansion"));
        assert!(eval.detect("cat $PATH").iter().any(|d| d.detection_type == "cmd_env_variable_expansion"));
        assert!(!eval.detect("echo hello").iter().any(|d| d.detection_type == "cmd_env_variable_expansion"));
    }

    #[test]
    fn test_cmd_process_substitution() {
        let eval = CmdInjectionEvaluator;
        assert!(eval.detect("cat <(ls)").iter().any(|d| d.detection_type == "cmd_process_substitution"));
        assert!(eval.detect("tee >(ls)").iter().any(|d| d.detection_type == "cmd_process_substitution"));
        assert!(!eval.detect("echo hello").iter().any(|d| d.detection_type == "cmd_process_substitution"));
    }

    #[test]
    fn test_cmd_here_string() {
        let eval = CmdInjectionEvaluator;
        assert!(eval.detect("cat <<<hello").iter().any(|d| d.detection_type == "cmd_here_string"));
        assert!(eval.detect("cat <<<world").iter().any(|d| d.detection_type == "cmd_here_string"));
        assert!(!eval.detect("echo hello").iter().any(|d| d.detection_type == "cmd_here_string"));
    }

    #[test]
    fn test_cmd_glob_expansion() {
        let eval = CmdInjectionEvaluator;
        assert!(eval.detect("ls /*").iter().any(|d| d.detection_type == "cmd_glob_expansion"));
        assert!(eval.detect("ls /?").iter().any(|d| d.detection_type == "cmd_glob_expansion"));
        assert!(!eval.detect("echo hello").iter().any(|d| d.detection_type == "cmd_glob_expansion"));
    }

    #[test]
    fn test_cmd_newline_injection() {
        let eval = CmdInjectionEvaluator;
        assert!(eval.detect("ls\\ncat").iter().any(|d| d.detection_type == "cmd_newline_injection"));
        assert!(eval.detect("ls%0acat").iter().any(|d| d.detection_type == "cmd_newline_injection"));
        assert!(!eval.detect("echo hello").iter().any(|d| d.detection_type == "cmd_newline_injection"));
    }
}"""

# Find the last closing brace and replace it
last_brace_idx = content.rfind("}")
if last_brace_idx != -1:
    content = content[:last_brace_idx] + tests_to_add + content[last_brace_idx+1:]

with open("packages/engine-rs/src/evaluators/cmd.rs", "w") as f:
    f.write(content)
