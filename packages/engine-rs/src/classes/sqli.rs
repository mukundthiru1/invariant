use regex::Regex;
use std::sync::LazyLock;

use crate::classes::{ClassDefinition, decode};
use crate::types::InvariantClass;

static SQL_KEYWORDS_AFTER_TERMINATOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)['\"`]\s*\)?\s*(?:;|\bOR\b\s+(?:\d|['"`(]|\S+\s*[=<>!]|NULL\b|TRUE\b|FALSE\b|NOT\b)|\bAND\b\s+(?:\d|['"`(]|\S+\s*[=<>!]|NULL\b|TRUE\b|FALSE\b|NOT\b)|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bEXEC\b)"#).unwrap()
});
static TAUTOLOGY_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)['"`()\s]\s*(?:OR|\|\|)\s*(?:\(?['"`]?\w*['"`]?\)?\s*(?:=|LIKE|IS)\s*\(?['"`]?\w*['"`]?\)?|\d+\s*[><= ]+\s*\d+|TRUE|NOT\s+FALSE|NOT\s+0|1\b)"#).unwrap()
});
static UNION_EXTRACTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)UNION\s+(?:ALL\s+)?SELECT\s").unwrap());
static STACKED_EXEC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i);\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC|EXECUTE|GRANT|REVOKE|SHUTDOWN|TRUNCATE)\s+").unwrap());
static TIME_ORACLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|PG_SLEEP\s*\(|DBMS_PIPE\.RECEIVE_MESSAGE)").unwrap());
static ERROR_ORACLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:EXTRACTVALUE|UPDATEXML|XMLTYPE|CONVERT\s*\(.*USING|EXP\s*\(\s*~|POLYGON\s*\(|GTID_SUBSET|FLOOR\s*\(\s*RAND|GROUP\s+BY\s+.*FLOOR)").unwrap());
static COMMENT_SYNTAX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/\*|--\s|--$|#").unwrap());
static SQL_KEYWORDS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|DROP|TABLE|DATABASE|EXEC|INTO|CREATE|ALTER|GRANT|REVOKE)\b").unwrap());
static TERMINATE_COMMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"['"`]\s*(?:--|#|/\*)"#).unwrap());

static JSON_FUNC_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:json_contains|json_overlaps|json_contains_path|jsonb_exists|jsonb_exists_any|jsonb_exists_all|json_valid|json_type|isjson|json_extract|json_value|json_unquote|json_length|json_depth|json_keys|json_search|json_extract_path|json_extract_path_text|jsonb_extract_path|jsonb_extract_path_text|json_array_length|json_query|openjson)\s*\(").unwrap());
static PG_JSON_OP_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:::jsonb?|->>{0,1}|#>{1,2}|@>|<@|\?\||\?&)").unwrap());
static JSON_LITERAL_IN_SQL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"['\"]?\{[^}]*\}['\"]?\s*(?:::jsonb?|->|,\s*'?\$)"#).unwrap());
static COND_CTX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:OR|AND|WHERE|HAVING)\s+").unwrap());
static SQL_CMP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:=|<>|!=|IS\s|LIKE|IN\s*\()").unwrap());
static FUNC_CMP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\)\s*(?:=|!=|<>|>|<|>=|<=|IS|LIKE|IN)\s").unwrap());

fn sql_string_termination(input: &str) -> bool {
    SQL_KEYWORDS_AFTER_TERMINATOR.is_match(&decode(input))
}
fn sql_tautology(input: &str) -> bool {
    TAUTOLOGY_PATTERN.is_match(&decode(input))
}
fn sql_union_extraction(input: &str) -> bool {
    UNION_EXTRACTION.is_match(&decode(input))
}
fn sql_stacked_execution(input: &str) -> bool {
    STACKED_EXEC.is_match(&decode(input))
}
fn sql_time_oracle(input: &str) -> bool {
    TIME_ORACLE.is_match(&decode(input))
}
fn sql_error_oracle(input: &str) -> bool {
    ERROR_ORACLE.is_match(&decode(input))
}
fn sql_comment_truncation(input: &str) -> bool {
    let d = decode(input);
    let has_comment = COMMENT_SYNTAX.is_match(input) || COMMENT_SYNTAX.is_match(&d);
    has_comment && (SQL_KEYWORDS.is_match(&d) || TERMINATE_COMMENT.is_match(input))
}
fn json_sql_bypass(input: &str) -> bool {
    let d = decode(input);
    if !JSON_FUNC_PATTERN.is_match(&d) && !PG_JSON_OP_PATTERN.is_match(&d) {
        return false;
    }
    if COND_CTX.is_match(&d) && JSON_FUNC_PATTERN.is_match(&d) {
        return true;
    }
    if PG_JSON_OP_PATTERN.is_match(&d) && SQL_CMP.is_match(&d) {
        return true;
    }
    if JSON_LITERAL_IN_SQL.is_match(&d) && Regex::new(r"(?:=|@>|<@)").unwrap().is_match(&d) {
        return true;
    }
    JSON_FUNC_PATTERN.is_match(&d) && FUNC_CMP.is_match(&d)
}

pub const SQL_CLASSES: &[ClassDefinition] = &[
    ClassDefinition {
        id: InvariantClass::SqlStringTermination,
        description: "Break out of a SQL string literal context to inject arbitrary SQL",
        detect: sql_string_termination,
        known_payloads: &[
            "' OR 1=1--",
            "' AND 1=1--",
            "' UNION SELECT 1--",
            "'; DROP TABLE users--",
            "\" OR \"\"=\"",
            "') OR 1=1--",
        ],
        known_benign: &["it's fine", "O'Reilly Media", "don't stop", "he said 'hello'", "customer's order"],
        mitre: &["T1190"],
        cwe: Some("CWE-89"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::SqlTautology,
        description: "Boolean tautology to bypass WHERE clause authentication/authorization checks",
        detect: sql_tautology,
        known_payloads: &[
            "' OR 1=1--",
            "' OR 'a'='a'--",
            "' OR 2>1--",
            "') OR ('x')=('x')",
            "' OR TRUE--",
            "\" OR \"\"=\"",
            "' OR 1 LIKE 1--",
            "' OR NOT FALSE--",
        ],
        known_benign: &[
            "O'Reilly Media",
            "it's a beautiful day",
            "SELECT * FROM users",
            "the score was 1 or more",
            "hello world",
            "John's pizza OR Jane's pasta",
        ],
        mitre: &["T1190"],
        cwe: Some("CWE-89"),
        formal_property: Some("∃ subexpr ∈ parse(input, SQL_GRAMMAR) : eval(subexpr, BOOLEAN_CONTEXT) ∈ {TRUE, TAUTOLOGY} ∧ context(subexpr) ∈ {CONDITIONAL, WHERE_CLAUSE, HAVING_CLAUSE}"),
        composable_with: &[
            InvariantClass::SqlUnionExtraction,
            InvariantClass::SqlStackedExecution,
            InvariantClass::SqlErrorOracle,
        ],
    },
    ClassDefinition {
        id: InvariantClass::SqlUnionExtraction,
        description: "UNION SELECT to extract data from other tables/columns",
        detect: sql_union_extraction,
        known_payloads: &[
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT 1,@@version,3--",
            "\" UNION SELECT 1,2,3--",
        ],
        known_benign: &[
            "SELECT name FROM users",
            "please select one option",
            "union of workers",
            "SELECT UNION label",
            "trade union agreement",
        ],
        mitre: &["T1190", "T1005"],
        cwe: Some("CWE-89"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::SqlStackedExecution,
        description: "Semicolon to terminate current query and execute arbitrary SQL statements",
        detect: sql_stacked_execution,
        known_payloads: &[
            "'; DROP TABLE users--",
            "'; DELETE FROM sessions--",
            "'; INSERT INTO admins VALUES('hack','hack')--",
            "'; UPDATE users SET role='admin' WHERE id=1--",
            "'; EXEC xp_cmdshell 'whoami'--",
            "; TRUNCATE TABLE audit_log--",
        ],
        known_benign: &["hello; world", "item; description; price", "a; b; c", "font-size: 12px; color: red;", "1; 2; 3"],
        mitre: &["T1190"],
        cwe: Some("CWE-89"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::SqlTimeOracle,
        description: "Time-based blind SQL injection using sleep/delay functions as oracle",
        detect: sql_time_oracle,
        known_payloads: &[
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND BENCHMARK(10000000,SHA1('test'))--",
            "' AND (SELECT pg_sleep(5))--",
            "' OR IF(1=1,SLEEP(5),0)--",
        ],
        known_benign: &["please wait for delay", "sleep mode enabled", "benchmark results", "I need to sleep", "pg_dump output"],
        mitre: &["T1190"],
        cwe: Some("CWE-89"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::SqlErrorOracle,
        description: "Error-based SQL injection using database error messages to extract data",
        detect: sql_error_oracle,
        known_payloads: &[
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
            "' AND EXP(~(SELECT * FROM (SELECT user())x))--",
            "' AND POLYGON((SELECT * FROM (SELECT @@version)f))--",
        ],
        known_benign: &["extract value from field", "update xml document", "polygon shape data", "floor plan design", "concat strings together"],
        mitre: &["T1190"],
        cwe: Some("CWE-89"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::SqlCommentTruncation,
        description: "SQL comment syntax to truncate the remainder of a query",
        detect: sql_comment_truncation,
        known_payloads: &["admin'--", "admin'#", "admin'/*", "' OR 1=1-- comment", "' UNION/**/SELECT/**/1,2,3--"],
        known_benign: &["hello world", "it's a test", "price is $5.00", "C++ programming", "color: #ff0000"],
        mitre: &["T1190"],
        cwe: Some("CWE-89"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::JsonSqlBypass,
        description: "JSON-in-SQL WAF bypass — uses database JSON operators to construct tautologies invisible to standard SQL parsers",
        detect: json_sql_bypass,
        known_payloads: &[
            "' OR JSON_EXTRACT('{\"a\":1}', '$.a') = 1 --",
            "' OR json_valid('{}') = 1 --",
            "' OR json_type('{\"a\":true}', '$.a') = 'true' --",
            "' UNION SELECT * FROM users WHERE 1=json_valid('{}') --",
            "' OR '{\"k\":\"v\"}'::jsonb @> '{\"k\":\"v\"}'::jsonb --",
            "' OR JSON_CONTAINS('{\"a\":1}', '1', '$.a') --",
            "' OR json_extract('{\"x\":1}','$.x')=1 OR '",
            "1' AND JSON_LENGTH('[1,2,3]') > 0 --",
        ],
        known_benign: &[
            "SELECT json_extract(data, \"$.name\") FROM users",
            "INSERT INTO logs VALUES (json_object(\"key\", \"value\"))",
            "{\"username\": \"admin\", \"password\": \"test\"}",
            "json_valid is a function",
            "postgres jsonb documentation",
            "/api/users?page=1&limit=20",
            "/products/category/electronics?sort=price",
            "/dashboard/analytics?from=2024-01-01&to=2024-12-31",
        ],
        mitre: &["T1190"],
        cwe: Some("CWE-89"),
        formal_property: Some("∃ subexpr ∈ parse(input, SQL_EXTENDED_GRAMMAR) : subexpr CONTAINS json_function(json_literal, json_path) ∧ context(subexpr) ∈ {CONDITIONAL, WHERE, HAVING, ON} → eval(subexpr) ∈ {TRUE, TAUTOLOGY}"),
        composable_with: &[
            InvariantClass::SqlTautology,
            InvariantClass::SqlUnionExtraction,
            InvariantClass::SqlStackedExecution,
        ],
    },
];
