//! Runtime Application Self-Protection (RASP) instrumentation primitives.
//!
//! This module models application-layer runtime events and provides taint-based
//! confirmation of exploitability for key classes (SQLi, RCE, SSRF, path traversal).

use std::collections::HashSet;

use crate::types::{DetectionLevels, InvariantClass, InvariantMatch, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileOp {
    Read,
    Write,
    Create,
    Delete,
    Metadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemOp {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DatabaseQuery {
    pub query: String,
    pub params: Vec<String>,
    pub driver: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileAccess {
    pub path: String,
    pub operation: FileOp,
    pub flags: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProcessExec {
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkCall {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemoryAccess {
    pub address: u64,
    pub size: usize,
    pub operation: MemOp,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct RaspContext {
    pub db_queries: Vec<DatabaseQuery>,
    pub file_accesses: Vec<FileAccess>,
    pub process_execs: Vec<ProcessExec>,
    pub network_calls: Vec<NetworkCall>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RaspDetection {
    pub class: InvariantClass,
    pub severity: Severity,
    pub confidence: f64,
    pub sink: String,
    pub evidence: String,
    pub message: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintHop {
    pub component: String,
    pub detail: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSink {
    pub class: InvariantClass,
    pub sink: String,
    pub evidence: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintTrace {
    pub input: String,
    pub hops: Vec<TaintHop>,
    pub sinks: Vec<TaintSink>,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RaspFindings {
    pub detections: Vec<RaspDetection>,
    pub correlated_classes: Vec<InvariantClass>,
}

impl RaspContext {
    /// Correlate runtime events with known detection classes.
    pub fn analyze(&self) -> RaspFindings {
        let mut detections = Vec::new();

        for q in &self.db_queries {
            let ql = q.query.to_ascii_lowercase();
            if ql.contains(" union ") || ql.contains(" or 1=1") || ql.contains("--") {
                detections.push(RaspDetection {
                    class: infer_sql_class(&q.query),
                    severity: Severity::High,
                    confidence: 0.86,
                    sink: "database".to_owned(),
                    evidence: q.query.clone(),
                    message: "database query contains injection semantics".to_owned(),
                    timestamp: q.timestamp,
                });
            }
        }

        for exec in &self.process_execs {
            let cls = infer_cmd_class(exec);
            if cls.is_some() {
                detections.push(RaspDetection {
                    class: cls.unwrap_or(InvariantClass::CmdArgumentInjection),
                    severity: Severity::Critical,
                    confidence: 0.84,
                    sink: "process_exec".to_owned(),
                    evidence: format!("{} {}", exec.command, exec.args.join(" ")).trim().to_owned(),
                    message: "dangerous process execution pattern observed".to_owned(),
                    timestamp: exec.timestamp,
                });
            }
        }

        for call in &self.network_calls {
            let url_l = call.url.to_ascii_lowercase();
            if is_internal_destination(&url_l) || is_cloud_metadata_url(&url_l) {
                detections.push(RaspDetection {
                    class: if is_cloud_metadata_url(&url_l) {
                        InvariantClass::SsrfCloudMetadata
                    } else {
                        InvariantClass::SsrfInternalReach
                    },
                    severity: Severity::High,
                    confidence: 0.82,
                    sink: "network".to_owned(),
                    evidence: call.url.clone(),
                    message: "suspicious outbound destination observed".to_owned(),
                    timestamp: call.timestamp,
                });
            }
        }

        for file in &self.file_accesses {
            if is_outside_allowed_dirs(&file.path) {
                detections.push(RaspDetection {
                    class: InvariantClass::PathDotdotEscape,
                    severity: Severity::High,
                    confidence: 0.8,
                    sink: "filesystem".to_owned(),
                    evidence: file.path.clone(),
                    message: "file access outside allowed directories".to_owned(),
                    timestamp: file.timestamp,
                });
            }
        }

        let correlated_classes: Vec<InvariantClass> = detections
            .iter()
            .map(|d| d.class)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        RaspFindings {
            detections,
            correlated_classes,
        }
    }
}

pub fn detect_sqli_via_query_taint(input: &str, queries: &[DatabaseQuery]) -> Vec<RaspDetection> {
    if input.is_empty() {
        return Vec::new();
    }

    queries
        .iter()
        .filter_map(|q| {
            if contains_verbatim(&q.query, input) || q.params.iter().any(|p| contains_verbatim(p, input)) {
                Some(RaspDetection {
                    class: infer_sql_class(&q.query),
                    severity: Severity::Critical,
                    confidence: 0.99,
                    sink: "database".to_owned(),
                    evidence: q.query.clone(),
                    message: "confirmed SQLi: input tainted SQL sink".to_owned(),
                    timestamp: q.timestamp,
                })
            } else {
                None
            }
        })
        .collect()
}

pub fn detect_rce_via_exec_taint(input: &str, execs: &[ProcessExec]) -> Vec<RaspDetection> {
    if input.is_empty() {
        return Vec::new();
    }

    execs
        .iter()
        .filter_map(|exec| {
            let tainted = contains_verbatim(&exec.command, input)
                || exec.args.iter().any(|a| contains_verbatim(a, input))
                || exec.env.iter().any(|(_, v)| contains_verbatim(v, input));

            if tainted {
                let cls = infer_cmd_class(exec).unwrap_or(InvariantClass::CmdArgumentInjection);
                Some(RaspDetection {
                    class: cls,
                    severity: Severity::Critical,
                    confidence: 0.99,
                    sink: "process_exec".to_owned(),
                    evidence: format!("{} {}", exec.command, exec.args.join(" ")).trim().to_owned(),
                    message: "confirmed RCE: input tainted process execution".to_owned(),
                    timestamp: exec.timestamp,
                })
            } else {
                None
            }
        })
        .collect()
}

pub fn detect_ssrf_via_network_taint(input: &str, calls: &[NetworkCall]) -> Vec<RaspDetection> {
    if input.is_empty() {
        return Vec::new();
    }

    calls
        .iter()
        .filter_map(|call| {
            if contains_verbatim(&call.url, input) {
                let url_l = call.url.to_ascii_lowercase();
                let class = if is_cloud_metadata_url(&url_l) {
                    InvariantClass::SsrfCloudMetadata
                } else {
                    InvariantClass::SsrfInternalReach
                };

                Some(RaspDetection {
                    class,
                    severity: Severity::Critical,
                    confidence: 0.99,
                    sink: "network".to_owned(),
                    evidence: call.url.clone(),
                    message: "confirmed SSRF: input tainted network destination".to_owned(),
                    timestamp: call.timestamp,
                })
            } else {
                None
            }
        })
        .collect()
}

pub fn detect_path_traversal_via_file_taint(input: &str, accesses: &[FileAccess]) -> Vec<RaspDetection> {
    if input.is_empty() {
        return Vec::new();
    }

    accesses
        .iter()
        .filter_map(|file| {
            if contains_verbatim(&file.path, input) && is_outside_allowed_dirs(&file.path) {
                let class = if file.path.contains('%') {
                    InvariantClass::PathEncodingBypass
                } else {
                    InvariantClass::PathDotdotEscape
                };

                Some(RaspDetection {
                    class,
                    severity: Severity::Critical,
                    confidence: 0.99,
                    sink: "filesystem".to_owned(),
                    evidence: file.path.clone(),
                    message: "confirmed path traversal: input tainted sensitive file path".to_owned(),
                    timestamp: file.timestamp,
                })
            } else {
                None
            }
        })
        .collect()
}

pub fn trace_taint(input: &str, context: &RaspContext) -> TaintTrace {
    let mut hops = vec![TaintHop {
        component: "source".to_owned(),
        detail: "http_request_input".to_owned(),
        timestamp: 0,
    }];
    let mut sinks = Vec::new();

    for q in &context.db_queries {
        if contains_verbatim(&q.query, input) || q.params.iter().any(|p| contains_verbatim(p, input)) {
            hops.push(TaintHop {
                component: "database".to_owned(),
                detail: format!("driver={} query_taint", q.driver),
                timestamp: q.timestamp,
            });
            sinks.push(TaintSink {
                class: infer_sql_class(&q.query),
                sink: "database_query".to_owned(),
                evidence: q.query.clone(),
                timestamp: q.timestamp,
            });
        }
    }

    for exec in &context.process_execs {
        if contains_verbatim(&exec.command, input)
            || exec.args.iter().any(|a| contains_verbatim(a, input))
            || exec.env.iter().any(|(_, v)| contains_verbatim(v, input))
        {
            hops.push(TaintHop {
                component: "process".to_owned(),
                detail: "exec_taint".to_owned(),
                timestamp: exec.timestamp,
            });
            sinks.push(TaintSink {
                class: infer_cmd_class(exec).unwrap_or(InvariantClass::CmdArgumentInjection),
                sink: "process_exec".to_owned(),
                evidence: format!("{} {}", exec.command, exec.args.join(" ")).trim().to_owned(),
                timestamp: exec.timestamp,
            });
        }
    }

    for call in &context.network_calls {
        if contains_verbatim(&call.url, input) {
            hops.push(TaintHop {
                component: "network".to_owned(),
                detail: "destination_taint".to_owned(),
                timestamp: call.timestamp,
            });
            sinks.push(TaintSink {
                class: if is_cloud_metadata_url(&call.url.to_ascii_lowercase()) {
                    InvariantClass::SsrfCloudMetadata
                } else {
                    InvariantClass::SsrfInternalReach
                },
                sink: "network_call".to_owned(),
                evidence: call.url.clone(),
                timestamp: call.timestamp,
            });
        }
    }

    for file in &context.file_accesses {
        if contains_verbatim(&file.path, input) && is_outside_allowed_dirs(&file.path) {
            hops.push(TaintHop {
                component: "filesystem".to_owned(),
                detail: format!("{:?}", file.operation),
                timestamp: file.timestamp,
            });
            sinks.push(TaintSink {
                class: if file.path.contains('%') {
                    InvariantClass::PathEncodingBypass
                } else {
                    InvariantClass::PathDotdotEscape
                },
                sink: "file_access".to_owned(),
                evidence: file.path.clone(),
                timestamp: file.timestamp,
            });
        }
    }

    TaintTrace {
        input: input.to_owned(),
        hops,
        confirmed: !sinks.is_empty(),
        sinks,
    }
}

pub fn detections_to_matches(detections: &[RaspDetection]) -> Vec<InvariantMatch> {
    detections
        .iter()
        .map(|d| InvariantMatch {
            class: d.class,
            confidence: d.confidence,
            category: d.class.category(),
            severity: d.severity,
            is_novel_variant: true,
            description: format!("RASP confirmed: {}", d.message),
            detection_levels: DetectionLevels {
                l1: false,
                l2: false,
                convergent: false,
            },
            l2_evidence: Some(d.evidence.clone()),
            proof: None,
            cve_enrichment: None,
        })
        .collect()
}

fn contains_verbatim(haystack: &str, needle: &str) -> bool {
    !needle.is_empty() && haystack.contains(needle)
}

fn infer_sql_class(query: &str) -> InvariantClass {
    let q = query.to_ascii_lowercase();
    if q.contains(" union ") {
        InvariantClass::SqlUnionExtraction
    } else if q.contains(";") && (q.contains(" drop ") || q.contains(" insert ") || q.contains(" update ") || q.contains(" delete ")) {
        InvariantClass::SqlStackedExecution
    } else if q.contains(" or ") && (q.contains("=1") || q.contains(" true")) {
        InvariantClass::SqlTautology
    } else {
        InvariantClass::SqlStringTermination
    }
}

fn infer_cmd_class(exec: &ProcessExec) -> Option<InvariantClass> {
    let mut blob = exec.command.to_ascii_lowercase();
    if !exec.args.is_empty() {
        blob.push(' ');
        blob.push_str(&exec.args.join(" ").to_ascii_lowercase());
    }

    if ["$(", "`", "${"].iter().any(|t| blob.contains(t)) {
        return Some(InvariantClass::CmdSubstitution);
    }
    if [";", "&&", "||", "|"].iter().any(|t| blob.contains(t)) {
        return Some(InvariantClass::CmdSeparator);
    }
    if !exec.command.trim().is_empty() {
        return Some(InvariantClass::CmdArgumentInjection);
    }
    None
}

fn is_internal_destination(url_l: &str) -> bool {
    url_l.contains("127.0.0.1")
        || url_l.contains("localhost")
        || url_l.contains("0.0.0.0")
        || url_l.contains("10.")
        || url_l.contains("172.16.")
        || url_l.contains("172.17.")
        || url_l.contains("172.18.")
        || url_l.contains("172.19.")
        || url_l.contains("172.2")
        || url_l.contains("172.30.")
        || url_l.contains("172.31.")
        || url_l.contains("192.168.")
}

fn is_cloud_metadata_url(url_l: &str) -> bool {
    url_l.contains("169.254.169.254")
        || url_l.contains("metadata.google.internal")
        || url_l.contains("100.100.100.200")
}

fn is_outside_allowed_dirs(path: &str) -> bool {
    const ALLOWED_DIRS: [&str; 4] = ["/app", "/srv/app", "/var/www", "/tmp/uploads"];

    let normalized = path.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    if lower.contains("../") || lower.contains("..\\") || lower.ends_with("/..") || lower.contains("%2e%2e") {
        return true;
    }

    if lower.starts_with('/') {
        return !ALLOWED_DIRS.iter().any(|d| lower == *d || lower.starts_with(&format!("{d}/")));
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{DefenseAction, UnifiedRequest, UnifiedRuntime};
    use crate::types::AttackCategory;

    fn q(query: &str) -> DatabaseQuery {
        DatabaseQuery {
            query: query.to_owned(),
            params: Vec::new(),
            driver: "postgres".to_owned(),
            timestamp: 10,
        }
    }

    fn exec(command: &str, args: &[&str]) -> ProcessExec {
        ProcessExec {
            command: command.to_owned(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: Vec::new(),
            timestamp: 20,
        }
    }

    fn net(url: &str) -> NetworkCall {
        NetworkCall {
            url: url.to_owned(),
            method: "GET".to_owned(),
            headers: Vec::new(),
            timestamp: 30,
        }
    }

    fn file(path: &str) -> FileAccess {
        FileAccess {
            path: path.to_owned(),
            operation: FileOp::Read,
            flags: 0,
            timestamp: 40,
        }
    }

    #[test]
    fn detect_sqli_via_query_taint_positive() {
        let ds = detect_sqli_via_query_taint("' OR 1=1--", &[q("SELECT * FROM users WHERE name = '' OR 1=1--'")]);
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0].class, InvariantClass::SqlTautology);
    }

    #[test]
    fn detect_sqli_via_query_taint_negative() {
        let ds = detect_sqli_via_query_taint("alice", &[q("SELECT * FROM users WHERE id = $1")]);
        assert!(ds.is_empty());
    }

    #[test]
    fn detect_rce_via_exec_taint_command() {
        let ds = detect_rce_via_exec_taint("; cat /etc/passwd", &[exec("sh", &["-c", "id; cat /etc/passwd"])]);
        assert_eq!(ds.len(), 1);
        assert!(matches!(ds[0].class, InvariantClass::CmdSeparator | InvariantClass::CmdSubstitution));
    }

    #[test]
    fn detect_rce_via_exec_taint_env() {
        let ds = detect_rce_via_exec_taint(
            "evil_payload",
            &[ProcessExec {
                command: "worker".to_owned(),
                args: vec!["run".to_owned()],
                env: vec![("TASK".to_owned(), "evil_payload".to_owned())],
                timestamp: 20,
            }],
        );
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0].class, InvariantClass::CmdArgumentInjection);
    }

    #[test]
    fn detect_ssrf_via_network_taint_positive() {
        let ds = detect_ssrf_via_network_taint("169.254.169.254", &[net("http://169.254.169.254/latest/meta-data")]);
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0].class, InvariantClass::SsrfCloudMetadata);
    }

    #[test]
    fn detect_ssrf_via_network_taint_negative() {
        let ds = detect_ssrf_via_network_taint("token", &[net("https://example.com/profile")]);
        assert!(ds.is_empty());
    }

    #[test]
    fn detect_path_traversal_via_file_taint_positive() {
        let ds = detect_path_traversal_via_file_taint("../../etc/passwd", &[file("/etc/../../etc/passwd")]);
        assert_eq!(ds.len(), 1);
        assert_eq!(ds[0].class, InvariantClass::PathDotdotEscape);
    }

    #[test]
    fn detect_path_traversal_via_file_taint_negative_when_allowed_dir() {
        let ds = detect_path_traversal_via_file_taint("avatar.png", &[file("/app/uploads/avatar.png")]);
        assert!(ds.is_empty());
    }

    #[test]
    fn trace_taint_collects_multiple_sinks() {
        let ctx = RaspContext {
            db_queries: vec![q("SELECT * FROM users WHERE id = 'abc'")],
            file_accesses: vec![file("/etc/abc")],
            process_execs: vec![exec("sh", &["-c", "echo abc"] )],
            network_calls: vec![net("http://internal.service/abc")],
        };

        let trace = trace_taint("abc", &ctx);
        assert!(trace.confirmed);
        assert!(trace.sinks.len() >= 4);
    }

    #[test]
    fn analyze_correlates_runtime_events() {
        let ctx = RaspContext {
            db_queries: vec![q("SELECT * FROM t WHERE id='' OR 1=1--")],
            file_accesses: vec![file("/etc/passwd")],
            process_execs: vec![exec("sh", &["-c", "id; whoami"])],
            network_calls: vec![net("http://169.254.169.254/latest")],
        };

        let findings = ctx.analyze();
        assert!(findings.correlated_classes.contains(&InvariantClass::SqlTautology));
        assert!(findings.correlated_classes.contains(&InvariantClass::PathDotdotEscape));
        assert!(findings.correlated_classes.iter().any(|c| matches!(c, InvariantClass::CmdSeparator | InvariantClass::CmdArgumentInjection | InvariantClass::CmdSubstitution)));
        assert!(findings.correlated_classes.contains(&InvariantClass::SsrfCloudMetadata));
    }

    #[test]
    fn detections_to_matches_maps_core_fields() {
        let detections = vec![RaspDetection {
            class: InvariantClass::SqlTautology,
            severity: Severity::Critical,
            confidence: 0.99,
            sink: "database".to_owned(),
            evidence: "SELECT ...".to_owned(),
            message: "confirmed".to_owned(),
            timestamp: 1,
        }];
        let matches = detections_to_matches(&detections);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].category, AttackCategory::Sqli);
        assert_eq!(matches[0].severity, Severity::Critical);
    }

    #[test]
    fn runtime_process_uses_rasp_confirmation() {
        let mut rt = UnifiedRuntime::new();
        let req = UnifiedRequest {
            input: "../../etc/passwd".to_owned(),
            source_hash: "rasp-source".to_owned(),
            method: "GET".to_owned(),
            path: "/download".to_owned(),
            content_type: None,
            known_context: None,
            headers: Vec::new(),
            user_agent: None,
            ja3: None,
            source_reputation: None,
            detected_tech: None,
            param_name: None,
            rasp_context: Some(RaspContext {
                db_queries: Vec::new(),
                file_accesses: vec![FileAccess {
                    path: "/etc/../../etc/passwd".to_owned(),
                    operation: FileOp::Read,
                    flags: 0,
                    timestamp: 100,
                }],
                process_execs: Vec::new(),
                network_calls: Vec::new(),
            }),
            response_status: None,
            response_headers: None,
            response_body: None,
            recent_paths: Vec::new(),
            recent_intervals_ms: Vec::new(),
            timestamp: 100,
        };

        let resp = rt.process(&req);
        assert!(resp.analysis.matches.iter().any(|m| m.class == InvariantClass::PathDotdotEscape || m.class == InvariantClass::PathEncodingBypass));
        assert!(resp.decision.action >= DefenseAction::Block || resp.analysis.recommendation.block);
    }
}
