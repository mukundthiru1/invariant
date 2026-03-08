//! Incident Response Recommender
//!
//! Given detection results, generates specific, actionable containment
//! and remediation recommendations. Turns INVARIANT from a detection
//! system into an automated SOC analyst.
//!
//! Recommendation phases:
//!   1. CONTAIN — immediate actions to stop the attack
//!   2. INVESTIGATE — what to examine to understand scope
//!   3. REMEDIATE — code/config changes to fix root cause
//!   4. HARDEN — long-term improvements to prevent recurrence

use crate::chain::ChainMatch;
use crate::effect::ExploitEffect;
use crate::types::InvariantClass;
use std::collections::HashSet;

// ── Types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Urgency {
    Immediate,
    Within1h,
    Within24h,
    NextSprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActionCategory {
    Contain,
    Investigate,
    Remediate,
    Harden,
}

#[derive(Debug, Clone)]
pub struct IncidentRecommendation {
    pub id: String,
    pub urgency: Urgency,
    pub category: ActionCategory,
    pub action: String,
    pub rationale: String,
    pub steps: Vec<String>,
    pub triggered_by: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct ResponsePlan {
    pub severity: IncidentSeverity,
    pub recommendations: Vec<IncidentRecommendation>,
    pub summary: String,
    pub blast_radius: String,
    pub requires_human: bool,
    pub indicators_of_compromise: Vec<String>,
    pub timeline_reconstruction_steps: Vec<String>,
}

// ── Detection Context ─────────────────────────────────────────────

pub struct DetectionContext<'a> {
    pub classes: &'a [InvariantClass],
    pub severities: &'a [&'a str],
    pub effect: Option<&'a ExploitEffect>,
    pub chains: &'a [ChainMatch],
    pub method: &'a str,
    pub path: &'a str,
    pub source_hash: &'a str,
}

// ── Helpers ───────────────────────────────────────────────────────

fn has_sql(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| {
        matches!(
            c,
            InvariantClass::SqlTautology
                | InvariantClass::SqlStringTermination
                | InvariantClass::SqlUnionExtraction
                | InvariantClass::SqlStackedExecution
                | InvariantClass::SqlTimeOracle
                | InvariantClass::SqlErrorOracle
                | InvariantClass::SqlCommentTruncation
                | InvariantClass::JsonSqlBypass
        )
    })
}

fn has_cmd(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| {
        matches!(
            c,
            InvariantClass::CmdSeparator
                | InvariantClass::CmdSubstitution
                | InvariantClass::CmdArgumentInjection
        )
    })
}

fn has_xss(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| {
        matches!(
            c,
            InvariantClass::XssTagInjection
                | InvariantClass::XssAttributeEscape
                | InvariantClass::XssEventHandler
                | InvariantClass::XssProtocolHandler
                | InvariantClass::XssTemplateExpression
        )
    })
}

fn has_path(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| {
        matches!(
            c,
            InvariantClass::PathDotdotEscape
                | InvariantClass::PathEncodingBypass
                | InvariantClass::PathNullTerminate
                | InvariantClass::PathNormalizationBypass
        )
    })
}

fn has_ssrf(classes: &[InvariantClass]) -> bool {
    classes.iter().any(|c| {
        matches!(
            c,
            InvariantClass::SsrfInternalReach
                | InvariantClass::SsrfCloudMetadata
                | InvariantClass::SsrfProtocolSmuggle
        )
    })
}

fn collect_iocs(
    classes: &[InvariantClass],
    path: &str,
    source_hash: &str,
    chains: &[ChainMatch],
) -> Vec<String> {
    if classes.is_empty() && chains.is_empty() {
        return Vec::new();
    }

    let mut iocs: Vec<String> = classes.iter().map(|c| format!("class:{c:?}")).collect();
    iocs.push(format!("source:{source_hash}"));
    iocs.push(format!("path:{path}"));
    for chain in chains {
        iocs.push(format!(
            "chain:{}:{:.0}%",
            chain.chain_id,
            chain.completion * 100.0
        ));
        iocs.extend(
            chain
                .associated_sources
                .iter()
                .map(|s| format!("pivot_source:{s}")),
        );
    }
    iocs.sort_unstable();
    iocs.dedup();
    iocs
}

fn timeline_steps(severity: IncidentSeverity, chains: &[ChainMatch]) -> Vec<String> {
    let mut steps = vec![
        "Reconstruct event order by source_hash and UTC timestamp".to_owned(),
        "Map phase transitions (detect -> probe -> exploit -> exfil)".to_owned(),
        "Compare request fingerprints against all matching chain definitions".to_owned(),
    ];

    if severity >= IncidentSeverity::Critical || chains.iter().any(|c| c.completion >= 0.66) {
        steps.push("Pull surrounding telemetry: 60s before and 10m after".to_owned());
        steps.push(
            "Capture exact chain path + path+behavior transitions for each matched step".to_owned(),
        );
        steps.push("Correlate with infrastructure logs for same campaign window".to_owned());
    }
    steps
}

fn highest_severity(severities: &[&str]) -> IncidentSeverity {
    if severities.iter().any(|s| *s == "critical") {
        IncidentSeverity::Critical
    } else if severities.iter().any(|s| *s == "high") {
        IncidentSeverity::High
    } else if severities.iter().any(|s| *s == "medium") {
        IncidentSeverity::Medium
    } else {
        IncidentSeverity::Low
    }
}

// ── Plan Generator ────────────────────────────────────────────────

/// Generate a full incident response plan from detection results.
pub fn generate_response_plan(ctx: &DetectionContext) -> ResponsePlan {
    let mut recs: Vec<IncidentRecommendation> = Vec::new();
    let sev = highest_severity(ctx.severities);

    // ── Containment ──
    if !ctx.classes.is_empty() {
        recs.push(IncidentRecommendation {
            id: "contain_block_source".into(),
            urgency: if sev >= IncidentSeverity::Critical {
                Urgency::Immediate
            } else {
                Urgency::Within1h
            },
            category: ActionCategory::Contain,
            action: format!("Block source {} at WAF/load balancer", ctx.source_hash),
            rationale: "Prevent further exploitation attempts from this source".into(),
            steps: vec![
                format!("Add {} to IP denylist", ctx.source_hash),
                "If behind CDN: add to Cloudflare/AWS WAF IP block rule".into(),
                "Monitor for same behavioral fingerprint from different IPs".into(),
            ],
            triggered_by: format!("{:?}", ctx.classes.first().unwrap()),
        });
    }

    if has_sql(ctx.classes) {
        recs.push(IncidentRecommendation {
            id: "contain_db_audit".into(),
            urgency: Urgency::Immediate,
            category: ActionCategory::Contain,
            action: "Audit database for unauthorized access".into(),
            rationale: "SQL injection may have already extracted or modified data".into(),
            steps: vec![
                format!("Check query logs for {} endpoint in last 24h", ctx.path),
                "Look for queries returning unusually large result sets".into(),
                "Check for DROP, DELETE, UPDATE from non-application sources".into(),
            ],
            triggered_by: "sql_*".into(),
        });

        recs.push(IncidentRecommendation {
            id: "remediate_sql_parameterize".into(),
            urgency: Urgency::Within24h,
            category: ActionCategory::Remediate,
            action: format!("Fix SQL injection in {} {}", ctx.method, ctx.path),
            rationale: "Root cause is string concatenation in SQL queries".into(),
            steps: vec![
                format!("Locate query handler for {} {}", ctx.method, ctx.path),
                "Replace string concatenation with parameterized queries".into(),
                "Add input validation for expected parameter types".into(),
            ],
            triggered_by: "sql_*".into(),
        });
    }

    if has_cmd(ctx.classes) {
        recs.push(IncidentRecommendation {
            id: "contain_cmd_audit".into(),
            urgency: Urgency::Immediate,
            category: ActionCategory::Contain,
            action: "Check for active reverse shells or unauthorized processes".into(),
            rationale: "Command injection may have established persistent access".into(),
            steps: vec![
                "Run: netstat -tlnp | grep ESTABLISHED".into(),
                "Check crontab -l for all users (persistence via cron)".into(),
                "Check /tmp and /var/tmp for dropped files".into(),
            ],
            triggered_by: "cmd_*".into(),
        });

        recs.push(IncidentRecommendation {
            id: "remediate_cmd_eliminate".into(),
            urgency: Urgency::Within24h,
            category: ActionCategory::Remediate,
            action: format!(
                "Eliminate shell command execution in {} {}",
                ctx.method, ctx.path
            ),
            rationale: "Any code path that passes user input to a shell is fundamentally unsafe"
                .into(),
            steps: vec![
                "Replace shell execution with native library calls".into(),
                "If unavoidable: use execFile with argument arrays".into(),
                "Whitelist allowed commands and arguments".into(),
            ],
            triggered_by: "cmd_*".into(),
        });
    }

    if has_xss(ctx.classes) {
        recs.push(IncidentRecommendation {
            id: "contain_xss_csp".into(),
            urgency: Urgency::Within1h,
            category: ActionCategory::Contain,
            action: "Deploy strict Content-Security-Policy header".into(),
            rationale: "XSS injection detected — CSP prevents script execution even if stored"
                .into(),
            steps: vec![
                "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'".into(),
                "If stored XSS possible: scan database for injected HTML/script content".into(),
            ],
            triggered_by: "xss_*".into(),
        });

        recs.push(IncidentRecommendation {
            id: "remediate_xss_encode".into(),
            urgency: Urgency::Within24h,
            category: ActionCategory::Remediate,
            action: format!("Fix XSS vulnerability in {} {}", ctx.method, ctx.path),
            rationale: "User input is rendered in HTML without proper encoding".into(),
            steps: vec![
                "Apply context-aware output encoding".into(),
                "Enable auto-escaping globally in template engine".into(),
                "Never use innerHTML/dangerouslySetInnerHTML with user data".into(),
            ],
            triggered_by: "xss_*".into(),
        });
    }

    if has_path(ctx.classes) {
        recs.push(IncidentRecommendation {
            id: "contain_path_audit".into(),
            urgency: Urgency::Within1h,
            category: ActionCategory::Contain,
            action: "Audit accessed files and check for sensitive data exposure".into(),
            rationale: "Path traversal may have read sensitive configuration or credential files"
                .into(),
            steps: vec![
                format!(
                    "Check access logs for {} — look for 200 responses with large bodies",
                    ctx.path
                ),
                "If .env, credentials, or key files readable: rotate all secrets".into(),
            ],
            triggered_by: "path_*".into(),
        });
    }

    if has_ssrf(ctx.classes) {
        recs.push(IncidentRecommendation {
            id: "contain_ssrf_metadata".into(),
            urgency: Urgency::Immediate,
            category: ActionCategory::Contain,
            action: "Rotate cloud IAM credentials if metadata service was accessed".into(),
            rationale: "SSRF to cloud metadata exposes temporary IAM credentials".into(),
            steps: vec![
                "AWS: Rotate IAM role credentials, check CloudTrail".into(),
                "GCP: Revoke service account tokens, check Audit Logs".into(),
                "Enable IMDSv2 to prevent future metadata access".into(),
            ],
            triggered_by: "ssrf_*".into(),
        });
    }

    // Chain-based escalation
    if !ctx.chains.is_empty() {
        let most_complete = ctx
            .chains
            .iter()
            .max_by(|a, b| a.completion.partial_cmp(&b.completion).unwrap())
            .unwrap();
        recs.push(IncidentRecommendation {
            id: "contain_chain_escalation".into(),
            urgency: Urgency::Immediate,
            category: ActionCategory::Contain,
            action: format!(
                "Active attack chain: {} ({}% complete)",
                most_complete.chain_id,
                (most_complete.completion * 100.0) as u32
            ),
            rationale: "Multi-step attack in progress — attacker advancing through kill chain"
                .into(),
            steps: vec![
                "Block the source IP/session immediately".into(),
                "Review all requests from this source in the last hour".into(),
                "Escalate to security team".into(),
            ],
            triggered_by: format!("chain:{}", most_complete.chain_id),
        });

        recs.push(IncidentRecommendation {
            id: "contain_temporary_automation".into(),
            urgency: Urgency::Immediate,
            category: ActionCategory::Contain,
            action: "Temporarily elevate enforcement for matched chain".into(),
            rationale: "Chain confidence and progression indicate active exploitation".into(),
            steps: vec![
                "Enable block mode for matching chain signatures for 30 minutes".into(),
                "If available, block suspicious egress destinations for source window".into(),
                "Invalidate sessions/refresh tokens observed in same browser context".into(),
            ],
            triggered_by: format!("chain:{}", most_complete.chain_id),
        });
    }

    if !ctx.classes.is_empty() || !ctx.chains.is_empty() {
        recs.push(IncidentRecommendation {
            id: "forensics_evidence_preservation".into(),
            urgency: Urgency::Immediate,
            category: ActionCategory::Contain,
            action: "Preserve evidence artifacts for chain reconstruction".into(),
            rationale: "Forensic continuity is often lost quickly due container log rotation and short retention".into(),
            steps: vec![
                format!("Capture and archive all traffic for {} for the last 15 minutes", ctx.source_hash),
                "Store raw request/response pairs, correlation IDs, and WAF decision records".into(),
                "Snapshot IAM session metadata and issued tokens for impacted accounts".into(),
            ],
            triggered_by: "detection".into(),
        });
    }

    // Investigation
    if !ctx.classes.is_empty() {
        recs.push(IncidentRecommendation {
            id: "investigate_source_history".into(),
            urgency: Urgency::Within1h,
            category: ActionCategory::Investigate,
            action: format!(
                "Review all requests from source {} in the last 24 hours",
                ctx.source_hash
            ),
            rationale: "Attack reconnaissance typically precedes exploitation".into(),
            steps: vec![
                format!("Grep access logs for source: {}", ctx.source_hash),
                "Plot request timeline — look for scanning patterns".into(),
            ],
            triggered_by: format!("{:?}", ctx.classes.first().unwrap()),
        });
    }

    // Hardening
    recs.push(IncidentRecommendation {
        id: "harden_edge_sensor".into(),
        urgency: Urgency::NextSprint,
        category: ActionCategory::Harden,
        action: "Deploy INVARIANT edge sensor for real-time blocking".into(),
        rationale: "Detection without prevention means attacks are logged but not stopped".into(),
        steps: vec![
            "Deploy CF Worker edge sensor".into(),
            "Start with monitor mode for tuning, then enforce".into(),
        ],
        triggered_by: "general".into(),
    });

    if ctx
        .severities
        .iter()
        .any(|s| *s == "critical" || *s == "high")
    {
        recs.push(IncidentRecommendation {
            id: "harden_input_validation".into(),
            urgency: Urgency::NextSprint,
            category: ActionCategory::Harden,
            action: "Add input shape validation at every entry point".into(),
            rationale: "Shape validation catches zero-day attacks by rejecting inputs that deviate from expected format".into(),
            steps: vec![
                "For each API parameter: validate shape before processing".into(),
                "Email → validateShape(input, Email)".into(),
                "Integer → validateShape(input, Integer)".into(),
            ],
            triggered_by: "general".into(),
        });
    }

    // Sort by urgency then category
    recs.sort_by(|a, b| {
        a.urgency
            .cmp(&b.urgency)
            .then_with(|| a.category.cmp(&b.category))
    });

    // Deduplicate by id
    let mut seen = HashSet::new();
    recs.retain(|r| seen.insert(r.id.clone()));

    // Blast radius
    let blast_radius = if ctx.chains.iter().any(|c| c.completion >= 0.8) {
        "CRITICAL — Active multi-stage attack near completion. Assume full compromise."
    } else if ctx.severities.iter().any(|s| *s == "critical") {
        "HIGH — Critical-severity vulnerability targeted. System-level access possible."
    } else if ctx.severities.iter().any(|s| *s == "high") {
        "MEDIUM — High-severity vulnerability targeted. Sensitive data exposure possible."
    } else {
        "LOW — Reconnaissance or low-severity probing. Limited immediate impact."
    };

    let summary = if ctx.classes.is_empty() {
        "No detections — no action required".to_string()
    } else {
        format!(
            "{} detection(s). Highest severity: {:?}.",
            ctx.classes.len(),
            sev
        )
    };

    ResponsePlan {
        severity: sev,
        recommendations: recs,
        summary,
        blast_radius: blast_radius.to_string(),
        indicators_of_compromise: collect_iocs(ctx.classes, ctx.path, ctx.source_hash, ctx.chains),
        timeline_reconstruction_steps: timeline_steps(sev, ctx.chains),
        requires_human: sev >= IncidentSeverity::Critical
            || ctx.chains.iter().any(|c| c.completion >= 0.66),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_injection_plan() {
        let ctx = DetectionContext {
            classes: &[InvariantClass::SqlUnionExtraction],
            severities: &["high"],
            effect: None,
            chains: &[],
            method: "POST",
            path: "/api/login",
            source_hash: "abc123",
        };
        let plan = generate_response_plan(&ctx);
        assert!(
            plan.recommendations
                .iter()
                .any(|r| r.id == "contain_db_audit")
        );
        assert!(
            plan.recommendations
                .iter()
                .any(|r| r.id == "remediate_sql_parameterize")
        );
        assert!(
            plan.indicators_of_compromise
                .iter()
                .any(|i| i.starts_with("class:SqlUnionExtraction"))
        );
        assert_eq!(plan.severity, IncidentSeverity::High);
    }

    #[test]
    fn cmd_injection_plan() {
        let ctx = DetectionContext {
            classes: &[InvariantClass::CmdSeparator],
            severities: &["critical"],
            effect: None,
            chains: &[],
            method: "GET",
            path: "/api/ping",
            source_hash: "def456",
        };
        let plan = generate_response_plan(&ctx);
        assert!(
            plan.recommendations
                .iter()
                .any(|r| r.id == "contain_cmd_audit")
        );
        assert!(
            plan.recommendations
                .iter()
                .any(|r| r.id == "remediate_cmd_eliminate")
        );
        assert_eq!(plan.severity, IncidentSeverity::Critical);
        assert!(plan.requires_human);
    }

    #[test]
    fn forensic_and_timeline_recommendations() {
        let chain = ChainMatch {
            chain_id: "sqli_data_exfil".into(),
            name: "test".into(),
            steps_matched: 2,
            total_steps: 3,
            completion: 0.67,
            confidence: 0.82,
            severity: crate::chain::ChainSeverity::Critical,
            description: "test".into(),
            recommended_action: crate::chain::RecommendedAction::Block,
            step_matches: vec![],
            duration_seconds: 42,
            associated_sources: vec!["src1".into(), "src2".into()],
            source_hash: "src1".into(),
        };

        let ctx = DetectionContext {
            classes: &[
                InvariantClass::SqlTautology,
                InvariantClass::SqlUnionExtraction,
            ],
            severities: &["critical", "high"],
            effect: None,
            chains: std::slice::from_ref(&chain),
            method: "GET",
            path: "/api/products",
            source_hash: "src1",
        };

        let plan = generate_response_plan(&ctx);
        assert!(
            plan.recommendations
                .iter()
                .any(|r| r.id == "contain_temporary_automation")
        );
        assert!(
            plan.recommendations
                .iter()
                .any(|r| r.id == "forensics_evidence_preservation")
        );
        assert!(
            plan.indicators_of_compromise
                .iter()
                .any(|i| i.contains("chain:sqli_data_exfil"))
        );
        assert!(plan.timeline_reconstruction_steps.len() >= 3);
    }

    #[test]
    fn empty_plan() {
        let ctx = DetectionContext {
            classes: &[],
            severities: &[],
            effect: None,
            chains: &[],
            method: "GET",
            path: "/",
            source_hash: "none",
        };
        let plan = generate_response_plan(&ctx);
        assert_eq!(plan.severity, IncidentSeverity::Low);
        assert!(plan.indicators_of_compromise.is_empty());
        // Should only have hardening recommendations
        assert!(
            plan.recommendations
                .iter()
                .all(|r| r.category == ActionCategory::Harden)
        );
    }

    #[test]
    fn recommendations_ordered() {
        let ctx = DetectionContext {
            classes: &[
                InvariantClass::SqlTautology,
                InvariantClass::XssTagInjection,
            ],
            severities: &["critical", "high"],
            effect: None,
            chains: &[],
            method: "POST",
            path: "/api/search",
            source_hash: "ghi789",
        };
        let plan = generate_response_plan(&ctx);
        // Verify ordering: immediate contain before investigation
        let contain_pos = plan
            .recommendations
            .iter()
            .position(|r| r.category == ActionCategory::Contain);
        let investigate_pos = plan
            .recommendations
            .iter()
            .position(|r| r.category == ActionCategory::Investigate);
        if let (Some(c), Some(i)) = (contain_pos, investigate_pos) {
            assert!(c < i, "containment should come before investigation");
        }
    }
}
