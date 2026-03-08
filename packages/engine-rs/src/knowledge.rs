//! Exploit Knowledge Graph
//!
//! The unified database that connects:
//!   CVE → Technology → Version → Invariant Properties → Defense Rules → Verification Plans
//!
//! This is not a CVE list. It is a structured graph where every exploit is mapped
//! to the invariant properties it relies on, enabling:
//!   1. Tech-stack-specific defense (only defend against relevant CVEs)
//!   2. Automatic rule generation from CVE data
//!   3. Exploit verification (confirm exploitability via probing)
//!   4. Mass defense propagation (one confirmation → all sensors defend)

use crate::types::InvariantClass;
use std::collections::{HashMap, HashSet};

// ── Types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TechCategory {
    Framework,
    Language,
    Server,
    Database,
    Cms,
    Library,
    Platform,
    Os,
}

#[derive(Debug, Clone)]
pub struct VersionRange {
    pub gte: Option<String>,
    pub lt: Option<String>,
    pub eq: Option<String>,
    pub fixed: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TechProduct {
    pub product: String,
    pub vendor: String,
    pub category: TechCategory,
    pub versions: Option<VersionRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExploitMaturity {
    Emerging,
    Public,
    Weaponized,
    Mature,
}

#[derive(Debug, Clone)]
pub struct ZeroDayHypothesis {
    pub invariant_class: InvariantClass,
    pub likelihood: f64,
    pub rationale: String,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityChainHypothesis {
    pub first_cve: String,
    pub second_cve: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationTechnique {
    BooleanDifferential,
    TimingOracle,
    ErrorElicitation,
    HeaderCheck,
    StatusDifferential,
    VersionFingerprint,
    ReflectionCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExploitSourceType {
    Nvd,
    Ghsa,
    Osv,
    CisaKev,
    Epss,
    Greynoise,
    ExploitDb,
    SanthArticle,
    SensorTelemetry,
}

// ── Knowledge Graph Entries ───────────────────────────────────────

/// Maps a CVE to the invariant property it relies on.
#[derive(Debug, Clone)]
pub struct InvariantPropertyMapping {
    pub invariant_class: InvariantClass,
    pub usage: String,
    pub detection_confidence: f64,
    pub l2_detectable: bool,
    pub framework_hints: Vec<String>,
}

/// An auto-generated defense rule from CVE analysis.
#[derive(Debug, Clone)]
pub struct DefenseRule {
    pub rule_id: String,
    pub description: String,
    pub match_condition: String,
    pub severity: RuleSeverity,
    pub confidence: f64,
    pub applies_to: Vec<String>,
    pub verified: bool,
}

/// A step in the exploit verification plan.
#[derive(Debug, Clone)]
pub struct VerificationStep {
    pub order: u32,
    pub technique: VerificationTechnique,
    pub probe: String,
    pub expected_signal: String,
    pub confirms: String,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ExploitSource {
    pub source_type: ExploitSourceType,
    pub url: Option<String>,
    pub last_checked: u64,
}

/// A node in the exploit knowledge graph.
#[derive(Debug, Clone)]
pub struct ExploitKnowledgeEntry {
    pub cve_id: String,
    pub title: String,
    pub affected: Vec<TechProduct>,
    pub cwes: Vec<String>,
    pub vector: AttackVector,
    pub cvss_score: f64,
    pub epss_score: f64,
    pub actively_exploited: bool,
    pub poc_available: bool,
    pub invariant_properties: Vec<InvariantPropertyMapping>,
    pub defense_rules: Vec<DefenseRule>,
    pub verification_plan: Vec<VerificationStep>,
    pub sources: Vec<ExploitSource>,
    pub last_updated: u64,
    pub santh_article_id: Option<String>,
}

impl ExploitKnowledgeEntry {
    pub fn exploit_maturity(&self) -> ExploitMaturity {
        if self.poc_available && self.actively_exploited && self.epss_score >= 0.7 {
            ExploitMaturity::Mature
        } else if self.actively_exploited && self.epss_score >= 0.3 {
            ExploitMaturity::Weaponized
        } else if self.actively_exploited || self.poc_available {
            ExploitMaturity::Public
        } else {
            ExploitMaturity::Emerging
        }
    }
}

// ── Framework Profiles ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMethod {
    Get,
    Post,
    Put,
    Delete,
}

#[derive(Debug, Clone)]
pub struct FrameworkProbe {
    pub description: String,
    pub method: ProbeMethod,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub expected_findings: Vec<String>,
}

/// A defense profile tailored to a specific technology stack.
#[derive(Debug, Clone)]
pub struct FrameworkProfile {
    pub framework: String,
    pub versions: Option<VersionRange>,
    pub relevant_classes: Vec<InvariantClass>,
    pub sensitivity_overrides: Vec<(InvariantClass, f64)>,
    pub known_cves: Vec<String>,
    pub probe_payloads: Vec<FrameworkProbe>,
    pub false_positive_exclusions: Vec<String>,
}

// ── Built-in Framework Profiles ───────────────────────────────────

pub fn builtin_framework_profiles() -> Vec<FrameworkProfile> {
    vec![
        FrameworkProfile {
            framework: "wordpress".into(),
            versions: None,
            relevant_classes: vec![
                InvariantClass::SqlStringTermination, InvariantClass::SqlTautology,
                InvariantClass::SqlUnionExtraction,
                InvariantClass::XssTagInjection, InvariantClass::XssEventHandler,
                InvariantClass::XssProtocolHandler,
                InvariantClass::PathDotdotEscape, InvariantClass::PathEncodingBypass,
                InvariantClass::DeserPhpObject,
                InvariantClass::AuthNoneAlgorithm, InvariantClass::AuthHeaderSpoof,
                InvariantClass::XxeEntityExpansion,
            ],
            sensitivity_overrides: vec![
                (InvariantClass::SqlStringTermination, 0.9),
                (InvariantClass::DeserPhpObject, 0.95),
                (InvariantClass::XxeEntityExpansion, 0.9),
            ],
            known_cves: vec![
                "CVE-2024-2961".into(),
                "CVE-2023-32243".into(),
                "CVE-2023-2732".into(),
            ],
            probe_payloads: vec![
                FrameworkProbe {
                    description: "WordPress version detection".into(),
                    method: ProbeMethod::Get, path: "/readme.html".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["wordpress_version".into()],
                },
                FrameworkProbe {
                    description: "XML-RPC availability".into(),
                    method: ProbeMethod::Post, path: "/xmlrpc.php".into(),
                    headers: vec![], body: Some("<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>".into()),
                    expected_findings: vec!["xmlrpc_enabled".into()],
                },
                FrameworkProbe {
                    description: "REST API user enumeration".into(),
                    method: ProbeMethod::Get, path: "/wp-json/wp/v2/users".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["user_enumeration".into()],
                },
                FrameworkProbe {
                    description: "Debug log exposure".into(),
                    method: ProbeMethod::Get, path: "/wp-content/debug.log".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["debug_log_exposed".into()],
                },
            ],
            false_positive_exclusions: vec![],
        },

        FrameworkProfile {
            framework: "laravel".into(),
            versions: None,
            relevant_classes: vec![
                InvariantClass::SqlStringTermination, InvariantClass::SqlTautology,
                InvariantClass::SqlUnionExtraction, InvariantClass::SqlStackedExecution,
                InvariantClass::SqlTimeOracle,
                InvariantClass::XssTagInjection, InvariantClass::XssTemplateExpression,
                InvariantClass::CmdSeparator, InvariantClass::CmdSubstitution,
                InvariantClass::SstiJinjaTwig,
                InvariantClass::DeserPhpObject,
                InvariantClass::MassAssignment,
            ],
            sensitivity_overrides: vec![
                (InvariantClass::DeserPhpObject, 0.95),
                (InvariantClass::MassAssignment, 0.9),
                (InvariantClass::SstiJinjaTwig, 0.85),
            ],
            known_cves: vec![
                "CVE-2021-3129".into(),
                "CVE-2022-40127".into(),
            ],
            probe_payloads: vec![
                FrameworkProbe {
                    description: "Laravel debug mode detection".into(),
                    method: ProbeMethod::Get, path: "/__clockwork".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["debug_mode_enabled".into()],
                },
                FrameworkProbe {
                    description: "Laravel Telescope exposure".into(),
                    method: ProbeMethod::Get, path: "/telescope".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["telescope_exposed".into()],
                },
                FrameworkProbe {
                    description: "Laravel .env exposure".into(),
                    method: ProbeMethod::Get, path: "/.env".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["env_file_exposed".into()],
                },
            ],
            false_positive_exclusions: vec![],
        },

        FrameworkProfile {
            framework: "django".into(),
            versions: None,
            relevant_classes: vec![
                InvariantClass::SqlStringTermination, InvariantClass::SqlTautology,
                InvariantClass::XssTagInjection, InvariantClass::XssTemplateExpression,
                InvariantClass::SstiJinjaTwig,
                InvariantClass::DeserPythonPickle,
                InvariantClass::PathDotdotEscape,
                InvariantClass::CmdSeparator,
            ],
            sensitivity_overrides: vec![
                (InvariantClass::DeserPythonPickle, 0.95),
                (InvariantClass::SstiJinjaTwig, 0.8),
            ],
            known_cves: vec![
                "CVE-2024-45231".into(),
                "CVE-2024-24680".into(),
            ],
            probe_payloads: vec![
                FrameworkProbe {
                    description: "Django debug page detection".into(),
                    method: ProbeMethod::Get, path: "/nonexistent-page-for-404".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["debug_mode_enabled".into()],
                },
                FrameworkProbe {
                    description: "Django admin exposure".into(),
                    method: ProbeMethod::Get, path: "/admin/".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["admin_panel_exposed".into()],
                },
            ],
            false_positive_exclusions: vec![],
        },

        FrameworkProfile {
            framework: "express".into(),
            versions: None,
            relevant_classes: vec![
                InvariantClass::XssTagInjection, InvariantClass::XssEventHandler,
                InvariantClass::XssTemplateExpression,
                InvariantClass::NosqlOperatorInjection, InvariantClass::NosqlJsInjection,
                InvariantClass::ProtoPollution,
                InvariantClass::SsrfInternalReach, InvariantClass::SsrfCloudMetadata,
                InvariantClass::CmdSeparator, InvariantClass::CmdSubstitution,
                InvariantClass::PathDotdotEscape, InvariantClass::PathNullTerminate,
            ],
            sensitivity_overrides: vec![
                (InvariantClass::ProtoPollution, 0.95),
                (InvariantClass::NosqlOperatorInjection, 0.9),
            ],
            known_cves: vec![
                "CVE-2024-29041".into(),
                "CVE-2022-24999".into(),
            ],
            probe_payloads: vec![
                FrameworkProbe {
                    description: "Express stack trace detection".into(),
                    method: ProbeMethod::Get, path: "/nonexistent".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["stack_trace_exposed".into()],
                },
            ],
            false_positive_exclusions: vec![],
        },

        FrameworkProfile {
            framework: "spring".into(),
            versions: None,
            relevant_classes: vec![
                InvariantClass::SqlStringTermination, InvariantClass::SqlTautology,
                InvariantClass::SqlUnionExtraction,
                InvariantClass::SstiElExpression,
                InvariantClass::DeserJavaGadget,
                InvariantClass::SsrfInternalReach,
                InvariantClass::CmdSeparator,
                InvariantClass::LogJndiLookup,
                InvariantClass::AuthHeaderSpoof,
            ],
            sensitivity_overrides: vec![
                (InvariantClass::DeserJavaGadget, 0.95),
                (InvariantClass::SstiElExpression, 0.95),
                (InvariantClass::LogJndiLookup, 0.95),
            ],
            known_cves: vec![
                "CVE-2022-22965".into(),
                "CVE-2022-22963".into(),
                "CVE-2021-44228".into(),
            ],
            probe_payloads: vec![
                FrameworkProbe {
                    description: "Spring Actuator exposure".into(),
                    method: ProbeMethod::Get, path: "/actuator".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["actuator_exposed".into()],
                },
                FrameworkProbe {
                    description: "Spring Actuator env".into(),
                    method: ProbeMethod::Get, path: "/actuator/env".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["env_exposed".into()],
                },
                FrameworkProbe {
                    description: "Spring Boot info".into(),
                    method: ProbeMethod::Get, path: "/actuator/info".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["version_info_exposed".into()],
                },
            ],
            false_positive_exclusions: vec![],
        },

        FrameworkProfile {
            framework: "nextjs".into(),
            versions: None,
            relevant_classes: vec![
                InvariantClass::XssTagInjection, InvariantClass::XssTemplateExpression,
                InvariantClass::SsrfInternalReach, InvariantClass::SsrfCloudMetadata,
                InvariantClass::AuthHeaderSpoof,
                InvariantClass::OpenRedirectBypass,
                InvariantClass::PathDotdotEscape,
            ],
            sensitivity_overrides: vec![
                (InvariantClass::AuthHeaderSpoof, 0.95),
            ],
            known_cves: vec![
                "CVE-2025-29927".into(),
                "CVE-2024-34351".into(),
            ],
            probe_payloads: vec![
                FrameworkProbe {
                    description: "Next.js middleware bypass".into(),
                    method: ProbeMethod::Get, path: "/".into(),
                    headers: vec![("x-middleware-subrequest".into(), "middleware".into())],
                    body: None,
                    expected_findings: vec!["middleware_bypass_vulnerable".into()],
                },
                FrameworkProbe {
                    description: "Next.js internal routes".into(),
                    method: ProbeMethod::Get, path: "/_next/data".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["internal_routes_exposed".into()],
                },
            ],
            false_positive_exclusions: vec![],
        },

        FrameworkProfile {
            framework: "rails".into(),
            versions: None,
            relevant_classes: vec![
                InvariantClass::SqlStringTermination, InvariantClass::SqlTautology,
                InvariantClass::SqlUnionExtraction,
                InvariantClass::XssTagInjection,
                InvariantClass::MassAssignment,
                InvariantClass::DeserJavaGadget, // YAML.load deserialization
                InvariantClass::SstiJinjaTwig,   // ERB templates
                InvariantClass::CmdSeparator,
                InvariantClass::PathDotdotEscape,
            ],
            sensitivity_overrides: vec![
                (InvariantClass::MassAssignment, 0.95),
            ],
            known_cves: vec![
                "CVE-2024-26143".into(),
                "CVE-2023-22795".into(),
            ],
            probe_payloads: vec![
                FrameworkProbe {
                    description: "Rails environment detection".into(),
                    method: ProbeMethod::Get, path: "/rails/info/properties".into(),
                    headers: vec![], body: None,
                    expected_findings: vec!["rails_info_exposed".into()],
                },
            ],
            false_positive_exclusions: vec![],
        },

        FrameworkProfile {
            framework: "flask".into(),
            versions: None,
            relevant_classes: vec![
                InvariantClass::SqlStringTermination, InvariantClass::SqlTautology,
                InvariantClass::SqlUnionExtraction,
                InvariantClass::DeserPythonPickle,
                InvariantClass::XssTagInjection,
                InvariantClass::XssTemplateExpression,
                InvariantClass::PathEncodingBypass,
                InvariantClass::AuthHeaderSpoof,
            ],
            sensitivity_overrides: vec![
                (InvariantClass::DeserPythonPickle, 0.95),
                (InvariantClass::AuthHeaderSpoof, 0.9),
            ],
            known_cves: vec![
                "CVE-2024-7346".into(),
                "CVE-2024-34044".into(),
            ],
            probe_payloads: vec![
                FrameworkProbe {
                    description: "Flask debug mode probe".into(),
                    method: ProbeMethod::Get,
                    path: "/console".into(),
                    headers: vec![],
                    body: None,
                    expected_findings: vec!["flask_debug_enabled".into()],
                },
                FrameworkProbe {
                    description: "Flask instance configuration".into(),
                    method: ProbeMethod::Get,
                    path: "/".into(),
                    headers: vec![],
                    body: None,
                    expected_findings: vec!["env_misconfig".into()],
                },
            ],
            false_positive_exclusions: vec![],
        },

        FrameworkProfile {
            framework: "fastapi".into(),
            versions: None,
            relevant_classes: vec![
                InvariantClass::SsrfInternalReach,
                InvariantClass::AuthNoneAlgorithm,
                InvariantClass::AuthHeaderSpoof,
                InvariantClass::DeserPythonPickle,
                InvariantClass::PathDotdotEscape,
                InvariantClass::CmdSeparator,
                InvariantClass::PathNormalizationBypass,
                InvariantClass::JwtJwkEmbedding,
            ],
            sensitivity_overrides: vec![
                (InvariantClass::AuthNoneAlgorithm, 0.9),
                (InvariantClass::DeserPythonPickle, 0.9),
            ],
            known_cves: vec![
                "CVE-2025-2975".into(),
                "CVE-2024-47875".into(),
            ],
            probe_payloads: vec![
                FrameworkProbe {
                    description: "OpenAPI schema exposure".into(),
                    method: ProbeMethod::Get,
                    path: "/openapi.json".into(),
                    headers: vec![],
                    body: None,
                    expected_findings: vec!["openapi_exposed".into()],
                },
                FrameworkProbe {
                    description: "Docs endpoint enumeration".into(),
                    method: ProbeMethod::Get,
                    path: "/docs".into(),
                    headers: vec![],
                    body: None,
                    expected_findings: vec!["docs_exposed".into()],
                },
            ],
            false_positive_exclusions: vec![],
        },
    ]
}

// ── Knowledge Graph Engine ────────────────────────────────────────

pub struct ExploitKnowledgeGraph {
    entries: HashMap<String, ExploitKnowledgeEntry>,
    profile_index: HashMap<String, FrameworkProfile>,
    tech_to_entries: HashMap<String, HashSet<String>>,
    class_to_entries: HashMap<InvariantClass, HashSet<String>>,
}

impl ExploitKnowledgeGraph {
    pub fn new() -> Self {
        let mut profile_index = HashMap::new();
        for profile in builtin_framework_profiles() {
            profile_index.insert(profile.framework.clone(), profile);
        }

        Self {
            entries: HashMap::new(),
            profile_index,
            tech_to_entries: HashMap::new(),
            class_to_entries: HashMap::new(),
        }
    }

    /// Add or update an exploit knowledge entry.
    pub fn add_entry(&mut self, entry: ExploitKnowledgeEntry) {
        // Index by technology
        for tech in &entry.affected {
            let key = format!("{}:{}", tech.vendor, tech.product);
            self.tech_to_entries.entry(key).or_default().insert(entry.cve_id.clone());
        }

        // Index by invariant class
        for prop in &entry.invariant_properties {
            self.class_to_entries.entry(prop.invariant_class).or_default().insert(entry.cve_id.clone());
        }

        self.entries.insert(entry.cve_id.clone(), entry);
    }

    /// Get all CVEs that affect a specific technology.
    pub fn get_cves_for_tech(&self, vendor: &str, product: &str) -> Vec<&ExploitKnowledgeEntry> {
        let key = format!("{vendor}:{product}");
        match self.tech_to_entries.get(&key) {
            Some(ids) => ids.iter().filter_map(|id| self.entries.get(id)).collect(),
            None => vec![],
        }
    }

    /// Get all CVEs that rely on a specific invariant property.
    pub fn get_cves_for_class(&self, class: InvariantClass) -> Vec<&ExploitKnowledgeEntry> {
        match self.class_to_entries.get(&class) {
            Some(ids) => ids.iter().filter_map(|id| self.entries.get(id)).collect(),
            None => vec![],
        }
    }

    /// Get the framework profile for a detected technology.
    pub fn get_framework_profile(&self, framework: &str) -> Option<&FrameworkProfile> {
        self.profile_index.get(&framework.to_lowercase())
    }

    /// Get all actively exploited CVEs for a specific tech stack.
    pub fn get_actively_exploited_for_tech(&self, vendor: &str, product: &str) -> Vec<&ExploitKnowledgeEntry> {
        self.get_cves_for_tech(vendor, product).into_iter()
            .filter(|e| e.actively_exploited)
            .collect()
    }

    /// Get all high-EPSS CVEs for a specific tech stack.
    pub fn get_high_epss_for_tech(&self, vendor: &str, product: &str, threshold: f64) -> Vec<&ExploitKnowledgeEntry> {
        self.get_cves_for_tech(vendor, product).into_iter()
            .filter(|e| e.epss_score >= threshold)
            .collect()
    }

    /// Get defense rules for a specific tech stack.
    pub fn get_defense_rules_for_tech(&self, vendor: &str, product: &str) -> Vec<&DefenseRule> {
        self.get_cves_for_tech(vendor, product).into_iter()
            .flat_map(|e| e.defense_rules.iter())
            .collect()
    }

    /// Enrich a detection with CVE context.
    pub fn enrich_detection(
        &self,
        invariant_class: InvariantClass,
        detected_tech: Option<(&str, &str)>,
    ) -> DetectionEnrichment {
        let mut entries = self.get_cves_for_class(invariant_class);

        if let Some((vendor, product)) = detected_tech {
            let tech_filtered: Vec<&ExploitKnowledgeEntry> = entries.iter()
                .filter(|e| e.affected.iter().any(|a| a.vendor == vendor && a.product == product))
                .copied()
                .collect();
            if !tech_filtered.is_empty() {
                entries = tech_filtered;
            }
        }

        DetectionEnrichment {
            linked_cves: entries.iter().map(|e| e.cve_id.clone()).collect(),
            linked_techniques: entries.iter()
                .flat_map(|e| e.cwes.iter().cloned())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect(),
            actively_exploited: entries.iter().any(|e| e.actively_exploited),
            highest_epss: entries.iter().map(|e| e.epss_score).fold(0.0_f64, f64::max),
            verification_available: entries.iter().any(|e| !e.verification_plan.is_empty()),
        }
    }

    pub fn assess_exploit_maturity(&self, cve_id: &str) -> Option<ExploitMaturity> {
        self.entries.get(cve_id).map(|entry| entry.exploit_maturity())
    }

    pub fn detect_zero_day_candidates(&self, classes: &[InvariantClass]) -> Vec<ZeroDayHypothesis> {
        let mut hypotheses = Vec::new();
        for class in classes {
            let entries = self.get_cves_for_class(*class);
            let known = entries.len() as f64;
            if known == 0.0 {
                hypotheses.push(ZeroDayHypothesis {
                    invariant_class: *class,
                    likelihood: 0.82,
                    rationale: "No known CVE currently linked to this invariant class".into(),
                });
            } else {
                let mature_count = entries.iter().filter(|e| e.exploit_maturity() >= ExploitMaturity::Weaponized).count();
                let active_count = entries.iter().filter(|e| e.actively_exploited).count();
                let signal = if known >= 3.0 {
                    0.2 + (active_count as f64 / known) * 0.25
                } else {
                    0.4 + (active_count as f64 / known) * 0.45 + (mature_count as f64 / known) * 0.2
                };
                if signal > 0.5 {
                    hypotheses.push(ZeroDayHypothesis {
                        invariant_class: *class,
                        likelihood: signal.min(0.95),
                        rationale: "Known CVEs exist, but threat coverage appears sparse for this observation".into(),
                    });
                }
            }
        }
        hypotheses
    }

    pub fn infer_vulnerability_chain(&self, vendor: &str, product: &str) -> Vec<VulnerabilityChainHypothesis> {
        let entries = self.get_cves_for_tech(vendor, product);
        let mut result = Vec::new();
        for i in 0..entries.len() {
            let first = &entries[i];
            let first_classes: HashSet<InvariantClass> = first.invariant_properties.iter().map(|p| p.invariant_class).collect();
            for j in i + 1..entries.len() {
                let second = &entries[j];
                let second_classes: HashSet<InvariantClass> = second.invariant_properties.iter().map(|p| p.invariant_class).collect();
                let overlap = first_classes.intersection(&second_classes).count();
                if overlap == 0 {
                    result.push(VulnerabilityChainHypothesis {
                        first_cve: first.cve_id.clone(),
                        second_cve: second.cve_id.clone(),
                        rationale: "Distinct invariant classes across CVEs suggests staged exploit chaining".into(),
                    });
                } else if first.actively_exploited && second.actively_exploited {
                    result.push(VulnerabilityChainHypothesis {
                        first_cve: first.cve_id.clone(),
                        second_cve: second.cve_id.clone(),
                        rationale: "Overlapping technique classes plus active status indicates possible lateral chain".into(),
                    });
                }
            }
        }
        result
    }

    /// Statistics.
    pub fn get_stats(&self) -> KnowledgeStats {
        let entries: Vec<&ExploitKnowledgeEntry> = self.entries.values().collect();
        KnowledgeStats {
            total_cves: entries.len(),
            actively_exploited: entries.iter().filter(|e| e.actively_exploited).count(),
            poc_available: entries.iter().filter(|e| e.poc_available).count(),
            with_verification_plan: entries.iter().filter(|e| !e.verification_plan.is_empty()).count(),
            covered_invariant_classes: self.class_to_entries.len(),
            framework_profiles: self.profile_index.len(),
            total_defense_rules: entries.iter().map(|e| e.defense_rules.len()).sum(),
        }
    }

    pub fn total_entries(&self) -> usize { self.entries.len() }
    pub fn total_technologies(&self) -> usize { self.tech_to_entries.len() }
    pub fn total_framework_profiles(&self) -> usize { self.profile_index.len() }
}

impl Default for ExploitKnowledgeGraph {
    fn default() -> Self { Self::new() }
}

// ── Result Types ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DetectionEnrichment {
    pub linked_cves: Vec<String>,
    pub linked_techniques: Vec<String>,
    pub actively_exploited: bool,
    pub highest_epss: f64,
    pub verification_available: bool,
}

#[derive(Debug, Clone)]
pub struct KnowledgeStats {
    pub total_cves: usize,
    pub actively_exploited: usize,
    pub poc_available: usize,
    pub with_verification_plan: usize,
    pub covered_invariant_classes: usize,
    pub framework_profiles: usize,
    pub total_defense_rules: usize,
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> ExploitKnowledgeEntry {
        ExploitKnowledgeEntry {
            cve_id: "CVE-2021-44228".into(),
            title: "Log4Shell".into(),
            affected: vec![TechProduct {
                product: "log4j".into(),
                vendor: "apache".into(),
                category: TechCategory::Library,
                versions: Some(VersionRange {
                    gte: Some("2.0".into()),
                    lt: Some("2.17.1".into()),
                    eq: None,
                    fixed: Some("2.17.1".into()),
                }),
            }],
            cwes: vec!["CWE-502".into(), "CWE-917".into()],
            vector: AttackVector::Network,
            cvss_score: 10.0,
            epss_score: 0.97,
            actively_exploited: true,
            poc_available: true,
            invariant_properties: vec![InvariantPropertyMapping {
                invariant_class: InvariantClass::LogJndiLookup,
                usage: "JNDI lookup via ${jndi:ldap://...}".into(),
                detection_confidence: 0.98,
                l2_detectable: true,
                framework_hints: vec!["Spring Boot".into()],
            }],
            defense_rules: vec![DefenseRule {
                rule_id: "log4shell-block".into(),
                description: "Block JNDI lookup patterns".into(),
                match_condition: "jndi:".into(),
                severity: RuleSeverity::Critical,
                confidence: 0.99,
                applies_to: vec!["apache:log4j".into()],
                verified: true,
            }],
            verification_plan: vec![VerificationStep {
                order: 1,
                technique: VerificationTechnique::ErrorElicitation,
                probe: "${jndi:ldap://canary.example.com/test}".into(),
                expected_signal: "DNS lookup to canary.example.com".into(),
                confirms: "JNDI lookup is processed".into(),
                timeout_ms: Some(5000),
            }],
            sources: vec![ExploitSource {
                source_type: ExploitSourceType::CisaKev,
                url: Some("https://nvd.nist.gov/vuln/detail/CVE-2021-44228".into()),
                last_checked: 1700000000,
            }],
            last_updated: 1700000000,
            santh_article_id: None,
        }
    }

    #[test]
    fn add_and_query_by_tech() {
        let mut kg = ExploitKnowledgeGraph::new();
        kg.add_entry(sample_entry());

        let results = kg.get_cves_for_tech("apache", "log4j");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cve_id, "CVE-2021-44228");
    }

    #[test]
    fn query_by_invariant_class() {
        let mut kg = ExploitKnowledgeGraph::new();
        kg.add_entry(sample_entry());

        let results = kg.get_cves_for_class(InvariantClass::LogJndiLookup);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn query_no_results() {
        let kg = ExploitKnowledgeGraph::new();
        assert!(kg.get_cves_for_tech("unknown", "product").is_empty());
        assert!(kg.get_cves_for_class(InvariantClass::SqlTautology).is_empty());
    }

    #[test]
    fn framework_profiles_loaded() {
        let kg = ExploitKnowledgeGraph::new();
        assert_eq!(kg.total_framework_profiles(), 9);

        let wp = kg.get_framework_profile("wordpress").unwrap();
        assert!(wp.relevant_classes.contains(&InvariantClass::SqlStringTermination));
        assert!(wp.relevant_classes.contains(&InvariantClass::DeserPhpObject));

        let spring = kg.get_framework_profile("spring").unwrap();
        assert!(spring.relevant_classes.contains(&InvariantClass::LogJndiLookup));
        assert!(spring.relevant_classes.contains(&InvariantClass::DeserJavaGadget));
    }

    #[test]
    fn flask_profile_loaded() {
        let kg = ExploitKnowledgeGraph::new();
        let flask = kg.get_framework_profile("Flask").unwrap();
        assert!(flask.relevant_classes.contains(&InvariantClass::DeserPythonPickle));
        assert!(flask.relevant_classes.contains(&InvariantClass::AuthHeaderSpoof));
    }

    #[test]
    fn exploit_maturity_assessment() {
        let mut kg = ExploitKnowledgeGraph::new();
        kg.add_entry(sample_entry());

        let maturity = kg.assess_exploit_maturity("CVE-2021-44228");
        assert_eq!(maturity, Some(ExploitMaturity::Mature));
    }

    #[test]
    fn zero_day_candidate_generation() {
        let mut kg = ExploitKnowledgeGraph::new();
        kg.add_entry(sample_entry());

        let hypos = kg.detect_zero_day_candidates(&[InvariantClass::LlmJailbreak]);
        assert_eq!(hypos.len(), 1);
        assert_eq!(hypos[0].invariant_class, InvariantClass::LlmJailbreak);
        assert!(hypos[0].likelihood > 0.5);
    }

    #[test]
    fn vulnerability_chain_inference() {
        let mut kg = ExploitKnowledgeGraph::new();
        let mut cve = sample_entry();
        cve.cve_id = "CVE-2024-9999".into();
        cve.invariant_properties.push(InvariantPropertyMapping {
            invariant_class: InvariantClass::DeserJavaGadget,
            usage: "alt".into(),
            detection_confidence: 0.82,
            l2_detectable: true,
            framework_hints: vec!["spring".into()],
        });
        kg.add_entry(sample_entry());
        kg.add_entry(cve);

        let chains = kg.infer_vulnerability_chain("apache", "log4j");
        assert!(!chains.is_empty());
    }

    #[test]
    fn case_insensitive_profile_lookup() {
        let kg = ExploitKnowledgeGraph::new();
        assert!(kg.get_framework_profile("WordPress").is_some());
        assert!(kg.get_framework_profile("DJANGO").is_some());
    }

    #[test]
    fn actively_exploited_filter() {
        let mut kg = ExploitKnowledgeGraph::new();
        kg.add_entry(sample_entry());

        let active = kg.get_actively_exploited_for_tech("apache", "log4j");
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn high_epss_filter() {
        let mut kg = ExploitKnowledgeGraph::new();
        kg.add_entry(sample_entry());

        let high = kg.get_high_epss_for_tech("apache", "log4j", 0.5);
        assert_eq!(high.len(), 1);

        let very_high = kg.get_high_epss_for_tech("apache", "log4j", 0.99);
        assert_eq!(very_high.len(), 0);
    }

    #[test]
    fn defense_rules_for_tech() {
        let mut kg = ExploitKnowledgeGraph::new();
        kg.add_entry(sample_entry());

        let rules = kg.get_defense_rules_for_tech("apache", "log4j");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_id, "log4shell-block");
    }

    #[test]
    fn enrich_detection_with_cve() {
        let mut kg = ExploitKnowledgeGraph::new();
        kg.add_entry(sample_entry());

        let enrichment = kg.enrich_detection(InvariantClass::LogJndiLookup, None);
        assert_eq!(enrichment.linked_cves, vec!["CVE-2021-44228"]);
        assert!(enrichment.actively_exploited);
        assert!(enrichment.highest_epss > 0.9);
        assert!(enrichment.verification_available);
    }

    #[test]
    fn enrich_with_tech_filter() {
        let mut kg = ExploitKnowledgeGraph::new();
        kg.add_entry(sample_entry());

        let enrichment = kg.enrich_detection(InvariantClass::LogJndiLookup, Some(("apache", "log4j")));
        assert_eq!(enrichment.linked_cves.len(), 1);

        let enrichment2 = kg.enrich_detection(InvariantClass::LogJndiLookup, Some(("unknown", "unknown")));
        // Falls back to all entries when tech filter yields nothing
        assert_eq!(enrichment2.linked_cves.len(), 1);
    }

    #[test]
    fn stats_correct() {
        let mut kg = ExploitKnowledgeGraph::new();
        kg.add_entry(sample_entry());

        let stats = kg.get_stats();
        assert_eq!(stats.total_cves, 1);
        assert_eq!(stats.actively_exploited, 1);
        assert_eq!(stats.poc_available, 1);
        assert_eq!(stats.with_verification_plan, 1);
        assert_eq!(stats.total_defense_rules, 1);
        assert_eq!(stats.framework_profiles, 9);
    }

    #[test]
    fn all_profiles_have_relevant_classes() {
        for profile in builtin_framework_profiles() {
            assert!(!profile.relevant_classes.is_empty(),
                "profile {} has no relevant classes", profile.framework);
            assert!(!profile.probe_payloads.is_empty(),
                "profile {} has no probe payloads", profile.framework);
        }
    }
}
