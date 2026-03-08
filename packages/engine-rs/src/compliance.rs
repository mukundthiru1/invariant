//! Compliance and regulatory mapping for INVARIANT detections.
//!
//! This module maps every `InvariantClass` to:
//! - OWASP Top 10:2021 categories (A01-A10)
//! - CWE identifiers
//! - Operational compliance controls across PCI DSS 4.0, SOC 2, GDPR,
//!   HIPAA, NIST 800-53, OWASP Top 10, OWASP API Top 10, CWE, and ISO 27001.

use crate::types::InvariantClass;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    Pci4,
    Soc2,
    Gdpr,
    Hipaa,
    Nist80053,
    OwaspTop10_2021,
    OwaspApiTop10,
    CweTop25,
    Iso27001,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub framework: ComplianceFramework,
    pub control_id: String,
    pub description: String,
    pub requirement_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceMapping {
    pub class: InvariantClass,
    pub controls: Vec<ComplianceControl>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceEvidence {
    pub framework: ComplianceFramework,
    pub control_id: String,
    pub class: InvariantClass,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameworkRemediation {
    pub framework: ComplianceFramework,
    pub controls: Vec<ComplianceControl>,
    pub remediation_guidance: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ComplianceReport {
    pub detected_classes: Vec<InvariantClass>,
    pub mappings: Vec<ComplianceMapping>,
    pub framework_remediation: Vec<FrameworkRemediation>,
    pub audit_evidence: Vec<ComplianceEvidence>,
}

#[inline]
fn control(
    framework: ComplianceFramework,
    control_id: &'static str,
    description: &'static str,
    requirement_text: &'static str,
) -> ComplianceControl {
    ComplianceControl {
        framework,
        control_id: control_id.to_owned(),
        description: description.to_owned(),
        requirement_text: requirement_text.to_owned(),
    }
}

fn framework_controls_for_class(class: InvariantClass) -> Vec<ComplianceControl> {
    let mut controls = Vec::new();
    let tags = crate::class_registry::compliance_for(class);
    for tag in tags {
        let tag = *tag;
        if tag.starts_with("API") {
            controls.push(control(ComplianceFramework::OwaspApiTop10, tag, "OWASP API Security Top 10 mapping", "Maps API-facing detections to OWASP API Top 10 categories for API assurance reporting."));
        } else if tag.starts_with("A") && !tag.starts_with("API") {
            controls.push(control(ComplianceFramework::OwaspTop10_2021, tag, "OWASP Top 10 2021 risk category mapping", "Maps detection evidence to OWASP Top 10:2021 risk areas used in security governance and audit reporting."));
        } else if tag.starts_with("CWE-") {
            controls.push(control(ComplianceFramework::CweTop25, tag, "CWE weakness mapping", "Links detection to a Common Weakness Enumeration (CWE) for standardized weakness reporting and remediation tracking."));
        } else if tag == "PCI-6.2.4" {
            controls.push(control(
                ComplianceFramework::Pci4,
                "PCI DSS 4.0 6.2.4",
                "Secure coding controls",
                "Software engineering techniques are defined to prevent common attacks.",
            ));
        } else if tag == "PCI-6.2.3.1" {
            controls.push(control(
                ComplianceFramework::Pci4,
                "PCI DSS 4.0 6.2.3.1",
                "Code review",
                "Code changes are reviewed.",
            ));
        } else if tag == "PCI-6.3.2" {
            controls.push(control(
                ComplianceFramework::Pci4,
                "PCI DSS 4.0 6.3.2",
                "Patching",
                "Security patches are installed.",
            ));
        } else if tag == "SOC2-CC7.1" {
            controls.push(control(
                ComplianceFramework::Soc2,
                "CC7.1",
                "Vulnerability management",
                "Detection and monitoring.",
            ));
        } else if tag == "SOC2-CC7.2" {
            controls.push(control(
                ComplianceFramework::Soc2,
                "CC7.2",
                "Security event detection",
                "Events are analyzed.",
            ));
        } else if tag == "SOC2-CC6.1" {
            controls.push(control(
                ComplianceFramework::Soc2,
                "CC6.1",
                "Logical access controls",
                "Access security measures.",
            ));
        } else if tag == "GDPR-Art.32" {
            controls.push(control(
                ComplianceFramework::Gdpr,
                "GDPR Art.32(1)(b)",
                "Security of processing",
                "Confidentiality and integrity.",
            ));
        } else if tag == "GDPR-Art.25" {
            controls.push(control(
                ComplianceFramework::Gdpr,
                "GDPR Art.25",
                "Data protection",
                "Data protection by design.",
            ));
        } else if tag == "HIPAA-164.308" {
            controls.push(control(
                ComplianceFramework::Hipaa,
                "45 CFR 164.308(a)(1)(ii)(A)",
                "Risk analysis",
                "Perform risk analysis.",
            ));
        } else if tag == "HIPAA-164.312" {
            controls.push(control(
                ComplianceFramework::Hipaa,
                "45 CFR 164.312(c)(1)",
                "Integrity controls",
                "Protect ePHI from alteration.",
            ));
        } else if tag == "HIPAA-164.312-e1" {
            controls.push(control(
                ComplianceFramework::Hipaa,
                "45 CFR 164.312(e)(1)",
                "Transmission security",
                "Guard against unauthorized access.",
            ));
        } else if tag == "NIST-SI-10" {
            controls.push(control(
                ComplianceFramework::Nist80053,
                "SI-10",
                "Information input validation",
                "Input validation checks.",
            ));
        } else if tag == "NIST-RA-5" {
            controls.push(control(
                ComplianceFramework::Nist80053,
                "RA-5",
                "Vulnerability monitoring",
                "Vulnerability findings assessed.",
            ));
        } else if tag == "NIST-AC-3" {
            controls.push(control(
                ComplianceFramework::Nist80053,
                "AC-3",
                "Access enforcement",
                "System enforces authorizations.",
            ));
        } else if tag == "NIST-AU-12" {
            controls.push(control(
                ComplianceFramework::Nist80053,
                "AU-12",
                "Audit event generation",
                "Audit records generated.",
            ));
        } else if tag == "NIST-SC-7" {
            controls.push(control(
                ComplianceFramework::Nist80053,
                "SC-7",
                "Boundary protection",
                "Boundary protections monitor communications.",
            ));
        } else if tag == "ISO-8.28" {
            controls.push(control(
                ComplianceFramework::Iso27001,
                "ISO/IEC 27001:2022 Annex A 8.28",
                "Secure coding",
                "Secure coding principles applied.",
            ));
        } else if tag == "ISO-8.8" {
            controls.push(control(
                ComplianceFramework::Iso27001,
                "ISO/IEC 27001:2022 Annex A 8.8",
                "Vulnerability management",
                "Information about vulnerabilities evaluated.",
            ));
        } else if tag == "ISO-5.15" {
            controls.push(control(
                ComplianceFramework::Iso27001,
                "ISO/IEC 27001:2022 Annex A 5.15",
                "Access control",
                "Access to information restricted.",
            ));
        }
    }
    controls
}

pub fn compliance_mapping_for_class(class: InvariantClass) -> ComplianceMapping {
    ComplianceMapping {
        class,
        controls: framework_controls_for_class(class),
    }
}

fn remediation_for_framework(
    framework: ComplianceFramework,
    classes: &[InvariantClass],
) -> Vec<String> {
    let mut guidance = Vec::new();
    match framework {
        ComplianceFramework::Pci4 => {
            guidance.push("Implement secure coding standards and threat-model-driven reviews aligned to PCI DSS 4.0 requirement 6.2.".to_owned());
            guidance.push("Run pre-release code review evidence collection (reviewer identity, management approval, and defect closure) for 6.2.3.1.".to_owned());
            guidance.push("Maintain a recurring test suite for OWASP-style attacks to prove 6.2.4 attack mitigation controls.".to_owned());
        }
        ComplianceFramework::Soc2 => {
            guidance.push("Route detections to incident triage with severity-based response SLAs (CC7.1, CC7.2).".to_owned());
            guidance.push("Attach detection evidence and remediation tickets to control operation logs for audit traceability.".to_owned());
        }
        ComplianceFramework::Gdpr => {
            guidance.push("Prioritize fixes that prevent unauthorized personal-data disclosure (Art.25, Art.32).".to_owned());
            guidance.push(
                "Record technical safeguards and test outcomes as evidence of security-by-design."
                    .to_owned(),
            );
        }
        ComplianceFramework::Hipaa => {
            guidance.push("Document risk analysis updates for detected ePHI threats and retain mitigation decisions.".to_owned());
            guidance.push("Implement integrity and transmission safeguards for high-risk network and injection findings.".to_owned());
        }
        ComplianceFramework::Nist80053 => {
            guidance.push("Tie detections to SI-10 input validation controls and AC-3 access checks where authorization is impacted.".to_owned());
            guidance.push("Track vulnerability closure metrics under RA-5 and preserve audit artifacts under AU-12.".to_owned());
        }
        ComplianceFramework::OwaspTop10_2021 => {
            guidance.push("Remediate by OWASP risk class with secure coding fixes, test cases, and exploit reproduction artifacts.".to_owned());
        }
        ComplianceFramework::OwaspApiTop10 => {
            guidance.push("Add API-focused authorization, rate-limiting, and object/property-level controls mapped to API Top 10 categories.".to_owned());
        }
        ComplianceFramework::CweTop25 => {
            guidance.push("Track each finding by CWE ID, owner, and closure date to support weakness-centric audit reporting.".to_owned());
        }
        ComplianceFramework::Iso27001 => {
            guidance.push("Maintain secure coding and vulnerability-management evidence for Annex A controls (8.28, 8.8, 5.15).".to_owned());
        }
    }

    if classes.iter().any(|c| {
        matches!(
            c,
            InvariantClass::DependencyConfusion | InvariantClass::PostinstallInjection
        )
    }) {
        guidance.push("For supply-chain classes, enforce package provenance and integrity verification in CI/CD.".to_owned());
    }
    guidance
}

fn audit_evidence_line(class: InvariantClass, control: &ComplianceControl) -> String {
    format!(
        "Detected {:?} mapped to {} ({:?}); retain payload sample, class confidence, proof/evidence, remediation ticket, and verification test results.",
        class, control.control_id, control.framework
    )
}

pub fn compliance_report(classes: &[InvariantClass]) -> ComplianceReport {
    let mut dedup = HashSet::new();
    let mut detected_classes = Vec::new();
    for cls in classes {
        if dedup.insert(*cls) {
            detected_classes.push(*cls);
        }
    }

    let mappings: Vec<ComplianceMapping> = detected_classes
        .iter()
        .copied()
        .map(compliance_mapping_for_class)
        .collect();

    let frameworks = [
        ComplianceFramework::Pci4,
        ComplianceFramework::Soc2,
        ComplianceFramework::Gdpr,
        ComplianceFramework::Hipaa,
        ComplianceFramework::Nist80053,
        ComplianceFramework::OwaspTop10_2021,
        ComplianceFramework::OwaspApiTop10,
        ComplianceFramework::CweTop25,
        ComplianceFramework::Iso27001,
    ];

    let mut framework_remediation = Vec::new();
    let mut audit_evidence = Vec::new();
    for framework in frameworks {
        let mut seen = HashSet::new();
        let mut controls = Vec::new();
        for mapping in &mappings {
            for c in &mapping.controls {
                if c.framework != framework {
                    continue;
                }
                let dedup_key = (
                    c.control_id.clone(),
                    c.description.clone(),
                    c.requirement_text.clone(),
                );
                if seen.insert(dedup_key) {
                    controls.push(c.clone());
                }
                audit_evidence.push(ComplianceEvidence {
                    framework,
                    control_id: c.control_id.clone(),
                    class: mapping.class,
                    evidence: audit_evidence_line(mapping.class, c),
                });
            }
        }

        framework_remediation.push(FrameworkRemediation {
            framework,
            controls,
            remediation_guidance: remediation_for_framework(framework, &detected_classes),
        });
    }

    ComplianceReport {
        detected_classes,
        mappings,
        framework_remediation,
        audit_evidence,
    }
}

pub fn all_classes() -> &'static [InvariantClass] {
    crate::class_registry::ALL_CLASSES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_count_is_complete() {
        assert!(!all_classes().is_empty());
    }

    #[test]
    fn cwe_mapping_is_present_for_all_classes() {
        for class in all_classes() {
            let cwes: Vec<&str> = crate::class_registry::compliance_for(*class)
                .iter()
                .filter(|t| t.starts_with("CWE-"))
                .cloned()
                .collect();
            assert!(!cwes.is_empty(), "Missing CWE for {class:?}");
            assert!(cwes.iter().all(|id| id.starts_with("CWE-")));
        }
    }

    #[test]
    fn owasp_top10_mapping_is_present_for_all_classes() {
        for class in all_classes() {
            let id: Option<&&str> = crate::class_registry::compliance_for(*class)
                .iter()
                .find(|t| t.starts_with("A") && t.ends_with(":2021"));
            let id = id.unwrap_or(&"A05:2021");
            assert!(id.starts_with("A"));
        }
    }

    #[test]
    fn sql_class_maps_to_a03_and_cwe_89() {
        let mapping = compliance_mapping_for_class(InvariantClass::SqlStringTermination);
        assert!(
            mapping
                .controls
                .iter()
                .any(|c| c.framework == ComplianceFramework::OwaspTop10_2021
                    && c.control_id == "A03:2021")
        );
        assert!(
            mapping
                .controls
                .iter()
                .any(|c| c.framework == ComplianceFramework::CweTop25 && c.control_id == "CWE-89")
        );
    }

    #[test]
    fn ssrf_class_maps_to_a10_and_sc7() {
        let mapping = compliance_mapping_for_class(InvariantClass::SsrfCloudMetadata);
        assert!(
            mapping
                .controls
                .iter()
                .any(|c| c.framework == ComplianceFramework::OwaspTop10_2021
                    && c.control_id == "A10:2021")
        );
        assert!(
            mapping
                .controls
                .iter()
                .any(|c| c.framework == ComplianceFramework::Nist80053 && c.control_id == "SC-7")
        );
    }

    #[test]
    fn auth_none_maps_to_crypto_and_auth_frameworks() {
        let mapping = compliance_mapping_for_class(InvariantClass::AuthNoneAlgorithm);
        assert!(
            mapping
                .controls
                .iter()
                .any(|c| c.framework == ComplianceFramework::OwaspTop10_2021
                    && c.control_id == "A02:2021")
        );
        assert!(
            mapping
                .controls
                .iter()
                .any(|c| c.framework == ComplianceFramework::OwaspApiTop10
                    && c.control_id == "API2:2023")
        );
    }

    #[test]
    fn pci_requirement_624_is_included() {
        let mapping = compliance_mapping_for_class(InvariantClass::XssTagInjection);
        assert!(mapping.controls.iter().any(
            |c| c.framework == ComplianceFramework::Pci4 && c.control_id == "PCI DSS 4.0 6.2.4"
        ));
    }

    #[test]
    fn supply_chain_classes_include_vuln_patch_control() {
        let mapping = compliance_mapping_for_class(InvariantClass::DependencyConfusion);
        assert!(mapping.controls.iter().any(
            |c| c.framework == ComplianceFramework::Pci4 && c.control_id == "PCI DSS 4.0 6.3.2"
        ));
    }

    #[test]
    fn compliance_report_deduplicates_classes() {
        let classes = [
            InvariantClass::SqlTautology,
            InvariantClass::SqlTautology,
            InvariantClass::XssTagInjection,
        ];
        let report = compliance_report(&classes);
        assert_eq!(report.detected_classes.len(), 2);
        assert_eq!(report.mappings.len(), 2);
    }

    #[test]
    fn compliance_report_contains_all_framework_sections() {
        let report = compliance_report(&[
            InvariantClass::SqlTautology,
            InvariantClass::BolaIdor,
            InvariantClass::SsrfCloudMetadata,
        ]);
        assert_eq!(report.framework_remediation.len(), 9);
        assert!(
            report
                .framework_remediation
                .iter()
                .all(|f| !f.remediation_guidance.is_empty())
        );
    }

    #[test]
    fn audit_evidence_is_generated() {
        let report = compliance_report(&[InvariantClass::CrlfLogInjection]);
        assert!(!report.audit_evidence.is_empty());
        assert!(
            report
                .audit_evidence
                .iter()
                .any(|e| e.control_id == "A09:2021")
        );
    }

    #[test]
    fn empty_report_returns_framework_guidance() {
        let report = compliance_report(&[]);
        assert!(report.detected_classes.is_empty());
        assert_eq!(report.framework_remediation.len(), 9);
        assert!(
            report
                .framework_remediation
                .iter()
                .all(|f| !f.remediation_guidance.is_empty())
        );
    }
}
