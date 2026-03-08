with open('src/compliance.rs', 'r') as f:
    text = f.read()

start_idx = text.find('const ALL_CLASSES')
end_idx = text.find('pub fn compliance_mapping_for_class')

if start_idx != -1 and end_idx != -1:
    text = text[:start_idx] + text[end_idx:]

controls_code = """
#[inline]
fn control(framework: ComplianceFramework, control_id: &'static str, description: &'static str, requirement_text: &'static str) -> ComplianceControl {
    ComplianceControl { framework, control_id: control_id.to_owned(), description: description.to_owned(), requirement_text: requirement_text.to_owned() }
}

fn framework_controls_for_class(class: InvariantClass) -> Vec<ComplianceControl> {
    let mut controls = Vec::new();
    let tags = crate::class_registry::compliance_for(class);
    for tag in tags {
        let tag = *tag;
        if tag.starts_with("A") {
            controls.push(control(ComplianceFramework::OwaspTop10_2021, tag, "OWASP Top 10 2021 risk category mapping", "Maps detection evidence to OWASP Top 10:2021 risk areas used in security governance and audit reporting."));
        } else if tag.starts_with("API") {
            controls.push(control(ComplianceFramework::OwaspApiTop10, tag, "OWASP API Security Top 10 mapping", "Maps API-facing detections to OWASP API Top 10 categories for API assurance reporting."));
        } else if tag.starts_with("CWE-") {
            controls.push(control(ComplianceFramework::CweTop25, tag, "CWE weakness mapping", "Links detection to a Common Weakness Enumeration (CWE) for standardized weakness reporting and remediation tracking."));
        } else if tag == "PCI-6.2.4" {
            controls.push(control(ComplianceFramework::Pci4, "PCI DSS 4.0 6.2.4", "Secure coding controls", "Software engineering techniques are defined to prevent common attacks."));
        } else if tag == "PCI-6.2.3.1" {
            controls.push(control(ComplianceFramework::Pci4, "PCI DSS 4.0 6.2.3.1", "Code review", "Code changes are reviewed."));
        } else if tag == "PCI-6.3.2" {
            controls.push(control(ComplianceFramework::Pci4, "PCI DSS 4.0 6.3.2", "Patching", "Security patches are installed."));
        } else if tag == "SOC2-CC7.1" {
            controls.push(control(ComplianceFramework::Soc2, "CC7.1", "Vulnerability management", "Detection and monitoring."));
        } else if tag == "SOC2-CC7.2" {
            controls.push(control(ComplianceFramework::Soc2, "CC7.2", "Security event detection", "Events are analyzed."));
        } else if tag == "SOC2-CC6.1" {
            controls.push(control(ComplianceFramework::Soc2, "CC6.1", "Logical access controls", "Access security measures."));
        } else if tag == "GDPR-Art.32" {
            controls.push(control(ComplianceFramework::Gdpr, "GDPR Art.32(1)(b)", "Security of processing", "Confidentiality and integrity."));
        } else if tag == "GDPR-Art.25" {
            controls.push(control(ComplianceFramework::Gdpr, "GDPR Art.25", "Data protection", "Data protection by design."));
        } else if tag == "HIPAA-164.308" {
            controls.push(control(ComplianceFramework::Hipaa, "45 CFR 164.308(a)(1)(ii)(A)", "Risk analysis", "Perform risk analysis."));
        } else if tag == "HIPAA-164.312" {
            controls.push(control(ComplianceFramework::Hipaa, "45 CFR 164.312(c)(1)", "Integrity controls", "Protect ePHI from alteration."));
        } else if tag == "HIPAA-164.312-e1" {
            controls.push(control(ComplianceFramework::Hipaa, "45 CFR 164.312(e)(1)", "Transmission security", "Guard against unauthorized access."));
        } else if tag == "NIST-SI-10" {
            controls.push(control(ComplianceFramework::Nist80053, "SI-10", "Information input validation", "Input validation checks."));
        } else if tag == "NIST-RA-5" {
            controls.push(control(ComplianceFramework::Nist80053, "RA-5", "Vulnerability monitoring", "Vulnerability findings assessed."));
        } else if tag == "NIST-AC-3" {
            controls.push(control(ComplianceFramework::Nist80053, "AC-3", "Access enforcement", "System enforces authorizations."));
        } else if tag == "NIST-AU-12" {
            controls.push(control(ComplianceFramework::Nist80053, "AU-12", "Audit event generation", "Audit records generated."));
        } else if tag == "NIST-SC-7" {
            controls.push(control(ComplianceFramework::Nist80053, "SC-7", "Boundary protection", "Boundary protections monitor communications."));
        } else if tag == "ISO-8.28" {
            controls.push(control(ComplianceFramework::Iso27001, "ISO/IEC 27001:2022 Annex A 8.28", "Secure coding", "Secure coding principles applied."));
        } else if tag == "ISO-8.8" {
            controls.push(control(ComplianceFramework::Iso27001, "ISO/IEC 27001:2022 Annex A 8.8", "Vulnerability management", "Information about vulnerabilities evaluated."));
        } else if tag == "ISO-5.15" {
            controls.push(control(ComplianceFramework::Iso27001, "ISO/IEC 27001:2022 Annex A 5.15", "Access control", "Access to information restricted."));
        }
    }
    controls
}

"""
text = text.replace('pub fn compliance_mapping_for_class(class: InvariantClass) -> ComplianceMapping {', controls_code + 'pub fn compliance_mapping_for_class(class: InvariantClass) -> ComplianceMapping {')

# Fix tests
text = text.replace('&ALL_CLASSES', 'crate::class_registry::ALL_CLASSES')

with open('src/compliance.rs', 'w') as f:
    f.write(text)

