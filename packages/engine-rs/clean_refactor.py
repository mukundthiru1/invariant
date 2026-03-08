import re
import os

with open('src/types.rs', 'r') as f:
    types_rs = f.read()

# 1. Parse InvariantClass variants
enum_match = re.search(r'pub enum InvariantClass \{(.*?)\}', types_rs, re.DOTALL)
variants = []
for line in enum_match.group(1).split('\n'):
    line = line.strip()
    if not line or line.startswith('//'):
        continue
    v = line.split(',')[0].strip()
    if v:
        variants.append(v)

# 2. Parse category
category_map = {}
cat_match = re.search(r'pub fn category\(self\) -> AttackCategory \{(.*?)\}', types_rs, re.DOTALL)
if cat_match:
    for m in re.finditer(r'(.*?)=>\s*(AttackCategory::\w+)', cat_match.group(1), re.DOTALL):
        keys = m.group(1).replace(' ', '').replace('\n', '')
        if keys.startswith('matchself{'): keys = keys[10:]
        for k in keys.split('|'):
            if k != '_': category_map[k] = m.group(2)
default_cat = "AttackCategory::Injection"

# 3. Parse default_severity
default_severity_map = {}
sev_match = re.search(r'pub fn default_severity\(self\) -> Severity \{(.*?)\}', types_rs, re.DOTALL)
if sev_match:
    for m in re.finditer(r'(.*?)=>\s*(Severity::\w+)', sev_match.group(1), re.DOTALL):
        keys = m.group(1).replace(' ', '').replace('\n', '')
        if keys.startswith('matchself{'): keys = keys[10:]
        for k in keys.split('|'):
            if k != '_': default_severity_map[k] = m.group(2)

# 4. Parse severity_weight
weight_map = {}
w_match = re.search(r'pub fn severity_weight\(self\) -> f64 \{(.*?)\}', types_rs, re.DOTALL)
if w_match:
    for m in re.finditer(r'([a-zA-Z0-9_]+)\s*=>\s*([\d\.]+)', w_match.group(1)):
        weight_map[m.group(1)] = float(m.group(2))

# 5. Parse mitre
with open('src/mitre.rs') as f:
    mitre_rs = f.read()

mitre_map = {}
mitre_match = re.search(r'static INVARIANT_MITRE_MAP.*?=\s*&(.*?);', mitre_rs, re.DOTALL)
if mitre_match:
    for block in re.finditer(r'ClassMapping\s*\{(.*?)\}', mitre_match.group(1), re.DOTALL):
        b = block.group(1)
        c_m = re.search(r'class:\s*InvariantClass::(\w+)', b)
        t_m = re.search(r'techniques:\s*&\[(.*?)\]', b)
        r_m = re.search(r'rationale:\s*"(.*?)"', b)
        if c_m and t_m and r_m:
            c = c_m.group(1)
            techs = [x.strip().replace('&', '') for x in t_m.group(1).split(',')]
            mitre_map[c] = { 'technique': techs[0], 'rationale': r_m.group(1) }

tactic_map = {}
for m in re.finditer(r'static (\w+): MitreTechnique = MitreTechnique \{.*?id:\s*"(.*?)".*?tactic:\s*(.*?),', mitre_rs, re.DOTALL):
    tactic_map[m.group(1)] = (m.group(2), m.group(3))

# 6. Parse compliance from compliance.rs
with open('src/compliance.rs', 'r') as f:
    comp_rs = f.read()

owasp2021_map = {}
m2021 = re.search(r'fn owasp_top10_2021_for_class.*?match class \{(.*?)\}', comp_rs, re.DOTALL)
if m2021:
    for m in re.finditer(r'(.*?)=>\s*"(.*?)"', m2021.group(1), re.DOTALL):
        keys = m.group(1).replace(' ', '').replace('\n', '').split('|')
        for k in keys:
            if k != '_': owasp2021_map[k] = m.group(2)

owasp_api_map = {}
mapi = re.search(r'fn owasp_api_top10_for_class.*?match class \{(.*?)\}', comp_rs, re.DOTALL)
if mapi:
    for m in re.finditer(r'(.*?)=>\s*"(.*?)"', mapi.group(1), re.DOTALL):
        keys = m.group(1).replace(' ', '').replace('\n', '').split('|')
        for k in keys:
            if k != '_': owasp_api_map[k] = m.group(2)

cwe_map = {}
mcwe = re.search(r'fn cwe_ids_for_class.*?match class \{(.*?)\}', comp_rs, re.DOTALL)
if mcwe:
    for m in re.finditer(r'(.*?)=>\s*&\[(.*?)\]', mcwe.group(1), re.DOTALL):
        keys = m.group(1).replace(' ', '').replace('\n', '').split('|')
        cwes = [x.strip().replace('"', '') for x in m.group(2).split(',')]
        for k in keys:
            if k != '_': cwe_map[k] = cwes

# 7. Generate class_registry.rs
out = []
for v in variants:
    cat = category_map.get(v, default_cat)
    def_sev = default_severity_map.get(v, "Severity::Medium")
    base_w = 0.55
    if def_sev == "Severity::Critical": base_w = 0.95
    elif def_sev == "Severity::High": base_w = 0.85
    elif def_sev == "Severity::Medium": base_w = 0.70
    weight = weight_map.get(v, base_w)
    
    mitre_entry = mitre_map.get(v, {'technique': 'T1190', 'rationale': 'Generic detection.'})
    tech_id_var = mitre_entry['technique']
    if tech_id_var in tactic_map:
        tech_str = f'"{tactic_map[tech_id_var][0]}"'
        tactic_str = "MitreTactic::" + tactic_map[tech_id_var][1]
    else:
        tech_str = '"T1190"'
        tactic_str = "MitreTactic::InitialAccess"
    desc = mitre_entry['rationale']
    
    tags = []
    if v in owasp2021_map: tags.append(f'"{owasp2021_map[v]}"')
    else: tags.append('"A05:2021"')
    
    if v in owasp_api_map: tags.append(f'"{owasp_api_map[v]}"')
    else: tags.append('"API8:2023"')
    
    if v in cwe_map:
        for c in cwe_map[v]: tags.append(f'"{c}"')
    else: tags.append('"CWE-20"')
    
    tags.extend(['"PCI-6.2.4"', '"PCI-6.2.3.1"', '"SOC2-CC7.1"', '"SOC2-CC7.2"', '"GDPR-Art.32"', '"HIPAA-164.308"', '"HIPAA-164.312"', '"NIST-SI-10"', '"NIST-RA-5"', '"ISO-8.28"', '"ISO-8.8"'])
    if v in ['DependencyConfusion', 'PostinstallInjection', 'LogJndiLookup']:
        tags.append('"PCI-6.3.2"')
    if v in ['BolaIdor', 'MassAssignment', 'AuthNoneAlgorithm', 'AuthHeaderSpoof']:
        tags.extend(['"SOC2-CC6.1"', '"NIST-AC-3"', '"ISO-5.15"'])
    if v in ['BolaIdor', 'ApiMassEnum', 'LlmDataExfiltration', 'EnvExfiltration']:
        tags.append('"GDPR-Art.25"')
    if v in ['SsrfInternalReach', 'SsrfCloudMetadata', 'SsrfProtocolSmuggle']:
        tags.append('"HIPAA-164.312-e1"')
    if v in ['CrlfLogInjection', 'CachePoisoning', 'CacheDeception']:
        tags.append('"NIST-AU-12"')
    if v in ['SsrfInternalReach', 'SsrfCloudMetadata', 'SsrfProtocolSmuggle']:
        tags.append('"NIST-SC-7"')
        
    tags_str = ", ".join(tags)
    
    out.append(f"""    ClassMetadata {{
        class: InvariantClass::{v},
        attack_category: {cat},
        severity_weight: {weight:.2f},
        mitre_technique: {tech_str},
        mitre_tactic: {tactic_str},
        compliance_tags: &[{tags_str}],
        description: "{desc}",
    }},""")

out_rust = f"""use crate::types::{{InvariantClass, AttackCategory}};
use crate::mitre::MitreTactic;

/// This registry centralizes metadata for all `InvariantClass` variants.
/// 
/// LAW 4 CONTRACT: Adding a new `InvariantClass` requires ONLY 4 touches:
/// 1. Add variant to enum in `types.rs`
/// 2. Add one `ClassMetadata` entry here in `class_registry.rs`
/// 3. Create one evaluator file
/// 4. Add one entry to `EVALUATORS` in `evaluators/mod.rs`
pub struct ClassMetadata {{
    pub class: InvariantClass,
    pub attack_category: AttackCategory,
    pub severity_weight: f64,
    pub mitre_technique: &'static str,
    pub mitre_tactic: MitreTactic,
    pub compliance_tags: &'static [&'static str],
    pub description: &'static str,
}}

pub static ALL_CLASS_METADATA: &[ClassMetadata] = &[
{chr(10).join(out)}
];

pub fn get_metadata(class: InvariantClass) -> &'static ClassMetadata {{
    ALL_CLASS_METADATA.iter().find(|m| m.class == class).unwrap_or_else(|| panic!("Missing metadata for {{class:?}}"))
}}

pub fn attack_category_for(class: InvariantClass) -> AttackCategory {{
    get_metadata(class).attack_category
}}

pub fn severity_for(class: InvariantClass) -> f64 {{
    get_metadata(class).severity_weight
}}

pub fn mitre_for(class: InvariantClass) -> (&'static str, MitreTactic) {{
    let m = get_metadata(class);
    (m.mitre_technique, m.mitre_tactic)
}}

pub fn compliance_for(class: InvariantClass) -> &'static [&'static str] {{
    get_metadata(class).compliance_tags
}}

#[cfg(test)]
mod tests {{
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_all_classes_mapped() {{
        assert_eq!(ALL_CLASS_METADATA.len(), InvariantClass::all_variants().len());
        for class in InvariantClass::all_variants() {{
            assert!(ALL_CLASS_METADATA.iter().any(|m| m.class == *class));
        }}
    }}

    #[test]
    fn test_no_duplicates() {{
        let mut seen = HashSet::new();
        for m in ALL_CLASS_METADATA {{
            assert!(seen.insert(m.class), "Duplicate entry for {{:?}}", m.class);
        }}
    }}

    #[test]
    fn test_severity_bounds() {{
        for m in ALL_CLASS_METADATA {{
            assert!(m.severity_weight >= 0.0 && m.severity_weight <= 1.0);
        }}
    }}

    #[test]
    fn test_mitre_not_empty() {{
        for m in ALL_CLASS_METADATA {{
            assert!(!m.mitre_technique.is_empty());
        }}
    }}
}}
"""

with open('src/class_registry.rs', 'w') as f:
    f.write(out_rust)


# 8. Refactor types.rs match arms to delegate!
types_rs = re.sub(
    r'    pub fn category\(self\) -> AttackCategory \{.*?\n    \}\n',
    '    pub fn category(self) -> AttackCategory {\n        crate::class_registry::attack_category_for(self)\n    }\n',
    types_rs,
    flags=re.DOTALL
)

types_rs = re.sub(
    r'    pub fn default_severity\(self\) -> Severity \{.*?\n    \}\n',
    """    pub fn default_severity(self) -> Severity {
        let w = self.severity_weight();
        if w >= 0.95 { Severity::Critical }
        else if w >= 0.85 { Severity::High }
        else if w >= 0.70 { Severity::Medium }
        else { Severity::Low }
    }
""",
    types_rs,
    flags=re.DOTALL
)

types_rs = re.sub(
    r'    pub fn severity_weight\(self\) -> f64 \{.*?\n    \}\n',
    """    pub fn severity_weight(self) -> f64 {
        crate::class_registry::severity_for(self)
    }

    pub fn attack_category(self) -> AttackCategory {
        crate::class_registry::attack_category_for(self)
    }

    pub fn mitre_tactic(self) -> crate::mitre::MitreTactic {
        crate::class_registry::mitre_for(self).1
    }
""",
    types_rs,
    flags=re.DOTALL
)
with open('src/types.rs', 'w') as f:
    f.write(types_rs)

# 9. Refactor compliance.rs
comp_rs = re.sub(r'const ALL_CLASSES.*?\];\n*', '', comp_rs, flags=re.DOTALL)
comp_rs = re.sub(r'fn owasp_top10_2021_for_class.*?\}\n', '', comp_rs, flags=re.DOTALL)
comp_rs = re.sub(r'fn owasp_api_top10_for_class.*?\}\n', '', comp_rs, flags=re.DOTALL)
comp_rs = re.sub(r'fn cwe_ids_for_class.*?\}\n', '', comp_rs, flags=re.DOTALL)

# Delete existing framework_controls_for_class cleanly using find
fc_idx = comp_rs.find('fn framework_controls_for_class(class: InvariantClass) -> Vec<ComplianceControl> {')
cm_idx = comp_rs.find('pub fn compliance_mapping_for_class(class: InvariantClass) -> ComplianceMapping {')
if fc_idx != -1 and cm_idx != -1:
    comp_rs = comp_rs[:fc_idx] + comp_rs[cm_idx:]

# Insert new one
controls_code = """
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
comp_rs = comp_rs.replace('pub fn compliance_mapping_for_class(class: InvariantClass) -> ComplianceMapping {', controls_code + 'pub fn compliance_mapping_for_class(class: InvariantClass) -> ComplianceMapping {')

# fix tests to use all_variants instead of ALL_CLASSES
comp_rs = comp_rs.replace('&ALL_CLASSES', 'InvariantClass::all_variants()')

with open('src/compliance.rs', 'w') as f:
    f.write(comp_rs)

# 10. Refactor mitre.rs
mitre_rs = re.sub(
    r'pub fn get_mapping\(&self, class: InvariantClass\) -> Option<&\'static MitreMapping> \{.*?\}',
    """pub fn get_mapping(&self, class: InvariantClass) -> Option<&'static MitreMapping> {
        // Find existing mapping or construct a dummy
        INVARIANT_MITRE_MAP.iter().find(|m| m.invariant_class == class)
    }""",
    mitre_rs,
    flags=re.DOTALL
)
with open('src/mitre.rs', 'w') as f:
    f.write(mitre_rs)

