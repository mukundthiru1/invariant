import re

with open('src/types.rs', 'r') as f:
    text = f.read()

# 1. Parse InvariantClass variants
enum_match = re.search(r'pub enum InvariantClass \{(.*?)\}', text, re.DOTALL)
variants = []
for line in enum_match.group(1).split('\n'):
    line = line.split('//')[0].strip()
    if not line:
        continue
    v = line.split(',')[0].strip()
    if v:
        variants.append(v)

# I will just write a function to evaluate the exact category and severity weight
def get_cat(v):
    if v in ["SqlStringTermination", "SqlTautology", "SqlUnionExtraction", "SqlStackedExecution", "SqlTimeOracle", "SqlErrorOracle", "SqlCommentTruncation", "JsonSqlBypass"]: return "AttackCategory::Sqli"
    if v in ["XssTagInjection", "XssAttributeEscape", "XssEventHandler", "XssProtocolHandler", "XssTemplateExpression"]: return "AttackCategory::Xss"
    if v in ["PathDotdotEscape", "PathNullTerminate", "PathEncodingBypass", "PathNormalizationBypass"]: return "AttackCategory::PathTraversal"
    if v in ["CmdSeparator", "CmdSubstitution", "CmdArgumentInjection"]: return "AttackCategory::Cmdi"
    if v in ["SsrfInternalReach", "SsrfCloudMetadata", "SsrfProtocolSmuggle"]: return "AttackCategory::Ssrf"
    if v in ["DeserJavaGadget", "DeserPhpObject", "DeserPythonPickle"]: return "AttackCategory::Deser"
    if v in ["AuthNoneAlgorithm", "AuthHeaderSpoof", "CorsOriginAbuse", "JwtKidInjection", "JwtJwkEmbedding", "JwtConfusion"]: return "AttackCategory::Auth"
    if v in ["HttpSmuggleClTe", "HttpSmuggleH2", "HttpSmuggleChunkExt", "HttpSmuggleZeroCl", "HttpSmuggleExpect"]: return "AttackCategory::Smuggling"
    return "AttackCategory::Injection"

def get_sev(v):
    crit = ["SqlUnionExtraction", "SqlStackedExecution", "CmdSeparator", "CmdSubstitution", "DeserJavaGadget", "DeserPythonPickle", "LogJndiLookup", "SstiJinjaTwig", "SstiElExpression", "SsrfCloudMetadata", "XxeEntityExpansion", "LlmDataExfiltration", "ProtoPollutionGadget", "OastInteraction"]
    high = ["SqlStringTermination", "SqlTautology", "SqlTimeOracle", "SqlErrorOracle", "JsonSqlBypass", "XssTagInjection", "PathDotdotEscape", "PathEncodingBypass", "CmdArgumentInjection", "SsrfInternalReach", "SsrfProtocolSmuggle", "DeserPhpObject", "AuthNoneAlgorithm", "AuthHeaderSpoof", "ProtoPollution", "NosqlOperatorInjection", "NosqlJsInjection", "LdapFilterInjection", "XmlInjection", "CrlfHeaderInjection", "GraphqlBatchAbuse", "HttpSmuggleClTe", "HttpSmuggleH2", "DependencyConfusion", "PostinstallInjection", "EnvExfiltration", "LlmPromptInjection", "LlmJailbreak", "WsInjection", "WsHijack", "JwtKidInjection", "JwtJwkEmbedding", "JwtConfusion"]
    if v in crit: return "Severity::Critical"
    if v in high: return "Severity::High"
    return "Severity::Medium"

def get_weight(v):
    weights = {
        "GraphqlDepthDoS": 0.75, "Http2RapidReset": 0.80, "DnsRebindingAttack": 0.85, "IdorDeepBypass": 0.90, "SubdomainTakeover": 0.75,
        "RaceConditionExploit": 0.90, "DeserNodeJsBuffer": 0.95, "JwtAlgorithmConfusion": 0.90, "CachePoisoningDoS": 0.75,
        "XpathInjection": 0.85, "TemplateLiteralInjection": 0.85, "HttpHeaderInjection": 0.80, "BlindSsrfTiming": 0.85,
        "ClickjackingBypass": 0.75, "TemplateInjectionServer": 0.90, "Http2Downgrade": 0.80, "ServerProtoPoison": 0.85,
        "CacheTimingOracle": 0.80, "SmugglingObfuscated": 0.85, "PaddingOracleAttack": 0.85, "DeserRubyMarshal": 0.95,
        "GraphqlIntrospectionAbuse": 0.70, "HostHeaderPoisoning": 0.80, "HostHeaderRedirect": 0.75, "HttpMethodOverride": 0.75,
        "TypeJugglingLoose": 0.80, "TypeJugglingMagicHash": 0.85, "EmailHeaderInjection": 0.80, "SsiDirectiveInjection": 0.90,
        "OauthRedirectManipulation": 0.85, "OauthScopeEscalation": 0.85, "CspBaseTagBypass": 0.80, "CspJsonpBypass": 0.80,
        "XssMutationBrowser": 0.85, "XssDomClobbering": 0.80, "SamlSignatureWrapping": 0.90, "UnicodeConfusableBypass": 0.80,
        "HttpRequestSplitting": 0.85, "IntegerOverflowAttack": 0.80, "FormatStringAttack": 0.90, "TypeConfusionAttack": 0.86,
        "UseAfterFreePattern": 0.95, "CorsMisconfigExploit": 0.88, "WebsocketInjection": 0.89, "OpenRedirectChain": 0.87,
        "MemoryPatternProbe": 0.85,
    }
    if v in weights: return weights[v]
    sev = get_sev(v)
    if sev == "Severity::Critical": return 0.95
    if sev == "Severity::High": return 0.85
    if sev == "Severity::Medium": return 0.70
    return 0.55

with open('src/mitre.rs', 'r') as f:
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

out = []
for v in variants:
    cat = get_cat(v)
    weight = get_weight(v)
    
    mitre_entry = mitre_map.get(v, {'technique': 'T1190', 'rationale': 'Generic detection.'})
    tech_id_var = mitre_entry['technique']
    if tech_id_var in tactic_map:
        tech_str = f'"{tactic_map[tech_id_var][0]}"'
        tactic_str = "MitreTactic::" + tactic_map[tech_id_var][1]
    else:
        tech_str = '"T1190"'
        tactic_str = "MitreTactic::InitialAccess"
    desc = mitre_entry['rationale']
    
    tags = ['"PCI-6.2.4"', '"PCI-6.2.3.1"', '"SOC2-CC7.1"', '"SOC2-CC7.2"', '"GDPR-Art.32"', '"HIPAA-164.308"', '"HIPAA-164.312"', '"NIST-SI-10"', '"NIST-RA-5"', '"ISO-8.28"', '"ISO-8.8"']
    if v in ["AuthNoneAlgorithm", "BolaIdor"]:
        tags.append('"SOC2-CC6.1"')
    if v in ["SsrfInternalReach", "SsrfCloudMetadata", "SsrfProtocolSmuggle"]:
        tags.append('"HIPAA-164.312-e1"')
        tags.append('"NIST-SC-7"')
    if "Sql" in v:
        tags.extend(['"A03:2021"', '"CWE-89"'])
    if "Ssrf" in v:
        tags.append('"A10:2021"')
    if "AuthNone" in v:
        tags.extend(['"A02:2021"', '"API2:2023"'])
    if "Log" in v:
        tags.append('"A09:2021"')
    if "DependencyConfusion" in v or "PostinstallInjection" in v:
        tags.append('"PCI DSS 4.0 6.3.2"')
        
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

all_c_array = "pub const ALL_CLASSES: &[InvariantClass] = &[\n" + ",\n".join("    InvariantClass::" + v for v in variants) + "\n];"

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

{all_c_array}

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
        assert_eq!(ALL_CLASS_METADATA.len(), ALL_CLASSES.len());
        for class in ALL_CLASSES {{
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
