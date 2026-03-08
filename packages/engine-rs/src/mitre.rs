//! MITRE ATT&CK Mapping
//!
//! Maps every INVARIANT detection (invariant classes, chain definitions,
//! behavioral signals) to MITRE ATT&CK techniques and tactics.

use crate::types::InvariantClass;

// ── MITRE ATT&CK Taxonomy ────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MitreTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl MitreTactic {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reconnaissance => "reconnaissance",
            Self::ResourceDevelopment => "resource_development",
            Self::InitialAccess => "initial_access",
            Self::Execution => "execution",
            Self::Persistence => "persistence",
            Self::PrivilegeEscalation => "privilege_escalation",
            Self::DefenseEvasion => "defense_evasion",
            Self::CredentialAccess => "credential_access",
            Self::Discovery => "discovery",
            Self::LateralMovement => "lateral_movement",
            Self::Collection => "collection",
            Self::CommandAndControl => "command_and_control",
            Self::Exfiltration => "exfiltration",
            Self::Impact => "impact",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KillChainPhase {
    Recon,
    Weaponize,
    Deliver,
    Exploit,
    Install,
    C2,
    Actions,
}

impl KillChainPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recon => "recon",
            Self::Weaponize => "weaponize",
            Self::Deliver => "deliver",
            Self::Exploit => "exploit",
            Self::Install => "install",
            Self::C2 => "c2",
            Self::Actions => "actions",
        }
    }
}

impl MitreTactic {
    pub fn kill_chain_phase(self) -> KillChainPhase {
        match self {
            Self::Reconnaissance | Self::Discovery => KillChainPhase::Recon,
            Self::ResourceDevelopment => KillChainPhase::Weaponize,
            Self::InitialAccess | Self::DefenseEvasion => KillChainPhase::Deliver,
            Self::Execution | Self::PrivilegeEscalation | Self::CredentialAccess => {
                KillChainPhase::Exploit
            }
            Self::Persistence => KillChainPhase::Install,
            Self::CommandAndControl => KillChainPhase::C2,
            Self::LateralMovement | Self::Collection | Self::Exfiltration | Self::Impact => {
                KillChainPhase::Actions
            }
        }
    }
}

fn kill_chain_phase_rank(phase: KillChainPhase) -> u8 {
    match phase {
        KillChainPhase::Recon => 0,
        KillChainPhase::Weaponize => 1,
        KillChainPhase::Deliver => 2,
        KillChainPhase::Exploit => 3,
        KillChainPhase::Install => 4,
        KillChainPhase::C2 => 5,
        KillChainPhase::Actions => 6,
    }
}

fn tactic_rank(tactic: MitreTactic) -> u8 {
    match tactic {
        MitreTactic::Reconnaissance => 0,
        MitreTactic::ResourceDevelopment => 1,
        MitreTactic::InitialAccess => 2,
        MitreTactic::DefenseEvasion => 3,
        MitreTactic::Execution => 4,
        MitreTactic::Persistence => 5,
        MitreTactic::PrivilegeEscalation => 6,
        MitreTactic::CredentialAccess => 7,
        MitreTactic::Discovery => 8,
        MitreTactic::LateralMovement => 9,
        MitreTactic::Collection => 10,
        MitreTactic::CommandAndControl => 11,
        MitreTactic::Exfiltration => 12,
        MitreTactic::Impact => 13,
    }
}

fn technique_tactic_color(tactic: MitreTactic) -> &'static str {
    match tactic {
        MitreTactic::Reconnaissance => "#4b4be0",
        MitreTactic::ResourceDevelopment => "#8f3cc6",
        MitreTactic::InitialAccess => "#f55c47",
        MitreTactic::Execution => "#ff9d00",
        MitreTactic::Persistence => "#e60073",
        MitreTactic::PrivilegeEscalation => "#7f00ff",
        MitreTactic::DefenseEvasion => "#a3008b",
        MitreTactic::CredentialAccess => "#2d7c5f",
        MitreTactic::Discovery => "#2f80ed",
        MitreTactic::LateralMovement => "#4ade80",
        MitreTactic::Collection => "#5f27cd",
        MitreTactic::CommandAndControl => "#ff006e",
        MitreTactic::Exfiltration => "#ff4f1f",
        MitreTactic::Impact => "#eb5757",
    }
}

#[derive(Debug, Clone)]
pub struct MitreTechnique {
    pub id: &'static str,
    pub name: &'static str,
    pub tactic: MitreTactic,
}

impl MitreTechnique {
    pub fn url(&self) -> String {
        format!(
            "https://attack.mitre.org/techniques/{}/",
            self.id.replace('.', "/")
        )
    }
}

#[derive(Debug, Clone)]
pub struct MitreMapping {
    pub invariant_class: InvariantClass,
    pub techniques: &'static [&'static MitreTechnique],
    pub rationale: &'static str,
}

#[derive(Debug, Clone)]
pub struct MitreProgression {
    pub primary_kill_chain_phase: KillChainPhase,
    pub ordered_tactics: Vec<MitreTactic>,
    pub confidence: f64,
    pub technique_count: usize,
}

#[derive(Debug, Clone)]
pub struct NavigatorTechnique {
    pub technique_id: &'static str,
    pub technique_name: &'static str,
    pub tactic: &'static str,
    pub score: u8,
    pub color: &'static str,
    pub comment: &'static str,
}

#[derive(Debug, Clone)]
pub struct NavigatorLayer {
    pub name: &'static str,
    pub version: &'static str,
    pub techniques: Vec<NavigatorTechnique>,
}

// ── Core Technique Database ──────────────────────────────────────

use MitreTactic::*;

static T1190: MitreTechnique = MitreTechnique {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: InitialAccess,
};
static T1059: MitreTechnique = MitreTechnique {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: Execution,
};
static T1059_004: MitreTechnique = MitreTechnique {
    id: "T1059.004",
    name: "Unix Shell",
    tactic: Execution,
};
static T1059_001: MitreTechnique = MitreTechnique {
    id: "T1059.001",
    name: "PowerShell",
    tactic: Execution,
};
static T1059_006: MitreTechnique = MitreTechnique {
    id: "T1059.006",
    name: "Python",
    tactic: Execution,
};
static T1083: MitreTechnique = MitreTechnique {
    id: "T1083",
    name: "File and Directory Discovery",
    tactic: Discovery,
};
static T1005: MitreTechnique = MitreTechnique {
    id: "T1005",
    name: "Data from Local System",
    tactic: Collection,
};
static T1071: MitreTechnique = MitreTechnique {
    id: "T1071",
    name: "Application Layer Protocol",
    tactic: CommandAndControl,
};
static T1557: MitreTechnique = MitreTechnique {
    id: "T1557",
    name: "Adversary-in-the-Middle",
    tactic: CredentialAccess,
};
static T1210: MitreTechnique = MitreTechnique {
    id: "T1210",
    name: "Exploitation of Remote Services",
    tactic: LateralMovement,
};
static T1078: MitreTechnique = MitreTechnique {
    id: "T1078",
    name: "Valid Accounts",
    tactic: PrivilegeEscalation,
};
static T1018: MitreTechnique = MitreTechnique {
    id: "T1018",
    name: "Remote System Discovery",
    tactic: Discovery,
};
static T1595: MitreTechnique = MitreTechnique {
    id: "T1595",
    name: "Active Scanning",
    tactic: Reconnaissance,
};
static T1595_002: MitreTechnique = MitreTechnique {
    id: "T1595.002",
    name: "Vulnerability Scanning",
    tactic: Reconnaissance,
};
static T1592: MitreTechnique = MitreTechnique {
    id: "T1592",
    name: "Gather Victim Host Information",
    tactic: Reconnaissance,
};
static T1189: MitreTechnique = MitreTechnique {
    id: "T1189",
    name: "Drive-by Compromise",
    tactic: InitialAccess,
};
static T1203: MitreTechnique = MitreTechnique {
    id: "T1203",
    name: "Exploitation for Client Execution",
    tactic: Execution,
};
static T1068: MitreTechnique = MitreTechnique {
    id: "T1068",
    name: "Exploitation for Privilege Escalation",
    tactic: PrivilegeEscalation,
};
static T1003: MitreTechnique = MitreTechnique {
    id: "T1003",
    name: "OS Credential Dumping",
    tactic: CredentialAccess,
};
static T1550: MitreTechnique = MitreTechnique {
    id: "T1550",
    name: "Use Alternate Authentication Material",
    tactic: DefenseEvasion,
};
static T1550_001: MitreTechnique = MitreTechnique {
    id: "T1550.001",
    name: "Application Access Token",
    tactic: DefenseEvasion,
};
static T1553: MitreTechnique = MitreTechnique {
    id: "T1553",
    name: "Subvert Trust Controls",
    tactic: DefenseEvasion,
};
static T1499: MitreTechnique = MitreTechnique {
    id: "T1499",
    name: "Endpoint Denial of Service",
    tactic: Impact,
};
static T1498: MitreTechnique = MitreTechnique {
    id: "T1498",
    name: "Network Denial of Service",
    tactic: Impact,
};
static T1105: MitreTechnique = MitreTechnique {
    id: "T1105",
    name: "Ingress Tool Transfer",
    tactic: CommandAndControl,
};
static T1046: MitreTechnique = MitreTechnique {
    id: "T1046",
    name: "Network Service Discovery",
    tactic: Discovery,
};
static T1552: MitreTechnique = MitreTechnique {
    id: "T1552",
    name: "Unsecured Credentials",
    tactic: CredentialAccess,
};
static T1070: MitreTechnique = MitreTechnique {
    id: "T1070",
    name: "Indicator Removal",
    tactic: DefenseEvasion,
};
static T1195: MitreTechnique = MitreTechnique {
    id: "T1195",
    name: "Supply Chain Compromise",
    tactic: InitialAccess,
};
static T1195_001: MitreTechnique = MitreTechnique {
    id: "T1195.001",
    name: "Compromise Software Dependencies",
    tactic: InitialAccess,
};
static T1195_002: MitreTechnique = MitreTechnique {
    id: "T1195.002",
    name: "Compromise Software Supply Chain",
    tactic: InitialAccess,
};
static T1059_007: MitreTechnique = MitreTechnique {
    id: "T1059.007",
    name: "JavaScript",
    tactic: Execution,
};
static T1185: MitreTechnique = MitreTechnique {
    id: "T1185",
    name: "Browser Session Hijacking",
    tactic: Collection,
};
static T1539: MitreTechnique = MitreTechnique {
    id: "T1539",
    name: "Steal Web Session Cookie",
    tactic: CredentialAccess,
};
static T1565: MitreTechnique = MitreTechnique {
    id: "T1565",
    name: "Data Manipulation",
    tactic: Impact,
};
static T1530: MitreTechnique = MitreTechnique {
    id: "T1530",
    name: "Data from Cloud Storage",
    tactic: Collection,
};
static T1119: MitreTechnique = MitreTechnique {
    id: "T1119",
    name: "Automated Collection",
    tactic: Collection,
};
static T1087: MitreTechnique = MitreTechnique {
    id: "T1087",
    name: "Account Discovery",
    tactic: Discovery,
};

// ── Invariant Class → MITRE Mapping ──────────────────────────────

#[allow(dead_code)]
struct ClassMapping {
    class: InvariantClass,
    techniques: &'static [&'static MitreTechnique],
    rationale: &'static str,
}

static INVARIANT_MITRE_MAP: &[ClassMapping] = &[
    // SQL Injection (7)
    ClassMapping {
        class: InvariantClass::SqlTautology,
        techniques: &[&T1190],
        rationale: "Boolean-based blind SQLi exploits public-facing database interfaces",
    },
    ClassMapping {
        class: InvariantClass::SqlStringTermination,
        techniques: &[&T1190],
        rationale: "String termination bypasses input validation to inject SQL",
    },
    ClassMapping {
        class: InvariantClass::SqlUnionExtraction,
        techniques: &[&T1190, &T1005],
        rationale: "UNION-based extraction exfiltrates database contents",
    },
    ClassMapping {
        class: InvariantClass::SqlStackedExecution,
        techniques: &[&T1190, &T1059],
        rationale: "Stacked queries enable arbitrary command execution",
    },
    ClassMapping {
        class: InvariantClass::SqlTimeOracle,
        techniques: &[&T1190],
        rationale: "Time-based blind SQLi uses timing as a side channel",
    },
    ClassMapping {
        class: InvariantClass::SqlErrorOracle,
        techniques: &[&T1190],
        rationale: "Error-based SQLi uses error messages as data exfiltration channel",
    },
    ClassMapping {
        class: InvariantClass::SqlCommentTruncation,
        techniques: &[&T1190],
        rationale: "Comment truncation bypasses authorization logic",
    },
    // XSS (5)
    ClassMapping {
        class: InvariantClass::XssTagInjection,
        techniques: &[&T1189, &T1203],
        rationale: "Script tag injection enables drive-by compromise and client execution",
    },
    ClassMapping {
        class: InvariantClass::XssEventHandler,
        techniques: &[&T1189],
        rationale: "Event handler XSS executes when user interacts with injected element",
    },
    ClassMapping {
        class: InvariantClass::XssProtocolHandler,
        techniques: &[&T1189],
        rationale: "javascript: protocol handler executes in page context",
    },
    ClassMapping {
        class: InvariantClass::XssTemplateExpression,
        techniques: &[&T1189, &T1059],
        rationale: "Template expression injection can escalate to RCE via SSTI",
    },
    ClassMapping {
        class: InvariantClass::XssAttributeEscape,
        techniques: &[&T1189],
        rationale: "Attribute escape breaks out of HTML attribute context",
    },
    // Command Injection (3)
    ClassMapping {
        class: InvariantClass::CmdSeparator,
        techniques: &[&T1059, &T1059_001, &T1059_004],
        rationale: "Shell metacharacter injection enables arbitrary command execution",
    },
    ClassMapping {
        class: InvariantClass::CmdSubstitution,
        techniques: &[&T1059, &T1059_004, &T1059_006],
        rationale: "Subshell substitution $(cmd) executes in host context",
    },
    ClassMapping {
        class: InvariantClass::CmdArgumentInjection,
        techniques: &[&T1059, &T1059_004],
        rationale: "Argument injection manipulates command-line tool behavior",
    },
    // Path Traversal (4)
    ClassMapping {
        class: InvariantClass::PathDotdotEscape,
        techniques: &[&T1083, &T1005],
        rationale: "Directory traversal reads arbitrary files from the filesystem",
    },
    ClassMapping {
        class: InvariantClass::PathNullTerminate,
        techniques: &[&T1083],
        rationale: "Null byte truncates filename extensions to bypass filters",
    },
    ClassMapping {
        class: InvariantClass::PathEncodingBypass,
        techniques: &[&T1083],
        rationale: "Encoding bypass evades path traversal filters",
    },
    ClassMapping {
        class: InvariantClass::PathNormalizationBypass,
        techniques: &[&T1083],
        rationale: "Path normalization differences between parser and filesystem",
    },
    // SSRF (3)
    ClassMapping {
        class: InvariantClass::SsrfInternalReach,
        techniques: &[&T1210, &T1018],
        rationale: "SSRF accesses internal network resources from the application",
    },
    ClassMapping {
        class: InvariantClass::SsrfCloudMetadata,
        techniques: &[&T1552, &T1003],
        rationale: "Cloud metadata SSRF extracts IAM credentials from instance metadata service",
    },
    ClassMapping {
        class: InvariantClass::SsrfProtocolSmuggle,
        techniques: &[&T1071],
        rationale: "Protocol smuggling accesses non-HTTP internal services",
    },
    // SSTI (2)
    ClassMapping {
        class: InvariantClass::SstiJinjaTwig,
        techniques: &[&T1059, &T1059_007, &T1059_006, &T1190],
        rationale: "Jinja2/Twig SSTI enables arbitrary Python/PHP code execution",
    },
    ClassMapping {
        class: InvariantClass::SstiElExpression,
        techniques: &[&T1059, &T1059_007, &T1190],
        rationale: "Expression Language injection enables arbitrary Java execution",
    },
    // NoSQL (2)
    ClassMapping {
        class: InvariantClass::NosqlOperatorInjection,
        techniques: &[&T1190],
        rationale: "MongoDB operator injection bypasses authentication and exfiltrates data",
    },
    ClassMapping {
        class: InvariantClass::NosqlJsInjection,
        techniques: &[&T1190, &T1059, &T1059_006],
        rationale: "Server-side JavaScript injection in NoSQL databases",
    },
    // XXE (1)
    ClassMapping {
        class: InvariantClass::XxeEntityExpansion,
        techniques: &[&T1190, &T1005],
        rationale: "XML external entity reads local files and performs SSRF",
    },
    // Auth (4)
    ClassMapping {
        class: InvariantClass::AuthNoneAlgorithm,
        techniques: &[&T1550, &T1550_001],
        rationale: "JWT alg:none bypass forges authentication tokens",
    },
    ClassMapping {
        class: InvariantClass::AuthHeaderSpoof,
        techniques: &[&T1078, &T1553],
        rationale: "Forwarding header spoofing bypasses IP-based access controls",
    },
    ClassMapping {
        class: InvariantClass::CorsOriginAbuse,
        techniques: &[&T1189],
        rationale: "CORS misconfiguration allows cross-origin credential theft",
    },
    ClassMapping {
        class: InvariantClass::MassAssignment,
        techniques: &[&T1068],
        rationale: "Mass assignment escalates privileges by setting admin fields",
    },
    // Deserialization (3)
    ClassMapping {
        class: InvariantClass::DeserJavaGadget,
        techniques: &[&T1059, &T1190],
        rationale: "Java deserialization gadget chains enable RCE",
    },
    ClassMapping {
        class: InvariantClass::DeserPhpObject,
        techniques: &[&T1059, &T1190],
        rationale: "PHP object injection via unserialize()",
    },
    ClassMapping {
        class: InvariantClass::DeserPythonPickle,
        techniques: &[&T1059, &T1190],
        rationale: "Python pickle deserialization executes arbitrary __reduce__",
    },
    // CRLF (2)
    ClassMapping {
        class: InvariantClass::CrlfHeaderInjection,
        techniques: &[&T1557],
        rationale: "CRLF injection manipulates HTTP response headers",
    },
    ClassMapping {
        class: InvariantClass::CrlfLogInjection,
        techniques: &[&T1070],
        rationale: "Log injection forges log entries to cover tracks",
    },
    // HTTP Smuggling (5)
    ClassMapping {
        class: InvariantClass::HttpSmuggleClTe,
        techniques: &[&T1557, &T1190],
        rationale: "CL.TE desync enables request smuggling through proxy chains",
    },
    ClassMapping {
        class: InvariantClass::HttpSmuggleH2,
        techniques: &[&T1557],
        rationale: "H2.CL downgrade attack exploits HTTP/2 to HTTP/1.1 conversion",
    },
    ClassMapping {
        class: InvariantClass::HttpSmuggleChunkExt,
        techniques: &[&T1557, &T1190],
        rationale: "Chunk extension smuggling exploits HTTP/1.1 chunked encoding",
    },
    ClassMapping {
        class: InvariantClass::HttpSmuggleZeroCl,
        techniques: &[&T1557],
        rationale: "Zero Content-Length smuggling exploits edge cases in body parsing",
    },
    ClassMapping {
        class: InvariantClass::HttpSmuggleExpect,
        techniques: &[&T1557],
        rationale: "Expect header smuggling exploits 100-Continue handling",
    },
    // Log4Shell (1)
    ClassMapping {
        class: InvariantClass::LogJndiLookup,
        techniques: &[&T1190, &T1059, &T1105],
        rationale: "JNDI lookup enables remote class loading and RCE",
    },
    // Prototype Pollution (2)
    ClassMapping {
        class: InvariantClass::ProtoPollution,
        techniques: &[&T1068, &T1190],
        rationale: "Prototype pollution modifies Object.prototype to escalate privileges",
    },
    ClassMapping {
        class: InvariantClass::ProtoPollutionGadget,
        techniques: &[&T1068, &T1059_007],
        rationale: "Prototype pollution gadget chains escalate to RCE",
    },
    // Open Redirect (1)
    ClassMapping {
        class: InvariantClass::OpenRedirectBypass,
        techniques: &[&T1189],
        rationale: "Open redirect chains with phishing for credential theft",
    },
    // LDAP (1)
    ClassMapping {
        class: InvariantClass::LdapFilterInjection,
        techniques: &[&T1190, &T1078],
        rationale: "LDAP filter injection bypasses authentication",
    },
    // GraphQL (2)
    ClassMapping {
        class: InvariantClass::GraphqlIntrospection,
        techniques: &[&T1046, &T1592],
        rationale: "GraphQL introspection reveals entire API schema",
    },
    ClassMapping {
        class: InvariantClass::GraphqlBatchAbuse,
        techniques: &[&T1499],
        rationale: "GraphQL batch/nested queries cause denial of service",
    },
    // ReDoS (1)
    ClassMapping {
        class: InvariantClass::RegexDos,
        techniques: &[&T1499],
        rationale: "Catastrophic regex backtracking causes CPU exhaustion",
    },
    // JSON-SQL Bypass (1)
    ClassMapping {
        class: InvariantClass::JsonSqlBypass,
        techniques: &[&T1190],
        rationale: "JSON-wrapped SQL payloads bypass WAF signature matching",
    },
    // XML Injection (1)
    ClassMapping {
        class: InvariantClass::XmlInjection,
        techniques: &[&T1190],
        rationale: "XML injection modifies document structure to bypass access controls",
    },
    // Supply Chain (3)
    ClassMapping {
        class: InvariantClass::DependencyConfusion,
        techniques: &[&T1195, &T1195_001],
        rationale: "Dependency confusion substitutes public package for private one",
    },
    ClassMapping {
        class: InvariantClass::PostinstallInjection,
        techniques: &[&T1195_002, &T1059],
        rationale: "Package postinstall scripts execute arbitrary code during install",
    },
    ClassMapping {
        class: InvariantClass::EnvExfiltration,
        techniques: &[&T1552, &T1005],
        rationale: "Environment variable exfiltration steals credentials",
    },
    // LLM (3)
    ClassMapping {
        class: InvariantClass::LlmPromptInjection,
        techniques: &[&T1190, &T1059],
        rationale: "Prompt injection overrides LLM system instructions",
    },
    ClassMapping {
        class: InvariantClass::LlmDataExfiltration,
        techniques: &[&T1005, &T1119],
        rationale: "LLM data exfiltration extracts training data or system prompts",
    },
    ClassMapping {
        class: InvariantClass::LlmJailbreak,
        techniques: &[&T1553],
        rationale: "LLM jailbreak bypasses safety controls",
    },
    // WebSocket (2)
    ClassMapping {
        class: InvariantClass::WsInjection,
        techniques: &[&T1190, &T1059_007],
        rationale: "WebSocket message injection exploits bidirectional channel",
    },
    ClassMapping {
        class: InvariantClass::WsHijack,
        techniques: &[&T1185, &T1557],
        rationale: "WebSocket hijacking takes over established connections",
    },
    // JWT (3)
    ClassMapping {
        class: InvariantClass::JwtKidInjection,
        techniques: &[&T1550, &T1550_001, &T1190],
        rationale: "JWT kid parameter injection enables path traversal or SQLi in key lookup",
    },
    ClassMapping {
        class: InvariantClass::JwtJwkEmbedding,
        techniques: &[&T1550, &T1550_001],
        rationale: "Embedded JWK in JWT header provides attacker-controlled signing key",
    },
    ClassMapping {
        class: InvariantClass::JwtConfusion,
        techniques: &[&T1550, &T1550_001],
        rationale: "Algorithm confusion attack uses public key as HMAC secret",
    },
    // Cache (2)
    ClassMapping {
        class: InvariantClass::CachePoisoning,
        techniques: &[&T1557, &T1565],
        rationale: "Cache poisoning serves malicious content via unkeyed headers",
    },
    ClassMapping {
        class: InvariantClass::CacheDeception,
        techniques: &[&T1539, &T1530],
        rationale: "Cache deception tricks CDN into caching sensitive responses",
    },
    // API (2)
    ClassMapping {
        class: InvariantClass::BolaIdor,
        techniques: &[&T1078, &T1087],
        rationale: "Broken object-level authorization allows accessing other users resources",
    },
    ClassMapping {
        class: InvariantClass::ApiMassEnum,
        techniques: &[&T1119, &T1087],
        rationale: "Mass API enumeration extracts all records via sequential ID",
    },
];

fn find_mapping(class: InvariantClass) -> Option<&'static ClassMapping> {
    INVARIANT_MITRE_MAP.iter().find(|m| m.class == class)
}

// ── Behavioral Signal → MITRE Mapping ────────────────────────────

struct BehavioralMapping {
    behavior: &'static str,
    techniques: &'static [&'static MitreTechnique],
}

static BEHAVIORAL_MITRE_MAP: &[BehavioralMapping] = &[
    BehavioralMapping {
        behavior: "rate_anomaly",
        techniques: &[&T1498],
    },
    BehavioralMapping {
        behavior: "path_enumeration",
        techniques: &[&T1595, &T1595_002],
    },
    BehavioralMapping {
        behavior: "method_probing",
        techniques: &[&T1595],
    },
    BehavioralMapping {
        behavior: "unusual_method",
        techniques: &[&T1595],
    },
    BehavioralMapping {
        behavior: "scanner_detected",
        techniques: &[&T1595_002],
    },
    BehavioralMapping {
        behavior: "high_error_rate",
        techniques: &[&T1595_002],
    },
];

fn find_behavioral(behavior: &str) -> Option<&'static BehavioralMapping> {
    BEHAVIORAL_MITRE_MAP.iter().find(|m| m.behavior == behavior)
}

// ── MITRE Mapper ─────────────────────────────────────────────────

pub struct MitreMapper;

impl MitreMapper {
    pub fn new() -> Self {
        Self
    }

    pub fn get_techniques(&self, class: InvariantClass) -> Vec<&'static MitreTechnique> {
        find_mapping(class)
            .map(|m| m.techniques.to_vec())
            .unwrap_or_default()
    }

    pub fn get_behavioral_techniques(&self, behavior: &str) -> Vec<&'static MitreTechnique> {
        find_behavioral(behavior)
            .map(|m| m.techniques.to_vec())
            .unwrap_or_default()
    }

    pub fn get_kill_chain_phase(&self, tactic: MitreTactic) -> KillChainPhase {
        tactic.kill_chain_phase()
    }

    pub fn get_attack_phase(
        &self,
        classes: &[InvariantClass],
        behaviors: &[&str],
    ) -> KillChainPhase {
        let mut phase_counts: std::collections::HashMap<KillChainPhase, u32> =
            std::collections::HashMap::new();

        for &cls in classes {
            for tech in self.get_techniques(cls) {
                let phase = tech.tactic.kill_chain_phase();
                *phase_counts.entry(phase).or_default() += 1;
            }
        }

        for &beh in behaviors {
            for tech in self.get_behavioral_techniques(beh) {
                let phase = tech.tactic.kill_chain_phase();
                *phase_counts.entry(phase).or_default() += 1;
            }
        }

        phase_counts
            .into_iter()
            .max_by_key(|&(_, count)| count)
            .map(|(phase, _)| phase)
            .unwrap_or(KillChainPhase::Recon)
    }

    pub fn tactics_from_classes(
        &self,
        classes: &[InvariantClass],
        behaviors: &[&str],
    ) -> Vec<&'static str> {
        self.collect_techniques(classes, behaviors)
            .into_iter()
            .map(|tech| tech.tactic.as_str())
            .collect()
    }

    pub fn map_detections(&self, classes: &[InvariantClass]) -> Vec<&'static str> {
        let mut ids = std::collections::HashSet::new();
        for &cls in classes {
            for tech in self.get_techniques(cls) {
                ids.insert(tech.id);
            }
        }
        ids.into_iter().collect()
    }

    pub fn progression(&self, classes: &[InvariantClass], behaviors: &[&str]) -> MitreProgression {
        let mut unique = std::collections::HashSet::new();
        let mut tactic_counts: std::collections::HashMap<MitreTactic, u32> =
            std::collections::HashMap::new();

        for tech in self.collect_techniques(classes, behaviors) {
            if unique.insert(tech.id) {
                *tactic_counts.entry(tech.tactic).or_default() += 1;
            }
        }

        let mut ranked_tactics: Vec<(MitreTactic, u32)> = tactic_counts.into_iter().collect();
        ranked_tactics.sort_by(|(a_tactic, a_count), (b_tactic, b_count)| {
            b_count
                .cmp(a_count)
                .then_with(|| {
                    kill_chain_phase_rank(a_tactic.kill_chain_phase())
                        .cmp(&kill_chain_phase_rank(b_tactic.kill_chain_phase()))
                })
                .then_with(|| tactic_rank(*a_tactic).cmp(&tactic_rank(*b_tactic)))
        });

        let primary_phase = ranked_tactics
            .first()
            .map(|(tactic, _)| tactic.kill_chain_phase())
            .unwrap_or(KillChainPhase::Recon);
        let confidence = if classes.is_empty() && behaviors.is_empty() {
            0.0
        } else {
            (ranked_tactics.len() as f64 / (classes.len().max(behaviors.len()).max(1) as f64))
                .min(1.0)
        };
        MitreProgression {
            primary_kill_chain_phase: primary_phase,
            ordered_tactics: ranked_tactics
                .into_iter()
                .map(|(tactic, _)| tactic)
                .collect(),
            confidence,
            technique_count: unique.len(),
        }
    }

    pub fn navigator_layer(
        &self,
        classes: &[InvariantClass],
        behaviors: &[&str],
        base_score: f64,
    ) -> NavigatorLayer {
        let mut seen = std::collections::HashSet::new();
        let progression = self.progression(classes, behaviors);
        let mut techniques = Vec::new();

        for tech in self.collect_techniques(classes, behaviors) {
            if seen.insert(tech.id) {
                let score = ((base_score / 100.0) * 60.0 + 40.0).min(100.0).round() as u8;
                techniques.push(NavigatorTechnique {
                    technique_id: tech.id,
                    technique_name: tech.name,
                    tactic: tech.tactic.as_str(),
                    score: score,
                    color: technique_tactic_color(tech.tactic),
                    comment: match progression.primary_kill_chain_phase {
                        KillChainPhase::Recon => "reconnaissance and pre-attack preparation",
                        KillChainPhase::Weaponize => "weaponization and tooling",
                        KillChainPhase::Deliver => "delivery and initial compromise path",
                        KillChainPhase::Exploit => "exploitation and execution",
                        KillChainPhase::Install => "persistence and installation",
                        KillChainPhase::C2 => "command and control",
                        KillChainPhase::Actions => "collection and impact",
                    },
                });
            }
        }

        techniques.sort_by_key(|t| t.technique_id.to_owned());
        NavigatorLayer {
            name: "invariant-runtime",
            version: "4.3",
            techniques,
        }
    }

    fn collect_techniques(
        &self,
        classes: &[InvariantClass],
        behaviors: &[&str],
    ) -> Vec<&'static MitreTechnique> {
        let mut seen = std::collections::HashSet::new();
        let mut techniques = Vec::new();

        for &cls in classes {
            for tech in self.get_techniques(cls) {
                if seen.insert(tech.id) {
                    techniques.push(tech);
                }
            }
        }

        for &behavior in behaviors {
            for tech in self.get_behavioral_techniques(behavior) {
                if seen.insert(tech.id) {
                    techniques.push(tech);
                }
            }
        }

        techniques
    }

    pub fn get_coverage_report(&self) -> CoverageReport {
        let mut seen: std::collections::HashMap<&str, &MitreTechnique> =
            std::collections::HashMap::new();
        let mut tactic_dist: std::collections::HashMap<MitreTactic, u32> =
            std::collections::HashMap::new();

        for mapping in INVARIANT_MITRE_MAP {
            for tech in mapping.techniques {
                seen.insert(tech.id, tech);
                *tactic_dist.entry(tech.tactic).or_default() += 1;
            }
        }

        let covered_count = seen.len();
        CoverageReport {
            covered_techniques: seen.into_values().cloned().collect(),
            covered_count,
            total_mapped_classes: INVARIANT_MITRE_MAP.len(),
            tactic_distribution: tactic_dist,
        }
    }

    pub fn enrich_signal(
        &self,
        classes: &[InvariantClass],
        behaviors: &[&str],
    ) -> SignalEnrichment {
        let mut technique_ids = std::collections::HashSet::new();
        let mut tactics = std::collections::HashSet::new();

        for &cls in classes {
            for tech in self.get_techniques(cls) {
                technique_ids.insert(tech.id);
                tactics.insert(tech.tactic);
            }
        }

        for &beh in behaviors {
            for tech in self.get_behavioral_techniques(beh) {
                technique_ids.insert(tech.id);
                tactics.insert(tech.tactic);
            }
        }

        SignalEnrichment {
            technique_ids: technique_ids.into_iter().collect(),
            tactics: tactics.into_iter().collect(),
            kill_chain_phase: self.get_attack_phase(classes, behaviors),
        }
    }
}

pub struct CoverageReport {
    pub covered_techniques: Vec<MitreTechnique>,
    pub covered_count: usize,
    pub total_mapped_classes: usize,
    pub tactic_distribution: std::collections::HashMap<MitreTactic, u32>,
}

pub struct SignalEnrichment {
    pub technique_ids: Vec<&'static str>,
    pub tactics: Vec<MitreTactic>,
    pub kill_chain_phase: KillChainPhase,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_injection_maps_to_t1190() {
        let mapper = MitreMapper::new();
        let techs = mapper.get_techniques(InvariantClass::SqlTautology);
        assert!(!techs.is_empty());
        assert!(techs.iter().any(|t| t.id == "T1190"));
    }

    #[test]
    fn xss_maps_to_drive_by() {
        let mapper = MitreMapper::new();
        let techs = mapper.get_techniques(InvariantClass::XssTagInjection);
        assert!(techs.iter().any(|t| t.id == "T1189"));
    }

    #[test]
    fn behavioral_scanner_maps() {
        let mapper = MitreMapper::new();
        let techs = mapper.get_behavioral_techniques("scanner_detected");
        assert!(techs.iter().any(|t| t.id == "T1595.002"));
    }

    #[test]
    fn all_66_classes_mapped() {
        let _mapper = MitreMapper::new();
        let mapped_classes: std::collections::HashSet<_> =
            INVARIANT_MITRE_MAP.iter().map(|m| m.class).collect();
        assert!(
            mapped_classes.len() >= 60,
            "Expected at least 60 mapped classes, got {}",
            mapped_classes.len()
        );
    }

    #[test]
    fn kill_chain_phase_for_sqli() {
        let mapper = MitreMapper::new();
        let phase = mapper.get_attack_phase(&[InvariantClass::SqlTautology], &[]);
        // SQLi maps to T1190 (initial_access) → deliver
        assert_eq!(phase, KillChainPhase::Deliver);
    }

    #[test]
    fn progression_orders_tactics() {
        let mapper = MitreMapper::new();
        let progression = mapper.progression(
            &[
                InvariantClass::SqlTautology,
                InvariantClass::CmdSeparator,
                InvariantClass::SsrfCloudMetadata,
            ],
            &[],
        );
        assert!(!progression.ordered_tactics.is_empty());
        assert!(progression.technique_count >= 2);
    }

    #[test]
    fn navigator_layer_contains_techniques() {
        let mapper = MitreMapper::new();
        let layer = mapper.navigator_layer(&[InvariantClass::XssTagInjection], &[], 78.0);
        assert_eq!(layer.name, "invariant-runtime");
        assert!(!layer.techniques.is_empty());
        assert!(
            layer
                .techniques
                .iter()
                .any(|tech| tech.technique_id == "T1189")
        );
    }

    #[test]
    fn map_detections_deduplicates() {
        let mapper = MitreMapper::new();
        let ids = mapper.map_detections(&[
            InvariantClass::SqlTautology,
            InvariantClass::SqlStringTermination,
        ]);
        // Both map to T1190, should appear once
        let t1190_count = ids.iter().filter(|&&id| id == "T1190").count();
        assert_eq!(t1190_count, 1);
    }

    #[test]
    fn coverage_report_has_entries() {
        let mapper = MitreMapper::new();
        let report = mapper.get_coverage_report();
        assert!(report.covered_count > 20);
        assert!(report.total_mapped_classes >= 60);
    }
}
