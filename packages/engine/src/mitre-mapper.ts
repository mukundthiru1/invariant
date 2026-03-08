/**
 * @santh/invariant-engine — MITRE ATT&CK Mapping
 *
 * Maps every INVARIANT detection (invariant classes, chain definitions,
 * behavioral signals) to MITRE ATT&CK techniques and tactics.
 *
 * Why this matters:
 *   Security teams think in ATT&CK. When INVARIANT tells them
 *   "sql_tautology detected", they need to know it maps to
 *   T1190 (Exploit Public-Facing Application) in the
 *   Initial Access tactic. This enables:
 *     - Coverage gap analysis ("Which ATT&CK techniques am I blind to?")
 *     - Kill chain phase tracking per source ("This IP progressed
 *       from Reconnaissance to Initial Access")
 *     - Compliance reporting (ATT&CK coverage is a board metric)
 *
 * Data source: MITRE ATT&CK Enterprise v14 (Web Application subset)
 */

import type { InvariantClass } from './invariant-engine.js'

// ── MITRE ATT&CK Taxonomy ────────────────────────────────────────

export type MitreTactic =
    | 'reconnaissance'
    | 'resource_development'
    | 'initial_access'
    | 'execution'
    | 'persistence'
    | 'privilege_escalation'
    | 'defense_evasion'
    | 'credential_access'
    | 'discovery'
    | 'lateral_movement'
    | 'collection'
    | 'command_and_control'
    | 'exfiltration'
    | 'impact'

export interface MitreTechnique {
    id: string             // e.g., 'T1190'
    name: string           // e.g., 'Exploit Public-Facing Application'
    tactic: MitreTactic
    url: string            // MITRE reference URL
}

export interface MitreMapping {
    invariantClass: InvariantClass | string
    techniques: MitreTechnique[]
    /** Description of the mapping rationale */
    rationale: string
}


// ── Kill Chain Phase ─────────────────────────────────────────────

export type KillChainPhase = 'recon' | 'weaponize' | 'deliver' | 'exploit' | 'install' | 'c2' | 'actions'

const TACTIC_TO_KILLCHAIN: Record<MitreTactic, KillChainPhase> = {
    reconnaissance: 'recon',
    resource_development: 'weaponize',
    initial_access: 'deliver',
    execution: 'exploit',
    persistence: 'install',
    privilege_escalation: 'exploit',
    defense_evasion: 'deliver',
    credential_access: 'exploit',
    discovery: 'recon',
    lateral_movement: 'actions',
    collection: 'actions',
    command_and_control: 'c2',
    exfiltration: 'actions',
    impact: 'actions',
}


// ── Core Technique Database ──────────────────────────────────────

const T = (id: string, name: string, tactic: MitreTactic): MitreTechnique => ({
    id,
    name,
    tactic,
    url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`,
})

// Frequently referenced techniques
const T1190 = T('T1190', 'Exploit Public-Facing Application', 'initial_access')
const T1059 = T('T1059', 'Command and Scripting Interpreter', 'execution')
const T1059_004 = T('T1059.004', 'Unix Shell', 'execution')
const T1083 = T('T1083', 'File and Directory Discovery', 'discovery')
const T1005 = T('T1005', 'Data from Local System', 'collection')
const T1071 = T('T1071', 'Application Layer Protocol', 'command_and_control')
const T1557 = T('T1557', 'Adversary-in-the-Middle', 'credential_access')
const T1210 = T('T1210', 'Exploitation of Remote Services', 'lateral_movement')
const T1078 = T('T1078', 'Valid Accounts', 'privilege_escalation')
const T1018 = T('T1018', 'Remote System Discovery', 'discovery')
const T1595 = T('T1595', 'Active Scanning', 'reconnaissance')
const T1595_002 = T('T1595.002', 'Vulnerability Scanning', 'reconnaissance')
const T1592 = T('T1592', 'Gather Victim Host Information', 'reconnaissance')
const T1189 = T('T1189', 'Drive-by Compromise', 'initial_access')
const T1203 = T('T1203', 'Exploitation for Client Execution', 'execution')
const T1068 = T('T1068', 'Exploitation for Privilege Escalation', 'privilege_escalation')
const T1003 = T('T1003', 'OS Credential Dumping', 'credential_access')
const T1550 = T('T1550', 'Use Alternate Authentication Material', 'defense_evasion')
const T1550_001 = T('T1550.001', 'Application Access Token', 'defense_evasion')
const T1553 = T('T1553', 'Subvert Trust Controls', 'defense_evasion')
const T1499 = T('T1499', 'Endpoint Denial of Service', 'impact')
const T1498 = T('T1498', 'Network Denial of Service', 'impact')
const T1105 = T('T1105', 'Ingress Tool Transfer', 'command_and_control')
const T1046 = T('T1046', 'Network Service Discovery', 'discovery')
const T1552 = T('T1552', 'Unsecured Credentials', 'credential_access')
const T1070 = T('T1070', 'Indicator Removal', 'defense_evasion')
const T1195 = T('T1195', 'Supply Chain Compromise', 'initial_access')
const T1195_001 = T('T1195.001', 'Compromise Software Dependencies', 'initial_access')
const T1195_002 = T('T1195.002', 'Compromise Software Supply Chain', 'initial_access')
const T1059_007 = T('T1059.007', 'JavaScript', 'execution')
const T1040 = T('T1040', 'Network Sniffing', 'credential_access')
const T1185 = T('T1185', 'Browser Session Hijacking', 'collection')
const T1539 = T('T1539', 'Steal Web Session Cookie', 'credential_access')
const T1565 = T('T1565', 'Data Manipulation', 'impact')
const T1530 = T('T1530', 'Data from Cloud Storage', 'collection')
const T1119 = T('T1119', 'Automated Collection', 'collection')
const T1087 = T('T1087', 'Account Discovery', 'discovery')


// ── Invariant Class → MITRE Mapping ──────────────────────────────

const INVARIANT_MITRE_MAP: Record<string, MitreMapping> = {
    // SQL Injection (7 classes)
    sql_tautology: { invariantClass: 'sql_tautology', techniques: [T1190], rationale: 'Boolean-based blind SQLi exploits public-facing database interfaces' },
    sql_string_termination: { invariantClass: 'sql_string_termination', techniques: [T1190], rationale: 'String termination bypasses input validation to inject SQL' },
    sql_union_extraction: { invariantClass: 'sql_union_extraction', techniques: [T1190, T1005], rationale: 'UNION-based extraction exfiltrates database contents' },
    sql_stacked_execution: { invariantClass: 'sql_stacked_execution', techniques: [T1190, T1059], rationale: 'Stacked queries enable arbitrary command execution' },
    sql_time_oracle: { invariantClass: 'sql_time_oracle', techniques: [T1190], rationale: 'Time-based blind SQLi uses timing as a side channel' },
    sql_error_oracle: { invariantClass: 'sql_error_oracle', techniques: [T1190], rationale: 'Error-based SQLi uses error messages as data exfiltration channel' },
    sql_comment_truncation: { invariantClass: 'sql_comment_truncation', techniques: [T1190], rationale: 'Comment truncation bypasses authorization logic' },

    // XSS (5 classes)
    xss_tag_injection: { invariantClass: 'xss_tag_injection', techniques: [T1189, T1203], rationale: 'Script tag injection enables drive-by compromise and client execution' },
    xss_event_handler: { invariantClass: 'xss_event_handler', techniques: [T1189], rationale: 'Event handler XSS executes when user interacts with injected element' },
    xss_protocol_handler: { invariantClass: 'xss_protocol_handler', techniques: [T1189], rationale: 'javascript: protocol handler executes in page context' },
    xss_template_expression: { invariantClass: 'xss_template_expression', techniques: [T1189, T1059], rationale: 'Template expression injection can escalate to RCE via SSTI' },
    xss_attribute_escape: { invariantClass: 'xss_attribute_escape', techniques: [T1189], rationale: 'Attribute escape breaks out of HTML attribute context' },

    // Command Injection (3 classes)
    cmd_separator: { invariantClass: 'cmd_separator', techniques: [T1059, T1059_004], rationale: 'Shell metacharacter injection enables arbitrary command execution' },
    cmd_substitution: { invariantClass: 'cmd_substitution', techniques: [T1059, T1059_004], rationale: 'Subshell substitution $(cmd) executes in host context' },
    cmd_argument_injection: { invariantClass: 'cmd_argument_injection', techniques: [T1059], rationale: 'Argument injection manipulates command-line tool behavior' },

    // Path Traversal (4 classes)
    path_dotdot_escape: { invariantClass: 'path_dotdot_escape', techniques: [T1083, T1005], rationale: 'Directory traversal reads arbitrary files from the filesystem' },
    path_null_terminate: { invariantClass: 'path_null_terminate', techniques: [T1083], rationale: 'Null byte truncates filename extensions to bypass filters' },
    path_encoding_bypass: { invariantClass: 'path_encoding_bypass', techniques: [T1083], rationale: 'Encoding bypass evades path traversal filters' },
    path_normalization_bypass: { invariantClass: 'path_normalization_bypass', techniques: [T1083], rationale: 'Path normalization differences between parser and filesystem' },

    // SSRF (3 classes)
    ssrf_internal_reach: { invariantClass: 'ssrf_internal_reach', techniques: [T1210, T1018], rationale: 'SSRF accesses internal network resources from the application' },
    ssrf_cloud_metadata: { invariantClass: 'ssrf_cloud_metadata', techniques: [T1552, T1003], rationale: 'Cloud metadata SSRF extracts IAM credentials from instance metadata service' },
    ssrf_protocol_smuggle: { invariantClass: 'ssrf_protocol_smuggle', techniques: [T1071], rationale: 'Protocol smuggling accesses non-HTTP internal services' },

    // SSTI (2 classes)
    ssti_jinja_twig: { invariantClass: 'ssti_jinja_twig', techniques: [T1059, T1190], rationale: 'Jinja2/Twig SSTI enables arbitrary Python/PHP code execution' },
    ssti_el_expression: { invariantClass: 'ssti_el_expression', techniques: [T1059, T1190], rationale: 'Expression Language injection enables arbitrary Java execution' },

    // NoSQL (2 classes)
    nosql_operator_injection: { invariantClass: 'nosql_operator_injection', techniques: [T1190], rationale: 'MongoDB operator injection bypasses authentication and exfiltrates data' },
    nosql_js_injection: { invariantClass: 'nosql_js_injection', techniques: [T1190, T1059], rationale: 'Server-side JavaScript injection in NoSQL databases' },

    // XXE (1 class)
    xxe_entity_expansion: { invariantClass: 'xxe_entity_expansion', techniques: [T1190, T1005], rationale: 'XML external entity reads local files and performs SSRF' },

    // Auth (4 classes)
    auth_none_algorithm: { invariantClass: 'auth_none_algorithm', techniques: [T1550, T1550_001], rationale: 'JWT alg:none bypass forges authentication tokens' },
    auth_header_spoof: { invariantClass: 'auth_header_spoof', techniques: [T1078, T1553], rationale: 'Forwarding header spoofing bypasses IP-based access controls' },
    cors_origin_abuse: { invariantClass: 'cors_origin_abuse', techniques: [T1189], rationale: 'CORS misconfiguration allows cross-origin credential theft' },
    mass_assignment: { invariantClass: 'mass_assignment', techniques: [T1068], rationale: 'Mass assignment escalates privileges by setting admin fields' },

    // Deserialization (3 classes)
    deser_java_gadget: { invariantClass: 'deser_java_gadget', techniques: [T1059, T1190], rationale: 'Java deserialization gadget chains enable RCE' },
    deser_php_object: { invariantClass: 'deser_php_object', techniques: [T1059, T1190], rationale: 'PHP object injection via unserialize()' },
    deser_python_pickle: { invariantClass: 'deser_python_pickle', techniques: [T1059, T1190], rationale: 'Python pickle deserialization executes arbitrary __reduce__' },

    // CRLF (2 classes)
    crlf_header_injection: { invariantClass: 'crlf_header_injection', techniques: [T1557], rationale: 'CRLF injection manipulates HTTP response headers' },
    crlf_log_injection: { invariantClass: 'crlf_log_injection', techniques: [T1070], rationale: 'Log injection forges log entries to cover tracks' },

    // HTTP Smuggling (2 classes)
    http_smuggle_cl_te: { invariantClass: 'http_smuggle_cl_te', techniques: [T1557, T1190], rationale: 'CL.TE desync enables request smuggling through proxy chains' },
    http_smuggle_h2: { invariantClass: 'http_smuggle_h2', techniques: [T1557], rationale: 'H2.CL downgrade attack exploits HTTP/2 to HTTP/1.1 conversion' },

    // Log4Shell (1 class)
    log_jndi_lookup: { invariantClass: 'log_jndi_lookup', techniques: [T1190, T1059, T1105], rationale: 'JNDI lookup enables remote class loading and RCE' },

    // Prototype Pollution (1 class)
    proto_pollution: { invariantClass: 'proto_pollution', techniques: [T1068, T1190], rationale: 'Prototype pollution modifies Object.prototype to escalate privileges' },

    // Open Redirect (1 class)
    open_redirect_bypass: { invariantClass: 'open_redirect_bypass', techniques: [T1189], rationale: 'Open redirect chains with phishing for credential theft' },

    // LDAP (1 class)
    ldap_filter_injection: { invariantClass: 'ldap_filter_injection', techniques: [T1190, T1078], rationale: 'LDAP filter injection bypasses authentication and extracts directory data' },

    // GraphQL (2 classes)
    graphql_introspection: { invariantClass: 'graphql_introspection', techniques: [T1046, T1592], rationale: 'GraphQL introspection reveals entire API schema' },
    graphql_batch_abuse: { invariantClass: 'graphql_batch_abuse', techniques: [T1499], rationale: 'GraphQL batch/nested queries cause denial of service' },

    // ReDoS (1 class)
    regex_dos: { invariantClass: 'regex_dos', techniques: [T1499], rationale: 'Catastrophic regex backtracking causes CPU exhaustion' },

    // HTTP Smuggling extensions (3 classes)
    http_smuggle_chunk_ext: { invariantClass: 'http_smuggle_chunk_ext', techniques: [T1557, T1190], rationale: 'Chunk extension smuggling exploits HTTP/1.1 chunked encoding parser differences' },
    http_smuggle_zero_cl: { invariantClass: 'http_smuggle_zero_cl', techniques: [T1557], rationale: 'Zero Content-Length smuggling exploits edge cases in request body parsing' },
    http_smuggle_expect: { invariantClass: 'http_smuggle_expect', techniques: [T1557], rationale: 'Expect header smuggling exploits 100-Continue handling differences' },

    // JSON-SQL WAF Bypass (1 class)
    json_sql_bypass: { invariantClass: 'json_sql_bypass', techniques: [T1190], rationale: 'JSON-wrapped SQL payloads bypass WAF signature matching' },

    // Prototype Pollution Gadget (1 class)
    proto_pollution_gadget: { invariantClass: 'proto_pollution_gadget', techniques: [T1068, T1059_007], rationale: 'Prototype pollution gadget chains escalate to RCE via known library sink' },

    // XML Injection (1 class)
    xml_injection: { invariantClass: 'xml_injection', techniques: [T1190], rationale: 'XML injection modifies document structure to bypass access controls' },

    // Supply Chain (3 classes)
    dependency_confusion: { invariantClass: 'dependency_confusion', techniques: [T1195, T1195_001], rationale: 'Dependency confusion substitutes public package for private one via version priority' },
    postinstall_injection: { invariantClass: 'postinstall_injection', techniques: [T1195_002, T1059], rationale: 'Package postinstall scripts execute arbitrary code during npm/pip install' },
    env_exfiltration: { invariantClass: 'env_exfiltration', techniques: [T1552, T1005], rationale: 'Environment variable exfiltration steals credentials from process env' },

    // LLM Injection (3 classes)
    llm_prompt_injection: { invariantClass: 'llm_prompt_injection', techniques: [T1190, T1059], rationale: 'Prompt injection overrides LLM system instructions to alter behavior' },
    llm_data_exfiltration: { invariantClass: 'llm_data_exfiltration', techniques: [T1005, T1119], rationale: 'LLM data exfiltration extracts training data or system prompts' },
    llm_jailbreak: { invariantClass: 'llm_jailbreak', techniques: [T1553], rationale: 'LLM jailbreak bypasses safety controls to enable harmful outputs' },

    // WebSocket (2 classes)
    ws_injection: { invariantClass: 'ws_injection', techniques: [T1190, T1059_007], rationale: 'WebSocket message injection exploits bidirectional channel for code execution' },
    ws_hijack: { invariantClass: 'ws_hijack', techniques: [T1185, T1557], rationale: 'WebSocket hijacking takes over established connections for session theft' },

    // JWT Abuse (3 classes)
    jwt_kid_injection: { invariantClass: 'jwt_kid_injection', techniques: [T1550, T1550_001, T1190], rationale: 'JWT kid parameter injection enables path traversal, SQLi, or command injection in key lookup' },
    jwt_jwk_embedding: { invariantClass: 'jwt_jwk_embedding', techniques: [T1550, T1550_001], rationale: 'Embedded JWK in JWT header provides attacker-controlled signing key' },
    jwt_confusion: { invariantClass: 'jwt_confusion', techniques: [T1550, T1550_001], rationale: 'Algorithm confusion attack uses public key as HMAC secret to forge tokens' },

    // Cache Attacks (2 classes)
    cache_poisoning: { invariantClass: 'cache_poisoning', techniques: [T1557, T1565], rationale: 'Cache poisoning serves malicious content to all users via unkeyed headers' },
    cache_deception: { invariantClass: 'cache_deception', techniques: [T1539, T1530], rationale: 'Cache deception tricks CDN into caching sensitive user-specific responses' },

    // API Logic Abuse (2 classes)
    bola_idor: { invariantClass: 'bola_idor', techniques: [T1078, T1087], rationale: 'Broken object-level authorization allows accessing other users resources' },
    api_mass_enum: { invariantClass: 'api_mass_enum', techniques: [T1119, T1087], rationale: 'Mass API enumeration extracts all records via sequential ID or filter bypass' },
}

// T1552 and T1070 declared above the map where they are referenced


// ── Behavioral Signal → MITRE Mapping ────────────────────────────

const BEHAVIORAL_MITRE_MAP: Record<string, MitreTechnique[]> = {
    rate_anomaly: [T1498],
    path_enumeration: [T1595, T1595_002],
    method_probing: [T1595],
    unusual_method: [T1595],
    scanner_detected: [T1595_002],
    high_error_rate: [T1595_002],
}


// ── MITRE Mapper ─────────────────────────────────────────────────

export class MitreMapper {
    /**
     * Get ATT&CK techniques for an invariant class.
     */
    getTechniques(cls: InvariantClass | string): MitreTechnique[] {
        return INVARIANT_MITRE_MAP[cls]?.techniques ?? []
    }

    /**
     * Get ATT&CK techniques for a behavioral signal.
     */
    getBehavioralTechniques(behavior: string): MitreTechnique[] {
        return BEHAVIORAL_MITRE_MAP[behavior] ?? []
    }

    /**
     * Get the kill chain phase for a MITRE tactic.
     */
    getKillChainPhase(tactic: MitreTactic): KillChainPhase {
        return TACTIC_TO_KILLCHAIN[tactic]
    }

    /**
     * Get the dominant kill chain phase for a set of detections.
     * Shows where the attacker is in the attack lifecycle.
     */
    getAttackPhase(classes: (InvariantClass | string)[], behaviors: string[]): KillChainPhase {
        const phaseCount = new Map<KillChainPhase, number>()

        for (const cls of classes) {
            for (const tech of this.getTechniques(cls)) {
                const phase = this.getKillChainPhase(tech.tactic)
                phaseCount.set(phase, (phaseCount.get(phase) ?? 0) + 1)
            }
        }

        for (const beh of behaviors) {
            for (const tech of this.getBehavioralTechniques(beh)) {
                const phase = this.getKillChainPhase(tech.tactic)
                phaseCount.set(phase, (phaseCount.get(phase) ?? 0) + 1)
            }
        }

        let maxPhase: KillChainPhase = 'recon'
        let maxCount = 0
        for (const [phase, count] of phaseCount) {
            if (count > maxCount) {
                maxCount = count
                maxPhase = phase
            }
        }

        return maxPhase
    }

    /**
     * Get full ATT&CK coverage report for INVARIANT.
     * Returns which techniques are covered and which are not.
     */
    getCoverageReport(): {
        coveredTechniques: MitreTechnique[]
        coveredCount: number
        totalMappedClasses: number
        tacticDistribution: Record<MitreTactic, number>
    } {
        const seen = new Map<string, MitreTechnique>()
        const tacticDist: Record<string, number> = {}

        for (const mapping of Object.values(INVARIANT_MITRE_MAP)) {
            for (const tech of mapping.techniques) {
                seen.set(tech.id, tech)
                tacticDist[tech.tactic] = (tacticDist[tech.tactic] ?? 0) + 1
            }
        }

        return {
            coveredTechniques: [...seen.values()],
            coveredCount: seen.size,
            totalMappedClasses: Object.keys(INVARIANT_MITRE_MAP).length,
            tacticDistribution: tacticDist as Record<MitreTactic, number>,
        }
    }

    /**
     * Get the mapping for all invariant classes.
     */
    getAllMappings(): MitreMapping[] {
        return Object.values(INVARIANT_MITRE_MAP)
    }

    /**
     * Get MITRE technique IDs for signal enrichment.
     * Used to decorate signals with ATT&CK metadata.
     */
    enrichSignal(classes: (InvariantClass | string)[], behaviors: string[]): {
        techniqueIds: string[]
        tactics: MitreTactic[]
        killChainPhase: KillChainPhase
    } {
        const techniqueIds = new Set<string>()
        const tactics = new Set<MitreTactic>()

        for (const cls of classes) {
            for (const tech of this.getTechniques(cls)) {
                techniqueIds.add(tech.id)
                tactics.add(tech.tactic)
            }
        }

        for (const beh of behaviors) {
            for (const tech of this.getBehavioralTechniques(beh)) {
                techniqueIds.add(tech.id)
                tactics.add(tech.tactic)
            }
        }

        return {
            techniqueIds: [...techniqueIds],
            tactics: [...tactics],
            killChainPhase: this.getAttackPhase(classes, behaviors),
        }
    }

    /**
     * Map detection matches directly to MITRE technique IDs.
     * Convenience for the unified runtime.
     */
    mapDetections(matches: Array<{ class: string }>): string[] {
        const ids = new Set<string>()
        for (const m of matches) {
            for (const tech of this.getTechniques(m.class)) {
                ids.add(tech.id)
            }
        }
        return [...ids]
    }
}

