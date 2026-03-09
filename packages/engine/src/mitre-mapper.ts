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
const T1056 = T('T1056', 'Input Capture', 'credential_access')
const T1566 = T('T1566', 'Phishing', 'initial_access')
const T1059_004 = T('T1059.004', 'Unix Shell', 'execution')
const T1083 = T('T1083', 'File and Directory Discovery', 'discovery')
const T1005 = T('T1005', 'Data from Local System', 'collection')
const T1071 = T('T1071', 'Application Layer Protocol', 'command_and_control')
const T1071_004 = T('T1071.004', 'DNS', 'command_and_control')
const T1557 = T('T1557', 'Adversary-in-the-Middle', 'credential_access')
const T1210 = T('T1210', 'Exploitation of Remote Services', 'lateral_movement')
const T1078 = T('T1078', 'Valid Accounts', 'privilege_escalation')
const T1018 = T('T1018', 'Remote System Discovery', 'discovery')
const T1595 = T('T1595', 'Active Scanning', 'reconnaissance')
const T1595_002 = T('T1595.002', 'Vulnerability Scanning', 'reconnaissance')
const T1592 = T('T1592', 'Gather Victim Host Information', 'reconnaissance')
const T1592_002 = T('T1592.002', 'Software', 'reconnaissance')
const T1590 = T('T1590', 'Gather Victim Network Information', 'reconnaissance')
const T1189 = T('T1189', 'Drive-by Compromise', 'initial_access')
const T1203 = T('T1203', 'Exploitation for Client Execution', 'execution')
const T1068 = T('T1068', 'Exploitation for Privilege Escalation', 'privilege_escalation')
const T1611 = T('T1611', 'Escape to Host', 'privilege_escalation')
const T1003 = T('T1003', 'OS Credential Dumping', 'credential_access')
const T1550 = T('T1550', 'Use Alternate Authentication Material', 'defense_evasion')
const T1550_001 = T('T1550.001', 'Application Access Token', 'defense_evasion')
const T1553 = T('T1553', 'Subvert Trust Controls', 'defense_evasion')
const T1499 = T('T1499', 'Endpoint Denial of Service', 'impact')
const T1498 = T('T1498', 'Network Denial of Service', 'impact')
const T1027 = T('T1027', 'Obfuscated Files or Information', 'defense_evasion')
const T1105 = T('T1105', 'Ingress Tool Transfer', 'command_and_control')
const T1046 = T('T1046', 'Network Service Discovery', 'discovery')
const T1552 = T('T1552', 'Unsecured Credentials', 'credential_access')
const T1552_001 = T('T1552.001', 'Credentials In Files', 'credential_access')
const T1552_004 = T('T1552.004', 'Private Keys', 'credential_access')
const T1070 = T('T1070', 'Indicator Removal', 'defense_evasion')
const T1195 = T('T1195', 'Supply Chain Compromise', 'initial_access')
const T1195_001 = T('T1195.001', 'Compromise Software Dependencies', 'initial_access')
const T1195_002 = T('T1195.002', 'Compromise Software Supply Chain', 'initial_access')
const T1059_007 = T('T1059.007', 'JavaScript', 'execution')
const T1040 = T('T1040', 'Network Sniffing', 'credential_access')
const T1185 = T('T1185', 'Browser Session Hijacking', 'collection')
const T1539 = T('T1539', 'Steal Web Session Cookie', 'credential_access')
const T1565 = T('T1565', 'Data Manipulation', 'impact')
const T1562_006 = T('T1562.006', 'Indicator Removal on Host: Timestomp', 'defense_evasion')
const T1530 = T('T1530', 'Data from Cloud Storage', 'collection')
const T1119 = T('T1119', 'Automated Collection', 'collection')
const T1087 = T('T1087', 'Account Discovery', 'discovery')
const T1110_004 = T('T1110.004', 'Credential Stuffing', 'credential_access')
const T1110_001 = T('T1110.001', 'Password Guessing', 'credential_access')
const T1110_003 = T('T1110.003', 'Password Spraying', 'credential_access')
const T1550_004 = T('T1550.004', 'Web Session Cookie', 'defense_evasion')
const T1528 = T('T1528', 'Steal Application Access Token', 'credential_access')
const T1584_001 = T('T1584.001', 'Domains', 'resource_development')
const T1566_002 = T('T1566.002', 'Spearphishing Link', 'initial_access')


// ── Invariant Class → MITRE Mapping ──────────────────────────────

const INVARIANT_MITRE_MAP: Record<string, MitreMapping> = {
    // SQL Injection (12 classes)
    sql_tautology: { invariantClass: 'sql_tautology', techniques: [T1190], rationale: 'Boolean-based blind SQLi exploits public-facing database interfaces' },
    sql_string_termination: { invariantClass: 'sql_string_termination', techniques: [T1190], rationale: 'String termination bypasses input validation to inject SQL' },
    sql_union_extraction: { invariantClass: 'sql_union_extraction', techniques: [T1190, T1005], rationale: 'UNION-based extraction exfiltrates database contents' },
    sql_stacked_execution: { invariantClass: 'sql_stacked_execution', techniques: [T1190, T1059], rationale: 'Stacked queries enable arbitrary command execution' },
    sql_time_oracle: { invariantClass: 'sql_time_oracle', techniques: [T1190], rationale: 'Time-based blind SQLi uses timing as a side channel' },
    sql_error_oracle: { invariantClass: 'sql_error_oracle', techniques: [T1190], rationale: 'Error-based SQLi uses error messages as data exfiltration channel' },
    sql_comment_truncation: { invariantClass: 'sql_comment_truncation', techniques: [T1190], rationale: 'Comment truncation bypasses authorization logic' },
    sql_second_order: { invariantClass: 'sql_second_order', techniques: [T1190], rationale: 'Second-order SQLi stores malicious data then executes it in later queries' },
    sql_out_of_band: { invariantClass: 'sql_out_of_band', techniques: [T1071_004, T1071, T1105], rationale: 'Out-of-band SQLi channels database exfiltration through DNS/HTTP network callbacks' },
    sql_lateral_movement: { invariantClass: 'sql_lateral_movement', techniques: [T1068, T1078], rationale: 'SQL privilege escalation and account hardening abuse for lateral movement' },
    sql_ddl_injection: { invariantClass: 'sql_ddl_injection', techniques: [T1565, T1190], rationale: 'DDL statements injected through SQL context destroy or alter schema and data stores' },
    sql_mysql_specific: { invariantClass: 'sql_mysql_specific', techniques: [T1190], rationale: 'MySQL-specific primitive attacks using advanced SQL functions and optimizer behaviors' },

    // XSS (5 classes)
    xss_tag_injection: { invariantClass: 'xss_tag_injection', techniques: [T1189, T1203], rationale: 'Script tag injection enables drive-by compromise and client execution' },
    xss_event_handler: { invariantClass: 'xss_event_handler', techniques: [T1189], rationale: 'Event handler XSS executes when user interacts with injected element' },
    xss_protocol_handler: { invariantClass: 'xss_protocol_handler', techniques: [T1189], rationale: 'javascript: protocol handler executes in page context' },
    xss_template_expression: { invariantClass: 'xss_template_expression', techniques: [T1189, T1059], rationale: 'Template expression injection can escalate to RCE via SSTI' },
    xss_attribute_escape: { invariantClass: 'xss_attribute_escape', techniques: [T1189], rationale: 'Attribute escape breaks out of HTML attribute context' },
    dom_xss: { invariantClass: 'dom_xss', techniques: [T1189, T1059_007], rationale: 'DOM-based XSS executes attacker-controlled JavaScript via client-side sink usage' },
    angularjs_sandbox_escape: { invariantClass: 'angularjs_sandbox_escape', techniques: [T1189, T1059_007], rationale: 'AngularJS expression sandbox bypasses enable arbitrary JavaScript execution in browser context' },
    css_injection: { invariantClass: 'css_injection', techniques: [T1059, T1185], rationale: 'CSS injection exfiltrates data via attribute selectors or executes code via expression()/behavior:' },

    // Command Injection (3 classes)
    cmd_separator: { invariantClass: 'cmd_separator', techniques: [T1059, T1059_004], rationale: 'Shell metacharacter injection enables arbitrary command execution' },
    cmd_substitution: { invariantClass: 'cmd_substitution', techniques: [T1059, T1059_004], rationale: 'Subshell substitution $(cmd) executes in host context' },
    cmd_argument_injection: { invariantClass: 'cmd_argument_injection', techniques: [T1059], rationale: 'Argument injection manipulates command-line tool behavior' },

    // Path Traversal (5 classes)
    path_dotdot_escape: { invariantClass: 'path_dotdot_escape', techniques: [T1083, T1005], rationale: 'Directory traversal reads arbitrary files from the filesystem' },
    path_null_terminate: { invariantClass: 'path_null_terminate', techniques: [T1083], rationale: 'Null byte truncates filename extensions to bypass filters' },
    path_encoding_bypass: { invariantClass: 'path_encoding_bypass', techniques: [T1083], rationale: 'Encoding bypass evades path traversal filters' },
    path_normalization_bypass: { invariantClass: 'path_normalization_bypass', techniques: [T1083], rationale: 'Path normalization differences between parser and filesystem' },
    path_windows_traversal: { invariantClass: 'path_windows_traversal', techniques: [T1083, T1005], rationale: 'Windows-specific traversal and path injection can expose sensitive local and network files' },

    // SSRF (3 classes)
    ssrf_internal_reach: { invariantClass: 'ssrf_internal_reach', techniques: [T1210, T1018], rationale: 'SSRF accesses internal network resources from the application' },
    ssrf_cloud_metadata: { invariantClass: 'ssrf_cloud_metadata', techniques: [T1552, T1003], rationale: 'Cloud metadata SSRF extracts IAM credentials from instance metadata service' },
    ssrf_protocol_smuggle: { invariantClass: 'ssrf_protocol_smuggle', techniques: [T1071], rationale: 'Protocol smuggling accesses non-HTTP internal services' },

    // SSTI (2 classes)
    ssti_jinja_twig: { invariantClass: 'ssti_jinja_twig', techniques: [T1059, T1190], rationale: 'Jinja2/Twig SSTI enables arbitrary Python/PHP code execution' },
    ssti_el_expression: { invariantClass: 'ssti_el_expression', techniques: [T1059, T1190], rationale: 'Expression Language injection enables arbitrary Java execution' },
    template_injection_generic: { invariantClass: 'template_injection_generic', techniques: [T1190], rationale: 'Generic template syntax abuse (ERB/Mako/Velocity/FreeMarker/etc.) enables server-side expression execution' },

    // NoSQL (2 classes)
    nosql_operator_injection: { invariantClass: 'nosql_operator_injection', techniques: [T1190], rationale: 'MongoDB operator injection bypasses authentication and exfiltrates data' },
    nosql_js_injection: { invariantClass: 'nosql_js_injection', techniques: [T1190, T1059], rationale: 'Server-side JavaScript injection in NoSQL databases' },

    // XXE (1 class)
    xxe_entity_expansion: { invariantClass: 'xxe_entity_expansion', techniques: [T1190, T1005], rationale: 'XML external entity reads local files and performs SSRF' },
    xxe_injection: { invariantClass: 'xxe_injection', techniques: [T1190, T1005], rationale: 'Legacy XXE alias: external entities can read local files and trigger SSRF' },

    // Auth (extended classes)
    auth_none_algorithm: { invariantClass: 'auth_none_algorithm', techniques: [T1550, T1550_001], rationale: 'JWT alg:none bypass forges authentication tokens' },
    auth_header_spoof: { invariantClass: 'auth_header_spoof', techniques: [T1078, T1553], rationale: 'Forwarding header spoofing bypasses IP-based access controls' },
    jwt_weak_hmac_secret: { invariantClass: 'jwt_weak_hmac_secret', techniques: [T1550, T1550_001], rationale: 'Weak/default HMAC secrets enable JWT signature forgery' },
    jwt_weak_secret: { invariantClass: 'jwt_weak_secret', techniques: [T1552_004], rationale: 'Weak HS* JWT secrets allow token forging with guessed signing material' },
    jwt_missing_expiry: { invariantClass: 'jwt_missing_expiry', techniques: [T1550_001], rationale: 'JWT tokens without exp are replayable across long windows' },
    jwt_privilege_escalation: { invariantClass: 'jwt_privilege_escalation', techniques: [T1078, T1068], rationale: 'Manipulated JWT claims escalate privileges to admin contexts' },
    oauth_token_leak: { invariantClass: 'oauth_token_leak', techniques: [T1528], rationale: 'OAuth access tokens leaked in query strings or referrers are replayable by attackers' },
    oauth_state_missing: { invariantClass: 'oauth_state_missing', techniques: [T1550_001], rationale: 'Missing or weak OAuth state enables callback CSRF and authorization response injection' },
    oauth_redirect_hijack: { invariantClass: 'oauth_redirect_hijack', techniques: [T1550_001], rationale: 'OAuth redirect_uri open redirects can steal tokens via attacker-controlled callback destinations' },
    oauth_redirect_uri_bypass: { invariantClass: 'oauth_redirect_uri_bypass', techniques: [T1550_001], rationale: 'redirect_uri bypass enables OAuth token theft via attacker-controlled callback destinations' },
    oauth_redirect_manipulation: { invariantClass: 'oauth_redirect_manipulation', techniques: [T1550_001, T1528], rationale: 'OAuth redirect_uri manipulation bypasses allowlists to redirect authorization codes to attacker servers' },
    oauth_state_bypass: { invariantClass: 'oauth_state_bypass', techniques: [T1550_001, T1185], rationale: 'Weak or missing OAuth state parameters allow CSRF-based token injection and account takeover' },
    saml_signature_wrapping: { invariantClass: 'saml_signature_wrapping', techniques: [T1550_001], rationale: 'SAML signature wrapping abuses alternate assertions while preserving valid signatures' },
    jwt_algorithm_confusion: { invariantClass: 'jwt_algorithm_confusion', techniques: [T1550, T1550_001], rationale: 'Algorithm confusion downgrades asymmetric JWT validation into symmetric forging paths' },
    mfa_bypass_indicator: { invariantClass: 'mfa_bypass_indicator', techniques: [T1110_001], rationale: 'Weak OTP/TOTP patterns indicate brute-force style MFA bypass attempts' },
    oidc_nonce_replay: { invariantClass: 'oidc_nonce_replay', techniques: [T1550_001], rationale: 'Weak/replayed OIDC nonce values enable login response replay and CSRF-like attacks' },
    session_fixation: { invariantClass: 'session_fixation', techniques: [T1550_004], rationale: 'Session fixation reuses attacker-selected session tokens across login transitions' },
    pkce_downgrade: { invariantClass: 'pkce_downgrade', techniques: [T1550_001], rationale: 'PKCE downgrade or missing challenge weakens OAuth authorization-code protections' },
    bearer_token_exposure: { invariantClass: 'bearer_token_exposure', techniques: [T1528], rationale: 'Bearer/access tokens leaking in URLs, referrers, and logs can be replayed by attackers' },
    password_spray_indicator: { invariantClass: 'password_spray_indicator', techniques: [T1110_003], rationale: 'Common password attempts across login events indicate password spraying activity' },
    credential_stuffing: { invariantClass: 'credential_stuffing', techniques: [T1110_004], rationale: 'Automated high-volume credential pair attempts indicate credential stuffing attacks' },
    cors_origin_abuse: { invariantClass: 'cors_origin_abuse', techniques: [T1189], rationale: 'CORS misconfiguration allows cross-origin credential theft' },
    cors_origin_misconfiguration: { invariantClass: 'cors_origin_misconfiguration', techniques: [T1189], rationale: 'Overly permissive CORS origin handling allows attacker-controlled origins to read sensitive responses' },
    mass_assignment: { invariantClass: 'mass_assignment', techniques: [T1068], rationale: 'Mass assignment escalates privileges by setting admin fields' },
    price_manipulation: { invariantClass: 'price_manipulation', techniques: [T1565], rationale: 'Negative/zero/tiny price fields and invalid discount amplification indicate transaction value tampering' },
    idor_parameter_probe: { invariantClass: 'idor_parameter_probe', techniques: [T1087, T1190], rationale: 'Sequential object ID probing and ID parameter abuse indicate broken object authorization discovery attempts' },
    http2_header_injection: { invariantClass: 'http2_header_injection', techniques: [T1557], rationale: 'HTTP/2 pseudo-header smuggling and injection patterns target parser/proxy trust boundaries' },
    websocket_protocol_confusion: { invariantClass: 'websocket_protocol_confusion', techniques: [T1185, T1557], rationale: 'WebSocket subprotocol confusion and smuggling can hijack session flows across protocol boundaries' },

    // Deserialization (3 classes)
    deser_java_gadget: { invariantClass: 'deser_java_gadget', techniques: [T1059, T1190], rationale: 'Java deserialization gadget chains enable RCE' },
    deser_php_object: { invariantClass: 'deser_php_object', techniques: [T1059, T1190], rationale: 'PHP object injection via unserialize()' },
    deser_python_pickle: { invariantClass: 'deser_python_pickle', techniques: [T1059, T1190], rationale: 'Python pickle deserialization executes arbitrary __reduce__' },
    yaml_deserialization: { invariantClass: 'yaml_deserialization', techniques: [T1059, T1190], rationale: 'YAML gadget-based deserialization (SnakeYAML/Psych/PyYAML style) enables RCE' },

    // CRLF (2 classes)
    crlf_header_injection: { invariantClass: 'crlf_header_injection', techniques: [T1557], rationale: 'CRLF injection manipulates HTTP response headers' },
    crlf_log_injection: { invariantClass: 'crlf_log_injection', techniques: [T1562_006], rationale: 'Log injection forges or tampers indicators to evade detection' },

    // HTTP Smuggling (2 classes)
    http_smuggle_cl_te: { invariantClass: 'http_smuggle_cl_te', techniques: [T1557, T1190], rationale: 'CL.TE desync enables request smuggling through proxy chains' },
    http_smuggle_h2: { invariantClass: 'http_smuggle_h2', techniques: [T1557], rationale: 'H2.CL downgrade attack exploits HTTP/2 to HTTP/1.1 conversion' },
    http_smuggling: { invariantClass: 'http_smuggling', techniques: [T1557, T1190], rationale: 'Legacy HTTP smuggling alias: parser differentials create proxy/backend request desynchronization' },
    http_request_smuggling: { invariantClass: 'http_request_smuggling', techniques: [T1557, T1190], rationale: 'CL.TE/TE.CL and chunk framing ambiguities cause frontend/backend desynchronization' },

    // Log4Shell (1 class)
    log_jndi_lookup: { invariantClass: 'log_jndi_lookup', techniques: [T1190, T1059, T1105], rationale: 'JNDI lookup enables remote class loading and RCE' },

    // Prototype Pollution (1 class)
    proto_pollution: { invariantClass: 'proto_pollution', techniques: [T1068, T1190], rationale: 'Prototype pollution modifies Object.prototype to escalate privileges' },
    prototype_pollution_via_query: { invariantClass: 'prototype_pollution_via_query', techniques: [T1068, T1190], rationale: 'Query-string prototype path injection reaches __proto__ or constructor.prototype in parser merge flows' },

    // Open Redirect (1 class)
    open_redirect_bypass: { invariantClass: 'open_redirect_bypass', techniques: [T1189], rationale: 'Open redirect chains with phishing for credential theft' },

    // LDAP (1 class)
    ldap_filter_injection: { invariantClass: 'ldap_filter_injection', techniques: [T1190, T1078], rationale: 'LDAP filter injection bypasses authentication and extracts directory data' },

    // GraphQL (2 classes)
    graphql_introspection: { invariantClass: 'graphql_introspection', techniques: [T1046, T1592], rationale: 'GraphQL introspection reveals entire API schema' },
    graphql_batch_abuse: { invariantClass: 'graphql_batch_abuse', techniques: [T1499], rationale: 'GraphQL batch/nested queries cause denial of service' },
    graphql_injection: { invariantClass: 'graphql_injection', techniques: [T1190, T1046], rationale: 'GraphQL probing and introspection abuse exploit public API query surfaces for schema and data discovery' },
    graphql_dos: { invariantClass: 'graphql_dos', techniques: [T1499], rationale: 'Extreme GraphQL depth, fragment cycles, and alias bombs exhaust resolver and application resources' },
    graphql_depth_attack: { invariantClass: 'graphql_depth_attack', techniques: [T1499], rationale: 'Deep nested GraphQL selections and circular fragment chains can exhaust resolver and application resources' },
    compression_bomb: { invariantClass: 'compression_bomb', techniques: [T1499], rationale: 'Nested compression declarations and oversized compressed payload indicators can trigger resource exhaustion' },
    http2_pseudo_header_injection: { invariantClass: 'http2_pseudo_header_injection', techniques: [T1557], rationale: 'Malformed HTTP/2 pseudo-headers can cause protocol desynchronization and parser abuse' },

    // ReDoS (1 class)
    regex_dos: { invariantClass: 'regex_dos', techniques: [T1499], rationale: 'Catastrophic regex backtracking causes CPU exhaustion' },
    race_condition_probe: { invariantClass: 'race_condition_probe', techniques: [T1190, T1499], rationale: 'Concurrent duplicate request attempts target race windows and application-layer resource contention' },
    redos_payload: { invariantClass: 'redos_payload', techniques: [T1499], rationale: 'Nested-quantifier and long-run regex inputs trigger catastrophic backtracking DoS' },
    http_desync_attack: { invariantClass: 'http_desync_attack', techniques: [T1557, T1190], rationale: 'Header confusion and malformed chunk framing create frontend/backend request desynchronization' },
    cache_deception_attack: { invariantClass: 'cache_deception_attack', techniques: [T1539, T1557], rationale: 'Sensitive dynamic routes disguised as static assets can be cached and exposed to other users' },
    parameter_pollution_advanced: { invariantClass: 'parameter_pollution_advanced', techniques: [T1190], rationale: 'Repeated/ambiguous parameters exploit parser differentials in authorization and routing logic' },

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
    xml_bomb_dos: { invariantClass: 'xml_bomb_dos', techniques: [T1499], rationale: 'Entity expansion bomb payloads exhaust parser memory/CPU and cause application-layer DoS' },

    // HTTP Method Abuse (4 classes)
    http_verb_tampering: { invariantClass: 'http_verb_tampering', techniques: [T1190], rationale: 'HTTP verb override/tampering bypasses method-based authorization controls' },
    webdav_method_abuse: { invariantClass: 'webdav_method_abuse', techniques: [T1190], rationale: 'Dangerous WebDAV methods expand exposed attack surface on public-facing apps' },
    trace_xst_attack: { invariantClass: 'trace_xst_attack', techniques: [T1185], rationale: 'TRACE/XST probing can expose session material and enable browser session abuse' },
    response_header_injection: { invariantClass: 'response_header_injection', techniques: [T1557], rationale: 'Header injection via CRLF/control separators manipulates downstream HTTP response handling' },

    // Network / C2 Indicators (2 classes)
    dns_tunneling_indicator: { invariantClass: 'dns_tunneling_indicator', techniques: [T1071_004], rationale: 'Long/high-entropy DNS query patterns are consistent with DNS-based C2 tunneling' },
    c2_beacon_indicator: { invariantClass: 'c2_beacon_indicator', techniques: [T1071], rationale: 'Regular beacon-like callback patterns indicate command-and-control traffic' },

    // Container / Platform Escape (1 class)
    container_escape_indicator: { invariantClass: 'container_escape_indicator', techniques: [T1611, T1068], rationale: 'Host breakout primitives from containerized workloads indicate escape and privilege escalation attempts' },
    log4shell_variant: { invariantClass: 'log4shell_variant', techniques: [T1190, T1059, T1105], rationale: 'Obfuscated JNDI lookup variants preserve Log4Shell-style remote class loading and execution paths' },
    spring4shell: { invariantClass: 'spring4shell', techniques: [T1190, T1059], rationale: 'Spring4Shell class.module binder abuse enables writing JSP webshells and server-side command execution' },
    spring_expression_injection: { invariantClass: 'spring_expression_injection', techniques: [T1190, T1059], rationale: 'SpEL injection evaluates attacker-controlled expressions that can invoke runtime execution primitives' },
    xpath_injection: { invariantClass: 'xpath_injection', techniques: [T1190], rationale: 'XPath boolean injection bypasses XML data access controls and leaks document structure' },
    ognl_injection: { invariantClass: 'ognl_injection', techniques: [T1190], rationale: 'OGNL expression injection via Struts2/WebWork enables RCE through EL evaluation' },
    velocity_injection: { invariantClass: 'velocity_injection', techniques: [T1190, T1059], rationale: 'Velocity template injection reaches Java Runtime APIs for command execution' },
    freemarker_injection: { invariantClass: 'freemarker_injection', techniques: [T1190, T1059], rationale: 'FreeMarker Execute utility abuse enables arbitrary command execution from template context' },
    expression_language_generic: { invariantClass: 'expression_language_generic', techniques: [T1190], rationale: 'Generic EL context access primitives indicate server-side expression injection risk' },
    groovy_sandbox_escape: { invariantClass: 'groovy_sandbox_escape', techniques: [T1190, T1059], rationale: 'Groovy classloader and evaluate primitives can bypass sandbox boundaries and run attacker code' },
    server_side_js_injection: { invariantClass: 'server_side_js_injection', techniques: [T1190, T1059_007], rationale: 'Node.js eval and child_process injection yields direct server-side JavaScript execution' },
    memory_disclosure_endpoint: { invariantClass: 'memory_disclosure_endpoint', techniques: [T1005, T1592], rationale: 'Heap/thread dump and debug endpoints disclose in-memory secrets and host internals' },
    kubernetes_secret_exposure: { invariantClass: 'kubernetes_secret_exposure', techniques: [T1552_001, T1210], rationale: 'Kubernetes secrets and authz API probing can expose credentials and cluster trust relationships' },
    aws_metadata_ssrf_advanced: { invariantClass: 'aws_metadata_ssrf_advanced', techniques: [T1552, T1190], rationale: 'Advanced metadata SSRF patterns target IMDS and cloud identity material for credential theft' },
    graphql_depth_bomb: { invariantClass: 'graphql_depth_bomb', techniques: [T1499], rationale: 'Excessive GraphQL nesting and alias amplification are application-layer DoS primitives' },
    file_inclusion_rfi: { invariantClass: 'file_inclusion_rfi', techniques: [T1190, T1059], rationale: 'Remote file inclusion and stream wrapper abuse can load attacker-controlled code into application runtime' },

    // Supply Chain (3 classes)
    dependency_confusion: { invariantClass: 'dependency_confusion', techniques: [T1195, T1195_001], rationale: 'Dependency confusion substitutes public package for private one via version priority' },
    postinstall_injection: { invariantClass: 'postinstall_injection', techniques: [T1195_002, T1059], rationale: 'Package postinstall scripts execute arbitrary code during npm/pip install' },
    env_exfiltration: { invariantClass: 'env_exfiltration', techniques: [T1552, T1005], rationale: 'Environment variable exfiltration steals credentials from process env' },
    github_actions_injection: { invariantClass: 'github_actions_injection', techniques: [T1195_002, T1059_004], rationale: 'GitHub Actions command/env injection abuses CI workflow trust to execute attacker-controlled shell directives' },
    kubernetes_rbac_abuse: { invariantClass: 'kubernetes_rbac_abuse', techniques: [T1068, T1078], rationale: 'RBAC wildcard grants, authz probing, and privileged exec patterns indicate Kubernetes privilege escalation and account abuse' },
    terraform_injection: { invariantClass: 'terraform_injection', techniques: [T1190, T1059_004], rationale: 'Terraform interpolation and local-exec abuse can execute attacker-controlled shell commands during infrastructure provisioning' },
    docker_escape_indicator: { invariantClass: 'docker_escape_indicator', techniques: [T1611, T1068], rationale: 'Docker socket abuse, host PID namespace traversal, and privileged runtime flags indicate escape-to-host attempts' },
    cloud_metadata_advanced: { invariantClass: 'cloud_metadata_advanced', techniques: [T1552, T1190], rationale: 'Advanced metadata endpoint probing targets cloud identity credentials via SSRF and direct IMDS token workflows' },

    // LLM Injection (5 classes)
    llm_prompt_injection: { invariantClass: 'llm_prompt_injection', techniques: [T1190, T1059], rationale: 'Prompt injection overrides LLM system instructions to alter behavior' },
    llm_data_exfiltration: { invariantClass: 'llm_data_exfiltration', techniques: [T1005, T1119], rationale: 'LLM data exfiltration extracts training data or system prompts' },
    llm_jailbreak: { invariantClass: 'llm_jailbreak', techniques: [T1553], rationale: 'LLM jailbreak bypasses safety controls to enable harmful outputs' },
    llm_indirect_injection: { invariantClass: 'llm_indirect_injection', techniques: [T1190, T1059, T1566_002], rationale: 'Indirect prompt injection embeds adversarial instructions in external content retrieved by an LLM agent' },
    llm_token_smuggling: { invariantClass: 'llm_token_smuggling', techniques: [T1027], rationale: 'Unicode homoglyph and zero-width token smuggling obfuscates malicious instructions until normalization/tokenization' },

    // WebSocket (2 classes)
    ws_injection: { invariantClass: 'ws_injection', techniques: [T1190, T1059_007], rationale: 'WebSocket message injection exploits bidirectional channel for code execution' },
    ws_hijack: { invariantClass: 'ws_hijack', techniques: [T1185, T1557], rationale: 'WebSocket hijacking takes over established connections for session theft' },
    websocket_origin_bypass: { invariantClass: 'websocket_origin_bypass', techniques: [T1185, T1190], rationale: 'Missing or weak Origin validation enables cross-site WebSocket hijacking and cross-origin abuse' },
    websocket_message_injection: { invariantClass: 'websocket_message_injection', techniques: [T1190, T1068], rationale: 'Prototype pollution payloads in WS messages manipulate server-side object behavior for privilege escalation' },
    websocket_dos: { invariantClass: 'websocket_dos', techniques: [T1499], rationale: 'Large WS frames, reconnect storms, and ping floods exhaust websocket server capacity' },

    // JWT Abuse (3 classes)
    jwt_kid_injection: { invariantClass: 'jwt_kid_injection', techniques: [T1550_001], rationale: 'JWT kid parameter injection manipulates key retrieval toward attacker-controlled key sources' },
    jwt_jwk_embedding: { invariantClass: 'jwt_jwk_embedding', techniques: [T1550_001], rationale: 'Embedded JWK/JKU in JWT header provides attacker-controlled signing key material' },
    jwt_confusion: { invariantClass: 'jwt_confusion', techniques: [T1550, T1550_001], rationale: 'Algorithm confusion attack uses public key as HMAC secret to forge tokens' },

    // Cache Attacks (2 classes)
    cache_poisoning: { invariantClass: 'cache_poisoning', techniques: [T1557, T1565], rationale: 'Cache poisoning serves malicious content to all users via unkeyed headers' },
    cache_deception: { invariantClass: 'cache_deception', techniques: [T1539, T1530], rationale: 'Cache deception tricks CDN into caching sensitive user-specific responses' },

    // API Logic Abuse (2 classes)
    bola_idor: { invariantClass: 'bola_idor', techniques: [T1078, T1087], rationale: 'Broken object-level authorization allows accessing other users resources' },
    api_mass_enum: { invariantClass: 'api_mass_enum', techniques: [T1119, T1087], rationale: 'Mass API enumeration extracts all records via sequential ID or filter bypass' },

    // New Advanced Web Attacks
    xss_mxss_mutation: { invariantClass: 'xss_mxss_mutation', techniques: [T1189], rationale: 'mXSS exploits parser differences' },
    xss_dom_clobbering: { invariantClass: 'xss_dom_clobbering', techniques: [T1189], rationale: 'DOM Clobbering manipulates global objects' },
    xss_svg_smil: { invariantClass: 'xss_svg_smil', techniques: [T1189], rationale: 'SVG SMIL animation performs XSS' },
    xss_css_keylogger: { invariantClass: 'xss_css_keylogger', techniques: [T1185, T1056], rationale: 'CSS exfiltrates sensitive attributes' },
    oauth_auth_code_interception: { invariantClass: 'oauth_auth_code_interception', techniques: [T1550], rationale: 'OAuth codes stolen in transit' },
    oauth_token_endpoint_csrf: { invariantClass: 'oauth_token_endpoint_csrf', techniques: [T1189], rationale: 'OAuth CSRF bypasses state checks' },
    oauth_redirect_uri_traversal: { invariantClass: 'oauth_redirect_uri_traversal', techniques: [T1550_001], rationale: 'OAuth traversal targets arbitrary endpoints' },
    oauth_device_code_phishing: { invariantClass: 'oauth_device_code_phishing', techniques: [T1566], rationale: 'Device Code phishing attacks' },
    ssrf_aws_imds_ttl_bypass: { invariantClass: 'ssrf_aws_imds_ttl_bypass', techniques: [T1552], rationale: 'SSRF extracts IMDSv2 metadata' },
    ssrf_gcp_metadata: { invariantClass: 'ssrf_gcp_metadata', techniques: [T1552], rationale: 'SSRF extracts GCP metadata' },
    ssrf_azure_imds: { invariantClass: 'ssrf_azure_imds', techniques: [T1552], rationale: 'SSRF extracts Azure metadata' },
    ssrf_dns_rebinding: { invariantClass: 'ssrf_dns_rebinding', techniques: [T1190], rationale: 'DNS Rebinding bypasses SSRF filters' },
    http2_rapid_reset: { invariantClass: 'http2_rapid_reset', techniques: [T1499], rationale: 'HTTP/2 Rapid Reset DoS' },
    http2_hpack_bomb: { invariantClass: 'http2_hpack_bomb', techniques: [T1499], rationale: 'HTTP/2 HPACK Bomb DoS' },
    crypto_weak_cipher: { invariantClass: 'crypto_weak_cipher', techniques: [T1557], rationale: 'Weak ciphers intercepted' },
    crypto_beast_poodle: { invariantClass: 'crypto_beast_poodle', techniques: [T1557], rationale: 'Legacy TLS versions vulnerable to downgrade' },
    jwt_rs256_hs256_confusion: { invariantClass: 'jwt_rs256_hs256_confusion', techniques: [T1550_001], rationale: 'JWT confusion attack' },
    graphql_alias_bomb: { invariantClass: 'graphql_alias_bomb', techniques: [T1499], rationale: 'GraphQL alias DoS' },
    graphql_fragment_bomb: { invariantClass: 'graphql_fragment_bomb', techniques: [T1499], rationale: 'GraphQL fragment DoS' },
    supply_chain_github_actions: { invariantClass: 'supply_chain_github_actions', techniques: [T1059], rationale: 'GitHub actions injection' },
    supply_chain_package_eval: { invariantClass: 'supply_chain_package_eval', techniques: [T1195], rationale: 'Package evaluate injection' },
    memory_actuator_heapdump: { invariantClass: 'memory_actuator_heapdump', techniques: [T1005], rationale: 'Actuator heapdump exposure' },
    memory_pprof_exposure: { invariantClass: 'memory_pprof_exposure', techniques: [T1005], rationale: 'Go pprof debug profile exposure' },
    memory_phpinfo_output: { invariantClass: 'memory_phpinfo_output', techniques: [T1592], rationale: 'phpinfo output leaks server configuration' },
    memory_json_stack_trace: { invariantClass: 'memory_json_stack_trace', techniques: [T1592], rationale: 'JSON stack traces expose execution details' },

    // Security Hygiene (15 classes)
    response_header_csp_missing: { invariantClass: 'response_header_csp_missing', techniques: [T1185], rationale: 'Missing or unsafe CSP allows browser script execution abuse' },
    response_header_hsts_missing: { invariantClass: 'response_header_hsts_missing', techniques: [T1557], rationale: 'Weak or missing HSTS permits protocol downgrade and interception risk' },
    hsts_missing: { invariantClass: 'hsts_missing', techniques: [T1557], rationale: 'Legacy HSTS class alias: missing Strict-Transport-Security allows downgrade/interception risk' },
    secret_in_request: { invariantClass: 'secret_in_request', techniques: [T1552_001], rationale: 'Secrets in request URLs and payloads leak through logs and telemetry systems' },
    business_logic_price_manipulation: { invariantClass: 'business_logic_price_manipulation', techniques: [T1565], rationale: 'Tampered monetary values manipulate business transaction integrity' },
    info_disclosure_stack_trace: { invariantClass: 'info_disclosure_stack_trace', techniques: [T1592], rationale: 'Verbose stack traces disclose target host and framework details' },
    git_exposure: { invariantClass: 'git_exposure', techniques: [T1083], rationale: 'Exposed repository/dotfile paths reveal sensitive application artifacts' },
    debug_parameter_abuse: { invariantClass: 'debug_parameter_abuse', techniques: [T1190], rationale: 'Debug/admin query toggles can expose dangerous behavior in public endpoints' },
    csrf_missing_token: { invariantClass: 'csrf_missing_token', techniques: [T1185], rationale: 'State-changing requests without CSRF indicators are vulnerable to browser-mediated abuse' },
    clickjacking_missing_header: { invariantClass: 'clickjacking_missing_header', techniques: [T1185], rationale: 'Missing framing controls permit clickjacking and UI redress attacks' },
    http_parameter_pollution: { invariantClass: 'http_parameter_pollution', techniques: [T1190], rationale: 'Duplicate and polluted parameter forms exploit parser differentials' },
    insecure_cors_wildcard: { invariantClass: 'insecure_cors_wildcard', techniques: [T1185], rationale: 'Credentialed wildcard CORS allows cross-origin data theft from authenticated sessions' },
    subdomain_takeover_indicator: { invariantClass: 'subdomain_takeover_indicator', techniques: [T1584_001], rationale: 'Dangling cloud hostnames indicate hijackable domain infrastructure' },
    integer_overflow_param: { invariantClass: 'integer_overflow_param', techniques: [T1565], rationale: 'Numeric overflows and signedness abuse manipulate application logic' },
    jsonp_hijacking: { invariantClass: 'jsonp_hijacking', techniques: [T1185], rationale: 'JSONP callback abuse executes attacker-controlled code in browser context' },

    // Additional Security Hygiene (12 classes)
    secret_aws_key: { invariantClass: 'secret_aws_key', techniques: [T1552_001], rationale: 'AWS access key identifiers in payloads indicate credentials exposed in files/content' },
    secret_github_token: { invariantClass: 'secret_github_token', techniques: [T1552_001], rationale: 'GitHub tokens in plaintext indicate leaked access credentials' },
    secret_private_key: { invariantClass: 'secret_private_key', techniques: [T1552_004], rationale: 'Exposed private key PEM blocks are directly usable authentication material' },
    secret_stripe_key: { invariantClass: 'secret_stripe_key', techniques: [T1552_001], rationale: 'Stripe live secret keys in plaintext indicate credential leakage risk' },
    info_disclosure_server_banner: { invariantClass: 'info_disclosure_server_banner', techniques: [T1592_002], rationale: 'Server/framework version headers disclose software inventory to attackers' },
    info_disclosure_internal_ip: { invariantClass: 'info_disclosure_internal_ip', techniques: [T1590], rationale: 'RFC1918 addresses in responses reveal internal network architecture' },
    open_redirect_header_injection: { invariantClass: 'open_redirect_header_injection', techniques: [T1566_002], rationale: 'Unvalidated Location redirects can be chained for phishing delivery' },
    coupon_abuse_indicator: { invariantClass: 'coupon_abuse_indicator', techniques: [T1565], rationale: 'Coupon stacking/replay attempts manipulate transactional data integrity' },
    path_disclosure_windows: { invariantClass: 'path_disclosure_windows', techniques: [T1592], rationale: 'Windows absolute path leaks expose host filesystem and deployment details' },
    xml_external_entity_parameter: { invariantClass: 'xml_external_entity_parameter', techniques: [T1190], rationale: 'Parameter-entity declarations are common XXE exploitation primitives' },
    file_upload_polyglot: { invariantClass: 'file_upload_polyglot', techniques: [T1190], rationale: 'Polyglot file payloads bypass upload validation to exploit parser differentials' },
    rate_limit_bypass_header: { invariantClass: 'rate_limit_bypass_header', techniques: [T1499], rationale: 'Header spoofing patterns help evade per-source throttling and sustain DoS traffic' },

    // Wave 4 new classes
    dns_rebinding: { invariantClass: 'dns_rebinding', techniques: [T1557], rationale: 'DNS rebinding attacks bypass SOP to reach internal services via browser-controlled DNS TTL manipulation' },
    web_cache_deception: { invariantClass: 'web_cache_deception', techniques: [T1185], rationale: 'Static-extension path tricks CDNs into caching sensitive responses accessible to attackers' },
    dependency_hijacking: { invariantClass: 'dependency_hijacking', techniques: [T1195_001], rationale: 'Internal package names published to public registries hijack build pipelines via confusion attacks' },
    git_history_tampering: { invariantClass: 'git_history_tampering', techniques: [T1070], rationale: 'Force-push, rebase, and filter-branch rewrites destroy forensic audit history and conceal malicious commits' },
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
