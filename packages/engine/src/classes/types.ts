/**
 * Invariant Class Framework — Shared Types
 *
 * Every invariant class module implements the InvariantClassModule interface.
 * This enables dynamic registration, hot-loading, per-class testing,
 * per-class confidence calibration, and per-class false-positive exclusions.
 *
 * v3 UPGRADE: Multi-level detection integration.
 *   - detectL1: Fast regex path (the original detect())
 *   - detectL2: Deep structural/expression evaluator (optional, wired via evaluator bridge)
 *   - detect() now runs both levels and returns true if either fires
 *   - Formal property specs and composability declarations added
 */


// ── Invariant Class Taxonomy ──────────────────────────────────────

export type InvariantClass =
    // SQL Injection invariants
    | 'sql_string_termination'
    | 'sql_tautology'
    | 'sql_union_extraction'
    | 'sql_stacked_execution'
    | 'sql_time_oracle'
    | 'sql_error_oracle'
    | 'sql_comment_truncation'
    | 'sql_second_order'
    | 'sql_out_of_band'
    | 'sql_lateral_movement'
    | 'sql_ddl_injection'
    | 'sql_mysql_specific'

    // XSS invariants
    | 'xss_tag_injection'
    | 'xss_attribute_escape'
    | 'xss_event_handler'
    | 'xss_protocol_handler'
    | 'xss_template_expression'
    | 'dom_xss'
    | 'angularjs_sandbox_escape'
    | 'css_injection'

    // Path traversal invariants
    | 'path_dotdot_escape'
    | 'path_null_terminate'
    | 'path_encoding_bypass'
    | 'path_normalization_bypass'
    | 'path_windows_traversal'

    // Command injection invariants
    | 'cmd_separator'
    | 'cmd_substitution'
    | 'cmd_argument_injection'

    // SSRF invariants
    | 'ssrf_internal_reach'
    | 'ssrf_cloud_metadata'
    | 'ssrf_protocol_smuggle'

    // Deserialization invariants
    | 'deser_java_gadget'
    | 'deser_php_object'
    | 'deser_python_pickle'
    | 'yaml_deserialization'

    // Auth bypass invariants
    | 'auth_none_algorithm'
    | 'auth_header_spoof'
    | 'jwt_weak_hmac_secret'
    | 'jwt_weak_secret'
    | 'jwt_missing_expiry'
    | 'jwt_privilege_escalation'
    | 'oauth_token_leak'
    | 'oauth_state_missing'
    | 'oauth_redirect_hijack'
    | 'oauth_redirect_uri_bypass'
    | 'oauth_redirect_manipulation'
    | 'oauth_state_bypass'
    | 'saml_signature_wrapping'
    | 'jwt_algorithm_confusion'
    | 'mfa_bypass_indicator'
    | 'session_fixation'
    | 'pkce_downgrade'
    | 'bearer_token_exposure'
    | 'password_spray_indicator'
    | 'oidc_nonce_replay'
    | 'credential_stuffing'
    | 'cors_origin_abuse'
    | 'response_header_csp_missing'
    | 'response_header_hsts_missing'
    | 'secret_in_request'
    | 'business_logic_price_manipulation'
    | 'info_disclosure_stack_trace'
    | 'git_exposure'
    | 'debug_parameter_abuse'
    | 'csrf_missing_token'
    | 'clickjacking_missing_header'
    | 'http_parameter_pollution'
    | 'insecure_cors_wildcard'
    | 'cors_origin_misconfiguration'
    | 'subdomain_takeover_indicator'
    | 'integer_overflow_param'
    | 'jsonp_hijacking'

    // Prototype pollution
    | 'proto_pollution'
    | 'prototype_pollution_via_query'

    // Log injection
    | 'log_jndi_lookup'

    // SSTI invariants
    | 'ssti_jinja_twig'
    | 'ssti_el_expression'
    | 'template_injection_generic'

    // NoSQL injection invariants
    | 'nosql_operator_injection'
    | 'nosql_js_injection'

    // LDAP injection
    | 'ldap_filter_injection'

    // XXE
    | 'xxe_entity_expansion'
    | 'xml_injection'
    | 'xxe_injection'
    | 'http_smuggling'
    | 'http_request_smuggling'

    // CRLF
    | 'crlf_header_injection'
    | 'crlf_log_injection'

    // GraphQL
    | 'graphql_introspection'
    | 'graphql_batch_abuse'
    | 'graphql_injection'
    | 'graphql_dos'
    | 'graphql_depth_attack'

    // Open redirect
    | 'open_redirect_bypass'

    // Mass assignment
    | 'mass_assignment'
    | 'price_manipulation'
    | 'idor_parameter_probe'
    | 'http2_header_injection'
    | 'http2_pseudo_header_injection'
    | 'websocket_protocol_confusion'
    | 'websocket_origin_bypass'
    | 'websocket_message_injection'
    | 'websocket_dos'

    // ReDoS
    | 'regex_dos'
    | 'race_condition_probe'
    | 'redos_payload'
    | 'http_desync_attack'
    | 'cache_deception_attack'
    | 'parameter_pollution_advanced'

    // HTTP Smuggling (Kettle 2022-2025 research coverage)
    | 'http_smuggle_cl_te'
    | 'http_smuggle_h2'
    | 'http_smuggle_chunk_ext'
    | 'http_smuggle_zero_cl'
    | 'http_smuggle_expect'

    // JSON-SQL WAF Bypass (Claroty Team82)
    | 'json_sql_bypass'

    // Prototype Pollution Gadget Chains
    | 'proto_pollution_gadget'

    // Supply-chain threats
    | 'dependency_confusion'
    | 'postinstall_injection'
    | 'env_exfiltration'
    | 'github_actions_injection'
    | 'kubernetes_rbac_abuse'
    | 'terraform_injection'
    | 'docker_escape_indicator'
    | 'cloud_metadata_advanced'

    // LLM-focused prompt and policy-injection threats
    | 'llm_prompt_injection'
    | 'llm_data_exfiltration'
    | 'llm_jailbreak'
    | 'llm_indirect_injection'
    | 'llm_token_smuggling'
    // WebSocket threats
    | 'ws_injection'
    | 'ws_hijack'

    // JWT abuse (beyond alg:none)
    | 'jwt_kid_injection'
    | 'jwt_jwk_embedding'
    | 'jwt_confusion'
    | 'jwt_claim_confusion'

    // Cache attacks
    | 'cache_poisoning'
    | 'cache_deception'

    // API logic abuse
    | 'bola_idor'
    | 'api_mass_enum'
    // Nation-state / advanced threats
    | 'xml_bomb_dos'
    | 'http_verb_tampering'
    | 'webdav_method_abuse'
    | 'trace_xst_attack'
    | 'dns_tunneling_indicator'
    | 'c2_beacon_indicator'
    | 'container_escape_indicator'
    | 'log4shell_variant'
    | 'spring4shell'
    | 'spring_expression_injection'
    | 'xpath_injection'
    | 'ognl_injection'
    | 'velocity_injection'
    | 'freemarker_injection'
    | 'expression_language_generic'
    | 'groovy_sandbox_escape'
    | 'server_side_js_injection'
    | 'memory_disclosure_endpoint'
    | 'kubernetes_secret_exposure'
    | 'aws_metadata_ssrf_advanced'
    | 'compression_bomb'
    | 'graphql_depth_bomb'
    | 'file_inclusion_rfi'

    // New Advanced Detections
    | 'xss_mxss_mutation'
    | 'xss_dom_clobbering'
    | 'xss_svg_smil'
    | 'xss_css_keylogger'
    | 'oauth_auth_code_interception'
    | 'oauth_token_endpoint_csrf'
    | 'oauth_redirect_uri_traversal'
    | 'oauth_device_code_phishing'
    | 'ssrf_aws_imds_ttl_bypass'
    | 'ssrf_gcp_metadata'
    | 'ssrf_azure_imds'
    | 'ssrf_dns_rebinding'
    | 'http2_rapid_reset'
    | 'http2_hpack_bomb'
    | 'crypto_weak_cipher'
    | 'crypto_beast_poodle'
    | 'jwt_rs256_hs256_confusion'
    | 'graphql_alias_bomb'
    | 'graphql_fragment_bomb'
    | 'supply_chain_github_actions'
    | 'supply_chain_package_eval'
    | 'memory_actuator_heapdump'
    | 'memory_pprof_exposure'
    | 'memory_phpinfo_output'
    | 'memory_json_stack_trace'

    // Security hygiene detections
    | 'secret_aws_key'
    | 'secret_github_token'
    | 'secret_private_key'
    | 'secret_stripe_key'
    | 'info_disclosure_server_banner'
    | 'info_disclosure_internal_ip'
    | 'open_redirect_header_injection'
    | 'coupon_abuse_indicator'
    | 'path_disclosure_windows'
    | 'xml_external_entity_parameter'
    | 'file_upload_polyglot'
    | 'rate_limit_bypass_header'
    | 'response_header_csp_missing'
    | 'hsts_missing'
    | 'secret_in_request'
    | 'info_disclosure_stack_trace'
    | 'git_exposure'
    | 'debug_parameter_abuse'
    | 'csrf_missing_token'
    | 'clickjacking_missing_header'
    | 'http_parameter_pollution'
    | 'insecure_cors_wildcard'
    | 'cors_origin_misconfiguration'
    | 'subdomain_takeover_indicator'
    | 'integer_overflow_param'
    | 'jsonp_hijacking'
    | 'response_header_injection'
    | 'csv_injection'


// ── Attack Category ───────────────────────────────────────────────

export type AttackCategory =
    | 'sqli'
    | 'xss'
    | 'path_traversal'
    | 'cmdi'
    | 'ssrf'
    | 'deser'
    | 'auth'
    | 'injection'
    | 'smuggling'

export type Severity = 'critical' | 'high' | 'medium' | 'low'


// ── Detection Result (returned by L1/L2 detectors) ───────────────

/**
 * Structured detection result from a single detection level.
 * Carries confidence, evidence, and human-readable explanation.
 */
export interface DetectionLevelResult {
    /** Whether this level detected a violation */
    detected: boolean
    /** Confidence in the detection (0.0–1.0) */
    confidence: number
    /** Human-readable explanation of what was found */
    explanation: string
    /** Raw evidence string (matched pattern, eval result, etc.) */
    evidence?: string

    /** Structured proof evidence generated by L2 evaluators */
    structuredEvidence?: {
        /** The proof step operation */
        operation: 'context_escape' | 'payload_inject' | 'syntax_repair' | 'encoding_decode' | 'type_coerce' | 'semantic_eval'
        /** Exact matched substring in the raw input */
        matchedInput: string
        /** Human-readable interpretation of the matched step */
        interpretation: string
        /** Byte offset in the original input */
        offset: number
        /** Violated formal property string */
        property: string
    }[]
}


// ── Invariant Class Module ────────────────────────────────────────

/**
 * The contract every invariant class module must satisfy.
 *
 * v3: Multi-level detection.
 *   detect()   — L1 regex fast-path. Runs first, sub-millisecond.
 *   detectL2() — Deep structural evaluator. Optional. Catches novel variants
 *                by evaluating PROPERTIES, not patterns.
 *
 * The engine calls L1 always, L2 when available. If BOTH fire,
 * confidence is boosted (convergent evidence). If only L2 fires,
 * it's flagged as a novel variant the regex missed.
 */
export interface InvariantClassModule {
    /** Unique invariant class identifier */
    readonly id: InvariantClass

    /** Human-readable description of WHY this invariant is dangerous */
    readonly description: string

    /** Attack category for grouping */
    readonly category: AttackCategory

    /** Default severity when this invariant is detected */
    readonly severity: Severity

    /**
     * L1: Fast regex-based detection.
     * Known patterns, high speed, may miss novel variants.
     * This is the minimum required detector.
     */
    readonly detect: (input: string) => boolean

    /**
     * L2: Deep structural/expression evaluator. OPTIONAL.
     * Catches novel variants by evaluating the PROPERTY,
     * not matching specific character sequences.
     *
     * Returns structured result with confidence and evidence.
     * null means "no detection at this level."
     */
    readonly detectL2?: (input: string) => DetectionLevelResult | null

    /**
     * Generate N concrete variant payloads expressing this invariant.
     * Used for self-testing, probe generation, and variant validation.
     */
    readonly generateVariants: (count: number) => string[]

    /**
     * Known malicious payloads that MUST detect (L1 or L2).
     * Automated regression test suite for this class.
     */
    readonly knownPayloads: string[]

    /**
     * Known benign inputs that MUST NOT detect.
     * False positive regression suite.
     */
    readonly knownBenign: string[]

    /**
     * MITRE ATT&CK technique IDs this class maps to.
     * e.g., ['T1190'] for Exploit Public-Facing Application.
     */
    readonly mitre?: string[]

    /**
     * CWE identifier for this vulnerability class.
     * e.g., 'CWE-89' for SQL Injection.
     */
    readonly cwe?: string

    /**
     * Formal property statement.
     * The mathematical invariant expressed in pseudo-ISL notation.
     * Readable by humans, verifiable by the test suite.
     *
     * Example: "∃ subexpr ∈ parse(input, SQL_GRAMMAR) :
     *           eval(subexpr, BOOLEAN_CONTEXT) ∈ {TRUE, TAUTOLOGY}"
     */
    readonly formalProperty?: string

    /**
     * IDs of classes this one composes with to form attack chains.
     * Used by the chain detector for multi-step correlation.
     */
    readonly composableWith?: InvariantClass[]

    /**
     * Calibration configuration for this class.
     * Allows per-environment tuning of detection sensitivity.
     */
    readonly calibration?: CalibrationConfig
}


// ── Calibration ───────────────────────────────────────────────────

export interface CalibrationConfig {
    /** Base confidence score (0-1) when this class matches */
    baseConfidence: number

    /**
     * Environment-specific confidence multipliers.
     * e.g., 'wordpress' → 1.2 (more likely to be real attack)
     *       'api_json'  → 0.8 (more likely to be false positive)
     */
    environmentMultipliers?: Record<string, number>

    /**
     * Known false-positive patterns.
     * If input matches one of these, reduce confidence.
     */
    falsePositivePatterns?: RegExp[]

    /**
     * Minimum input length to consider for this class.
     * Short inputs are more likely to be false positives.
     */
    minInputLength?: number
}


// ── Property Proof System ─────────────────────────────────────────
//
// What makes INVARIANT fundamentally different from CrowdStrike:
// we don't say "this looks like an attack" — we produce a constructive
// proof showing exactly WHY the input violates a mathematical property.
//
// A proof consists of steps that trace the exploitation algebra:
//   1. CONTEXT ESCAPE:  how the input breaks out of its intended context
//   2. PAYLOAD INJECT:  what malicious operation is introduced
//   3. SYNTAX REPAIR:   how the input repairs the broken syntax to avoid errors
//
// Each step is independently verifiable. The proof is machine-checkable.
// No other security product on earth does this.

/**
 * A single step in a property violation proof.
 * Shows one phase of the exploitation algebra with the exact
 * substring, its interpretation, and the property it violates.
 */
export interface ProofStep {
    /** Phase of the exploitation algebra */
    operation: 'context_escape' | 'payload_inject' | 'syntax_repair' | 'encoding_decode' | 'type_coerce' | 'semantic_eval'
    /** The exact substring being analyzed */
    input: string
    /** What it becomes when interpreted in the target context */
    output: string
    /** Which formal property this step violates */
    property: string
    /** Byte offset in the original input where this step begins */
    offset: number
    /** Confidence that this step is correctly identified */
    confidence: number
    /** Whether this step has been computationally verified (not just structurally assembled) */
    verified?: boolean
    /** Verification method used (e.g., 'ast_evaluation', 'tokenizer_parse', 'structural_match') */
    verificationMethod?: string
}

/**
 * A constructive proof that an input violates a mathematical property.
 *
 * This is the output that SOC analysts read instead of "confidence: 0.92".
 * Each proof step is independently verifiable. The complete proof shows
 * the full exploitation chain from context escape through payload injection
 * to syntax repair.
 *
 * Legal admissibility: A PropertyProof constitutes technical evidence
 * suitable for incident response reporting and forensic analysis.
 */
export interface PropertyProof {
    /** The formal property statement that was violated (ISL notation) */
    property: string
    /** The exact witness substring that demonstrates the violation */
    witness: string
    /** Ordered steps showing how the violation works */
    steps: ProofStep[]
    /** Whether all three phases (escape + payload + repair) are present */
    isComplete: boolean
    /** The interpretation domain (sql, html, shell, etc.) */
    domain: string
    /** What the attack would accomplish if it succeeded */
    impact: string
    /** Confidence derived from proof structure (independent of heuristics) */
    proofConfidence: number
    /** Number of steps that are computationally verified */
    verifiedSteps: number
    /** Verification coverage: verifiedSteps / steps.length */
    verificationCoverage: number
    /** Aggregate verification confidence level */
    proofVerificationLevel: 'none' | 'structural' | 'verified' | 'formally_verified'
}


// ── Invariant Match ───────────────────────────────────────────────

export interface InvariantMatch {
    /** Which invariant class was matched */
    class: InvariantClass
    /** Detection confidence (0-1) */
    confidence: number
    /** Category for grouping */
    category: string
    /** Severity of this invariant class */
    severity: Severity
    /** Was this caught by invariant defense but NOT by any static signature? */
    isNovelVariant: boolean
    /** Description of the invariant */
    description: string
    /** Which detection levels fired */
    detectionLevels?: {
        l1: boolean
        l2: boolean
        convergent: boolean
    }
    /** L2 evidence detail (if L2 detected) */
    l2Evidence?: string
    /**
     * Constructive proof of property violation.
     * Present when the detection pipeline can construct a formal
     * demonstration of why this input violates the invariant.
     * This is the machine-verifiable evidence that differentiates
     * INVARIANT from signature/ML-based systems.
     */
    proof?: PropertyProof
    /** CVE enrichment from exploit knowledge graph */
    cveEnrichment?: {
        linkedCves: string[]
        activelyExploited: boolean
        highestEpss: number
        verificationAvailable: boolean
    }
}

export type EscapeOperation = 'string_terminate' | 'context_break' | 'encoding_bypass' | 'comment_bypass' | 'null_terminate' | 'whitespace_bypass'
export type PayloadOperation = 'tautology' | 'union_extract' | 'time_oracle' | 'error_oracle' | 'stacked_exec' | 'tag_inject' | 'event_handler' | 'cmd_substitute' | 'path_escape' | 'entity_expand' | 'proto_pollute' | 'nosql_operator'
export type RepairOperation = 'comment_close' | 'string_close' | 'tag_close' | 'natural_end' | 'none'
export type InputContext = 'sql' | 'html' | 'shell' | 'xml' | 'json' | 'ldap' | 'template' | 'graphql' | 'url' | string

export interface AlgebraicComposition {
    escape: EscapeOperation | null
    payload: PayloadOperation
    repair: RepairOperation
    context: InputContext
    confidence: number
    derivedClass: InvariantClass
    isComplete: boolean
}

export interface InterClassCorrelation {
    classes: InvariantClass[]
    compoundConfidence: number
    reason: string
}

export interface BlockRecommendation {
    block: boolean
    confidence: number
    reason: string
    threshold: number
}

export interface AnalysisRequest {
    input: string
    knownContext?: InputContext
    sourceReputation?: number
    requestMeta?: {
        method?: string
        path?: string
        contentType?: string
    }
}

export interface AnalysisResult {
    matches: InvariantMatch[]
    compositions: AlgebraicComposition[]
    correlations: InterClassCorrelation[]
    recommendation: BlockRecommendation
    novelByL2: number
    novelByL3: number
    convergent: number
    processingTimeUs: number
    /** Detected input contexts from decomposition */
    contexts?: string[]
    /** CVE enrichment summary */
    cveEnrichment?: {
        totalLinkedCves: number
        activelyExploitedClasses: string[]
        highestEpss: number
    }
    /** Polyglot analysis — multi-context attack detection */
    polyglot?: {
        isPolyglot: boolean
        domains: string[]
        domainCount: number
        confidenceBoost: number
        detail: string
    }
    /** Statistical anomaly profile of the input */
    anomalyScore?: number
    /** Whether encoding evasion was detected */
    encodingEvasion?: boolean
    /** Semantic intent classification of the detected attack */
    intent?: {
        primaryIntent: string
        intents: string[]
        confidence: number
        detail: string
        severityMultiplier: number
        targets: string[]
    }
}
