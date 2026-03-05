/**
 * Invariant Class Framework — Shared Types
 *
 * Every invariant class module implements the InvariantClassModule interface.
 * This enables dynamic registration, hot-loading, per-class testing,
 * per-class confidence calibration, and per-class false-positive exclusions.
 *
 * The InvariantClass union type remains the single source of truth for
 * all valid class identifiers. It is re-exported from here so that
 * class modules don't need to import the monolithic engine file.
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

    // XSS invariants
    | 'xss_tag_injection'
    | 'xss_attribute_escape'
    | 'xss_event_handler'
    | 'xss_protocol_handler'
    | 'xss_template_expression'

    // Path traversal invariants
    | 'path_dotdot_escape'
    | 'path_null_terminate'
    | 'path_encoding_bypass'
    | 'path_normalization_bypass'

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

    // Auth bypass invariants
    | 'auth_none_algorithm'
    | 'auth_header_spoof'
    | 'cors_origin_abuse'

    // Prototype pollution
    | 'proto_pollution'

    // Log injection
    | 'log_jndi_lookup'

    // SSTI invariants
    | 'ssti_jinja_twig'
    | 'ssti_el_expression'

    // NoSQL injection invariants
    | 'nosql_operator_injection'
    | 'nosql_js_injection'

    // LDAP injection
    | 'ldap_filter_injection'

    // XXE
    | 'xxe_entity_expansion'
    | 'xml_injection'

    // CRLF
    | 'crlf_header_injection'
    | 'crlf_log_injection'

    // GraphQL
    | 'graphql_introspection'
    | 'graphql_batch_abuse'

    // Open redirect
    | 'open_redirect_bypass'

    // Mass assignment
    | 'mass_assignment'

    // ReDoS
    | 'regex_dos'

    // HTTP Smuggling
    | 'http_smuggle_cl_te'
    | 'http_smuggle_h2'


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

export type Severity = 'critical' | 'high' | 'medium' | 'low'


// ── Invariant Class Module ────────────────────────────────────────

/**
 * The contract every invariant class module must satisfy.
 *
 * Each module is a self-contained detection unit for one invariant property.
 * The detect() function is the defense pattern — it matches the INVARIANT
 * PROPERTY, not specific payloads.
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
     * The defense pattern — matches the INVARIANT PROPERTY,
     * not specific payloads. This is what catches novel variants.
     *
     * Each pattern is a function for maximum expressiveness.
     * RegExp alone can't capture multi-step invariants like
     * "string terminator THEN boolean tautology THEN comment."
     */
    readonly detect: (input: string) => boolean

    /**
     * Generate N concrete variant payloads expressing this invariant.
     * Used for:
     *   1. Self-testing the defense pattern
     *   2. Generating probe payloads for internal testing
     *   3. Validating that the defense pattern catches novel variants
     */
    readonly generateVariants: (count: number) => string[]

    /**
     * Known malicious payloads that MUST detect.
     * These form the automated regression test suite for this class.
     * Every payload in this list must cause detect() to return true.
     * If a code change breaks detection of any of these, the class is broken.
     */
    readonly knownPayloads: string[]

    /**
     * Known benign inputs that MUST NOT detect.
     * False positive regression suite. Every input in this list must
     * cause detect() to return false. This prevents over-detection.
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
}
