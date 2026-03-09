/**
 * Polyglot Detector — Cross-Context Attack Detection
 *
 * A polyglot payload is valid in MULTIPLE interpretation contexts
 * simultaneously. This is the most sophisticated class of attacks:
 *
 *   `<img src=x onerror="';exec('id');--">` is:
 *     - Valid XSS (HTML tag with event handler)
 *     - Valid SQLi (string termination + exec)
 *     - Valid CMDi (exec command)
 *
 * The invariant: legitimate input is meaningful in exactly ONE context.
 * Multi-context validity is an adversarial construction.
 *
 * Why polyglots are dangerous:
 *   If the application uses context-dependent escaping (SQL sanitizer for
 *   SQL, HTML sanitizer for HTML), a polyglot may survive one sanitizer
 *   but execute in another context. The attacker doesn't need to know
 *   which context the input reaches — the payload works in all of them.
 *
 * Detection principle:
 *   Run ALL evaluators on the input. If the input triggers detections
 *   in 2+ DISTINCT attack domains, it's a polyglot. The compound
 *   confidence is HIGHER than any individual detection because
 *   multi-context validity is near-impossible in legitimate input.
 *
 * This is not a separate evaluator — it's a POST-DETECTION analysis
 * that runs on the combined detection results.
 */


// ── Domain Classification ───────────────────────────────────────

/**
 * Group invariant classes into attack DOMAINS.
 * Two classes in the same domain = one attack technique.
 * Two classes in different domains = possible polyglot.
 */
const CLASS_TO_DOMAIN: Record<string, string> = {
    // SQL domain
    sql_tautology: 'sql',
    sql_string_termination: 'sql',
    sql_union_extraction: 'sql',
    sql_stacked_execution: 'sql',
    sql_time_oracle: 'sql',
    sql_error_oracle: 'sql',
    sql_comment_truncation: 'sql',
    json_sql_bypass: 'sql',

    // XSS domain
    xss_tag_injection: 'xss',
    xss_attribute_escape: 'xss',
    xss_event_handler: 'xss',
    xss_protocol_handler: 'xss',
    xss_template_expression: 'xss',

    // CMDi domain
    cmd_separator: 'cmdi',
    cmd_substitution: 'cmdi',
    cmd_argument_injection: 'cmdi',

    // SSRF domain
    ssrf_internal_reach: 'ssrf',
    ssrf_cloud_metadata: 'ssrf',
    ssrf_protocol_smuggle: 'ssrf',

    // Path traversal domain
    path_dotdot_escape: 'path',
    path_null_terminate: 'path',
    path_encoding_bypass: 'path',
    path_normalization_bypass: 'path',
    path_windows_traversal: 'path',

    // SSTI domain
    ssti_jinja_twig: 'ssti',
    ssti_el_expression: 'ssti',
    template_injection_generic: 'ssti',

    // XXE domain
    xxe_entity_expansion: 'xxe',

    // Deserialization domain
    deser_java_gadget: 'deser',
    deser_php_object: 'deser',
    deser_python_pickle: 'deser',
    yaml_deserialization: 'deser',

    // Auth domain
    auth_none_algorithm: 'auth',
    auth_header_spoof: 'auth',
    credential_stuffing: 'auth',
    jwt_kid_injection: 'auth',
    jwt_jwk_embedding: 'auth',
    jwt_confusion: 'auth',

    // NoSQL domain
    nosql_operator_injection: 'nosql',
    nosql_js_injection: 'nosql',

    // Prototype pollution
    proto_pollution: 'proto',

    // Log4Shell
    log_jndi_lookup: 'log4j',

    // LDAP
    ldap_filter_injection: 'ldap',

    // CRLF
    crlf_header_injection: 'crlf',

    // HTTP smuggling
    http_smuggle_cl_te: 'smuggle',
    http_smuggle_h2: 'smuggle',

    // Open redirect
    redirect_open: 'redirect',

    // LLM
    llm_prompt_injection: 'llm',
    llm_data_exfiltration: 'llm',
    llm_jailbreak: 'llm',

    // Supply chain
    dependency_confusion: 'supply',
    postinstall_injection: 'supply',
    env_exfiltration: 'supply',

    // Mass assignment
    mass_assignment: 'mass_assign',

    // GraphQL
    graphql_deep_nesting: 'graphql',
    graphql_batch_abuse: 'graphql',
    graphql_introspection_leak: 'graphql',

    // WebSocket
    ws_injection: 'ws',
    ws_hijack: 'ws',

    // Cache
    cache_poisoning: 'cache',
    cache_deception: 'cache',

    // API abuse
    bola_idor: 'api',
    api_mass_enum: 'api',
}


// ── Polyglot Analysis ───────────────────────────────────────────

export interface PolyglotDetection {
    /** Is this a polyglot (multi-domain) attack? */
    isPolyglot: boolean
    /** Which distinct attack domains are present */
    domains: string[]
    /** Number of distinct domains */
    domainCount: number
    /** Confidence boost for polyglot status (0 if not polyglot) */
    confidenceBoost: number
    /** Human-readable explanation */
    detail: string
}

/**
 * Known dangerous domain combinations. These represent attack
 * compositions that are especially dangerous because they exploit
 * the gap between context-specific sanitizers.
 */
const DANGEROUS_COMBINATIONS: Array<{ domains: Set<string>; boost: number; reason: string }> = [
    {
        domains: new Set(['sql', 'xss']),
        boost: 0.08,
        reason: 'SQL+XSS polyglot — bypasses context-specific sanitization',
    },
    {
        domains: new Set(['sql', 'cmdi']),
        boost: 0.10,
        reason: 'SQL+CMDi polyglot — may chain SQL to OS command execution',
    },
    {
        domains: new Set(['xss', 'ssti']),
        boost: 0.08,
        reason: 'XSS+SSTI polyglot — client-side AND server-side template execution',
    },
    {
        domains: new Set(['cmdi', 'ssti']),
        boost: 0.10,
        reason: 'CMDi+SSTI polyglot — template escape to command execution',
    },
    {
        domains: new Set(['path', 'cmdi']),
        boost: 0.07,
        reason: 'Path+CMDi polyglot — file access combined with command injection',
    },
    {
        domains: new Set(['ssrf', 'cmdi']),
        boost: 0.08,
        reason: 'SSRF+CMDi polyglot — internal network access with command execution',
    },
]

/**
 * Analyze detection results for polyglot characteristics.
 *
 * This runs AFTER individual evaluators have produced their detections.
 * It looks at the COMBINATION of detected domains to identify
 * multi-context attacks.
 *
 * @param detectedClasses Array of invariant class IDs that were detected
 * @returns Polyglot analysis result
 */
export function analyzePolyglot(detectedClasses: string[]): PolyglotDetection {
    // Map classes to domains
    const domains = new Set<string>()
    for (const cls of detectedClasses) {
        const domain = CLASS_TO_DOMAIN[cls]
        if (domain) domains.add(domain)
    }

    const domainArray = [...domains]
    const isPolyglot = domainArray.length >= 2

    if (!isPolyglot) {
        return {
            isPolyglot: false,
            domains: domainArray,
            domainCount: domainArray.length,
            confidenceBoost: 0,
            detail: domainArray.length === 1
                ? `Single domain: ${domainArray[0]}`
                : 'No attack domains detected',
        }
    }

    // Check for known dangerous combinations
    let maxBoost = 0
    let bestReason = ''
    for (const combo of DANGEROUS_COMBINATIONS) {
        // Check if ALL domains in the combo are present in detections
        const allPresent = [...combo.domains].every(d => domains.has(d))
        if (allPresent && combo.boost > maxBoost) {
            maxBoost = combo.boost
            bestReason = combo.reason
        }
    }

    // Base boost for any polyglot (generic multi-context)
    const baseBoost = 0.04
    const domainCountBoost = (domainArray.length - 2) * 0.02  // 3+ domains = even more suspicious
    const confidenceBoost = Math.max(maxBoost, baseBoost) + domainCountBoost

    const detail = bestReason ||
        `Multi-context polyglot: ${domainArray.join(' + ')} (${domainArray.length} domains)`

    return {
        isPolyglot: true,
        domains: domainArray,
        domainCount: domainArray.length,
        confidenceBoost: Math.min(0.15, confidenceBoost),
        detail,
    }
}
