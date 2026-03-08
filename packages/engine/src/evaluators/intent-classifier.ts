/**
 * Intent Classifier — Semantic Attack Intent Analysis
 *
 * Detection answers: "IS this an attack?"
 * Intent classification answers: "WHAT WOULD this attack DO?"
 *
 * This is the difference between:
 *   - "SQL injection detected" (what every WAF says)
 *   - "SQL injection targeting credential extraction from users table" (what we say)
 *
 * Intent categories (ordered by severity):
 *   - exfiltrate_credentials: targeting passwords, tokens, keys, secrets
 *   - destroy_data: DROP, DELETE, TRUNCATE — irrecoverable damage
 *   - escalate_privilege: admin promotion, role manipulation, auth bypass
 *   - establish_persistence: backdoor creation, user creation, cron injection
 *   - exfiltrate_data: general data theft (not specifically credentials)
 *   - enumerate: schema discovery, user listing, version fingerprinting
 *   - denial_of_service: resource exhaustion, sleep, benchmark, infinite loops
 *   - reconnaissance: error-based probing, timing attacks, blind discovery
 *   - unknown: attack detected but intent unclear
 *
 * The classifier runs AFTER detection. It examines:
 *   1. The detected class IDs (what type of attack)
 *   2. The raw input (what specific payload was used)
 *   3. The request context (what endpoint was targeted)
 *
 * This is a POST-DETECTION analysis, not a detection mechanism.
 * It produces zero false positives by design — it only classifies
 * inputs that are ALREADY known to be attacks.
 */


// ── Intent Categories ────────────────────────────────────────────

export type AttackIntent =
    | 'exfiltrate_credentials'
    | 'destroy_data'
    | 'escalate_privilege'
    | 'establish_persistence'
    | 'exfiltrate_data'
    | 'enumerate'
    | 'denial_of_service'
    | 'reconnaissance'
    | 'code_execution'
    | 'unknown'

/** Severity multiplier for each intent — higher means more dangerous */
const INTENT_SEVERITY: Record<AttackIntent, number> = {
    exfiltrate_credentials: 1.00,
    destroy_data: 0.98,
    code_execution: 0.97,
    establish_persistence: 0.95,
    escalate_privilege: 0.93,
    exfiltrate_data: 0.85,
    denial_of_service: 0.75,
    enumerate: 0.60,
    reconnaissance: 0.45,
    unknown: 0.30,
}

export interface IntentClassification {
    /** Primary intent of the attack */
    primaryIntent: AttackIntent
    /** All detected intents (an attack may have multiple goals) */
    intents: AttackIntent[]
    /** Confidence in the classification (0-1) */
    confidence: number
    /** Human-readable explanation */
    detail: string
    /** Severity multiplier based on intent (0-1) */
    severityMultiplier: number
    /** Specific targets identified (table names, file paths, etc.) */
    targets: string[]
}


// ── SQL Intent Patterns ──────────────────────────────────────────

const SQL_CREDENTIAL_TARGETS = /\b(?:password|passwd|pwd|secret|token|api_key|apikey|credential|hash|salt|private_key|ssn|credit_card|cc_num)\b/i
const SQL_USER_TABLES = /\b(?:users?|accounts?|admins?|members?|auth|login|credentials?|staff|employees?)\b/i
const SQL_DESTRUCTIVE = /\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX)|DELETE\s+FROM|TRUNCATE\s+TABLE?|ALTER\s+TABLE\s+\w+\s+DROP)\b/i
const SQL_PERSIST = /\b(?:INSERT\s+INTO\s+\w*(?:user|admin|account|role)|CREATE\s+(?:USER|LOGIN|ROLE)|GRANT\s+(?:ALL|ADMIN|SUPER)|INTO\s+(?:OUTFILE|DUMPFILE))\b/i
const SQL_ESCALATE = /\b(?:UPDATE\s+\w*(?:user|admin|account|role)\s+SET\s+\w*(?:role|admin|is_admin|privilege|level|type)|GRANT\s+(?:ALL|ADMIN))\b/i
const SQL_ENUMERATE = /\b(?:information_schema|pg_catalog|sys\.(?:tables|columns|databases)|sqlite_master|SHOW\s+(?:TABLES|DATABASES|COLUMNS)|table_name|column_name|schema_name)\b/i
const SQL_DOS = /\b(?:BENCHMARK|SLEEP|WAITFOR\s+DELAY|PG_SLEEP|RANDOMBLOB|GENERATE_SERIES)\b/i
const SQL_RECON = /(?:@@version|version\(\)|@@datadir|current_user\b|system_user\b|session_user\b)/i

// ── CMD Intent Patterns ──────────────────────────────────────────

const CMD_CREDENTIAL_TARGETS = /(?:\/etc\/(?:passwd|shadow)|\.ssh\/|id_rsa|\.aws\/credentials|\.env|\.git\/config|\.docker\/config|\.kube\/config|web\.config|wp-config\.php|appsettings\.json|database\.yml)/i
const CMD_REVERSE_SHELL = /(?:\/bin\/(?:ba)?sh|nc\s+-[elp]|ncat\s|netcat\s|mkfifo|\/dev\/tcp|socat\s|python[23]?\s+-c.*(?:socket|subprocess)|perl\s+-e.*(?:socket|exec)|ruby\s+-e.*(?:TCPSocket|exec)|php\s+-r.*(?:fsockopen|exec))/i
const CMD_PERSIST = /(?:crontab|\/etc\/cron|\.bashrc|\.profile|\.bash_profile|systemctl\s+(?:enable|start)|chmod\s+\+s|setuid)/i
const CMD_EXFIL = /(?:curl\s+.*-d|wget\s+.*--post|base64.*\|.*(?:curl|wget|nc)|xxd.*\|.*(?:curl|wget)|tar\s+.*\|.*(?:curl|nc))/i
const CMD_DESTRUCTIVE = /(?:rm\s+-rf|mkfs\.|dd\s+if=.*of=\/dev|shred\s|wipe\s|:\(\)\{|fork\s*bomb)/i
const CMD_ESCALATE = /(?:sudo\s|su\s+-|chmod\s+[0-7]*[4-7][0-7]*\s|chown\s+root|passwd\s|usermod\s+-aG\s+(?:sudo|wheel|admin))/i

// ── XSS Intent Patterns ─────────────────────────────────────────

const XSS_COOKIE_THEFT = /(?:document\.cookie|localStorage|sessionStorage|\.getItem\()/i
const XSS_KEYLOG = /(?:addEventListener.*keypress|addEventListener.*keydown|onkeypress|onkeydown.*=)/i
const XSS_REDIRECT = /(?:location\.href|location\.replace|window\.location|document\.location|location\s*=)/i
const XSS_FORM_HIJACK = /(?:\.action\s*=|form.*submit|XMLHttpRequest|fetch\(|navigator\.sendBeacon)/i

// ── Path Traversal Intent ────────────────────────────────────────

const PATH_CREDENTIAL_TARGETS = /(?:\/etc\/(?:passwd|shadow)|\.ssh\/|id_rsa|\.env|\.git\/|\.aws\/|\.docker\/|web\.config|\.htpasswd)/i
const PATH_SOURCE_CODE = /(?:\.(?:php|py|rb|js|ts|java|cs|go|rs)$|app\.(?:js|py)|manage\.py|server\.|index\.|main\.)/i


// ── Classifier ───────────────────────────────────────────────────

/**
 * Classify the semantic intent of a detected attack.
 *
 * @param detectedClasses Array of invariant class IDs that fired
 * @param input The raw input that triggered detection
 * @param path Optional request path for context
 * @returns Intent classification with targets and severity
 */
export function classifyIntent(
    detectedClasses: string[],
    input: string,
    path?: string,
): IntentClassification {
    const classSet = new Set(detectedClasses)
    const intents: AttackIntent[] = []
    const targets: string[] = []
    const lower = input.toLowerCase()
    const details: string[] = []

    // ── SQL injection intent ──
    const hasSql = detectedClasses.some(c => c.startsWith('sql_') || c === 'json_sql_bypass')
    if (hasSql) {
        if (SQL_CREDENTIAL_TARGETS.test(input) || (SQL_USER_TABLES.test(input) && /SELECT/i.test(input))) {
            intents.push('exfiltrate_credentials')
            const tables = input.match(SQL_USER_TABLES)
            const cols = input.match(SQL_CREDENTIAL_TARGETS)
            if (tables) targets.push(`table:${tables[0]}`)
            if (cols) targets.push(`column:${cols[0]}`)
            details.push('SQL credential extraction')
        }
        if (SQL_DESTRUCTIVE.test(input)) {
            intents.push('destroy_data')
            details.push('SQL destructive operation')
        }
        if (SQL_PERSIST.test(input)) {
            intents.push('establish_persistence')
            details.push('SQL persistence (file write or user creation)')
        }
        if (SQL_ESCALATE.test(input)) {
            intents.push('escalate_privilege')
            details.push('SQL privilege escalation')
        }
        if (SQL_ENUMERATE.test(input)) {
            intents.push('enumerate')
            details.push('SQL schema enumeration')
        }
        if (SQL_DOS.test(input)) {
            intents.push('denial_of_service')
            details.push('SQL time-based DoS')
        }
        if (SQL_RECON.test(input)) {
            intents.push('reconnaissance')
            details.push('SQL version/environment fingerprinting')
        }
        // General data extraction (UNION SELECT without specific credential targets)
        if (/UNION\s+(?:ALL\s+)?SELECT/i.test(input) && !intents.includes('exfiltrate_credentials')) {
            intents.push('exfiltrate_data')
            details.push('SQL data extraction via UNION')
        }
    }

    // ── Command injection intent ──
    const hasCmd = detectedClasses.some(c => c.startsWith('cmd_'))
    if (hasCmd) {
        if (CMD_REVERSE_SHELL.test(input)) {
            intents.push('code_execution')
            intents.push('establish_persistence')
            details.push('Reverse shell establishment')
        }
        if (CMD_CREDENTIAL_TARGETS.test(input)) {
            intents.push('exfiltrate_credentials')
            const files = input.match(CMD_CREDENTIAL_TARGETS)
            if (files) targets.push(`file:${files[0]}`)
            details.push('Command injection targeting credentials')
        }
        if (CMD_PERSIST.test(input)) {
            intents.push('establish_persistence')
            details.push('Command injection persistence mechanism')
        }
        if (CMD_EXFIL.test(input)) {
            intents.push('exfiltrate_data')
            details.push('Command injection data exfiltration')
        }
        if (CMD_DESTRUCTIVE.test(input)) {
            intents.push('destroy_data')
            details.push('Command injection destructive operation')
        }
        if (CMD_ESCALATE.test(input)) {
            intents.push('escalate_privilege')
            details.push('Command injection privilege escalation')
        }
        // Generic code execution if nothing more specific
        if (!intents.some(i => ['code_execution', 'establish_persistence', 'destroy_data'].includes(i))) {
            intents.push('code_execution')
            details.push('Command execution')
        }
    }

    // ── XSS intent ──
    const hasXss = detectedClasses.some(c => c.startsWith('xss_'))
    if (hasXss) {
        if (XSS_COOKIE_THEFT.test(input)) {
            intents.push('exfiltrate_credentials')
            targets.push('session:cookie')
            details.push('XSS session theft')
        }
        if (XSS_KEYLOG.test(input)) {
            intents.push('exfiltrate_credentials')
            details.push('XSS keylogger')
        }
        if (XSS_REDIRECT.test(input)) {
            intents.push('exfiltrate_data')
            details.push('XSS redirect/phishing')
        }
        if (XSS_FORM_HIJACK.test(input)) {
            intents.push('exfiltrate_data')
            details.push('XSS form hijack/data theft')
        }
        if (!intents.some(i => i.startsWith('exfiltrate'))) {
            intents.push('code_execution')
            details.push('XSS code execution in browser')
        }
    }

    // ── Path traversal intent ──
    const hasPath = detectedClasses.some(c => c.startsWith('path_'))
    if (hasPath) {
        if (PATH_CREDENTIAL_TARGETS.test(input)) {
            intents.push('exfiltrate_credentials')
            const files = input.match(PATH_CREDENTIAL_TARGETS)
            if (files) targets.push(`file:${files[0]}`)
            details.push('Path traversal targeting credentials')
        } else if (PATH_SOURCE_CODE.test(input)) {
            intents.push('exfiltrate_data')
            details.push('Path traversal targeting source code')
        } else {
            intents.push('reconnaissance')
            details.push('Path traversal probing')
        }
    }

    // ── SSRF intent ──
    if (classSet.has('ssrf_cloud_metadata')) {
        intents.push('exfiltrate_credentials')
        targets.push('service:cloud_metadata')
        details.push('SSRF targeting cloud credentials (IMDS)')
    } else if (detectedClasses.some(c => c.startsWith('ssrf_'))) {
        intents.push('reconnaissance')
        details.push('SSRF internal network probing')
    }

    // ── Deserialization intent ──
    if (detectedClasses.some(c => c.startsWith('deser_'))) {
        intents.push('code_execution')
        details.push('Deserialization remote code execution')
    }

    // ── SSTI intent ──
    if (detectedClasses.some(c => c.startsWith('ssti_'))) {
        if (lower.includes('exec(') || lower.includes('popen(') || lower.includes('getruntime()')) {
            intents.push('code_execution')
            details.push('SSTI to RCE')
        } else if (lower.includes('__class__') || lower.includes('__mro__')) {
            intents.push('enumerate')
            details.push('SSTI object graph traversal')
        } else {
            intents.push('code_execution')
            details.push('SSTI code execution')
        }
    }

    // ── Auth bypass intent ──
    if (detectedClasses.some(c => c.startsWith('auth_') || c.startsWith('jwt_'))) {
        intents.push('escalate_privilege')
        details.push('Authentication/authorization bypass')
    }

    // ── XXE intent ──
    if (classSet.has('xxe_entity_expansion')) {
        if (lower.includes('file://') || lower.includes('/etc/passwd')) {
            intents.push('exfiltrate_data')
            details.push('XXE file disclosure')
        } else if (/ENTITY\s+\w+\s+"[^"]*ENTITY/i.test(input)) {
            intents.push('denial_of_service')
            details.push('XXE billion laughs / entity expansion DoS')
        } else {
            intents.push('exfiltrate_data')
            details.push('XXE data extraction')
        }
    }

    // ── Log4Shell intent ──
    if (classSet.has('log_jndi_lookup')) {
        intents.push('code_execution')
        intents.push('establish_persistence')
        details.push('Log4Shell JNDI remote class loading')
    }

    // ── LLM attacks ──
    if (classSet.has('llm_data_exfiltration')) {
        intents.push('exfiltrate_data')
        details.push('LLM data exfiltration')
    }
    if (classSet.has('llm_prompt_injection') || classSet.has('llm_jailbreak')) {
        intents.push('escalate_privilege')
        details.push('LLM instruction override')
    }

    // ── Supply chain ──
    if (classSet.has('dependency_confusion') || classSet.has('postinstall_injection')) {
        intents.push('code_execution')
        intents.push('establish_persistence')
        details.push('Supply chain code execution')
    }
    if (classSet.has('env_exfiltration')) {
        intents.push('exfiltrate_credentials')
        details.push('Environment variable credential theft')
    }

    // ── Prototype pollution ──
    if (classSet.has('proto_pollution')) {
        intents.push('escalate_privilege')
        details.push('Prototype pollution property injection')
    }

    // ── GraphQL abuse ──
    if (classSet.has('graphql_deep_nesting')) {
        intents.push('denial_of_service')
        details.push('GraphQL depth-based DoS')
    }
    if (classSet.has('graphql_batch_abuse')) {
        intents.push('denial_of_service')
        details.push('GraphQL batch amplification')
    }
    if (classSet.has('graphql_introspection_leak')) {
        intents.push('enumerate')
        details.push('GraphQL schema enumeration')
    }

    // ── NoSQL ──
    if (detectedClasses.some(c => c.startsWith('nosql_'))) {
        if (lower.includes('$ne') || lower.includes('$gt') || lower.includes('$regex')) {
            intents.push('escalate_privilege')
            details.push('NoSQL authentication bypass')
        } else {
            intents.push('exfiltrate_data')
            details.push('NoSQL data extraction')
        }
    }

    // ── Deduplicate ──
    const uniqueIntents = [...new Set(intents)]

    // If nothing specific identified, fall back to unknown
    if (uniqueIntents.length === 0) {
        uniqueIntents.push('unknown')
        details.push('Attack detected but specific intent unclear')
    }

    // Primary intent = highest severity among detected intents
    const primaryIntent = uniqueIntents.reduce((a, b) =>
        INTENT_SEVERITY[a] >= INTENT_SEVERITY[b] ? a : b
    )

    const confidence = Math.min(0.99,
        uniqueIntents.length === 1 && uniqueIntents[0] === 'unknown'
            ? 0.30
            : 0.70 + (targets.length > 0 ? 0.15 : 0) + (uniqueIntents.length > 1 ? 0.10 : 0)
    )

    return {
        primaryIntent,
        intents: uniqueIntents,
        confidence,
        detail: details.join('; '),
        severityMultiplier: INTENT_SEVERITY[primaryIntent],
        targets: [...new Set(targets)],
    }
}

/**
 * Get the intent severity multiplier for a given intent.
 * Used by the defense decision engine to weight blocking decisions.
 */
export function intentSeverity(intent: AttackIntent): number {
    return INTENT_SEVERITY[intent] ?? 0.30
}
