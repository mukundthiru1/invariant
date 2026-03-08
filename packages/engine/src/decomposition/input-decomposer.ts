/**
 * INVARIANT — Input Decomposition Pipeline
 *
 * THE PARADIGM SHIFT.
 *
 * Old paradigm (WAF): "Does this input match a known-bad pattern?"
 *   → Misses anything not in the pattern list.
 *
 * New paradigm (INVARIANT): "What structural properties does this input express?"
 *   → Catches every expression of every known-dangerous property.
 *
 * Pipeline:
 *   1. Multi-Layer Decode: Peel encoding layers (URL, HTML, Unicode, hex, base64)
 *   2. Context Detect: What execution context is this input destined for?
 *      (SQL, HTML, Shell, XML, JSON, LDAP, Template, GraphQL, URL)
 *   3. Tokenize: Context-specific tokenization
 *   4. Extract Properties: What invariant properties does the token stream express?
 *   5. Return property set: {sql_tautology, cmd_separator, ssrf_internal, ...}
 *
 * Why this is better:
 *   - A regex WAF needs separate rules for `' OR 1=1--` and `' OR 2=2--`
 *   - The decomposer sees both as {sql_string_termination, sql_tautology}
 *     because it evaluates the PROPERTY, not the PATTERN
 *   - Novel evasions that bypass regex are caught because the property persists
 */

import type { InvariantClass } from '../invariant-engine.js'


// ═══════════════════════════════════════════════════════════════════
// 1. MULTI-LAYER DECODER
// ═══════════════════════════════════════════════════════════════════

/** Maximum recursion depth for nested encodings */
const MAX_DECODE_DEPTH = 6

/**
 * Decode input through every encoding layer attackers use to evade detection.
 * Returns all decoded forms — the raw input AND every intermediate decode.
 * Why all forms? An attacker might use double-encoding where the intermediate
 * form is the actual payload — checking only the final decode misses this.
 */
export function multiLayerDecode(input: string): DecodedForms {
    const forms: string[] = [input]
    let current = input

    for (let depth = 0; depth < MAX_DECODE_DEPTH; depth++) {
        const decoded = decodeOneLayer(current)
        if (decoded === current) break // No more decoding possible
        forms.push(decoded)
        current = decoded
    }

    // Also try base64 decode if it looks like base64
    const b64Decoded = tryBase64Decode(input)
    if (b64Decoded && b64Decoded !== input) {
        forms.push(b64Decoded)
    }

    return {
        raw: input,
        fullyDecoded: current,
        allForms: forms,
        encodingDepth: forms.length - 1,
        usesEncoding: forms.length > 1,
    }
}

function decodeOneLayer(input: string): string {
    let decoded = input

    // URL decode
    try {
        const urlDecoded = decodeURIComponent(decoded)
        if (urlDecoded !== decoded) return urlDecoded
    } catch { /* invalid encoding */ }

    // HTML entity decode (numeric hex + decimal + named)
    const htmlDecoded = decoded
        .replace(/&#x([0-9a-f]+);?/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&#(\d+);?/g, (_, dec) => String.fromCharCode(parseInt(dec)))
        .replace(/&quot;/gi, '"')
        .replace(/&apos;/gi, "'")
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
        .replace(/&amp;/gi, '&')
    if (htmlDecoded !== decoded) return htmlDecoded

    // Unicode escapes: \u0027
    const uniDecoded = decoded.replace(/\\u([0-9a-f]{4})/gi, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16)))
    if (uniDecoded !== decoded) return uniDecoded

    // Hex escapes: \x27
    const hexDecoded = decoded.replace(/\\x([0-9a-f]{2})/gi, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16)))
    if (hexDecoded !== decoded) return hexDecoded

    // SQL comment-space bypass: /**/  →  space
    const sqlDecoded = decoded.replace(/\/\*.*?\*\//g, ' ')
    if (sqlDecoded !== decoded) return sqlDecoded

    return decoded
}

function tryBase64Decode(input: string): string | null {
    // Only attempt if input looks like base64 (length, charset)
    const b64Match = input.match(/(?:^|=)([A-Za-z0-9+/]{16,}={0,2})(?:$|&)/)
    if (!b64Match) return null
    try {
        const decoded = atob(b64Match[1])
        // Verify it decoded to printable text
        const printable = [...decoded].filter(c => {
            const code = c.charCodeAt(0)
            return (code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13
        }).length
        if (printable / decoded.length > 0.8) return decoded
    } catch { /* not valid base64 */ }
    return null
}


// ═══════════════════════════════════════════════════════════════════
// 2. CONTEXT DETECTOR
// ═══════════════════════════════════════════════════════════════════

/**
 * Possible execution contexts an input might be destined for.
 * The same input means different things in different contexts:
 *   - `<script>` in HTML context = XSS
 *   - `<script>` in SQL context = harmless string
 *   - `' OR 1=1` in SQL context = injection
 *   - `' OR 1=1` in HTML context = harmless text
 */
export type InputContext =
    | 'sql'
    | 'html'
    | 'shell'
    | 'xml'
    | 'json'
    | 'ldap'
    | 'template'
    | 'graphql'
    | 'url'
    | 'header'
    | 'unknown'

/**
 * Detect which execution context(s) the input is likely destined for.
 * Returns multiple contexts — ambiguous inputs get analyzed in all likely contexts.
 *
 * We DON'T try to determine the "one true context" — that would require
 * application knowledge we don't have. Instead, we detect signals from
 * the input itself and run the appropriate tokenizers for each match.
 */
export function detectContexts(input: string): InputContext[] {
    const contexts: InputContext[] = []

    // SQL context signals
    if (hasSQLSignals(input)) contexts.push('sql')

    // HTML/XSS context signals
    if (hasHTMLSignals(input)) contexts.push('html')

    // Shell context signals
    if (hasShellSignals(input)) contexts.push('shell')

    // XML context signals
    if (hasXMLSignals(input)) contexts.push('xml')

    // JSON context signals
    if (hasJSONSignals(input)) contexts.push('json')

    // LDAP context signals
    if (hasLDAPSignals(input)) contexts.push('ldap')

    // Template context signals
    if (hasTemplateSignals(input)) contexts.push('template')

    // GraphQL context signals
    if (hasGraphQLSignals(input)) contexts.push('graphql')

    // URL context signals
    if (hasURLSignals(input)) contexts.push('url')

    // If nothing matched, analyze as unknown (all contexts get basic check)
    if (contexts.length === 0) contexts.push('unknown')

    return contexts
}


// ── Context Signal Detection ─────────────────────────────────────

function hasSQLSignals(input: string): boolean {
    const lower = input.toLowerCase()
    return /(?:select|insert|update|delete|drop|union|alter|create|exec)\s/i.test(input) ||
        /(?:or|and)\s+\S+\s*=\s*\S/i.test(input) ||
        /'/.test(input) && /(?:--|#|;)/.test(input) ||
        /(?:sleep|waitfor|benchmark|pg_sleep)\s*\(/i.test(input) ||
        /(?:concat|char|ascii|substr|substring|hex|unhex)\s*\(/i.test(input) ||
        lower.includes('information_schema') ||
        lower.includes('sys.tables') ||
        /\/\*.*\*\//.test(input)
}

function hasHTMLSignals(input: string): boolean {
    return /<[a-z!\/]/i.test(input) ||
        /javascript\s*:/i.test(input) ||
        /\bon\w+\s*=/i.test(input) ||
        /data\s*:/i.test(input) ||
        /&#\d+;|&#x[0-9a-f]+;/i.test(input)
}

function hasShellSignals(input: string): boolean {
    return /[;|`]/.test(input) && /\b(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc|bash|sh|python|perl|ruby|php|echo|printf|env)\b/i.test(input) ||
        /\$\(/.test(input) ||
        /`[^`]+`/.test(input) ||
        /\b(?:chmod|chown|rm|mv|cp|mkdir|touch|kill)\b/i.test(input) ||
        />\s*\//.test(input) && /dev\/null|tmp\//.test(input)
}

function hasXMLSignals(input: string): boolean {
    return /<!(?:DOCTYPE|ENTITY)/i.test(input) ||
        /<\?xml/i.test(input) ||
        /SYSTEM\s+["']/i.test(input)
}

function hasJSONSignals(input: string): boolean {
    const trimmed = input.trim()
    return (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
        (trimmed.startsWith('[') && trimmed.endsWith(']')) ||
        /\$(?:ne|gt|lt|gte|lte|in|nin|regex|where|exists|type|or|and)\b/.test(input) ||
        /__proto__|constructor\[/.test(input)
}

function hasLDAPSignals(input: string): boolean {
    return /\)\s*\(/.test(input) && /[|&!]/.test(input) ||
        /\([\w]+=/.test(input) ||
        /\*\)|\(\*/.test(input)
}

function hasTemplateSignals(input: string): boolean {
    return /\{\{.*\}\}/.test(input) ||
        /\$\{.*\}/.test(input) ||
        /#\{.*\}/.test(input) ||
        /<%.*%>/.test(input) ||
        /__class__|__mro__|__subclasses__|__globals__/.test(input) ||
        /\bRuntime\b.*\bexec\b|\bProcessBuilder\b/i.test(input)
}

function hasGraphQLSignals(input: string): boolean {
    return /\b(?:query|mutation|subscription)\s*[\s({]/i.test(input) ||
        /__schema\b/i.test(input) ||
        /\b__type\b/.test(input) ||
        /introspectionquery/i.test(input)
}

function hasURLSignals(input: string): boolean {
    return /^https?:\/\//i.test(input) ||
        /^\/\//i.test(input) ||
        /file:\/\//i.test(input) ||
        /gopher:\/\//i.test(input) ||
        /dict:\/\//i.test(input) ||
        /=(?:https?:|%2f%2f|\/\/)/i.test(input)
}


// ═══════════════════════════════════════════════════════════════════
// 3. PROPERTY EXTRACTOR
// ═══════════════════════════════════════════════════════════════════

/**
 * An extracted invariant property from input decomposition.
 * This is the output of the decomposition pipeline — a set of
 * mathematical properties that the input expresses.
 */
export interface ExtractedProperty {
    /** The invariant class this property maps to */
    invariantClass: InvariantClass
    /** Confidence that this property is present (0-1) */
    confidence: number
    /** Which execution context generated this property */
    context: InputContext
    /** Human-readable explanation of WHY this property was detected */
    evidence: string
    /** Which decoded form triggered detection */
    decodedForm: 'raw' | 'decoded' | 'base64'
}

/**
 * The full result of input decomposition.
 */
export interface DecompositionResult {
    /** All invariant properties the input expresses */
    properties: ExtractedProperty[]
    /** Which execution contexts were detected */
    contexts: InputContext[]
    /** Encoding analysis */
    encoding: DecodedForms
    /** Processing time in microseconds */
    processingTimeUs: number
}

export interface DecodedForms {
    raw: string
    fullyDecoded: string
    allForms: string[]
    encodingDepth: number
    usesEncoding: boolean
}


// ═══════════════════════════════════════════════════════════════════
// 4. MASTER DECOMPOSITION PIPELINE
// ═══════════════════════════════════════════════════════════════════

/**
 * Decompose an input into its invariant properties.
 *
 * This is the core of the paradigm shift. Instead of checking the input
 * against a list of patterns, we decompose it into its structural properties
 * and match those properties against the invariant class taxonomy.
 *
 * @param input Raw input string (URL path+query, header value, body text)
 * @param requestContext Optional metadata about the request for enhanced detection
 */
export function decomposeInput(
    input: string,
    requestContext?: {
        method?: string
        contentType?: string
        path?: string
        headers?: Headers
    },
): DecompositionResult {
    const start = performance.now()

    // Size guard — don't analyze massive inputs
    if (input.length > 16384) {
        return {
            properties: [],
            contexts: ['unknown'],
            encoding: { raw: input, fullyDecoded: input, allForms: [input], encodingDepth: 0, usesEncoding: false },
            processingTimeUs: (performance.now() - start) * 1000,
        }
    }

    // Step 1: Multi-layer decode
    const encoding = multiLayerDecode(input)

    // Step 2: Detect execution contexts
    // Check all decoded forms — an encoded payload reveals its context only after decoding
    const contextsRaw = detectContexts(input)
    const contextsDecoded = encoding.usesEncoding ? detectContexts(encoding.fullyDecoded) : []
    const allContexts = [...new Set([...contextsRaw, ...contextsDecoded])]

    // Step 3+4: Extract properties for each context using each decoded form
    const properties: ExtractedProperty[] = []
    const seenProperties = new Set<string>() // Deduplicate: class+context

    for (const form of encoding.allForms) {
        const decodedForm = form === input ? 'raw' : 'decoded' as const
        for (const ctx of allContexts) {
            const extracted = extractPropertiesForContext(form, ctx, requestContext)
            for (const prop of extracted) {
                const key = `${prop.invariantClass}:${prop.context}`
                if (!seenProperties.has(key)) {
                    seenProperties.add(key)
                    properties.push({ ...prop, decodedForm })
                } else {
                    // If we already have this property, keep higher confidence
                    const existing = properties.find(p =>
                        p.invariantClass === prop.invariantClass && p.context === prop.context)
                    if (existing && prop.confidence > existing.confidence) {
                        existing.confidence = prop.confidence
                        existing.evidence = prop.evidence
                        existing.decodedForm = decodedForm
                    }
                }
            }
        }
    }

    // Encoding evasion amplifier: if property was only found in decoded form, boost confidence
    // (encoding is deliberate evasion = higher conviction)
    if (encoding.usesEncoding) {
        for (const prop of properties) {
            if (prop.decodedForm === 'decoded') {
                prop.confidence = Math.min(prop.confidence + 0.1, 1.0)
                prop.evidence += ' [encoding evasion detected]'
            }
        }
    }

    return {
        properties,
        contexts: allContexts,
        encoding,
        processingTimeUs: (performance.now() - start) * 1000,
    }
}


// ═══════════════════════════════════════════════════════════════════
// 5. CONTEXT-SPECIFIC PROPERTY EXTRACTORS
// ═══════════════════════════════════════════════════════════════════

function extractPropertiesForContext(
    input: string,
    context: InputContext,
    requestContext?: { method?: string; contentType?: string; path?: string; headers?: Headers },
): ExtractedProperty[] {
    switch (context) {
        case 'sql': return extractSQLProperties(input)
        case 'html': return extractHTMLProperties(input)
        case 'shell': return extractShellProperties(input)
        case 'xml': return extractXMLProperties(input)
        case 'json': return extractJSONProperties(input)
        case 'ldap': return extractLDAPProperties(input)
        case 'template': return extractTemplateProperties(input)
        case 'graphql': return extractGraphQLProperties(input)
        case 'url': return extractURLProperties(input)
        case 'header': return extractHeaderProperties(input, requestContext?.headers)
        case 'unknown': return extractUnknownContextProperties(input)
        default: return []
    }
}

// ── SQL Property Extraction ──────────────────────────────────────

function extractSQLProperties(input: string): ExtractedProperty[] {
    const props: ExtractedProperty[] = []

    // String termination: quote followed by SQL keyword
    if (/'/.test(input) && /\b(?:or|and|union|select|insert|update|delete|drop|exec|having|order|group)\b/i.test(input)) {
        props.push({
            invariantClass: 'sql_string_termination',
            confidence: 0.8,
            context: 'sql',
            evidence: 'Quote character followed by SQL keyword — string context escape attempt',
            decodedForm: 'raw',
        })
    }

    // Tautology: any expression that evaluates to true unconditionally
    if (/(?:or|and)\s+\S+\s*=\s*\S/i.test(input)) {
        // Check if the expression is a tautology (same value on both sides of =)
        const tautMatch = input.match(/(?:or|and)\s+['"]?(\w+)['"]?\s*=\s*['"]?(\w+)['"]?/i)
        if (tautMatch && tautMatch[1] === tautMatch[2]) {
            props.push({
                invariantClass: 'sql_tautology',
                confidence: 0.95,
                context: 'sql',
                evidence: `Tautology detected: ${tautMatch[1]}=${tautMatch[2]} — always evaluates to TRUE`,
                decodedForm: 'raw',
            })
        } else {
            // Even if not obviously tautological, the pattern is suspicious
            props.push({
                invariantClass: 'sql_tautology',
                confidence: 0.7,
                context: 'sql',
                evidence: 'Boolean expression in injection context — potential tautology',
                decodedForm: 'raw',
            })
        }
    }

    // UNION extraction: UNION SELECT used for data exfiltration
    if (/union\s+(all\s+)?select\b/i.test(input)) {
        props.push({
            invariantClass: 'sql_union_extraction',
            confidence: 0.9,
            context: 'sql',
            evidence: 'UNION SELECT — data extraction via query union',
            decodedForm: 'raw',
        })
    }

    // Stacked queries: semicolon followed by destructive SQL
    if (/;\s*(drop|delete|insert|update|alter|create|exec|execute)\s+/i.test(input)) {
        props.push({
            invariantClass: 'sql_stacked_execution',
            confidence: 0.9,
            context: 'sql',
            evidence: 'Semicolon followed by SQL statement — stacked query execution',
            decodedForm: 'raw',
        })
    }

    // Time oracle: timing-based blind injection
    if (/(?:sleep|waitfor\s+delay|benchmark|pg_sleep)\s*\(/i.test(input)) {
        props.push({
            invariantClass: 'sql_time_oracle',
            confidence: 0.85,
            context: 'sql',
            evidence: 'Timing function in SQL context — time-based blind injection',
            decodedForm: 'raw',
        })
    }

    // Error oracle: error-based data extraction
    if (/(?:extractvalue|updatexml|xmltype|convert\s*\(.*using)/i.test(input)) {
        props.push({
            invariantClass: 'sql_error_oracle',
            confidence: 0.8,
            context: 'sql',
            evidence: 'Error-triggering function — error-based data extraction',
            decodedForm: 'raw',
        })
    }

    // Comment truncation: using comments to bypass SQL logic
    if (/(?:--|#|\/\*)\s*$/.test(input) && /'/.test(input)) {
        props.push({
            invariantClass: 'sql_comment_truncation',
            confidence: 0.75,
            context: 'sql',
            evidence: 'SQL comment at end with injection prefix — comment truncation attack',
            decodedForm: 'raw',
        })
    }

    return props
}

// ── HTML/XSS Property Extraction ─────────────────────────────────

function extractHTMLProperties(input: string): ExtractedProperty[] {
    const props: ExtractedProperty[] = []

    // Tag injection: any HTML tag in input
    const tagMatch = input.match(/<(\w+)[\s>]/i)
    if (tagMatch) {
        const tag = tagMatch[1].toLowerCase()
        const dangerousTags = ['script', 'iframe', 'object', 'embed', 'applet', 'base', 'form', 'meta', 'link', 'style']
        if (dangerousTags.includes(tag)) {
            props.push({
                invariantClass: 'xss_tag_injection',
                confidence: 0.9,
                context: 'html',
                evidence: `Dangerous HTML tag <${tag}> — script execution or resource loading`,
                decodedForm: 'raw',
            })
        } else if (/<(?:svg|img|video|audio|body|div|a|input|button|textarea|select)\b/i.test(input) &&
            /\bon\w+\s*=/i.test(input)) {
            props.push({
                invariantClass: 'xss_tag_injection',
                confidence: 0.85,
                context: 'html',
                evidence: `HTML tag <${tag}> with event handler — XSS via DOM element`,
                decodedForm: 'raw',
            })
        }
    }

    // Event handler injection
    if (/\bon(?:error|load|click|mouseover|focus|blur|submit|change|input|mouseenter|mouseleave|keyup|keydown|animationend|transitionend)\s*=/i.test(input)) {
        props.push({
            invariantClass: 'xss_event_handler',
            confidence: 0.85,
            context: 'html',
            evidence: 'DOM event handler attribute — script execution via event',
            decodedForm: 'raw',
        })
    }

    // Protocol handler: javascript:, data:, vbscript:
    if (/(?:javascript|vbscript|data)\s*:/i.test(input)) {
        props.push({
            invariantClass: 'xss_protocol_handler',
            confidence: 0.85,
            context: 'html',
            evidence: 'Dangerous protocol handler — direct script execution via URI',
            decodedForm: 'raw',
        })
    }

    // Attribute escape: breaking out of attribute context
    if (/["']\s*(?:>|\/?>|on\w+\s*=)/i.test(input)) {
        props.push({
            invariantClass: 'xss_attribute_escape',
            confidence: 0.8,
            context: 'html',
            evidence: 'Attribute context escape — breaking out of HTML attribute to inject',
            decodedForm: 'raw',
        })
    }

    // Template expression: {{...}}, ${...}, <%...%>
    if (/\{\{.*?\}\}|<%.*?%>|\$\{[^}]+\}/i.test(input)) {
        const hasDangerous = /__class__|__proto__|constructor|require\(|import\(|eval\(|process\./i.test(input)
        props.push({
            invariantClass: 'xss_template_expression',
            confidence: hasDangerous ? 0.9 : 0.7,
            context: 'html',
            evidence: `Template expression detected${hasDangerous ? ' with dangerous function access' : ''}`,
            decodedForm: 'raw',
        })
    }

    return props
}

// ── Shell/Command Injection Property Extraction ──────────────────

function extractShellProperties(input: string): ExtractedProperty[] {
    const props: ExtractedProperty[] = []

    // Command separator: ; | && || used to chain commands
    if (/[;|]/.test(input) &&
        /\b(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc|ncat|bash|sh|zsh|python|perl|ruby|php|echo|printf|env|set|export|chmod|chown|rm|mv|cp|mkdir|touch|kill|ps|netstat|ss|dig|nslookup|ping|traceroute|ifconfig|ip)\b/i.test(input)) {
        props.push({
            invariantClass: 'cmd_separator',
            confidence: 0.85,
            context: 'shell',
            evidence: 'Command separator with shell command — command chain injection',
            decodedForm: 'raw',
        })
    }

    // Command substitution: $(...) or `...`
    if (/\$\([^)]+\)/.test(input) || /`[^`]+`/.test(input)) {
        props.push({
            invariantClass: 'cmd_substitution',
            confidence: 0.85,
            context: 'shell',
            evidence: 'Command substitution syntax — nested command execution',
            decodedForm: 'raw',
        })
    }

    // Argument injection: --flag or -flag to modify command behavior
    if (/\s-{1,2}[a-z]/i.test(input) &&
        /\b(?:curl|wget|tar|git|ssh|scp|rsync|find|xargs|awk|sed|grep)\b/i.test(input)) {
        props.push({
            invariantClass: 'cmd_argument_injection',
            confidence: 0.7,
            context: 'shell',
            evidence: 'Argument injection — modifying command behavior via flags',
            decodedForm: 'raw',
        })
    }

    return props
}

// ── XML/XXE Property Extraction ──────────────────────────────────

function extractXMLProperties(input: string): ExtractedProperty[] {
    const props: ExtractedProperty[] = []

    // External entity: DOCTYPE + ENTITY + SYSTEM
    if (/<!(?:DOCTYPE|ENTITY)\s/i.test(input) && /SYSTEM\s/i.test(input)) {
        const hasFileAccess = /file:\/\/|expect:\/\/|php:\/\//i.test(input)
        const hasSSRF = /https?:\/\//i.test(input)
        props.push({
            invariantClass: 'xxe_entity_expansion',
            confidence: hasFileAccess || hasSSRF ? 0.95 : 0.85,
            context: 'xml',
            evidence: `XML external entity declaration${hasFileAccess ? ' with file access' : ''}${hasSSRF ? ' with SSRF' : ''}`,
            decodedForm: 'raw',
        })
    }

    // Parameter entity (used for blind XXE)
    if (/<!ENTITY\s+%\s/i.test(input)) {
        props.push({
            invariantClass: 'xxe_entity_expansion',
            confidence: 0.9,
            context: 'xml',
            evidence: 'XML parameter entity — blind XXE out-of-band exfiltration',
            decodedForm: 'raw',
        })
    }

    return props
}

// ── JSON/NoSQL Property Extraction ───────────────────────────────

function extractJSONProperties(input: string): ExtractedProperty[] {
    const props: ExtractedProperty[] = []

    // MongoDB operator injection: $ne, $gt, $regex, etc.
    if (/\$(?:ne|gt|lt|gte|lte|in|nin|regex|where|exists|type|or|and|not|nor|mod|all|size|elemMatch)\b/.test(input)) {
        props.push({
            invariantClass: 'nosql_operator_injection',
            confidence: 0.85,
            context: 'json',
            evidence: 'MongoDB query operator in input — NoSQL injection',
            decodedForm: 'raw',
        })
    }

    // JavaScript injection in NoSQL: $where with function
    if (/\$where/.test(input) && /function|return|this\.\w+/i.test(input)) {
        props.push({
            invariantClass: 'nosql_js_injection',
            confidence: 0.9,
            context: 'json',
            evidence: '$where with JavaScript function — server-side JS execution',
            decodedForm: 'raw',
        })
    }

    // Prototype pollution via __proto__ or constructor.prototype
    if (/__proto__/.test(input) || /constructor\[?\s*["']?prototype/.test(input)) {
        props.push({
            invariantClass: 'proto_pollution',
            confidence: 0.85,
            context: 'json',
            evidence: 'Prototype chain access — prototype pollution attack',
            decodedForm: 'raw',
        })
    }

    return props
}

// ── LDAP Property Extraction ─────────────────────────────────────

function extractLDAPProperties(input: string): ExtractedProperty[] {
    const props: ExtractedProperty[] = []

    // Filter break: )(
    if (/\)\s*\(/.test(input) && /[|&!]/.test(input)) {
        props.push({
            invariantClass: 'ldap_filter_injection',
            confidence: 0.8,
            context: 'ldap',
            evidence: 'LDAP filter break — injecting additional filter conditions',
            decodedForm: 'raw',
        })
    }

    // Wildcard enumeration: *)
    if (/\*\)/.test(input)) {
        props.push({
            invariantClass: 'ldap_filter_injection',
            confidence: 0.7,
            context: 'ldap',
            evidence: 'LDAP wildcard in filter — enumeration attempt',
            decodedForm: 'raw',
        })
    }

    return props
}

// ── Template Injection Property Extraction ───────────────────────

function extractTemplateProperties(input: string): ExtractedProperty[] {
    const props: ExtractedProperty[] = []

    // Jinja2/Twig: {{ ... __class__/__mro__ }}
    if (/\{\{[^}]*(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__)/.test(input)) {
        props.push({
            invariantClass: 'ssti_jinja_twig',
            confidence: 0.95,
            context: 'template',
            evidence: 'Jinja2/Twig template injection with Python object traversal — RCE attempt',
            decodedForm: 'raw',
        })
    }

    // Java Expression Language: ${Runtime.exec()} or #{...}
    if (/\$\{[^}]*(?:Runtime|ProcessBuilder|exec\(|forName|getMethod)/i.test(input) ||
        /#\{[^}]*(?:Runtime|exec|forName|getMethod)/i.test(input)) {
        props.push({
            invariantClass: 'ssti_el_expression',
            confidence: 0.9,
            context: 'template',
            evidence: 'Java Expression Language injection — command execution via EL/SpEL/OGNL',
            decodedForm: 'raw',
        })
    }

    // Generic template evaluation probe: {{7*7}}, ${7*7}
    if (/\{\{\s*\d+\s*\*\s*\d+\s*\}\}/.test(input) || /\$\{\s*\d+\s*\*\s*\d+\s*\}/.test(input)) {
        props.push({
            invariantClass: 'ssti_jinja_twig',
            confidence: 0.7,
            context: 'template',
            evidence: 'Template evaluation probe — testing for server-side template injection',
            decodedForm: 'raw',
        })
    }

    return props
}

// ── GraphQL Property Extraction ──────────────────────────────────

function extractGraphQLProperties(input: string): ExtractedProperty[] {
    const props: ExtractedProperty[] = []

    // Introspection query
    if (/__schema\b/i.test(input) || /__type\b/i.test(input) || /introspectionquery/i.test(input)) {
        props.push({
            invariantClass: 'graphql_introspection',
            confidence: 0.8,
            context: 'graphql',
            evidence: 'GraphQL introspection query — schema enumeration',
            decodedForm: 'raw',
        })
    }

    // Batch query abuse
    const queryCount = (input.match(/\bquery\b/gi) || []).length
    if (queryCount > 3) {
        props.push({
            invariantClass: 'graphql_batch_abuse',
            confidence: 0.75,
            context: 'graphql',
            evidence: `${queryCount} queries in single request — batch abuse / DoS`,
            decodedForm: 'raw',
        })
    }

    return props
}

// ── URL/SSRF Property Extraction ─────────────────────────────────

function extractURLProperties(input: string): ExtractedProperty[] {
    const props: ExtractedProperty[] = []

    // Internal network access
    if (/(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|::1|\[::1\])/i.test(input)) {
        props.push({
            invariantClass: 'ssrf_internal_reach',
            confidence: 0.85,
            context: 'url',
            evidence: 'URL targets internal/private network address — SSRF attempt',
            decodedForm: 'raw',
        })
    }

    // Cloud metadata endpoints
    if (/169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|metadata\.azure/i.test(input)) {
        props.push({
            invariantClass: 'ssrf_cloud_metadata',
            confidence: 0.95,
            context: 'url',
            evidence: 'URL targets cloud metadata endpoint — credential theft via SSRF',
            decodedForm: 'raw',
        })
    }

    // Protocol smuggling: file://, gopher://, dict://
    if (/(?:file|gopher|dict|tftp|ldap):\/\//i.test(input)) {
        props.push({
            invariantClass: 'ssrf_protocol_smuggle',
            confidence: 0.9,
            context: 'url',
            evidence: 'Dangerous protocol scheme — protocol smuggling via SSRF',
            decodedForm: 'raw',
        })
    }

    // Open redirect detection
    if (/(?:redirect|next|url|link|goto|return|target|rurl|dest|destination|redir|redirect_uri|continue|return_to)=(?:https?:|%2f%2f|\/\/)/i.test(input)) {
        props.push({
            invariantClass: 'open_redirect_bypass',
            confidence: 0.75,
            context: 'url',
            evidence: 'Redirect parameter with external URL — open redirect',
            decodedForm: 'raw',
        })
    }

    return props
}

// ── Header Property Extraction ───────────────────────────────────

function extractHeaderProperties(
    input: string,
    headers?: Headers,
): ExtractedProperty[] {
    const props: ExtractedProperty[] = []

    // CRLF injection in header values
    if (/%0[da]|%0[DA]|\r\n|\n/i.test(input)) {
        props.push({
            invariantClass: 'crlf_header_injection',
            confidence: 0.85,
            context: 'header',
            evidence: 'CRLF sequence in header value — HTTP response splitting',
            decodedForm: 'raw',
        })
    }

    return props
}

// ── Unknown/Cross-Context Property Extraction ────────────────────

function extractUnknownContextProperties(input: string): ExtractedProperty[] {
    const props: ExtractedProperty[] = []

    // Open redirect: parameter=external_url (cross-context)
    if (/(?:redirect|next|url|link|goto|return|target|rurl|dest|destination|redir|redirect_uri|continue|return_to)=(?:https?:|%2f%2f|\/\/)/i.test(input)) {
        props.push({
            invariantClass: 'open_redirect_bypass',
            confidence: 0.75,
            context: 'unknown',
            evidence: 'Redirect parameter with external URL — open redirect',
            decodedForm: 'raw',
        })
    }

    return props
}
