/**
 * L2 Evaluator Registry — Self-Registering Detection Module System
 *
 * Eliminates the boilerplate growth problem in evaluator-bridge.ts.
 * Each evaluator registers a descriptor with:
 *   - detect(): the domain-specific detection function
 *   - typeToClass: maps evaluator-internal type strings to InvariantClass IDs
 *   - prefix: human-readable label for detail messages
 *
 * Adding a new evaluator = adding ONE descriptor entry here.
 * No changes to evaluator-bridge.ts, no changes to classToCategory/classToSeverity.
 *
 * INVARIANT: This registry is the single source of truth for L2 evaluator
 * routing. The bridge iterates it; the adapters reference it.
 */

import type { DetectionLevelResult, InvariantClass, Severity } from '../classes/types.js'
import { detectTautologies, type TautologyDetection } from './sql-expression-evaluator.js'
import { detectSqlStructural, type SqlStructuralDetection } from './sql-structural-evaluator.js'
import { detectXssVectors, type XssDetection } from './xss-context-evaluator.js'
import { detectCmdInjection, type CmdInjectionDetection } from './cmd-injection-evaluator.js'
import { detectPathTraversal, type PathTraversalDetection } from './path-traversal-evaluator.js'
import { detectSSRF, type SSRFDetection } from './ssrf-evaluator.js'
import { detectSSTI, type SSTIDetection } from './ssti-evaluator.js'
import { detectNoSQLInjection, type NoSQLDetection } from './nosql-evaluator.js'
import { detectXXE, type XXEDetection } from './xxe-evaluator.js'
import { detectCRLFInjection, type CRLFDetection } from './crlf-evaluator.js'
import { detectOpenRedirect, type OpenRedirectDetection } from './redirect-evaluator.js'
import { detectPrototypePollution, type ProtoPollutionDetection } from './proto-pollution-evaluator.js'
import { detectLog4Shell, type Log4ShellDetection } from './log4shell-evaluator.js'
import { detectDeserialization, type DeserDetection } from './deser-evaluator.js'
import { detectLDAPInjection, type LDAPDetection } from './ldap-evaluator.js'
import { detectGraphQLAbuse, type GraphQLDetection } from './graphql-evaluator.js'
import { detectHTTPSmuggling, type HTTPSmuggleDetection } from './http-smuggle-evaluator.js'
import { detectMassAssignment, type MassAssignmentDetection } from './mass-assignment-evaluator.js'
import { detectSupplyChain, type SupplyChainDetection } from './supply-chain-evaluator.js'
import { detectLLMInjection, type LLMDetection } from './llm-evaluator.js'
import { detectWebSocketAttack, type WebSocketDetection } from './websocket-evaluator.js'
import { detectJWTAbuse, type JWTDetection } from './jwt-evaluator.js'
import { detectCacheAttack, type CacheDetection } from './cache-evaluator.js'
import { detectAPIAbuse, type APIAbuseDetection } from './api-abuse-evaluator.js'
import { detectOAuthTheft, type OAuthDetection } from './oauth-theft-evaluator.js'


// ── Descriptor Interface ────────────────────────────────────────

/** Minimum shape every evaluator detection must satisfy */
export interface L2Detection {
    type: string
    confidence: number
    detail: string

    // Optional structured evidence for proof construction.
    // The proof system will consume this directly when available.
    proofEvidence?: {
        operation: 'context_escape' | 'payload_inject' | 'syntax_repair' | 'encoding_decode' | 'type_coerce' | 'semantic_eval'
        matchedInput: string
        interpretation: string
        offset: number
        property: string
    }[]
}

/**
 * Descriptor for a single L2 evaluator.
 * The registry collects these; the bridge iterates them.
 */
export interface L2EvaluatorDescriptor {
    /** Unique evaluator identifier (for diagnostics/stats) */
    readonly id: string
    /** Detection function returning typed detections */
    readonly detect: (input: string) => L2Detection[]
    /** Maps evaluator-specific type → InvariantClass */
    readonly typeToClass: Readonly<Record<string, InvariantClass>>
    /** Human-readable prefix for detail messages (e.g., "L2 SQL") */
    readonly prefix: string
}

type ProofEvidence = NonNullable<DetectionLevelResult['structuredEvidence']>[number]

function mapL2Detections<T extends { type: string; confidence: number; detail: string }>(
    input: string,
    detect: (input: string) => readonly T[],
    buildEvidence: (detection: T, input: string) => ProofEvidence[] | undefined,
): L2Detection[] {
    return detect(input).map(detection => ({
        type: detection.type,
        confidence: detection.confidence,
        detail: detection.detail,
        proofEvidence: buildEvidence(detection, input),
    }))
}


// ── Proof Evidence Helpers ──────────────────────────────────────

function buildSqlTautologyEvidence(t: TautologyDetection) {
    return [{
        operation: 'payload_inject' as const,
        matchedInput: t.expression,
        interpretation: 'Tautological expression evaluates to TRUE',
        offset: t.position,
        property: 'Boolean evaluation of SQL conditional expression must not be unconditional TRUE',
    }]
}

function buildSqlStructuralMatchedInput(input: string, detection: SqlStructuralDetection): string {
    const remaining = input.slice(detection.position)

    if (detection.type === 'string_termination') {
        const quote = input[detection.position]
        if (quote === '\'' || quote === '"') {
            let i = detection.position + 1
            while (i < input.length) {
                if (input[i] === quote) {
                    if (input[i + 1] === quote) {
                        i += 2
                        continue
                    }
                    return input.slice(detection.position, i + 1)
                }
                i++
            }
            const normalized = input.slice(detection.position).trimStart()
            return normalized.length > 0 ? normalized[0] : input.slice(detection.position)
        }
        const prefixMatch = detection.detail.match(/Injection prefix: quote terminator followed by\s+([^\s]+)/)
        if (prefixMatch?.[1] && remaining.startsWith(prefixMatch[1], 0)) {
            return `${input[detection.position]}${prefixMatch[1]}`
        }
    }

    if (detection.type === 'union_extraction') {
        const unionMatch = remaining.match(/^(UNION\b\s*(?:ALL\b\s*)?SELECT)\b/i)
        return unionMatch ? unionMatch[1] : remaining.match(/^\S+/)?.[0] ?? ''
    }

    if (detection.type === 'stacked_execution') {
        const stackedMatch = remaining.match(/^(;\s*[A-Za-z_][A-Za-z0-9_]*)/i)
        return stackedMatch ? stackedMatch[1] : remaining.match(/^\S+/)?.[0] ?? ''
    }

    if (detection.type === 'time_oracle') {
        const timeoutMatch = detection.detail.match(/^Time-delay function call: (.+?)\(/i)
        if (timeoutMatch?.[1]) {
            return `${timeoutMatch[1]}(`
        }
        if (/WAITFOR DELAY/.test(detection.detail)) {
            const waitMatch = remaining.match(/^(WAITFOR\s+DELAY)/i)
            return waitMatch ? waitMatch[1] : remaining.match(/^\S+/)?.[0] ?? ''
        }
        const benchmarkMatch = detection.detail.match(/^BENCHMARK with high iteration count:/i)
        if (benchmarkMatch) {
            return remaining.match(/^(BENCHMARK\s*\()/i)?.[0] ?? remaining.match(/^\S+/)?.[0] ?? ''
        }
    }

    if (detection.type === 'time_based_blind') {
        const blindMatch = remaining.match(/^(?:sleep|waitfor\s+delay|pg_sleep|benchmark|dbms_pipe\.receive_message)\s*\(/i)
        return blindMatch ? blindMatch[0] : detection.detail
    }

    if (detection.type === 'error_oracle') {
        const fn = detection.detail.match(/^Error-based extraction function: ([A-Za-z_][A-Za-z0-9_]* )?\(/)
        if (fn?.[1]) return `${fn[1].trim()}(`
        const fnMatch = detection.detail.match(/^Error-based extraction function: ([A-Za-z_][A-Za-z0-9_]*)/i)
        if (fnMatch?.[1]) return `${fnMatch[1]}(`
    }

    if (detection.type === 'comment_truncation') {
        const commentMatch = remaining.match(/^(--|#|\/\*)/)
        return commentMatch ? commentMatch[0] : remaining.match(/^\S+/)?.[0] ?? ''
    }

    return remaining.match(/^\S{1,60}/)?.[0] ?? ''
}

function buildSqlStructuralEvidence(detection: SqlStructuralDetection, input: string) {
    const propertyByType: Record<SqlStructuralDetection['type'], string> = {
        string_termination: 'String context must remain scoped; user input should not terminate the intended SQL literal',
        union_extraction: 'Injected SQL payloads must not introduce UNION query execution paths',
        stacked_execution: 'SQL statement boundary must remain single-statement unless explicitly intended',
        time_oracle: 'Execution time of SQL evaluation must remain independent of attacker-controlled timing',
        time_based_blind: 'Execution time of SQL evaluation must remain independent of attacker-controlled timing',
        error_oracle: 'SQL evaluation must not execute attacker-controlled error-reflection functions',
        comment_truncation: 'Injected SQL comments must not truncate application query semantics',
    }

    const interpretationByType: Record<SqlStructuralDetection['type'], string> = {
        string_termination: 'Input closes an application string context and injects SQL syntax',
        union_extraction: 'Input appends UNION SELECT and changes result set scope',
        stacked_execution: 'Input terminates one SQL statement and starts another',
        time_oracle: 'Input reaches a SQL timing function for delay-based logic',
        time_based_blind: 'Input contains time-delay function call for blind SQLi',
        error_oracle: 'Input reaches an SQL function used to trigger verbose database errors',
        comment_truncation: 'Input injects comment syntax to truncate remaining SQL statement',
    }

    return [{
        operation: 'payload_inject' as const,
        matchedInput: buildSqlStructuralMatchedInput(input, detection),
        interpretation: interpretationByType[detection.type],
        offset: detection.position,
        property: propertyByType[detection.type],
    }]
}

function extractTagFromOffset(input: string, offset: number): string {
    const remaining = input.slice(offset)
    const tagMatch = remaining.match(/^<[^>]*>?/)
    return tagMatch?.[0] ?? remaining.trim().split(/\s+/)[0] ?? ''
}

function buildXssEvidence(detection: XssDetection, input: string) {
    const interpretationByType: Record<XssDetection['type'], string> = {
        tag_injection: 'Dangerous HTML tag is injected into trusted markup context',
        event_handler: 'Untrusted attribute handler enables script execution in event context',
        protocol_handler: 'Attribute value introduces executable URI scheme into document sink',
        template_expression: 'Template-like attribute or node can be resolved as executable HTML context',
        attribute_escape: 'Attribute context has escaped into executable behavior',
        dom_clobbering: 'Named element shadows browser global object reference',
        mutation_xss: 'HTML parser namespace confusion mutates benign markup into executable form',
        dangling_markup: 'Unclosed attribute leaks subsequent page content to attacker-controlled endpoint',
        css_expression: 'CSS expression or binding executes attacker-controlled JavaScript',
    }

    const propertyByType: Record<XssDetection['type'], string> = {
        tag_injection: 'HTML context must not transition into executable tag context',
        event_handler: 'Event-handler attributes must remain inert for user input',
        protocol_handler: 'URI-bearing attributes must not evaluate attacker-controlled schemes',
        template_expression: 'Template contexts must not evaluate attacker-controlled expressions',
        attribute_escape: 'Attribute escaping must prevent interpreter transitions',
        dom_clobbering: 'Named DOM elements must not shadow browser globals',
        mutation_xss: 'HTML serialization round-trips must not introduce executable markup',
        dangling_markup: 'Unclosed attribute values must not steal subsequent document content',
        css_expression: 'CSS property values must not evaluate attacker-controlled expressions',
    }

    return [{
        operation: 'payload_inject' as const,
        matchedInput: extractTagFromOffset(input, detection.position),
        interpretation: interpretationByType[detection.type],
        offset: detection.position,
        property: propertyByType[detection.type],
    }]
}

function buildCmdEvidence(detection: CmdInjectionDetection, input: string) {
    const rawMatched = [detection.separator, detection.command].filter(Boolean).join(' ').trim()
    const matchedInput = rawMatched.length > 0
        ? rawMatched
        : input.slice(detection.position, detection.position + 16)

    return [{
        operation: 'payload_inject' as const,
        matchedInput,
        interpretation: detection.detail,
        offset: detection.position,
        property: 'Shell tokenization must treat user input as data, not executable syntax',
    }]
}


function buildPathTraversalEvidence(detection: PathTraversalDetection, input: string) {
    const evidence: Array<{
        operation: 'context_escape' | 'payload_inject' | 'syntax_repair' | 'encoding_decode'
        matchedInput: string
        interpretation: string
        offset: number
        property: string
    }> = []

    if (detection.type === 'dotdot_escape' || detection.type === 'normalization_bypass') {
        evidence.push({
            operation: 'context_escape',
            matchedInput: detection.resolvedPath ? `../ x${detection.escapeDepth}` : input.slice(0, 30),
            interpretation: detection.detail,
            offset: 0,
            property: 'File path must resolve within the application root directory',
        })
    }

    if (detection.type === 'encoding_bypass') {
        evidence.push({
            operation: 'encoding_decode',
            matchedInput: input.slice(0, 40),
            interpretation: detection.detail,
            offset: 0,
            property: 'Decoded path must not differ semantically from the encoded form in security-relevant ways',
        })
    }

    if (detection.type === 'null_terminate') {
        evidence.push({
            operation: 'syntax_repair',
            matchedInput: '%00',
            interpretation: detection.detail,
            offset: input.indexOf('%00'),
            property: 'Null bytes must not appear in file path input',
        })
    }

    if (detection.resolvedPath) {
        evidence.push({
            operation: 'payload_inject',
            matchedInput: detection.resolvedPath,
            interpretation: `Resolved target: ${detection.resolvedPath}`,
            offset: 0,
            property: 'Resolved file path must not reference sensitive system files',
        })
    }

    return evidence
}

function buildSsrfEvidence(detection: SSRFDetection, input: string) {
    const evidence: Array<{
        operation: 'context_escape' | 'payload_inject' | 'syntax_repair'
        matchedInput: string
        interpretation: string
        offset: number
        property: string
    }> = []

    if (detection.type === 'protocol_smuggle') {
        evidence.push({
            operation: 'context_escape',
            matchedInput: input.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:/)?.[0] ?? input.slice(0, 10),
            interpretation: detection.detail,
            offset: 0,
            property: 'URL scheme must be restricted to HTTP(S) for server-side requests',
        })
    }

    evidence.push({
        operation: 'payload_inject',
        matchedInput: detection.resolvedHost || detection.resolvedIP || input.slice(0, 30),
        interpretation: detection.detail,
        offset: input.indexOf(detection.resolvedHost) >= 0 ? input.indexOf(detection.resolvedHost) : 0,
        property: detection.type === 'cloud_metadata'
            ? 'Server-side request must not target cloud metadata endpoint'
            : 'Server-side request must not target internal/private network addresses',
    })

    return evidence
}

function buildXxeEvidence(detection: XXEDetection, input: string) {
    const matchedInput = detection.type === 'billion_laughs'
        ? input.match(/<!ENTITY\s+\w+\s+"[^"]*"/)?.[0] ?? input.slice(0, 40)
        : input.match(/SYSTEM\s+["'][^"']+["']/)?.[0] ??
          input.match(/<!ENTITY\s+[^>]+/)?.[0] ?? input.slice(0, 40)

    return [{
        operation: 'payload_inject' as const,
        matchedInput,
        interpretation: detection.detail,
        offset: 0,
        property: 'XML parser must not resolve external entities or allow recursive entity expansion',
    }]
}


function buildSstiEvidence(detection: SSTIDetection, input: string) {
    return [{
        operation: 'payload_inject' as const,
        matchedInput: detection.expression || input.slice(0, 40),
        interpretation: detection.detail,
        offset: input.indexOf(detection.expression) >= 0 ? input.indexOf(detection.expression) : 0,
        property: `Template expression must not execute arbitrary code in ${detection.engine} engine`,
    }]
}

function buildNoSqlEvidence(detection: NoSQLDetection, input: string) {
    return [{
        operation: 'payload_inject' as const,
        matchedInput: detection.operator || input.slice(0, 40),
        interpretation: detection.detail,
        offset: input.indexOf(detection.operator) >= 0 ? input.indexOf(detection.operator) : 0,
        property: 'NoSQL query operators must not appear in user-supplied input',
    }]
}

function buildCrlfEvidence(detection: CRLFDetection, input: string) {
    const crlfOffset = input.search(/\r\n|\r|\n/)
    return [{
        operation: 'context_escape' as const,
        matchedInput: detection.injectedHeader || input.slice(0, 40),
        interpretation: detection.detail,
        offset: crlfOffset >= 0 ? crlfOffset : 0,
        property: 'HTTP response headers must not contain user-controlled CRLF sequences',
    }]
}

function buildLog4ShellEvidence(detection: Log4ShellDetection, input: string) {
    return [{
        operation: 'payload_inject' as const,
        matchedInput: detection.resolvedExpression || input.slice(0, 40),
        interpretation: detection.detail,
        offset: input.indexOf('${') >= 0 ? input.indexOf('${') : 0,
        property: 'Log message must not contain JNDI lookup expressions that trigger remote class loading',
    }]
}

function buildDeserEvidence(detection: DeserDetection, input: string) {
    return [{
        operation: 'payload_inject' as const,
        matchedInput: detection.gadgetChain || detection.format || input.slice(0, 40),
        interpretation: detection.detail,
        offset: 0,
        property: `Deserialized ${detection.format} data must not contain executable gadget chains`,
    }]
}

function buildProtoPollutionEvidence(detection: ProtoPollutionDetection, input: string) {
    return [{
        operation: 'payload_inject' as const,
        matchedInput: detection.path || input.slice(0, 40),
        interpretation: detection.detail,
        offset: input.indexOf(detection.pollutedProperty) >= 0 ? input.indexOf(detection.pollutedProperty) : 0,
        property: `Object property path must not traverse __proto__/constructor.prototype`,
    }]
}

function buildOpenRedirectEvidence(detection: OpenRedirectDetection, input: string) {
    return [{
        operation: 'context_escape' as const,
        matchedInput: detection.extractedHost || input.slice(0, 40),
        interpretation: detection.detail,
        offset: 0,
        property: 'Redirect URL must not resolve to an external domain not in the allowlist',
    }]
}

function buildLdapEvidence(detections: LDAPDetection[]): ProofEvidence[] {
    const propertyByType: Record<LDAPDetection['type'], string> = {
        filter_break: 'LDAP filter structure must not be altered by untrusted input',
        wildcard_enum: 'LDAP filters must not permit wildcard-based enumeration on security attributes',
        auth_bypass: 'LDAP authentication filters must not be transformable into always-true predicates',
        operator_injection: 'LDAP logical operators must not be attacker-controlled',
    }

    return detections.map(detection => ({
        operation: 'payload_inject' as const,
        matchedInput: detection.attribute ?? detection.type,
        interpretation: detection.detail,
        offset: 0,
        property: propertyByType[detection.type],
    }))
}

function buildGraphqlEvidence(detections: GraphQLDetection[]): ProofEvidence[] {
    const propertyByType: Record<GraphQLDetection['type'], string> = {
        introspection: 'GraphQL schema metadata must not be exposed to untrusted clients',
        depth_abuse: 'GraphQL query depth must remain within configured limits',
        batch_abuse: 'GraphQL batching must not allow abusive operation fan-out',
        alias_abuse: 'GraphQL aliases must not amplify backend resolver load',
        fragment_abuse: 'GraphQL fragments must not create cyclic or amplification execution paths',
    }

    return detections.map(detection => ({
        operation: 'semantic_eval' as const,
        matchedInput: detection.evidence,
        interpretation: detection.detail,
        offset: 0,
        property: propertyByType[detection.type],
    }))
}

function buildHttpSmuggleEvidence(detections: HTTPSmuggleDetection[]): ProofEvidence[] {
    const propertyByType: Record<HTTPSmuggleDetection['type'], string> = {
        cl_te_desync: 'HTTP parsing must produce a single unambiguous message length interpretation',
        te_te_desync: 'Transfer-Encoding must not admit parser ambiguity across intermediaries',
        te_obfuscation: 'Transfer-Encoding syntax must not allow obfuscated smuggling variants',
        h2_pseudo_header: 'HTTP/2 pseudo-headers must not be interpreted as tunneled HTTP/1 request boundaries',
        h2_crlf: 'HTTP/2 pseudo-header values must not contain CRLF request-splitting controls',
        chunked_body: 'Chunked message termination must not permit appended smuggled requests',
    }

    return detections.map(detection => ({
        operation: 'context_escape' as const,
        matchedInput: detection.type,
        interpretation: detection.detail,
        offset: 0,
        property: propertyByType[detection.type],
    }))
}

function buildMassAssignmentEvidence(detections: MassAssignmentDetection[]): ProofEvidence[] {
    const propertyByType: Record<MassAssignmentDetection['type'], string> = {
        privilege_injection: 'API binding must not allow direct assignment of privileged fields',
        suspicious_key_combo: 'Untrusted object binding must not include privilege-escalation key combinations',
        nested_privilege_injection: 'Nested object binding must not permit privilege field injection',
    }

    return detections.map(detection => ({
        operation: 'type_coerce' as const,
        matchedInput: detection.evidence,
        interpretation: detection.detail,
        offset: 0,
        property: propertyByType[detection.type],
    }))
}

function buildSupplyChainEvidence(detections: SupplyChainDetection[]): ProofEvidence[] {
    const propertyByType: Record<SupplyChainDetection['type'], string> = {
        dependency_confusion: 'Dependency resolution must not allow private package shadowing by untrusted sources',
        postinstall_injection: 'Lifecycle scripts must not execute untrusted code during package installation',
        env_exfiltration: 'Build/runtime environment secrets must not flow to outbound network sinks',
    }

    return detections.map(detection => ({
        operation: 'semantic_eval' as const,
        matchedInput: detection.indicators.join('; ') || detection.type,
        interpretation: detection.detail,
        offset: 0,
        property: propertyByType[detection.type],
    }))
}

function buildLlmEvidence(detections: LLMDetection[]): ProofEvidence[] {
    const propertyByType: Record<LLMDetection['type'], string> = {
        prompt_injection: 'Untrusted prompt segments must not override higher-priority instructions',
        data_exfiltration: 'Model outputs must not disclose protected or confidential internal context',
        jailbreak: 'Prompt inputs must not disable safety policy constraints',
    }

    return detections.map(detection => ({
        operation: 'semantic_eval' as const,
        matchedInput: detection.technique,
        interpretation: detection.detail,
        offset: 0,
        property: propertyByType[detection.type],
    }))
}

function buildWebsocketEvidence(detections: WebSocketDetection[]): ProofEvidence[] {
    const propertyByType: Record<WebSocketDetection['type'], string> = {
        ws_injection: 'WebSocket frame payloads must not carry executable injection vectors',
        ws_hijack: 'WebSocket upgrade handshake must enforce origin and header integrity checks',
    }

    return detections.map(detection => ({
        operation: detection.type === 'ws_hijack' ? 'context_escape' as const : 'payload_inject' as const,
        matchedInput: detection.indicators.join('; ') || detection.type,
        interpretation: detection.detail,
        offset: 0,
        property: propertyByType[detection.type],
    }))
}

function buildJwtEvidence(detections: JWTDetection[]): ProofEvidence[] {
    const propertyByType: Record<JWTDetection['type'], string> = {
        jwt_kid_injection: 'JWT key identifier fields must not be interpreted as executable or traversal input',
        jwt_jwk_embedding: 'JWT headers must not accept attacker-controlled embedded signing key material',
        jwt_confusion: 'JWT verification algorithm must not permit asymmetric-to-symmetric confusion',
    }

    return detections.map(detection => ({
        operation: 'payload_inject' as const,
        matchedInput: detection.headerFields.join(',') || detection.type,
        interpretation: detection.detail,
        offset: 0,
        property: propertyByType[detection.type],
    }))
}

function buildCacheEvidence(detections: CacheDetection[]): ProofEvidence[] {
    const propertyByType: Record<CacheDetection['type'], string> = {
        cache_poisoning: 'Cache keys must incorporate attacker-controlled request metadata influencing responses',
        cache_deception: 'Dynamic application content must not be cacheable via static-path deception',
    }

    return detections.map(detection => ({
        operation: 'context_escape' as const,
        matchedInput: detection.type,
        interpretation: detection.detail,
        offset: 0,
        property: propertyByType[detection.type],
    }))
}

function buildApiAbuseEvidence(detections: APIAbuseDetection[]): ProofEvidence[] {
    const propertyByType: Record<APIAbuseDetection['type'], string> = {
        bola_idor: 'Object access authorization must be enforced per resource identifier',
        api_mass_enum: 'API enumeration controls must bound object discovery and extraction rates',
    }

    return detections.map(detection => ({
        operation: 'semantic_eval' as const,
        matchedInput: detection.type,
        interpretation: detection.detail,
        offset: 0,
        property: propertyByType[detection.type],
    }))
}


// ── Category + Severity Data ────────────────────────────────────

/**
 * Data-driven class → category mapping.
 * Single source of truth — replaces the if/else chain in evaluator-bridge.
 */
export const CLASS_CATEGORY: Readonly<Record<string, string>> = {
    // SQL
    sql_tautology: 'sqli', sql_string_termination: 'sqli', sql_union_extraction: 'sqli',
    sql_stacked_execution: 'sqli', sql_time_oracle: 'sqli', sql_error_oracle: 'sqli',
    sql_comment_truncation: 'sqli', json_sql_bypass: 'sqli',
    // NoSQL
    nosql_operator_injection: 'sqli', nosql_js_injection: 'sqli',
    // XSS
    xss_tag_injection: 'xss', xss_event_handler: 'xss', xss_protocol_handler: 'xss',
    xss_template_expression: 'xss', xss_attribute_escape: 'xss', css_injection: 'xss',
    // CMDi
    cmd_separator: 'cmdi', cmd_substitution: 'cmdi', cmd_argument_injection: 'cmdi',
    // Path traversal
    path_dotdot_escape: 'path_traversal', path_null_terminate: 'path_traversal',
    path_encoding_bypass: 'path_traversal', path_normalization_bypass: 'path_traversal',
    path_windows_traversal: 'path_traversal',
    // SSRF
    ssrf_internal_reach: 'ssrf', ssrf_cloud_metadata: 'ssrf', ssrf_protocol_smuggle: 'ssrf',
    // Deser
    deser_java_gadget: 'deser', deser_php_object: 'deser', deser_python_pickle: 'deser', yaml_deserialization: 'deser',
    // SSTI
    ssti_jinja_twig: 'injection', ssti_el_expression: 'injection', template_injection_generic: 'injection',
    // Auth
    auth_none_algorithm: 'auth', auth_header_spoof: 'auth', credential_stuffing: 'auth', cors_origin_abuse: 'auth',
    mass_assignment: 'auth',
    // JWT
    jwt_kid_injection: 'auth', jwt_jwk_embedding: 'auth', jwt_confusion: 'auth',
    // OAuth / PKCE / token
    oauth_token_leak: 'auth', oauth_state_missing: 'auth', oauth_redirect_hijack: 'auth',
    oauth_redirect_uri_bypass: 'auth', oauth_state_bypass: 'auth', pkce_downgrade: 'auth',
    bearer_token_exposure: 'auth',
    // Proto
    proto_pollution: 'injection', prototype_pollution_via_query: 'injection', proto_pollution_gadget: 'injection',
    // Log4Shell
    log_jndi_lookup: 'injection',
    // XXE / XML
    xxe_entity_expansion: 'injection', xml_injection: 'injection',
    // CRLF
    crlf_header_injection: 'injection', crlf_log_injection: 'injection',
    // GraphQL
    graphql_introspection: 'injection', graphql_batch_abuse: 'injection',
    // Redirect
    open_redirect_bypass: 'injection',
    // ReDoS
    regex_dos: 'injection',
    // HTTP Smuggling
    http_smuggle_cl_te: 'smuggling', http_smuggle_h2: 'smuggling',
    http_smuggle_chunk_ext: 'smuggling', http_smuggle_zero_cl: 'smuggling',
    http_smuggle_expect: 'smuggling',
    // Supply chain
    dependency_confusion: 'injection', postinstall_injection: 'injection',
    env_exfiltration: 'injection',
    // LLM
    llm_prompt_injection: 'injection', llm_data_exfiltration: 'injection',
    llm_jailbreak: 'injection', llm_token_smuggling: 'injection',
    // WebSocket
    ws_injection: 'injection', ws_hijack: 'injection',
    // Cache
    cache_poisoning: 'injection', cache_deception: 'injection',
    // API abuse
    bola_idor: 'injection', api_mass_enum: 'injection',
}

/**
 * Data-driven class → severity mapping.
 * Single source of truth — replaces the if/else chain in evaluator-bridge.
 */
export const CLASS_SEVERITY: Readonly<Record<string, Severity>> = {
    // Critical
    cmd_separator: 'critical', cmd_substitution: 'critical',
    sql_stacked_execution: 'critical', sql_union_extraction: 'critical',
    ssrf_cloud_metadata: 'critical',
    ssti_jinja_twig: 'critical', ssti_el_expression: 'critical',
    deser_java_gadget: 'critical', deser_python_pickle: 'critical', yaml_deserialization: 'critical',
    log_jndi_lookup: 'critical', xxe_entity_expansion: 'critical',
    http_smuggle_cl_te: 'critical', http_smuggle_h2: 'critical',
    auth_none_algorithm: 'critical',
    postinstall_injection: 'critical',
    llm_data_exfiltration: 'critical', llm_jailbreak: 'critical',
    jwt_kid_injection: 'critical', jwt_jwk_embedding: 'critical', jwt_confusion: 'critical',
    nosql_operator_injection: 'critical',
    oauth_redirect_uri_bypass: 'high', oauth_redirect_hijack: 'high', pkce_downgrade: 'high',
    bearer_token_exposure: 'high', oauth_token_leak: 'high', oauth_state_missing: 'high',
    oauth_state_bypass: 'high',
    // High
    sql_tautology: 'high', sql_time_oracle: 'high', sql_error_oracle: 'high',
    sql_string_termination: 'high',
    ssrf_internal_reach: 'high', ssrf_protocol_smuggle: 'high',
    path_dotdot_escape: 'high', path_encoding_bypass: 'high',
    path_windows_traversal: 'high',
    xss_tag_injection: 'high', xss_event_handler: 'high', xss_protocol_handler: 'high',
    css_injection: 'high',
    nosql_js_injection: 'high',
    crlf_header_injection: 'high', proto_pollution: 'high', prototype_pollution_via_query: 'high',
    deser_php_object: 'high', ldap_filter_injection: 'high',
    cmd_argument_injection: 'high', graphql_batch_abuse: 'high',
    mass_assignment: 'high', xml_injection: 'high',
    dependency_confusion: 'high', env_exfiltration: 'high',
    llm_prompt_injection: 'high', llm_token_smuggling: 'high', ws_injection: 'high', ws_hijack: 'high',
    cache_poisoning: 'high', cache_deception: 'high', bola_idor: 'high',
    json_sql_bypass: 'high', proto_pollution_gadget: 'high',
    // Medium
    cors_origin_abuse: 'medium', crlf_log_injection: 'medium',
    open_redirect_bypass: 'medium', regex_dos: 'medium',
    graphql_introspection: 'medium', sql_comment_truncation: 'medium',
    path_null_terminate: 'medium', path_normalization_bypass: 'medium',
    xss_template_expression: 'medium', xss_attribute_escape: 'medium',
    auth_header_spoof: 'medium', credential_stuffing: 'high', api_mass_enum: 'medium',
    template_injection_generic: 'high',
    http_smuggle_chunk_ext: 'medium', http_smuggle_zero_cl: 'medium',
    http_smuggle_expect: 'medium',
}

/** Look up category for a class, with prefix-based fallback */
export function lookupCategory(cls: InvariantClass): string {
    return CLASS_CATEGORY[cls] ?? 'injection'
}

/** Look up severity for a class, with 'high' fallback */
export function lookupSeverity(cls: InvariantClass): Severity {
    return CLASS_SEVERITY[cls] ?? 'high'
}


// ── Evaluator Descriptors ───────────────────────────────────────

export const L2_EVALUATOR_DESCRIPTORS: readonly L2EvaluatorDescriptor[] = [
    // SQL: Tautology (special — wraps TautologyDetection into L2Detection shape)
    {
        id: 'sql_tautology',
        detect: (input: string) => detectTautologies(input).map(t => ({
            type: 'tautology' as const,
            confidence: 0.92,
            detail: `tautology: ${t.expression}`,
            proofEvidence: buildSqlTautologyEvidence(t),
        })),
        typeToClass: { tautology: 'sql_tautology' as InvariantClass },
        prefix: 'L2 SQL',
    },

    // SQL: Structural analysis (6 classes)
    {
        id: 'sql_structural',
        detect: (input: string) => mapL2Detections(input, detectSqlStructural, buildSqlStructuralEvidence),
        typeToClass: {
            string_termination: 'sql_string_termination' as InvariantClass,
            union_extraction: 'sql_union_extraction' as InvariantClass,
            stacked_execution: 'sql_stacked_execution' as InvariantClass,
            time_oracle: 'sql_time_oracle' as InvariantClass,
            error_oracle: 'sql_error_oracle' as InvariantClass,
            comment_truncation: 'sql_comment_truncation' as InvariantClass,
        },
        prefix: 'L2 SQL',
    },

    // XSS: Context-aware HTML analysis (5 classes)
    {
        id: 'xss_context',
        detect: (input: string) => mapL2Detections(input, detectXssVectors, buildXssEvidence),
        typeToClass: {
            tag_injection: 'xss_tag_injection' as InvariantClass,
            event_handler: 'xss_event_handler' as InvariantClass,
            protocol_handler: 'xss_protocol_handler' as InvariantClass,
            template_expression: 'xss_template_expression' as InvariantClass,
            attribute_escape: 'xss_attribute_escape' as InvariantClass,
        },
        prefix: 'L2 XSS',
    },

    // Command Injection (3 classes — invariant-based structural detection)
    {
        id: 'cmd_injection',
        detect: (input: string) => mapL2Detections(input, detectCmdInjection, buildCmdEvidence),
        typeToClass: {
            // Primary structural violations
            separator: 'cmd_separator' as InvariantClass,
            substitution: 'cmd_substitution' as InvariantClass,
            argument_injection: 'cmd_argument_injection' as InvariantClass,
            // Extended invariant violations (new — structural, not signature-based)
            variable_expansion: 'cmd_substitution' as InvariantClass,
            quote_fragmentation: 'cmd_separator' as InvariantClass,
            glob_path: 'cmd_separator' as InvariantClass,
            structural: 'cmd_separator' as InvariantClass,
            redirection: 'cmd_argument_injection' as InvariantClass,
            heredoc: 'cmd_argument_injection' as InvariantClass,
        },
        prefix: 'L2 CMDi',
    },

    // Path Traversal (4 classes)
    {
        id: 'path_traversal',
        detect: (input: string) => mapL2Detections(input, detectPathTraversal, buildPathTraversalEvidence),
        typeToClass: {
            dotdot_escape: 'path_dotdot_escape' as InvariantClass,
            null_terminate: 'path_null_terminate' as InvariantClass,
            encoding_bypass: 'path_encoding_bypass' as InvariantClass,
            normalization_bypass: 'path_normalization_bypass' as InvariantClass,
        },
        prefix: 'L2 Path',
    },

    // SSRF (3 classes)
    {
        id: 'ssrf',
        detect: (input: string) => mapL2Detections(input, detectSSRF, buildSsrfEvidence),
        typeToClass: {
            internal_reach: 'ssrf_internal_reach' as InvariantClass,
            cloud_metadata: 'ssrf_cloud_metadata' as InvariantClass,
            protocol_smuggle: 'ssrf_protocol_smuggle' as InvariantClass,
        },
        prefix: 'L2 SSRF',
    },

    // SSTI (2 classes)
    {
        id: 'ssti',
        detect: (input: string) => mapL2Detections(input, detectSSTI, buildSstiEvidence),
        typeToClass: {
            jinja_twig: 'ssti_jinja_twig' as InvariantClass,
            el_expression: 'ssti_el_expression' as InvariantClass,
        },
        prefix: 'L2 SSTI',
    },

    // NoSQL (2 classes)
    {
        id: 'nosql',
        detect: (input: string) => mapL2Detections(input, detectNoSQLInjection, buildNoSqlEvidence),
        typeToClass: {
            operator_injection: 'nosql_operator_injection' as InvariantClass,
            js_injection: 'nosql_js_injection' as InvariantClass,
        },
        prefix: 'L2 NoSQL',
    },

    // XXE (1 class — maps multiple detection types to single class)
    {
        id: 'xxe',
        detect: (input: string) => mapL2Detections(input, detectXXE, buildXxeEvidence),
        typeToClass: {
            external_entity: 'xxe_entity_expansion' as InvariantClass,
            parameter_entity: 'xxe_entity_expansion' as InvariantClass,
            billion_laughs: 'xxe_entity_expansion' as InvariantClass,
            entity_expansion: 'xxe_entity_expansion' as InvariantClass,
        },
        prefix: 'L2 XXE',
    },

    // CRLF (2 classes)
    {
        id: 'crlf',
        detect: (input: string) => mapL2Detections(input, detectCRLFInjection, buildCrlfEvidence),
        typeToClass: {
            header_injection: 'crlf_header_injection' as InvariantClass,
            response_split: 'crlf_header_injection' as InvariantClass,
            log_injection: 'crlf_log_injection' as InvariantClass,
        },
        prefix: 'L2 CRLF',
    },

    // Open Redirect (1 class — maps all types to single class)
    {
        id: 'open_redirect',
        detect: (input: string) => mapL2Detections(input, detectOpenRedirect, buildOpenRedirectEvidence),
        typeToClass: {
            protocol_relative: 'open_redirect_bypass' as InvariantClass,
            backslash: 'open_redirect_bypass' as InvariantClass,
            auth_confusion: 'open_redirect_bypass' as InvariantClass,
            data_uri: 'open_redirect_bypass' as InvariantClass,
            javascript_uri: 'open_redirect_bypass' as InvariantClass,
            domain_bypass: 'open_redirect_bypass' as InvariantClass,
        },
        prefix: 'L2 Redirect',
    },

    // Prototype Pollution (1 class)
    {
        id: 'proto_pollution',
        detect: (input: string) => mapL2Detections(input, detectPrototypePollution, buildProtoPollutionEvidence),
        typeToClass: {
            proto_key_assignment: 'proto_pollution' as InvariantClass,
            constructor_chain: 'proto_pollution' as InvariantClass,
            json_proto_path: 'proto_pollution' as InvariantClass,
            bracket_proto_path: 'proto_pollution' as InvariantClass,
        },
        prefix: 'L2 Proto',
    },

    // Log4Shell (1 class)
    {
        id: 'log4shell',
        detect: (input: string) => mapL2Detections(input, detectLog4Shell, buildLog4ShellEvidence),
        typeToClass: {
            jndi_direct: 'log_jndi_lookup' as InvariantClass,
            jndi_obfuscated: 'log_jndi_lookup' as InvariantClass,
            env_exfil: 'log_jndi_lookup' as InvariantClass,
            nested_lookup: 'log_jndi_lookup' as InvariantClass,
        },
        prefix: 'L2 Log4Shell',
    },

    // Deserialization (3 classes)
    {
        id: 'deser',
        detect: (input: string) => mapL2Detections(input, detectDeserialization, buildDeserEvidence),
        typeToClass: {
            java_gadget: 'deser_java_gadget' as InvariantClass,
            php_object: 'deser_php_object' as InvariantClass,
            python_pickle: 'deser_python_pickle' as InvariantClass,
        },
        prefix: 'L2 Deser',
    },

    // LDAP (1 class)
    {
        id: 'ldap',
        detect: (input: string) => mapL2Detections(input, detectLDAPInjection, (detection, _input) => buildLdapEvidence([detection])),
        typeToClass: {
            filter_break: 'ldap_filter_injection' as InvariantClass,
            wildcard_enum: 'ldap_filter_injection' as InvariantClass,
            auth_bypass: 'ldap_filter_injection' as InvariantClass,
            operator_injection: 'ldap_filter_injection' as InvariantClass,
        },
        prefix: 'L2 LDAP',
    },

    // GraphQL (2 classes)
    {
        id: 'graphql',
        detect: (input: string) => mapL2Detections(input, detectGraphQLAbuse, (detection, _input) => buildGraphqlEvidence([detection])),
        typeToClass: {
            introspection: 'graphql_introspection' as InvariantClass,
            depth_abuse: 'graphql_batch_abuse' as InvariantClass,
            batch_abuse: 'graphql_batch_abuse' as InvariantClass,
            alias_abuse: 'graphql_batch_abuse' as InvariantClass,
            fragment_abuse: 'graphql_batch_abuse' as InvariantClass,
        },
        prefix: 'L2 GraphQL',
    },

    // HTTP Smuggling (2 classes)
    {
        id: 'http_smuggle',
        detect: (input: string) => mapL2Detections(input, detectHTTPSmuggling, (detection, _input) => buildHttpSmuggleEvidence([detection])),
        typeToClass: {
            cl_te_desync: 'http_smuggle_cl_te' as InvariantClass,
            te_te_desync: 'http_smuggle_cl_te' as InvariantClass,
            te_obfuscation: 'http_smuggle_cl_te' as InvariantClass,
            chunked_body: 'http_smuggle_cl_te' as InvariantClass,
            h2_pseudo_header: 'http_smuggle_h2' as InvariantClass,
            h2_crlf: 'http_smuggle_h2' as InvariantClass,
        },
        prefix: 'L2 Smuggle',
    },

    // Mass Assignment (1 class)
    {
        id: 'mass_assignment',
        detect: (input: string) => mapL2Detections(input, detectMassAssignment, (detection, _input) => buildMassAssignmentEvidence([detection])),
        typeToClass: {
            privilege_injection: 'mass_assignment' as InvariantClass,
            suspicious_key_combo: 'mass_assignment' as InvariantClass,
            nested_privilege_injection: 'mass_assignment' as InvariantClass,
        },
        prefix: 'L2 MassAssign',
    },

    // Supply Chain (3 classes)
    {
        id: 'supply_chain',
        detect: (input: string) => mapL2Detections(input, detectSupplyChain, (detection, _input) => buildSupplyChainEvidence([detection])),
        typeToClass: {
            dependency_confusion: 'dependency_confusion' as InvariantClass,
            postinstall_injection: 'postinstall_injection' as InvariantClass,
            env_exfiltration: 'env_exfiltration' as InvariantClass,
        },
        prefix: 'L2 SupplyChain',
    },

    // LLM Injection (3 classes)
    {
        id: 'llm',
        detect: (input: string) => mapL2Detections(input, detectLLMInjection, (detection, _input) => buildLlmEvidence([detection])),
        typeToClass: {
            prompt_injection: 'llm_prompt_injection' as InvariantClass,
            data_exfiltration: 'llm_data_exfiltration' as InvariantClass,
            jailbreak: 'llm_jailbreak' as InvariantClass,
        },
        prefix: 'L2 LLM',
    },

    // WebSocket (2 classes)
    {
        id: 'websocket',
        detect: (input: string) => mapL2Detections(input, detectWebSocketAttack, (detection, _input) => buildWebsocketEvidence([detection])),
        typeToClass: {
            ws_injection: 'ws_injection' as InvariantClass,
            ws_hijack: 'ws_hijack' as InvariantClass,
        },
        prefix: 'L2 WebSocket',
    },

    // JWT Abuse (3 classes)
    {
        id: 'jwt',
        detect: (input: string) => mapL2Detections(input, detectJWTAbuse, (detection, _input) => buildJwtEvidence([detection])),
        typeToClass: {
            jwt_kid_injection: 'jwt_kid_injection' as InvariantClass,
            jwt_jwk_embedding: 'jwt_jwk_embedding' as InvariantClass,
            jwt_confusion: 'jwt_confusion' as InvariantClass,
        },
        prefix: 'L2 JWT',
    },

    // Cache Attacks (2 classes)
    {
        id: 'cache',
        detect: (input: string) => mapL2Detections(input, detectCacheAttack, (detection, _input) => buildCacheEvidence([detection])),
        typeToClass: {
            cache_poisoning: 'cache_poisoning' as InvariantClass,
            cache_deception: 'cache_deception' as InvariantClass,
        },
        prefix: 'L2 Cache',
    },

    // API Abuse (2 classes)
    {
        id: 'api_abuse',
        detect: (input: string) => mapL2Detections(input, detectAPIAbuse, (detection, _input) => buildApiAbuseEvidence([detection])),
        typeToClass: {
            bola_idor: 'bola_idor' as InvariantClass,
            api_mass_enum: 'api_mass_enum' as InvariantClass,
        },
        prefix: 'L2 API',
    },

    // OAuth Theft / PKCE Bypass (5 detection types → auth classes)
    {
        id: 'oauth_theft',
        detect: (input: string) =>
            detectOAuthTheft(input).map((d: OAuthDetection) => ({
                type: d.type,
                confidence: d.confidence,
                detail: d.detail,
            })),
        typeToClass: {
            auth_code_interception: 'oauth_redirect_uri_bypass' as InvariantClass,
            pkce_downgrade: 'pkce_downgrade' as InvariantClass,
            oauth_mixup: 'oauth_state_missing' as InvariantClass,
            token_leakage_referrer: 'bearer_token_exposure' as InvariantClass,
            implicit_flow_abuse: 'oauth_token_leak' as InvariantClass,
        },
        prefix: 'L2 OAuth',
    },
]
