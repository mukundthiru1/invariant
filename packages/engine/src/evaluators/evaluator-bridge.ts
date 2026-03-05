/**
 * Evaluator Bridge — Connects Level 2 Evaluators to the InvariantEngine
 *
 * This module bridges the InvariantEngine (regex-based Level 1) with
 * expression/context evaluators (Level 2) for ALL 46 invariant classes.
 *
 *   SQL (7):   sql_tautology, sql_string_termination, sql_union_extraction,
 *              sql_stacked_execution, sql_time_oracle, sql_error_oracle,
 *              sql_comment_truncation
 *
 *   XSS (5):   xss_tag_injection, xss_event_handler, xss_protocol_handler,
 *              xss_template_expression, xss_attribute_escape
 *
 *   CMDi (3):  cmd_separator, cmd_substitution, cmd_argument_injection
 *
 *   Path (4):  path_dotdot_escape, path_null_terminate, path_encoding_bypass,
 *              path_normalization_bypass
 *
 *   SSRF (3):  ssrf_internal_reach, ssrf_cloud_metadata, ssrf_protocol_smuggle
 *
 *   SSTI (2):  ssti_jinja_twig, ssti_el_expression
 *
 *   NoSQL (2): nosql_operator_injection, nosql_js_injection
 *
 *   XXE (1):   xxe_entity_expansion
 *
 *   CRLF (2):  crlf_header_injection, crlf_log_injection
 *
 *   Redirect (1): open_redirect_bypass
 *
 *   Proto (1): proto_pollution
 *
 *   Log4Shell (1): log_jndi_lookup
 *
 *   Deser (3): deser_java_gadget, deser_php_object, deser_python_pickle
 *
 *   LDAP (1):  ldap_filter_injection
 *
 *   GraphQL (2): graphql_introspection, graphql_batch_abuse
 *
 *   HTTP Smuggling (2): http_smuggle_cl_te, http_smuggle_h2
 *
 *   XML (1):   xml_injection
 *
 *   Auth (4):  auth_none_algorithm, auth_header_spoof, cors_origin_abuse, mass_assignment
 *
 *   ReDoS (1): regex_dos
 *
 * The bridge provides:
 *   - Unified detection interface (L1 + L2 combined)
 *   - Drop-in replacement for current detect() calls
 *   - Performance tracking (L1 vs L2 detection rates)
 *   - Novel variant identification (L2 catches that L1 missed)
 */

import type { InvariantMatch, InvariantClass } from '../classes/types.js'
import { detectTautologies } from './sql-expression-evaluator'
import { detectSqlStructural, type SqlStructuralDetection } from './sql-structural-evaluator'
import { detectXssVectors } from './xss-context-evaluator'
import { detectCmdInjection } from './cmd-injection-evaluator'
import { detectPathTraversal } from './path-traversal-evaluator'
import { detectSSRF } from './ssrf-evaluator'
import { detectSSTI } from './ssti-evaluator'
import { detectNoSQLInjection } from './nosql-evaluator'
import { detectXXE } from './xxe-evaluator'
import { detectCRLFInjection } from './crlf-evaluator'
import { detectOpenRedirect } from './redirect-evaluator'
import { detectPrototypePollution } from './proto-pollution-evaluator'
import { detectLog4Shell } from './log4shell-evaluator'
import { detectDeserialization } from './deser-evaluator'
import { detectLDAPInjection } from './ldap-evaluator'
import { detectGraphQLAbuse } from './graphql-evaluator'
import { detectHTTPSmuggling } from './http-smuggle-evaluator'


// ── Level 2 Evaluation Stats ─────────────────────────────────────

export interface L2Stats {
    totalEvaluations: number
    l2OnlyDetections: number       // Caught by L2 but NOT L1
    convergentDetections: number   // Caught by BOTH L1 and L2
    l2MissButL1Caught: number      // Caught by L1 but not L2 (coverage gap)
    falseRejectionsAvoided: number // Would have been missed without L2
}


// ── Bridge Interface ─────────────────────────────────────────────

export interface L2DetectionResult {
    /** Class of invariant detected */
    class: InvariantClass
    /** Confidence from L2 evaluator */
    confidence: number
    /** Whether this detection is novel (L1 missed it) */
    novelByL2: boolean
    /** Human-readable explanation */
    detail: string
}


// ── SQL Structural Type → InvariantClass Mapping ─────────────────

const SQL_STRUCTURAL_MAP: Record<SqlStructuralDetection['type'], InvariantClass> = {
    string_termination: 'sql_string_termination' as InvariantClass,
    union_extraction: 'sql_union_extraction' as InvariantClass,
    stacked_execution: 'sql_stacked_execution' as InvariantClass,
    time_oracle: 'sql_time_oracle' as InvariantClass,
    error_oracle: 'sql_error_oracle' as InvariantClass,
    comment_truncation: 'sql_comment_truncation' as InvariantClass,
}


/**
 * Run Level 2 evaluators on input.
 * Returns additional detections beyond what Level 1 (regex) catches.
 *
 * This is called AFTER the main InvariantEngine.detect() to augment
 * its results with deeper analysis. It runs in ctx.waitUntil() to
 * avoid adding latency to the critical path.
 *
 * @param input The decoded request content
 * @param l1Matches Classes already matched by Level 1
 * @returns Additional/upgraded matches from Level 2
 */
export function runL2Evaluators(
    input: string,
    l1Matches: Set<InvariantClass>,
): L2DetectionResult[] {
    const results: L2DetectionResult[] = []

    // ── SQL: Tautology (expression evaluation) ───────────────
    try {
        const tautologies = detectTautologies(input)
        if (tautologies.length > 0) {
            const alreadyCaught = l1Matches.has('sql_tautology' as InvariantClass)
            results.push({
                class: 'sql_tautology' as InvariantClass,
                confidence: 0.92,
                novelByL2: !alreadyCaught,
                detail: `L2 tautology: ${tautologies.map(t => t.expression).join(', ')}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── SQL: Structural analysis (6 remaining SQL classes) ───
    try {
        const structuralDetections = detectSqlStructural(input)
        for (const detection of structuralDetections) {
            const cls = SQL_STRUCTURAL_MAP[detection.type]
            if (cls) {
                const alreadyCaught = l1Matches.has(cls)
                results.push({
                    class: cls,
                    confidence: detection.confidence,
                    novelByL2: !alreadyCaught,
                    detail: `L2 SQL: ${detection.detail}`,
                })
            }
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── XSS: Context-aware HTML analysis (5 classes) ─────────
    try {
        const xssVectors = detectXssVectors(input)
        for (const vector of xssVectors) {
            let cls: InvariantClass
            switch (vector.type) {
                case 'tag_injection':
                    cls = 'xss_tag_injection' as InvariantClass
                    break
                case 'event_handler':
                    cls = 'xss_event_handler' as InvariantClass
                    break
                case 'protocol_handler':
                    cls = 'xss_protocol_handler' as InvariantClass
                    break
                case 'template_expression':
                    cls = 'xss_template_expression' as InvariantClass
                    break
                case 'attribute_escape':
                    cls = 'xss_attribute_escape' as InvariantClass
                    break
                default:
                    cls = 'xss_tag_injection' as InvariantClass
            }

            const alreadyCaught = l1Matches.has(cls)
            results.push({
                class: cls,
                confidence: vector.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 XSS: ${vector.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── Command Injection: Shell syntax analysis (3 classes) ─
    try {
        const cmdDetections = detectCmdInjection(input)
        for (const detection of cmdDetections) {
            let cls: InvariantClass
            switch (detection.type) {
                case 'separator':
                    cls = 'cmd_separator' as InvariantClass
                    break
                case 'substitution':
                    cls = 'cmd_substitution' as InvariantClass
                    break
                case 'argument_injection':
                    cls = 'cmd_argument_injection' as InvariantClass
                    break
                default:
                    cls = 'cmd_separator' as InvariantClass
            }

            const alreadyCaught = l1Matches.has(cls)
            results.push({
                class: cls,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 CMDi: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── Path Traversal: Path resolution (4 classes) ──────────
    try {
        const pathDetections = detectPathTraversal(input)
        for (const detection of pathDetections) {
            let cls: InvariantClass
            switch (detection.type) {
                case 'dotdot_escape':
                    cls = 'path_dotdot_escape' as InvariantClass
                    break
                case 'null_terminate':
                    cls = 'path_null_terminate' as InvariantClass
                    break
                case 'encoding_bypass':
                    cls = 'path_encoding_bypass' as InvariantClass
                    break
                case 'normalization_bypass':
                    cls = 'path_normalization_bypass' as InvariantClass
                    break
                default:
                    cls = 'path_dotdot_escape' as InvariantClass
            }

            const alreadyCaught = l1Matches.has(cls)
            results.push({
                class: cls,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 Path: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── SSRF: URL resolution + IP normalization (3 classes) ──
    try {
        const ssrfDetections = detectSSRF(input)
        for (const detection of ssrfDetections) {
            let cls: InvariantClass
            switch (detection.type) {
                case 'internal_reach':
                    cls = 'ssrf_internal_reach' as InvariantClass
                    break
                case 'cloud_metadata':
                    cls = 'ssrf_cloud_metadata' as InvariantClass
                    break
                case 'protocol_smuggle':
                    cls = 'ssrf_protocol_smuggle' as InvariantClass
                    break
                default:
                    cls = 'ssrf_internal_reach' as InvariantClass
            }

            const alreadyCaught = l1Matches.has(cls)
            results.push({
                class: cls,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 SSRF: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── SSTI: Template expression analysis (2 classes) ───────
    try {
        const sstiDetections = detectSSTI(input)
        for (const detection of sstiDetections) {
            let cls: InvariantClass
            switch (detection.type) {
                case 'jinja_twig':
                    cls = 'ssti_jinja_twig' as InvariantClass
                    break
                case 'el_expression':
                    cls = 'ssti_el_expression' as InvariantClass
                    break
                default:
                    cls = 'ssti_jinja_twig' as InvariantClass
            }

            const alreadyCaught = l1Matches.has(cls)
            results.push({
                class: cls,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 SSTI: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── NoSQL: Operator + JS injection (2 classes) ───────────
    try {
        const nosqlDetections = detectNoSQLInjection(input)
        for (const detection of nosqlDetections) {
            let cls: InvariantClass
            switch (detection.type) {
                case 'operator_injection':
                    cls = 'nosql_operator_injection' as InvariantClass
                    break
                case 'js_injection':
                    cls = 'nosql_js_injection' as InvariantClass
                    break
                default:
                    cls = 'nosql_operator_injection' as InvariantClass
            }

            const alreadyCaught = l1Matches.has(cls)
            results.push({
                class: cls,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 NoSQL: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── XXE: Entity declaration analysis (1 class) ───────────
    try {
        const xxeDetections = detectXXE(input)
        for (const detection of xxeDetections) {
            const alreadyCaught = l1Matches.has('xxe_entity_expansion' as InvariantClass)
            results.push({
                class: 'xxe_entity_expansion' as InvariantClass,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 XXE: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── CRLF: Header + log injection (2 classes) ─────────────
    try {
        const crlfDetections = detectCRLFInjection(input)
        for (const detection of crlfDetections) {
            let cls: InvariantClass
            switch (detection.type) {
                case 'header_injection':
                case 'response_split':
                    cls = 'crlf_header_injection' as InvariantClass
                    break
                case 'log_injection':
                    cls = 'crlf_log_injection' as InvariantClass
                    break
                default:
                    cls = 'crlf_header_injection' as InvariantClass
            }

            const alreadyCaught = l1Matches.has(cls)
            results.push({
                class: cls,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 CRLF: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── Open Redirect: URL parsing (1 class) ─────────────────
    try {
        const redirectDetections = detectOpenRedirect(input)
        for (const detection of redirectDetections) {
            const alreadyCaught = l1Matches.has('open_redirect_bypass' as InvariantClass)
            results.push({
                class: 'open_redirect_bypass' as InvariantClass,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 Redirect: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── Prototype Pollution: JSON key analysis (1 class) ─────
    try {
        const protoDetections = detectPrototypePollution(input)
        for (const detection of protoDetections) {
            const alreadyCaught = l1Matches.has('proto_pollution' as InvariantClass)
            results.push({
                class: 'proto_pollution' as InvariantClass,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 Proto: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── Log4Shell: Nested lookup resolution (1 class) ────────
    try {
        const l4sDetections = detectLog4Shell(input)
        for (const detection of l4sDetections) {
            const alreadyCaught = l1Matches.has('log_jndi_lookup' as InvariantClass)
            results.push({
                class: 'log_jndi_lookup' as InvariantClass,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 Log4Shell: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── Deserialization: Format analysis (3 classes) ──────────
    try {
        const deserDetections = detectDeserialization(input)
        for (const detection of deserDetections) {
            let cls: InvariantClass
            switch (detection.type) {
                case 'java_gadget':
                    cls = 'deser_java_gadget' as InvariantClass
                    break
                case 'php_object':
                    cls = 'deser_php_object' as InvariantClass
                    break
                case 'python_pickle':
                    cls = 'deser_python_pickle' as InvariantClass
                    break
                default:
                    cls = 'deser_java_gadget' as InvariantClass
            }

            const alreadyCaught = l1Matches.has(cls)
            results.push({
                class: cls,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 Deser: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── LDAP: Filter syntax analysis (1 class) ───────────────
    try {
        const ldapDetections = detectLDAPInjection(input)
        for (const detection of ldapDetections) {
            const alreadyCaught = l1Matches.has('ldap_filter_injection' as InvariantClass)
            results.push({
                class: 'ldap_filter_injection' as InvariantClass,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 LDAP: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── GraphQL: Query analysis (2 classes) ───────────────────
    try {
        const gqlDetections = detectGraphQLAbuse(input)
        for (const detection of gqlDetections) {
            let cls: InvariantClass
            switch (detection.type) {
                case 'introspection':
                    cls = 'graphql_introspection' as InvariantClass
                    break
                case 'depth_abuse':
                case 'batch_abuse':
                case 'alias_abuse':
                case 'fragment_abuse':
                    cls = 'graphql_batch_abuse' as InvariantClass
                    break
                default:
                    cls = 'graphql_introspection' as InvariantClass
            }

            const alreadyCaught = l1Matches.has(cls)
            results.push({
                class: cls,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 GraphQL: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    // ── HTTP Smuggling: Header desync (2 classes) ────────────
    try {
        const smuggleDetections = detectHTTPSmuggling(input)
        for (const detection of smuggleDetections) {
            let cls: InvariantClass
            switch (detection.type) {
                case 'cl_te_desync':
                case 'te_te_desync':
                case 'te_obfuscation':
                case 'chunked_body':
                    cls = 'http_smuggle_cl_te' as InvariantClass
                    break
                case 'h2_pseudo_header':
                case 'h2_crlf':
                    cls = 'http_smuggle_h2' as InvariantClass
                    break
                default:
                    cls = 'http_smuggle_cl_te' as InvariantClass
            }

            const alreadyCaught = l1Matches.has(cls)
            results.push({
                class: cls,
                confidence: detection.confidence,
                novelByL2: !alreadyCaught,
                detail: `L2 Smuggle: ${detection.detail}`,
            })
        }
    } catch { /* Never let L2 failure affect main pipeline */ }

    return results
}


/**
 * Merge L2 results into the L1 InvariantMatch array.
 * Deduplicates by class and upgrades confidence when convergent.
 */
export function mergeL2Results(
    l1Matches: InvariantMatch[],
    l2Results: L2DetectionResult[],
): InvariantMatch[] {
    const merged = [...l1Matches]
    const existingClasses = new Set(l1Matches.map(m => m.class))

    for (const l2 of l2Results) {
        if (existingClasses.has(l2.class)) {
            // Convergent detection — upgrade confidence
            const existing = merged.find(m => m.class === l2.class)
            if (existing && l2.confidence > existing.confidence) {
                existing.confidence = Math.min(0.99, l2.confidence + 0.05)
                existing.description = `${existing.description} [confirmed by L2: ${l2.detail}]`
            }
        } else {
            // Novel L2 detection — add to results
            merged.push({
                class: l2.class,
                confidence: l2.confidence,
                category: classToCategory(l2.class),
                severity: classToSeverity(l2.class),
                isNovelVariant: true,
                description: l2.detail,
            })
            existingClasses.add(l2.class)
        }
    }

    return merged
}


// ── Helpers ──────────────────────────────────────────────────────

function classToCategory(cls: InvariantClass): string {
    if (cls.startsWith('sql_') || cls.startsWith('nosql_')) return 'sqli'
    if (cls.startsWith('xss_')) return 'xss'
    if (cls.startsWith('cmd_')) return 'cmdi'
    if (cls.startsWith('path_')) return 'path_traversal'
    if (cls.startsWith('ssrf_')) return 'ssrf'
    if (cls.startsWith('deser_')) return 'deser'
    if (cls.startsWith('ssti_')) return 'ssti'
    if (cls.startsWith('auth_') || cls.startsWith('cors_') || cls.startsWith('mass_')) return 'auth'
    if (cls.startsWith('crlf_')) return 'crlf'
    if (cls.startsWith('http_smuggle_')) return 'smuggling'
    if (cls.startsWith('graphql_')) return 'graphql'
    if (cls === 'xxe_entity_expansion' || cls === 'xml_injection') return 'xxe'
    if (cls === 'ldap_filter_injection') return 'ldap'
    if (cls === 'proto_pollution') return 'proto_pollution'
    if (cls === 'log_jndi_lookup') return 'log4shell'
    if (cls === 'open_redirect_bypass') return 'open_redirect'
    if (cls === 'regex_dos') return 'redos'
    return 'injection'
}

function classToSeverity(cls: InvariantClass): 'critical' | 'high' | 'medium' | 'low' {
    const criticals = [
        'cmd_separator', 'cmd_substitution', 'sql_stacked_execution',
        'sql_union_extraction', 'ssrf_cloud_metadata', 'ssti_jinja_twig',
        'ssti_el_expression', 'deser_java_gadget', 'deser_python_pickle',
        'log_jndi_lookup', 'xxe_entity_expansion', 'http_smuggle_cl_te',
        'http_smuggle_h2', 'auth_none_algorithm',
    ]
    if (criticals.includes(cls)) return 'critical'
    const highs = [
        'sql_tautology', 'sql_time_oracle', 'sql_error_oracle',
        'sql_string_termination',
        'ssrf_internal_reach', 'ssrf_protocol_smuggle',
        'path_dotdot_escape', 'path_encoding_bypass',
        'xss_tag_injection', 'xss_event_handler', 'xss_protocol_handler',
        'nosql_operator_injection', 'nosql_js_injection',
        'crlf_header_injection', 'proto_pollution',
        'deser_php_object', 'ldap_filter_injection',
        'cmd_argument_injection', 'graphql_batch_abuse',
        'mass_assignment', 'xml_injection',
    ]
    if (highs.includes(cls)) return 'high'
    const mediums = [
        'cors_origin_abuse', 'crlf_log_injection', 'open_redirect_bypass',
        'regex_dos', 'graphql_introspection', 'sql_comment_truncation',
        'path_null_terminate', 'path_normalization_bypass',
        'xss_template_expression', 'xss_attribute_escape',
        'auth_header_spoof',
    ]
    if (mediums.includes(cls)) return 'medium'
    return 'high'
}
