/**
 * L2 Adapter — Shared helpers to wire L2 evaluators into class modules.
 *
 * Each domain evaluator returns domain-specific detection types.
 * This module provides adapters that convert them into DetectionLevelResult
 * for the InvariantClassModule.detectL2 contract.
 *
 * Design: One adapter per evaluator, each filtering by detection type
 * to match the specific class module it's wired into.
 */

import type { DetectionLevelResult } from '../classes/types.js'
import { detectCmdInjection, type CmdInjectionDetection } from './cmd-injection-evaluator.js'
import { detectPathTraversal, type PathTraversalDetection } from './path-traversal-evaluator.js'
import { detectSSRF, type SSRFDetection } from './ssrf-evaluator.js'
import { detectDeserialization, type DeserDetection } from './deser-evaluator.js'
import { detectNoSQLInjection, type NoSQLDetection } from './nosql-evaluator.js'
import { detectSSTI, type SSTIDetection } from './ssti-evaluator.js'
import { detectCRLFInjection, type CRLFDetection } from './crlf-evaluator.js'
import { detectXXE, type XXEDetection } from './xxe-evaluator.js'
import { detectGraphQLAbuse, type GraphQLDetection } from './graphql-evaluator.js'
import { detectPrototypePollution, type ProtoPollutionDetection } from './proto-pollution-evaluator.js'
import { detectMassAssignment, type MassAssignmentDetection } from './mass-assignment-evaluator.js'
import { detectOpenRedirect, type OpenRedirectDetection } from './redirect-evaluator.js'
import { detectLDAPInjection, type LDAPDetection } from './ldap-evaluator.js'
import { detectHTTPSmuggling, type HTTPSmuggleDetection } from './http-smuggle-evaluator.js'
import { detectLog4Shell, type Log4ShellDetection } from './log4shell-evaluator.js'
import { detectSupplyChain, type SupplyChainDetection } from './supply-chain-evaluator.js'
import { detectLLMInjection, type LLMDetection } from './llm-evaluator.js'
import { detectWebSocketAttack, type WebSocketDetection } from './websocket-evaluator.js'
import { detectJWTAbuse, type JWTDetection } from './jwt-evaluator.js'
import { detectCacheAttack, type CacheDetection } from './cache-evaluator.js'
import { detectAPIAbuse, type APIAbuseDetection } from './api-abuse-evaluator.js'


type ProofEvidenceCarrier = { proofEvidence?: DetectionLevelResult['structuredEvidence'] }

// ── Generic adapter: evaluator → DetectionLevelResult ──────────

function adapt<T extends { confidence: number; detail: string; proofEvidence?: DetectionLevelResult['structuredEvidence'] }>(
    detections: T[],
    filterFn: (d: T) => boolean,
    explanationPrefix: string,
): DetectionLevelResult | null {
    const match = detections.find(filterFn)
    if (match) {
        return {
            detected: true,
            confidence: match.confidence,
            explanation: `${explanationPrefix}: ${match.detail}`,
            evidence: match.detail,
            structuredEvidence: match.proofEvidence ? [...match.proofEvidence] : undefined,
        }
    }
    return null
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


// ── Command Injection Adapters ──────────────────────────────────

export function l2CmdSeparator(input: string): DetectionLevelResult | null {
    try {
        const relevant = detectCmdInjection(input).filter(d =>
            d.type === 'separator' || d.type === 'structural' ||
            d.type === 'quote_fragmentation' || d.type === 'glob_path'
        )
        if (relevant.length === 0) return null
        const match = relevant.reduce((a, b) => a.confidence > b.confidence ? a : b)
        return {
            detected: true,
            confidence: match.confidence,
            explanation: `Shell analysis: ${match.detail}`,
            evidence: match.command,
            structuredEvidence: buildCmdEvidence(match, input),
        }
    } catch { return null }
}

export function l2CmdSubstitution(input: string): DetectionLevelResult | null {
    try {
        const relevant = detectCmdInjection(input).filter(d =>
            d.type === 'substitution' || (
                d.type === 'variable_expansion' && !/^\$\d+$/.test(d.command)
            )
        )
        if (relevant.length === 0) return null
        const match = relevant.reduce((a, b) => a.confidence > b.confidence ? a : b)
        return {
            detected: true,
            confidence: match.confidence,
            explanation: `Shell analysis: ${match.detail}`,
            evidence: match.command,
            structuredEvidence: buildCmdEvidence(match, input),
        }
    } catch { return null }
}

export function l2CmdArgInjection(input: string): DetectionLevelResult | null {
    try {
        const relevant = detectCmdInjection(input).filter(d =>
            d.type === 'argument_injection' || d.type === 'redirection' || d.type === 'heredoc'
        )
        if (relevant.length === 0) return null
        const match = relevant.reduce((a, b) => a.confidence > b.confidence ? a : b)
        return {
            detected: true,
            confidence: match.confidence,
            explanation: `Shell analysis: ${match.detail}`,
            evidence: match.command,
            structuredEvidence: buildCmdEvidence(match, input),
        }
    } catch { return null }
}


// ── Path Traversal Adapters ──────────────────────────────────────

export function l2PathDotdot(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectPathTraversal(input),
            (d: PathTraversalDetection) => d.type === 'dotdot_escape',
            'Path resolution')
    } catch { return null }
}

export function l2PathNull(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectPathTraversal(input),
            (d: PathTraversalDetection) => d.type === 'null_terminate',
            'Path resolution')
    } catch { return null }
}

export function l2PathEncoding(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectPathTraversal(input),
            (d: PathTraversalDetection) => d.type === 'encoding_bypass',
            'Path resolution')
    } catch { return null }
}

export function l2PathNormalization(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectPathTraversal(input),
            (d: PathTraversalDetection) => d.type === 'normalization_bypass',
            'Path resolution')
    } catch { return null }
}


// ── SSRF Adapters ────────────────────────────────────────────────

export function l2SsrfInternal(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectSSRF(input),
            (d: SSRFDetection) => d.type === 'internal_reach',
            'URL analysis')
    } catch { return null }
}

export function l2SsrfCloudMetadata(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectSSRF(input),
            (d: SSRFDetection) => d.type === 'cloud_metadata',
            'URL analysis')
    } catch { return null }
}

export function l2SsrfProtocolSmuggle(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectSSRF(input),
            (d: SSRFDetection) => d.type === 'protocol_smuggle',
            'URL analysis')
    } catch { return null }
}


// ── Deserialization Adapters ─────────────────────────────────────

export function l2DeserJava(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectDeserialization(input),
            (d: DeserDetection) => d.type === 'java_gadget',
            'Deser analysis')
    } catch { return null }
}

export function l2DeserPHP(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectDeserialization(input),
            (d: DeserDetection) => d.type === 'php_object',
            'Deser analysis')
    } catch { return null }
}

export function l2DeserPython(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectDeserialization(input),
            (d: DeserDetection) => d.type === 'python_pickle',
            'Deser analysis')
    } catch { return null }
}


// ── NoSQL Adapters ───────────────────────────────────────────────

export function l2NoSQLOperator(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectNoSQLInjection(input),
            (d: NoSQLDetection) => d.type === 'operator_injection',
            'NoSQL analysis')
    } catch { return null }
}

export function l2NoSQLJS(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectNoSQLInjection(input),
            (d: NoSQLDetection) => d.type === 'js_injection',
            'NoSQL analysis')
    } catch { return null }
}


// ── SSTI Adapters ────────────────────────────────────────────────

export function l2SSTIJinja(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectSSTI(input),
            (d: SSTIDetection) => d.type === 'jinja_twig',
            'Template analysis')
    } catch { return null }
}

export function l2SSTIEL(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectSSTI(input),
            (d: SSTIDetection) => d.type === 'el_expression',
            'Template analysis')
    } catch { return null }
}


// ── CRLF Adapters ────────────────────────────────────────────────

export function l2CRLFHeader(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectCRLFInjection(input),
            (d: CRLFDetection) => d.type === 'header_injection' || d.type === 'response_split',
            'CRLF analysis')
    } catch { return null }
}

export function l2CRLFLog(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectCRLFInjection(input),
            (d: CRLFDetection) => d.type === 'log_injection',
            'CRLF analysis')
    } catch { return null }
}


// ── XXE Adapters ─────────────────────────────────────────────────

export function l2XXEEntity(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectXXE(input),
            (d: XXEDetection) => d.type === 'external_entity' || d.type === 'parameter_entity' || d.type === 'billion_laughs',
            'XML analysis')
    } catch { return null }
}

export function l2XMLInjection(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectXXE(input),
            (d: XXEDetection) => d.type === 'entity_expansion',
            'XML analysis')
    } catch { return null }
}


// ── GraphQL Adapters ─────────────────────────────────────────────

export function l2GraphQLIntrospection(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectGraphQLAbuse(input),
            (d: GraphQLDetection) => d.type === 'introspection',
            'GraphQL analysis')
    } catch { return null }
}

export function l2GraphQLBatch(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectGraphQLAbuse(input),
            (d: GraphQLDetection) => d.type === 'depth_abuse' || d.type === 'batch_abuse' || d.type === 'alias_abuse' || d.type === 'fragment_abuse',
            'GraphQL analysis')
    } catch { return null }
}


// ── Prototype Pollution Adapter ──────────────────────────────────

export function l2ProtoPollution(input: string): DetectionLevelResult | null {
    try {
        const detections = detectPrototypePollution(input)
        if (detections.length > 0) {
            const best = detections.reduce((a, b) => a.confidence > b.confidence ? a : b)
            return {
                detected: true,
                confidence: best.confidence,
                explanation: `Proto analysis: ${best.detail}`,
                evidence: best.path,
                structuredEvidence: (best as ProofEvidenceCarrier).proofEvidence,
            }
        }
    } catch { /* safe */ }
    return null
}

export function l2MassAssignment(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectMassAssignment(input),
            (d: MassAssignmentDetection) => d.type === 'privilege_injection' || d.type === 'suspicious_key_combo' || d.type === 'nested_privilege_injection',
            'Mass-assignment analysis')
    } catch { return null }
}


// ── Open Redirect Adapter ────────────────────────────────────────

export function l2OpenRedirect(input: string): DetectionLevelResult | null {
    try {
        const detections = detectOpenRedirect(input)
        if (detections.length > 0) {
            const best = detections.reduce((a, b) => a.confidence > b.confidence ? a : b)
            return {
                detected: true,
                confidence: best.confidence,
                explanation: `Redirect analysis: ${best.detail}`,
                evidence: best.extractedHost,
                structuredEvidence: (best as ProofEvidenceCarrier).proofEvidence,
            }
        }
    } catch { /* safe */ }
    return null
}


// ── LDAP Adapter ─────────────────────────────────────────────────

export function l2LDAPInjection(input: string): DetectionLevelResult | null {
    try {
        const detections = detectLDAPInjection(input)
        if (detections.length > 0) {
            const best = detections.reduce((a, b) => a.confidence > b.confidence ? a : b)
            return {
                detected: true,
                confidence: best.confidence,
                explanation: `LDAP analysis: ${best.detail}`,
                evidence: best.detail,
                structuredEvidence: (best as ProofEvidenceCarrier).proofEvidence,
            }
        }
    } catch { /* safe */ }
    return null
}


// ── HTTP Smuggling Adapters ──────────────────────────────────────

export function l2HTTPSmuggleCLTE(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectHTTPSmuggling(input),
            (d: HTTPSmuggleDetection) => d.type === 'cl_te_desync' || d.type === 'te_te_desync' || d.type === 'te_obfuscation' || d.type === 'chunked_body',
            'HTTP analysis')
    } catch { return null }
}

export function l2HTTPSmuggleH2(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectHTTPSmuggling(input),
            (d: HTTPSmuggleDetection) => d.type === 'h2_pseudo_header' || d.type === 'h2_crlf',
            'HTTP analysis')
    } catch { return null }
}


// ── Log4Shell Adapter ────────────────────────────────────────────

export function l2Log4Shell(input: string): DetectionLevelResult | null {
    try {
        const detections = detectLog4Shell(input)
        if (detections.length > 0) {
            const best = detections.reduce((a, b) => a.confidence > b.confidence ? a : b)
            return {
                detected: true,
                confidence: best.confidence,
                explanation: `Log4j analysis: ${best.detail}`,
                evidence: best.resolvedExpression,
                structuredEvidence: (best as ProofEvidenceCarrier).proofEvidence,
            }
        }
    } catch { /* safe */ }
    return null
}


// ── Supply Chain Adapters ────────────────────────────────────────

export function l2DependencyConfusion(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectSupplyChain(input),
            (d: SupplyChainDetection) => d.type === 'dependency_confusion',
            'Supply-chain analysis')
    } catch { return null }
}

export function l2PostinstallInjection(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectSupplyChain(input),
            (d: SupplyChainDetection) => d.type === 'postinstall_injection',
            'Supply-chain analysis')
    } catch { return null }
}

export function l2EnvExfiltration(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectSupplyChain(input),
            (d: SupplyChainDetection) => d.type === 'env_exfiltration',
            'Supply-chain analysis')
    } catch { return null }
}


// ── LLM Injection Adapters ───────────────────────────────────────

export function l2LLMPromptInjection(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectLLMInjection(input),
            (d: LLMDetection) => d.type === 'prompt_injection',
            'LLM analysis')
    } catch { return null }
}

export function l2LLMDataExfiltration(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectLLMInjection(input),
            (d: LLMDetection) => d.type === 'data_exfiltration',
            'LLM analysis')
    } catch { return null }
}

export function l2LLMJailbreak(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectLLMInjection(input),
            (d: LLMDetection) => d.type === 'jailbreak',
            'LLM analysis')
    } catch { return null }
}


// ── WebSocket Adapters ───────────────────────────────────────────

export function l2WsInjection(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectWebSocketAttack(input),
            (d: WebSocketDetection) => d.type === 'ws_injection',
            'WebSocket analysis')
    } catch { return null }
}

export function l2WsHijack(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectWebSocketAttack(input),
            (d: WebSocketDetection) => d.type === 'ws_hijack',
            'WebSocket analysis')
    } catch { return null }
}


// ── JWT Abuse Adapters ──────────────────────────────────────────

export function l2JwtKidInjection(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectJWTAbuse(input),
            (d: JWTDetection) => d.type === 'jwt_kid_injection',
            'JWT analysis')
    } catch { return null }
}

export function l2JwtJwkEmbedding(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectJWTAbuse(input),
            (d: JWTDetection) => d.type === 'jwt_jwk_embedding',
            'JWT analysis')
    } catch { return null }
}

export function l2JwtConfusion(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectJWTAbuse(input),
            (d: JWTDetection) => d.type === 'jwt_confusion',
            'JWT analysis')
    } catch { return null }
}


// ── Cache Attack Adapters ───────────────────────────────────────

export function l2CachePoisoning(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectCacheAttack(input),
            (d: CacheDetection) => d.type === 'cache_poisoning',
            'Cache analysis')
    } catch { return null }
}

export function l2CacheDeception(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectCacheAttack(input),
            (d: CacheDetection) => d.type === 'cache_deception',
            'Cache analysis')
    } catch { return null }
}


// ── API Abuse Adapters ──────────────────────────────────────────

export function l2BolaIdor(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectAPIAbuse(input),
            (d: APIAbuseDetection) => d.type === 'bola_idor',
            'API analysis')
    } catch { return null }
}

export function l2ApiMassEnum(input: string): DetectionLevelResult | null {
    try {
        return adapt(detectAPIAbuse(input),
            (d: APIAbuseDetection) => d.type === 'api_mass_enum',
            'API analysis')
    } catch { return null }
}
