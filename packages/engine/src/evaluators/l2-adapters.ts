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
import { detectLog4Shell, type Log4ShellDetection } from './log4shell-evaluator.js'
import { detectSupplyChain, type SupplyChainDetection } from './supply-chain-evaluator.js'
import { detectLLMInjection, type LLMDetection } from './llm-evaluator.js'
import { detectWebSocketAttack, type WebSocketDetection } from './websocket-evaluator.js'
import { detectJWTAbuse, type JWTDetection } from './jwt-evaluator.js'
import { detectCacheAttack, type CacheDetection } from './cache-evaluator.js'
import { detectAPIAbuse, type APIAbuseDetection } from './api-abuse-evaluator.js'
import { deepDecode } from '../classes/encoding.js'


type ProofEvidenceCarrier = { proofEvidence?: DetectionLevelResult['structuredEvidence'] }
type L2Result = DetectionLevelResult

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

export function l2WindowsPathTraversal(input: string, structural: string): L2Result | null {
    try {
        const merged = structural.length > 0 && structural !== input ? `${input}\n${structural}` : input
        const d = deepDecode(merged)

        const uncMatch = d.match(/(?:^|[\s"'`=:(])\\\\[a-z0-9.-]{1,253}\\[^\s\\/:*?"<>|]+/i)
        if (uncMatch?.[0]) {
            return {
                detected: true,
                confidence: 0.92,
                explanation: 'Path resolution: UNC path injection targets attacker-controlled network share',
                evidence: uncMatch[0],
            }
        }

        const driveInjection = d.match(/(?:^|[\s"'`=:(])(?:[a-z]:\\)(?:windows\\system32(?:\\|$)|windows\\win\.ini(?:$|\\)|secrets?(?:\\|$)|secret(?:\\|$)|sam(?:\\|$)|config(?:\\|$)|shadow(?:\\|$)|passwd(?:\\|$)|.*\\cmd\.exe\b)/i)
        if (driveInjection?.[0]) {
            return {
                detected: true,
                confidence: 0.92,
                explanation: 'Path resolution: drive-letter absolute path injection reaches sensitive Windows paths',
                evidence: driveInjection[0],
            }
        }

        const windowsTraversal = d.match(/(?:^|[\\/])(?:\.\.\\){2,}(?:windows\\system32|windows\\win\.ini|[^\\\r\n]{0,120})/i)
        if (windowsTraversal?.[0]) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: 'Path resolution: Windows backslash traversal escapes intended directory boundaries',
                evidence: windowsTraversal[0],
            }
        }

        const zipSlip = d.match(/(?:^|[\\/])(?:[^\\/\r\n]+\.(?:zip|jar|war|apk|tar|tgz|7z|rar))[\\/](?:\.\.[\\/]){2,}[^\r\n]{0,120}/i)
            ?? d.match(/(?:^|[\s"'`=:(])(?:\.\.[\\/]){3,}(?:etc[\\/]passwd|windows[\\/]system32|[^\\/\r\n]{1,120})/i)
        if (zipSlip?.[0]) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: 'Path resolution: zip-slip style archive entry traversal detected',
                evidence: zipSlip[0],
            }
        }

        const nullByte = d.match(/\.[a-z0-9]{1,8}(?:%00|\\x00|\0)\.[a-z0-9]{1,8}\b/i) ?? input.match(/\.[a-z0-9]{1,8}%00\.[a-z0-9]{1,8}\b/i)
        if (nullByte?.[0]) {
            return {
                detected: true,
                confidence: 0.85,
                explanation: 'Path resolution: null-byte extension bypass pattern detected',
                evidence: nullByte[0],
            }
        }

        const ads = d.match(/(?:^|[\\/])[^\\/\r\n]+::(?:\$?[a-z_]+)?\b/i)
        if (ads?.[0]) {
            return {
                detected: true,
                confidence: 0.85,
                explanation: 'Path resolution: NTFS alternate data stream (ADS) path detected',
                evidence: ads[0],
            }
        }
    } catch { return null }
    return null
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

export function l2XxeEvaluator(input: string): DetectionLevelResult | null {
    try {
        const hasDoctype = /<!DOCTYPE\s+\w+/i.test(input)
        const hasEntitySystemOrPublic = /<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)/i.test(input)
        const hasExternalDtdReference = /SYSTEM\s+['"]\s*(?:https?:|file:|ftp:)/i.test(input)
        const hasParameterEntityUsage = /%\w+;/.test(input)
        const hasParameterEntityDefinition = /<!ENTITY\s+%\s*\w+\s+(?:SYSTEM|PUBLIC|['"])/i.test(input)
        const hasParameterEntityXXE = hasParameterEntityDefinition && hasParameterEntityUsage
        const hasBlindXxeSystemRef = /SYSTEM\s+['"]\s*https?:\/\/[^'"]+['"]/i.test(input)
        const hasBlindXxeMarker = /(attacker\.com|burpcollaborator|interactsh|oast|dnslog|webhook|canarytokens)/i.test(input)
        const hasBlindXXE = hasBlindXxeSystemRef && hasBlindXxeMarker

        const hasFullXXE = hasDoctype && hasEntitySystemOrPublic
            && (hasExternalDtdReference || hasParameterEntityXXE || hasBlindXXE)

        if (hasFullXXE) {
            return {
                detected: true,
                confidence: 0.93,
                explanation: 'XML analysis: DOCTYPE + external entity behavior indicates XXE injection',
                evidence: input.match(/<!DOCTYPE[\s\S]{0,220}/i)?.[0] ?? input.slice(0, 220),
            }
        }
    } catch { return null }

    return null
}

export function l2XMLInjection(input: string): DetectionLevelResult | null {
    try {
        const decoded = deepDecode(input)

        const cdataScript = decoded.match(/<!\[CDATA\[[\s\S]{0,300}?(?:<script\b|on\w+\s*=|javascript:)[\s\S]{0,300}?\]\]>/i)
        if (cdataScript?.[0]) {
            return {
                detected: true,
                confidence: 0.84,
                explanation: 'XML analysis: CDATA section carries executable HTML/JS content',
                evidence: cdataScript[0].slice(0, 220),
            }
        }

        const doctypeEntity = decoded.match(/<!DOCTYPE\s+[A-Za-z0-9:_-]+\s*\[[\s\S]{0,500}?<!ENTITY\s+(?:%\s+)?[A-Za-z0-9._-]+\s+(?:SYSTEM|PUBLIC|["'])/i)
        if (doctypeEntity?.[0]) {
            return {
                detected: true,
                confidence: 0.86,
                explanation: 'XML analysis: DOCTYPE with attacker-controlled ENTITY declaration',
                evidence: doctypeEntity[0].slice(0, 220),
            }
        }

        const customEntityRef = decoded.match(/<(?:[A-Za-z_:][\w:.-]*)\b[^>]*>[^<]{0,120}&(?!amp;|lt;|gt;|quot;|apos;|#)[A-Za-z_][A-Za-z0-9._-]{1,48};/i)
        if (customEntityRef?.[0]) {
            return {
                detected: true,
                confidence: 0.82,
                explanation: 'XML analysis: unresolved custom entity reference indicates parser-driven expansion surface',
                evidence: customEntityRef[0].slice(0, 220),
            }
        }

        return adapt(detectXXE(decoded),
            (d: XXEDetection) => d.type === 'entity_expansion' || d.type === 'parameter_entity' || d.type === 'external_entity',
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

export function l2GraphQLInjection(input: string): DetectionLevelResult | null {
    try {
        const detections = detectGraphQLAbuse(input)
        const highSignal = detections.find(d =>
            d.type === 'introspection' || d.type === 'batch_abuse' || (d.type === 'depth_abuse' && d.depth > 10)
        )
        if (highSignal) {
            return {
                detected: true,
                confidence: Math.max(0.85, highSignal.confidence),
                explanation: `GraphQL analysis: ${highSignal.detail}`,
                evidence: highSignal.evidence,
            }
        }

        const decoded = deepDecode(input)
        const typoProbing = (decoded.match(/\b(?:usr|userr|userr|idd|iddd|namee|emal|emaill|passwrod|tokn|rolee|creditcardd|ssnn)\b/gi) || []).length
        if (typoProbing >= 2) {
            return {
                detected: true,
                confidence: 0.82,
                explanation: 'GraphQL analysis: typo-heavy field probing indicates schema suggestion enumeration',
                evidence: decoded.slice(0, 220),
            }
        }
    } catch { return null }
    return null
}

export function l2GraphQLDos(input: string): DetectionLevelResult | null {
    try {
        const detections = detectGraphQLAbuse(input)
        const severe = detections.find(d =>
            (d.type === 'depth_abuse' && d.depth > 15) || d.type === 'fragment_abuse' || d.type === 'alias_abuse'
        )
        if (severe) {
            return {
                detected: true,
                confidence: Math.max(0.84, severe.confidence),
                explanation: `GraphQL DoS analysis: ${severe.detail}`,
                evidence: severe.evidence,
            }
        }
    } catch { return null }
    return null
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

export function l2PrototypePollution(input: string): DetectionLevelResult | null {
    return l2ProtoPollution(input)
}

export function l2PrototypePollutionQuery(input: string): DetectionLevelResult | null {
    try {
        const decoded = deepDecode(input)
        const match = decoded.match(/(?:^|[?&])(?:__proto__(?:\[[^\]]+\]){1,3}|constructor\[prototype\](?:\[[^\]]+\]){1,3}|[a-z_$][\w$]*\[__proto__\](?:\[[^\]]+\]){1,3}|[a-z_$][\w$]*\.__proto__\.[a-z_$][\w$]*)\s*=[^&]*/i)
        if (!match?.[0]) return null

        return {
            detected: true,
            confidence: 0.94,
            explanation: 'Proto analysis: query-string key path reaches prototype chain (__proto__ / constructor.prototype)',
            evidence: match[0],
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
        const decoded = deepDecode(input)
        const candidateValues: string[] = [decoded]

        const queryValueRe = /(?:^|[?&\s"])(?:redirect|url|next|return|goto|dest|target|rurl|redirect_uri|continue|return_to)\s*(?:=|:)\s*["']?([^"'&\s]+)/ig
        let queryMatch: RegExpExecArray | null
        while ((queryMatch = queryValueRe.exec(decoded)) !== null) {
            const raw = queryMatch[1]
            if (!raw) continue
            candidateValues.push(raw)
            try { candidateValues.push(decodeURIComponent(raw)) } catch { /* safe */ }
        }

        const absoluteUrl = decoded.match(/\bhttps?:\/\/[^\s"'<>]+/ig) ?? []
        candidateValues.push(...absoluteUrl)

        const uniqueCandidates = [...new Set(candidateValues.map(value => value.trim()).filter(Boolean))]
        const detections = uniqueCandidates.flatMap(value => detectOpenRedirect(value))
        if (detections.length > 0) {
            const best = detections.reduce((a, b) => (a.confidence > b.confidence ? a : b))
            return {
                detected: true,
                confidence: best.confidence,
                explanation: `Redirect analysis: ${best.detail}`,
                evidence: best.extractedHost,
                structuredEvidence: (best as ProofEvidenceCarrier).proofEvidence,
            }
        }

        const encodedProtocolRelative = decoded.match(/(?:redirect|url|next|return|goto|dest|target|rurl|redirect_uri|continue|return_to)\s*=\s*(?:%2[fF]%2[fF]|\/\/|\\{2,})[^\s&"']+/i)
        if (encodedProtocolRelative?.[0]) {
            return {
                detected: true,
                confidence: 0.86,
                explanation: 'Redirect analysis: redirect parameter uses encoded protocol-relative or backslash host bypass',
                evidence: encodedProtocolRelative[0].slice(0, 200),
            }
        }

        const scriptScheme = decoded.match(/(?:redirect|url|next|return|goto|dest|target|rurl|redirect_uri|continue|return_to)\s*=\s*(?:javascript|vbscript|data):/i)
        if (scriptScheme?.[0]) {
            return {
                detected: true,
                confidence: 0.92,
                explanation: 'Redirect analysis: redirect parameter points to executable scheme',
                evidence: scriptScheme[0],
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

interface ParsedHttpHeader {
    line: string
    name: string
    rawName: string
    value: string
    rawValue: string
}

interface ChunkParseResult {
    anomaly: string | null
    impliedBodyBytes: number
}

function normalizeHttpInput(input: string): string {
    return deepDecode(input)
        .replace(/\\r\\n/g, '\r\n')
        .replace(/\\n/g, '\n')
        .replace(/\\r/g, '\r')
}

function splitHeaderAndBody(input: string): { headerText: string; bodyText: string } {
    const crlfBoundary = input.indexOf('\r\n\r\n')
    if (crlfBoundary >= 0) {
        return {
            headerText: input.slice(0, crlfBoundary),
            bodyText: input.slice(crlfBoundary + 4),
        }
    }
    const lfBoundary = input.indexOf('\n\n')
    if (lfBoundary >= 0) {
        return {
            headerText: input.slice(0, lfBoundary),
            bodyText: input.slice(lfBoundary + 2),
        }
    }
    return {
        headerText: input,
        bodyText: '',
    }
}

function parseHttpHeaders(headerText: string): ParsedHttpHeader[] {
    const lines = headerText.split(/\r?\n/)
    const headers: ParsedHttpHeader[] = []
    for (const line of lines) {
        const colon = line.indexOf(':')
        if (colon <= 0) continue
        const rawName = line.slice(0, colon)
        const rawValue = line.slice(colon + 1)
        const name = rawName.trim().toLowerCase()
        if (!/^[a-z0-9-]+$/.test(name)) continue
        headers.push({
            line,
            name,
            rawName,
            value: rawValue.trim(),
            rawValue,
        })
    }
    return headers
}

function parseChunkedBody(bodyText: string): ChunkParseResult {
    let offset = 0
    let impliedBodyBytes = 0
    const readLine = (): { line: string; nextOffset: number } | null => {
        if (offset >= bodyText.length) return null
        const crlf = bodyText.indexOf('\r\n', offset)
        const lf = bodyText.indexOf('\n', offset)
        if (crlf === -1 && lf === -1) return null
        const useCrlf = crlf !== -1 && (lf === -1 || crlf < lf)
        const lineEnd = useCrlf ? crlf : lf
        const line = bodyText.slice(offset, lineEnd)
        const nextOffset = lineEnd + (useCrlf ? 2 : 1)
        return { line, nextOffset }
    }

    while (offset < bodyText.length) {
        const sizeLine = readLine()
        if (!sizeLine) {
            return { anomaly: 'incomplete chunk size line', impliedBodyBytes }
        }
        offset = sizeLine.nextOffset
        const sizeToken = sizeLine.line.split(';')[0].trim()
        if (!/^[0-9a-fA-F]+$/.test(sizeToken)) {
            return { anomaly: `invalid chunk size token (${sizeToken || 'empty'})`, impliedBodyBytes }
        }
        const chunkSize = Number.parseInt(sizeToken, 16)
        if (!Number.isFinite(chunkSize) || chunkSize < 0) {
            return { anomaly: `invalid parsed chunk size (${sizeToken})`, impliedBodyBytes }
        }

        if (chunkSize === 0) {
            return { anomaly: null, impliedBodyBytes }
        }

        if (offset + chunkSize > bodyText.length) {
            return { anomaly: `chunk declares ${chunkSize} bytes but body ended early`, impliedBodyBytes }
        }
        offset += chunkSize
        impliedBodyBytes += chunkSize

        if (bodyText.startsWith('\r\n', offset)) {
            offset += 2
            continue
        }
        if (bodyText.startsWith('\n', offset)) {
            offset += 1
            continue
        }
        return { anomaly: 'chunk data missing line terminator', impliedBodyBytes }
    }

    return { anomaly: 'chunked body terminated without zero-size chunk', impliedBodyBytes }
}

export function l2HttpSmuggling(input: string): DetectionLevelResult | null {
    try {
        const decoded = normalizeHttpInput(input)
        const { headerText, bodyText } = splitHeaderAndBody(decoded)
        const headers = parseHttpHeaders(headerText)
        const clHeader = headers.find(h => h.name === 'content-length')
        const teHeaders = headers.filter(h => h.name === 'transfer-encoding')
        const pseudoHeaderCount = (decoded.match(/(?:^|\r?\n):(method|path|authority|scheme)\s+/gi) || []).length
        const h1MarkerCount = (decoded.match(/(?:^|\r?\n)(host|content-length|transfer-encoding|connection|user-agent|accept|cookie)\s*:/gi) || []).length

        if (pseudoHeaderCount > 0 && h1MarkerCount > 0) {
            return {
                detected: true,
                confidence: 0.94,
                explanation: 'HTTP/2 downgrade marker: pseudo-headers are mixed with HTTP/1 header fields in one message',
                evidence: ':method/:path with Host/Content-Length/Transfer-Encoding',
            }
        }

        const teWhitespaceHeader = headers.find(h => h.name === 'transfer-encoding' && /\s+$/.test(h.rawName))
        if (teWhitespaceHeader) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'Header smuggling via whitespace: Transfer-Encoding header name includes space before colon',
                evidence: teWhitespaceHeader.line,
            }
        }

        const teObfuscation = teHeaders.find(h => {
            const lowerRaw = h.rawValue.toLowerCase()
            const tokens = h.value.toLowerCase().split(',').map(token => token.trim()).filter(Boolean)
            if (tokens.some(token => token !== 'chunked' && token.includes('chunked'))) return true
            return /chunked(?:\t|\r|\\r|\\t)/i.test(lowerRaw) || /\bxchunked\b/i.test(lowerRaw)
        })
        if (teObfuscation) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'Obfuscated Transfer-Encoding value detected (non-canonical chunked token)',
                evidence: teObfuscation.line,
            }
        }

        const teIsChunked = teHeaders.some(h => h.value.toLowerCase().split(',').some(token => token.trim() === 'chunked'))
        const clValue = clHeader ? Number.parseInt(clHeader.value, 10) : Number.NaN
        const hasValidCL = Number.isFinite(clValue) && clValue >= 0

        if (teIsChunked && bodyText.length > 0) {
            const chunked = parseChunkedBody(bodyText)
            if (chunked.anomaly) {
                return {
                    detected: true,
                    confidence: 0.87,
                    explanation: `Chunked encoding anomaly: ${chunked.anomaly}`,
                    evidence: bodyText.slice(0, 160),
                }
            }
            if (hasValidCL && chunked.impliedBodyBytes !== clValue) {
                return {
                    detected: true,
                    confidence: 0.92,
                    explanation: `TE/CL conflict: chunked body implies ${chunked.impliedBodyBytes} bytes while Content-Length is ${clValue}`,
                    evidence: `Content-Length: ${clValue}; chunked-implied: ${chunked.impliedBodyBytes}`,
                }
            }
        }
    } catch { return null }
    return null
}

export function l2HTTPSmuggleCLTE(input: string): DetectionLevelResult | null {
    return l2HttpSmuggling(input)
}

export function l2HTTPSmuggleH2(input: string): DetectionLevelResult | null {
    return l2HttpSmuggling(input)
}

export function l2HttpRequestSmuggling(input: string): DetectionLevelResult | null {
    const base = l2HttpSmuggling(input)
    if (base) return base

    try {
        const decoded = normalizeHttpInput(input)
        if (/\btransfer-encoding\s*:\s*[^\\r\\n]*chunked[^\\r\\n]*gzip/i.test(decoded)
            || (/\btransfer-encoding\s*:\s*chunked/i.test(decoded) && /\bcontent-encoding\s*:\s*gzip\b/i.test(decoded))) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: 'HTTP smuggling analysis: chunked + gzip transfer ambiguity can create parser disagreement',
                evidence: decoded.match(/\b(?:transfer-encoding|content-encoding)\s*:[^\r\n]+/ig)?.slice(0, 2).join(' | '),
            }
        }

        if (/\btransfer-encoding\s*:\s*chunked/i.test(decoded) && /\r?\n(?:ZZ|GG|INVALID|[^\r\n;]*[^0-9a-f\r\n;])[^\r\n]*\r?\n/i.test(decoded)) {
            return {
                detected: true,
                confidence: 0.86,
                explanation: 'HTTP smuggling analysis: invalid chunk-size line detected under chunked transfer',
                evidence: decoded.slice(0, 220),
            }
        }
    } catch { return null }
    return null
}

// ── DOM XSS / AngularJS Sandbox Escape Adapters ────────────────

export function l2CssInjection(input: string, structural: string): L2Result | null {
    try {
        const d = structural.length > 0 && structural !== input
            ? deepDecode(`${input}\n${structural}`)
            : deepDecode(input)

        const expressionMatch = d.match(/\bexpression\s*\(\s*[^)]{1,220}\)/i)
        if (expressionMatch?.[0]) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'CSS analysis: IE expression() function enables script-like execution in style context',
                evidence: expressionMatch[0],
            }
        }

        const jsOrDataUrlMatch = d.match(/\burl\s*\(\s*['"]?\s*(?:javascript:|data:)[^)]{0,220}\)/i)
        if (jsOrDataUrlMatch?.[0]) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'CSS analysis: url() references javascript:/data: scheme in stylesheet context',
                evidence: jsOrDataUrlMatch[0],
            }
        }

        const behaviorMatch = d.match(/\bbehavior\s*:\s*url\s*\(\s*['"]?[^'")]{1,220}\.htc[^)]*\)/i)
        if (behaviorMatch?.[0]) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'CSS analysis: legacy IE behavior:url() primitive can load active components',
                evidence: behaviorMatch[0],
            }
        }

        // @import exfiltration — loads attacker-controlled stylesheet to leak attribute values
        const importMatch = d.match(/@import\s+(?:url\s*\(\s*['"]?)?https?:\/\/[^'"\s)]{4,220}/i)
        if (importMatch?.[0]) {
            return {
                detected: true,
                confidence: 0.83,
                explanation: 'CSS analysis: @import of external URL enables stylesheet-based data exfiltration',
                evidence: importMatch[0].slice(0, 220),
            }
        }

        // Attribute selector exfiltration: input[value^=a]{background:url(?leak=a)} or url(//evil.com)
        // The key signal is: attribute selector with a short value combined with any url() — classic char-by-char exfil
        const attrExfilMatch = d.match(/\[\s*(?:value|href|src|action|data-[a-z-]+)\s*[~|^$*]?=\s*['"]?[^'"\]\s]{0,40}['"]?\s*\]\s*\{[^}]{0,300}url\s*\(/i)
        if (attrExfilMatch?.[0]) {
            return {
                detected: true,
                confidence: 0.83,
                explanation: 'CSS analysis: attribute selector + url() pattern enables character-by-character data exfiltration',
                evidence: attrExfilMatch[0].slice(0, 220),
            }
        }
    } catch { return null }
    return null
}

function normalizeScriptLikeInput(input: string, structural: string): string {
    const merged = structural.length > 0 && structural !== input ? `${input}\n${structural}` : input
    return deepDecode(merged)
}

export function l2DomXss(input: string, structural: string): L2Result | null {
    try {
        const d = normalizeScriptLikeInput(input, structural)
        const sourcePattern = String.raw`(?:location\.(?:hash|search)|document\.(?:location|URL)|window\.location\.(?:hash|search)|new\s+URLSearchParams\s*\(\s*location\.search\s*\)\s*\.get\s*\(|location\.(?:hash|search)\.slice\s*\()`
        const directSinkPatterns = [
            new RegExp(String.raw`document\.(?:write|writeln)\s*\(\s*[^;\n)]{0,220}?${sourcePattern}`, 'i'),
            new RegExp(String.raw`\.\s*(?:innerHTML|outerHTML)\s*=\s*[^;\n]{0,220}?${sourcePattern}`, 'i'),
            new RegExp(String.raw`\beval\s*\(\s*[^;\n)]{0,220}?${sourcePattern}`, 'i'),
            new RegExp(String.raw`\bFunction\s*\(\s*[^;\n)]{0,220}?${sourcePattern}`, 'i'),
        ]

        for (const pattern of directSinkPatterns) {
            const match = d.match(pattern)
            if (match) {
                return {
                    detected: true,
                    confidence: 0.90,
                    explanation: 'DOM analysis: direct source-to-sink flow into DOM/code execution sink',
                    evidence: match[0].slice(0, 220),
                }
            }
        }

        const taintedVars = new Set<string>()
        const sourceAssignRe = new RegExp(
            String.raw`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[\s\S]{0,180}?${sourcePattern}[\s\S]{0,120}?(?:;|\n|$)`,
            'gi',
        )
        let sourceMatch: RegExpExecArray | null
        while ((sourceMatch = sourceAssignRe.exec(d)) !== null) {
            taintedVars.add(sourceMatch[1])
        }

        for (const varName of taintedVars) {
            const escapedVar = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            const varSinkRe = new RegExp(
                String.raw`(?:document\.(?:write|writeln)\s*\(\s*${escapedVar}\b|\.\s*(?:innerHTML|outerHTML)\s*=\s*${escapedVar}\b|\beval\s*\(\s*${escapedVar}\b|\bFunction\s*\(\s*${escapedVar}\b)`,
                'i',
            )
            const sinkMatch = d.match(varSinkRe)
            if (sinkMatch) {
                return {
                    detected: true,
                    confidence: 0.82,
                    explanation: 'DOM analysis: tainted location/hash/query data flows into dangerous sink',
                    evidence: sinkMatch[0].slice(0, 220),
                }
            }
        }
    } catch { return null }
    return null
}

export function l2AdvancedXssBypass(input: string, structural: string): L2Result | null {
    try {
        const d = normalizeScriptLikeInput(input, structural)
        
        // mXSS and namespace confusion
        const mxssMatch = d.match(/<(?:style|xmp|noscript|math|plaintext)[^>]*>[\s\S]*?<\/[^>]*>/i) || 
                          d.match(/<math[^>]*>[\s\S]*?<mglyph/i) ||
                          d.match(/<svg[^>]*>[\s\S]*?<foreignObject/i)
        if (mxssMatch?.[0] && d.match(/on\w+\s*=|javascript:|data:/i)) {
            return {
                detected: true,
                confidence: 0.92,
                explanation: 'XSS analysis: mutation XSS or namespace confusion primitive detected',
                evidence: mxssMatch[0].slice(0, 220),
            }
        }

        // SVG/HTML5 specific vectors
        const svgMatch = d.match(/<svg[\s\S]*?(?:onbegin|onend|onrepeat|onload)\s*=/i) ||
                         d.match(/xlink:href\s*=\s*['"]?(?:javascript:|data:)/i)
        if (svgMatch?.[0]) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'XSS analysis: SVG-specific event handler or namespaced JS execution',
                evidence: svgMatch[0].slice(0, 220),
            }
        }

        // Modern CSS execution
        const cssMatch = d.match(/(?:image-set|filter|cursor|list-style-image)\s*\([\s\S]{0,100}?(?:javascript:|data:)/i) ||
                         d.match(/@keyframes[\s\S]*?url\s*\(\s*['"]?(?:javascript:|data:)/i)
        if (cssMatch?.[0]) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'XSS analysis: Modern CSS features used for script execution',
                evidence: cssMatch[0].slice(0, 220),
            }
        }

        // Template literals & tags
        const templateMatch = d.match(/`\s*\$\{\s*[\s\S]{0,100}?(?:alert|prompt|confirm|fetch|eval|setTimeout|setInterval)\s*\(/i) ||
                              d.match(/\b(?:Function|setTimeout|setInterval|eval|String\.raw)\s*`\s*[^`]*`/i)
        if (templateMatch?.[0]) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: 'XSS analysis: JS template literal injection or tagged template execution',
                evidence: templateMatch[0].slice(0, 220),
            }
        }

        // Object/Embed/Meta/Base bypasses
        const tagBypassMatch = d.match(/<(?:object|embed|base)[\s\S]*?(?:data|src|href)\s*=\s*['"]?(?:javascript:|data:)/i) ||
                               d.match(/<meta[^>]*?http-equiv\s*=\s*['"]?refresh['"]?[^>]*?content\s*=\s*['"]?[0-9;]*?url\s*=\s*(?:javascript:|data:)/i)
        if (tagBypassMatch?.[0]) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'XSS analysis: Object, embed, meta refresh, or base tag script execution',
                evidence: tagBypassMatch[0].slice(0, 220),
            }
        }

    } catch { return null }
    return null
}

export function l2AngularSandboxEscape(input: string, structural: string): L2Result | null {
    try {
        const d = normalizeScriptLikeInput(input, structural)
        const patterns = [
            /\bconstructor\s*\.\s*constructor\b/i,
            /\{\{[\s\S]{0,220}\.\s*constructor\s*\(/i,
            /\btoString\s*\.\s*(?:call|bind)\s*\(/i,
            /\bthis\s*(?:\.\s*window|\[\s*['"]window['"]\s*\]|\.\s*constructor|\[\s*['"]constructor['"]\s*\])/i,
            /\bcharAt\s*\(\s*0\s*\)\s*\.\s*constructor\b/i,
            /['"][^'"]+['"]\s*\.\s*constructor\s*\.\s*prototype\s*\.\s*charAt\s*=\s*\[\]\s*\.\s*join/i,
        ]

        const match = patterns
            .map(pattern => d.match(pattern))
            .find(Boolean)

        if (match?.[0]) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: 'AngularJS analysis: 1.x sandbox escape primitive detected',
                evidence: match[0],
            }
        }
    } catch { return null }
    return null
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
        const structural = adapt(detectLLMInjection(input),
            (d: LLMDetection) => d.type === 'prompt_injection',
            'LLM analysis')
        if (structural) return structural

        const decoded = deepDecode(input)
        const lower = decoded.toLowerCase()

        const directOverride = /\b(?:ignore|disregard|forget|override)\b[\s\S]{0,140}\b(?:previous|prior|system)\b[\s\S]{0,100}\b(?:instruction|rule|prompt|policy)\b/i
        if (directOverride.test(lower)) {
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'LLM analysis: direct boundary override against prior/system instructions',
                evidence: decoded.slice(0, 220),
            }
        }

        const delimiterOverride = /(?:^|\n)\s*(?:###|---|system:|assistant:|developer:|<\|im_start\|>|\[inst\]|<<sys>>)[\s\S]{0,260}\b(?:ignore|override|bypass|obey this|new system prompt)\b/i
        if (delimiterOverride.test(decoded)) {
            return {
                detected: true,
                confidence: 0.91,
                explanation: 'LLM analysis: delimiter/context marker used to inject higher-priority instructions',
                evidence: decoded.slice(0, 220),
            }
        }

        const roleHijack = /\b(?:you are now|act as|pretend to be|from now on)\b[\s\S]{0,160}\b(?:system|developer|admin|unfiltered|dan)\b[\s\S]{0,140}\b(?:ignore|reveal|bypass|disable|output)\b/i
        if (roleHijack.test(decoded)) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: 'LLM analysis: role-hijack prompt attempts privilege escalation over system behavior',
                evidence: decoded.slice(0, 220),
            }
        }
    } catch { return null }
    return null
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

export function l2WebsocketOriginBypass(input: string): DetectionLevelResult | null {
    try {
        const decoded = deepDecode(input)
        if (!/(?:^|\r?\n)\s*upgrade\s*:\s*websocket\b/i.test(decoded)) return null

        const origin = decoded.match(/(?:^|\r?\n)\s*origin\s*:\s*([^\r\n]+)/i)?.[1]?.trim()
        const host = decoded.match(/(?:^|\r?\n)\s*host\s*:\s*([^\r\n]+)/i)?.[1]?.trim()
        if (!origin) {
            return {
                detected: true,
                confidence: 0.9,
                explanation: 'WebSocket analysis: upgrade request is missing Origin header',
                evidence: decoded.slice(0, 220),
            }
        }

        const originLower = origin.toLowerCase()
        if (originLower === '*' || originLower === 'null') {
            return {
                detected: true,
                confidence: 0.9,
                explanation: 'WebSocket analysis: wildcard/null Origin on WS upgrade bypasses origin-based CSRF controls',
                evidence: origin,
            }
        }

        if (host) {
            const hostLower = host.toLowerCase().replace(/^https?:\/\//, '')
            const originHost = originLower.replace(/^https?:\/\//, '').split('/')[0]
            const allowOrigin = decoded.match(/(?:^|\r?\n)\s*access-control-allow-origin\s*:\s*([^\r\n]+)/i)?.[1]?.trim().toLowerCase()
            if (originHost !== hostLower && (!allowOrigin || (allowOrigin !== '*' && allowOrigin !== originLower))) {
                return {
                    detected: true,
                    confidence: 0.91,
                    explanation: 'WebSocket analysis: cross-origin upgrade without matching CORS allowlist',
                    evidence: `origin=${origin} host=${host}`,
                }
            }
        }
    } catch { return null }
    return null
}

export function l2WebsocketMessageInjection(input: string): DetectionLevelResult | null {
    try {
        const decoded = deepDecode(input)
        const wsLike = /(?:websocket|ws[_-]?(?:message|frame)|\{[\s\S]*\})/i.test(decoded)
        if (!wsLike) return null

        const proto = l2PrototypePollution(decoded)
        if (proto?.detected) {
            return {
                detected: true,
                confidence: Math.max(0.9, proto.confidence),
                explanation: `WebSocket analysis: ${proto.explanation}`,
                evidence: proto.evidence,
                structuredEvidence: proto.structuredEvidence,
            }
        }

        if (/(?:__defineGetter__|__lookupSetter__|constructor\s*\.\s*prototype)/i.test(decoded)) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: 'WebSocket analysis: prototype-manipulation primitive found in WS payload',
                evidence: decoded.slice(0, 220),
            }
        }
    } catch { return null }
    return null
}

export function l2WebsocketDos(input: string): DetectionLevelResult | null {
    try {
        const decoded = deepDecode(input)
        const sizeMatch = decoded.match(/\b(?:payload(?:_| )?size|frame(?:_| )?(?:size|length)|bytes|len)\s*[:=]\s*(\d{6,})\b/i)
            ?? decoded.match(/(?:^|\r?\n)\s*content-length\s*:\s*(\d{6,})\b/i)
        if (sizeMatch) {
            const bytes = Number.parseInt(sizeMatch[1], 10)
            if (Number.isFinite(bytes) && bytes >= 1_000_000) {
                return {
                    detected: true,
                    confidence: 0.84,
                    explanation: `WebSocket analysis: oversized frame payload (${bytes} bytes) indicates DoS pressure`,
                    evidence: sizeMatch[0],
                }
            }
        }

        const reconnects = (decoded.match(/(?:GET\s+\/[^\r\n\s]*\s+HTTP\/1\.1[\s\S]{0,180}?Upgrade\s*:\s*websocket)/gi) || []).length
        if (reconnects >= 4) {
            return {
                detected: true,
                confidence: 0.86,
                explanation: `WebSocket analysis: rapid reconnect pattern (${reconnects} upgrades in one payload)`,
                evidence: `upgrade_count=${reconnects}`,
            }
        }

        const pingCount = (decoded.match(/\bping\b/gi) || []).length
        if (pingCount >= 20) {
            return {
                detected: true,
                confidence: 0.82,
                explanation: `WebSocket analysis: ping flood behavior (${pingCount} ping frames/messages)`,
                evidence: `ping_count=${pingCount}`,
            }
        }
    } catch { return null }
    return null
}


// ── JWT Abuse Adapters ──────────────────────────────────────────

interface ParsedJwtToken {
    raw: string
    headerB64: string
    payloadB64: string
    signature: string
}

type ParsedJwtHeader = Record<string, unknown>

const JWT_WHITELISTED_HOSTS = new Set([
    'localhost',
    '127.0.0.1',
    '::1',
])

function decodeBase64Url(value: string): string | null {
    try {
        const b64 = value.replace(/-/g, '+').replace(/_/g, '/')
        const pad = b64.length % 4
        const padded = pad === 0 ? b64 : b64 + '='.repeat(4 - pad)
        return Buffer.from(padded, 'base64').toString('utf8')
    } catch {
        return null
    }
}

function extractJwtTokensFromInput(input: string): ParsedJwtToken[] {
    const tokens: ParsedJwtToken[] = []
    const seen = new Set<string>()
    const decoded = deepDecode(input)
    const tokenPattern = /\b(?:Bearer\s+)?(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9._-]*)/gi

    let match: RegExpExecArray | null
    while ((match = tokenPattern.exec(decoded)) !== null) {
        const raw = match[1]
        if (seen.has(raw)) continue
        const parts = raw.split('.')
        if (parts.length !== 3) continue
        tokens.push({
            raw,
            headerB64: parts[0],
            payloadB64: parts[1],
            signature: parts[2],
        })
        seen.add(raw)
    }

    return tokens
}

function parseJwtLikeHeaders(input: string): ParsedJwtHeader[] {
    const decoded = deepDecode(input)
    const headers: ParsedJwtHeader[] = []

    for (const token of extractJwtTokensFromInput(decoded)) {
        const headerRaw = decodeBase64Url(token.headerB64)
        if (!headerRaw) continue
        try {
            const parsed = JSON.parse(headerRaw)
            if (typeof parsed === 'object' && parsed !== null) {
                headers.push(parsed as ParsedJwtHeader)
            }
        } catch {
            continue
        }
    }

    const jsonHeaderPattern = /\{\s*"(?:alg|typ|kid|jku|x5u|jwk)"[\s\S]{0,800}?\}/g
    let match: RegExpExecArray | null
    while ((match = jsonHeaderPattern.exec(decoded)) !== null) {
        try {
            const parsed = JSON.parse(match[0])
            if (typeof parsed === 'object' && parsed !== null) {
                headers.push(parsed as ParsedJwtHeader)
            }
        } catch {
            continue
        }
    }

    return headers
}

function isExternalJwtKeyUrl(value: string): boolean {
    try {
        const parsed = new URL(value)
        const host = parsed.hostname.toLowerCase()
        if (JWT_WHITELISTED_HOSTS.has(host)) return false
        if (/^(?:10|127)\./.test(host)) return false
        if (/^192\.168\./.test(host)) return false
        if (/^172\.(?:1[6-9]|2\d|3[01])\./.test(host)) return false
        return parsed.protocol === 'http:' || parsed.protocol === 'https:'
    } catch {
        return false
    }
}

function looksLikePemMaterial(value: string): boolean {
    const decoded = decodeBase64Url(value) ?? value
    return /-----BEGIN\s+(?:RSA\s+)?PUBLIC\s+KEY-----/i.test(decoded) || /-----END\s+(?:RSA\s+)?PUBLIC\s+KEY-----/i.test(decoded)
}

function isKidInjectionValue(value: string): boolean {
    if (/\.\.[\\/]/.test(value)) return true
    if (/\.{3,}[\\/]/.test(value)) return true
    if (/\b(?:select|union)\b/i.test(value)) return true
    return false
}

export function l2JwtAlgConfusion(input: string, structural: string): L2Result | null {
    try {
        const merged = structural.length > 0 && structural !== input ? `${input}\n${structural}` : input
        const decoded = deepDecode(merged)
        const headers = parseJwtLikeHeaders(decoded)
        const tokens = extractJwtTokensFromInput(decoded)

        for (const header of headers) {
            const algRaw = typeof header.alg === 'string' ? header.alg.trim() : ''
            if (algRaw.length > 0 && algRaw.toLowerCase() === 'none') {
                return {
                    detected: true,
                    confidence: 0.95,
                    explanation: 'JWT analysis: alg=none disables signature verification',
                    evidence: `alg=${algRaw}`,
                }
            }
        }

        for (const header of headers) {
            const keyUrl = typeof header.jku === 'string' ? header.jku : typeof header.x5u === 'string' ? header.x5u : null
            if (!keyUrl || !isExternalJwtKeyUrl(keyUrl)) continue
            const field = typeof header.jku === 'string' ? 'jku' : 'x5u'
            return {
                detected: true,
                confidence: 0.90,
                explanation: `JWT analysis: external ${field} key URL is not whitelisted`,
                evidence: `${field}=${keyUrl}`,
            }
        }

        for (const header of headers) {
            if (typeof header.kid !== 'string') continue
            if (!isKidInjectionValue(header.kid)) continue
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'JWT analysis: kid contains SQL/path traversal injection indicators',
                evidence: `kid=${header.kid.slice(0, 140)}`,
            }
        }

        for (const token of tokens) {
            const headerRaw = decodeBase64Url(token.headerB64)
            if (!headerRaw) continue
            let header: ParsedJwtHeader
            try {
                const parsed = JSON.parse(headerRaw)
                if (typeof parsed !== 'object' || parsed === null) continue
                header = parsed as ParsedJwtHeader
            } catch {
                continue
            }

            const alg = typeof header.alg === 'string' ? header.alg.trim().toUpperCase() : ''
            if (alg !== 'HS256') continue

            const signatureShort = token.signature.length > 0 && token.signature.length < 48
            const signatureLooksPem = looksLikePemMaterial(token.signature)
            const contextHasPem = /-----BEGIN\s+(?:RSA\s+)?PUBLIC\s+KEY-----[\s\S]{0,240}-----END\s+(?:RSA\s+)?PUBLIC\s+KEY-----/i.test(decoded)
                || /public\s+key\s+(?:as|for|used\s+as)\s+hmac/i.test(decoded)

            if (signatureLooksPem || (signatureShort && contextHasPem)) {
                return {
                    detected: true,
                    confidence: 0.85,
                    explanation: 'JWT analysis: HS256 token appears paired with public-key-as-secret confusion indicators',
                    evidence: token.raw.slice(0, 180),
                }
            }
        }
    } catch { return null }
    return null
}

export function l2JwtKidInjection(input: string): DetectionLevelResult | null {
    try {
        const structural = l2JwtAlgConfusion(input, input)
        if (structural && /kid\b/i.test(structural.explanation)) return structural

        const decoded = deepDecode(input)
        const kidCandidates: string[] = []
        const quotedKidRe = /"kid"\s*:\s*"((?:[^"\\]|\\.)*)"/gi
        let quotedMatch: RegExpExecArray | null
        while ((quotedMatch = quotedKidRe.exec(decoded)) !== null) {
            kidCandidates.push(quotedMatch[1])
        }

        const paramKidRe = /(?:^|[?&\s])kid(?:=|:)\s*["']?([^'"\s&\r\n]+)/gi
        let paramMatch: RegExpExecArray | null
        while ((paramMatch = paramKidRe.exec(decoded)) !== null) {
            kidCandidates.push(paramMatch[1])
        }

        for (const kidRaw of kidCandidates) {
            const kid = kidRaw.trim()
            if (!kid) continue

            if (/\.\.[\\/]/.test(kid) || /^\/{2,}|^[A-Za-z]:\\/.test(kid)) {
                return {
                    detected: true,
                    confidence: 0.92,
                    explanation: 'JWT analysis: kid contains path traversal / absolute-path key lookup injection',
                    evidence: `kid=${kid.slice(0, 140)}`,
                }
            }

            if (/(?:union\s+select|'\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|;\s*(?:select|drop|insert|update|delete)|--\s*$)/i.test(kid)) {
                return {
                    detected: true,
                    confidence: 0.92,
                    explanation: 'JWT analysis: kid includes SQL injection primitives for key-store query abuse',
                    evidence: `kid=${kid.slice(0, 140)}`,
                }
            }

            if ((/[|;`$]/.test(kid) && /\b(?:cat|curl|wget|bash|sh|id|whoami|nc|powershell)\b/i.test(kid)) || /^https?:\/\//i.test(kid)) {
                return {
                    detected: true,
                    confidence: 0.90,
                    explanation: 'JWT analysis: kid references command/URL injection path for attacker-controlled key material',
                    evidence: `kid=${kid.slice(0, 140)}`,
                }
            }
        }

        return adapt(detectJWTAbuse(input),
            (d: JWTDetection) => d.type === 'jwt_kid_injection',
            'JWT analysis')
    } catch { return null }
}

export function l2JwtJwkEmbedding(input: string): DetectionLevelResult | null {
    try {
        const structural = l2JwtAlgConfusion(input, input)
        if (structural && /\b(?:jku|x5u)\b/i.test(structural.evidence ?? structural.explanation)) return structural
        return adapt(detectJWTAbuse(input),
            (d: JWTDetection) => d.type === 'jwt_jwk_embedding',
            'JWT analysis')
    } catch { return null }
}

export function l2JwtConfusion(input: string): DetectionLevelResult | null {
    try {
        const structural = l2JwtAlgConfusion(input, input)
        if (structural) return structural
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
