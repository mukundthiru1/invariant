/**
 * Property Proof Constructor — Constructive Verification Engine
 *
 * Builds machine-verifiable proofs that an input violates a mathematical
 * property. This is the core of what makes INVARIANT fundamentally
 * different from every other security product:
 *
 *   CrowdStrike: "blocked — ML confidence 0.92"
 *   INVARIANT:   "blocked — PROOF: single quote at offset 0 terminates
 *                 string context, expression 1=1 at offset 5 is tautological,
 *                 comment -- at offset 9 suppresses remaining syntax"
 *
 * Each proof step is independently verifiable. The complete proof shows
 * the full exploitation algebra: context_escape ∘ payload_inject ∘ syntax_repair.
 *
 * Proof construction is per-domain: SQL, HTML, Shell, Path, URL, XML.
 * Each domain has its own structural analysis that identifies the three
 * algebraic phases in the input.
 */

import type {
    InvariantClassModule,
    DetectionLevelResult,
    PropertyProof,
    ProofStep,
} from './classes/types.js'
import {
    sqlTokenize,
    type SqlToken,
    detectTautologies,
    type TautologyDetection,
} from './evaluators/sql-expression-evaluator.js'
import { HtmlTokenizer, type HtmlTokenType } from './tokenizers/html-tokenizer.js'
import { ShellTokenizer, type ShellTokenType } from './tokenizers/shell-tokenizer.js'
import { UrlTokenizer, type UrlTokenType } from './tokenizers/url-tokenizer.js'
import { PathTokenizer, type PathTokenType } from './tokenizers/path-tokenizer.js'
import { TemplateTokenizer, type TemplateTokenType } from './tokenizers/template-tokenizer.js'
import type { Token } from './tokenizers/types.js'


// ── Domain Proof Patterns ────────────────────────────────────────
//
// Per-domain regex patterns that identify the three phases of an injection.
// These are NOT detection patterns — they're STRUCTURAL ANALYSIS patterns
// that extract proof components from inputs already identified as malicious.

interface DomainPattern {
    /** Identify the context escape component */
    escape: RegExp
    /** Labels for what the escape does in this domain */
    escapeProperty: string
    /** Identify the payload injection component */
    payload: RegExp
    /** Labels for what the payload does in this domain */
    payloadProperty: string
    /** Identify the syntax repair component */
    repair: RegExp
    /** Labels for what the repair does in this domain */
    repairProperty: string
}

const DOMAIN_PATTERNS: Readonly<Record<string, DomainPattern>> = {
    sqli: {
        escape: /['"`)]\s*(?=(?:OR|AND|UNION|SELECT|;|HAVING|ORDER|GROUP|INSERT|UPDATE|DELETE|DROP)\b)/i,
        escapeProperty: 'String/expression context terminated — input escapes SQL literal',
        payload: /(?:OR\s+\S+\s*(?:=|<>|!=|LIKE|IS|BETWEEN|IN)\s*\S+|UNION\s+(?:ALL\s+)?SELECT\b|;\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC)\b|SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|PG_SLEEP\s*\(|EXTRACTVALUE\s*\(|UPDATEXML\s*\()/i,
        payloadProperty: 'Injected SQL operation modifies query semantics',
        repair: /(?:--\s*$|#\s*$|\/\*)/,
        repairProperty: 'SQL comment suppresses remaining query syntax',
    },
    xss: {
        escape: /['"><]\s*(?=[/a-z]|on\w)/i,
        escapeProperty: 'Attribute/element context broken — input escapes HTML boundary',
        payload: /(?:<script|<iframe|<img|<svg|<object|on\w+\s*=\s*['"]?|javascript\s*:|data\s*:\s*text\/html)/i,
        payloadProperty: 'Script execution payload injected into DOM',
        repair: /(?:>|['"]|\/\s*>)\s*$/,
        repairProperty: 'HTML syntax repaired to produce valid DOM',
    },
    cmdi: {
        escape: /[;|&`\n]\s*/,
        escapeProperty: 'Command boundary broken — input terminates current command',
        payload: /(?:\b(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc|bash|sh|python|perl|ruby|php|echo|rm|chmod|chown|kill|ps|env|export|set)\b|\$\(|\$\{)/i,
        payloadProperty: 'System command injected after boundary break',
        repair: /(?:[;#]\s*$|$)/,
        repairProperty: 'Command sequence terminates naturally or via comment',
    },
    path_traversal: {
        escape: /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e%252f)/i,
        escapeProperty: 'Directory traversal escapes intended file path boundary',
        payload: /(?:etc\/passwd|etc\/shadow|\.env|\.ssh|\.aws|\.git|win\.ini|boot\.ini|web\.config|wp-config)/i,
        payloadProperty: 'Sensitive file targeted outside allowed directory',
        repair: /(?:%00|\.(?:jpg|png|gif|pdf|txt)$|\x00)/i,
        repairProperty: 'Null byte or extension appended to bypass file type validation',
    },
    ssrf: {
        escape: /(?:https?:\/\/|\/\/)/i,
        escapeProperty: 'URL scheme initiates server-side request',
        payload: /(?:127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.169\.254|metadata\.google|::1|\[::1\]|0x7f|2130706433)/i,
        payloadProperty: 'Request targets internal/metadata endpoint not accessible to client',
        repair: /(?:\/|$)/,
        repairProperty: 'URL path completes valid HTTP request',
    },
    xxe: {
        escape: /<!(?:DOCTYPE|ENTITY)\s/i,
        escapeProperty: 'XML DTD declaration introduces entity definitions',
        payload: /(?:SYSTEM\s+['"](?:file|http|https|ftp|gopher|expect|php):\/\/|%\s+\w+\s+SYSTEM)/i,
        payloadProperty: 'External entity references resource outside document scope',
        repair: /(?:>|]>)\s*$/,
        repairProperty: 'DTD/entity declaration properly closed for XML parsing',
    },
    ssti: {
        escape: /(?:\{\{|\$\{|#\{|<%=?|{%)\s*/i,
        escapeProperty: 'Template delimiter opens server-side expression context',
        payload: /(?:__class__|__mro__|__subclasses__|constructor\s*\.\s*constructor|getruntime|processbuilder|exec\s*\()/i,
        payloadProperty: 'Injected expression traverses object graph toward execution capabilities',
        repair: /(?:\}\}|%>|\}|%})\s*$/,
        repairProperty: 'Template expression is syntactically closed for engine evaluation',
    },
}

// Map category strings to domain pattern keys
const CATEGORY_TO_DOMAIN: Readonly<Record<string, string>> = {
    sqli: 'sqli',
    xss: 'xss',
    cmdi: 'cmdi',
    path_traversal: 'path_traversal',
    ssrf: 'ssrf',
    injection: 'sqli', // fallback — many injection subtypes
}

function evidenceStepsFromL2(l2Result: DetectionLevelResult | null): ProofStep[] {
    if (!l2Result?.structuredEvidence?.length) return []
    return l2Result.structuredEvidence.map(ev => ({
        operation: ev.operation,
        input: ev.matchedInput,
        output: ev.interpretation,
        property: ev.property,
        offset: ev.offset,
        confidence: l2Result.confidence,
    }))
}

function dedupeNonSemanticStepsByOffset(steps: ProofStep[]): ProofStep[] {
    const semanticSteps: ProofStep[] = []
    const nonSemanticByOffset = new Map<number, ProofStep>()

    for (const step of steps) {
        if (step.operation === 'semantic_eval') {
            semanticSteps.push(step)
            continue
        }

        const existing = nonSemanticByOffset.get(step.offset)
        if (!existing || step.confidence > existing.confidence) {
            nonSemanticByOffset.set(step.offset, step)
        }
    }

    const deduped = [...nonSemanticByOffset.values(), ...semanticSteps]
    return deduped.sort((a, b) => a.offset - b.offset)
}

function ensureProofVerificationDefaults(proof: Omit<PropertyProof, 'verifiedSteps' | 'verificationCoverage' | 'proofVerificationLevel'> & Partial<Pick<PropertyProof, 'verifiedSteps' | 'verificationCoverage' | 'proofVerificationLevel'>>): PropertyProof {
    return {
        ...proof,
        verifiedSteps: proof.verifiedSteps ?? 0,
        verificationCoverage: proof.verificationCoverage ?? 0,
        proofVerificationLevel: proof.proofVerificationLevel ?? 'none',
    }
}

function normalizeVerificationText(value: string): string {
    return value.trim().replace(/\s+/g, ' ').toUpperCase()
}

function findTokenAtOffsetInVariants(
    variants: { tokens: SqlToken[]; baseOffset: number }[],
    offset: number,
): { token: SqlToken; index: number; variant: { tokens: SqlToken[]; baseOffset: number } } | null {
    for (const variant of variants) {
        for (let i = 0; i < variant.tokens.length; i++) {
            if (variant.baseOffset + variant.tokens[i].position === offset) {
                return { token: variant.tokens[i], index: i, variant }
            }
        }
    }
    return null
}

function nextMeaningfulToken(tokens: SqlToken[], startIndex: number): SqlToken | null {
    for (let i = startIndex; i < tokens.length; i++) {
        if (tokens[i].type !== 'WHITESPACE') return tokens[i]
    }
    return null
}

/**
 * Computationally verify proof steps that were structurally assembled.
 *
 * Current verification coverage:
 * - payload_inject (SQL): expression must be a detected tautology via AST evaluation
 * - context_escape (SQL): STRING token at offset must be followed by non-STRING token
 * - syntax_repair (SQL): separator token (-- or #) with no meaningful tokens after
 *
 * Non-SQL domains keep step-level verification fields undefined while still
 * reporting aggregate metadata.
 */
export function verifyProofSteps(proof: PropertyProof, input: string): PropertyProof {
    if (proof.domain !== 'sqli') {
        // Non-SQL domains may already have verified steps from tokenizer-based proof construction.
        // Count them instead of zeroing — path/SSRF/XSS/CMD constructors set verified: true.
        const alreadyVerified = proof.steps.filter(s => s.verified).length
        const coverage = proof.steps.length > 0 ? alreadyVerified / proof.steps.length : 0
        const level = coverage >= 0.5 ? 'verified' : coverage > 0 ? 'structural' : 'none'
        return ensureProofVerificationDefaults({
            ...proof,
            verifiedSteps: alreadyVerified,
            verificationCoverage: coverage,
            proofVerificationLevel: level as PropertyProof['proofVerificationLevel'],
        })
    }

    let tokens: SqlToken[] = []
    let tautologies: TautologyDetection[] = []
    try {
        tokens = sqlTokenize(input)
        tautologies = detectTautologies(input)
    } catch {
        return ensureProofVerificationDefaults({
            ...proof,
            verifiedSteps: 0,
            verificationCoverage: 0,
            proofVerificationLevel: 'structural',
        })
    }

    const matchingTautologies = new Set(tautologies.map(t => normalizeVerificationText(t.expression)))
    const variants = getSqlTokenVariants(input, tokens)

    const verifiedSteps = proof.steps.map(step => {
        if (step.operation === 'payload_inject') {
            const normalizedInput = normalizeVerificationText(step.input)
            if (normalizedInput && matchingTautologies.has(normalizedInput)) {
                return {
                    ...step,
                    verified: true,
                    verificationMethod: 'ast_evaluation',
                }
            }
            return step
        }

        if (step.operation === 'context_escape') {
            const tokenMatch = findTokenAtOffsetInVariants(variants, step.offset)
            const nextToken = tokenMatch
                ? nextMeaningfulToken(tokenMatch.variant.tokens, tokenMatch.index + 1)
                : null
            if (tokenMatch?.token.type === 'STRING' && nextToken && nextToken.type !== 'STRING') {
                return {
                    ...step,
                    verified: true,
                    verificationMethod: 'tokenizer_parse',
                }
            }

            if (step.input.length > 0 && /['"`]/.test(step.input[0])) {
                const trailing = sqlTokenize(input.slice(step.offset + 1)).filter(
                    tok => tok.type !== 'WHITESPACE',
                )
                if (trailing.length > 0 && trailing[0].type !== 'STRING') {
                    return {
                        ...step,
                        verified: true,
                        verificationMethod: 'tokenizer_parse',
                    }
                }
            }
            return step
        }

        if (step.operation === 'syntax_repair') {
            const match = findTokenAtOffsetInVariants(variants, step.offset)
            if (match) {
                if (match.token.type === 'SEPARATOR'
                    && (match.token.value.startsWith('--') || match.token.value.startsWith('#'))
                    && !match.variant.tokens.slice(match.index + 1).some(tok => tok.type !== 'WHITESPACE')
                ) {
                    return {
                        ...step,
                        verified: true,
                        verificationMethod: 'tokenizer_parse',
                    }
                }
            }

            const trailing = sqlTokenize(input.slice(step.offset)).filter(tok => tok.type !== 'WHITESPACE')
            const first = trailing[0]
            if (
                first &&
                first.type === 'SEPARATOR' &&
                (first.value.startsWith('--') || first.value.startsWith('#')) &&
                !trailing.slice(1).some(tok => tok.type !== 'WHITESPACE')
            ) {
                return {
                    ...step,
                    verified: true,
                    verificationMethod: 'tokenizer_parse',
                }
            }

            return step
        }

        return step
    })

    const verifiedCount = verifiedSteps.filter(step => step.verified).length
    const coverage = verifiedSteps.length > 0 ? verifiedCount / verifiedSteps.length : 0
    const proofVerificationLevel = coverage > 0.5 ? 'verified' : 'structural'

    return {
        ...proof,
        steps: verifiedSteps,
        verifiedSteps: verifiedCount,
        verificationCoverage: coverage,
        proofVerificationLevel,
    }
}

function applyStructuredEvidence(
    proof: PropertyProof | null,
    l2Result: DetectionLevelResult | null,
): PropertyProof | null {
    if (!proof || !l2Result?.structuredEvidence?.length) return proof

    const mergedSteps = dedupeNonSemanticStepsByOffset([
        ...proof.steps,
        ...evidenceStepsFromL2(l2Result),
    ])
    const { isComplete, proofConfidence } = calculateProofMetrics(mergedSteps, l2Result)

    return ensureProofVerificationDefaults({
        ...proof,
        steps: mergedSteps,
        isComplete,
        proofConfidence,
    })
}


// ── Proof Construction ───────────────────────────────────────────

/**
 * Construct a PropertyProof for a detection.
 *
 * Analyzes the input to identify the three phases of the exploitation
 * algebra (escape, payload, repair) and produces a machine-verifiable
 * proof with exact byte offsets and property statements.
 *
 * @param module   The class module that detected the violation
 * @param input    The raw input string
 * @param l2Result The L2 structural evaluator result (if available)
 * @returns A PropertyProof, or null if insufficient evidence for a proof
 */
export function constructProof(
    module: InvariantClassModule,
    input: string,
    l2Result: DetectionLevelResult | null,
): PropertyProof | null {
    const category = String(module.category)
    const moduleId = String(module.id)
    const inferredDomain =
        moduleId.startsWith('xxe_') ? 'xxe' :
            moduleId.startsWith('ssti_') ? 'ssti' :
                null
    const domainKey = inferredDomain ?? CATEGORY_TO_DOMAIN[category] ?? category
    const pattern = DOMAIN_PATTERNS[domainKey]

    // If we don't have domain patterns, construct a minimal proof from L2 evidence
    if (!pattern) {
        if (!l2Result?.detected) return null
        return applyStructuredEvidence(constructMinimalProof(module, input, l2Result), l2Result)
    }

    // SQLI now uses tokenizer + evaluator-based proof construction.
    // Regex patterns remain as fallback only when tokenization fails or has no tokens.
    if (domainKey === 'sqli') {
        let canUseTokenizer = false
        try {
            canUseTokenizer = sqlTokenize(input).length > 0
        } catch {
            canUseTokenizer = false
        }

        if (canUseTokenizer) {
            const sqlProof = constructSqlProof(input, l2Result)
            if (!sqlProof) return null
            const merged = applyStructuredEvidence({
                ...sqlProof,
                property: module.formalProperty ?? module.description,
                impact: module.description,
            }, l2Result)
            if (!merged) return null
            return verifyProofSteps(merged, input)
        }
    }

    if (domainKey === 'xss') {
        const xssProof = constructXssProof(input, l2Result)
        if (xssProof) {
            return applyStructuredEvidence({
                ...xssProof,
                property: module.formalProperty ?? module.description,
                impact: module.description,
            }, l2Result)
        }
    }

    if (domainKey === 'cmdi') {
        const cmdProof = constructCmdProof(input, l2Result)
        if (cmdProof) {
            return applyStructuredEvidence({
                ...cmdProof,
                property: module.formalProperty ?? module.description,
                impact: module.description,
            }, l2Result)
        }
    }

    if (domainKey === 'path_traversal') {
        const pathProof = constructPathProof(input, l2Result)
        if (pathProof) {
            const merged = applyStructuredEvidence({
                ...pathProof,
                property: module.formalProperty ?? module.description,
                impact: module.description,
            }, l2Result)
            if (merged) return verifyProofSteps(merged, input)
        }
    }

    if (domainKey === 'ssrf') {
        const ssrfProof = constructSsrfProof(input, l2Result)
        if (ssrfProof) {
            const merged = applyStructuredEvidence({
                ...ssrfProof,
                property: module.formalProperty ?? module.description,
                impact: module.description,
            }, l2Result)
            if (merged) return verifyProofSteps(merged, input)
        }
    }

    if (domainKey === 'xxe') {
        const xxeProof = constructXxeProof(input, l2Result)
        if (xxeProof) {
            const merged = applyStructuredEvidence({
                ...xxeProof,
                property: module.formalProperty ?? module.description,
                impact: module.description,
            }, l2Result)
            if (merged) return verifyProofSteps(merged, input)
        }
    }

    if (domainKey === 'ssti') {
        const sstiProof = constructSstiProof(input, l2Result)
        if (sstiProof) {
            const merged = applyStructuredEvidence({
                ...sstiProof,
                property: module.formalProperty ?? module.description,
                impact: module.description,
            }, l2Result)
            if (merged) return verifyProofSteps(merged, input)
        }
    }

    const steps: ProofStep[] = []

    const structuredEvidence = evidenceStepsFromL2(l2Result)
    if (structuredEvidence.length > 0) {
        steps.push(...structuredEvidence)
    }

    // Phase 1: Context Escape
    const escapeMatch = pattern.escape.exec(input)
    if (escapeMatch) {
        steps.push({
            operation: 'context_escape',
            input: escapeMatch[0],
            output: pattern.escapeProperty,
            property: `escape(${domainKey}): ${pattern.escapeProperty}`,
            offset: escapeMatch.index,
            confidence: 0.90,
        })
    }

    // Phase 2: Payload Injection
    const payloadMatch = pattern.payload.exec(input)
    if (payloadMatch) {
        steps.push({
            operation: 'payload_inject',
            input: payloadMatch[0],
            output: pattern.payloadProperty,
            property: `payload(${domainKey}): ${pattern.payloadProperty}`,
            offset: payloadMatch.index,
            confidence: 0.92,
        })
    }

    // Phase 3: Syntax Repair
    const repairMatch = pattern.repair.exec(input)
    if (repairMatch && repairMatch[0].length > 0) {
        steps.push({
            operation: 'syntax_repair',
            input: repairMatch[0],
            output: pattern.repairProperty,
            property: `repair(${domainKey}): ${pattern.repairProperty}`,
            offset: repairMatch.index,
            confidence: 0.85,
        })
    }

    // Add L2 semantic evaluation step (if available)
    if (l2Result?.detected) {
        steps.push({
            operation: 'semantic_eval',
            input: l2Result.evidence ?? input.slice(0, 100),
            output: l2Result.explanation,
            property: module.formalProperty ?? module.description,
            offset: 0,
            confidence: l2Result.confidence,
        })
    }

    if (steps.length === 0) return null

    const normalizedSteps = l2Result?.structuredEvidence?.length
        ? dedupeNonSemanticStepsByOffset(steps)
        : steps.sort((a, b) => a.offset - b.offset)

    if (normalizedSteps.length === 0) return null

    const { isComplete, proofConfidence } = calculateProofMetrics(normalizedSteps, l2Result)

    return ensureProofVerificationDefaults({
        property: module.formalProperty ?? module.description,
        witness: input.length > 200 ? input.slice(0, 200) + '…' : input,
        steps: normalizedSteps,
        isComplete,
        domain: domainKey,
        impact: module.description,
        proofConfidence,
    })
}

/**
 * Construct SQL proof steps from tokenizer + evaluator evidence.
 *
 * Returns null when tokenization fails or produces no tokens so caller can
 * fall back to legacy regex patterns.
 */
export function constructSqlProof(
    input: string,
    l2Result: DetectionLevelResult | null,
): PropertyProof | null {
    let tokens: SqlToken[] = []
    try {
        tokens = sqlTokenize(input)
    } catch {
        return null
    }

    if (tokens.length === 0) return null

    const variants = getSqlTokenVariants(input, tokens)
    const steps: ProofStep[] = []

    // Phase 1: Context Escape (string termination)
    const escapeStep = findSqlEscapeStep(input, variants)
    if (escapeStep) steps.push(escapeStep)

    // Phase 2: Payload Injection (tautology / union / stacked / time oracle)
    const payloadStep = findSqlPayloadStep(input, variants)
    if (payloadStep) steps.push(payloadStep)

    // Phase 3: Syntax Repair (comment separator at end)
    const repairStep = findSqlRepairStep(variants)
    if (repairStep) steps.push(repairStep)

    // L2 semantic evidence (kept as independent proof step)
    if (l2Result?.detected) {
        steps.push({
            operation: 'semantic_eval',
            input: l2Result.evidence ?? input.slice(0, 100),
            output: l2Result.explanation,
            property: l2Result.explanation,
            offset: 0,
            confidence: l2Result.confidence,
        })
    }

    if (steps.length === 0) return null
    steps.sort((a, b) => a.offset - b.offset)

    const { isComplete, proofConfidence } = calculateProofMetrics(steps, l2Result)
    return verifyProofSteps(
        ensureProofVerificationDefaults({
        property: l2Result?.explanation ?? 'SQL property violation',
        witness: input.length > 200 ? input.slice(0, 200) + '…' : input,
        steps,
        isComplete,
        domain: 'sqli',
        impact: 'SQL injection alters query semantics',
        proofConfidence,
        }),
        input,
    )
}

interface SqlTokenVariant {
    tokens: SqlToken[]
    baseOffset: number
}

function getSqlTokenVariants(input: string, baseTokens: SqlToken[]): SqlTokenVariant[] {
    const variants: SqlTokenVariant[] = [{
        tokens: baseTokens.filter(t => t.type !== 'WHITESPACE'),
        baseOffset: 0,
    }]

    const firstNonWs = input.search(/\S/)
    if (firstNonWs < 0) return variants
    const trimmed = input.slice(firstNonWs)

    const prefixes = [
        /^['"`]+\)?\s*/,
        /^\)+\s*/,
        /^['"`]?\)\s*/,
    ]

    for (const prefix of prefixes) {
        const match = trimmed.match(prefix)
        if (!match || !match[0]) continue
        const consumed = match[0].length
        const rest = trimmed.slice(consumed)
        if (rest.length === 0) continue
        const restTokens = sqlTokenize(rest).filter(t => t.type !== 'WHITESPACE')
        if (restTokens.length === 0) continue
        variants.push({
            tokens: restTokens,
            baseOffset: firstNonWs + consumed,
        })
    }

    return variants
}

function findSqlEscapeStep(input: string, variants: SqlTokenVariant[]): ProofStep | null {
    for (const variant of variants) {
        const meaningful = variant.tokens
        for (let i = 0; i < meaningful.length - 1; i++) {
            const current = meaningful[i]
            const next = meaningful[i + 1]
            if (
                current.type === 'STRING' &&
                (next.type === 'BOOLEAN_OP' || next.type === 'KEYWORD' || next.type === 'SEPARATOR')
            ) {
                return {
                    operation: 'context_escape',
                    input: current.value,
                    output: `String context terminated before SQL ${next.type}: ${next.value}`,
                    property: 'escape(sqli): SQL string boundary is closed before injected operators/keywords',
                    offset: variant.baseOffset + current.position,
                    confidence: 0.90,
                }
            }
        }
    }

    // Injection-prefix fallback using tokenizer on post-quote content.
    // This still uses token evidence for the SQL continuation.
    const firstNonWs = input.search(/\S/)
    if (firstNonWs >= 0) {
        const ch = input[firstNonWs]
        if (ch === '\'' || ch === '"' || ch === '`') {
            const rest = input.slice(firstNonWs + 1)
            const restMeaningful = sqlTokenize(rest).filter(t => t.type !== 'WHITESPACE')
            const first = restMeaningful[0]
            if (first && (first.type === 'BOOLEAN_OP' || first.type === 'KEYWORD' || first.type === 'SEPARATOR')) {
                return {
                    operation: 'context_escape',
                    input: ch,
                    output: `Leading quote terminates host SQL string; injected ${first.type}: ${first.value} follows`,
                    property: 'escape(sqli): leading delimiter escapes application SQL string context',
                    offset: firstNonWs,
                    confidence: 0.88,
                }
            }
        }
    }

    return null
}

function findSqlPayloadStep(input: string, variants: SqlTokenVariant[]): ProofStep | null {
    const tautologies = detectTautologies(input)
    const tautologyStep = buildTautologyStep(variants, tautologies)
    if (tautologyStep) return tautologyStep

    for (const variant of variants) {
        const meaningful = variant.tokens
        for (let i = 0; i < meaningful.length; i++) {
            const tok = meaningful[i]
            if (tok.type === 'KEYWORD' && tok.value === 'UNION') {
                let j = i + 1
                if (j < meaningful.length && meaningful[j].type === 'KEYWORD' && meaningful[j].value === 'ALL') j++
                if (j < meaningful.length && meaningful[j].type === 'KEYWORD' && meaningful[j].value === 'SELECT') {
                    const endTok = meaningful[j]
                    return {
                        operation: 'payload_inject',
                        input: input.slice(variant.baseOffset + tok.position, variant.baseOffset + endTok.position + endTok.value.length),
                        output: 'UNION SELECT appends attacker-controlled result set',
                        property: 'payload(sqli): UNION-based extraction modifies query projection',
                        offset: variant.baseOffset + tok.position,
                        confidence: 0.93,
                    }
                }
            }
        }
    }

    const destructive = new Set(['DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER', 'CREATE', 'EXEC', 'EXECUTE', 'TRUNCATE'])
    for (const variant of variants) {
        const meaningful = variant.tokens
        for (let i = 0; i < meaningful.length - 1; i++) {
            const tok = meaningful[i]
            const next = meaningful[i + 1]
            if (tok.type === 'SEPARATOR' && tok.value === ';' && next.type === 'KEYWORD' && destructive.has(next.value)) {
                return {
                    operation: 'payload_inject',
                    input: input.slice(variant.baseOffset + tok.position, variant.baseOffset + next.position + next.value.length),
                    output: `Statement stacking starts a new ${next.value} query`,
                    property: 'payload(sqli): stacked query execution introduces a second SQL statement',
                    offset: variant.baseOffset + tok.position,
                    confidence: 0.92,
                }
            }
        }
    }

    const timeFns = new Set(['SLEEP', 'WAITFOR', 'BENCHMARK', 'PG_SLEEP', 'DELAY'])
    for (const variant of variants) {
        const meaningful = variant.tokens
        for (let i = 0; i < meaningful.length; i++) {
            const tok = meaningful[i]
            const upper = tok.value.toUpperCase()
            if ((tok.type === 'IDENTIFIER' || tok.type === 'KEYWORD') && upper === 'WAITFOR') {
                const next = meaningful[i + 1]
                if (next && (next.type === 'IDENTIFIER' || next.type === 'KEYWORD') && next.value.toUpperCase() === 'DELAY') {
                    return {
                        operation: 'payload_inject',
                        input: input.slice(variant.baseOffset + tok.position, variant.baseOffset + next.position + next.value.length),
                        output: 'WAITFOR DELAY introduces timing side-channel oracle',
                        property: 'payload(sqli): time-delay primitive enables blind extraction',
                        offset: variant.baseOffset + tok.position,
                        confidence: 0.91,
                    }
                }
            }
            if ((tok.type === 'IDENTIFIER' || tok.type === 'KEYWORD') && timeFns.has(upper)) {
                const next = meaningful[i + 1]
                if (next && next.type === 'PAREN_OPEN') {
                    return {
                        operation: 'payload_inject',
                        input: input.slice(variant.baseOffset + tok.position, variant.baseOffset + next.position + 1),
                        output: `${upper}() function call introduces timing oracle`,
                        property: 'payload(sqli): time-based function call modifies execution timing',
                        offset: variant.baseOffset + tok.position,
                        confidence: 0.90,
                    }
                }
            }
        }
    }

    return null
}

function buildTautologyStep(variants: SqlTokenVariant[], tautologies: TautologyDetection[]): ProofStep | null {
    for (const tautology of tautologies) {
        const expressionTokens = sqlTokenize(tautology.expression).filter(t =>
            t.type !== 'WHITESPACE' &&
            t.type !== 'SEPARATOR' &&
            t.type !== 'UNKNOWN',
        )
        if (expressionTokens.length === 0) continue

        for (const variant of variants) {
            const meaningful = variant.tokens
            for (let i = 0; i <= meaningful.length - expressionTokens.length; i++) {
                let matches = true
                for (let j = 0; j < expressionTokens.length; j++) {
                    const source = meaningful[i + j]
                    const exprTok = expressionTokens[j]
                    if (source.type !== exprTok.type || source.value.toUpperCase() !== exprTok.value.toUpperCase()) {
                        matches = false
                        break
                    }
                }
                if (matches) {
                    const first = meaningful[i]
                    return {
                        operation: 'payload_inject',
                        input: tautology.expression,
                        output: `Tautology evaluates to ${String(tautology.value)} by expression evaluation`,
                        property: 'payload(sqli): boolean tautology forces conditional clause to TRUE',
                        offset: variant.baseOffset + first.position,
                        confidence: 0.95,
                    }
                }
            }
        }
    }

    return null
}

function findSqlRepairStep(variants: SqlTokenVariant[]): ProofStep | null {
    for (const variant of variants) {
        const meaningful = variant.tokens
        for (let i = 0; i < meaningful.length; i++) {
            const tok = meaningful[i]
            if (tok.type !== 'SEPARATOR') continue
            if (!(tok.value.startsWith('--') || tok.value.startsWith('#'))) continue

            const hasFollowing = meaningful.slice(i + 1).some(t => t.type !== 'WHITESPACE')
            if (!hasFollowing) {
                return {
                    operation: 'syntax_repair',
                    input: tok.value,
                    output: 'Comment separator truncates trailing host SQL',
                    property: 'repair(sqli): comment repair suppresses remaining application query syntax',
                    offset: variant.baseOffset + tok.position,
                    confidence: 0.86,
                }
            }
        }
    }

    return null
}

const XSS_EXEC_TAGS = new Set(['script', 'svg', 'iframe'])
const XSS_EVENT_ATTR = /^on[a-z0-9_:-]+$/i
const XSS_PROTOCOL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'xlink:href', 'data'])
const CMD_DANGEROUS_COMMANDS = new Set([
    'cat', 'ls', 'id', 'whoami', 'pwd', 'uname', 'hostname',
    'env', 'printenv', 'echo', 'printf', 'touch', 'rm', 'cp',
    'mv', 'mkdir', 'rmdir', 'chmod', 'chown', 'chgrp',
    'curl', 'wget', 'nc', 'ncat', 'nmap', 'netcat', 'socat',
    'telnet', 'ssh', 'scp', 'sftp', 'ftp', 'ping', 'traceroute',
    'dig', 'nslookup', 'host', 'bash', 'sh', 'zsh', 'csh',
    'tcsh', 'ksh', 'fish', 'dash', 'python', 'python2', 'python3',
    'perl', 'ruby', 'php', 'node', 'lua', 'awk', 'sed', 'grep',
    'find', 'xargs', 'ps', 'kill', 'top', 'df', 'du',
    'mount', 'umount', 'crontab', 'at', 'systemctl', 'service',
    'head', 'tail', 'more', 'less', 'sort', 'uniq', 'wc',
    'tee', 'tr', 'cut', 'paste', 'diff', 'sudo', 'su', 'doas',
    'passwd', 'useradd', 'userdel', 'groupadd', 'usermod',
    'gcc', 'g++', 'make', 'tar', 'gzip', 'gunzip', 'zip',
    'unzip', 'cmd', 'powershell', 'certutil', 'bitsadmin',
    'wmic', 'reg', 'net', 'sc', 'schtasks', 'tasklist',
    'taskkill', 'type', 'dir', 'copy', 'del', 'move', 'ipconfig',
])

export function constructXssProof(
    input: string,
    l2Result: DetectionLevelResult | null,
): PropertyProof | null {
    let tokens: readonly Token<HtmlTokenType>[] = []
    try {
        tokens = new HtmlTokenizer().tokenize(input).all()
    } catch {
        return null
    }
    if (tokens.length === 0) return null

    const steps: ProofStep[] = []
    const escapeStep = findXssEscapeStep(input, tokens)
    if (escapeStep) steps.push(escapeStep)

    const payloadStep = findXssPayloadStep(input, tokens)
    if (payloadStep) steps.push(payloadStep)

    const repairStep = findXssRepairStep(input, tokens, payloadStep?.offset ?? -1)
    if (repairStep) steps.push(repairStep)

    if (l2Result?.detected) {
        steps.push({
            operation: 'semantic_eval',
            input: l2Result.evidence ?? input.slice(0, 100),
            output: l2Result.explanation,
            property: l2Result.explanation,
            offset: 0,
            confidence: l2Result.confidence,
        })
    }

    if (steps.length === 0) return null
    steps.sort((a, b) => a.offset - b.offset)
    const { isComplete, proofConfidence } = calculateProofMetrics(steps, l2Result)

    return ensureProofVerificationDefaults({
        property: l2Result?.explanation ?? 'XSS property violation',
        witness: input.length > 200 ? input.slice(0, 200) + '…' : input,
        steps,
        isComplete,
        domain: 'xss',
        impact: 'XSS payload introduces executable browser context',
        proofConfidence,
    })
}

export function constructCmdProof(
    input: string,
    l2Result: DetectionLevelResult | null,
): PropertyProof | null {
    let tokens: readonly Token<ShellTokenType>[] = []
    try {
        tokens = new ShellTokenizer().tokenize(input).all()
    } catch {
        return null
    }
    if (tokens.length === 0) return null

    const steps: ProofStep[] = []
    const escapeStep = findCmdEscapeStep(tokens)
    if (escapeStep) steps.push(escapeStep)

    const payloadStep = findCmdPayloadStep(tokens, input, escapeStep?.offset ?? -1)
    if (payloadStep) steps.push(payloadStep)

    const repairStep = findCmdRepairStep(tokens)
    if (repairStep) steps.push(repairStep)

    if (l2Result?.detected) {
        steps.push({
            operation: 'semantic_eval',
            input: l2Result.evidence ?? input.slice(0, 100),
            output: l2Result.explanation,
            property: l2Result.explanation,
            offset: 0,
            confidence: l2Result.confidence,
        })
    }

    if (steps.length === 0) return null
    steps.sort((a, b) => a.offset - b.offset)
    const { isComplete, proofConfidence } = calculateProofMetrics(steps, l2Result)

    return ensureProofVerificationDefaults({
        property: l2Result?.explanation ?? 'Command-injection property violation',
        witness: input.length > 200 ? input.slice(0, 200) + '…' : input,
        steps,
        isComplete,
        domain: 'cmdi',
        impact: 'Shell metacharacters introduce unintended command execution',
        proofConfidence,
    })
}

function findXssEscapeStep(
    input: string,
    tokens: ReadonlyArray<Token<HtmlTokenType>>,
): ProofStep | null {
    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i]
        if (tok.type !== 'TAG_OPEN') continue
        const prev = findPrevMeaningful(tokens, i)
        if (!prev || prev.type !== 'TEXT') continue
        const quoteIndex = Math.max(prev.value.lastIndexOf('"'), prev.value.lastIndexOf('\''))
        if (quoteIndex < 0) continue

        const quoteOffset = prev.start + quoteIndex
        return {
            operation: 'context_escape',
            input: prev.value[quoteIndex],
            output: 'Quoted HTML context is terminated before a new injected tag opens',
            property: 'escape(xss): attacker closes host HTML boundary before creating a new element',
            offset: quoteOffset,
            confidence: 0.90,
        }
    }

    // Attribute-only context escape: payload starts with quote + on*= in text fragment
    for (const tok of tokens) {
        if (tok.type !== 'TEXT') continue
        const match = /['"]\s*on[a-z0-9_:-]+\s*=/i.exec(tok.value)
        if (!match) continue
        return {
            operation: 'context_escape',
            input: match[0][0],
            output: 'Attribute quote terminates host value before attacker-controlled attribute injection',
            property: 'escape(xss): attribute value boundary is broken to introduce new attributes',
            offset: tok.start + match.index,
            confidence: 0.88,
        }
    }

    return null
}

function findXssPayloadStep(
    input: string,
    tokens: ReadonlyArray<Token<HtmlTokenType>>,
): ProofStep | null {
    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i]
        if (tok.type === 'TAG_NAME' && XSS_EXEC_TAGS.has(tok.value.toLowerCase())) {
            const prev = findPrevMeaningful(tokens, i)
            if (!prev || prev.type !== 'TAG_OPEN') continue
            return {
                operation: 'payload_inject',
                input: input.slice(prev.start, tok.end),
                output: `Script-capable element <${tok.value.toLowerCase()}> is injected`,
                property: 'payload(xss): executable HTML tag introduces JavaScript execution capability',
                offset: prev.start,
                confidence: 0.94,
            }
        }
    }

    for (const tok of tokens) {
        if (tok.type === 'ATTR_NAME' && XSS_EVENT_ATTR.test(tok.value)) {
            return {
                operation: 'payload_inject',
                input: tok.value,
                output: `Event handler ${tok.value} binds JavaScript execution to browser event`,
                property: 'payload(xss): event-handler attribute enables script execution in DOM',
                offset: tok.start,
                confidence: 0.93,
            }
        }
    }

    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i]
        if (tok.type !== 'ATTR_VALUE') continue
        const attrName = findNearestAttrName(tokens, i)?.value.toLowerCase()
        if (!attrName || !XSS_PROTOCOL_ATTRS.has(attrName)) continue
        const normalized = tok.value.trim().toLowerCase()
        if (normalized.startsWith('javascript:')) {
            return {
                operation: 'payload_inject',
                input: tok.value,
                output: `javascript: protocol in ${attrName} causes script execution on navigation`,
                property: 'payload(xss): protocol handler injects executable script URI',
                offset: tok.start,
                confidence: 0.93,
            }
        }
    }

    for (const tok of tokens) {
        if (tok.type !== 'TEXT') continue
        const evtMatch = /\bon[a-z0-9_:-]+\s*=\s*['"]?/i.exec(tok.value)
        if (evtMatch) {
            return {
                operation: 'payload_inject',
                input: evtMatch[0].trim(),
                output: `Event-handler attribute sequence appears in injected HTML fragment`,
                property: 'payload(xss): event handler attribute introduces executable DOM behavior',
                offset: tok.start + evtMatch.index,
                confidence: 0.91,
            }
        }
    }

    return null
}

function findXssRepairStep(
    input: string,
    tokens: ReadonlyArray<Token<HtmlTokenType>>,
    payloadOffset: number,
): ProofStep | null {
    let fallbackTagClose: Token<HtmlTokenType> | null = null

    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i]
        if (tok.type === 'TAG_CLOSE' && tok.start >= payloadOffset && fallbackTagClose === null) {
            fallbackTagClose = tok
        }
        if (tok.type !== 'TAG_END_OPEN') continue

        const nameTok = tokens[i + 1]
        if (!nameTok || nameTok.type !== 'TAG_NAME') continue
        const closeTok = tokens.slice(i + 2).find(t => t.type === 'TAG_CLOSE')
        if (!closeTok) continue

        return {
            operation: 'syntax_repair',
            input: input.slice(tok.start, closeTok.end),
            output: 'Closing tag repairs HTML tree so injected payload parses as valid element',
            property: 'repair(xss): closing markup finalizes attacker-controlled DOM subtree',
            offset: tok.start,
            confidence: 0.88,
        }
    }

    const selfClose = tokens.find(t => t.type === 'TAG_SELF_CLOSE' && t.start >= payloadOffset)
    if (selfClose) {
        return {
            operation: 'syntax_repair',
            input: selfClose.value,
            output: 'Self-closing syntax finalizes injected element',
            property: 'repair(xss): self-closing tag repairs HTML structure after payload injection',
            offset: selfClose.start,
            confidence: 0.86,
        }
    }

    if (fallbackTagClose) {
        return {
            operation: 'syntax_repair',
            input: fallbackTagClose.value,
            output: 'Tag close token completes the injected element',
            property: 'repair(xss): injected element is closed into valid HTML syntax',
            offset: fallbackTagClose.start,
            confidence: 0.84,
        }
    }

    return null
}

function findCmdEscapeStep(tokens: ReadonlyArray<Token<ShellTokenType>>): ProofStep | null {
    for (const tok of tokens) {
        if (
            tok.type === 'SEPARATOR' ||
            tok.type === 'PIPE' ||
            tok.type === 'AND_CHAIN' ||
            tok.type === 'OR_CHAIN' ||
            tok.type === 'NEWLINE' ||
            tok.type === 'CMD_SUBST_OPEN' ||
            tok.type === 'BACKTICK_SUBST'
        ) {
            const escapedContext = tok.type === 'CMD_SUBST_OPEN' || tok.type === 'BACKTICK_SUBST'
                ? 'Command substitution opens a nested shell execution context'
                : `Shell control token ${tok.value} starts a new command boundary`
            return {
                operation: 'context_escape',
                input: tok.value,
                output: escapedContext,
                property: 'escape(cmdi): shell control syntax escapes host command argument context',
                offset: tok.start,
                confidence: 0.90,
            }
        }
    }
    return null
}

function findCmdPayloadStep(
    tokens: ReadonlyArray<Token<ShellTokenType>>,
    input: string,
    escapeOffset: number,
): ProofStep | null {
    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i]
        if (tok.type !== 'CMD_SUBST_OPEN') continue

        const cmdWord = tokens.slice(i + 1).find(t => t.type === 'WORD')
        if (!cmdWord) {
            return {
                operation: 'payload_inject',
                input: tok.value,
                output: '$() command substitution marker introduces executable shell expression',
                property: 'payload(cmdi): command substitution payload executes attacker-controlled command text',
                offset: tok.start,
                confidence: 0.88,
            }
        }

        const isDangerous = CMD_DANGEROUS_COMMANDS.has(cmdWord.value.toLowerCase())
        return {
            operation: 'payload_inject',
            input: cmdWord.value,
            output: `$() substitution executes command ${cmdWord.value}${isDangerous ? ' (known dangerous command)' : ''}`,
            property: 'payload(cmdi): nested command execution executes attacker-provided command token',
            offset: cmdWord.start,
            confidence: isDangerous ? 0.94 : 0.90,
        }
    }

    const backtick = tokens.find(t => t.type === 'BACKTICK_SUBST')
    if (backtick) {
        const inner = backtick.value.slice(1, -1).trim().split(/\s+/)[0] ?? ''
        const isDangerous = CMD_DANGEROUS_COMMANDS.has(inner.toLowerCase())
        return {
            operation: 'payload_inject',
            input: backtick.value,
            output: `Backtick substitution executes embedded command${inner ? ` (${inner})` : ''}${isDangerous ? ' and matches known dangerous command' : ''}`,
            property: 'payload(cmdi): backtick substitution executes attacker-controlled shell command',
            offset: backtick.start,
            confidence: isDangerous ? 0.93 : 0.89,
        }
    }

    const separators = new Set<ShellTokenType>(['SEPARATOR', 'PIPE', 'AND_CHAIN', 'OR_CHAIN', 'NEWLINE'])
    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i]
        if (!separators.has(tok.type)) continue
        const cmdWord = tokens.slice(i + 1).find(t => t.type === 'WORD')
        if (!cmdWord) continue
        const isDangerous = CMD_DANGEROUS_COMMANDS.has(cmdWord.value.toLowerCase())
        return {
            operation: 'payload_inject',
            input: input.slice(cmdWord.start, cmdWord.end),
            output: `Command token ${cmdWord.value} executes after shell boundary break${isDangerous ? ' and is known-dangerous' : ''}`,
            property: 'payload(cmdi): new command token executes after separator-induced command break',
            offset: cmdWord.start,
            confidence: isDangerous ? 0.93 : 0.88,
        }
    }

    const firstWord = tokens.find(t => t.type === 'WORD' && t.start >= escapeOffset)
    if (firstWord) {
        return {
            operation: 'payload_inject',
            input: firstWord.value,
            output: `Shell word ${firstWord.value} appears in executable command position`,
            property: 'payload(cmdi): executable command token is introduced in shell stream',
            offset: firstWord.start,
            confidence: 0.84,
        }
    }

    return null
}

function findCmdRepairStep(tokens: ReadonlyArray<Token<ShellTokenType>>): ProofStep | null {
    const comment = tokens.find(t => t.type === 'COMMENT')
    if (comment) {
        return {
            operation: 'syntax_repair',
            input: comment.value,
            output: 'Shell comment truncates trailing command text',
            property: 'repair(cmdi): comment repair suppresses remaining host command syntax',
            offset: comment.start,
            confidence: 0.86,
        }
    }

    const meaningful = tokens.filter(t => t.type !== 'WHITESPACE')
    const last = meaningful[meaningful.length - 1]
    if (!last) return null
    return {
        operation: 'syntax_repair',
        input: last.value,
        output: 'Injected command terminates naturally at input boundary',
        property: 'repair(cmdi): natural command termination leaves payload parseable by shell',
        offset: last.start,
        confidence: 0.82,
    }
}

function findPrevMeaningful<T extends string>(
    tokens: ReadonlyArray<Token<T>>,
    index: number,
): Token<T> | null {
    for (let i = index - 1; i >= 0; i--) {
        if (tokens[i].type !== ('WHITESPACE' as T)) return tokens[i]
    }
    return null
}

function findNearestAttrName(
    tokens: ReadonlyArray<Token<HtmlTokenType>>,
    index: number,
): Token<HtmlTokenType> | null {
    for (let i = index - 1; i >= 0; i--) {
        const tok = tokens[i]
        if (tok.type === 'ATTR_NAME') return tok
        if (tok.type === 'TAG_OPEN' || tok.type === 'TAG_END_OPEN') break
    }
    return null
}

function calculateProofMetrics(
    steps: ProofStep[],
    l2Result: DetectionLevelResult | null,
): { isComplete: boolean; proofConfidence: number } {
    const hasEscape = steps.some(s => s.operation === 'context_escape')
    const hasPayload = steps.some(s => s.operation === 'payload_inject')
    const hasRepair = steps.some(s => s.operation === 'syntax_repair')
    const isComplete = hasEscape && hasPayload && hasRepair

    // Proof confidence: derived from structural completeness and step count
    // 1 step = 0.60, 2 steps = 0.80, 3+ steps = 0.90, complete algebra = 0.95
    // L2 semantic verification adds +0.04 when the L2 result doesn't already
    // carry structured evidence (which encodes the same phase detail explicitly).
    const stepConfidence = Math.min(0.90, 0.40 + steps.filter(s => s.operation !== 'semantic_eval').length * 0.20)
    const completenessBonus = isComplete ? 0.05 : 0
    const semanticBonus = l2Result?.detected && !l2Result?.structuredEvidence?.length ? 0.04 : 0
    const proofConfidence = Math.min(0.99, stepConfidence + completenessBonus + semanticBonus)

    return { isComplete, proofConfidence }
}

/**
 * Construct a minimal proof from L2 evidence alone.
 * Used for domains without dedicated structural patterns.
 */
function constructMinimalProof(
    module: InvariantClassModule,
    input: string,
    l2Result: DetectionLevelResult,
): PropertyProof {
    const steps: ProofStep[] = [{
        operation: 'semantic_eval',
        input: l2Result.evidence ?? input.slice(0, 100),
        output: l2Result.explanation,
        property: module.formalProperty ?? module.description,
        offset: 0,
        confidence: l2Result.confidence,
    }]

    return ensureProofVerificationDefaults({
        property: module.formalProperty ?? module.description,
        witness: input.length > 200 ? input.slice(0, 200) + '…' : input,
        steps,
        isComplete: false,
        domain: String(module.category),
        impact: module.description,
        proofConfidence: l2Result.confidence * 0.85,
    })
}


// ── Path Traversal Proof Constructor ────────────────────────────
//
// Uses PathTokenizer to structurally identify:
//   Phase 1 (escape): TRAVERSAL tokens (../) escaping directory boundary
//   Phase 2 (payload): SENSITIVE_TARGET tokens targeting system files
//   Phase 3 (repair): NULL_BYTE tokens for extension bypass

export function constructPathProof(
    input: string,
    l2Result: DetectionLevelResult | null,
): PropertyProof | null {
    const tokenizer = new PathTokenizer()
    let tokens: readonly Token<PathTokenType>[]
    try {
        tokens = tokenizer.tokenize(input).all()
    } catch {
        return null
    }

    if (tokens.length === 0) return null

    const steps: ProofStep[] = []

    // Phase 1: Context Escape — directory traversal sequences
    const traversalTokens = tokens.filter(t => t.type === 'TRAVERSAL')
    if (traversalTokens.length > 0) {
        const firstTraversal = traversalTokens[0]
        const traversalCount = traversalTokens.length
        const traversalChain = traversalTokens.map(t => t.value).join('/')
        steps.push({
            operation: 'context_escape',
            input: traversalChain,
            output: `${traversalCount} traversal sequence(s) escape directory boundary`,
            property: `escape(path): ${traversalCount}x directory traversal escapes webroot`,
            offset: firstTraversal.start,
            confidence: Math.min(0.99, 0.80 + traversalCount * 0.05),
            verified: true,
            verificationMethod: 'tokenizer_structural',
        })
    }

    // Check for encoding layers (multi-encoding evasion)
    const encodingTokens = tokens.filter(t => t.type === 'ENCODING_LAYER')
    if (encodingTokens.length > 0) {
        const first = encodingTokens[0]
        steps.push({
            operation: 'encoding_decode',
            input: first.value,
            output: 'Multi-layer encoding detected — path characters are double/triple encoded',
            property: 'escape(path): Encoding layers bypass WAF/filter normalization',
            offset: first.start,
            confidence: 0.92,
            verified: true,
            verificationMethod: 'tokenizer_decode',
        })
    }

    // Phase 2: Payload — sensitive file target
    const sensitiveTokens = tokens.filter(t => t.type === 'SENSITIVE_TARGET')
    if (sensitiveTokens.length > 0) {
        const target = sensitiveTokens[0]
        steps.push({
            operation: 'payload_inject',
            input: target.value,
            output: `Targets sensitive system file: ${target.value}`,
            property: 'payload(path): Request targets file outside allowed directory scope',
            offset: target.start,
            confidence: 0.95,
            verified: true,
            verificationMethod: 'sensitive_path_match',
        })
    }

    // Phase 3: Repair — null byte injection for extension bypass
    const nullTokens = tokens.filter(t => t.type === 'NULL_BYTE')
    if (nullTokens.length > 0) {
        const nullByte = nullTokens[0]
        steps.push({
            operation: 'syntax_repair',
            input: nullByte.value,
            output: 'Null byte truncates file extension validation',
            property: 'repair(path): Null byte injection bypasses file type check',
            offset: nullByte.start,
            confidence: 0.93,
            verified: true,
            verificationMethod: 'null_byte_detection',
        })
    }

    // Path parameter injection (Tomcat ;jsessionid)
    const paramTokens = tokens.filter(t => t.type === 'PARAM_INJECTION')
    if (paramTokens.length > 0) {
        const param = paramTokens[0]
        steps.push({
            operation: 'context_escape',
            input: param.value,
            output: 'Semicolon path parameter injection bypasses path-based authorization',
            property: 'escape(path): Path parameter injection circumvents access control',
            offset: param.start,
            confidence: 0.88,
            verified: true,
            verificationMethod: 'tokenizer_structural',
        })
    }

    // L2 semantic evidence
    if (l2Result?.detected) {
        steps.push({
            operation: 'semantic_eval',
            input: l2Result.evidence ?? input.slice(0, 100),
            output: l2Result.explanation,
            property: l2Result.explanation,
            offset: 0,
            confidence: l2Result.confidence,
        })
    }

    if (steps.length === 0) return null
    steps.sort((a, b) => a.offset - b.offset)

    const { isComplete, proofConfidence } = calculateProofMetrics(steps, l2Result)
    return ensureProofVerificationDefaults({
        property: 'Path traversal violates directory confinement invariant',
        witness: input.length > 200 ? input.slice(0, 200) + '…' : input,
        steps,
        isComplete,
        domain: 'path_traversal',
        impact: 'Directory traversal allows reading arbitrary files from the server filesystem',
        proofConfidence,
    })
}


// ── SSRF Proof Constructor ──────────────────────────────────────
//
// Uses UrlTokenizer to structurally identify:
//   Phase 1 (escape): SCHEME token initiates server-side request
//   Phase 2 (payload): HOST_INTERNAL/HOST_METADATA/HOST_OBFUSCATED targets internal network
//   Phase 3 (repair): PATH_SEGMENT completes valid request to metadata/sensitive endpoint

export function constructSsrfProof(
    input: string,
    l2Result: DetectionLevelResult | null,
): PropertyProof | null {
    const tokenizer = new UrlTokenizer()
    let tokens: readonly Token<UrlTokenType>[]
    try {
        tokens = tokenizer.tokenize(input).all()
    } catch {
        return null
    }

    if (tokens.length === 0) return null

    const steps: ProofStep[] = []

    // Phase 1: Context Escape — URL scheme initiates request
    const schemeTokens = tokens.filter(t => t.type === 'SCHEME')
    if (schemeTokens.length > 0) {
        const scheme = schemeTokens[0]
        const schemeName = scheme.value.replace(/:$/, '').toLowerCase()
        const dangerousSchemes = new Set(['gopher', 'file', 'dict', 'ftp', 'ldap', 'tftp'])
        const confidence = dangerousSchemes.has(schemeName) ? 0.95 : 0.85
        steps.push({
            operation: 'context_escape',
            input: scheme.value,
            output: `URL scheme "${schemeName}" initiates server-side request`,
            property: `escape(ssrf): ${schemeName}:// scheme triggers outbound request from server`,
            offset: scheme.start,
            confidence,
            verified: true,
            verificationMethod: 'scheme_parse',
        })
    }

    // Phase 2: Payload — internal/metadata host target
    const internalTokens = tokens.filter(t => t.type === 'HOST_INTERNAL')
    const metadataTokens = tokens.filter(t => t.type === 'HOST_METADATA')
    const obfuscatedTokens = tokens.filter(t => t.type === 'HOST_OBFUSCATED')

    if (metadataTokens.length > 0) {
        const meta = metadataTokens[0]
        steps.push({
            operation: 'payload_inject',
            input: meta.value,
            output: `Cloud metadata endpoint: ${meta.value} — exposes IAM credentials and instance identity`,
            property: 'payload(ssrf): Request targets cloud metadata service (credential theft)',
            offset: meta.start,
            confidence: 0.98,
            verified: true,
            verificationMethod: 'metadata_host_match',
        })
    } else if (internalTokens.length > 0) {
        const internal = internalTokens[0]
        steps.push({
            operation: 'payload_inject',
            input: internal.value,
            output: `Internal network host: ${internal.value} — not accessible from external clients`,
            property: 'payload(ssrf): Request targets internal network bypassing firewall boundary',
            offset: internal.start,
            confidence: 0.94,
            verified: true,
            verificationMethod: 'private_ip_match',
        })
    } else if (obfuscatedTokens.length > 0) {
        const obfuscated = obfuscatedTokens[0]
        steps.push({
            operation: 'payload_inject',
            input: obfuscated.value,
            output: `Obfuscated IP address: ${obfuscated.value} — encoding hides internal network target`,
            property: 'payload(ssrf): IP obfuscation (hex/octal/decimal) bypasses SSRF filter',
            offset: obfuscated.start,
            confidence: 0.96,
            verified: true,
            verificationMethod: 'ip_obfuscation_decode',
        })
    }

    // Check for userinfo (credential in URL for auth bypass)
    const userinfoTokens = tokens.filter(t => t.type === 'USERINFO')
    if (userinfoTokens.length > 0) {
        const userinfo = userinfoTokens[0]
        steps.push({
            operation: 'context_escape',
            input: userinfo.value,
            output: 'URL userinfo field may bypass host validation via @-based URL confusion',
            property: 'escape(ssrf): Userinfo@host confusion tricks URL parsers',
            offset: userinfo.start,
            confidence: 0.88,
            verified: true,
            verificationMethod: 'userinfo_parse',
        })
    }

    // Phase 3: Repair — path completes the request to a sensitive endpoint
    const pathTokens = tokens.filter(t => t.type === 'PATH_SEGMENT')
    if (pathTokens.length > 0) {
        const sensitiveApiPaths = [
            '/latest/meta-data', '/latest/api/token', '/metadata/instance',
            '/computeMetadata', '/openstack', '/hetzner',
        ]
        const fullPath = pathTokens.map(t => t.value).join('')
        const isSensitivePath = sensitiveApiPaths.some(p => fullPath.includes(p))
        if (isSensitivePath) {
            steps.push({
                operation: 'syntax_repair',
                input: fullPath,
                output: 'Request path targets sensitive metadata API endpoint',
                property: 'repair(ssrf): Path completes credential-exfiltration request',
                offset: pathTokens[0].start,
                confidence: 0.95,
                verified: true,
                verificationMethod: 'sensitive_path_match',
            })
        } else if (pathTokens.length > 0) {
            steps.push({
                operation: 'syntax_repair',
                input: pathTokens[0].value,
                output: 'Path segment completes valid HTTP request',
                property: 'repair(ssrf): URL path produces valid server-side request',
                offset: pathTokens[0].start,
                confidence: 0.80,
            })
        }
    }

    // L2 semantic evidence
    if (l2Result?.detected) {
        steps.push({
            operation: 'semantic_eval',
            input: l2Result.evidence ?? input.slice(0, 100),
            output: l2Result.explanation,
            property: l2Result.explanation,
            offset: 0,
            confidence: l2Result.confidence,
        })
    }

    if (steps.length === 0) return null
    steps.sort((a, b) => a.offset - b.offset)

    const { isComplete, proofConfidence } = calculateProofMetrics(steps, l2Result)
    return ensureProofVerificationDefaults({
        property: 'SSRF violates network boundary confinement invariant',
        witness: input.length > 200 ? input.slice(0, 200) + '…' : input,
        steps,
        isComplete,
        domain: 'ssrf',
        impact: 'Server-side request forgery allows accessing internal services and cloud metadata',
        proofConfidence,
    })
}

// ── XXE Proof Constructor ───────────────────────────────────────
//
// Structural extraction of DTD/entity components:
//   DOCTYPE_DECLARATION -> ENTITY_DEFINITION -> EXTERNAL_REFERENCE -> ENTITY_USAGE

export function constructXxeProof(
    input: string,
    l2Result: DetectionLevelResult | null,
): PropertyProof | null {
    const steps: ProofStep[] = []

    const doctypeMatch = /<!DOCTYPE\b[^>]*?(?:\[[\s\S]*?\])?>/i.exec(input)
    if (doctypeMatch) {
        steps.push({
            operation: 'context_escape',
            input: doctypeMatch[0],
            output: 'DOCTYPE_DECLARATION: XML DTD context is declared and parsed',
            property: 'escape(xxe): DOCTYPE declaration enables attacker-controlled DTD definitions',
            offset: doctypeMatch.index,
            confidence: 0.90,
            verified: true,
            verificationMethod: 'doctype_parse',
        })
    }

    const entityPattern = /<!ENTITY\s+(?:%\s+)?([a-zA-Z_][\w.-]*)\s+(SYSTEM|PUBLIC)\s+['"]([^'"]+)['"][^>]*>/gi
    const entityDecls = [...input.matchAll(entityPattern)]
    if (entityDecls.length > 0) {
        const first = entityDecls[0]
        steps.push({
            operation: 'payload_inject',
            input: first[0],
            output: `ENTITY_DEFINITION: External entity "${first[1]}" declared via ${first[2].toUpperCase()}`,
            property: 'payload(xxe): ENTITY definition introduces externally-resolved XML resource',
            offset: first.index ?? 0,
            confidence: Math.min(0.99, 0.90 + entityDecls.length * 0.02),
            verified: true,
            verificationMethod: 'entity_reference_check',
        })
    }

    const externalRefPattern = /\b(?:SYSTEM|PUBLIC)\b\s+['"]((?:file|https?|ftp|gopher|expect|php):\/\/[^'"]+)['"]/i
    const externalRef = externalRefPattern.exec(input)
    if (externalRef) {
        steps.push({
            operation: 'payload_inject',
            input: externalRef[1],
            output: `EXTERNAL_REFERENCE: External protocol target "${externalRef[1]}" is resolvable by XML parser`,
            property: 'payload(xxe): External URI resolution crosses document trust boundary',
            offset: (externalRef.index ?? 0) + externalRef[0].indexOf(externalRef[1]),
            confidence: externalRef[1].toLowerCase().startsWith('file://') ? 0.98 : 0.94,
            verified: true,
            verificationMethod: 'protocol_analysis',
        })
    }

    const declaredNames = entityDecls.map(m => m[1]).filter(Boolean)
    const usagePattern = /&([a-zA-Z_][\w.-]*);/g
    let usageMatch: RegExpExecArray | null = null
    while ((usageMatch = usagePattern.exec(input)) !== null) {
        if (declaredNames.length === 0 || declaredNames.includes(usageMatch[1])) break
    }
    if (usageMatch) {
        steps.push({
            operation: 'syntax_repair',
            input: usageMatch[0],
            output: `ENTITY_USAGE: Entity reference ${usageMatch[0]} triggers expansion during XML parse`,
            property: 'repair(xxe): Entity usage completes external-entity expansion path',
            offset: usageMatch.index,
            confidence: declaredNames.includes(usageMatch[1]) ? 0.95 : 0.82,
            verified: true,
            verificationMethod: 'entity_reference_check',
        })
    }

    if (l2Result?.detected) {
        steps.push({
            operation: 'semantic_eval',
            input: l2Result.evidence ?? input.slice(0, 100),
            output: l2Result.explanation,
            property: l2Result.explanation,
            offset: 0,
            confidence: l2Result.confidence,
        })
    }

    if (steps.length === 0) return null
    steps.sort((a, b) => a.offset - b.offset)

    const { isComplete, proofConfidence } = calculateProofMetrics(steps, l2Result)
    return ensureProofVerificationDefaults({
        property: 'XXE violates XML entity confinement invariant',
        witness: input.length > 200 ? input.slice(0, 200) + '…' : input,
        steps,
        isComplete,
        domain: 'xxe',
        impact: 'External entity resolution enables local file read, SSRF, and parser-side resource access',
        proofConfidence,
    })
}

// ── SSTI Proof Constructor ──────────────────────────────────────
//
// Uses TemplateTokenizer to identify:
//   TEMPLATE_DELIMITER -> EXPRESSION_INJECT -> OBJECT_TRAVERSAL -> CODE_EXECUTION

export function constructSstiProof(
    input: string,
    l2Result: DetectionLevelResult | null,
): PropertyProof | null {
    let tokens: readonly Token<TemplateTokenType>[]
    try {
        tokens = new TemplateTokenizer().tokenize(input).all()
    } catch {
        return null
    }

    if (tokens.length === 0) return null
    const steps: ProofStep[] = []

    const openers = tokens.filter(t => t.type === 'EXPR_OPEN' || t.type === 'STMT_OPEN')
    if (openers.length > 0) {
        const first = openers[0]
        steps.push({
            operation: 'context_escape',
            input: first.value,
            output: `TEMPLATE_DELIMITER: ${openers.length} template expression delimiter(s) open evaluation context`,
            property: 'escape(ssti): Template delimiter escapes literal rendering into expression evaluation',
            offset: first.start,
            confidence: Math.min(0.97, 0.84 + openers.length * 0.03),
            verified: true,
            verificationMethod: 'delimiter_match',
        })
    }

    const expressionPattern = /(?:\{\{|\$\{|#\{|<%=|<%|{%)([\s\S]*?)(?:\}\}|%>|}|%})/g
    const expressions = [...input.matchAll(expressionPattern)]
    if (expressions.length > 0) {
        const first = expressions[0]
        const expression = first[1].trim()
        steps.push({
            operation: 'payload_inject',
            input: expression.slice(0, 120),
            output: `EXPRESSION_INJECT: Template expression "${expression.slice(0, 60)}${expression.length > 60 ? '…' : ''}" is parsed for evaluation`,
            property: 'payload(ssti): Injected expression content enters template evaluation pipeline',
            offset: (first.index ?? 0) + first[0].indexOf(first[1]),
            confidence: 0.90,
            verified: true,
            verificationMethod: 'expression_parse',
        })
    }

    const traversalPattern = /(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|constructor\s*\.\s*constructor|getClass|getRuntime|forName|ProcessBuilder)/i
    const traversalMatch = traversalPattern.exec(input)
    if (traversalMatch) {
        steps.push({
            operation: 'payload_inject',
            input: traversalMatch[0],
            output: `OBJECT_TRAVERSAL: Dangerous object traversal token "${traversalMatch[0]}" reaches privileged runtime objects`,
            property: 'payload(ssti): Object graph traversal accesses execution-capable internals',
            offset: traversalMatch.index,
            confidence: 0.96,
            verified: true,
            verificationMethod: 'traversal_chain_analysis',
        })
    }

    const execPattern = /(?:\bexec\s*\(|\beval\s*\(|\bsystem\s*\(|\bpopen\s*\(|__import__\s*\(|Runtime\s*\.\s*getRuntime\s*\(\)\s*\.\s*exec\s*\()/i
    const execMatch = execPattern.exec(input)
    if (execMatch) {
        steps.push({
            operation: 'syntax_repair',
            input: execMatch[0],
            output: `CODE_EXECUTION: Expression contains execution primitive "${execMatch[0]}"`,
            property: 'repair(ssti): Parsed expression resolves to runtime code execution primitive',
            offset: execMatch.index,
            confidence: 0.97,
            verified: true,
            verificationMethod: 'execution_detection',
        })
    }

    if (l2Result?.detected) {
        steps.push({
            operation: 'semantic_eval',
            input: l2Result.evidence ?? input.slice(0, 100),
            output: l2Result.explanation,
            property: l2Result.explanation,
            offset: 0,
            confidence: l2Result.confidence,
        })
    }

    if (steps.length === 0) return null
    steps.sort((a, b) => a.offset - b.offset)

    const { isComplete, proofConfidence } = calculateProofMetrics(steps, l2Result)
    return ensureProofVerificationDefaults({
        property: 'SSTI violates template evaluation confinement invariant',
        witness: input.length > 200 ? input.slice(0, 200) + '…' : input,
        steps,
        isComplete,
        domain: 'ssti',
        impact: 'Server-side template expression injection enables object traversal and code execution',
        proofConfidence,
    })
}
