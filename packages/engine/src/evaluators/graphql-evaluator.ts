/**
 * GraphQL Abuse Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for GraphQL abuse is:
 *   ∃ query ∈ parse(input, GRAPHQL_GRAMMAR) :
 *     query.depth > DEPTH_THRESHOLD
 *     ∨ query.contains("__schema") ∨ query.contains("__type")
 *     ∨ query.is_batch ∧ query.batch_size > BATCH_THRESHOLD
 *     → attacker enumerates schema or causes resource exhaustion
 *
 * Unlike regex matching __schema, this evaluator:
 *   1. Measures actual query depth via brace counting
 *   2. Detects batch query arrays with operation counting
 *   3. Identifies field alias abuse for brute force
 *   4. Recognizes fragment-based depth amplification
 *   5. Extracts introspection field targets
 *
 * Covers:
 *   - graphql_introspection: schema enumeration queries
 *   - graphql_batch_abuse:   batch/depth/alias resource exhaustion
 */


// ── Result Type ──────────────────────────────────────────────────

export interface GraphQLDetection {
    type: 'introspection' | 'depth_abuse' | 'batch_abuse' | 'alias_abuse' | 'fragment_abuse'
    detail: string
    depth: number
    confidence: number
}


// ── Introspection Field Detection ────────────────────────────────

const INTROSPECTION_FIELDS = new Set([
    '__schema', '__type', '__inputvalue',
    '__field', '__enumvalue', '__directive',
])

function detectIntrospection(input: string): GraphQLDetection[] {
    const detections: GraphQLDetection[] = []
    const lower = input.toLowerCase()

    // Find introspection fields used
    // Use word-boundary matching to prevent __type matching __typename
    const fields: string[] = []
    for (const field of INTROSPECTION_FIELDS) {
        const pattern = new RegExp(`\\b${field}\\b`)
        if (pattern.test(lower)) {
            fields.push(field)
        }
    }

    if (fields.length === 0) return detections

    // Check for full introspection query patterns
    const isFullIntrospection = lower.includes('__schema') && (
        lower.includes('types') || lower.includes('querytype') ||
        lower.includes('mutationtype') || lower.includes('subscriptiontype')
    )

    const isTypeEnumeration = lower.includes('__type') && (
        lower.includes('fields') || lower.includes('inputfields') ||
        lower.includes('enumvalues') || lower.includes('interfaces')
    )

    detections.push({
        type: 'introspection',
        detail: `GraphQL introspection: ${fields.join(', ')}${isFullIntrospection ? ' (FULL SCHEMA DUMP)' : ''}${isTypeEnumeration ? ' (TYPE ENUMERATION)' : ''}`,
        depth: 0,
        confidence: isFullIntrospection ? 0.96 : isTypeEnumeration ? 0.92 : 0.85,
    })

    return detections
}


// ── Query Depth Analysis ─────────────────────────────────────────

function measureQueryDepth(input: string): number {
    let maxDepth = 0
    let currentDepth = 0

    for (const char of input) {
        if (char === '{') {
            currentDepth++
            maxDepth = Math.max(maxDepth, currentDepth)
        } else if (char === '}') {
            currentDepth--
        }
    }

    return maxDepth
}

function detectDepthAbuse(input: string): GraphQLDetection[] {
    const detections: GraphQLDetection[] = []

    const depth = measureQueryDepth(input)

    if (depth > 10) {
        detections.push({
            type: 'depth_abuse',
            detail: `GraphQL query depth: ${depth} levels (threshold: 10) — resource exhaustion risk`,
            depth,
            confidence: depth > 20 ? 0.96 : depth > 15 ? 0.92 : 0.85,
        })
    }

    return detections
}


// ── Batch Query Detection ────────────────────────────────────────

function detectBatchAbuse(input: string): GraphQLDetection[] {
    const detections: GraphQLDetection[] = []

    // JSON array of queries
    const trimmed = input.trim()
    if (trimmed.startsWith('[')) {
        try {
            const parsed = JSON.parse(trimmed)
            if (Array.isArray(parsed)) {
                const queryCount = parsed.length
                if (queryCount > 5) {
                    detections.push({
                        type: 'batch_abuse',
                        detail: `GraphQL batch: ${queryCount} queries in single request — brute force / enumeration risk`,
                        depth: 0,
                        confidence: queryCount > 50 ? 0.96 : queryCount > 20 ? 0.92 : 0.85,
                    })
                }
            }
        } catch { /* not valid JSON array */ }
    }

    return detections
}


// ── Alias Abuse Detection ────────────────────────────────────────
//
// Alias abuse: using aliases to repeat the same query many times
//   { a1:user(id:1){name} a2:user(id:2){name} ... a100:user(id:100){name} }
// This bypasses rate limiting since it's a single HTTP request.

function detectAliasAbuse(input: string): GraphQLDetection[] {
    const detections: GraphQLDetection[] = []

    // Count unique aliases (word followed by colon at top query level)
    const aliasPattern = /\b([a-zA-Z_]\w*)\s*:/g
    const aliases = new Set<string>()
    let match: RegExpExecArray | null
    while ((match = aliasPattern.exec(input)) !== null) {
        // Exclude known GraphQL keywords
        const name = match[1].toLowerCase()
        if (name !== 'query' && name !== 'mutation' && name !== 'subscription' &&
            name !== 'fragment' && name !== 'on' && name !== 'type' && name !== 'name') {
            aliases.add(match[1])
        }
    }

    if (aliases.size > 10) {
        detections.push({
            type: 'alias_abuse',
            detail: `GraphQL alias abuse: ${aliases.size} unique aliases — rate limit bypass / brute force`,
            depth: 0,
            confidence: aliases.size > 50 ? 0.96 : aliases.size > 25 ? 0.92 : 0.85,
        })
    }

    return detections
}


// ── Fragment Abuse Detection ─────────────────────────────────────
//
// Fragment spreading can amplify query depth/breadth:
//   fragment A on User { friends { ...B } }
//   fragment B on User { friends { ...A } }  ← circular!

function detectFragmentAbuse(input: string): GraphQLDetection[] {
    const detections: GraphQLDetection[] = []

    // Count fragments and fragment spreads
    const fragmentDefs = (input.match(/\bfragment\s+\w+\s+on\s+/g) || []).length
    const fragmentSpreads = (input.match(/\.\.\.\s*\w+/g) || []).length

    if (fragmentDefs >= 3 && fragmentSpreads > fragmentDefs) {
        detections.push({
            type: 'fragment_abuse',
            detail: `GraphQL fragment explosion: ${fragmentDefs} definitions, ${fragmentSpreads} spreads — depth amplification`,
            depth: 0,
            confidence: 0.88,
        })
    }

    return detections
}


// ── Public API ───────────────────────────────────────────────────

export function detectGraphQLAbuse(input: string): GraphQLDetection[] {
    const detections: GraphQLDetection[] = []

    if (input.length < 5) return detections

    // Quick bail: must contain GraphQL-like structures
    const lower = input.toLowerCase()
    if (!lower.includes('{') && !lower.includes('query') &&
        !lower.includes('mutation') && !lower.includes('[')) {
        return detections
    }

    try { detections.push(...detectIntrospection(input)) } catch { /* safe */ }
    try { detections.push(...detectDepthAbuse(input)) } catch { /* safe */ }
    try { detections.push(...detectBatchAbuse(input)) } catch { /* safe */ }
    try { detections.push(...detectAliasAbuse(input)) } catch { /* safe */ }
    try { detections.push(...detectFragmentAbuse(input)) } catch { /* safe */ }

    return detections
}
