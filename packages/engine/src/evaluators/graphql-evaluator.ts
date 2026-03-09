/**
 * GraphQL Abuse Evaluator — structural L2 analysis.
 */

export interface GraphQLDetection {
    type: 'introspection' | 'depth_abuse' | 'batch_abuse' | 'alias_abuse' | 'fragment_abuse'
    detail: string
    depth: number
    confidence: number
    l1: boolean
    l2: boolean
    evidence: string
}

const INTROSPECTION_FIELDS = ['__schema', '__type', '__inputvalue', '__field', '__enumvalue', '__directive']
const GRAPHQL_KEYWORDS = ['query', 'mutation', 'subscription', 'fragment', 'on']

function stripQuotedAndComments(input: string): string {
    let out = ''
    let i = 0
    let inSingle = false
    let inDouble = false
    let inBlock = false

    while (i < input.length) {
        const ch = input[i]
        const next = input[i + 1]
        if (!inSingle && !inDouble && !inBlock && ch === '#' ) {
            while (i < input.length && input[i] !== '\n') i++
            continue
        }
        if (!inSingle && !inDouble && ch === '"' && next === '"' && input[i + 2] === '"') {
            inBlock = !inBlock
            i += 3
            continue
        }
        if (!inDouble && !inBlock && ch === "'" && input[i - 1] !== '\\') {
            inSingle = !inSingle
            i++
            continue
        }
        if (!inSingle && !inBlock && ch === '"' && input[i - 1] !== '\\') {
            inDouble = !inDouble
            i++
            continue
        }
        if (!inSingle && !inDouble && !inBlock) out += ch
        i++
    }
    return out
}

function maxDepth(structural: string): number {
    let depth = 0
    let max = 0
    for (const ch of structural) {
        if (ch === '{') {
            depth++
            if (depth > max) max = depth
        } else if (ch === '}') {
            depth = Math.max(0, depth - 1)
        }
    }
    return max
}

function detectIntrospection(structural: string): GraphQLDetection[] {
    const lower = structural.toLowerCase()
    const used = INTROSPECTION_FIELDS.filter(field => new RegExp(`\\b${field}\\b`).test(lower))
    if (used.length === 0) return []

    const fullSchema = lower.includes('__schema') && /(types|querytype|mutationtype|subscriptiontype)/.test(lower)
    return [{
        type: 'introspection',
        detail: `GraphQL introspection fields used: ${used.join(', ')}`,
        depth: 0,
        confidence: fullSchema ? 0.96 : 0.88,
        l1: false,
        l2: true,
        evidence: used.join(','),
    }]
}

function detectDepthAbuse(structural: string): GraphQLDetection[] {
    const depth = maxDepth(structural)
    if (depth <= 10) return []
    return [{
        type: 'depth_abuse',
        detail: `GraphQL depth ${depth} exceeds threshold 10`,
        depth,
        confidence: depth > 20 ? 0.96 : depth > 15 ? 0.92 : 0.86,
        l1: false,
        l2: true,
        evidence: `depth=${depth}`,
    }]
}

function detectBatchAbuse(input: string): GraphQLDetection[] {
    const trimmed = input.trim()
    if (!trimmed.startsWith('[')) return []
    try {
        const parsed = JSON.parse(trimmed)
        if (!Array.isArray(parsed)) return []
        const queryItems = parsed.filter(item =>
            typeof item === 'object' && item !== null &&
            ('query' in (item as Record<string, unknown>) || 'operationName' in (item as Record<string, unknown>)),
        ).length
        if (queryItems <= 5) return []
        return [{
            type: 'batch_abuse',
            detail: `GraphQL batched request with ${queryItems} operations`,
            depth: 0,
            confidence: queryItems > 25 ? 0.95 : 0.88,
            l1: false,
            l2: true,
            evidence: `batch_count=${queryItems}`,
        }]
    } catch {
        return []
    }
}

function detectAliasAbuse(structural: string): GraphQLDetection[] {
    const aliases = new Set<string>()
    const aliasPattern = /\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:\(|\{)/g
    let match: RegExpExecArray | null
    while ((match = aliasPattern.exec(structural)) !== null) {
        const alias = match[1].toLowerCase()
        if (!GRAPHQL_KEYWORDS.includes(alias)) aliases.add(alias)
    }
    if (aliases.size <= 10) return []
    return [{
        type: 'alias_abuse',
        detail: `GraphQL alias fan-out detected (${aliases.size} unique aliases)`,
        depth: 0,
        confidence: aliases.size > 30 ? 0.95 : 0.87,
        l1: false,
        l2: true,
        evidence: `alias_count=${aliases.size}`,
    }]
}

function extractFragmentBodies(structural: string): Map<string, string> {
    const fragments = new Map<string, string>()
    const startPattern = /\bfragment\s+([A-Za-z_][A-Za-z0-9_]*)\s+on\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/g
    let match: RegExpExecArray | null
    while ((match = startPattern.exec(structural)) !== null) {
        const name = match[1]
        let i = startPattern.lastIndex
        let depth = 1
        while (i < structural.length && depth > 0) {
            if (structural[i] === '{') depth++
            if (structural[i] === '}') depth--
            i++
        }
        const body = structural.slice(startPattern.lastIndex, i - 1)
        fragments.set(name, body)
        startPattern.lastIndex = i
    }
    return fragments
}

function hasFragmentCycle(edges: Map<string, Set<string>>): string[] | null {
    const visiting = new Set<string>()
    const visited = new Set<string>()
    const trail: string[] = []

    const dfs = (node: string): string[] | null => {
        if (visiting.has(node)) {
            const cycleStart = trail.indexOf(node)
            return cycleStart >= 0 ? trail.slice(cycleStart).concat(node) : [node, node]
        }
        if (visited.has(node)) return null
        visiting.add(node)
        trail.push(node)
        for (const next of edges.get(node) ?? []) {
            const cycle = dfs(next)
            if (cycle) return cycle
        }
        trail.pop()
        visiting.delete(node)
        visited.add(node)
        return null
    }

    for (const node of edges.keys()) {
        const cycle = dfs(node)
        if (cycle) return cycle
    }
    return null
}

function detectFragmentAbuse(structural: string): GraphQLDetection[] {
    const fragments = extractFragmentBodies(structural)
    if (fragments.size === 0) return []

    const edges = new Map<string, Set<string>>()
    let spreadCount = 0
    for (const [name, body] of fragments) {
        const refs = new Set<string>()
        const spreadPattern = /\.\.\.\s*([A-Za-z_][A-Za-z0-9_]*)/g
        let match: RegExpExecArray | null
        while ((match = spreadPattern.exec(body)) !== null) {
            refs.add(match[1])
            spreadCount++
        }
        edges.set(name, refs)
    }

    // Count total spreads across the entire query (including query body, not just fragment bodies)
    const totalSpreads = (structural.match(/\.\.\.\s*[A-Za-z_][A-Za-z0-9_]*/g) ?? []).length

    const cycle = hasFragmentCycle(edges)
    if (cycle) {
        return [{
            type: 'fragment_abuse',
            detail: `Circular fragment references detected: ${cycle.join(' -> ')}`,
            depth: 0,
            confidence: 0.94,
            l1: false,
            l2: true,
            evidence: cycle.join('->'),
        }]
    }

    if (fragments.size >= 4 && totalSpreads >= fragments.size * 2) {
        return [{
            type: 'fragment_abuse',
            detail: `Fragment spread amplification detected (${fragments.size} fragments, ${spreadCount} spreads)`,
            depth: 0,
            confidence: 0.86,
            l1: false,
            l2: true,
            evidence: `fragments=${fragments.size},spreads=${spreadCount}`,
        }]
    }

    return []
}

// ─── Advanced attack detection (L2 hardening) ───────────────────────────────

/** GraphQL batching (array of queries) or aliased query flooding in one request. */
export function detectGraphqlBatchAbuse(input: string): GraphQLDetection | null {
    const trimmed = input.trim()
    const structural = stripQuotedAndComments(input)

    if (trimmed.startsWith('[')) {
        try {
            const parsed = JSON.parse(trimmed)
            if (!Array.isArray(parsed)) return null
            const queryItems = parsed.filter(
                (item: unknown) =>
                    typeof item === 'object' &&
                    item !== null &&
                    ('query' in (item as Record<string, unknown>) ||
                        'operationName' in (item as Record<string, unknown>)),
            ).length
            if (queryItems >= 6) {
                return {
                    type: 'batch_abuse',
                    detail: `GraphQL batched request with ${queryItems} operations (rate-limit bypass)`,
                    depth: 0,
                    confidence: 0.9,
                    l1: false,
                    l2: true,
                    evidence: `batch_count=${queryItems}`,
                }
            }
        } catch {
            // not valid JSON batch
        }
    }

    const aliasPattern = /\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:\(|\{)/g
    const aliases = new Set<string>()
    let match: RegExpExecArray | null
    while ((match = aliasPattern.exec(structural)) !== null) {
        const alias = match[1].toLowerCase()
        if (!GRAPHQL_KEYWORDS.includes(alias)) aliases.add(alias)
    }
    if (aliases.size >= 50) {
        return {
            type: 'batch_abuse',
            detail: `GraphQL aliased query flooding (${aliases.size} aliases in one request)`,
            depth: 0,
            confidence: 0.9,
            l1: false,
            l2: true,
            evidence: `alias_count=${aliases.size}`,
        }
    }
    return null
}

/** Production introspection enabled: __schema / __type enumeration (schema + multiple type queries). */
export function detectGraphqlIntrospectionLeakage(input: string): GraphQLDetection | null {
    const structural = stripQuotedAndComments(input)
    const lower = structural.toLowerCase()
    const hasSchema = /\b__schema\b/.test(lower)
    const typeMatches = lower.match(/\b__type\s*\(/g)
    const typeCount = typeMatches ? typeMatches.length : 0
    if (hasSchema && typeCount >= 2) {
        return {
            type: 'introspection',
            detail: 'GraphQL introspection enumeration: __schema with multiple __type queries',
            depth: 0,
            confidence: 0.85,
            l1: false,
            l2: true,
            evidence: 'schema_plus_type_enum',
        }
    }
    if (hasSchema && typeCount === 1) {
        return {
            type: 'introspection',
            detail: 'GraphQL introspection: __schema and __type in same request',
            depth: 0,
            confidence: 0.85,
            l1: false,
            l2: true,
            evidence: 'schema_plus_type',
        }
    }
    return null
}

function levenshtein(a: string, b: string): number {
    const m = a.length
    const n = b.length
    const dp: number[][] = Array(m + 1)
        .fill(0)
        .map(() => Array(n + 1).fill(0))
    for (let i = 0; i <= m; i++) dp[i][0] = i
    for (let j = 0; j <= n; j++) dp[0][j] = j
    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1
            dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
        }
    }
    return dp[m][n]
}

const COMMON_GRAPHQL_FIELDS = ['user', 'id', 'name', 'email', 'query', 'users', 'node', 'edges', 'cursor', 'data']

/** Field suggestion exploitation: misspelled fields to trigger "Did you mean...?" error leakage. */
export function detectGraphqlFieldSuggestionAbuse(input: string): GraphQLDetection | null {
    const structural = stripQuotedAndComments(input)
    const fieldLike = structural.match(/\b([a-z_][a-z0-9_]{2,24})\b/gi)
    if (!fieldLike || fieldLike.length < 2) return null
    const normalized = [...new Set(fieldLike.map((f) => f.toLowerCase()))].filter(
        (f) => !GRAPHQL_KEYWORDS.includes(f) && !INTROSPECTION_FIELDS.includes(f),
    )
    let nearMissCount = 0
    for (let i = 0; i < normalized.length; i++) {
        for (let j = i + 1; j < normalized.length; j++) {
            if (levenshtein(normalized[i], normalized[j]) <= 2) nearMissCount++
        }
        for (const common of COMMON_GRAPHQL_FIELDS) {
            if (levenshtein(normalized[i], common) === 1) nearMissCount++
        }
    }
    if (nearMissCount >= 2) {
        return {
            type: 'introspection',
            detail: 'GraphQL field suggestion abuse: misspelled fields likely to trigger schema leakage',
            depth: 0,
            confidence: 0.82,
            l1: false,
            l2: true,
            evidence: 'field_suggestion_probe',
        }
    }
    return null
}

/** Mutation injection (nested create/delete/update) or subscription abuse. */
export function detectGraphqlOperationAbuse(input: string): GraphQLDetection | null {
    const structural = stripQuotedAndComments(input)
    const lower = structural.toLowerCase()
    const isMutation = /\bmutation\b/.test(lower)
    const isSubscription = /\bsubscription\b/.test(lower)
    const mutationOps = lower.match(/\b(create|delete|update|add|remove|insert|drop)[a-z0-9_]*\s*[{(]/g)
    const opCount = mutationOps ? mutationOps.length : 0
    if (isMutation && opCount >= 3) {
        return {
            type: 'batch_abuse',
            detail: `GraphQL mutation injection: ${opCount} nested mutation operations`,
            depth: 0,
            confidence: 0.88,
            l1: false,
            l2: true,
            evidence: `mutation_ops=${opCount}`,
        }
    }
    if (isSubscription && lower.includes('subscription') && structural.length > 500) {
        return {
            type: 'batch_abuse',
            detail: 'GraphQL subscription abuse: large subscription likely for connection draining',
            depth: 0,
            confidence: 0.88,
            l1: false,
            l2: true,
            evidence: 'subscription_abuse',
        }
    }
    return null
}

/** Deeply nested query DoS: recursion beyond reasonable depth. */
export function detectGraphqlDepthDosProbe(input: string): GraphQLDetection | null {
    const structural = stripQuotedAndComments(input)
    const depth = maxDepth(structural)
    if (depth <= 12) return null
    return {
        type: 'depth_abuse',
        detail: `GraphQL depth DoS probe: nesting depth ${depth} exceeds safe threshold`,
        depth,
        confidence: 0.89,
        l1: false,
        l2: true,
        evidence: `depth=${depth}`,
    }
}

export function detectGraphQLAbuse(input: string): GraphQLDetection[] {
    if (input.length < 5) return []
    const structural = stripQuotedAndComments(input)
    const lower = structural.toLowerCase()
    if (!lower.includes('{') && !lower.includes('query') && !lower.includes('fragment') && !lower.includes('[')) {
        return []
    }

    const advanced: GraphQLDetection[] = [
        detectGraphqlBatchAbuse(input),
        detectGraphqlIntrospectionLeakage(input),
        detectGraphqlFieldSuggestionAbuse(input),
        detectGraphqlOperationAbuse(input),
        detectGraphqlDepthDosProbe(input),
    ].filter((d): d is GraphQLDetection => d !== null)

    const detections = [
        ...detectIntrospection(structural),
        ...detectDepthAbuse(structural),
        ...detectBatchAbuse(input),
        ...detectAliasAbuse(structural),
        ...detectFragmentAbuse(structural),
        ...advanced,
    ]

    const deduped = new Map<string, GraphQLDetection>()
    for (const d of detections) {
        const key = `${d.type}:${d.evidence}`
        const existing = deduped.get(key)
        if (!existing || d.confidence > existing.confidence) deduped.set(key, d)
    }
    return [...deduped.values()]
}
