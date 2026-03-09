/**
 * GraphQL abuse classes
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2GraphQLIntrospection, l2GraphQLBatch, l2GraphQLInjection, l2GraphQLDos } from '../../evaluators/l2-adapters.js'

const GQL_INTROSPECTION_SCHEMA_RE = /__schema\s*\{/i
const GQL_INTROSPECTION_TYPE_CALL_RE = /__type\s*\(/i
const GQL_INTROSPECTION_TYPE_SELECTION_RE = /__type\s*\{/i
const GQL_INTROSPECTION_QUERYTYPE_RE = /\{\s*__schema\s*\{.*queryType/i
const GQL_BATCH_ARRAY_RE = /^\s*\[.*\{.*query.*\}.*\{.*query.*\}/s
const GQL_FIELD_PROBING_RE = /\b(?:usr|userr|userr|idd|iddd|namee|emal|emaill|passwrod|tokn|rolee|creditcardd|ssnn)\b/i

function maxDepth(input: string): number {
    let depth = 0
    let max = 0
    for (const ch of input) {
        if (ch === '{') {
            depth++
            if (depth > max) max = depth
        } else if (ch === '}') {
            depth = Math.max(0, depth - 1)
        }
    }
    return max
}

function hasCircularFragments(input: string): boolean {
    const defs = Array.from(input.matchAll(/\bfragment\s+([A-Za-z_][A-Za-z0-9_]*)\s+on\s+[A-Za-z_][A-Za-z0-9_]*\s*\{([\s\S]*?)\}/g))
    if (defs.length < 2) return false
    const refs = new Map<string, Set<string>>()
    for (const def of defs) {
        const name = def[1]
        const body = def[2]
        const spreadRefs = new Set<string>()
        for (const spread of body.matchAll(/\.\.\.\s*([A-Za-z_][A-Za-z0-9_]*)/g)) {
            spreadRefs.add(spread[1])
        }
        refs.set(name, spreadRefs)
    }

    const visited = new Set<string>()
    const stack = new Set<string>()
    const dfs = (node: string): boolean => {
        if (stack.has(node)) return true
        if (visited.has(node)) return false
        visited.add(node)
        stack.add(node)
        for (const next of refs.get(node) ?? []) {
            if (dfs(next)) return true
        }
        stack.delete(node)
        return false
    }

    for (const node of refs.keys()) {
        if (dfs(node)) return true
    }
    return false
}

function countAliases(input: string): number {
    // Use a fresh regex per call so /g lastIndex state cannot leak across detections.
    return Array.from(input.matchAll(/\b\w+\s*:\s*\w+\s*[({]/g)).length
}

export const graphqlIntrospection: InvariantClassModule = {
    id: 'graphql_introspection',
    description: 'GraphQL introspection query — exposes the full schema',
    category: 'injection',
    severity: 'low',
    calibration: { baseConfidence: 0.70 },

    mitre: ['T1087'],
    cwe: 'CWE-200',

    knownPayloads: [
        '{__schema{queryType{name}}}',
        '{__schema{types{name fields{name}}}}',
        'query{__type(name:"User"){fields{name type{name}}}}',
    ],

    knownBenign: [
        '{ user { name } }',
        'query { posts { title } }',
        'mutation { addUser }',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return GQL_INTROSPECTION_SCHEMA_RE.test(d)
            || GQL_INTROSPECTION_TYPE_CALL_RE.test(d)
            || GQL_INTROSPECTION_TYPE_SELECTION_RE.test(d)
            || GQL_INTROSPECTION_QUERYTYPE_RE.test(d)
    },
    detectL2: l2GraphQLIntrospection,
    generateVariants: (count: number): string[] => {
        const v = ['{__schema{queryType{name}}}', '{__schema{types{name fields{name}}}}',
            'query{__type(name:"User"){fields{name type{name}}}}']
        return v.slice(0, count)
    },
}

export const graphqlBatchAbuse: InvariantClassModule = {
    id: 'graphql_batch_abuse',
    description: 'GraphQL batch query abuse — brute-force or DoS via many queries',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.75 },

    mitre: ['T1110'],
    cwe: 'CWE-770',

    knownPayloads: [
        '[{"query":"{ user(id:1) { name } }"},{"query":"{ user(id:2) { name } }"},{"query":"{ user(id:3) { name } }"},{"query":"{ user(id:4) { name } }"},{"query":"{ user(id:5) { name } }"},{"query":"{ user(id:6) { name } }"}]',
        '{ a1: login(u:"a",p:"1") a2: login(u:"b",p:"2") a3: login(u:"c",p:"3") a4: login(u:"d",p:"4") a5: login(u:"e",p:"5") }',
        '{"query":"query{a:node(id:1){id} b:node(id:2){id} c:node(id:3){id} d:node(id:4){id} e:node(id:5){id} f:node(id:6){id}"}',
    ],

    knownBenign: [
        '{"query":"{ user { name } }"}',
        '{ user { name email } }',
        'single query',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const aliasCount = countAliases(d)
        return aliasCount >= 5
            || GQL_BATCH_ARRAY_RE.test(d)
    },
    detectL2: l2GraphQLBatch,
    generateVariants: (count: number): string[] => {
        const v = [
            '[{"query":"{ user(id:1) { name } }"},{"query":"{ user(id:2) { name } }"},{"query":"{ user(id:3) { name } }"},{"query":"{ user(id:4) { name } }"},{"query":"{ user(id:5) { name } }"},{"query":"{ user(id:6) { name } }"}]',
            '{ a1: login(u:"a",p:"1") a2: login(u:"b",p:"2") a3: login(u:"c",p:"3") a4: login(u:"d",p:"4") a5: login(u:"e",p:"5") }',
        ]
        return v.slice(0, count)
    },
}

export const graphql_injection: InvariantClassModule = {
    id: 'graphql_injection',
    description: 'GraphQL injection abuse via introspection probing, deep query recursion, typo-based field suggestion probing, or batch fan-out',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.86 },

    mitre: ['T1190', 'T1087'],
    cwe: 'CWE-917',

    knownPayloads: [
        '{__schema{types{name}}}',
        '{ a { b { c { d { e { f { g { h { i { j { k } } } } } } } } } }',
        '{"query":"{ usr { idd emal namee } }"}',
        '[{"query":"{ user(id:1){id} }"},{"query":"{ user(id:2){id} }"},{"query":"{ user(id:3){id} }"},{"query":"{ user(id:4){id} }"},{"query":"{ user(id:5){id} }"},{"query":"{ user(id:6){id} }"}]',
    ],

    knownBenign: [
        '{ user { id name } }',
        'mutation { updateProfile(name:"alice") { id } }',
        '{"query":"{ posts { title } }"}',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const depth = maxDepth(d)
        const aliasCount = countAliases(d)
        const typoCount = (d.match(/\b(?:usr|userr|userr|idd|iddd|namee|emal|emaill|passwrod|tokn|rolee|creditcardd|ssnn)\b/gi) || []).length

        return GQL_INTROSPECTION_SCHEMA_RE.test(d)
            || GQL_INTROSPECTION_TYPE_CALL_RE.test(d)
            || depth > 10
            || (GQL_FIELD_PROBING_RE.test(d) && typoCount >= 2)
            || GQL_BATCH_ARRAY_RE.test(d)
            || aliasCount >= 8
    },

    detectL2: l2GraphQLInjection,

    generateVariants: (count: number): string[] => {
        const variants = [
            '{__schema{types{name}}}',
            'query{__type(name:"User"){fields{name type{name}}}}',
            '{ a { b { c { d { e { f { g { h { i { j { k } } } } } } } } } }',
            '{"query":"{ usr { idd emal namee } }"}',
            '[{"query":"{ user(id:1){id} }"},{"query":"{ user(id:2){id} }"},{"query":"{ user(id:3){id} }"},{"query":"{ user(id:4){id} }"},{"query":"{ user(id:5){id} }"},{"query":"{ user(id:6){id} }"}]',
            '{ a1:user(id:1){id} a2:user(id:2){id} a3:user(id:3){id} a4:user(id:4){id} a5:user(id:5){id} a6:user(id:6){id} a7:user(id:7){id} a8:user(id:8){id} }',
        ]
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}

export const graphql_dos: InvariantClassModule = {
    id: 'graphql_dos',
    description: 'GraphQL denial-of-service via extreme nesting depth, circular fragments, or alias bombing',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.82 },

    mitre: ['T1499'],
    cwe: 'CWE-400',

    knownPayloads: [
        '{ a { b { c { d { e { f { g { h { i { j { k { l { m { n { o { p } } } } } } } } } } } } } } } }',
        'fragment A on Query { user { ...B } } fragment B on Query { user { ...A } } query { user { ...A } }',
        '{ a1:user{id} a2:user{id} a3:user{id} a4:user{id} a5:user{id} a6:user{id} a7:user{id} a8:user{id} a9:user{id} a10:user{id} a11:user{id} a12:user{id} a13:user{id} a14:user{id} a15:user{id} a16:user{id} }',
    ],

    knownBenign: [
        '{ user { id name profile { city } } }',
        'fragment UserFields on User { id name } query { user { ...UserFields } }',
        '{ a1:user{id} a2:user{id} a3:user{id} }',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const depth = maxDepth(d)
        const aliasCount = countAliases(d)

        return depth > 15 || aliasCount >= 15 || hasCircularFragments(d)
    },

    detectL2: l2GraphQLDos,

    generateVariants: (count: number): string[] => {
        const variants = [
            '{ a { b { c { d { e { f { g { h { i { j { k { l { m { n { o { p } } } } } } } } } } } } } } } }',
            'fragment A on Query { user { ...B } } fragment B on Query { user { ...C } } fragment C on Query { user { ...A } } query { user { ...A } }',
            '{ a1:user{id} a2:user{id} a3:user{id} a4:user{id} a5:user{id} a6:user{id} a7:user{id} a8:user{id} a9:user{id} a10:user{id} a11:user{id} a12:user{id} a13:user{id} a14:user{id} a15:user{id} a16:user{id} }',
            '{ root { a { b { c { d { e { f { g { h { i { j { k { l { m { n { o } } } } } } } } } } } } } } }',
        ]
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}
