import { describe, expect, it } from 'vitest'
import {
    detectGraphQLAbuse,
    detectGraphqlBatchAbuse,
    detectGraphqlIntrospectionLeakage,
    detectGraphqlFieldSuggestionAbuse,
    detectGraphqlOperationAbuse,
    detectGraphqlDepthDosProbe,
} from './graphql-evaluator.js'

describe('graphql-evaluator advanced attack detection', () => {
    it('detectGraphqlBatchAbuse: batch array with 6+ operations', () => {
        const batch = JSON.stringify(
            Array.from({ length: 8 }, (_, i) => ({ query: `query { user(id:${i}) { name } }` })),
        )
        const d = detectGraphqlBatchAbuse(batch)
        expect(d).not.toBeNull()
        expect(d!.type).toBe('batch_abuse')
        expect(d!.confidence).toBe(0.9)
        expect(d!.evidence).toContain('batch_count=8')
    })

    it('detectGraphqlBatchAbuse: aliased query flooding (50+ aliases)', () => {
        const aliases = Array.from({ length: 55 }, (_, i) => `a${i}: user(id:${i}){name}`).join(' ')
        const query = `query { ${aliases} }`
        const d = detectGraphqlBatchAbuse(query)
        expect(d).not.toBeNull()
        expect(d!.type).toBe('batch_abuse')
        expect(d!.confidence).toBe(0.9)
        expect(d!.evidence).toContain('alias_count=55')
    })

    it('detectGraphqlBatchAbuse: no detection for small batch or few aliases', () => {
        const smallBatch = JSON.stringify([{ query: '{ user { id } }' }, { query: '{ post { id } }' }])
        expect(detectGraphqlBatchAbuse(smallBatch)).toBeNull()
        const fewAliases = '{ a: user(id:1){name} b: user(id:2){name} }'
        expect(detectGraphqlBatchAbuse(fewAliases)).toBeNull()
    })

    it('detectGraphqlIntrospectionLeakage: __schema with multiple __type', () => {
        const input = 'query { __schema { types { name } } __type(name:"User"){name} __type(name:"Post"){name} }'
        const d = detectGraphqlIntrospectionLeakage(input)
        expect(d).not.toBeNull()
        expect(d!.type).toBe('introspection')
        expect(d!.confidence).toBe(0.85)
        expect(d!.evidence).toBe('schema_plus_type_enum')
    })

    it('detectGraphqlIntrospectionLeakage: __schema with single __type', () => {
        const input = '{ __schema { queryType { name } } __type(name:"Query") { name } }'
        const d = detectGraphqlIntrospectionLeakage(input)
        expect(d).not.toBeNull()
        expect(d!.confidence).toBe(0.85)
    })

    it('detectGraphqlFieldSuggestionAbuse: misspelled fields to trigger suggestions', () => {
        const input = 'query { usr { id } emaill { id } }'
        const d = detectGraphqlFieldSuggestionAbuse(input)
        expect(d).not.toBeNull()
        expect(d!.type).toBe('introspection')
        expect(d!.confidence).toBe(0.82)
        expect(d!.evidence).toBe('field_suggestion_probe')
    })

    it('detectGraphqlOperationAbuse: mutation with 3+ nested create/delete/update', () => {
        const input = `mutation {
            createUser(input:{name:"a"}) { id }
            createPost(input:{title:"b"}) { id }
            deleteComment(id:1) { id }
            updateProfile(id:2,input:{}) { id }
        }`
        const d = detectGraphqlOperationAbuse(input)
        expect(d).not.toBeNull()
        expect(d!.type).toBe('batch_abuse')
        expect(d!.confidence).toBe(0.88)
        expect(d!.evidence).toContain('mutation_ops=')
    })

    it('detectGraphqlDepthDosProbe: deeply nested query beyond depth 12', () => {
        const deep = '{ a { b { c { d { e { f { g { h { i { j { k { l { m } } } } } } } } } } } } }'
        const d = detectGraphqlDepthDosProbe(deep)
        expect(d).not.toBeNull()
        expect(d!.type).toBe('depth_abuse')
        expect(d!.depth).toBeGreaterThanOrEqual(12)
        expect(d!.confidence).toBe(0.89)
    })

    it('detectGraphQLAbuse wires advanced detectors and returns combined results', () => {
        const batch = JSON.stringify(
            Array.from({ length: 10 }, (_, i) => ({ query: `{ user(id:${i}){name} }` })),
        )
        const all = detectGraphQLAbuse(batch)
        const batchDetection = all.find((d) => d.type === 'batch_abuse' && d.evidence.includes('batch_count'))
        expect(batchDetection).toBeDefined()
        expect(batchDetection!.confidence).toBe(0.9)
    })

    it('benign query not flagged by advanced detectors', () => {
        const benign = 'query { user(id: 1) { name email } }'
        expect(detectGraphqlBatchAbuse(benign)).toBeNull()
        expect(detectGraphqlIntrospectionLeakage(benign)).toBeNull()
        expect(detectGraphqlFieldSuggestionAbuse(benign)).toBeNull()
        expect(detectGraphqlOperationAbuse(benign)).toBeNull()
        expect(detectGraphqlDepthDosProbe(benign)).toBeNull()
    })
})
