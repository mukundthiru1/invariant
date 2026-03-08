import { describe, it, expect } from 'vitest'
import { detectPrototypePollution } from './proto-pollution-evaluator.js'
import { detectMassAssignment } from './mass-assignment-evaluator.js'
import { detectGraphQLAbuse } from './graphql-evaluator.js'
import { runL2Evaluators } from './evaluator-bridge.js'

describe('Proto pollution evaluator', () => {
    it('detects obfuscated computed __proto__ key assignment', () => {
        const payload = 'obj["__" + "proto__"]["isAdmin"] = true'
        const detections = detectPrototypePollution(payload)
        expect(detections.length).toBeGreaterThan(0)
        expect(detections.some(d => d.path.includes('__proto__'))).toBe(true)
        expect(detections.some(d => d.l2)).toBe(true)
        expect(detections.some(d => typeof d.evidence === 'string' && d.evidence.length > 0)).toBe(true)
    })

    it('detects constructor prototype traversal chain', () => {
        const payload = 'x["constructor"]["prototype"]["polluted"] = 1'
        const detections = detectPrototypePollution(payload)
        expect(detections.some(d => d.type === 'constructor_chain')).toBe(true)
    })
})

describe('Mass assignment evaluator', () => {
    it('detects role escalation combined with normal profile fields', () => {
        const payload = 'name=alice&email=a@b.com&role=admin'
        const detections = detectMassAssignment(payload)
        expect(detections.length).toBeGreaterThan(0)
        expect(detections[0].l2).toBe(true)
        expect(detections[0].evidence).toContain('role=admin')
    })

    it('detects suspicious JSON key combos', () => {
        const payload = '{"name":"alice","role":"admin","isAdmin":true,"is_staff":1}'
        const detections = detectMassAssignment(payload)
        expect(detections.some(d => d.type === 'suspicious_key_combo')).toBe(true)
    })

    it('does not flag benign role update', () => {
        const payload = '{"name":"alice","email":"a@b.com","role":"user","isAdmin":false}'
        const detections = detectMassAssignment(payload)
        expect(detections.length).toBe(0)
    })
})

describe('GraphQL evaluator', () => {
    it('detects introspection abuse', () => {
        const payload = 'query { __schema { types { name } } }'
        const detections = detectGraphQLAbuse(payload)
        expect(detections.some(d => d.type === 'introspection')).toBe(true)
    })

    it('detects deep nested query abuse', () => {
        const payload = 'query { a{b{c{d{e{f{g{h{i{j{k{l}}}}}}}}}} }'
        const detections = detectGraphQLAbuse(payload)
        expect(detections.some(d => d.type === 'depth_abuse')).toBe(true)
    })

    it('detects circular fragment bomb', () => {
        const payload = 'fragment A on Query { ...B } fragment B on Query { ...A } query { ...A }'
        const detections = detectGraphQLAbuse(payload)
        expect(detections.some(d => d.type === 'fragment_abuse')).toBe(true)
    })

    it('detects batch query abuse', () => {
        const payload = JSON.stringify([
            { query: '{ user(id:1){name} }' },
            { query: '{ user(id:2){name} }' },
            { query: '{ user(id:3){name} }' },
            { query: '{ user(id:4){name} }' },
            { query: '{ user(id:5){name} }' },
            { query: '{ user(id:6){name} }' },
        ])
        const detections = detectGraphQLAbuse(payload)
        expect(detections.some(d => d.type === 'batch_abuse')).toBe(true)
    })
})

describe('Evaluator bridge wiring', () => {
    it('runs proto, mass-assignment, and graphql evaluators in L2 bridge', () => {
        const protoInput = 'obj["__proto__"]["polluted"] = 1'
        const massInput = 'name=alice&role=admin&isAdmin=true'
        const gqlInput = 'query { __schema { types { name } } }'
        const results = runL2Evaluators(`${protoInput}&${massInput} ${gqlInput}`, new Set())
        const classes = new Set(results.map(r => r.class as string))
        expect(classes).toContain('proto_pollution')
        expect(classes.has('mass_assignment')).toBe(true)
        expect(classes.has('graphql_introspection')).toBe(true)
    })
})
