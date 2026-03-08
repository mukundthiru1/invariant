/**
 * GraphQL abuse classes
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2GraphQLIntrospection, l2GraphQLBatch } from '../../evaluators/l2-adapters.js'

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
        return /__schema\s*\{/i.test(d) || /__type\s*\(/i.test(d)
            || /\{\s*__schema\s*\{.*queryType/i.test(d)
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
    ],

    knownBenign: [
        '{"query":"{ user { name } }"}',
        '{ user { name email } }',
        'single query',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const aliasCount = (d.match(/\w+\s*:\s*\w+\s*\(/g) || []).length
        return aliasCount >= 5
            || /^\s*\[.*\{.*query.*\}.*\{.*query.*\}/s.test(d)
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
