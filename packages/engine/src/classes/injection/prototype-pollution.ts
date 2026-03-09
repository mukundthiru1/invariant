/**
 * Emerging injection classes: prototype pollution, mass assignment, GraphQL injection
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2ProtoPollution, l2MassAssignment, l2GraphQLIntrospection } from '../../evaluators/l2-adapters.js'

export const protoPollution: InvariantClassModule = {
    id: 'proto_pollution',
    description: 'Prototype pollution via __proto__, constructor.prototype, and tainted object merge paths',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.86 },

    mitre: ['T1059.007'],
    cwe: 'CWE-1321',

    knownPayloads: [
        '{"__proto__":{"isAdmin":true}}',
        'constructor.prototype.isAdmin=true',
        '__proto__.polluted=true',
    ],

    knownBenign: [
        'prototype pattern',
        'constructor call()',
        'prototype chain inspection',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        // Core prototype pollution sinks and path traversal to Object.prototype
        if (/__proto__(?:\s*\[|\s*\.|\s*"\s*:)/i.test(d)) return true
        if (/constructor\s*(?:\.|\[\s*['"]?prototype['"]?\s*\])/i.test(d)) return true
        if (/Object\.assign\s*\(.*(?:__proto__|constructor\s*\[\s*['"]?prototype['"]?\s*\])/i.test(d)) return true

        // Object.create(null) bypass attempts that still try prototype paths
        if (/Object\.create\s*\(\s*null\s*\).*(?:__proto__|constructor\s*\[\s*['"]?prototype['"]?\s*\])/i.test(d)) return true

        return false
    },
    detectL2: l2ProtoPollution,

    generateVariants: (count: number): string[] => {
        const variants = [
            '__proto__[isAdmin]=true',
            '{"__proto__":{"isAdmin":true}}',
            'constructor[prototype][isAdmin]=true',
            'constructor.prototype.isAdmin=true',
            '__proto__.polluted=true',
            'Object.assign(target, JSON.parse(payloadWith__proto__))',
            'Object.create(null);obj["__proto__"]["isAdmin"]=true',
        ]
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}

export const massAssignment: InvariantClassModule = {
    id: 'mass_assignment',
    description: 'Mass assignment through bulk parameter binding of privileged fields',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.82 },

    mitre: ['T1548'],
    cwe: 'CWE-915',

    knownPayloads: [
        'role=admin&isAdmin=true',
        'user[role]=superadmin',
        '{"isVerified":true,"role":"admin"}',
    ],

    knownBenign: [
        'role=user',
        'isAdmin=false',
        '{"name":"test","role":"user"}',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        // Query/form-style escalations
        if (/(?:^|[?&\s])(role|user\[role\])\s*=\s*(?:admin|superadmin|root)(?:$|[&\s])/i.test(d)) return true
        if (/(?:^|[?&\s])(isAdmin|is_admin|is_staff|isVerified|is_verified)\s*=\s*(?:true|1)(?:$|[&\s])/i.test(d)) return true

        // JSON-style escalations
        if (/"(?:role|user_role)"\s*:\s*"(?:admin|superadmin|root)"/i.test(d)) return true
        if (/"(?:isAdmin|is_admin|is_staff|isVerified|is_verified)"\s*:\s*(?:true|1)/i.test(d)) return true

        return false
    },
    detectL2: l2MassAssignment,

    generateVariants: (count: number): string[] => {
        const variants = [
            'role=admin&isAdmin=true',
            'user[role]=superadmin',
            'is_staff=1&email=a@b.com',
            '{"isVerified":true,"role":"admin"}',
            '{"profile":{"role":"admin"}}',
        ]
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}

export const graphqlIntrospection: InvariantClassModule = {
    id: 'graphql_introspection',
    description: 'GraphQL injection via introspection abuse and fragment-bomb query structures',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.78 },

    mitre: ['T1087', 'T1499'],
    cwe: 'CWE-200',

    knownPayloads: [
        '{__schema{types{name}}}',
        'query{__type(name:"User"){fields{name}}}',
        '__schema{queryType{name}}',
    ],

    knownBenign: [
        'query { users { name } }',
        'mutation { createUser }',
        '{ user(id: "123") { id name } }',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        if (/__schema\s*\{/i.test(d)) return true
        if (/__type\s*\(\s*name\s*:/i.test(d)) return true
        if (/\bintrospection\b/i.test(d) && /\bquery\b/i.test(d)) return true

        // Nested fragment bomb / recursive spread abuse indicators
        const fragmentDefs = (d.match(/\bfragment\s+[A-Za-z_][A-Za-z0-9_]*\s+on\s+[A-Za-z_][A-Za-z0-9_]*/g) || []).length
        const fragmentSpreads = (d.match(/\.\.\.[A-Za-z_][A-Za-z0-9_]*/g) || []).length
        if (fragmentDefs >= 3 && fragmentSpreads >= 8) return true

        return false
    },
    detectL2: l2GraphQLIntrospection,

    generateVariants: (count: number): string[] => {
        const variants = [
            '{__schema{types{name}}}',
            'query{__type(name:"User"){fields{name}}}',
            '__schema{queryType{name}}',
            'query Bomb{a{...F1} b{...F2} c{...F3}} fragment F1 on Query{a{...F2 ...F3}} fragment F2 on Query{b{...F1 ...F3}} fragment F3 on Query{c{...F1 ...F2}}',
        ]
        const out: string[] = []
        for (let i = 0; i < count; i++) out.push(variants[i % variants.length])
        return out
    },
}

// Alias for request naming consistency.
export const graphqlInjection = graphqlIntrospection
