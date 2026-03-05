/**
 * proto_pollution — Prototype pollution to modify object prototypes
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

export const protoPollution: InvariantClassModule = {
    id: 'proto_pollution',
    description: 'Prototype pollution to modify object prototypes and gain code execution',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },

    mitre: ['T1059.007'],
    cwe: 'CWE-1321',

    knownPayloads: [
        '__proto__[isAdmin]=true',
        'constructor[prototype][isAdmin]=true',
        '{"__proto__":{"isAdmin":true}}',
        'constructor.prototype.polluted=true',
    ],

    knownBenign: [
        'constructor function',
        'prototype design pattern',
        'class constructor',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /__proto__|constructor\s*\[\s*['"]?prototype['"]?\s*\]|constructor\.prototype|Object\.assign.*__proto__/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = [
            '__proto__[isAdmin]=true', 'constructor[prototype][isAdmin]=true',
            '__proto__.toString=1', '{"__proto__":{"isAdmin":true}}',
            'constructor.prototype.polluted=true',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
