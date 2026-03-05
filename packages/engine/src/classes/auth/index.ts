/**
 * Auth Bypass Invariant Classes — All 2
 */
import type { InvariantClassModule } from '../types.js'

export const authNoneAlgorithm: InvariantClassModule = {
    id: 'auth_none_algorithm',
    description: 'JWT alg:none attack to bypass signature verification entirely',
    category: 'auth',
    severity: 'critical',
    calibration: { baseConfidence: 0.95 },

    mitre: ['T1550.001'],
    cwe: 'CWE-347',

    knownPayloads: [
        'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
    ],

    knownBenign: [
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
        'not.a.jwt.token',
        'hello world',
    ],

    detect: (input: string): boolean => {
        try {
            if (!input.includes('.')) return false
            const parts = input.split('.')
            if (parts.length !== 3) return false
            const header = JSON.parse(atob(parts[0].replace('Bearer ', '')))
            return header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE' || header.alg === 'nOnE'
        } catch {
            return false
        }
    },
    generateVariants: (count: number): string[] => {
        const v = [
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const authHeaderSpoof: InvariantClassModule = {
    id: 'auth_header_spoof',
    description: 'Spoof proxy/forwarding headers to bypass IP-based access controls',
    category: 'auth',
    severity: 'medium',
    calibration: { baseConfidence: 0.80 },

    mitre: ['T1090'],
    cwe: 'CWE-290',

    knownPayloads: [
        'X-Forwarded-For: 127.0.0.1',
        'X-Original-URL: /admin',
        'X-Rewrite-URL: /admin',
    ],

    knownBenign: [
        'normal header value',
        '192.168.1.1',
        '/api/users',
    ],

    // This invariant is checked differently — via dedicated header analysis, not input text
    detect: (_input: string): boolean => false,
    generateVariants: (count: number): string[] => {
        const v = [
            'X-Forwarded-For: 127.0.0.1', 'X-Original-URL: /admin',
            'X-Rewrite-URL: /admin', 'X-Custom-IP-Authorization: 127.0.0.1',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const AUTH_CLASSES: InvariantClassModule[] = [authNoneAlgorithm, authHeaderSpoof]
