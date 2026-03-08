/**
 * Auth Bypass Invariant Classes — All 2
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { jwtKidInjection, jwtJwkEmbedding, jwtConfusion } from './jwt-abuse.js'

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
    detectL2: (input: string): DetectionLevelResult | null => {
        try {
            if (!input.includes('.')) return null;
            const parts = input.split('.');
            if (parts.length === 3) {
                const header = JSON.parse(atob(parts[0].replace('Bearer ', '').trim()));
                if (/^none$/i.test(header.alg)) {
                    return { detected: true, confidence: 0.97, explanation: 'JWT algorithm set to none', evidence: header.alg };
                }
            }
            return null;
        } catch { return null; }
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
        'X-Custom-IP-Authorization: 127.0.0.1',
        'X-Real-IP: 127.0.0.1',
        'X-Client-IP: 10.0.0.1',
    ],

    knownBenign: [
        'normal header value',
        '192.168.1.1',
        '/api/users',
    ],

    // Detects IP/URL spoofing headers used to bypass access controls
    detect: (input: string): boolean => {
        const i = input.toLowerCase();
        // Standard proxy headers
        if (i.includes('x-forwarded-for:') || i.includes('x-original-url:') || i.includes('x-rewrite-url:')) return true
        // Additional IP spoofing headers
        if (i.includes('x-real-ip:') || i.includes('x-client-ip:') || i.includes('x-cluster-client-ip:')) return true
        // Custom auth/IP override headers (X-*-IP-*, X-*-Authorization-*)
        if (/x-[a-z-]*(?:ip|authorization)[a-z-]*:\s*(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|localhost)/i.test(input)) return true
        return false
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        try {
            const lowerInput = input.toLowerCase();
            const forwardedMatches = lowerInput.match(/x-forwarded-[a-z-]+:/g) || [];
            if (forwardedMatches.length >= 3) {
                return { detected: true, confidence: 0.82, explanation: 'Multiple X-Forwarded headers detected, likely spoofing attempt' };
            }
            if (lowerInput.includes('x-original-url:') || lowerInput.includes('x-rewrite-url:')) {
                return { detected: true, confidence: 0.87, explanation: 'URL rewrite header spoofing detected' };
            }
            return null;
        } catch { return null; }
    },
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

export { jwtKidInjection, jwtJwkEmbedding, jwtConfusion } from './jwt-abuse.js'

export const AUTH_CLASSES: InvariantClassModule[] = [
    authNoneAlgorithm,
    authHeaderSpoof,
    jwtKidInjection,
    jwtJwkEmbedding,
    jwtConfusion,
]
