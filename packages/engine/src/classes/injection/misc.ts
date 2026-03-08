/**
 * Open redirect, mass assignment, LDAP, ReDoS
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2OpenRedirect, l2LDAPInjection } from '../../evaluators/l2-adapters.js'

export const openRedirectBypass: InvariantClassModule = {
    id: 'open_redirect_bypass',
    description: 'Open redirect bypass — URL schemes and encoding tricks to redirect to malicious domains',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.75 },

    mitre: ['T1566.002'],
    cwe: 'CWE-601',

    knownPayloads: [
        '?redirect=//evil.com',
        '?url=https://evil.com',
        '?next=%2F%2Fevil.com',
        '?redirect=\\\\evil.com\\path',
    ],

    knownBenign: [
        '?redirect=/home',
        '?url=/dashboard',
        '?next=/login',
        '/api/redirect',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return (/\/\/[^/]+\.[^/]+/.test(d) && /(?:redirect|url|next|return|goto|dest|target|rurl|forward)\s*[=:]/i.test(d))
            || /\\\\[^\\]+\\/.test(d)
            || /(?:redirect|url|next|goto)=(?:\/\/|https?:|%2[fF]%2[fF])/i.test(input)
    },
    detectL2: l2OpenRedirect,
    generateVariants: (count: number): string[] => {
        const v = ['?redirect=//evil.com', '?url=https://evil.com', '?next=%2F%2Fevil.com',
            '?redirect=\\\\evil.com\\path', '?goto=//evil.com%0d%0a']
        return v.slice(0, count)
    },
}

export const massAssignment: InvariantClassModule = {
    id: 'mass_assignment',
    description: 'Mass assignment attack — injecting admin/role/privilege fields in request bodies',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.80 },

    mitre: ['T1548'],
    cwe: 'CWE-915',

    knownPayloads: [
        '{"name":"test","role":"admin"}',
        '{"email":"a@b.com","isAdmin":true}',
        '{"username":"test","is_admin":true,"access_level":"superuser"}',
    ],

    knownBenign: [
        '{"name":"test","email":"test@test.com"}',
        '{"username":"john","age":25}',
        '{"title":"post","content":"hello"}',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /(?:"|\b)(?:role|isAdmin|is_admin|admin|privilege|permission|access_level|user_type|account_type|verified|approved|activated)\s*"\s*:\s*(?:true|"admin"|"root"|1|"superuser")/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = ['{"name":"test","role":"admin"}', '{"email":"a@b.com","isAdmin":true}',
            '{"username":"test","is_admin":true,"access_level":"superuser"}',
            '{"name":"test","permission":"admin","verified":true}']
        return v.slice(0, count)
    },
}

export const ldapFilterInjection: InvariantClassModule = {
    id: 'ldap_filter_injection',
    description: 'LDAP filter injection — unescaped metacharacters in LDAP search filters',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.82 },

    mitre: ['T1190'],
    cwe: 'CWE-90',

    knownPayloads: [
        '*)(uid=*))(|(uid=*',
        '*(|(mail=*))',
        'admin)(|(password=*)',
    ],

    knownBenign: [
        'search for user',
        'filter by name',
        'uid=12345',
        '(status=active)',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /\(\|?\(?\w+=\*\)/.test(d)
            || /\)\(\w+=/.test(d)
            || /\(\|\(\w+=\*\)\)/.test(d)
            || (/\x00/.test(d) && /\(/.test(d))
    },
    detectL2: l2LDAPInjection,
    generateVariants: (count: number): string[] => {
        const v = ['*)(uid=*))(|(uid=*', '*(|(mail=*))', 'admin)(|(password=*)',
            '*)(&(objectClass=*)']
        return v.slice(0, count)
    },
}

export const regexDos: InvariantClassModule = {
    id: 'regex_dos',
    description: 'Regular expression denial of service — catastrophic backtracking inputs',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.70, minInputLength: 50 },

    mitre: ['T1499.004'],
    cwe: 'CWE-1333',

    knownPayloads: [
        'a'.repeat(100) + '!',
        'x'.repeat(200),
    ],

    knownBenign: [
        'normal input text',
        'short string',
        'hello world',
        'a'.repeat(10),
    ],

    detect: (input: string): boolean => {
        if (input.length < 50) return false
        let maxRun = 1
        let currentRun = 1
        for (let i = 1; i < input.length; i++) {
            if (input[i] === input[i - 1]) {
                currentRun++
                if (currentRun > maxRun) maxRun = currentRun
            } else {
                currentRun = 1
            }
        }
        return maxRun >= 50
    },
    generateVariants: (count: number): string[] => {
        const v = ['a'.repeat(100) + '!', 'x'.repeat(200),
        'b'.repeat(60) + 'y'.repeat(60)]
        return v.slice(0, count)
    },
}
