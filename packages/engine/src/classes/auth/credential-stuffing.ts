import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'

const AUTH_CREDENTIAL_CONTEXT_RE = /\b(?:login|signin|authenticate|password|username|credential)\b/i
const AUTH_REPEATED_ATTEMPTS_RE = /\b(?:[1-9]\d)\s*(?:failed\s+)?(?:login\s+)?attempts?\b/i
const AUTH_COMBO_LIST_RE = /\b(?:admin:admin|root:toor|test:test|user:password|administrator:password)\b/i

export const credentialStuffing: InvariantClassModule = {
    id: 'credential_stuffing',
    description: 'Credential stuffing signals — repeated automated login attempts using credential lists',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.83 },

    mitre: ['T1110.004'],
    cwe: 'CWE-307',

    knownPayloads: [
        'login failed 25 attempts for user admin from 10.0.0.5',
        'POST /login username=admin&password=admin username=root&password=toor username=test&password=test',
        'credential stuffing run with combo list admin:admin root:toor user:password',
    ],

    knownBenign: [
        'user login success for account alice',
        'password reset requested by user',
        'single failed login attempt',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const hasAuthContext = AUTH_CREDENTIAL_CONTEXT_RE.test(d)
        if (!hasAuthContext) return false

        const repeatedAttempts = AUTH_REPEATED_ATTEMPTS_RE.test(d) ||
            /\b(?:failed\s+login|invalid\s+password)\b[\s\S]{0,120}\b(?:failed\s+login|invalid\s+password)\b/i.test(d)

        const comboList = AUTH_COMBO_LIST_RE.test(d) ||
            /(?:username=[^&\s]{1,40}&password=[^&\s]{1,40})[\s\S]{0,120}(?:username=[^&\s]{1,40}&password=[^&\s]{1,40})/i.test(d)

        return repeatedAttempts || comboList
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const authEvents = (d.match(/\b(?:failed\s+login|invalid\s+password|login\s+attempt)\b/ig) ?? []).length
        const comboEvents = (d.match(/\b(?:[a-z0-9_.-]{2,32}:[^,\s]{2,32})\b/ig) ?? []).length

        if (authEvents >= 2 || comboEvents >= 3) {
            return {
                detected: true,
                confidence: Math.min(0.93, 0.80 + authEvents * 0.04 + comboEvents * 0.03),
                explanation: 'Multiple authentication failures or credential pairs suggest credential stuffing',
                evidence: `auth_events=${authEvents}, combo_events=${comboEvents}`,
            }
        }

        return null
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'login failed 25 attempts for user admin from 10.0.0.5',
            'POST /login username=admin&password=admin username=root&password=toor username=test&password=test',
            'credential stuffing run with combo list admin:admin root:toor user:password',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
