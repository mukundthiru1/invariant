/**
 * sql_second_order — Second-order SQL injection
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'

const ADMIN_SECOND_ORDER_PATTERN = /\b(?:username|user(?:_?name)?|email|profile)\b[^'"\n\r;]{0,80}['"][^'"\n\r;]*admin'--/i
const SELECT_CONCAT_PATTERN = /['"]\s*\+\s*\(?\s*SELECT\s+password\s+FROM\s+users\s+WHERE\s+username\s*=\s*'admin'\)?\s*\+\s*['"]?\s*?/i
const INSERT_CONCAT_PATTERN = /\bINSERT\s+INTO\s+users\s+VALUES\s*\(\s*'victim'\s*,\s*'x'\s*\+\s*char\s*\(\s*0x27\s*\)\s*\+\s*' OR 1=1--'\s*\)/i
const STORED_QUOTE_CONCAT_PATTERN = /\b(?:username|user(?:_?name)?|email|profile)\b[^'"\n\r;]{0,120}['"][^'"\n\r;]*\+\s*(?:char\s*\(\s*0x27\s*\)|0x27)\s*\+\s*'[^']*OR\s+1=1/i
const LONE_ADMIN_SECOND_ORDER_PATTERN = /\badmin'--/i

export const sqlSecondOrder: InvariantClassModule = {
    id: 'sql_second_order',
    description: 'Second-order SQL injection where user data becomes SQL payload in a later execution step',
    category: 'sqli',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },

    mitre: ['T1190'],
    cwe: 'CWE-89',

    knownPayloads: [
        `admin'--`,
        `' + (SELECT password FROM users WHERE username='admin')+ '`,
        `INSERT INTO users VALUES ('victim', 'x' + char(0x27) + ' OR 1=1--')`,
    ],

    knownBenign: [
        `O'Brien`,
        `it's a test`,
        `user's profile`,
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        return ADMIN_SECOND_ORDER_PATTERN.test(d)
            || LONE_ADMIN_SECOND_ORDER_PATTERN.test(d)
            || SELECT_CONCAT_PATTERN.test(d)
            || INSERT_CONCAT_PATTERN.test(d)
            || STORED_QUOTE_CONCAT_PATTERN.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const matched = ADMIN_SECOND_ORDER_PATTERN.test(d)
            || LONE_ADMIN_SECOND_ORDER_PATTERN.test(d)
            || SELECT_CONCAT_PATTERN.test(d)
            || INSERT_CONCAT_PATTERN.test(d)
            || STORED_QUOTE_CONCAT_PATTERN.test(d)

        if (!matched) return null

        return {
            detected: true,
            confidence: 0.88,
            explanation: 'Second-order SQL injection pattern in stored-data field input was detected',
            evidence: d.substring(0, 180),
        }
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            `admin'--`,
            `email=admin'--`,
            `' + (SELECT password FROM users WHERE username='admin')+ '`,
            `INSERT INTO users VALUES ('victim', 'x' + char(0x27) + ' OR 1=1--')`,
            `username='x' + char(0x27) + ' OR 1=1--'`,
            `email='admin'--`,
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}
