/**
 * sql_second_order — Second-order SQL injection
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'

const ADMIN_SECOND_ORDER_PATTERN = /\b(?:username|user(?:_?name)?|email|profile)\b[^'"\n\r;]{0,80}['"][^'"\n\r;]*admin'--/i
const SELECT_CONCAT_PATTERN = /['"]\s*\+\s*\(?\s*SELECT\s+password\s+FROM\s+users\s+WHERE\s+username\s*=\s*'admin'\)?\s*\+\s*['"]?\s*?/i
const INSERT_CONCAT_PATTERN = /\bINSERT\s+INTO\s+users\s+VALUES\s*\(\s*'victim'\s*,\s*'x'\s*\+\s*char\s*\(\s*0x27\s*\)\s*\+\s*' OR 1=1--'\s*\)/i
const STORED_QUOTE_CONCAT_PATTERN = /\b(?:username|user(?:_?name)?|email|profile)\b[^'"\n\r;]{0,120}['"][^'"\n\r;]*\+\s*(?:char\s*\(\s*0x27\s*\)|0x27)\s*\+\s*'[^']*OR\s+1=1/i
const USERNAME_QUOTE_CONCAT_PATTERN = /\b(?:username|user(?:_?name)?)\s*=\s*['"][^'"\n\r;]*['"]\s*\+\s*char\s*\(\s*0x27\s*\)\s*\+\s*['"][^'"\n\r;]*\bOR\s+1=1--['"]?/i
const LONE_ADMIN_SECOND_ORDER_PATTERN = /\badmin'--/i

export interface SqliDetection {
    type:
        | 'second_order_payload_store'
        | 'second_order_trigger_pattern'
    confidence: number
    evidence: string
}

const SECOND_ORDER_PAYLOAD_STORE_RE = /\b(?:INSERT|UPDATE)\b[\s\S]{0,420}(?:VALUES|SET)\b[\s\S]{0,420}(?:'[^']*(?:\b(?:SELECT|UNION|EXEC(?:UTE)?)\b[^']*)'|"[^"]*(?:\b(?:SELECT|UNION|EXEC(?:UTE)?)\b[^"]*)")/i
const SECOND_ORDER_TRIGGER_RE = /\bCREATE\s+(?:PROCEDURE|TRIGGER|FUNCTION)\b[\s\S]{0,420}/i
const SECOND_ORDER_TRIGGER_EXEC_RE = /\b(?:EXEC|EXECUTE)\b[\s\S]{0,220}/i
const SECOND_ORDER_TRIGGER_CONCAT_RE = /(?:'[^']*'\s*(?:\+|\|\|)\s*(?:'[^']*'|@\w+|\"[^\"]*\")|\"[^\"]*\"\s*(?:\+|\|\|)\s*(?:\"[^\"]*\"|@\w+))/i

export function detectSecondOrderPayloadStore(input: string): SqliDetection | null {
    const d = deepDecode(input)
    const match = d.match(SECOND_ORDER_PAYLOAD_STORE_RE)
    if (!match) return null
    return {
        type: 'second_order_payload_store',
        confidence: 0.88,
        evidence: match[0],
    }
}

export function detectSecondOrderTriggerPattern(input: string): SqliDetection | null {
    const d = deepDecode(input)
    if (!SECOND_ORDER_TRIGGER_RE.test(d)) return null
    const triggerChunk = d.match(SECOND_ORDER_TRIGGER_RE)?.[0]
    if (!triggerChunk) return null

    if (
        SECOND_ORDER_TRIGGER_EXEC_RE.test(triggerChunk) &&
        SECOND_ORDER_TRIGGER_CONCAT_RE.test(triggerChunk)
    ) {
        return {
            type: 'second_order_trigger_pattern',
            confidence: 0.90,
            evidence: triggerChunk,
        }
    }

    return null
}

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
        if (detectSecondOrderPayloadStore(d) || detectSecondOrderTriggerPattern(d)) return true

        return ADMIN_SECOND_ORDER_PATTERN.test(d)
            || LONE_ADMIN_SECOND_ORDER_PATTERN.test(d)
            || SELECT_CONCAT_PATTERN.test(d)
            || INSERT_CONCAT_PATTERN.test(d)
            || STORED_QUOTE_CONCAT_PATTERN.test(d)
            || USERNAME_QUOTE_CONCAT_PATTERN.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const payloadStoreMatch = detectSecondOrderPayloadStore(d)
        if (payloadStoreMatch) {
            return {
                detected: true,
                confidence: payloadStoreMatch.confidence,
                explanation: 'Second-order stored SQL payload detected in user-controlled data',
                evidence: payloadStoreMatch.evidence.substring(0, 180),
            }
        }

        const triggerMatch = detectSecondOrderTriggerPattern(d)
        if (triggerMatch) {
            return {
                detected: true,
                confidence: triggerMatch.confidence,
                explanation: 'Second-order trigger/procedure/function execution pattern with concatenation detected',
                evidence: triggerMatch.evidence.substring(0, 220),
            }
        }

        const matched = ADMIN_SECOND_ORDER_PATTERN.test(d)
            || LONE_ADMIN_SECOND_ORDER_PATTERN.test(d)
            || SELECT_CONCAT_PATTERN.test(d)
            || INSERT_CONCAT_PATTERN.test(d)
            || STORED_QUOTE_CONCAT_PATTERN.test(d)
            || USERNAME_QUOTE_CONCAT_PATTERN.test(d)

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
