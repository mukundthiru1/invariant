/**
 * sql_string_termination — Break out of SQL string literal context
 *
 * Invariant property:
 *   ∃ (quote_char ∈ {'\'', '"', '`'}) :
 *     input contains quote_char followed by SQL keyword
 *     → attacker terminated application's string context
 *     → injected arbitrary SQL after the terminator
 *
 * This is the foundational SQL injection invariant. Every other SQL
 * injection class (tautology, UNION, stacked) requires string
 * termination first. Detecting this property alone catches the
 * entire class of SQL injection attacks that begin with context escape.
 */

import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectSqlStructural } from '../../evaluators/sql-structural-evaluator.js'

// OR/AND after a terminator must be followed by a SQL-like expression
// (digit, quote, paren, comparison operator, NULL/TRUE/FALSE, subquery)
// to avoid false positives on English prose like "'OR contact support".
// Other SQL keywords (UNION, SELECT, DROP, etc.) are unambiguous.
const SQL_KEYWORDS_AFTER_TERMINATOR = /['\"`]\s*\)?\s*(?:;|\bOR\b\s+(?:\d|['"`(]|\S+\s*[=<>!]|NULL\b|TRUE\b|FALSE\b|NOT\b)|\bAND\b\s+(?:\d|['"`(]|\S+\s*[=<>!]|NULL\b|TRUE\b|FALSE\b|NOT\b)|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bEXEC\b)/i

export const sqlStringTermination: InvariantClassModule = {
    id: 'sql_string_termination',
    description: 'Break out of a SQL string literal context to inject arbitrary SQL',
    category: 'sqli',
    severity: 'high',

    calibration: {
        baseConfidence: 0.85,
        environmentMultipliers: {
            'api_json': 0.7,
            'wordpress': 1.1,
            'login_form': 1.2,
        },
        minInputLength: 3,
    },

    mitre: ['T1190'],
    cwe: 'CWE-89',

    knownPayloads: [
        "' OR 1=1--",
        "' AND 1=1--",
        "' UNION SELECT 1--",
        "'; DROP TABLE users--",
        '" OR ""="',
        "') OR 1=1--",
    ],

    knownBenign: [
        "it's fine",
        "O'Reilly Media",
        "don't stop",
        "he said 'hello'",
        "customer's order",
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return SQL_KEYWORDS_AFTER_TERMINATOR.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        try {
            const detections = detectSqlStructural(d)
            const match = detections.find(det => det.type === 'string_termination')
            if (match) {
                return {
                    detected: true,
                    confidence: match.confidence,
                    explanation: `Token analysis: ${match.detail}`,
                    evidence: match.detail,
                }
            }
        } catch { /* L2 failure must not affect pipeline */ }
        return null
    },

    generateVariants: (count: number): string[] => {
        const terminators = ["'", '"', '`', "';", "')", "'))"]
        const injections = [
            ' OR ', ' AND ', '; DROP TABLE ', ' UNION SELECT ',
            '; INSERT INTO ', ' AND 1=CONVERT(', '; EXEC xp_',
        ]
        const suffixes = ['--', '#', '/*', '-- -', ';--', '']
        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            const t = terminators[i % terminators.length]
            const inj = injections[i % injections.length]
            const s = suffixes[i % suffixes.length]
            variants.push(`${t}${inj}1${s}`)
        }
        return variants
    },
}
