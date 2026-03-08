/**
 * sql_comment_truncation — SQL comment truncation
 *
 * Two-phase detection:
 *   Phase 1: Check RAW input for SQL comment syntax
 *   Phase 2: Check DECODED input for SQL keywords
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectSqlStructural } from '../../evaluators/sql-structural-evaluator.js'

const COMMENT_SYNTAX = /\/\*|--\s|--$|#/
const SQL_KEYWORDS = /\b(?:SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|DROP|TABLE|DATABASE|EXEC|INTO|CREATE|ALTER|GRANT|REVOKE)\b/i
const TERMINATE_COMMENT = /['"`]\s*(?:--|#|\/\*)/

export const sqlCommentTruncation: InvariantClassModule = {
    id: 'sql_comment_truncation',
    description: 'SQL comment syntax to truncate the remainder of a query',
    category: 'sqli',
    severity: 'medium',
    calibration: { baseConfidence: 0.75 },

    mitre: ['T1190'],
    cwe: 'CWE-89',

    knownPayloads: [
        "admin'--",
        "admin'#",
        "admin'/*",
        "' OR 1=1-- comment",
        "' UNION/**/SELECT/**/1,2,3--",
    ],

    knownBenign: [
        "hello world",
        "it's a test",
        "price is $5.00",
        "C++ programming",
        "color: #ff0000",
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const hasComment = COMMENT_SYNTAX.test(input) || COMMENT_SYNTAX.test(d)
        if (!hasComment) return false
        return SQL_KEYWORDS.test(d) || TERMINATE_COMMENT.test(input)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        try {
            const detections = detectSqlStructural(d)
            const match = detections.find(det => det.type === 'comment_truncation')
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
        const v = [
            "' OR 1=1-- comment", "' UNION/**/SELECT/**/1,2,3--",
            "' AND 1=1/*bypass*/--", "admin'--", "admin'/*", "admin'-- -", "admin'#",
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
