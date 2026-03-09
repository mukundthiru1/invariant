/**
 * sql_union_extraction — UNION SELECT data extraction
 *
 * Invariant property:
 *   input contains UNION [ALL] SELECT sequence
 *   → attacker appends a second query to extract data from other tables
 *
 * This is the primary data exfiltration mechanism in SQL injection.
 * The attacker appends a UNION SELECT to the application's query,
 * matching the original query's column count, to extract data from
 * arbitrary tables (users, credentials, schema metadata).
 */

import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectSqlStructural } from '../../evaluators/sql-structural-evaluator.js'

// Standard: UNION [ALL] SELECT ...
const UNION_EXTRACT_PATTERN = /UNION\s+(?:ALL\s+)?SELECT\s/i
// Space/whitespace-obfuscated letters: U N I O N S E L E C T
const UNION_EXTRACT_OBFUSCATED_PATTERN = /(?:^|[^a-z])U\s*N\s*I\s*O\s*N\s*(?:A\s*L\s*L\s*)?S\s*E\s*L\s*E\s*C\s*T(?:\s|$)/i
// PostgreSQL dollar-quoting with SELECT inside
const POSTGRES_DOLLAR_QUOTING_PATTERN = /\$(?:[a-z_][a-z0-9_]*)?\$[\s\S]{0,200}?\bSELECT\b[\s\S]{0,200}?\$(?:[a-z_][a-z0-9_]*)?\$/i
// Hex-encoded SELECT keyword
const HEX_KEYWORD_SELECT_PATTERN = /\b0x53454c454354\b/i

// C-005: Bypass patterns not covered by primary regex

// UNION (SELECT ...) — parenthesized SELECT
const UNION_PAREN_SELECT_RE = /UNION\s+(?:ALL\s+|DISTINCT\s+)?\(?\s*SELECT\b/i
// UNION DISTINCT SELECT — explicit DISTINCT keyword
const UNION_DISTINCT_RE = /UNION\s+DISTINCT\s+SELECT\b/i
// PostgreSQL VALUES literal: UNION VALUES(1,2,3)
const UNION_VALUES_RE = /UNION\s+(?:ALL\s+)?VALUES\s*\(/i
// PostgreSQL TABLE expression: UNION TABLE tablename
const UNION_TABLE_RE = /UNION\s+(?:ALL\s+)?TABLE\s+\w+/i
// UNION/*comment*/ALL SELECT — comments injected between UNION and SELECT/ALL
const UNION_COMMENT_RE = /UNION\s*\/\*[\s\S]{0,100}?\*\/\s*(?:ALL\s*\/\*[\s\S]{0,50}?\*\/\s*)?SELECT\b/i

export const sqlUnionExtraction: InvariantClassModule = {
    id: 'sql_union_extraction',
    description: 'UNION SELECT to extract data from other tables/columns',
    category: 'sqli',
    severity: 'critical',

    calibration: {
        baseConfidence: 0.92,
        minInputLength: 10,
    },

    mitre: ['T1190', 'T1005'],
    cwe: 'CWE-89',

    knownPayloads: [
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL,NULL--",
        "' UNION SELECT username,password FROM users--",
        "' UNION SELECT 1,@@version,3--",
        '" UNION SELECT 1,2,3--',
        "' UN/**/ION SE/**/LECT 1,2,3--",
        "' U/**/NION ALL SE/**/LECT NULL,NULL--",
        "' UNION%0BSELECT 1,2,3--",
        "' || $$SELECT password FROM users$$--",
        "' || $tag$SELECT current_user$tag$--",
        "' UNION SELECT 0x53454c454354,2,3--",
        // C-005: Parenthesized SELECT bypass
        "' UNION (SELECT 1,2,3)--",
        // C-005: DISTINCT keyword bypass
        "' UNION DISTINCT SELECT 1,2,3--",
        // C-005: PostgreSQL VALUES bypass
        "' UNION VALUES(1,'x',3)--",
        // C-005: PostgreSQL TABLE bypass
        "' UNION TABLE users--",
        // C-005: Comment injection between UNION and ALL/SELECT
        "' UNION/*comment*/ALL SELECT 1,2,3--",
    ],

    knownBenign: [
        "SELECT name FROM users",
        "please select one option",
        "union of workers",
        "SELECT UNION label",
        "trade union agreement",
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return UNION_EXTRACT_PATTERN.test(d)
            || UNION_EXTRACT_OBFUSCATED_PATTERN.test(d)
            || POSTGRES_DOLLAR_QUOTING_PATTERN.test(d)
            || HEX_KEYWORD_SELECT_PATTERN.test(d)
            // C-005: Bypass patterns
            || UNION_PAREN_SELECT_RE.test(d)
            || UNION_DISTINCT_RE.test(d)
            || UNION_VALUES_RE.test(d)
            || UNION_TABLE_RE.test(d)
            || UNION_COMMENT_RE.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const detections = detectSqlStructural(d)
        const match = detections.find(det => det.type === 'union_extraction')
        if (match) {
            return {
                detected: true,
                confidence: match.confidence,
                explanation: `Token analysis: ${match.detail}`,
                evidence: match.detail,
            }
        }
        return null
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT 1,@@version,3--",
            "') UNION SELECT 1,2,3#",
            '" UNION SELECT 1,2,3--',
            "' UNION/**/SELECT/**/1,2,3--",
            "' UnIoN SeLeCt 1,2,3--",
            "' UNION SELECT CHAR(65),2,3--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' || $$SELECT version()$$--",
            "' || $tag$SELECT current_database()$tag$--",
            "' UNION SELECT 0x53454c454354,2,3--",
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}
