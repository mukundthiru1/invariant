/**
 * sql_stacked_execution — Semicolon-terminated stacked queries
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectSqlStructural } from '../../evaluators/sql-structural-evaluator.js'

const SQL_STACKED_QUERY_TERMINATION_STRIPPED = /;\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|CALL|UNION|WITH|MERGE|GRANT|REVOKE|SHUTDOWN|TRUNCATE)\b/i
const SQL_STACKED_QUERY_TERMINATION_RAW = /;\s*(?:SELECT|UNION|WITH|CALL|MERGE|DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC|EXECUTE|GRANT|REVOKE|SHUTDOWN|TRUNCATE)\b/i
const SQL_STACKED_COMMENT_OPEN_CLOSE_PATTERN = /\/\*!\d*\s*([\s\S]*?)\*\//g
const SQL_STACKED_BLOCK_COMMENT_PATTERN = /\/\*[\s\S]*?\*\//g
const SQL_STACKED_LINE_COMMENT_PATTERN = /--[^\n]*/g
const SQL_STACKED_WHITESPACE_PATTERN = /\s+/g

export const sqlStackedExecution: InvariantClassModule = {
    id: 'sql_stacked_execution',
    description: 'Semicolon to terminate current query and execute arbitrary SQL statements',
    category: 'sqli',
    severity: 'critical',
    calibration: { baseConfidence: 0.92, minInputLength: 8 },

    mitre: ['T1190'],
    cwe: 'CWE-89',

    knownPayloads: [
        "'; DROP TABLE users--",
        "'; DELETE FROM sessions--",
        "'; INSERT INTO admins VALUES('hack','hack')--",
        "'; UPDATE users SET role='admin' WHERE id=1--",
        "'; EXEC xp_cmdshell 'whoami'--",
        "; TRUNCATE TABLE audit_log--",
    ],

    knownBenign: [
        "hello; world",
        "item; description; price",
        "a; b; c",
        "font-size: 12px; color: red;",
        "1; 2; 3",
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // BYP-001: MySQL conditional comments (/*!50000SELECT*/) must be unwrapped
        // BEFORE generic block comment stripping to preserve the injected keyword.
        const stripSqlComments = (sql: string) => sql
            .replace(SQL_STACKED_COMMENT_OPEN_CLOSE_PATTERN, (_, inner) => ' ' + inner + ' ')
            .replace(SQL_STACKED_BLOCK_COMMENT_PATTERN, ' ')
            .replace(SQL_STACKED_LINE_COMMENT_PATTERN, ' ')
            .replace(SQL_STACKED_WHITESPACE_PATTERN, ' ')
            .trim()
        const stripped = stripSqlComments(d)
        return SQL_STACKED_QUERY_TERMINATION_STRIPPED.test(stripped) ||
               SQL_STACKED_QUERY_TERMINATION_RAW.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const detections = detectSqlStructural(d)
        const match = detections.find(det => det.type === 'stacked_execution')
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
        const v = [
            "'; DROP TABLE users--", "'; DELETE FROM sessions--",
            "'; INSERT INTO admins VALUES('hack','hack')--",
            "'; UPDATE users SET role='admin' WHERE id=1--",
            "'; EXEC xp_cmdshell 'whoami'--",
            "; ALTER TABLE users ADD backdoor VARCHAR(100)--",
            "'; CREATE TABLE pwned(data TEXT)--",
            '; TRUNCATE TABLE audit_log--',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
