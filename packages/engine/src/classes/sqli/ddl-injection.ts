/**
 * sql_ddl_injection — DDL injection (DROP/TRUNCATE/ALTER)
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'

const SQL_DDL_QUOTE_PREFIX = /['"]\s*;\s*/i
const SQL_DDL_DROP_TABLE = /\bDROP\s+TABLE\s+\w+/i
const SQL_DDL_TRUNCATE_TABLE = /\bTRUNCATE\s+TABLE\s+\w+/i
const SQL_DDL_ALTER_TABLE = /\bALTER\s+TABLE\s+\w+\s+ADD\s+COLUMN\s+\w+\s+\w+/i

export const sqlDdlInjection: InvariantClassModule = {
    id: 'sql_ddl_injection',
    description: 'DDL injection that runs destructive/privileged schema statements',
    category: 'sqli',
    severity: 'critical',
    calibration: { baseConfidence: 0.91 },

    mitre: ['T1565', 'T1190'],
    cwe: 'CWE-89',

    knownPayloads: [
        `'; DROP TABLE users;--`,
        `'; TRUNCATE TABLE sessions;--`,
        `'; ALTER TABLE users ADD COLUMN backdoor TEXT;--`,
    ],

    knownBenign: [
        `SELECT * FROM dropped_items`,
        `ALTER TABLE mentioned in documentation text`,
        `SELECT * FROM audit_log`,
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (!SQL_DDL_QUOTE_PREFIX.test(d)) {
            return false
        }

        return SQL_DDL_DROP_TABLE.test(d)
            || SQL_DDL_TRUNCATE_TABLE.test(d)
            || SQL_DDL_ALTER_TABLE.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        if (!SQL_DDL_QUOTE_PREFIX.test(d)) {
            return null
        }

        if (
            SQL_DDL_DROP_TABLE.test(d)
            || SQL_DDL_TRUNCATE_TABLE.test(d)
            || SQL_DDL_ALTER_TABLE.test(d)
        ) {
            return {
                detected: true,
                confidence: 0.94,
                explanation: 'Semicolon-terminated DDL statement injection detected',
                evidence: d.substring(0, 200),
            }
        }

        return null
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            `'; DROP TABLE users;--`,
            `'; TRUNCATE TABLE sessions;--`,
            `'; ALTER TABLE users ADD COLUMN backdoor TEXT;--`,
            `admin'; TRUNCATE TABLE logs;--`,
            `'; ALTER TABLE audit_log ADD COLUMN attacker_note TEXT;--`,
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}
