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
        return /UNION\s+(?:ALL\s+)?SELECT\s/i.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        try {
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
        } catch { /* L2 failure must not affect pipeline */ }
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
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}
