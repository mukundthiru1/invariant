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

const UNION_EXTRACT_PATTERN = /UNION\s+(?:ALL\s+)?SELECT\s/i
const UNION_EXTRACT_OBFUSCATED_PATTERN = /(?:^|[^a-z])U\s*N\s*I\s*O\s*N\s*(?:A\s*L\s*L\s*)?S\s*E\s*L\s*E\s*C\s*T(?:\s|$)/i

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
        return UNION_EXTRACT_PATTERN.test(d) || UNION_EXTRACT_OBFUSCATED_PATTERN.test(d)
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
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}
