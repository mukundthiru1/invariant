/**
 * sql_time_oracle — Time-based blind SQL injection
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectSqlStructural } from '../../evaluators/sql-structural-evaluator.js'

export const sqlTimeOracle: InvariantClassModule = {
    id: 'sql_time_oracle',
    description: 'Time-based blind SQL injection using sleep/delay functions as oracle',
    category: 'sqli',
    severity: 'high',
    calibration: { baseConfidence: 0.88 },

    mitre: ['T1190'],
    cwe: 'CWE-89',

    knownPayloads: [
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND BENCHMARK(10000000,SHA1('test'))--",
        "' AND (SELECT pg_sleep(5))--",
        "' OR IF(1=1,SLEEP(5),0)--",
    ],

    knownBenign: [
        "please wait for delay",
        "sleep mode enabled",
        "benchmark results",
        "I need to sleep",
        "pg_dump output",
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /(?:SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|PG_SLEEP\s*\(|DBMS_PIPE\.RECEIVE_MESSAGE)/i.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        try {
            const detections = detectSqlStructural(d)
            const match = detections.find(det => det.type === 'time_oracle')
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
            "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
            "' AND BENCHMARK(10000000,SHA1('test'))--",
            "' AND (SELECT pg_sleep(5))--",
            "' OR IF(1=1,SLEEP(5),0)--", "1 AND SLEEP(5)",
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
