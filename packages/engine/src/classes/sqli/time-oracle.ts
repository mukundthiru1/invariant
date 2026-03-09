/**
 * sql_time_oracle — Time-based blind SQL injection
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectSqlStructural } from '../../evaluators/sql-structural-evaluator.js'

const TIME_ORACLE_CLASSIC_PATTERN = /(?:SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|PG_SLEEP\s*\(|DBMS_PIPE\.RECEIVE_MESSAGE)/i
const TIME_ORACLE_OBFUSCATED_FUNCTION_PATTERN = /(?:^|['"`;\s])(?:AND|OR)?\s*(?:S\s*L\s*E\s*E\s*P|P\s*G\s*_?\s*S\s*L\s*E\s*E\s*P|B\s*E\s*N\s*C\s*H\s*M\s*A\s*R\s*K|D\s*B\s*M\s*S\s*_?\s*P\s*I\s*P\s*E\s*\.\s*R\s*E\s*C\s*E\s*I\s*V\s*E\s*_?\s*M\s*E\s*S\s*S\s*A\s*G\s*E|D\s*B\s*M\s*S\s*_?\s*L\s*O\s*C\s*K\s*\.\s*S\s*L\s*E\s*E\s*P)\s*\(/i
const TIME_ORACLE_WAITFOR_PATTERN = /(?:^|['"`;\s])\s*W\s*A\s*I\s*T\s*F\s*O\s*R\s*D\s*E\s*L\s*A\s*Y\s*['"]?\d{1,2}:\d{1,2}:\d{1,2}['"]?/i

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
        "1 OR pg_sleep(5)--",
        "1; WAITFOR DELAY '0:0:5'--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND BENCHMARK(10000000,SHA1('test'))--",
        "' AND (SELECT pg_sleep(5))--",
        "' OR IF(1=1,SLEEP(5),0)--",
        "' AND SL/**/EEP(5)--",
        "'; WAIT/**/FOR DELAY '0:0:5'--",
        "' AND BENCH/**/MARK(1000000,SHA1('x'))--",
        "' AND DBMS_PIPE.RECEIVE/**/_MESSAGE('a',5)--",
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
        const classic = TIME_ORACLE_CLASSIC_PATTERN.test(d)
        const obfuscatedFuncs = TIME_ORACLE_OBFUSCATED_FUNCTION_PATTERN.test(d)
        const obfuscatedWaitfor = TIME_ORACLE_WAITFOR_PATTERN.test(d)
        return classic || obfuscatedFuncs || obfuscatedWaitfor
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const detections = detectSqlStructural(d)
        const match = detections.find(det => det.type === 'time_oracle' || det.type === 'time_based_blind')
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
