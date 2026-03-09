/**
 * sql_error_oracle — Error-based SQL injection
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectSqlStructural } from '../../evaluators/sql-structural-evaluator.js'

const ERROR_ORACLE_CLASSIC_PATTERN = /(?:EXTRACTVALUE|UPDATEXML|XMLTYPE|CONVERT\s*\(.*USING|EXP\s*\(\s*~|POLYGON\s*\(|GTID_SUBSET|FLOOR\s*\(\s*RAND|GROUP\s+BY\s+.*FLOOR)/i
const ERROR_ORACLE_OBFUSCATED_PATTERN = /(?:^|['"`;\s)])(?:AND|OR)?\s*(?:E\s*X\s*T\s*R\s*A\s*C\s*T\s*V\s*A\s*L\s*U\s*E|U\s*P\s*D\s*A\s*T\s*E\s*X\s*M\s*L|G\s*T\s*I\s*D\s*_?\s*S\s*U\s*B\s*S\s*E\s*T)\s*\(/i

export const sqlErrorOracle: InvariantClassModule = {
    id: 'sql_error_oracle',
    description: 'Error-based SQL injection using database error messages to extract data',
    category: 'sqli',
    severity: 'high',
    calibration: { baseConfidence: 0.88 },

    mitre: ['T1190'],
    cwe: 'CWE-89',

    knownPayloads: [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
        "' AND EXP(~(SELECT * FROM (SELECT user())x))--",
        "' AND POLYGON((SELECT * FROM (SELECT @@version)f))--",
        "' AND EXTR/**/ACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "' AND UPDAT/**/EXML(1,CONCAT(0x7e,(SELECT user())),1)--",
        "' AND GTID/**/_SUBSET(CONCAT(0x7e,(SELECT version())),1)--",
    ],

    knownBenign: [
        "extract value from field",
        "update xml document",
        "polygon shape data",
        "floor plan design",
        "concat strings together",
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const classic = ERROR_ORACLE_CLASSIC_PATTERN.test(d)
        const obfuscated = ERROR_ORACLE_OBFUSCATED_PATTERN.test(d)
        return classic || obfuscated
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const detections = detectSqlStructural(d)
        const match = detections.find(det => det.type === 'error_oracle')
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
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
            "' AND EXP(~(SELECT * FROM (SELECT user())x))--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
            "' AND POLYGON((SELECT * FROM (SELECT @@version)f)x))--",
            "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version())),1)--",
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
