/**
 * sql_error_oracle — Error-based SQL injection
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

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
        return /(?:EXTRACTVALUE|UPDATEXML|XMLTYPE|CONVERT\s*\(.*USING|EXP\s*\(\s*~|POLYGON\s*\(|GTID_SUBSET|FLOOR\s*\(\s*RAND|GROUP\s+BY\s+.*FLOOR)/i.test(d)
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
