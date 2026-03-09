/**
 * sql_mysql_specific — MySQL-specific advanced SQLi techniques
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'

const MYSQL_PROC_ANALYSE_PATTERN = /\bPROCEDURE\s+ANALYSE\s*\(\s*EXTRACT(?:VALUE)?\s*\(/i
const MYSQL_EXTRACT_UPDATE_PATTERN = /\b(?:EXTRACTVALUE|UPDATEXML)\s*\(\s*1\s*,\s*CONCAT\s*\(\s*0x7e\s*,\s*\(?\s*SELECT\s+/i
const MYSQL_RANDOM_ERROR_PATTERN = /FLOOR\s*\(\s*RAND\s*\(\s*0\s*\)\s*\*\s*2\s*\)/i
const MYSQL_GROUP_BY_X_PATTERN = /\bGROUP\s+BY\s+\w+/i
const MYSQL_SYSTEM_FUNC_PATTERN = /\b(?:VERSION|USER|DATABASE)\b|@@datadir/i
const MYSQL_CHARSET_BYPASS_PATTERN = /\bSET\s+NAMES\s+utf8\b[\s;]+(?:SELECT|INSERT|UPDATE|DELETE)\b/i
const MYSQL_CONVERT_UTF8_PATTERN = /\bCONVERT\s*\(\s*.+?\s+USING\s+utf8\s*\)/i
const SQL_HEX_SELECT_PATTERN = /\b0x53454c454354\b/i

export const sqlMysqlSpecific: InvariantClassModule = {
    id: 'sql_mysql_specific',
    description: 'MySQL-specific SQL injection primitives such as PROCEDURE ANALYSE and error-based RAND(FLOOR) chains',
    category: 'sqli',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },

    mitre: ['T1190'],
    cwe: 'CWE-89',

    knownPayloads: [
        ` ' PROCEDURE ANALYSE(extractvalue(1,concat(0x7e,(SELECT version()))),1)-- -`,
        ` ' AND ExtractValue(1, concat(0x7e, (select @@datadir)))-- -`,
        ` ' AND (SELECT 1 FROM(SELECT COUNT(*),concat((SELECT database()),0x3a,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -`,
        `SET NAMES utf8; SELECT user();`,
        `' AND CONVERT((SELECT password FROM users LIMIT 1) USING utf8)--`,
        `/*!50000SELECT*/ 0x53454c454354`,
    ],

    knownBenign: [
        `SELECT PROCEDURE_NAME FROM information_schema`,
        `ExtractValue(xml, xpath)`,
        `SELECT 1 FROM users LIMIT 1`,
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return MYSQL_PROC_ANALYSE_PATTERN.test(d)
            || (MYSQL_EXTRACT_UPDATE_PATTERN.test(d) && MYSQL_SYSTEM_FUNC_PATTERN.test(d))
            || (MYSQL_RANDOM_ERROR_PATTERN.test(d) && MYSQL_GROUP_BY_X_PATTERN.test(d))
            || MYSQL_CHARSET_BYPASS_PATTERN.test(d)
            || MYSQL_CONVERT_UTF8_PATTERN.test(d)
            || SQL_HEX_SELECT_PATTERN.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const detected = MYSQL_PROC_ANALYSE_PATTERN.test(d)
            || (MYSQL_EXTRACT_UPDATE_PATTERN.test(d) && MYSQL_SYSTEM_FUNC_PATTERN.test(d))
            || (MYSQL_RANDOM_ERROR_PATTERN.test(d) && MYSQL_GROUP_BY_X_PATTERN.test(d))
            || MYSQL_CHARSET_BYPASS_PATTERN.test(d)
            || MYSQL_CONVERT_UTF8_PATTERN.test(d)
            || SQL_HEX_SELECT_PATTERN.test(d)

        if (!detected) return null

        return {
            detected: true,
            confidence: 0.93,
            explanation: 'MySQL-specific advanced SQL injection primitive detected',
            evidence: d.substring(0, 240),
        }
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            `' PROCEDURE ANALYSE(extractvalue(1,concat(0x7e,(SELECT version()))),1)-- -`,
            `' AND ExtractValue(1, concat(0x7e, (select @@datadir)))-- -`,
            `' AND (SELECT 1 FROM(SELECT COUNT(*),concat((SELECT database()),0x3a,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -`,
            `' AND UpdateXML(1,concat(0x7e, (SELECT user())),1)-- -`,
            `' OR 1=1 AND (SELECT 1 FROM(SELECT FLOOR(RAND(0)*2) x)q GROUP BY x)-- -`,
            `SET NAMES utf8; SELECT version();`,
            `' AND CONVERT((SELECT @@version) USING utf8)--`,
            `' UNION SELECT 0x53454c454354--`,
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}
