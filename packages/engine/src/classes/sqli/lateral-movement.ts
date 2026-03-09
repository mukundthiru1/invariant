/**
 * sql_lateral_movement — SQL privilege escalation and lateral movement
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'

const SQL_SRVROLEPATTERN = /\bsp_addsrvrolemember\b(?:\s*\(\s*'attacker'\s*,\s*'sysadmin'\s*\)|\s+'attacker'\s*,\s*'sysadmin')/i
const SQL_GRANT_ALL_WILDCARD = /\bGRANT\s+ALL\s+PRIVILEGES\s+ON\s+\*\.\*\s+TO\s*'attacker'@'%'/i
const SQL_CREATE_GRANT_DBA = /\bCREATE\s+USER\s+attacker\s+IDENTIFIED\s+BY\s+'[^']+'\s*;\s*GRANT\s+DBA\s+TO\s+attacker/i
const SQL_SP_CONFIGURE_XP_CMDSHELL = /\bsp_configure\s*\(\s*'xp_cmdshell'\s*,\s*1\s*\)|\bsp_configure\s+'xp_cmdshell'/i

export const sqlLateralMovement: InvariantClassModule = {
    id: 'sql_lateral_movement',
    description: 'SQL privilege escalation and lateral movement primitives in database context',
    category: 'sqli',
    severity: 'critical',
    calibration: { baseConfidence: 0.9 },

    mitre: ['T1068', 'T1078'],
    cwe: 'CWE-89',

    knownPayloads: [
        `EXEC sp_addsrvrolemember 'attacker', 'sysadmin'`,
        `GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'`,
        `CREATE USER attacker IDENTIFIED BY 'pass'; GRANT DBA TO attacker`,
    ],

    knownBenign: [
        `GRANT SELECT ON table TO user`,
        `CREATE USER app_user`,
        `REVOKE ALL PRIVILEGES ON *.* FROM 'appuser'@'localhost'`,
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return SQL_SRVROLEPATTERN.test(d)
            || SQL_GRANT_ALL_WILDCARD.test(d)
            || SQL_CREATE_GRANT_DBA.test(d)
            || SQL_SP_CONFIGURE_XP_CMDSHELL.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        if (
            !SQL_SRVROLEPATTERN.test(d)
            && !SQL_GRANT_ALL_WILDCARD.test(d)
            && !SQL_CREATE_GRANT_DBA.test(d)
            && !SQL_SP_CONFIGURE_XP_CMDSHELL.test(d)
        ) {
            return null
        }

        return {
            detected: true,
            confidence: 0.94,
            explanation: 'Privilege escalation or lateral movement SQL primitives detected',
            evidence: d.substring(0, 220),
        }
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            `EXEC sp_addsrvrolemember 'attacker', 'sysadmin'`,
            `GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'`,
            `CREATE USER attacker IDENTIFIED BY 'pass'; GRANT DBA TO attacker`,
            `sp_configure 'xp_cmdshell', 1`,
            `EXEC sp_addsrvrolemember 'attacker', 'sysadmin'; GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'`,
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}
