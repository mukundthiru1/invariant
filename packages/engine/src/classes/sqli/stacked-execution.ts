/**
 * sql_stacked_execution — Semicolon-terminated stacked queries
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

export const sqlStackedExecution: InvariantClassModule = {
    id: 'sql_stacked_execution',
    description: 'Semicolon to terminate current query and execute arbitrary SQL statements',
    category: 'sqli',
    severity: 'critical',
    calibration: { baseConfidence: 0.92, minInputLength: 8 },

    mitre: ['T1190'],
    cwe: 'CWE-89',

    knownPayloads: [
        "'; DROP TABLE users--",
        "'; DELETE FROM sessions--",
        "'; INSERT INTO admins VALUES('hack','hack')--",
        "'; UPDATE users SET role='admin' WHERE id=1--",
        "'; EXEC xp_cmdshell 'whoami'--",
        "; TRUNCATE TABLE audit_log--",
    ],

    knownBenign: [
        "hello; world",
        "item; description; price",
        "a; b; c",
        "font-size: 12px; color: red;",
        "1; 2; 3",
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /;\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC|EXECUTE|GRANT|REVOKE|SHUTDOWN|TRUNCATE)\s+/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = [
            "'; DROP TABLE users--", "'; DELETE FROM sessions--",
            "'; INSERT INTO admins VALUES('hack','hack')--",
            "'; UPDATE users SET role='admin' WHERE id=1--",
            "'; EXEC xp_cmdshell 'whoami'--",
            "; ALTER TABLE users ADD backdoor VARCHAR(100)--",
            "'; CREATE TABLE pwned(data TEXT)--",
            '; TRUNCATE TABLE audit_log--',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
