/**
 * @santh/agent — Command Execution RASP Wrapper
 *
 * Wraps child_process.exec/execSync/spawn to detect command injection.
 *
 * The math:
 *   Given command string C:
 *   If C contains shell metacharacters (;|&`$) followed by system commands,
 *   the input is an injection.
 */

import type { InvariantDB, DefenseAction, Severity } from '../db.js'

export interface ExecRaspConfig {
    mode: 'observe' | 'sanitize' | 'defend' | 'lockdown'
    db: InvariantDB
    onViolation?: (violation: ExecViolation) => void
}

export interface ExecViolation {
    command: string
    invariantClass: string
    action: DefenseAction
    timestamp: string
}

const CMD_INVARIANTS = [
    {
        id: 'cmd_separator',
        test: (cmd: string) => /[;&|`]\s*(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc|ncat|bash|sh|python|perl|ruby|php|powershell|cmd|net\s+user|certutil|bitsadmin)\b/i.test(cmd),
        severity: 'critical' as Severity,
    },
    {
        id: 'cmd_substitution',
        test: (cmd: string) => /\$\([^)]*(?:cat|ls|id|whoami|curl|wget|bash|sh|python)\b[^)]*\)|`[^`]*(?:cat|ls|id|whoami)\b[^`]*`/i.test(cmd),
        severity: 'critical' as Severity,
    },
    {
        id: 'cmd_argument_injection',
        test: (cmd: string) => /(?:^|\s)--(?:output|exec|post-file|upload-file|config|shell)\b/i.test(cmd),
        severity: 'high' as Severity,
    },
    {
        id: 'cmd_reverse_shell',
        test: (cmd: string) => /(?:bash\s+-i|\/dev\/tcp|nc\s+-[elp]|ncat\s+-[elp]|mkfifo|python\s+-c\s+['"]import\s+socket)/i.test(cmd),
        severity: 'critical' as Severity,
    },
]

export function wrapExec<T extends (...args: unknown[]) => unknown>(
    originalFn: T,
    config: ExecRaspConfig,
    fnName: string,
): T {
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
        const cmd = typeof args[0] === 'string' ? args[0] : ''
        if (!cmd) return originalFn.apply(this, args)

        const violations: Array<{ id: string; severity: Severity }> = []
        for (const inv of CMD_INVARIANTS) {
            try { if (inv.test(cmd)) violations.push({ id: inv.id, severity: inv.severity }) } catch { /* */ }
        }

        if (violations.length === 0) return originalFn.apply(this, args)

        const action: DefenseAction =
            config.mode === 'observe' ? 'monitored' :
                config.mode === 'lockdown' ? 'blocked' :
                    violations.some(v => v.severity === 'critical') ? 'blocked' : 'monitored'

        const now = new Date().toISOString()

        try {
            config.db.insertSignal({
                type: 'cmd_invariant_violation',
                subtype: violations[0].id,
                severity: violations[0].severity,
                action,
                path: `child_process.${fnName}()`,
                method: 'EXEC',
                source_hash: null,
                invariant_classes: JSON.stringify(violations.map(v => v.id)),
                is_novel: false,
                timestamp: now,
            })
            config.db.insertFinding({
                type: 'runtime_invariant_violation',
                category: 'cmdi',
                severity: violations[0].severity,
                status: 'open',
                title: `Command injection: ${violations[0].id}`,
                description: `Detected ${violations[0].id} in child_process.${fnName}(). Command: ${cmd.slice(0, 200)}`,
                location: `child_process.${fnName}()`,
                evidence: JSON.stringify({ command: cmd.slice(0, 200), violations: violations.map(v => v.id) }),
                remediation: 'Use execFile() or spawn() with argument arrays instead of exec() with string commands. Never pass user input directly to shell commands.',
                cve_id: null, confidence: 0.9, first_seen: now, last_seen: now, rasp_active: action === 'blocked',
            })
        } catch { /* Never break */ }

        if (config.onViolation) {
            try {
                config.onViolation({ command: cmd.slice(0, 200), invariantClass: violations[0].id, action, timestamp: now })
            } catch { /* */ }
        }

        if (action === 'blocked') {
            throw new Error(`[INVARIANT] Command execution blocked — ${violations.map(v => v.id).join(', ')} detected.`)
        }

        return originalFn.apply(this, args)
    }

    return wrapped as unknown as T
}
