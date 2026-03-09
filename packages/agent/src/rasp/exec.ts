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
import { createRequire } from 'node:module'
import { recordRaspEvent } from './request-session.js'

export interface ExecRaspConfig {
    mode: 'observe' | 'sanitize' | 'defend' | 'lockdown'
    db: InvariantDB
    onViolation?: (violation: ExecViolation) => void
}

export interface ExecViolation {
    command: string
    invariantClass: string
    action: DefenseAction
    confidence: number
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

const DANGEROUS_CODE_PATTERNS = [
    /\bchild_process\b/i,
    /\brequire\s*\(\s*["']fs["']\s*\)/i,
    /\bexec\s*\(/i,
    /\bspawn\s*\(/i,
    /\b__dirname\b/i,
    /\bprocess\.env\b/i,
]

const WORKER_FILE_INVARIANTS = [
    {
        id: 'worker_file_traversal',
        test: (filePath: string) => /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(filePath) || /%2e%2e/i.test(filePath),
        severity: 'high' as Severity,
    },
    {
        id: 'worker_file_protocol',
        test: (filePath: string) => /^(?:https?|data|file):/i.test(filePath),
        severity: 'critical' as Severity,
    },
    {
        id: 'worker_file_sensitive_path',
        test: (filePath: string) => /(?:\/etc\/|\/proc\/|\/sys\/|\\windows\\system32)/i.test(filePath),
        severity: 'critical' as Severity,
    },
]

type VmInvariant = { id: string; severity: Severity }

function containsDangerousCode(code: string): boolean {
    for (const pattern of DANGEROUS_CODE_PATTERNS) {
        if (pattern.test(code)) return true
    }
    return false
}

function inspectForInvariants(input: string, invariants: Array<{ id: string; severity: Severity; test: (value: string) => boolean }>): Array<VmInvariant> {
    const violations: Array<VmInvariant> = []
    for (const inv of invariants) {
        try {
            if (inv.test(input)) violations.push({ id: inv.id, severity: inv.severity })
        } catch { /* Never break */ }
    }
    return violations
}

function reportVmViolation(
    config: ExecRaspConfig,
    context: string,
    payload: string,
    violations: Array<VmInvariant>,
    opts: {
        category?: string
        path?: string
        action?: DefenseAction
    } = {},
): boolean {
    if (violations.length === 0) return false

    const hasCritical = violations.some(v => v.severity === 'critical')
    const action: DefenseAction =
        config.mode === 'observe' ? 'monitored' :
            config.mode === 'sanitize' ? 'normalized' :
                hasCritical || config.mode === 'lockdown' ? 'blocked' : 'monitored'

        if (config.mode === 'observe' || config.mode === 'defend' || config.mode === 'sanitize' || config.mode === 'lockdown') {
        try {
            recordRaspEvent('vm_code_execution', payload, violations.map(v => v.id), action === 'blocked' ? 0.97 : 0.86, action === 'blocked')
        } catch { /* Never break */ }

        const now = new Date().toISOString()
        const eventPath = opts.path ?? context
        try {
            config.db.insertSignal({
                type: 'runtime_invariant_violation',
                subtype: violations[0].id,
                severity: violations[0].severity,
                action,
                path: eventPath,
                method: 'VM',
                source_hash: null,
                invariant_classes: JSON.stringify(violations.map(v => v.id)),
                is_novel: false,
                timestamp: now,
            })
            config.db.insertFinding({
                type: 'runtime_invariant_violation',
                category: opts.category ?? 'vm_execution',
                severity: violations[0].severity,
                status: 'open',
                title: `VM runtime bypass: ${violations[0].id}`,
                description: `Detected ${violations[0].id} in ${context}: ${payload.slice(0, 180)}`,
                location: eventPath,
                evidence: JSON.stringify({ context, payload: payload.slice(0, 180), violations: violations.map(v => v.id) }),
                remediation: 'Disallow runtime code evaluation/bypass paths with dangerous code, especially child_process/fs usage.',
                cve_id: null,
                confidence: 0.92,
                first_seen: now,
                last_seen: now,
                rasp_active: action === 'blocked',
            })
        } catch { /* Never break */ }
    }

    if (config.onViolation) {
        try {
            config.onViolation({
                command: payload.slice(0, 200),
                invariantClass: violations[0].id,
                action,
                confidence: action === 'blocked' ? 0.97 : 0.86,
                timestamp: new Date().toISOString(),
            })
        } catch { /* Never break */ }
    }

    if (action === 'blocked') {
        throw new Error(`[INVARIANT] VM execution blocked — ${violations.map(v => v.id).join(', ')} detected.`)
    }

    return false
}

export function inspectCode(code: unknown, config: ExecRaspConfig, context: string): void {
    if (typeof code !== 'string') return
    if (!containsDangerousCode(code)) return
    const violations: Array<VmInvariant> = [{ id: 'vm_code_execution', severity: 'critical' }]
    reportVmViolation(config, context, code, violations, { category: 'vm_execution', path: `${context}()`, action: undefined })
}

function inspectWorkerPath(filePath: unknown, config: ExecRaspConfig, context: string): void {
    if (typeof filePath !== 'string') return
    const violations = inspectForInvariants(filePath, WORKER_FILE_INVARIANTS)
    if (violations.length === 0) return
    reportVmViolation(config, context, filePath, violations, { category: 'worker_execution', path: `${context}(${filePath})` })
}

let vmHooksInstalled = false
let workerHooksInstalled = false
let inspectorHooksInstalled = false
let linkedBindingHookInstalled = false

function installVmModuleHooks(config: ExecRaspConfig, vm: Record<string, unknown>): void {
    if (vmHooksInstalled) return
    if (typeof vm.runInContext === 'function') {
        const originalRunInContext = vm.runInContext.bind(vm)
        vm.runInContext = function (...args: unknown[]) {
            const [code, context, opts] = args
            if (typeof code === 'string' && containsDangerousCode(code)) {
                reportVmViolation(
                    config,
                    'vm.runInContext',
                    code,
                    [{ id: 'vm_code_execution', severity: 'critical' }],
                    { category: 'vm_execution', path: 'vm.runInContext()' },
                )
            }
            return (originalRunInContext as (...fnArgs: unknown[]) => unknown)(code, context, opts)
        }
    }

    if (typeof vm.runInNewContext === 'function') {
        const originalRunInNewContext = vm.runInNewContext.bind(vm)
        vm.runInNewContext = function (...args: unknown[]) {
            const [code, context, opts] = args
            if (typeof code === 'string' && containsDangerousCode(code)) {
                reportVmViolation(
                    config,
                    'vm.runInNewContext',
                    code,
                    [{ id: 'vm_code_execution', severity: 'critical' }],
                    { category: 'vm_execution', path: 'vm.runInNewContext()' },
                )
            }
            return (originalRunInNewContext as (...fnArgs: unknown[]) => unknown)(code, context, opts)
        }
    }

    if (typeof vm.runInThisContext === 'function') {
        const originalRunInThisContext = vm.runInThisContext.bind(vm)
        vm.runInThisContext = function (...args: unknown[]) {
            const [code, opts] = args
            if (typeof code === 'string' && containsDangerousCode(code)) {
                reportVmViolation(
                    config,
                    'vm.runInThisContext',
                    code,
                    [{ id: 'vm_code_execution', severity: 'critical' }],
                    { category: 'vm_execution', path: 'vm.runInThisContext()' },
                )
            }
            return (originalRunInThisContext as (...fnArgs: unknown[]) => unknown)(code, opts)
        }
    }

    vmHooksInstalled = true
}

function installWorkerThreadHooks(config: ExecRaspConfig): void {
    if (workerHooksInstalled) return
    const require = createRequire(import.meta.url)
    const workerThreads = require('node:worker_threads') as {
        Worker?: new (...args: unknown[]) => unknown
    }
    const WorkerCtor = workerThreads.Worker
    if (typeof WorkerCtor !== 'function') {
        workerHooksInstalled = true
        return
    }

    const wrappedWorker = class extends (WorkerCtor as new (...args: unknown[]) => unknown) {
        constructor(filename: unknown, opts?: { eval?: boolean }) {
            if (opts?.eval && typeof filename === 'string' && containsDangerousCode(filename)) {
                reportVmViolation(
                    config,
                    'worker_threads.Worker(eval)',
                    filename,
                    [{ id: 'worker_eval_execution', severity: 'critical' }],
                    { category: 'worker_execution', path: 'worker_threads.Worker(eval)' },
                )
            } else if (typeof filename === 'string' && !opts?.eval) {
                inspectWorkerPath(filename, config, 'worker_threads.Worker(file)')
            }
            super(filename, opts)
        }
    } as unknown as typeof WorkerCtor

    workerThreads.Worker = wrappedWorker
    workerHooksInstalled = true
}

function installInspectorHooks(config: ExecRaspConfig): void {
    if (inspectorHooksInstalled) return
    const require = createRequire(import.meta.url)
    const inspector = require('node:inspector') as { Session?: unknown }
    const Session: unknown = inspector.Session
    if (typeof Session !== 'function') {
        inspectorHooksInstalled = true
        return
    }

    const sessionCtor = Session as {
        prototype?: {
            post?: (...args: unknown[]) => unknown
        }
    }

    const originalPost = sessionCtor.prototype?.post
    if (typeof originalPost === 'function') {
        sessionCtor.prototype.post = function (...args: unknown[]) {
            const [method, params, cb] = args
            if (method === 'Runtime.evaluate') {
                const expression =
                    typeof params === 'object' && params !== null && 'expression' in (params as Record<string, unknown>)
                        ? String((params as { expression?: unknown }).expression ?? '')
                        : ''
                if (containsDangerousCode(expression)) {
                    inspectCode(expression, config, 'inspector.Runtime.evaluate')
                } else {
                    reportVmViolation(
                        config,
                        'inspector.Runtime.evaluate',
                        expression,
                        [{ id: 'inspector_runtime_evaluate', severity: 'high' }],
                        { category: 'inspector', path: 'inspector.Runtime.evaluate()' },
                    )
                }
            }

            return (originalPost as (...postArgs: unknown[]) => unknown).apply(this, args)
        }
    }

    const wrappedSessionCtor = new Proxy(Session, {
        construct(target, args) {
            const session = Reflect.construct(target as new (...args: unknown[]) => object, args as never[])
            reportVmViolation(
                config,
                'inspector.Session',
                'new Session()',
                [{ id: 'inspector_session_created', severity: 'high' }],
                { category: 'inspector', path: 'inspector.Session' },
            )
            return session
        },
    }) as typeof Session

    inspector.Session = wrappedSessionCtor as unknown as typeof inspector.Session
    inspectorHooksInstalled = true
}

function installLinkedBindingHook(config: ExecRaspConfig): void {
    if (linkedBindingHookInstalled) return

    const originalLinkedBinding = (process as unknown as { _linkedBinding?: (...args: unknown[]) => unknown })._linkedBinding
    if (typeof originalLinkedBinding !== 'function') {
        linkedBindingHookInstalled = true
        return
    }

    const processWithLinkedBinding = process as unknown as { _linkedBinding: (...args: unknown[]) => unknown }
    processWithLinkedBinding._linkedBinding = function (...args: unknown[]) {
        const [bindingName] = args
        if (typeof bindingName === 'string' && (bindingName === 'spawn_sync' || bindingName === 'pipe_wrap' || bindingName === 'tcp_wrap' || bindingName === 'pipe_sync')) {
            reportVmViolation(
                config,
                'process._linkedBinding',
                String(bindingName),
                [{ id: 'native_binding_access', severity: 'critical' }],
                { category: 'linked_binding', path: `process._linkedBinding(${bindingName})` },
            )
        }
        return originalLinkedBinding.apply(processWithLinkedBinding, args)
    }

    linkedBindingHookInstalled = true
}

export function installVmRuntimeHooks(config: ExecRaspConfig, vm: Record<string, unknown>): void {
    installVmModuleHooks(config, vm)
    installWorkerThreadHooks(config)
    installInspectorHooks(config)
    installLinkedBindingHook(config)
}

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
        if (violations.length > 0) {
            recordRaspEvent('exec', cmd, violations.map(v => v.id), action === 'blocked' ? 0.97 : 0.85, action === 'blocked')
        }

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
                config.onViolation({
                    command: cmd.slice(0, 200),
                    invariantClass: violations[0].id,
                    action,
                    confidence: action === 'blocked' ? 0.97 : 0.85,
                    timestamp: now,
                })
            } catch { /* */ }
        }

        if (action === 'blocked') {
            throw new Error(`[INVARIANT] Command execution blocked — ${violations.map(v => v.id).join(', ')} detected.`)
        }

        return originalFn.apply(this, args)
    }

    return wrapped as unknown as T
}
