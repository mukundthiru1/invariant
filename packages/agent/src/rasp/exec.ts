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
import { isAbsolute, relative, resolve } from 'node:path'
import { recordRaspEvent } from './request-session.js'
import { InvariantEngine } from '../../../engine/src/invariant-engine.js'

const CODE_ENGINE_CONFIDENCE_THRESHOLD = 0.7
const codeEngine = new InvariantEngine()

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

/** Run InvariantEngine.detect() on code string; return violations with confidence > threshold. */
function engineDetectCode(code: string): Array<VmInvariant> {
    if (typeof code !== 'string' || code.length === 0) return []
    try {
        const matches = codeEngine.detect(code, [], 'javascript')
        const violations: Array<VmInvariant> = []
        for (const m of matches) {
            if (m.confidence > CODE_ENGINE_CONFIDENCE_THRESHOLD) {
                violations.push({ id: m.class, severity: (m.severity ?? 'high') as Severity })
            }
        }
        return violations
    } catch {
        return []
    }
}

/** Combined check: dangerous patterns OR engine detection above threshold. */
function inspectCodeForVm(code: string): Array<VmInvariant> {
    const byPattern = containsDangerousCode(code) ? [{ id: 'vm_code_execution', severity: 'critical' as Severity }] : []
    const byEngine = engineDetectCode(code)
    const seen = new Set<string>()
    const out: Array<VmInvariant> = []
    for (const v of [...byPattern, ...byEngine]) {
        if (!seen.has(v.id)) { seen.add(v.id); out.push(v) }
    }
    return out
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
let processBindingHookInstalled = false
let processDlopenHookInstalled = false
let functionHookInstalled = false
let resolveFilenameHookInstalled = false

const storedOriginals: {
    vm?: { runInContext?: (...args: unknown[]) => unknown; runInNewContext?: (...args: unknown[]) => unknown; runInThisContext?: (...args: unknown[]) => unknown; compileFunction?: (...args: unknown[]) => unknown; Script?: new (...args: unknown[]) => unknown }
    workerThreads?: { Worker: new (...args: unknown[]) => unknown }
    inspector?: { Session: new (...args: unknown[]) => unknown; sessionPost?: (...args: unknown[]) => unknown }
    linkedBinding?: (...args: unknown[]) => unknown
    processBinding?: (...args: unknown[]) => unknown
    processDlopen?: (...args: unknown[]) => unknown
    Function?: (...args: unknown[]) => unknown
    resolveFilename?: (request: string, parent: unknown, isMain: boolean, options?: unknown) => string
} = {}
const wrappedRefs: {
    vmRunInContext?: (...args: unknown[]) => unknown
    vmRunInNewContext?: (...args: unknown[]) => unknown
    vmRunInThisContext?: (...args: unknown[]) => unknown
    vmCompileFunction?: (...args: unknown[]) => unknown
    vmScript?: new (...args: unknown[]) => unknown
    resolveFilename?: (request: string, parent: unknown, isMain: boolean, options?: unknown) => string
    processBinding?: (...args: unknown[]) => unknown
    processDlopen?: (...args: unknown[]) => unknown
} = {}

function isOutsideCwd(absPath: string): boolean {
    const fromCwd = relative(process.cwd(), resolve(absPath))
    if (fromCwd === '') return false
    return fromCwd === '..' || fromCwd.startsWith(`..${'/'}`) || fromCwd.startsWith(`..${'\\'}`)
}

function isSuspiciousForkModulePath(modulePath: string): boolean {
    const normalized = modulePath.replace(/\\/g, '/')
    const isNodeModulesPath = normalized.includes('/node_modules/') || normalized.startsWith('node_modules/') || normalized.endsWith('/node_modules')
    const absoluteOutsideCwd = isAbsolute(modulePath) && isOutsideCwd(modulePath)
    return !isNodeModulesPath || absoluteOutsideCwd
}

function isSuspiciousNativeAddonPath(filePath: string): boolean {
    if (/^(?:https?|data|file):/i.test(filePath)) return true
    if (/(?:^|[\\/])\.\.(?:[\\/]|$)|%2e%2e/i.test(filePath)) return true
    if (isAbsolute(filePath) && isOutsideCwd(filePath)) return true
    const normalized = filePath.replace(/\\/g, '/')
    return !normalized.includes('/node_modules/')
}

function installFunctionConstructorHook(config: ExecRaspConfig): void {
    if (functionHookInstalled) return
    const g = globalThis as unknown as { Function: (...args: string[]) => CallableFunction }
    const OriginalFunction = g.Function
    if (typeof OriginalFunction !== 'function') {
        functionHookInstalled = true
        return
    }
    storedOriginals.Function = OriginalFunction as unknown as (...args: unknown[]) => unknown
    try {
        const WrappedFunction = function (this: unknown, ...args: unknown[]): unknown {
            try {
                if (args.length >= 1) {
                    const body = args[args.length - 1]
                    if (typeof body === 'string') {
                        const violations = inspectCodeForVm(body)
                        if (violations.length > 0) {
                            reportVmViolation(config, 'Function()', body, violations, { category: 'vm_execution', path: 'Function()' })
                        }
                    }
                }
            } catch (err) {
                if (err instanceof Error && err.message.includes('[INVARIANT]')) throw err
                console.warn('[invariant] exec RASP: Function() hook error', err)
            }
            return OriginalFunction.apply(this, args as string[])
        }
        Object.defineProperty(g, 'Function', {
            value: WrappedFunction,
            writable: true,
            configurable: true,
            enumerable: false,
        })
    } catch (err) {
        console.warn('[invariant] exec RASP: Function constructor hook install error', err)
        throw err
    }
    functionHookInstalled = true
}

function installResolveFilenameHook(config: ExecRaspConfig): void {
    if (resolveFilenameHookInstalled) return
    try {
        const require = createRequire(import.meta.url)
        const Mod = require('node:module') as { _resolveFilename: (request: string, parent: unknown, isMain: boolean, options?: unknown) => string }
        const original = Mod._resolveFilename
        storedOriginals.resolveFilename = original
        const wrapped = function (this: unknown, request: string, parent: unknown, isMain: boolean, options?: unknown): string {
            const result = original.call(this, request, parent, isMain, options)
            const suspicious = /(?:^|[\\/])\.\.(?:[\\/]|$)|%2e%2e/i.test(request) || /^[\\/]|^\w:[\\/]/.test(request)
            if (suspicious && config.mode !== 'observe') {
                try {
                    recordRaspEvent('vm_code_execution', request, ['dynamic_import_unexpected'], 0.75, false)
                    config.db.insertSignal({
                        type: 'runtime_invariant_violation',
                        subtype: 'dynamic_import_unexpected',
                        severity: 'medium',
                        action: 'monitored',
                        path: 'Module._resolveFilename',
                        method: 'IMPORT',
                        source_hash: null,
                        invariant_classes: JSON.stringify(['dynamic_import_unexpected']),
                        is_novel: false,
                        timestamp: new Date().toISOString(),
                    })
                } catch { /* never break */ }
            }
            return result
        }
        wrappedRefs.resolveFilename = wrapped
        Mod._resolveFilename = wrapped
    } catch (err) {
        console.warn('[invariant] exec RASP: Module._resolveFilename hook install error', err)
        throw err
    }
    resolveFilenameHookInstalled = true
}

function installVmModuleHooks(config: ExecRaspConfig, vm: Record<string, unknown>): void {
    if (vmHooksInstalled) return
    try {
        if (typeof vm.runInContext === 'function') {
            const originalRunInContext = vm.runInContext.bind(vm) as (...args: unknown[]) => unknown
            storedOriginals.vm = storedOriginals.vm ?? {}
            storedOriginals.vm.runInContext = originalRunInContext
            const wrapped = function (...args: unknown[]) {
                const [code, context, opts] = args
                try {
                    if (typeof code === 'string') {
                        const violations = inspectCodeForVm(code)
                        if (violations.length > 0) {
                            reportVmViolation(config, 'vm.runInContext', code, violations, { category: 'vm_execution', path: 'vm.runInContext()' })
                        }
                    }
                } catch (err) {
                    if (err instanceof Error && err.message.includes('[INVARIANT]')) throw err
                    console.warn('[invariant] exec RASP: vm.runInContext hook error', err)
                }
                return originalRunInContext(code, context, opts)
            }
            wrappedRefs.vmRunInContext = wrapped
            vm.runInContext = wrapped
        }

        if (typeof vm.runInNewContext === 'function') {
            const originalRunInNewContext = vm.runInNewContext.bind(vm) as (...args: unknown[]) => unknown
            storedOriginals.vm = storedOriginals.vm ?? {}
            storedOriginals.vm.runInNewContext = originalRunInNewContext
            const wrapped = function (...args: unknown[]) {
                const [code, context, opts] = args
                try {
                    if (typeof code === 'string') {
                        const violations = inspectCodeForVm(code)
                        if (violations.length > 0) {
                            reportVmViolation(config, 'vm.runInNewContext', code, violations, { category: 'vm_execution', path: 'vm.runInNewContext()' })
                        }
                    }
                } catch (err) {
                    if (err instanceof Error && err.message.includes('[INVARIANT]')) throw err
                    console.warn('[invariant] exec RASP: vm.runInNewContext hook error', err)
                }
                return originalRunInNewContext(code, context, opts)
            }
            wrappedRefs.vmRunInNewContext = wrapped
            vm.runInNewContext = wrapped
        }

        if (typeof vm.runInThisContext === 'function') {
            const originalRunInThisContext = vm.runInThisContext.bind(vm) as (...args: unknown[]) => unknown
            storedOriginals.vm = storedOriginals.vm ?? {}
            storedOriginals.vm.runInThisContext = originalRunInThisContext
            const wrapped = function (...args: unknown[]) {
                const [code, opts] = args
                try {
                    if (typeof code === 'string') {
                        const violations = inspectCodeForVm(code)
                        if (violations.length > 0) {
                            reportVmViolation(config, 'vm.runInThisContext', code, violations, { category: 'vm_execution', path: 'vm.runInThisContext()' })
                        }
                    }
                } catch (err) {
                    if (err instanceof Error && err.message.includes('[INVARIANT]')) throw err
                    console.warn('[invariant] exec RASP: vm.runInThisContext hook error', err)
                }
                return originalRunInThisContext(code, opts)
            }
            wrappedRefs.vmRunInThisContext = wrapped
            vm.runInThisContext = wrapped
        }

        if (typeof vm.compileFunction === 'function') {
            const originalCompileFunction = vm.compileFunction.bind(vm) as (...args: unknown[]) => unknown
            storedOriginals.vm = storedOriginals.vm ?? {}
            storedOriginals.vm.compileFunction = originalCompileFunction
            const wrapped = function (...args: unknown[]) {
                const [code] = args
                try {
                    if (typeof code === 'string') {
                        const violations = inspectCodeForVm(code)
                        if (violations.length > 0) {
                            reportVmViolation(config, 'vm.compileFunction', code, violations, { category: 'vm_execution', path: 'vm.compileFunction()' })
                        }
                    }
                } catch (err) {
                    if (err instanceof Error && err.message.includes('[INVARIANT]')) throw err
                    console.warn('[invariant] exec RASP: vm.compileFunction hook error', err)
                }
                return originalCompileFunction(...args)
            }
            wrappedRefs.vmCompileFunction = wrapped
            vm.compileFunction = wrapped
        }

        const ScriptCtor = vm.Script as unknown as abstract new (code: string, options?: unknown) => { runInContext: unknown; runInNewContext: unknown }
        if (typeof ScriptCtor === 'function') {
            storedOriginals.vm = storedOriginals.vm ?? {}
            storedOriginals.vm.Script = ScriptCtor as unknown as new (...args: unknown[]) => unknown
            class WrappedScript extends (ScriptCtor as abstract new (code: string, options?: unknown) => { runInContext: unknown; runInNewContext: unknown }) {
                constructor(code: string, options?: unknown) {
                    if (typeof code === 'string') {
                        const violations = inspectCodeForVm(code)
                        if (violations.length > 0) {
                            reportVmViolation(config, 'vm.Script', code, violations, { category: 'vm_execution', path: 'vm.Script()' })
                        }
                    }
                    super(code, options)
                }
            }
            wrappedRefs.vmScript = WrappedScript as new (...args: unknown[]) => unknown
            vm.Script = WrappedScript as typeof vm.Script
        }
    } catch (err) {
        console.warn('[invariant] exec RASP: vm hook install error', err)
        if (storedOriginals.vm) {
            if (storedOriginals.vm.runInContext) vm.runInContext = storedOriginals.vm.runInContext as typeof vm.runInContext
            if (storedOriginals.vm.runInNewContext) vm.runInNewContext = storedOriginals.vm.runInNewContext as typeof vm.runInNewContext
            if (storedOriginals.vm.runInThisContext) vm.runInThisContext = storedOriginals.vm.runInThisContext as typeof vm.runInThisContext
            if (storedOriginals.vm.compileFunction) vm.compileFunction = storedOriginals.vm.compileFunction as typeof vm.compileFunction
            if (storedOriginals.vm.Script) vm.Script = storedOriginals.vm.Script as typeof vm.Script
        }
        throw err
    }
    vmHooksInstalled = true
}

function installWorkerThreadHooks(config: ExecRaspConfig): void {
    if (workerHooksInstalled) return
    try {
        const require = createRequire(import.meta.url)
        const workerThreads = require('node:worker_threads') as { Worker?: new (...args: unknown[]) => unknown }
        const WorkerCtor = workerThreads.Worker
        if (typeof WorkerCtor !== 'function') {
            workerHooksInstalled = true
            return
        }
        storedOriginals.workerThreads = { Worker: WorkerCtor }
        const wrappedWorker = class extends (WorkerCtor as abstract new (...args: unknown[]) => object) {
            constructor(filename: unknown, opts?: { eval?: boolean }) {
                if (opts?.eval && typeof filename === 'string') {
                    let violations = inspectCodeForVm(filename)
                    if (violations.length === 0 && containsDangerousCode(filename)) {
                        violations = [{ id: 'worker_eval_execution', severity: 'critical' }]
                    }
                    if (violations.length > 0) {
                        reportVmViolation(
                            config,
                            'worker_threads.Worker(eval)',
                            filename,
                            violations,
                            { category: 'worker_execution', path: 'worker_threads.Worker(eval)' },
                        )
                    }
                } else if (typeof filename === 'string' && !opts?.eval) {
                    inspectWorkerPath(filename, config, 'worker_threads.Worker(file)')
                }
                super(filename, opts)
            }
        } as unknown as typeof WorkerCtor
        workerThreads.Worker = wrappedWorker
    } catch (err) {
        console.warn('[invariant] exec RASP: worker_threads hook install error', err)
        if (storedOriginals.workerThreads) {
            const require = createRequire(import.meta.url)
            const wt = require('node:worker_threads') as { Worker?: new (...args: unknown[]) => unknown }
            wt.Worker = storedOriginals.workerThreads.Worker
        }
        throw err
    }
    workerHooksInstalled = true
}

function installInspectorHooks(config: ExecRaspConfig): void {
    if (inspectorHooksInstalled) return
    try {
        const require = createRequire(import.meta.url)
        const inspector = require('node:inspector') as { Session?: unknown }
        const Session: unknown = inspector.Session
        if (typeof Session !== 'function') {
            inspectorHooksInstalled = true
            return
        }
        storedOriginals.inspector = { Session: Session as new (...args: unknown[]) => unknown }
        const sessionCtor = Session as { prototype?: unknown }
        const sessionPrototype = sessionCtor.prototype as Record<string, unknown> | undefined
        const originalPost = sessionPrototype?.['post'] as ((...args: unknown[]) => unknown) | undefined
        if (typeof originalPost === 'function') {
            storedOriginals.inspector.sessionPost = originalPost
            ;(sessionPrototype as { post?: (...args: unknown[]) => unknown }).post = function (...args: unknown[]) {
                const [method, params] = args
                if (method === 'Runtime.evaluate') {
                    const expression =
                        typeof params === 'object' && params !== null && 'expression' in (params as Record<string, unknown>)
                            ? String((params as { expression?: unknown }).expression ?? '')
                            : ''
                    const violations = inspectCodeForVm(expression)
                    if (violations.length > 0) {
                        reportVmViolation(config, 'inspector.Runtime.evaluate', expression, violations, { category: 'inspector', path: 'inspector.Runtime.evaluate()' })
                    } else if (expression.length > 0) {
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
    } catch (err) {
        console.warn('[invariant] exec RASP: inspector hook install error', err)
        throw err
    }
    inspectorHooksInstalled = true
}

function installLinkedBindingHook(config: ExecRaspConfig): void {
    if (linkedBindingHookInstalled) return
    const originalLinkedBinding = (process as unknown as { _linkedBinding?: (...args: unknown[]) => unknown })._linkedBinding
    if (typeof originalLinkedBinding !== 'function') {
        linkedBindingHookInstalled = true
        return
    }
    storedOriginals.linkedBinding = originalLinkedBinding
    const processWithLinkedBinding = process as unknown as { _linkedBinding: (...args: unknown[]) => unknown }
    try {
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
    } catch (err) {
        console.warn('[invariant] exec RASP: _linkedBinding hook install error', err)
        processWithLinkedBinding._linkedBinding = originalLinkedBinding
        throw err
    }
    linkedBindingHookInstalled = true
}

function installProcessBindingHook(config: ExecRaspConfig): void {
    if (processBindingHookInstalled) return
    const processWithBinding = process as unknown as { binding?: (...args: unknown[]) => unknown }
    const originalBinding = processWithBinding.binding
    if (typeof originalBinding !== 'function') {
        processBindingHookInstalled = true
        return
    }
    storedOriginals.processBinding = originalBinding
    const wrappedBinding = new Proxy(originalBinding, {
        apply(target, thisArg, args) {
            const [name] = args
            if (typeof name === 'string' && ['fs', 'binding', 'os', 'crypto'].includes(name)) {
                reportVmViolation(
                    config,
                    'process.binding',
                    name,
                    [{ id: 'process_binding_access', severity: 'high' }],
                    { category: 'native_binding', path: `process.binding(${name})` },
                )
            }
            return Reflect.apply(target as (...callArgs: unknown[]) => unknown, thisArg, args)
        },
    })
    processWithBinding.binding = wrappedBinding
    wrappedRefs.processBinding = wrappedBinding
    processBindingHookInstalled = true
}

function installProcessDlopenHook(config: ExecRaspConfig): void {
    if (processDlopenHookInstalled) return
    const processWithDlopen = process as unknown as { dlopen?: (...args: unknown[]) => unknown }
    const originalDlopen = processWithDlopen.dlopen
    if (typeof originalDlopen !== 'function') {
        processDlopenHookInstalled = true
        return
    }
    storedOriginals.processDlopen = originalDlopen
    const wrappedDlopen = function (this: unknown, ...args: unknown[]): unknown {
        const [, filePath] = args
        if (typeof filePath === 'string' && isSuspiciousNativeAddonPath(filePath)) {
            reportVmViolation(
                config,
                'process.dlopen',
                filePath,
                [{ id: 'process_dlopen_suspicious_path', severity: 'critical' }],
                { category: 'native_binding', path: `process.dlopen(${filePath})` },
            )
        }
        return originalDlopen.apply(this, args)
    }
    processWithDlopen.dlopen = wrappedDlopen
    wrappedRefs.processDlopen = wrappedDlopen
    processDlopenHookInstalled = true
}

export function installVmRuntimeHooks(config: ExecRaspConfig, vm: Record<string, unknown>): void {
    installVmModuleHooks(config, vm)
    installWorkerThreadHooks(config)
    installInspectorHooks(config)
    installLinkedBindingHook(config)
    installProcessBindingHook(config)
    installProcessDlopenHook(config)
    installFunctionConstructorHook(config)
    installResolveFilenameHook(config)
}

/**
 * Restore all RASP hooks to their original implementations.
 * Call on shutdown/cleanup so the process can exit or re-initialize cleanly.
 */
export function uninstallVmRuntimeHooks(vm: Record<string, unknown>): void {
    if (storedOriginals.vm) {
        if (storedOriginals.vm.runInContext) vm.runInContext = storedOriginals.vm.runInContext as typeof vm.runInContext
        if (storedOriginals.vm.runInNewContext) vm.runInNewContext = storedOriginals.vm.runInNewContext as typeof vm.runInNewContext
        if (storedOriginals.vm.runInThisContext) vm.runInThisContext = storedOriginals.vm.runInThisContext as typeof vm.runInThisContext
        if (storedOriginals.vm.compileFunction) vm.compileFunction = storedOriginals.vm.compileFunction as typeof vm.compileFunction
        if (storedOriginals.vm.Script) vm.Script = storedOriginals.vm.Script as typeof vm.Script
        storedOriginals.vm = undefined
    }
    vmHooksInstalled = false
    if (storedOriginals.workerThreads) {
        const require = createRequire(import.meta.url)
        const wt = require('node:worker_threads') as { Worker?: new (...args: unknown[]) => unknown }
        wt.Worker = storedOriginals.workerThreads.Worker
        storedOriginals.workerThreads = undefined
    }
    workerHooksInstalled = false
    if (storedOriginals.inspector) {
        const require = createRequire(import.meta.url)
        const inspector = require('node:inspector') as { Session?: unknown }
        if (storedOriginals.inspector.Session) inspector.Session = storedOriginals.inspector.Session
        if (storedOriginals.inspector.sessionPost) {
            const Session = inspector.Session as { prototype?: { post?: (...args: unknown[]) => unknown } }
            if (Session?.prototype) Session.prototype.post = storedOriginals.inspector.sessionPost
        }
        storedOriginals.inspector = undefined
    }
    inspectorHooksInstalled = false
    if (storedOriginals.linkedBinding) {
        (process as unknown as { _linkedBinding: (...args: unknown[]) => unknown })._linkedBinding = storedOriginals.linkedBinding
        storedOriginals.linkedBinding = undefined
    }
    linkedBindingHookInstalled = false
    if (storedOriginals.processBinding) {
        ;(process as unknown as { binding: (...args: unknown[]) => unknown }).binding = storedOriginals.processBinding
        storedOriginals.processBinding = undefined
    }
    processBindingHookInstalled = false
    if (storedOriginals.processDlopen) {
        ;(process as unknown as { dlopen: (...args: unknown[]) => unknown }).dlopen = storedOriginals.processDlopen
        storedOriginals.processDlopen = undefined
    }
    processDlopenHookInstalled = false
    if (storedOriginals.Function) {
        Object.defineProperty(globalThis, 'Function', { value: storedOriginals.Function, writable: true, configurable: true, enumerable: false })
        storedOriginals.Function = undefined
    }
    functionHookInstalled = false
    if (storedOriginals.resolveFilename) {
        const require = createRequire(import.meta.url)
        const Mod = require('node:module') as { _resolveFilename: (request: string, parent: unknown, isMain: boolean, options?: unknown) => string }
        Mod._resolveFilename = storedOriginals.resolveFilename
        storedOriginals.resolveFilename = undefined
    }
    resolveFilenameHookInstalled = false
}

/**
 * Verify that RASP hooks are still in place. Call periodically to detect tampering.
 * Returns an object with a boolean per hook surface; true means the hook is still active.
 */
export function hookIntegrityCheck(vm: Record<string, unknown>): {
    vmRunInContext: boolean
    vmRunInNewContext: boolean
    vmRunInThisContext: boolean
    vmCompileFunction: boolean
    vmScript: boolean
    workerThreads: boolean
    resolveFilename: boolean
    processBinding: boolean
    processDlopen: boolean
} {
    const require = createRequire(import.meta.url)
    const Mod = require('node:module') as { _resolveFilename: (request: string, parent: unknown, isMain: boolean, options?: unknown) => string }
    const wt = require('node:worker_threads') as { Worker?: new (...args: unknown[]) => unknown }
    return {
        vmRunInContext: wrappedRefs.vmRunInContext !== undefined && vm.runInContext === wrappedRefs.vmRunInContext,
        vmRunInNewContext: wrappedRefs.vmRunInNewContext !== undefined && vm.runInNewContext === wrappedRefs.vmRunInNewContext,
        vmRunInThisContext: wrappedRefs.vmRunInThisContext !== undefined && vm.runInThisContext === wrappedRefs.vmRunInThisContext,
        vmCompileFunction: wrappedRefs.vmCompileFunction !== undefined && vm.compileFunction === wrappedRefs.vmCompileFunction,
        vmScript: wrappedRefs.vmScript !== undefined && vm.Script === wrappedRefs.vmScript,
        workerThreads: storedOriginals.workerThreads !== undefined && wt.Worker !== storedOriginals.workerThreads.Worker,
        resolveFilename: wrappedRefs.resolveFilename !== undefined && Mod._resolveFilename === wrappedRefs.resolveFilename,
        processBinding: wrappedRefs.processBinding !== undefined && (process as unknown as { binding?: (...args: unknown[]) => unknown }).binding === wrappedRefs.processBinding,
        processDlopen: wrappedRefs.processDlopen !== undefined && (process as unknown as { dlopen?: (...args: unknown[]) => unknown }).dlopen === wrappedRefs.processDlopen,
    }
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

export function wrapFork<T extends (...args: unknown[]) => unknown>(
    originalFn: T,
    config: ExecRaspConfig,
): T {
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
        const modulePath = typeof args[0] === 'string' ? args[0] : ''
        if (!modulePath) return originalFn.apply(this, args)
        if (!isSuspiciousForkModulePath(modulePath)) return originalFn.apply(this, args)

        const violation = { id: 'fork_suspicious_module_path', severity: 'high' as Severity }
        const action: DefenseAction =
            config.mode === 'observe' ? 'monitored' :
                config.mode === 'lockdown' ? 'blocked' :
                    'monitored'
        const now = new Date().toISOString()

        try {
            recordRaspEvent('exec', modulePath, [violation.id], action === 'blocked' ? 0.96 : 0.82, action === 'blocked')
            config.db.insertSignal({
                type: 'cmd_invariant_violation',
                subtype: violation.id,
                severity: violation.severity,
                action,
                path: 'child_process.fork()',
                method: 'EXEC',
                source_hash: null,
                invariant_classes: JSON.stringify([violation.id]),
                is_novel: false,
                timestamp: now,
            })
            config.db.insertFinding({
                type: 'runtime_invariant_violation',
                category: 'cmdi',
                severity: violation.severity,
                status: 'open',
                title: `Fork module path risk: ${violation.id}`,
                description: `Detected suspicious child_process.fork() modulePath: ${modulePath.slice(0, 200)}`,
                location: 'child_process.fork()',
                evidence: JSON.stringify({ modulePath: modulePath.slice(0, 200), violation: violation.id }),
                remediation: 'Only fork trusted module paths under your app root or node_modules; reject untrusted absolute/relative traversal paths.',
                cve_id: null,
                confidence: action === 'blocked' ? 0.96 : 0.82,
                first_seen: now,
                last_seen: now,
                rasp_active: action === 'blocked',
            })
        } catch { /* Never break */ }

        if (config.onViolation) {
            try {
                config.onViolation({
                    command: modulePath.slice(0, 200),
                    invariantClass: violation.id,
                    action,
                    confidence: action === 'blocked' ? 0.96 : 0.82,
                    timestamp: now,
                })
            } catch { /* Never break */ }
        }

        if (action === 'blocked') {
            throw new Error(`[INVARIANT] child_process.fork blocked — ${violation.id} detected.`)
        }
        return originalFn.apply(this, args)
    }

    return wrapped as unknown as T
}

export function wrapExecFile<T extends (...args: unknown[]) => unknown>(
    originalFn: T,
    config: ExecRaspConfig,
    fnName: 'execFile' | 'execFileSync',
): T {
    return wrapExec(originalFn, config, fnName)
}
