import type { InvariantDB, DefenseAction, Severity } from '../db.js'
import { recordRaspEvent } from './request-session.js'

export interface GrpcRaspConfig {
    mode: 'observe' | 'sanitize' | 'defend' | 'lockdown'
    db: InvariantDB
    onViolation?: (violation: GrpcViolation) => void
}

export interface GrpcViolation {
    method: string
    invariantClass: string
    action: DefenseAction
    timestamp: string
}

const GRPC_INVARIANTS = [
    {
        id: 'grpc_proto_pollution',
        test: (payload: string) => /__proto__|constructor\s*["']?\s*:\s*["']?prototype/i.test(payload),
        severity: 'high' as Severity,
    },
    {
        id: 'grpc_command_injection',
        test: (payload: string) => /(?:;|\|\||&&|`|\$\().*(?:cat|bash|sh|curl|wget|powershell)\b/i.test(payload),
        severity: 'critical' as Severity,
    },
    {
        id: 'grpc_sqli_marker',
        test: (payload: string) => /\b(?:union\s+select|or\s+1=1|drop\s+table)\b/i.test(payload),
        severity: 'high' as Severity,
    },
]

function toPayload(input: unknown): string {
    if (typeof input === 'string') return input
    try {
        return JSON.stringify(input)
    } catch {
        return String(input ?? '')
    }
}

function resolveAction(config: GrpcRaspConfig['mode'], violations: Array<{ severity: Severity }>): DefenseAction {
    if (config === 'observe') return 'monitored'
    if (config === 'lockdown') return 'blocked'
    if (config === 'defend') return violations.some(v => v.severity === 'high' || v.severity === 'critical') ? 'blocked' : 'monitored'
    return violations.some(v => v.severity === 'critical') ? 'blocked' : 'monitored'
}

function recordViolation(
    config: GrpcRaspConfig,
    method: string,
    payload: string,
    violations: Array<{ id: string; severity: Severity }>,
    action: DefenseAction,
): void {
    const now = new Date().toISOString()
    recordRaspEvent('deser', payload.slice(0, 200), violations.map(v => v.id), action === 'blocked' ? 0.95 : 0.8, action === 'blocked')
    try {
        config.db.insertSignal({
            type: 'grpc_invariant_violation',
            subtype: violations[0].id,
            severity: violations[0].severity,
            action,
            path: method,
            method: 'gRPC',
            source_hash: null,
            invariant_classes: JSON.stringify(violations.map(v => v.id)),
            is_novel: false,
            timestamp: now,
        })
    } catch {
        // Never break app.
    }
    if (config.onViolation) {
        try {
            config.onViolation({ method, invariantClass: violations[0].id, action, timestamp: now })
        } catch {
            // Never break app.
        }
    }
}

export function wrapGrpcClientMethod<T extends (...args: unknown[]) => unknown>(
    originalFn: T,
    config: GrpcRaspConfig,
    methodName: string,
): T {
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
        const payload = toPayload(args[1] ?? args[0])
        const violations: Array<{ id: string; severity: Severity }> = []
        for (const inv of GRPC_INVARIANTS) {
            try {
                if (inv.test(payload)) violations.push({ id: inv.id, severity: inv.severity })
            } catch {
                // Fail-open.
            }
        }
        if (violations.length === 0) return originalFn.apply(this, args)

        const action = resolveAction(config.mode, violations)
        recordViolation(config, methodName, payload, violations, action)
        if (action === 'blocked') {
            const callback = args.find(a => typeof a === 'function') as ((error: Error) => void) | undefined
            if (callback) {
                callback(new Error(`[INVARIANT] gRPC request blocked: ${violations.map(v => v.id).join(', ')}`))
                return undefined
            }
            throw new Error(`[INVARIANT] gRPC request blocked: ${violations.map(v => v.id).join(', ')}`)
        }
        return originalFn.apply(this, args)
    }
    return wrapped as unknown as T
}

export function wrapGrpcClient(client: Record<string, unknown>, config: GrpcRaspConfig): void {
    for (const [name, value] of Object.entries(client)) {
        if (typeof value !== 'function' || name.startsWith('$')) continue
        ;(client as Record<string, unknown>)[name] = wrapGrpcClientMethod(
            value as (...args: unknown[]) => unknown,
            config,
            `grpc.${name}`,
        )
    }
}
