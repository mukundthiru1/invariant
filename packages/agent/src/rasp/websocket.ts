import type { InvariantDB, DefenseAction, Severity } from '../db.js'
import { recordRaspEvent } from './request-session.js'

export interface WebSocketRaspConfig {
    mode: 'observe' | 'sanitize' | 'defend' | 'lockdown'
    db: InvariantDB
    onViolation?: (violation: WebSocketViolation) => void
}

export interface WebSocketViolation {
    direction: 'inbound' | 'outbound'
    invariantClass: string
    action: DefenseAction
    timestamp: string
}

const WS_INVARIANTS = [
    {
        id: 'ws_payload_size_abuse',
        test: (payload: string) => payload.length > 256_000,
        severity: 'high' as Severity,
    },
    {
        id: 'ws_proto_pollution',
        test: (payload: string) => /__proto__|constructor\s*["']?\s*:\s*["']?prototype/i.test(payload),
        severity: 'high' as Severity,
    },
    {
        id: 'ws_command_injection',
        test: (payload: string) => /(?:;|\|\||&&|`|\$\().*(?:cat|bash|sh|curl|wget|powershell)\b/i.test(payload),
        severity: 'critical' as Severity,
    },
]

function resolveAction(mode: WebSocketRaspConfig['mode'], violations: Array<{ severity: Severity }>): DefenseAction {
    if (mode === 'observe') return 'monitored'
    if (mode === 'lockdown') return 'blocked'
    if (mode === 'defend') {
        return violations.some(v => v.severity === 'critical' || v.severity === 'high') ? 'blocked' : 'monitored'
    }
    return violations.some(v => v.severity === 'critical') ? 'blocked' : 'monitored'
}

function asPayload(input: unknown): string {
    if (typeof input === 'string') return input
    if (input instanceof Uint8Array) return new TextDecoder().decode(input)
    if (ArrayBuffer.isView(input)) return new TextDecoder().decode(new Uint8Array(input.buffer))
    if (input instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(input))
    try {
        return JSON.stringify(input)
    } catch {
        return String(input ?? '')
    }
}

function checkPayload(payload: string): Array<{ id: string; severity: Severity }> {
    const violations: Array<{ id: string; severity: Severity }> = []
    for (const inv of WS_INVARIANTS) {
        try {
            if (inv.test(payload)) violations.push({ id: inv.id, severity: inv.severity })
        } catch {
            // Fail-open.
        }
    }
    return violations
}

function recordViolation(
    config: WebSocketRaspConfig,
    direction: 'inbound' | 'outbound',
    payload: string,
    violations: Array<{ id: string; severity: Severity }>,
    action: DefenseAction,
): void {
    const now = new Date().toISOString()
    recordRaspEvent('deser', payload.slice(0, 200), violations.map(v => v.id), action === 'blocked' ? 0.95 : 0.8, action === 'blocked')
    try {
        config.db.insertSignal({
            type: 'ws_invariant_violation',
            subtype: violations[0].id,
            severity: violations[0].severity,
            action,
            path: `ws.${direction}`,
            method: 'WS',
            source_hash: null,
            invariant_classes: JSON.stringify(violations.map(v => v.id)),
            is_novel: false,
            timestamp: now,
        })
    } catch {
        // Never break host app.
    }
    if (config.onViolation) {
        try {
            config.onViolation({ direction, invariantClass: violations[0].id, action, timestamp: now })
        } catch {
            // Never break host app.
        }
    }
}

export function wrapWebSocketServer(server: Record<string, unknown>, config: WebSocketRaspConfig): void {
    const on = server.on as ((event: string, listener: (...args: unknown[]) => unknown) => unknown) | undefined
    if (typeof on !== 'function') return
    ;(server as { on: typeof on }).on = function wrappedOn(
        this: unknown,
        event: string,
        listener: (...args: unknown[]) => unknown,
    ): unknown {
        if (event !== 'message' || typeof listener !== 'function') {
            return on.call(this, event, listener)
        }
        const wrappedListener = function (this: unknown, ...args: unknown[]): unknown {
            const payload = asPayload(args[0])
            const violations = checkPayload(payload)
            if (violations.length === 0) return listener.apply(this, args)
            const action = resolveAction(config.mode, violations)
            recordViolation(config, 'inbound', payload, violations, action)
            if (action === 'blocked') return undefined
            return listener.apply(this, args)
        }
        return on.call(this, event, wrappedListener)
    }
}

export function wrapWebSocketSend<T extends (...args: unknown[]) => unknown>(
    originalSend: T,
    config: WebSocketRaspConfig,
): T {
    const wrapped = function (this: unknown, ...args: unknown[]): unknown {
        const payload = asPayload(args[0])
        const violations = checkPayload(payload)
        if (violations.length === 0) return originalSend.apply(this, args)
        const action = resolveAction(config.mode, violations)
        recordViolation(config, 'outbound', payload, violations, action)
        if (action === 'blocked') return undefined
        return originalSend.apply(this, args)
    }
    return wrapped as unknown as T
}
