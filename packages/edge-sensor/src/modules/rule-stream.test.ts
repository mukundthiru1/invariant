import { afterEach, describe, expect, it, vi } from 'vitest'
import {
    consumeRuleEventStream,
    getRuleStreamStatus,
    startRuleStream,
    stopRuleStream,
} from './rule-stream.js'
import type { DynamicRule } from './sensor-state.js'

type TestState = {
    rules: { rules: DynamicRule[]; version: string } | null
    updateRules: (rules: DynamicRule[], version: string, source: string) => void
}

function makeState(): TestState {
    return {
        rules: null,
        updateRules(rules, version) {
            this.rules = { rules, version }
        },
    }
}

function sseResponse(chunks: string[], keepOpen = false): Response {
    const stream = new ReadableStream<Uint8Array>({
        start(controller) {
            for (const chunk of chunks) {
                controller.enqueue(new TextEncoder().encode(chunk))
            }
            if (!keepOpen) {
                controller.close()
            }
        },
    })

    return new Response(stream, {
        status: 200,
        headers: { 'Content-Type': 'text/event-stream' },
    })
}

afterEach(async () => {
    stopRuleStream()
    await new Promise(resolve => setTimeout(resolve, 20))
    vi.restoreAllMocks()
})

describe('rule stream', () => {
    it('establishes SSE connection', async () => {
        const state = makeState()
        const onConnect = vi.fn()

        const task = startRuleStream(state as any, 'https://intel.example', 'token', {
            fetchImpl: vi.fn(async (_url, init) => {
                const signal = (init as RequestInit).signal as AbortSignal
                return new Promise<Response>((resolve) => {
                    const stream = new ReadableStream<Uint8Array>({
                        start(controller) {
                            controller.enqueue(new TextEncoder().encode(': connected\n\n'))
                            signal.addEventListener('abort', () => controller.close(), { once: true })
                        },
                    })
                    resolve(new Response(stream, { status: 200, headers: { 'Content-Type': 'text/event-stream' } }))
                })
            }),
            onConnect,
            reconnectDelayMs: 10,
            maxReconnectDelayMs: 20,
        })

        await vi.waitFor(() => {
            expect(onConnect).toHaveBeenCalled()
            expect(getRuleStreamStatus().connected).toBe(true)
        })

        stopRuleStream()
        await task
    })

    it('applies rule_update events without restart', async () => {
        const state = makeState()
        const payload = {
            type: 'rule_update',
            rules: [{
                ruleId: 'rule-1',
                name: 'Rule 1',
                signalType: 'sqli',
                signalSubtype: null,
                matchType: 'contains',
                patterns: [{ field: 'path', operator: 'contains', value: 'union select' }],
                baseConfidence: 0.9,
                linkedCves: [],
                linkedTechniques: [],
                enabled: true,
            }],
        }

        const response = sseResponse([
            `data: ${JSON.stringify(payload)}\n`,
            '\n',
        ])

        await consumeRuleEventStream(response, state as any, 'https://intel.example/v1/stream')

        expect(state.rules).not.toBeNull()
        expect(state.rules?.rules).toHaveLength(1)
        expect(state.rules?.rules[0]?.ruleId).toBe('rule-1')
        expect(state.rules?.version.startsWith('stream-')).toBe(true)
    })

    it('reconnects after stream disconnect', async () => {
        const state = makeState()
        const fetchImpl = vi.fn(async () => sseResponse([': ping\n\n']))

        const task = startRuleStream(state as any, 'https://intel.example', 'token', {
            fetchImpl,
            reconnectDelayMs: 5,
            maxReconnectDelayMs: 10,
        })

        await vi.waitFor(() => {
            expect(fetchImpl.mock.calls.length).toBeGreaterThanOrEqual(2)
        })

        stopRuleStream()
        await task
    })
})
