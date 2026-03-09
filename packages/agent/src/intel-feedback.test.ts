import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

describe('intel feedback batching', () => {
    const originalEnv = { ...process.env }
    const originalFetch = globalThis.fetch

    beforeEach(() => {
        vi.useFakeTimers()
        vi.resetModules()
        process.env = { ...originalEnv }
    })

    afterEach(() => {
        vi.useRealTimers()
        process.env = { ...originalEnv }
        globalThis.fetch = originalFetch
        vi.restoreAllMocks()
    })

    it('queues signals without flushing before threshold or interval', async () => {
        process.env.SANTH_INTEL_URL = 'https://intel.example'
        process.env.SANTH_API_KEY = 'test-key'

        const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 202 }))
        globalThis.fetch = fetchSpy as unknown as typeof globalThis.fetch

        const { queueSignal } = await import('./intel-feedback.js')
        queueSignal('cmd_injection', 'abcd1234', 0.95)

        expect(fetchSpy).not.toHaveBeenCalled()
    })

    it('flushes immediately when buffer reaches 50 events', async () => {
        process.env.SANTH_INTEL_URL = 'https://intel.example'
        process.env.SANTH_API_KEY = 'test-key'

        const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 202 }))
        globalThis.fetch = fetchSpy as unknown as typeof globalThis.fetch

        const { queueSignal } = await import('./intel-feedback.js')
        for (let i = 0; i < 50; i++) {
            queueSignal(`class_${i}`, `hash_${i}`, 0.9)
        }

        await Promise.resolve()
        await Promise.resolve()

        expect(fetchSpy).toHaveBeenCalledTimes(50)
    })

    it('flushes pending signals on 60 second interval', async () => {
        process.env.SANTH_INTEL_URL = 'https://intel.example'
        process.env.SANTH_API_KEY = 'test-key'

        const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 202 }))
        globalThis.fetch = fetchSpy as unknown as typeof globalThis.fetch

        const { queueSignal } = await import('./intel-feedback.js')
        queueSignal('sqli', 'deadbeef', 0.88)

        await vi.advanceTimersByTimeAsync(60_000)
        await Promise.resolve()

        expect(fetchSpy).toHaveBeenCalledTimes(1)
        expect(fetchSpy.mock.calls[0]?.[0]).toBe('https://intel.example/v1/signal')
    })
})
