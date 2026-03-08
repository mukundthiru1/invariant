import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
    finalizeRequestSession,
    getCurrentSession,
    recordRaspEvent,
    runWithSession,
    startRequestSession,
} from './rasp/request-session.js'

describe('RequestSession cross-RASP aggregation', () => {
    beforeEach(() => {
        vi.useFakeTimers()
        vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
    })

    afterEach(() => {
        vi.useRealTimers()
    })

    it('recordRaspEvent with single surface does not produce compound on finalizeRequestSession()', () => {
        const compound = runWithSession({ sourceHash: 'single-surface' }, () => {
            recordRaspEvent('sql', "SELECT * FROM users WHERE id = '1'", ['sql_tautology'], 0.82, false)
            return finalizeRequestSession()
        })

        expect(compound).toBeNull()
    })

    it("recordRaspEvent('sql', ...) + recordRaspEvent('http', ...) produces compound with isCompound=true and compoundConfidence=0.95", () => {
        const compound = runWithSession({ sourceHash: 'two-surfaces' }, () => {
            recordRaspEvent('sql', "SELECT * FROM users WHERE id = '' OR 1=1--", ['sql_tautology'], 0.9, true)
            recordRaspEvent('http', 'http://127.0.0.1/admin', ['ssrf_internal_reach'], 0.91, true)
            return finalizeRequestSession()
        })

        expect(compound).not.toBeNull()
        expect(compound!.isCompound).toBe(true)
        expect(compound!.compoundConfidence).toBe(0.95)
        expect(compound!.surfaces).toEqual(['sql', 'http'])
    })

    it('recordRaspEvent on 3 different surfaces produces compound with compoundConfidence=0.99', () => {
        const compound = runWithSession({ sourceHash: 'three-surfaces' }, () => {
            recordRaspEvent('sql', "SELECT * FROM users WHERE id = '' OR 1=1--", ['sql_tautology'], 0.9, false)
            recordRaspEvent('http', 'http://169.254.169.254/latest/meta-data/', ['ssrf_cloud_metadata'], 0.95, true)
            recordRaspEvent('exec', '; cat /etc/passwd', ['cmd_separator'], 0.88, true)
            return finalizeRequestSession()
        })

        expect(compound).not.toBeNull()
        expect(compound!.isCompound).toBe(true)
        expect(compound!.compoundConfidence).toBe(0.99)
        expect(compound!.surfaces).toEqual(['sql', 'http', 'exec'])
    })

    it('getCurrentSession() returns undefined when called outside startRequestSession() context', () => {
        expect(getCurrentSession()).toBeUndefined()
    })

    it('runWithSession runs the function in a session context and returns its return value', () => {
        const result = runWithSession({ sourceHash: 'return-value' }, () => {
            const active = getCurrentSession()
            expect(active).toBeDefined()
            return 'ok-value'
        })

        expect(result).toBe('ok-value')
    })

    it("two concurrent runWithSession calls don't interfere with each other's events (AsyncLocalStorage isolation)", async () => {
        const [a, b] = await Promise.all([
            runWithSession({ sourceHash: 'session-a' }, async () => {
                recordRaspEvent('sql', 'a-sql', ['sql_tautology'], 0.91, true)
                await Promise.resolve()
                recordRaspEvent('http', 'a-http', ['ssrf_internal_reach'], 0.89, true)
                return finalizeRequestSession()
            }),
            runWithSession({ sourceHash: 'session-b' }, async () => {
                recordRaspEvent('exec', 'b-exec', ['cmd_separator'], 0.86, true)
                await Promise.resolve()
                return finalizeRequestSession()
            }),
        ])

        expect(a).not.toBeNull()
        expect(a!.surfaces).toEqual(['sql', 'http'])
        expect(a!.events.map(e => e.context)).toEqual(['a-sql', 'a-http'])

        expect(b).toBeNull()
    })

    it('finalizeRequestSession() returns null when no attacking events (all events with matches=[])', () => {
        const result = runWithSession({ sourceHash: 'benign-events' }, () => {
            recordRaspEvent('sql', 'SELECT 1', [], 0.01, false)
            recordRaspEvent('http', 'https://example.com', [], 0.02, false)
            return finalizeRequestSession()
        })

        expect(result).toBeNull()
    })

    it('events accumulate in order and are all accessible from finalizeRequestSession().events', () => {
        const result = runWithSession({ sourceHash: 'ordered-events' }, () => {
            recordRaspEvent('sql', 'event-1', ['sql_tautology'], 0.8, true)
            vi.advanceTimersByTime(1)
            recordRaspEvent('http', 'event-2', ['ssrf_internal_reach'], 0.85, false)
            vi.advanceTimersByTime(1)
            recordRaspEvent('exec', 'event-3', ['cmd_separator'], 0.9, true)
            return finalizeRequestSession()
        })

        expect(result).not.toBeNull()
        expect(result!.events).toHaveLength(3)
        expect(result!.events.map(e => e.context)).toEqual(['event-1', 'event-2', 'event-3'])
        expect(result!.events[0].timestamp).toBeLessThan(result!.events[1].timestamp)
        expect(result!.events[1].timestamp).toBeLessThan(result!.events[2].timestamp)
    })

    it('startRequestSession() creates context for direct record/finalize flow', () => {
        startRequestSession({ sourceHash: 'manual-start', method: 'POST', path: '/api/x' })
        recordRaspEvent('sql', 'manual-event', ['sql_tautology'], 0.93, true)
        recordRaspEvent('http', 'manual-http', ['ssrf_internal_reach'], 0.94, true)

        const compound = finalizeRequestSession()
        expect(compound).not.toBeNull()
        expect(compound!.isCompound).toBe(true)
        expect(compound!.surfaces).toEqual(['sql', 'http'])
    })
})
