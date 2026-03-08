import { describe, it, expect, vi } from 'vitest'
import { createInvariantHandler } from './handler.js'

describe('createInvariantHandler', () => {
    it('passes clean requests', async () => {
        const handler = createInvariantHandler()
        const req = new Request('https://example.com/?q=hello')
        const next = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))

        const res = await handler(req, next)

        expect(next).toHaveBeenCalledOnce()
        expect(res.status).toBe(200)
    })

    it('detects SQL injection in request body', async () => {
        const detected: Array<{ surface: string; matches: Array<{ class: string }> }> = []
        const handler = createInvariantHandler({
            onDetect: (_req, match) => detected.push(match as { surface: string; matches: Array<{ class: string }> }),
        })
        const req = new Request('https://example.com/search', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ q: "' OR 1=1--" }),
        })
        const next = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }))

        const res = await handler(req, next)

        expect(next).toHaveBeenCalledOnce()
        expect(detected.some(d => d.surface === 'body_param')).toBe(true)
        expect(detected.flatMap(d => d.matches).some(m => m.class === 'sql_tautology')).toBe(true)
        expect(res.status).toBe(200)
    })

    it('blocks in enforce mode', async () => {
        const onBlock = vi.fn()
        const handler = createInvariantHandler({ mode: 'enforce', onBlock })
        const req = new Request('https://example.com/?q=%27%20OR%201=1--')
        const next = vi.fn().mockResolvedValue(new Response('ok'))

        const res = await handler(req, next)

        expect(res.status).toBe(403)
        expect(onBlock).toHaveBeenCalledOnce()
        expect(await res.json()).toEqual({ error: 'blocked' })
        expect(next).not.toHaveBeenCalled()
    })

    it('monitors in monitor mode', async () => {
        const handler = createInvariantHandler({ mode: 'monitor' })
        const req = new Request('https://example.com/?q=%27%20OR%201=1--')
        const next = vi.fn().mockResolvedValue(new Response('ok', { status: 201 }))

        const res = await handler(req, next)

        expect(next).toHaveBeenCalledOnce()
        expect(res.status).toBe(201)
    })
})
