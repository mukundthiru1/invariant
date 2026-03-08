import { describe, it, expect, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { invariantMiddleware } from './express.js'

const mockReq = (overrides: Record<string, unknown> = {}) => ({
    query: {},
    body: {},
    params: {},
    headers: {},
    cookies: {},
    path: '/',
    method: 'GET',
    ...overrides,
})

const mockRes = () => {
    const r: {
        statusCode: number
        body?: unknown
        status: (n: number) => typeof r
        json: (d: unknown) => typeof r
    } = {
        statusCode: 200,
        status(n: number) {
            r.statusCode = n
            return r
        },
        json(d: unknown) {
            r.body = d
            return r
        },
    }
    return r
}

describe('invariantMiddleware', () => {
    it('passes clean requests', () => {
        const middleware = invariantMiddleware()
        const req = mockReq({ query: { page: '1' }, body: { q: 'hello world' } })
        const res = mockRes()
        const next = vi.fn()

        middleware(req, res, next)

        expect(next).toHaveBeenCalledOnce()
        expect(res.statusCode).toBe(200)
    })

    it('detects SQL injection in query params', () => {
        const detected: Array<{ surface: string; matches: Array<{ class: string }> }> = []
        const middleware = invariantMiddleware({ onDetect: (_req, match) => detected.push(match) })
        const req = mockReq({ query: { user: "' OR 1=1--" } })
        const res = mockRes()
        const next = vi.fn()

        middleware(req, res, next)

        expect(next).toHaveBeenCalledOnce()
        expect(detected.some(d => d.surface === 'query_param')).toBe(true)
        expect(detected.flatMap(d => d.matches).some(m => m.class === 'sql_tautology')).toBe(true)
    })

    it('detects XSS in body', () => {
        const detected: Array<{ surface: string; matches: Array<{ class: string }> }> = []
        const middleware = invariantMiddleware({ onDetect: (_req, match) => detected.push(match) })
        const req = mockReq({ body: { comment: '<script>alert(1)</script>' } })
        const res = mockRes()
        const next = vi.fn()

        middleware(req, res, next)

        expect(next).toHaveBeenCalledOnce()
        expect(detected.some(d => d.surface === 'body_param')).toBe(true)
        expect(detected.flatMap(d => d.matches).some(m => m.class === 'xss_tag_injection')).toBe(true)
    })

    it('blocks in enforce mode', () => {
        const onBlock = vi.fn()
        const middleware = invariantMiddleware({ mode: 'enforce', onBlock })
        const req = mockReq({ query: { q: "' OR 1=1--" } })
        const res = mockRes()
        const next = vi.fn()

        middleware(req, res, next)

        expect(res.statusCode).toBe(403)
        expect(res.body).toEqual({ error: 'blocked' })
        expect(onBlock).toHaveBeenCalledOnce()
        expect(next).not.toHaveBeenCalled()
    })

    it('monitors (does not block) in monitor mode', () => {
        const middleware = invariantMiddleware({ mode: 'monitor' })
        const req = mockReq({ query: { q: "' OR 1=1--" } })
        const res = mockRes()
        const next = vi.fn()

        middleware(req, res, next)

        expect(res.statusCode).toBe(200)
        expect(next).toHaveBeenCalledOnce()
    })

    it('detects surfaces for query, body, and header', () => {
        const detected: Array<{ surface: string }> = []
        const middleware = invariantMiddleware({ onDetect: (_req, match) => detected.push(match) })
        const req = mockReq({
            query: { q: "' OR 1=1--" },
            body: { comment: '<script>alert(1)</script>' },
            headers: { 'x-test': "' OR 1=1--" },
        })
        const res = mockRes()
        const next = vi.fn()

        middleware(req, res, next)

        const surfaces = new Set(detected.map(d => d.surface))
        expect(surfaces.has('query_param')).toBe(true)
        expect(surfaces.has('body_param')).toBe(true)
        expect(surfaces.has('header')).toBe(true)
        expect(next).toHaveBeenCalledOnce()
    })

    it('loads config from invariant.config.json', () => {
        const prevCwd = process.cwd()
        const tempDir = mkdtempSync(join(tmpdir(), 'invariant-agent-'))

        try {
            writeFileSync(join(tempDir, 'invariant.config.json'), JSON.stringify({ v: 1, mode: 'enforce' }))
            process.chdir(tempDir)

            const middleware = invariantMiddleware()
            const req = mockReq({ query: { q: "' OR 1=1--" } })
            const res = mockRes()
            const next = vi.fn()

            middleware(req, res, next)

            expect(res.statusCode).toBe(403)
            expect(res.body).toEqual({ error: 'blocked' })
            expect(next).not.toHaveBeenCalled()
        } finally {
            process.chdir(prevCwd)
            rmSync(tempDir, { recursive: true, force: true })
        }
    })
})
