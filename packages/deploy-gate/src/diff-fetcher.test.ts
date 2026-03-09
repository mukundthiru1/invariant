import { afterEach, describe, expect, it, vi } from 'vitest'

import { fetchGithubDiff, fetchGithubDiffFromRequest, parseDiff } from './diff-fetcher.js'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('diff-fetcher', () => {
  it('parseDiff keeps only added lines excluding file headers', () => {
    const lines = parseDiff(['diff --git a/a.ts b/a.ts', '+++ b/a.ts', '+const x = 1', '-const y = 2', '+return x'].join('\n'))
    expect(lines).toEqual(['const x = 1', 'return x'])
  })

  it('fetchGithubDiff calls GitHub compare API with token', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('+added', { status: 200 }))

    const patch = await fetchGithubDiff('acme', 'repo', 'main', 'head', 'token-1')

    expect(patch).toBe('+added')
    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.github.com/repos/acme/repo/compare/main...head',
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({ Authorization: 'Bearer token-1' }),
      }),
    )
  })

  it('fetchGithubDiffFromRequest fetches and parses added lines', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(['+++ b/a.ts', '+safe = true', '+run()'].join('\n'), { status: 200 }))

    const lines = await fetchGithubDiffFromRequest({ owner: 'acme', repo: 'repo', base: 'base', head: 'head' })
    expect(lines).toEqual(['safe = true', 'run()'])
  })
})
