import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

const { runPrScanMock } = vi.hoisted(() => ({ runPrScanMock: vi.fn() }))

vi.mock('../../cli/src/commands/pr.js', () => ({
  runPrScan: runPrScanMock,
}))

import { readPullRequestNumberFromEvent, runActionPrScan } from './pr.js'

afterEach(() => {
  runPrScanMock.mockReset()
})

describe('github-action pr helpers', () => {
  it('reads pull request number from pull_request payload', () => {
    const dir = mkdtempSync(join(tmpdir(), 'gha-pr-'))
    const file = join(dir, 'event.json')
    writeFileSync(file, JSON.stringify({ pull_request: { number: 42 } }), 'utf8')

    expect(readPullRequestNumberFromEvent(file)).toBe(42)
    rmSync(dir, { recursive: true, force: true })
  })

  it('reads pull request number from issue payload when issue is a PR', () => {
    const dir = mkdtempSync(join(tmpdir(), 'gha-pr-'))
    const file = join(dir, 'event.json')
    writeFileSync(file, JSON.stringify({ issue: { number: 7, pull_request: {} } }), 'utf8')

    expect(readPullRequestNumberFromEvent(file)).toBe(7)
    rmSync(dir, { recursive: true, force: true })
  })

  it('returns null for malformed event payload', () => {
    const dir = mkdtempSync(join(tmpdir(), 'gha-pr-'))
    const file = join(dir, 'event.json')
    writeFileSync(file, '{not-json', 'utf8')

    expect(readPullRequestNumberFromEvent(file)).toBeNull()
    rmSync(dir, { recursive: true, force: true })
  })

  it('runActionPrScan throws for invalid PR number', async () => {
    await expect(runActionPrScan({
      projectDir: '.',
      token: 'token',
      pr: 0,
      postComments: false,
    })).rejects.toThrow('Invalid pull request number')
  })

  it('runActionPrScan forwards options to runPrScan', async () => {
    runPrScanMock.mockResolvedValue({ findings: [] })

    await runActionPrScan({
      projectDir: '/repo',
      token: 'token',
      owner: 'acme',
      repo: 'repo',
      pr: 9,
      postComments: true,
    })

    expect(runPrScanMock).toHaveBeenCalledWith(expect.objectContaining({
      projectDir: '/repo',
      token: 'token',
      owner: 'acme',
      repo: 'repo',
      pr: 9,
      postComments: true,
    }))
  })
})
