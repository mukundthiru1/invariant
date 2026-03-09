import { describe, expect, it, vi } from 'vitest'

const { execSyncMock } = vi.hoisted(() => ({ execSyncMock: vi.fn() }))

vi.mock('node:child_process', () => ({
  execSync: execSyncMock,
}))

vi.mock('@actions/core', () => ({
  getInput: vi.fn(() => ''),
  setFailed: vi.fn(),
  setOutput: vi.fn(),
}))

vi.mock('./pr.js', () => ({
  runActionPrScan: vi.fn(),
  readPullRequestNumberFromEvent: vi.fn(),
}))

import { checkSlsaAttestation, generateCOWNERSEntry } from './main.js'

describe('github-action main exports', () => {
  it('generateCOWNERSEntry includes required security ownership paths', () => {
    const entry = generateCOWNERSEntry()
    expect(entry).toContain('.github/workflows/*santh* @santh-security')
    expect(entry).toContain('santh.config.* @santh-security')
  })

  it('checkSlsaAttestation returns true when cosign succeeds', async () => {
    execSyncMock.mockImplementation(() => Buffer.from('ok'))
    await expect(checkSlsaAttestation('artifact.tar.gz')).resolves.toBe(true)
  })

  it('checkSlsaAttestation returns false when cosign fails', async () => {
    execSyncMock.mockImplementation(() => { throw new Error('missing cosign') })
    await expect(checkSlsaAttestation('artifact.tar.gz')).resolves.toBe(false)
  })
})
