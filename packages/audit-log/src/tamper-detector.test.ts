import { describe, expect, it } from 'vitest'

import { detectRebase } from './tamper-detector.js'

describe('detectRebase', () => {
  it('detects commits older than the before commit timestamp', () => {
    const report = detectRebase({
      forced: false,
      before: 'before-hash',
      after: 'after-hash',
      commits: [
        { id: 'before-hash', timestamp: '2026-02-01T10:00:00.000Z', message: 'latest commit' },
        { id: 'older-hash', timestamp: '2026-01-01T10:00:00.000Z', message: 'older commit' },
      ],
      repository: { full_name: 'acme/repo' },
      customer_id: 'cust-1',
    })

    expect(report?.reason).toBe('suspected_rebase')
  })

  it('detects non-fast-forward pushes without forced flag when before is not an ancestor', () => {
    const report = detectRebase({
      forced: false,
      before: 'old-base',
      after: 'new-tip',
      commits: [
        { id: 'new-tip', parents: ['new-parent'], message: 'new history' },
        { id: 'new-parent', parents: ['root'], message: 'stacked commit' },
      ],
    })

    expect(report?.reason).toBe('suspected_rebase')
  })

  it('detects rebase markers in recent commit messages', () => {
    const report = detectRebase({
      forced: false,
      before: 'a',
      after: 'b',
      commits: [
        { id: 'b', message: 'fixup! tighten deploy law checks' },
      ],
    })

    expect(report?.reason).toBe('suspected_rebase')
  })

  it('returns null for normal fast-forward context without rebase markers', () => {
    const report = detectRebase({
      forced: false,
      before: 'base',
      after: 'head',
      commits: [
        { id: 'head', parents: ['base'], timestamp: '2026-03-01T00:00:00.000Z', message: 'normal commit' },
      ],
    })

    expect(report).toBeNull()
  })
})
