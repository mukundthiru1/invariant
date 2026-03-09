import { describe, expect, it } from 'vitest'

import { scanDiff } from './scanner.js'

describe('scanner', () => {
  it('returns empty result for empty diff', () => {
    expect(scanDiff([])).toEqual([])
  })

  it('preserves line ordering and numbering', () => {
    const result = scanDiff(['const a = 1', 'const b = 2'])
    expect(result[0]?.lineNumber).toBe(1)
    expect(result[1]?.lineNumber).toBe(2)
  })

  it('produces matches array for each line', () => {
    const result = scanDiff(['const x = "<script>alert(1)</script>"'])
    expect(Array.isArray(result[0]?.matches)).toBe(true)
  })
})
