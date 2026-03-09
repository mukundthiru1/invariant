import { describe, expect, it } from 'vitest'

import { evaluateDeployLaws } from './laws.js'

describe('deploy laws', () => {
  it('passes all laws for complete safe input', () => {
    const result = evaluateDeployLaws({
      repo: 'acme/repo',
      gitRef: 'refs/heads/main',
      diffLines: ['const x = 1'],
      scanResults: [{ line: 'const x = 1', lineNumber: 1, file: 'a.ts', matches: [] }],
      trivyPassed: true,
      hasBehaviorModel: true,
    })

    expect(result.every(item => item.passed)).toBe(true)
  })

  it('fails no-stubs and fail-safe when diff is missing', () => {
    const result = evaluateDeployLaws({
      repo: 'acme/repo',
      gitRef: 'refs/heads/main',
      diffLines: [],
      scanResults: [],
      trivyPassed: true,
      hasBehaviorModel: true,
    })

    expect(result.find(item => item.law === 1)?.passed).toBe(false)
    expect(result.find(item => item.law === 5)?.passed).toBe(false)
  })

  it('fails architecture-fit when behavior model is unavailable', () => {
    const result = evaluateDeployLaws({
      repo: 'acme/repo',
      gitRef: 'refs/heads/main',
      diffLines: ['const x = 1'],
      scanResults: [{ line: 'const x = 1', lineNumber: 1, file: 'a.ts', matches: [] }],
      trivyPassed: true,
      hasBehaviorModel: false,
    })

    expect(result.find(item => item.law === 3)?.passed).toBe(false)
  })
})
