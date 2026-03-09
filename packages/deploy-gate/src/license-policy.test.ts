import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { describe, expect, it } from 'vitest'

import { DEFAULT_LICENSE_POLICY, evaluateLicense, loadLicensePolicy } from './license-policy.js'

describe('license-policy', () => {
  it('evaluateLicense classifies denied, warned and allowed licenses', () => {
    expect(evaluateLicense('GPL-3.0-only', DEFAULT_LICENSE_POLICY)).toBe('denied')
    expect(evaluateLicense('LGPL-3.0', DEFAULT_LICENSE_POLICY)).toBe('warned')
    expect(evaluateLicense('MIT', DEFAULT_LICENSE_POLICY)).toBe('allowed')
  })

  it('loadLicensePolicy returns default policy when file is missing', () => {
    const policy = loadLicensePolicy('/path/that/does/not/exist.json')
    expect(policy).toEqual(DEFAULT_LICENSE_POLICY)
  })

  it('loadLicensePolicy reads a valid JSON policy file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'license-policy-'))
    const path = join(dir, 'policy.json')
    writeFileSync(path, JSON.stringify({ deny: ['X'], warn: ['Y'], allow: ['Z'] }), 'utf8')

    const policy = loadLicensePolicy(path)
    expect(policy).toEqual({ deny: ['X'], warn: ['Y'], allow: ['Z'] })

    rmSync(dir, { recursive: true, force: true })
  })
})
