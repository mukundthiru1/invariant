import * as nodeCrypto from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'


import { buildArtifactManifest, signPackageArtifact, verifyPackageSignature } from './package-signing.js'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('package-signing', () => {
  it('signs and verifies a package artifact', () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000)
    const artifact = { name: '@acme/core', version: '1.2.3', sha256: 'a'.repeat(64) }
    const signature = signPackageArtifact(artifact, 'secret-key')

    expect(verifyPackageSignature(artifact, signature, 'secret-key')).toBe(true)
  })

  it('fails verification when artifact content is tampered', () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000)
    const artifact = { name: '@acme/core', version: '1.2.3', sha256: 'b'.repeat(64) }
    const signature = signPackageArtifact(artifact, 'secret-key')

    expect(verifyPackageSignature({ ...artifact, sha256: 'c'.repeat(64) }, signature, 'secret-key')).toBe(false)
  })

  it('fails verification with a different secret key', () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000)
    const artifact = { name: '@acme/core', version: '1.2.3', sha256: 'd'.repeat(64) }
    const signature = signPackageArtifact(artifact, 'secret-key')

    expect(verifyPackageSignature(artifact, signature, 'other-secret')).toBe(false)
  })

  it('fails verification on malformed signature input', () => {
    const artifact = { name: '@acme/core', version: '1.2.3', sha256: 'e'.repeat(64) }
    expect(verifyPackageSignature(artifact, 'not-a-valid-signature', 'secret-key')).toBe(false)
  })

  it('builds manifest entries with signatures and deterministic root from joined signatures', () => {
    vi.spyOn(Date, 'now')
      .mockReturnValueOnce(1_700_000_000_001)
      .mockReturnValueOnce(1_700_000_000_002)

    const packages = [
      { name: '@acme/a', version: '1.0.0', sha256: '1'.repeat(64) },
      { name: '@acme/b', version: '2.0.0', sha256: '2'.repeat(64) },
    ]

    const manifest = buildArtifactManifest(packages, 'secret-key')
    expect(manifest.entries).toHaveLength(2)
    expect(manifest.entries.every(entry => verifyPackageSignature(entry, entry.sig, 'secret-key'))).toBe(true)

    const expectedRoot = nodeCrypto
      .createHash('sha256')
      .update(manifest.entries.map(entry => entry.sig).join(''))
      .digest('hex')
    expect(manifest.root).toBe(expectedRoot)
  })

  it('rejects a signature with a single character flipped (timing-safe comparison integrity)', () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000)
    const artifact = { name: '@acme/core', version: '1.2.3', sha256: 'f'.repeat(64) }
    const signature = signPackageArtifact(artifact, 'secret-key')

    // Flip the last hex character of the digest portion
    const parts = signature.split(':')
    const flipped = parts[1].slice(0, -1) + (parts[1].endsWith('a') ? 'b' : 'a')
    const tampered = `${parts[0]}:${flipped}`

    expect(verifyPackageSignature(artifact, tampered, 'secret-key')).toBe(false)
    expect(verifyPackageSignature(artifact, signature, 'secret-key')).toBe(true)
  })
})
