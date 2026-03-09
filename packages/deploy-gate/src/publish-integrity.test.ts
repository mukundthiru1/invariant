import { afterEach, describe, expect, it, vi } from 'vitest'

import { buildArtifactManifest } from '../../audit-log/src/package-signing.js'
import { verifyInvariantPackageManifest } from './publish-integrity.js'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('verifyInvariantPackageManifest', () => {
  it('returns valid=true when all package signatures verify', async () => {
    vi.spyOn(Date, 'now')
      .mockReturnValueOnce(1_700_000_000_001)
      .mockReturnValueOnce(1_700_000_000_002)

    const manifest = buildArtifactManifest(
      [
        { name: '@acme/a', version: '1.0.0', sha256: 'a'.repeat(64) },
        { name: '@acme/b', version: '2.0.0', sha256: 'b'.repeat(64) },
      ],
      'manifest-secret',
    )

    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(manifest), { status: 200, headers: { 'content-type': 'application/json' } }),
    )

    const result = await verifyInvariantPackageManifest('https://example.test/manifest.json', 'manifest-secret')
    expect(result.valid).toBe(true)
    expect(result.packages).toHaveLength(2)
    expect(result.packages.every(pkg => pkg.matches)).toBe(true)
  })

  it('returns valid=false when any package signature is tampered', async () => {
    vi.spyOn(Date, 'now')
      .mockReturnValueOnce(1_700_000_000_101)
      .mockReturnValueOnce(1_700_000_000_102)

    const manifest = buildArtifactManifest(
      [
        { name: '@acme/a', version: '1.0.0', sha256: 'c'.repeat(64) },
        { name: '@acme/b', version: '2.0.0', sha256: 'd'.repeat(64) },
      ],
      'manifest-secret',
    )
    manifest.entries[1] = { ...manifest.entries[1], sha256: 'e'.repeat(64) }

    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(manifest), { status: 200, headers: { 'content-type': 'application/json' } }),
    )

    const result = await verifyInvariantPackageManifest('https://example.test/manifest.json', 'manifest-secret')
    expect(result.valid).toBe(false)
    expect(result.packages[0]?.matches).toBe(true)
    expect(result.packages[1]?.matches).toBe(false)
    expect(result.packages[1]?.tampered).toBe(true)
  })

  it('throws when manifest fetch fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('not found', { status: 404 }))

    await expect(
      verifyInvariantPackageManifest('https://example.test/manifest.json', 'manifest-secret'),
    ).rejects.toThrow('manifest fetch failed: HTTP 404')
  })
})
