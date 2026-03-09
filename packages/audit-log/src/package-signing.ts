import * as nodeCrypto from 'node:crypto'

type PackageArtifact = {
  name: string
  version: string
  sha256: string
}

type SignedPackageArtifact = PackageArtifact & { sig: string }

function canonicalPayload(artifact: PackageArtifact, ts: number): string {
  return JSON.stringify({
    name: artifact.name,
    version: artifact.version,
    sha256: artifact.sha256,
    ts,
  })
}

function hmacSha256Hex(payload: string, secretKey: string): string {
  return nodeCrypto.createHmac('sha256', secretKey).update(payload).digest('hex')
}

function parseTimestampedSignature(signature: string): { ts: number; digestHex: string } | null {
  const parts = signature.split(':')
  if (parts.length !== 2) return null

  const ts = Number.parseInt(parts[0], 10)
  if (!Number.isFinite(ts) || ts <= 0) return null

  const digestHex = parts[1]
  if (!/^[0-9a-f]{64}$/i.test(digestHex)) return null

  return { ts, digestHex: digestHex.toLowerCase() }
}

export function signPackageArtifact(artifact: PackageArtifact, secretKey: string): string {
  const ts = Date.now()
  const payload = canonicalPayload(artifact, ts)
  const digestHex = hmacSha256Hex(payload, secretKey)
  return `${ts}:${digestHex}`
}

export function verifyPackageSignature(artifact: PackageArtifact, signature: string, secretKey: string): boolean {
  const parsed = parseTimestampedSignature(signature)
  if (!parsed) return false

  const expectedDigestHex = hmacSha256Hex(canonicalPayload(artifact, parsed.ts), secretKey)
  const expected = Buffer.from(expectedDigestHex, 'hex')
  const actual = Buffer.from(parsed.digestHex, 'hex')
  if (expected.length !== actual.length) return false
  return nodeCrypto.timingSafeEqual(expected, actual)
}

export function buildArtifactManifest(
  packages: Array<{ name: string; version: string; sha256: string }>,
  secretKey: string,
): { entries: SignedPackageArtifact[]; root: string } {
  const entries = packages.map((pkg) => ({
    ...pkg,
    sig: signPackageArtifact(pkg, secretKey),
  }))

  const joinedSignatures = entries.map(entry => entry.sig).join('')
  const root = nodeCrypto.createHash('sha256').update(joinedSignatures).digest('hex')

  return { entries, root }
}
