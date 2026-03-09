import { readFile } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { verifyPackageSignature } from '../../audit-log/src/package-signing.js'

export interface IntegrityResult {
  name: string
  version: string
  registryHash: string
  localHash: string
  matches: boolean
  tampered: boolean
}

export interface DependencyWithDepth {
  name: string
  version: string
  depth: number
}

interface RegistryVersionResponse {
  name?: string
  version?: string
  dist?: {
    integrity?: string
  }
}

interface LockfilePackageEntry {
  name?: string
  version?: string
  integrity?: string
}

interface NpmLsNode {
  version?: string
  dependencies?: Record<string, NpmLsNode>
}

interface NpmLsResponse {
  dependencies?: Record<string, NpmLsNode>
}

interface SignedManifestEntry {
  name?: string
  version?: string
  sha256?: string
  sig?: string
}

interface SignedManifestResponse {
  entries?: SignedManifestEntry[]
}

async function readJsonFile<T>(path: string): Promise<T | null> {
  try {
    const raw = await readFile(path, 'utf8')
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

async function fetchRegistryIntegrity(packageName: string, version: string): Promise<string> {
  const encodedName = encodeURIComponent(packageName)
  const url = `https://registry.npmjs.org/${encodedName}/${encodeURIComponent(version)}`

  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`npm registry lookup failed for ${packageName}@${version}: HTTP ${response.status}`)
  }

  const parsed = await response.json() as RegistryVersionResponse
  return typeof parsed.dist?.integrity === 'string' ? parsed.dist.integrity : ''
}

function lockfileEntryMatches(entry: LockfilePackageEntry, packageName: string, version: string): boolean {
  if (entry.version !== version) return false
  if (!entry.name) return false
  return entry.name === packageName
}

async function getLocalIntegrityFromLockfile(packageName: string, version: string): Promise<string> {
  const hiddenLock = await readJsonFile<{ packages?: Record<string, LockfilePackageEntry> }>('node_modules/.package-lock.json')
  const rootLock = await readJsonFile<{ packages?: Record<string, LockfilePackageEntry> }>('package-lock.json')

  const candidates = [hiddenLock, rootLock]

  for (const lock of candidates) {
    const packages = lock?.packages
    if (!packages) continue

    for (const entry of Object.values(packages)) {
      if (!entry) continue
      if (!lockfileEntryMatches(entry, packageName, version)) continue
      if (typeof entry.integrity === 'string' && entry.integrity.length > 0) {
        return entry.integrity
      }
    }

    for (const [packagePath, entry] of Object.entries(packages)) {
      if (!entry) continue
      if (entry.version !== version) continue
      const expectedTail = packageName
      if (!packagePath.endsWith(`node_modules/${expectedTail}`)) continue
      if (typeof entry.integrity === 'string' && entry.integrity.length > 0) {
        return entry.integrity
      }
    }
  }

  return ''
}

export async function checkNpmIntegrity(packageName: string, version: string): Promise<IntegrityResult> {
  const [registryHash, localHash] = await Promise.all([
    fetchRegistryIntegrity(packageName, version),
    getLocalIntegrityFromLockfile(packageName, version),
  ])

  const matches = registryHash.length > 0 && localHash.length > 0 && registryHash === localHash
  return {
    name: packageName,
    version,
    registryHash,
    localHash,
    matches,
    tampered: !matches,
  }
}

async function runNpmLs(): Promise<NpmLsResponse | null> {
  const output = await new Promise<string>((resolve) => {
    const child = spawn('npm', ['ls', '--all', '--json'], { stdio: ['ignore', 'pipe', 'ignore'] })
    let stdout = ''
    child.stdout.on('data', (chunk) => { stdout += chunk.toString() })
    child.on('error', () => { resolve('') })
    child.on('close', () => { resolve(stdout) })
  })

  if (!output) return null

  try {
    return JSON.parse(output) as NpmLsResponse
  } catch {
    return null
  }
}

export async function getTopDependenciesByDepth(limit = 20): Promise<DependencyWithDepth[]> {
  const tree = await runNpmLs()
  const rootDeps = tree?.dependencies
  if (!rootDeps) return []

  const queue: Array<{ name: string; node: NpmLsNode; depth: number }> = Object.entries(rootDeps).map(([name, node]) => ({
    name,
    node,
    depth: 1,
  }))

  const bestByName = new Map<string, DependencyWithDepth>()

  while (queue.length > 0) {
    const current = queue.shift()
    if (!current) break

    const version = typeof current.node.version === 'string' ? current.node.version : ''
    if (version) {
      const existing = bestByName.get(current.name)
      if (!existing || current.depth < existing.depth) {
        bestByName.set(current.name, {
          name: current.name,
          version,
          depth: current.depth,
        })
      }
    }

    const nested = current.node.dependencies ?? {}
    for (const [nestedName, nestedNode] of Object.entries(nested)) {
      queue.push({
        name: nestedName,
        node: nestedNode,
        depth: current.depth + 1,
      })
    }
  }

  return [...bestByName.values()]
    .sort((a, b) => {
      const depthCompare = a.depth - b.depth
      if (depthCompare !== 0) return depthCompare
      return a.name.localeCompare(b.name)
    })
    .slice(0, limit)
}

export async function verifyInvariantPackageManifest(
  manifestUrl: string,
  secretKey: string,
): Promise<{ valid: boolean; packages: IntegrityResult[] }> {
  const response = await fetch(manifestUrl)
  if (!response.ok) {
    throw new Error(`manifest fetch failed: HTTP ${response.status}`)
  }

  const parsed = (await response.json()) as SignedManifestResponse
  const entries = Array.isArray(parsed.entries) ? parsed.entries : []

  const packages: IntegrityResult[] = entries.map((entry) => {
    const name = typeof entry.name === 'string' ? entry.name : ''
    const version = typeof entry.version === 'string' ? entry.version : ''
    const sha256 = typeof entry.sha256 === 'string' ? entry.sha256 : ''
    const sig = typeof entry.sig === 'string' ? entry.sig : ''

    const matches = name.length > 0
      && version.length > 0
      && sha256.length > 0
      && sig.length > 0
      && verifyPackageSignature({ name, version, sha256 }, sig, secretKey)

    return {
      name,
      version,
      registryHash: sig,
      localHash: matches ? sig : '',
      matches,
      tampered: !matches,
    }
  })

  return {
    valid: packages.every(pkg => pkg.matches),
    packages,
  }
}
