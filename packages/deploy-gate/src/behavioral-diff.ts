export interface Behaviors {
  newDomains: string[]
  newExecCalls: string[]
  newFilePaths: string[]
  newDeps: string[]
}

const DOMAIN_PATTERNS = [
  /fetch\(\s*['\"](https?:\/\/[^'\"\s)]+)/g,
  /axios\.get\(\s*['\"](https?:\/\/[^'\"\s)]+)/g,
  /http\.request\(\s*['\"](https?:\/\/[^'\"\s)]+)/g,
]

const EXEC_PATTERN = /(exec|spawn|execFile)\s*\(/g
const FILE_PATH_PATTERN = /['\"]((?:\.\.?\/|\/)[^'\"]+)['\"]/g
const DEP_PATTERN = /(?:from|require\()\s*['\"]([^'\".][^'\"]*)['\"]/g

function unique(values: string[]): string[] {
  return [...new Set(values)]
}

function extractDomains(line: string): string[] {
  const matches: string[] = []
  for (const pattern of DOMAIN_PATTERNS) {
    const cloned = new RegExp(pattern.source, pattern.flags)
    let match = cloned.exec(line)
    while (match) {
      matches.push(match[1])
      match = cloned.exec(line)
    }
  }
  return matches
}

export function extractBehaviors(diffLines: string[]): Behaviors {
  const domains: string[] = []
  const execCalls: string[] = []
  const filePaths: string[] = []
  const deps: string[] = []

  for (const line of diffLines) {
    domains.push(...extractDomains(line))

    if (EXEC_PATTERN.test(line)) {
      execCalls.push(line.trim())
    }
    EXEC_PATTERN.lastIndex = 0

    let fileMatch = FILE_PATH_PATTERN.exec(line)
    while (fileMatch) {
      filePaths.push(fileMatch[1])
      fileMatch = FILE_PATH_PATTERN.exec(line)
    }
    FILE_PATH_PATTERN.lastIndex = 0

    let depMatch = DEP_PATTERN.exec(line)
    while (depMatch) {
      deps.push(depMatch[1])
      depMatch = DEP_PATTERN.exec(line)
    }
    DEP_PATTERN.lastIndex = 0
  }

  return {
    newDomains: unique(domains),
    newExecCalls: unique(execCalls),
    newFilePaths: unique(filePaths),
    newDeps: unique(deps),
  }
}

export async function getBehaviorBaseline(env: { DEPLOY_STATE: KVNamespace }, repo: string): Promise<Behaviors | null> {
  const raw = await env.DEPLOY_STATE.get(`baseline:${repo}`)
  if (!raw) return null

  try {
    const parsed = JSON.parse(raw) as Behaviors
    return {
      newDomains: Array.isArray(parsed.newDomains) ? parsed.newDomains : [],
      newExecCalls: Array.isArray(parsed.newExecCalls) ? parsed.newExecCalls : [],
      newFilePaths: Array.isArray(parsed.newFilePaths) ? parsed.newFilePaths : [],
      newDeps: Array.isArray(parsed.newDeps) ? parsed.newDeps : [],
    }
  } catch {
    return null
  }
}

export async function saveBehaviorBaseline(env: { DEPLOY_STATE: KVNamespace }, repo: string, behaviors: Behaviors): Promise<void> {
  await env.DEPLOY_STATE.put(`baseline:${repo}`, JSON.stringify(behaviors))
}

export function computeBehaviorDelta(current: Behaviors, baseline: Behaviors | null): Behaviors {
  if (!baseline) return current

  const existing = {
    newDomains: new Set(baseline.newDomains),
    newExecCalls: new Set(baseline.newExecCalls),
    newFilePaths: new Set(baseline.newFilePaths),
    newDeps: new Set(baseline.newDeps),
  }

  return {
    newDomains: current.newDomains.filter(domain => !existing.newDomains.has(domain)),
    newExecCalls: current.newExecCalls.filter(call => !existing.newExecCalls.has(call)),
    newFilePaths: current.newFilePaths.filter(path => !existing.newFilePaths.has(path)),
    newDeps: current.newDeps.filter(dep => !existing.newDeps.has(dep)),
  }
}
