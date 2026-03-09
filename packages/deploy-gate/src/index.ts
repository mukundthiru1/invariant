import { computeBehaviorDelta, extractBehaviors, getBehaviorBaseline, saveBehaviorBaseline, type Behaviors } from './behavioral-diff.js'
import { fetchGithubDiffFromRequest, parseDiff } from './diff-fetcher.js'
import { evaluateDeployLaws, type DeployLawResult } from './laws.js'
import { notifyEmail, notifySlack, notifyWebPush } from './notification.js'
import { checkNpmIntegrity, getTopDependenciesByDepth, type IntegrityResult } from './publish-integrity.js'
import { scanDiff, type ScanResult } from './scanner.js'
import { diffSbom, type SbomComponent, type SbomDiff } from './sbom-diff.js'
import { approveDeployRecord, createDeployRecord, denyDeployRecord, getDeployRecord, type DeployRecord } from './store.js'
import { generateSbom, runTrivyScan, type TrivyScanOptions, type TrivyReport } from './trivy.js'
import { readFile } from 'node:fs/promises'

export type { TrivyScanOptions, TrivyReport }

export interface Env {
  DEPLOY_STATE: KVNamespace
  GITHUB_TOKEN?: string
  APPROVAL_SHARED_SECRET?: string
  APPROVAL_EMAIL_TO?: string
  SLACK_WEBHOOK_URL?: string
  WEB_PUSH_ENDPOINT?: string
  AUTO_APPROVE_ON_CLEAN?: string
}

interface DeployWebhookInput {
  deployId: string
  gitRef: string
  repo: string
  platform: string
  callbackUrl: string | null
  owner?: string
  repoName?: string
  base?: string
  head?: string
  diffLines?: string[]
  diffPatch?: string
  previousSbomPath?: string
}

interface AnalyzeResult {
  findings: {
    gitRef: string
    repo: string
    diffLineCount: number
    scanResults: ScanResult[]
    behavioralDelta: Behaviors
    lawCompliance: DeployLawResult[]
    sbomDiff?: SbomDiff
    integrityResults: IntegrityResult[]
  }
  clean: boolean
  behavioralCurrent: Behaviors
}

type NormalizedSeverity = 'critical' | 'high' | 'medium' | 'low'

function normalizeSeverity(value: string): NormalizedSeverity {
  const normalized = value.trim().toLowerCase()
  if (normalized === 'critical') return 'critical'
  if (normalized === 'high') return 'high'
  if (normalized === 'low') return 'low'
  return 'medium'
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

function boolFromEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback
  const normalized = value.toLowerCase()
  return normalized === '1' || normalized === 'true' || normalized === 'yes'
}

function extractPathParam(pathname: string, prefix: string): string | null {
  if (!pathname.startsWith(prefix)) return null
  const value = pathname.slice(prefix.length)
  return value.length > 0 ? decodeURIComponent(value) : null
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function parseRepoParts(repo: string): { owner?: string; repoName?: string } {
  const parts = repo.split('/').filter(Boolean)
  if (parts.length < 2) return {}
  return { owner: parts[0], repoName: parts[1] }
}

function normalizeGenericPayload(payload: Record<string, unknown>): DeployWebhookInput {
  const deployId = asString(payload.deploy_id) ?? asString(payload.deployId) ?? crypto.randomUUID()
  const repo = asString(payload.repo) ?? asString(payload.repository) ?? 'unknown/unknown'
  const { owner, repoName } = parseRepoParts(repo)

  return {
    deployId,
    gitRef: asString(payload.git_ref) ?? asString(payload.gitRef) ?? 'unknown',
    repo,
    platform: asString(payload.platform) ?? 'generic',
    callbackUrl: asString(payload.callback_url) ?? asString(payload.callbackUrl) ?? null,
    owner,
    repoName,
    base: asString(payload.base) ?? asString(payload.baseRef),
    head: asString(payload.head) ?? asString(payload.headRef),
    diffLines: Array.isArray(payload.diff_lines) ? payload.diff_lines.filter((line): line is string => typeof line === 'string') : undefined,
    diffPatch: asString(payload.diff_patch),
    previousSbomPath: asString(payload.previous_sbom_path) ?? asString(payload.previousSbomPath),
  }
}

function normalizeVercelPayload(payload: Record<string, unknown>): DeployWebhookInput {
  const deployment = (payload.deployment ?? {}) as Record<string, unknown>
  const gitSource = (payload.gitSource ?? {}) as Record<string, unknown>
  const meta = (payload.meta ?? {}) as Record<string, unknown>

  const repo = asString(meta.githubCommitOrg) && asString(meta.githubCommitRepo)
    ? `${asString(meta.githubCommitOrg)}/${asString(meta.githubCommitRepo)}`
    : (asString(payload.repo) ?? 'unknown/unknown')

  const { owner, repoName } = parseRepoParts(repo)

  return {
    deployId: asString(deployment.id) ?? asString(payload.deploy_id) ?? crypto.randomUUID(),
    gitRef: asString(gitSource.ref) ?? asString(meta.githubCommitRef) ?? asString(payload.git_ref) ?? 'unknown',
    repo,
    platform: 'vercel',
    callbackUrl: asString(payload.callback_url) ?? null,
    owner,
    repoName,
    base: asString(payload.base),
    head: asString(gitSource.sha) ?? asString(meta.githubCommitSha) ?? asString(payload.head),
    diffLines: Array.isArray(payload.diff_lines) ? payload.diff_lines.filter((line): line is string => typeof line === 'string') : undefined,
    diffPatch: asString(payload.diff_patch),
    previousSbomPath: asString(payload.previous_sbom_path) ?? asString(payload.previousSbomPath),
  }
}

function normalizeGithubPayload(payload: Record<string, unknown>): DeployWebhookInput {
  const checkRun = (payload.check_run ?? {}) as Record<string, unknown>
  const repository = (payload.repository ?? {}) as Record<string, unknown>

  const repo = asString(repository.full_name) ?? asString(payload.repo) ?? 'unknown/unknown'
  const { owner, repoName } = parseRepoParts(repo)

  return {
    deployId: asString(checkRun.external_id) ?? asString(checkRun.id) ?? asString(payload.deploy_id) ?? crypto.randomUUID(),
    gitRef: asString(checkRun.head_branch) ?? asString(payload.git_ref) ?? 'unknown',
    repo,
    platform: 'github',
    callbackUrl: asString(payload.callback_url) ?? null,
    owner,
    repoName,
    base: asString(payload.base),
    head: asString(checkRun.head_sha) ?? asString(payload.head),
    diffLines: Array.isArray(payload.diff_lines) ? payload.diff_lines.filter((line): line is string => typeof line === 'string') : undefined,
    diffPatch: asString(payload.diff_patch),
    previousSbomPath: asString(payload.previous_sbom_path) ?? asString(payload.previousSbomPath),
  }
}

interface CycloneDxComponent {
  name?: string
  version?: string
  purl?: string
  licenses?: Array<{
    license?: {
      id?: string
      name?: string
    }
  }>
}

interface CycloneDxDocument {
  components?: CycloneDxComponent[]
}

function extractLicense(component: CycloneDxComponent): string {
  if (!Array.isArray(component.licenses) || component.licenses.length === 0) return 'UNKNOWN'
  const entry = component.licenses[0]?.license
  if (!entry) return 'UNKNOWN'
  return entry.id ?? entry.name ?? 'UNKNOWN'
}

function parseSbomComponents(raw: string): SbomComponent[] {
  let parsed: CycloneDxDocument
  try {
    parsed = JSON.parse(raw) as CycloneDxDocument
  } catch {
    return []
  }

  const components = parsed.components ?? []
  const normalized: SbomComponent[] = []

  for (const component of components) {
    const name = component.name ?? ''
    const version = component.version ?? ''
    if (!name || !version) continue
    normalized.push({
      name,
      version,
      purl: component.purl ?? '',
      license: extractLicense(component),
    })
  }

  return normalized
}

async function resolveDiffLines(env: Env, input: DeployWebhookInput): Promise<string[]> {
  if (input.diffLines && input.diffLines.length > 0) return input.diffLines
  if (input.diffPatch) return parseDiff(input.diffPatch)

  if (input.owner && input.repoName && input.base && input.head) {
    return fetchGithubDiffFromRequest({
      owner: input.owner,
      repo: input.repoName,
      base: input.base,
      head: input.head,
      token: env.GITHUB_TOKEN,
    })
  }

  return []
}

async function runAnalysis(env: Env, input: DeployWebhookInput): Promise<AnalyzeResult> {
  const diffLines = await resolveDiffLines(env, input)
  const scanResults = scanDiff(diffLines)
  const integrityResults: IntegrityResult[] = []
  let sbomDiff: SbomDiff | undefined
  
  let trivyReport: TrivyReport = {
    passed: false,
    cves: [],
    licenses: [],
    sbom: {},
  }
  try {
    trivyReport = await runTrivyScan('.', { mode: 'fs' })
  } catch {
    trivyReport = {
      passed: false,
      cves: [],
      licenses: [],
      sbom: {},
    }
  }

  if (input.previousSbomPath) {
    try {
      const [previousRaw, currentRaw] = await Promise.all([
        readFile(input.previousSbomPath, 'utf8'),
        generateSbom('.'),
      ])
      const previousSbom = parseSbomComponents(previousRaw)
      const currentSbom = parseSbomComponents(currentRaw)
      sbomDiff = await diffSbom(previousSbom, currentSbom)
    } catch (error) {
      console.warn(`Failed to diff SBOMs for path ${input.previousSbomPath}.`, error)
    }
  }
  
  try {
    const dependencies = await getTopDependenciesByDepth(20)
    const checks = await Promise.allSettled(dependencies.map((dep) => checkNpmIntegrity(dep.name, dep.version)))
    for (const check of checks) {
      if (check.status === 'fulfilled') {
        integrityResults.push(check.value)
      }
    }
  } catch (error) {
    console.warn('Failed to perform npm publish integrity checks.', error)
  }
  
  for (const cve of trivyReport.cves) {
    scanResults.push({
      line: `Dependency: ${cve.packageName} @ ${cve.installedVersion}`,
      lineNumber: 1,
      file: 'trivy-scan',
      matches: [{
        class: 'supply_chain_package_eval',
        confidence: 1.0,
        category: 'vulnerability',
        severity: normalizeSeverity(cve.severity),
        isNovelVariant: false,
        description: cve.description || `CVE ${cve.id} found in ${cve.packageName}`,
        detectionLevels: { l1: true, l2: false, convergent: false }
      }]
    })
  }

  for (const lic of trivyReport.licenses) {
    if (lic.category !== 'allowed') {
      scanResults.push({
        line: `Dependency: ${lic.packageName}`,
        lineNumber: 1,
        file: 'trivy-scan',
        matches: [{
          class: 'supply_chain_github_actions',
          confidence: 1.0,
          category: 'license',
          severity: lic.category === 'denied' ? 'critical' : 'medium',
          isNovelVariant: false,
          description: `License ${lic.license} is ${lic.category} for package ${lic.packageName}`,
          detectionLevels: { l1: true, l2: false, convergent: false }
        }]
      })
    }
  }

  if (sbomDiff) {
    for (const licenseChange of sbomDiff.licenseChanged) {
      scanResults.push({
        line: `License changed: ${licenseChange.from.name} ${licenseChange.from.license} -> ${licenseChange.to.license}`,
        lineNumber: 1,
        file: 'sbom-diff',
        matches: [{
          class: 'supply_chain_package_eval',
          confidence: 1.0,
          category: 'license',
          severity: 'critical',
          isNovelVariant: false,
          description: `License changed for ${licenseChange.from.name}: ${licenseChange.from.license} -> ${licenseChange.to.license}`,
          detectionLevels: { l1: true, l2: false, convergent: false },
        }],
      })
    }
  }

  for (const integrity of integrityResults) {
    if (!integrity.matches) {
      scanResults.push({
        line: `Integrity mismatch: ${integrity.name} @ ${integrity.version}`,
        lineNumber: 1,
        file: 'publish-integrity',
        matches: [{
          class: 'supply_chain_tampering' as ScanResult['matches'][number]['class'],
          confidence: 1.0,
          category: 'supply_chain',
          severity: 'critical',
          isNovelVariant: false,
          description: `Registry hash and local hash mismatch for ${integrity.name}@${integrity.version}`,
          detectionLevels: { l1: true, l2: false, convergent: false },
        }],
      })
    }
  }

  const hasInvariantMatches = scanResults.some(result => result.matches.length > 0)

  const behavioralCurrent = extractBehaviors(diffLines)
  const baseline = await getBehaviorBaseline(env, input.repo)
  const behavioralDelta = computeBehaviorDelta(behavioralCurrent, baseline)
  const lawCompliance = evaluateDeployLaws({
    repo: input.repo,
    gitRef: input.gitRef,
    diffLines,
    scanResults,
    trivyPassed: trivyReport.passed,
    hasBehaviorModel: behavioralCurrent !== undefined && baseline !== undefined,
  })
  const hasLawViolation = lawCompliance.some((law) => !law.passed)

  const hasBehaviorRisk =
    behavioralDelta.newDomains.length > 0 ||
    behavioralDelta.newExecCalls.length > 0 ||
    behavioralDelta.newFilePaths.length > 0 ||
    behavioralDelta.newDeps.length > 0

  const clean = !hasInvariantMatches && !hasBehaviorRisk && trivyReport.passed && !hasLawViolation

  return {
    findings: {
      gitRef: input.gitRef,
      repo: input.repo,
      diffLineCount: diffLines.length,
      scanResults,
      behavioralDelta,
      lawCompliance,
      sbomDiff,
      integrityResults,
    },
    clean,
    behavioralCurrent,
  }
}

async function notifyPending(env: Env, deployId: string, findings: unknown): Promise<void> {
  const tasks: Promise<unknown>[] = []

  if (env.WEB_PUSH_ENDPOINT) {
    tasks.push(notifyWebPush({ endpoint: env.WEB_PUSH_ENDPOINT }, { deployId, findings }))
  }

  if (env.APPROVAL_EMAIL_TO) {
    tasks.push(notifyEmail(env.APPROVAL_EMAIL_TO, deployId, findings))
  }

  if (env.SLACK_WEBHOOK_URL) {
    tasks.push(notifySlack(env.SLACK_WEBHOOK_URL, deployId, findings))
  }

  await Promise.allSettled(tasks)
}

async function notifyDownstream(record: DeployRecord): Promise<void> {
  if (!record.callbackUrl) return

  await fetch(record.callbackUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      deploy_id: record.deployId,
      status: record.status,
      approver_credential_id: record.approverCredentialId,
    }),
  })
}

async function handleWebhook(env: Env, source: 'vercel' | 'github' | 'generic', request: Request): Promise<Response> {
  let payload: Record<string, unknown>

  try {
    payload = (await request.json()) as Record<string, unknown>
  } catch {
    return json({ error: 'invalid_json' }, 400)
  }

  const input = source === 'vercel'
    ? normalizeVercelPayload(payload)
    : source === 'github'
      ? normalizeGithubPayload(payload)
      : normalizeGenericPayload(payload)

  const analysis = await runAnalysis(env, input)
  await createDeployRecord(env, input.deployId, analysis.findings, input.platform, input.callbackUrl)

  const autoApprove = boolFromEnv(env.AUTO_APPROVE_ON_CLEAN, true)
  if (analysis.clean && autoApprove) {
    const approved = await approveDeployRecord(env, input.deployId, 'auto-clean')
    if (approved) {
      await saveBehaviorBaseline(env, input.repo, analysis.behavioralCurrent)
      await notifyDownstream(approved)
      return json({ deploy_id: input.deployId, status: 'approved', findings: analysis.findings }, 200)
    }
  }

  await notifyPending(env, input.deployId, analysis.findings)
  return json({ deploy_id: input.deployId, status: 'pending', findings: analysis.findings }, 202)
}

async function handleApprove(env: Env, request: Request, deployId: string): Promise<Response> {
  let payload: Record<string, unknown>
  try {
    payload = (await request.json()) as Record<string, unknown>
  } catch {
    return json({ error: 'invalid_json' }, 400)
  }

  const providedToken = asString(payload.token)
  if (env.APPROVAL_SHARED_SECRET && providedToken !== env.APPROVAL_SHARED_SECRET) {
    return json({ error: 'invalid_token' }, 401)
  }

  const approverCredentialId = asString(payload.approver_credential_id) ?? 'unknown-approver'
  const approved = await approveDeployRecord(env, deployId, approverCredentialId)

  if (!approved) {
    return json({ error: 'deploy_not_found' }, 404)
  }

  await notifyDownstream(approved)
  return json({ deploy_id: deployId, status: 'approved' }, 200)
}

async function handleDeny(env: Env, request: Request, deployId: string): Promise<Response> {
  let payload: Record<string, unknown>
  try {
    payload = (await request.json()) as Record<string, unknown>
  } catch {
    return json({ error: 'invalid_json' }, 400)
  }

  const providedToken = asString(payload.token)
  if (env.APPROVAL_SHARED_SECRET && providedToken !== env.APPROVAL_SHARED_SECRET) {
    return json({ error: 'invalid_token' }, 401)
  }

  const denied = await denyDeployRecord(env, deployId)
  if (!denied) {
    return json({ error: 'deploy_not_found' }, 404)
  }

  await notifyDownstream(denied)
  return json({ deploy_id: deployId, status: 'denied' }, 200)
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)
    const { pathname } = url

    if (request.method === 'GET' && pathname === '/health') {
      return json({ ok: true, service: 'deploy-gate' }, 200)
    }

    if (request.method === 'POST' && pathname === '/v1/webhook/vercel') {
      return handleWebhook(env, 'vercel', request)
    }

    if (request.method === 'POST' && pathname === '/v1/webhook/github') {
      return handleWebhook(env, 'github', request)
    }

    if (request.method === 'POST' && pathname === '/v1/webhook/generic') {
      return handleWebhook(env, 'generic', request)
    }

    if (request.method === 'GET' && pathname.startsWith('/v1/status/')) {
      const deployId = extractPathParam(pathname, '/v1/status/')
      if (!deployId) return json({ error: 'missing_deploy_id' }, 400)

      const record = await getDeployRecord(env, deployId)
      if (!record) return json({ error: 'deploy_not_found' }, 404)
      return json({ deploy_id: deployId, status: record.status, record }, 200)
    }

    if (request.method === 'POST' && pathname.startsWith('/v1/approve/')) {
      const deployId = extractPathParam(pathname, '/v1/approve/')
      if (!deployId) return json({ error: 'missing_deploy_id' }, 400)
      return handleApprove(env, request, deployId)
    }

    if (request.method === 'POST' && pathname.startsWith('/v1/deny/')) {
      const deployId = extractPathParam(pathname, '/v1/deny/')
      if (!deployId) return json({ error: 'missing_deploy_id' }, 400)
      return handleDeny(env, request, deployId)
    }

    return json({ error: 'not_found' }, 404)
  },
}
