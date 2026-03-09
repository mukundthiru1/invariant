import type { AuditEvent, MissingCommits, TamperReport } from './types.js'

type PushCommit = { id?: string }

type PushWebhookPayload = {
  forced?: boolean
  before?: string
  after?: string
  commits?: PushCommit[]
  repository?: { full_name?: string }
  customer_id?: string
}

export function detectForcePush(webhookPayload: PushWebhookPayload): TamperReport | null {
  if (webhookPayload.forced !== true) {
    return null
  }

  return {
    reason: 'forced_push',
    forced: true,
    missing_commits: [],
    before: webhookPayload.before,
    after: webhookPayload.after,
    repository: webhookPayload.repository?.full_name,
    customer_id: webhookPayload.customer_id,
  }
}

export async function compareShadowLog(
  repoApi: { hasCommit: (hash: string) => Promise<boolean> },
  auditLog: AuditEvent[],
): Promise<MissingCommits[]> {
  const commitSet = new Set(
    auditLog
      .filter(e => e.event_type === 'commit' && typeof e.commit_hash === 'string' && e.commit_hash.length > 0)
      .map(e => e.commit_hash as string),
  )

  const missing: MissingCommits[] = []
  for (const hash of commitSet) {
    const present = await repoApi.hasCommit(hash)
    if (!present) {
      missing.push({ commit_hash: hash })
    }
  }

  return missing.sort((a, b) => a.commit_hash.localeCompare(b.commit_hash))
}

export function buildWebhookRepoApi(payload: PushWebhookPayload): { hasCommit: (hash: string) => Promise<boolean> } {
  const hashes = new Set<string>()
  for (const commit of payload.commits ?? []) {
    if (commit.id) hashes.add(commit.id)
  }
  if (payload.after) hashes.add(payload.after)

  return {
    async hasCommit(hash: string): Promise<boolean> {
      return hashes.has(hash)
    },
  }
}

type RebaseAwarePushCommit = PushCommit & {
  timestamp?: string
  ts?: string
  message?: string
  parents?: Array<string | { id?: string; sha?: string }>
}

type RebaseAwarePushWebhookPayload = PushWebhookPayload & {
  commits?: RebaseAwarePushCommit[]
}

function parseCommitTime(value: string | undefined): number | null {
  if (!value) return null
  const parsed = Date.parse(value)
  return Number.isNaN(parsed) ? null : parsed
}

function commitMentionsRebaseMarkers(commits: RebaseAwarePushCommit[]): boolean {
  const marker = /\b(rebase|squash|amend|fixup)\b/i
  return commits.some(commit => marker.test(commit.message ?? ''))
}

function beforeIsAncestorInPush(before: string, commits: RebaseAwarePushCommit[]): boolean {
  for (const commit of commits) {
    if (commit.id === before) {
      return true
    }

    for (const parent of commit.parents ?? []) {
      if (typeof parent === 'string' && parent === before) {
        return true
      }
      if (typeof parent === 'object' && (parent.id === before || parent.sha === before)) {
        return true
      }
    }
  }
  return false
}

export function detectRebase(webhookPayload: RebaseAwarePushWebhookPayload): TamperReport | null {
  const commits = webhookPayload.commits ?? []
  if (commits.length === 0) return null

  const before = webhookPayload.before
  const beforeCommit = before ? commits.find(commit => commit.id === before) : undefined
  const beforeCommitTs = parseCommitTime(beforeCommit?.timestamp ?? beforeCommit?.ts)
  const hasOlderThanBefore = beforeCommitTs !== null && commits.some((commit) => {
    const commitTs = parseCommitTime(commit.timestamp ?? commit.ts)
    return commitTs !== null && commitTs < beforeCommitTs
  })

  const hasNonFastForwardWithoutForced =
    webhookPayload.forced !== true &&
    typeof before === 'string' &&
    before.length > 0 &&
    !beforeIsAncestorInPush(before, commits)

  const hasRebaseMarker = commitMentionsRebaseMarkers(commits)

  if (!hasOlderThanBefore && !hasNonFastForwardWithoutForced && !hasRebaseMarker) {
    return null
  }

  return {
    reason: 'suspected_rebase',
    forced: webhookPayload.forced === true,
    missing_commits: [],
    before: webhookPayload.before,
    after: webhookPayload.after,
    repository: webhookPayload.repository?.full_name,
    customer_id: webhookPayload.customer_id,
  }
}
