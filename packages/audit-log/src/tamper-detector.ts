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
