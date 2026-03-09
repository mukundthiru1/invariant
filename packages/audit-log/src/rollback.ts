import type { AuditEvent, RollbackPlatform } from './types.js'

export async function findLastCleanDeploy(
  customerId: string,
  listEvents: (customerId: string) => Promise<AuditEvent[]>,
): Promise<AuditEvent | null> {
  const events = await listEvents(customerId)
  const sorted = [...events].sort((a, b) => {
    const ta = Date.parse(a.ts ?? '1970-01-01T00:00:00.000Z')
    const tb = Date.parse(b.ts ?? '1970-01-01T00:00:00.000Z')
    return tb - ta
  })

  const blockedDeployIds = new Set(
    sorted.filter(e => e.event_type === 'block' && e.deploy_id).map(e => e.deploy_id as string),
  )

  for (const event of sorted) {
    if (event.event_type !== 'deploy' || !event.deploy_id) continue
    if (!blockedDeployIds.has(event.deploy_id)) return event
  }

  return null
}

export async function triggerRollback(
  deployId: string,
  platform: RollbackPlatform,
  platformToken: string,
  opts?: {
    fetchImpl?: typeof fetch
    cloudflareAccountId?: string
    cloudflareProjectName?: string
  },
): Promise<void> {
  const fetchImpl = opts?.fetchImpl ?? fetch

  if (platform === 'vercel') {
    const res = await fetchImpl(`https://api.vercel.com/v13/deployments/${encodeURIComponent(deployId)}/rollback`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${platformToken}`,
      },
    })
    if (!res.ok) {
      throw new Error(`vercel rollback failed (${res.status})`)
    }
    return
  }

  if (platform === 'cloudflare_pages') {
    const accountId = opts?.cloudflareAccountId
    const projectName = opts?.cloudflareProjectName
    if (!accountId || !projectName) {
      throw new Error('cloudflare_pages rollback requires accountId and projectName')
    }
    const url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/pages/projects/${encodeURIComponent(projectName)}/deployments/${encodeURIComponent(deployId)}/rollback`
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${platformToken}`,
      },
    })
    if (!res.ok) {
      throw new Error(`cloudflare pages rollback failed (${res.status})`)
    }
    return
  }

  throw new Error(`unsupported platform: ${platform}`)
}
