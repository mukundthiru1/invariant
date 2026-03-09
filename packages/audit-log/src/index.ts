import { buildMerkleRoot } from './merkle.js'
import { signEvent, verifyEvent } from './hmac.js'
import { buildWebhookRepoApi, compareShadowLog, detectForcePush } from './tamper-detector.js'
import { findLastCleanDeploy, triggerRollback } from './rollback.js'
import type { AuditEvent, AuditEventType, DbClient, DbRowResult, RollbackPlatform, TamperReport } from './types.js'
export { buildArtifactManifest, signPackageArtifact, verifyPackageSignature } from './package-signing.js'

export type Env = {
  AUDIT_DB?: DbClient
  NEON_SQL_URL?: string
  NEON_API_KEY?: string
  HMAC_SECRET: string
  ALERT_WEBHOOK_URL?: string
  VERCEL_TOKEN?: string
  CF_PAGES_TOKEN?: string
  CF_ACCOUNT_ID?: string
  CF_PAGES_PROJECT?: string
}

type RequestHandler = (request: Request, env: Env) => Promise<Response>

const EVENT_TYPES = new Set<AuditEventType>([
  'commit',
  'deploy',
  'approval',
  'block',
  'tamper_detected',
  'rollback',
])

let merkleCache: { day: string; root: string } | null = null

function utcDay(d = new Date()): string {
  return d.toISOString().slice(0, 10)
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

async function getDb(env: Env): Promise<DbClient> {
  if (env.AUDIT_DB) return env.AUDIT_DB
  if (!env.NEON_SQL_URL || !env.NEON_API_KEY) {
    throw new Error('no database binding configured')
  }

  return {
    async query<T = Record<string, unknown>>(text: string, params: unknown[] = []): Promise<DbRowResult<T>> {
      const res = await fetch(env.NEON_SQL_URL as string, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${env.NEON_API_KEY}`,
        },
        body: JSON.stringify({ query: text, params }),
      })
      if (!res.ok) {
        throw new Error(`neon query failed (${res.status})`)
      }
      const data = (await res.json()) as { rows?: T[]; data?: T[] }
      return { rows: data.rows ?? data.data ?? [] }
    },
  }
}

function toAuditEvent(row: Record<string, unknown>): AuditEvent {
  return {
    id: typeof row.id === 'number' ? row.id : undefined,
    event_type: row.event_type as AuditEventType,
    commit_hash: (row.commit_hash as string | null) ?? null,
    tree_hash: (row.tree_hash as string | null) ?? null,
    author_email: (row.author_email as string | null) ?? null,
    ts: typeof row.ts === 'string' ? row.ts : new Date(row.ts as string).toISOString(),
    deploy_id: (row.deploy_id as string | null) ?? null,
    approved_by: (row.approved_by as string | null) ?? null,
    customer_id: row.customer_id as string,
    platform: (row.platform as string | null) ?? null,
    findings_json: (row.findings_json as string | null) ?? null,
    hmac: row.hmac as string,
  }
}

async function insertEvent(db: DbClient, event: AuditEvent): Promise<void> {
  await db.query(
    `INSERT INTO audit_events (
      event_type, commit_hash, tree_hash, author_email, ts, deploy_id,
      approved_by, customer_id, platform, findings_json, hmac
    ) VALUES (
      $1, $2, $3, $4, COALESCE($5::timestamptz, NOW()), $6,
      $7, $8, $9, $10, $11
    )`,
    [
      event.event_type,
      event.commit_hash ?? null,
      event.tree_hash ?? null,
      event.author_email ?? null,
      event.ts ?? null,
      event.deploy_id ?? null,
      event.approved_by ?? null,
      event.customer_id,
      event.platform ?? null,
      event.findings_json ?? null,
      event.hmac,
    ],
  )
}

async function listEvents(db: DbClient, customerId: string, limit: number, since?: string): Promise<AuditEvent[]> {
  const boundedLimit = Math.max(1, Math.min(limit, 1000))

  if (since) {
    const out = await db.query<Record<string, unknown>>(
      `SELECT * FROM audit_events
       WHERE customer_id = $1 AND ts >= $2::timestamptz
       ORDER BY ts DESC
       LIMIT $3`,
      [customerId, since, boundedLimit],
    )
    return out.rows.map(toAuditEvent)
  }

  const out = await db.query<Record<string, unknown>>(
    `SELECT * FROM audit_events
     WHERE customer_id = $1
     ORDER BY ts DESC
     LIMIT $2`,
    [customerId, boundedLimit],
  )
  return out.rows.map(toAuditEvent)
}

async function listAllEvents(db: DbClient): Promise<AuditEvent[]> {
  const out = await db.query<Record<string, unknown>>('SELECT * FROM audit_events ORDER BY ts ASC')
  return out.rows.map(toAuditEvent)
}

async function appendGeneratedEvent(env: Env, db: DbClient, event: Omit<AuditEvent, 'hmac'>): Promise<AuditEvent> {
  const hmac = await signEvent(event, env.HMAC_SECRET)
  const full: AuditEvent = { ...event, hmac }
  await insertEvent(db, full)
  return full
}

function validateEventType(eventType: unknown): eventType is AuditEventType {
  return typeof eventType === 'string' && EVENT_TYPES.has(eventType as AuditEventType)
}

async function handlePostEvent(request: Request, env: Env): Promise<Response> {
  const payload = (await request.json()) as Partial<AuditEvent>

  if (!validateEventType(payload.event_type) || typeof payload.customer_id !== 'string' || !payload.customer_id) {
    return jsonResponse({ error: 'invalid event payload' }, 400)
  }
  if (typeof payload.hmac !== 'string' || payload.hmac.length === 0) {
    return jsonResponse({ error: 'hmac required' }, 400)
  }

  const event: AuditEvent = {
    event_type: payload.event_type,
    commit_hash: payload.commit_hash ?? null,
    tree_hash: payload.tree_hash ?? null,
    author_email: payload.author_email ?? null,
    ts: payload.ts,
    deploy_id: payload.deploy_id ?? null,
    approved_by: payload.approved_by ?? null,
    customer_id: payload.customer_id,
    platform: payload.platform ?? null,
    findings_json: payload.findings_json ?? null,
    hmac: payload.hmac,
  }

  const valid = await verifyEvent(event, payload.hmac, env.HMAC_SECRET)
  if (!valid) {
    return jsonResponse({ error: 'hmac verification failed' }, 401)
  }

  const db = await getDb(env)
  await insertEvent(db, event)
  return jsonResponse({ ok: true }, 201)
}

async function handleGetEvents(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url)
  const customerId = url.searchParams.get('customer_id')
  if (!customerId) {
    return jsonResponse({ error: 'customer_id is required' }, 400)
  }

  const since = url.searchParams.get('since') ?? undefined
  if (since && Number.isNaN(Date.parse(since))) {
    return jsonResponse({ error: 'since must be ISO date' }, 400)
  }

  const limitRaw = Number.parseInt(url.searchParams.get('limit') ?? '100', 10)
  const limit = Number.isFinite(limitRaw) ? limitRaw : 100

  const db = await getDb(env)
  const events = await listEvents(db, customerId, limit, since)
  return jsonResponse({ events })
}

async function handleTamperCheck(request: Request, env: Env): Promise<Response> {
  const payload = (await request.json()) as {
    forced?: boolean
    before?: string
    after?: string
    commits?: Array<{ id?: string }>
    repository?: { full_name?: string }
    customer_id?: string
  }

  const customerId = payload.customer_id ?? request.headers.get('x-customer-id') ?? ''
  if (!customerId) {
    return jsonResponse({ error: 'customer_id required in body or x-customer-id header' }, 400)
  }

  const db = await getDb(env)
  const recentEvents = await listEvents(db, customerId, 2000)

  const forcedReport = detectForcePush(payload)
  const missing = await compareShadowLog(buildWebhookRepoApi(payload), recentEvents)

  let report: TamperReport | null = null
  if (forcedReport || missing.length > 0) {
    report = {
      reason: forcedReport ? 'forced_push' : 'missing_commits',
      forced: payload.forced === true,
      missing_commits: missing.map(m => m.commit_hash),
      before: payload.before,
      after: payload.after,
      repository: payload.repository?.full_name,
      customer_id: customerId,
    }

    await appendGeneratedEvent(env, db, {
      event_type: 'tamper_detected',
      customer_id: customerId,
      findings_json: JSON.stringify(report),
      ts: new Date().toISOString(),
    })

    if (env.ALERT_WEBHOOK_URL) {
      await fetch(env.ALERT_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ type: 'tamper_detected', report }),
      })
    }
  }

  return jsonResponse({ tamper_detected: report !== null, report })
}

async function handleMerkle(_request: Request, env: Env): Promise<Response> {
  const day = utcDay()
  if (merkleCache && merkleCache.day === day) {
    return jsonResponse({ merkle_root: merkleCache.root, cached: true, day })
  }

  const db = await getDb(env)
  const events = await listAllEvents(db)
  const root = await buildMerkleRoot(events)
  merkleCache = { day, root }
  return jsonResponse({ merkle_root: root, cached: false, day })
}

async function handleExport(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url)
  const prefix = '/v1/export/'
  const customerId = decodeURIComponent(url.pathname.slice(prefix.length))
  if (!customerId) {
    return jsonResponse({ error: 'customer_id missing in path' }, 400)
  }

  const db = await getDb(env)
  const events = await listEvents(db, customerId, 100000)
  return jsonResponse({ customer_id: customerId, events })
}

async function handleRollback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url)
  const prefix = '/v1/rollback/'
  const deployId = decodeURIComponent(url.pathname.slice(prefix.length))
  if (!deployId) {
    return jsonResponse({ error: 'deploy_id missing in path' }, 400)
  }

  const body = request.method === 'POST' ? ((await request.json().catch(() => ({}))) as {
    customer_id?: string
    platform?: RollbackPlatform
    platform_token?: string
  }) : {}

  const db = await getDb(env)

  let customerId = body.customer_id
  let platform = body.platform
  if (!customerId || !platform) {
    const found = await db.query<Record<string, unknown>>(
      `SELECT * FROM audit_events WHERE deploy_id = $1 ORDER BY ts DESC LIMIT 1`,
      [deployId],
    )
    const latest = found.rows[0]
    if (!latest) {
      return jsonResponse({ error: 'deploy event not found' }, 404)
    }
    customerId = customerId ?? (latest.customer_id as string)
    const p = latest.platform as string | undefined
    if (!platform && (p === 'vercel' || p === 'cloudflare_pages')) {
      platform = p
    }
  }

  if (!customerId || !platform) {
    return jsonResponse({ error: 'customer_id and platform are required' }, 400)
  }

  const cleanDeploy = await findLastCleanDeploy(customerId, async (cid: string) => listEvents(db, cid, 2000))
  if (!cleanDeploy?.deploy_id) {
    return jsonResponse({ error: 'no clean deploy found' }, 404)
  }

  const platformToken =
    body.platform_token ??
    (platform === 'vercel' ? env.VERCEL_TOKEN : env.CF_PAGES_TOKEN)

  if (!platformToken) {
    return jsonResponse({ error: 'platform token missing' }, 400)
  }

  await triggerRollback(cleanDeploy.deploy_id, platform, platformToken, {
    cloudflareAccountId: env.CF_ACCOUNT_ID,
    cloudflareProjectName: env.CF_PAGES_PROJECT,
  })

  await appendGeneratedEvent(env, db, {
    event_type: 'rollback',
    customer_id: customerId,
    deploy_id: deployId,
    platform,
    findings_json: JSON.stringify({ target_deploy_id: cleanDeploy.deploy_id }),
    ts: new Date().toISOString(),
  })

  return jsonResponse({ ok: true, rollback_to: cleanDeploy.deploy_id })
}

function notFound(): Response {
  return jsonResponse({ error: 'not found' }, 404)
}

export function createApp(): { fetch: RequestHandler } {
  return {
    async fetch(request: Request, env: Env): Promise<Response> {
      try {
        const { pathname } = new URL(request.url)

        if (request.method === 'POST' && pathname === '/v1/events') {
          return handlePostEvent(request, env)
        }
        if (request.method === 'GET' && pathname === '/v1/events') {
          return handleGetEvents(request, env)
        }
        if (request.method === 'POST' && pathname === '/v1/tamper-check') {
          return handleTamperCheck(request, env)
        }
        if (request.method === 'GET' && pathname === '/v1/merkle') {
          return handleMerkle(request, env)
        }
        if (request.method === 'GET' && pathname.startsWith('/v1/export/')) {
          return handleExport(request, env)
        }
        if (request.method === 'POST' && pathname.startsWith('/v1/rollback/')) {
          return handleRollback(request, env)
        }

        return notFound()
      } catch (error) {
        return jsonResponse(
          { error: (error as Error).message || 'internal error' },
          500,
        )
      }
    },
  }
}

const app = createApp()

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return app.fetch(request, env)
  },
}
