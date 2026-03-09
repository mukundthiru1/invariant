import { describe, expect, it } from 'vitest'

import { createApp, type Env } from './index.js'
import { signEvent, verifyEvent } from './hmac.js'
import { buildMerkleRoot } from './merkle.js'
import { compareShadowLog, detectForcePush } from './tamper-detector.js'
import type { AuditEvent, DbClient } from './types.js'

type Row = Required<AuditEvent> & { id: number }

function makeDb(): DbClient & { rows: Row[] } {
  const rows: Row[] = []
  let id = 0

  return {
    rows,
    async query<T = Record<string, unknown>>(text: string, params: unknown[] = []) {
      if (text.includes('INSERT INTO audit_events')) {
        id += 1
        const row: Row = {
          id,
          event_type: params[0] as Row['event_type'],
          commit_hash: (params[1] as string | null) ?? null,
          tree_hash: (params[2] as string | null) ?? null,
          author_email: (params[3] as string | null) ?? null,
          ts: (params[4] as string | null) ?? new Date('2026-01-01T00:00:00.000Z').toISOString(),
          deploy_id: (params[5] as string | null) ?? null,
          approved_by: (params[6] as string | null) ?? null,
          customer_id: params[7] as string,
          platform: (params[8] as string | null) ?? null,
          findings_json: (params[9] as string | null) ?? null,
          hmac: params[10] as string,
        }
        rows.push(row)
        return { rows: [] as T[] }
      }

      if (text.includes('SELECT * FROM audit_events WHERE deploy_id = $1')) {
        const deployId = params[0] as string
        const found = rows
          .filter(r => r.deploy_id === deployId)
          .sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts))
          .slice(0, 1)
        return { rows: found as T[] }
      }

      if (text.includes('SELECT * FROM audit_events ORDER BY ts ASC')) {
        return {
          rows: [...rows].sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts)) as T[],
        }
      }

      if (text.includes('WHERE customer_id = $1 AND ts >= $2::timestamptz')) {
        const customerId = params[0] as string
        const since = Date.parse(params[1] as string)
        const limit = params[2] as number
        const found = rows
          .filter(r => r.customer_id === customerId && Date.parse(r.ts) >= since)
          .sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts))
          .slice(0, limit)
        return { rows: found as T[] }
      }

      if (text.includes('WHERE customer_id = $1')) {
        const customerId = params[0] as string
        const limit = params[1] as number
        const found = rows
          .filter(r => r.customer_id === customerId)
          .sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts))
          .slice(0, limit)
        return { rows: found as T[] }
      }

      throw new Error(`unexpected SQL in test db: ${text}`)
    },
  }
}

async function makeSignedEvent(overrides: Partial<AuditEvent>, secret: string): Promise<AuditEvent> {
  const base: Omit<AuditEvent, 'hmac'> = {
    event_type: 'commit',
    customer_id: 'cust-1',
    commit_hash: 'abc123',
    tree_hash: 'def456',
    author_email: 'dev@example.com',
    ts: '2026-01-01T00:00:00.000Z',
    deploy_id: null,
    approved_by: null,
    platform: null,
    findings_json: null,
    ...overrides,
  }

  return {
    ...base,
    hmac: await signEvent(base, secret),
  }
}

describe('audit-log worker', () => {
  it('appends event on POST /v1/events when HMAC is valid', async () => {
    const db = makeDb()
    const env: Env = { AUDIT_DB: db, HMAC_SECRET: 'test-secret' }
    const app = createApp()
    const event = await makeSignedEvent({}, env.HMAC_SECRET)

    const res = await app.fetch(
      new Request('https://audit.test/v1/events', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(event),
      }),
      env,
    )

    expect(res.status).toBe(201)
    expect(db.rows).toHaveLength(1)
    expect(db.rows[0].commit_hash).toBe('abc123')
  })

  it('rejects tampered event payload with bad HMAC', async () => {
    const db = makeDb()
    const env: Env = { AUDIT_DB: db, HMAC_SECRET: 'test-secret' }
    const app = createApp()
    const event = await makeSignedEvent({}, env.HMAC_SECRET)
    const tampered = { ...event, commit_hash: 'DIFFERENT' }

    const res = await app.fetch(
      new Request('https://audit.test/v1/events', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(tampered),
      }),
      env,
    )

    expect(res.status).toBe(401)
    expect(db.rows).toHaveLength(0)
  })

  it('detects force push and records tamper_detected event', async () => {
    const db = makeDb()
    const env: Env = { AUDIT_DB: db, HMAC_SECRET: 'test-secret' }
    const app = createApp()

    const commit1 = await makeSignedEvent({ commit_hash: 'old-1' }, env.HMAC_SECRET)
    const commit2 = await makeSignedEvent({ commit_hash: 'old-2' }, env.HMAC_SECRET)
    await app.fetch(
      new Request('https://audit.test/v1/events', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(commit1),
      }),
      env,
    )
    await app.fetch(
      new Request('https://audit.test/v1/events', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(commit2),
      }),
      env,
    )

    const res = await app.fetch(
      new Request('https://audit.test/v1/tamper-check', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          customer_id: 'cust-1',
          forced: true,
          before: 'old-2',
          after: 'new-1',
          commits: [{ id: 'new-1' }],
          repository: { full_name: 'acme/repo' },
        }),
      }),
      env,
    )

    const body = (await res.json()) as { tamper_detected: boolean }
    expect(res.status).toBe(200)
    expect(body.tamper_detected).toBe(true)
    expect(db.rows.some(r => r.event_type === 'tamper_detected')).toBe(true)
  })

  it('returns stable merkle root for same events regardless of order', async () => {
    const ev1 = await makeSignedEvent({ commit_hash: 'h1' }, 'test-secret')
    const ev2 = await makeSignedEvent({ commit_hash: 'h2' }, 'test-secret')
    const ev3 = await makeSignedEvent({ commit_hash: 'h3' }, 'test-secret')

    const rootA = await buildMerkleRoot([ev1, ev2, ev3])
    const rootB = await buildMerkleRoot([ev3, ev1, ev2])

    expect(rootA).toBe(rootB)
  })
})

describe('hmac helpers', () => {
  it('verifyEvent returns true for untampered events and false for tampered events', async () => {
    const secret = 'test-secret'
    const event = await makeSignedEvent({ commit_hash: 'safe' }, secret)

    expect(await verifyEvent(event, event.hmac, secret)).toBe(true)
    expect(await verifyEvent({ ...event, commit_hash: 'changed' }, event.hmac, secret)).toBe(false)
  })
})

describe('tamper detector helpers', () => {
  it('detectForcePush identifies forced pushes', () => {
    const report = detectForcePush({ forced: true, before: 'a', after: 'b' })
    expect(report).not.toBeNull()
    expect(report?.reason).toBe('forced_push')
  })

  it('compareShadowLog returns commits missing from repo state', async () => {
    const auditLog: AuditEvent[] = [
      await makeSignedEvent({ commit_hash: 'keep' }, 's'),
      await makeSignedEvent({ commit_hash: 'missing' }, 's'),
    ]

    const missing = await compareShadowLog(
      {
        async hasCommit(hash: string) {
          return hash === 'keep'
        },
      },
      auditLog,
    )

    expect(missing).toEqual([{ commit_hash: 'missing' }])
  })
})
