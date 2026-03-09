import { afterEach, describe, expect, it, vi } from 'vitest'

import worker, { type Env } from './index.js'

class MemoryKV {
  private readonly map = new Map<string, string>()

  async get(
    key: string,
    typeOrOptions?:
      | 'text'
      | 'json'
      | 'arrayBuffer'
      | 'stream'
      | Partial<KVNamespaceGetOptions<undefined>>
      | KVNamespaceGetOptions<'text'>
      | KVNamespaceGetOptions<'json'>
      | KVNamespaceGetOptions<'arrayBuffer'>
      | KVNamespaceGetOptions<'stream'>,
  ): Promise<string | ArrayBuffer | ReadableStream | unknown | null> {
    const value = this.map.get(key)
    if (value === undefined) return null

    const type = typeof typeOrOptions === 'string' ? typeOrOptions : typeOrOptions?.type
    if (!type || type === 'text') return value
    if (type === 'json') return JSON.parse(value)
    if (type === 'arrayBuffer') return new TextEncoder().encode(value).buffer
    return new ReadableStream()
  }

  async getWithMetadata(key: string): Promise<KVNamespaceGetWithMetadataResult<string, unknown>> {
    const value = this.map.get(key)
    return { value: value ?? null, metadata: null, cacheStatus: null }
  }

  async put(key: string, value: string | ArrayBuffer | ReadableStream | ArrayBufferView): Promise<void> {
    if (typeof value === 'string') {
      this.map.set(key, value)
      return
    }

    if (value instanceof ArrayBuffer) {
      this.map.set(key, new TextDecoder().decode(value))
      return
    }

    if (ArrayBuffer.isView(value)) {
      this.map.set(key, new TextDecoder().decode(value))
      return
    }

    this.map.set(key, '')
  }

  async list(): Promise<KVNamespaceListResult<unknown>> {
    const keys = [...this.map.keys()].map(name => ({ name }))
    return {
      keys,
      list_complete: true,
      cacheStatus: null,
    }
  }

  async delete(key: string): Promise<void> {
    this.map.delete(key)
  }
}

function makeEnv(): Env {
  return {
    DEPLOY_STATE: new MemoryKV() as unknown as KVNamespace<string>,
    APPROVAL_SHARED_SECRET: 'secret-token',
  }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('deploy-gate worker', () => {
  it('supports legacy camelCase webhook fields (Law 2 compatibility)', async () => {
    const env = makeEnv()

    const response = await worker.fetch(new Request('https://gate.test/v1/webhook/generic', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        gitRef: 'refs/heads/main',
        repository: 'acme/invariant',
        deployId: 'deploy-camel',
        diff_lines: ['const secure = true'],
      }),
    }), env)

    expect([200, 202]).toContain(response.status)
    const statusResponse = await worker.fetch(new Request('https://gate.test/v1/status/deploy-camel'), env)
    expect(statusResponse.status).toBe(200)
  })

  it('webhook receives valid payload and creates deploy record', async () => {
    const env = makeEnv()

    const request = new Request('https://gate.test/v1/webhook/generic', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        git_ref: 'refs/heads/main',
        repo: 'acme/invariant',
        platform: 'generic',
        deploy_id: 'deploy-created',
        diff_lines: ['const safeValue = 42;'],
      }),
    })

    const response = await worker.fetch(request, env)
    expect([200, 202]).toContain(response.status)

    const statusResponse = await worker.fetch(new Request('https://gate.test/v1/status/deploy-created'), env)
    expect(statusResponse.status).toBe(200)

    const statusJson = await statusResponse.json() as { record: { deployId: string } }
    expect(statusJson.record.deployId).toBe('deploy-created')
  })

  it('clean diff auto-approves and returns 200', async () => {
    const env = makeEnv()

    const response = await worker.fetch(new Request('https://gate.test/v1/webhook/generic', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        git_ref: 'refs/heads/main',
        repo: 'acme/invariant',
        platform: 'generic',
        deploy_id: 'deploy-clean',
        diff_lines: ['const userCount = total + 1;'],
      }),
    }), env)

    expect(response.status).toBe(200)
    const body = await response.json() as { status: string }
    expect(body.status).toBe('approved')
  })

  it('flagged diff returns 202 pending', async () => {
    const env = makeEnv()

    const response = await worker.fetch(new Request('https://gate.test/v1/webhook/generic', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        git_ref: 'refs/heads/main',
        repo: 'acme/invariant',
        platform: 'generic',
        deploy_id: 'deploy-flagged',
        diff_lines: ["const payload = \"<script>alert(1)</script>\";"],
      }),
    }), env)

    expect(response.status).toBe(202)
    const body = await response.json() as { status: string }
    expect(body.status).toBe('pending')
  })

  it('empty diff requires manual review (Law 1 no-stub gate)', async () => {
    const env = makeEnv()

    const response = await worker.fetch(new Request('https://gate.test/v1/webhook/generic', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        git_ref: 'refs/heads/main',
        repo: 'acme/invariant',
        deploy_id: 'deploy-empty-diff',
        diff_lines: [],
      }),
    }), env)

    expect(response.status).toBe(202)
    const body = await response.json() as { status: string }
    expect(body.status).toBe('pending')
  })

  it('approval token received approves and notifies downstream', async () => {
    const env = makeEnv()
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('ok', { status: 200 }))

    const createResponse = await worker.fetch(new Request('https://gate.test/v1/webhook/generic', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        git_ref: 'refs/heads/main',
        repo: 'acme/invariant',
        platform: 'generic',
        deploy_id: 'deploy-approval',
        callback_url: 'https://downstream.test/deploy-status',
        diff_lines: ["const payload = \"<script>alert(1)</script>\";"],
      }),
    }), env)

    expect(createResponse.status).toBe(202)

    const approveResponse = await worker.fetch(new Request('https://gate.test/v1/approve/deploy-approval', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: 'secret-token',
        approver_credential_id: 'cred-123',
      }),
    }), env)

    expect(approveResponse.status).toBe(200)

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://downstream.test/deploy-status',
      expect.objectContaining({ method: 'POST' }),
    )

    const statusResponse = await worker.fetch(new Request('https://gate.test/v1/status/deploy-approval'), env)
    const statusBody = await statusResponse.json() as { status: string }
    expect(statusBody.status).toBe('approved')
  })
})
