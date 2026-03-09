import { describe, expect, it } from 'vitest'

import { approveDeployRecord, createDeployRecord, denyDeployRecord, getDeployRecord } from './store.js'

class MemoryKV {
  private readonly map = new Map<string, string>()

  async get(key: string): Promise<string | null> {
    return this.map.get(key) ?? null
  }

  async put(key: string, value: string): Promise<void> {
    this.map.set(key, value)
  }
}

const env = () => ({ DEPLOY_STATE: new MemoryKV() as unknown as KVNamespace })

describe('store', () => {
  it('createDeployRecord persists pending status', async () => {
    const storeEnv = env()
    const record = await createDeployRecord(storeEnv, 'd1', { findings: [] }, 'github')

    expect(record.status).toBe('pending')
    const loaded = await getDeployRecord(storeEnv, 'd1')
    expect(loaded?.deployId).toBe('d1')
  })

  it('approveDeployRecord updates status and approver', async () => {
    const storeEnv = env()
    await createDeployRecord(storeEnv, 'd2', { findings: [] }, 'github')

    const approved = await approveDeployRecord(storeEnv, 'd2', 'cred-1')
    expect(approved?.status).toBe('approved')
    expect(approved?.approverCredentialId).toBe('cred-1')
  })

  it('denyDeployRecord updates status', async () => {
    const storeEnv = env()
    await createDeployRecord(storeEnv, 'd3', { findings: [] }, 'github')

    const denied = await denyDeployRecord(storeEnv, 'd3')
    expect(denied?.status).toBe('denied')
  })
})
