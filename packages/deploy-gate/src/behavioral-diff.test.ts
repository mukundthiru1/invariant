import { describe, expect, it } from 'vitest'

import { computeBehaviorDelta, extractBehaviors, getBehaviorBaseline, saveBehaviorBaseline, type Behaviors } from './behavioral-diff.js'

class MemoryKV {
  private readonly map = new Map<string, string>()

  async get(key: string): Promise<string | null> {
    return this.map.get(key) ?? null
  }

  async put(key: string, value: string): Promise<void> {
    this.map.set(key, value)
  }
}

describe('behavioral-diff', () => {
  it('extractBehaviors parses and deduplicates behavior signals', () => {
    const behaviors = extractBehaviors([
      "fetch('https://api.example.com/data')",
      "axios.get('https://api.example.com/data')",
      "exec('ls')",
      "const p = '../secrets.txt'",
      "import dep from 'left-pad'",
      "const dep2 = require('left-pad')",
    ])

    expect(behaviors.newDomains).toEqual(['https://api.example.com/data'])
    expect(behaviors.newExecCalls).toHaveLength(1)
    expect(behaviors.newFilePaths).toContain('../secrets.txt')
    expect(behaviors.newDeps).toEqual(['left-pad'])
  })

  it('getBehaviorBaseline returns null for invalid JSON', async () => {
    const kv = new MemoryKV()
    await kv.put('baseline:acme/repo', '{invalid json}')

    const baseline = await getBehaviorBaseline({ DEPLOY_STATE: kv as unknown as KVNamespace }, 'acme/repo')
    expect(baseline).toBeNull()
  })

  it('save/get baseline and computeBehaviorDelta returns only new values', async () => {
    const kv = new MemoryKV()
    const baseline: Behaviors = {
      newDomains: ['https://a.example.com'],
      newExecCalls: ["exec('ls')"],
      newFilePaths: ['../a.txt'],
      newDeps: ['pkg-a'],
    }

    await saveBehaviorBaseline({ DEPLOY_STATE: kv as unknown as KVNamespace }, 'acme/repo', baseline)
    const loaded = await getBehaviorBaseline({ DEPLOY_STATE: kv as unknown as KVNamespace }, 'acme/repo')

    expect(loaded).toEqual(baseline)

    const delta = computeBehaviorDelta({
      newDomains: ['https://a.example.com', 'https://b.example.com'],
      newExecCalls: ["exec('ls')", "spawn('sh')"],
      newFilePaths: ['../a.txt', '/etc/passwd'],
      newDeps: ['pkg-a', 'pkg-b'],
    }, loaded)

    expect(delta).toEqual({
      newDomains: ['https://b.example.com'],
      newExecCalls: ["spawn('sh')"],
      newFilePaths: ['/etc/passwd'],
      newDeps: ['pkg-b'],
    })
  })
})
