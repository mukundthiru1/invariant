import type { AuditEvent } from './types.js'

const encoder = new TextEncoder()

function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
    throw new Error('invalid hex input')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

async function sha256(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(data))
  return bytesToHex(new Uint8Array(digest))
}

export async function buildMerkleRoot(events: AuditEvent[]): Promise<string> {
  if (events.length === 0) {
    return sha256(encoder.encode('empty_merkle_tree'))
  }

  let level = [...events]
    .map(e => e.hmac)
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b))

  if (level.length === 0) {
    return sha256(encoder.encode('empty_hmac_set'))
  }

  while (level.length > 1) {
    const next: string[] = []
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]
      const right = level[i + 1] ?? level[i]
      const combined = new Uint8Array(hexToBytes(left).length + hexToBytes(right).length)
      combined.set(hexToBytes(left), 0)
      combined.set(hexToBytes(right), hexToBytes(left).length)
      next.push(await sha256(combined))
    }
    level = next
  }

  return level[0]
}
