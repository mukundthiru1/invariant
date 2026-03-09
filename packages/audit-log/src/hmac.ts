import type { AuditEvent, EventForSignature } from './types.js'

const encoder = new TextEncoder()

function canonicalizeEvent(event: EventForSignature): string {
  const ordered: Record<string, unknown> = {
    event_type: event.event_type,
    commit_hash: event.commit_hash ?? null,
    tree_hash: event.tree_hash ?? null,
    author_email: event.author_email ?? null,
    ts: event.ts ?? null,
    deploy_id: event.deploy_id ?? null,
    approved_by: event.approved_by ?? null,
    customer_id: event.customer_id,
    platform: event.platform ?? null,
    findings_json: event.findings_json ?? null,
  }
  return JSON.stringify(ordered)
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  )
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/i.test(hex)) {
    throw new Error('invalid hmac hex format')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export async function signEvent(event: EventForSignature, secret: string): Promise<string> {
  const key = await importHmacKey(secret)
  const payload = encoder.encode(canonicalizeEvent(event))
  const sig = await crypto.subtle.sign('HMAC', key, payload)
  return bytesToHex(new Uint8Array(sig))
}

export async function verifyEvent(event: AuditEvent, hmac: string, secret: string): Promise<boolean> {
  try {
    const key = await importHmacKey(secret)
    const payloadEvent: EventForSignature = {
      event_type: event.event_type,
      commit_hash: event.commit_hash ?? null,
      tree_hash: event.tree_hash ?? null,
      author_email: event.author_email ?? null,
      ts: event.ts,
      deploy_id: event.deploy_id ?? null,
      approved_by: event.approved_by ?? null,
      customer_id: event.customer_id,
      platform: event.platform ?? null,
      findings_json: event.findings_json ?? null,
    }
    const payload = encoder.encode(canonicalizeEvent(payloadEvent))
    const signature = new Uint8Array(hexToBytes(hmac))
    return crypto.subtle.verify('HMAC', key, signature, payload)
  } catch {
    return false
  }
}
