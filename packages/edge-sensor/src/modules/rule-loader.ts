import DynamicRuleStore from './dynamic-rules.js'
import { decryptRuleBundle, verifyRuleBundle } from '../crypto/rules.js'
import type { EncryptedRuleBundle, RuleBundle } from '../../../engine/src/crypto/types.js'

interface KVNamespace {
    get(key: string, type: 'text'): Promise<string | null>
    delete(key: string): Promise<void>
}

export interface LoadRuleResult {
    applied: boolean
    /** The decrypted bundle, present only when applied === true. */
    bundle?: RuleBundle
    reason?: string
}

// Note: the KV namespace stores the rule bundle in its encrypted form
// (encBundleKey + encRules — see EncryptedRuleBundle). The subscriber's
// X25519 private key is used to decrypt it. The general-purpose AES storage key
// (INVARIANT_STORAGE_KEY) is for other KV values and is NOT used here.
export async function loadPendingRules(
    kv: KVNamespace,
    store: DynamicRuleStore,
    subscriberPrivateKeyB64: string,
    santhVerifyKeyB64: string,
): Promise<LoadRuleResult> {

    try {
        const raw = await kv.get('invariant:rules:pending', 'text')
        if (raw == null) {
            return {
                applied: false,
                reason: 'no_pending_bundle',
            }
        }

        // SAA-091: Prototype pollution guard on KV-sourced data
        const bundle: EncryptedRuleBundle = JSON.parse(raw, (k, v) =>
            k === '__proto__' || k === 'constructor' || k === 'prototype' ? undefined : v)
        if (bundle.v !== 1 || bundle.expiresAt <= Date.now()) {
            return {
                applied: false,
                reason: 'expired_or_unknown_schema',
            }
        }

        const valid = await verifyRuleBundle(bundle, santhVerifyKeyB64)
        if (!valid) {
            await kv.delete('invariant:rules:pending')
            return {
                applied: false,
                reason: 'signature_invalid',
            }
        }

        const ruleBundle = await decryptRuleBundle(bundle, subscriberPrivateKeyB64)
        const applied = store.applyBundle(ruleBundle)

        await kv.delete('invariant:rules:pending')

        return {
            applied,
            bundle: applied ? ruleBundle : undefined,
            reason: applied ? undefined : 'stale_version',
        }
    } catch (error) {
        return {
            applied: false,
            reason: error instanceof Error ? error.message : String(error),
        }
    }
}
