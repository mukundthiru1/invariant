/**
 * @santh/edge-sensor — Rule Bundle Crypto Module
 *
 * Verifies and decrypts signed rule bundles dispatched by Santh central.
 */

import type { EncryptedRuleBundle, RuleBundle } from '../../../engine/src/crypto/types.js'
import { concat, decode, encode, fromBase64Url, uint64BE } from '../../../engine/src/crypto/encoding.js'

// PKCS8 v0 ASN.1 prefix for an X25519 private key (RFC 5958 / RFC 8410).
// This is the format produced by Web Crypto (Node.js 20+, CF Workers, Chrome).
// Layout (48 bytes total = 16-byte header + 32-byte key):
//   SEQUENCE {
//     INTEGER 0                      -- PrivateKeyInfo version = 0
//     SEQUENCE { OID 1.3.101.110 }   -- X25519 algorithm
//     OCTET STRING {
//       OCTET STRING { <32 raw bytes> }  -- PrivateKey
//     }
//   }
// Byte sequence: 30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20
const PKCS8_X25519_PREFIX = new Uint8Array([
    0x30, 0x2e,                      // SEQUENCE (46 bytes)
    0x02, 0x01, 0x00,                // INTEGER 0 (version)
    0x30, 0x05,                      // SEQUENCE (5 bytes)
    0x06, 0x03, 0x2b, 0x65, 0x6e,   // OID 1.3.101.110 (X25519)
    0x04, 0x22,                      // OCTET STRING (34 bytes)
    0x04, 0x20,                      // OCTET STRING (32 bytes) — key follows
])
// 16 bytes total prefix; raw key at offset 16


export class InvariantCryptoError extends Error {
    constructor(message: string) {
        super(`[InvariantCryptoError] ${message}`)
        this.name = 'InvariantCryptoError'
    }
}

// ── Ed25519 Signature Verification ─────────────────────────────────

/**
 * Verify the Ed25519 signature on a dispatched rule bundle.
 * Returns false (never throws) if signature invalid or bundle expired.
 */
export async function verifyRuleBundle(
    bundle: EncryptedRuleBundle,
    santhVerifyKeyB64: string,
): Promise<boolean> {
    if (bundle.expiresAt <= Date.now()) return false

    try {
        const verifyKeyBytes = fromBase64Url(santhVerifyKeyB64)
        const verifyKey = await crypto.subtle.importKey(
            'raw',
            verifyKeyBytes,
            { name: 'Ed25519' },
            false,
            ['verify'],
        )

        const encBundleKeyBytes = fromBase64Url(bundle.encBundleKey)
        const encRulesBytes = fromBase64Url(bundle.encRules)

        const signedMessage = concat(
            encBundleKeyBytes,
            encRulesBytes,
            uint64BE(bundle.bundleVersion),
            uint64BE(bundle.expiresAt),
        )

        return await crypto.subtle.verify(
            { name: 'Ed25519' },
            verifyKey,
            fromBase64Url(bundle.signature),
            signedMessage,
        )
    } catch {
        return false
    }
}


// ── Rule Bundle Decryption ────────────────────────────────────────

/**
 * Decrypt a verified rule bundle using the subscriber's X25519 private key.
 */
export async function decryptRuleBundle(
    bundle: EncryptedRuleBundle,
    subscriberPrivateKeyB64: string,
): Promise<RuleBundle> {
    try {
        const encBundleKeyBytes = fromBase64Url(bundle.encBundleKey)
        if (encBundleKeyBytes.length < 44) throw new InvariantCryptoError('encBundleKey too short')

        const ephemeralPubKeyBytes = encBundleKeyBytes.slice(0, 32)
        const encKeyBlob = encBundleKeyBytes.slice(32)
        if (encKeyBlob.length < 28) {
            throw new InvariantCryptoError('encBundleKey blob too short to contain AES-GCM iv/ciphertext/tag')
        }

        const subscriberPrivateKey = await importX25519PrivateKey(subscriberPrivateKeyB64)
        const ephemeralPublicKey = await crypto.subtle.importKey(
            'raw',
            ephemeralPubKeyBytes,
            { name: 'X25519' },
            false,
            [],
        )

        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'X25519', public: ephemeralPublicKey },
            subscriberPrivateKey,
            256,
        )

        const hkdfKey = await crypto.subtle.importKey(
            'raw',
            new Uint8Array(sharedBits),
            { name: 'HKDF' },
            false,
            ['deriveKey'],
        )

        const bundleKeyDerivationKey = await crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: encode('invariant-rule-salt-v1'),
                info: encode('santh-rule-bundle-v1'),
            },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt'],
        )

        const keyIv = encKeyBlob.slice(0, 12)
        const encryptedBundleKey = encKeyBlob.slice(12)

        const decryptedBundleKey = new Uint8Array(
            await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: keyIv },
                bundleKeyDerivationKey,
                encryptedBundleKey,
            ),
        )
        if (decryptedBundleKey.length !== 32) {
            throw new InvariantCryptoError('decrypted bundle key has unexpected length')
        }

        const bundleKey = await crypto.subtle.importKey(
            'raw',
            decryptedBundleKey,
            { name: 'AES-GCM' },
            false,
            ['decrypt'],
        )

        const encRulesBytes = fromBase64Url(bundle.encRules)
        if (encRulesBytes.length <= 12) throw new InvariantCryptoError('encRules too short')
        const rulesIv = encRulesBytes.slice(0, 12)
        const encRules = encRulesBytes.slice(12)

        // AAD = subscriberId || bundleVersion (UTF-8), matching what central writes.
        // Using a colon separator makes the concatenation unambiguous across all possible
        // subscriberId values (which are UUIDs — no colons — so this is collision-free).
        const aad = encode(bundle.subscriberId + ':' + String(bundle.bundleVersion))
        const plaintext = new Uint8Array(
            await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: rulesIv,
                    additionalData: aad,
                },
                bundleKey,
                encRules,
            ),
        )

        // SAA-091: Prototype pollution guard — decrypted content is a trust boundary
        const parsed = JSON.parse(decode(plaintext), (key, value) => {
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                return undefined
            }
            return value
        }) as RuleBundle
        if (!parsed || parsed.v !== 1) {
            throw new InvariantCryptoError('decrypted rule bundle has invalid schema version')
        }

        return parsed
    } catch (err) {
        if (err instanceof InvariantCryptoError) throw err
        throw new InvariantCryptoError(`failed to decrypt rule bundle: ${String(err)}`)
    }
}


/**
 * Import a raw 32-byte X25519 private key (stored as base64url in CF Secrets).
 *
 * Web Crypto does not support 'raw' import for private keys — only public keys.
 * We wrap the 32 bytes in a minimal PKCS8 ASN.1 envelope (RFC 8410) and import
 * as 'pkcs8', which is supported identically on CF Workers and Node.js ≥ 20.
 * The key material is the same 32 bytes; the wrapper is pure format overhead.
 */
async function importX25519PrivateKey(rawKeyB64: string): Promise<CryptoKey> {
    const rawBytes = fromBase64Url(rawKeyB64)
    if (rawBytes.length !== 32) {
        throw new InvariantCryptoError(
            `X25519 private key must be 32 bytes; got ${rawBytes.length}`,
        )
    }

    const pkcs8 = concat(PKCS8_X25519_PREFIX, rawBytes)

    try {
        return await crypto.subtle.importKey(
            'pkcs8',
            pkcs8,
            { name: 'X25519' },
            false,
            ['deriveBits'],
        )
    } catch (err) {
        throw new InvariantCryptoError(`failed to import X25519 private key: ${String(err)}`)
    }
}
