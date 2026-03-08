import type { EncryptedSignalBundle, SignalBundle } from '../../../engine/src/crypto/types.js'
import { decode, encode, fromBase64Url, toBase64Url } from '../../../engine/src/crypto/encoding.js'

/**
 * Encrypt a signal bundle using ephemeral X25519 ECDH, HKDF-SHA256 key derivation,
 * and AES-256-GCM with anonymous daily token bound as AAD.
 *
 * No subscriber ID is transmitted — the anonToken is a daily-rotating hash
 * that allows same-day deduplication but cannot build a profile over time.
 */
export async function encryptSignal(
    bundle: SignalBundle,
    centralPublicKeyB64: string,
    anonToken?: string,
): Promise<EncryptedSignalBundle> {
    const token = anonToken ?? 'anonymous'

    const ephemeral = await globalThis.crypto.subtle.generateKey(
        { name: 'X25519' },
        true,
        ['deriveBits'],
    )

    const centralPublicKey = await globalThis.crypto.subtle.importKey(
        'raw',
        fromBase64Url(centralPublicKeyB64),
        { name: 'X25519' },
        false,
        [],
    )

    const sharedBits = await globalThis.crypto.subtle.deriveBits(
        { name: 'X25519', public: centralPublicKey },
        ephemeral.privateKey,
        256,
    )

    const hkdfKey = await globalThis.crypto.subtle.importKey(
        'raw',
        sharedBits,
        'HKDF',
        false,
        ['deriveKey'],
    )

    const encKey = await globalThis.crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: encode('invariant-signal-salt-v2'),
            info: encode(`santh-signal-v2:${token}`),
        },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt'],
    )

    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
    const aad = encode(token)
    const plaintext = encode(JSON.stringify(bundle))

    const ciphertext = await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad },
        encKey,
        plaintext,
    )

    const ephemeralPublicKey = await globalThis.crypto.subtle.exportKey('raw', ephemeral.publicKey)

    return {
        ephemeralPublicKey: toBase64Url(new Uint8Array(ephemeralPublicKey)),
        ciphertext: toBase64Url(new Uint8Array(ciphertext)),
        iv: toBase64Url(iv),
        anonToken: token,
        v: 2,
    }
}

/**
 * Decrypt an encrypted signal bundle (central-side).
 * Uses the anonToken as AAD — no subscriber identity is recovered.
 */
export async function decryptSignal(
    encrypted: EncryptedSignalBundle,
    centralPrivateKeyB64: string,
): Promise<SignalBundle> {
    const centralPrivateKey = await globalThis.crypto.subtle.importKey(
        'raw',
        fromBase64Url(centralPrivateKeyB64),
        { name: 'X25519' },
        false,
        ['deriveBits'],
    )

    const ephemeralPublicKey = await globalThis.crypto.subtle.importKey(
        'raw',
        fromBase64Url(encrypted.ephemeralPublicKey),
        { name: 'X25519' },
        false,
        [],
    )

    const sharedBits = await globalThis.crypto.subtle.deriveBits(
        { name: 'X25519', public: ephemeralPublicKey },
        centralPrivateKey,
        256,
    )

    const hkdfKey = await globalThis.crypto.subtle.importKey(
        'raw',
        sharedBits,
        'HKDF',
        false,
        ['deriveKey'],
    )

    const token = encrypted.anonToken

    const decKey = await globalThis.crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: encode('invariant-signal-salt-v2'),
            info: encode(`santh-signal-v2:${token}`),
        },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt'],
    )

    const plaintext = await globalThis.crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: fromBase64Url(encrypted.iv),
            additionalData: encode(token),
        },
        decKey,
        fromBase64Url(encrypted.ciphertext),
    )

    // Prototype pollution guard — decrypted content is a trust boundary
    return JSON.parse(decode(new Uint8Array(plaintext)), (key, value) => {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            return undefined
        }
        return value
    }) as SignalBundle
}
