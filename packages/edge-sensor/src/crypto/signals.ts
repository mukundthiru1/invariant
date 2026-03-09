import type { EncryptedSignalBundle, SignalBundle } from '../../../engine/src/crypto/types.js'
import { decode, encode, fromBase64Url, toBase64Url } from '../../../engine/src/crypto/encoding.js'

function asBufferSource(bytes: Uint8Array<ArrayBufferLike>): Uint8Array<ArrayBuffer> {
    return bytes as Uint8Array<ArrayBuffer>
}

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

    const ephemeral = await crypto.subtle.generateKey(
        { name: 'X25519' },
        true,
        ['deriveBits'],
    ) as CryptoKeyPair

    const centralPublicKey = await crypto.subtle.importKey(
        'raw',
        asBufferSource(fromBase64Url(centralPublicKeyB64)),
        { name: 'X25519' },
        false,
        [],
    )

    const sharedBits = await crypto.subtle.deriveBits(
        { name: 'X25519', public: centralPublicKey } as any,
        ephemeral.privateKey,
        256,
    )

    const hkdfKey = await crypto.subtle.importKey(
        'raw',
        sharedBits,
        'HKDF',
        false,
        ['deriveKey'],
    )

    const encKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: asBufferSource(encode('invariant-signal-salt-v2')),
            info: asBufferSource(encode(`santh-signal-v2:${token}`)),
        },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt'],
    )

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const aad = encode(token)
    const plaintext = encode(JSON.stringify(bundle))

    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: asBufferSource(iv), additionalData: asBufferSource(aad) },
        encKey,
        asBufferSource(plaintext),
    )

    const ephemeralPublicKey = await crypto.subtle.exportKey('raw', ephemeral.publicKey) as ArrayBuffer

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
    const centralPrivateKey = await crypto.subtle.importKey(
        'raw',
        asBufferSource(fromBase64Url(centralPrivateKeyB64)),
        { name: 'X25519' },
        false,
        ['deriveBits'],
    )

    const ephemeralPublicKey = await crypto.subtle.importKey(
        'raw',
        asBufferSource(fromBase64Url(encrypted.ephemeralPublicKey)),
        { name: 'X25519' },
        false,
        [],
    )

    const sharedBits = await crypto.subtle.deriveBits(
        { name: 'X25519', public: ephemeralPublicKey } as any,
        centralPrivateKey,
        256,
    )

    const hkdfKey = await crypto.subtle.importKey(
        'raw',
        sharedBits,
        'HKDF',
        false,
        ['deriveKey'],
    )

    const token = encrypted.anonToken

    const decKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: asBufferSource(encode('invariant-signal-salt-v2')),
            info: asBufferSource(encode(`santh-signal-v2:${token}`)),
        },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt'],
    )

    const plaintext = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: asBufferSource(fromBase64Url(encrypted.iv)),
            additionalData: asBufferSource(encode(token)),
        },
        decKey,
        asBufferSource(fromBase64Url(encrypted.ciphertext)),
    )

    // Prototype pollution guard — decrypted content is a trust boundary
    return JSON.parse(decode(new Uint8Array(plaintext)), (key, value) => {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            return undefined
        }
        return value
    }) as SignalBundle
}
