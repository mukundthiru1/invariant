import { concat, decode, encode, fromBase64Url, toBase64Url } from '../../../engine/src/crypto/encoding.js'

const storageKeyCache = new Map<string, CryptoKey>()

export class StorageDecryptionError extends Error {
    constructor(message: string) {
        super(message)
        this.name = 'StorageDecryptionError'
    }
}

export async function importStorageKey(keyB64: string): Promise<CryptoKey> {
    const cached = storageKeyCache.get(keyB64)
    if (cached) return cached

    const key = await crypto.subtle.importKey(
        'raw',
        fromBase64Url(keyB64),
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt'],
    )

    storageKeyCache.set(keyB64, key)
    return key
}

export async function encryptStorageValue(
    plaintext: string,
    keyB64: string,
    kvKey: string,
): Promise<string> {
    const key = await importStorageKey(keyB64)
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const aad = encode(kvKey)

    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad },
        key,
        encode(plaintext),
    )

    return toBase64Url(concat(iv, new Uint8Array(ciphertext)))
}

export async function decryptStorageValue(
    blob: string,
    keyB64: string,
    kvKey: string,
): Promise<string> {
    const bytes = fromBase64Url(blob)
    const iv = bytes.slice(0, 12)
    const ciphertext = bytes.slice(12)

    const key = await importStorageKey(keyB64)
    const aad = encode(kvKey)

    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, additionalData: aad },
            key,
            ciphertext,
        )
        return decode(new Uint8Array(plaintext))
    } catch (err) {
        if (err instanceof DOMException) {
            throw new StorageDecryptionError('Decryption failed — tampered or wrong key')
        }
        throw err
    }
}
