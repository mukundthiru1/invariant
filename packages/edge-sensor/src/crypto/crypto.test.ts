import { describe, it, expect, afterEach, vi } from 'vitest'
import { decryptSignal, encryptSignal } from './signals.js'
import {
    StorageDecryptionError,
    decryptStorageValue,
    encryptStorageValue,
    importStorageKey,
} from './storage.js'
import {
    SignalBuffer,
    makeSignalBundle,
    sanitizePayload,
    type PendingSignal,
} from '../modules/signal-uploader.js'
import { SignalDeduplicator, hashPayload } from '../modules/signal-dedup.js'
import { computeCampaignFingerprint } from '../modules/campaign-fingerprint.js'
import { fromBase64Url, toBase64Url } from '../../../engine/src/crypto/encoding.js'
import type { SignalBundle } from '../../../engine/src/crypto/types.js'

const PKCS8_X25519_RAW_KEY_OFFSET = 16
const PKCS8_X25519_PREFIX = new Uint8Array([
    0x30, 0x2e,
    0x02, 0x01, 0x00,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x6e,
    0x04, 0x22,
    0x04, 0x20,
])

function installNodeX25519RawPrivateImportCompat(): void {
    const originalImportKey = globalThis.crypto.subtle.importKey.bind(globalThis.crypto.subtle)
    vi.spyOn(globalThis.crypto.subtle, 'importKey').mockImplementation(
        (format, keyData, algorithm, extractable, keyUsages) => {
            if (
                format === 'raw' &&
                algorithm &&
                typeof algorithm === 'object' &&
                'name' in algorithm &&
                algorithm.name === 'X25519' &&
                keyUsages.length === 1 &&
                keyUsages[0] === 'deriveBits' &&
                keyData instanceof Uint8Array &&
                keyData.length === 32
            ) {
                const pkcs8 = new Uint8Array(PKCS8_X25519_PREFIX.length + keyData.length)
                pkcs8.set(PKCS8_X25519_PREFIX, 0)
                pkcs8.set(keyData, PKCS8_X25519_PREFIX.length)
                return originalImportKey('pkcs8', pkcs8, { name: 'X25519' }, extractable, keyUsages)
            }

            return originalImportKey(format, keyData, algorithm, extractable, keyUsages)
        },
    )
}

async function generateX25519RawKeyPairB64(): Promise<{ publicKey: string; privateKey: string }> {
    const keypair = await globalThis.crypto.subtle.generateKey(
        { name: 'X25519' },
        true,
        ['deriveBits'],
    )

    const publicKeyRaw = new Uint8Array(
        await globalThis.crypto.subtle.exportKey('raw', keypair.publicKey),
    )
    const privateKeyPkcs8 = new Uint8Array(
        await globalThis.crypto.subtle.exportKey('pkcs8', keypair.privateKey),
    )
    const privateKeyRaw = privateKeyPkcs8.slice(PKCS8_X25519_RAW_KEY_OFFSET)

    if (privateKeyRaw.length !== 32) {
        throw new Error(`unexpected X25519 private key length: ${privateKeyRaw.length}`)
    }

    return {
        publicKey: toBase64Url(publicKeyRaw),
        privateKey: toBase64Url(privateKeyRaw),
    }
}

function makeFixtureSignalBundle(overrides: Partial<SignalBundle> = {}): SignalBundle {
    return {
        invariantClass: 'sql_tautology',
        detectionLevel: 'l2',
        confidence: 0.92,
        encodingDepth: 2,
        method: 'POST',
        surface: 'body_param',
        timestamp: 1731000000000,
        evidence: 'pattern=OR 1=1',
        v: 2,
        ...overrides,
    }
}

describe('signals.ts', () => {
    afterEach(() => {
        vi.restoreAllMocks()
    })

    it('encryptSignal + decryptSignal round-trip preserves bundle fields', async () => {
        installNodeX25519RawPrivateImportCompat()
        const keys = await generateX25519RawKeyPairB64()
        const bundle = makeFixtureSignalBundle()

        const encrypted = await encryptSignal(bundle, keys.publicKey, 'anon-token-abc')
        const decrypted = await decryptSignal(encrypted, keys.privateKey)

        expect(decrypted).toEqual(bundle)
    })

    it('throws when signal ciphertext is tampered', async () => {
        installNodeX25519RawPrivateImportCompat()
        const keys = await generateX25519RawKeyPairB64()
        const encrypted = await encryptSignal(makeFixtureSignalBundle(), keys.publicKey, 'tok')
        const tamperedCiphertext = fromBase64Url(encrypted.ciphertext)
        tamperedCiphertext[0] ^= 0x01

        await expect(
            decryptSignal(
                { ...encrypted, ciphertext: toBase64Url(tamperedCiphertext) },
                keys.privateKey,
            ),
        ).rejects.toThrow()
    })

    it('throws when decrypted with the wrong private key', async () => {
        installNodeX25519RawPrivateImportCompat()
        const keyA = await generateX25519RawKeyPairB64()
        const keyB = await generateX25519RawKeyPairB64()
        const encrypted = await encryptSignal(makeFixtureSignalBundle(), keyA.publicKey, 'tok')

        await expect(decryptSignal(encrypted, keyB.privateKey)).rejects.toThrow()
    })

    it('throws when anonToken is modified (AAD mismatch)', async () => {
        installNodeX25519RawPrivateImportCompat()
        const keys = await generateX25519RawKeyPairB64()
        const encrypted = await encryptSignal(makeFixtureSignalBundle(), keys.publicKey, 'tok-a')
        const modified = { ...encrypted, anonToken: 'tok-b' }

        await expect(decryptSignal(modified, keys.privateKey)).rejects.toThrow()
    })
})

describe('storage.ts', () => {
    it('encryptStorageValue + decryptStorageValue round-trip', async () => {
        const keyB64 = toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(32)))
        const plaintext = 'stored-state-value'
        const kvKey = 'session:123'

        const blob = await encryptStorageValue(plaintext, keyB64, kvKey)
        const decrypted = await decryptStorageValue(blob, keyB64, kvKey)

        expect(decrypted).toBe(plaintext)
    })

    it('throws StorageDecryptionError for kvKey AAD mismatch', async () => {
        const keyB64 = toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(32)))
        const blob = await encryptStorageValue('secret', keyB64, 'a')

        await expect(decryptStorageValue(blob, keyB64, 'b')).rejects.toBeInstanceOf(
            StorageDecryptionError,
        )
    })

    it('importStorageKey caches key instances by key string', async () => {
        const keyB64 = toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(32)))
        const importedA = await importStorageKey(keyB64)
        const importedB = await importStorageKey(keyB64)

        expect(importedA).toBe(importedB)
    })

    it('throws when storage blob is tampered', async () => {
        const keyB64 = toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(32)))
        const blob = await encryptStorageValue('payload', keyB64, 'item:key')
        const tampered = fromBase64Url(blob)
        tampered[15] ^= 0x80

        await expect(
            decryptStorageValue(toBase64Url(tampered), keyB64, 'item:key'),
        ).rejects.toBeInstanceOf(StorageDecryptionError)
    })
})

describe('signal-uploader.ts', () => {
    it('SignalBuffer accepts l2/l3 and rejects l1', () => {
        const buffer = new SignalBuffer()
        buffer.push({ bundle: makeFixtureSignalBundle({ detectionLevel: 'l2' }), queuedAt: 1 })
        buffer.push({ bundle: makeFixtureSignalBundle({ detectionLevel: 'l3' }), queuedAt: 2 })
        buffer.push({ bundle: makeFixtureSignalBundle({ detectionLevel: 'l1' }), queuedAt: 3 })

        expect(buffer.size).toBe(2)
    })

    it('SignalBuffer drops oldest signal after maxSize=500 is exceeded', () => {
        const buffer = new SignalBuffer()
        for (let i = 0; i < 501; i++) {
            buffer.push({
                bundle: makeFixtureSignalBundle({
                    detectionLevel: 'l2',
                    invariantClass: `class-${i}`,
                }),
                queuedAt: i,
            })
        }

        expect(buffer.size).toBe(500)
        const drained = buffer.drain()
        expect(drained[0].bundle.invariantClass).toBe('class-1')
        expect(drained[499].bundle.invariantClass).toBe('class-500')
    })

    it('SignalBuffer.drain returns all signals and empties the buffer', () => {
        const buffer = new SignalBuffer()
        buffer.push({ bundle: makeFixtureSignalBundle({ invariantClass: 'a' }), queuedAt: 1 })
        buffer.push({ bundle: makeFixtureSignalBundle({ invariantClass: 'b' }), queuedAt: 2 })

        const drained = buffer.drain()

        expect(drained.length).toBe(2)
        expect(buffer.size).toBe(0)
        expect(buffer.isEmpty).toBe(true)
    })

    it('makeSignalBundle sets detection level and rounds timestamp to hour', () => {
        const bundle = makeSignalBundle(
            {
                class: 'xss_tag_injection',
                confidence: 0.8,
                detectionLevel: { l1: true, l2: true },
                l2Evidence: 'evidence',
            },
            { method: 'GET', pathname: '/users/123' },
            0,
        )

        expect(bundle.detectionLevel).toBe('l2')
        expect(bundle.timestamp % 3_600_000).toBe(0) // rounded to hour
        expect(bundle.v).toBe(2)
    })

    it('makeSignalBundle sanitizes quoted strings and key=value evidence', () => {
        const bundle = makeSignalBundle(
            {
                class: 'sql_tautology',
                confidence: 0.9,
                detectionLevel: { l1: true, l2: true },
                l2Evidence: `user='alice' token="abc123" apiKey=sekret and \`cmd\``,
            },
            { method: 'POST', pathname: '/api/login' },
            1,
        )

        expect(bundle.evidence).toBeDefined()
        expect(bundle.evidence).not.toContain('alice')
        expect(bundle.evidence).not.toContain('abc123')
        expect(bundle.evidence).not.toContain('sekret')
        expect(bundle.evidence).toContain('apiKey=[redacted]')
    })

    it('makeSignalBundle sets detectionLevel using l2/l1 precedence rules', () => {
        const l2Bundle = makeSignalBundle(
            { class: 'cmd_separator', confidence: 0.9, detectionLevel: { l1: true, l2: true } },
            { method: 'GET', pathname: '/a' }, 0,
        )
        const l3Bundle = makeSignalBundle(
            { class: 'cmd_separator', confidence: 0.9, detectionLevel: { l1: false, l2: false } },
            { method: 'GET', pathname: '/b' }, 0,
        )
        const l1Bundle = makeSignalBundle(
            { class: 'cmd_separator', confidence: 0.9, detectionLevel: { l1: true, l2: false } },
            { method: 'GET', pathname: '/c' }, 0,
        )

        expect(l2Bundle.detectionLevel).toBe('l2')
        expect(l3Bundle.detectionLevel).toBe('l3')
        expect(l1Bundle.detectionLevel).toBe('l1')
    })
})

describe('sanitizePayload', () => {
    it('strips email addresses', () => {
        const result = sanitizePayload("admin@company.com' OR 1=1--")
        expect(result).toContain('[email]')
        expect(result).not.toContain('admin@company.com')
        expect(result).toContain("OR 1=1--")
    })

    it('strips internal IP addresses', () => {
        const result = sanitizePayload('http://192.168.1.100:8080/admin')
        expect(result).toContain('[internal-ip]')
        expect(result).not.toContain('192.168.1.100')
    })

    it('strips internal hostnames', () => {
        const result = sanitizePayload('http://db-prod.acme.internal:5432/query')
        expect(result).toContain('[internal-host]')
        expect(result).not.toContain('db-prod.acme.internal')
    })

    it('masks domains in URLs but keeps attack-relevant ones', () => {
        const ssrf = sanitizePayload('http://169.254.169.254/latest/meta-data/')
        expect(ssrf).toContain('169.254.169.254')

        const external = sanitizePayload('http://evil-callback.com/steal?data=1')
        expect(external).toContain('[domain]')
        expect(external).not.toContain('evil-callback.com')
    })

    it('keeps SQL injection syntax intact', () => {
        const result = sanitizePayload("' UNION SELECT username,password FROM users--")
        expect(result).toContain('UNION SELECT')
        expect(result).toContain('FROM users')
    })

    it('keeps XSS vectors intact', () => {
        const result = sanitizePayload('<script>alert(document.cookie)</script>')
        expect(result).toContain('<script>')
        expect(result).toContain('alert(document.cookie)')
    })

    it('keeps path traversal sequences intact', () => {
        const result = sanitizePayload('../../../etc/passwd')
        expect(result).toContain('../../../etc/passwd')
    })

    it('strips bearer tokens and API keys', () => {
        const result = sanitizePayload('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U')
        expect(result).toContain('[redacted]')
        expect(result).not.toContain('eyJhbGci')
    })

    it('strips Authorization header values', () => {
        const result = sanitizePayload('Authorization: Basic dXNlcjpwYXNz')
        expect(result).toContain('Authorization:')
        expect(result).toContain('[redacted]')
        expect(result).not.toContain('dXNlcjpwYXNz')
    })

    it('strips cookie values but keeps header name', () => {
        const result = sanitizePayload('Cookie: session=abc123secret; user=admin')
        expect(result).toContain('Cookie:')
        expect(result).toContain('[value]')
        expect(result).not.toContain('abc123secret')
    })

    it('returns undefined for empty input', () => {
        expect(sanitizePayload('')).toBeUndefined()
    })

    it('truncates payloads over 4KB', () => {
        const long = 'A'.repeat(5000)
        const result = sanitizePayload(long)
        expect(result!.length).toBeLessThanOrEqual(4096)
    })
})

describe('signal-dedup.ts', () => {
    it('Bloom filter catches duplicates', () => {
        const deduplicator = new SignalDeduplicator()
        const key = hashPayload('sql_tautology', 'OR 1=1')

        expect(deduplicator.isDuplicate(key)).toBe(false)
        expect(deduplicator.isDuplicate(key)).toBe(true)
    })

    it('Bloom filter does not false-negative on new signals', () => {
        const deduplicator = new SignalDeduplicator()
        const keyA = hashPayload('xss_tag_injection', '<script>alert(1)</script>')
        const keyB = hashPayload('cmd_separator', 'a;cat /etc/passwd')

        expect(deduplicator.isDuplicate(keyA)).toBe(false)
        expect(deduplicator.isDuplicate(keyB)).toBe(false)
        expect(deduplicator.isDuplicate(keyA)).toBe(true)
        expect(deduplicator.isDuplicate(keyB)).toBe(true)
    })

    it('saturation tracking works and reset clears it', () => {
        const deduplicator = new SignalDeduplicator()
        expect(deduplicator.saturation()).toBe(0)

        deduplicator.isDuplicate(hashPayload('sql_union', "UNION SELECT 'x'"))
        const afterInsert = deduplicator.saturation()
        expect(afterInsert).toBeGreaterThan(0)
        expect(afterInsert).toBeLessThanOrEqual(1)

        deduplicator.reset()
        expect(deduplicator.saturation()).toBe(0)
    })
})

describe('campaign-fingerprint.ts', () => {
    function pendingSignalsForOrder(
        firstClass: string,
        secondClass: string,
    ): PendingSignal[] {
        const baseTs = 1731003600000
        return [
            {
                bundle: {
                    ...makeFixtureSignalBundle({
                        invariantClass: firstClass,
                        payload: 'q=%3Cscript%3Ealert(1)%3C/script%3E',
                        surface: 'query_param',
                        encodingDepth: 1,
                        timestamp: baseTs,
                    }),
                },
                queuedAt: baseTs,
            },
            {
                bundle: {
                    ...makeFixtureSignalBundle({
                        invariantClass: secondClass,
                        payload: 'dGVzdD0x',
                        evidence: '\\u003cimg\\u003e',
                        surface: 'body_param',
                        encodingDepth: 2,
                        timestamp: baseTs + 60_000,
                    }),
                },
                queuedAt: baseTs + 60_000,
            },
        ]
    }

    it('campaign fingerprint is deterministic', () => {
        const signals = pendingSignalsForOrder('sql_tautology', 'xss_tag_injection')
        const a = computeCampaignFingerprint(signals)
        const b = computeCampaignFingerprint(signals)
        expect(a).toBe(b)
    })

    it('same attack pattern produces same fingerprint regardless of order', () => {
        const ordered = pendingSignalsForOrder('sql_tautology', 'xss_tag_injection')
        const reversed = pendingSignalsForOrder('xss_tag_injection', 'sql_tautology')
        expect(computeCampaignFingerprint(ordered)).toBe(computeCampaignFingerprint(reversed))
    })
})
