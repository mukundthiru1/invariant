import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('./webauthn.js', () => ({
    generateRegistrationOptions: vi.fn(),
    verifyRegistration: vi.fn(),
    generateAuthenticationOptions: vi.fn(),
    verifyAuthentication: vi.fn(),
    setWebAuthnConfig: vi.fn(),
}))

import worker from './index.js'
import * as webauthn from './webauthn.js'
import { bindStoreEnv, getChallenge, getCredential, storeCredential, storeChallenge } from './store.js'
import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/types'

type JsonLike = Record<string, unknown> | null

class InMemoryKV {
    private readonly entries = new Map<string, { value: string; expiresAt?: number }>()

    async get<T = string>(key: string): Promise<T | null> {
        const entry = this.entries.get(key)
        if (!entry) return null
        if (entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
            this.entries.delete(key)
            return null
        }
        return (entry.value as unknown) as T
    }

    async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
        const expiresAt = options?.expirationTtl === undefined ? undefined : Date.now() + options.expirationTtl * 1000
        this.entries.set(key, { value, expiresAt })
    }

    async delete(key: string): Promise<void> {
        this.entries.delete(key)
    }

    async getWithMetadata<T = string, M = unknown>(key: string): Promise<KVNamespaceGetWithMetadataResult<T, M>> {
        const value = await this.get<T>(key)
        return {
            value,
            metadata: null,
            cacheStatus: null,
        }
    }

    async list<M = unknown>(): Promise<KVNamespaceListResult<M>> {
        return {
            keys: [...this.entries.keys()].map(name => ({ name })),
            list_complete: true,
            cacheStatus: null,
        }
    }
}

interface TestEnv {
    AUTH_GATE_CREDENTIAL_STORE: KVNamespace
    AUTH_GATE_CHALLENGE_STORE: KVNamespace
    WEBAUTHN_RP_NAME?: string
    WEBAUTHN_RP_ID?: string
    WEBAUTHN_ORIGIN?: string
    AUTH_GATE_DEFAULT_USER_ID?: string
}

function createEnv(): TestEnv {
    const credentialStore = new InMemoryKV()
    const challengeStore = new InMemoryKV()
    return {
        AUTH_GATE_CREDENTIAL_STORE: credentialStore as unknown as KVNamespace,
        AUTH_GATE_CHALLENGE_STORE: challengeStore as unknown as KVNamespace,
        AUTH_GATE_DEFAULT_USER_ID: 'operator',
        WEBAUTHN_RP_NAME: 'Santh Deploy Gate',
        WEBAUTHN_RP_ID: 'localhost',
        WEBAUTHN_ORIGIN: 'http://localhost',
    }
}

function parseResponse(body: string): JsonLike {
    if (!body) return null
    try {
        return JSON.parse(body) as JsonLike
    } catch {
        return null
    }
}

async function request(path: string, env: TestEnv, init: RequestInit = {}): Promise<{ status: number; body: JsonLike; raw: Response }> {
    const response = await worker.fetch(
        new Request(`https://auth-gate.test${path}`, {
            headers: {
                'content-type': 'application/json',
                ...(init.headers ?? {}),
            },
            ...init,
        }),
        env,
    )

    const text = await response.text()
    const body = parseResponse(text)
    return { status: response.status, body, raw: response }
}

beforeEach(async () => {
    vi.clearAllMocks()
})

describe('auth-gate API', () => {
    it('supports registration begin + complete', async () => {
        const env = createEnv()
        bindStoreEnv(env)

        const begin = vi.spyOn(webauthn, 'generateRegistrationOptions').mockResolvedValue({
            challenge: 'registration-challenge',
            user: {
                id: 'dGVzdA',
            },
        } as unknown as PublicKeyCredentialCreationOptionsJSON)

        const complete = vi.spyOn(webauthn, 'verifyRegistration').mockResolvedValue({
            verified: true,
            storedCredential: {
                id: 'credential-id',
                publicKey: 'public-key',
                counter: 0,
                transports: ['internal'],
            },
        })

        const beginRes = await request('/v1/register/begin', env, {
            method: 'POST',
            body: JSON.stringify({ userId: 'operator', userName: 'operator' }),
        })
        expect(beginRes.status).toBe(200)
        expect(beginRes.body?.challenge).toBe('registration-challenge')
        expect(await getChallenge('register:operator')).toBe('registration-challenge')
        expect(begin).toHaveBeenCalledTimes(1)

        const completeRes = await request('/v1/register/complete', env, {
            method: 'POST',
            body: JSON.stringify({ userId: 'operator', credential: { id: 'request-cred-id' } }),
        })
        expect(completeRes.status).toBe(200)
        expect(completeRes.body?.success).toBe(true)
        expect(complete).toHaveBeenCalledTimes(1)

        const storedCredential = await getCredential('operator')
        expect(storedCredential).toMatchObject({
            id: 'credential-id',
            publicKey: 'public-key',
            counter: 0,
        })
    })

    it('issues a challenge with 5m TTL for approval', async () => {
        const env = createEnv()
        bindStoreEnv(env)

        await storeCredential('operator', {
            id: 'credential-id',
            publicKey: 'public-key',
            counter: 0,
            transports: ['internal'],
        })

        vi.spyOn(webauthn, 'generateAuthenticationOptions').mockResolvedValue({
            challenge: 'auth-challenge',
        } as unknown as PublicKeyCredentialRequestOptionsJSON)

        const response = await request('/v1/auth/challenge', env, {
            method: 'POST',
            body: JSON.stringify({ deployId: 'deploy-001', userId: 'operator' }),
        })
        expect(response.status).toBe(200)
        expect(response.body?.challenge).toBe('auth-challenge')
        expect(await getChallenge('deploy-001')).toBe('auth-challenge')
    })

    it('verifies passkey assertion and approves deploy', async () => {
        const env = createEnv()
        bindStoreEnv(env)

        await storeCredential('operator', {
            id: 'credential-id',
            publicKey: 'public-key',
            counter: 0,
            transports: ['internal'],
        })
        await storeChallenge('deploy-approved', 'auth-challenge', 300)
        vi.spyOn(webauthn, 'verifyAuthentication').mockResolvedValue(true)

        const response = await request('/v1/auth/verify', env, {
            method: 'POST',
            body: JSON.stringify({
                deploy_id: 'deploy-approved',
                userId: 'operator',
                credential: { id: 'assertion-id' },
            }),
        })

        expect(response.status).toBe(200)
        expect(response.body?.success).toBe(true)
        expect(await getChallenge('deploy-approved')).toBeNull()
    })

    it('rejects expired authentication challenge', async () => {
        const env = createEnv()
        bindStoreEnv(env)

        await storeCredential('operator', {
            id: 'credential-id',
            publicKey: 'public-key',
            counter: 0,
            transports: ['internal'],
        })
        await env.AUTH_GATE_CHALLENGE_STORE.put(
            'challenge:deploy-expired',
            JSON.stringify({
                challenge: 'expired-challenge',
                createdAt: new Date().toISOString(),
                expiresAt: Date.now() - 1_000,
            }),
        )
        vi.spyOn(webauthn, 'verifyAuthentication').mockResolvedValue(true)

        const response = await request('/v1/auth/verify', env, {
            method: 'POST',
            body: JSON.stringify({
                deploy_id: 'deploy-expired',
                userId: 'operator',
                credential: { id: 'assertion-id' },
            }),
        })

        expect(response.status).toBe(410)
        expect(response.body?.error).toBe('Challenge not found or expired')
    })
})
