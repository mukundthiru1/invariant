interface StoreEnv {
    AUTH_GATE_CREDENTIAL_STORE: KVNamespace
    AUTH_GATE_CHALLENGE_STORE: KVNamespace
}

export interface StoredCredential {
    id: string
    publicKey: string
    counter: number
    transports?: string[]
    userId: string
    createdAt: string
}

interface StoredChallenge {
    challenge: string
    expiresAt: number
    createdAt: string
}

const CREDENTIAL_PREFIX = 'credential:'
const CHALLENGE_PREFIX = 'challenge:'
const DEFAULT_CHALLENGE_TTL_SECONDS = 300

let boundEnv: StoreEnv | null = null

export function bindStoreEnv(env: StoreEnv): void {
    boundEnv = env
}

function getEnv(): StoreEnv {
    if (!boundEnv) {
        throw new Error('Store bindings are not initialized')
    }
    return boundEnv
}

function nowIso(): string {
    return new Date().toISOString()
}

function getCredentialKey(userId: string): string {
    return `${CREDENTIAL_PREFIX}${userId}`
}

function getChallengeKey(deployId: string): string {
    return `${CHALLENGE_PREFIX}${deployId}`
}

export async function storeCredential(userId: string, credential: Omit<StoredCredential, 'userId' | 'createdAt'>): Promise<void> {
    const env = getEnv()
    const payload: StoredCredential = {
        userId,
        createdAt: nowIso(),
        ...credential,
    }
    await env.AUTH_GATE_CREDENTIAL_STORE.put(getCredentialKey(userId), JSON.stringify(payload))
}

export async function getCredential(userId: string): Promise<StoredCredential | null> {
    const env = getEnv()
    const raw = await env.AUTH_GATE_CREDENTIAL_STORE.get<string>(getCredentialKey(userId))
    if (!raw) return null

    try {
        const parsed = JSON.parse(raw) as Record<string, unknown>
        if (!parsed || typeof parsed !== 'object' || parsed.userId !== userId) return null
        if (typeof parsed.id !== 'string' || typeof parsed.publicKey !== 'string') return null
        const counter = Number(parsed.counter)
        if (!Number.isFinite(counter)) return null

        return {
            id: parsed.id,
            publicKey: parsed.publicKey,
            counter,
            transports: Array.isArray(parsed.transports)
                ? parsed.transports.filter((value): value is string => typeof value === 'string')
                : undefined,
            userId: parsed.userId as string,
            createdAt: typeof parsed.createdAt === 'string' ? parsed.createdAt : nowIso(),
        }
    } catch {
        return null
    }
}

export async function storeChallenge(deployId: string, challenge: string, ttl = DEFAULT_CHALLENGE_TTL_SECONDS): Promise<void> {
    const env = getEnv()
    const record: StoredChallenge = {
        challenge,
        createdAt: nowIso(),
        expiresAt: Date.now() + ttl * 1000,
    }
    await env.AUTH_GATE_CHALLENGE_STORE.put(getChallengeKey(deployId), JSON.stringify(record), { expirationTtl: ttl })
}

export async function getChallenge(deployId: string): Promise<string | null> {
    const env = getEnv()
    const raw = await env.AUTH_GATE_CHALLENGE_STORE.get<string>(getChallengeKey(deployId))
    if (!raw) return null

    try {
        const parsed = JSON.parse(raw) as StoredChallenge
        if (!parsed || typeof parsed.challenge !== 'string') return null
        if (!Number.isFinite(parsed.expiresAt) || parsed.expiresAt <= Date.now()) {
            await env.AUTH_GATE_CHALLENGE_STORE.delete(getChallengeKey(deployId))
            return null
        }
        return parsed.challenge
    } catch {
        const trimmed = raw.trim()
        if (!trimmed) {
            await env.AUTH_GATE_CHALLENGE_STORE.delete(getChallengeKey(deployId))
            return null
        }
        return trimmed
    }
}

export async function deleteChallenge(deployId: string): Promise<void> {
    const env = getEnv()
    await env.AUTH_GATE_CHALLENGE_STORE.delete(getChallengeKey(deployId))
}
