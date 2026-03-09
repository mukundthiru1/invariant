import {
    generateAuthenticationOptions as simpleGenerateAuthenticationOptions,
    generateRegistrationOptions as simpleGenerateRegistrationOptions,
    verifyAuthenticationResponse as simpleVerifyAuthenticationResponse,
    verifyRegistrationResponse as simpleVerifyRegistrationResponse,
} from '@simplewebauthn/server'
import type {
    AuthenticationResponseJSON,
    AuthenticatorTransportFuture,
    PublicKeyCredentialCreationOptionsJSON,
    PublicKeyCredentialRequestOptionsJSON,
    RegistrationResponseJSON,
} from '@simplewebauthn/types'

import { decodeBase64Url, encodeBase64 } from './webauthn-encoding.js'

export type VerifiedRegistrationInfo = {
    verified: boolean
    storedCredential: StoredCredential | null
}

export interface StoredCredential {
    id: string
    publicKey: string
    counter: number
    transports?: string[]
}

interface WebAuthnConfig {
    rpName: string
    rpId: string
    origin: string
}

type RawCredentialRegistration = RegistrationResponseJSON
type RawAuthenticationCredential = AuthenticationResponseJSON

type BufferLike = ArrayBuffer | Uint8Array | string

let config: WebAuthnConfig = {
    rpName: 'Santh Deploy Gate',
    rpId: 'localhost',
    origin: 'http://localhost',
}

export function setWebAuthnConfig(next: Partial<WebAuthnConfig>): void {
    config = { ...config, ...next }
}

function toBase64Url(value: BufferLike): string {
    if (typeof value === 'string') return value
    const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : value
    return encodeBase64(bytes)
}

function randomChallenge(): string {
    const random = new Uint8Array(32)
    crypto.getRandomValues(random)
    return toBase64Url(random)
}

export function generateRandomChallenge(): string {
    return randomChallenge()
}

const KNOWN_TRANSPORTS = new Set<AuthenticatorTransportFuture>([
    'ble',
    'cable',
    'hybrid',
    'internal',
    'nfc',
    'smart-card',
    'usb',
])

function normalizeTransports(values: unknown): AuthenticatorTransportFuture[] | undefined {
    if (!Array.isArray(values)) return undefined
    const parsed = values.filter((value): value is AuthenticatorTransportFuture =>
        typeof value === 'string' && KNOWN_TRANSPORTS.has(value as AuthenticatorTransportFuture),
    )
    return parsed.length > 0 ? parsed : undefined
}

export async function generateRegistrationOptions(userId: string, userName: string): Promise<PublicKeyCredentialCreationOptionsJSON> {
    return simpleGenerateRegistrationOptions({
        rpName: config.rpName,
        rpID: config.rpId,
        userID: new TextEncoder().encode(userId),
        userName,
        userDisplayName: userName,
        timeout: 60_000,
        attestationType: 'none',
        authenticatorSelection: {
            userVerification: 'preferred',
            residentKey: 'preferred',
            authenticatorAttachment: 'platform',
        },
        supportedAlgorithmIDs: [-7, -257],
        challenge: randomChallenge(),
    })
}

export async function verifyRegistration(
    credential: RawCredentialRegistration,
    expectedChallenge: string,
): Promise<VerifiedRegistrationInfo> {
    const verification = await simpleVerifyRegistrationResponse({
        response: credential,
        expectedChallenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpId,
        requireUserVerification: true,
    })

    if (!verification.verified || !verification.registrationInfo) {
        return { verified: false, storedCredential: null }
    }

    const info = verification.registrationInfo
    const credentialID = info.credentialID
    const publicKey = toBase64Url(info.credentialPublicKey)
    const counter = Number.isFinite(info.counter) ? Number(info.counter) : 0
    const transports = normalizeTransports(credential.response?.transports)

    if (!credentialID || !publicKey) {
        return { verified: false, storedCredential: null }
    }

    return {
        verified: true,
        storedCredential: {
            id: credentialID,
            publicKey,
            counter,
            transports,
        },
    }
}

export async function generateAuthenticationOptions(
    credentialId: string,
): Promise<PublicKeyCredentialRequestOptionsJSON> {
    return simpleGenerateAuthenticationOptions({
        rpID: config.rpId,
        timeout: 60_000,
        allowCredentials: [{
            id: credentialId,
            transports: ['internal'],
        }],
        userVerification: 'preferred',
        challenge: randomChallenge(),
    })
}

export async function verifyAuthentication(
    credential: RawAuthenticationCredential,
    expectedChallenge: string,
    storedCredential: StoredCredential,
): Promise<boolean> {
    const verification = await simpleVerifyAuthenticationResponse({
        response: credential,
        expectedChallenge,
        expectedOrigin: config.origin,
        expectedRPID: config.rpId,
        authenticator: {
            credentialID: storedCredential.id,
            credentialPublicKey: decodeBase64Url(storedCredential.publicKey),
            counter: Number.isFinite(storedCredential.counter) ? storedCredential.counter : 0,
            transports: normalizeTransports(storedCredential.transports),
        },
    })

    return verification.verified
}
