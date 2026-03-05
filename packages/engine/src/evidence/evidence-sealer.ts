/**
 * @santh/invariant-engine — Cryptographic Evidence Sealing
 *
 * Converts INVARIANT signals into evidence-grade artifacts with:
 *   - SHA-256 content hashing (content-addressed, immutable)
 *   - Merkle tree over signal batches (batch integrity proof)
 *   - Per-signal inclusion proofs (prove a signal existed at a specific time)
 *   - Seal metadata (sensor ID, timestamp, version)
 *
 * Architecture from Axiom Drift's evidence infrastructure, adapted
 * for Cloudflare Workers' Web Crypto API (no Node crypto required).
 *
 * Why this matters:
 *   A log says "we saw an attack."
 *   An evidence seal says "here is a cryptographic proof that this
 *   exact signal, with this exact content, existed at this exact time,
 *   and has not been modified since." That's the difference between
 *   an alert and a court exhibit.
 */

// ── Types ─────────────────────────────────────────────────────────

export interface EvidenceSeal {
    /** Unique seal identifier */
    sealId: string
    /** SHA-256 hash of the Merkle root (hex) */
    merkleRoot: string
    /** Number of signals in this batch */
    signalCount: number
    /** Sensor that produced the batch */
    sensorId: string
    /** ISO timestamp when the seal was created */
    sealedAt: string
    /** Engine version that produced the seal */
    engineVersion: string
    /** HMAC signature over the seal metadata (hex) */
    signature: string
}

export interface SignalWithProof {
    /** The original signal (serialized JSON) */
    signalHash: string
    /** Index of this signal in the Merkle tree */
    leafIndex: number
    /** Sibling hashes for Merkle inclusion proof */
    proof: string[]
    /** The Merkle root this proof verifies against */
    merkleRoot: string
}

export interface SealedBatch {
    /** The seal metadata */
    seal: EvidenceSeal
    /** Individual signal proofs */
    proofs: SignalWithProof[]
}


// ── Crypto Helpers (Web Crypto API — works on Workers) ────────────

async function sha256(data: string): Promise<string> {
    const encoded = new TextEncoder().encode(data)
    const hash = await crypto.subtle.digest('SHA-256', encoded)
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}

async function sha256Pair(left: string, right: string): Promise<string> {
    return sha256(left + right)
}

async function hmacSign(data: string, key: string): Promise<string> {
    const keyData = new TextEncoder().encode(key)
    const cryptoKey = await crypto.subtle.importKey(
        'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    )
    const signature = await crypto.subtle.sign(
        'HMAC', cryptoKey, new TextEncoder().encode(data),
    )
    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
}


// ── Merkle Tree ───────────────────────────────────────────────────

async function buildMerkleTree(leaves: string[]): Promise<{
    root: string
    layers: string[][]
}> {
    if (leaves.length === 0) return { root: '', layers: [] }
    if (leaves.length === 1) return { root: leaves[0], layers: [leaves] }

    const layers: string[][] = [leaves]
    let currentLayer = leaves

    while (currentLayer.length > 1) {
        const nextLayer: string[] = []
        for (let i = 0; i < currentLayer.length; i += 2) {
            if (i + 1 < currentLayer.length) {
                nextLayer.push(await sha256Pair(currentLayer[i], currentLayer[i + 1]))
            } else {
                // Odd node: promote (duplicate to pair with itself)
                nextLayer.push(await sha256Pair(currentLayer[i], currentLayer[i]))
            }
        }
        layers.push(nextLayer)
        currentLayer = nextLayer
    }

    return { root: currentLayer[0], layers }
}

function getInclusionProof(layers: string[][], leafIndex: number): string[] {
    const proof: string[] = []
    let idx = leafIndex

    for (let layerIdx = 0; layerIdx < layers.length - 1; layerIdx++) {
        const layer = layers[layerIdx]
        const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1

        if (siblingIdx < layer.length) {
            proof.push(layer[siblingIdx])
        } else {
            // Odd node at end — sibling is self
            proof.push(layer[idx])
        }

        idx = Math.floor(idx / 2)
    }

    return proof
}


// ── Evidence Sealer ───────────────────────────────────────────────

export class EvidenceSealer {
    private readonly sensorId: string
    private readonly version: string
    private readonly signingKey: string

    constructor(sensorId: string, signingKey: string, version = '7.0.0') {
        this.sensorId = sensorId
        this.signingKey = signingKey
        this.version = version
    }

    /**
     * Seal a batch of signals into a cryptographically verifiable bundle.
     *
     * Each signal is:
     *   1. Serialized to stable JSON
     *   2. SHA-256 hashed (content-addressed)
     *   3. Inserted as a leaf in a Merkle tree
     *   4. Given an inclusion proof (verifiable against the root)
     *
     * The root is signed with HMAC-SHA256 using the sensor's key.
     */
    async seal<T>(signals: T[]): Promise<SealedBatch> {
        if (signals.length === 0) {
            return {
                seal: {
                    sealId: await this.generateSealId(),
                    merkleRoot: '',
                    signalCount: 0,
                    sensorId: this.sensorId,
                    sealedAt: new Date().toISOString(),
                    engineVersion: this.version,
                    signature: '',
                },
                proofs: [],
            }
        }

        // Hash each signal
        const leafHashes: string[] = []
        for (const signal of signals) {
            const serialized = JSON.stringify(signal, Object.keys(signal as object).sort())
            leafHashes.push(await sha256(serialized))
        }

        // Build Merkle tree
        const { root, layers } = await buildMerkleTree(leafHashes)

        // Build inclusion proofs
        const proofs: SignalWithProof[] = leafHashes.map((hash, index) => ({
            signalHash: hash,
            leafIndex: index,
            proof: getInclusionProof(layers, index),
            merkleRoot: root,
        }))

        // Sign the seal
        const sealId = await this.generateSealId()
        const sealedAt = new Date().toISOString()
        const sealData = `${sealId}:${root}:${signals.length}:${this.sensorId}:${sealedAt}`
        const signature = await hmacSign(sealData, this.signingKey)

        return {
            seal: {
                sealId,
                merkleRoot: root,
                signalCount: signals.length,
                sensorId: this.sensorId,
                sealedAt,
                engineVersion: this.version,
                signature,
            },
            proofs,
        }
    }

    /**
     * Verify that a signal was part of a sealed batch.
     *
     * Given a signal's hash and its inclusion proof, reconstruct
     * the path to the Merkle root and compare.
     */
    static async verifyInclusion(proof: SignalWithProof): Promise<boolean> {
        let currentHash = proof.signalHash
        let idx = proof.leafIndex

        for (const sibling of proof.proof) {
            if (idx % 2 === 0) {
                currentHash = await sha256Pair(currentHash, sibling)
            } else {
                currentHash = await sha256Pair(sibling, currentHash)
            }
            idx = Math.floor(idx / 2)
        }

        return currentHash === proof.merkleRoot
    }

    /**
     * Verify the HMAC signature of a seal.
     */
    async verifySeal(seal: EvidenceSeal): Promise<boolean> {
        const sealData = `${seal.sealId}:${seal.merkleRoot}:${seal.signalCount}:${seal.sensorId}:${seal.sealedAt}`
        const expectedSignature = await hmacSign(sealData, this.signingKey)
        return seal.signature === expectedSignature
    }

    private async generateSealId(): Promise<string> {
        // Use crypto.getRandomValues for CSPRNG entropy
        // Prevents prediction of seal IDs by nation-state actors
        const randomBytes = new Uint8Array(16)
        crypto.getRandomValues(randomBytes)
        const randomHex = Array.from(randomBytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')
        
        const entropy = `${this.sensorId}:${Date.now()}:${randomHex}`
        const hash = await sha256(entropy)
        return `seal_${hash.slice(0, 16)}`
    }
}
