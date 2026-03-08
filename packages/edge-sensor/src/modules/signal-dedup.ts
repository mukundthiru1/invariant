const BLOOM_FILTER_BYTES = 8 * 1024
const BLOOM_FILTER_BITS = BLOOM_FILTER_BYTES * 8
const FNV_PRIME = 0x01000193
const FNV_OFFSET_BASIS = 0x811c9dc5

const encoder = new TextEncoder()

function fnv1a32(input: string, seed = 0): number {
    const data = encoder.encode(input)
    let hash = (FNV_OFFSET_BASIS ^ seed) >>> 0

    for (let i = 0; i < data.length; i++) {
        hash ^= data[i]
        hash = Math.imul(hash, FNV_PRIME) >>> 0
    }

    return hash >>> 0
}

function toHex(value: number): string {
    return (value >>> 0).toString(16).padStart(8, '0')
}

export function hashPayload(invariantClass: string, evidence: string): string {
    const key = `${invariantClass}\u001f${evidence}`
    const h1 = fnv1a32(key, 0)
    const h2 = fnv1a32(key, 0x9e3779b9)
    return `${toHex(h1)}${toHex(h2)}`
}

export class SignalDeduplicator {
    private readonly bits = new Uint8Array(BLOOM_FILTER_BYTES)
    private bitsSet = 0

    isDuplicate(payloadHash: string): boolean {
        const h1 = fnv1a32(payloadHash, 0)
        const h2 = fnv1a32(payloadHash, 0x85ebca6b)
        const h3 = fnv1a32(payloadHash, 0xc2b2ae35)

        const idx1 = h1 % BLOOM_FILTER_BITS
        const idx2 = h2 % BLOOM_FILTER_BITS
        const idx3 = h3 % BLOOM_FILTER_BITS

        const b1 = this.hasBit(idx1)
        const b2 = this.hasBit(idx2)
        const b3 = this.hasBit(idx3)

        this.setBit(idx1)
        this.setBit(idx2)
        this.setBit(idx3)

        return b1 && b2 && b3
    }

    reset(): void {
        this.bits.fill(0)
        this.bitsSet = 0
    }

    saturation(): number {
        return this.bitsSet / BLOOM_FILTER_BITS
    }

    private hasBit(bitIndex: number): boolean {
        const byteIndex = bitIndex >>> 3
        const mask = 1 << (bitIndex & 7)
        return (this.bits[byteIndex] & mask) !== 0
    }

    private setBit(bitIndex: number): void {
        const byteIndex = bitIndex >>> 3
        const mask = 1 << (bitIndex & 7)
        if ((this.bits[byteIndex] & mask) === 0) {
            this.bits[byteIndex] |= mask
            this.bitsSet++
        }
    }
}
