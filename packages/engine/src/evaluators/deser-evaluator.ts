/**
 * Deserialization Evaluator — Level 2 Invariant Detection
 *
 * Structural detection strategy:
 *   1) Deep-decode input and extract base64 candidates.
 *   2) Decode candidate bytes and check serialization magic headers.
 *   3) Tokenize decoded material and look for gadget-chain indicators.
 *   4) Return class-mapped detections with proof evidence.
 */

import type { DetectionLevelResult } from '../classes/types.js'
import { deepDecode } from '../classes/encoding.js'


// ── Result Types ────────────────────────────────────────────────

type ProofEvidence = NonNullable<DetectionLevelResult['structuredEvidence']>

export interface DeserDetection {
    type: 'java_gadget' | 'php_object' | 'python_pickle'
    detail: string
    format: string
    gadgetChain: string | null
    confidence: number
    proofEvidence?: ProofEvidence
}

interface Artifact {
    source: string
    text: string
    bytes: Uint8Array
}

interface GadgetHit {
    family: 'java' | 'php' | 'python' | 'dotnet' | 'ruby' | 'yaml' | 'json' | 'xml' | 'node' | 'messagepack'
    label: string
    match: string
}


// ── Core Helpers ────────────────────────────────────────────────

function toBytes(text: string): Uint8Array {
    return new Uint8Array(Buffer.from(text, 'latin1'))
}

function hasBytesSequence(buf: Uint8Array, seq: number[]): boolean {
    if (buf.length < seq.length) return false
    outer: for (let i = 0; i <= buf.length - seq.length; i++) {
        for (let j = 0; j < seq.length; j++) {
            if (buf[i + j] !== seq[j]) continue outer
        }
        return true
    }
    return false
}

function extractBase64Candidates(input: string): string[] {
    const matches = input.match(/[A-Za-z0-9+/=]{16,}/g) ?? []
    const dedup = new Set<string>()

    const stripped = input.replace(/\s+/g, '')
    if (/^[A-Za-z0-9+/=]{16,}$/.test(stripped)) matches.push(stripped)

    for (const candidate of matches) {
        if (candidate.length % 4 !== 0) continue
        if (!/[A-Za-z]/.test(candidate) || !/\d|\+|\//.test(candidate)) continue
        dedup.add(candidate)
        if (dedup.size >= 8) break
    }

    return [...dedup]
}

function decodeBase64Artifacts(input: string): Artifact[] {
    const out: Artifact[] = []

    for (const b64 of extractBase64Candidates(input)) {
        try {
            const bytes = new Uint8Array(Buffer.from(b64, 'base64'))
            if (bytes.length < 4) continue
            const text = Buffer.from(bytes).toString('latin1')
            out.push({ source: `base64:${b64.slice(0, 20)}`, text, bytes })
        } catch {
            // Ignore non-decodable candidates
        }
    }

    return out
}

function tokenize(input: string): string[] {
    return input.match(/[@A-Za-z_][@A-Za-z0-9_.$:\\/-]{1,80}/g) ?? []
}

function mkEvidence(
    input: string,
    matchedInput: string,
    interpretation: string,
    property: string,
    operation: ProofEvidence[number]['operation'] = 'payload_inject',
): ProofEvidence[number] {
    const offset = matchedInput.length > 0 ? Math.max(0, input.indexOf(matchedInput)) : 0
    return { operation, matchedInput, interpretation, offset, property }
}


// ── Signatures and Gadgets ──────────────────────────────────────

const JAVA_MAGIC = [0xac, 0xed, 0x00, 0x05]
const RUBY_MAGIC = [0x04, 0x08]

const JAVA_GADGET_PATTERNS: RegExp[] = [
    /java\.lang\.Runtime\.getRuntime\(\)\.exec/i,
    /java\.lang\.ProcessBuilder/i,
    /(?:ChainedTransformer|InvokerTransformer|ConstantTransformer)/i,
    /(?:TemplatesImpl|BeanComparator|PriorityQueue|AnnotationInvocationHandler)/i,
    /org\.apache\.commons\.collections(?:4)?\.functors\./i,
    /(?:ObjectInputStream\s*\.\s*readObject|readObject\s*\()/i,
]

const PYTHON_PICKLE_PATTERNS: RegExp[] = [
    /(?:^|\n)c(?:os|posix)\nsystem\n/i,
    /(?:^|\n)c(?:builtins|__builtin__)\n(?:eval|exec|compile)\n/i,
    /(?:^|\n)csubprocess\n(?:Popen|call|check_output)\n/i,
    /\x80[\x02-\x05]/,
    /\\x80\\x0[2-5]/i,
    /\ntR\./,
]

const PHP_OBJECT_PATTERNS: RegExp[] = [
    /\b[OC]\s*:\s*[+-]?\d+\s*:\s*"[^"]+"\s*:\s*[+-]?\d+\s*:\s*\{/i,
    /\ba\s*:\s*[+-]?\d+\s*:\s*\{\s*(?:i|s|O|C)\s*:/i,
    /(?:__wakeup|__destruct|__toString|__invoke)/i,
]

const DOTNET_PATTERNS: RegExp[] = [
    /AAEAAAD\/{0,4}/i,
    /System\.Runtime\.Serialization\.Formatters\.Binary\.BinaryFormatter/i,
    /\bBinaryFormatter\s*\.\s*Deserialize\s*\(/i,
]

const RUBY_PATTERNS: RegExp[] = [
    /\\x04\\x08/i,
    /(?:Gem::SpecFetcher|Gem::Installer|Marshal\.load|marshal_load)/i,
]

const YAML_PATTERNS: RegExp[] = [
    /!!python\/object\/apply\s*:/i,
    /!!java\.lang\.ProcessBuilder/i,
    /!!ruby\/object\s*:/i,
]

const JSON_GADGET_PATTERNS: RegExp[] = [
    /"(?:@class|@type|_class|className)"\s*:\s*"[^"]+"/i,
    /"(?:@class|@type|_class|className)"\s*:\s*"(?:java\.|com\.|org\.|javax\.|sun\.)/i,
]

const XML_DESER_PATTERNS: RegExp[] = [
    /<java\.beans\.XMLDecoder\b/i,
    /<void\s+method\s*=\s*"(?:exec|start)"/i,
    /com\.thoughtworks\.xstream/i,
    /<object\s+class\s*=\s*"(?:java\.|com\.|org\.)/i,
]

const NODE_JSON_PROTO_PATTERNS: RegExp[] = [
    /"__proto__"\s*:/i,
    /"constructor"\s*:\s*\{\s*"prototype"\s*:/i,
    /constructor\.prototype/i,
]

const MESSAGEPACK_PATTERNS: RegExp[] = [
    /(?:application\/x-msgpack|msgpack(?:-lite)?)/i,
    /(?:ExtType|__ext__|type\s*:\s*['"]?ext['"]?)/i,
]


function findFirstPattern(patterns: RegExp[], candidates: string[]): string | null {
    for (const candidate of candidates) {
        for (const pattern of patterns) {
            const match = candidate.match(pattern)
            if (match?.[0]) return match[0]
        }
    }
    return null
}

function collectGadgets(texts: string[], tokens: string[]): GadgetHit[] {
    const joined = [...texts, tokens.join(' ')]
    const hits: GadgetHit[] = []

    const add = (family: GadgetHit['family'], label: string, patterns: RegExp[]) => {
        const match = findFirstPattern(patterns, joined)
        if (match) hits.push({ family, label, match })
    }

    add('java', 'Java gadget chain', JAVA_GADGET_PATTERNS)
    add('python', 'Python pickle gadget', PYTHON_PICKLE_PATTERNS)
    add('php', 'PHP serialized object', PHP_OBJECT_PATTERNS)
    add('dotnet', '.NET BinaryFormatter gadget', DOTNET_PATTERNS)
    add('ruby', 'Ruby Marshal gadget', RUBY_PATTERNS)
    add('yaml', 'YAML object-apply gadget', YAML_PATTERNS)
    add('json', 'JSON type-hint gadget', JSON_GADGET_PATTERNS)
    add('xml', 'XMLDecoder/XStream gadget', XML_DESER_PATTERNS)
    add('node', 'JSON prototype chain mutation', NODE_JSON_PROTO_PATTERNS)
    add('messagepack', 'MessagePack typed extension gadget', MESSAGEPACK_PATTERNS)

    return hits
}


// ── Public API ───────────────────────────────────────────────────

export function detectDeserialization(input: string): DeserDetection[] {
    const detections: DeserDetection[] = []
    if (input.length < 4) return detections

    const normalized = deepDecode(input)
    const artifacts: Artifact[] = [
        { source: 'raw', text: normalized, bytes: toBytes(normalized) },
        ...decodeBase64Artifacts(normalized),
    ]

    const texts = artifacts.map(a => a.text)
    const tokens = tokenize(texts.join(' '))
    const gadgetHits = collectGadgets(texts, tokens)

    const hasJavaMagic = artifacts.some(a => hasBytesSequence(a.bytes, JAVA_MAGIC)) ||
        /rO0AB(?:Q|X|[A-Za-z0-9+/=])|aced\s*0005|\\x?ac\\x?ed\\x?00\\x?05/i.test(normalized)

    const hasPickleMagic = artifacts.some(a => a.bytes.length >= 2 && a.bytes[0] === 0x80 && a.bytes[1] >= 0x02 && a.bytes[1] <= 0x05) ||
        /\\x80\\x0[2-5]/i.test(normalized)

    const hasRubyMagic = artifacts.some(a => hasBytesSequence(a.bytes, RUBY_MAGIC)) || /\\x04\\x08/i.test(normalized)
    const hasDotNetMagic = /AAEAAAD\/{0,4}|\/wEAAAAAAAAA/i.test(normalized)

    const javaLikeHit = gadgetHits.find(h => ['java', 'dotnet', 'ruby', 'yaml', 'json', 'xml', 'messagepack'].includes(h.family))
    if (hasJavaMagic || hasRubyMagic || hasDotNetMagic || javaLikeHit) {
        const chain = javaLikeHit?.match ?? (hasJavaMagic ? 'aced0005' : hasDotNetMagic ? 'AAEAAAD' : hasRubyMagic ? '\\x04\\x08' : null)
        const format = hasJavaMagic
            ? 'Java serialization stream'
            : hasDotNetMagic
                ? '.NET BinaryFormatter'
                : hasRubyMagic
                    ? 'Ruby Marshal'
                    : javaLikeHit?.family === 'yaml'
                        ? 'YAML object tags'
                        : javaLikeHit?.family === 'xml'
                            ? 'XML object graph'
                            : javaLikeHit?.family === 'json'
                                ? 'JSON type-hints'
                                : javaLikeHit?.family === 'messagepack'
                                    ? 'MessagePack typed extension'
                                    : 'Serialized object graph'

        const confidence = (hasJavaMagic || hasDotNetMagic) && javaLikeHit ? 0.98
            : hasJavaMagic || hasDotNetMagic || hasRubyMagic ? 0.88
                : javaLikeHit?.family === 'json' ? 0.84 : 0.9

        detections.push({
            type: 'java_gadget',
            detail: `${format}${chain ? ` with gadget indicator: ${chain}` : ' with deserialization indicators'}`,
            format,
            gadgetChain: chain,
            confidence,
            proofEvidence: [
                mkEvidence(
                    normalized,
                    chain ?? format,
                    `Detected ${format} deserialization indicator${chain ? ` (${chain})` : ''}`,
                    'Deserialized object graphs must not allow attacker-controlled gadget invocation',
                    chain && chain.startsWith('base64:') ? 'encoding_decode' : 'payload_inject',
                ),
            ],
        })
    }

    const pickleHit = gadgetHits.find(h => h.family === 'python' || h.family === 'yaml')
    if (hasPickleMagic || pickleHit?.family === 'python' || /!!python\/object\/apply\s*:/i.test(normalized)) {
        const chain = pickleHit?.match ?? (hasPickleMagic ? '\\x80\\x02..\\x05' : '!!python/object/apply')
        const isYaml = /!!python\/object\/apply\s*:/i.test(normalized)
        detections.push({
            type: 'python_pickle',
            detail: `${isYaml ? 'YAML Python object apply' : 'Python pickle'}${chain ? ` with gadget indicator: ${chain}` : ''}`,
            format: isYaml ? 'YAML Python tags' : 'Python pickle',
            gadgetChain: chain,
            confidence: (hasPickleMagic && pickleHit) || isYaml ? 0.97 : 0.86,
            proofEvidence: [
                mkEvidence(
                    normalized,
                    chain,
                    `Detected Python deserialization opcode/tag sequence (${chain})`,
                    'Python object deserialization must not execute imported callables from untrusted input',
                ),
            ],
        })
    }

    const phpHit = gadgetHits.find(h => h.family === 'php' || h.family === 'node')
    if (phpHit || /\b[OC]\s*:\s*[+-]?\d+\s*:\s*"[^"]+"/i.test(normalized)) {
        const chain = phpHit?.match ?? normalized.match(/\b[OC]\s*:\s*[+-]?\d+\s*:\s*"[^"]+"/i)?.[0] ?? null
        const isNodeProto = phpHit?.family === 'node'
        detections.push({
            type: 'php_object',
            detail: `${isNodeProto ? 'JSON prototype mutation chain' : 'PHP serialized object'}${chain ? ` with gadget indicator: ${chain}` : ''}`,
            format: isNodeProto ? 'JSON object graph' : 'PHP serialize',
            gadgetChain: chain,
            confidence: isNodeProto ? 0.87 : 0.93,
            proofEvidence: [
                mkEvidence(
                    normalized,
                    chain ?? 'serialized object',
                    `Detected ${isNodeProto ? 'prototype chain mutation via JSON keys' : 'PHP object serialization gadget markers'}`,
                    isNodeProto
                        ? 'Object graph deserialization must not permit constructor/prototype path mutation'
                        : 'PHP unserialize() must not instantiate attacker-controlled object graphs',
                ),
            ],
        })
    }

    return detections
}
