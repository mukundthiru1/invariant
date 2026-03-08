/**
 * Prototype Pollution Evaluator — structural L2 analysis.
 */

interface Token {
    type: 'identifier' | 'string' | 'symbol' | 'operator'
    value: string
}

export interface ProtoPollutionDetection {
    type: 'proto_key_assignment' | 'constructor_chain' | 'json_proto_path' | 'bracket_proto_path'
    detail: string
    path: string
    pollutedProperty: string
    confidence: number
    l1: boolean
    l2: boolean
    evidence: string
}

const SUSPICIOUS_KEYWORDS = ['proto', 'constructor', 'prototype']

function deepDecode(input: string): string {
    let current = input
    for (let i = 0; i < 3; i++) {
        let next = current
        try { next = decodeURIComponent(next) } catch { /* ignore */ }
        next = next.replace(/\\u([0-9a-fA-F]{4})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
        next = next.replace(/\\x([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
        if (next === current) break
        current = next
    }
    return current
}

function isInteresting(input: string): boolean {
    const lower = input.toLowerCase()
    return SUSPICIOUS_KEYWORDS.some(k => lower.includes(k))
}

function decodeStringLiteral(raw: string): string {
    if (raw.length < 2) return raw
    const quote = raw[0]
    if ((quote !== '"' && quote !== "'") || raw[raw.length - 1] !== quote) return raw
    const body = raw.slice(1, -1)
    return body
        .replace(/\\u([0-9a-fA-F]{4})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\\x([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\\'/g, "'")
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, '\\')
}

function tokenize(input: string): Token[] {
    const tokens: Token[] = []
    const bounded = input.slice(0, 12000)
    let i = 0

    while (i < bounded.length) {
        const ch = bounded[i]
        if (/\s/.test(ch)) {
            i++
            continue
        }
        if (ch === '"' || ch === "'") {
            const quote = ch
            let value = ch
            i++
            while (i < bounded.length) {
                const c = bounded[i]
                value += c
                i++
                if (c === '\\' && i < bounded.length) {
                    value += bounded[i]
                    i++
                    continue
                }
                if (c === quote) break
            }
            tokens.push({ type: 'string', value })
            continue
        }
        if (/[a-zA-Z_$]/.test(ch)) {
            const start = i
            i++
            while (i < bounded.length && /[a-zA-Z0-9_$]/.test(bounded[i])) i++
            tokens.push({ type: 'identifier', value: bounded.slice(start, i) })
            continue
        }
        if ('[]().,:;{}'.includes(ch)) {
            tokens.push({ type: 'symbol', value: ch })
            i++
            continue
        }
        if ('=+-*/!<>'.includes(ch)) {
            const next = bounded[i + 1] ?? ''
            if ((ch === '=' && next === '=') || (ch === '!' && next === '=') || (ch === '<' && next === '=') || (ch === '>' && next === '=')) {
                tokens.push({ type: 'operator', value: ch + next })
                i += 2
            } else {
                tokens.push({ type: 'operator', value: ch })
                i++
            }
            continue
        }
        i++
    }

    return tokens
}

function normalizeKey(key: string): string {
    return key.replace(/\s+/g, '').toLowerCase()
}

function resolveBracketKey(tokens: Token[]): string | null {
    if (tokens.length === 0) return null
    if (tokens.length === 1) {
        const [only] = tokens
        if (only.type === 'string') return normalizeKey(decodeStringLiteral(only.value))
        if (only.type === 'identifier') return normalizeKey(only.value)
        return null
    }
    // Support "__" + "proto__" concatenation.
    let out = ''
    let expectPiece = true
    for (const tok of tokens) {
        if (expectPiece) {
            if (tok.type === 'string') {
                out += decodeStringLiteral(tok.value)
                expectPiece = false
                continue
            }
            if (tok.type === 'identifier') {
                out += tok.value
                expectPiece = false
                continue
            }
            return null
        }
        if (tok.type === 'operator' && tok.value === '+') {
            expectPiece = true
            continue
        }
        return null
    }
    return expectPiece ? null : normalizeKey(out)
}

function parseMemberChain(tokens: Token[], start: number): { keys: string[]; next: number } | null {
    if (tokens[start]?.type !== 'identifier') return null
    const keys: string[] = [normalizeKey(tokens[start].value)]
    let i = start + 1

    while (i < tokens.length) {
        const tok = tokens[i]
        if (tok.type === 'symbol' && tok.value === '.') {
            const next = tokens[i + 1]
            if (!next || (next.type !== 'identifier' && next.type !== 'string')) break
            keys.push(normalizeKey(next.type === 'string' ? decodeStringLiteral(next.value) : next.value))
            i += 2
            continue
        }
        if (tok.type === 'symbol' && tok.value === '[') {
            let depth = 1
            const inside: Token[] = []
            i++
            while (i < tokens.length && depth > 0) {
                if (tokens[i].type === 'symbol' && tokens[i].value === '[') {
                    depth++
                } else if (tokens[i].type === 'symbol' && tokens[i].value === ']') {
                    depth--
                    if (depth === 0) break
                }
                if (depth > 0) inside.push(tokens[i])
                i++
            }
            if (depth !== 0) break
            const resolved = resolveBracketKey(inside)
            keys.push(resolved ?? '<dynamic>')
            i++
            continue
        }
        break
    }

    return { keys, next: i }
}

function detectAssignmentChains(decoded: string): ProtoPollutionDetection[] {
    const detections: ProtoPollutionDetection[] = []
    const tokens = tokenize(decoded)

    for (let i = 0; i < tokens.length; i++) {
        const chain = parseMemberChain(tokens, i)
        if (!chain) continue
        const op = tokens[chain.next]
        if (!op || op.type !== 'operator' || op.value !== '=') {
            i = chain.next
            continue
        }
        const keys = chain.keys
        const protoIndex = keys.indexOf('__proto__')
        const ctorProto = keys.some((k, idx) => k === 'constructor' && keys[idx + 1] === 'prototype')
        if (protoIndex >= 0) {
            const pollutedProperty = keys[protoIndex + 1] ?? '<unknown>'
            detections.push({
                type: 'proto_key_assignment',
                detail: `Prototype key assignment via member chain: ${keys.join(' -> ')}`,
                path: keys.join('.'),
                pollutedProperty,
                confidence: keys.includes('<dynamic>') ? 0.87 : 0.95,
                l1: false,
                l2: true,
                evidence: keys.join('.'),
            })
        }
        if (ctorProto) {
            const protoIdx = keys.findIndex((k, idx) => k === 'constructor' && keys[idx + 1] === 'prototype')
            const pollutedProperty = keys[protoIdx + 2] ?? '<unknown>'
            detections.push({
                type: 'constructor_chain',
                detail: `Constructor prototype traversal: ${keys.join(' -> ')}`,
                path: keys.join('.'),
                pollutedProperty,
                confidence: keys.includes('<dynamic>') ? 0.89 : 0.96,
                l1: false,
                l2: true,
                evidence: keys.join('.'),
            })
        }
        i = chain.next
    }

    return detections
}

function extractJsonFragments(input: string): string[] {
    const fragments: string[] = []
    let depth = 0
    let start = -1
    for (let i = 0; i < input.length; i++) {
        if (input[i] === '{') {
            if (depth === 0) start = i
            depth++
        } else if (input[i] === '}') {
            depth--
            if (depth === 0 && start >= 0) {
                fragments.push(input.slice(start, i + 1))
                start = -1
            }
        }
    }
    return fragments
}

function analyzeJsonObject(value: unknown, path: string[] = []): ProtoPollutionDetection[] {
    const detections: ProtoPollutionDetection[] = []
    if (typeof value !== 'object' || value === null) return detections

    if (Array.isArray(value)) {
        value.forEach((item, idx) => detections.push(...analyzeJsonObject(item, [...path, `[${idx}]`])))
        return detections
    }

    const entries = Object.entries(value as Record<string, unknown>)
    for (const [key, nested] of entries) {
        const norm = normalizeKey(key)
        const current = [...path, norm]
        if (norm === '__proto__') {
            const polluted = typeof nested === 'object' && nested !== null ? Object.keys(nested as Record<string, unknown>)[0] ?? '<unknown>' : '<unknown>'
            detections.push({
                type: 'json_proto_path',
                detail: `JSON object contains __proto__ path: ${current.join(' -> ')}`,
                path: current.join('.'),
                pollutedProperty: polluted,
                confidence: 0.95,
                l1: false,
                l2: true,
                evidence: current.join('.'),
            })
        }
        if (norm === 'constructor' && typeof nested === 'object' && nested !== null && 'prototype' in (nested as Record<string, unknown>)) {
            const proto = (nested as Record<string, unknown>).prototype
            const polluted = typeof proto === 'object' && proto !== null ? Object.keys(proto as Record<string, unknown>)[0] ?? '<unknown>' : '<unknown>'
            detections.push({
                type: 'json_proto_path',
                detail: `JSON constructor.prototype chain detected`,
                path: `${current.join('.')}.prototype`,
                pollutedProperty: polluted,
                confidence: 0.96,
                l1: false,
                l2: true,
                evidence: `${current.join('.')}.prototype`,
            })
        }
        detections.push(...analyzeJsonObject(nested, current))
    }

    return detections
}

function detectJsonProtoPaths(decoded: string): ProtoPollutionDetection[] {
    const detections: ProtoPollutionDetection[] = []
    const fragments = decoded.trim().startsWith('{') ? [decoded] : extractJsonFragments(decoded)
    for (const fragment of fragments) {
        try {
            detections.push(...analyzeJsonObject(JSON.parse(fragment)))
        } catch {
            // ignore malformed JSON
        }
    }
    return detections
}

function parseQueryKeyPath(key: string): string[] {
    const path: string[] = []
    let cursor = ''
    for (let i = 0; i < key.length; i++) {
        const ch = key[i]
        if (ch === '[') {
            if (cursor) {
                path.push(normalizeKey(cursor))
                cursor = ''
            }
            let j = i + 1
            let segment = ''
            while (j < key.length && key[j] !== ']') {
                segment += key[j]
                j++
            }
            path.push(normalizeKey(segment))
            i = j
        } else {
            cursor += ch
        }
    }
    if (cursor) path.push(normalizeKey(cursor))
    return path.filter(Boolean)
}

function detectBracketPaths(decoded: string): ProtoPollutionDetection[] {
    const detections: ProtoPollutionDetection[] = []
    for (const part of decoded.split('&')) {
        const [rawKey] = part.split('=')
        if (!rawKey || !rawKey.includes('[')) continue
        const path = parseQueryKeyPath(rawKey)
        const protoIndex = path.indexOf('__proto__')
        const ctorProto = path.some((k, idx) => k === 'constructor' && path[idx + 1] === 'prototype')
        if (protoIndex >= 0) {
            detections.push({
                type: 'bracket_proto_path',
                detail: `Bracket path reaches __proto__: ${path.join(' -> ')}`,
                path: path.join('.'),
                pollutedProperty: path[protoIndex + 1] ?? '<unknown>',
                confidence: 0.93,
                l1: false,
                l2: true,
                evidence: path.join('.'),
            })
        } else if (ctorProto) {
            const idx = path.findIndex((k, i) => k === 'constructor' && path[i + 1] === 'prototype')
            detections.push({
                type: 'constructor_chain',
                detail: `Bracket path reaches constructor.prototype: ${path.join(' -> ')}`,
                path: path.join('.'),
                pollutedProperty: path[idx + 2] ?? '<unknown>',
                confidence: 0.95,
                l1: false,
                l2: true,
                evidence: path.join('.'),
            })
        }
    }
    return detections
}

export function detectPrototypePollution(input: string): ProtoPollutionDetection[] {
    if (input.length < 6) return []
    const decoded = deepDecode(input)
    if (!isInteresting(decoded)) return []

    const detections = [
        ...detectAssignmentChains(decoded),
        ...detectJsonProtoPaths(decoded),
        ...detectBracketPaths(decoded),
    ]

    const deduped = new Map<string, ProtoPollutionDetection>()
    for (const d of detections) {
        const key = `${d.type}:${d.path}:${d.pollutedProperty}`
        const existing = deduped.get(key)
        if (!existing || d.confidence > existing.confidence) deduped.set(key, d)
    }
    return [...deduped.values()]
}
