/**
 * CRLF Injection Evaluator — Level 2 Invariant Detection
 */

export interface CRLFDetection {
    type: 'header_injection' | 'response_split' | 'log_injection'
    detail: string
    injectedHeader: string | null
    confidence: number
}

const DANGEROUS_HEADERS = new Set([
    'set-cookie',
    'location',
    'content-type',
    'transfer-encoding',
    'content-length',
    'x-forwarded-for',
    'x-forwarded-host',
    'authorization',
    'proxy-authorization',
    'cookie',
    'host',
    'referer',
    'origin',
    'location',
    'content-security-policy',
])

interface LineBreak {
    index: number
    length: number
    isDouble: boolean
    secondLength: number
}

function decodeCRLF(input: string, maxIterations = 4): string {
    let current = input

    for (let i = 0; i < maxIterations; i++) {
        let next = current

        next = next.replace(/%u00(0[dD])|%u00(0[aA])/gi, (_, a, b) => {
            const lower = (a ?? b).toLowerCase()
            return lower === '0d' ? '\r' : '\n'
        })

        try {
            next = decodeURIComponent(next)
        } catch {
            next = next.replace(/%([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        }

        next = next.replace(/\\r\\n/g, '\r\n')
            .replace(/\\n/g, '\n')
            .replace(/\\r/g, '\r')

        if (next === current) return current
        current = next
    }

    return current
}

function detectEncodedPatterns(raw: string): CRLFDetection[] {
    const detections: CRLFDetection[] = []
    const normalized = raw.toLowerCase()

    if (/%0d%0a/.test(normalized)) {
        detections.push({
            type: 'header_injection',
            detail: 'URL-encoded CRLF sequence (%0d%0a) detected',
            injectedHeader: null,
            confidence: 0.93,
        })
    }

    if (/(?:%0a|%0A)/.test(normalized)) {
        detections.push({
            type: 'header_injection',
            detail: 'URL-encoded LF sequence (%0a) detected',
            injectedHeader: null,
            confidence: 0.86,
        })
    }

    if (/%e5%98%8a|%e5%98%8d|%u000d|%u000a/.test(normalized)) {
        detections.push({
            type: 'header_injection',
            detail: 'Unicode/UTF-16 CRLF obfuscation sequence detected',
            injectedHeader: null,
            confidence: 0.76,
        })
    }

    return detections
}

function findBreaks(decoded: string): LineBreak[] {
    const breaks: LineBreak[] = []
    let i = 0

    while (i < decoded.length) {
        const ch = decoded[i]

        if (ch === '\r') {
            const firstLen = decoded[i + 1] === '\n' ? 2 : 1
            let isDouble = false
            let secondLen = 0

            const afterFirst = i + firstLen
            if (decoded.startsWith('\r\n', afterFirst) || (firstLen === 1 && decoded[afterFirst] === '\n')) {
                isDouble = true
                if (decoded[afterFirst] === '\r' && decoded[afterFirst + 1] === '\n') {
                    secondLen = 2
                } else {
                    secondLen = 1
                }
            }

            breaks.push({ index: i, length: firstLen, isDouble, secondLength: secondLen })
            i = isDouble ? afterFirst + secondLen : i + firstLen
            continue
        }

        if (ch === '\n' && decoded[i - 1] !== '\r') {
            const isDouble = decoded[i + 1] === '\n'
            breaks.push({
                index: i,
                length: 1,
                isDouble,
                secondLength: isDouble ? 1 : 0,
            })
            i += isDouble ? 2 : 1
            continue
        }

        i++
    }

    return breaks
}

function detectLogInjectionFromPrefix(decoded: string): CRLFDetection[] {
    const detections: CRLFDetection[] = []
    const lower = decoded.toLowerCase()

    for (const header of ['user-agent', 'referer', 'referrer']) {
        if (lower.includes(`${header}=`) && (/\\r|\\n/.test(decoded))) {
            detections.push({
                type: 'log_injection',
                detail: `Potential log forging in ${header}`,
                injectedHeader: null,
                confidence: 0.81,
            })
        }
    }

    return detections
}

function detectHeaderInjection(decoded: string, breaks: LineBreak[]): CRLFDetection[] {
    const detections: CRLFDetection[] = []

    for (const item of breaks) {
        if (item.isDouble) continue

        const start = item.index + item.length
        const after = decoded.slice(start).match(/^\s*([A-Za-z][A-Za-z0-9-]*)\s*:\s*([^\r\n]*)/i)
        if (!after) continue

        const name = after[1].toLowerCase()
        const value = after[2].trim().slice(0, 60)
        const isDangerous = DANGEROUS_HEADERS.has(name)
        detections.push({
            type: 'header_injection',
            detail: `CRLF header injection: ${name}: ${value}`,
            injectedHeader: after[1],
            confidence: isDangerous ? 0.95 : 0.87,
        })
    }

    return detections
}

function detectResponseSplit(decoded: string, breaks: LineBreak[]): CRLFDetection[] {
    const detections: CRLFDetection[] = []

    for (const item of breaks) {
        if (!item.isDouble) continue

        const start = item.index + item.length + item.secondLength
        const trailing = decoded.slice(start).trimStart()

        if (!trailing) {
            continue
        }

        const lower = trailing.toLowerCase()
        const hasSetCookie = lower.includes('set-cookie')
        detections.push({
            type: 'response_split',
            detail: hasSetCookie
                ? 'HTTP response splitting with Set-Cookie injection candidate'
                : 'HTTP response splitting via double-CRLF marker',
            injectedHeader: hasSetCookie ? 'Set-Cookie' : null,
            confidence: hasSetCookie ? 0.96 : 0.90,
        })
    }

    return detections
}

function dedupe(values: CRLFDetection[]): CRLFDetection[] {
    const seen = new Set<string>()
    const out: CRLFDetection[] = []
    for (const value of values) {
        const key = `${value.type}|${value.injectedHeader ?? ''}|${value.detail}`
        if (seen.has(key)) continue
        seen.add(key)
        out.push(value)
    }
    return out
}

export function detectCRLF(input: string): CRLFDetection[] {
    if (!input) return []

    const lower = input.toLowerCase()
    const hasCrOrLfEvidence = /\\r|\\n|%0d|%0a|%u000d|%u000a|%e5%98%8a|%e5%98%8d/.test(lower)
    if (!hasCrOrLfEvidence) return []

    const encodedDetections = detectEncodedPatterns(input)
    const decoded = decodeCRLF(input)
    const breaks = findBreaks(decoded)
    if (breaks.length === 0) return dedupe(encodedDetections)

    return dedupe([
        ...encodedDetections,
        ...detectHeaderInjection(decoded, breaks),
        ...detectResponseSplit(decoded, breaks),
        ...detectLogInjectionFromPrefix(decoded),
    ])
}

export function detectCRLFInjection(input: string): CRLFDetection[] {
    return detectCRLF(input)
}
