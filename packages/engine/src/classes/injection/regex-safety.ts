/**
 * ReDoS-aware regex helpers for user-supplied input.
 *
 * We keep these wrappers synchronous and apply deterministic guards:
 * 1) untrusted input length cap
 * 2) quick runtime budget check
 *
 * This is an additional safety net and does not replace deeper input validation.
 */

export interface RegexSafetyOptions {
    timeoutMs: number
    maxInputLength: number
}

const DEFAULT_OPTIONS: RegexSafetyOptions = {
    timeoutMs: 10,
    maxInputLength: 20_000,
}

function isInputOverLimit(input: string, options: RegexSafetyOptions): boolean {
    return input.length > options.maxInputLength
}

function clonePattern(pattern: RegExp): RegExp {
    return new RegExp(pattern.source, pattern.flags)
}

function measureBoolean<T>(runner: () => T, timeoutMs: number): { elapsedMs: number; result: T } {
    const start = Date.now()
    const result = runner()
    return { elapsedMs: Date.now() - start, result }
}

export function safeRegexTest(
    pattern: RegExp,
    input: string,
    options?: Partial<RegexSafetyOptions>,
): boolean {
    const merged = { ...DEFAULT_OPTIONS, ...options }
    if (isInputOverLimit(input, merged)) return false

    const patternCopy = clonePattern(pattern)
    if (patternCopy.global || patternCopy.sticky) patternCopy.lastIndex = 0

    const { result, elapsedMs } = measureBoolean(() => patternCopy.test(input), merged.timeoutMs)
    if (elapsedMs > merged.timeoutMs) {
        return false
    }
    return result
}

export function safeRegexMatch(
    pattern: RegExp,
    input: string,
    options?: Partial<RegexSafetyOptions>,
): RegExpMatchArray | null {
    const merged = { ...DEFAULT_OPTIONS, ...options }
    if (isInputOverLimit(input, merged)) return null

    const patternCopy = clonePattern(pattern)
    const { result, elapsedMs } = measureBoolean(() => input.match(patternCopy), merged.timeoutMs)
    return elapsedMs > merged.timeoutMs ? null : result
}

export function safeRegexExec(
    pattern: RegExp,
    input: string,
    options?: Partial<RegexSafetyOptions>,
): RegExpExecArray | null {
    const merged = { ...DEFAULT_OPTIONS, ...options }
    if (isInputOverLimit(input, merged)) return null

    const patternCopy = clonePattern(pattern)
    if (patternCopy.global || patternCopy.sticky) patternCopy.lastIndex = 0

    const { result, elapsedMs } = measureBoolean(() => patternCopy.exec(input), merged.timeoutMs)
    if (elapsedMs > merged.timeoutMs) {
        return null
    }
    return result
}

export function safeRegexMatchAll(
    pattern: RegExp,
    input: string,
    options?: Partial<RegexSafetyOptions>,
): RegExpMatchArray[] | null {
    const merged = { ...DEFAULT_OPTIONS, ...options }
    if (isInputOverLimit(input, merged)) return null

    let patternCopy = clonePattern(pattern)
    if (!patternCopy.global) {
        const expandedFlags = patternCopy.flags.includes('g') ? patternCopy.flags : `${patternCopy.flags}g`
        patternCopy = new RegExp(patternCopy.source, expandedFlags)
    }

    patternCopy.lastIndex = 0

    const { result, elapsedMs } = measureBoolean(() => Array.from(input.matchAll(patternCopy)), merged.timeoutMs)
    if (elapsedMs > merged.timeoutMs) {
        return null
    }

    return result as RegExpMatchArray[]
}
