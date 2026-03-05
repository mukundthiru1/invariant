/**
 * Tokenizer Framework — Shared Types for All Language Tokenizers
 *
 * Every language tokenizer (SQL, HTML, Shell, Template) produces a
 * stream of typed tokens. Invariant detection then operates on the
 * token stream structure, not the raw string. This is what makes
 * INVARIANT immune to encoding evasion — the tokenizer normalizes
 * before the detector analyzes.
 *
 * The tokenizer framework provides:
 *   1. A common Token<T> interface parameterized by token type
 *   2. A TokenStream abstraction with lookahead and backtracking
 *   3. A Tokenizer<T> interface that all language tokenizers implement
 *   4. Security bounds (max input length, max token count, timeouts)
 *
 * SECURITY INVARIANTS:
 *   - All tokenizers MUST be bounded: O(n) where n = input length
 *   - All tokenizers MUST cap output token count (prevent memory exhaustion)
 *   - All tokenizers MUST handle malformed input gracefully (partial parses)
 *   - No tokenizer may throw — all errors produce token type UNKNOWN
 */


// ── Security Bounds ──────────────────────────────────────────────

/** Maximum input bytes any tokenizer will process */
export const MAX_TOKENIZER_INPUT = 8192

/** Maximum tokens any tokenizer will produce before stopping */
export const MAX_TOKEN_COUNT = 2048


// ── Token ────────────────────────────────────────────────────────

/**
 * A single token produced by a tokenizer.
 * Parameterized by T which is the language-specific token type enum.
 */
export interface Token<T extends string> {
    /** Language-specific token type */
    readonly type: T

    /** Raw text of this token (the source characters it represents) */
    readonly value: string

    /** Byte offset in the original input where this token starts */
    readonly start: number

    /** Byte offset in the original input where this token ends (exclusive) */
    readonly end: number
}


// ── Token Stream ─────────────────────────────────────────────────

/**
 * Immutable token stream with lookahead, filtering, and structural queries.
 * This is what invariant detectors consume.
 */
export class TokenStream<T extends string> {
    private readonly tokens: ReadonlyArray<Token<T>>
    private position: number

    constructor(tokens: ReadonlyArray<Token<T>>) {
        this.tokens = tokens
        this.position = 0
    }

    /** Current position in the stream */
    get pos(): number {
        return this.position
    }

    /** Total number of tokens */
    get length(): number {
        return this.tokens.length
    }

    /** Whether we've consumed all tokens */
    get done(): boolean {
        return this.position >= this.tokens.length
    }

    /** Current token (without advancing) */
    peek(): Token<T> | undefined {
        return this.tokens[this.position]
    }

    /** Lookahead N tokens */
    peekAt(offset: number): Token<T> | undefined {
        return this.tokens[this.position + offset]
    }

    /** Consume and return current token */
    next(): Token<T> | undefined {
        if (this.position >= this.tokens.length) return undefined
        return this.tokens[this.position++]
    }

    /** Consume current token if it matches the expected type */
    expect(type: T): Token<T> | undefined {
        const tok = this.peek()
        if (tok && tok.type === type) {
            this.position++
            return tok
        }
        return undefined
    }

    /** Skip tokens while they match the predicate */
    skipWhile(predicate: (t: Token<T>) => boolean): void {
        while (this.position < this.tokens.length && predicate(this.tokens[this.position])) {
            this.position++
        }
    }

    /** Skip whitespace tokens (type must be named 'WHITESPACE') */
    skipWhitespace(): void {
        this.skipWhile(t => t.type === ('WHITESPACE' as T))
    }

    /** Save position for backtracking */
    save(): number {
        return this.position
    }

    /** Restore to a previously saved position */
    restore(position: number): void {
        this.position = position
    }

    /** Get all tokens (no filtering) */
    all(): ReadonlyArray<Token<T>> {
        return this.tokens
    }

    /** Get tokens of a specific type */
    ofType(type: T): Token<T>[] {
        return this.tokens.filter(t => t.type === type)
    }

    /** Get all tokens filtered to exclude whitespace */
    meaningful(): Token<T>[] {
        return this.tokens.filter(t => t.type !== ('WHITESPACE' as T))
    }

    /** Check if the stream contains a token of a given type */
    contains(type: T): boolean {
        return this.tokens.some(t => t.type === type)
    }

    /** Count tokens of a given type */
    count(type: T): number {
        return this.tokens.filter(t => t.type === type).length
    }

    /**
     * Find sequences of N consecutive tokens matching a type pattern.
     * For structural detection: "does the stream contain STRING, KEYWORD(OR), COMPARISON?"
     */
    findPattern(pattern: T[]): Array<{ startIndex: number; tokens: Token<T>[] }> {
        const matches: Array<{ startIndex: number; tokens: Token<T>[] }> = []
        const meaningful = this.meaningful()

        for (let i = 0; i <= meaningful.length - pattern.length; i++) {
            let match = true
            for (let j = 0; j < pattern.length; j++) {
                if (meaningful[i + j].type !== pattern[j]) {
                    match = false
                    break
                }
            }
            if (match) {
                matches.push({
                    startIndex: i,
                    tokens: meaningful.slice(i, i + pattern.length),
                })
            }
        }

        return matches
    }

    /** Create a sub-stream from a range of token indices */
    slice(start: number, end?: number): TokenStream<T> {
        return new TokenStream(this.tokens.slice(start, end))
    }
}


// ── Tokenizer Interface ──────────────────────────────────────────

/**
 * The interface all language tokenizers implement.
 */
export interface Tokenizer<T extends string> {
    /** Language identifier for this tokenizer */
    readonly language: string

    /**
     * Tokenize the input string into a stream of typed tokens.
     *
     * INVARIANTS:
     * - Input is bounded to MAX_TOKENIZER_INPUT characters
     * - Output is bounded to MAX_TOKEN_COUNT tokens
     * - Never throws — malformed input produces UNKNOWN tokens
     * - O(n) time complexity where n = input length
     */
    tokenize(input: string): TokenStream<T>
}


// ── Tokenize Result (with diagnostics) ───────────────────────────

export interface TokenizeResult<T extends string> {
    /** The token stream */
    stream: TokenStream<T>

    /** Whether the input was truncated due to size limits */
    truncated: boolean

    /** Whether the tokenizer produced the maximum number of tokens */
    maxTokensReached: boolean

    /** Time taken to tokenize in microseconds */
    durationMicros: number
}

/**
 * Helper to run a tokenizer with diagnostics.
 */
export function tokenizeWithDiagnostics<T extends string>(
    tokenizer: Tokenizer<T>,
    input: string,
): TokenizeResult<T> {
    const truncated = input.length > MAX_TOKENIZER_INPUT
    const bounded = truncated ? input.slice(0, MAX_TOKENIZER_INPUT) : input

    const start = performance.now()
    const stream = tokenizer.tokenize(bounded)
    const durationMicros = (performance.now() - start) * 1000

    return {
        stream,
        truncated,
        maxTokensReached: stream.length >= MAX_TOKEN_COUNT,
        durationMicros,
    }
}
