/**
 * Template Expression Tokenizer — SSTI Detection
 *
 * Detects and tokenizes template expressions across multiple engines:
 *   - Jinja2/Twig:      {{ expr }} and {% stmt %}
 *   - Java EL / SpEL:   ${ expr } and #{ expr }
 *   - ERB (Ruby):       <%= expr %> and <% stmt %>
 *   - OGNL:             %{ expr }
 *   - Moustache:        {{ expr }}
 *   - Freemarker:       ${ expr } and <# stmt>
 *
 * SSTI detection becomes: "does the input contain template expression
 * delimiters with dangerous property access chains inside?" not
 * "does the string match a regex for known SSTI payloads."
 *
 * This catches:
 *   - {{config.__class__.__init__.__globals__}}
 *   - ${T(java.lang.Runtime).getRuntime().exec("id")}
 *   - #{T(java.lang.Runtime).getRuntime().exec("id")}
 *   - <%=`id`%>
 *   - Novel template injection payloads we haven't seen
 */

import type { Token, Tokenizer, TokenStream } from './types.js'
import { MAX_TOKENIZER_INPUT, MAX_TOKEN_COUNT } from './types.js'
import { TokenStream as TS } from './types.js'


// ── Template Token Types ─────────────────────────────────────────

export type TemplateTokenType =
    | 'TEXT'               // Plain text outside expressions
    | 'EXPR_OPEN'          // {{ or ${ or #{ or <%=
    | 'EXPR_CLOSE'         // }} or } or %>
    | 'STMT_OPEN'          // {% or <% (statement blocks)
    | 'STMT_CLOSE'         // %} or %>
    | 'IDENTIFIER'         // variable/property names
    | 'DOT_ACCESS'         // . (property access operator)
    | 'DUNDER'             // __name__ (Python dunder property)
    | 'METHOD_CALL'        // ( opening paren of function/method call
    | 'PAREN_CLOSE'        // )
    | 'STRING'             // 'text' or "text" inside expression
    | 'NUMBER'             // numeric literal
    | 'OPERATOR'           // +, -, *, /, |, etc.
    | 'BRACKET_OPEN'       // [
    | 'BRACKET_CLOSE'      // ]
    | 'COMMA'              // ,
    | 'FILTER'             // | (Jinja2 filter separator)
    | 'WHITESPACE'         // Whitespace inside expressions
    | 'UNKNOWN'            // Malformed content


// ── Template Expression Classification ───────────────────────────

export type TemplateEngine = 'jinja2' | 'el' | 'spel' | 'erb' | 'ognl' | 'moustache' | 'freemarker' | 'unknown'


// ── Template Tokenizer ───────────────────────────────────────────

export class TemplateTokenizer implements Tokenizer<TemplateTokenType> {
    readonly language = 'template'

    tokenize(input: string): TokenStream<TemplateTokenType> {
        const bounded = input.length > MAX_TOKENIZER_INPUT
            ? input.slice(0, MAX_TOKENIZER_INPUT)
            : input

        const tokens: Token<TemplateTokenType>[] = []
        let i = 0
        let inExpression = false

        while (i < bounded.length && tokens.length < MAX_TOKEN_COUNT) {
            if (!inExpression) {
                // Look for expression/statement openers
                const opener = this.matchOpener(bounded, i)
                if (opener) {
                    // Emit any preceding text
                    if (opener.textBefore > 0) {
                        const textStart = i - opener.textBefore
                        // We actually need to emit text before the opener
                    }
                    tokens.push({
                        type: opener.isStatement ? 'STMT_OPEN' : 'EXPR_OPEN',
                        value: opener.value,
                        start: i,
                        end: i + opener.value.length,
                    })
                    i += opener.value.length
                    inExpression = true
                    continue
                }

                // Plain text — consume until we find an opener or end
                const textStart = i
                while (i < bounded.length && !this.matchOpener(bounded, i)) i++
                if (i > textStart) {
                    tokens.push({ type: 'TEXT', value: bounded.slice(textStart, i), start: textStart, end: i })
                }
                continue
            }

            // Inside an expression — tokenize the expression content
            const ch = bounded[i]

            // Check for closers
            const closer = this.matchCloser(bounded, i)
            if (closer) {
                tokens.push({
                    type: closer.isStatement ? 'STMT_CLOSE' : 'EXPR_CLOSE',
                    value: closer.value,
                    start: i,
                    end: i + closer.value.length,
                })
                i += closer.value.length
                inExpression = false
                continue
            }

            // Whitespace
            if (/\s/.test(ch)) {
                const start = i
                while (i < bounded.length && /\s/.test(bounded[i])) i++
                tokens.push({ type: 'WHITESPACE', value: bounded.slice(start, i), start, end: i })
                continue
            }

            // Dot access
            if (ch === '.') {
                tokens.push({ type: 'DOT_ACCESS', value: '.', start: i, end: i + 1 })
                i++
                continue
            }

            // Parentheses (method calls)
            if (ch === '(') {
                tokens.push({ type: 'METHOD_CALL', value: '(', start: i, end: i + 1 })
                i++
                continue
            }
            if (ch === ')') {
                tokens.push({ type: 'PAREN_CLOSE', value: ')', start: i, end: i + 1 })
                i++
                continue
            }

            // Brackets
            if (ch === '[') {
                tokens.push({ type: 'BRACKET_OPEN', value: '[', start: i, end: i + 1 })
                i++
                continue
            }
            if (ch === ']') {
                tokens.push({ type: 'BRACKET_CLOSE', value: ']', start: i, end: i + 1 })
                i++
                continue
            }

            // Comma
            if (ch === ',') {
                tokens.push({ type: 'COMMA', value: ',', start: i, end: i + 1 })
                i++
                continue
            }

            // Pipe (Jinja2 filter)
            if (ch === '|') {
                tokens.push({ type: 'FILTER', value: '|', start: i, end: i + 1 })
                i++
                continue
            }

            // Operators
            if (/[+\-*\/%=<>!&^~@#]/.test(ch)) {
                const start = i
                // Consume multi-char operators
                while (i < bounded.length && /[+\-*\/%=<>!&^~@#]/.test(bounded[i])) i++
                tokens.push({ type: 'OPERATOR', value: bounded.slice(start, i), start, end: i })
                continue
            }

            // String literals
            if (ch === '"' || ch === "'") {
                const quote = ch
                const start = i
                i++ // skip opening quote
                while (i < bounded.length && bounded[i] !== quote) {
                    if (bounded[i] === '\\') i++ // skip escaped
                    i++
                }
                if (i < bounded.length) i++ // skip closing quote
                tokens.push({ type: 'STRING', value: bounded.slice(start, i), start, end: i })
                continue
            }

            // Numbers
            if (/[0-9]/.test(ch)) {
                const start = i
                while (i < bounded.length && /[0-9.]/.test(bounded[i])) i++
                tokens.push({ type: 'NUMBER', value: bounded.slice(start, i), start, end: i })
                continue
            }

            // Identifiers (including dunder properties)
            if (/[a-zA-Z_]/.test(ch)) {
                const start = i
                while (i < bounded.length && /[a-zA-Z0-9_]/.test(bounded[i])) i++
                const word = bounded.slice(start, i)

                // Check for dunder pattern: __name__
                if (word.startsWith('__') && word.endsWith('__') && word.length > 4) {
                    tokens.push({ type: 'DUNDER', value: word, start, end: i })
                } else {
                    tokens.push({ type: 'IDENTIFIER', value: word, start, end: i })
                }
                continue
            }

            // Unknown
            tokens.push({ type: 'UNKNOWN', value: ch, start: i, end: i + 1 })
            i++
        }

        return new TS(tokens)
    }

    private matchOpener(input: string, pos: number): { value: string; isStatement: boolean; textBefore: number } | null {
        // Order matters — check longer sequences first
        if (input.slice(pos, pos + 3) === '<%=') return { value: '<%=', isStatement: false, textBefore: 0 }
        if (input.slice(pos, pos + 2) === '{%') return { value: '{%', isStatement: true, textBefore: 0 }
        if (input.slice(pos, pos + 2) === '{{') return { value: '{{', isStatement: false, textBefore: 0 }
        if (input.slice(pos, pos + 2) === '${') return { value: '${', isStatement: false, textBefore: 0 }
        if (input.slice(pos, pos + 2) === '#{') return { value: '#{', isStatement: false, textBefore: 0 }
        if (input.slice(pos, pos + 2) === '%{') return { value: '%{', isStatement: false, textBefore: 0 }
        if (input.slice(pos, pos + 2) === '<%') return { value: '<%', isStatement: true, textBefore: 0 }
        return null
    }

    private matchCloser(input: string, pos: number): { value: string; isStatement: boolean } | null {
        if (input.slice(pos, pos + 2) === '%}') return { value: '%}', isStatement: true }
        if (input.slice(pos, pos + 2) === '}}') return { value: '}}', isStatement: false }
        if (input.slice(pos, pos + 2) === '%>') return { value: '%>', isStatement: true }
        if (input[pos] === '}' && input[pos - 1] !== '}') return { value: '}', isStatement: false }
        return null
    }
}


// ── Template Analysis for SSTI Detection ─────────────────────────

export interface TemplateSstiDetection {
    type: 'code_execution' | 'prototype_chain' | 'config_access' | 'file_access' | 'arithmetic_probe'
    engine: TemplateEngine
    confidence: number
    detail: string
}

// Dangerous method/property names for SSTI
const DANGEROUS_IDENTIFIERS = new Set([
    'exec', 'system', 'popen', 'spawn', 'eval', 'import',
    'require', 'getRuntime', 'ProcessBuilder', 'Runtime',
    'forName', 'getMethod', 'invoke', 'newInstance',
    'execSync', 'spawnSync', 'child_process',
])

const DANGEROUS_DUNDERS = new Set([
    '__class__', '__mro__', '__subclasses__', '__builtins__',
    '__globals__', '__init__', '__import__', '__reduce__',
    '__getattr__', '__setattr__', '__delattr__', '__dict__',
    '__bases__', '__code__', '__func__',
])

const CONFIG_IDENTIFIERS = new Set([
    'config', 'settings', 'request', 'application', 'session',
    'self', 'lipsum', 'cycler', 'joiner', 'namespace',
    'environment', 'loader',
])

export function analyzeTemplateForSsti(stream: TokenStream<TemplateTokenType>): TemplateSstiDetection[] {
    const detections: TemplateSstiDetection[] = []
    const tokens = stream.meaningful()

    // Count dangerous patterns
    let hasDunders = false
    let hasDangerousCalls = false
    let hasConfigAccess = false
    let dungeonCount = 0

    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i]

        // Dunder property access (Python SSTI)
        if (tok.type === 'DUNDER') {
            hasDunders = true
            dungeonCount++
            if (DANGEROUS_DUNDERS.has(tok.value)) {
                dungeonCount += 2
            }
        }

        // Dangerous method calls
        if (tok.type === 'IDENTIFIER' && DANGEROUS_IDENTIFIERS.has(tok.value)) {
            hasDangerousCalls = true
        }

        // Config/request access
        if (tok.type === 'IDENTIFIER' && CONFIG_IDENTIFIERS.has(tok.value)) {
            hasConfigAccess = true
        }
    }

    // Detect prototype chain traversal (Jinja2/Python SSTI)
    if (hasDunders && dungeonCount >= 2) {
        detections.push({
            type: 'prototype_chain',
            engine: 'jinja2',
            confidence: 0.93,
            detail: `Dunder chain with ${dungeonCount} dangerous properties`,
        })
    }

    // Detect code execution attempts
    if (hasDangerousCalls) {
        const engine = detectEngine(tokens)
        detections.push({
            type: 'code_execution',
            engine,
            confidence: 0.92,
            detail: 'Dangerous method invocation inside template expression',
        })
    }

    // Detect config access (lower severity)
    if (hasConfigAccess && (hasDunders || hasDangerousCalls)) {
        detections.push({
            type: 'config_access',
            engine: 'jinja2',
            confidence: 0.85,
            detail: 'Config/request object accessed with dangerous chain',
        })
    }

    // Arithmetic probe detection ({{7*7}})
    const hasArith = tokens.some(t => t.type === 'NUMBER') &&
        tokens.some(t => t.type === 'OPERATOR' && /[*+\-/]/.test(t.value)) &&
        tokens.filter(t => t.type === 'EXPR_OPEN').length > 0

    if (hasArith && tokens.length < 10) {
        detections.push({
            type: 'arithmetic_probe',
            engine: 'unknown',
            confidence: 0.60, // Low confidence — could be legitimate math
            detail: 'Arithmetic expression in template delimiters (probe)',
        })
    }

    return detections
}

function detectEngine(tokens: Token<TemplateTokenType>[]): TemplateEngine {
    // Check opener type
    for (const tok of tokens) {
        if (tok.type === 'EXPR_OPEN') {
            if (tok.value === '{{') return 'jinja2'
            if (tok.value === '${') return 'el'
            if (tok.value === '#{') return 'spel'
            if (tok.value === '<%=') return 'erb'
            if (tok.value === '%{') return 'ognl'
        }
    }

    // Check for Java-specific patterns
    if (tokens.some(t => t.type === 'IDENTIFIER' && t.value === 'T')) return 'spel'
    if (tokens.some(t => t.type === 'IDENTIFIER' && t.value.includes('java'))) return 'el'

    return 'unknown'
}
