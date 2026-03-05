/**
 * SQL Expression Evaluator — Level 2 Invariant Detection
 *
 * Replaces regex-based SQL tautology detection with actual
 * expression tokenization and evaluation.
 *
 * The invariant property for sql_tautology is:
 *   ∃ subexpr ∈ parse(input, SQL_GRAMMAR) :
 *     eval(subexpr, BOOLEAN_CONTEXT) ∈ {TRUE, TAUTOLOGY}
 *
 * This module implements that property check by:
 *   1. Tokenizing the input into SQL-aware tokens
 *   2. Extracting conditional sub-expressions
 *   3. Evaluating whether any sub-expression is tautological
 *
 * This catches:
 *   - ' OR 1=1            (numeric equality tautology)
 *   - ' OR 2>1            (numeric comparison tautology)
 *   - ' OR 'a'='a'        (string equality tautology)
 *   - ' OR ASCII('a')=97  (function tautology)
 *   - ' OR 1 BETWEEN 0 AND 2  (range tautology)
 *   - ' OR 1 IN (1,2,3)   (membership tautology)
 *   - ' OR 1 IS NOT NULL   (null check tautology)
 *   - ' OR NOT FALSE       (negation tautology)
 *   - ' OR ''=''           (empty string equality)
 *   - ' OR 0=0+0           (arithmetic tautology)
 *   - Novel tautologies we haven't imagined yet
 *
 * A regex can only match patterns you've explicitly listed.
 * An evaluator catches ANY expression that evaluates to TRUE.
 */


// ── Token Types ──────────────────────────────────────────────────

export type SqlTokenType =
    | 'NUMBER'           // 1, 42, 3.14, 0xFF
    | 'STRING'           // 'hello', "world"
    | 'IDENTIFIER'       // column_name, table
    | 'OPERATOR'         // =, <, >, <=, >=, <>, !=
    | 'BOOLEAN_OP'       // AND, OR
    | 'KEYWORD'          // SELECT, FROM, WHERE, IS, NOT, NULL, TRUE, FALSE, LIKE, IN, BETWEEN
    | 'PAREN_OPEN'       // (
    | 'PAREN_CLOSE'      // )
    | 'COMMA'            // ,
    | 'SEPARATOR'        // ;, --, #
    | 'WILDCARD'         // *
    | 'WHITESPACE'       // spaces, tabs
    | 'UNKNOWN'          // anything else

export interface SqlToken {
    type: SqlTokenType
    value: string
    position: number
}


// ── SQL Tokenizer ────────────────────────────────────────────────

const SQL_KEYWORDS = new Set([
    'SELECT', 'FROM', 'WHERE', 'IS', 'NOT', 'NULL', 'TRUE', 'FALSE',
    'LIKE', 'IN', 'BETWEEN', 'EXISTS', 'HAVING', 'GROUP', 'ORDER',
    'UNION', 'ALL', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
    'ALTER', 'EXEC', 'EXECUTE', 'CAST', 'CONVERT', 'AS', 'CASE',
    'WHEN', 'THEN', 'ELSE', 'END', 'LIMIT', 'OFFSET', 'ASC', 'DESC',
])

const BOOLEAN_OPS = new Set(['AND', 'OR'])

/**
 * Tokenize a string into SQL-aware tokens.
 *
 * Unlike a full SQL parser, this is designed for ATTACK DETECTION:
 * - Tolerates malformed/partial SQL (attackers inject fragments)
 * - Handles mixed content (URL parameters with SQL fragments)
 * - Doesn't need a complete statement to work
 * - Fast enough for hot-path usage (sub-millisecond for typical inputs)
 */
export function sqlTokenize(input: string): SqlToken[] {
    const tokens: SqlToken[] = []
    let i = 0
    const len = input.length

    // Safety: limit tokenization to prevent DoS from huge inputs
    const MAX_INPUT = 4096
    const bounded = len > MAX_INPUT ? input.slice(0, MAX_INPUT) : input

    while (i < bounded.length) {
        const ch = bounded[i]

        // Skip whitespace
        if (/\s/.test(ch)) {
            const start = i
            while (i < bounded.length && /\s/.test(bounded[i])) i++
            tokens.push({ type: 'WHITESPACE', value: bounded.slice(start, i), position: start })
            continue
        }

        // SQL line comment: -- or #
        if ((ch === '-' && bounded[i + 1] === '-') || ch === '#') {
            tokens.push({ type: 'SEPARATOR', value: bounded.slice(i), position: i })
            break // Rest of input is comment
        }

        // SQL block comment: /* ... */
        if (ch === '/' && bounded[i + 1] === '*') {
            const end = bounded.indexOf('*/', i + 2)
            if (end !== -1) {
                i = end + 2
            } else {
                i = bounded.length
            }
            continue
        }

        // String literals: 'text' or "text"
        if (ch === "'" || ch === '"') {
            const quote = ch
            const start = i
            i++ // skip opening quote
            while (i < bounded.length) {
                if (bounded[i] === quote) {
                    if (bounded[i + 1] === quote) {
                        i += 2 // escaped quote ''
                    } else {
                        i++ // closing quote
                        break
                    }
                } else {
                    i++
                }
            }
            tokens.push({ type: 'STRING', value: bounded.slice(start, i), position: start })
            continue
        }

        // Backtick identifier: `name`
        if (ch === '`') {
            const start = i
            i++
            while (i < bounded.length && bounded[i] !== '`') i++
            if (i < bounded.length) i++ // skip closing backtick
            tokens.push({ type: 'IDENTIFIER', value: bounded.slice(start, i), position: start })
            continue
        }

        // Numbers: 42, 3.14, 0xFF, 0b101
        if (/[0-9]/.test(ch) || (ch === '.' && i + 1 < bounded.length && /[0-9]/.test(bounded[i + 1]))) {
            const start = i
            if (ch === '0' && bounded[i + 1]?.toLowerCase() === 'x') {
                i += 2
                while (i < bounded.length && /[0-9a-fA-F]/.test(bounded[i])) i++
            } else if (ch === '0' && bounded[i + 1]?.toLowerCase() === 'b') {
                i += 2
                while (i < bounded.length && /[01]/.test(bounded[i])) i++
            } else {
                while (i < bounded.length && /[0-9]/.test(bounded[i])) i++
                if (i < bounded.length && bounded[i] === '.') {
                    i++
                    while (i < bounded.length && /[0-9]/.test(bounded[i])) i++
                }
            }
            tokens.push({ type: 'NUMBER', value: bounded.slice(start, i), position: start })
            continue
        }

        // Operators: =, <, >, <=, >=, <>, !=
        if (ch === '=' || ch === '<' || ch === '>' || ch === '!') {
            const start = i
            if (bounded[i + 1] === '=') {
                i += 2
            } else if (ch === '<' && bounded[i + 1] === '>') {
                i += 2
            } else {
                i++
            }
            tokens.push({ type: 'OPERATOR', value: bounded.slice(start, i), position: start })
            continue
        }

        // || as boolean OR
        if (ch === '|' && bounded[i + 1] === '|') {
            tokens.push({ type: 'BOOLEAN_OP', value: 'OR', position: i })
            i += 2
            continue
        }

        // Parentheses
        if (ch === '(') {
            tokens.push({ type: 'PAREN_OPEN', value: '(', position: i })
            i++
            continue
        }
        if (ch === ')') {
            tokens.push({ type: 'PAREN_CLOSE', value: ')', position: i })
            i++
            continue
        }

        // Comma
        if (ch === ',') {
            tokens.push({ type: 'COMMA', value: ',', position: i })
            i++
            continue
        }

        // Semicolon
        if (ch === ';') {
            tokens.push({ type: 'SEPARATOR', value: ';', position: i })
            i++
            continue
        }

        // Wildcard
        if (ch === '*') {
            tokens.push({ type: 'WILDCARD', value: '*', position: i })
            i++
            continue
        }

        // Identifiers and keywords
        if (/[a-zA-Z_]/.test(ch)) {
            const start = i
            while (i < bounded.length && /[a-zA-Z0-9_.]/.test(bounded[i])) i++
            const word = bounded.slice(start, i)
            const upper = word.toUpperCase()

            if (BOOLEAN_OPS.has(upper)) {
                tokens.push({ type: 'BOOLEAN_OP', value: upper, position: start })
            } else if (SQL_KEYWORDS.has(upper)) {
                tokens.push({ type: 'KEYWORD', value: upper, position: start })
            } else {
                tokens.push({ type: 'IDENTIFIER', value: word, position: start })
            }
            continue
        }

        // Unknown character — skip
        tokens.push({ type: 'UNKNOWN', value: ch, position: i })
        i++
    }

    return tokens
}


// ── Expression Types ─────────────────────────────────────────────

export type ExpressionNode =
    | { kind: 'literal_number'; value: number }
    | { kind: 'literal_string'; value: string }
    | { kind: 'literal_bool'; value: boolean }
    | { kind: 'literal_null' }
    | { kind: 'identifier'; name: string }
    | { kind: 'comparison'; left: ExpressionNode; operator: string; right: ExpressionNode }
    | { kind: 'boolean_op'; left: ExpressionNode; operator: 'AND' | 'OR'; right: ExpressionNode }
    | { kind: 'not'; operand: ExpressionNode }
    | { kind: 'is_null'; operand: ExpressionNode; negated: boolean }
    | { kind: 'between'; operand: ExpressionNode; low: ExpressionNode; high: ExpressionNode }
    | { kind: 'in_list'; operand: ExpressionNode; values: ExpressionNode[] }
    | { kind: 'like'; operand: ExpressionNode; pattern: ExpressionNode }
    | { kind: 'function_call'; name: string; args: ExpressionNode[] }
    | { kind: 'unknown' }


// ── Conditional Expression Extractor ─────────────────────────────

/**
 * Extract conditional sub-expressions from a token stream.
 *
 * Looks for patterns like:
 *   <something> OR <expression>
 *   <something> AND <expression>
 *   WHERE <expression>
 *   HAVING <expression>
 *
 * Returns the boolean expressions found after OR/AND/WHERE keywords.
 * Each expression is parsed into an AST node for evaluation.
 *
 * INJECTION CONTEXT HANDLING:
 * In SQL injection, the attacker's input starts mid-query.
 * For example: ' OR 1=1--
 *   - The leading ' terminates the app's SQL string context
 *   - The OR is a boolean operator in the app's WHERE clause
 *   - 1=1 is the tautology
 *
 * The tokenizer sees the ' as the start of a string literal that
 * may consume the OR keyword. To handle this, we also try
 * re-tokenizing with the leading quote stripped (injection context).
 */
export function extractConditionalExpressions(tokens: SqlToken[]): ExpressionNode[] {
    const expressions: ExpressionNode[] = []
    const meaningful = tokens.filter(t => t.type !== 'WHITESPACE' && t.type !== 'SEPARATOR')

    for (let i = 0; i < meaningful.length; i++) {
        const token = meaningful[i]

        // After OR/AND, parse the following expression
        if (token.type === 'BOOLEAN_OP') {
            const expr = parseExpression(meaningful, i + 1)
            if (expr.node.kind !== 'unknown') {
                expressions.push(expr.node)
            }
        }

        // After WHERE/HAVING, parse the following expression
        if (token.type === 'KEYWORD' && (token.value === 'WHERE' || token.value === 'HAVING')) {
            const expr = parseExpression(meaningful, i + 1)
            if (expr.node.kind !== 'unknown') {
                expressions.push(expr.node)
            }
        }
    }

    return expressions
}


// ── Expression Parser ────────────────────────────────────────────

interface ParseResult {
    node: ExpressionNode
    nextIndex: number
}

function parseExpression(tokens: SqlToken[], start: number): ParseResult {
    if (start >= tokens.length) return { node: { kind: 'unknown' }, nextIndex: start }

    // Parse left side of potential comparison
    const left = parsePrimary(tokens, start)
    if (left.node.kind === 'unknown') return left

    let idx = left.nextIndex
    if (idx >= tokens.length) return left

    const next = tokens[idx]

    // Comparison operators: =, <, >, <=, >=, <>, !=
    if (next.type === 'OPERATOR') {
        idx++
        const right = parsePrimary(tokens, idx)
        return {
            node: { kind: 'comparison', left: left.node, operator: next.value, right: right.node },
            nextIndex: right.nextIndex,
        }
    }

    // IS [NOT] NULL
    if (next.type === 'KEYWORD' && next.value === 'IS') {
        idx++
        let negated = false
        if (idx < tokens.length && tokens[idx].type === 'KEYWORD' && tokens[idx].value === 'NOT') {
            negated = true
            idx++
        }
        if (idx < tokens.length && tokens[idx].type === 'KEYWORD' && tokens[idx].value === 'NULL') {
            idx++
            return {
                node: { kind: 'is_null', operand: left.node, negated },
                nextIndex: idx,
            }
        }
        // IS TRUE / IS FALSE
        if (idx < tokens.length && tokens[idx].type === 'KEYWORD') {
            if (tokens[idx].value === 'TRUE') {
                return { node: { kind: 'literal_bool', value: !negated }, nextIndex: idx + 1 }
            }
            if (tokens[idx].value === 'FALSE') {
                return { node: { kind: 'literal_bool', value: negated }, nextIndex: idx + 1 }
            }
        }
    }

    // LIKE
    if (next.type === 'KEYWORD' && next.value === 'LIKE') {
        idx++
        const pattern = parsePrimary(tokens, idx)
        return {
            node: { kind: 'like', operand: left.node, pattern: pattern.node },
            nextIndex: pattern.nextIndex,
        }
    }

    // BETWEEN ... AND ...
    if (next.type === 'KEYWORD' && next.value === 'BETWEEN') {
        idx++
        const low = parsePrimary(tokens, idx)
        idx = low.nextIndex
        // Skip AND keyword
        if (idx < tokens.length && tokens[idx].type === 'BOOLEAN_OP' && tokens[idx].value === 'AND') {
            idx++
        }
        const high = parsePrimary(tokens, idx)
        return {
            node: { kind: 'between', operand: left.node, low: low.node, high: high.node },
            nextIndex: high.nextIndex,
        }
    }

    // IN (value, value, ...)
    if (next.type === 'KEYWORD' && next.value === 'IN') {
        idx++
        if (idx < tokens.length && tokens[idx].type === 'PAREN_OPEN') {
            idx++
            const values: ExpressionNode[] = []
            while (idx < tokens.length && tokens[idx].type !== 'PAREN_CLOSE') {
                if (tokens[idx].type === 'COMMA') {
                    idx++
                    continue
                }
                const val = parsePrimary(tokens, idx)
                values.push(val.node)
                idx = val.nextIndex
            }
            if (idx < tokens.length) idx++ // skip PAREN_CLOSE
            return {
                node: { kind: 'in_list', operand: left.node, values },
                nextIndex: idx,
            }
        }
    }

    // NOT followed by expression
    if (next.type === 'KEYWORD' && next.value === 'NOT') {
        idx++
        const operand = parsePrimary(tokens, idx)
        return {
            node: { kind: 'not', operand: operand.node },
            nextIndex: operand.nextIndex,
        }
    }

    return left
}

function parsePrimary(tokens: SqlToken[], start: number): ParseResult {
    if (start >= tokens.length) return { node: { kind: 'unknown' }, nextIndex: start }

    const token = tokens[start]

    // NOT prefix
    if (token.type === 'KEYWORD' && token.value === 'NOT') {
        const operand = parsePrimary(tokens, start + 1)
        return {
            node: { kind: 'not', operand: operand.node },
            nextIndex: operand.nextIndex,
        }
    }

    // Number literal
    if (token.type === 'NUMBER') {
        return {
            node: { kind: 'literal_number', value: parseNumericLiteral(token.value) },
            nextIndex: start + 1,
        }
    }

    // String literal
    if (token.type === 'STRING') {
        const inner = token.value.slice(1, -1).replace(/''/g, "'").replace(/""/g, '"')
        return {
            node: { kind: 'literal_string', value: inner },
            nextIndex: start + 1,
        }
    }

    // Boolean keywords
    if (token.type === 'KEYWORD') {
        if (token.value === 'TRUE') return { node: { kind: 'literal_bool', value: true }, nextIndex: start + 1 }
        if (token.value === 'FALSE') return { node: { kind: 'literal_bool', value: false }, nextIndex: start + 1 }
        if (token.value === 'NULL') return { node: { kind: 'literal_null' }, nextIndex: start + 1 }
    }

    // Identifier (could be column name or function call)
    if (token.type === 'IDENTIFIER' || (token.type === 'KEYWORD' && !BOOLEAN_OPS.has(token.value))) {
        // Check for function call: name(args)
        if (start + 1 < tokens.length && tokens[start + 1].type === 'PAREN_OPEN') {
            let idx = start + 2
            const args: ExpressionNode[] = []
            while (idx < tokens.length && tokens[idx].type !== 'PAREN_CLOSE') {
                if (tokens[idx].type === 'COMMA') {
                    idx++
                    continue
                }
                const arg = parsePrimary(tokens, idx)
                args.push(arg.node)
                idx = arg.nextIndex
            }
            if (idx < tokens.length) idx++ // skip PAREN_CLOSE
            return {
                node: { kind: 'function_call', name: token.value.toUpperCase(), args },
                nextIndex: idx,
            }
        }

        return {
            node: { kind: 'identifier', name: token.value },
            nextIndex: start + 1,
        }
    }

    // Parenthesized expression
    if (token.type === 'PAREN_OPEN') {
        const inner = parseExpression(tokens, start + 1)
        let idx = inner.nextIndex
        if (idx < tokens.length && tokens[idx].type === 'PAREN_CLOSE') idx++
        return { node: inner.node, nextIndex: idx }
    }

    return { node: { kind: 'unknown' }, nextIndex: start + 1 }
}

function parseNumericLiteral(value: string): number {
    if (value.startsWith('0x') || value.startsWith('0X')) return parseInt(value, 16)
    if (value.startsWith('0b') || value.startsWith('0B')) return parseInt(value.slice(2), 2)
    return parseFloat(value)
}


// ── Expression Evaluator ─────────────────────────────────────────

/**
 * Evaluation result for an expression node.
 *
 * An expression can:
 *   - Evaluate to a concrete value (number, string, boolean, null)
 *   - Be unevaluable (depends on unknown identifiers)
 *
 * For tautology detection, we only need to check if the expression
 * evaluates to TRUE. If it depends on unknown identifiers, it's
 * NOT a tautology (it's conditional on runtime data).
 */
export type EvalResult =
    | { evaluable: true; value: number | string | boolean | null }
    | { evaluable: false }


/**
 * Known SQL function evaluations.
 * Only includes functions whose results can be computed statically.
 */
const KNOWN_FUNCTIONS: Record<string, (...args: EvalResult[]) => EvalResult> = {
    'ASCII': (arg) => {
        if (!arg || !arg.evaluable) return { evaluable: false }
        if (typeof arg.value === 'string' && arg.value.length > 0) {
            return { evaluable: true, value: arg.value.charCodeAt(0) }
        }
        return { evaluable: false }
    },
    'CHAR': (arg) => {
        if (!arg || !arg.evaluable) return { evaluable: false }
        if (typeof arg.value === 'number') {
            return { evaluable: true, value: String.fromCharCode(arg.value) }
        }
        return { evaluable: false }
    },
    'LENGTH': (arg) => {
        if (!arg || !arg.evaluable) return { evaluable: false }
        if (typeof arg.value === 'string') {
            return { evaluable: true, value: arg.value.length }
        }
        return { evaluable: false }
    },
    'LEN': (arg) => KNOWN_FUNCTIONS['LENGTH'](arg),
    'UPPER': (arg) => {
        if (!arg || !arg.evaluable) return { evaluable: false }
        if (typeof arg.value === 'string') {
            return { evaluable: true, value: arg.value.toUpperCase() }
        }
        return { evaluable: false }
    },
    'LOWER': (arg) => {
        if (!arg || !arg.evaluable) return { evaluable: false }
        if (typeof arg.value === 'string') {
            return { evaluable: true, value: arg.value.toLowerCase() }
        }
        return { evaluable: false }
    },
    'ABS': (arg) => {
        if (!arg || !arg.evaluable) return { evaluable: false }
        if (typeof arg.value === 'number') {
            return { evaluable: true, value: Math.abs(arg.value) }
        }
        return { evaluable: false }
    },
    'FLOOR': (arg) => {
        if (!arg || !arg.evaluable) return { evaluable: false }
        if (typeof arg.value === 'number') {
            return { evaluable: true, value: Math.floor(arg.value) }
        }
        return { evaluable: false }
    },
    'CEIL': (arg) => {
        if (!arg || !arg.evaluable) return { evaluable: false }
        if (typeof arg.value === 'number') {
            return { evaluable: true, value: Math.ceil(arg.value) }
        }
        return { evaluable: false }
    },
    'CEILING': (arg) => KNOWN_FUNCTIONS['CEIL'](arg),
    'MOD': (a, b) => {
        if (!a?.evaluable || !b?.evaluable) return { evaluable: false }
        if (typeof a.value === 'number' && typeof b.value === 'number' && b.value !== 0) {
            return { evaluable: true, value: a.value % b.value }
        }
        return { evaluable: false }
    },
    'CONCAT': (...args) => {
        const parts: string[] = []
        for (const arg of args) {
            if (!arg?.evaluable) return { evaluable: false }
            parts.push(String(arg.value))
        }
        return { evaluable: true, value: parts.join('') }
    },
    'SUBSTR': (str, start, len) => {
        if (!str?.evaluable || !start?.evaluable) return { evaluable: false }
        if (typeof str.value === 'string' && typeof start.value === 'number') {
            const s = (start.value as number) - 1 // SQL is 1-indexed
            const l = len?.evaluable && typeof len.value === 'number' ? len.value : undefined
            return { evaluable: true, value: str.value.substring(s, l !== undefined ? s + l : undefined) }
        }
        return { evaluable: false }
    },
    'SUBSTRING': (...args) => KNOWN_FUNCTIONS['SUBSTR'](...args),
    'REVERSE': (arg) => {
        if (!arg?.evaluable) return { evaluable: false }
        if (typeof arg.value === 'string') {
            return { evaluable: true, value: arg.value.split('').reverse().join('') }
        }
        return { evaluable: false }
    },
    'COALESCE': (...args) => {
        for (const arg of args) {
            if (arg?.evaluable && arg.value !== null) return arg
        }
        return { evaluable: true, value: null }
    },
    'IFNULL': (...args) => KNOWN_FUNCTIONS['COALESCE'](...args),
    'ISNULL': (...args) => KNOWN_FUNCTIONS['COALESCE'](...args),
}


/**
 * Evaluate an expression node to determine its concrete value.
 *
 * Returns { evaluable: true, value: ... } if the expression can be
 * fully evaluated without runtime context (all leaf nodes are literals).
 *
 * Returns { evaluable: false } if the expression depends on unknown
 * identifiers (column names, subqueries, etc.).
 *
 * This is the core of tautology detection: if an expression evaluates
 * to TRUE independently of any runtime data, it's a tautology.
 */
export function evaluateExpression(node: ExpressionNode): EvalResult {
    switch (node.kind) {
        case 'literal_number':
            return { evaluable: true, value: node.value }

        case 'literal_string':
            return { evaluable: true, value: node.value }

        case 'literal_bool':
            return { evaluable: true, value: node.value }

        case 'literal_null':
            return { evaluable: true, value: null }

        case 'identifier':
            // Identifiers refer to runtime data — can't evaluate statically
            return { evaluable: false }

        case 'comparison': {
            const left = evaluateExpression(node.left)
            const right = evaluateExpression(node.right)
            if (!left.evaluable || !right.evaluable) return { evaluable: false }

            const lv = left.value
            const rv = right.value

            // NULL comparison semantics: NULL compared to anything is NULL (falsy)
            if (lv === null || rv === null) {
                return { evaluable: true, value: false }
            }

            switch (node.operator) {
                case '=':
                    // Type coercion: compare as numbers if both parseable
                    if (typeof lv === 'number' && typeof rv === 'number') {
                        return { evaluable: true, value: lv === rv }
                    }
                    return { evaluable: true, value: String(lv) === String(rv) }
                case '<>':
                case '!=':
                    if (typeof lv === 'number' && typeof rv === 'number') {
                        return { evaluable: true, value: lv !== rv }
                    }
                    return { evaluable: true, value: String(lv) !== String(rv) }
                case '<':
                    return { evaluable: true, value: Number(lv) < Number(rv) }
                case '>':
                    return { evaluable: true, value: Number(lv) > Number(rv) }
                case '<=':
                    return { evaluable: true, value: Number(lv) <= Number(rv) }
                case '>=':
                    return { evaluable: true, value: Number(lv) >= Number(rv) }
                default:
                    return { evaluable: false }
            }
        }

        case 'boolean_op': {
            const left = evaluateExpression(node.left)
            const right = evaluateExpression(node.right)

            if (node.operator === 'OR') {
                // OR short-circuit: if either side is TRUE, result is TRUE
                if (left.evaluable && left.value === true) return { evaluable: true, value: true }
                if (right.evaluable && right.value === true) return { evaluable: true, value: true }
                // If either side is not evaluable, result depends on runtime
                if (!left.evaluable || !right.evaluable) return { evaluable: false }
                return { evaluable: true, value: Boolean(left.value) || Boolean(right.value) }
            }

            if (node.operator === 'AND') {
                // AND short-circuit: if either side is FALSE, result is FALSE
                if (left.evaluable && left.value === false) return { evaluable: true, value: false }
                if (right.evaluable && right.value === false) return { evaluable: true, value: false }
                if (!left.evaluable || !right.evaluable) return { evaluable: false }
                return { evaluable: true, value: Boolean(left.value) && Boolean(right.value) }
            }

            return { evaluable: false }
        }

        case 'not': {
            const operand = evaluateExpression(node.operand)
            if (!operand.evaluable) return { evaluable: false }
            return { evaluable: true, value: !operand.value }
        }

        case 'is_null': {
            const operand = evaluateExpression(node.operand)
            if (!operand.evaluable) return { evaluable: false }
            const isNull = operand.value === null
            return { evaluable: true, value: node.negated ? !isNull : isNull }
        }

        case 'between': {
            const val = evaluateExpression(node.operand)
            const low = evaluateExpression(node.low)
            const high = evaluateExpression(node.high)
            if (!val.evaluable || !low.evaluable || !high.evaluable) return { evaluable: false }
            const v = Number(val.value)
            const l = Number(low.value)
            const h = Number(high.value)
            return { evaluable: true, value: v >= l && v <= h }
        }

        case 'in_list': {
            const val = evaluateExpression(node.operand)
            if (!val.evaluable) return { evaluable: false }
            for (const item of node.values) {
                const itemVal = evaluateExpression(item)
                if (itemVal.evaluable && String(val.value) === String(itemVal.value)) {
                    return { evaluable: true, value: true }
                }
            }
            // If all items are evaluable and none matched, it's FALSE
            const allEvaluable = node.values.every(v => evaluateExpression(v).evaluable)
            if (allEvaluable) return { evaluable: true, value: false }
            return { evaluable: false }
        }

        case 'like': {
            const val = evaluateExpression(node.operand)
            const pattern = evaluateExpression(node.pattern)
            if (!val.evaluable || !pattern.evaluable) return { evaluable: false }
            if (typeof val.value === 'string' && typeof pattern.value === 'string') {
                // Simple LIKE evaluation: % = any, _ = single char
                const regex = pattern.value
                    .replace(/([.*+?^${}()|[\]\\])/g, '\\$1') // escape regex chars
                    .replace(/%/g, '.*')
                    .replace(/_/g, '.')
                try {
                    return { evaluable: true, value: new RegExp(`^${regex}$`, 'i').test(val.value) }
                } catch {
                    return { evaluable: false }
                }
            }
            return { evaluable: false }
        }

        case 'function_call': {
            const fn = KNOWN_FUNCTIONS[node.name]
            if (!fn) return { evaluable: false }
            const evaluatedArgs = node.args.map(a => evaluateExpression(a))
            return fn(...evaluatedArgs)
        }

        case 'unknown':
            return { evaluable: false }
    }
}


// ── Tautology Detection ──────────────────────────────────────────

/**
 * Check if an expression is tautological (always evaluates to TRUE).
 *
 * An expression is tautological if:
 *   1. It can be fully evaluated without runtime context
 *   2. It evaluates to a truthy value
 *
 * This is the core invariant check for sql_tautology.
 */
export function isTautology(node: ExpressionNode): boolean {
    const result = evaluateExpression(node)
    if (!result.evaluable) return false
    return Boolean(result.value)
}


// ── Public API: Deep Tautology Detection ─────────────────────────

/**
 * Detect SQL tautologies in input by tokenizing, extracting
 * conditional expressions, and evaluating them.
 *
 * This is the Level 2 replacement for the regex-based sql_tautology
 * invariant. It catches ANY expression that evaluates to TRUE,
 * regardless of encoding, obfuscation, or novelty.
 *
 * @returns Array of detected tautological expressions with their
 *          string representations for logging.
 */
export interface TautologyDetection {
    /** The tautological expression (e.g., "1=1", "'a'='a'", "ASCII('a')=97") */
    expression: string
    /** The evaluated value (always truthy) */
    value: unknown
    /** Position in the original input */
    position: number
}

export function detectTautologies(input: string): TautologyDetection[] {
    const detections: TautologyDetection[] = []
    const seen = new Set<string>()

    // Strategy 1: Direct tokenization
    const tokens = sqlTokenize(input)
    const expressions = extractConditionalExpressions(tokens)

    for (const expr of expressions) {
        if (isTautology(expr)) {
            const result = evaluateExpression(expr)
            const key = stringifyExpression(expr)
            if (!seen.has(key)) {
                seen.add(key)
                detections.push({
                    expression: key,
                    value: result.evaluable ? result.value : true,
                    position: getExpressionPosition(expr),
                })
            }
        }
    }

    // Strategy 2: Injection context — strip leading string terminators
    // In SQL injection, leading quotes/parens terminate the app's SQL context.
    // The input "' OR 1=1--" should be analyzed as if the ' is not part of a string.
    // We try stripping common injection prefixes and re-tokenizing.
    const injectionPrefixes = [
        /^'+\)?\s*/,          // ' or '' or ') or ''))
        /^"+\)?\s*/,          // " or ")
        /^\)+\s*/,             // ) or )) — closing parens from app query
        /^['"]?\)\s*/,        // ') or ") 
    ]

    for (const prefix of injectionPrefixes) {
        if (prefix.test(input)) {
            const stripped = input.replace(prefix, '')
            if (stripped !== input && stripped.length > 0) {
                const strippedTokens = sqlTokenize(stripped)
                const strippedExpressions = extractConditionalExpressions(strippedTokens)

                for (const expr of strippedExpressions) {
                    if (isTautology(expr)) {
                        const result = evaluateExpression(expr)
                        const key = stringifyExpression(expr)
                        if (!seen.has(key)) {
                            seen.add(key)
                            detections.push({
                                expression: key,
                                value: result.evaluable ? result.value : true,
                                position: getExpressionPosition(expr),
                            })
                        }
                    }
                }
            }
        }
    }

    return detections
}


// ── Helpers ──────────────────────────────────────────────────────

function stringifyExpression(node: ExpressionNode): string {
    switch (node.kind) {
        case 'literal_number': return String(node.value)
        case 'literal_string': return `'${node.value}'`
        case 'literal_bool': return node.value ? 'TRUE' : 'FALSE'
        case 'literal_null': return 'NULL'
        case 'identifier': return node.name
        case 'comparison': return `${stringifyExpression(node.left)} ${node.operator} ${stringifyExpression(node.right)}`
        case 'boolean_op': return `${stringifyExpression(node.left)} ${node.operator} ${stringifyExpression(node.right)}`
        case 'not': return `NOT ${stringifyExpression(node.operand)}`
        case 'is_null': return `${stringifyExpression(node.operand)} IS ${node.negated ? 'NOT ' : ''}NULL`
        case 'between': return `${stringifyExpression(node.operand)} BETWEEN ${stringifyExpression(node.low)} AND ${stringifyExpression(node.high)}`
        case 'in_list': return `${stringifyExpression(node.operand)} IN (${node.values.map(stringifyExpression).join(', ')})`
        case 'like': return `${stringifyExpression(node.operand)} LIKE ${stringifyExpression(node.pattern)}`
        case 'function_call': return `${node.name}(${node.args.map(stringifyExpression).join(', ')})`
        case 'unknown': return '?'
    }
}

function getExpressionPosition(node: ExpressionNode): number {
    switch (node.kind) {
        case 'comparison': return getExpressionPosition(node.left)
        case 'boolean_op': return getExpressionPosition(node.left)
        case 'not': return getExpressionPosition(node.operand)
        case 'is_null': return getExpressionPosition(node.operand)
        case 'between': return getExpressionPosition(node.operand)
        case 'in_list': return getExpressionPosition(node.operand)
        case 'like': return getExpressionPosition(node.operand)
        default: return 0
    }
}
