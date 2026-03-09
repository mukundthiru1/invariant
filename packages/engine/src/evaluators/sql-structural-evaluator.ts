/**
 * SQL Structural Evaluator — Level 2 Detection for ALL SQL Invariant Classes
 *
 * The sql-expression-evaluator handles sql_tautology (expression evaluation).
 * This module handles the remaining 6 SQL invariant classes via tokenization-
 * based structural analysis:
 *
 *   - sql_string_termination:  quote closed + SQL keyword follows
 *   - sql_union_extraction:    UNION keyword after context break
 *   - sql_stacked_execution:   semicolon + new DML/DDL statement
 *   - sql_time_oracle:         time-delaying function call
 *   - sql_error_oracle:        error-triggering function call
 *   - sql_comment_truncation:  comment syntax after injection context
 *
 * Each of these operates on the SQL token stream (reusing sqlTokenize from
 * sql-expression-evaluator.ts), not regex. The properties are structural:
 * we check for TOKEN SEQUENCES, not character patterns.
 */

import { sqlTokenize, type SqlToken } from './sql-expression-evaluator.js'


// ── Result Type ──────────────────────────────────────────────────

export interface SqlStructuralDetection {
    type:
    | 'string_termination'
    | 'union_extraction'
    | 'stacked_execution'
    | 'time_oracle'
    | 'time_based_blind'
    | 'error_oracle'
    | 'comment_truncation'
    detail: string
    position: number
    confidence: number
}


// ── String Termination ───────────────────────────────────────────
//
// Property: quote_closed ∧ sql_keyword_follows
//
// In SQL injection, the attacker closes the application's string
// context (with ' or ") and then injects SQL keywords. The invariant
// property is: "a string literal is terminated AND a SQL keyword
// appears immediately after."
//
// Token analysis is superior to regex because:
//   - We correctly handle escaped quotes ('')
//   - We identify SQL keywords as tokens, not substrings
//   - We don't false-positive on words like "reunion" containing "UNION"

const SQL_INJECTION_KEYWORDS = new Set([
    'OR', 'AND', 'UNION', 'SELECT', 'INSERT', 'UPDATE', 'DELETE',
    'DROP', 'EXEC', 'EXECUTE', 'CREATE', 'ALTER', 'HAVING', 'WHERE',
    'ORDER', 'GROUP', 'GRANT', 'REVOKE', 'TRUNCATE',
])

function detectStringTermination(tokens: SqlToken[], rawInput?: string): SqlStructuralDetection[] {
    const detections: SqlStructuralDetection[] = []
    const meaningful = tokens.filter(t => t.type !== 'WHITESPACE')

    // Strategy 1: standard token sequence — STRING followed by SQL keyword
    for (let i = 0; i < meaningful.length - 1; i++) {
        const current = meaningful[i]
        const next = meaningful[i + 1]

        if (current.type === 'STRING') {
            if (
                next.type === 'BOOLEAN_OP' ||
                next.type === 'KEYWORD' ||
                next.type === 'SEPARATOR'
            ) {
                const followingKw = next.value
                detections.push({
                    type: 'string_termination',
                    detail: `String literal terminated, followed by SQL ${next.type}: '${followingKw}'`,
                    position: current.position,
                    confidence: 0.75,
                })
            }
        }
    }

    // Strategy 2: injection prefix detection on raw input.
    // When input starts with a quote character, the SQL tokenizer treats
    // the entire input as a single STRING literal (consuming the quote
    // as the opening delimiter). We detect this by checking the raw
    // input: if it starts with ' or " followed by SQL keywords, the
    // quote is a string TERMINATOR (closing the app's query), not an opener.
    if (rawInput) {
        const trimmed = rawInput.trimStart()
        const quoteMatch = trimmed.match(/^(['"`])(\)?\s*)(.+)/)
        if (quoteMatch) {
            const rest = quoteMatch[3]
            const restTokens = sqlTokenize(rest)
            const restMeaningful = restTokens.filter((t: SqlToken) => t.type !== 'WHITESPACE')
            if (restMeaningful.length > 0) {
                const first = restMeaningful[0]
                if (
                    first.type === 'BOOLEAN_OP' ||
                    (first.type === 'KEYWORD' && SQL_INJECTION_KEYWORDS.has(first.value)) ||
                    first.type === 'SEPARATOR'
                ) {
                    detections.push({
                        type: 'string_termination',
                        detail: `Injection prefix: quote terminator followed by ${first.value}`,
                        position: 0,
                        confidence: 0.78,
                    })
                }
            }
        }
    }

    return detections
}


// ── Injection Context Detection ──────────────────────────────────
//
// Many SQL classes require understanding that the input starts
// in injection context: a leading quote terminates the app's SQL
// string, and the rest is injected SQL.
//
// We strip common injection prefixes and re-tokenize.

const INJECTION_PREFIXES = [
    /^'+\)?\s*/,         // ' or '' or ') or ''))
    /^"+\)?\s*/,         // " or ")
    /^\)+\s*/,           // ) or ))
    /^['"]?\)\s*/,       // ') or ")
]

function stripInjectionPrefix(input: string): string[] {
    const variants = [input]
    for (const prefix of INJECTION_PREFIXES) {
        if (prefix.test(input)) {
            const stripped = input.replace(prefix, '')
            if (stripped !== input && stripped.length > 0) {
                variants.push(stripped)
            }
        }
    }
    return variants
}


// ── UNION Extraction ─────────────────────────────────────────────
//
// Property: ∃ UNION token ∧ SELECT token follows
//
// The attacker appends UNION SELECT to extract data from other
// tables. The invariant: UNION and SELECT appear as SQL keywords
// (tokens), not as substrings of identifiers.
//
// This catches:
//   - ' UNION SELECT username, password FROM users--
//   - ' UNION ALL SELECT NULL, table_name FROM information_schema.tables--
//   - ') UNION SELECT 1,2,3--
//
// This correctly ignores:
//   - "family reunion selected" (UNION is inside "reunion", SELECT inside "selected")
//   - "union_type" (identifier, not keyword)

function detectUnionExtraction(tokens: SqlToken[]): SqlStructuralDetection[] {
    const detections: SqlStructuralDetection[] = []
    // Filter whitespace AND SQL comments (/**/ used to obfuscate)
    const meaningful = tokens.filter(t =>
        t.type !== 'WHITESPACE' &&
        !(t.type === 'SEPARATOR' && t.value.startsWith('/*') && t.value.endsWith('*/'))
    )

    for (let i = 0; i < meaningful.length; i++) {
        const token = meaningful[i]

        if (token.type === 'KEYWORD' && token.value === 'UNION') {
            // Look for SELECT after UNION (possibly with ALL between)
            let j = i + 1
            if (j < meaningful.length && meaningful[j].type === 'KEYWORD' && meaningful[j].value === 'ALL') {
                j++
            }
            if (j < meaningful.length && meaningful[j].type === 'KEYWORD' && meaningful[j].value === 'SELECT') {
                detections.push({
                    type: 'union_extraction',
                    detail: `UNION SELECT detected as SQL keyword tokens (not substring match)`,
                    position: token.position,
                    confidence: 0.92,
                })
            }
        }
    }

    return detections
}


// ── Stacked Execution ────────────────────────────────────────────
//
// Property: ∃ SEPARATOR(;) token ∧ DML/DDL keyword follows
//
// The attacker terminates the current statement and starts a new
// one. The invariant: a semicolon separator token is followed by
// a statement-starting keyword (SELECT, INSERT, UPDATE, DELETE,
// DROP, CREATE, ALTER, EXEC).

const STATEMENT_STARTERS = new Set([
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
    'ALTER', 'EXEC', 'EXECUTE', 'GRANT', 'REVOKE', 'TRUNCATE',
])

function detectStackedExecution(tokens: SqlToken[]): SqlStructuralDetection[] {
    const detections: SqlStructuralDetection[] = []
    const meaningful = tokens.filter(t => t.type !== 'WHITESPACE')

    for (let i = 0; i < meaningful.length - 1; i++) {
        const current = meaningful[i]

        if (current.type === 'SEPARATOR' && current.value === ';') {
            // Look for a statement-starting keyword after the semicolon
            const next = meaningful[i + 1]
            if (next && next.type === 'KEYWORD' && STATEMENT_STARTERS.has(next.value)) {
                detections.push({
                    type: 'stacked_execution',
                    detail: `Statement separator (;) followed by ${next.value} — stacked query execution`,
                    position: current.position,
                    confidence: 0.90,
                })
            }
        }
    }

    return detections
}


// ── Time Oracle ──────────────────────────────────────────────────
//
// Property: ∃ function_call(name ∈ TIME_DELAY_FUNCTIONS, args)
//
// The attacker calls a time-delaying function to infer boolean
// conditions from response timing. The invariant: a function call
// token with a known time-delay function name.

const TIME_DELAY_FUNCTIONS = new Set([
    'SLEEP', 'WAITFOR', 'PG_SLEEP', 'DBMS_LOCK.SLEEP',
    'BENCHMARK', 'DELAY',
])

function detectTimeOracle(tokens: SqlToken[]): SqlStructuralDetection[] {
    const detections: SqlStructuralDetection[] = []
    const meaningful = tokens.filter(t => t.type !== 'WHITESPACE')

    for (let i = 0; i < meaningful.length; i++) {
        const token = meaningful[i]

        // Direct function call: SLEEP(5)
        if (
            (token.type === 'IDENTIFIER' || token.type === 'KEYWORD') &&
            TIME_DELAY_FUNCTIONS.has(token.value.toUpperCase())
        ) {
            if (i + 1 < meaningful.length && meaningful[i + 1].type === 'PAREN_OPEN') {
                detections.push({
                    type: 'time_oracle',
                    detail: `Time-delay function call: ${token.value}()`,
                    position: token.position,
                    confidence: 0.90,
                })
            }
        }

        // WAITFOR DELAY pattern (T-SQL): WAITFOR DELAY '0:0:5'
        // WAITFOR may tokenize as KEYWORD or IDENTIFIER depending on
        // whether it's in the SQL_KEYWORDS set. DELAY is always IDENTIFIER.
        if (
            (token.type === 'KEYWORD' || token.type === 'IDENTIFIER') &&
            token.value.toUpperCase() === 'WAITFOR' &&
            i + 1 < meaningful.length &&
            (meaningful[i + 1].type === 'IDENTIFIER' || meaningful[i + 1].type === 'KEYWORD') &&
            meaningful[i + 1].value.toUpperCase() === 'DELAY'
        ) {
            detections.push({
                type: 'time_oracle',
                detail: `WAITFOR DELAY — time-based blind SQL injection`,
                position: token.position,
                confidence: 0.92,
            })
        }

        // BENCHMARK function (MySQL): BENCHMARK(10000000, SHA1('test'))
        if (
            (token.type === 'IDENTIFIER' || token.type === 'KEYWORD') &&
            token.value.toUpperCase() === 'BENCHMARK'
        ) {
            if (i + 1 < meaningful.length && meaningful[i + 1].type === 'PAREN_OPEN') {
                // Check for a large numeric argument (indicative of DoS/timing)
                if (i + 2 < meaningful.length && meaningful[i + 2].type === 'NUMBER') {
                    const val = parseFloat(meaningful[i + 2].value)
                    if (val > 100000) {
                        detections.push({
                            type: 'time_oracle',
                            detail: `BENCHMARK with high iteration count: ${val}`,
                            position: token.position,
                            confidence: 0.92,
                        })
                    }
                }
            }
        }
    }

    return detections
}


// ── Error Oracle ─────────────────────────────────────────────────
//
// Property: ∃ function_call(name ∈ ERROR_FUNCTIONS)
//     ∨ deliberate type-error construction
//
// The attacker calls functions that trigger verbose error messages
// containing data. The invariant: function calls to known
// error-triggering functions.

// Only functions that are used exclusively for error-based extraction.
// CONVERT and CAST are excluded — they are common legitimate SQL functions
// and would create unacceptable false positive rates.
const ERROR_FUNCTIONS = new Set([
    'EXTRACTVALUE', 'UPDATEXML', 'XMLTYPE', 'DBMS_XMLGEN',
    'UTL_INADDR', 'CTXSYS',
])

function detectErrorOracle(tokens: SqlToken[]): SqlStructuralDetection[] {
    const detections: SqlStructuralDetection[] = []
    const meaningful = tokens.filter(t => t.type !== 'WHITESPACE')

    for (let i = 0; i < meaningful.length; i++) {
        const token = meaningful[i]

        if (
            (token.type === 'IDENTIFIER' || token.type === 'KEYWORD') &&
            ERROR_FUNCTIONS.has(token.value.toUpperCase())
        ) {
            if (i + 1 < meaningful.length && meaningful[i + 1].type === 'PAREN_OPEN') {
                // Check if the function contains a subquery (SELECT inside)
                let depth = 0
                let hasSubquery = false
                for (let j = i + 1; j < meaningful.length; j++) {
                    if (meaningful[j].type === 'PAREN_OPEN') depth++
                    if (meaningful[j].type === 'PAREN_CLOSE') depth--
                    if (meaningful[j].type === 'KEYWORD' && meaningful[j].value === 'SELECT') {
                        hasSubquery = true
                    }
                    if (depth === 0) break
                }

                detections.push({
                    type: 'error_oracle',
                    detail: `Error-based extraction function: ${token.value}()${hasSubquery ? ' with embedded SELECT' : ''}`,
                    position: token.position,
                    confidence: hasSubquery ? 0.92 : 0.80,
                })
            }
        }
    }

    return detections
}


// ── Comment Truncation ───────────────────────────────────────────
//
// Property: ∃ SEPARATOR(-- | # | /*) token, AND tokens before
//           it include injection-relevant context (quote, keyword)
//
// The attacker uses a comment to truncate the rest of the
// application's SQL query. The invariant: a comment separator
// appears after injection context (string termination, boolean
// operator, keyword).

function detectCommentTruncation(tokens: SqlToken[]): SqlStructuralDetection[] {
    const detections: SqlStructuralDetection[] = []
    const meaningful = tokens.filter(t => t.type !== 'WHITESPACE')

    for (let i = 0; i < meaningful.length; i++) {
        const token = meaningful[i]

        if (token.type === 'SEPARATOR' && (token.value.startsWith('--') || token.value === '#')) {
            // Check if tokens before the comment include injection context.
            // OPERATOR alone is too loose ("1=1--" where = is just assignment).
            // Require actual injection indicators.
            const hasPriorInjectionContext = meaningful.slice(0, i).some(t =>
                t.type === 'BOOLEAN_OP' ||
                (t.type === 'KEYWORD' && STATEMENT_STARTERS.has(t.value)) ||
                (t.type === 'KEYWORD' && t.value === 'UNION') ||
                (t.type === 'KEYWORD' && t.value === 'HAVING') ||
                (t.type === 'KEYWORD' && t.value === 'ORDER')
            )

            if (hasPriorInjectionContext) {
                detections.push({
                    type: 'comment_truncation',
                    detail: `SQL comment (${token.value.slice(0, 2)}) after injection context — truncates remaining query`,
                    position: token.position,
                    confidence: 0.82,
                })
            }
        }
    }

    return detections
}


// ── Time-based blind (regex) ───────────────────────────────────────
//
// Fast regex checks for time-delay SQL primitives before tokenization.
// Complements token-based detectTimeOracle for payloads like SLEEP(5), WAITFOR DELAY 0:0:5.
const TIME_BASED_BLIND_PATTERNS = [
    /\bsleep\s*\(\s*\d+(?:\.\d+)?\s*\)/i,
    /\bbenchmark\s*\(\s*\d+\s*,/i,
    /\bpg_sleep\s*\(\s*\d+(?:\.\d+)?\s*\)/i,
    /\bpg_sleep_for\b/i,
    /\bwaitfor\s+delay\b/i,
    /\bwaitfor\s+time\b/i,
] as const
const PG_DOLLAR_QUOTE_RE = /\$\$[^\$]*(?:select|union|insert|drop|exec)[^\$]*\$\$/i
const PG_TAGGED_DOLLAR_QUOTE_RE = /\$\w*\$[^\$]*(?:select|union|insert)[^\$]*\$\w*\$/i
const BRACE_EXPANSION_SQL_RE = /\{[A-Za-z,]+SELECT[A-Za-z,]*\}|\$\{IFS\}[A-Za-z]/i

function classifyBypassDetection(match: string): SqlStructuralDetection['type'] {
    if (/(?:select|union)/i.test(match)) return 'union_extraction'
    if (/(?:insert|drop|exec)/i.test(match)) return 'stacked_execution'
    return 'string_termination'
}

function detectSqlBypassObfuscation(input: string): SqlStructuralDetection[] {
    const detections: SqlStructuralDetection[] = []
    const regexes = [PG_DOLLAR_QUOTE_RE, PG_TAGGED_DOLLAR_QUOTE_RE, BRACE_EXPANSION_SQL_RE]

    for (const re of regexes) {
        const match = input.match(re)
        if (!match) continue
        detections.push({
            type: classifyBypassDetection(match[0]),
            detail: `SQL bypass obfuscation pattern detected: ${match[0]}`,
            position: input.search(re),
            confidence: 0.90,
        })
    }

    return detections
}

export function detectTimeBasedBlind(decoded: string): { type: 'time_based_blind'; confidence: number; evidence: string } | null {
    const match = findTimeBasedBlindMatch(decoded)
    if (!match) return null
    return {
        type: 'time_based_blind',
        confidence: 0.88,
        evidence: match[0],
    }
}

function findTimeBasedBlindMatch(input: string): RegExpMatchArray | null {
    for (const pattern of TIME_BASED_BLIND_PATTERNS) {
        const match = input.match(pattern)
        if (match) return match
    }
    return null
}

export function detectTimeBasedBlindSqli(input: string): boolean {
    return findTimeBasedBlindMatch(input) !== null
}

// ── Public API ───────────────────────────────────────────────────

/**
 * Run all SQL structural evaluators on input.
 * Handles injection context by stripping common prefixes.
 *
 * Returns the union of all detections across all variants.
 */
export function detectSqlStructural(input: string): SqlStructuralDetection[] {
    const allDetections: SqlStructuralDetection[] = []
    const seen = new Set<string>()
    const hasTimeBasedBlindSqli = detectTimeBasedBlindSqli(input)

    const bypassDetections = detectSqlBypassObfuscation(input)
    for (const detection of bypassDetections) {
        const key = `${detection.type}:${detection.detail}`
        if (!seen.has(key)) {
            seen.add(key)
            allDetections.push(detection)
        }
    }

    const timeBasedBlind = detectTimeBasedBlind(input)
    if (timeBasedBlind) {
        const key = `time_based_blind:${timeBasedBlind.evidence}`
        if (!seen.has(key)) {
            seen.add(key)
            allDetections.push({
                type: 'time_based_blind',
                detail: timeBasedBlind.evidence,
                position: Math.max(0, input.toLowerCase().indexOf(timeBasedBlind.evidence.toLowerCase())),
                confidence: Math.max(0.85, timeBasedBlind.confidence),
            })
        }
    }

    for (const variant of stripInjectionPrefix(input)) {
        const tokens = sqlTokenize(variant)

        // String termination needs raw input for injection prefix analysis
        try {
            const stDetections = detectStringTermination(tokens, variant)
            for (const d of stDetections) {
                const key = `${d.type}:${d.detail}`
                if (!seen.has(key)) {
                    seen.add(key)
                    allDetections.push(d)
                }
            }
        } catch { /* never crash */ }

        // All other detectors only need tokens
        const detectorFns: Array<(tokens: SqlToken[]) => SqlStructuralDetection[]> = [
            detectUnionExtraction,
            detectStackedExecution,
            detectTimeOracle,
            detectErrorOracle,
            detectCommentTruncation,
        ]

        for (const detector of detectorFns) {
            try {
                const detections = detector(tokens)
                for (const d of detections) {
                    // Dedup across variants using type + detail
                    const key = `${d.type}:${d.detail}`
                    if (!seen.has(key)) {
                        seen.add(key)
                        allDetections.push(d)
                    }
                }
            } catch { /* never let L2 crash the pipeline */ }
        }
    }

    if (hasTimeBasedBlindSqli) {
        for (const detection of allDetections) {
            if (detection.type === 'time_oracle' || detection.type === 'time_based_blind') {
                detection.confidence = Math.max(0.85, detection.confidence)
            }
        }
    }

    return allDetections
}
