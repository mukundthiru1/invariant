/**
 * json_sql_bypass — JSON-in-SQL WAF bypass technique
 *
 * Research: Claroty Team82 (December 2022), patched across 5 major WAFs
 * but the technique is transferable to any WAF that doesn't parse JSON
 * operators in SQL context.
 *
 * INVARIANT PROPERTY:
 *   ∃ subexpr ∈ parse(input, SQL_GRAMMAR) :
 *     subexpr CONTAINS json_function(json_literal, json_path)
 *     ∧ eval(json_function, json_literal, json_path) ∈ KNOWN_VALUES
 *     ∧ context(subexpr) ∈ {CONDITIONAL, WHERE_CLAUSE}
 *     → tautology via JSON function evaluation
 *
 * Why this matters: Modern database engines (PostgreSQL 9.2+, MySQL 5.7.8+,
 * SQLite 3.38+, MSSQL 2016+) support JSON operators in SQL. Attackers
 * use JSON functions to construct tautologies that WAFs don't recognize
 * because their SQL parsers predate JSON support.
 *
 * Examples:
 *   ' OR JSON_EXTRACT('{"a":1}', '$.a') = 1 --      → 1=1 → TRUE
 *   ' OR json_type('{"a":true}', '$.a') = 'true' --  → matches → TRUE
 *   ' OR '{"k":"v"}'::jsonb @> '{"k":"v"}'::jsonb -- → contains → TRUE
 *   ' UNION SELECT * FROM users WHERE 1=json_valid('{}') --
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'


// ── JSON SQL Functions by Database ──────────────────────────────

/**
 * Known JSON functions across major database engines.
 * Organized by what they return for tautology analysis.
 */
const JSON_FUNCTIONS_BOOLEAN = new Set([
    // MySQL / MariaDB
    'json_contains', 'json_overlaps', 'json_contains_path',
    // PostgreSQL
    'jsonb_exists', 'jsonb_exists_any', 'jsonb_exists_all',
    // SQLite
    'json_valid', 'json_type',
    // Generic
    'isjson',
])

const JSON_FUNCTIONS_VALUE = new Set([
    // MySQL / MariaDB
    'json_extract', 'json_value', 'json_unquote', 'json_length',
    'json_depth', 'json_keys', 'json_search',
    // PostgreSQL  
    'json_extract_path', 'json_extract_path_text',
    'jsonb_extract_path', 'jsonb_extract_path_text',
    // SQLite
    'json_extract', 'json_array_length',
    // SQL Server
    'json_value', 'json_query', 'openjson',
])

const JSON_OPERATORS = new Set([
    '->', '->>', '#>', '#>>', '@>', '<@', '?', '?|', '?&',
    'json_set', 'json_insert', 'json_replace', 'json_remove',
])

const ALL_JSON_FUNCTIONS = new Set([...JSON_FUNCTIONS_BOOLEAN, ...JSON_FUNCTIONS_VALUE])

// Build a regex from the function names for L1 detection
const JSON_FUNC_PATTERN = new RegExp(
    `(?:${[...ALL_JSON_FUNCTIONS].join('|')})\\s*\\(`,
    'i',
)

// PostgreSQL JSON operators: ->, ->>, @>, <@, ?|, ?&, etc.
// NOTE: bare '?' is intentionally excluded — it appears in URL query strings
// (?page=1&...) and produces massive false positive rates on web traffic.
// The unambiguous multi-character forms (?|, ?&) are kept.
const PG_JSON_OP_PATTERN = /(?:::jsonb?|->>{0,1}|#>{1,2}|@>|<@|\?\||\?&)/i

// JSON literal in SQL context (indicates JSON-in-SQL technique)
const JSON_LITERAL_IN_SQL = /['"]?\{[^}]*\}['"]?\s*(?:::jsonb?|->|,\s*'?\$)/


// ── L1: Pattern Detection ────────────────────────────────────────

function detectL1(input: string): boolean {
    const d = deepDecode(input)
    const lower = d.toLowerCase()

    // Quick bail — no JSON function or operator present
    if (!JSON_FUNC_PATTERN.test(d) && !PG_JSON_OP_PATTERN.test(d)) return false

    // JSON function in a conditional context (OR/AND/WHERE/HAVING)
    if (/(?:OR|AND|WHERE|HAVING)\s+/i.test(d) && JSON_FUNC_PATTERN.test(d)) return true

    // PostgreSQL JSON operator with comparison
    if (PG_JSON_OP_PATTERN.test(d) && /(?:=|<>|!=|IS\s|LIKE|IN\s*\()/i.test(d)) return true

    // JSON literal being cast and compared
    if (JSON_LITERAL_IN_SQL.test(d) && /(?:=|@>|<@)/i.test(d)) return true

    // JSON function result compared to a literal
    if (JSON_FUNC_PATTERN.test(d) && /\)\s*(?:=|!=|<>|>|<|>=|<=|IS|LIKE|IN)\s/i.test(d)) return true

    return false
}


// ── L2: Structural Analysis ─────────────────────────────────────

function detectL2(input: string): DetectionLevelResult | null {
    const d = deepDecode(input)

    // Extract JSON function calls with their arguments
    const funcCallPattern = new RegExp(
        `(${[...ALL_JSON_FUNCTIONS].join('|')})\\s*\\(([^)]+)\\)`,
        'gi',
    )

    let match
    const jsonCalls: Array<{ func: string; args: string; full: string }> = []

    while ((match = funcCallPattern.exec(d)) !== null) {
        jsonCalls.push({
            func: match[1].toLowerCase(),
            args: match[2],
            full: match[0],
        })
    }

    if (jsonCalls.length === 0) {
        // Check for PostgreSQL JSON operators
        if (PG_JSON_OP_PATTERN.test(d) && JSON_LITERAL_IN_SQL.test(d)) {
            return {
                detected: true,
                confidence: 0.85,
                explanation: 'PostgreSQL JSON operator with JSON literal in SQL context — JSON-SQL WAF bypass technique',
                evidence: d.substring(0, 200),
            }
        }
        return null
    }

    // Check if any JSON function is used in a conditional context
    for (const call of jsonCalls) {
        const callIdx = d.indexOf(call.full)
        const surrounding = d.substring(Math.max(0, callIdx - 30), Math.min(d.length, callIdx + call.full.length + 30))

        // JSON function in OR condition — likely tautology construction
        if (/\bOR\b/i.test(surrounding)) {
            // Check if comparing to a known value
            const afterFunc = d.substring(callIdx + call.full.length, callIdx + call.full.length + 50)
            if (/^\s*(?:=|!=|<>|IS)\s/i.test(afterFunc)) {
                return {
                    detected: true,
                    confidence: 0.92,
                    explanation: `JSON-SQL tautology via ${call.func}(): JSON function result compared to literal in OR clause — WAF bypass technique (Claroty Team82)`,
                    evidence: surrounding.trim(),
                }
            }
        }

        // json_valid() = 1 is always true for valid JSON
        if (call.func === 'json_valid') {
            const afterFunc = d.substring(callIdx + call.full.length, callIdx + call.full.length + 20)
            if (/^\s*(?:=\s*1|=\s*true|IS\s+NOT\s+NULL)/i.test(afterFunc)) {
                return {
                    detected: true,
                    confidence: 0.95,
                    explanation: `json_valid() with valid JSON argument always returns 1 — deterministic tautology`,
                    evidence: `${call.full}${afterFunc.substring(0, 10).trim()}`,
                }
            }
        }

        // JSON function with explicit JSON literal — indicates deliberate construction
        if (/['"]\s*\{/.test(call.args) || /['"]\s*\[/.test(call.args)) {
            return {
                detected: true,
                confidence: 0.88,
                explanation: `JSON function ${call.func}() with inline JSON literal in SQL context — characteristic of JSON-SQL WAF bypass`,
                evidence: call.full,
            }
        }
    }

    // Multiple JSON functions in one input — high confidence
    if (jsonCalls.length >= 2) {
        return {
            detected: true,
            confidence: 0.90,
            explanation: `Multiple JSON functions in SQL context (${jsonCalls.map(c => c.func).join(', ')}) — likely JSON-SQL bypass technique`,
            evidence: jsonCalls.map(c => c.full).join(' | '),
        }
    }

    return null
}


// ── Module Export ─────────────────────────────────────────────────

export const jsonSqlBypass: InvariantClassModule = {
    id: 'json_sql_bypass',
    description: 'JSON-in-SQL WAF bypass — uses database JSON operators to construct tautologies invisible to standard SQL parsers',
    category: 'sqli',
    severity: 'high',
    calibration: {
        baseConfidence: 0.88,
        environmentMultipliers: {
            'postgresql': 1.3,
            'mysql_5.7+': 1.2,
            'sqlite_3.38+': 1.2,
            'mssql_2016+': 1.2,
            'api_json': 1.1,
        },
        minInputLength: 15,
    },

    formalProperty: `∃ subexpr ∈ parse(input, SQL_EXTENDED_GRAMMAR) :
        subexpr CONTAINS json_function(json_literal, json_path)
        ∧ context(subexpr) ∈ {CONDITIONAL, WHERE, HAVING, ON}
        → eval(subexpr) ∈ {TRUE, TAUTOLOGY}
        ∨ subexpr CONTAINS jsonb_operator(json_literal, json_literal)
        ∧ operator ∈ {@>, <@, ?, ?|, ?&}
        → self-containment check → TRUE`,

    composableWith: ['sql_tautology', 'sql_union_extraction', 'sql_stacked_execution'],

    mitre: ['T1190'],
    cwe: 'CWE-89',

    knownPayloads: [
        "' OR JSON_EXTRACT('{\"a\":1}', '$.a') = 1 --",
        "' OR json_valid('{}') = 1 --",
        "' OR json_type('{\"a\":true}', '$.a') = 'true' --",
        "' UNION SELECT * FROM users WHERE 1=json_valid('{}') --",
        "' OR '{\"k\":\"v\"}'::jsonb @> '{\"k\":\"v\"}'::jsonb --",
        "' OR JSON_CONTAINS('{\"a\":1}', '1', '$.a') --",
        "' OR json_extract('{\"x\":1}','$.x')=1 OR '",
        "1' AND JSON_LENGTH('[1,2,3]') > 0 --",
    ],

    knownBenign: [
        'SELECT json_extract(data, "$.name") FROM users',
        'INSERT INTO logs VALUES (json_object("key", "value"))',
        '{"username": "admin", "password": "test"}',
        'json_valid is a function',
        'postgres jsonb documentation',
        // URL query strings with = signs — must not trigger (bare ? is excluded)
        '/api/users?page=1&limit=20',
        '/products/category/electronics?sort=price',
        '/dashboard/analytics?from=2024-01-01&to=2024-12-31',
    ],

    detect: detectL1,
    detectL2: detectL2,

    generateVariants: (count: number): string[] => {
        const templates = [
            "' OR JSON_EXTRACT('{\"a\":1}', '$.a') = 1 --",
            "' OR json_valid('{}') = 1 --",
            "' OR json_type('{\"a\":true}', '$.a') = 'true' --",
            "' OR '{\"k\":\"v\"}'::jsonb @> '{\"k\":\"v\"}'::jsonb --",
            "' OR JSON_CONTAINS('{\"a\":1}', '1', '$.a') --",
            "' OR JSON_LENGTH('[1,2,3]') > 0 --",
            "' OR json_extract('{\"x\":1}','$.x')=1 OR '",
            '1 OR ISJSON(\'{"a":1}\') = 1 --',
        ]
        // WAF-A-MoLE mutation operators
        const mutations: Array<(s: string) => string> = [
            s => s,
            s => s.replace(/ /g, '/**/'),                                      // comment substitution
            s => s.replace(/OR/gi, m => m === 'OR' ? 'oR' : 'Or'),            // case swapping
            s => s.replace(/ /g, '\t'),                                         // whitespace substitution
            s => s.replace(/1/g, '0x1'),                                       // integer encoding
            s => s.replace(/= 1/g, 'LIKE 1'),                                 // operator swapping
        ]
        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            const tpl = templates[i % templates.length]
            const mut = mutations[Math.floor(i / templates.length) % mutations.length]
            variants.push(mut(tpl))
        }
        return variants
    },
}
