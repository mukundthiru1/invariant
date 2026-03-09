/**
 * sql_tautology — Boolean tautology to bypass WHERE clauses
 *
 * Invariant property:
 *   ∃ subexpr ∈ parse(input, SQL_GRAMMAR) :
 *     eval(subexpr, BOOLEAN_CONTEXT) ≡ TRUE
 *     ∀ bindings of free variables
 *
 * L1: Regex pattern matching for common tautologies.
 * L2: Full tokenization → AST → expression evaluation.
 *     The L2 evaluator catches ARBITRARY tautologies including
 *     novel expressions that have never been seen before.
 */

import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectTautologies } from '../../evaluators/sql-expression-evaluator.js'

const TAUTOLOGY_PATTERN = /(?:^|['"`()\s])\s*(?:OR|\|\|)\s*(?:\(?['"`]?\w*['"`]?\)?\s*(?:=|LIKE|IS)\s*\(?['"`]?\w*['"`]?\)?|\d+\s*[><= ]+\s*\d+|TRUE|NOT\s+FALSE|NOT\s+0|1\b)/i
const TAUTOLOGY_BETWEEN_PATTERN = /['"`()\s]\s*(?:OR|\|\|)\s*(?:0x[0-9a-f]+|\d+)\s+BETWEEN\s+(?:0x[0-9a-f]+|\d+)\s+AND\s+(?:0x[0-9a-f]+|\d+)/i
const TAUTOLOGY_IF_PATTERN = /['"`()\s]\s*(?:OR|\|\|)\s*IF\s*\(\s*(?:1|0x1|TRUE)\s*,\s*(?:1|TRUE)\s*,\s*(?:0|FALSE)\s*\)/i
const TAUTOLOGY_ANDAND_PATTERN = /['"`()\s]\s*&&\s*(?:\d+\s*=\s*\d+|0x[0-9a-f]+\s*=\s*0x[0-9a-f]+|TRUE|NOT\s+FALSE|['"]([^'"]*)['"]\s*=\s*['"]\1['"])/i
const TAUTOLOGY_JSONB_EQUAL_PATTERN = /['"`()\s]\s*(?:OR|\|\|)\s*'[^']*'\s*::\s*jsonb\s*=\s*'[^']*'\s*::\s*jsonb/i
const TAUTOLOGY_JSON_VALID_PATTERN = /['"`()\s]\s*(?:OR|\|\|)\s*JSON_VALID\s*\(\s*['"]\[\]['"]\s*\)(?:\s*=\s*(?:1|TRUE))?/i
const TAUTOLOGY_MEMBER_OF_PATTERN = /['"`()\s]\s*(?:OR|\|\|)\s*['"][^'"]+['"]\s+MEMBER\s+OF\s*\(\s*['"]\[[^\]]+\]['"]\s*\)/i
const TAUTOLOGY_QUOTED_EQUAL_PATTERN = /['"]([^'"]*)['"]\s*=\s*['"]\1['"]/
const TAUTOLOGY_HEX_EQUAL_PATTERN = /0x[0-9a-fA-F]+\s*=\s*0x[0-9a-fA-F]+/
const TAUTOLOGY_COMMENT_OPEN_CLOSE_PATTERN = /\/\*!\d*\s*([\s\S]*?)\*\//g
const TAUTOLOGY_BLOCK_COMMENT_PATTERN = /\/\*[\s\S]*?\*\//g
const TAUTOLOGY_LINE_COMMENT_PATTERN = /--[^\n]*/g
const TAUTOLOGY_WHITESPACE_PATTERN = /\s+/g

export const sqlTautology: InvariantClassModule = {
    id: 'sql_tautology',
    description: 'Boolean tautology to bypass WHERE clause authentication/authorization checks',
    category: 'sqli',
    severity: 'high',

    formalProperty: `∃ subexpr ∈ parse(input, SQL_GRAMMAR) :
        eval(subexpr, BOOLEAN_CONTEXT) ∈ {TRUE, TAUTOLOGY}
        ∧ context(subexpr) ∈ {CONDITIONAL, WHERE_CLAUSE, HAVING_CLAUSE}`,

    composableWith: ['sql_union_extraction', 'sql_stacked_execution', 'sql_error_oracle'],

    calibration: {
        baseConfidence: 0.85,
        environmentMultipliers: {
            'login_form': 1.3,
            'search': 0.8,
            'api_json': 0.7,
        },
        falsePositivePatterns: [
            /\bx=x\b.*\bcss\b/i,
        ],
        minInputLength: 5,
    },

    mitre: ['T1190'],
    cwe: 'CWE-89',

    knownPayloads: [
        "' OR 1=1--",
        "' OR 'a'='a'--",
        "' OR 2>1--",
        "') OR ('x')=('x')",
        "' OR TRUE--",
        '" OR ""="',
        "' OR 1 LIKE 1--",
        "' OR NOT FALSE--",
        "' OR 0x1 BETWEEN 0x0 AND 0x2--",
        "' OR IF(1,1,0)--",
        "' && 1=1--",
        `' OR 'a'::jsonb = '"a"'::jsonb--`,
        "' OR JSON_VALID('[]')--",
        `' OR 'a' MEMBER OF('["a"]')--`,
    ],

    knownBenign: [
        "O'Reilly Media",
        "it's a beautiful day",
        "SELECT * FROM users",
        "the score was 1 or more",
        "hello world",
        "John's pizza OR Jane's pasta",
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // BYP-001: SQL comment injection bypass — strip comments before matching.
        // MySQL conditional comments (/*!50000OR*/) must be unwrapped first to
        // preserve the injected keyword before generic block comment removal.
        const stripSqlComments = (sql: string) => sql
            .replace(TAUTOLOGY_COMMENT_OPEN_CLOSE_PATTERN, (_, inner) => ' ' + inner + ' ')
            .replace(TAUTOLOGY_BLOCK_COMMENT_PATTERN, ' ')
            .replace(TAUTOLOGY_LINE_COMMENT_PATTERN, ' ')
            .replace(TAUTOLOGY_WHITESPACE_PATTERN, ' ').trim()
        const stripped = stripSqlComments(d)
        const match1 = TAUTOLOGY_PATTERN.test(d) || TAUTOLOGY_PATTERN.test(stripped)
        const match2 = TAUTOLOGY_QUOTED_EQUAL_PATTERN.test(d) || TAUTOLOGY_QUOTED_EQUAL_PATTERN.test(stripped)
        const match3 = TAUTOLOGY_HEX_EQUAL_PATTERN.test(d)
        const match4 = TAUTOLOGY_BETWEEN_PATTERN.test(d) || TAUTOLOGY_BETWEEN_PATTERN.test(stripped)
        const match5 = TAUTOLOGY_IF_PATTERN.test(d) || TAUTOLOGY_IF_PATTERN.test(stripped)
        const match6 = TAUTOLOGY_ANDAND_PATTERN.test(d) || TAUTOLOGY_ANDAND_PATTERN.test(stripped)
        const match7 = TAUTOLOGY_JSONB_EQUAL_PATTERN.test(d) || TAUTOLOGY_JSONB_EQUAL_PATTERN.test(stripped)
        const match8 = TAUTOLOGY_JSON_VALID_PATTERN.test(d) || TAUTOLOGY_JSON_VALID_PATTERN.test(stripped)
        const match9 = TAUTOLOGY_MEMBER_OF_PATTERN.test(d) || TAUTOLOGY_MEMBER_OF_PATTERN.test(stripped)
        return match1 || match2 || match3 || match4 || match5 || match6 || match7 || match8 || match9
    },

    /**
     * L2: Full SQL expression evaluation.
     * Tokenizes input into SQL tokens, extracts conditional subexpressions,
     * parses them into an AST, and evaluates them to determine if any
     * are tautological (evaluate to TRUE regardless of runtime data).
     *
     * This catches novel tautologies like:
     *   ' OR ASCII('a')=97--     → AST eval: 97=97 → TRUE
     *   ' OR LENGTH('abc')=3--   → AST eval: 3=3 → TRUE
     *   ' OR 0xFF=255--          → AST eval: 255=255 → TRUE
     */
    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const tautologies = detectTautologies(d)
        if (tautologies.length > 0) {
            return {
                detected: true,
                confidence: 0.92,
                explanation: `Expression evaluator: tautological expression ${tautologies[0].expression} evaluates to ${tautologies[0].value}`,
                evidence: tautologies.map(t => t.expression).join(', '),
            }
        }
        return null
    },

    generateVariants: (count: number): string[] => {
        const bases = [
            "' OR 1=1--",
            "' OR 'a'='a'--",
            "' OR 2>1--",
            "') OR ('x')=('x')",
            "' OR 1 LIKE 1--",
            "' OR TRUE--",
            "' OR NOT FALSE--",
            '" OR ""="',
            "' || 1#",
            "') OR 1=1/*",
            "' OR 1=1-- -",
            "admin'--",
            "' OR 'x' LIKE 'x'--",
            "' OR 1 IS NOT NULL--",
            "' OR 1 BETWEEN 0 AND 2--",
            "' OR 1=1;--",
        ]

        /**
         * WAF-A-MoLE semantic mutation operators (OWASP).
         *
         * Each mutation preserves the SEMANTIC MEANING of the payload
         * while varying the SYNTACTIC REPRESENTATION. This is the exact
         * set CrowdStrike / Cloudflare ML models are trained against.
         *
         * Our L2 property evaluator is IMMUNE to all of these because
         * it evaluates the mathematical expression, not the character
         * sequence. If any variant bypasses L2, the evaluator has a gap
         * and we auto-detect it through self-testing.
         */
        const mutations: Array<(s: string) => string> = [
            // Identity
            s => s,
            // 1. URL encoding
            s => encodeURIComponent(s),
            // 2. Comment substitution (SQL ignores /* */)
            s => s.replace(/ /g, '/**/'),
            // 3. URL encoding of special chars
            s => s.replace(/ /g, '%20').replace(/'/g, '%27'),
            // 4. Case swapping (SQL keywords are case-insensitive)
            s => s.replace(/OR/g, 'oR').replace(/AND/g, 'aNd').replace(/NOT/g, 'nOt')
                .replace(/TRUE/g, 'TrUe').replace(/FALSE/g, 'FaLsE')
                .replace(/LIKE/g, 'LiKe').replace(/BETWEEN/g, 'BeTwEeN'),
            // 5. Whitespace substitution (tab, newline)
            s => s.replace(/ /g, '\t'),
            // 6. Integer encoding (hex)
            s => s.replace(/\b1\b/g, '0x1').replace(/\b2\b/g, '0x2'),
            // 7. Operator swapping (= → LIKE, RLIKE)
            s => s.replace(/1=1/g, '1 LIKE 1').replace(/'a'='a'/g, "'a' LIKE 'a'"),
            // 8. Logical invariant injection (tautology padding)
            s => s.replace(/--$/, ' AND 0<1--'),
            // 9. Function wrapping (IFNULL wraps don't change value)
            s => s.replace(/\b1\b/, 'IFNULL(1,1)'),
            // 10. String concatenation
            s => s.replace(/'a'/g, "CONCAT('a','')").replace(/'x'/g, "CONCAT('x','')"),
            // 11. Double URL encoding
            s => encodeURIComponent(encodeURIComponent(s)),
            // 12. Line comment variant (MySQL #, MSSQL --, PG --)
            s => s.replace(/--\s*-\s*$/, '#'),
        ]

        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            const base = bases[i % bases.length]
            const mut = mutations[Math.floor(i / bases.length) % mutations.length]
            variants.push(mut(base))
        }
        return variants
    },
}
