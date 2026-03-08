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

const TAUTOLOGY_PATTERN = /['"`()\s]\s*(?:OR|\|\|)\s*(?:\(?['"`]?\w*['"`]?\)?\s*(?:=|LIKE|IS)\s*\(?['"`]?\w*['"`]?\)?|\d+\s*[><= ]+\s*\d+|TRUE|NOT\s+FALSE|NOT\s+0|1\b)/i

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
        return TAUTOLOGY_PATTERN.test(d)
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
        try {
            const tautologies = detectTautologies(d)
            if (tautologies.length > 0) {
                return {
                    detected: true,
                    confidence: 0.92,
                    explanation: `Expression evaluator: tautological expression ${tautologies[0].expression} evaluates to ${tautologies[0].value}`,
                    evidence: tautologies.map(t => t.expression).join(', '),
                }
            }
        } catch { /* L2 failure must not affect pipeline */ }
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
            s => s.replace(/--$/, '#').replace(/--\s*-$/, '#'),
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

