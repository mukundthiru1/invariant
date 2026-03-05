/**
 * sql_tautology — Boolean tautology to bypass WHERE clauses
 *
 * Invariant property:
 *   ∃ subexpr ∈ parse(input, SQL_GRAMMAR) :
 *     eval(subexpr, BOOLEAN_CONTEXT) ≡ TRUE
 *     ∀ bindings of free variables
 *
 * The attacker injects a condition that is always true, making
 * the WHERE clause pass regardless of the actual data. This bypasses
 * authentication ("WHERE user=X AND pass=Y OR 1=1") and authorization
 * ("WHERE owner=X OR 1=1") checks.
 *
 * L1 detection: regex-based pattern matching for common tautologies.
 * L2 detection: full tokenization → AST → evaluation (sql-expression-evaluator).
 * The L2 evaluator catches arbitrary tautologies including novel ones.
 */

import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

const TAUTOLOGY_PATTERN = /['"`()\s]\s*(?:OR|\|\|)\s*(?:\(?['"`]?\w*['"`]?\)?\s*(?:=|LIKE|IS)\s*\(?['"`]?\w*['"`]?\)?|\d+\s*[><= ]+\s*\d+|TRUE|NOT\s+FALSE|NOT\s+0|1\b)/i

export const sqlTautology: InvariantClassModule = {
    id: 'sql_tautology',
    description: 'Boolean tautology to bypass WHERE clause authentication/authorization checks',
    category: 'sqli',
    severity: 'high',

    calibration: {
        baseConfidence: 0.85,
        environmentMultipliers: {
            'login_form': 1.3,
            'search': 0.8,
            'api_json': 0.7,
        },
        falsePositivePatterns: [
            /\bx=x\b.*\bcss\b/i,  // CSS selectors sometimes look like tautologies
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
        const encodings: Array<(s: string) => string> = [
            s => s,
            s => encodeURIComponent(s),
            s => s.replace(/ /g, '/**/'),
            s => s.replace(/ /g, '%20').replace(/'/g, '%27'),
            s => s.replace(/OR/g, 'oR'),
        ]
        const variants: string[] = []
        for (let i = 0; i < count; i++) {
            const base = bases[i % bases.length]
            const enc = encodings[Math.floor(i / bases.length) % encodings.length]
            variants.push(enc(base))
        }
        return variants
    },
}
