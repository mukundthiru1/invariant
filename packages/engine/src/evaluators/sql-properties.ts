/**
 * SQL Invariant Properties — Formal Specifications
 *
 * These are the SQL injection invariant properties expressed as
 * formal ISL specifications with multi-level detection.
 */

import type { InvariantProperty, DetectionResult } from './property-spec.js'
import { PROPERTY_REGISTRY } from './property-spec.js'
import { detectTautologies } from './sql-expression-evaluator.js'
import { detectSqlStructural } from './sql-structural-evaluator.js'


// ── Shared Helpers ───────────────────────────────────────────────

function deepDecode(input: string, depth = 0): string {
    if (depth > 4) return input
    let decoded = input
    try {
        const urlDecoded = decodeURIComponent(decoded)
        if (urlDecoded !== decoded) decoded = deepDecode(urlDecoded, depth + 1)
    } catch { /* invalid encoding */ }
    decoded = decoded
        .replace(/&#x([0-9a-f]+);?/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&#(\d+);?/g, (_, dec) => String.fromCharCode(parseInt(dec)))
        .replace(/&quot;/gi, '"').replace(/&apos;/gi, "'")
        .replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&amp;/gi, '&')
    decoded = decoded.replace(/\\u([0-9a-f]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    decoded = decoded.replace(/\\x([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    decoded = decoded.replace(/\/\*.*?\*\//g, ' ')
    return decoded
}


// ═══════════════════════════════════════════════════════════════════
// SQL_TAUTOLOGY — The flagship Level 2 invariant
// ═══════════════════════════════════════════════════════════════════

export const SQL_TAUTOLOGY_PROPERTY: InvariantProperty = {
    id: 'sql-tautology',
    name: 'SQL Boolean Tautology',
    domain: 'sql_injection',
    contexts: ['WHERE', 'HAVING'],
    severity: 'high',

    formalProperty: `∃ subexpr ∈ parse(input, SQL_GRAMMAR) :
        eval(subexpr, BOOLEAN_CONTEXT) ∈ {TRUE, TAUTOLOGY}
        ∧ context(subexpr) ∈ {CONDITIONAL, WHERE_CLAUSE, HAVING_CLAUSE}`,

    rationale: `If eval(subexpr) = TRUE unconditionally,
        then WHERE clause is bypassed regardless of other predicates.
        WHERE (condition) OR (TRUE) ≡ TRUE → full table returned.
        This enables authentication bypass, data exfiltration, and
        authorization circumvention.`,

    detectL1: (input: string): DetectionResult => {
        const d = deepDecode(input)
        // Core regex: string terminator + boolean operator + always-true expression
        const match = /['"`)\s]\s*(?:OR|\|\|)\s*(?:['"`]?\w+['"`]?\s*(?:=|LIKE|IS)\s*['"`]?\w+['"`]?|\d+\s*[><= ]+\s*\d+|TRUE|NOT\s+FALSE|NOT\s+0|1\b)/i.test(d)
        if (match) {
            return {
                detected: true,
                confidence: 0.8,
                explanation: 'Regex match: SQL tautology pattern detected',
                evidence: d.slice(0, 200),
            }
        }
        return { detected: false, confidence: 0, explanation: '' }
    },

    detectL2: (input: string): DetectionResult => {
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
        return { detected: false, confidence: 0, explanation: '' }
    },

    composableWith: [
        'sql-union-extraction',    // tautology + UNION → data exfiltration
        'sql-stacked-execution',   // tautology + stacked query → RCE
        'sql-error-oracle',        // tautology + error-based → schema leak
    ],

    discoveryChannels: ['runtime_sensor', 'code_analysis', 'incident_analysis'],

    generatePositives: (count: number) => {
        const positives = [
            "' OR 1=1--",
            "' OR 'a'='a'--",
            "' OR 2>1--",
            "') OR ((1=1))--",
            "' OR 1 BETWEEN 0 AND 2--",
            "' OR 1 IN (1,2,3)--",
            "' OR 1 IS NOT NULL--",
            "' OR NOT FALSE--",
            "' OR TRUE--",
            "' OR 'x' LIKE 'x'--",
            "' OR 100>=1--",
            "' OR 5<>3--",
            "' OR ''=''--",
            "' OR ASCII('a')=97--",
            "' OR LENGTH('abc')=3--",
            "' OR 0xFF=255--",
        ]
        return positives.slice(0, Math.min(count, positives.length))
    },

    generateNegatives: (count: number) => {
        const negatives = [
            '/api/users?id=42&name=john',
            '/search?q=how+to+order+pizza',
            '/api/projects?filter=status:active',
            '{"username":"admin","password":"secret123"}',
            '/api/v1/orders',
            'SELECT * FROM users',   // No tautology, just a query
            'normal search term',
            '/path/to/resource?page=5',
            'Content-Type: application/json',
            'The quick brown fox jumps over the lazy dog',
        ]
        return negatives.slice(0, Math.min(count, negatives.length))
    },
}


// ═══════════════════════════════════════════════════════════════════
// SQL_STRING_TERMINATION
// ═══════════════════════════════════════════════════════════════════

export const SQL_STRING_TERMINATION_PROPERTY: InvariantProperty = {
    id: 'sql-string-termination',
    name: 'SQL String Context Escape',
    domain: 'sql_injection',
    contexts: ['WHERE', 'INSERT_VALUES', 'UPDATE_SET'],
    severity: 'high',

    formalProperty: `∃ delimiter ∈ {', ", \`} :
        input CONTAINS delimiter
        ∧ ∃ keyword ∈ SQL_KEYWORDS : input[after(delimiter)] CONTAINS keyword
        → attacker terminates string context and injects SQL`,

    rationale: `Breaking out of a SQL string literal is the prerequisite
        for nearly all SQL injection attacks. Without string termination,
        injected SQL remains inert data inside a string context.`,

    detectL1: (input: string): DetectionResult => {
        const d = deepDecode(input)
        // Allow optional closing parens between string terminator and SQL keyword
        const match = /['"`]\)?\s*(?:;|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bEXEC\b)/i.test(d)
        if (match) {
            return {
                detected: true,
                confidence: 0.85,
                explanation: 'SQL string terminator followed by SQL keyword',
                evidence: d.slice(0, 200),
            }
        }
        return { detected: false, confidence: 0, explanation: '' }
    },

    detectL2: (input: string): DetectionResult => {
        const d = deepDecode(input)
        const detections = detectSqlStructural(d)
        const match = detections.find(det => det.type === 'string_termination')
        if (match) {
            return {
                detected: true,
                confidence: match.confidence,
                explanation: `Token analysis: ${match.detail}`,
                evidence: match.detail,
            }
        }
        return { detected: false, confidence: 0, explanation: '' }
    },

    composableWith: [
        'sql-tautology',
        'sql-union-extraction',
        'sql-stacked-execution',
        'sql-time-oracle',
        'sql-error-oracle',
    ],

    discoveryChannels: ['runtime_sensor', 'code_analysis'],

    generatePositives: (count: number) => {
        const t = ["'", '"', '`', "';", "')", "'))"]
        const inj = [' OR ', ' AND ', '; DROP TABLE ', ' UNION SELECT ', '; INSERT INTO ']
        const s = ['--', '#', '/*', '']
        const result: string[] = []
        for (let i = 0; i < count; i++) {
            result.push(`${t[i % t.length]}${inj[i % inj.length]}1${s[i % s.length]}`)
        }
        return result
    },

    generateNegatives: (count: number) => {
        const negatives = [
            "it's a test",
            'normal text',
            '/api/users?name=john',
            '{"key":"value"}',
            "user's input",
        ]
        return negatives.slice(0, Math.min(count, negatives.length))
    },
}


// ═══════════════════════════════════════════════════════════════════
// SQL_UNION_EXTRACTION
// ═══════════════════════════════════════════════════════════════════

export const SQL_UNION_EXTRACTION_PROPERTY: InvariantProperty = {
    id: 'sql-union-extraction',
    name: 'SQL UNION Data Extraction',
    domain: 'sql_injection',
    contexts: ['WHERE', 'HAVING'],
    severity: 'critical',

    formalProperty: `input CONTAINS (UNION [ALL] SELECT)
        ∧ context = SQL_QUERY
        → attacker appends second query to extract data from other tables`,

    rationale: `UNION SELECT allows an attacker to append their own query
        to the application's query, extracting data from any accessible
        table in the database. This is the primary data exfiltration
        technique in SQL injection attacks.`,

    detectL1: (input: string): DetectionResult => {
        const d = deepDecode(input)
        const match = /union\s+(all\s+)?select\s/i.test(d)
        if (match) {
            return {
                detected: true,
                confidence: 0.9,
                explanation: 'UNION SELECT pattern detected',
                evidence: d.slice(0, 200),
            }
        }
        return { detected: false, confidence: 0, explanation: '' }
    },

    detectL2: (input: string): DetectionResult => {
        const d = deepDecode(input)
        const detections = detectSqlStructural(d)
        const match = detections.find(det => det.type === 'union_extraction')
        if (match) {
            return {
                detected: true,
                confidence: match.confidence,
                explanation: `Token analysis: ${match.detail}`,
                evidence: match.detail,
            }
        }
        return { detected: false, confidence: 0, explanation: '' }
    },

    composableWith: [
        'sql-tautology',           // tautology + UNION → bypass WHERE + exfil
        'sql-string-termination',  // break string + UNION
    ],

    discoveryChannels: ['runtime_sensor', 'code_analysis', 'incident_analysis'],

    generatePositives: (count: number) => {
        const bases = [
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT username,password FROM users--",
            "' UNION SELECT NULL,NULL,NULL--",
            '" UNION SELECT table_name FROM information_schema.tables--',
            "') UNION SELECT 1,2,3--",
            "'/**/UNION/**/SELECT/**/1,2,3--",
        ]
        return bases.slice(0, Math.min(count, bases.length))
    },

    generateNegatives: (count: number) => {
        const negatives = [
            '/api/union/members',
            'SELECT * FROM users',
            'labor union meeting',
            '/union-station',
        ]
        return negatives.slice(0, Math.min(count, negatives.length))
    },
}


// ═══════════════════════════════════════════════════════════════════
// SQL_STACKED_EXECUTION
// ═══════════════════════════════════════════════════════════════════

export const SQL_STACKED_EXECUTION_PROPERTY: InvariantProperty = {
    id: 'sql-stacked-execution',
    name: 'SQL Stacked Query Execution',
    domain: 'sql_injection',
    contexts: ['WHERE', 'INSERT_VALUES', 'UPDATE_SET'],
    severity: 'critical',

    formalProperty: `input CONTAINS ';'
        ∧ ∃ statement ∈ {DROP, DELETE, INSERT, UPDATE, ALTER, CREATE, EXEC} :
            input[after(';')] STARTS_WITH statement
        → attacker terminates current query and executes arbitrary SQL`,

    rationale: `Stacked queries allow arbitrary SQL execution independent
        of the original query structure. Unlike UNION, this enables
        destructive operations (DROP TABLE, DELETE) and stored procedure
        execution (EXEC xp_cmdshell → RCE).`,

    detectL1: (input: string): DetectionResult => {
        const d = deepDecode(input)
        const match = /;\s*(drop|delete|insert|update|alter|create|exec|execute)\s+/i.test(d)
        if (match) {
            return {
                detected: true,
                confidence: 0.9,
                explanation: 'Semicolon followed by destructive SQL statement',
                evidence: d.slice(0, 200),
            }
        }
        return { detected: false, confidence: 0, explanation: '' }
    },

    detectL2: (input: string): DetectionResult => {
        const d = deepDecode(input)
        const detections = detectSqlStructural(d)
        const match = detections.find(det => det.type === 'stacked_execution')
        if (match) {
            return {
                detected: true,
                confidence: match.confidence,
                explanation: `Token analysis: ${match.detail}`,
                evidence: match.detail,
            }
        }
        return { detected: false, confidence: 0, explanation: '' }
    },

    composableWith: [
        'sql-string-termination',
        'sql-tautology',
    ],

    discoveryChannels: ['runtime_sensor', 'code_analysis', 'incident_analysis'],

    generatePositives: (count: number) => {
        const bases = [
            "'; DROP TABLE users--",
            "'; INSERT INTO admin VALUES('evil','password')--",
            "'; UPDATE users SET role='admin'--",
            "'; DELETE FROM sessions--",
            "'; EXEC xp_cmdshell 'whoami'--",
        ]
        return bases.slice(0, Math.min(count, bases.length))
    },

    generateNegatives: (count: number) => {
        const negatives = [
            'DROP us a line',
            '/api/users;jsessionid=abc',
            'semi;colon;in;text',
        ]
        return negatives.slice(0, Math.min(count, negatives.length))
    },
}


// ═══════════════════════════════════════════════════════════════════
// SQL_TIME_ORACLE
// ═══════════════════════════════════════════════════════════════════

export const SQL_TIME_ORACLE_PROPERTY: InvariantProperty = {
    id: 'sql-time-oracle',
    name: 'SQL Time-Based Blind Oracle',
    domain: 'sql_injection',
    contexts: ['WHERE', 'HAVING'],
    severity: 'high',

    formalProperty: `∃ function ∈ {SLEEP, WAITFOR DELAY, BENCHMARK, PG_SLEEP} :
        input CONTAINS function(duration)
        → attacker uses time delay as oracle for boolean extraction`,

    rationale: `Time-based blind injection uses database sleep functions
        as a side-channel oracle. By asking "if condition then sleep(5)",
        the attacker extracts data one bit at a time by measuring
        response times. Slow but universal — works on any SQL injection
        regardless of whether output is visible.`,

    detectL1: (input: string): DetectionResult => {
        const d = deepDecode(input)
        const match = /(?:sleep\s*\(|waitfor\s+delay|benchmark\s*\(|pg_sleep)/i.test(d)
        if (match) {
            return {
                detected: true,
                confidence: 0.85,
                explanation: 'SQL time delay function detected',
                evidence: d.slice(0, 200),
            }
        }
        return { detected: false, confidence: 0, explanation: '' }
    },

    detectL2: (input: string): DetectionResult => {
        const d = deepDecode(input)
        const detections = detectSqlStructural(d)
        const match = detections.find(det => det.type === 'time_oracle')
        if (match) {
            return {
                detected: true,
                confidence: match.confidence,
                explanation: `Token analysis: ${match.detail}`,
                evidence: match.detail,
            }
        }
        return { detected: false, confidence: 0, explanation: '' }
    },

    composableWith: [
        'sql-string-termination',
        'sql-tautology',
    ],

    discoveryChannels: ['runtime_sensor', 'code_analysis'],

    generatePositives: (count: number) => {
        const bases = [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND BENCHMARK(5000000,SHA1('test'))--",
            "' AND pg_sleep(5)--",
            "' OR IF(1=1,SLEEP(5),0)--",
        ]
        return bases.slice(0, Math.min(count, bases.length))
    },

    generateNegatives: (count: number) => {
        const negatives = [
            'sleep well tonight',
            'benchmark report',
            '/api/pg/sleep-mode',
        ]
        return negatives.slice(0, Math.min(count, negatives.length))
    },
}


// ═══════════════════════════════════════════════════════════════════
// REGISTRATION
// ═══════════════════════════════════════════════════════════════════

/** Register all SQL properties into the global registry */
export function registerSqlProperties(): void {
    PROPERTY_REGISTRY.register(SQL_TAUTOLOGY_PROPERTY)
    PROPERTY_REGISTRY.register(SQL_STRING_TERMINATION_PROPERTY)
    PROPERTY_REGISTRY.register(SQL_UNION_EXTRACTION_PROPERTY)
    PROPERTY_REGISTRY.register(SQL_STACKED_EXECUTION_PROPERTY)
    PROPERTY_REGISTRY.register(SQL_TIME_ORACLE_PROPERTY)
}
