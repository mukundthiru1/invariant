/**
 * sql_stacked_execution — Semicolon-terminated stacked queries
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { detectSqlStructural } from '../../evaluators/sql-structural-evaluator.js'

const SQL_STACKED_QUERY_TERMINATION_STRIPPED = /;\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|CALL|UNION|WITH|MERGE|GRANT|REVOKE|SHUTDOWN|TRUNCATE)\b/i
const SQL_STACKED_QUERY_TERMINATION_RAW = /;\s*(?:SELECT|UNION|WITH|CALL|MERGE|DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC|EXECUTE|GRANT|REVOKE|SHUTDOWN|TRUNCATE)\b/i
const SQL_STACKED_COMMENT_OPEN_CLOSE_PATTERN = /\/\*!\d*\s*([\s\S]*?)\*\//g
const SQL_STACKED_BLOCK_COMMENT_PATTERN = /\/\*[\s\S]*?\*\//g
const SQL_STACKED_LINE_COMMENT_PATTERN = /--[^\n]*/g
const SQL_STACKED_WHITESPACE_PATTERN = /\s+/g

// SAA-C004: PostgreSQL dollar-quoting bypass patterns
// $tag$...$tag$ can hide a semicolon+keyword sequence inside a literal,
// so the primary termination regex never fires.
const SQL_DOLLAR_QUOTE_RE = /\$([A-Za-z_][A-Za-z0-9_]*)?\$([\s\S]*?)\$\1\$/g
const SQL_DOLLAR_ANON_BLOCK_RE = /\bDO\s+\$\$[\s\S]*?\$\$/i

// SAA-C004: Prepared/dynamic statement patterns not requiring ';' terminator
// PREPARE stmt FROM '...'; EXECUTE stmt
const SQL_PREPARE_RE = /\bPREPARE\s+\w+\s+FROM\s+['"`]/i
// MSSQL: DECLARE @s ...; SET @s = '...'; EXEC(@s) / EXECUTE(@s)
const SQL_MSSQL_DYNAMIC_RE = /\bDECLARE\s+@\w+\s+(?:VARCHAR|NVARCHAR|CHAR|NCHAR|SYSNAME|TEXT)\b[\s\S]{0,200}\bEXEC(?:UTE)?\s*\(@\w+\)/i
// Oracle: EXECUTE IMMEDIATE '...'
const SQL_ORACLE_EXEC_IMMED_RE = /\bEXECUTE\s+IMMEDIATE\s*['"`]/i
// PostgreSQL anonymous block: DO $$ BEGIN ... END $$
const SQL_PG_ANON_WITH_DDL_RE = /\bDO\s+\$\$[\s\S]{0,600}\b(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|COPY|PERFORM\s+pg_)\b/i

/** Strip dollar-quoted literals, exposing any semicolons/keywords inside them */
function expandDollarQuotes(input: string): string {
    // Replace $tag$content$tag$ with a space + the content (revealing inner statements)
    return input.replace(SQL_DOLLAR_QUOTE_RE, (_, _tag, body) => ' ' + body + ' ')
}

export const sqlStackedExecution: InvariantClassModule = {
    id: 'sql_stacked_execution',
    description: 'Semicolon to terminate current query and execute arbitrary SQL statements',
    category: 'sqli',
    severity: 'critical',
    calibration: { baseConfidence: 0.92, minInputLength: 8 },

    mitre: ['T1190'],
    cwe: 'CWE-89',

    knownPayloads: [
        "'; DROP TABLE users--",
        "'; DELETE FROM sessions--",
        "'; INSERT INTO admins VALUES('hack','hack')--",
        "'; UPDATE users SET role='admin' WHERE id=1--",
        "'; EXEC xp_cmdshell 'whoami'--",
        "; TRUNCATE TABLE audit_log--",
        // SAA-C004: Dollar-quoting bypass payloads
        "$body$; DROP TABLE users$body$",
        "admin'; DO $$ BEGIN PERFORM pg_sleep(5); END $$--",
        "'; DO $$ DECLARE r RECORD; BEGIN FOR r IN SELECT * FROM pg_authid LOOP RAISE NOTICE '%', r.rolname; END LOOP; END $$--",
        // Prepared statement bypass
        "x'; PREPARE stmt FROM 'DROP TABLE users'; EXECUTE stmt--",
        // MSSQL dynamic execution
        "'; DECLARE @s VARCHAR(100); SET @s='DROP TABLE users'; EXEC(@s)--",
        // Oracle EXECUTE IMMEDIATE
        "'; EXECUTE IMMEDIATE 'DROP TABLE users'--",
    ],

    knownBenign: [
        "hello; world",
        "item; description; price",
        "a; b; c",
        "font-size: 12px; color: red;",
        "1; 2; 3",
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        // BYP-001: MySQL conditional comments (/*!50000SELECT*/) must be unwrapped
        // BEFORE generic block comment stripping to preserve the injected keyword.
        const stripSqlComments = (sql: string) => sql
            .replace(SQL_STACKED_COMMENT_OPEN_CLOSE_PATTERN, (_, inner) => ' ' + inner + ' ')
            .replace(SQL_STACKED_BLOCK_COMMENT_PATTERN, ' ')
            .replace(SQL_STACKED_LINE_COMMENT_PATTERN, ' ')
            .replace(SQL_STACKED_WHITESPACE_PATTERN, ' ')
            .trim()
        const stripped = stripSqlComments(d)
        if (SQL_STACKED_QUERY_TERMINATION_STRIPPED.test(stripped)) return true
        if (SQL_STACKED_QUERY_TERMINATION_RAW.test(d)) return true

        // SAA-C004: PostgreSQL dollar-quoting bypass — expand $tag$...$tag$ literals,
        // then re-run the stacked-query termination check on the exposed content.
        const dollarExpanded = expandDollarQuotes(d)
        if (dollarExpanded !== d) {
            const expandedStripped = stripSqlComments(dollarExpanded)
            if (SQL_STACKED_QUERY_TERMINATION_STRIPPED.test(expandedStripped)) return true
        }

        // SAA-C004: Anonymous PostgreSQL blocks with DDL (DO $$ ... $$)
        if (SQL_PG_ANON_WITH_DDL_RE.test(d)) return true
        if (SQL_DOLLAR_ANON_BLOCK_RE.test(d) && /\b(?:DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|TRUNCATE|pg_sleep|pg_authid)\b/i.test(d)) return true

        // SAA-C004: Prepared statement attacks
        if (SQL_PREPARE_RE.test(d)) return true

        // SAA-C004: MSSQL dynamic execution
        if (SQL_MSSQL_DYNAMIC_RE.test(d)) return true

        // SAA-C004: Oracle EXECUTE IMMEDIATE
        if (SQL_ORACLE_EXEC_IMMED_RE.test(d)) return true

        return false
    },

    detectL2: (input: string): DetectionLevelResult | null => {
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
        return null
    },

    generateVariants: (count: number): string[] => {
        const v = [
            "'; DROP TABLE users--", "'; DELETE FROM sessions--",
            "'; INSERT INTO admins VALUES('hack','hack')--",
            "'; UPDATE users SET role='admin' WHERE id=1--",
            "'; EXEC xp_cmdshell 'whoami'--",
            "; ALTER TABLE users ADD backdoor VARCHAR(100)--",
            "'; CREATE TABLE pwned(data TEXT)--",
            '; TRUNCATE TABLE audit_log--',
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}
