# INVARIANT Security System — Red Team Audit Summary

**Audit Date:** 2026-03-09  
**Scope:** Full-stack security assessment (Engine, Edge Sensor, RASP Agent)  
**Methodology:** Static source code analysis + architectural review  

---

## Findings Overview

| Severity | Count | Description |
|----------|-------|-------------|
| **CRITICAL** | 4 | Complete detection bypass vectors |
| **HIGH** | 5 | Significant evasion techniques |
| **MEDIUM** | 3 | Exploitable under specific conditions |
| **LOW/INFO** | 11 | Architectural concerns, DoS vectors |

**Total Exploitable Vectors:** 23

---

## Critical Vulnerabilities (4)

### 1. Static Asset Query String Bypass [CRITICAL]
- **Location:** `edge-sensor/src/index.ts:883-887`
- **Vector:** `GET /style.css?user=' UNION SELECT * FROM passwords--`
- **Impact:** Complete bypass of L5 invariant engine for query string attacks
- **Fix:** Analyze query strings regardless of path extension

### 2. Body Size Limit Bypass [CRITICAL]
- **Location:** `edge-sensor/src/modules/body-analysis.ts:51`
- **Vector:** POST body >32KB with malicious payload at end
- **Impact:** POST-based SQLi/XSS completely undetected
- **Fix:** Analyze truncated bodies OR block oversized requests in enforce mode

### 3. SQL Comment Injection [CRITICAL]
- **Location:** `engine/src/evaluators/sql-expression-evaluator.ts:109-117`
- **Vector:** `' OR 1=1 /*...(4090 As)...*/union select * from users--`
- **Impact:** Detection bypass via comment content hiding
- **Fix:** Validate comment contents for SQL keywords

### 4. Input Length Truncation [CRITICAL]
- **Location:** `engine/src/evaluators/sql-expression-evaluator.ts:88-89`
- **Vector:** Payload at position >4096 in input string
- **Impact:** Malicious content truncated before detection
- **Fix:** Reject oversized inputs in enforce mode

---

## High Severity Vulnerabilities (5)

### 5. RASP Code Pattern Bypass [HIGH]
- **Location:** `agent/src/rasp/exec.ts:53-60`
- **Vector:** String concatenation, indirect requires, fromCharCode
- **Impact:** RCE in Node.js environment despite RASP
- **Fix:** AST-based analysis instead of regex

### 6. Command Injection Regex Evasion [HIGH]
- **Location:** `agent/src/rasp/exec.ts:33`
- **Vector:** `${IFS}`, globbing (`/???/b??h`), newlines
- **Impact:** Shell command execution bypass
- **Fix:** Comprehensive separator coverage + glob detection

### 7. SSRF IP Encoding Bypass [HIGH]
- **Location:** `engine/src/classes/ssrf/index.ts:42`
- **Vector:** Octal (`0177.0.0.1`), short form (`127.1`), IPv6 full form
- **Impact:** Cloud metadata access, internal network reach
- **Fix:** IP canonicalization library

### 8. WebSocket Binary Frame Bypass [HIGH]
- **Location:** `edge-sensor/src/index.ts`
- **Vector:** CBOR/BSON/msgpack-encoded payloads over WebSocket
- **Impact:** Real-time attack channel completely undetected
- **Fix:** Add binary frame analysis

### 9. Multipart File Upload Bypass [HIGH]
- **Location:** `edge-sensor/src/modules/body-analysis.ts:315-339`
- **Vector:** `Content-Type: text/plain; filename=shell.php`
- **Impact:** Arbitrary file upload → RCE
- **Fix:** Parse multipart properly, check filename extension

---

## Medium Severity Issues (3)

### 10. Confidence Score Manipulation [MEDIUM]
- **Location:** `engine/src/invariant-engine.ts:676-692`
- **Vector:** Craft payload triggering only L1 (0.70 confidence)
- **Impact:** Sub-threshold attack delivery
- **Fix:** Consider lowering block threshold for L1-only

### 11. Pattern Cache Memory Exhaustion [MEDIUM]
- **Location:** `agent/src/rasp/sql.ts:34-88`
- **Vector:** Unique query flooding
- **Impact:** Unbounded memory growth → OOM → defense down
- **Fix:** Add LRU cache eviction

### 12. Frozen Intrinsics Bypass [MEDIUM]
- **Location:** `agent/src/rasp/exec.ts`, `agent/src/rasp/sql.ts`
- **Vector:** Node 20+ frozen built-in modules
- **Impact:** Silent hook failure
- **Fix:** Detect frozen state, implement fallback

---

## Novel Attack Vectors Identified

1. **Unicode Homoglyph Canonicalization Gap** — Cyrillic 'а' vs Latin 'a'
2. **Context Confusion via Polyglot Payloads** — Valid in multiple contexts
3. **Decomposition Timing Side-Channel** — Measurable processing delays

---

## Exploitation Chains

### Chain A: Complete Edge Bypass
```
Target: POST /api/v1/users  
→ Vector: GET /api/v1/users.css?action=delete&id=1  
→ Result: Query string NEVER analyzed, action executes
```

### Chain B: SQLi via Body + Truncation
```
Step 1: 33KB JSON body with 32KB padding + 1KB payload  
Step 2: Body analyzer skips (too large)  
Step 3: Application parses full body  
Step 4: SQL executes without detection
```

### Chain C: RCE via RASP Evasion
```
Step 1: Use Node 20+ frozen intrinsics to disable hooks  
Step 2: Dynamic import with string obfuscation  
Step 3: Execute commands undetected
```

---

## Recommended Mitigation Priority

### P0 (Immediate — 24-48 hours)
- [ ] Fix body size bypass (analyze truncated OR block oversized)
- [ ] Fix static asset bypass (analyze query strings)
- [ ] Add MAX_INPUT enforcement (reject >4096 in enforce mode)
- [ ] Patch comment skipping (validate comment contents)

### P1 (Short-term — 1-2 weeks)
- [ ] Implement AST-based VM hook detection
- [ ] Add IP canonicalization for SSRF
- [ ] Add binary WebSocket frame analysis
- [ ] Implement frozen intrinsics detection

### P2 (Long-term — 1 month+)
- [ ] LRU cache eviction for pattern cache
- [ ] Distributed chain correlation
- [ ] ML-based anomaly detection
- [ ] Audit closed-source Rust/WASM layer

---

## Artifacts Generated

| File | Description |
|------|-------------|
| `REDTEAM_AUDIT_INVARIANT.md` | Full detailed audit report |
| `REDTEAM_QUICK_REFERENCE.md` | Quick reference card for testers |
| `REDTEAM_AUDIT_SUMMARY.md` | This summary document |
| `pocs/invariant_bypass_poc.py` | Automated bypass payload generator |

---

## Risk Assessment

| Risk | Level | Justification |
|------|-------|---------------|
| Detection Bypass | **CRITICAL** | 4 confirmed complete bypass vectors |
| Data Exfiltration | **HIGH** | SQLi bypass enables direct DB access |
| RCE Possibility | **HIGH** | Multiple RASP evasion techniques |
| DoS Potential | **MEDIUM** | Memory exhaustion, cache poisoning |
| Supply Chain | **MEDIUM** | Opaque Rust/WASM layer |

---

## Final Assessment

The INVARIANT system presents an innovative multi-layer architecture with genuine advances in structural detection (L2/L3 evaluators). However, **the "mathematical invariant" claim does not hold across all attack vectors** due to:

1. **Boundary condition failures** — Size limits, truncation points
2. **Encoding asymmetries** — IP canonicalization, character encodings
3. **Context confusion** — Query strings vs path, binary vs text frames
4. **Regex limitations** — Pattern-based detection evadable via transformation

**Recommendation:** Deploy with additional compensating controls until critical bypasses are patched.

---

**Report Classification:** RED TEAM / AUTHORIZED SECURITY TESTING  
**Distribution:** Security team, Engineering leadership, CISO
