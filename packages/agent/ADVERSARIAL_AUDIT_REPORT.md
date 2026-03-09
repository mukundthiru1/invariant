# Adversarial Security Audit Report
## @santh/agent - Runtime Application Self-Protection (RASP) System

**Audit Date:** 2026-03-08  
**Auditor:** Security Analysis Agent  
**Scope:** packages/agent/src/ - All middleware, RASP modules, and core infrastructure  
**Classification:** CONFIDENTIAL - Contains exploitable vulnerability details

---

## Executive Summary

This audit identifies **3 confirmed vulnerabilities** in the @santh/agent RASP system through adversarial testing. Additionally, **4 potential weaknesses** were analyzed but could not be reproduced as exploitable bypasses with current test cases.

### Risk Distribution
| Severity | Count | Finding IDs | Status |
|----------|-------|-------------|--------|
| Critical | 2 | BODY-001, HDR-001 | ✅ Confirmed |
| High | 1 | FC-001 | ✅ Confirmed |
| Medium | 4 | BYP-001, ENC-001, EXP-001, MEM-001 | ⚠️ Analysis Only |

---

## Detailed Findings

### 🔴 CRITICAL

#### BODY-001: Method-Restricted Body Parsing Bypass
**Status:** ✅ **Confirmed Exploitable**  
**CVSS:** 9.1 (Critical)  
**Location:** `middleware/handler.ts:163-180`

**Description:**
The generic handler's `readBodyIfPost()` function ONLY processes request bodies for POST requests, completely ignoring PUT, PATCH, and DELETE methods that can also carry payloads.

**Vulnerable Code:**
```typescript
async function readBodyIfPost(request: Request): Promise<unknown> {
    if (request.method.toUpperCase() !== 'POST') return ''  // BYPASS: PUT/DELETE ignored
    // ... body parsing only happens for POST
}
```

**Proof of Concept:**
```bash
# Standard SQL injection via POST (DETECTED - body scanned)
curl -X POST https://api.example.com/search \
  -H "Content-Type: application/json" \
  -d '{"q": "'"'"' OR 1=1--"}'

# SAME PAYLOAD via PUT (BYPASSED - body ignored)
curl -X PUT https://api.example.com/users/1 \
  -H "Content-Type: application/json" \
  -d '{"name": "'"'"' OR 1=1--"}'
```

**Impact:** Complete RASP bypass for all body-based attacks on REST APIs using proper HTTP semantics.

**Remediation:**
```typescript
const METHODS_WITH_BODY = ['POST', 'PUT', 'PATCH', 'DELETE']
async function readBodyIfMethod(request: Request): Promise<unknown> {
    if (!METHODS_WITH_BODY.includes(request.method.toUpperCase())) return ''
    // ... rest of parsing
}
```

---

#### HDR-001: IP Spoofing via X-Forwarded-For Trust
**Status:** ✅ **Confirmed Exploitable**  
**CVSS:** 8.2 (High)  
**Location:** `middleware/handler.ts:273-275`

**Description:**
The generic handler (used by Cloudflare Workers/edge runtimes) extracts source IP using X-Forwarded-For header WITHOUT validation, while other middlewares (Hono, Next.js) explicitly reject it per SAA-090 guidelines.

**Vulnerable Code:**
```typescript
// handler.ts (VULNERABLE)
function getSourceHash(request: Request): string {
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0].trim() ||  // TRUSTED!
        request.headers.get('cf-connecting-ip') ||
        'unknown'
    // ...
}
```

**Secure Code (hono.ts):**
```typescript
// SAA-090: Relying on client-supplied headers is unreliable
const ip = c.req.header('cf-connecting-ip') || 'unknown'
```

**Proof of Concept:**
```bash
# Attacker spoofs IP to bypass rate limiting
curl https://api.example.com/ \
  -H "X-Forwarded-For: 1.2.3.4"  # New identity per request

# With proxy chain spoofing
curl https://api.example.com/ \
  -H "X-Forwarded-For: 10.0.0.1, 192.168.1.1, 172.16.0.1"
# Extracts: 10.0.0.1 (attacker-controlled, first value)
```

**Impact:** Complete bypass of source-based security controls (rate limiting, blocking, reputation tracking), potential for impersonation attacks.

**Remediation:** 
```typescript
function getSourceHash(request: Request): string {
    // Only trust verified headers from edge/CDN
    const ip = request.headers.get('cf-connecting-ip') ||  // Cloudflare
        request.headers.get('true-client-ip') ||           // Akamai
        'unknown'
    // Never trust X-Forwarded-From directly
}
```

---

### 🟠 HIGH

#### FC-001: Missing failClosed in Generic Handler
**Status:** ✅ **Confirmed Design Gap**  
**CVSS:** 6.5 (Medium-High)  
**Location:** `middleware/handler.ts:330-335`

**Description:**
While all framework-specific middlewares (express.ts, hono.ts, etc.) implement `failClosed` option (returning 503 on internal errors), the generic handler lacks this entirely.

**Comparison:**
```typescript
// express.ts (HAS failClosed)
} catch (error) {
    if (failClosed) {
        return res.status(503).json({ error: 'Service Unavailable' })
    }
    next(error)
}

// handler.ts (MISSING failClosed)
} catch (error) {
    if (options.verbose) console.warn('[invariant] Handler error:', error)
    return next(request)  // ALWAYS fails open!
}
```

**Impact:** In edge environments, any error in the RASP (Rust engine crash, parsing error, etc.) results in silent bypass rather than secure failure.

**Remediation:** Add failClosed option consistent with other middlewares.

---

### 🟡 ANALYSIS NOTES (Non-Reproducible/Pattern-Specific)

#### BYP-001: SQL Comment Stripping Bypass (MySQL)
**Status:** ⚠️ **Not Reproduced**  
**Analysis:** The current implementation correctly strips MySQL executable comments (`/*!50000 ... */`). The regex `///*[/*[/*s/]*?/*//g` successfully matches and removes these comments.

**Test Result:**
```
Input:  SELECT * FROM users WHERE id = 1 /*!50000UNION SELECT*/ password FROM admin
Output: SELECT * FROM users WHERE id = 1   password FROM admin
```

**Note:** May still be vulnerable to nested comments or edge cases. Recommend fuzz testing.

---

#### ENC-001: Path Traversal Deep Decode Bypass
**Status:** ⚠️ **Not Reproduced**  
**Analysis:** The current `deepDecodePath()` implementation correctly handles mixed-encoding path traversal attempts.

**Test Results:**
| Input | Output |
|-------|--------|
| `%25%32%65%25%32%66...` | `././etc/passwd` |
| `%252e%252f%252e%252f...` | `./././etc/passwd` |
| `%25252e%25252f...` | `././etc/passwd` |

**Note:** The loop termination condition based on change detection appears to work correctly in tested cases.

---

#### EXP-001: Exception Rule Regex Bypass
**Status:** ⚠️ **Pattern-Specific**  
**Analysis:** The vulnerability depends on the specific regex pattern used in exception rules.

**Test Results:**
- Pattern `//api//` does NOT match `/evilapi/` (slashes prevent substring matching)
- Pattern `/api/` DOES match `/evilapi/` (no delimiters)

**Recommendation:** Document that exception patterns should use path delimiters (`/api/`) rather than simple substrings (`api`).

---

#### MEM-001: Unbounded Memory Growth
**Status:** ⚠️ **Theoretical**  
**Location:** `autonomous-defense.ts:124`, `behavioral.ts:109`

**Analysis:** Multiple Maps used for source tracking have no size limits or eviction policies. While theoretically exploitable for DoS, the practical impact depends on deployment environment memory limits and traffic patterns.

**Recommendation:** Implement LRU eviction with configurable limits as defense in depth.

---

## Attack Chain Scenarios

### Scenario 1: Complete RASP Bypass in Edge Environment
```
1. Use PUT method to bypass body scanning (BODY-001)
2. Spoof X-Forwarded-For to bypass source tracking (HDR-001)  
3. If any error occurs, handler fails open (FC-001)
```

### Scenario 2: Rate Limit Evasion
```
1. Send requests with rotating X-Forwarded-For values (HDR-001)
2. Each request appears to come from different source
3. Bypass rate limiting and behavioral detection
```

---

## Remediation Priority Matrix

| Priority | Finding | Complexity | Impact |
|----------|---------|------------|--------|
| P0 | BODY-001 | Low | Complete body bypass |
| P0 | HDR-001 | Low | Identity spoofing |
| P1 | FC-001 | Low | Fail-open risk |
| P2 | MEM-001 | Medium | DoS potential |

---

## Testing Artifacts

Proof-of-concept tests are provided in: `packages/agent/src/poc_vulnerabilities.test.ts`

Run with:
```bash
npx vitest run packages/agent/src/poc_vulnerabilities.test.ts
```

---

## Appendix: Code References

All findings verified against current HEAD at time of audit.

| Finding | File | Line(s) |
|---------|------|---------|
| BODY-001 | handler.ts | 163-180 |
| HDR-001 | handler.ts | 273-275 |
| FC-001 | handler.ts | 330-335 |
| MEM-001 | autonomous-defense.ts | 124 |

**End of Report**
