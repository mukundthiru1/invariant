# RASP Agent & Edge Sensor — Comprehensive Security Audit Report

**Audit Date:** 2026-03-09  
**Scope:** `packages/agent`, `packages/edge-sensor`, `packages/engine`  
**Auditor:** Automated Code Analysis  

---

## Executive Summary

This audit examines the Invariant security system's RASP (Runtime Application Self-Protection) Agent and Edge Sensor components across five critical security dimensions: interception coverage gaps, bypass vectors, performance characteristics, crash vulnerabilities, and enterprise-grade feature gaps.

**Overall Risk Assessment: MEDIUM-HIGH**
- **RASP Agent:** Good coverage for common libraries but significant gaps in database driver support, bundler compatibility issues, and missing parameterized query enforcement.
- **Edge Sensor:** Comprehensive 14-layer detection pipeline with sophisticated evasion handling, but body handling limitations and static asset bypasses create exploitable gaps.
- **Engine:** Well-designed L1/L2/L3 detection with algebraic composition rules, but regex backtracking risks and unbounded inputs in some paths present DoS vectors.

---

## 1. RASP Agent — Interception Coverage Analysis

### 1.1 SQL Injection Protection

**Current Coverage (GOOD):**
- `pg` (PostgreSQL) — Client/Pool/Query wrappers
- `mysql2` — Connection/Query wrappers  
- `better-sqlite3` — Database wrapper

**Critical Gaps (HIGH RISK):**
| Driver | Risk | Impact |
|--------|------|--------|
| `tedious` (MSSQL) | HIGH | Enterprise SQL Server apps unprotected |
| `oracledb` (Oracle) | HIGH | Enterprise Oracle deployments unprotected |
| `mongodb` native | MEDIUM | NoSQL injection not detected |
| `ioredis` | LOW | Command injection via Redis protocol |
| `prisma` | MEDIUM | ORM queries bypass detection |
| `sequelize` | MEDIUM | Query builder patterns may evade |
| `typeorm` | MEDIUM | Query builder patterns may evade |
| `knex` | MEDIUM | Raw SQL executions may not be caught |

**Non-Parameterized Query Detection:**
```typescript
// Current implementation (weak heuristic)
const hasInlineData = /=\\\\\\*['"][^'"]*['"]|=\\\*\*\d+/.test(sql)
const hasPlaceholders = /\\\$\\d+|\\\?|:[a-zA-Z_]+/.test(sql)
```

**Issue:** This only warns to console — no blocking, no signal generation. An application could be using 100% non-parameterized queries and the agent would only log warnings.

### 1.2 Command Execution Protection

**Current Coverage (GOOD):**
- `child_process` — `exec`, `execSync`, `spawn`, `spawnSync`
- VM module hooks — `runInContext`, `runInNewContext`, `runInThisContext`
- `worker_threads.Worker` proxy
- `inspector.Session.post` (Runtime.evaluate detection)
- `process._linkedBinding` (spawn_sync detection)

**Gaps (MEDIUM RISK):**
| Vector | Status | Notes |
|--------|--------|-------|
| `node:child_process` via dynamic import | PARTIAL | May race with wrapper initialization |
| ` Bun.spawn` (Bun runtime) | NOT COVERED | Bun runtime gaining adoption |
| `Deno.run` | NOT COVERED | Deno runtime not supported |
| WebAssembly instantiation | NOT COVERED | wasm-based sandbox escape |

### 1.3 File System Protection

**Current Coverage (GOOD):**
- `fs.readFile`, `readFileSync`, `createReadStream`
- `fs.writeFile`, `writeFileSync`, `createWriteStream`
- `fs.open`, `openSync`
- Path traversal detection with multi-layer URL decoding

**Gaps (LOW-MEDIUM RISK):**
- `fs/promises` methods not explicitly wrapped
- `fs.rm`, `fs.unlink` (destructive operations without read/write)
- Symbolic link operations (`fs.symlink`, `fs.readlink`)

### 1.4 HTTP/Network Protection

**Current Coverage (ADECUATE):**
- Global `fetch` wrapper for SSRF detection
- Internal IP range blocking
- Cloud metadata endpoint detection

**Gaps (MEDIUM RISK):**
- `http.request`, `https.request` not explicitly wrapped (relies on global fetch)
- `node:net` socket connections bypass SSRF detection
- WebSocket client connections not wrapped
- gRPC client detection is basic regex-only

### 1.5 Node.js/Bundler Compatibility Issues

**CRITICAL: Frozen Intrinsics (Node 20+)**
```javascript
// Node 20+ may freeze built-in modules
Object.freeze(require('child_process'))
Object.freeze(require('fs'))
```

The agent's monkey-patching approach will fail silently or throw on frozen intrinsics. No detection of frozen state, no fallback strategy.

**Bundler Issues:**
| Bundler | Issue | Impact |
|---------|-------|--------|
| Webpack | Module inlining before RASP init | HIGH — wrapped module never used |
| esbuild | Tree-shaking may remove "unused" patches | HIGH — patches eliminated |
| Rollup | Same as above | HIGH |
| Vite | ES modules load before CommonJS hooks | MEDIUM |

**No explicit handling found for:**
- ES module import interception
- Import maps
- Dynamic import wrapping

---

## 2. Edge Sensor — Bypass Vector Analysis

### 2.1 Body Handling Bypasses

**32KB Body Limit Bypass:**
```typescript
// packages/edge-sensor/src/modules/body-analysis.ts:51
const MAX_BODY_SIZE = 32_768
```

**Attack:** An attacker can send a 33KB+ request body with the malicious payload at the end. The sensor skips body analysis entirely, passing the payload to the origin.

**Exploit Example:**
```bash
curl -X POST https://target.com/api \
  -H "Content-Type: application/json" \
  -d "$(python3 -c 'print("A"*32768 + "'\"'" union select * from users --")')"
```

**Streaming Request Bypass:**
- `Transfer-Encoding: chunked` with body content after headers are processed
- No streaming body analysis — only buffered bodies are checked

### 2.2 Static Asset Bypass

**packages/edge-sensor/src/index.ts (lines 145-152):**
```typescript
// Skip static asset paths — these shouldn't contain attack payloads
const pathLower = path.toLowerCase()
if (\\.css$|\\.js$|\\.png|\\.jpg|\\.gif|\\.svg|\\.ico|\\.woff|\\.ttf|\\.eot\\/i.test(pathLower)) {
    // Static asset — skip full analysis for performance
    // Still apply rate limiting but skip signature scans
    if (mode === 'enforce') {
        return withHeaders(await fetch(request))
    }
}
```

**CRITICAL BYPASS:** An attacker can send attack payloads in query strings of static assets:
```
GET /style.css?foo=' UNION SELECT * FROM passwords-- HTTP/1.1
```

The request bypasses ALL signature scans, invariant detection, and body analysis. If the application reflects the query parameter, the SQLi executes.

### 2.3 Multipart Form Data Bypass

**Current Implementation (body-analysis.ts:315-339):**
```typescript
export function extractFromMultipart(raw: string): string[] {
    const parts = raw.split(/------?[a-zA-Z0-9]+/)
    for (const part of parts) {
        // Skip parts that look like file uploads
        if (part.includes('Content-Type:') && !part.includes('text/plain')) continue
        // ...
    }
}
```

**Bypass:** The multipart parser is extremely basic:
1. Boundary detection regex may fail on valid multipart
2. Binary file detection is trivially bypassed: `Content-Type: text/plain; filename=shell.php`
3. No content-disposition parsing for filename injection attacks

### 2.4 WebSocket Bypass Vectors

**Binary Frame Bypass:**
```typescript
// packages/edge-sensor/src/index.ts (WebSocket handler)
server.addEventListener('message', event => {
    if (typeof event.data === 'string') {
        // Only string frames analyzed — binary frames pass through
        const matches = analyzeWebSocketFrameBody(event.data, engine)
        // ...
    }
    ws.send(event.data)
})
```

**Attack:** Send binary WebSocket frames containing serialized attack payloads (CBOR, BSON, msgpack) that are deserialized by the origin application. No inspection of binary payloads.

**Frame Fragmentation Bypass:**
- No handling of fragmented WebSocket frames
- A large payload split across multiple continuation frames may evade size checks

### 2.5 Header Abuse Risks

**Host Header Injection:**
The sensor trusts the `Host` header for various decisions but doesn't validate against a whitelist. SSRF via `Host: 169.254.169.254` in conjunction with path-based routing could bypass protections.

**X-Forwarded-* Trust:**
No validation of forwarded headers. An attacker can set:
```
X-Forwarded-For: 127.0.0.1
```
And potentially bypass IP-based rate limiting or detection.

### 2.6 Encoding Bypass Resilience

**Good Coverage:**
- 6-layer deep decoding (MAX_DECODE_DEPTH = 6)
- URL, HTML entity, Unicode escape, hex escape, base32, ROT13 decoding
- Punycode domain decoding
- Homoglyph normalization (Cyrillic/Greek → Latin)
- Invisible character stripping (zero-width, BIDI, tags block)
- SQL comment normalization

**Potential Gaps:**
- No JavaScript escape sequence decoding (`\x41`, `\u0041` in JS context)
- No template literal encoding detection
- No CSS escape sequence handling

---

## 3. Performance Impact Analysis

### 3.1 Edge Sensor Performance Characteristics

**Request Body Cloning Overhead:**
```typescript
// packages/edge-sensor/src/modules/body-analysis.ts:114
const clone = request.clone()
const rawBody = await clone.text()
```

**Issue:** Every non-GET request is cloned and read into memory. For a 32KB body limit:
- Memory overhead: 64KB per request (original + clone)
- At 1000 RPS: 64MB/s memory churn
- No streaming — full buffer materialization

**Regex Performance — L1 Signatures:**

| Pattern | Risk | Notes |
|---------|------|-------|
| `union\\s+(all\\s+)?select\\s` | LOW | Well-anchored |
| `\\$\\([^)]*(?:cat\\|ls\\|id)` | MEDIUM | Unbounded `[^)]*` can cause backtracking |
| `<svg[\\s/].*?on\\w+\\s*=` | MEDIUM | Lazy quantifier with nested pattern |
| `\\$\\{[^}]*(?:Runtime\\|ProcessBuilder)` | MEDIUM | Unbounded `[^}]*` |

### 3.2 Engine Performance Characteristics

**L1 (Regex) Detection:**
- Fast path: O(n) single-pass regex in most cases
- 60+ class modules loaded at startup
- No lazy loading of class modules

**L2 (Structural) Detection:**
```typescript
// SQL Expression Evaluator
tokens.filter(t => t.type !== 'WHITESPACE')  // O(n) filter
parseExpression(tokens)  // Recursive descent parsing
```

**Complexity:** O(n) tokenization + O(m) parsing where m = token count. Well-bounded with 4096 char input limit.

**L3 (Decomposition) Detection:**
```typescript
// No explicit bounds checking found for decomposition
const decoded = deepDecode(input)  // Recursively decodes
deepDecode(input, depth) // depth bounded to 6
```

Input size bounded to 8192 bytes, depth to 6 levels. Good DoS prevention.

### 3.3 RASP Performance Impact

**Per-Query Overhead:**
```typescript
// SQL wrapper
engine.detectDeep(query, [], 'sql')  // Full L1+L2+L3 pipeline
```

Every SQL query triggers deep detection. For high-throughput applications:
- Estimated 0.5-2ms overhead per query
- No caching of safe query patterns
- No query hashing for duplicate detection

**Memory Growth:**
```typescript
// BehavioralAnalyzer
private sources: Map<string, SourceWindow> = new Map()
```

Unbounded Map growth for source tracking. No TTL on entries, only decay check every 10 seconds.

---

## 4. Engine Crash / ReDoS Vulnerability Assessment

### 4.1 Regex Backtracking Analysis

**HIGH RISK Patterns:**

```typescript
// packages/engine/src/classes/sqli/error-oracle.ts:8
/CONVERT\\s*\\(.*USING/i
```
The `\\s*` after CONVERT combined with `.*` can cause catastrophic backtracking on crafted input.

```typescript
// packages/engine/src/classes/sqli/tautology.ts:53
/\\bx=x\\b.*\\bcss\\b/i
```
`.*` between two patterns can backtrack exponentially.

**MEDIUM RISK Patterns:**
```typescript
// L1 signatures with unbounded wildcards
/\\$\\([^)]*(?:cat\\|ls\\|id)/  // [^)]* is greedy
/<svg[\\s/].*?on\\w+\\s*=/      // lazy but with alternation
```

### 4.2 Input Size Validation

**GOOD (Bounded):**
- `encoding.ts`: MAX_INPUT_SIZE = 8192
- `sql-expression-evaluator.ts`: MAX_INPUT = 4096
- `body-analysis.ts`: MAX_BODY_SIZE = 32768

**MISSING BOUNDS:**
- WebSocket frame analysis (no explicit limit)
- gRPC payload analysis (no explicit limit)
- Header value analysis (relies on CF Worker limits)

### 4.3 Recursion Safety

**Bounded Recursion:**
```typescript
// encoding.ts
deepDecode(input, depth) // depth <= MAX_DECODE_DEPTH (6)

// protocol normalization
normalizeProtocolKeyword(input, keyword, depth) // depth <= 10
```

**Potential Unbounded Recursion:**
```typescript
// SQL CASE WHEN parsing
parseCaseWhen(tokens, start) // recursive descent, depth not explicitly bounded
```

### 4.4 Memory Exhaustion Vectors

**Signal Buffer:**
```typescript
// edge-sensor/index.ts
signalBuffer.add(signal)
if (signalBuffer.shouldFlush()) {
    ctx.waitUntil(signalBuffer.flush())
}
```

Buffer flush is async — during a flood, signals accumulate in memory until flush completes.

**Behavioral Tracker:**
```typescript
// edge-sensor/modules/behavior-tracker.ts
export class BehaviorTracker {
    private requests = new Map<string, number[]>()
    private paths = new Map<string, Set<string>>()
}
```

Maps grow unbounded per source hash during high-volume attacks.

---

## 5. Enterprise Feature Gap Analysis

### 5.1 Parameterized Query Enforcement

**Current State:** Only heuristic warning, no enforcement.

**Gap:** No runtime detection of actually-unsafe vs actually-safe queries. An enterprise needs:
- Query structure hashing to identify repeat offenders
- Integration with ORMs to detect unsafe raw query usage
- Blocking mode for non-parameterized queries

### 5.2 Session Fingerprinting

**Current State:** Basic source hash tracking (likely IP-based).

**Gap:** No advanced session fingerprinting:
- TLS fingerprinting (JA3/JA4)
- HTTP/2 fingerprinting
- Browser canvas/webgl fingerprinting
- Behavioral biometrics

**Impact:** Attackers can rotate IPs (VPN, proxies, residential proxies) to evade reputation tracking.

### 5.3 Rate Limiting Granularity

**Current State (Edge Sensor):**
```typescript
// Basic rate limiting with configurable threshold
const rateLimitKey = `rate_limit:${sourceHash}`
```

**Gaps:**
- No path-specific rate limiting (e.g., login endpoint vs static assets)
- No per-user rate limiting (when auth context available)
- No progressive penalty (always same delay/block)
- No integration with external rate limiters (Redis, etc.)

### 5.4 Behavioral Tracking Limitations

**Current State:** 
```typescript
// packages/agent/src/behavioral.ts
export class BehavioralAnalyzer {
    private sources: Map<string, SourceWindow>
    // 60 second window, 50 request threshold
}
```

**Gaps:**
- No cross-request correlation (session-level attack chain detection)
- No device fingerprint persistence
- No geo-velocity checks (impossible travel)
- No time-of-day pattern analysis

### 5.5 Attack Chain Detection

**Current State:** Good chain detection exists in `chain-detector.ts` and `autonomous-defense.ts`.

**Gap:** Chain detection is per-sensor/per-agent. No distributed chain correlation across:
- Multiple edge sensors
- Edge sensor + RASP agent together
- Multiple RASP agents in microservices

### 5.6 Compliance & Audit Features

**Gaps:**
- No PCI DSS specific detection rules (card number patterns in logs)
- No GDPR data flow tracking
- No SOC 2 audit trail generation
- No retention policy enforcement for signals

### 5.7 Integration Gaps

**Missing Enterprise Integrations:**
| System | Status | Use Case |
|--------|--------|----------|
| Splunk | NOT PRESENT | SIEM integration |
| Datadog | NOT PRESENT | APM/security correlation |
| PagerDuty | NOT PRESENT | Incident response |
| Slack/Teams | NOT PRESENT | Alerting |
| Jira | NOT PRESENT | Ticket creation |
| Threat Intel Feeds | PARTIAL | IOC correlation exists but limited feeds |

### 5.8 Deployment & Operations

**Gaps:**
- No Kubernetes admission controller for RASP injection
- No Istio/Envoy WASM plugin for service mesh
- No Terraform provider for edge sensor configuration
- No configuration hot-reloading (requires restart)

---

## Recommendations Summary

### Immediate (Critical)
1. **Fix static asset bypass** — Apply signature scanning to static asset query strings
2. **Fix body size bypass** — Analyze truncated bodies or block oversized requests with unknown content
3. **Add frozen intrinsics detection** — Warn/error when monkey-patching fails on Node 20+

### Short-term (High Priority)
1. Extend SQL RASP to cover `tedious`, `oracledb`, `prisma` drivers
2. Add binary WebSocket frame analysis
3. Implement proper multipart form parsing
4. Fix regex backtracking vulnerabilities in error-oracle and tautology patterns
5. Add bounds checking to CASE WHEN parsing

### Medium-term
1. Build bundler-aware initialization (webpack/esbuild/rollup plugins)
2. Implement distributed chain correlation
3. Add enterprise SIEM integrations
4. Implement TLS/HTTP2 fingerprinting
5. Add query pattern caching for performance

### Long-term
1. Build WASM-based detection for Edge (lighter weight)
2. Implement ML-based anomaly detection for L3
3. Build comprehensive compliance rule packs
4. Add eBPF-based kernel-level monitoring as alternative to monkey-patching

---

## Appendix: Critical Code Locations

| Issue | File | Line(s) |
|-------|------|---------|
| Static asset bypass | edge-sensor/src/index.ts | 145-152 |
| Body size limit | edge-sensor/src/modules/body-analysis.ts | 51, 101-110 |
| Binary WebSocket bypass | edge-sensor/src/index.ts | WebSocket handler |
| ReDoS: error-oracle | engine/src/classes/sqli/error-oracle.ts | 8 |
| ReDoS: tautology | engine/src/classes/sqli/tautology.ts | 53 |
| Unbounded behavior maps | agent/src/behavioral.ts | 108-114 |
| Frozen intrinsics risk | agent/src/rasp/*.ts | All monkey-patching |

---

*End of Audit Report*
