# INVARIANT Edge Sensor Security Audit Report

**Date:** 2026-03-07  
**Scope:** Cloudflare Worker codebase (`src/` directory)  
**Version:** 8.0.0  
**Auditor:** Kimi Code (automated analysis)

---

## Executive Summary

This audit identifies **47 security findings** across the edge-sensor codebase, categorized as:

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 **Critical** | 4 | Race conditions, timeouts missing on critical paths, info disclosure |
| 🟠 **High** | 8 | Silent failures, hardcoded secrets, ReDoS risks, logging leaks |
| 🟡 **Medium** | 18 | Hardcoded thresholds, magic numbers, configuration gaps |
| 🟢 **Low** | 17 | Best practice violations, non-optimal patterns |

### Key Findings

1. **Race Condition in Module Initialization** - Multiple concurrent requests during cold start can corrupt shared state
2. **Missing Fetch Timeouts** - Origin fetches lack AbortSignal, can hang indefinitely
3. **Silent KV Failures** - KV write failures swallowed without alerting
4. **Information Disclosure** - Console warnings leak configuration state
5. **Fail-Open Design** - Multiple silent failures result in defense bypass

---

## 🔴 Critical Severity

### C1: Race Condition in Module-Level State Initialization

**Location:** `src/index.ts` lines 437-458

```typescript
// Module-level shared state (persists across requests in same isolate)
let initialized = false
let rulesInitialized = false
// ... behaviorTracker, engine, chainCorrelator, signalBuffer, stateManager

async function initializeModules(env: Env) {
    if (initialized) return  // Race: multiple requests pass this simultaneously
    // ... initialization logic
    try {
        await stateManager.initialize()
    } catch {
        // Silent failure - sensor runs without state
        initialized = true
    }
}
```

**Risk:** Multiple concurrent requests during cold start can trigger parallel initialization, leading to:
- State corruption
- Duplicate KV operations
- Inconsistent configuration
- Memory leaks

**Recommendation:** Implement proper locking or atomic initialization pattern.

---

### C2: Missing Timeout on Origin fetch()

**Location:** `src/index.ts` lines 623, 664, 672, 1148

```typescript
// Line 623
const response = await fetch(request)

// Line 664, 672
const originResponse = await fetch(originRequest)

// Line 1148 (WebSocket upgrade)
return fetch(request)  // No timeout, can hang forever
```

**Risk:** No AbortSignal/timeout means requests to slow/unresponsive origins hang indefinitely, exhausting Worker CPU quota and causing cascade failures.

**Recommendation:** Add `AbortSignal.timeout()` with configurable timeout (e.g., 30s default).

---

### C3: Cache Stampede on Cold Start

**Location:** `src/index.ts` lines 468-475

```typescript
const [pathRules, ipRules, rateLimits, responseHeaders] = await Promise.all([
    getPathRulesConfig(env.SENSOR_STATE),
    getIpRulesConfig(env.SENSOR_STATE),
    getRateLimitsConfig(env.SENSOR_STATE),
    getResponseHeadersConfig(env.SENSOR_STATE),
])
```

**Risk:** Cold start triggers N parallel KV reads. Under high load, concurrent isolates each execute parallel reads, causing KV quota exhaustion.

**Recommendation:** Implement request coalescing or staggered initialization.

---

### C4: Fail-Open Rate Limiting

**Location:** `src/index.ts` lines 657-661

```typescript
try {
    const rateLimitResult = await checkRateLimit(...)
    // ...
} catch {
    // Rate limiting is fail-open — if check fails, we don't block
}
```

**Risk:** Any error in rate limiting (KV failure, timeout, bug) results in unlimited requests.

**Recommendation:** Make fail-closed configurable; at minimum, log and alert on rate limit failures.

---

## 🟠 High Severity

### H1: Silent KV Write Failures

**Location:** `src/index.ts` lines 178-183, 192-198

```typescript
// Line 178-183
} catch {
    // Silently ignore persist errors — sensor continues operating
}

// Line 192-198
try {
    // State persistence
} catch {
    // Ignore state persist errors
}
```

**Risk:** State loss, data inconsistency, undetected operational issues. KV write failures give no indication to operators.

**Recommendation:** Log errors to external monitoring; implement circuit breaker.

---

### H2: Information Disclosure via console.warn

**Location:** `src/index.ts` line 1495

```typescript
console.warn('Evidence sealer disabled: SEAL_SECRET not configured or too short')
```

**Risk:** Leaks configuration state to logs which may be accessible to attackers with log access.

**Recommendation:** Remove or downgrade to debug-only logging.

---

### H3: Potential ReDoS in Regex Compilation

**Location:** `src/modules/ioc-correlator.ts` lines 91-106, `src/modules/rule-sync.ts` lines 142-154

```typescript
// IOC patterns compiled without adequate safety checks
case 'user_agent_sig': {
    const safeRegex = this.compileRegexSafe(entry.value)
    if (safeRegex) {
        this.uaSignatures.push({ pattern: safeRegex, entry })
    }
}
```

**Risk:** Regex compilation happens in hot path; complex patterns can cause CPU exhaustion.

**Recommendation:** Pre-compile regexes; add timeout wrapper around compilation.

---

### H4: Missing Input Validation on Dynamic Rules

**Location:** `src/modules/rule-loader.ts` lines 37-39

```typescript
const bundle: EncryptedRuleBundle = JSON.parse(raw, (k, v) =>
    k === '__proto__' || k === 'constructor' || k === 'prototype' ? undefined : v)
if (bundle.v !== 1 || bundle.expiresAt <= Date.now()) {
```

**Risk:** `expiresAt` is not validated for reasonable bounds; malicious value could cause immediate expiration or never-expire.

**Recommendation:** Validate `expiresAt` is within acceptable window (e.g., 1 min - 90 days).

---

### H5: Hardcoded Retry Logic Without Backoff

**Location:** `src/modules/signal-uploader.ts` lines 78-123

```typescript
export async function flushSignalBuffer(...): Promise<...> {
    try {
        // ...
        const response = await fetch(ingestUrl, {...})
        if (!response.ok) {
            return { uploaded: 0, failed: true }
        }
    } catch {
        return { uploaded: 0, failed: true }
    }
}
```

**Risk:** Immediate failure on first error; no retry logic for transient failures.

**Recommendation:** Implement exponential backoff retry for 5xx errors.

---

### H6: Weak HSTS Default (1 year vs preload requirement)

**Location:** `src/modules/response-audit.ts` lines 64-91

```typescript
const maxAge = parseInt(value.match(/max-age=(\d+)/i)?.[1] ?? '0')
if (maxAge < 31536000) {  // Exactly 1 year
    return {
        finding: `HSTS max-age too short (${maxAge}s, need ≥31536000)`,
        // ...
    }
}
```

**Risk:** Preload list requires 2 years (63072000); 1-year recommendation is insufficient for preload.

**Recommendation:** Update threshold to 63072000 seconds.

---

### H7: PoW Challenge Without Request Timeout

**Location:** `src/layers/signal-buffer.ts` lines 147-149

```typescript
const resp = await fetch(challengeUrl, {
    headers: { 'Authorization': `Bearer ${this.apiKey}` },
})  // No AbortSignal timeout
```

**Risk:** Challenge fetch can hang, blocking signal submission.

**Recommendation:** Add `AbortSignal.timeout(5000)`.

---

### H8: Missing Bounds Check on Nonce Iteration

**Location:** `src/layers/signal-buffer.ts` lines 56-81

```typescript
async function solveChallenge(challenge: string, difficulty: number): Promise<string> {
    // ...
    while (true) {
        // ...
        if (nonce > 100_000_000) {
            throw new Error(`PoW solve exceeded max iterations`)
        }
    }
}
```

**Risk:** `difficulty` parameter not validated; extremely high difficulty causes infinite loop until 100M iterations.

**Recommendation:** Validate `difficulty <= 26` before solving.

---

## 🟡 Medium Severity

### M1-M18: Hardcoded Constants (Magic Numbers)

| Location | Value | Context | Recommendation |
|----------|-------|---------|----------------|
| `src/index.ts:43` | `60_000` | Config cache TTL | Make configurable via env |
| `src/index.ts:47-49` | Various | KV key prefixes | Extract to configuration |
| `src/index.ts:126` | `{ requests_per_minute: 100, burst: 20 }` | Rate limit defaults | Configurable thresholds |
| `src/index.ts:943` | `5 + Math.random() * 45` | Jitter range | Document timing oracle defense |
| `src/index.ts:970` | `3` | Unstable origin threshold | Configurable |
| `src/index.ts:985` | `0.6` | Circuit breaker threshold | Configurable |
| `src/index.ts:1048` | `5_000` | Token refill rate | Configurable |
| `src/index.ts:1057` | `24 * 60 * 60 * 1000` | Daily interval | Document or make configurable |
| `src/modules/body-analysis.ts:13` | `32_768` | Max body size | Configurable |
| `src/modules/body-analysis.ts:14` | `200` | Max extracted values | Configurable |
| `src/modules/body-analysis.ts:15` | `10` | Max JSON depth | Configurable |
| `src/modules/body-analysis.ts:71,74` | `8192`, `1024` | String length limits | Configurable |
| `src/modules/application-model.ts:11-14` | Various | MAX_ENDPOINTS, etc. | Configurable limits |
| `src/modules/application-model.ts:22` | `7 * 24 * 60 * 60 * 1000` | Stale threshold (7 days) | Configurable |
| `src/modules/signal-uploader.ts:169` | `3_600_000` | Hour rounding | Document privacy rationale |
| `src/layers/encoding.ts:9-10` | `6`, `8192` | Decode depth/size | Configurable |
| `src/layers/signal-buffer.ts:77` | `100_000_000` | PoW max iterations | Document + configurable |
| `src/layers/l2-behavior.ts:14-19` | Various | Thresholds | Configurable |

---

## 🟢 Low Severity

### L1-L17: Code Quality & Best Practices

| ID | Location | Issue | Recommendation |
|----|----------|-------|----------------|
| L1 | `src/index.ts:404` | `let isShuttingDown = false` | Not used; remove or implement |
| L2 | `src/index.ts:942` | Comment typo | "jitter prevents synchronized retries" |
| L3 | `src/modules/blast-radius.ts` | Hardcoded scoring weights | Extract to configuration |
| L4 | `src/modules/blast-radius.ts` | Regex patterns hardcoded | Make configurable |
| L5 | `src/modules/cve-stack-correlation.ts` | Static TECH_CPE_MAP | Fetch from remote config |
| L6 | `src/modules/reactivation-engine.ts` | Rules hardcoded | Make configurable |
| L7 | `src/modules/signal-dedup.ts:1-4` | FNV constants duplicated | Share with campaign-fingerprint |
| L8 | `src/modules/threat-scoring.ts` | Thresholds hardcoded | Configurable scoring |
| L9 | `src/layers/l3-fingerprint.ts` | Regex patterns | Extract and make configurable |
| L10 | `src/layers/signal-buffer.ts:152` | `console.error` in production | Use structured logging |
| L11 | `src/layers/signal-buffer.ts:170` | `console.error` in production | Use structured logging |
| L12 | `src/layers/signal-buffer.ts:183` | `console.error` in production | Use structured logging |
| L13 | `src/layers/signal-buffer.ts:213` | `console.error` in production | Use structured logging |
| L14 | `src/modules/rule-sync.ts:150` | `console.warn` for regex fail | Consider structured logging |
| L15 | `src/modules/sensor-state.ts:178-186` | DEFAULT_CONFIG hardcoded | Accept override from env |
| L16 | `src/index.ts` | Multiple `any` casts | Add proper typing |
| L17 | Various | Missing JSDoc on public methods | Add documentation |

---

## Security Architecture Observations

### Positive Security Controls

1. **SAA-091: Prototype Pollution Guards** - Multiple locations use reviver functions to prevent prototype pollution
2. **SAA-060: Deterministic IP Hashing** - Daily salt derived from API key ensures consistent hashing across isolates
3. **SAA-087: ReDoS Protection** - Regex patterns validated before compilation
4. **SAA-052: O(1) Lookup Index** - Reputation table uses Map for constant-time lookups
5. **Privacy-Preserving Design** - SHA-256 hashed IPs, no PII persistence, hourly-rounded timestamps

### Defense in Depth Gaps

1. **No Alerting on Silent Failures** - KV failures, rate limit errors not surfaced
2. **No Circuit Breaker** - Repeated failures don't trigger fallback mode
3. **No Health Check Endpoint** - No way to verify sensor operational status
4. **No Metrics Export** - Prometheus/StatsD integration missing

---

## Compliance Notes

### SAA References Found

| Reference | Location | Description |
|-----------|----------|-------------|
| SAA-072 | `src/index.ts` | Cookie name inspection only |
| SAA-073 | `src/layers/signal-buffer.ts` | PoW challenges for signal submission |
| SAA-060 | `src/layers/utils.ts` | Deterministic IP hashing |
| SAA-091 | Multiple | Prototype pollution guards |
| SAA-093 | `src/modules/ioc-correlator.ts` | ReDoS defense |
| SAA-087 | `src/modules/rule-sync.ts` | ReDoS pattern detection |
| SAA-052 | `src/modules/sensor-state.ts` | O(1) reputation lookup |
| SAA-053 | `src/modules/sensor-state.ts` | Config validation |
| SAA-043 | `src/layers/l1-signatures.ts` | JWT alg=none detection with reviver |
| SAA-058 | `src/layers/encoding.ts` | Protocol keyword normalization |
| SAA-062 | `src/layers/utils.ts` | No X-Invariant-Action header |
| SAA-003 | `src/layers/utils.ts` | No CORS headers on block |
| SAA-036 | `src/modules/rule-sync.ts` | Auth headers for rule fetch |
| SAA-037 | `src/modules/rule-sync.ts` | Regex compilation caching |

---

## Recommendations Summary

### Immediate Actions (Critical/High)

1. **Fix race condition** in module initialization with proper locking
2. **Add timeouts** to all fetch() calls with configurable durations
3. **Implement alerting** for KV failures and rate limit errors
4. **Remove or guard** console.warn information disclosures
5. **Validate difficulty** parameter in PoW challenge solving

### Short-term (Medium)

1. Extract all hardcoded thresholds to environment configuration
2. Add request coalescing for KV reads on cold start
3. Implement retry with exponential backoff for signal uploads
4. Update HSTS recommendation to 2 years for preload compliance

### Long-term (Low)

1. Add structured logging/metrics export (Prometheus)
2. Implement health check endpoint
3. Add circuit breaker pattern for external dependencies
4. Complete JSDoc documentation

---

*Report generated by automated security analysis. Manual review recommended for critical findings.*
