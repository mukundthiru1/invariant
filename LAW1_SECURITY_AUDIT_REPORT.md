# LAW 1 (NO STUBS) Security Audit Report
## Invariant Engine Class Compliance Analysis

**Audit Date:** 2026-03-08  
**Auditor:** Automated security analysis  
**Scope:** 45+ invariant class implementations across 8 categories  
**Standard:** LAW 1 — "stub = function that promises X but delivers nothing"

---

## Executive Summary

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 CRITICAL | 2 | Unconditional `detectL2: () => null` stubs |
| 🟠 HIGH | 1 | Severely under-tested (<3 payloads for critical severity) |
| 🟡 MEDIUM | 17 | Static generateVariants (cycling vs dynamic generation) |
| 🟡 MEDIUM | 2 | Empty knownBenign arrays (no FP testing) |
| ⚪ LOW | 30+ | DeepDecode dependency in detect() |

---

## 🔴 CRITICAL VIOLATIONS (Unconditional Null Stubs)

### 1. `xxeInjection` (misc.ts:172)

**Violation Type:** UNCONDITIONAL_NULL_L2  
**LAW 1 Quote:** *"a stub is a function that promises X but delivers nothing"*

```typescript
detectL2: (input: string) => null,  // STUB - promises structural analysis, delivers null
```

**Why This Is Dangerous:**
- XML External Entity (XXE) injection is a critical attack vector (CWE-611)
- The class presents an L2 structural evaluator interface
- Returns null unconditionally → bypasses all structural analysis
- Attackers using novel XXE encoding will bypass detection

**knownPayloads:** 3 (borderline adequate)  
**knownBenign:** 3 (minimal)  
**generateVariants:** Static cycling pattern

### 2. `httpSmuggling` (misc.ts:192)

**Violation Type:** UNCONDITIONAL_NULL_L2  
**Attack Class:** HTTP Request Smuggling (HRS)

```typescript
detectL2: (input: string) => null,  // STUB
```

**Why This Is Dangerous:**
- HTTP smuggling enables cache poisoning, session hijacking, SSRF
- Modern variants (H2.CL, H2.TE) require structural header analysis
- L1 regex cannot reliably detect TE.CL smuggling boundaries
- Unconditional null = complete bypass for structural variants

---

## 🟠 HIGH VIOLATIONS (Under-Tested Critical Classes)

### 3. `authNoneAlgorithm` (auth/index.ts)

**Violation Type:** INSUFFICIENT_TEST_COVERAGE  
**Severity:** CRITICAL (auth bypass)  
**LAW 1 Principle:** Hardened = tested against mutation

```typescript
knownPayloads: [
    'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
    // Only 1 payload for critical auth bypass!
],
```

**Why This Is Dangerous:**
- JWT "alg:none" is a catastrophic auth bypass (CWE-347)
- Single payload = not mutation-tested
- WAFs bypass via: base64 padding variants, whitespace in header, case variations
- Should have 10+ variants minimum for critical auth class

**Secondary Violation:** Static generateVariants
```typescript
generateVariants: (count) => {
    const v = ['eyJhbGciOiJub25l...'];  // Single variant repeated
    const r: string[] = [];
    for (let i = 0; i < count; i++) r.push(v[i % v.length]);
    return r;  // Returns identical array on every call
}
```

---

## 🟡 MEDIUM VIOLATIONS (Static generateVariants)

The following classes use the **static cycling pattern** instead of dynamic variant generation:

```typescript
// PATTERN: Static array with modulo cycling
const r: string[] = [];
for (let i = 0; i < count; i++) r.push(v[i % v.length]);
return r;
```

This violates LAW 1's principle of "generate variants" — it only cycles through known payloads without producing novel variations.

| Class | File | Severity |
|-------|------|----------|
| authNoneAlgorithm | auth/index.ts | CRITICAL |
| authHeaderSpoof | auth/index.ts | HIGH |
| jwtKidInjection | auth/jwt-abuse.ts | CRITICAL |
| jwtJwkEmbedding | auth/jwt-abuse.ts | CRITICAL |
| jwtConfusion | auth/jwt-abuse.ts | CRITICAL |
| ssrfInternalReach | ssrf/index.ts | HIGH |
| ssrfCloudMetadata | ssrf/index.ts | HIGH |
| ssrfProtocolSmuggle | ssrf/index.ts | HIGH |
| pathDotdotEscape | path/index.ts | HIGH |
| pathNullTerminate | path/index.ts | HIGH |
| pathEncodingBypass | path/index.ts | HIGH |
| pathNormalizationBypass | path/index.ts | HIGH |
| deserJavaGadget | deser/index.ts | HIGH |
| deserPhpObject | deser/index.ts | HIGH |
| deserPythonPickle | deser/index.ts | HIGH |
| cmdSeparator | cmdi/index.ts | HIGH |
| cmdSubstitution | cmdi/index.ts | HIGH |
| cmdArgumentInjection | cmdi/index.ts | HIGH |

### Exemplary COMPLIANT Implementation

`sqlStringTermination` (sqli/string-termination.ts) shows proper dynamic generation:

```typescript
generateVariants: (count: number): string[] => {
    const terminators = ["'", '"', '`', "';", "')", "'))"];
    const injections = [' OR ', ' AND ', '; DROP TABLE ', ' UNION SELECT '];
    const suffixes = ['--', '#', '/*', '-- -', ';--', ''];
    const variants: string[] = [];
    for (let i = 0; i < count; i++) {
        const t = terminators[i % terminators.length];
        const inj = injections[i % injections.length];
        const s = suffixes[i % suffixes.length];
        variants.push(`${t}${inj}1${s}`);
    }
    return variants;  // Combinatorial generation produces novel variations
}
```

---

## 🟡 MEDIUM VIOLATIONS (Empty knownBenign)

### 4. `regexDos` (misc.ts)

```typescript
knownBenign: [],  // EMPTY - no false positive testing
```

**Risk:** No validation that benign regex patterns don't trigger detection.

### 5. `massAssignment` (injection/prototype-pollution.ts vs misc.ts)

Note: There are TWO `massAssignment` definitions with different knownBenign arrays. The one in misc.ts has undefined knownBenign (acceptable), but the one in prototype-pollution.ts has minimal coverage.

---

## ⚪ ARCHITECTURAL RISK (DeepDecode Dependency)

### Issue: detect() Functions Depend on deepDecode Preprocessing

**Affected Classes:** 30+ including:
- All SQLi classes (sqlStringTermination, sqlTautology, sqlUnionExtraction, etc.)
- All XSS classes (xssTagInjection, xssEventHandler, etc.)
- All auth classes (jwtKidInjection, jwtConfusion, etc.)
- All path traversal classes

**Pattern:**
```typescript
detect: (input: string): boolean => {
    const d = deepDecode(input);  // CRITICAL DEPENDENCY
    return SOME_REGEX.test(d);    // Will fail on encoded input if deepDecode skipped
}
```

**Risk Scenario:**
1. `detect()` is called directly without `deepDecode()` preprocessing
2. Input contains URL-encoded payload: `%27%20%4F%52%20%31%3D%31%20%2D%2D` (' OR 1=1 --)
3. Regex pattern expects decoded form
4. **Result:** Attack bypasses detection

**LAW 1 Implication:**
The class *promises* to detect its knownPayloads, but if called without the expected preprocessing, encoded variants in knownPayloads would fail to match. This is a coupling violation.

---

## 🟢 EXEMPLARY COMPLIANT IMPLEMENTATIONS

### 1. `jsonSqlBypass` (sqli/json-sql-bypass.ts)

- ✅ 8 knownPayloads with semantic variety
- ✅ 7 knownBenign including edge cases (URLs with = signs)
- ✅ Full L2 implementation with function call extraction
- ✅ Dynamic generateVariants with WAF-A-MoLE mutation operators
- ✅ Formal property documented

### 2. `sqlTautology` (sqli/tautology.ts)

- ✅ 11 knownPayloads (well-tested)
- ✅ Full L2 via detectTautologies()
- ✅ 12 mutation operators for variant generation

### 3. `cmdSeparator` (cmdi/index.ts)

- ✅ 6 knownPayloads
- ✅ Proper L2 via l2CmdSeparator
- ✅ Dynamic combinatorial variant generation (seps × cmds)

---

## Remediation Priority Matrix

| Priority | Class | Fix Required |
|----------|-------|--------------|
| P0 | xxeInjection | Implement detectL2 or remove stub |
| P0 | httpSmuggling | Implement detectL2 or remove stub |
| P1 | authNoneAlgorithm | Add 10+ knownPayloads, implement dynamic generateVariants |
| P2 | All JWT classes | Implement dynamic generateVariants |
| P2 | All SSRF classes | Implement dynamic generateVariants |
| P3 | 17 static generateVariants classes | Convert to combinatorial generation |
| P4 | All detect() functions | Document deepDecode dependency or inline decoding |

---

## Audit Methodology

1. **File Discovery:** Scanned 45+ class files across packages/engine/src/classes/
2. **Stub Detection:** Grepped for `detectL2.*=>.*null` patterns
3. **Payload Counting:** Analyzed knownPayloads array lengths
4. **Variant Analysis:** Classified generateVariants as static cycling vs dynamic
5. **Dependency Mapping:** Traced deepDecode usage in detect() functions
6. **Benign Coverage:** Checked knownBenign array contents

---

## Conclusion

The invariant engine has **2 CRITICAL violations** that directly contravene LAW 1's prohibition on stubs. These represent exploitable gaps in XXE and HTTP smuggling detection.

Additionally, **authNoneAlgorithm** presents severe under-testing risk for a critical auth bypass class.

The widespread use of **static generateVariants** (17 classes) reduces the engine's effectiveness against mutation-based WAF bypasses.

**Recommended Actions:**
1. Immediately implement proper detectL2 for xxeInjection and httpSmuggling
2. Expand authNoneAlgorithm test coverage to 10+ payloads with mutation operators
3. Migrate static generateVariants to combinatorial generation patterns
4. Document deepDecode dependency in class interfaces

---

*Report generated for security hardening compliance verification.*
