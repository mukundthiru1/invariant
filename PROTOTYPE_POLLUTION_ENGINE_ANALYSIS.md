# Security Analysis: Prototype Pollution in JavaScript Detection Pipeline

## Executive Summary

**Severity:** HIGH (Defense-in-Depth Issue)  
**Attack Vector:** Meta-level Prototype Pollution Risk  
**Impact:** Potential Detection Engine Compromise  
**Status:** Partially Mitigated by Modern Node.js, but Code Quality Issue Remains

The INVARIANT detection engine parses untrusted JSON input without explicit prototype pollution protection. While modern Node.js (v20+) provides built-in protections against the most common prototype pollution vectors, the engine lacks defense-in-depth measures that exist in other parts of the codebase (dashboard, agent RASP).

---

## The Vulnerability

### Root Cause

The detection engine's L2 structural evaluators parse JSON from untrusted user input using `JSON.parse()` without a reviver function to strip prototype pollution keys (`__proto__`, `constructor.prototype`). This creates a "do as I say, not as I do" security posture where the engine designed to detect prototype pollution doesn't protect itself against the same attack vector.

### Vulnerable Code Locations

| File | Line | Function | Issue |
|------|------|----------|-------|
| `proto-pollution-evaluator.ts` | 308 | `detectJsonProtoPaths()` | `JSON.parse(fragment)` without reviver |
| `mass-assignment-evaluator.ts` | 171 | `detectFromJson()` | `JSON.parse(raw)` without reviver |
| `nosql-evaluator.ts` | 150, 159 | `extractJsonKeys()` | `JSON.parse()` without reviver |
| `jwt-evaluator.ts` | 50, 73 | JWT parsing | `JSON.parse()` without reviver |
| `supply-chain-evaluator.ts` | 55 | Package manifest parsing | `JSON.parse()` without reviver |

### The Irony

The `proto-pollution-evaluator.ts` file - which is specifically designed to DETECT prototype pollution attacks - is itself using the same unsafe JSON parsing patterns that could theoretically enable such attacks.

---

## Attack Scenarios

### Scenario 1: Direct Prototype Pollution (MITIGATED in Node v20+)

In older Node.js versions, this payload would pollute `Object.prototype`:

```json
{
  "__proto__": {
    "isAdmin": true
  }
}
```

**Current Status:** Modern Node.js treats `__proto__` as a regular property key, preventing direct prototype access during JSON parsing.

### Scenario 2: Recursive Object Traversal Pollution (CONTEXT DEPENDENT)

If the engine's object traversal logic modifies internal state objects using bracket notation with `__proto__` as a key, pollution could still occur:

```typescript
// Hypothetical vulnerable pattern (NOT confirmed in current code)
function processObject(obj, target) {
    for (const [k, v] of Object.entries(obj)) {
        if (typeof v === 'object') {
            target[k] = target[k] || {};  // If k === '__proto__', this pollutes!
            processObject(v, target[k]);
        }
    }
}
```

### Scenario 3: Detection Logic Interference

Even without successful prototype pollution, an attacker could:

1. Send payloads with `__proto__` keys to create unexpected object structures
2. Cause the detection engine to process objects with `__proto__` as a regular property
3. Potentially confuse detection logic that expects standard object shapes

---

## Technical Analysis

### Node.js Version Impact

| Node.js Version | Direct `__proto__` in JSON.parse | `constructor.prototype` | Assignment via bracket notation |
|----------------|----------------------------------|------------------------|--------------------------------|
| < v16 | Vulnerable | Vulnerable | Vulnerable |
| v16 - v18 | Partially protected | Vulnerable | Vulnerable |
| v20+ | Protected | Protected | Still vulnerable* |

\* Bracket notation assignment with `__proto__` as key can still pollute in some contexts

### Code Flow Analysis

```
Input: '{"__proto__":{"isAdmin":true},"test":"value"}'
       ↓
┌─────────────────────────────────────────────────────────────┐
│  Engine.detect() / Engine.analyze()                          │
│  ─────────────────────────────────                           │
│  • No input sanitization before parsing                      │
└─────────────────────────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────────────────────────┐
│  L2 Evaluators Invoke JSON.parse()                           │
│  ─────────────────────────────────                           │
│  1. proto-pollution-evaluator.ts:308                         │
│     JSON.parse(fragment)                                     │
│     → Returns object with __proto__ as regular property      │
│                                                              │
│  2. mass-assignment-evaluator.ts:171                         │
│     JSON.parse(raw)                                          │
│     → Flattens object for analysis                           │
│     → flatObject entries include __proto__.isAdmin           │
│                                                              │
│  3. nosql-evaluator.ts:150,159                               │
│     JSON.parse(...)                                          │
│     → Extracts keys recursively                              │
│     → Keys include __proto__                                 │
└─────────────────────────────────────────────────────────────┘
       ↓
  Result: Detection logic may process unexpected structures
```

### Current Behavior

The engine currently:
1. Parses JSON with `__proto__` keys (safe in Node v20+)
2. Processes objects containing `__proto__` as a property name
3. Flattened results include entries like `{key: "__proto__.isAdmin", value: true}`
4. Detection logic treats these as regular findings (not prototype pollution)

### Why This Is Still a Problem

1. **Defense in Depth:** Security tools should practice what they preach
2. **Future-Proofing:** If Node.js behavior changes, engine becomes vulnerable
3. **Code Quality:** Inconsistent security posture across codebase
4. **Edge Cases:** Complex object merging patterns may still be vulnerable

---

## Proof of Concept

### PoC: Demonstrating the Gap

```typescript
// poc-engine-prototype-gap.ts

console.log('=== INVARIANT Engine Prototype Pollution Gap ===\n');

// What the engine does (vulnerable pattern)
function engineParseUnsafe(json: string): any {
    return JSON.parse(json);  // No reviver!
}

// What it should do (secure pattern)
function engineParseSafe(json: string): any {
    return JSON.parse(json, (key, value) => {
        if (key === '__proto__' || key === 'constructor') {
            return undefined;  // Strip pollution keys
        }
        return value;
    });
}

const maliciousPayload = '{"__proto__":{"isAdmin":true},"normal":"data"}';

console.log('Payload:', maliciousPayload);
console.log();

// Unsafe parse (current engine behavior)
const unsafe = engineParseUnsafe(maliciousPayload);
console.log('Unsafe parse result keys:', Object.keys(unsafe));
console.log('Unsafe parse has __proto__ key:', '__proto__' in unsafe);
console.log();

// Safe parse (recommended)
const safe = engineParseSafe(maliciousPayload);
console.log('Safe parse result keys:', Object.keys(safe));
console.log('Safe parse has __proto__ key:', '__proto__' in safe);
console.log();

// The gap: even though Node.js protects against pollution,
// the engine still processes __proto__ as a regular property
// instead of recognizing it as a potential attack indicator
```

### Expected Output

```
=== INVARIANT Engine Prototype Pollution Gap ===

Payload: {"__proto__":{"isAdmin":true},"normal":"data"}

Unsafe parse result keys: [ '__proto__', 'normal' ]
Unsafe parse has __proto__ key: true

Safe parse result keys: [ 'normal' ]
Safe parse has __proto__ key: false
```

---

## Impact Assessment

### Direct Impacts

| Impact | Severity | Likelihood | Notes |
|--------|----------|------------|-------|
| Prototype Pollution | Low | Low | Mitigated by Node.js v20+ |
| Detection Logic Confusion | Medium | Medium | Engine processes `__proto__` as regular key |
| Code Quality | High | N/A | Inconsistent with security best practices |
| Future Vulnerability | Medium | Unknown | Depends on Node.js changes |

### Attack Complexity

| Factor | Assessment |
|--------|------------|
| Difficulty | LOW - Standard prototype pollution payload |
| Prerequisites | None |
| Current Exploitability | LOW (in Node v20+) |
| Exploitability (Node <20) | HIGH |

---

## Recommended Remediations

### Immediate Fix (Priority: HIGH)

Add a safe JSON parser utility to the engine package:

```typescript
// packages/engine/src/utils/safe-json.ts

/**
 * Reviver function that strips prototype pollution keys.
 * Use this instead of JSON.parse() for all untrusted input.
 */
export function stripPrototypePollution(key: string, value: unknown): unknown {
    // Block __proto__ and constructor keys at any nesting level
    if (key === '__proto__' || key === 'constructor') {
        return undefined;
    }
    return value;
}

/**
 * Safe JSON parse that prevents prototype pollution.
 * Drop-in replacement for JSON.parse() on untrusted input.
 */
export function safeJsonParse(text: string): unknown {
    return JSON.parse(text, stripPrototypePollution);
}

/**
 * Safe JSON parse with explicit type casting.
 */
export function safeJsonParseAs<T>(text: string): T {
    return JSON.parse(text, stripPrototypePollution) as T;
}
```

### Files to Update

1. **proto-pollution-evaluator.ts** (line 308)
   ```typescript
   // BEFORE:
   detections.push(...analyzeJsonObject(JSON.parse(fragment)))
   
   // AFTER:
   detections.push(...analyzeJsonObject(safeJsonParse(fragment)))
   ```

2. **mass-assignment-evaluator.ts** (line 171)
   ```typescript
   // BEFORE:
   const obj = JSON.parse(raw)
   
   // AFTER:
   const obj = safeJsonParse(raw)
   ```

3. **nosql-evaluator.ts** (lines 150, 159)
   ```typescript
   // BEFORE:
   const obj = JSON.parse(input)
   const obj = JSON.parse(frag.text)
   
   // AFTER:
   const obj = safeJsonParse(input)
   const obj = safeJsonParse(frag.text)
   ```

4. **jwt-evaluator.ts** (lines 50, 73)
5. **supply-chain-evaluator.ts** (line 55)

### Additional Evaluators to Audit

- `protocol-attacks.ts`
- `jwt-attacks.ts`
- `websocket-evaluator.ts`
- Any file with `JSON.parse()` on untrusted input

### Long-term Improvements

1. **Linting Rule:** Add ESLint rule to require reviver for JSON.parse on untrusted input
2. **Security Tests:** Add unit tests that verify prototype pollution resistance
3. **Documentation:** Document secure parsing practices for engine developers
4. **CI/CD:** Add security scanning for prototype pollution patterns
5. **Consistency:** Ensure all packages use the same safe parsing utilities

---

## Conclusion

The INVARIANT detection engine has a defense-in-depth gap where it parses untrusted JSON without explicit prototype pollution protection. While modern Node.js (v20+) mitigates the most common attack vectors, the engine should:

1. **Practice what it preaches** - A security engine should be exemplary in its own security
2. **Be future-proof** - Protection shouldn't rely solely on runtime behavior
3. **Be consistent** - The dashboard and agent have protection; the engine should too

The fix is straightforward and adds minimal overhead while significantly improving the engine's security posture.

---

## Evidence

### Evidence 1: Vulnerable Code Location

File: `packages/engine/src/evaluators/proto-pollution-evaluator.ts`
Lines: 303-314

```typescript
function detectJsonProtoPaths(decoded: string): ProtoPollutionDetection[] {
    const detections: ProtoPollutionDetection[] = []
    const fragments = decoded.trim().startsWith('{') ? [decoded] : extractJsonFragments(decoded)
    for (const fragment of fragments) {
        try {
            detections.push(...analyzeJsonObject(JSON.parse(fragment)))  // ← NO REVIVER
        } catch {
            // ignore malformed JSON
        }
    }
    return detections
}
```

### Evidence 2: Existing Protection Elsewhere

File: `packages/dashboard/src/server.ts`
Line: 496

```typescript
return stripPrototypePollution(JSON.parse(str))  // ← PROTECTED
```

### Evidence 3: RASP Protection in Agent

File: `packages/agent/src/rasp/deser.ts`
Lines: 174-183

```typescript
function stripProtoKeys(obj: unknown, depth = 0): unknown {
    if (depth > 10 || !obj || typeof obj !== 'object') return obj
    if (Array.isArray(obj)) return obj.map(item => stripProtoKeys(item, depth + 1))
    const clean: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
        if (key === '__proto__' || key === 'constructor') continue  // ← PROTECTION
        clean[key] = stripProtoKeys(value, depth + 1)
    }
    return clean
}
```

### Evidence 4: Test Coverage Gap

File: `packages/engine/src/engine.test.ts`
Lines: 147-150

```typescript
it('detects proto_pollution', () => {
    const matches = engine.detect("constructor.prototype.isAdmin=true", [])
    expect(matches.some(m => m.class === 'proto_pollution')).toBe(true)
})
```

The existing test only checks for the `constructor.prototype` pattern string, not for prototype pollution via JSON parsing.

---

*Analysis completed: March 2026*  
*Analyst: Claude (AI Security Analyst)*
