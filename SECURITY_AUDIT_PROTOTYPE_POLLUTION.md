# Security Audit Report: Prototype Pollution in Detection Engine

**Audit Date:** March 2026  
**Auditor:** Claude (AI Security Analyst)  
**Scope:** INVARIANT Detection Engine (`packages/engine/src`)  
**Classification:** Defense-in-Depth Issue / Code Quality Gap

---

## Executive Summary

### Findings Overview

| Severity | Finding | Status |
|----------|---------|--------|
| MEDIUM | JSON.parse without prototype pollution protection in evaluators | Confirmed |
| LOW | Inconsistent security posture across codebase | Confirmed |
| INFO | Missing linting rules for secure JSON parsing | Identified |

### Key Discovery

The INVARIANT detection engine, which is designed to identify prototype pollution attacks in user applications, does not apply the same security measures to its own JSON parsing. While modern Node.js (v20+) provides built-in protections, this creates a "do as I say, not as I do" security posture that should be addressed for defense-in-depth.

---

## Detailed Findings

### Finding 1: Unprotected JSON.parse() in Evaluators

**Severity:** MEDIUM  
**Confidence:** HIGH

#### Description

Multiple L2 structural evaluators in the engine package parse untrusted JSON input using `JSON.parse()` without a reviver function to strip prototype pollution keys (`__proto__`, `constructor`).

#### Locations

| File | Line | Code |
|------|------|------|
| `proto-pollution-evaluator.ts` | 308 | `JSON.parse(fragment)` |
| `mass-assignment-evaluator.ts` | 171 | `JSON.parse(raw)` |
| `nosql-evaluator.ts` | 150 | `JSON.parse(input)` |
| `nosql-evaluator.ts` | 159 | `JSON.parse(frag.text)` |
| `jwt-evaluator.ts` | 50 | `JSON.parse(decoded)` |
| `jwt-evaluator.ts` | 73 | `JSON.parse(input.slice(...))` |
| `supply-chain-evaluator.ts` | 55 | `JSON.parse(input)` |

#### Impact Analysis

**In Node.js ≥ v20:**
- Direct prototype pollution via JSON.parse is **mitigated**
- `__proto__` is treated as a regular property name
- Engine processes `__proto__` as a legitimate property (detection logic confusion)

**In Node.js < v20:**
- Direct prototype pollution is **possible**
- Attacker could pollute `Object.prototype` during detection
- Could cause missed detections or engine instability

#### Recommended Fix

Create a shared utility and use it across all evaluators:

```typescript
// packages/engine/src/utils/safe-json.ts
export function safeJsonParse(text: string): unknown {
    return JSON.parse(text, (key, value) => {
        if (key === '__proto__' || key === 'constructor') {
            return undefined;
        }
        return value;
    });
}
```

Update all evaluators to use `safeJsonParse()` instead of `JSON.parse()`.

---

### Finding 2: Inconsistent Security Posture

**Severity:** LOW  
**Confidence:** HIGH

#### Description

Other packages in the INVARIANT codebase already implement prototype pollution protection, but the engine does not.

#### Evidence

**Dashboard (packages/dashboard/src/server.ts:496):**
```typescript
return stripPrototypePollution(JSON.parse(str))  // Protected ✅
```

**Agent RASP (packages/agent/src/rasp/deser.ts:174-183):**
```typescript
function stripProtoKeys(obj: unknown, depth = 0): unknown {
    // ... strips __proto__ and constructor keys
}
```

**Engine (packages/engine/src/evaluators/*.ts):**
```typescript
JSON.parse(fragment)  // No protection ❌
```

#### Impact

- Creates confusion about security requirements
- Indicates incomplete security review when engine was developed
- May lead developers to copy unsafe patterns

#### Recommended Fix

1. Create a shared `safe-json.ts` utility in the engine package
2. Migrate all `JSON.parse()` calls to use the safe version
3. Add ESLint rule to prevent unprotected JSON.parse on untrusted input
4. Document the security requirement in AGENTS.md

---

### Finding 3: Missing Test Coverage

**Severity:** INFO  
**Confidence:** HIGH

#### Description

The engine test suite does not verify that the engine itself is resistant to prototype pollution during analysis.

#### Current Test

```typescript
// engine.test.ts:147-150
it('detects proto_pollution', () => {
    const matches = engine.detect("constructor.prototype.isAdmin=true", [])
    expect(matches.some(m => m.class === 'proto_pollution')).toBe(true)
})
```

This test checks detection of the pattern, but doesn't verify that the engine's own JSON parsing is protected.

#### Recommended Fix

Add tests that verify:

```typescript
it('does not pollute prototype during JSON analysis', () => {
    const payload = JSON.stringify({
        "__proto__": { "polluted": true },
        "normal": "data"
    })
    
    // Run detection
    engine.detect(payload, [])
    
    // Verify prototype was not polluted
    const testObj = {}
    expect((testObj as any).polluted).toBeUndefined()
})
```

---

## Attack Scenarios

### Scenario 1: Detection Logic Confusion

**Attack Vector:** Attacker sends JSON with `__proto__` as a property name

```json
{
  "__proto__": {
    "isAdmin": true
  },
  "username": "attacker"
}
```

**Current Behavior:**
1. Engine parses JSON successfully
2. `__proto__` is treated as a regular property
3. Mass-assignment evaluator flattens to `{key: "__proto__.isAdmin", value: true}`
4. Detection logic may not recognize this as prototype pollution attempt

**Desired Behavior:**
1. Engine strips `__proto__` key during parsing
2. Only `{username: "attacker"}` is processed
3. Pollution attempt is neutralized

### Scenario 2: Legacy Node.js Exploitation

**Attack Vector:** On Node.js < v20, direct prototype pollution

```json
{"__proto__":{"toString":"polluted"}}
```

**Impact:**
- All objects in the engine process get polluted `toString` method
- Detection logic that relies on `toString()` may fail
- Could cause missed detections or crashes

---

## Recommendations

### Immediate (High Priority)

1. **Create Safe JSON Utility**
   ```typescript
   // packages/engine/src/utils/safe-json.ts
   export const safeJsonParse = (text: string): unknown =>
       JSON.parse(text, (key, value) => 
           key === '__proto__' || key === 'constructor' ? undefined : value
       );
   ```

2. **Update Evaluators**
   - `proto-pollution-evaluator.ts`
   - `mass-assignment-evaluator.ts`
   - `nosql-evaluator.ts`
   - `jwt-evaluator.ts`
   - `supply-chain-evaluator.ts`

3. **Add Test Coverage**
   - Verify prototype is not polluted during detection
   - Test with various `__proto__` and `constructor` payloads

### Short Term (Medium Priority)

4. **Add ESLint Rule**
   ```javascript
   // .eslintrc
   {
     "rules": {
       "no-restricted-syntax": ["error", {
         "selector": "CallExpression[callee.name='JSON.parse']",
         "message": "Use safeJsonParse for untrusted input"
       }]
     }
   }
   ```

5. **Update Documentation**
   - Document secure parsing requirements in AGENTS.md
   - Add security guidelines for engine developers

### Long Term (Low Priority)

6. **Consolidate Security Utilities**
   - Consider moving `safeJsonParse` to a shared package
   - Use across all INVARIANT packages consistently

7. **Security Audit**
   - Review all object manipulation code for pollution vectors
   - Check for vulnerable merge/assign patterns

---

## Conclusion

The INVARIANT detection engine has a defense-in-depth gap in its handling of JSON input. While the current risk is mitigated by modern Node.js protections, addressing this issue will:

1. Improve code quality and consistency
2. Ensure protection against future Node.js changes
3. Demonstrate security best practices
4. Close a gap between the engine and other INVARIANT packages

The recommended fix is straightforward and adds minimal overhead while significantly improving the engine's security posture.

---

## Appendix: Proof of Concept Files

The following files demonstrate the vulnerability and recommended fix:

| File | Description |
|------|-------------|
| `poc-simple.js` | Simple demonstration of JSON.parse behavior |
| `poc-advanced.js` | Advanced prototype pollution vectors |
| `poc-engine-prototype-pollution.ts` | Full PoC for the engine |

---

## References

- [Node.js Prototype Pollution Protection](https://nodejs.org/en/blog/release/v20.0.0)
- [MDN: JSON.parse() Reviver](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse#the_reviver_parameter)
- [OWASP Prototype Pollution](https://owasp.org/www-community/attacks/Prototype_Pollution)
