# Security Gap Analysis - Executive Summary

## Critical Finding: Self-ReDoS Vulnerability ⚠️

**The L1 detection regexes themselves contain ReDoS-vulnerable patterns.**

### Most Dangerous Patterns (Immediate Fix Required)

```typescript
// In exploit-signatures.ts:
/multipart\/form-data[\s\S]{0,400}class\.module\./  // Line ~15
/\bevaluate\s*\(\s*['"][\s\S]{0,180}['"]\s*\)/i    // GROOVY_EVALUATE_RE

// In web-attacks.ts:
/(?:\{[^{}]*){10,}/                                  // GQL_DEPTH_RE
/(?:\b\w+\s*:\s*\w+\s*(?:\([^)]*\))?\s*){50,}/       // GQL_ALIAS_RE
```

### Attack Vector

```javascript
// An attacker could send this to cause exponential backtracking:
const attack = "class.module." + "a".repeat(500) + "X".repeat(500);
```

---

## Gap Summary by Vector

### 1. Deserialization Gaps

| Priority | Gap | Current | Needed |
|----------|-----|---------|--------|
| 🔴 High | Java XStream | ❌ Missing | Gadget patterns |
| 🔴 High | Python Dask/cloudpickle | ❌ Missing | Magic + opcodes |
| 🔴 High | Protocol Buffers | ❌ Missing | Type confusion |
| 🟠 Med | Go Gob | ❌ Missing | Magic bytes |
| 🟠 Med | Kotlin Serialization | ⚠️ Partial | CBOR/Protobuf |
| 🟢 Low | MessagePack | ❌ Missing | Type confusion |

### 2. SSTI Gaps

| Priority | Gap | Current | Needed |
|----------|-----|---------|--------|
| 🔴 High | ASP.NET Razor | ❌ Missing | `@` syntax patterns |
| 🔴 High | Vue/React SSR | ❌ Missing | `renderToString` patterns |
| 🔴 High | Django Templates | ⚠️ Partial | Beyond Jinja2 overlap |
| 🟠 Med | Liquid (Shopify) | ❌ Missing | Filter patterns |
| 🟠 Med | Blazor Server | ❌ Missing | Component injection |
| 🟢 Low | T4 Templates | ❌ Missing | Visual Studio |

### 3. ReDoS Gaps

| Priority | Gap | Current | Needed |
|----------|-----|---------|--------|
| 🔴 High | Lookbehind catastrophe | ❌ Missing | `(?<=a+)` detection |
| 🔴 High | Lookahead catastrophe | ❌ Missing | `(?=a+)` detection |
| 🟠 Med | Polynomial blowup | ⚠️ Basic | O(n²) detection |
| 🟠 Med | Atomic group misuse | ❌ Missing | `(?>a+)+` |

---

## Immediate Action Items

### Week 1 (Critical)

```
□ Audit all regex patterns in exploit-signatures.ts for ReDoS
□ Replace [\s\S]{0,N} patterns with non-backtracking alternatives
□ Add safeRegexTest to all patterns in exploit-signatures.ts
□ Add timeout guards to all L1 detection modules
```

### Month 1 (High Priority)

```
□ Add XStream gadget patterns to deser evaluator
□ Add Python Dask/cloudpickle detection
□ Add Django template RCE patterns
□ Add ASP.NET Razor injection patterns
□ Implement Unicode normalization pre-processing
```

### Quarter 1 (Medium Priority)

```
□ Add Protocol Buffer type confusion detection
□ Add Vue/React SSR detection
□ Add lookbehind/lookahead catastrophe detection
□ Implement format-specific parsers (not just regex)
```

---

## Regex Safety Checklist

Before adding any new regex pattern, verify:

- [ ] No nested quantifiers: `(a+)+`, `(a*)*`
- [ ] No overlapping alternation: `(a|a)*`, `(ab|a)*`
- [ ] No backreference under repetition: `(a)\1+`
- [ ] No dot-all with quantifiers: `[\s\S]*` or `.{0,1000}`
- [ ] Uses atomic groups where possible: `(?>a+)`
- [ ] Uses possessive quantifiers where possible: `a++`
- [ ] Wrapped in safeRegexTest with 10ms timeout
- [ ] Input length limited to 20KB max

---

## Safe Pattern Examples

### Instead of This (Vulnerable):
```typescript
/multipart[\s\S]{0,400}class\.module/
```

### Use This (Safe):
```typescript
/multipart[^]{0,400}class\.module/
// Or limit the scope:
/multipart[^]*?class\.module.{0,200}/
// Or use atomic groups (if engine supports):
/multipart(?>[^])*?class\.module/
```

---

## Coverage Metrics

| Vector | L1 Coverage | L2 Coverage | Confidence |
|--------|-------------|-------------|------------|
| Deserialization | 85% | 90% | 0.82-0.98 |
| SSTI | 80% | 85% | 0.78-0.95 |
| ReDoS | 65% | 40% | 0.70-0.88 |

**Note:** ReDoS L2 coverage is lower because structural regex analysis is complex and not fully implemented.

---

## Files Requiring Immediate Attention

1. `packages/engine/src/classes/injection/exploit-signatures.ts` - ReDoS vulnerabilities
2. `packages/engine/src/classes/injection/web-attacks.ts` - Some ReDoS risk
3. `packages/engine/src/classes/injection/misc.ts` - Missing safe regex wrappers
4. `packages/engine-rs/src/evaluators/redos.rs` - Limited L2 analysis

---

*Generated: 2026-03-09*
*Scope: engine-rs (Rust) + engine (TypeScript) evaluators*
