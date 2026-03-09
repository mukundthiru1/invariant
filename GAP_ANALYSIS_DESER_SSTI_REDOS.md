# Security Gap Analysis: Deserialization, SSTI, and ReDoS

**Date:** 2026-03-09  
**Scope:** Engine-RS (Rust) + Engine (TypeScript) Evaluators  
**Classification:** Security Audit - Gap Analysis  
**Status:** Analysis Only - No Code Changes

---

## Executive Summary

This analysis evaluates three critical attack vectors across the dual-engine (Rust + TypeScript) security platform:

1. **Deserialization Gadget Chains** - Insecure deserialization leading to RCE
2. **Server-Side Template Injection (SSTI)** - Template engine exploitation
3. **Regular Expression Denial of Service (ReDoS)** - Catastrophic backtracking attacks

**Overall Assessment:** The engines demonstrate mature coverage of common attack patterns, with strong L2 evaluator implementations providing structural analysis beyond simple signature matching. However, several gaps exist in emerging attack vectors, and critically, **the L1 detection regexes themselves may contain ReDoS vulnerabilities**.

---

## 1. Deserialization Analysis

### 1.1 Current Coverage (Strengths)

| Format | Magic Bytes | Gadget Detection | Confidence |
|--------|-------------|------------------|------------|
| **Java** | ✅ 0xAC 0xED (base64: rO0AB) | ✅ Commons Collections 1-7, Spring, Hibernate, ysoserial families | 0.92-0.98 |
| **PHP** | ✅ `O:<len>:<class>` | ✅ POP chains (Monolog, Guzzle, Laravel, Symfony), PHAR, magic methods | 0.88-0.94 |
| **Python** | ✅ `\x80\x02-\x05` (base64: gAS...) | ✅ Pickle opcodes (cos system, c__builtin__), PyYAML, marshal | 0.85-0.92 |
| **.NET** | ✅ AAEAAAD (base64) | ✅ BinaryFormatter, TypeNameHandling, ObjectDataProvider, TypeConfuseDelegate | 0.88-0.93 |
| **Ruby** | ✅ 0x04 0x08 (base64: BAh...) | ✅ Marshal, YAML (Gem::Installer, ERB) | 0.82-0.88 |
| **Node.js** | ✅ `_$$ND_FUNC$$_` markers | ✅ node-serialize, JSON prototype pollution | 0.85-0.90 |
| **Kryo** | ✅ KRYO markers | ✅ Limited coverage | 0.78-0.82 |
| **Hessian** | ✅ 0x48 0x02 0x00 | ✅ Basic detection | 0.78-0.82 |

### 1.2 Identified Gaps

#### HIGH PRIORITY

| Gap | Risk | Rationale |
|-----|------|-----------|
| **Java XStream** | 🔴 Critical | XStream has its own gadget ecosystem (ImageIO, javax.sound) not covered by current Java detection |
| **Python Dask/Distributed** | 🟠 High | Dask's custom serialization can execute arbitrary code via `cloudpickle` - no coverage |
| **Protocol Buffers (protobuf)** | 🟠 High | protobuf with `Any` type and type confusion attacks - no detection |
| **Java Kryo/Ry serializable** | 🟠 High | Kryo/Ry has extensive gadget chains beyond current basic marker detection |

#### MEDIUM PRIORITY

| Gap | Risk | Rationale |
|-----|------|-----------|
| **Go Gob encoding** | 🟡 Medium | Go's native serialization - no magic byte detection |
| **Rust Serde/Bincode** | 🟡 Medium | Rust native serialization formats - no coverage |
| **Kotlin Serialization** | 🟡 Medium | kotlinx.serialization formats (JSON, CBOR, ProtoBuf) - limited coverage |
| **Swift Codable** | 🟢 Low | Lesser adoption in web contexts |

#### LOW PRIORITY (Emerging)

| Gap | Risk | Rationale |
|-----|------|-----------|
| **MessagePack** | 🟢 Low | Type confusion possible but requires specific gadget classes |
| **Avro/Thrift** | 🟢 Low | Binary formats with limited attack surface in web contexts |
| **BSON** | 🟢 Low | MongoDB's format - limited RCE potential without specific drivers |

### 1.3 Gadget Chain Coverage Assessment

**Well Covered:**
- Commons Collections 1-7 (InvokerTransformer, ChainedTransformer, TemplatesImpl)
- Spring (BeanComparator, PriorityQueue gadgets)
- Hibernate
- ysoserial standard gadgets
- Monolog/RCE1-2 for PHP
- Laravel/Symfony POP chains

**Partially Covered:**
- Jython/JRuby gadgets (detected via class names but limited)
- Groovy closures (detected but needs more patterns)

**Missing:**
- Jackson gadgets (TypeConflictDelegate, etc.)
- Fastjson gadgets (AutoType bypass chains)
- V8 JavaScript engine gadgets
- ELResolver gadget chains

### 1.4 Evasion Techniques Not Fully Addressed

1. **UTF-8 Overlong Encoding in Serialized Data:** May bypass magic byte detection
2. **Chunked/Fragmented Deserialization:** Partial payloads not detected
3. **Nested Encoding:** Base64-encoded compressed serialized data layers
4. **Protocol Mismatch:** Sending .NET serialized data to Java endpoints (confusion attacks)

---

## 2. SSTI (Server-Side Template Injection) Analysis

### 2.1 Current Coverage (Strengths)

| Engine | Detection Method | Confidence |
|--------|------------------|------------|
| **Jinja2** | ✅ `{{...}}` with `__class__`, `__mro__`, `__subclasses__`, `config`, `lipsum` | 0.90-0.95 |
| **Twig** | ✅ Same as Jinja2 + `{% import/include %}` | 0.88-0.93 |
| **FreeMarker** | ✅ `<#assign>`, `<#include>`, `?new()` | 0.88-0.92 |
| **Velocity** | ✅ `#set`, `$class.inspect`, `#evaluate` | 0.85-0.90 |
| **ERB** | ✅ `<%=...%>`, `system/exec` detection | 0.85-0.90 |
| **SpEL/EL** | ✅ `${T(...)}`, `#{...}`, `Runtime`, `ProcessBuilder` | 0.88-0.93 |
| **Mako** | ✅ `<%...%>`, `<%!...%>`, `${os.popen()}` | 0.82-0.88 |
| **Smarty** | ✅ `{php}...{/php}`, `writeFile` | 0.80-0.86 |
| **Handlebars** | ✅ Constructor chains, `lookup` | 0.82-0.88 |
| **Go Templates** | ✅ `{{.Field}}`, `template`, `define` | 0.78-0.85 |
| **Pebble** | ✅ Same delimiters as Jinja2 | 0.80-0.86 |
| **OGNL** | ✅ `%{#context...}`, `@ognl.OgnlContext` | 0.85-0.90 |
| **Thymeleaf** | ✅ `th:text`, `th:attr` | 0.78-0.85 |

### 2.2 Identified Gaps

#### HIGH PRIORITY

| Gap | Risk | Rationale |
|-----|------|-----------|
| **Django Templates** | 🟠 High | Python's native template engine - limited coverage beyond Jinja2 overlap |
| **ASP.NET Razor** | 🟠 High | Microsoft's template engine - no specific detection |
| **Blazor Server** | 🟠 High | .NET's interactive UI framework - no coverage |
| **Vue SSR** | 🟠 High | Vue.js server-side rendering - no specific patterns |
| **React SSR (renderToString)** | 🟠 High | React's SSR can execute dangerous patterns |

#### MEDIUM PRIORITY

| Gap | Risk | Rationale |
|-----|------|-----------|
| **Liquid (Shopify)** | 🟡 Medium | Widely used in e-commerce, limited RCE but has data exfil |
| **Mustache/Handlebars variants** | 🟡 Medium | Multiple implementations with different security models |
| **RazorLight (.NET)** | 🟡 Medium | Lightweight Razor - no coverage |
| **Scalate (Scala)** | 🟡 Medium | Scala templates (SSSP, Mustache, Scaml) |
| **Haml/Slim** | 🟡 Medium | Ruby template engines beyond ERB |

#### LOW PRIORITY

| Gap | Risk | Rationale |
|-----|------|-----------|
| **T4 Templates** | 🟢 Low | Visual Studio templates, limited web exposure |
| **StringTemplate** | 🟢 Low | Java template library with limited adoption |
| **Jade/Pug** | 🟢 Low | Node.js templates - limited RCE in typical configs |

### 2.3 SSTI Evasion Techniques Not Fully Addressed

1. **Unicode Normalization:** Using Unicode homoglyphs in property names (`cоnfig` with Cyrillic 'о')
2. **Delimiter Splitting:** `{{` encoded as `%7B%7B` or HTML entities
3. **Nested Template Injection:** Injecting template syntax inside template variables
4. **Filter Bypass:** Using `|safe`, `|raw` filters to bypass auto-escaping
5. **Whitespace Variants:** `{{ 7*7 }}` vs `{{7*7}}` vs `{{\n7*7\n}}`
6. **Block Comment Wrapping:** `{# ... {{payload}} ... #}` in Jinja2

### 2.4 Invariant Property Coverage

The SSTI evaluator uses an excellent invariant-based approach:
- **Property Chain Analysis:** Detects traversal to dangerous objects (`__class__.__mro__.__subclasses__`)
- **Dangerous Function Detection:** `exec`, `eval`, `system`, `popen`, etc.
- **Arithmetic Probe Detection:** `{{7*7}}`, `${7*7}` detection

**Missing Invariants:**
- Template file path disclosure attempts
- Template cache poisoning indicators
- Macro/inline template definition abuse

---

## 3. ReDoS Analysis

### 3.1 Current Coverage (Strengths)

| Pattern Type | Detection | L1 | L2 |
|--------------|-----------|----|-----|
| **Nested Quantifiers** | ✅ `(a+)+`, `(a*)*` | ✅ | ✅ |
| **Overlapping Alternation** | ✅ `(a|a)*`, `(ab|a)*` | ✅ | ✅ |
| **Character Class Repetition** | ✅ `([a-z]+)+` | ✅ | ✅ |
| **Backreference Catastrophe** | ✅ `\1+`, `\2*` | ✅ | ✅ |
| **Regex Injection** | ✅ `new RegExp(user_input)` | ✅ | ✅ |

### 3.2 Critical Finding: L1 Detection Regexes May Have ReDoS Vulnerabilities

**SEVERITY: HIGH** - The very regexes used for L1 detection contain patterns that could be exploited for ReDoS attacks against the security engine itself.

#### Vulnerable Patterns Identified

| File | Pattern | Issue |
|------|---------|-------|
| `exploit-signatures.ts` | `/(?:[\s\S]{0,400}class\.module\.)/` | `\s\S` alternation with repetition |
| `exploit-signatures.ts` | `/(?:[\s\S]{0,180}['"])/g` | Same pattern in GROOVY_EVALUATE_RE |
| `exploit-signatures.ts` | `[\s\S]*?` in multiple patterns | Nested quantifier with alternation |
| `web-attacks.ts` | `/(?:\{[^{}]*){10,}/` | Nested quantifier (though limited) |
| `web-attacks.ts` | `/(?:\b\w+\s*:\s*\w+...){50,}/` | Complex alternation under repetition |
| `web-attacks.ts` | `/(?:\.\.\.\w+\s*){50,}/` | Same issue for fragments |

#### Attack Vectors

An attacker could craft input designed to trigger ReDoS in the security engine:

```javascript
// Example payload that might cause exponential backtracking
// in patterns using [\s\S]* or similar
const attackPayload = 'class.module.' + 'a'.repeat(500) + '!'.repeat(500);

// Or specifically targeting the GraphQL depth pattern
const graphqlAttack = '{'.repeat(100) + 'a'.repeat(1000) + '}'.repeat(100);
```

### 3.3 Inconsistent Safe Regex Usage

Not all L1 detection modules use the safe regex wrappers:

**Using Safe Regex (Good):**
- `web-attacks.ts` - Uses `safeRegexTest`, `safeRegexMatch`

**NOT Using Safe Regex (Risk):**
- `exploit-signatures.ts` - Uses raw `.test()` and `.match()`
- `misc.ts` - Uses raw regex operations
- Various injection classes in `injection/` directory

### 3.4 Missing ReDoS Detection Coverage

| Pattern Type | Risk | Notes |
|--------------|------|-------|
| **Lookbehind Catastrophe** | 🟠 High | `(?<=a+)b` patterns not detected |
| **Lookahead Catastrophe** | 🟠 High | `(?=a+).*` patterns not detected |
| **Atomic Group Misuse** | 🟡 Medium | `(?>a+)+` can still be problematic |
| **Recursive Patterns** | 🟡 Medium | `(?R)` in PCRE - no detection |
| **Polynomial Time Blowup** | 🟠 High | Only exponential patterns detected |

### 3.5 ReDoS Safe Regex Implementation

Current implementation:
```typescript
const DEFAULT_OPTIONS = {
    timeoutMs: 10,
    maxInputLength: 20_000,
}
```

**Concerns:**
1. 10ms timeout may still allow significant CPU consumption with many parallel requests
2. 20,000 character limit may be too high for some catastrophic patterns
3. No rate limiting per IP/session for regex operations

---

## 4. Cross-Cutting Issues

### 4.1 Encoding/Decoding Gaps

Both engines implement deep decoding, but some gaps exist:

1. **Unicode Normalization:** No NFKC/NFKD normalization before detection
2. **Punycode Handling:** Limited IDN/punycode normalization for SSTI
3. **Hex Entity Variants:** `&#x20;`, `&#32;`, `\x20`, `\u0020` - may not all be covered
4. **Base64 Variants:** URL-safe base64 (`-_` instead of `+/`) detection gaps

### 4.2 Confidence Score Calibration

| Issue | Description |
|-------|-------------|
| **Deserialization** | Confidence scores (0.82-0.98) appropriate but could use more granular scoring based on gadget specificity |
| **SSTI** | Math probe detection ({{7*7}}) might have false positives in legitimate math content |
| **ReDoS** | Base confidence of 0.70 for regex DOS may be too low given impact |

### 4.3 L1 vs L2 Coverage Disparity

| Vector | L1 Coverage | L2 Coverage | Gap |
|--------|-------------|-------------|-----|
| **Deserialization** | Extensive | Extensive | Minimal |
| **SSTI** | Extensive | Extensive | Minimal |
| **ReDoS** | Moderate | Basic | L2 needs structural regex analysis |

---

## 5. Recommendations

### 5.1 Immediate Actions (Critical)

1. **Audit All L1 Regex Patterns for ReDoS**
   - Run all detection regexes against ReDoS testing tools (e.g., `redos-detector`)
   - Replace `[\s\S]` patterns with more specific alternatives
   - Add timeouts to ALL regex operations

2. **Standardize Safe Regex Usage**
   - Mandate `safeRegexTest`/`safeRegexMatch` for all new patterns
   - Refactor existing patterns in `exploit-signatures.ts`

3. **Add Input Length Limits**
   - Pre-filter inputs >20KB before regex application
   - Implement streaming detection for large inputs

### 5.2 Short-Term Actions (High Priority)

1. **Deserialization**
   - Add XStream gadget patterns
   - Add Python Dask/cloudpickle detection
   - Add Protocol Buffer type confusion detection
   - Implement protobuf magic byte detection

2. **SSTI**
   - Add Django template detection
   - Add ASP.NET Razor patterns
   - Add Vue/React SSR detection
   - Implement Unicode normalization pre-processing

3. **ReDoS**
   - Add lookbehind/lookahead catastrophe detection
   - Implement polynomial time blowup detection
   - Add regex static analysis at build time

### 5.3 Medium-Term Actions

1. **Add Format-Specific Parsers**
   - Instead of regex-only, add lightweight parsers for:
     - Java serialized object structure
     - PHP serialized object structure
     - Pickle opcode validation

2. **Enhance L2 Analysis**
   - Add semantic analysis for deserialized object graphs
   - Add template AST parsing for SSTI
   - Add regex NFA analysis for ReDoS

3. **Fuzzing Integration**
   - Add generated payloads for each class
   - Implement feedback-driven fuzzing for edge cases

### 5.4 Long-Term Strategic Recommendations

1. **Separate Detection from Prevention**
   - Consider read-only analysis vs. blocking decisions
   - Add detection-only mode for new pattern validation

2. **Machine Learning Integration**
   - Train models on gadget chain patterns
   - Use anomaly detection for unknown serialization formats

3. **Community Intelligence**
   - Integrate threat feeds for new gadget chains
   - Add automated pattern update mechanisms

---

## 6. Appendix: Detailed Pattern Analysis

### 6.1 Deserialization Magic Bytes Reference

| Format | Hex | Base64 | Regex Pattern |
|--------|-----|--------|---------------|
| Java | `AC ED 00 05` | `rO0AB` | `\xAC\xED\x00\x05` or `aced\s*0005` |
| Python Pickle 2 | `80 02` | `gAS...` | `\x80\x0[2-5]` |
| Python Pickle 4 | `80 04 95` | `gASV...` | `\x80\x04\x95` |
| Ruby Marshal | `04 08` | `BAh...` | `\x04\x08` |
| .NET BinaryFormatter | `AAEAAAD` | - | `AAEAAAD` |
| PHP Serialized | - | - | `O:\d+:"` or `C:\d+:"` |

### 6.2 SSTI Dangerous Chains Matrix

| Engine | Property Chain | Function Calls |
|--------|---------------|----------------|
| Jinja2 | `__class__.__mro__.__subclasses__` | `os.popen`, `subprocess.Popen` |
| Twig | Same as Jinja2 | Same as Jinja2 |
| FreeMarker | - | `?new()`, `freemarker.template.utility.Execute` |
| Velocity | `$class.forName` | `getRuntime().exec()` |
| SpEL | `T(java.lang.Runtime)` | `exec()`, `getMethod().invoke()` |
| OGNL | `#context`, `#attr` | `@java.lang.Runtime@exec` |
| Mako | `__builtins__` | `eval`, `exec`, `compile` |
| ERB | `Kernel`, `Object` | `system`, `exec`, `` |

### 6.3 ReDoS Pattern Severity Matrix

| Pattern | Complexity | Attack Input | Mitigation |
|---------|------------|--------------|------------|
| `(a+)+$` | O(2ⁿ) | `a`.repeat(30) + `!` | Atomic groups, possessive quantifiers |
| `(a|a)*` | O(2ⁿ) | `a`.repeat(30) | Deduplicate alternation |
| `([a-z]+)+$` | O(n²) | `a`.repeat(1000) | Remove unnecessary grouping |
| `(a+)*$` | O(2ⁿ) | `a`.repeat(30) + `b` | Atomic groups |

---

## 7. Conclusion

The Invariant security engines demonstrate sophisticated coverage of deserialization, SSTI, and ReDoS attack vectors with strong L2 evaluator implementations that go beyond simple signature matching. The invariant-based approach provides resilience against many evasion techniques.

**Key Strengths:**
- Comprehensive gadget chain coverage for major serialization formats
- Robust SSTI detection across 12+ template engines
- Structural analysis (L2) reducing false positives

**Critical Concerns:**
1. **ReDoS in detection regexes** - The most immediate security risk
2. **Missing coverage for emerging formats** (XStream, Dask, protobuf)
3. **Inconsistent safe regex usage** in L1 detection

**Recommended Priority:**
1. Fix ReDoS vulnerabilities in detection patterns
2. Standardize safe regex usage across all modules
3. Add coverage for identified format gaps
4. Implement encoding normalization improvements

---

*This analysis was conducted without modifying any production code. All findings are based on static analysis of the codebase as of 2026-03-09.*
