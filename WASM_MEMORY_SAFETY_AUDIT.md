# WASM Memory Safety & Security Audit: engine-rs

**Date**: 2026-03-09  
**Target**: `packages/engine-rs` compiled to `wasm32-unknown-unknown`  
**Focus Areas**: Memory corruption, sanitization bypasses, protocol confusion  

## Executive Summary

This audit identified **4 high-priority security concerns** in the WASM-compiled engine-rs component, including potential memory corruption in the streaming processor, multipart boundary confusion vulnerabilities, and HTML tokenizer truncation attacks.

---

## 1. WASM Memory Corruption Vulnerabilities

### 1.1 Integer Overflow in Capacity Calculation (HIGH)

**Location**: `wasm.rs:686` - `push_chunk()` method

```rust
let mut lookahead = String::with_capacity(self.tail.len() + chunk.len());
```

**Vulnerability**: On 32-bit WASM (`usize = 4 bytes`), the addition `self.tail.len() + chunk.len()` can overflow if both values are close to `u32::MAX / 2` (~2GB each).

**Attack Scenario**:
1. Attacker sends two 1.5GB chunks to `push_chunk()`
2. Sum overflows to small value (e.g., 1GB + 1GB = 2GB, wraps to 0 in 32-bit)
3. `String::with_capacity(0)` allocates minimal memory
4. `push_str()` writes 3GB of data, causing heap corruption

**Mitigation**: Input is limited to 1MB (`MAX_INPUT_BYTES = 1024 * 1024`)

**Recommendation**:
```rust
let capacity = self.tail.len().saturating_add(chunk.len());
if capacity > self.max_buffered_bytes() {
    // Handle overflow or excessive size
}
```

---

### 1.2 Potential Underflow in trim_prefix_keep_suffix (MEDIUM)

**Location**: `wasm.rs:578`

```rust
let mut cut = text.len() - max_len; // Potential underflow
```

**Recommendation**: Use `saturating_sub` for defense-in-depth:
```rust
let mut cut = text.len().saturating_sub(max_len);
```

---

### 1.3 Temporary Overallocation in Tail Buffer (MEDIUM)

**Location**: `wasm.rs:702-703`

The `tail` buffer grows unbounded before truncation. If an attacker sends a very large chunk, temporary memory exhaustion could occur.

---

## 2. Multipart Boundary Confusion (MEDIUM)

### 2.1 Boundary Injection in Body Content

**Location**: `body_parser.rs:595-624`

The multipart parsing doesn't properly handle boundaries containing special characters.

**Attack Payload**:
```
Content-Type: multipart/form-data; boundary=evil

--evil
Content-Disposition: form-data; name="field1"

--evil--
--evil
Content-Disposition: form-data; name="field2"

actual_data
--evil--
```

---

## 3. HTML Tokenizer Truncation Attacks (MEDIUM)

### 3.1 Input Truncation at Unsafe Boundaries

**Location**: `tokenizers/html.rs:47-52`

Truncating HTML at arbitrary points can break out of context and cause detection bypass.

**Example**:
```html
<!-- 16380 bytes of padding --><img src="http://evil.com/.../x" onerror="alert(1)
```

If truncated at `"`, browser sees unclosed attribute, engine sees safe input.

---

## 4. XSS Detection Bypass Vectors

### 4.1 HTML Entity Decoding Incompleteness

**Location**: `evaluators/xss.rs:338-395`

The `decode_html_entities` function only handles basic entities. It doesn't decode named HTML5 entities.

**Bypass Example**:
```html
&LeftAngleBracket;script&RightAngleBracket;alert(1)&LeftAngleBracket;/script&RightAngleBracket;
```

---

## 5. Recommendations

### Immediate Actions

1. **Fix integer overflow in push_chunk**: Use `saturating_add` for capacity calculations
2. **Add defense-in-depth for trim_prefix_keep_suffix**: Use `saturating_sub`
3. **Fix temporary overallocation**: Pre-check chunk size before appending to tail

### Medium-term Actions

1. **Improve HTML entity decoding**: Support full HTML5 entity set
2. **Context-aware truncation**: Truncate at safe HTML boundaries
3. **Strict multipart validation**: Reject suspicious boundaries before parsing

### Long-term Actions

1. **Fuzz testing**: Target WASM boundary with large inputs
2. **Memory safety audit**: Review all unsafe blocks and raw pointer usage
3. **Differential testing**: Compare behavior between Rust and browser parsing
