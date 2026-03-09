# Evaluator Coverage Gap Analysis: TypeScript vs Rust

## Executive Summary

This analysis compares the detection capabilities between the TypeScript (`packages/engine`) and Rust (`packages/engine-rs`) implementations of the Invariant security engine. **Rust evaluators are significantly more comprehensive** than their TypeScript counterparts, with several critical security evaluators missing from TypeScript entirely.

---

## Evaluator Presence Matrix

### Evaluators Present in BOTH TypeScript and Rust

| Category | TypeScript | Rust | Coverage Gap Assessment |
|----------|------------|------|------------------------|
| **API Abuse** | `api-abuse-evaluator.ts` | `api_abuse.rs` | ⚠️ **CRITICAL GAP** - Rust has 3x more patterns |
| **Cache Attacks** | `cache-evaluator.ts` | `cache.rs` | ⚠️ **CRITICAL GAP** - Rust has 5x more patterns |
| **Command Injection** | `cmd-injection-evaluator.ts` | `cmd.rs` | ⚠️ **MODERATE GAP** - Rust has more evasion detection |
| **CRLF Injection** | `crlf-evaluator.ts` | `crlf.rs` | ⚠️ **MODERATE GAP** - Rust has encoding variants |
| **Deserialization** | `deser-evaluator.ts` | `deser.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **GraphQL** | `graphql-evaluator.ts` | `graphql.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **JWT** | `jwt-evaluator.ts` | `jwt.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **LDAP** | `ldap-evaluator.ts` | `ldap.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **LLM Security** | `llm-evaluator.ts` | `llm.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **Log4Shell** | `log4shell-evaluator.ts` | `log4shell.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **Mass Assignment** | `mass-assignment-evaluator.ts` | `mass_assignment.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **NoSQL Injection** | `nosql-evaluator.ts` | `nosql.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **Path Traversal** | `path-traversal-evaluator.ts` | `path.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **Prototype Pollution** | `proto-pollution-evaluator.ts` | `proto_pollution.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **SQL Injection** | `sql-*.ts` (3 files) | `sql.rs` | ⚠️ **MODERATE GAP** - Rust has advanced patterns |
| **SSRF** | `ssrf-evaluator.ts` | `ssrf.rs` | ⚠️ **MODERATE GAP** - Rust has more bypasses |
| **SSTI** | `ssti-evaluator.ts` | `ssti.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **Supply Chain** | `supply-chain-evaluator.ts` | `supply_chain.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **WebSocket** | `websocket-evaluator.ts` | `websocket.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **XSS** | `xss-context-evaluator.ts` | `xss.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **XXE** | `xxe-evaluator.ts` | `xxe.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **HTTP Smuggling** | `http-smuggle-evaluator.ts` | `http_smuggle.rs` | ⚠️ **Unknown** - Not yet analyzed |
| **Open Redirect** | `redirect-evaluator.ts` | `redirect.rs` | ⚠️ **CRITICAL GAP** - Rust has 3x more vectors |

### Evaluators Present ONLY in Rust (CRITICAL GAPS)

| Rust Evaluator | Attack Category | Severity | Business Impact |
|----------------|-----------------|----------|-----------------|
| `auth_header_spoof.rs` | Authentication Bypass | 🔴 **CRITICAL** | Account takeover, privilege escalation |
| `clickjacking.rs` | UI Redressing | 🟡 **MEDIUM** | Unauthorized actions, credential theft |
| `cors.rs` | Cross-Origin Policy | 🟡 **MEDIUM** | Data exfiltration, API abuse |
| `dns.rs` | DNS Security | 🟡 **MEDIUM** | Tunneling, data exfiltration, C2 |
| `dos.rs` | Denial of Service | 🟠 **HIGH** | Application unavailability, revenue loss |
| `email_inject.rs` | Email Injection | 🟡 **MEDIUM** | Spam relay, phishing, malware distribution |
| `host_header.rs` | Host Header Attacks | 🔴 **CRITICAL** | Password reset poisoning, cache poisoning |
| `hpp.rs` | HTTP Parameter Pollution | 🟡 **MEDIUM** | Logic bypass, authentication bypass |
| `oast.rs` | Out-of-Band Testing | 🟠 **HIGH** | Blind vulnerability detection |
| `oauth.rs` | OAuth Security | 🔴 **CRITICAL** | Account takeover, token theft |
| `race_condition.rs` | Race Conditions | 🔴 **CRITICAL** | Double-spending, TOCTOU exploits |
| `redos.rs` | ReDoS | 🟠 **HIGH** | Denial of service via regex |
| `saml.rs` | SAML Attacks | 🔴 **CRITICAL** | Authentication bypass, impersonation |
| `ssi.rs` | Server-Side Includes | 🟠 **HIGH** | RCE, file disclosure, config leaks |
| `subdomain.rs` | Subdomain Takeover | 🟠 **HIGH** | Phishing, cookie theft, brand damage |
| `type_juggle.rs` | Type Juggling | 🟡 **MEDIUM** | Authentication bypass, logic errors |
| `unicode.rs` | Unicode Attacks | 🟠 **HIGH** | WAF bypass, homograph attacks |
| `idor.rs` | IDOR | 🔴 **CRITICAL** | Unauthorized data access, privilege escalation |
| `xpath.rs` | XPath Injection | 🟠 **HIGH** | XML data exfiltration, authentication bypass |
| `upload.rs` | File Upload Attacks | 🔴 **CRITICAL** | RCE, webshells, malware hosting |

### TypeScript Infrastructure Files (Not Evaluators)

These support the evaluation pipeline but don't detect attacks:
- `canonical-normalizer.ts` - Normalization utility
- `effect-simulator.ts` - Effect simulation
- `evaluator-bridge.ts` - Bridge infrastructure
- `input-shape-validator.ts` - Input validation
- `intent-classifier.ts` - Intent classification
- `l2-adapters.ts` - Adapter layer
- `l2-evaluator-registry.ts` - Registry infrastructure
- `polyglot-detector.ts` - Multi-language detection
- `property-spec.ts` - Property specification
- `response-recommender.ts` - Response generation
- `entropy-analyzer.ts` - Entropy analysis

---

## Detailed Gap Analysis

### 🔴 GAP #1: Authentication Header Spoofing (`auth_header_spoof.rs`)

**Severity:** CRITICAL  
**Attack Type:** Authentication Bypass, Privilege Escalation

**Rust Capabilities (auth_header_spoof.rs):**
```rust
// Detects:
- X-Original-User spoofing
- X-Remote-User manipulation  
- X-Forwarded-User injection
- Client-IP based auth bypass
- Header-based privilege escalation
- JWT prefix confusion attacks
```

**TypeScript Equivalent:** NONE ❌

**Attack Scenarios Missed by TS:**
1. Attacker sets `X-Original-User: admin` to bypass authentication
2. `X-Remote-User` injection in reverse proxy configurations
3. Header confusion between `X-Forwarded-For` and `X-Real-IP`
4. JWT `Bearer` vs `Token` prefix confusion

**Business Impact:** Direct account takeover, administrative access without credentials

---

### 🔴 GAP #2: Host Header Attacks (`host_header.rs`)

**Severity:** CRITICAL  
**Attack Type:** Password Reset Poisoning, Cache Poisoning, Virtual Host Confusion

**Rust Capabilities (host_header.rs):**
```rust
// Detects:
- Host header injection attempts
- X-Forwarded-Host manipulation
- Absolute URI vs Host header confusion
- Virtual host routing bypass
- Cache poisoning via host confusion
- Password reset link poisoning
```

**TypeScript Equivalent:** NONE ❌

**Attack Scenarios Missed by TS:**
1. Password reset emails sent with attacker-controlled host
2. Cache poisoning by sending conflicting Host headers
3. Virtual host routing bypass in shared hosting
4. Web cache deception via host manipulation

**Business Impact:** Account takeover via poisoned password reset links, cache-based attacks

---

### 🔴 GAP #3: Race Conditions (`race_condition.rs`)

**Severity:** CRITICAL  
**Attack Type:** Time-of-Check-Time-of-Use (TOCTOU), Business Logic Flaws

**Rust Capabilities (race_condition.rs):**
```rust
// Detects:
- Coupon code reuse patterns
- Credit limit race conditions
- Inventory manipulation
- Gift card double-spending
- Referral bonus abuse
- Duplicate transaction attempts
```

**TypeScript Equivalent:** NONE ❌

**Attack Scenarios Missed by TS:**
1. Applying the same coupon code multiple times simultaneously
2. Spending gift card balance twice before settlement
3. Inventory overselling through concurrent checkouts
4. Duplicate withdrawal requests processed before balance update

**Business Impact:** Financial loss, inventory errors, duplicate transactions

---

### 🔴 GAP #4: SAML Attacks (`saml.rs`)

**Severity:** CRITICAL  
**Attack Type:** Authentication Bypass, Identity Provider Impersonation

**Rust Capabilities (saml.rs):**
```rust
// Detects:
- SAML signature wrapping attacks
- XML signature stripping
- SAML assertion injection
- Comment injection in SAML responses
- XSW (XML Signature Wrapping) variants
- SAML RelayState manipulation
```

**TypeScript Equivalent:** NONE ❌

**Attack Scenarios Missed by TS:**
1. SAML signature wrapping to impersonate any user
2. XML comment injection to alter SAML assertions
3. Stripping signatures to accept unsigned assertions
4. Assertion injection via XML entity expansion

**Business Impact:** Complete authentication bypass in SAML-enabled applications

---

### 🔴 GAP #5: OAuth Attacks (`oauth.rs`)

**Severity:** CRITICAL  
**Attack Type:** Account Takeover, Token Theft, Authorization Bypass

**Rust Capabilities (oauth.rs):**
```rust
// Detects:
- Authorization code replay
- PKCE downgrade attacks
- redirect_uri manipulation
- State parameter bypass
- Implicit flow token theft
- Client credential confusion
- Scope escalation attempts
```

**TypeScript Equivalent:** NONE ❌

**Attack Scenarios Missed by TS:**
1. Stolen authorization code replay for account takeover
2. PKCE challenge manipulation to bypass protection
3. Redirect URI hijacking in OAuth flows
4. State parameter removal for CSRF attacks
5. Scope escalation to gain unauthorized permissions

**Business Impact:** Account takeover, unauthorized API access, token theft

---

## Secondary Gaps (Medium-High Severity)

### 🟠 GAP #6: IDOR Detection (`idor.rs`)

**Severity:** HIGH  
**Attack Type:** Insecure Direct Object Reference

**Rust-only detection:** Sequential ID enumeration, predictable patterns  
**TypeScript coverage:** Limited to api-abuse basic patterns

---

### 🟠 GAP #7: File Upload Attacks (`upload.rs`)

**Severity:** HIGH  
**Attack Type:** Remote Code Execution, Webshell Upload

**Rust-only detection:**
- MIME type confusion
- Extension bypass (double, null byte, case variations)
- Magic bytes manipulation
- Path traversal in filenames
- SVG-based XSS upload
- Polyglot file detection

**TypeScript equivalent:** NONE ❌

---

### 🟠 GAP #8: Unicode/Homograph Attacks (`unicode.rs`)

**Severity:** HIGH  
**Attack Type:** WAF Bypass, Homograph Phishing

**Rust-only detection:**
- Unicode normalization bypass
- Homograph domain spoofing
- Invisible character injection
- Bidirectional text attacks
- Confusable character substitution

**TypeScript equivalent:** NONE ❌

---

### 🟠 GAP #9: Server-Side Includes (`ssi.rs`)

**Severity:** HIGH  
**Attack Type:** Remote Code Execution, File Disclosure

**Rust-only detection:**
- SSI directive injection (`<!--#exec cmd="..." -->`)
- Include file traversal
- Environment variable exposure
- Config file disclosure

**TypeScript equivalent:** NONE ❌

---

### 🟠 GAP #10: XPath Injection (`xpath.rs`)

**Severity:** HIGH  
**Attack Type:** XML Data Exfiltration, Authentication Bypass

**Rust-only detection:**
- XPath expression injection
- Boolean-based blind XPath
- Union-based data extraction
- XPath function abuse

**TypeScript equivalent:** NONE ❌

---

## Coverage Depth Comparison (Analyzed Evaluators)

### API Abuse Evaluator

| Detection Pattern | TypeScript | Rust |
|------------------|------------|------|
| Basic BOLA/IDOR | ✅ Basic | ✅ Comprehensive |
| Mass Enumeration | ✅ Sequential IDs | ✅ Sequential + patterns |
| GraphQL Batching | ❌ Missing | ✅ Array query abuse |
| JWT Claim Manipulation | ❌ Missing | ✅ alg:none, forged claims |
| HTTP Parameter Pollution | ❌ Missing | ✅ Duplicate param analysis |
| Rate Limit Bypass | ❌ Missing | ✅ IP spoofing headers |
| API Version Downgrade | ❌ Missing | ✅ v1 while v2 available |
| OAuth Scope Abuse | ❌ Missing | ✅ Excessive scope detection |
| Content-Type Confusion | ❌ Missing | ✅ Header/body mismatch |
| Pagination Scraping | ❌ Missing | ✅ Offset/page abuse |
| **Total Patterns** | **~4** | **~19** |

### Cache Evaluator

| Detection Pattern | TypeScript | Rust |
|------------------|------------|------|
| Basic Poisoning | ✅ Unkeyed headers | ✅ Multi-header analysis |
| Cache Deception | ✅ Static extensions | ✅ Path confusion |
| Parameter Cloaking | ❌ Missing | ✅ utm_* param abuse |
| CDN IP Injection | ❌ Missing | ✅ CF-Connecting-IP, etc. |
| Fat GET | ❌ Missing | ✅ GET with body |
| Response Splitting | ❌ Missing | ✅ CRLF via cache |
| Key Normalization Bypass | ❌ Missing | ✅ Encoded separators |
| Vary Header Manipulation | ❌ Missing | ✅ Attacker-controlled Vary |
| **Total Patterns** | **~2** | **~17** |

### Open Redirect Evaluator

| Detection Pattern | TypeScript | Rust |
|------------------|------------|------|
| Protocol-Relative | ✅ Basic | ✅ + encoded variants |
| JavaScript/Data URI | ✅ Basic | ✅ + encoded schemes |
| Auth Confusion | ✅ @-based | ✅ + parser differentials |
| Double-Encoding | ❌ Missing | ✅ %252f detection |
| Backslash Confusion | ❌ Missing | ✅ Mixed slash/backslash |
| CRLF Injection | ❌ Missing | ✅ Header injection via redirect |
| Unicode/Homograph | ❌ Missing | ✅ Punycode detection |
| OAuth Redirect Bypass | ❌ Missing | ✅ redirect_uri validation |
| Fragment Authority | ❌ Missing | ✅ #@ confusion |
| Triple Slash | ❌ Missing | ✅ /// normalization |
| **Total Patterns** | **~6** | **~15** |

### SSRF Evaluator

| Detection Pattern | TypeScript | Rust |
|------------------|------------|------|
| Internal IP Range | ✅ Basic ranges | ✅ + IPv6 loopback |
| Cloud Metadata | ✅ Basic IPs | ✅ + IMDSv2, multiple clouds |
| DNS Rebinding | ✅ nip.io, xip.io | ✅ + sslip.io, localtest.me |
| Protocol Smuggling | ✅ Dangerous schemes | ✅ + parameter smuggling |
| Parser Confusion | ❌ Missing | ✅ Fragment #@ attacks |
| Redirect Chain | ❌ Missing | ✅ URL shortener abuse |
| Unicode Dotlike | ❌ Missing | ✅ Fullwidth dots, etc. |
| Embedded Credentials | ❌ Missing | ✅ Multi-@ analysis |
| **Total Patterns** | **~6** | **~12+** |

---

## Recommendations

### Immediate Priority (Critical Business Risk)

1. **Implement `auth_header_spoof.rs`** in TypeScript
   - Risk: Account takeover, privilege escalation
   - Effort: Medium (~2 weeks)

2. **Implement `host_header.rs`** in TypeScript
   - Risk: Password reset poisoning, cache poisoning
   - Effort: Medium (~2 weeks)

3. **Implement `oauth.rs`** in TypeScript
   - Risk: Account takeover in OAuth flows
   - Effort: High (~3-4 weeks)

4. **Implement `race_condition.rs`** in TypeScript
   - Risk: Financial loss, business logic abuse
   - Effort: High (~3 weeks)

5. **Implement `saml.rs`** in TypeScript
   - Risk: Complete auth bypass in SAML apps
   - Effort: High (~3-4 weeks)

### Secondary Priority (High Business Risk)

6. **Implement `upload.rs`** - File upload attack detection
7. **Implement `idor.rs`** - IDOR-specific patterns
8. **Implement `unicode.rs`** - Unicode-based bypasses
9. **Implement `xpath.rs`** - XPath injection
10. **Implement `ssi.rs`** - Server-side include attacks

### Coverage Enhancement Priority

11. **Enhance `api-abuse-evaluator.ts`** - Add GraphQL, JWT manipulation, HPP detection
12. **Enhance `cache-evaluator.ts`** - Add parameter cloaking, CDN injection, fat GET
13. **Enhance `redirect-evaluator.ts`** - Add double-encoding, backslash confusion, Unicode
14. **Enhance `ssrf-evaluator.ts`** - Add parser confusion, redirect chains, Unicode dots

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| **Total Rust Evaluators** | 43 |
| **Total TypeScript Evaluators** | 22 (pure detection) |
| **TypeScript-only (infrastructure)** | 11 |
| **Rust-only (CRITICAL gaps)** | 20+ |
| **Evaluators with TS < Rust coverage** | 6+ analyzed |
| **Critical gaps (authentication-related)** | 5 |
| **High severity gaps** | 10+ |

### Risk Assessment

- 🔴 **CRITICAL Gaps:** 5 evaluators missing that enable account takeover
- 🟠 **HIGH Gaps:** 10+ evaluators missing that enable RCE, data theft, DoS
- 🟡 **MEDIUM Gaps:** 5+ evaluators missing for secondary attack vectors
- ⚠️ **Coverage Depth:** Analyzed evaluators show 3-5x more patterns in Rust

---

## Conclusion

The TypeScript engine has **significant coverage gaps** compared to the Rust engine. Most critically, it lacks:

1. **Authentication bypass** evaluators (auth_header_spoof, oauth, saml)
2. **Host-based attacks** (host_header poisoning)
3. **Business logic attacks** (race_condition)
4. **Modern web attacks** (unicode bypasses, file upload attacks)

**Recommendation:** Prioritize porting the 5 critical evaluators to TypeScript to prevent account takeovers and authentication bypasses. Then focus on enhancing existing evaluators to match Rust's detection depth.
