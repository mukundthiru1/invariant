# INVARIANT Engine: TypeScript → Rust Gap Analysis

**Date:** 2026-03-07  
**TypeScript Engine:** v3.0 (full featured)  
**Rust Engine:** v2.5 (partial v3 implementation)  
**Goal:** Determine remaining work for TypeScript deprecation

---

## Executive Summary

The Rust engine has **~75% feature parity** with TypeScript. The TypeScript engine can be deprecated once **3 CRITICAL** features are fully ported. An additional **2 HIGH** and **3 MEDIUM** priority items exist for complete parity.

| Priority | Count | Status |
|----------|-------|--------|
| CRITICAL | 3 | Blocking TS deprecation |
| HIGH | 2 | Required for production parity |
| MEDIUM | 3 | Important for feature completeness |
| LOW | 1 | Nice-to-have |

---

## CRITICAL Priority (Blocking Deprecation)

### 1. L3 Input Decomposition Pipeline

**TypeScript Location:** `packages/engine/src/decomposition/input-decomposer.ts` (~900 lines)  
**Rust Status:** ❌ NOT IMPLEMENTED  
**Complexity:** HIGH (~2-3 weeks)

#### What's Missing
The TypeScript engine has a full **Level 3 (L3)** decomposition pipeline that extracts structural properties from inputs independent of regex patterns:

```typescript
// TypeScript: Full L3 pipeline
const decomposition = decomposeInput(input)
for (const prop of decomposition.properties) {
  if (!matchMap.has(prop.invariantClass)) {
    novelByL3++  // Deep novel variants detected via property analysis
    matchMap.set(prop.invariantClass, {/*L3 detection*/})
  }
}
```

**Pipeline Components:**
1. **Multi-layer decoder** - URL, HTML entities, Unicode, hex, base64, SQL comment bypass
2. **Context detector** - SQL, HTML, Shell, XML, JSON, LDAP, Template, GraphQL, URL
3. **Context-specific tokenizers** - Grammar-aware parsing per context
4. **Property extractor** - Extracts invariant properties from token streams

#### Why It's Critical
- Enables detection of **novel variants** that bypass L1/L2 entirely
- Property-based detection (vs pattern-based) catches zero-day evasions
- The Rust engine currently returns `novel_by_l3: 0` always

#### Porting Strategy
```rust
// New module: src/decomposition.rs
pub struct InputDecomposer;
impl InputDecomposer {
    pub fn decompose(input: &str) -> DecompositionResult { ... }
    fn multi_layer_decode(input: &str) -> DecodedForms { ... }
    fn detect_contexts(input: &str) -> Vec<InputContext> { ... }
    fn extract_properties(tokens: &[Token]) -> Vec<InvariantProperty> { ... }
}
```

---

### 2. Engine Configuration System

**TypeScript Location:** `packages/engine/src/invariant-engine.ts` (lines 69-91, 297-335)  
**Rust Status:** ❌ NOT IMPLEMENTED (static thresholds only)  
**Complexity:** MEDIUM (~3-5 days)

#### What's Missing
```typescript
// TypeScript: Dynamic configuration from rule bundles
export interface EngineConfig {
    thresholdOverrides?: EngineThresholdOverride[]  // EPSS-weighted
    classPriorities?: Map<InvariantClass, number>  // Tech-stack aware
}

export interface EngineThresholdOverride {
    invariantClass: InvariantClass
    adjustedThreshold: number      // base_threshold × (1 − epss × 0.30)
    validUntil: number             // Expiry timestamp
}

updateConfig(config: EngineConfig): void  // Runtime rule bundle injection
```

**Rust Current State:**
```rust
// Rust: Static thresholds only
impl Severity {
    pub fn block_threshold(self) -> f64 {
        match self {
            Severity::Critical => 0.45,
            Severity::High => 0.65,
            Severity::Medium => 0.80,
            Severity::Low => 0.92,
        }
    }
}
```

#### Why It's Critical
- Required for **production deployment** with dynamic rule updates
- EPSS-weighted thresholds enable threat-informed blocking
- Rule bundle dispatch depends on runtime config updates
- Static thresholds can't adapt to emerging threat intelligence

#### Porting Strategy
```rust
// Add to types.rs
pub struct EngineConfig {
    pub threshold_overrides: Vec<ThresholdOverride>,
    pub class_priorities: HashMap<InvariantClass, f64>,
}

pub struct ThresholdOverride {
    pub invariant_class: InvariantClass,
    pub adjusted_threshold: f64,
    pub valid_until: u64,  // Unix timestamp ms
}

// Add to engine.rs
impl InvariantEngine {
    pub fn update_config(&mut self, config: EngineConfig) { ... }
    fn get_effective_threshold(&self, class: InvariantClass, severity: Severity) -> f64 { ... }
}
```

---

### 3. Exploit Knowledge Graph Integration

**TypeScript Location:** `packages/engine/src/decomposition/exploit-knowledge-graph.ts` (~600 lines)  
**Rust Location:** `packages/engine-rs/src/knowledge.rs` (exists but NOT integrated)  
**Complexity:** MEDIUM-HIGH (~1 week)

#### What's Missing
The Rust `knowledge.rs` module exists with full implementation BUT is **not wired into the detection flow**:

```rust
// Rust: AnalysisResult has the field
pub struct AnalysisResult {
    pub cve_enrichment: Option<CveEnrichmentSummary>,  // Always None!
    // ...
}

// Rust: KnowledgeGraph exists but engine doesn't call it
pub struct ExploitKnowledgeGraph { ... }
impl ExploitKnowledgeGraph {
    pub fn enrich_detection(&self, class: InvariantClass, tech: Option<...>) -> DetectionEnrichment { ... }
}
```

**TypeScript Integration Point:**
```typescript
// TypeScript: analyze() enriches every match
const enrichment = this.knowledgeGraph.enrichDetection(m.class)
return {
    ...m,
    cveEnrichment: {
        linkedCves: enrichment.linkedCves,
        activelyExploited: enrichment.activelyExploited,
        highestEpss: enrichment.highestEpss,
    }
}
```

#### Why It's Critical
- Threat-informed defense requires CVE enrichment
- Active exploitation detection drives emergency patching
- Framework profiles enable tech-stack-aware defense
- SOC analysts need CVE context for triage

#### Porting Strategy
```rust
// Modify engine.rs analyze() method
fn analyze(&self, request: &AnalysisRequest) -> AnalysisResult {
    // ... existing L1/L2 detection ...
    
    // Add CVE enrichment per match
    let enriched_matches: Vec<InvariantMatch> = matches
        .into_iter()
        .map(|m| {
            let enrichment = self.knowledge_graph.enrich_detection(m.class, detected_tech);
            InvariantMatch {
                cve_enrichment: Some(CveEnrichment {
                    linked_cves: enrichment.linked_cves,
                    actively_exploited: enrichment.actively_exploited,
                    highest_epss: enrichment.highest_epss,
                    verification_available: enrichment.verification_available,
                }),
                ..m
            }
        })
        .collect();
    
    // Aggregate CVE enrichment for AnalysisResult
    let cve_summary = aggregate_cve_enrichment(&enriched_matches);
    
    AnalysisResult {
        matches: enriched_matches,
        cve_enrichment: Some(cve_summary),
        // ...
    }
}
```

---

## HIGH Priority (Production Parity)

### 4. Inter-Class Correlation System

**TypeScript Location:** `packages/engine/src/classes/registry.ts` (lines 29-162, 375-430)  
**Rust Status:** ❌ NOT IMPLEMENTED  
**Complexity:** MEDIUM (~1 week)

#### What's Missing
The TypeScript registry has **data-driven correlation rules**:

```typescript
const CORRELATION_RULES: readonly CorrelationRule[] = [
    // SQL injection triad
    {
        required: [['sql_string_termination'], ['sql_tautology', 'sql_union_extraction'], ['sql_comment_truncation', 'sql_stacked_execution']],
        confidence: { type: 'fixed', value: 0.99 },
        reason: 'Complete SQL injection structure: escape + payload + termination',
        group: 'sql',
    },
    // XSS patterns, SSRF escalation, JWT forgery, etc.
    // ... 20+ correlation rules
];

computeCorrelations(matches: InvariantMatch[]): InterClassCorrelation[] { ... }
```

**Rust Current State:**
```rust
// Rust: AnalysisResult has the field but always empty
pub struct AnalysisResult {
    pub correlations: Vec<InterClassCorrelation>,  // Always empty!
    // ...
}
```

#### Why It's Important
- Compound attack detection (SQLi triad, XSS patterns)
- Confidence boosting for correlated classes
- Exclusive groups prevent over-counting
- Novel variant + 3+ classes = encoding evasion signal

---

### 5. Header Invariant Detection

**TypeScript Location:** `packages/engine/src/invariant-engine.ts` (lines 853-895)  
**Rust Status:** ❌ NOT IMPLEMENTED  
**Complexity:** LOW (~1-2 days)

#### What's Missing
```typescript
detectHeaderInvariants(headers: Headers): InvariantMatch[] {
    // X-Forwarded-For clustering (3+ = auth bypass attempt)
    const forwardHeaders = ['x-forwarded-for', 'x-real-ip', 'x-originating-ip', ...]
    const forwardCount = forwardHeaders.filter(h => headers.has(h)).length
    if (forwardCount >= 3) { /* auth_header_spoof detection */ }
    
    // X-Original-Url / X-Rewrite-Url access control bypass
    if (headers.has('x-original-url') || headers.has('x-rewrite-url')) { ... }
    
    // JWT "none" algorithm in Authorization header
    const auth = headers.get('authorization') || headers.get('x-authorization')
    if (auth?.toLowerCase().includes('none')) { /* auth_none_algorithm */ }
}
```

#### Why It's Important
- Auth bypass via header spoofing is common in production
- JWT "none" algorithm is a critical security issue
- Currently completely unprotected in Rust

---

## MEDIUM Priority (Feature Completeness)

### 6. Polyglot Detection Integration

**TypeScript Location:** `packages/engine/src/evaluators/polyglot-detector.ts` (260 lines)  
**Rust Location:** `packages/engine-rs/src/polyglot.rs` (exists but NOT integrated)  
**Complexity:** LOW (~2-3 days)

#### What's Missing
The Rust `polyglot.rs` module is **fully implemented** but not called in `analyze()`:

```rust
// Rust: analyze() always returns None for polyglot
pub struct AnalysisResult {
    pub polyglot: Option<PolyglotAnalysis>,  // Always None!
    // ...
}

// Rust: Module exists with full implementation
pub fn analyze_polyglot(detected_classes: &[InvariantClass]) -> PolyglotDetection { ... }
pub fn detect_polyglot_structure(input: &[u8]) -> PolyglotStructure { ... }
```

**Integration Point:**
```rust
// Add to engine.rs analyze() method
let polyglot = analyze_polyglot(&detected_classes);
let structural = detect_polyglot_structure(input.as_bytes());
// Combine and add to AnalysisResult
```

---

### 7. Intent Classification Integration

**TypeScript Location:** `packages/engine/src/evaluators/intent-classifier.ts` (398 lines)  
**Rust Location:** `packages/engine-rs/src/intent.rs` (exists but NOT integrated)  
**Complexity:** LOW (~2-3 days)

#### What's Missing
The Rust `intent.rs` module is **fully implemented** but not called:

```rust
// Rust: analyze() always returns None for intent
pub struct AnalysisResult {
    pub intent: Option<IntentClassification>,  // Always None!
    // ...
}

// Rust: Module exists with full implementation
pub fn classify_intent(
    detected_classes: &[InvariantClass],
    input: &str,
    path: Option<&str>,
) -> IntentClassification { ... }
```

**TypeScript Usage:**
```typescript
const intent = classifyIntent(detectedClasses, input, path)
// Used for: severity adjustment, SOC triage, response prioritization
```

---

### 8. Variant Generation

**TypeScript Location:** `packages/engine/src/classes/registry.ts` (line 195, interface requirement)  
**Rust Status:** ❌ NOT IMPLEMENTED  
**Complexity:** LOW (~1 week)

#### What's Missing
Each class module in TypeScript has a `generateVariants()` method:

```typescript
export interface InvariantClassModule {
    // ...
    generateVariants(): string[]  // Generate attack variants for testing
}
```

This is used for:
- Fuzz testing the detection engine
- Generating synthetic attack traffic
- Security research and validation

#### Note
This is the **lowest priority** as it's primarily for testing/research, not runtime defense.

---

## Summary Table

| # | Feature | Priority | Status | Complexity | Est. Effort |
|---|---------|----------|--------|------------|-------------|
| 1 | L3 Input Decomposition | CRITICAL | ❌ Missing | HIGH | 2-3 weeks |
| 2 | Engine Configuration | CRITICAL | ❌ Missing | MEDIUM | 3-5 days |
| 3 | Knowledge Graph Integration | CRITICAL | ⚠️ Exists, Not Wired | MEDIUM | 1 week |
| 4 | Inter-Class Correlation | HIGH | ❌ Missing | MEDIUM | 1 week |
| 5 | Header Invariant Detection | HIGH | ❌ Missing | LOW | 1-2 days |
| 6 | Polyglot Integration | MEDIUM | ⚠️ Exists, Not Wired | LOW | 2-3 days |
| 7 | Intent Classification Integration | MEDIUM | ⚠️ Exists, Not Wired | LOW | 2-3 days |
| 8 | Variant Generation | LOW | ❌ Missing | LOW | 1 week |

---

## Recommended Porting Order

### Phase 1: Deprecation Blockers (CRITICAL)
1. **Engine Configuration** (quickest win, unblocks production)
2. **Knowledge Graph Integration** (wire up existing code)
3. **L3 Input Decomposition** (largest effort, highest impact)

### Phase 2: Production Parity (HIGH)
4. **Header Invariant Detection** (quick security win)
5. **Inter-Class Correlation** (compound attack detection)

### Phase 3: Completeness (MEDIUM)
6. **Polyglot Integration** (wire up existing module)
7. **Intent Classification Integration** (wire up existing module)

### Phase 4: Nice-to-Have (LOW)
8. **Variant Generation** (testing/research utility)

---

## Test Coverage Requirements

For full TypeScript deprecation, the Rust test suite must cover:

| Feature | TypeScript Tests | Rust Tests Needed |
|---------|-----------------|-------------------|
| L3 Decomposition | `decomposer.test.ts` | New test file required |
| Engine Config | `engine.test.ts` | Add threshold override tests |
| Knowledge Graph | `knowledge-graph.test.ts` | Add enrichment flow tests |
| Correlation | `registry.test.ts` | Add correlation rule tests |
| Header Detection | `engine.test.ts` | Add header invariant tests |
| Polyglot | `polyglot.test.ts` | Add integration tests |
| Intent | `intent.test.ts` | Add integration tests |

---

## Appendix: TypeScript-Only Features Inventory

### Files Exclusive to TypeScript Engine
```
packages/engine/src/
├── decomposition/
│   ├── input-decomposer.ts          (900 lines - CRITICAL)
│   └── exploit-knowledge-graph.ts   (600 lines - CRITICAL)
├── evaluators/
│   ├── polyglot-detector.ts         (260 lines - EXISTS IN RUST)
│   └── intent-classifier.ts         (400 lines - EXISTS IN RUST)
└── classes/
    └── registry.ts                  (466 lines - correlation logic)
```

### Rust Modules Ready for Integration
```
packages/engine-rs/src/
├── polyglot.rs                      (528 lines - READY)
├── intent.rs                        (671 lines - READY)
└── knowledge.rs                     (1037 lines - READY)
```
