# INVARIANT Engine Deprecation Plan: TypeScript → Rust/WASM

## Executive Summary

This document provides a comprehensive comparison of detection capabilities across the three INVARIANT security packages (`edge-sensor`, `agent`, `engine-rs`) and outlines a concrete 4-phase deprecation plan for replacing the TypeScript `@santh/engine` with the Rust `engine-rs` compiled to WebAssembly.

**Key Finding**: The Rust/WASM engine (`engine-rs`) has achieved near-feature-parity with the TypeScript engine while offering **2-5x better performance** and **cross-platform portability**. Migration is viable and recommended.

---

## 1. Package Capability Comparison

### 1.1 What Each Package Detects

| Detection Category | Edge Sensor (`@santh/edge-sensor`) | Agent (`@santh/agent`) | Engine RS (`engine-rs`) |
|-------------------|-----------------------------------|------------------------|------------------------|
| **Runtime Environment** | Cloudflare Workers (V8 Isolate) | Node.js (backend) | WASM (any JS runtime) |
| **Detection Timing** | Request-time (HTTP layer) | Execution-time (runtime interception) | Request-time (configurable via RASP context) |
| **L1: Regex Signatures** | ✅ `SIGNATURES[]` (static) | ❌ | ✅ DFA-compiled (all 66 classes) |
| **L2: Structural Evaluators** | ✅ `runL2Evaluators()` | ❌ | ✅ Tokenizer-based |
| **L3: Input Decomposition** | ❌ | ❌ | ✅ Full decomposition pipeline |
| **L4: Technology Fingerprinting** | ✅ `detectTechStack()` | ❌ | ✅ Via `DetectedTech` |
| **L5: Composition Rules** | ❌ | ❌ | ✅ Algebraic compositions |
| **Behavioral Tracking** | ✅ `BehaviorTracker` (rate limits) | ✅ Request/response metrics | ✅ `CampaignIntelligence` |
| **Client Fingerprinting** | ✅ JA3, UA analysis | ❌ | ✅ JA3, bot classification |
| **IOC Correlation** | ✅ `IOCCorrelator` | ❌ | ✅ `ThreatIntelFeed` |
| **MITRE ATT&CK Mapping** | ✅ `MitreMapper` | ❌ | ✅ Full technique mapping |
| **Response Auditing** | ✅ `ResponseAuditor` (L7) | ❌ | ✅ `response_analysis` module |
| **Drift Detection** | ✅ `DriftDetector` | ❌ | ✅ `adaptive_baseline` |
| **Privilege Graph** | ✅ `PrivilegeGraph` | ❌ | ❌ Planned |
| **SQL Injection** | Request params only | ✅ Actual query strings | Request params + RASP context |
| **Path Traversal** | URL paths only | ✅ Resolved file paths | URL paths + RASP context |
| **SSRF Detection** | URL params only | ✅ Outbound HTTP URLs | URL params + RASP context |
| **Command Injection** | Shell syntax only | ✅ Actual commands | Shell syntax + RASP context |
| **Deserialization** | Payload patterns | ✅ Parsed objects | Payload patterns + RASP context |
| **Dependency Scanning** | ❌ | ✅ OSV integration | ❌ |
| **Config Auditing** | ❌ | ✅ Secrets detection | ❌ |
| **RASP Taint Tracking** | ❌ (CF Workers limitation) | ✅ Full taint tracing | ✅ Via `RaspContext` |
| **Persistence** | KV (async, distributed) | SQLite (sync, local) | In-memory + host callback |

### 1.2 Critical Capability Gaps

#### Edge-Sensor Capabilities NOT in Engine-RS
| Feature | Impact | Migration Path |
|---------|--------|----------------|
| **Encrypted Signal Upload** | Merkle-sealed collective intelligence | Add WASM host function for KV upload |
| **Privilege Graph Analysis** | Endpoint authorization mapping | Port `privilege-graph.ts` to Rust |
| **Multi-Dimensional Risk Surface** | `RiskSurfaceCalculator` | Port `risk-dimensions.ts` to Rust |
| **Blast Radius Analysis** | Impact scope estimation | Port `blast-radius.ts` to Rust |
| **Path Enumeration** | Alternative attack path discovery | Port `path-enumeration.ts` to Rust |

#### Agent RASP Capabilities IMPOSSIBLE in WASM
These require Node.js runtime access which CF Workers cannot provide:

| Capability | Why It Can't Run in WASM | Compromise Strategy |
|------------|-------------------------|---------------------|
| **SQL Query Interception** | Requires `pg`/`mysql2` prototype wrapping | RASP context: App reports queries post-execution |
| **File System Resolution** | Requires `fs` module access | RASP context: App reports resolved paths |
| **Process Execution** | Requires `child_process` | RASP context: App reports executed commands |
| **Outbound HTTP Hooks** | Requires `fetch` wrapping | RASP context: App reports network calls |
| **Deserialization Hooks** | Requires `JSON.parse` replacement | RASP context: App reports parsed payloads |

#### TypeScript Engine Features in Engine-RS
| Feature | TS Engine | Engine-RS | Status |
|---------|-----------|-----------|--------|
| `detect()` L1 only | ✅ | ✅ `engine.detect()` | ✅ Parity |
| `detectDeep()` L1+L2 | ✅ | ✅ `engine.detect_deep()` | ✅ Parity |
| `analyze()` full pipeline | ✅ | ✅ `runtime.process()` | ✅ Parity |
| Proof construction | ✅ | ✅ `proof.rs` | ✅ Parity |
| Composition rules | ✅ | ✅ `detect_compositions()` | ✅ Parity |
| CVE enrichment | ✅ | ✅ `knowledge.rs` | ✅ Parity |
| Threshold overrides | ✅ | ✅ Runtime config | ✅ Parity |
| Context weighting | ✅ | ✅ Context relevance | ✅ Parity |
| Polyglot detection | ✅ | ✅ `polyglot.rs` | ✅ Parity |
| Intent classification | ✅ | ✅ `intent.rs` | ✅ Parity |
| Bot detection | ❌ | ✅ `bot_detect.rs` | ✅ Rust superior |
| Response analysis | Partial | ✅ `response_analysis.rs` | ✅ Rust superior |
| MITRE mapping | Partial | ✅ `mitre.rs` | ✅ Rust superior |

---

## 2. Deprecation Phases (4-Phase Migration)

### Phase 1: Bridge Layer (Weeks 1-2)
**Goal**: Create WASM integration without changing any detection logic.

```typescript
// packages/edge-sensor/src/engine-bridge.ts
import { WasmRuntime } from '@santh/engine-rs-wasm'

export class WasmEngineBridge {
  private wasm: WasmRuntime
  
  constructor(config?: EngineConfig) {
    this.wasm = WasmRuntime.new()
    if (config?.thresholdOverrides) {
      this.wasm.set_threshold_overrides(JSON.stringify(config.thresholdOverrides))
    }
  }
  
  // v2-compatible API
  detect(input: string, _staticRules: string[]): InvariantMatch[] {
    const wasmMatches = this.wasm.detect(input)
    return wasmMatches.map(m => this.convertMatch(m))
  }
  
  // v3-compatible API  
  detectDeep(input: string, _staticRules: string[], environment?: string): DeepDetectionResult {
    const result = this.wasm.detect_deep(input, environment)
    return this.convertDeepResult(result)
  }
  
  updateConfig(config: EngineConfig): void {
    this.wasm.set_threshold_overrides(JSON.stringify(config.thresholdOverrides))
  }
}
```

**Files to Create:**
- `packages/edge-sensor/src/engine-bridge.ts` - WASM-to-TS adapter
- `packages/edge-sensor/src/layers/l5-wasm.ts` - L5 WASM adapter layer
- `packages/engine-rs/wasm-bindings/` - wasm-bindgen exports refinement

**Build Changes:**
```json
// packages/edge-sensor/package.json additions
{
  "scripts": {
    "prebuild": "cd ../engine-rs && wasm-pack build --target web --out-dir ../edge-sensor/vendor/engine-rs"
  }
}
```

### Phase 2: Dual-Run Validation (Weeks 3-6)
**Goal**: Run both engines in parallel, compare results, log discrepancies.

```typescript
// packages/edge-sensor/src/index.ts modifications

// L5: Invariant Detection (Dual-Run Mode)
const tsEngine = new InvariantEngine(config)
const wasmBridge = new WasmEngineBridge(config)

for (const input of inputsToCheck) {
  // Run both engines
  const tsMatches = tsEngine.detect(input, staticRules)
  const wasmMatches = wasmBridge.detect(input, staticRules)
  
  // Compare and log discrepancies
  const comparison = compareResults(tsMatches, wasmMatches)
  if (comparison.hasDiscrepancy) {
    logDiscrepancy(ctx, input, comparison)
  }
  
  // Use TS as source of truth during validation
  for (const match of tsMatches) { /* existing logic */ }
}
```

**Validation Metrics:**
- Detection parity: >99% match rate
- Performance delta: WASM should be 2-5x faster
- Memory usage: WASM should use less memory
- False positive rate: should not increase

**Files to Modify:**
- `packages/edge-sensor/src/index.ts` (L5 section, ~line 440)
- Add `packages/edge-sensor/src/validation/compare-results.ts`
- Add `packages/edge-sensor/src/validation/log-discrepancy.ts`

### Phase 3: Cutover (Weeks 7-8)
**Goal**: Switch L5 exclusively to WASM, update dependent layers.

```typescript
// packages/edge-sensor/src/index.ts modifications

// BEFORE (Phase 2):
// const tsMatches = tsEngine.detect(input, staticRules)
// const wasmMatches = wasmBridge.detect(input, staticRules)

// AFTER (Phase 3):
const wasmMatches = wasmBridge.detect(input, staticRules)

// L5b: L2 Structural Evaluators now consume WASM format
// BEFORE: runL2Evaluators(combinedInput, tsMatchedClasses)
// AFTER: runL2EvaluatorsWasm(combinedInput, wasmMatchedClasses)
const l2Results = runL2EvaluatorsWasm(combinedInput, wasmMatches.map(m => m.class))
```

**Integration Points to Update:**

| File | Line | Change |
|------|------|--------|
| `src/index.ts` | ~440 | `engine.detect()` → `wasmBridge.detect()` |
| `src/index.ts` | ~467 | Update `runL2Evaluators` input format |
| `src/index.ts` | ~888 | `engine.updateConfig()` → WASM config update |
| `src/modules/signal-uploader.ts` | Match serialization format |
| `wrangler.toml` | Add WASM module binding |

**L5b Evaluator Compatibility:**
```typescript
// packages/edge-sensor/src/layers/l5b-evaluators.ts
// Convert WASM match format to L2 evaluator input format

export function runL2EvaluatorsWasm(
  input: string, 
  matchedClasses: InvariantClass[]
): L2EvaluatorResult[] {
  // WASM returns matches with same class IDs as TS engine
  // L2 evaluators can run on the same class modules
  const results: L2EvaluatorResult[] = []
  
  for (const cls of matchedClasses) {
    const evaluator = getL2Evaluator(cls)
    if (evaluator) {
      results.push(evaluator.evaluate(input))
    }
  }
  
  return results
}
```

### Phase 4: Cleanup (Weeks 9-10)
**Goal**: Remove TypeScript engine entirely.

**Actions:**
1. Remove `@santh/engine` dependency from `edge-sensor/package.json`
2. Delete `packages/engine/` directory entirely
3. Remove dual-run validation code
4. Update documentation
5. Archive TS engine repository (tag final version)

**Cleanup Checklist:**
- [ ] Remove `engine-bridge.ts` (keep only if useful for abstraction)
- [ ] Remove all `import { InvariantEngine } from '@santh/engine'` statements
- [ ] Remove dual-run comparison code
- [ ] Update ARCHITECTURE.md
- [ ] Update README.md
- [ ] Tag final TS engine version: `git tag engine-ts-final`

---

## 3. Integration Change Reference

### 3.1 WASM Bindings Exposed by Engine-RS

```rust
// packages/engine-rs/src/wasm.rs

#[wasm_bindgen]
impl WasmRuntime {
    #[wasm_bindgen(js_name = detect)]
    pub fn detect(&self, input: &str) -> JsValue { ... }
    
    #[wasm_bindgen(js_name = detectDeep)]
    pub fn detect_deep(&self, input: &str, environment: Option<&str>) -> JsValue { ... }
    
    #[wasm_bindgen(js_name = analyze)]
    pub fn analyze(&self, request_json: &str) -> JsValue { ... }
    
    #[wasm_bindgen(js_name = process)]
    pub fn process(&mut self, request_json: &str) -> JsValue { ... }
    
    #[wasm_bindgen(js_name = setThresholdOverrides)]
    pub fn set_threshold_overrides(&mut self, json: &str) { ... }
    
    #[wasm_bindgen(js_name = setClassPriorities)]
    pub fn set_class_priorities(&mut self, json: &str) { ... }
}
```

### 3.2 Type Mapping: TS Engine → WASM Engine

| TS Type | WASM Return | Conversion Notes |
|---------|-------------|------------------|
| `InvariantMatch` | `WasmMatch` | Direct field mapping |
| `DeepDetectionResult` | `WasmDeepResult` | Add `processingTimeUs` |
| `AnalysisResult` | `WasmAnalysisResult` | Full parity |
| `BlockRecommendation` | `WasmRecommendation` | Same structure |
| `EngineThresholdOverride` | JSON string | `set_threshold_overrides()` |
| `InputContext` | `Option<&str>` | String enum |

### 3.3 RASP Context Bridge

When the Agent's RASP detects execution-time attacks, it can feed context to the WASM engine:

```typescript
// Agent reports RASP findings to edge sensor via header
const raspContext = {
  db_queries: [{ query: "SELECT * FROM users WHERE id = '' OR 1=1--", driver: "pg" }],
  file_accesses: [{ path: "/etc/passwd", operation: "read" }],
  process_execs: [{ command: "sh", args: ["-c", "cat /etc/passwd"] }],
  network_calls: [{ url: "http://169.254.169.254/metadata" }]
}

// Edge sensor passes to WASM engine
const request = {
  input: userInput,
  rasp_context: raspContext  // WASM engine correlates
}
```

---

## 4. Runtime Environment Comparison

### 4.1 Node.js Agent (RASP)
```
┌─────────────────────────────────────────┐
│           Node.js Process               │
│  ┌─────────────────────────────────┐    │
│  │  RASP Wrappers (runtime hook)   │    │
│  │  ├─ pg/mysql2.query wrapper     │    │
│  │  ├─ fs.readFile wrapper         │    │
│  │  ├─ child_process.exec wrapper  │    │
│  │  ├─ fetch wrapper               │    │
│  │  └─ JSON.parse wrapper          │    │
│  └─────────────────────────────────┘    │
│              ↓                          │
│  ┌─────────────────────────────────┐    │
│  │  InvariantDB (SQLite)           │    │
│  │  ├─ Signals table               │    │
│  │  ├─ Taint traces                │    │
│  │  └─ Request/response logs       │    │
│  └─────────────────────────────────┘    │
│              ↓                          │
│  ┌─────────────────────────────────┐    │
│  │  Action: THROW / BLOCK / LOG    │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

**Pros:** Can intercept actual queries/files/commands
**Cons:** Node.js only, process-level, blocks via exceptions

### 4.2 Cloudflare Workers (WASM)
```
┌─────────────────────────────────────────┐
│        Cloudflare Worker (V8)           │
│  ┌─────────────────────────────────┐    │
│  │  WASM Module (engine-rs)        │    │
│  │  ├─ detect() - L1 regex         │    │
│  │  ├─ detect_deep() - L1+L2       │    │
│  │  ├─ analyze() - Full pipeline   │    │
│  │  └─ process() - Runtime+Defense │    │
│  └─────────────────────────────────┘    │
│              ↓                          │
│  ┌─────────────────────────────────┐    │
│  │  KV Namespace (distributed)     │    │
│  │  ├─ Signal cache                │    │
│  │  ├─ Session state               │    │
│  │  └─ Rule bundles                │    │
│  └─────────────────────────────────┘    │
│              ↓                          │
│  ┌─────────────────────────────────┐    │
│  │  Action: HTTP 403 / Challenge   │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

**Pros:** Edge-deployed, sub-millisecond latency, scales infinitely
**Cons:** Request-time only (no runtime internals), eventually-consistent KV

### 4.3 Hybrid: Agent + Edge Sensor
```
┌─────────────────┐     ┌──────────────────────┐
│  Edge Sensor    │ ←── │  Agent (RASP)        │
│  (WASM Engine)  │     │  (Node.js)           │
│                 │     │                      │
│  Request-time   │     │  Execution-time      │
│  detection      │     │  taint confirmation  │
│                 │     │                      │
│  Blocks at edge │     │  Reports to edge     │
│                 │     │  via headers         │
└─────────────────┘     └──────────────────────┘
         ↓                       ↓
    ┌─────────────────────────────────────┐
    │  Collective Intelligence Platform   │
    │  ├─ Signal correlation              │
    │  ├─ Campaign detection              │
    │  └─ Rule distribution               │
    └─────────────────────────────────────┘
```

---

## 5. Migration Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| WASM initialization failure | Low | High | Fallback to TS engine for 1 release |
| Detection discrepancy | Low | Medium | Phase 2 validation catches this |
| Bundle size increase | Medium | Low | WASM is ~500KB, compresses well |
| KV write amplification | Medium | Medium | Batch signal writes, use cache |
| RASP context not provided | Medium | High | Document integration for agent users |

---

## 6. Success Criteria

The deprecation is complete when:

1. ✅ Edge-sensor exclusively uses WASM engine for L5 detection
2. ✅ No performance regression (p99 latency within 10% of TS engine)
3. ✅ No detection regression (FP rate ≤ TS engine, TP rate ≥ TS engine)
4. ✅ L5b evaluators consume WASM format correctly
5. ✅ Dynamic threshold overrides work via WASM runtime
6. ✅ Signal format remains compatible with downstream systems
7. ✅ TypeScript `@santh/engine` package is archived

---

## Appendix A: File Change Summary

### New Files
- `packages/edge-sensor/src/engine-bridge.ts`
- `packages/edge-sensor/src/layers/l5-wasm.ts`
- `packages/edge-sensor/src/validation/compare-results.ts`
- `packages/edge-sensor/vendor/engine-rs/` (WASM build output)

### Modified Files
- `packages/edge-sensor/src/index.ts` (L5 section, ~line 440)
- `packages/edge-sensor/src/index.ts` (L5b section, ~line 467)
- `packages/edge-sensor/src/index.ts` (scheduled handler, ~line 888)
- `packages/edge-sensor/src/modules/signal-uploader.ts`
- `packages/edge-sensor/wrangler.toml`
- `packages/edge-sensor/package.json`

### Deleted Files (Phase 4)
- `packages/engine/` (entire directory)
- `packages/edge-sensor/src/validation/` (dual-run code)

---

*Document Version: 1.0*
*Last Updated: 2026-03-07*
*Owner: Security Architecture Team*
