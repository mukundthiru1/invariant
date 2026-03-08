# INVARIANT — Complete Architecture Reference

> **Source of Truth.** All implementation decisions derive from this document.
> When code and this document conflict, this document wins — fix the code.
>
> **Last Updated:** 2026-03-05

---

## The Three Laws

These laws are inviolable. No deadline, no complexity, no investor, no team member overrides them.

### LAW 1 — NO STUBS. NOTHING IS BETTER THAN A FAKE.
A function that doesn't do what it says is a lie. A missing function is honest.
If you cannot implement something fully right now: delete it. Do not stub it.
A stub deceives callers, hides gaps, and rots. A gap is visible and fixable.

### LAW 2 — BACKWARDS COMPATIBLE FOR DECADES. COMPLETE MODULARITY.
Every public interface is a contract. Contracts are permanent.
- Never remove a public method, type, or field. Add; never remove.
- Never change a required parameter signature. Add optional parameters.
- Every module must be replaceable without modifying its callers.
- "Swappable in minutes" is the standard. If swapping requires 5 file changes outside the module boundary, the abstraction is wrong.

### LAW 3 — IF IT DOESN'T FIT, MAKE THE ARCHITECTURE FIT. NEVER THE REVERSE.
When a new requirement conflicts with the architecture, the answer is never "work around it."
The answer is always "extend the architecture cleanly to accommodate it."
This costs more upfront. It is the correct cost.

---

## System Overview

INVARIANT is a **federated sensor network with encrypted collective intelligence**.

The subscriber deploys open-source components to their own infrastructure.
Santh operates closed-source central processing that turns collective signals into rules.
Rules are dispatched back to sensors with forward-secret encryption — every cycle.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SANTH CENTRAL  (closed source)                   │
│                                                                     │
│  Signal Ingest DB ──▶ Pattern Analyzer ──▶ Rule Generator           │
│       ▲                                         │                   │
│       │ encrypted signals                       ▼                   │
│       │                              Rule Signer + Encryptor        │
│       │                                         │                   │
│       │                              Dispatch → Workers KV          │
│       │                              (per-subscriber, encrypted)    │
└───────┼─────────────────────────────────────────┼───────────────────┘
        │                                         │
        │  X25519+AES-256-GCM                     │  Ed25519+X25519
        │  (Santh pubkey)                         │  (subscriber pubkey)
        │                                         │
┌───────┼─────────────────────────────────────────┼───────────────────┐
│       │      SUBSCRIBER ZONE  (open source)      │                   │
│       │                                          │                   │
│  ┌────┴──────────────────────────────────────────┴─────────────────┐ │
│  │                  @santh/edge-sensor  (CF Worker)                │ │
│  │                                                                 │ │
│  │  Request ──▶ [14-layer detection pipeline] ──▶ decision         │ │
│  │                        │                          │             │ │
│  │                        ▼                          ▼             │ │
│  │              encrypt signal                block | pass         │ │
│  │                        │                                        │ │
│  │                        ▼                                        │ │
│  │              buffer ──▶ upload (on cron)                        │ │
│  │                                                                 │ │
│  │  Rule store: Workers KV (ciphertext only — never plaintext)     │ │
│  │  Decryption: in-memory only, never written                      │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  @santh/agent (RASP)          @santh/dashboard (localhost:4444)       │
│  ├── wraps sql/fs/exec/http   ├── reads encrypted local KV           │
│  └── local SQLite (encrypted) └── decrypts for display only          │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Encryption Protocol

This is the hardest part to get right. It is fully specified here.

### Signal Upload: Worker → Central

**Goal:** Central learns attack patterns. Central never sees raw request content.

```
Protocol: X25519-ECDH + AES-256-GCM

1. Worker generates ephemeral X25519 keypair per upload session
2. DH: shared_secret = ECDH(worker_ephemeral_privkey, santh_static_pubkey)
3. Key derivation: enc_key = HKDF-SHA256(shared_secret, "santh-signal-v1" || session_id)
4. Encryption: ciphertext = AES-256-GCM(enc_key, signal_bundle, aad=subscriber_id)
5. Upload: { ephemeral_pubkey, ciphertext, aad } → central ingest endpoint
6. Central decrypts: shared_secret = ECDH(santh_static_privkey, worker_ephemeral_pubkey)

Signal bundle contents (what central receives):
  - class: InvariantClass           (which invariant fired)
  - detectionLevel: 'l1'|'l2'|'l3' (how it was caught)
  - confidence: number              (0-1)
  - encodingDepth: number           (how many decode layers)
  - pathPattern: string             (normalized, no values)
  - method: string
  - timestamp: number
  - subscriberId: string            (pseudonymous)

Signal bundle NEVER contains:
  - Raw request body
  - Query parameter values
  - Cookie or authorization header values
  - IP address (hashed separately with daily-rotating salt)
  - Any PII
```

### Rule Dispatch: Central → Workers KV

**Goal:** Rules are cryptographically authenticated (can only come from Santh) and encrypted (only the target subscriber can read them). Rules have forward secrecy — each bundle uses a unique key.

```
Protocol: X25519 + Ed25519 + AES-256-GCM

SETUP (at npx @santh/invariant init):
  subscriber_keypair = X25519.generateKeypair()
  - private key stored in: CF Worker Secrets (INVARIANT_DECRYPT_KEY)
  - public key registered with Santh central
  subscriber_storage_key stored in: CF Worker Secrets (INVARIANT_STORAGE_KEY)

DISPATCH (per cycle, default: every hour):
  1. Santh generates bundle_key:
       bundle_key = HKDF-SHA256(subscriber_master, subscriber_id || bundle_version || unix_ts_hour)
  2. Santh encrypts rule bundle:
       enc_rules = AES-256-GCM(bundle_key, rule_bundle, aad=subscriber_id || bundle_version)
  3. Santh encrypts bundle_key to subscriber:
       enc_bundle_key = X25519-seal(subscriber_pubkey, bundle_key)
  4. Santh signs the dispatch payload:
       signature = Ed25519.sign(santh_signing_key, enc_rules || enc_bundle_key || bundle_version || expiresAt)
  5. Write to subscriber's KV:
       KV["invariant:rules:pending"] = { enc_rules, enc_bundle_key, bundle_version, expiresAt, signature }

RECEIPT (worker startup and on cron):
  1. Read KV["invariant:rules:pending"]
  2. Verify signature with Santh's static Ed25519 public key (embedded in worker)
     → if invalid: reject entirely, log tamper attempt, keep previous rules
  3. Check expiresAt > now() → if expired: reject, alert
  4. Decrypt bundle_key: bundle_key = X25519-open(INVARIANT_DECRYPT_KEY, enc_bundle_key)
  5. Decrypt rules: rule_bundle = AES-256-GCM-open(bundle_key, enc_rules)
  6. Apply rules to in-memory rule store
  7. NEVER write plaintext rules to KV
  8. Delete KV["invariant:rules:pending"] after successful application

Rule bundle contents:
  - version: number
  - expiresAt: number                         (unix timestamp, default: now + 2h)
  - l1_additions: PatternRule[]               (new L1 regex rules)
  - l1_removals: string[]                     (rule IDs to retire)
  - threshold_overrides: ThresholdOverride[]  (EPSS-weighted adjustments)
  - class_priorities: ClassPriority[]         (tech-stack-aware weights)
  - blocklist_additions: string[]             (IP hash additions)
  - blocklist_removals: string[]              (IP hash removals)
```

### Local Storage Encryption

```
Workers KV (edge sensor):
  All values encrypted before write:
    key:   INVARIANT_STORAGE_KEY (from CF Worker Secrets)
    cipher: AES-256-GCM
    aad:   kv_key_name (prevents key-swapping attacks)
    format: base64(nonce || ciphertext || tag)

SQLite (RASP agent):
  File encrypted at rest using libsodium secretbox (XSalsa20-Poly1305)
  Key: INVARIANT_DB_KEY env var (user sets at init, never stored in project)
  Per-row encryption for signal table (additional layer)
```

### Forward Secrecy Guarantee

An attacker who captures the entire encrypted Workers KV of a subscriber at time T faces:
1. AES-256-GCM ciphertext (computationally infeasible to break directly)
2. Even if they break it: the rule bundle has `expiresAt = T + 2h`
3. By the time they break it (theoretically: millions of years), the rules have been replaced hundreds of times
4. The `bundle_key` is derived from a time-component: HKDF(master, ...|| unix_ts_hour). Even Santh cannot reconstruct the bundle_key for past hours without storing it (which it does not).

This is forward secrecy: compromise of future keys does not reveal past communications.

---

## Open Source Split

### Open Source: `@santh/invariant` (npm package people install)

```
packages/
├── engine/        @santh/invariant-engine   zero-dep detection core
├── edge-sensor/   @santh/edge-sensor        CF Worker
├── agent/         @santh/agent              Node.js RASP
├── dashboard/     @santh/dashboard          localhost:4444
└── cli/           @santh/invariant          npx entry point
```

Every line of code that runs on a subscriber's infrastructure is public.
The subscriber can audit exactly what INVARIANT does to their traffic.
The encryption implementation is visible — the keys are not.

### Closed Source: Santh Central

```
intel/
├── pollers/       7 data sources (NVD, CISA KEV, GHSA, EPSS, OSV, GreyNoise, Exploit Monitor)
├── pipeline/      Signal processing, correlation, rule generation
├── dispatch/      Rule encryption, per-subscriber KV writes, key management
└── api/           Signal ingest endpoint, subscriber registration, key exchange
```

The processing intelligence is the product. The sensor code is the trust.

---

## Package Architecture

### @santh/invariant-engine

**Contract:** Zero runtime dependencies. Runs in Workers, Node.js, Bun, Deno — anywhere JS runs.
**Stability guarantee:** v1.x is stable forever. Additive changes only after v1.0.0.

```
src/
├── index.ts                   Public API barrel — never remove an export
├── invariant-engine.ts        InvariantEngine class (detect, detectDeep, analyze)
├── unified-runtime.ts         UnifiedRuntime (full 8-step pipeline)
├── chain-detector.ts          ChainCorrelator (multi-step attack chain detection)
├── defense-validator.ts       DefenseValidator (self-testing coverage)
├── mitre-mapper.ts            MitreMapper (ATT&CK v14 mapping)
│
├── classes/
│   ├── types.ts               InvariantClassModule interface — the contract
│   ├── registry.ts            InvariantRegistry — additive-only, enforces contract at registration
│   ├── encoding.ts            deepDecode — multi-layer decoder
│   ├── index.ts               ALL_CLASS_MODULES barrel + category exports
│   ├── sqli/                  8 SQL injection classes
│   ├── xss/                   5 XSS classes
│   ├── path/                  4 path traversal classes
│   ├── cmdi/                  3 command injection classes
│   ├── ssrf/                  3 SSRF classes
│   ├── deser/                 3 deserialization classes
│   ├── auth/                  2 auth bypass classes
│   └── injection/             25 injection classes (proto, log4shell, ssti, nosql, ...)
│
├── evaluators/
│   ├── evaluator-bridge.ts    Runs all L2 evaluators, merges with L1 results
│   ├── sql-expression-evaluator.ts    Tautology AST evaluation
│   ├── sql-structural-evaluator.ts    6 SQL classes via tokenization
│   ├── xss-context-evaluator.ts       HTML tokenizer + context analysis
│   ├── cmd-injection-evaluator.ts     Shell syntax tokenization
│   ├── path-traversal-evaluator.ts    Path resolution + multi-layer decode
│   ├── ssrf-evaluator.ts              URL parsing + IP normalization
│   ├── ssti-evaluator.ts              Template expression parser
│   ├── nosql-evaluator.ts             JSON key + MongoDB operator analysis
│   ├── xxe-evaluator.ts               XML DTD + entity chain analysis
│   ├── crlf-evaluator.ts              Header pattern matching
│   ├── redirect-evaluator.ts          URL parser + 6 bypass detectors
│   ├── proto-pollution-evaluator.ts   JSON deep key walker
│   ├── log4shell-evaluator.ts         Recursive nested lookup resolver
│   ├── deser-evaluator.ts             Java/PHP/Python format analysis
│   ├── ldap-evaluator.ts              RFC 4515 filter tokenization
│   ├── graphql-evaluator.ts           Depth/batch/alias/fragment analysis
│   └── http-smuggle-evaluator.ts      CL/TE desync + H2 header parser
│
├── decomposition/
│   ├── input-decomposer.ts            L3: multi-layer decode → context detect → property extract
│   ├── exploit-knowledge-graph.ts     CVE → tech → invariant property mapping
│   ├── exploit-verifier.ts            PoC validation against subscriber configs
│   └── campaign-intelligence.ts       Behavioral fingerprinting + attack phase modeling
│
├── evidence/
│   └── evidence-sealer.ts             Merkle-tree cryptographic proof generation
│
└── tokenizers/
    ├── html-tokenizer.ts
    ├── shell-tokenizer.ts
    └── template-tokenizer.ts
```

**Module contract for invariant classes:**

```typescript
interface InvariantClassModule {
    // Identity — immutable after registration
    readonly id: InvariantClass
    readonly description: string
    readonly category: AttackCategory
    readonly severity: Severity

    // L1: Fast regex (required)
    readonly detect: (input: string) => boolean

    // L2: Structural evaluator (optional — if present, must be correct)
    readonly detectL2?: (input: string) => DetectionLevelResult | null

    // Self-testing (enforced at registration time — not optional)
    readonly knownPayloads: string[]   // ALL must return detect()=true
    readonly knownBenign:   string[]   // ALL must return detect()=false

    // Variant generation (used for self-testing + discovery automation)
    readonly generateVariants: (count: number) => string[]

    // Documentation
    readonly formalProperty?: string   // ISL pseudo-notation
    readonly mitre?: string[]
    readonly cwe?: string

    // Composition
    readonly composableWith?: InvariantClass[]

    // Calibration
    readonly calibration?: CalibrationConfig
}
```

**Registry contract:** `register()` validates knownPayloads and knownBenign at registration time. A class that doesn't detect its own payloads cannot be registered. This is not a test — it is the guarantee.

### @santh/edge-sensor

**Contract:** Cloudflare Worker. Stateless per-request detection. State via Workers KV only.
**Backwards compat:** The ingest API (signal upload format) is versioned. Central accepts all versions simultaneously.

**14-layer detection pipeline:**
```
Layer  1: Static signatures              (L1 regex, 28+ rules)
Layer  2: Behavioral analysis            (BehaviorTracker — rate, path spray, entropy)
Layer  3: Client fingerprinting          (TLS, browser, bot, scanner classification)
Layer  3b: Request body analysis         (JSON/form/multipart parsing + deep inspection)
Layer  4: Technology detection           (TechStackTracker — 22+ tech fingerprints)
Layer  5: InvariantEngine.analyze()      (53 classes, L1+L2+L3, convergent detection)
Layer  5b: L2 evaluator bridge           (runL2Evaluators, mergeL2Results)
Layer  5c: IOC feed correlation          (IP hash / domain / payload / UA / CVE feeds)
Layer  5d: MITRE ATT&CK enrichment       (MitreMapper — 25+ techniques)
Layer  5e: Multi-dimensional risk surface (4-axis: security/privacy/compliance/operational)
Layer  5f: Threat scoring                (ThreatScoringEngine — composite score)
Layer  6: Defense decision               (block | pass | challenge — threshold-based)
Layer  7: Response audit                 (header stripping, info leak detection)
          ↓ cron triggers:
Layer  8: Internal probing               (InternalProber — 40+ probe targets)
Layer  9: Drift detection                (DriftDetector — temporal posture comparison)
```

**Encryption integration points (new):**
```
Signal path:    detect → buffer → [cron] encrypt(signal, santh_pubkey) → upload
Rule path:      [startup/cron] fetch KV → verify(Ed25519, santh_verify_key) → decrypt(subscriber_privkey) → apply in-memory
Storage path:   write → encrypt(value, INVARIANT_STORAGE_KEY) → KV.put
                read → KV.get → decrypt(value, INVARIANT_STORAGE_KEY)
```

### @santh/agent

**Contract:** Node.js 20+. Wraps stdlib APIs. Fails safe (detection failure never breaks application).
**Defense modes:** `observe` | `sanitize` | `defend` | `lockdown`

RASP wraps: `pg`, `mysql2`, `fs`, `fetch`, `child_process`, `JSON.parse`

### @santh/cli

**Contract:** `npx @santh/invariant` works without any global install. All commands documented in README.

Commands: `init`, `scan`, `dashboard`, `deploy`, `watch`, `status`

---

## Architecture Decisions (Committed)

These are decided and implemented or scheduled for next implementation cycle. They are not aspirational.

### AD-1: Collective Invariant Propagation

**Problem:** Sensor A detects a novel variant (L2-only, regex missed it). Sensor B sees the same attack 10 minutes later — still no L1 rule. Every sensor reinvents the wheel.

**Decision:** When any sensor reports a signal with `detectionLevel: 'l2'` or `'l3'` (novel), the central pipeline:
1. Deduplicates by property hash (same invariant class + similar evidence)
2. Aggregates across subscribers (N sensors saw it → higher confidence)
3. Synthesizes a candidate L1 regex pattern from the evidence
4. Adds it to the next rule dispatch bundle as `l1_additions`
5. All sensors globally get the new L1 rule in the next cycle (≤1 hour)

**Interface (in rule bundle):**
```typescript
interface PatternRule {
    id: string                    // stable, never reused
    invariantClass: InvariantClass
    pattern: string               // regex source
    flags: string                 // 'i' | 'gi' | ''
    minConfidence: number
    source: 'central' | 'sensor_collective'
    addedAt: number               // unix timestamp
    expiresAt?: number            // if temporary
}
```

### AD-2: EPSS-Weighted Block Thresholds

**Problem:** `critical` threshold is 0.45 regardless of whether the CVE is theoretical (EPSS 0.001) or actively exploited by nation-states (EPSS 0.97).

**Decision:** Thresholds are dynamically adjusted per dispatch based on EPSS data from the Intel pipeline.

```typescript
interface ThresholdOverride {
    invariantClass: InvariantClass
    epss: number                  // 0-1, from EPSS feed
    adjustedThreshold: number     // base_threshold × (1 - epss × 0.3)
    linkedCve: string
    validUntil: number            // unix timestamp
}
```

Base thresholds (static fallback when no override dispatched):
```
critical: 0.45
high:     0.65
medium:   0.80
low:      0.92
```

### AD-3: Tech-Stack-Aware Class Prioritization

**Problem:** Running `deser_java_gadget` at high priority on a WordPress PHP site generates noise and wastes compute.

**Decision:** Dispatched rule bundles include class priority adjustments based on the subscriber's detected tech stack. TechStackTracker identifies the stack; central dispatches appropriate `ClassPriority` adjustments.

```typescript
interface ClassPriority {
    invariantClass: InvariantClass
    priorityMultiplier: number    // 0.0 (skip) to 2.0 (high priority)
    reason: string                // e.g., 'tech_stack:wordpress'
}
```

Known tech → priority mappings (central generates, not hardcoded in worker):
- WordPress → `deser_php_object` ×1.5, `mass_assignment` ×1.5, `deser_java_gadget` ×0.1
- Node.js → `proto_pollution` ×1.8, `nosql_operator_injection` ×1.5
- Spring/Java → `deser_java_gadget` ×2.0, `ssti_el_expression` ×1.8
- Django/Rails → `ssti_jinja_twig` ×1.5

### AD-4: Research Ingestion Pipeline (Santh Central)

**Problem:** A paper published at USENIX Security takes weeks to become a CrowdStrike detection. We can do it in hours.

**Decision:** Automated pipeline (central, closed source):
1. Monitor: arXiv cs.CR daily digest, USENIX/S&P/CCS proceedings RSS
2. Extract: attack class descriptions, sample payloads, CWE mappings
3. Generate: candidate `InvariantClassModule` skeleton (L1 pattern + formalProperty)
4. Queue: for human review in internal tool
5. Review: security engineer validates in < 1 hour
6. Ship: added to next dispatch bundle as `l1_additions`

The open-source engine has no coupling to this pipeline. New classes arrive via the standard `PatternRule` dispatch format.

### AD-5: Formal ISL Verification

**Problem:** `formalProperty` is documentation. There's no machine-checkable connection between the formal spec and the implementation.

**Decision:** `formalProperty` strings follow a restricted grammar that a verifier can parse and use to auto-generate test cases. The verifier runs in CI on every class change.

```
formalProperty grammar (ISL-lite):
  "∃ subexpr ∈ parse(input, GRAMMAR) : eval(subexpr, CONTEXT) ∈ {RESULT_SET}"

  GRAMMAR:  SQL_GRAMMAR | HTML_GRAMMAR | SHELL_GRAMMAR | URL_GRAMMAR | JSON_GRAMMAR
  CONTEXT:  BOOLEAN_CONTEXT | STRING_CONTEXT | NUMERIC_CONTEXT
  RESULT_SET: {TRUE} | {TAUTOLOGY} | {TRUTHY} | ...
```

The verifier: parses the formalProperty → generates 100 random inputs matching the spec → asserts all are detected. If any evade, CI fails.

### AD-6: Per-Subscriber Exposure Scoring

**Problem:** Subscribers know INVARIANT blocked something. They don't know how exposed they are.

**Decision:** Central computes an exposure score per subscriber on each dispatch:

```
exposure_score = Σ(relevant_cves) (epss × probe_volume_weight × tech_match_score)

Where:
  relevant_cves = CVEs in knowledge graph matching subscriber's tech stack
  epss = EPSS score from daily feed
  probe_volume_weight = normalized count of signals for that class in last 48h
  tech_match_score = 0.0-1.0 from TechStackTracker confidence
```

Delivered to dashboard as `ExposureReport` in the dispatched bundle (encrypted, subscriber-side only).

### AD-7: Variant Discovery Automation

**Problem:** When a CVE drops with a published PoC, it takes analyst time to check if INVARIANT catches all variants.

**Decision:** Automated pipeline (central, runs on new CVE ingest):
1. Fetch PoC from ExploitMonitor feed
2. Identify which invariant classes the PoC exercises
3. Run `generateVariants(200)` for each relevant class
4. Run every variant through the engine in simulation mode
5. Collect evasions (variants that don't detect)
6. If evasions found: auto-open internal issue with evidence + candidate fix
7. Publish the gap + fix as a santh.io article (content marketing + proof of research velocity)

---

## Adding a New Invariant Class

Follow this protocol exactly. Do not deviate.

```
1. Create file: packages/engine/src/classes/{category}/{class_name}.ts
   Implement InvariantClassModule fully. No stubs.
   Required fields: id, description, category, severity, detect, generateVariants,
                    knownPayloads (≥5 malicious), knownBenign (≥5 safe)

2. Add L2 evaluator (if the class benefits from structural analysis):
   Create or extend: packages/engine/src/evaluators/{class_name}-evaluator.ts
   Wire into evaluator-bridge.ts (add a new try/catch block — never remove existing ones)

3. Add to category barrel:
   packages/engine/src/classes/{category}/index.ts → add to CATEGORY_CLASSES array

4. Add type to InvariantClass union:
   packages/engine/src/classes/types.ts → add to the union type

5. Run: cd packages/engine && npm test
   All 151+ tests must pass. The new class's knownPayloads and knownBenign
   are validated automatically by the registry contract.

6. Update count in README.md and ARCHITECTURE.md.
```

**What the registry does at registration time (not at test time):**
```typescript
// In register():
for (const payload of module.knownPayloads) {
    if (!module.detect(payload)) throw new RegistryError(`detect() misses: ${payload}`)
}
for (const benign of module.knownBenign) {
    if (module.detect(benign)) throw new RegistryError(`detect() false-positives on: ${benign}`)
}
```
If this throws, the engine fails to initialize. This is the contract enforcement.

---

## Swapping a Module (Backwards Compat Guarantee)

This is how modularity is validated. Every module must be swappable by:
1. Implementing the same interface in a new file
2. Updating the single import in the consuming module
3. Running tests

No other files change. If they do, the abstraction is wrong and must be fixed before merge.

**Example: replacing the SQL expression evaluator**
```
Old: packages/engine/src/evaluators/sql-expression-evaluator.ts
     exports: detectTautologies(input: string): TautologyResult[]

New: packages/engine/src/evaluators/sql-expression-evaluator-v2.ts
     exports: detectTautologies(input: string): TautologyResult[]  ← same signature

Change: sql-structural-evaluator.ts imports from v2 instead of v1
        evaluator-bridge.ts imports from v2 instead of v1
        Two files changed, zero interface changes.
```

---

## Memory Bounds

Every stateful component has explicit memory bounds. Unbounded growth is a bug.

| Component | Bound | Enforcement |
|---|---|---|
| ChainCorrelator source windows | 5,000 | LRU eviction |
| ChainCorrelator signals per window | 200 | Ring buffer |
| CampaignIntelligence sessions | 10,000 | LRU eviction |
| BehaviorTracker (edge sensor) | 10,000 sources | LRU eviction |
| Signal buffer (pre-upload) | 500 signals | Drop-oldest on overflow |
| Rule store (in-memory) | O(rules) | Bounded by dispatch bundle size limit |
| Evidence sealer | Batched | Written to disk, not retained |
| ExploitKnowledgeGraph | Static | Read-only after init |

---

## Test Counts and Coverage

```
packages/engine:        run with: cd packages/engine && npm test
packages/agent:         run with: cd packages/agent && npm test
packages/edge-sensor:   run with: cd packages/edge-sensor && npm test
workspace:              run with: npm run test --workspaces

Total: 151+ tests, all passing. Zero warnings.
```

Coverage requirements:
- Every invariant class: knownPayloads + knownBenign validated at registration (automatic)
- Every L2 evaluator: ≥5 test cases in engine.test.ts or evaluator's own test file
- Every attack chain: at least one complete chain detection test
- FP suite: 50+ benign inputs that must not trigger any class

---

## What Is Implemented vs Planned

### Implemented (ship now)
- 53 invariant classes (L1 + L2 for all)
- 3-level detection pipeline (L1 regex, L2 structural, L3 decomposer)
- 14-layer edge sensor pipeline
- ChainCorrelator (12 chain definitions)
- CampaignIntelligence (behavioral fingerprinting)
- ExploitKnowledgeGraph (CVE → class mapping)
- EvidenceSealer (Merkle proofs)
- MitreMapper (ATT&CK v14)
- DefenseValidator (self-testing)
- UnifiedRuntime (8-step orchestration)
- RASP agent (5 wraps)
- Dashboard (4-tab, localhost:4444)
- CLI (6 commands)

### Planned (next implementation cycle — in priority order)
1. Encryption protocol (AD-1 through AD-7 infrastructure)
   - Signal upload encryption (X25519 + AES-256-GCM)
   - Rule dispatch encryption (Ed25519 + X25519 + AES-256-GCM)
   - Local storage encryption (Workers KV + SQLite)
2. Collective invariant propagation (AD-1)
3. EPSS-weighted thresholds (AD-2)
4. Tech-stack-aware prioritization (AD-3)
5. Formal ISL verifier (AD-5)
6. Per-subscriber exposure scoring (AD-6)
7. Variant discovery automation (AD-7)
8. Research ingestion pipeline (AD-4) — central only

Nothing above is stubbed. Nothing is listed as implemented before it is. When implemented, move it from Planned to Implemented.
