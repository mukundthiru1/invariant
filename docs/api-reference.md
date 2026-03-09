# INVARIANT API Reference

This document covers the core **InvariantEngine**, **chain detection**, **plugin system**, and the main **TypeScript interfaces** exported from the engine. Package: `@santh/invariant-engine` (or monorepo path `packages/engine/src`).

---

## InvariantEngine

**Constructor**

```ts
constructor(config?: EngineConfig)
```

- **config** (optional): Runtime overrides. Omit for default behavior (all 66 classes, static thresholds).
- **EngineConfig**:
  - `thresholdOverrides?: EngineThresholdOverride[]` — Per-class block thresholds (e.g. EPSS-weighted). Entries with `validUntil < Date.now()` are ignored.
  - `classPriorities?: Map<InvariantClass, number>` — Multipliers applied to confidence before threshold comparison (e.g. tech-stack-aware). `0` effectively disables a class.

**Instance properties**

| Property | Type | Description |
|----------|------|-------------|
| **registry** | `InvariantRegistry` | The class registry (all registered modules). |
| **knowledgeGraph** | `ExploitKnowledgeGraph` | Used for CVE enrichment in `analyze()`. |
| **classCount** | `number` | Number of registered classes. |
| **classes** | `InvariantClass[]` | All registered class IDs. |

---

### detect(input, staticRuleIds, environment?)

**Signature**

```ts
detect(
  input: string,
  staticRuleIds: string[],
  environment?: string
): InvariantMatch[]
```

- **input**: Raw string to analyze (e.g. query param, body field, header value).
- **staticRuleIds**: IDs of static/signature rules that already fired. If non-empty, matches are not marked as novel variants; can boost confidence when combined with invariant detection.
- **environment**: Optional context hint (e.g. `'sql'`, `'json'`, `'url'`) for calibration; not used for filtering.

**Returns**: Array of **InvariantMatch** (class, confidence, category, severity, description, isNovelVariant, detectionLevels). Uses **L1 (regex) only**; fast path.

---

### detectDeep(input, staticRuleIds, environment?)

**Signature**

```ts
detectDeep(
  input: string,
  staticRuleIds: string[],
  environment?: string
): DeepDetectionResult
```

Runs the full multi-level pipeline: L1 regex, L2 structural evaluators, L3 decomposition, context weighting, anomaly and polyglot analysis. Use when you need maximum detection and confidence quality.

**Returns**: **DeepDetectionResult**

| Field | Type | Description |
|-------|------|-------------|
| **matches** | `InvariantMatch[]` | All matches (L1 + L2 + L3 merged, deduplicated). |
| **novelByL2** | number | Count of matches detected only by L2. |
| **novelByL3** | number | Count of matches detected only by L3 decomposition. |
| **convergent** | number | Count of matches where L1 and L2 both agreed. |
| **processingTimeUs** | number | Total processing time in microseconds. |
| **contexts** | string[]? | Detected input contexts from decomposition. |
| **encodingDepth** | number? | Encoding layers from decomposition. |
| **anomalyProfile** | AnomalyProfile? | Entropy/structural anomaly data. |
| **encodingEvasion** | boolean? | Whether encoding evasion was detected. |
| **polyglot** | PolyglotDetection? | Multi-context (polyglot) analysis result. |

---

### analyze(request)

**Signature**

```ts
analyze(request: AnalysisRequest): AnalysisResult
```

Full analysis: runs `detectDeep`, applies source reputation, computes inter-class correlations and algebraic compositions, block recommendation, CVE enrichment, and intent classification.

**AnalysisRequest**

| Field | Type | Description |
|-------|------|-------------|
| **input** | string | Raw input to analyze. |
| **knownContext**? | InputContext | Optional context: `'sql'`, `'html'`, `'shell'`, `'xml'`, `'json'`, `'url'`, etc. |
| **sourceReputation**? | number | 0–1; if > 0.6, confidence is boosted. |
| **requestMeta**? | { method?, path?, contentType? } | Optional request metadata for intent classification. |

**AnalysisResult**

| Field | Type | Description |
|-------|------|-------------|
| **matches** | InvariantMatch[] | All matches (after reputation and correlation boosts). |
| **compositions** | AlgebraicComposition[] | Structural compositions (escape + payload + repair). |
| **correlations** | InterClassCorrelation[] | Inter-class compound patterns. |
| **recommendation** | BlockRecommendation | Whether to block and at what threshold. |
| **novelByL2** | number | L2-only match count. |
| **novelByL3** | number | L3-only match count. |
| **convergent** | number | Convergent (L1+L2) count. |
| **processingTimeUs** | number | Processing time in microseconds. |
| **contexts**? | string[] | Detected contexts. |
| **cveEnrichment**? | { totalLinkedCves, activelyExploitedClasses, highestEpss } | CVE summary. |
| **polyglot**? | { isPolyglot, domains, domainCount, confidenceBoost, detail } | Polyglot analysis. |
| **anomalyScore**? | number | Statistical anomaly score. |
| **encodingEvasion**? | boolean | Encoding evasion detected. |
| **intent**? | { primaryIntent, intents, confidence, detail, severityMultiplier, targets } | Attack intent classification. |

---

### detectHeaderInvariants(headers)

**Signature**

```ts
detectHeaderInvariants(headers: Headers): InvariantMatch[]
```

Checks headers for auth-bypass and JWT invariants (e.g. multiple X-Forwarded-* headers, X-Original-URL / X-Rewrite-URL, Bearer token with alg:none). Does not scan arbitrary header values as generic input; use `detect`/`detectDeep` for that.

**Returns**: Array of **InvariantMatch** (e.g. `auth_header_spoof`, `auth_none_algorithm`).

---

### shouldBlock(matches)

**Signature**

```ts
shouldBlock(matches: InvariantMatch[]): boolean
```

Returns `true` if the engine recommends blocking given the current thresholds and (optionally) EPSS/priority overrides. Implemented as `computeBlockRecommendation(matches, []).block`.

---

### highestSeverity(matches)

**Signature**

```ts
highestSeverity(matches: InvariantMatch[]): 'critical' | 'high' | 'medium' | 'low' | 'info'
```

Returns the highest severity among the given matches.

---

### updateConfig(config)

**Signature**

```ts
updateConfig(config: EngineConfig): void
```

Applies new threshold overrides and/or class priorities without reconstructing the engine. Used when a new rule bundle is applied (e.g. from edge sensor).

---

### generateVariants(cls, count)

**Signature**

```ts
generateVariants(cls: InvariantClass, count: number): string[]
```

Returns up to `count` variant payloads for the given class (from the class module’s `generateVariants`). Used for testing or probe generation.

---

## InvariantMatch

Returned by `detect`, `detectDeep`, `detectHeaderInvariants`, and inside `AnalysisResult`.

| Field | Type | Description |
|-------|------|-------------|
| **class** | InvariantClass | Class ID (e.g. `'sql_string_termination'`). |
| **confidence** | number | 0–1. |
| **category** | string | Attack category (e.g. `'sqli'`, `'xss'`). |
| **severity** | Severity | `'critical'` \| `'high'` \| `'medium'` \| `'low'`. |
| **isNovelVariant** | boolean | True if not matched by static rules (when staticRuleIds was empty). |
| **description** | string | Human-readable description from the class module. |
| **detectionLevels**? | { l1, l2, convergent: boolean } | Which levels fired. |
| **l2Evidence**? | string | Explanation from L2 evaluator. |
| **proof**? | PropertyProof | Optional constructive proof of property violation. |
| **cveEnrichment**? | { linkedCves, activelyExploited, highestEpss, verificationAvailable } | Optional CVE data. |

---

## BlockRecommendation

Returned by the internal `computeBlockRecommendation` and as part of **AnalysisResult.recommendation**.

| Field | Type | Description |
|-------|------|-------------|
| **block** | boolean | Whether to block the request. |
| **confidence** | number | Max confidence among matches (or composition). |
| **reason** | string | e.g. `'no_detections'`, `'below_severity_thresholds'`, or class/threshold reason. |
| **threshold** | number | Threshold that was used for the decision. |

---

## Chain detection

**Exports** (from `chain-detector.ts` or `@santh/invariant-engine`):

- **ATTACK_CHAINS**: `ChainDefinition[]` — All built-in chain definitions.
- **ChainCorrelator**: Class that advances per-source chain state and returns **ChainMatch[]**.
- **ChainDefinition**, **ChainStep**, **ChainSignal**, **ChainMatch** — Types (see [Chains](./chains.md)).

**ChainSignal** (input to the correlator):

- **sourceHash**: string (e.g. hashed IP or session ID)
- **classes**: InvariantClass[]
- **behaviors**: string[]
- **confidence**: number
- **path**: string
- **method**: string
- **timestamp**: number (ms)

**ChainMatch** (output):

- **chainId**, **name**, **description**, **severity**
- **stepsMatched**, **totalSteps**, **completion**, **confidence**
- **recommendedAction**: `'monitor'` \| `'throttle'` \| `'challenge'` \| `'block'` \| `'lockdown'`
- **stepMatches**, **durationSeconds**, **sourceHash**

---

## Plugin system

Plugins add custom **InvariantClassModule** implementations to the registry.

### InvariantPlugin

```ts
interface InvariantPlugin {
  readonly name: string
  readonly version: string
  readonly classes: InvariantClassModule[]
}
```

- **name**: Unique plugin name (non-empty).
- **version**: Semantic version string.
- **classes**: Array of class modules. Each must satisfy the **InvariantClassModule** contract (id, description, category, severity, detect, generateVariants, knownPayloads, knownBenign).

### PluginRegistry

```ts
class PluginRegistry {
  constructor(registry?: InvariantRegistry)

  register(plugin: InvariantPlugin): void
  unregister(pluginName: string): boolean
  getPlugin(name: string): InvariantPlugin | undefined
  listPlugins(): InvariantPlugin[]
  getRegistry(): InvariantRegistry
}
```

- **register(plugin)**: Validates the plugin and each class (contract + knownPayloads/knownBenign checks), then registers each class into the provided (or internal) **InvariantRegistry**. Throws **PluginError** if validation fails or name is duplicate.
- **unregister(name)**: Removes the plugin and all its classes from the registry.
- **getRegistry()**: Returns the **InvariantRegistry** used by this plugin registry.

### defineClass(module)

**Signature**

```ts
function defineClass(module: InvariantClassModule): InvariantClassModule
```

Validates the module against the class contract and returns it (frozen). Use before passing modules in a plugin’s `classes` array if you want early validation.

### PluginError

Error thrown when plugin validation fails (e.g. duplicate name, invalid class, missing fields). `message` is prefixed with `[PluginRegistry]`.

---

## InvariantClassModule

Contract for every invariant class (built-in or from a plugin).

| Field | Type | Description |
|-------|------|-------------|
| **id** | InvariantClass | Unique class ID. |
| **description** | string | Why this invariant is dangerous. |
| **category** | AttackCategory | e.g. `'sqli'`, `'xss'`, `'injection'`. |
| **severity** | Severity | `'critical'` \| `'high'` \| `'medium'` \| `'low'`. |
| **detect** | (input: string) => boolean | L1 regex detection. |
| **detectL2**? | (input: string) => DetectionLevelResult \| null | Optional L2 structural evaluator. |
| **generateVariants** | (count: number) => string[] | Generate test/probe payloads. |
| **knownPayloads** | string[] | Payloads that MUST be detected (regression). |
| **knownBenign** | string[] | Inputs that MUST NOT be detected (false positive). |
| **mitre**? | string[] | MITRE ATT&CK technique IDs. |
| **cwe**? | string | CWE ID. |
| **calibration**? | CalibrationConfig | Optional confidence tuning. |

---

## InvariantRegistry

Central registry for class modules (used by the engine and by **PluginRegistry**).

**Methods:**

- **register(module)**, **registerAll(modules)** — Register one or more **InvariantClassModule**. Validates contract and knownPayloads/knownBenign; throws **RegistryError** on duplicate ID or contract failure.
- **get(id)** — Get module by class ID.
- **all()** — All registered modules.
- **getByCategory(category)**, **getBySeverity(severity)** — Filter by category or severity.
- **classIds()** — All registered class IDs.
- **setCalibrationOverride(classId, override)** — Override calibration for a class.
- **getCalibration(classId)** — Effective calibration (default + override).
- **computeConfidence(classId, input, environment?, hasStaticMatch?)** — Confidence for a class given input and context.
- **computeCorrelations(matches)** — Inter-class correlation results.
- **stats()** — **RegistryStats** (totalClasses, byCategory, bySeverity, withCalibration, withOverrides).

**Property:** **size** — Number of registered classes.

---

## Other types (summary)

- **InvariantClass**: Union of all 66 class ID strings (see [Classes](./classes.md)).
- **AttackCategory**: `'sqli'` \| `'xss'` \| `'path_traversal'` \| `'cmdi'` \| `'ssrf'` \| `'deser'` \| `'auth'` \| `'injection'` \| `'smuggling'`.
- **Severity**: `'critical'` \| `'high'` \| `'medium'` \| `'low'`.
- **EngineThresholdOverride**: `{ invariantClass, adjustedThreshold, validUntil }`.
- **PropertyProof**, **ProofStep**: Proof of property violation (see classes/types.ts).
- **AnalysisRequest**, **AnalysisResult**: See [analyze](#analyze-request) above.
- **DeepDetectionResult**: See [detectDeep](#detectdeepinput-staticruleids-environment) above.

---

## References

- Engine: `packages/engine/src/invariant-engine.ts`
- Config: `packages/engine/src/config.ts`
- Classes: `packages/engine/src/classes/`
- Plugin: `packages/engine/src/plugin.ts`
- Chain detector: `packages/engine/src/chain-detector.ts`
- Public exports: `packages/engine/src/index.ts`
- [Classes reference](./classes.md)
- [Chains](./chains.md)
- [Configuration](./configuration.md)
