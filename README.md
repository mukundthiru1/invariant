# INVARIANT

> **Full-stack automated defense. One command.**

INVARIANT protects your application at every layer — from the edge to the runtime. It's not a WAF. It's a defense reasoning engine that understands the **mathematical invariants** underlying every attack class.

One payload discovered → decompose into invariant property → defend against ALL expressions → patch for payloads that haven't been written yet.

## Quick Start

```bash
npx @santh/invariant
```

That's it. INVARIANT will:

1. **Scan** your dependencies against the OSV vulnerability database
2. **Audit** your configuration for security issues
3. **Compute** a posture grade
4. **Start** the defense agent

## Commands

```bash
npx @santh/invariant              # Interactive setup
npx @santh/invariant scan         # Scan dependencies + config
npx @santh/invariant dashboard    # Open localhost:4444 dashboard
npx @santh/invariant status       # Show current posture grade
npx @santh/invariant deploy       # Deploy edge sensor to Cloudflare
npx @santh/invariant watch        # Continuous monitoring
```

## Programmatic Usage

```javascript
import { InvariantAgent } from '@santh/agent'

const agent = new InvariantAgent({
    mode: 'observe',      // observe → sanitize → defend → lockdown
    scanOnStart: true,
    auditOnStart: true,
})

await agent.start()

// Wrap database modules
import pg from 'pg'
agent.wrapPg(pg)

// Wrap JSON.parse for deser attack detection
agent.wrapJsonParse()

// Wrap global fetch for SSRF detection
agent.wrapGlobalFetch()
```

### Express Middleware

```javascript
import express from 'express'
import { invariantMiddleware } from '@santh/agent/middleware/express'

const app = express()
app.use(invariantMiddleware({ mode: 'observe' }))
```

## Defense Modes

| Mode | Behavior |
|------|----------|
| `observe` | Detect and log. Never block. |
| `sanitize` | Normalize dangerous inputs when safe. |
| `defend` | Block critical + high severity attacks. |
| `lockdown` | Block everything suspicious. |

## What It Detects

### 46 Invariant Classes (Detection Core)

| Category | Classes | Count |
|----------|---------|-------|
| **SQL Injection** | Tautology, string termination, union extraction, stacked execution, time oracle, error oracle, comment truncation | 7 |
| **XSS** | Tag injection, event handler, protocol handler, template expression, attribute escape | 5 |
| **Command Injection** | Separator, substitution, argument injection | 3 |
| **Path Traversal** | dotdot escape, null terminate, encoding bypass, normalization bypass | 4 |
| **SSRF** | Internal reach, cloud metadata, protocol smuggle | 3 |
| **SSTI** | Jinja/Twig, Expression Language | 2 |
| **NoSQL Injection** | Operator injection, JS injection | 2 |
| **XXE** | Entity expansion | 1 |
| **CRLF** | Header injection, log injection | 2 |
| **Open Redirect** | URL redirect bypass | 1 |
| **Prototype Pollution** | __proto__ / constructor.prototype | 1 |
| **Log4Shell** | JNDI lookup | 1 |
| **Deserialization** | Java gadget, PHP object, Python pickle | 3 |
| **LDAP** | Filter injection | 1 |
| **GraphQL** | Introspection, batch/depth abuse | 2 |
| **HTTP Smuggling** | CL-TE desync, H2 pseudo headers | 2 |
| **XML** | XML injection | 1 |
| **Auth** | JWT alg:none, header spoof, CORS abuse, mass assignment | 4 |
| **ReDoS** | Regex denial of service | 1 |

### Two-Level Detection Architecture

- **Level 1 (Regex)**: InvariantEngine — fast pattern matching across all 46 classes
- **Level 2 (Structural)**: 16 specialized evaluators — expression parsing, AST analysis, context-aware validation
- **Convergence**: When both levels detect the same class, confidence is upgraded. When L2 catches something L1 missed, it's flagged as a novel variant.

### Attack Chain Correlation

12 predefined multi-step attack sequences are continuously evaluated:

| Chain | Pattern | Severity |
|-------|---------|----------|
| LFI → Credential Theft | Traversal → sensitive file → credential use | Critical |
| SQLi → Data Exfiltration | Blind probe → UNION extract → stacked execution | Critical |
| SSRF → Cloud Credential Theft | Internal SSRF → metadata endpoint → credential extraction | Critical |
| XSS → Session Hijack | Script injection → cookie theft → admin access | Critical |
| Deserialization → RCE | Gadget chain → command execution | Critical |
| Prototype Pollution → RCE | __proto__ → child_process | Critical |
| Log4Shell → RCE | JNDI lookup → remote class loading | Critical |
| Scanner → Targeted Exploit | Automated recon → specific payload | High |
| Multi-Vector SQLi | Error → boolean → UNION → stacked | Critical |
| SSTI → Template RCE | Template probe → class traversal → code execution | Critical |
| XXE → SSRF → Internal Pivot | Entity injection → server-side request | Critical |
| Auth Bypass → Privesc | JWT/header bypass → mass assignment | Critical |

### Edge Sensor (Cloudflare Worker) — 14-Layer Pipeline

```
Request → L1: Static Signatures (28 rules)
        → L2: Behavioral Analysis (rate/path/method anomalies)
        → L3: Client Fingerprinting (8 client classes)
        → L3b: Request Body Analysis (JSON/form/multipart)
        → L4: Technology Detection (22 technologies)
        → L5: InvariantEngine (46 invariant classes)
        → L5b: L2 Evaluator Bridge (16 structural evaluators)
        → L5c: IOC Feed Correlation (IP/domain/payload/UA intel)
        → L5d: MITRE ATT&CK Enrichment (25+ techniques mapped)
        → L5e: Multi-Dimensional Risk Surface (4-axis scoring)
        → L5f: Threat Scoring (composite score with chain correlation)
        → L6: Defense Decision (monitor/enforce/block)
        → [Block Response | Pass to Origin]
        → L7: Response Audit (security headers, version leaks)
        → L8: Internal Probing (scheduled, 40+ probe targets)
        → L9: Drift Detection (temporal posture comparison)
```

### Application Intelligence Modules

| Module | Purpose |
|--------|---------|
| **Application Model** | Passively learns endpoint structure, auth patterns, response characteristics |
| **Privilege Graph** | Infers privilege levels from observed traffic — detects sensitive endpoints served publicly |
| **CVE-Stack Correlation** | Maps detected technologies to CPE → CWE associations |
| **Blast Radius Engine** | Computes impact scope of a compromised endpoint |
| **Path Enumeration** | Finds alternative routes to same data through shared auth |
| **Reactivation Engine** | Identifies how misconfigurations re-enable "patched" vulnerabilities |
| **Threat Scoring** | Synthesizes multi-source signals into composite threat score |
| **Response Auditor** | Audits origin responses for missing security headers |
| **Internal Prober** | Probes origin for exposed `.env`, admin panels, debug endpoints |
| **Sensor State** | KV-backed persistence for application model, reputation, rules |
| **Rule Sync** | Pulls detection rules from intel pipeline |
| **Body Analysis** | Extracts values from JSON/form/multipart for deep inspection |
| **IOC Correlator** | Cross-references traffic against threat intelligence feeds |
| **Drift Detector** | Compares posture snapshots over time — detects security regressions |
| **Risk Surface** | Decomposes threats into security/privacy/compliance/operational axes |

### Engine Intelligence (from Axiom Drift merge)

| Module | Purpose |
|--------|---------|
| **Evidence Sealer** | Merkle-tree based cryptographic proofs for tamper-proof signal trails |
| **MITRE ATT&CK Mapper** | Maps all 46 invariant classes to ATT&CK techniques and kill chain phases |

### Static Analysis

- **Dependency Vulnerabilities** — OSV database (zero API keys needed)
- **Configuration Auditing** — Exposed secrets, missing gitignore, debug mode, CORS misconfiguration

## Architecture

```
invariant/
├── packages/
│   ├── engine/            ← Detection core (zero deps, runs anywhere)
│   │   ├── invariant-engine.ts     46 invariant classes
│   │   ├── chain-detector.ts       12 attack chain definitions
│   │   ├── defense-validator.ts    Self-testing defense patterns
│   │   ├── evaluators/             16 L2 structural evaluators
│   │   │   ├── evaluator-bridge.ts     Unified L1+L2 interface
│   │   │   ├── sql-expression-evaluator.ts
│   │   │   ├── sql-structural-evaluator.ts
│   │   │   ├── xss-context-evaluator.ts
│   │   │   ├── cmd-injection-evaluator.ts
│   │   │   ├── path-traversal-evaluator.ts
│   │   │   ├── ssrf-evaluator.ts
│   │   │   ├── ssti-evaluator.ts
│   │   │   ├── nosql-evaluator.ts
│   │   │   ├── xxe-evaluator.ts
│   │   │   ├── crlf-evaluator.ts
│   │   │   ├── redirect-evaluator.ts
│   │   │   ├── proto-pollution-evaluator.ts
│   │   │   ├── log4shell-evaluator.ts
│   │   │   ├── deser-evaluator.ts
│   │   │   ├── ldap-evaluator.ts
│   │   │   ├── graphql-evaluator.ts
│   │   │   └── http-smuggle-evaluator.ts
│   │   └── decomposition/          Exploit analysis pipeline
│   │       ├── input-decomposer.ts     Multi-layer decoding
│   │       ├── exploit-knowledge-graph.ts
│   │       ├── exploit-verifier.ts
│   │       └── campaign-intelligence.ts
│   │
│   ├── engine/            ← Detection core (zero deps, runs anywhere)
│   │   ├── invariant-engine.ts     46 invariant classes
│   │   ├── chain-detector.ts       12 attack chain definitions
│   │   ├── defense-validator.ts    Self-testing defense patterns
│   │   ├── mitre-mapper.ts         MITRE ATT&CK mapping (Axiom Drift)
│   │   ├── evidence/               Cryptographic evidence sealing
│   │   │   └── evidence-sealer.ts  Merkle proofs for signal bundles
│   │   ├── evaluators/             16 L2 structural evaluators
│   │   │   └── ...
│   │   └── decomposition/          Exploit analysis pipeline
│   │       └── ...
│   │
│   ├── edge-sensor/       ← Cloudflare Worker (edge defense)
│   │   ├── src/index.ts           14-layer detection pipeline
│   │   └── src/modules/           15 sensor intelligence modules
│   │       ├── body-analysis.ts
│   │       ├── threat-scoring.ts
│   │       ├── response-audit.ts
│   │       ├── internal-probe.ts
│   │       ├── application-model.ts
│   │       ├── privilege-graph.ts
│   │       ├── blast-radius.ts
│   │       ├── path-enumeration.ts
│   │       ├── cve-stack-correlation.ts
│   │       ├── reactivation-engine.ts
│   │       ├── sensor-state.ts
│   │       ├── rule-sync.ts
│   │       ├── drift-detector.ts     Temporal posture comparison (Axiom Drift)
│   │       ├── ioc-correlator.ts     Threat intel feed correlation (Axiom Drift)
│   │       └── risk-dimensions.ts    4-axis risk surface scoring (Axiom Drift)
│   │
│   ├── agent/             ← Backend defense (RASP + scanning)
│   ├── cli/               ← CLI entry point
│   └── dashboard/         ← localhost:4444 (no hosting needed)
```

Everything runs on **your** infrastructure:
- Edge sensor → your Cloudflare account
- Backend agent → your app process
- Dashboard → your localhost
- Database → your project directory (`invariant.db`)

**Zero attack surface. Zero hosting cost. Full transparency.**

## Dashboard

The dashboard runs at `localhost:4444` with a 4-tab interface:

- **Overview** — Posture grade, finding/signal stats, 24h timeline
- **Findings** — Filterable by severity, with remediation details
- **Signals** — Real-time attack traffic visualization
- **Analytics** — Invariant class distribution, top attacked paths, posture history

## Introspection Endpoints

The edge sensor exposes diagnostic endpoints:

- `/__invariant/health` — Engine status, MITRE coverage, IOC indicators, chain correlator stats
- `/__invariant/posture` — Security posture report with grade, drift detection, and recommendations

## Testing

```bash
# Run engine tests (62 tests, 36 suites)
cd packages/engine && npm test

# Run edge sensor integration tests
cd packages/edge-sensor && npm test

# Run all workspace tests
npm test
```

## Requirements

- Node.js ≥ 20.0.0
- npm ≥ 8

## License

MIT — [santh.io](https://santh.io)
