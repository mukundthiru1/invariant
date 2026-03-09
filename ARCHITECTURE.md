# Invariant — Architecture

> **Source of Truth.** All implementation decisions derive from this document.
> When code and this document conflict, this document wins — fix the code.

## The Security Perimeter

Invariant secures applications across six layers simultaneously. Each layer is independent and additive.

```
DEVELOPER                          PRODUCTION
    │                                   │
    ▼                                   ▼
┌─────────┐  ┌──────────┐  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐
│   CLI   │  │  PR/CI   │  │ DEPLOY │  │  GIT   │  │  EDGE  │  │  RASP  │
│ Scanner │  │  Review  │  │  GATE  │  │ AUDIT  │  │ SENSOR │  │ AGENT  │
│ local   │  │  GitHub  │  │ phone  │  │immutbl │  │   CF   │  │Node.js │
│ offline │  │  Actions │  │ apprvl │  │  log   │  │ Worker │  │runtime │
└─────────┘  └──────────┘  └────────┘  └────────┘  └────────┘  └────────┘
     │             │             │           │           │            │
     └─────────────┴─────────────┴───────────┴───────────┴────────────┘
                                       │
                             INVARIANT ENGINE CORE
                             168 detection classes
                             L1 → L2 → L3 pipeline
                             Rust/WASM Layer 5a
```

---

## Layer 1 — CLI Scanner (local, offline)

```
npx santh scan                # full codebase scan
npx santh scan --diff         # only git-changed files
npx santh scan --watch        # live as you code
npx santh scan --pr 142       # scan PR, post GitHub inline comments
npx santh fix                 # interactive: find → explain → patch
```

- Runs fully offline. Zero network. Your code never leaves your machine.
- 12 vuln categories, 40+ sink patterns, auto-fixer for all 12.
- SARIF output → plugs into GitHub Code Scanning natively.
- Free forever. Primary distribution channel.

---

## Layer 2 — PR / CI Review

Every PR gets the full 168-class engine run on its diff. Inline comments
on vulnerable lines with: class ID, CWE, CVSS score, MITRE technique, fix.
Required status check — PR cannot merge until findings resolved or suppressed.

Free for open source. Runs in the GitHub Action runner — code never leaves.

---

## Layer 3 — Deployment Firewall

**Core insight: a codebase cannot harm anyone until it deploys.**
Control that moment with out-of-band approval and the entire threat class disappears.

```
push → CI/CD build → [INVARIANT GATE] → deploy or BLOCK
                             │
               Behavioral diff vs last approved deploy:
               - New outbound domains?
               - New file paths accessed?
               - New exec() / child_process calls?
               - New or updated dependencies?
               - 168-class scan on every changed line
                             │
               Clean  → auto-approve, deploy proceeds
               Flagged → BLOCK → push notification to phone
                             → biometric approval required
                             → approve / deny / view diff
```

Integrations: Vercel, Cloudflare Pages, Railway, Render, GitHub Actions,
any CI/CD via webhook.

The approval channel is out-of-band from the deployment pipeline.
Compromising Vercel, GitHub, or CI/CD cannot bypass it.
Phone + biometric is the only trust anchor.

---

## Layer 4 — Git Audit Log (immutable forensic trail)

**The unrecoverable attack:** force-push or rebase after a malicious deploy
deletes evidence. Production runs malicious code. Git history shows nothing.

**Our solution:** Append-only audit log, entirely separate from git.

```
Every commit passing through our pipeline is recorded:
  {
    commit_hash:  "abc123",
    tree_hash:    "def456",      ← hash of actual file contents
    author:       "dev@co.com",
    timestamp:    1741478400,
    approved_by:  "phone:+1...",
    deploy_id:    "vercel-xyz",
    signature:    <HMAC-SHA256>  ← we sign it, not git
  }
```

Stored in our append-only database. Cannot be altered by anyone
with git access. Separate trust domain from the repo entirely.

Tamper detection:
- GitHub fires push webhook with forced: true
- We compare new graph against audit log
- Alert: "3 commits removed from history since last deploy"
- Auto-rollback available to last verified clean commit

Enforcement:
- GPG commit signing required at deploy gate
- Branch protection monitoring — alert if force-push protection disabled
- Daily Merkle root published — cryptographic proof of log integrity
- Optional read-only shadow mirror — any divergence triggers alert

---

## Layer 5 — Edge Sensor (Cloudflare Worker)

Every inbound request scanned before it reaches your app server.
Sub-millisecond overhead. Block / monitor / pass decision at the edge.

```
Request → L1 regex (<0.1ms) → L2 structural eval → Rust/WASM Layer 5a → decision
                                                          │
                              44 evaluators compiled to WASM, runs in CF Worker
```

Signals fired async: payload_hash + class_id + confidence → D1 → intel pipeline.
Configurable per-route: enforce on /api/, monitor on /public/.

---

## Layer 6 — RASP Agent (Node.js runtime)

Sits inside your running process. Intercepts every dangerous operation:

```
child_process.exec/spawn     → exec.ts
fs.readFile/writeFile        → fs.ts
SQL client query()           → sql.ts
outbound http/https          → http.ts
WebSocket messages           → websocket.ts
gRPC calls                   → grpc.ts
vm.runInContext/NewContext    → exec.ts (vm hooks)
worker_threads Worker        → exec.ts (worker hooks)
process._linkedBinding       → exec.ts (native binding monitor)
```

Behavioral baseline:
1. First 24h in observe mode — agent learns normal behavior
2. Builds allowlist: approved domains, file paths, processes
3. Enforce mode — deviations are security events, blocked immediately

Zero trust contract: app declares its behavior at deploy time (via config
generated by the deploy gate). RASP enforces it at runtime. Supply chain
attack causing new outbound call → blocked even with no signature for payload.

Intel feedback: every block sends { class_id, payload_hash, confidence }
to intel pipeline async. Never blocks the request path.

---

## Intel Pipeline (Collective Intelligence Flywheel)

```
Edge sensors + RASP agents
        │  payload_hash + class_id (+ full payload if opted in)
        ▼
  signal-store.ts → D1 (per-worker)
        │  hourly
        ▼
  collective_signals table (Neon PG)
        │  hourly
        ▼
  collective-synthesis.ts
  → engine-rs CollectiveIntelligence
  → new L1 regex from patterns seen 3+ times
  → detection_rules table
        │  push via SSE (not polling)
        ▼
  All connected edge sensors hot-reload new rules

  epss-thresholds.ts (daily 6AM)
  → EPSS scores from NVD → threshold_overrides

  tech-stack-priorities.ts
  → Rails: SSTI 2x, Spring: SpEL/RCE 2x, Next.js: prototype-pollution 1.5x
```

Data collected per signal:
- Default: payload_hash (SHA-256, not reversible), class_id, confidence, timestamp, opaque customer ID
- Opt-in: full payload string — stored encrypted, customer retains ownership
- Never: user IPs, auth headers, response bodies, PII fields

Published at santh.io/privacy: exact technical data sheet of every field stored.
No legal boilerplate — a developer-readable spec.

The flywheel: more customers → more signals → better rules → better protection → more customers.
Real attack payloads from production are the most valuable dataset in security.
No CVE database has this. No WAF vendor shares it. We do.

---

## Detection Engine Core

168 invariant classes across 14 categories:
- SQL injection (13): tautology, union, stacked, time/error oracle, OOB, DDL, lateral movement, second-order, MySQL-specific, JSON bypass, comment truncation, string termination, stacked execution
- XSS (5+): tag injection, event handler, attribute escape, protocol handler, template expression, mXSS, DOM clobbering, SVG SMIL
- CMDi (3+): separator, substitution, argument injection + array expansion, brace expansion
- Path traversal (4+): dotdot, encoding bypass, NTFS ADS, file:// traversal
- SSRF (3+): IP variants, cloud metadata (AWS/GCP/Azure), DNS rebinding indicators
- Deserialization (3+): Java, PHP, Python pickle
- Auth/JWT/OAuth/SAML (21): JWT attacks, algorithm confusion, OAuth redirect hijack, SAML signature wrapping, OIDC nonce replay, protocol attacks
- Hygiene/headers (26): CSP, HSTS, CORS, clickjacking, CSRF, secret exposure, debug params
- LLM injection, Supply chain, HTTP smuggling, WebSocket, Nation-state/exploit signatures, Business logic, Infra attacks (K8s, Docker, GitHub Actions, Terraform, cloud metadata)

3-tier detection pipeline:
- L1: Regex scan — <0.1ms, ~90% of known patterns
- L2: Structural evaluator — <2ms, semantic analysis, false positive suppression
- L3: Decomposer — novel variant detection via generateVariants()

Registry contract: every class self-tested at startup. knownPayloads must all
detect()=true, knownBenign must all detect()=false. Impossible to ship broken detector.

Confidence model: L1+L2 convergent=0.97, L2-only=0.92, L1-only=0.70
Block thresholds: critical=0.45, high=0.65, medium=0.80, low=0.92

---

## Free vs Paid

| Tool | Runs where | Data leaves? | Tier |
|------|-----------|--------------|------|
| CLI scanner | Your machine | Never | Free |
| --watch mode | Your machine | Never | Free |
| PR review (GH Action) | Action runner | Never | Free OSS |
| /scan page (santh.io WASM) | Your browser | Never | Free |
| Dashboard (localhost:4444) | Your machine | Never | Free |
| Offline threat feed (weekly) | Your machine | Never | Free |
| Edge sensor | Cloudflare | Hashed signals | Paid |
| RASP agent | Your server | Hashed signals | Paid |
| Deployment firewall | Our infra | Hashed signals | Paid |
| Git audit log | Our infra | Commit metadata | Paid |
| Real-time intel | Our infra | — | Paid |
| Phone approval channel | Our infra | — | Paid |

---

## Open / Closed Source Split

| Package | Visibility | Reason |
|---------|-----------|--------|
| packages/cli | Public MIT | Distribution channel |
| packages/dashboard | Public MIT | Distribution channel |
| packages/engine | Private | Core detection IP |
| packages/engine-rs | Private | Rust/WASM performance moat |
| packages/edge-sensor | Private | Artifact only |
| packages/agent | Private | Artifact only |
| packages/intel | Private | Pipeline is the moat |

---

## Repositories

| Repo | Visibility | Contents |
|------|-----------|----------|
| mukundthiru1/invariant | Public | cli + dashboard only |
| mukundthiru1/invariant-private | Private | Full engine, all packages |
| mukundthiru1/Santh_Real | Private | santh.io hub |
| mukundthiru1/santhstack | Public | santhstack.santh.io |

---

## Approval Channel — Passkey / Face ID / Touch ID

**The first deployment system gated by biometric approval.**

No one else does this. GitHub has TOTP/SMS/hardware keys.
Nobody offers: "approve your production deploy with Face ID."

### How it works

```
Deploy flagged by Invariant gate
        ↓
Push notification to developer device
        ↓
Browser/app opens approval prompt:
  "Deploy to production blocked.
   sql_tautology in auth.ts:47
   [View diff] [Deny] [Approve →]"
        ↓
Developer taps Approve → Face ID / Touch ID / Windows Hello
        ↓
Biometric evaluated by device Secure Enclave (never leaves device)
        ↓
Signed WebAuthn assertion sent to Invariant
        ↓
Cryptographic verification → deploy proceeds
```

### Technology: WebAuthn / Passkeys (no app install required)

Passkeys are the W3C WebAuthn standard. Built into every modern device:
- iPhone/iPad: Face ID or Touch ID
- Mac: Touch ID
- Android: fingerprint / face unlock
- Windows: Windows Hello
- Any device: hardware security key (YubiKey, etc.)

The biometric NEVER leaves the device. We receive a signed challenge-response.
We never store biometric data. GDPR-clean by design.

### Three approval tiers

| Tier | Method | Use case |
|------|--------|----------|
| Low | Email magic link | Staging deploys, low-risk changes |
| Medium | SMS OTP | Standard production deploys |
| High | Passkey (Face ID / Touch ID) | Suspicious findings, critical systems |

### New package: packages/auth-gate/

- WebAuthn registration: `dashboard.santh.io/setup` → enroll your device
- Challenge-response API: `POST /v1/auth/challenge`, `POST /v1/auth/verify`
- Push notification dispatch: Web Push API (no app install, works on all devices)
- Approval tokens: short-lived HMAC-signed JWTs, single-use, tied to specific deploy ID

---

## Deployment Firewall — New Package: packages/deploy-gate/

Webhook receiver that integrates with every major deployment platform.

```
Vercel:          Deploy hook → POST /v1/webhook/vercel
CF Pages:        Deploy hook → POST /v1/webhook/cloudflare
GitHub Actions:  Required status check → POST /v1/webhook/github
Railway:         Deploy hook → POST /v1/webhook/railway
Generic CI/CD:   POST /v1/webhook/generic (any platform via script)
```

Flow per webhook:
1. Receive deploy event with git ref
2. Fetch diff from GitHub/GitLab API
3. Run 168-class engine on every changed line
4. Behavioral diff vs last approved deploy (new domains? new exec calls?)
5. Scan new/updated dependencies (npm audit + our engine on package source)
6. Clean → approve (return 200, deploy proceeds)
7. Flagged → block (return 202 pending) → dispatch approval notification
8. On approval → return 200 to platform → deploy proceeds
9. On denial or timeout → return 403 → deploy stays blocked

Behavioral baseline stored per customer per deploy:
- Approved outbound domains
- Approved file paths accessed
- Approved child processes
- Approved dependency list

---

## Git Audit Log — New Package: packages/audit-log/

Append-only, cryptographically signed record of every commit + deploy.

```
Schema (Neon PG, append-only — no UPDATE/DELETE permissions):
  audit_events {
    id:           SERIAL PRIMARY KEY
    event_type:   'commit' | 'deploy' | 'approval' | 'block' | 'tamper_detected'
    commit_hash:  TEXT NOT NULL
    tree_hash:    TEXT NOT NULL      -- hash of actual file contents
    author_email: TEXT NOT NULL
    ts:           TIMESTAMPTZ NOT NULL
    deploy_id:    TEXT               -- platform deploy ID
    approved_by:  TEXT               -- passkey credential ID
    customer_id:  TEXT NOT NULL
    hmac:         TEXT NOT NULL      -- HMAC-SHA256 of all fields, our key
  }
```

Tamper detection:
- GitHub webhook: on `push` with `forced: true` → query audit log for removed commits
- Daily Merkle root: hash of all records published to public GitHub gist
- Shadow mirror: read-only git clone, compared against origin every 15min
- Alert channels: email, Slack webhook, PagerDuty

Recovery:
- We know the last verified commit_hash + tree_hash
- Trigger redeploy of last clean state via platform API
- Full forensic timeline exported as JSON/CSV for incident response

---

## CLI Improvements — Layers 1 + 2

### PR Review mode (CodeRabbit competitor)

```bash
npx santh scan --pr 142
# Fetches diff from GitHub API (needs GITHUB_TOKEN env var)
# Runs 168-class engine on every changed line
# Posts inline comments on vulnerable lines:
#   "⚠ sql_tautology — CWE-89, CVSS 9.8
#    Parameterized queries prevent this class of attack.
#    [View class docs] [Apply fix]"
# Returns exit code 1 if critical findings, 0 if clean
```

### Interactive Fix mode

```bash
npx santh fix
# Shows each finding interactively:
#   Finding 1/3: sql_tautology in src/routes/auth.ts:47
#   const q = `SELECT * FROM users WHERE id = ${req.params.id}`
#   → Replace with parameterized query? [Y/n/skip/view]
# Applies auto-fix from auto-fixer.ts
# Re-runs scan to confirm fixed
# Loops until 0 findings or user skips all
```

### GitHub Action (required status check)

```yaml
# .github/workflows/santh.yml
- uses: santh-io/scan-action@v1
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    fail-on: high        # block PR merge on high+ severity
    post-comments: true  # inline PR comments
```
