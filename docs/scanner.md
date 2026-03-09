# INVARIANT Codebase Scanner

The codebase scanner looks for **sink patterns** in source code that indicate potential vulnerabilities (e.g. raw SQL, `eval`, unsafe redirects). It does **not** execute code; it uses regex and pattern matching over the text of your files. Implemented in `packages/engine/src/codebase-scanner.ts`.

---

## Scanner categories (55)

Each finding has a **category**, **severity**, **sink** (matched pattern), **snippet**, **suggestion**, and optional **CWE** and **riskScore**. Categories map to invariant detection classes where applicable.

| Category | CWE | Description (summary) |
|----------|-----|------------------------|
| sqli | CWE-89 | Raw SQL / string interpolation in queries |
| xss | CWE-79 | Unencoded user output in HTML/JS context |
| command_injection | CWE-78 | Dynamic command construction / shell execution |
| path_traversal | CWE-22 | User input in file paths without canonicalization |
| ssrf | CWE-918 | User-controlled URLs in server-side fetch |
| auth | CWE-287 | Authentication/authorization weaknesses |
| secrets | CWE-798 | Hardcoded secrets, tokens, credentials |
| crypto | CWE-327 | Weak or deprecated crypto algorithms |
| deserialization | CWE-502 | Insecure deserialization / eval of user data |
| prototype_pollution | CWE-1321 | Recursive merge with user input; prototype mutation |
| nosql_injection | CWE-943 | NoSQL operator/JS injection in queries |
| header_misconfiguration | CWE-16 | Insecure or missing HTTP security headers |
| idor | CWE-284 | Insecure direct object reference / missing object-level auth |
| missing_auth | CWE-306 | Route handler missing authentication |
| jwt_misconfiguration | CWE-347 | JWT verification/signing misconfiguration |
| missing_rate_limit | CWE-770 | Sensitive endpoint without rate limiting |
| sensitive_data_logging | CWE-532 | Logging of secrets or PII |
| insecure_session | CWE-614 | Insecure session/cookie configuration |
| redos | CWE-1333 | User input in regex leading to ReDoS |
| graphql_abuse | CWE-400 | Missing depth/complexity limits; unsafe introspection |
| env_exposure | CWE-526 | process.env or secrets exposed to client |
| vulnerable_dependency | CWE-1104 | Known vulnerable dependency versions |
| iac_secrets | CWE-798 | Hardcoded secrets in IaC files |
| iac_misconfig | CWE-16 | Cloud/IaC misconfigurations |
| github_actions_security | CWE-693 | Insecure GitHub Actions workflow config |
| container_security | CWE-16 | Docker/container security issues |
| http_security_headers | CWE-16 | Missing HSTS, CSP, etc. |
| debug_exposure | CWE-489 | Debug mode or verbose errors in production |
| hardcoded_credentials | CWE-798 | Hardcoded usernames/passwords |
| timing_attack | CWE-208 | Non-constant-time comparison |
| xxe_risk | CWE-611 | XML parsing without disabling external entities |
| cors_misconfiguration | CWE-942 | Overly permissive CORS |
| clickjacking | CWE-1021 | Missing X-Frame-Options / frame-ancestors |
| weak_password_policy | CWE-521 | Weak password requirements |
| insecure_random | CWE-338 | Insecure RNG for security-sensitive use |
| file_permission_exposure | CWE-732 | Overly permissive file permissions |
| error_information_leakage | CWE-209 | Detailed errors/stack traces to users |
| api_versioning_security | CWE-693 | Insecure legacy API versions exposed |
| open_redirect | CWE-601 | User-controlled redirect target |
| crlf_injection | CWE-113 | CRLF in headers / response splitting |
| ssti | CWE-94 | User input in template render/compile |
| ldap_injection | CWE-90 | Unescaped LDAP filter input |
| mass_assignment | CWE-915 | Request body bound to model without allowlist |
| http_response_splitting | CWE-113 | CRLF in header names/values |
| insecure_deserialization | CWE-502 | Unsafe object loaders for untrusted data |
| csrf_missing | CWE-352 | State-changing endpoints without CSRF protection |
| websocket_security | CWE-346 | Missing Origin/auth validation for WebSocket |
| oauth_misconfiguration | CWE-601 | OAuth redirect_uri, state, PKCE issues |
| log_injection | CWE-117 | Unsanitized log input / CRLF in logs |
| cache_control_missing | CWE-525 | Sensitive responses cacheable |
| health_endpoint_exposure | CWE-200 | Health/debug endpoints publicly exposed |
| webhook_missing_validation | CWE-347 | Webhook without signature verification |
| dependency_confusion | CWE-829 | Supply chain / dependency confusion risk |
| insecure_cors_credentials | CWE-942 | CORS credentials with permissive origin |
| path_traversal_zip | CWE-22 | Zip Slip in archive extraction |
| subdomain_takeover_risk | CWE-350 | Dangling DNS / subdomain takeover |

---

## How to run from the CLI

Install and run from the project root:

```bash
npx @santh/invariant codescan
```

Or, if the CLI is installed locally:

```bash
node packages/cli/src/index.js codescan
```

**Behavior:**

- **Root directory**: Default is current working directory. The CLI uses `projectDir` (e.g. from `invariant init` or cwd).
- **Scan**: `CodebaseScanner` is constructed with `{ rootDir: projectDir }` and `scanDirectory()` is called.
- **Output**: By default the CLI prints `formatReport(result)` (human-readable summary and per-finding details).

**Output formats:**

- **Default**: Human-readable report (severity counts, file:line, sink, snippet, suggestion).
- **SARIF**: `npx @santh/invariant codescan --format sarif` (or equivalent) prints `toSarif(result)` as JSON for integration with GitHub Code Scanning, etc.
- **JUnit XML**: `npx @santh/invariant codescan --format junit` prints `toJunitXml(result)` for CI test reporters.

CLI options (see `packages/cli/src/index.ts`) may include:

- `--format sarif` → SARIF 2.1.0 JSON
- `--format junit` → JUnit XML
- Path/extensions/exclude may be configurable via env or flags (check CLI help).

---

## How to interpret risk scores

- **Severity** (per finding): `critical` \| `high` \| `medium` \| `low`. Assigned by the sink pattern; critical/high indicate likely exploitable or high-impact patterns.
- **riskScore** (optional): Numeric score on the finding when the scanner computes it. Higher = higher risk. Use for ordering or thresholding.
- **confidence** (optional): Some patterns have `confidence: 'high'` or `'medium'` or `'low'` to indicate how likely the match is a real vulnerability (e.g. string concatenation in SQL is high confidence; a generic `db.query` may be medium).

**Aggregate metrics:**

- **findings-count**: Total number of findings.
- **critical-count**, **high-count**: Counts by severity (used in GitHub Action outputs).
- **risk-score**: In the GitHub Action, this is the average risk score across findings (0 when none). Use with a threshold to fail the job.

**Recommendation:** Treat **critical** and **high** as must-fix or must-justify; **medium** and **low** as review and reduce over time.

---

## CI/CD integration: GitHub Actions

The INVARIANT GitHub Action runs the codebase scanner and can fail the workflow based on severity.

**Example workflow** (`.github/workflows/invariant-scan.yml`):

```yaml
name: Invariant Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  invariant:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run Invariant codebase scan
        uses: ./packages/github-action
        with:
          path: .
          mode: defend
          fail-on: high
          extensions: .ts,.js,.tsx,.jsx,.vue,.svelte
          exclude: node_modules,.git,dist,build,coverage,.next
```

**Action inputs** (from `action.yml`):

| Input | Default | Description |
|-------|---------|-------------|
| path | `.` | Directory to scan. |
| mode | `defend` | `monitor` (report only) or `defend` (fail on threshold). |
| fail-on | `high` | Severity threshold to fail: `critical`, `high`, `medium`, `all`, or `any`, `none`. |
| extensions | `.ts,.js,.tsx,.jsx` | Comma-separated file extensions to include. |
| exclude | `node_modules,.git,dist,build` | Comma-separated paths to exclude. |

**Action outputs:**

- **findings-count**: Total findings.
- **risk-score**: Average risk score (0 if no findings).
- **critical-count**, **high-count**: Counts by severity.

**Behavior:**

- The action runs the same codebase scanner as the CLI (`CodebaseScanner`, `scanDirectory()`).
- If **mode** is `defend` and the number of findings at or above **fail-on** severity exceeds the configured threshold (or any finding meets the fail condition), the step fails.
- You can upload SARIF to GitHub Code Scanning in a follow-up step using the action’s output or a separate run that outputs SARIF.

**Uploading SARIF to GitHub:**

Run the scanner with SARIF output, then use `github/codeql-action/upload-sarif` (or GitHub’s native SARIF upload). Example:

```yaml
- name: Invariant scan (SARIF)
  id: scan
  run: |
    npx @santh/invariant codescan --format sarif > invariant.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: invariant.sarif
```

(Adjust the exact CLI command to match how your project invokes the scanner and writes SARIF.)

---

## Programmatic API

```ts
import { CodebaseScanner, formatReport, toSarif, toJunitXml } from '@santh/invariant-engine/codebase-scanner'
// or from your monorepo:
// import { CodebaseScanner, formatReport, toSarif, toJunitXml } from '../../engine/src/codebase-scanner.js'

const scanner = new CodebaseScanner({ rootDir: process.cwd() })
const result = await scanner.scanDirectory()

console.log(formatReport(result))
// or
const sarif = toSarif(result)
const junit = toJunitXml(result)
```

**ScanResult:**

- `files`: number of files scanned
- `findings`: `ScanFinding[]`
- `duration`: milliseconds

**ScanFinding:**

- `file`, `line`, `column`, `category`, `sink`, `snippet`, `severity`, `suggestion`
- Optional: `confidence`, `cweId`, `riskScore`

---

## References

- Implementation: `packages/engine/src/codebase-scanner.ts`
- CLI: `packages/cli/src/index.ts` (commands `scan`, `codescan`)
- GitHub Action: `packages/github-action/action.yml`, `packages/github-action/src/index.ts`
- [Classes](./classes.md) for mapping from scanner categories to invariant classes
- [Configuration](./configuration.md) for project config and thresholds
