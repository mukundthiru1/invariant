# INVARIANT Attack Chain Documentation

Attack chain detection correlates **multiple invariant signals from the same source** over time. A single low-confidence payload may be ambiguous; a **sequence** of probes and exploits from the same IP/session is a strong indicator of a real attack. Chain definitions are in `packages/engine/src/chain-detector.ts` (`ATTACK_CHAINS`).

---

## How chains work

- **Steps**: Each chain has ordered steps. Each step is satisfied if **any** of its `classes` (or optional `behaviors`) match.
- **Time window**: All steps must occur within `windowSeconds` (from the first matching signal).
- **Minimum steps**: `minimumSteps` (default: all) must match to consider the chain detected.
- **Confidence**: When a chain completes, `confidenceBoost` is added to the compounded confidence.
- **Defense per step**: Each step can suggest `alert`, `throttle`, `challenge`, or `block`.

The engine maintains **per-source, per-chain state** (e.g. by hashed IP or session). Partial progress is tracked so that early steps trigger alerts and later steps can trigger blocks.

---

## Chain types and severity escalation

| Chain severity | Meaning | Typical recommended action |
|----------------|---------|-----------------------------|
| **critical** | Full chain indicates RCE, credential theft, or major data exfiltration | Block source; alert; forensics |
| **high** | Recon + targeted exploit, or mass enumeration / abuse | Throttle or block; review |
| **medium** | Recon or low-impact abuse | Monitor; optional throttle |

`ChainMatch.recommendedAction` is one of: `monitor` | `throttle` | `challenge` | `block` | `lockdown`.

---

## All chain definitions (summary)

| ID | Name | Severity | Window | Min steps |
|----|------|----------|--------|-----------|
| `lfi_credential_theft` | LFI → Credential Extraction | critical | 300s | 2 |
| `sqli_data_exfil` | SQLi → Data Exfiltration | critical | 600s | 2 |
| `ssrf_cloud_credential_theft` | SSRF → Cloud Credential Theft | critical | 300s | 2 |
| `xss_session_hijack` | XSS → Session Hijack → Admin Takeover | critical | 1800s | 2 |
| `deser_rce` | Deserialization → RCE | critical | 60s | 1 |
| `proto_pollution_rce` | Prototype Pollution → RCE | critical | 30s | 1 |
| `log4shell_rce` | Log4Shell → JNDI Lookup → RCE | critical | 30s | 1 |
| `automated_attack_pipeline` | Automated Scanner → Targeted Exploit | high | 3600s | 2 |
| `sqli_multi_vector` | Multi-Vector SQL Injection Campaign | critical | 1800s | 2 |
| `ssti_rce` | SSTI → Template Engine RCE | critical | 300s | 1 |
| `xxe_ssrf_chain` | XXE → SSRF → Internal Pivot | critical | 120s | 1 |
| `auth_bypass_privesc` | Auth Bypass → Privilege Escalation | critical | 300s | 1 |
| `supply_chain_pivot` | Supply Chain Exploit → Cloud Pivot | critical | 600s | 2 |
| `dns_rebinding_ssrf` | DNS Rebinding → SSRF → Internal Access | critical | 120s | 2 |
| `http_desync_auth_bypass` | HTTP Desync → Request Smuggling → Auth Bypass | critical | 60s | 1 |
| `cloud_iam_escalation` | SSRF → Cloud IAM → Cross-Account Escalation | critical | 900s | 2 |
| `webshell_deployment` | Vuln Exploit → File Write → Web Shell → C2 | critical | 1800s | 2 |
| `oob_data_exfil` | Blind Injection → OOB Exfiltration | critical | 1200s | 2 |
| `cors_credential_theft` | CORS Abuse → XSS → Credential Harvest | critical | 3600s | 2 |
| `slow_sqli_recon` | Low-and-Slow SQLi Reconnaissance | high | 7200s | 3 |
| `jwt_forgery_pipeline` | JWT Forgery Pipeline | critical | 300s | 2 |
| `supply_chain_full_compromise` | Supply Chain Full Compromise | critical | 600s | 2 |
| `llm_jailbreak_escalation` | LLM Jailbreak Escalation | critical | 300s | 2 |
| `cache_poison_xss` | Cache Poisoning to Stored XSS | critical | 120s | 2 |
| `api_idor_mass_exfil` | API IDOR to Mass Data Exfiltration | critical | 300s | 2 |
| `jwt_idor_escalation` | JWT Forgery to IDOR Privilege Escalation | critical | 300s | 2 |
| `cache_deception_session_theft` | Cache Deception to Session Theft | critical | 180s | 1 |
| `llm_supply_chain_pivot` | LLM Jailbreak to Supply Chain Compromise | critical | 600s | 2 |
| `ssrf_api_exfil` | SSRF to Internal API Mass Exfiltration | critical | 300s | 2 |
| `sqli_lfi_credential_theft` | SQLi Probe to LFI Credential Extraction | critical | 600s | 2 |
| `mass_assign_priv_esc_admin` | Mass Assignment to Admin Takeover | critical | 300s | 2 |
| `oast_blind_ssrf_internal_pivot` | OAST DNS Probe to Blind SSRF Internal Pivot | critical | 480s | 2 |
| `supply_chain_typosquat_rce` | Supply Chain Typosquatting to RCE | critical | 120s | 2 |
| `proto_pollution_auth_bypass` | Prototype Pollution to Auth Bypass | critical | 240s | 2 |
| `cicd_pipeline_poison` | CI/CD Pipeline Injection to Artifact Tampering | critical | 600s | 2 |
| `websocket_hijack_chain` | WebSocket Origin Spoof to Session Hijack | high | 180s | 2 |
| `graphql_batch_ratelimit_bypass` | GraphQL Query Batching to Rate Limit Bypass and Data Exfiltration | high | 120s | 2 |
| `h2_rapid_reset_smuggle` | HTTP/2 Rapid Reset to Smuggling Tunnel | critical | 60s | 2 |
| `llm_prompt_inject_exfil` | LLM Prompt Injection to Sensitive Data Exfiltration | critical | 300s | 2 |
| `dep_confusion_env_exfil` | Dependency Confusion to CI Environment Credential Exfiltration | critical | 180s | 2 |
| `kubernetes_api_server_pivot` | Kubernetes API Server Pivot to RCE | critical | 120s | 3 |
| `ci_cd_secrets_exfil` | CI/CD Injection to Secrets Exfiltration | critical | 300s | 2 |
| `graphql_batching_auth_bypass` | GraphQL Batching to Auth Bypass and IDOR | high | 120s | 2 |
| `jwt_algorithm_confusion_privesc` | JWT Algorithm Confusion to Privilege Escalation | critical | 300s | 2 |
| `ssti_rce_chain` | SSTI to Command Execution Chain | critical | 300s | 2 |

---

## Example attack flows (detailed)

### 1. LFI → Credential Extraction (`lfi_credential_theft`)

- **Trigger classes (by step)**:
  1. `path_dotdot_escape`, `path_encoding_bypass` — probe for path traversal
  2. `path_dotdot_escape`, `path_null_terminate`, `path_encoding_bypass` + behavior `path_sensitive_file` — read sensitive files
  3. `auth_header_spoof` + behaviors `auth_change`, `privilege_escalation` — use stolen creds
- **Example flow**: Attacker requests `?file=../../../.env`, then `?file=....//....//etc/passwd%00.txt`, then sends requests with stolen tokens in headers. Same source within 5 minutes.
- **Severity**: critical. **Recommended**: block at step 2; alert at step 1.

---

### 2. SQLi → Data Exfiltration (`sqli_data_exfil`)

- **Trigger classes**:
  1. `sql_string_termination`, `sql_error_oracle`, `sql_time_oracle` — probe
  2. `sql_tautology`, `sql_union_extraction` — extract data
  3. `sql_stacked_execution` — modify data or escalate
- **Example flow**: Error-based probe on `id=1'`, then UNION SELECT on same parameter, then `; DROP TABLE x` or privilege change. Same source within 10 minutes.
- **Severity**: critical. **Recommended**: block at step 2 or 3.

---

### 3. SSRF → Cloud Credential Theft (`ssrf_cloud_credential_theft`)

- **Trigger classes**:
  1. `ssrf_internal_reach` — probe internal/metadata
  2. `ssrf_cloud_metadata` — reach 169.254.169.254
  3. `ssrf_protocol_smuggle` + behavior `credential_extraction` — use creds or smuggle
- **Example flow**: URL param `?url=http://169.254.169.254/latest/meta-data/`, then access to token endpoint, then use of token in follow-up. Same source within 5 minutes.
- **Severity**: critical. **Recommended**: block at step 2.

---

### 4. JWT Forgery Pipeline (`jwt_forgery_pipeline`)

- **Trigger classes**:
  1. `auth_none_algorithm` — alg:none probe
  2. `jwt_kid_injection` — kid header injection
  3. `jwt_jwk_embedding`, `jwt_confusion` — self-signed key or algorithm confusion
- **Example flow**: Request with JWT alg:none; then JWT with malicious `kid`; then JWT with embedded `jwk` or HS256 with public key. Same source within 5 minutes.
- **Severity**: critical. **Recommended**: block at step 2 or 3.

---

### 5. Cache Poisoning to Stored XSS (`cache_poison_xss`)

- **Trigger classes**:
  1. `cache_poisoning` — unkeyed header manipulation
  2. `xss_tag_injection`, `xss_event_handler`, `xss_protocol_handler` — XSS in cached response
- **Example flow**: Request with crafted header that gets reflected in response; cache stores poisoned response; next user gets XSS. Same source within 2 minutes.
- **Severity**: critical. **Recommended**: block at step 2; alert at step 1.

---

### 6. Automated Scanner → Targeted Exploit (`automated_attack_pipeline`)

- **Trigger classes**:
  1. (no classes) behaviors: `scanner_detected`, `path_spray`, `rate_anomaly` — scanner fingerprinting
  2. `sql_string_termination`, `xss_tag_injection`, `path_dotdot_escape`, `cmd_separator`, `ssrf_internal_reach`, `log_jndi_lookup` — targeted payload
- **Example flow**: Many requests to varied paths (path spray), then same source sends SQLi/XSS/SSRF payloads to a discovered endpoint. Within 1 hour.
- **Severity**: high. **Recommended**: throttle at step 1; block at step 2.

---

## Using chain detection in code

The chain detector is used with `ChainStateStore` and `ATTACK_CHAINS`. You feed it `ChainSignal` objects (source hash, classes, behaviors, confidence, path, method, timestamp) and it advances per-source, per-chain state and returns `ChainMatch` when a chain satisfies its `minimumSteps` within `windowSeconds`.

```ts
import { ATTACK_CHAINS, ChainCorrelator } from '@santh/invariant-engine/chain-detector'

const detector = new ChainCorrelator(ATTACK_CHAINS, { windowSeconds: 600, maxSources: 5000 })

// On each request that had invariant matches:
const signal = {
  sourceHash: hashIpOrSession(req.ip, req.sessionId),
  classes: matches.map(m => m.class),
  behaviors: [], // optional: e.g. 'scanner_detected', 'path_spray'
  confidence: Math.max(...matches.map(m => m.confidence)),
  path: req.path,
  method: req.method,
  timestamp: Date.now(),
}
const chainMatches = detector.advance(signal)
// chainMatches: ChainMatch[] — act on recommendedAction (block, throttle, etc.)
```

---

## References

- Chain definitions: `packages/engine/src/chain-detector.ts` (`ATTACK_CHAINS`, `ChainStep`, `ChainDefinition`, `ChainMatch`, `ChainSignal`)
- Invariant classes: [Classes reference](./classes.md)
- Config: [Configuration](./configuration.md)
