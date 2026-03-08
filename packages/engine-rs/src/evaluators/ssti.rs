//! SSTI Evaluator — Server-Side Template Injection Detection

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

pub struct SstiEvaluator;

impl L2Evaluator for SstiEvaluator {
    fn id(&self) -> &'static str {
        "ssti"
    }
    fn prefix(&self) -> &'static str {
        "L2 SSTI"
    }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        // Jinja2/Twig: {{ ... }}
        static jinja: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"\{\{.*?\}\}").unwrap());
        if let Some(m) = jinja.find(&decoded) {
            let content = m.as_str();
            static JINJA_CODE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                Regex::new(r"(?i)(?:__class__|__mro__|__subclasses__|__import__|config|lipsum|cycler|joiner|request|self\._)").unwrap()
            });
            static JINJA_PROBE_RE: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r"\b(?:7\*7|49|__|\[\]|'')\b").unwrap());
            let has_code = JINJA_CODE_RE.is_match(content) || JINJA_PROBE_RE.is_match(content);
            if has_code {
                dets.push(L2Detection {
                    detection_type: "ssti_jinja".into(),
                    confidence: 0.92,
                    detail: format!("Jinja2/Twig SSTI: {} with code execution indicators", content),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: content.to_owned(),
                        interpretation: "Template expression accesses Python object hierarchy for code execution".into(),
                        offset: m.start(),
                        property: "User input must not inject template expressions".into(),
                    }],
                });
            }
        }

        // Mathematical probe: {{7*7}} or ${7*7} or #{7*7}
        static math_probe: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?:\{\{|\$\{|#\{)\s*\d+\s*\*\s*\d+\s*(?:\}\}|\})").unwrap()
        });
        if let Some(m) = math_probe.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_probe".into(),
                confidence: 0.78,
                detail: format!("Template injection probe: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Arithmetic probe tests for template engine evaluation".into(),
                    offset: m.start(),
                    property: "User input must not inject template expressions".into(),
                }],
            });
        }

        // Freemarker: <#assign ...>
        static freemarker: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"<#(?:assign|include|import)\s").unwrap());
        if let Some(m) = freemarker.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_freemarker".into(),
                confidence: 0.90,
                detail: format!(
                    "FreeMarker SSTI: {}",
                    &decoded[m.start()..decoded.len().min(m.start() + 60)]
                ),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "FreeMarker directive enables code execution".into(),
                    offset: m.start(),
                    property: "User input must not inject template directives".into(),
                }],
            });
        }

        // Velocity: #set($x = ...)
        static velocity: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"#(?:set|foreach|if|include|parse)\s*\(").unwrap()
        });
        if let Some(m) = velocity.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_velocity".into(),
                confidence: 0.88,
                detail: format!("Velocity SSTI: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Velocity template directive enables code execution".into(),
                    offset: m.start(),
                    property: "User input must not inject template directives".into(),
                }],
            });
        }

        // ERB: <%= ... %>
        static erb: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"<%=?\s*.*?%>").unwrap());
        if let Some(m) = erb.find(&decoded) {
            let content = m.as_str();
            static ERB_EXEC_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
                Regex::new(r"(?i)(?:system|exec|eval|`|IO\.|File\.|Kernel\.)").unwrap()
            });
            if ERB_EXEC_RE.is_match(content) {
                dets.push(L2Detection {
                    detection_type: "ssti_erb".into(),
                    confidence: 0.90,
                    detail: format!("ERB SSTI with code execution: {}", content),
                    position: m.start(),
                    evidence: vec![ProofEvidence {
                        operation: EvidenceOperation::PayloadInject,
                        matched_input: content.to_owned(),
                        interpretation: "ERB template tag executes Ruby code".into(),
                        offset: m.start(),
                        property: "User input must not inject template expressions".into(),
                    }],
                });
            }
        }

        // Pebble/Spring EL expression: ${T(java.lang.Runtime)...}
        static spel_runtime: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?i)\$\{\s*T\s*\(\s*java\.lang\.(?:Runtime|ProcessBuilder|Class)\s*\)")
                .unwrap()
        });
        if let Some(m) = spel_runtime.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_spel_runtime".into(),
                confidence: 0.95,
                detail: format!("SpEL runtime access in template expression: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Template expression resolves Java runtime classes for code execution"
                            .into(),
                    offset: m.start(),
                    property: "User input must not inject Spring/Pebble template expressions"
                        .into(),
                }],
            });
        }

        // Mako SSTI: <% import os %> and ${os.popen(...).read()}
        static mako_import: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?is)<%\s*import\s+os\s*%>").unwrap());
        static mako_popen: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\$\{\s*os\.popen\s*\([^)]*\)\.read\(\)\s*\}").unwrap()
        });
        if let Some(m) = mako_import.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_mako_rce".into(),
                confidence: if mako_popen.is_match(&decoded) {
                    0.95
                } else {
                    0.91
                },
                detail: format!("Mako import-based SSTI: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Mako template block imports OS module for command execution"
                        .into(),
                    offset: m.start(),
                    property: "User input must not inject Mako template code blocks".into(),
                }],
            });
        }
        if let Some(m) = mako_popen.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_mako_rce".into(),
                confidence: if mako_import.is_match(&decoded) {
                    0.95
                } else {
                    0.93
                },
                detail: format!("Mako command execution chain: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Mako expression executes shell command and returns output"
                        .into(),
                    offset: m.start(),
                    property: "User input must not execute commands through Mako expressions"
                        .into(),
                }],
            });
        }

        // Twig sandbox escape chains: |filter('system') and _self.env.getRuntime
        static TWIG_FILTER_SYSTEM_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)\|\s*filter\s*\(\s*['"]system['"]\s*\)"#).unwrap()
        });
        let twig_filter_system = &*TWIG_FILTER_SYSTEM_RE;
        static twig_runtime: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?i)_self\.env\.getRuntime").unwrap());
        if let Some(m) = twig_filter_system.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_twig_escape".into(),
                confidence: if twig_runtime.is_match(&decoded) {
                    0.96
                } else {
                    0.92
                },
                detail: format!("Twig sandbox escape via system filter: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Twig filter is coerced to execute system-level command".into(),
                    offset: m.start(),
                    property: "User input must not inject Twig runtime filters".into(),
                }],
            });
        }
        if let Some(m) = twig_runtime.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_twig_escape".into(),
                confidence: 0.94,
                detail: format!("Twig runtime object traversal: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Twig self object traversal reaches runtime internals for escape".into(),
                    offset: m.start(),
                    property: "User input must not access Twig runtime internals".into(),
                }],
            });
        }

        // Jinja2 block-tag SSTI without {{ }} expressions.
        static JINJA_BLOCK_TAG_SSTI_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r"\{%-?\s*(?:for|if|set|import|from|with|block|macro|call|filter|extends|include|raw|autoescape|recursive|do)\s+[^%]*(?:popen|subprocess|os|system|exec|eval|compile|__class__|__base__|__mro__|__subclasses__)").unwrap()
            });
        if let Some(m) = JINJA_BLOCK_TAG_SSTI_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_jinja_block_tag".into(),
                confidence: 0.88,
                detail: format!("Jinja2 block tag SSTI directive: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Jinja2 control block embeds execution or object-traversal primitives".into(),
                    offset: m.start(),
                    property: "Template control blocks from user input must not include dangerous directives".into(),
                }],
            });
        }

        // Jinja2 attr filter bypass: |attr('__class__') style access.
        static JINJA_ATTR_FILTER_BYPASS_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r#"\{\{[^}]*\|\s*attr\s*\(['"][^'"]*(?:__class__|__base__|__mro__|__subclasses__|__builtins__|__import__|__globals__|__code__|func_code|__func__|im_func)[^'"]*['"]\s*\)"#).unwrap()
            });
        if let Some(m) = JINJA_ATTR_FILTER_BYPASS_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_jinja_attr_filter_bypass".into(),
                confidence: 0.92,
                detail: format!("Jinja2 attr-filter sandbox bypass: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Attribute filter resolves restricted internals to bypass sandboxing".into(),
                    offset: m.start(),
                    property: "Template filters from user input must not access sensitive object attributes".into(),
                }],
            });
        }

        // Twig map/filter chain sandbox bypass gadgets.
        static TWIG_MAP_FILTER_CHAIN_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r#"(?i)\[\s*['"](?:system|exec|popen|passthru|shell_exec|proc_open|assert)['"]\s*\]\s*\|\s*(?:map|filter|reduce|merge)"#).unwrap()
            });
        if let Some(m) = TWIG_MAP_FILTER_CHAIN_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_twig_map_filter_chain".into(),
                confidence: 0.91,
                detail: format!("Twig map/filter gadget chain: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Twig functional filter chain coerces dangerous callable execution".into(),
                    offset: m.start(),
                    property: "Template filters from user input must not compose callable execution chains".into(),
                }],
            });
        }

        // Comment-stripping / double-parse bypass patterns that hide {{ ... }} payloads.
        static TEMPLATE_COMMENT_STRIP_BYPASS_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| {
                Regex::new(r"(?:\{#[^#]*\{\{|\{%-?\s*comment\s*-?%\}[^{]*\{\{|<!--[^<]*\{\{)")
                    .unwrap()
            });
        if let Some(m) = TEMPLATE_COMMENT_STRIP_BYPASS_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_template_comment_bypass".into(),
                confidence: 0.79,
                detail: format!("Template comment-stripping bypass marker: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Template comment context can hide payloads that re-emerge after parser transformations".into(),
                    offset: m.start(),
                    property: "User input must not rely on template comment contexts to smuggle expressions".into(),
                }],
            });
        }

        // Jinja2 class traversal gadget enumeration
        static jinja_class_chain: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"''\.__class__\.__mro__\[\s*2\s*\]\.__subclasses__\(\)").unwrap()
        });
        if let Some(m) = jinja_class_chain.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_jinja_class_chain".into(),
                confidence: 0.94,
                detail: format!("Jinja2 class traversal chain: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Python object model traversal enumerates subclasses to locate RCE primitives".into(),
                    offset: m.start(),
                    property: "Template expressions must not traverse Python class hierarchy".into(),
                }],
            });
        }

        // Smarty SSTI: {php}system(...){/php}
        static smarty_php_system: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\{php\}.*?system\s*\([^)]*\).*?\{/php\}").unwrap()
        });
        if let Some(m) = smarty_php_system.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_smarty_php".into(),
                confidence: 0.96,
                detail: format!("Smarty PHP execution block: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Smarty php tag executes system command in template context"
                        .into(),
                    offset: m.start(),
                    property: "User input must not inject Smarty php execution tags".into(),
                }],
            });
        }
        static SMARTY_WRITE_FILE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)\{Smarty_Internal_Write_File::writeFile\(\$SCRIPT_NAME,\s*["'][^"']*["']\)\}"#).unwrap()
        });
        let smarty_write_file = &*SMARTY_WRITE_FILE_RE;
        if let Some(m) = smarty_write_file.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_smarty_writefile".into(),
                confidence: 0.95,
                detail: format!("Smarty file-write primitive in template: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "Smarty internal writeFile API writes attacker-controlled template content"
                            .into(),
                    offset: m.start(),
                    property: "Template input must not invoke Smarty internal file-write APIs"
                        .into(),
                }],
            });
        }

        // Handlebars gadget chain: nested with blocks and this resolution
        static HANDLEBARS_CHAIN_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"\{\{#with\s+["'][^"']+["']\s+as\s+\|[^|]+\|\}\}\s*\{\{#with\s+["'][^"']+["']\}\}\s*\{\{this\}\}"#).unwrap()
        });
        let handlebars_chain = &*HANDLEBARS_CHAIN_RE;
        if let Some(m) = handlebars_chain.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_handlebars_chain".into(),
                confidence: 0.90,
                detail: format!("Handlebars helper-chain gadget: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Nested Handlebars helpers manipulate context to expose executable object chain".into(),
                    offset: m.start(),
                    property: "Template input must not construct unsafe Handlebars helper chains".into(),
                }],
            });
        }

        // Explicit Jinja2 class hierarchy traversal markers (__mro__, __subclasses__)
        static JINJA_MRO_SUBCLASS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)\{\{[^}]*__(?:mro|subclasses)__[^}]*\}\}").unwrap()
        });
        if let Some(m) = JINJA_MRO_SUBCLASS_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_jinja_hierarchy_traversal".into(),
                confidence: 0.95,
                detail: format!("Jinja2 hierarchy traversal payload: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Template expression walks Python class hierarchy to reach dangerous gadgets".into(),
                    offset: m.start(),
                    property: "Template expressions must not expose Python object model internals".into(),
                }],
            });
        }

        // Twig template injection via block/parent/source primitives.
        static TWIG_BLOCK_PARENT_SOURCE_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(
            || {
                Regex::new(r#"(?is)(?:\{%\s*block\s+[a-zA-Z_][a-zA-Z0-9_]*\s*%|\{\{\s*parent\s*\(|\{\{\s*source\s*\()"#).unwrap()
            },
        );
        if let Some(m) = TWIG_BLOCK_PARENT_SOURCE_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_twig_function_injection".into(),
                confidence: 0.92,
                detail: format!("Twig block/parent/source injection primitive: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Twig template control/function primitives can expose templates and bypass sandboxing".into(),
                    offset: m.start(),
                    property: "User input must not inject Twig control blocks or template-loading functions".into(),
                }],
            });
        }

        // Smarty PHP and literal tags as template execution/escaping control surfaces.
        static SMARTY_LITERAL_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"(?is)\{literal\}.*?\{/literal\}").unwrap());
        if let Some(m) = SMARTY_LITERAL_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_smarty_literal".into(),
                confidence: 0.84,
                detail: format!("Smarty literal block injection: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SyntaxRepair,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Literal blocks can alter parser behavior and assist payload smuggling across filters".into(),
                    offset: m.start(),
                    property: "Template input must not permit raw Smarty control tags".into(),
                }],
            });
        }

        // Pebble Java template injection chains (beans/runtime).
        static PEBBLE_RUNTIME_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?is)(?:\{\{|\$\{)[^}\n]*(?:beans|beanResolver|request\.getAttribute\(['"]?beans['"]?\)|runtime|java\.lang\.Runtime|forName\(['"]java\.lang\.Runtime['"]\))[^}\n]*(?:\}\}|\})"#,
            )
            .unwrap()
        });
        if let Some(m) = PEBBLE_RUNTIME_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_pebble_runtime".into(),
                confidence: 0.93,
                detail: format!("Pebble/Java template runtime traversal payload: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::SemanticEval,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Template expression traverses bean/runtime objects toward command execution primitives".into(),
                    offset: m.start(),
                    property: "Pebble template evaluation must not expose beans or runtime reflection objects".into(),
                }],
            });
        }

        // EL injection beyond direct ${T(...)} style (e.g. #{T(...)} and reflective getClass/forName chains).
        static EL_INJECTION_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(
                r#"(?is)(?:\$\{|#\{)\s*(?:T\s*\(\s*java\.lang\.(?:Runtime|ProcessBuilder|Class)\s*\)|['"][^'"]*['"]\s*\.getClass\(\)\.forName\(\s*['"]java\.lang\.(?:Runtime|ProcessBuilder|Class)['"]\s*\))"#,
            )
            .unwrap()
        });
        if let Some(m) = EL_INJECTION_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_el_injection".into(),
                confidence: 0.95,
                detail: format!("Expression Language runtime access payload: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation:
                        "EL expression resolves runtime/reflective Java classes for code execution"
                            .into(),
                    offset: m.start(),
                    property: "EL expressions from user input must be disabled or sandboxed".into(),
                }],
            });
        }

        // Mako module-level Python code block: <%! import os %>
        static MAKO_MODULE_IMPORT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"(?is)<%!\s*import\s+(?:os|subprocess|sys)\s*%>").unwrap()
        });
        if let Some(m) = MAKO_MODULE_IMPORT_RE.find(&decoded) {
            dets.push(L2Detection {
                detection_type: "ssti_mako_module_block".into(),
                confidence: 0.94,
                detail: format!("Mako module-level code block import: {}", m.as_str()),
                position: m.start(),
                evidence: vec![ProofEvidence {
                    operation: EvidenceOperation::PayloadInject,
                    matched_input: m.as_str().to_owned(),
                    interpretation: "Mako module declaration executes arbitrary Python imports at template compile time".into(),
                    offset: m.start(),
                    property: "User input must not inject Mako `<%! %>` module declarations".into(),
                }],
            });
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "ssti_jinja" | "ssti_probe" | "ssti_freemarker" | "ssti_velocity" | "ssti_erb" => {
                Some(InvariantClass::SstiJinjaTwig)
            }
            "ssti_spel_runtime" | "ssti_el_injection" => Some(InvariantClass::SstiElExpression),
            "ssti_mako_rce"
            | "ssti_twig_escape"
            | "ssti_jinja_block_tag"
            | "ssti_jinja_attr_filter_bypass"
            | "ssti_twig_map_filter_chain"
            | "ssti_template_comment_bypass"
            | "ssti_jinja_class_chain"
            | "ssti_smarty_php"
            | "ssti_smarty_writefile"
            | "ssti_handlebars_chain"
            | "ssti_jinja_hierarchy_traversal"
            | "ssti_twig_function_injection"
            | "ssti_smarty_literal"
            | "ssti_pebble_runtime"
            | "ssti_mako_module_block" => Some(InvariantClass::SstiJinjaTwig),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_spel_runtime_expression() {
        let eval = SstiEvaluator;
        let dets = eval.detect("${T(java.lang.Runtime).getRuntime().exec('id')}");
        assert!(dets.iter().any(|d| d.detection_type == "ssti_spel_runtime"));
    }

    #[test]
    fn detects_mako_import_and_popen() {
        let eval = SstiEvaluator;
        let dets = eval.detect("<% import os %>${os.popen('id').read()}");
        assert!(dets.iter().any(|d| d.detection_type == "ssti_mako_rce"));
    }

    #[test]
    fn detects_twig_sandbox_escape_patterns() {
        let eval = SstiEvaluator;
        let dets = eval.detect("{{ value|filter('system') }} {{ _self.env.getRuntime() }}");
        assert!(dets.iter().any(|d| d.detection_type == "ssti_twig_escape"));
    }

    #[test]
    fn detects_jinja_class_traversal_chain() {
        let eval = SstiEvaluator;
        let dets = eval.detect("{{''.__class__.__mro__[2].__subclasses__()}}");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssti_jinja_class_chain")
        );
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssti_jinja_class_chain"
                    && (d.confidence - 0.94).abs() < f64::EPSILON)
        );
    }

    #[test]
    fn detects_smarty_php_and_writefile_payloads() {
        let eval = SstiEvaluator;
        let dets = eval.detect("{php}system('id');{/php} {Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"code\")}");
        assert!(dets.iter().any(|d| d.detection_type == "ssti_smarty_php"));
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssti_smarty_writefile")
        );
    }

    #[test]
    fn detects_handlebars_chain_payload() {
        let eval = SstiEvaluator;
        let dets = eval.detect(r#"{{#with "s" as |string|}}{{#with "e"}}{{this}}"#);
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssti_handlebars_chain")
        );
    }

    #[test]
    fn detects_jinja_hierarchy_traversal_markers() {
        let eval = SstiEvaluator;
        let dets = eval.detect("{{ ''.__class__.__mro__[1].__subclasses__() }}");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssti_jinja_hierarchy_traversal")
        );
    }

    #[test]
    fn detects_twig_block_injection() {
        let eval = SstiEvaluator;
        let dets = eval.detect("{% block body %}{{ source('admin.twig') }}{% endblock %}");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssti_twig_function_injection")
        );
    }

    #[test]
    fn detects_twig_parent_function_injection() {
        let eval = SstiEvaluator;
        let dets = eval.detect("{{ parent() }}");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssti_twig_function_injection")
        );
    }

    #[test]
    fn detects_smarty_literal_tag_injection() {
        let eval = SstiEvaluator;
        let dets = eval.detect("{literal}{$smarty.server.DOCUMENT_ROOT}{/literal}");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssti_smarty_literal")
        );
    }

    #[test]
    fn detects_pebble_runtime_chain() {
        let eval = SstiEvaluator;
        let dets = eval.detect("{{ beans['runtime'].exec('id') }}");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssti_pebble_runtime")
        );
    }

    #[test]
    fn detects_el_injection_with_hash_prefix() {
        let eval = SstiEvaluator;
        let dets = eval.detect("#{T(java.lang.Runtime).getRuntime().exec('id')}");
        assert!(dets.iter().any(|d| d.detection_type == "ssti_el_injection"));
    }

    #[test]
    fn detects_el_reflective_runtime_access() {
        let eval = SstiEvaluator;
        let dets = eval.detect("${''.getClass().forName('java.lang.Runtime')}");
        assert!(dets.iter().any(|d| d.detection_type == "ssti_el_injection"));
    }

    #[test]
    fn detects_mako_module_import_block() {
        let eval = SstiEvaluator;
        let dets = eval.detect("<%! import os %>${os.system('id')}");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssti_mako_module_block")
        );
    }

    #[test]
    fn detects_mako_module_import_subprocess_block() {
        let eval = SstiEvaluator;
        let dets = eval.detect("<%! import subprocess %>${7*7}");
        assert!(
            dets.iter()
                .any(|d| d.detection_type == "ssti_mako_module_block")
        );
    }

    #[test]
    fn detects_jinja_block_tag_ssti_with_confidence_threshold() {
        let eval = SstiEvaluator;
        let dets = eval.detect("{% for x in os.popen('id').read() %}{{ x }}{% endfor %}");
        assert!(dets.iter().any(|d| {
            d.detection_type == "ssti_jinja_block_tag" && d.confidence > 0.75
        }));
    }

    #[test]
    fn detects_jinja_attr_filter_bypass_with_confidence_threshold() {
        let eval = SstiEvaluator;
        let dets = eval.detect("{{ request|attr('__class__') }}");
        assert!(dets.iter().any(|d| {
            d.detection_type == "ssti_jinja_attr_filter_bypass" && d.confidence > 0.75
        }));
    }

    #[test]
    fn detects_twig_map_filter_chain_with_confidence_threshold() {
        let eval = SstiEvaluator;
        let dets = eval.detect("{{ ['system']|map('trim') }}");
        assert!(dets.iter().any(|d| {
            d.detection_type == "ssti_twig_map_filter_chain" && d.confidence > 0.75
        }));
    }

    #[test]
    fn detects_template_comment_stripping_bypass_with_confidence_threshold() {
        let eval = SstiEvaluator;
        let dets = eval.detect("{# hidden {{ cycler.__init__.__globals__ }} #}");
        assert!(dets.iter().any(|d| {
            d.detection_type == "ssti_template_comment_bypass" && d.confidence > 0.75
        }));
    }
}
