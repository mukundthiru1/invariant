//! Deserialization Evaluator — Insecure Deserialization Detection

use crate::evaluators::{EvidenceOperation, L2Detection, L2Evaluator, ProofEvidence};
use crate::types::InvariantClass;
use regex::Regex;

pub struct DeserEvaluator;

impl L2Evaluator for DeserEvaluator {
    fn id(&self) -> &'static str { "deser" }
    fn prefix(&self) -> &'static str { "L2 Deser" }

    #[inline]

    fn detect(&self, input: &str) -> Vec<L2Detection> {
        let mut dets = Vec::new();
        let decoded = crate::encoding::multi_layer_decode(input).fully_decoded;

        // Java serialized object magic bytes (check as bytes since 0xAC/0xED are non-ASCII)
        let has_java_magic = decoded.as_bytes().windows(4).any(|w| w == [0xAC, 0xED, 0x00, 0x05]);
        if has_java_magic || decoded.starts_with("rO0AB") {
            dets.push(mk("java_serial", 0.92, "Java serialized object detected",
                "Java serialized object can trigger arbitrary code via gadget chains",
                "Serialized Java objects must not be accepted from untrusted sources",
                &decoded, 0));
        }

        // Java gadget chains: Commons Collections / Spring / Jackson polymorphic gadgets
        static java_gadget: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:InvokerTransformer|ChainedTransformer|ConstantTransformer|MethodInvokeTypeProvider|AbstractBeanFactoryBasedTargetSource|com\.sun\.rowset\.JdbcRowSetImpl|javax\.management(?:\.[A-Za-z0-9_$]+)?)").unwrap());
        if let Some(m) = java_gadget.find(&decoded) {
            dets.push(mk("java_gadget_chain", 0.94, &format!("Java gadget chain token: {}", m.as_str()),
                "Known Java deserialization gadget class can be used for RCE",
                "Java deserialization input must enforce strict allowlisted types",
                m.as_str(), m.start()));
        }

        // Additional Java gadget families commonly used in ysoserial chains
        static java_ysoserial: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:TemplatesImpl|AnnotationInvocationHandler|BadAttributeValueExpException|PriorityQueue|BeanComparator|JdbcRowSetImpl|com\.mchange\.v2\.c3p0\.WrapperConnectionPoolDataSource)").unwrap());
        if let Some(m) = java_ysoserial.find(&decoded) {
            dets.push(mk("java_ysoserial_gadget", 0.95, &format!("Java ysoserial gadget token: {}", m.as_str()),
                "Known ysoserial gadget token indicates high-probability Java deserialization RCE chain",
                "Java deserialization must enforce type allowlists and disable native object deserialization on untrusted input",
                m.as_str(), m.start()));
        }

        // Jackson/Fastjson polymorphic type abuse patterns
        static JAVA_POLY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)"@type"\s*:\s*"(?:com\.sun\.org\.apache\.xalan\.internal\.xsltc\.trax\.TemplatesImpl|java\.lang\.Runtime|org\.apache\.commons\.collections\.[^"]+)""#).unwrap()
        });
        let java_poly = &*JAVA_POLY_RE;
        if let Some(m) = java_poly.find(&decoded) {
            dets.push(mk("java_polymorphic_type_abuse", 0.93, "Polymorphic type metadata targets known Java gadget class",
                "Polymorphic type deserialization can instantiate attacker-selected gadget classes",
                "Polymorphic deserialization must disable global auto-type and strictly constrain allowed types",
                m.as_str(), m.start()));
        }

        // PHP serialized object with class instantiation
        static PHP_OBJ_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"O:\d+:"[^"]+?":\d+:\{"#).unwrap());
        let php_obj = &*PHP_OBJ_RE;
        if let Some(m) = php_obj.find(&decoded) {
            dets.push(mk("php_object", 0.90, &format!("PHP serialized object: {}", m.as_str()),
                "PHP object deserialization triggers __wakeup/__destruct magic methods",
                "PHP serialized objects must not be accepted from untrusted sources",
                m.as_str(), m.start()));
        }

        // PHP POP chains in common frameworks/libraries
        static php_pop: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r#"(?i)(?:Monolog\\+Handler\\+[A-Za-z0-9_]+|Guzzle\\+[A-Za-z0-9_\\]+|Laravel\\+[A-Za-z0-9_\\]+|Symfony\\+[A-Za-z0-9_\\]+)"#).unwrap());
        if let Some(m) = php_pop.find(&decoded) {
            dets.push(mk("php_pop_chain", 0.92, &format!("PHP POP chain token: {}", m.as_str()),
                "Known PHP POP gadget namespace suggests exploitable object injection chain",
                "Serialized PHP object input must block gadget-prone classes",
                m.as_str(), m.start()));
        }

        // Base64-like PHP serialized object marker
        if let Some(pos) = decoded.find("Tzo") {
            dets.push(mk("php_base64_serial", 0.82, "Potential base64-encoded PHP serialized object marker (Tzo)",
                "Encoded payload resembles PHP serialized object preamble",
                "Encoded serialized blobs must be treated as untrusted object data",
                "Tzo", pos));
        }

        // PHP magic-method gadget primitives inside serialized payloads
        static php_magic: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r#"(?i)(?:__wakeup|__destruct|__toString|__call|__invoke)"#).unwrap());
        if php_obj.is_match(&decoded) {
            if let Some(m) = php_magic.find(&decoded) {
                dets.push(mk("php_magic_method_chain", 0.91, &format!("PHP magic method gadget primitive: {}", m.as_str()),
                    "Serialized object references PHP magic methods frequently used in POP exploit chains",
                    "PHP object deserialization should deny gadget classes exposing dangerous magic methods",
                    m.as_str(), m.start()));
            }
        }

        // PHAR wrapper abuse for implicit object deserialization
        static PHAR_WRAPPER_RE: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r#"(?i)phar://[^\s"'<>]+"#).unwrap());
        let phar_wrapper = &*PHAR_WRAPPER_RE;
        if let Some(m) = phar_wrapper.find(&decoded) {
            dets.push(mk("php_phar_deser", 0.90, "PHAR stream wrapper reference (implicit PHP deserialization path)",
                "PHAR metadata can trigger object deserialization through filesystem API calls",
                "PHP applications must block phar:// wrappers on user-controlled paths",
                m.as_str(), m.start()));
        }

        // Python pickle
        static pickle: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?:c__builtin__|cos\nsystem|cposix|c__main__)").unwrap());
        if let Some(m) = pickle.find(&decoded) {
            dets.push(mk("python_pickle", 0.92, "Python pickle with code execution opcodes",
                "Pickle deserialization executes arbitrary Python code",
                "Pickle objects must not be accepted from untrusted sources",
                m.as_str(), m.start()));
        }

        // Python deserialization primitives used by pickle/copyreg payloads
        static py_reduce: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:__reduce_ex?__|copyreg\._reconstructor|pickle\.loads\s*\(|dill\.loads\s*\()").unwrap());
        if let Some(m) = py_reduce.find(&decoded) {
            dets.push(mk("python_reduce", 0.90, &format!("Python deserialization primitive: {}", m.as_str()),
                "Python reduce/copyreg primitive can invoke attacker-controlled callables",
                "Deserialization helpers must reject untrusted pickle-like payloads",
                m.as_str(), m.start()));
        }

        // Base64-encoded pickle payload signature (protocol 4/5 blobs commonly start with gAS)
        static pickle_b64: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)\bgAS[A-Za-z0-9+/=_-]{12,}\b").unwrap());
        if let Some(m) = pickle_b64.find(&decoded) {
            dets.push(mk("python_pickle_base64", 0.88, "Base64-encoded Python pickle marker (gAS...)",
                "Payload appears to embed serialized pickle bytecode in base64 form",
                "Base64 decoding paths must treat pickle-like payloads as untrusted executable objects",
                m.as_str(), m.start()));
        }

        // Python pickle RCE opcodes / GLOBAL + REDUCE primitives
        static pickle_opcode_rce: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)(?:c(?:os|posix)\nsystem\n.{0,96}R|__reduce_ex?__|cos/system|(?:^|[\r\n])c[^\r\n]{1,80}[\r\n].{0,96}[\r\n]R(?:$|[\r\n]))"#).unwrap()
        });
        if let Some(m) = pickle_opcode_rce.find(&decoded) {
            dets.push(mk("python_pickle_opcode_rce", 0.94, "Python pickle RCE opcode pattern (GLOBAL/REDUCE)",
                "Pickle GLOBAL and REDUCE opcodes can invoke dangerous callables like os.system",
                "Pickle bytecode opcodes must be rejected for untrusted payloads",
                m.as_str(), m.start()));
        }

        // .NET serialized: TypeConfuseDelegate, ObjectDataProvider
        static dotnet: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:TypeConfuseDelegate|ObjectDataProvider|System\.Diagnostics\.Process|System\.Windows\.Data)").unwrap());
        if let Some(m) = dotnet.find(&decoded) {
            dets.push(mk("dotnet_deser", 0.88, &format!(".NET deserialization gadget: {}", m.as_str()),
                ".NET gadget chain enables arbitrary code execution",
                "Serialized .NET objects must be validated against type allowlist",
                m.as_str(), m.start()));
        }

        // .NET gadget classes seen in ysoserial.net payloads
        static dotnet_gadget: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:ActivitySurrogateSelector|TextFormattingRunProperties)").unwrap());
        if let Some(m) = dotnet_gadget.find(&decoded) {
            dets.push(mk("dotnet_gadget_chain", 0.92, &format!(".NET gadget class: {}", m.as_str()),
                "Known .NET gadget class indicates possible deserialization RCE chain",
                ".NET serializer inputs must enforce strict type binders/allowlists",
                m.as_str(), m.start()));
        }

        // BinaryFormatter payloads in base64 often begin with AAEAAAD/////
        static dotnet_binaryformatter: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"\bAAEAAAD/////[A-Za-z0-9+/=]{12,}\b").unwrap());
        if let Some(m) = dotnet_binaryformatter.find(&decoded) {
            dets.push(mk("dotnet_binaryformatter_payload", 0.91, "Possible .NET BinaryFormatter payload blob",
                "BinaryFormatter payload markers indicate unsafe type metadata deserialization",
                "BinaryFormatter/NetDataContract serializers must not process untrusted input",
                m.as_str(), m.start()));
        }

        // ASP.NET ViewState carrying BinaryFormatter markers
        static viewstate_binaryformatter: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?is)(?:^|[?&\s])__VIEWSTATE=([A-Za-z0-9%+/=_-]{24,}).{0,256}(?:AAEAAAD/////|AQAAAP////8)"#).unwrap()
        });
        if let Some(m) = viewstate_binaryformatter.find(&decoded) {
            dets.push(mk("dotnet_viewstate_binaryformatter", 0.93, "ASP.NET __VIEWSTATE with BinaryFormatter payload marker",
                "ViewState can embed unsafe BinaryFormatter object graphs when MAC/signature protections are weak or bypassed",
                "__VIEWSTATE must be integrity-protected and never deserialize untrusted BinaryFormatter data",
                m.as_str(), m.start()));
        }
        if decoded.contains("__VIEWSTATE=") && dotnet_binaryformatter.is_match(&decoded) {
            let pos = decoded.find("__VIEWSTATE=").unwrap_or(0);
            dets.push(mk("dotnet_viewstate_binaryformatter", 0.93, "ASP.NET __VIEWSTATE co-occurs with BinaryFormatter payload marker",
                "ViewState field includes BinaryFormatter-like payload bytes, a common insecure deserialization path",
                "ASP.NET ViewState handling must reject unsigned/tampered state and disable unsafe formatter paths",
                "__VIEWSTATE", pos));
        }

        // YAML deserialization: !!python/object
        static yaml: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"!!(?:python/object|ruby/object|java\.net|javax\.)").unwrap());
        if let Some(m) = yaml.find(&decoded) {
            dets.push(mk("yaml_deser", 0.90, &format!("YAML deserialization payload: {}", m.as_str()),
                "YAML type tag triggers language-specific object instantiation",
                "YAML input must use safe_load without custom type constructors",
                m.as_str(), m.start()));
        }

        // YAML language-specific object tags (broader coverage)
        static yaml_lang_tags: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)!!(?:python/object(?:/new|/apply)?|ruby/object|java(?:/[a-z0-9_.:$-]+)?)"#).unwrap()
        });
        if let Some(m) = yaml_lang_tags.find(&decoded) {
            dets.push(mk("yaml_language_tag_deser", 0.91, &format!("YAML language object tag: {}", m.as_str()),
                "Language-specific YAML tags can instantiate arbitrary objects during load",
                "YAML parsers must disable custom tags and only parse primitive schemas for untrusted input",
                m.as_str(), m.start()));
        }

        // Ruby YAML/Marshal gadget classes
        static ruby_gadget: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)(?:Gem::Installer|Gem::SpecFetcher|ERB)").unwrap());
        if let Some(m) = ruby_gadget.find(&decoded) {
            dets.push(mk("ruby_yaml_gadget", 0.91, &format!("Ruby deserialization gadget: {}", m.as_str()),
                "Ruby gadget class appears in deserialization payloads that lead to command execution",
                "Ruby YAML/Marshal deserialization must reject untrusted class instantiation",
                m.as_str(), m.start()));
        }

        // Ruby Marshal serialized payloads (binary/base64 marker "BAh")
        static ruby_marshal: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r#"(?i)\bBAh(?:[A-Za-z0-9+/=]{10,})"#).unwrap());
        if let Some(m) = ruby_marshal.find(&decoded) {
            dets.push(mk("ruby_marshal_payload", 0.89, "Ruby Marshal payload marker (BAh...)",
                "Ruby Marshal blobs are executable object graphs when loaded",
                "Ruby Marshal.load must never receive attacker-controlled data",
                m.as_str(), m.start()));
        }

        // Ruby Marshal raw magic bytes 0x04 0x08, including escaped representation
        let has_ruby_marshal_magic = decoded.as_bytes().windows(2).any(|w| w == [0x04, 0x08]);
        if has_ruby_marshal_magic || decoded.contains("\\x04\\x08") {
            let marker = if decoded.contains("\\x04\\x08") { "\\x04\\x08" } else { "\u{0004}\u{0008}" };
            let pos = decoded.find("\\x04\\x08").unwrap_or(0);
            dets.push(mk("ruby_marshal_magic_bytes", 0.93, "Ruby Marshal magic bytes detected (0x04 0x08)",
                "Ruby Marshal binary header indicates object graph deserialization entrypoint",
                "Ruby Marshal.load must reject attacker-controlled binary blobs",
                marker, pos));
        }

        // PHP object gadget chains encoded as O:<len> with known framework classes
        static php_gadget_object: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r#"(?i)O:\d+:"(?:Monolog(?:\\[A-Za-z0-9_]+)+|Guzzle(?:\\[A-Za-z0-9_]+)+|Laravel(?:\\[A-Za-z0-9_]+)+)":\d+:\{"#).unwrap()
        });
        if let Some(m) = php_gadget_object.find(&decoded) {
            dets.push(mk("php_gadget_object_chain", 0.94, "PHP unserialize gadget object chain (Monolog/Guzzle/Laravel)",
                "Known gadget-bearing PHP framework class appears in serialized object format",
                "PHP unserialize() must block framework gadget classes and untrusted serialized blobs",
                m.as_str(), m.start()));
        }

        // Java-specific binary serializer format signatures (Kryo/Hessian)
        let decoded_bytes = decoded.as_bytes();
        let has_kryo_signature = decoded_bytes.windows(4).any(|w| w == b"KRYO")
            || decoded.contains("com.esotericsoftware.kryo")
            || decoded.contains("S1JZTw");
        if has_kryo_signature {
            dets.push(mk("java_kryo_serial", 0.88, "Kryo serialization signature detected",
                "Kryo binary payloads can deserialize attacker-controlled class graphs in Java stacks",
                "Kryo deserialization must enforce class allowlisting and untrusted input isolation",
                "KRYO", decoded.find("KRYO").unwrap_or(0)));
        }

        let has_hessian_signature = decoded_bytes.windows(3).any(|w| w == [0x48, 0x02, 0x00])
            || decoded.contains("Hessian2Input")
            || decoded.contains("com.caucho.hessian");
        if has_hessian_signature {
            dets.push(mk("java_hessian_serial", 0.89, "Hessian serialization signature detected",
                "Hessian payloads may instantiate attacker-controlled Java object graphs",
                "Hessian deserialization must restrict allowed types and reject untrusted blobs",
                "Hessian", decoded.find("Hessian").unwrap_or(0)));
        }

        // Node.js unserialize abuse marker from node-serialize style payloads
        static node_unserialize: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(r"(?i)_\$\$ND_FUNC\$\$_|(?:node-serialize|serialize-javascript)").unwrap());
        if let Some(m) = node_unserialize.find(&decoded) {
            dets.push(mk("node_unserialize_gadget", 0.90, "Node.js unserialize gadget/function marker",
                "Serialized JavaScript function marker indicates unsafe deserialization path to code execution",
                "Node deserialization libraries must reject function-valued serialized content",
                m.as_str(), m.start()));
        }

        dets
    }

    fn map_class(&self, detection_type: &str) -> Option<InvariantClass> {
        match detection_type {
            "java_serial" | "java_gadget_chain" | "java_ysoserial_gadget" | "java_polymorphic_type_abuse" | "ruby_yaml_gadget" | "ruby_marshal_payload" | "ruby_marshal_magic_bytes" | "java_kryo_serial" | "java_hessian_serial" => Some(InvariantClass::DeserJavaGadget),
            "php_object" | "php_pop_chain" | "php_base64_serial" | "php_magic_method_chain" | "php_phar_deser" | "php_gadget_object_chain" => Some(InvariantClass::DeserPhpObject),
            "python_pickle" | "python_reduce" | "python_pickle_base64" | "python_pickle_opcode_rce" | "dotnet_deser" | "dotnet_gadget_chain" | "dotnet_binaryformatter_payload" | "dotnet_viewstate_binaryformatter" | "yaml_deser" | "yaml_language_tag_deser" | "node_unserialize_gadget" => Some(InvariantClass::DeserPythonPickle),
            _ => None,
        }
    }
}

fn mk(det_type: &str, confidence: f64, detail: &str, interp: &str, prop: &str, matched: &str, offset: usize) -> L2Detection {
    L2Detection {
        detection_type: det_type.into(),
        confidence,
        detail: detail.into(),
        position: offset,
        evidence: vec![ProofEvidence {
            operation: EvidenceOperation::PayloadInject,
            matched_input: matched[..matched.len().min(80)].to_owned(),
            interpretation: interp.into(),
            offset,
            property: prop.into(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_java_commons_gadget_chain() {
        let eval = DeserEvaluator;
        let dets = eval.detect("payload=InvokerTransformer+ChainedTransformer");
        assert!(dets.iter().any(|d| d.detection_type == "java_gadget_chain"));
    }

    #[test]
    fn detects_php_pop_chain_namespace() {
        let eval = DeserEvaluator;
        let dets = eval.detect(r#"O:8:"Exploit":1:{s:4:"x";s:24:"Monolog\\Handler\\SyslogUdpHandler";}"#);
        assert!(dets.iter().any(|d| d.detection_type == "php_pop_chain"));
    }

    #[test]
    fn detects_python_reduce_patterns() {
        let eval = DeserEvaluator;
        let dets = eval.detect("__reduce__ and copyreg._reconstructor can execute code");
        assert!(dets.iter().any(|d| d.detection_type == "python_reduce"));
    }

    #[test]
    fn detects_dotnet_and_ruby_gadgets() {
        let eval = DeserEvaluator;
        let dotnet = eval.detect("ActivitySurrogateSelector");
        let ruby = eval.detect("--- !ruby/object:Gem::Installer {}");
        assert!(dotnet.iter().any(|d| d.detection_type == "dotnet_gadget_chain"));
        assert!(ruby.iter().any(|d| d.detection_type == "ruby_yaml_gadget"));
    }

    #[test]
    fn detects_java_ysoserial_and_polymorphic_abuse() {
        let eval = DeserEvaluator;
        let ysoserial = eval.detect("TemplatesImpl BadAttributeValueExpException");
        let poly = eval.detect(r#"{"@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"}"#);
        assert!(ysoserial.iter().any(|d| d.detection_type == "java_ysoserial_gadget"));
        assert!(poly.iter().any(|d| d.detection_type == "java_polymorphic_type_abuse"));
    }

    #[test]
    fn detects_php_magic_and_phar() {
        let eval = DeserEvaluator;
        let magic = eval.detect(r#"O:8:"Exploit":1:{s:4:"x";s:10:"__destruct";}"#);
        let phar = eval.detect("file=phar://uploads/avatar.jpg/test.txt");
        assert!(magic.iter().any(|d| d.detection_type == "php_magic_method_chain"));
        assert!(phar.iter().any(|d| d.detection_type == "php_phar_deser"));
    }

    #[test]
    fn detects_pickle_base64_dotnet_blob_and_node_marker() {
        let eval = DeserEvaluator;
        let pickle = eval.detect("gASVdQAAAAAAAAB9lCiMBGNtZJSUjAZvcy5zeXN0ZW2Uk5R1Lg==");
        let dotnet = eval.detect("AAEAAAD/////AQAAAAAAAAAMAgAA");
        let node = eval.detect(r#"{"rce":"_$$ND_FUNC$$_function(){return process.mainModule.require('child_process').exec('id') }()"}"#);
        assert!(pickle.iter().any(|d| d.detection_type == "python_pickle_base64"));
        assert!(dotnet.iter().any(|d| d.detection_type == "dotnet_binaryformatter_payload"));
        assert!(node.iter().any(|d| d.detection_type == "node_unserialize_gadget"));
    }

    #[test]
    fn detects_python_pickle_opcode_rce_patterns() {
        let eval = DeserEvaluator;
        let dets = eval.detect("payload=cos\nsystem\n(S'id'\ntR.");
        assert!(dets.iter().any(|d| d.detection_type == "python_pickle_opcode_rce"));
    }

    #[test]
    fn detects_php_o_pattern_known_gadget_classes() {
        let eval = DeserEvaluator;
        let dets = eval.detect(r#"O:31:"Monolog\Handler\SyslogUdpHandler":1:{s:7:"socket";s:2:"fd";}"#);
        assert!(dets.iter().any(|d| d.detection_type == "php_gadget_object_chain"));
    }

    #[test]
    fn detects_ruby_marshal_magic_bytes_marker() {
        let eval = DeserEvaluator;
        let dets = eval.detect(r#"\x04\x08o:12:"Gem::SpecFetcher""#);
        assert!(dets.iter().any(|d| d.detection_type == "ruby_marshal_magic_bytes"));
    }

    #[test]
    fn detects_dotnet_viewstate_binaryformatter_combo() {
        let eval = DeserEvaluator;
        let dets = eval.detect("__VIEWSTATE=AAEAAAD/////AQAAAAAAAAAMAgAA");
        assert!(dets.iter().any(|d| d.detection_type == "dotnet_viewstate_binaryformatter"));
    }

    #[test]
    fn detects_yaml_python_ruby_java_object_tags() {
        let eval = DeserEvaluator;
        let py = eval.detect("!!python/object/new:os.system ['id']");
        let rb = eval.detect("!!ruby/object:Gem::Installer {}");
        let jv = eval.detect("!!java/lang/Runtime {}");
        assert!(py.iter().any(|d| d.detection_type == "yaml_language_tag_deser"));
        assert!(rb.iter().any(|d| d.detection_type == "yaml_language_tag_deser"));
        assert!(jv.iter().any(|d| d.detection_type == "yaml_language_tag_deser"));
    }

    #[test]
    fn detects_kryo_format_signature() {
        let eval = DeserEvaluator;
        let dets = eval.detect("KRYO\x01\x00payload");
        assert!(dets.iter().any(|d| d.detection_type == "java_kryo_serial"));
    }

    #[test]
    fn detects_hessian_format_signature() {
        let eval = DeserEvaluator;
        let dets = eval.detect("Hessian2Input stream marker");
        assert!(dets.iter().any(|d| d.detection_type == "java_hessian_serial"));
    }
}
