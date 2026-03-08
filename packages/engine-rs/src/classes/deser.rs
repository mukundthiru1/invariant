use regex::Regex;
use std::sync::LazyLock;

use crate::classes::{ClassDefinition, decode};
use crate::types::InvariantClass;

static JAVA_1: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"aced0005|rO0ABX").unwrap());
static JAVA_2: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:java\.lang\.Runtime|ProcessBuilder|ChainedTransformer|InvokerTransformer|ConstantTransformer|commons-collections|ysoserial)").unwrap());
static PHP_1: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"O:\d+:"[^"]+""#).unwrap());
static PHP_2: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"a:\d+:\{").unwrap());
static PY_PICKLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x80\x04\x95|cos\nsystem|cbuiltins\n|c__builtin__|cposix\nsystem").unwrap());

fn deser_java_gadget(input: &str) -> bool {
    let d = decode(input);
    JAVA_1.is_match(&d) || JAVA_2.is_match(&d)
}
fn deser_php_object(input: &str) -> bool {
    let d = decode(input);
    PHP_1.is_match(&d) || PHP_2.is_match(&d)
}
fn deser_python_pickle(input: &str) -> bool {
    PY_PICKLE.is_match(&decode(input))
}

pub const DESER_CLASSES: &[ClassDefinition] = &[
    ClassDefinition {
        id: InvariantClass::DeserJavaGadget,
        description: "Java deserialization gadget chain to achieve remote code execution",
        detect: deser_java_gadget,
        known_payloads: &["rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==", "aced00057372", "java.lang.Runtime.getRuntime().exec(\"id\")"],
        known_benign: &["java programming language", "runtime error occurred", "application serialized data"],
        mitre: &["T1203"],
        cwe: Some("CWE-502"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::DeserPhpObject,
        description: "PHP object injection via unserialize() to trigger magic methods",
        detect: deser_php_object,
        known_payloads: &[
            "O:4:\"User\":2:{s:4:\"name\";s:5:\"admin\";s:4:\"role\";s:5:\"admin\";}",
            "O:11:\"Application\":1:{s:3:\"cmd\";s:2:\"id\";}",
        ],
        known_benign: &["Order #12345", "O: oxygen", "a: apple", "the format is O:N:"],
        mitre: &["T1203"],
        cwe: Some("CWE-502"),
        formal_property: None,
        composable_with: &[],
    },
    ClassDefinition {
        id: InvariantClass::DeserPythonPickle,
        description: "Python pickle deserialization to execute arbitrary code via __reduce__",
        detect: deser_python_pickle,
        known_payloads: &["cos\nsystem\n(S'id'\ntR.", "cbuiltins\neval\n(S'__import__(\"os\").system(\"id\")'\ntR."],
        known_benign: &["pickle jar", "python programming", "import os", "reduce function"],
        mitre: &["T1203"],
        cwe: Some("CWE-502"),
        formal_property: None,
        composable_with: &[],
    },
];
