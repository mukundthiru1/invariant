use crate::encoding::multi_layer_decode;
use crate::types::InvariantClass;

pub mod auth;
pub mod cmdi;
pub mod deser;
pub mod injection;
pub mod path;
pub mod sqli;
pub mod ssrf;
pub mod xss;

#[derive(Clone, Copy)]
pub struct ClassDefinition {
    pub id: InvariantClass,
    pub description: &'static str,
    pub detect: fn(&str) -> bool,
    pub known_payloads: &'static [&'static str],
    pub known_benign: &'static [&'static str],
    pub mitre: &'static [&'static str],
    pub cwe: Option<&'static str>,
    pub formal_property: Option<&'static str>,
    pub composable_with: &'static [InvariantClass],
}

pub(crate) fn decode(input: &str) -> String {
    multi_layer_decode(input).fully_decoded
}

pub fn all_classes() -> &'static [ClassDefinition] {
    static ALL: std::sync::LazyLock<Vec<ClassDefinition>> = std::sync::LazyLock::new(|| {
        let mut all = Vec::new();
        all.extend_from_slice(sqli::SQL_CLASSES);
        all.extend_from_slice(xss::XSS_CLASSES);
        all.extend_from_slice(cmdi::CMD_CLASSES);
        all.extend_from_slice(path::PATH_CLASSES);
        all.extend_from_slice(ssrf::SSRF_CLASSES);
        all.extend_from_slice(deser::DESER_CLASSES);
        all.extend_from_slice(auth::AUTH_CLASSES);
        all.extend_from_slice(injection::INJECTION_CLASSES);
        all
    });
    ALL.as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_payloads_and_benign_regression() {
        for class in all_classes() {
            for payload in class.known_payloads {
                assert!(
                    (class.detect)(payload),
                    "{} failed payload detection: {:?}",
                    format!("{:?}", class.id),
                    payload
                );
            }
            for benign in class.known_benign {
                assert!(
                    !(class.detect)(benign),
                    "{} false-positive on benign: {:?}",
                    format!("{:?}", class.id),
                    benign
                );
            }
        }
    }
}
