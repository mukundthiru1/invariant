with open('src/compliance.rs', 'r') as f:
    text = f.read()

text = text.replace('let cwes = cwe_ids_for_class(*class);', 'let cwes: Vec<&str> = crate::class_registry::compliance_for(*class).iter().filter(|t| t.starts_with("CWE-")).cloned().collect();')
text = text.replace('let id = owasp_top10_2021_for_class(*class);', 'let id: Option<&&str> = crate::class_registry::compliance_for(*class).iter().find(|t| t.starts_with("A") && t.ends_with(":2021")); let id = id.unwrap_or(&"A05:2021");')

with open('src/compliance.rs', 'w') as f:
    f.write(text)
