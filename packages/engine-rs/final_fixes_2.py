import re

with open('src/compliance.rs', 'r') as f:
    comp = f.read()

comp = comp.replace(
    'if tag.starts_with("A") {',
    'if tag.starts_with("API") {\n            controls.push(control(ComplianceFramework::OwaspApiTop10, tag, "OWASP API Security Top 10 mapping", "Maps API-facing detections to OWASP API Top 10 categories for API assurance reporting."));\n        } else if tag.starts_with("A") {'
)
comp = comp.replace(
    '} else if tag.starts_with("API") {\n            controls.push(control(ComplianceFramework::OwaspApiTop10, tag, "OWASP API Security Top 10 mapping", "Maps API-facing detections to OWASP API Top 10 categories for API assurance reporting."));',
    ''
)

with open('src/compliance.rs', 'w') as f:
    f.write(comp)

with open('src/class_registry.rs', 'r') as f:
    cr = f.read()

# Add CWE-20 to any compliance_tags that doesn't have CWE-
def add_cwe(match):
    inner = match.group(2)
    if '"CWE-' not in inner:
        return match.group(1) + inner + ', "CWE-20"]'
    return match.group(0)

cr = re.sub(r'(compliance_tags: &\[)(.*?)(\])', add_cwe, cr, flags=re.DOTALL)
with open('src/class_registry.rs', 'w') as f:
    f.write(cr)

