import re

home_path = '/home/mukund-thiru/Santh/hub/src/pages/Home.tsx'
with open(home_path, 'r') as f:
    home_content = f.read()

home_content = re.sub(
    r'title="[^"]*"',
    r'title="INVARIANT — Runtime Security That Detects What WAFs Miss | Santh"',
    home_content,
    count=1
)

home_content = re.sub(
    r'description=\{`[^`]*`\}',
    r'description="INVARIANT is a zero-dependency runtime security engine for Next.js, Cloudflare Workers, and Node.js. Detects SQL injection, XSS, SSRF, path traversal and 63 more attack classes using mathematical invariants — not signature updates."',
    home_content,
    count=1
)

home_content = re.sub(
    r'keywords="([^"]*)"',
    r'keywords="\1, runtime application self-protection, RASP TypeScript, Cloudflare WAF alternative, Next.js security middleware, SQL injection detection, web application firewall alternative, runtime security engine, zero-day detection"',
    home_content,
    count=1
)

with open(home_path, 'w') as f:
    f.write(home_content)

col_path = '/home/mukund-thiru/Santh/hub/src/pages/Collective.tsx'
with open(col_path, 'r') as f:
    col_content = f.read()

col_content = re.sub(
    r'title="[^"]*"',
    r'title="Collective Intelligence — Crowdsourced Attack Pattern Detection | Santh"',
    col_content,
    count=1
)

col_content = re.sub(
    r'description="[^"]*"',
    r'description="INVARIANT Collective aggregates real-time attack signals across thousands of sensors worldwide. Detect emerging campaigns before they hit your infrastructure."',
    col_content,
    count=1
)

with open(col_path, 'w') as f:
    f.write(col_content)

print("SEO tags updated successfully!")