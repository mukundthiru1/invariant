import os
import re

base_dir = '/home/mukund-thiru/Santh/hub/src/'

# 1. Update SEO.tsx
seo_path = os.path.join(base_dir, 'components/SEO.tsx')
with open(seo_path, 'r') as f:
    seo_content = f.read()

seo_content = seo_content.replace(
    "const DEFAULT_TITLE = 'Santh | Enterprise Application Security & RASP Protection'",
    "const DEFAULT_TITLE = 'Santh | RASP, Runtime Application Security & Application Security Middleware'"
)
seo_content = seo_content.replace(
    "description = 'Santh is the leading WAF alternative and RASP protection platform. We provide enterprise-grade application security using mathematical invariant matching to stop zero-day attacks without signatures.'",
    "description = 'Santh is a zero configuration, edge-native RASP (Runtime Application Security Protection) platform. We use mathematical invariants to stop zero-day attacks without signatures, offering no agents required deployment, minimal false positive rate, and collective threat intelligence.'"
)
with open(seo_path, 'w') as f:
    f.write(seo_content)


# 2. Update Home.tsx
home_path = os.path.join(base_dir, 'pages/Home.tsx')
with open(home_path, 'r') as f:
    home_content = f.read()

# Update Hero
home_content = re.sub(
    r'<p id="home-hero-statement" className="home-hero__statement">.*?<\/p>',
    '<p id="home-hero-statement" className="home-hero__statement">Your application has mathematical invariants.<br />Attacks violate them. We prove it.</p>',
    home_content,
    flags=re.DOTALL
)

home_content = re.sub(
    r'<p className="home-hero__pillars">.*?<\/p>',
    '<p className="home-hero__pillars" style={{textTransform: "none", letterSpacing: "normal"}}>INVARIANT is a formal property-based security engine deployed as a single Cloudflare Worker. Detects SQLi, XSS, RCE, and 50+ attack classes through structural proof — not signatures.</p>',
    home_content,
    flags=re.DOTALL
)

# Insert WAF comparison
waf_section = """
      {/* ═══════════════════════════════════════════
          WAF COMPARISON
          ═══════════════════════════════════════════ */}
      <section className="home-section home-snap" aria-labelledby="waf-comparison">
        <div className="home-section__inner">
          <Reveal>
            <div className="home-section__header">
              <div>
                <span className="home-section__label" data-signal="defense">The Difference</span>
                <h2 id="waf-comparison" className="home-section__title">
                  Why INVARIANT defeats WAFs
                </h2>
                <p className="home-section__prose">
                  WAFs match known signatures, missing novel variants. INVARIANT proves properties violated, catching every variant by definition. Zero configuration. Edge-native. No agents required. Minimal false positive rate.
                </p>
              </div>
            </div>
          </Reveal>
          <Reveal delay={1}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mt-8 text-left" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', marginTop: '2rem' }}>
              <div className="bg-white/[0.02] border border-white/[0.05] p-6 rounded-sm" style={{ padding: '1.5rem', border: '1px solid rgba(255,255,255,0.05)' }}>
                <h3 className="text-red-400 font-mono text-sm mb-4" style={{ color: '#f87171', marginBottom: '1rem', fontFamily: 'monospace' }}>WAF: Signature Matching</h3>
                <p className="text-white/60 text-sm mb-4" style={{ color: 'rgba(255,255,255,0.6)', marginBottom: '1rem' }}>Fails when syntax changes slightly.</p>
                <pre className="text-xs bg-black p-4 rounded border border-white/10 text-white/80 overflow-x-auto" style={{ backgroundColor: 'black', padding: '1rem', border: '1px solid rgba(255,255,255,0.1)' }}>
                  <code>
{`// Payload 1 (Blocked by WAF)
' OR 1=1--

// Payload 2 (Bypasses WAF)
' /*!50000OR*/ 2=2--`}
                  </code>
                </pre>
              </div>
              <div className="bg-white/[0.02] border border-[#17A589]/30 p-6 rounded-sm relative overflow-hidden" style={{ padding: '1.5rem', border: '1px solid rgba(23,165,137,0.3)' }}>
                <h3 className="text-[#17A589] font-mono text-sm mb-4" style={{ color: '#17A589', marginBottom: '1rem', fontFamily: 'monospace' }}>INVARIANT: Property Proof</h3>
                <p className="text-white/60 text-sm mb-4" style={{ color: 'rgba(255,255,255,0.6)', marginBottom: '1rem' }}>Proves tautology property. Catches everything.</p>
                <pre className="text-xs bg-black p-4 rounded border border-[#17A589]/20 text-[#17A589] overflow-x-auto" style={{ backgroundColor: 'black', padding: '1rem', border: '1px solid rgba(23,165,137,0.2)', color: '#17A589' }}>
                  <code>
{`// Decomposed Property:
// string_termination + tautology_condition
// BOTH Payloads Blocked. 
// Infinite variants covered.`}
                  </code>
                </pre>
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      <hr className="divider-glow" />
"""

home_content = home_content.replace(
    '<section className="home-product home-snap" aria-labelledby="invariant-heading" data-signal="defense">',
    waf_section + '\n      <section className="home-product home-snap" aria-labelledby="invariant-heading" data-signal="defense">'
)

# Update SEO description and CTAs in Home
home_content = re.sub(r'description="[^"]*"', 'description="Santh Security Intelligence: Research, CVE analysis, and our INVARIANT engine — an edge-native RASP stopping attacks with structural proofs, zero configuration."', home_content, count=1)
home_content = home_content.replace('Explore Detection Classes →', 'Start Free')

with open(home_path, 'w') as f:
    f.write(home_content)


# 3. Update Collective.tsx (and fix BUG-001)
collective_path = os.path.join(base_dir, 'pages/Collective.tsx')
with open(collective_path, 'r') as f:
    coll_content = f.read()

if 'getSiteStats' not in coll_content:
    coll_content = coll_content.replace(
        "import { sanitizeJsonLdObject, safeJsonStringify } from '../utils/sanitize'",
        "import { sanitizeJsonLdObject, safeJsonStringify } from '../utils/sanitize'\nimport { getSiteStats } from '../utils/stats'"
    )

coll_content = coll_content.replace("export default function Collective() {\n    return (", "export default function Collective() {\n    const stats = getSiteStats();\n    return (")

coll_content = re.sub(
    r'description="[^"]*"',
    'description="Deploy INVARIANT: Edge-native RASP with zero configuration. No agents required. Minimal false positive rate. Real-time collective threat intelligence mapped to MITRE ATT&CK."',
    coll_content,
    count=1
)

coll_content = coll_content.replace('Deploy INVARIANT →', 'Start Free')
coll_content = coll_content.replace('Learn More →', 'Get Early Access')

with open(collective_path, 'w') as f:
    f.write(coll_content)


# 4. Update Community.tsx, Principles.tsx, Train.tsx Meta Descriptions and CTAs
def update_page(filename, new_desc):
    path = os.path.join(base_dir, f'pages/{filename}')
    if os.path.exists(path):
        with open(path, 'r') as f:
            content = f.read()
        
        content = re.sub(r'description="[^"]*"', f'description="{new_desc}"', content, count=1)
        content = content.replace('Learn More →', 'Get Early Access')
        
        with open(path, 'w') as f:
            f.write(content)

update_page('Community.tsx', 'Join Santh Community: an independent network of security researchers driving collective threat intelligence. Edge-native security collaboration, zero configuration needed.')
update_page('Principles.tsx', 'Santh Principles: Our commitment to transparent security research, minimal false positive rate, and structural property proofs over basic signature matching.')
update_page('Train.tsx', 'VARIANT Training: Master runtime application security and MITRE ATT&CK techniques on real systems. No agents required, edge-native security education.')

print("Patch applied successfully.")
