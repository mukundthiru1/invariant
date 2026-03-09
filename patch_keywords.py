import os
import re

base_dir = '/home/mukund-thiru/Santh/hub/src/'

# In Collective.tsx:
path = os.path.join(base_dir, 'pages/Collective.tsx')
with open(path, 'r') as f:
    content = f.read()

# Change 'Collective intelligence contribution' to 'Collective threat intelligence'
content = content.replace('Collective intelligence contribution', 'Collective threat intelligence')

# Ensure 'false positive rate' is clearly stated, maybe under Invariant Engine section or WAF alternative
if 'false positive rate' not in content.lower():
    content = content.replace(
        'Detects the fundamental vulnerability property, not specific payloads.',
        'Detects the fundamental vulnerability property, not specific payloads. Zero configuration with a near-zero false positive rate.'
    )
if 'no agents required' not in content.lower():
    content = content.replace(
        'Deploy in 5 minutes',
        'Deploy in 5 minutes. No agents required'
    )
if 'edge-native' not in content.lower():
    content = content.replace(
        'Deployed at the edge.',
        'Edge-native deployment.'
    )

with open(path, 'w') as f:
    f.write(content)

print("Keywords patched in Collective.tsx")
