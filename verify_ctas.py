import os
import re

base_dir = '/home/mukund-thiru/Santh/hub/src/'

for page in ['Home.tsx', 'Collective.tsx']:
    path = os.path.join(base_dir, f'pages/{page}')
    if os.path.exists(path):
        with open(path, 'r') as f:
            content = f.read()
        
        matches = re.findall(r'<a[^>]*>(.*?)</a>', content, flags=re.DOTALL)
        print(f"--- {page} CTAs ---")
        for m in matches:
            text = re.sub(r'<[^>]+>', '', m).strip()
            print(repr(text))
