import os

base_dir = '/home/mukund-thiru/Santh/hub/src/'
files = ['pages/Community.tsx', 'pages/Principles.tsx', 'pages/Train.tsx', 'pages/Collective.tsx']

for f in files:
    path = os.path.join(base_dir, f)
    with open(path, 'r') as file:
        content = file.read()
        print(f"--- {f} ---")
        print(content)
        print("-" * 40)
