import os
import glob

def patch_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    old_string = "        return v.slice(0, count)"
    new_string = """        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r"""

    if old_string in content:
        content = content.replace(old_string, new_string)
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Patched {filepath}")

for root, _, files in os.walk("packages/engine/src/classes"):
    for file in files:
        if file.endswith(".ts"):
            patch_file(os.path.join(root, file))
