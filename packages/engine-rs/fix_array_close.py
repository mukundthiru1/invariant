with open('src/compliance.rs', 'r') as f:
    text = f.read()

import re
text = re.sub(r'// const ALL_CLASSES.*?\];', '// const ALL_CLASSES', text, flags=re.DOTALL)

with open('src/compliance.rs', 'w') as f:
    f.write(text)
