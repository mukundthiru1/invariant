const fs = require('fs');
let content = fs.readFileSync('packages/engine/src/classes/injection/misc.ts', 'utf8');
content = content.replace(/detect: \(input: string\): boolean => \{[\s\S]*?\},/m, `detect: (input: string): boolean => {
        const hasBreak = /(?:\\\\u0022|["'])\\s*,\\s*(?:\\\\u0022|["'])|\\}\\s*,\\s*\\{/.test(input);
        if (!hasBreak) return false;
        return /(?:\\\\u0022|["'])?(?:isadmin|admin|injected|role|permissions)(?:\\\\u0022|["'])?\\s*:\\s*(?:true|false|null|\\d+|(?:\\\\u0022|["']).+?(?:\\\\u0022|["']))/i.test(input);
    },`);
fs.writeFileSync('packages/engine/src/classes/injection/misc.ts', content);
