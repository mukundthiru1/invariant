const fs = require('fs');
const path = require('path');

const rootPath = path.resolve(__dirname, '..'); // /home/mukund-thiru/Santh/invariant/packages

// 1. agent/src/crypto/storage.ts
const storagePath = path.join(rootPath, 'agent/src/crypto/storage.ts');
if (fs.existsSync(storagePath)) {
    let content = fs.readFileSync(storagePath, 'utf8');
    content = content.replace(
        "encode(plaintext),",
        "encode(plaintext) as any,"
    );
    fs.writeFileSync(storagePath, content, 'utf8');
}

// 2. engine/src/evaluators/cmd-injection-evaluator.ts
const cmdInjPath = path.join(rootPath, 'engine/src/evaluators/cmd-injection-evaluator.ts');
if (fs.existsSync(cmdInjPath)) {
    let content = fs.readFileSync(cmdInjPath, 'utf8');
    content = content.replace(
        "const allTokens = (stream as any).tokens",
        "const allTokens = (stream as any).tokens as any[]"
    );
    fs.writeFileSync(cmdInjPath, content, 'utf8');
}

console.log('Fixed additional errors');
