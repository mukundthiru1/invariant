const fs = require('fs');

const block = `
    detectL2: (input: string) => {
        const decoded = typeof deepDecode === 'function' ? deepDecode(input) : input;
        if (decoded.length > 5) return { confidence: 0.95, explanation: 'L2 structural evaluator confirmed anomalous pattern layout', isNovelVariant: false };
        return null;
    },`;

const moduleDetectL2 = `,\n    detectL2: (input: string) => {\n        const decoded = typeof deepDecode === 'function' ? deepDecode(input) : input;\n        if (decoded.length > 5) return { confidence: 0.95, explanation: 'L2 structural evaluator confirmed anomalous pattern layout', isNovelVariant: false };\n        return null;\n    },`;

function fixFile(file) {
    let content = fs.readFileSync(file, 'utf8');

    // infra-attacks.ts
    content = content.replace("            'run: echo ${{ github.event.issue.title }" + block + "}',",
                              "            'run: echo ${{ github.event.issue.title }}',");
    content = content.replace("            'rules: [{ apiGroups:[\"*\"], resources:[\"*\"], verbs:[*] }" + block + "]',",
                              "            'rules: [{ apiGroups:[\"*\"], resources:[\"*\"], verbs:[*] }]',");
    content = content.replace("            '${file(\"/etc/passwd\")}" + block + "',",
                              "            '${file(\"/etc/passwd\")}',");
    content = content.replace("            'POST /containers/create?name=pwn {\"HostConfig\":{\"Privileged\":true}" + block + "}',",
                              "            'POST /containers/create?name=pwn {\"HostConfig\":{\"Privileged\":true}}',");
    
    // business-logic.ts
    content = content.replace("            '{\"isAdmin\":true,\"role\":\"admin\",\"__proto__\":{\"admin\":true}" + block + "}',",
                              "            '{\"isAdmin\":true,\"role\":\"admin\",\"__proto__\":{\"admin\":true}}',");
    content = content.replace("            '{\"price\":0.001,\"total\":-99.99}" + block + "',",
                              "            '{\"price\":0.001,\"total\":-99.99}',");
    content = content.replace("            'POST /api/bulk-delete {\"ids\":[1,2,3,4,5]}" + block + "',",
                              "            'POST /api/bulk-delete {\"ids\":[1,2,3,4,5]}',");
    content = content.replace("            '{\"type\":\"__proto__\",\"payload\":{\"admin\":true}" + block + "}',",
                              "            '{\"type\":\"__proto__\",\"payload\":{\"admin\":true}}',");

    // Module level detectL2 (trailing)
    content = content.replace(moduleDetectL2, "");

    fs.writeFileSync(file, content);
}

fixFile('packages/engine/src/classes/injection/infra-attacks.ts');
fixFile('packages/engine/src/classes/injection/business-logic.ts');
console.log('Fixed');
