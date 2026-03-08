const fs = require('fs');
const path = 'packages/engine/src/tokenizers/html-tokenizer.ts';
let code = fs.readFileSync(path, 'utf8');

// Fix TypeScript error by removing the unreachable COMMENT case
code = code.replace(/case 'COMMENT': \{[\s\S]*?break;\n\s*\}/, '');

// Add getXssProperties export
const newExport = `
export function getXssProperties(input: string): Array<{ type: 'tag_inject' | 'event_handler' | 'protocol_handler' | 'attr_escape', confidence: number, evidence: string }> {
    const tokenizer = new HtmlTokenizer();
    const stream = tokenizer.tokenize(input);
    const tokens = stream.all();
    const props: Array<{ type: 'tag_inject' | 'event_handler' | 'protocol_handler' | 'attr_escape', confidence: number, evidence: string }> = [];

    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i];
        
        if (tok.type === 'TAG_NAME' && ['script', 'iframe', 'object'].includes(tok.value.toLowerCase())) {
            props.push({ type: 'tag_inject', confidence: 0.95, evidence: tok.value });
        }
        
        if (tok.type === 'ATTR_NAME' && tok.value.toLowerCase().startsWith('on')) {
            props.push({ type: 'event_handler', confidence: 0.90, evidence: tok.value });
        }

        if (tok.type === 'ATTR_VALUE') {
            const val = tok.value.trim().toLowerCase();
            if (val.startsWith('javascript:') || val.startsWith('vbscript:') || (val.startsWith('data:') && val.includes('text/html'))) {
                props.push({ type: 'protocol_handler', confidence: 0.95, evidence: tok.value });
            }
        }
        
        if (tok.type === 'TEXT') {
            if (tok.value.includes('">') || tok.value.includes("'>") || tok.value.includes('" >') || tok.value.includes("' >") || tok.value.includes('"/>') || tok.value.includes("'/>")) {
                props.push({ type: 'attr_escape', confidence: 0.80, evidence: tok.value.trim() });
            }
        }
    }
    return props;
}
`;

code = code + newExport;
fs.writeFileSync(path, code);
