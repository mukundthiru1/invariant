const regexes = [
    /\{\{#?with\s+.*constructor|lookup\s+\.\s+'constructor'/i,
    /\{\{\{.*\}\}\}/,
    /\{\{>\s*.*\}\}/,
    /\{\{[^}]*(?:\.Env|call\s|printf|println|\.OS|exec\.Command)/i
];

const payloads = [
    "{{#with (constructor.constructor 'alert(1)')()}}",
    "{{lookup . 'constructor'}}",
    "{{{raw_html}}}",
    "{{> partial}}",
    "{{.Env}}",
    "{{call .FieldName}}",
    "{{println}}",
    "{{exec.Command}}"
];

const benign = [
    "{{greeting}}",
    "{{name}}",
    "Hello {{world}}"
];

payloads.forEach(p => {
    let matched = regexes.some(r => r.test(p));
    console.log(`Payload: ${p} -> ${matched}`);
});

benign.forEach(p => {
    let matched = regexes.some(r => r.test(p));
    console.log(`Benign: ${p} -> ${matched}`);
});
