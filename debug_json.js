const input = '{"name": "Alice"}';
const hasBreak = /(?:\\u0022|["'])\s*,\s*(?:\\u0022|["'])/.test(input) || /}\s*,\s*{/.test(input);
const result = hasBreak && /(?:\\u0022|["'])?(?:isadmin|admin|injected|role|permissions)(?:\\u0022|["'])?\s*:\s*(?:true|false|null|\d+|(?:\\u0022|["']).+?(?:\\u0022|["']))/i.test(input);
console.log({ hasBreak, result });
