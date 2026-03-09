import { deepDecode } from './packages/engine/src/classes/encoding.js';
const input = '?redirect=//evil.com';
const d = deepDecode(input);
const match1 = /\/\/[^/]+\.[^/]+/.test(d);
const match2 = /(?:redirect|url|next|return|goto|dest|target|rurl|forward)\s*[=:]/i.test(d);
console.log({ d, match1, match2 });
