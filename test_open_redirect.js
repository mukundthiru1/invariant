const { deepDecode } = require('./packages/engine/dist/src/classes/encoding.js');
const input = '?redirect=//evil.com';
const d = deepDecode(input);
console.log(d);
