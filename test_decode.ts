import { deepDecode } from './packages/engine/src/classes/encoding.ts'
const urlSafeB64 = Buffer.from('<script>alert(1);</script>').toString('base64').replace(/\+/g, '-').replace(/\//g, '_')
console.log("Original B64:", urlSafeB64)
console.log("Decoded:", deepDecode(urlSafeB64))
