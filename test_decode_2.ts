import { deepDecode } from './packages/engine/src/classes/encoding.ts'
const urlSafeB64 = 'PHNjcmlwdD5hbGVydCgxKTs8L3NjcmlwdD4-'
console.log("Original B64:", urlSafeB64)
console.log("Decoded:", deepDecode(urlSafeB64))
