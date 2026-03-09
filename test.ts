import { deepDecode } from './packages/engine/src/encoding.js'
console.log(deepDecode('data://text/plain;base64,SGVsbG8='))
console.log(deepDecode('php://filter/read=convert.base64-encode/resource=/etc/passwd'))
