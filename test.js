console.log(/(?:file|gopher|dict|ldap|tftp|ftp|jar|netdoc|phar|expect|data|php|zip):\/\//i.test('data://text/plain;base64,SGVsbG8='))
console.log(/(?:file|gopher|dict|ldap|tftp|ftp|jar|netdoc|phar|expect|data|php|zip):\/\//i.test('php://filter/read=convert.base64-encode/resource=/etc/passwd'))
