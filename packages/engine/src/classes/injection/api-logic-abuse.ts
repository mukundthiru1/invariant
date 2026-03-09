import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

const SENSITIVE_ASSIGNMENT_RE = /"(?:role|isAdmin|admin|permissions|balance|creditLimit)"\s*:\s*(?:true|"admin"|\[[^\]]+\]|\d{3,})/i
const WRITE_METHOD_RE = /^(?:POST|PUT|PATCH)\s+/im

const BFLA_ADMIN_PATH_RE = /\/api\/(?:v\d+\/)?(?:admin|internal|management|billing\/refund|users\/\d+\/role)/i
const BFLA_WEAK_AUTH_RE = /Authorization:\s*Bearer\s*(?:user|guest|basic|public|test)[-_a-z0-9]*/i
const BFLA_MISSING_AUTH_RE = /(?:^|\r?\n)(?:GET|POST|PUT|PATCH|DELETE)\s+\/api\/(?:v\d+\/)?(?:admin|internal|management)[^\r\n]*\r?\n(?![\s\S]{0,200}Authorization:)/i

const VERSION_DOWNGRADE_RE = /(?:[?&](?:api[-_]?version|version|v)\s*=\s*(?:1|v1|0\.9)\b|Accept:\s*application\/vnd\.[^;\r\n]+(?:\.v1|\+v1)\b|X-Api-Version:\s*(?:1|v1)\b|downgrade(?:d)?\s+to\s+v?1\b)/i
const LEGACY_OVERRIDE_RE = /(?:x-api-version-override|x-version-override)\s*:\s*(?:1|v1)\b/i

export const apiMassAssignment: InvariantClassModule = {
    id: 'api_mass_assignment',
    description: 'Detects mass-assignment attempts that set sensitive model fields through public API payloads',
    category: 'injection',
    severity: 'high',
    mitre: ['T1190'],
    cwe: 'CWE-915',
    knownPayloads: [
        'PATCH /api/users/42 HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"name":"alice","role":"admin"}',
        'PUT /api/account/42 HTTP/1.1\r\n\r\n{"isAdmin":true}',
        'POST /api/users HTTP/1.1\r\n\r\n{"email":"a@b.com","permissions":["*"]}',
        '{"admin":true,"creditLimit":1000000}',
    ],
    knownBenign: [
        'PATCH /api/users/42 HTTP/1.1\r\n\r\n{"name":"alice"}',
        'POST /api/users HTTP/1.1\r\n\r\n{"email":"a@b.com","password":"safe"}',
        '{"theme":"light","timezone":"UTC"}',
        'GET /api/users/42 HTTP/1.1',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const hasSensitiveAssignment = SENSITIVE_ASSIGNMENT_RE.test(d)
        const isWriteContext = WRITE_METHOD_RE.test(d) || d.trim().startsWith('{')
        return hasSensitiveAssignment && isWriteContext
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'PATCH /api/users/42 HTTP/1.1\r\n\r\n{"role":"admin"}',
            'PUT /api/account/42 HTTP/1.1\r\n\r\n{"isAdmin":true}',
            'POST /api/users HTTP/1.1\r\n\r\n{"permissions":["*"]}',
            '{"admin":true,"balance":999999}',
        ]
        return variants.slice(0, count)
    },
}

export const apiBfla: InvariantClassModule = {
    id: 'api_bfla',
    description: 'Detects Broken Function Level Authorization indicators where non-privileged callers target privileged API functions',
    category: 'injection',
    severity: 'high',
    mitre: ['T1190'],
    cwe: 'CWE-285',
    knownPayloads: [
        'POST /api/admin/users/1/disable HTTP/1.1\r\nAuthorization: Bearer user-token\r\n',
        'DELETE /api/internal/config HTTP/1.1\r\nAuthorization: Bearer guest-session\r\n',
        'PUT /api/v1/management/feature-flags HTTP/1.1\r\nAuthorization: Bearer public-client\r\n',
        'GET /api/admin/audit HTTP/1.1\r\n',
    ],
    knownBenign: [
        'GET /api/users/me HTTP/1.1\r\nAuthorization: Bearer user-token\r\n',
        'POST /api/orders HTTP/1.1\r\nAuthorization: Bearer user-token\r\n',
        'GET /api/admin/audit HTTP/1.1\r\nAuthorization: Bearer admin-token\r\n',
        'GET /health HTTP/1.1',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        if (!BFLA_ADMIN_PATH_RE.test(d)) return false
        return BFLA_WEAK_AUTH_RE.test(d) || BFLA_MISSING_AUTH_RE.test(d)
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'POST /api/admin/users/1/disable HTTP/1.1\r\nAuthorization: Bearer user-token\r\n',
            'DELETE /api/internal/config HTTP/1.1\r\nAuthorization: Bearer guest-session\r\n',
            'PUT /api/management/roles HTTP/1.1\r\nAuthorization: Bearer public-client\r\n',
            'GET /api/admin/audit HTTP/1.1\r\n',
        ]
        return variants.slice(0, count)
    },
}

export const apiVersionDowngrade: InvariantClassModule = {
    id: 'api_version_downgrade',
    description: 'Detects API version downgrade attempts that force legacy endpoints or weaker compatibility paths',
    category: 'injection',
    severity: 'medium',
    mitre: ['T1190'],
    cwe: 'CWE-444',
    knownPayloads: [
        'GET /api/users?api_version=1 HTTP/1.1',
        'GET /api/resource HTTP/1.1\r\nX-Api-Version: 1\r\n',
        'GET /api/orders HTTP/1.1\r\nAccept: application/vnd.company.orders.v1+json\r\n',
        'POST /api/payments HTTP/1.1\r\nX-Version-Override: v1\r\n',
    ],
    knownBenign: [
        'GET /api/users?api_version=2 HTTP/1.1',
        'GET /api/resource HTTP/1.1\r\nX-Api-Version: 3\r\n',
        'GET /api/orders HTTP/1.1\r\nAccept: application/json\r\n',
        'POST /api/payments HTTP/1.1\r\nX-Version-Override: v3\r\n',
    ],
    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return VERSION_DOWNGRADE_RE.test(d) || LEGACY_OVERRIDE_RE.test(d)
    },
    generateVariants: (count: number): string[] => {
        const variants = [
            'GET /api/users?api_version=1 HTTP/1.1',
            'GET /api/resource HTTP/1.1\r\nX-Api-Version: 1\r\n',
            'GET /api/orders HTTP/1.1\r\nAccept: application/vnd.company.orders.v1+json\r\n',
            'POST /api/payments HTTP/1.1\r\nX-Version-Override: v1\r\n',
        ]
        return variants.slice(0, count)
    },
}
