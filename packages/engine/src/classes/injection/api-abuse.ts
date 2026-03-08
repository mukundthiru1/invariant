/**
 * API Abuse Invariant Classes
 *
 * Detects structural attacks on API logic:
 *   - bola_idor: Broken Object Level Authorization (IDOR)
 *   - api_mass_enum: Mass enumeration via sequential/predictable IDs
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'
import { l2BolaIdor, l2ApiMassEnum } from '../../evaluators/l2-adapters.js'


// ── 1) bola_idor ────────────────────────────────────────────────

export const bolaIdor: InvariantClassModule = {
    id: 'bola_idor',
    description: 'Broken Object Level Authorization (IDOR) — accessing resources by manipulating object IDs in API paths/params with authorization bypass indicators',
    category: 'auth',
    severity: 'high',
    calibration: { baseConfidence: 0.80 },

    mitre: ['T1078'],
    cwe: 'CWE-639',

    knownPayloads: [
        '/api/users/2/profile with Authorization: Bearer <token_for_user_1>',
        '/api/orders/99999?userId=1 (sequential ID probe)',
        '/api/v1/documents/../../admin/config',
    ],

    knownBenign: [
        '/api/users/me/profile',
        '/api/users/current',
        '/api/orders?page=2&limit=10',
    ],

    detectL2: l2BolaIdor,

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        // Must be an API path
        if (!/\/api\//i.test(d)) return false

        // Pattern 1: API path with numeric ID + authorization context mismatch
        const hasNumericId = /\/api\/[a-z]+\/\d+/i.test(d)
        if (hasNumericId) {
            const authMismatch = /(?:token[_\s]*for[_\s]*user|bearer\s+<|as\s+user\s+\d|impersonat|other[_\s]*user)/i.test(d)
            const sequentialProbe = /(?:sequential|probe|enumerate|brute|scan|fuzz)/i.test(d)
            if (authMismatch || sequentialProbe) return true
        }

        // Pattern 2: Path traversal in API path to access admin/config resources
        if (/\/api\/.*\.\.\//i.test(d) && /(?:admin|config|internal|private|secret)/i.test(d)) return true

        // Pattern 3: Numeric ID with different-user token
        if (/\/\d+\/\.\./i.test(d)) return true

        return false
    },

    generateVariants: (count: number): string[] => {
        const v = [
            '/api/users/2/profile with Authorization: Bearer <token_for_user_1>',
            '/api/orders/99999?userId=1 (sequential ID probe)',
            '/api/v1/documents/../../admin/config',
        ]
        return v.slice(0, count)
    },
}


// ── 2) api_mass_enum ────────────────────────────────────────────

export const apiMassEnum: InvariantClassModule = {
    id: 'api_mass_enum',
    description: 'API mass enumeration — sequential ID iteration, bulk object access, or wildcard/range queries to exfiltrate all records',
    category: 'injection',
    severity: 'medium',
    calibration: { baseConfidence: 0.78 },

    mitre: ['T1087'],
    cwe: 'CWE-200',

    knownPayloads: [
        'GET /api/users/1 GET /api/users/2 GET /api/users/3 GET /api/users/4 GET /api/users/5',
        '/api/invoices?id[gte]=1&id[lte]=99999',
        '/api/v1/records?filter=id>0&limit=999999',
    ],

    knownBenign: [
        '/api/users?page=1&limit=20',
        '/api/orders?status=pending',
        '/api/products?category=electronics',
    ],

    detectL2: l2ApiMassEnum,

    detect: (input: string): boolean => {
        const d = deepDecode(input)

        // Pattern 1: Multiple sequential API calls with incrementing IDs
        const apiCalls = d.match(/\/api\/\w+\/(\d+)/gi) ?? []
        if (apiCalls.length >= 4) {
            const ids = apiCalls.map(c => parseInt(c.replace(/.*\//, ''), 10)).filter(n => !isNaN(n))
            if (ids.length >= 4) {
                // Check for sequential pattern
                let sequential = 0
                for (let i = 1; i < ids.length; i++) {
                    if (ids[i] === ids[i - 1] + 1) sequential++
                }
                if (sequential >= 3) return true
            }
        }

        // Pattern 2: Range/bulk query operators with wide range
        const rangeOps = d.match(/(?:id|_id)\s*\[?\s*(?:gte|gt)\s*\]?\s*[=:]\s*(\d+)/i)
        const rangeEnd = d.match(/(?:id|_id)\s*\[?\s*(?:lte|lt)\s*\]?\s*[=:]\s*(\d+)/i)
        if (rangeOps && rangeEnd) {
            const start = parseInt(rangeOps[1], 10)
            const end = parseInt(rangeEnd[1], 10)
            if (end - start > 100) return true
        }

        // Pattern 3: Absurdly large limit
        const largeLimit = /\blimit\s*[=:]\s*(\d+)/i
        const limitMatch = d.match(largeLimit)
        if (limitMatch && parseInt(limitMatch[1], 10) > 50000) return true

        // Pattern 4: filter=id>0 (get everything)
        if (/\bfilter\s*=\s*(?:id|_id)\s*[>]=?\s*0\b/i.test(d)) return true

        return false
    },

    generateVariants: (count: number): string[] => {
        const v = [
            'GET /api/users/1 GET /api/users/2 GET /api/users/3 GET /api/users/4 GET /api/users/5',
            '/api/invoices?id[gte]=1&id[lte]=99999',
            '/api/v1/records?filter=id>0&limit=999999',
        ]
        return v.slice(0, count)
    },
}
