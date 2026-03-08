/**
 * Mass Assignment Evaluator — structural L2 analysis.
 */

export interface MassAssignmentDetection {
    type: 'privilege_injection' | 'suspicious_key_combo' | 'nested_privilege_injection'
    detail: string
    confidence: number
    keys: string[]
    evidence: string
    l1: boolean
    l2: boolean
}

const PRIVILEGE_KEYS = new Set([
    'role', 'user.role', 'account.role',
    'isadmin', 'is_admin', 'isstaff', 'is_staff',
    'isverified', 'is_verified', 'permissions', 'permission',
    'accesslevel', 'access_level', 'usertype', 'user_type',
    'accounttype', 'account_type',
])

const PROFILE_KEYS = new Set([
    'name', 'email', 'username', 'phone', 'bio',
    'avatar', 'password', 'first_name', 'last_name', 'title',
])

const ELEVATED_VALUES = new Set(['admin', 'superadmin', 'root', 'superuser', 'owner', 'true', '1', 'staff'])
const SAFE_ROLE_VALUES = new Set(['user', 'member', 'guest', 'false', '0'])

function normalizeKey(raw: string): string {
    return raw.trim().replace(/[\s"'`]/g, '').toLowerCase()
}

function normalizeValue(raw: unknown): string {
    if (typeof raw === 'boolean') return raw ? 'true' : 'false'
    if (typeof raw === 'number') return String(raw)
    if (typeof raw !== 'string') return ''
    return raw.trim().replace(/^['"]|['"]$/g, '').toLowerCase()
}

function deepDecode(input: string): string {
    let decoded = input
    for (let i = 0; i < 3; i++) {
        let next = decoded
        try { next = decodeURIComponent(next) } catch { /* noop */ }
        if (next === decoded) break
        decoded = next
    }
    return decoded
}

function flattenObject(obj: unknown, prefix = ''): Array<{ key: string; value: unknown }> {
    if (typeof obj !== 'object' || obj === null) return []
    if (Array.isArray(obj)) {
        const out: Array<{ key: string; value: unknown }> = []
        obj.forEach((item, idx) => out.push(...flattenObject(item, `${prefix}[${idx}]`)))
        return out
    }
    const out: Array<{ key: string; value: unknown }> = []
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
        const key = prefix ? `${prefix}.${k}` : k
        out.push({ key, value: v })
        if (typeof v === 'object' && v !== null) {
            out.push(...flattenObject(v, key))
        }
    }
    return out
}

function parseQueryLike(decoded: string): Array<{ key: string; value: string }> {
    const entries: Array<{ key: string; value: string }> = []
    for (const part of decoded.split('&')) {
        const [k, v = ''] = part.split('=')
        if (!k) continue
        entries.push({ key: k, value: v })
    }
    return entries
}

function canonicalPrivilegeKey(key: string): string | null {
    const norm = normalizeKey(key)
    const noBrackets = norm.replace(/\]/g, '').replace(/\[/g, '.').replace(/\.+/g, '.')
    const compact = noBrackets.replace(/[.\-_]/g, '')
    if (PRIVILEGE_KEYS.has(noBrackets) || PRIVILEGE_KEYS.has(compact)) return noBrackets
    return null
}

function isPrivilegeEscalationValue(key: string, value: string): boolean {
    if (!value) return false
    if (key.includes('role') || key.includes('type') || key.includes('permission') || key.includes('access')) {
        return ELEVATED_VALUES.has(value)
    }
    if (key.includes('isadmin') || key.includes('is_staff') || key.includes('isstaff') || key.includes('is_verified') || key.includes('isverified')) {
        return value === 'true' || value === '1'
    }
    return ELEVATED_VALUES.has(value)
}

function detectFromEntries(entries: Array<{ key: string; value: unknown }>): MassAssignmentDetection[] {
    const detections: MassAssignmentDetection[] = []
    const privilegeEntries: Array<{ key: string; value: string }> = []
    const profileTouched = new Set<string>()

    for (const entry of entries) {
        const key = normalizeKey(entry.key)
        const value = normalizeValue(entry.value)
        const privilegeKey = canonicalPrivilegeKey(key)
        const rootKey = key.split('.')[0]
        if (PROFILE_KEYS.has(rootKey)) profileTouched.add(rootKey)
        if (!privilegeKey) continue
        if (SAFE_ROLE_VALUES.has(value)) continue
        if (isPrivilegeEscalationValue(privilegeKey, value)) {
            privilegeEntries.push({ key: privilegeKey, value })
        }
    }

    if (privilegeEntries.length === 0) return detections

    const keys = [...new Set(privilegeEntries.map(e => e.key))]
    const evidence = privilegeEntries.map(e => `${e.key}=${e.value}`).join('&')
    const hasCombo = keys.length >= 2 || ['role', 'isadmin', 'is_admin', 'isstaff', 'is_staff'].every(k => keys.some(x => x.includes(k)))
    const hasProfileContext = profileTouched.size > 0

    if (hasCombo) {
        detections.push({
            type: 'suspicious_key_combo',
            detail: `Suspicious privilege key combination detected (${keys.join(', ')})`,
            confidence: 0.95,
            keys,
            evidence,
            l1: false,
            l2: true,
        })
    } else if (hasProfileContext) {
        detections.push({
            type: keys.some(k => k.includes('.')) ? 'nested_privilege_injection' : 'privilege_injection',
            detail: `Privilege field injection combined with normal profile update (${keys.join(', ')})`,
            confidence: 0.9,
            keys,
            evidence,
            l1: false,
            l2: true,
        })
    } else {
        detections.push({
            type: keys.some(k => k.includes('.')) ? 'nested_privilege_injection' : 'privilege_injection',
            detail: `Direct privilege field assignment detected (${keys.join(', ')})`,
            confidence: 0.87,
            keys,
            evidence,
            l1: false,
            l2: true,
        })
    }

    return detections
}

function detectFromJson(decoded: string): MassAssignmentDetection[] {
    if (!decoded.includes('{')) return []
    const candidates: string[] = []
    const trimmed = decoded.trim()
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) candidates.push(trimmed)
    const first = decoded.indexOf('{')
    const last = decoded.lastIndexOf('}')
    if (first >= 0 && last > first) candidates.push(decoded.slice(first, last + 1))

    for (const raw of candidates) {
        try {
            const obj = JSON.parse(raw)
            const entries = flattenObject(obj)
            return detectFromEntries(entries)
        } catch {
            // continue
        }
    }
    return []
}

export function detectMassAssignment(input: string): MassAssignmentDetection[] {
    if (input.length < 6) return []
    const decoded = deepDecode(input)

    const detections = [
        ...detectFromJson(decoded),
        ...detectFromEntries(parseQueryLike(decoded)),
    ]

    const deduped = new Map<string, MassAssignmentDetection>()
    for (const detection of detections) {
        const key = `${detection.type}:${detection.evidence}`
        const existing = deduped.get(key)
        if (!existing || detection.confidence > existing.confidence) deduped.set(key, detection)
    }

    return [...deduped.values()]
}
