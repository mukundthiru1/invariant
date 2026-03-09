import { describe, expect, it } from 'vitest'
import { InvariantEngine } from './invariant-engine.js'
import type { InvariantClassModule, InvariantClass, AttackCategory, Severity } from './classes/types.js'
import { deepDecode } from './classes/encoding.js'

type JsonRuleType = 'contains_any' | 'regex' | 'starts_with'

interface JsonRule {
    id?: string
    type?: JsonRuleType
    value?: unknown
    category?: AttackCategory
    severity?: Severity
}

interface RegistryInternals {
    modules: Map<InvariantClass, InvariantClassModule>
    byCategory: Map<AttackCategory, InvariantClassModule[]>
    bySeverity: Map<Severity, InvariantClassModule[]>
    calibrationOverrides: Map<InvariantClass, unknown>
}

function removeClass(registry: object, classId: InvariantClass): void {
    const internals = registry as RegistryInternals
    const module = internals.modules.get(classId)
    if (!module) return

    internals.modules.delete(classId)
    internals.calibrationOverrides.delete(classId)

    const category = internals.byCategory.get(module.category)
    if (category) {
        const next = category.filter((m) => m.id !== classId)
        if (next.length === 0) internals.byCategory.delete(module.category)
        else internals.byCategory.set(module.category, next)
    }

    const severity = internals.bySeverity.get(module.severity)
    if (severity) {
        const next = severity.filter((m) => m.id !== classId)
        if (next.length === 0) internals.bySeverity.delete(module.severity)
        else internals.bySeverity.set(module.severity, next)
    }
}

function buildDetector(type: JsonRuleType, value: unknown): (input: string) => boolean {
    switch (type) {
        case 'contains_any': {
            const needles = Array.isArray(value) ? value : [value]
            const terms = needles.filter((v): v is string => typeof v === 'string' && v.length > 0)
            if (terms.length === 0) throw new Error('[RuleLoader] contains_any requires a non-empty string or string[] value')
            return (input: string) => {
                const decoded = deepDecode(input).toLowerCase()
                return terms.some((t) => decoded.includes(t.toLowerCase()))
            }
        }
        case 'regex': {
            if (typeof value !== 'string' || value.length === 0) {
                throw new Error('[RuleLoader] regex requires a non-empty string pattern')
            }
            let re: RegExp
            try {
                re = new RegExp(value, 'i')
            } catch {
                throw new Error(`[RuleLoader] invalid regex pattern: ${value}`)
            }
            return (input: string) => re.test(deepDecode(input))
        }
        case 'starts_with': {
            if (typeof value !== 'string' || value.length === 0) {
                throw new Error('[RuleLoader] starts_with requires a non-empty string value')
            }
            return (input: string) => deepDecode(input).toLowerCase().startsWith(value.toLowerCase())
        }
        default:
            throw new Error(`[RuleLoader] unsupported rule type: ${String(type)}`)
    }
}

function loadRuleFromJson(engine: InvariantEngine, rule: JsonRule): void {
    if (!rule.id) throw new Error('[RuleLoader] missing required field: id')
    if (!rule.type) throw new Error('[RuleLoader] missing required field: type')
    if (!rule.category) throw new Error('[RuleLoader] missing required field: category')
    if (!rule.severity) throw new Error('[RuleLoader] missing required field: severity')
    if (rule.value === undefined) throw new Error('[RuleLoader] missing required field: value')

    const classId = rule.id as InvariantClass
    if (!engine.classes.includes(classId)) {
        throw new Error(`[RuleLoader] unsupported class id for this engine: ${rule.id}`)
    }

    const detect = buildDetector(rule.type, rule.value)
    const knownPayload = Array.isArray(rule.value)
        ? String(rule.value[0] ?? '')
        : String(rule.value)

    const module: InvariantClassModule = {
        id: classId,
        description: `JSON rule for ${rule.id}`,
        category: rule.category,
        severity: rule.severity,
        detect,
        generateVariants: (_count: number) => [knownPayload],
        knownPayloads: [knownPayload],
        knownBenign: ['normal harmless request'],
    }

    removeClass(engine.registry as unknown as object, classId)
    engine.registry.register(module)
}

describe('Rule format JSON loading', () => {
    it('loads a contains_any rule from JSON object and detects payload', () => {
        const engine = new InvariantEngine()
        loadRuleFromJson(engine, {
            id: 'sql_tautology',
            type: 'contains_any',
            value: ['dynamic_marker_123'],
            category: 'sqli',
            severity: 'high',
        })

        const matches = engine.detect('prefix dynamic_marker_123 suffix', [])
        expect(matches.some((m) => m.class === 'sql_tautology')).toBe(true)
    })

    it('loads a regex rule from JSON object and detects payload', () => {
        const engine = new InvariantEngine()
        loadRuleFromJson(engine, {
            id: 'xss_tag_injection',
            type: 'regex',
            value: '<script\\b[^>]*>',
            category: 'xss',
            severity: 'high',
        })

        const matches = engine.detect('<script>alert(1)</script>', [])
        expect(matches.some((m) => m.class === 'xss_tag_injection')).toBe(true)
    })

    it('loads a starts_with rule from JSON object and detects payload', () => {
        const engine = new InvariantEngine()
        loadRuleFromJson(engine, {
            id: 'cmd_separator',
            type: 'starts_with',
            value: 'danger:',
            category: 'cmdi',
            severity: 'critical',
        })

        const matches = engine.detect('danger: run whoami', [])
        expect(matches.some((m) => m.class === 'cmd_separator')).toBe(true)
    })

    it('throws a clear error when required fields are missing', () => {
        const engine = new InvariantEngine()
        expect(() =>
            loadRuleFromJson(engine, {
                id: 'sql_tautology',
                type: 'contains_any',
                value: ['x'],
                category: 'sqli',
            })
        ).toThrow(/missing required field: severity/i)
    })
})
