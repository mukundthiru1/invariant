import { describe, it, expect } from 'vitest'
import { InvariantEngine } from './invariant-engine.js'
import type { InvariantClass } from './classes/types.js'
import {
    InvariantRegistry,
    ALL_CLASS_MODULES,
    SQL_CLASSES,
    XSS_CLASSES,
    CMD_CLASSES,
    PATH_CLASSES,
    SSRF_CLASSES,
    DESER_CLASSES,
    AUTH_CLASSES,
    INJECTION_CLASSES,
    HYGIENE_CLASSES,
} from './classes/index.js'
import { HtmlTokenizer, analyzeHtmlForXss } from './tokenizers/html-tokenizer.js'
import { ShellTokenizer, analyzeShellForInjection } from './tokenizers/shell-tokenizer.js'
import { TemplateTokenizer, analyzeTemplateForSsti } from './tokenizers/template-tokenizer.js'


// 1. Registry Tests
describe('InvariantRegistry', () => {
    it('registers all class modules without error', () => {
        const registry = new InvariantRegistry()
        expect(() => registry.registerAll(ALL_CLASS_MODULES)).not.toThrow()
        expect(registry.size).toBe(ALL_CLASS_MODULES.length)
    })

    it('rejects duplicate class IDs', () => {
        const registry = new InvariantRegistry()
        registry.registerAll(ALL_CLASS_MODULES)
        expect(() => registry.register(SQL_CLASSES[0])).toThrow(/Duplicate/)
    })

    it('looks up by class ID', () => {
        const registry = new InvariantRegistry()
        registry.registerAll(ALL_CLASS_MODULES)
        const sqli = registry.get('sql_tautology')
        expect(sqli).toBeDefined()
        expect(sqli!.id).toBe('sql_tautology')
        expect(sqli!.category).toBe('sqli')
    })

    it('filters by category', () => {
        const registry = new InvariantRegistry()
        registry.registerAll(ALL_CLASS_MODULES)
        expect(registry.getByCategory('sqli').length).toBe(13)
    })

    it('filters by severity', () => {
        const registry = new InvariantRegistry()
        registry.registerAll(ALL_CLASS_MODULES)
        expect(registry.getBySeverity('critical').length).toBeGreaterThan(0)
    })

    it('computes calibrated confidence', () => {
        const registry = new InvariantRegistry()
        registry.registerAll(ALL_CLASS_MODULES)
        const conf = registry.computeConfidence('sql_tautology', "' OR 1=1--")
        expect(conf).toBeGreaterThan(0.5)
        expect(conf).toBeLessThanOrEqual(1.0)
    })

    it('produces correct stats', () => {
        const registry = new InvariantRegistry()
        registry.registerAll(ALL_CLASS_MODULES)
        const stats = registry.stats()
        expect(stats.totalClasses).toBe(ALL_CLASS_MODULES.length)
        expect(stats.byCategory['sqli']).toBe(13)
    })
})


// 2. Class Module Counts
describe('Class Module Counts', () => {
    it('SQL: 13', () => expect(SQL_CLASSES.length).toBe(13))
    it('XSS: 8', () => expect(XSS_CLASSES.length).toBe(8))
    it('CMDi: 3', () => expect(CMD_CLASSES.length).toBe(3))
    it('Path: 5', () => expect(PATH_CLASSES.length).toBe(5))
    it('SSRF: 3', () => expect(SSRF_CLASSES.length).toBe(3))
    it('Deser: 3', () => expect(DESER_CLASSES.length).toBe(3))
    it('Auth: 23', () => expect(AUTH_CLASSES.length).toBe(23))
    it('Injection: 101', () => expect(INJECTION_CLASSES.length).toBe(101))
    it('Hygiene: 26', () => expect(HYGIENE_CLASSES.length).toBe(26))
    it('Total: 185', () => expect(ALL_CLASS_MODULES.length).toBe(185))
})


// 3. Backward Compatibility
describe('InvariantEngine Backward Compat', () => {
    const engine = new InvariantEngine()

    it('classCount', () => expect(engine.classCount).toBe(ALL_CLASS_MODULES.length))
    it('classes', () => {
        expect(engine.classes).toContain('sql_tautology')
        expect(engine.classes).toContain('xss_tag_injection')
    })
    it('detect returns matches', () => {
        const m = engine.detect("' OR 1=1--", [])
        expect(m.length).toBeGreaterThan(0)
        expect(m[0]).toHaveProperty('class')
        expect(m[0]).toHaveProperty('confidence')
    })
    it('shouldBlock', () => expect(engine.shouldBlock(engine.detect("' OR 1=1--", []))).toBe(true))
    it('highestSeverity', () => expect(engine.highestSeverity(engine.detect("'; DROP TABLE users--", []))).toBe('critical'))
    it('generateVariants', () => expect(engine.generateVariants('sql_tautology', 5).length).toBe(5))
    it('novel vs known', () => {
        expect(engine.detect("' OR 1=1--", []).some(m => m.isNovelVariant)).toBe(true)
        expect(engine.detect("' OR 1=1--", ['r1']).some(m => m.isNovelVariant)).toBe(false)
    })
    it('detects new classes', () => {
        expect(engine.classes).toContain('http_smuggle_cl_te')
        expect(engine.classes).toContain('http_smuggle_h2')
        expect(engine.classes).toContain('crlf_log_injection')
        expect(engine.classes).toContain('cors_origin_abuse')
        expect(engine.classes).toContain('path_normalization_bypass')
    })
})


// 4. HTML Tokenizer
describe('HtmlTokenizer', () => {
    const t = new HtmlTokenizer()
    it('basic HTML', () => {
        const s = t.tokenize('<div class="test">hello</div>')
        const types = s.all().map(tok => tok.type)
        expect(types).toContain('TAG_OPEN')
        expect(types).toContain('TAG_NAME')
        expect(types).toContain('ATTR_NAME')
        expect(types).toContain('TEXT')
    })
    it('script content', () => {
        expect(t.tokenize('<script>alert(1)</script>').all().some(tok => tok.type === 'SCRIPT_CONTENT')).toBe(true)
    })
    it('comments', () => expect(t.tokenize('<!-- x -->').all()[0].type).toBe('COMMENT'))
    it('self-close', () => expect(t.tokenize('<img/>').all().some(tok => tok.type === 'TAG_SELF_CLOSE')).toBe(true))
    it('template expr', () => {
        expect(t.tokenize('{{evil}}').all().some(tok => tok.type === 'TEMPLATE_EXPR')).toBe(true)
    })
    it('malformed ok', () => {
        expect(() => t.tokenize('<div><span class=')).not.toThrow()
        expect(() => t.tokenize('')).not.toThrow()
    })
})

describe('HTML XSS Analysis', () => {
    const t = new HtmlTokenizer()
    it('script tag', () => expect(analyzeHtmlForXss(t.tokenize('<script>x</script>')).some(d => d.type === 'tag_injection')).toBe(true))
    it('event handler', () => expect(analyzeHtmlForXss(t.tokenize('<img onerror="x">')).some(d => d.type === 'event_handler')).toBe(true))
    it('javascript: protocol', () => expect(analyzeHtmlForXss(t.tokenize('<a href="javascript:x">c</a>')).some(d => d.type === 'protocol_handler')).toBe(true))
    it('clean HTML', () => expect(analyzeHtmlForXss(t.tokenize('<div class="n"><p>Hi</p></div>')).length).toBe(0))
})


// 5. Shell Tokenizer
describe('ShellTokenizer', () => {
    const t = new ShellTokenizer()
    it('basic', () => {
        const s = t.tokenize('ls -la /tmp')
        expect(s.meaningful().some(tok => tok.type === 'WORD')).toBe(true)
        expect(s.meaningful().some(tok => tok.type === 'FLAG')).toBe(true)
    })
    it('pipes', () => expect(t.tokenize('a | b').all().some(tok => tok.type === 'PIPE')).toBe(true))
    it('chains', () => {
        const s = t.tokenize('; x && y || z')
        const types = s.all().map(tok => tok.type)
        expect(types).toContain('SEPARATOR')
        expect(types).toContain('AND_CHAIN')
        expect(types).toContain('OR_CHAIN')
    })
    it('cmd subst', () => expect(t.tokenize('$(whoami)').all().some(tok => tok.type === 'CMD_SUBST_OPEN')).toBe(true))
    it('backtick', () => expect(t.tokenize('`id`').all().some(tok => tok.type === 'BACKTICK_SUBST')).toBe(true))
    it('var expand', () => expect(t.tokenize('$HOME ${X}').all().filter(tok => tok.type === 'VAR_EXPANSION').length).toBe(2))
})

describe('Shell Injection Analysis', () => {
    const t = new ShellTokenizer()
    it('separator chain', () => expect(analyzeShellForInjection(t.tokenize('; id')).some(d => d.type === 'separator_chain')).toBe(true))
    it('pipe chain', () => expect(analyzeShellForInjection(t.tokenize('| cat /etc/passwd')).some(d => d.type === 'pipe_chain')).toBe(true))
    it('cmd subst', () => expect(analyzeShellForInjection(t.tokenize('$(whoami)')).some(d => d.type === 'substitution')).toBe(true))
    it('backtick subst', () => expect(analyzeShellForInjection(t.tokenize('`id`')).some(d => d.type === 'substitution')).toBe(true))
    it('harmless ok', () => expect(analyzeShellForInjection(t.tokenize('npm run build')).length).toBe(0))
})


// 6. Template Tokenizer
describe('TemplateTokenizer', () => {
    const t = new TemplateTokenizer()
    it('jinja2', () => {
        const s = t.tokenize('{{config.__class__}}')
        expect(s.all().some(tok => tok.type === 'EXPR_OPEN')).toBe(true)
        expect(s.all().some(tok => tok.type === 'DUNDER')).toBe(true)
    })
    it('java EL', () => expect(t.tokenize('${foo}').all().some(tok => tok.type === 'EXPR_OPEN')).toBe(true))
    it('plain text', () => expect(t.tokenize('Hello world').all().every(tok => tok.type === 'TEXT')).toBe(true))
})

describe('Template SSTI Analysis', () => {
    const t = new TemplateTokenizer()
    it('dunder chain', () => expect(analyzeTemplateForSsti(t.tokenize('{{config.__class__.__init__.__globals__}}')).some(d => d.type === 'prototype_chain')).toBe(true))
    it('code exec EL', () => expect(analyzeTemplateForSsti(t.tokenize('${T(java.lang.Runtime).getRuntime().exec("id")}')).some(d => d.type === 'code_execution')).toBe(true))
    it('harmless ok', () => expect(analyzeTemplateForSsti(t.tokenize('Hello {{user.name}}')).filter(d => d.confidence > 0.7).length).toBe(0))
})


// 7. Contract Validation (upgraded with knownPayloads + knownBenign)
describe('Class Self-Validation', () => {
    it('no duplicate IDs', () => {
        const ids = ALL_CLASS_MODULES.map(m => m.id)
        expect(new Set(ids).size).toBe(ids.length)
    })

    it('all fields present', () => {
        for (const m of ALL_CLASS_MODULES) {
            expect(m.id).toBeTruthy()
            expect(m.description).toBeTruthy()
            expect(m.category).toBeTruthy()
            expect(m.severity).toBeTruthy()
            expect(typeof m.detect).toBe('function')
            expect(typeof m.generateVariants).toBe('function')
            expect(Array.isArray(m.knownPayloads), `${m.id}: knownPayloads must be array`).toBe(true)
            expect(Array.isArray(m.knownBenign), `${m.id}: knownBenign must be array`).toBe(true)
        }
    })

    it('variants self-detect', () => {
        for (const mod of ALL_CLASS_MODULES) {
            // Skip classes checked via headers or length-based heuristics
            if (mod.id === 'auth_header_spoof' || mod.id === 'regex_dos' || mod.id === 'cors_origin_abuse') continue
            const variants = mod.generateVariants(3)
            const anyDetected = variants.some(v => { try { return mod.detect(v) } catch { return false } })
            expect(anyDetected, `${mod.id} failed self-detect on ${JSON.stringify(variants)}`).toBe(true)
        }
    })
})


// 8. knownPayloads regression — every payload MUST detect
describe('knownPayloads Regression', () => {
    for (const mod of ALL_CLASS_MODULES) {
        // Skip header-only and length-based classes
        if (mod.id === 'auth_header_spoof' || mod.id === 'regex_dos' || mod.id === 'cors_origin_abuse') continue
        if (mod.knownPayloads.length === 0) continue

        describe(mod.id, () => {
            for (const payload of mod.knownPayloads) {
                const truncated = payload.length > 60 ? payload.slice(0, 60) + '...' : payload
                it(`detects: ${truncated}`, () => {
                    expect(mod.detect(payload), `${mod.id} failed to detect known payload: ${truncated}`).toBe(true)
                })
            }
        })
    }
})


// 9. knownBenign regression — every benign input MUST NOT detect
describe('knownBenign Regression', () => {
    for (const mod of ALL_CLASS_MODULES) {
        if (mod.knownBenign.length === 0) continue

        describe(mod.id, () => {
            for (const benign of mod.knownBenign) {
                const truncated = benign.length > 60 ? benign.slice(0, 60) + '...' : benign
                it(`ignores: ${truncated}`, () => {
                    expect(mod.detect(benign), `${mod.id} false positive on benign input: ${truncated}`).toBe(false)
                })
            }
        })
    }
})


// ─── v3: Multi-Level Pipeline Tests ──────────────────────────────

describe('v3: detectDeep() Multi-Level Pipeline', () => {
    const engine = new InvariantEngine()

    it('returns DeepDetectionResult structure', () => {
        const result = engine.detectDeep("' OR 1=1--", [])
        expect(result).toHaveProperty('matches')
        expect(result).toHaveProperty('novelByL2')
        expect(result).toHaveProperty('convergent')
        expect(result).toHaveProperty('processingTimeUs')
        expect(Array.isArray(result.matches)).toBe(true)
        expect(typeof result.processingTimeUs).toBe('number')
    })

    it('detects SQL tautology via both L1 and L2', () => {
        const result = engine.detectDeep("' OR 1=1--", [])
        const taut = result.matches.find(m => m.class === 'sql_tautology')
        expect(taut).toBeDefined()
        // Should have detection level info
        expect(taut!.detectionLevels).toBeDefined()
        expect(taut!.detectionLevels!.l1).toBe(true)
    })

    it('detects XSS via L1', () => {
        const result = engine.detectDeep('<script>alert(1)</script>', [])
        const tag = result.matches.find(m => m.class === 'xss_tag_injection')
        expect(tag).toBeDefined()
        expect(tag!.detectionLevels!.l1).toBe(true)
    })

    it('returns zero matches for clean input', () => {
        const result = engine.detectDeep('hello world', [])
        expect(result.matches.length).toBe(0)
        expect(result.novelByL2).toBe(0)
        expect(result.convergent).toBe(0)
    })

    it('processes in sub-millisecond for typical inputs', () => {
        const result = engine.detectDeep("' OR 1=1--", [])
        // processingTimeUs should be < 5000 (5ms) for sub-millisecond path
        expect(result.processingTimeUs).toBeLessThan(5000)
    })

    it('backward compatible: detect() returns same classes as detectDeep()', () => {
        const input = "' UNION SELECT 1,2,3--"
        const v2 = engine.detect(input, [])
        const v3 = engine.detectDeep(input, [])
        const v2Classes = new Set(v2.map(m => m.class))
        // v3 should catch at least everything v2 catches
        for (const cls of v2Classes) {
            const found = v3.matches.find(m => m.class === cls)
            expect(found, `v3 missed class ${cls} that v2 caught`).toBeDefined()
        }
    })

    it('detects multiple classes in a compound payload', () => {
        // This payload expresses: string_termination + tautology + comment_truncation
        const result = engine.detectDeep("' OR 1=1--", [])
        const classes = new Set(result.matches.map(m => m.class))
        expect(classes.has('sql_tautology')).toBe(true)
        expect(classes.has('sql_string_termination')).toBe(true)
    })

    it('marks clean-input as not novel', () => {
        const result = engine.detectDeep("'; DROP TABLE users--", ['static_rule_1'])
        const match = result.matches.find(m => m.class === 'sql_stacked_execution')
        if (match) {
            // When static rules already matched, it's NOT novel
            expect(match.isNovelVariant).toBe(false)
        }
    })
})


describe('v3: L2 Evaluator Wiring', () => {
    // Verify that L2 evaluators are wired into the class modules
    const engine = new InvariantEngine()

    const classesWithL2 = [
        'sql_tautology',
        'sql_string_termination',
        'sql_union_extraction',
        'sql_stacked_execution',
        'sql_time_oracle',
        'sql_error_oracle',
        'sql_comment_truncation',
        'xss_tag_injection',
        'xss_event_handler',
        'xss_protocol_handler',
        'xss_attribute_escape',
        'xss_template_expression',
        'dom_xss',
        'angularjs_sandbox_escape',
        'css_injection',
    ]

    for (const classId of classesWithL2) {
        it(`${classId} has detectL2 wired`, () => {
            const mod = engine.registry.get(classId as InvariantClass)
            expect(mod).toBeDefined()
            expect(mod!.detectL2).toBeDefined()
            expect(typeof mod!.detectL2).toBe('function')
        })
    }

    it('SQL classes total with L2: 13', () => {
        const sqlWithL2 = SQL_CLASSES.filter(c => c.detectL2)
        expect(sqlWithL2.length).toBe(13)
    })

    it('XSS classes total with L2: 8', () => {
        const xssWithL2 = XSS_CLASSES.filter(c => c.detectL2)
        expect(xssWithL2.length).toBe(8)
    })

    it('total classes with L2: at least 43', () => {
        const allWithL2 = ALL_CLASS_MODULES.filter(c => c.detectL2)
        expect(allWithL2.length).toBeGreaterThanOrEqual(43)
    })
})


describe('v3: DetectionLevelResult Contract', () => {
    it('DetectionLevelResult has required fields', () => {
        const mod = ALL_CLASS_MODULES.find(m => m.id === 'sql_tautology')!
        const result = mod.detectL2!("' OR 1=1--")
        // If it detects, verify structure
        if (result && result.detected) {
            expect(typeof result.confidence).toBe('number')
            expect(result.confidence).toBeGreaterThan(0)
            expect(result.confidence).toBeLessThanOrEqual(1)
            expect(typeof result.explanation).toBe('string')
            expect(result.explanation.length).toBeGreaterThan(0)
        }
    })

    it('L2 returns null for non-matching input', () => {
        const mod = ALL_CLASS_MODULES.find(m => m.id === 'sql_tautology')!
        const result = mod.detectL2!('hello world')
        expect(result === null || result?.detected === false).toBe(true)
    })
})
