/**
 * SSTI Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for SSTI is:
 *   ∃ template_expression ∈ extract(input, TEMPLATE_DELIMITERS) :
 *     parse(expression).property_chain ∩ DANGEROUS_OBJECTS ≠ ∅
 *     ∨ parse(expression).function_call ∈ DANGEROUS_FUNCTIONS
 *
 * Template engines (Jinja2, Twig, EL, Pebble, Velocity, etc.)
 * evaluate expressions inside delimiters like {{ }}, ${ }, #{ }.
 * The attack: inject an expression that traverses the object model
 * to reach dangerous capabilities (code execution, file access).
 *
 * This evaluator parses the expression structure instead of
 * matching specific payload strings. It identifies dangerous
 * property chains (constructor.constructor, __class__.__mro__)
 * regardless of how they're expressed.
 *
 * Covers:
 *   - ssti_jinja_twig:    {{ }}, {% %}, {# #} expressions
 *   - ssti_el_expression: ${ }, #{ }, T() expressions
 */


// ── Result Type ──────────────────────────────────────────────────

export interface SSTIDetection {
    type: 'jinja_twig' | 'el_expression'
    detail: string
    expression: string
    engine: string
    confidence: number
}


// ── Template Delimiter Patterns ──────────────────────────────────

interface TemplateDelimiter {
    open: string
    close: string
    engine: string
    type: SSTIDetection['type']
}

const DELIMITERS: TemplateDelimiter[] = [
    // Jinja2 / Twig / Django
    { open: '{{', close: '}}', engine: 'Jinja2/Twig/Django', type: 'jinja_twig' },
    { open: '{%', close: '%}', engine: 'Jinja2/Twig (block)', type: 'jinja_twig' },

    // Java EL / SpEL
    { open: '${', close: '}', engine: 'Java EL/SpEL', type: 'el_expression' },
    { open: '#{', close: '}', engine: 'JSF EL/SpEL', type: 'el_expression' },

    // Velocity
    { open: '#set(', close: ')', engine: 'Velocity', type: 'el_expression' },

    // Pebble
    { open: '{{', close: '}}', engine: 'Pebble', type: 'jinja_twig' },

    // Mako / ERB (Python / Ruby)
    { open: '<%', close: '%>', engine: 'Mako/ERB', type: 'el_expression' },

    // Freemarker
    { open: '${', close: '}', engine: 'Freemarker', type: 'el_expression' },
]


// ── Dangerous Object Chains ──────────────────────────────────────
//
// These represent the INVARIANT: if the expression traverses to
// any of these object paths, it has access to code execution.
// The specific syntax varies by engine, but the PROPERTY is the same:
// "expression reaches a dangerous capability."

const DANGEROUS_CHAINS: Array<{ segments: string[]; reason: string }> = [
    // Python: Jinja2/Mako object traversal
    { segments: ['__class__', '__mro__'], reason: 'Python MRO traversal → code execution' },
    { segments: ['__class__', '__bases__'], reason: 'Python base class traversal' },
    { segments: ['__class__', '__subclasses__'], reason: 'Python subclass enumeration → code exec' },
    { segments: ['__init__', '__globals__'], reason: 'Python global scope access' },
    { segments: ['__builtins__'], reason: 'Python builtins access' },
    { segments: ['__import__'], reason: 'Python dynamic import' },
    { segments: ['config', '__class__'], reason: 'Flask config → class traversal' },

    // JavaScript: prototype chain traversal
    { segments: ['constructor', 'constructor'], reason: 'Function constructor → eval equivalent' },
    { segments: ['__proto__'], reason: 'Prototype access → chain manipulation' },
    { segments: ['constructor', 'prototype'], reason: 'Prototype access via constructor' },

    // Java: Spring EL / EL injection
    { segments: ['getClass'], reason: 'Java getClass() → reflection' },
    { segments: ['forName'], reason: 'Java Class.forName() → arbitrary class load' },
    { segments: ['getRuntime'], reason: 'Java Runtime.getRuntime() → RCE' },
    { segments: ['getMethod'], reason: 'Java reflection method invocation' },
    { segments: ['getDeclaredMethod'], reason: 'Java reflection (declared)' },
    { segments: ['newInstance'], reason: 'Java arbitrary instantiation' },
    { segments: ['ProcessBuilder'], reason: 'Java ProcessBuilder → RCE' },
    { segments: ['Runtime'], reason: 'Java Runtime access' },
]

// Dangerous function calls within template expressions
const DANGEROUS_FUNCTIONS = new Set([
    // Python
    'exec', 'eval', 'compile', 'execfile', 'input',
    '__import__', 'open', 'file', 'popen', 'system',
    // Java
    'getruntime', 'exec', 'processbuilder', 'forname',
    'getmethod', 'invoke', 'newinstance',
    // PHP
    'system', 'exec', 'shell_exec', 'passthru', 'popen',
    'proc_open', 'pcntl_exec', 'assert', 'eval',
    // Ruby
    'system', 'exec', 'spawn', 'io.popen',
    // General
    'process', 'require', 'import',
])


// ── Expression Parser ────────────────────────────────────────────

/**
 * Extract template expressions from input by matching delimiters.
 */
function extractExpressions(input: string): Array<{ content: string; engine: string; type: SSTIDetection['type'] }> {
    const expressions: Array<{ content: string; engine: string; type: SSTIDetection['type'] }> = []
    const seen = new Set<string>()

    for (const delim of DELIMITERS) {
        let startIdx = 0
        while (startIdx < input.length) {
            const openIdx = input.indexOf(delim.open, startIdx)
            if (openIdx === -1) break

            const contentStart = openIdx + delim.open.length
            const closeIdx = input.indexOf(delim.close, contentStart)
            if (closeIdx === -1) {
                startIdx = contentStart
                continue
            }

            const content = input.substring(contentStart, closeIdx).trim()
            if (content.length > 0 && !seen.has(content)) {
                seen.add(content)
                expressions.push({ content, engine: delim.engine, type: delim.type })
            }

            startIdx = closeIdx + delim.close.length
        }
    }

    // Also check for Java Spring T() type expressions: T(java.lang.Runtime)
    const tExprRegex = /T\(([^)]+)\)/g
    let tMatch
    while ((tMatch = tExprRegex.exec(input)) !== null) {
        const content = tMatch[1].trim()
        if (content.length > 0 && !seen.has(content)) {
            seen.add(content)
            expressions.push({ content, engine: 'Spring SpEL T()', type: 'el_expression' })
        }
    }

    return expressions
}

/**
 * Parse a property access chain from an expression.
 * "a.b.c()" → ["a", "b", "c"]
 * "__class__.__mro__[2]" → ["__class__", "__mro__"]
 */
function parsePropertyChain(expr: string): string[] {
    // Remove array access brackets
    const clean = expr.replace(/\[[^\]]*\]/g, '')
    // Remove function call parens and args
    const noFuncArgs = clean.replace(/\([^)]*\)/g, '')
    // Split on . or ->
    return noFuncArgs.split(/[.\->]+/).map(s => s.trim()).filter(s => s.length > 0)
}

/**
 * Extract function calls from an expression.
 * "exec('id')" → ["exec"]
 * "os.popen('cmd').read()" → ["popen", "read"]
 */
function extractFunctionCalls(expr: string): string[] {
    const calls: string[] = []
    const funcPattern = /([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g
    let match
    while ((match = funcPattern.exec(expr)) !== null) {
        calls.push(match[1].toLowerCase())
    }
    return calls
}


// ── Detection Logic ──────────────────────────────────────────────

function isDangerousExpression(content: string): { dangerous: boolean; reason: string } {
    const chain = parsePropertyChain(content)
    const lowerChain = chain.map(s => s.toLowerCase())

    // Check for dangerous property chains
    for (const dc of DANGEROUS_CHAINS) {
        const segments = dc.segments.map(s => s.toLowerCase())
        // Check if ALL segments of the dangerous chain appear in order
        let lastIdx = -1
        let allFound = true
        for (const seg of segments) {
            const idx = lowerChain.indexOf(seg, lastIdx + 1)
            if (idx === -1) {
                allFound = false
                break
            }
            lastIdx = idx
        }
        if (allFound) {
            return { dangerous: true, reason: dc.reason }
        }
    }

    // Check for dangerous function calls
    const functionCalls = extractFunctionCalls(content)
    for (const fn of functionCalls) {
        if (DANGEROUS_FUNCTIONS.has(fn)) {
            return { dangerous: true, reason: `Dangerous function call: ${fn}()` }
        }
    }

    // Check for string-based evasion of function checks
    // e.g., ''.__class__.__mro__ → starts with empty string literal
    const strippedQuotes = content.replace(/['"]/g, '')
    if (strippedQuotes !== content) {
        const strippedChain = parsePropertyChain(strippedQuotes)
        const strippedLower = strippedChain.map(s => s.toLowerCase())
        for (const dc of DANGEROUS_CHAINS) {
            const segments = dc.segments.map(s => s.toLowerCase())
            let lastIdx = -1
            let allFound = true
            for (const seg of segments) {
                const idx = strippedLower.indexOf(seg, lastIdx + 1)
                if (idx === -1) { allFound = false; break }
                lastIdx = idx
            }
            if (allFound) {
                return { dangerous: true, reason: `${dc.reason} (quote-wrapped)` }
            }
        }
    }

    return { dangerous: false, reason: '' }
}


// ── Public API ───────────────────────────────────────────────────

/**
 * Detect SSTI vectors by extracting template expressions and
 * analyzing their property chains for dangerous object access.
 */
export function detectSSTI(input: string): SSTIDetection[] {
    const detections: SSTIDetection[] = []

    // Quick bail: must contain template-like delimiters
    if (!input.includes('{') && !input.includes('<%') && !input.includes('T(')) {
        return detections
    }

    const expressions = extractExpressions(input)

    for (const expr of expressions) {
        try {
            const result = isDangerousExpression(expr.content)
            if (result.dangerous) {
                detections.push({
                    type: expr.type,
                    detail: result.reason,
                    expression: expr.content.slice(0, 100),
                    engine: expr.engine,
                    confidence: 0.90,
                })
            }
        } catch { /* never crash */ }
    }

    return detections
}
