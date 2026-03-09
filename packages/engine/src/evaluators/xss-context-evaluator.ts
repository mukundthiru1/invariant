/**
 * XSS Context Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for XSS tag injection is:
 *   ∃ element ∈ parse(input, HTML_FRAGMENT_GRAMMAR) :
 *     element.type = HTML_TAG
 *     ∧ element.tagName ∈ SCRIPT_CAPABLE_TAGS
 *     ∨ element.attributes ∃ attr :
 *         attr.name STARTS_WITH 'on' ∨ attr.value STARTS_WITH 'javascript:'
 *
 * This module implements context-aware HTML fragment analysis:
 *   1. Tokenizes input as HTML fragment
 *   2. Identifies injected elements vs benign text
 *   3. Evaluates whether any element achieves script execution
 *
 * Unlike regex, this catches:
 *   - Self-closing XSS: <img/src/onerror=alert(1)>
 *   - Uppercase evasion: <SCRIPT>alert(1)</SCRIPT>
 *   - Mixed case: <sCrIpT>
 *   - Attribute-only: <div onmouseover=alert(1)>
 *   - Template literals: <img src=x onerror=`alert(1)`>
 *   - SVG/MathML payloads: <svg onload=alert(1)>
 *   - Data URI payloads: <a href="data:text/html,<script>alert(1)</script>">
 *   - Novel tag/attribute combinations
 */


// ── HTML Token Types ─────────────────────────────────────────────

export type HtmlTokenType =
    | 'TAG_OPEN'          // <tag
    | 'TAG_CLOSE'         // </tag>
    | 'TAG_SELF_CLOSE'    // />
    | 'TAG_END'           // >
    | 'ATTR_NAME'         // name
    | 'ATTR_EQUALS'       // =
    | 'ATTR_VALUE'        // "value" or 'value' or value
    | 'TEXT'              // plain text
    | 'COMMENT'           // <!-- ... -->

export interface HtmlToken {
    type: HtmlTokenType
    value: string
    position: number
}

export interface ParsedHtmlElement {
    tagName: string
    attributes: Record<string, string>
    selfClosing: boolean
    position: number
}


// ── Dangerous Tags and Attributes ────────────────────────────────

/**
 * Tags that can directly execute JavaScript or load external resources.
 */
const SCRIPT_CAPABLE_TAGS = new Set([
    'script', 'img', 'svg', 'iframe', 'object', 'embed', 'video',
    'audio', 'source', 'body', 'input', 'select', 'textarea',
    'button', 'details', 'marquee', 'isindex', 'form', 'math',
    'base', 'link', 'style', 'meta', 'applet', 'bgsound',
    'layer', 'ilayer', 'xml', 'xss', 'image', 'a', 'template',
])

/**
 * Event handler attributes that execute JavaScript.
 * Pattern: starts with "on" followed by an event name.
 */
const EVENT_HANDLER_PATTERN = /^on[a-z]+$/i

/**
 * URI schemes that can execute JavaScript.
 */
const DANGEROUS_SCHEMES = [
    'javascript:', 'data:text/html', 'data:text/javascript',
    'vbscript:', 'livescript:',
]

/**
 * Attributes that accept URIs (and thus can use javascript: scheme).
 */
const URI_ATTRIBUTES = new Set([
    'href', 'src', 'action', 'formaction', 'data', 'background',
    'poster', 'codebase', 'cite', 'icon', 'manifest', 'dynsrc',
    'lowsrc', 'srcdoc', 'to', 'xlink:href',
])

const DOM_CLOBBERING_TAGS = new Set(['form', 'img', 'input', 'textarea', 'select', 'button'])
const DOM_CLOBBERING_ID_VALUES = new Set(['__proto__', 'prototype', 'constructor'])
const DOM_CLOBBERING_NAME_VALUES = new Set(['domain', 'polluted', 'constructor', 'prototype', '__proto__'])

const DOM_CLOBBERING_RE = /<(?:form|input|img|a|iframe)\s[^>]{0,200}(?:id|name)\s*=\s*['"]?(?:body|document|location|frames|window|history|navigator|top|parent|opener)['"]?/i
const DOM_CLOBBERING_OWNER_DOC_RE = /<input\s[^>]{0,200}\bname\s*=\s*['"]?ownerdocument['"]?/i
const DOM_CLOBBERING_ANCHOR_JS_RE = /<a\s[^>]{0,200}\bid\s*=\s*['"]?location['"]?[^>]{0,200}\bhref\s*=\s*['"]?\s*javascript:/i

const MUTATION_XSS_NOSCRIPT_RE = /<noscript\b[^>]{0,120}>\s*<p\b[^>]{0,200}\btitle\s*=\s*['"]?[^>'"\n]{0,120}\s*<\/noscript>\s*<img\b/i
const MUTATION_XSS_FOREIGN_OBJECT_RE = /<svg\b[^>]{0,120}>[\s\S]{0,200}<foreignObject\b[^>]{0,120}>[\s\S]{0,200}<html\b/i
const MUTATION_XSS_MATHML_RE = /<math\b[^>]{0,120}>[\s\S]{0,200}<mtext\b[^>]{0,120}>\s*<\/form>\s*<form\b[^>]{0,120}>[\s\S]{0,200}<mglyph\b[^>]{0,120}>[\s\S]{0,200}<svg\b/i
const MUTATION_XSS_TEMPLATE_RE = /<template\b[^>]{0,120}>[\s\S]{0,200}<script\b/i

const DANGLING_MARKUP_IMG_RE = /<img\b[^>\n]{0,180}\bsrc\s*=\s*['"]\s*https?:\/\/[^'"\n>]{1,200}(?:\n|$)/i
const DANGLING_MARKUP_BASE_RE = /<base\b[^>\n]{0,180}\bhref\s*=\s*['"]\s*https?:\/\/[^'"\n>]{1,200}(?:\n|$)/i
const DANGLING_MARKUP_LINK_RE = /<link\b[^>\n]{0,120}\brel\s*=\s*['"]?stylesheet['"]?[^>\n]{0,120}\bhref\s*=\s*['"]\s*https?:\/\/[^'"\n>]{1,200}(?:\n|$)/i

const CSS_EXPRESSION_XSS_RE = /\bexpression\s*\(\s*(?:alert|document|window)[^)]{0,180}\)/i
const CSS_MOZ_BINDING_RE = /\b-moz-binding\s*:\s*url\s*\(\s*['"]?[^)]{0,180}\)/i
const CSS_BEHAVIOR_XSS_RE = /\bbehavior\s*:\s*url\s*\(\s*['"]?[^)]{0,180}\)/i
const CSS_IMPORT_JS_DATA_RE = /@import\s+(?:url\s*\(\s*['"]?\s*)?(?:javascript:|data:)[^'"\s)]{0,220}/i
const CSS_URL_JS_DATA_RE = /\burl\s*\(\s*['"]?\s*(?:javascript:|data:)[^)]{0,220}\)/i


// ── HTML Fragment Tokenizer ──────────────────────────────────────

/**
 * Tokenize an HTML fragment for XSS detection.
 * 
 * This is NOT a full HTML parser — it's designed for attack detection:
 *  - Tolerates malformed HTML (attackers craft invalid markup)
 *  - Handles partial fragments
 *  - Focuses on extracting tags and attributes
 */
export function htmlTokenize(input: string): HtmlToken[] {
    const tokens: HtmlToken[] = []
    let i = 0
    const MAX_INPUT = 4096
    const bounded = input.length > MAX_INPUT ? input.slice(0, MAX_INPUT) : input

    while (i < bounded.length) {
        // HTML comment
        if (bounded.slice(i, i + 4) === '<!--') {
            const end = bounded.indexOf('-->', i + 4)
            if (end !== -1) {
                tokens.push({ type: 'COMMENT', value: bounded.slice(i, end + 3), position: i })
                i = end + 3
            } else {
                tokens.push({ type: 'COMMENT', value: bounded.slice(i), position: i })
                break
            }
            continue
        }

        // Closing tag: </tagname>
        if (bounded[i] === '<' && bounded[i + 1] === '/') {
            const start = i
            i += 2
            while (i < bounded.length && bounded[i] !== '>') i++
            if (i < bounded.length) i++ // skip >
            tokens.push({ type: 'TAG_CLOSE', value: bounded.slice(start, i), position: start })
            continue
        }

        // Opening tag: <tagname
        if (bounded[i] === '<' && /[a-zA-Z!?]/.test(bounded[i + 1] ?? '')) {
            const start = i
            i++ // skip <
            // Read tag name
            const tagStart = i
            while (i < bounded.length && /[a-zA-Z0-9-]/.test(bounded[i])) i++
            const tagName = bounded.slice(tagStart, i)
            tokens.push({ type: 'TAG_OPEN', value: tagName, position: start })

            // Parse attributes until > or />
            while (i < bounded.length && bounded[i] !== '>' && !(bounded[i] === '/' && bounded[i + 1] === '>')) {
                // Skip whitespace
                if (/\s/.test(bounded[i])) { i++; continue }

                // Attribute name
                const attrStart = i
                while (i < bounded.length && /[a-zA-Z0-9\-_:]/.test(bounded[i])) i++
                if (i > attrStart) {
                    const attrName = bounded.slice(attrStart, i)
                    tokens.push({ type: 'ATTR_NAME', value: attrName, position: attrStart })

                    // Skip whitespace
                    while (i < bounded.length && /\s/.test(bounded[i])) i++

                    // Check for =
                    if (i < bounded.length && bounded[i] === '=') {
                        tokens.push({ type: 'ATTR_EQUALS', value: '=', position: i })
                        i++

                        // Skip whitespace
                        while (i < bounded.length && /\s/.test(bounded[i])) i++

                        // Attribute value
                        if (i < bounded.length) {
                            const quote = bounded[i]
                            if (quote === '"' || quote === "'") {
                                i++ // skip opening quote
                                const valStart = i
                                while (i < bounded.length && bounded[i] !== quote) i++
                                tokens.push({ type: 'ATTR_VALUE', value: bounded.slice(valStart, i), position: valStart })
                                if (i < bounded.length) i++ // skip closing quote
                            } else if (quote === '`') {
                                // Template literal — rare but used in XSS payloads
                                i++
                                const valStart = i
                                while (i < bounded.length && bounded[i] !== '`') i++
                                tokens.push({ type: 'ATTR_VALUE', value: bounded.slice(valStart, i), position: valStart })
                                if (i < bounded.length) i++
                            } else {
                                // Unquoted attribute value
                                const valStart = i
                                while (i < bounded.length && !/[\s>]/.test(bounded[i])) i++
                                tokens.push({ type: 'ATTR_VALUE', value: bounded.slice(valStart, i), position: valStart })
                            }
                        }
                    }
                } else {
                    // Unknown character in attribute context — skip
                    i++
                }
            }

            // Self-closing /> or >
            if (i < bounded.length && bounded[i] === '/' && bounded[i + 1] === '>') {
                tokens.push({ type: 'TAG_SELF_CLOSE', value: '/>', position: i })
                i += 2
            } else if (i < bounded.length && bounded[i] === '>') {
                tokens.push({ type: 'TAG_END', value: '>', position: i })
                i++
            }
            continue
        }

        // Bare < followed by non-alpha (might be text or malformed)
        if (bounded[i] === '<') {
            tokens.push({ type: 'TEXT', value: '<', position: i })
            i++
            continue
        }

        // Plain text
        const textStart = i
        while (i < bounded.length && bounded[i] !== '<') i++
        if (i > textStart) {
            tokens.push({ type: 'TEXT', value: bounded.slice(textStart, i), position: textStart })
        }
    }

    return tokens
}


// ── HTML Element Extractor ───────────────────────────────────────

/**
 * Extract parsed HTML elements from a token stream.
 */
export function extractHtmlElements(tokens: HtmlToken[]): ParsedHtmlElement[] {
    const elements: ParsedHtmlElement[] = []
    let i = 0

    while (i < tokens.length) {
        if (tokens[i].type === 'TAG_OPEN') {
            const tagName = tokens[i].value.toLowerCase()
            const position = tokens[i].position
            const attributes: Record<string, string> = {}
            let selfClosing = false
            i++

            // Collect attributes
            while (i < tokens.length) {
                if (tokens[i].type === 'ATTR_NAME') {
                    const name = tokens[i].value.toLowerCase()
                    i++
                    if (i < tokens.length && tokens[i].type === 'ATTR_EQUALS') {
                        i++
                        if (i < tokens.length && tokens[i].type === 'ATTR_VALUE') {
                            attributes[name] = tokens[i].value
                            i++
                        } else {
                            attributes[name] = ''
                        }
                    } else {
                        attributes[name] = ''
                    }
                } else if (tokens[i].type === 'TAG_SELF_CLOSE') {
                    selfClosing = true
                    i++
                    break
                } else if (tokens[i].type === 'TAG_END') {
                    i++
                    break
                } else {
                    i++
                }
            }

            elements.push({ tagName, attributes, selfClosing, position })
        } else {
            i++
        }
    }

    return elements
}

function isDomClobberingAttribute(element: ParsedHtmlElement, name: string, value: string): boolean {
    if (value.trim().length === 0) return false
    if (!DOM_CLOBBERING_TAGS.has(element.tagName)) return false

    const attrName = name.toLowerCase()
    const attrValue = value.trim().toLowerCase()

    if (attrName === 'id') {
        return DOM_CLOBBERING_ID_VALUES.has(attrValue)
    }

    if (attrName === 'name') {
        return DOM_CLOBBERING_NAME_VALUES.has(attrValue)
    }

    return false
}

function extractNestedMarkupElements(value: string): ParsedHtmlElement[] {
    if (!value.includes('<') || !value.includes('>') || !value.includes('</')) {
        return []
    }

    return extractHtmlElements(htmlTokenize(value))
}

function detectElementThreats(elem: ParsedHtmlElement): XssDetection[] {
    const detections: XssDetection[] = []

    // Check 1: Script-capable tag injection
    if (SCRIPT_CAPABLE_TAGS.has(elem.tagName)) {
        if (elem.tagName === 'script') {
            detections.push({
                type: 'tag_injection',
                element: `<${elem.tagName}>`,
                detail: 'Direct script tag injection — arbitrary JavaScript execution',
                position: elem.position,
                confidence: 0.95,
            })
        } else {
            const hasDangerousAttr = Object.entries(elem.attributes).some(([name, value]) => {
                return EVENT_HANDLER_PATTERN.test(name) ||
                    (URI_ATTRIBUTES.has(name) && hasDangerousScheme(value))
            })

            if (hasDangerousAttr) {
                detections.push({
                    type: 'tag_injection',
                    element: `<${elem.tagName}>`,
                    detail: `Script-capable tag with dangerous attributes`,
                    position: elem.position,
                    confidence: 0.9,
                })
            }
        }
    }

    // Check 2: Event handler attributes (works on ANY tag)
    for (const [name, value] of Object.entries(elem.attributes)) {
        if (EVENT_HANDLER_PATTERN.test(name) && value.length > 0) {
            detections.push({
                type: 'event_handler',
                element: `<${elem.tagName} ${name}=...>`,
                detail: `Event handler ${name}="${value.slice(0, 50)}"`,
                position: elem.position,
                confidence: 0.9,
            })
        }
    }

    // Check 3: Dangerous URI schemes in link/src attributes
    for (const [name, value] of Object.entries(elem.attributes)) {
        if (URI_ATTRIBUTES.has(name) && hasDangerousScheme(value)) {
            detections.push({
                type: 'protocol_handler',
                element: `<${elem.tagName} ${name}=...>`,
                detail: `Dangerous URI scheme: ${value.slice(0, 50)}`,
                position: elem.position,
                confidence: 0.88,
            })
        }
    }

    // Check 4: DOM clobbering via id/name collisions
    for (const [name, value] of Object.entries(elem.attributes)) {
        if (isDomClobberingAttribute(elem, name, value)) {
            detections.push({
                type: 'template_expression',
                element: `<${elem.tagName} ${name}=...>`,
                detail: `DOM clobbering sink: ${name}="${value.slice(0, 50)}"`,
                position: elem.position,
                confidence: 0.84,
            })
        }
    }

    return detections
}


// ── XSS Detection Results ────────────────────────────────────────

export interface XssDetection {
    /** Type of XSS vector */
    type:
    | 'tag_injection'
    | 'event_handler'
    | 'protocol_handler'
    | 'template_expression'
    | 'attribute_escape'
    | 'dom_clobbering'
    | 'mutation_xss'
    | 'dangling_markup'
    | 'css_expression'
    /** The dangerous element */
    element: string
    /** What specifically is dangerous */
    detail: string
    /** Position in input */
    position: number
    /** Confidence (0-1) */
    confidence: number
}


// ── XSS Context Evaluator ────────────────────────────────────────

/**
 * Evaluate an input string for XSS vectors by parsing it as an
 * HTML fragment and analyzing the resulting elements.
 *
 * This catches XSS that regexes miss because it analyzes the
 * STRUCTURE of the injected HTML, not specific character patterns.
 */
export function detectXssVectors(input: string): XssDetection[] {
    const topLevel = extractHtmlElements(htmlTokenize(input))
    const nested = topLevel.flatMap(elem =>
        Object.values(elem.attributes).flatMap(extractNestedMarkupElements),
    )
    const elements = [...topLevel, ...nested]
    const detections: XssDetection[] = []

    for (const elem of elements) {
        detections.push(...detectElementThreats(elem))
    }

    detections.push(...detectDomClobbering(input))
    detections.push(...detectMutationXSS(input))
    detections.push(...detectDanglingMarkup(input))
    detections.push(...detectCssExpressionXss(input))

    return detections
}

export function detectDomClobbering(input: string): XssDetection[] {
    if (
        !DOM_CLOBBERING_RE.test(input)
        && !DOM_CLOBBERING_OWNER_DOC_RE.test(input)
        && !DOM_CLOBBERING_ANCHOR_JS_RE.test(input)
    ) {
        return []
    }

    return [{
        type: 'dom_clobbering',
        element: '<dom-clobbering>',
        detail: 'DOM clobbering via named/id element shadowing critical document globals',
        position: 0,
        confidence: 0.87,
    }]
}

export function detectMutationXSS(input: string): XssDetection[] {
    if (
        !MUTATION_XSS_NOSCRIPT_RE.test(input)
        && !MUTATION_XSS_FOREIGN_OBJECT_RE.test(input)
        && !MUTATION_XSS_MATHML_RE.test(input)
        && !MUTATION_XSS_TEMPLATE_RE.test(input)
    ) {
        return []
    }

    return [{
        type: 'mutation_xss',
        element: '<mutation-xss>',
        detail: 'Potential parser-mutation or namespace confusion XSS pattern',
        position: 0,
        confidence: 0.88,
    }]
}

export function detectDanglingMarkup(input: string): XssDetection[] {
    if (
        !DANGLING_MARKUP_IMG_RE.test(input)
        && !DANGLING_MARKUP_BASE_RE.test(input)
        && !DANGLING_MARKUP_LINK_RE.test(input)
    ) {
        return []
    }

    return [{
        type: 'dangling_markup',
        element: '<dangling-markup>',
        detail: 'Unclosed quoted attribute can steal following markup or data',
        position: 0,
        confidence: 0.82,
    }]
}

export function detectCssExpressionXss(input: string): XssDetection[] {
    if (
        !CSS_EXPRESSION_XSS_RE.test(input)
        && !CSS_MOZ_BINDING_RE.test(input)
        && !CSS_BEHAVIOR_XSS_RE.test(input)
        && !CSS_IMPORT_JS_DATA_RE.test(input)
        && !CSS_URL_JS_DATA_RE.test(input)
    ) {
        return []
    }

    return [{
        type: 'css_expression',
        element: '<css-expression>',
        detail: 'Legacy CSS execution primitive or JavaScript/data URL in CSS context',
        position: 0,
        confidence: 0.86,
    }]
}

function hasDangerousScheme(value: string): boolean {
    const normalized = value.replace(/\s+/g, '').toLowerCase()
    return DANGEROUS_SCHEMES.some(scheme => normalized.startsWith(scheme))
}
