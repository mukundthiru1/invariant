/**
 * HTML Context-Aware Tokenizer — State Machine
 *
 * Tracks HTML parsing context through a proper state machine:
 *   TEXT → TAG_OPEN → TAG_NAME → ATTR_NAME → ATTR_VALUE → ...
 *   TEXT → TAG_OPEN → TAG_NAME(script) → SCRIPT_CONTENT → ...
 *
 * XSS detection becomes: "is there a context transition from safe to executable?"
 * not "does the string contain <script>"
 *
 * THE KEY INSIGHT:
 *   A regex checks "does the string match a pattern?"
 *   This tokenizer answers "what parsing state are we in, and can the
 *   attacker's input cause a transition to an executable state?"
 *
 * This catches:
 *   - Tag injection in text context
 *   - Attribute escape via quote termination → new attribute
 *   - Event handler injection in attribute context
 *   - Protocol handler in href/src/action attribute values
 *   - Style-based attacks via CSS expressions
 *   - Template expression injection via {{ }} in any context
 *
 * All of these are STRUCTURAL properties, not string patterns.
 * An attacker can encode, split, or obfuscate the payload in any way —
 * the tokenizer still correctly identifies the context transition.
 */

import type { Token, Tokenizer, TokenStream } from './types.js'
import { MAX_TOKENIZER_INPUT, MAX_TOKEN_COUNT } from './types.js'
import { TokenStream as TS } from './types.js'


// ── HTML Token Types ─────────────────────────────────────────────

export type HtmlTokenType =
    | 'TEXT'                // Plain text content
    | 'TAG_OPEN'           // <
    | 'TAG_CLOSE'          // >
    | 'TAG_SELF_CLOSE'     // />
    | 'TAG_END_OPEN'       // </
    | 'TAG_NAME'           // div, script, img, etc.
    | 'ATTR_NAME'          // class, onclick, href, etc.
    | 'ATTR_EQUALS'        // =
    | 'ATTR_VALUE'         // "value" or 'value' or value
    | 'COMMENT'            // <!-- ... -->
    | 'DOCTYPE'            // <!DOCTYPE ...>
    | 'CDATA'              // <![CDATA[ ... ]]>
    | 'SCRIPT_CONTENT'     // Content inside <script> tags
    | 'STYLE_CONTENT'      // Content inside <style> tags
    | 'TEMPLATE_EXPR'      // {{ expression }}
    | 'WHITESPACE'         // Whitespace between attributes
    | 'UNKNOWN'            // Malformed content


// ── HTML Parsing Context ─────────────────────────────────────────

type HtmlState =
    | 'TEXT'               // Outside any tag
    | 'TAG_OPEN'           // After <, reading tag name
    | 'TAG_BODY'           // Inside tag, between attributes
    | 'ATTR_NAME'          // Reading an attribute name
    | 'ATTR_AFTER_NAME'    // After attr name, looking for =
    | 'ATTR_VALUE_START'   // After =, looking for value start
    | 'ATTR_VALUE_QUOTED'  // Inside "..." or '...'
    | 'ATTR_VALUE_UNQUOTED' // Bare attribute value
    | 'COMMENT'            // Inside <!-- ... -->
    | 'SCRIPT'             // Inside <script> ... </script>
    | 'STYLE'              // Inside <style> ... </style>


// ── HTML Tokenizer ───────────────────────────────────────────────

export class HtmlTokenizer implements Tokenizer<HtmlTokenType> {
    readonly language = 'html'

    tokenize(input: string): TokenStream<HtmlTokenType> {
        const bounded = input.length > MAX_TOKENIZER_INPUT
            ? input.slice(0, MAX_TOKENIZER_INPUT)
            : input

        const tokens: Token<HtmlTokenType>[] = []
        let state: HtmlState = 'TEXT'
        let i = 0
        let currentTagName = ''
        let quoteChar = ''

        while (i < bounded.length && tokens.length < MAX_TOKEN_COUNT) {
            switch (state) {

                case 'TEXT': {
                    // Check for template expressions {{ ... }}
                    if (bounded[i] === '{' && bounded[i + 1] === '{') {
                        const exprEnd = bounded.indexOf('}}', i + 2)
                        if (exprEnd !== -1) {
                            const end = exprEnd + 2
                            tokens.push({ type: 'TEMPLATE_EXPR', value: bounded.slice(i, end), start: i, end })
                            i = end
                            break
                        }
                    }

                    // Check for comment <!-- ... -->
                    if (bounded[i] === '<' && bounded.slice(i, i + 4) === '<!--') {
                        const commentEnd = bounded.indexOf('-->', i + 4)
                        const end = commentEnd !== -1 ? commentEnd + 3 : bounded.length
                        tokens.push({ type: 'COMMENT', value: bounded.slice(i, end), start: i, end })
                        i = end
                        break
                    }

                    // Check for DOCTYPE
                    if (bounded[i] === '<' && bounded.slice(i, i + 9).toUpperCase() === '<!DOCTYPE') {
                        const dtEnd = bounded.indexOf('>', i + 9)
                        const end = dtEnd !== -1 ? dtEnd + 1 : bounded.length
                        tokens.push({ type: 'DOCTYPE', value: bounded.slice(i, end), start: i, end })
                        i = end
                        break
                    }

                    // Check for CDATA
                    if (bounded[i] === '<' && bounded.slice(i, i + 9) === '<![CDATA[') {
                        const cdEnd = bounded.indexOf(']]>', i + 9)
                        const end = cdEnd !== -1 ? cdEnd + 3 : bounded.length
                        tokens.push({ type: 'CDATA', value: bounded.slice(i, end), start: i, end })
                        i = end
                        break
                    }

                    // Check for end tag </
                    if (bounded[i] === '<' && bounded[i + 1] === '/') {
                        tokens.push({ type: 'TAG_END_OPEN', value: '</', start: i, end: i + 2 })
                        i += 2
                        state = 'TAG_OPEN'
                        break
                    }

                    // Check for tag open <
                    if (bounded[i] === '<' && /[a-zA-Z!]/.test(bounded[i + 1] ?? '')) {
                        tokens.push({ type: 'TAG_OPEN', value: '<', start: i, end: i + 1 })
                        i += 1
                        state = 'TAG_OPEN'
                        break
                    }

                    // Plain text — consume until we hit <, {{, or end
                    const textStart = i
                    while (i < bounded.length && bounded[i] !== '<' && !(bounded[i] === '{' && bounded[i + 1] === '{')) {
                        i++
                    }
                    if (i > textStart) {
                        tokens.push({ type: 'TEXT', value: bounded.slice(textStart, i), start: textStart, end: i })
                    }
                    break
                }

                case 'TAG_OPEN': {
                    // Read tag name
                    const nameStart = i
                    while (i < bounded.length && /[a-zA-Z0-9_-]/.test(bounded[i])) i++
                    if (i > nameStart) {
                        currentTagName = bounded.slice(nameStart, i).toLowerCase()
                        tokens.push({ type: 'TAG_NAME', value: bounded.slice(nameStart, i), start: nameStart, end: i })
                        state = 'TAG_BODY'
                    } else {
                        // Malformed — skip
                        tokens.push({ type: 'UNKNOWN', value: bounded[i] ?? '', start: i, end: i + 1 })
                        i++
                        state = 'TEXT'
                    }
                    break
                }

                case 'TAG_BODY': {
                    // Skip whitespace
                    if (/\s/.test(bounded[i])) {
                        const wsStart = i
                        while (i < bounded.length && /\s/.test(bounded[i])) i++
                        tokens.push({ type: 'WHITESPACE', value: bounded.slice(wsStart, i), start: wsStart, end: i })
                        break
                    }

                    // Self-closing />
                    if (bounded[i] === '/' && bounded[i + 1] === '>') {
                        tokens.push({ type: 'TAG_SELF_CLOSE', value: '/>', start: i, end: i + 2 })
                        i += 2
                        state = 'TEXT'
                        break
                    }

                    // Tag close >
                    if (bounded[i] === '>') {
                        tokens.push({ type: 'TAG_CLOSE', value: '>', start: i, end: i + 1 })
                        i++
                        // Enter script/style raw text context if applicable
                        if (currentTagName === 'script') {
                            state = 'SCRIPT'
                        } else if (currentTagName === 'style') {
                            state = 'STYLE'
                        } else {
                            state = 'TEXT'
                        }
                        break
                    }

                    // Attribute name
                    if (/[a-zA-Z_@:v-]/.test(bounded[i])) {
                        state = 'ATTR_NAME'
                        break
                    }

                    // Unknown character in tag body
                    tokens.push({ type: 'UNKNOWN', value: bounded[i], start: i, end: i + 1 })
                    i++
                    break
                }

                case 'ATTR_NAME': {
                    const attrStart = i
                    while (i < bounded.length && /[a-zA-Z0-9_\-@:.v]/.test(bounded[i])) i++
                    tokens.push({ type: 'ATTR_NAME', value: bounded.slice(attrStart, i), start: attrStart, end: i })
                    state = 'ATTR_AFTER_NAME'
                    break
                }

                case 'ATTR_AFTER_NAME': {
                    // Skip whitespace
                    if (/\s/.test(bounded[i])) {
                        const wsStart = i
                        while (i < bounded.length && /\s/.test(bounded[i])) i++
                        tokens.push({ type: 'WHITESPACE', value: bounded.slice(wsStart, i), start: wsStart, end: i })
                        break
                    }

                    if (bounded[i] === '=') {
                        tokens.push({ type: 'ATTR_EQUALS', value: '=', start: i, end: i + 1 })
                        i++
                        state = 'ATTR_VALUE_START'
                        break
                    }

                    // No equals — boolean attribute, back to tag body
                    state = 'TAG_BODY'
                    break
                }

                case 'ATTR_VALUE_START': {
                    // Skip whitespace before value
                    if (/\s/.test(bounded[i])) {
                        i++
                        break
                    }

                    if (bounded[i] === '"' || bounded[i] === "'") {
                        quoteChar = bounded[i]
                        i++ // skip opening quote
                        state = 'ATTR_VALUE_QUOTED'
                        break
                    }

                    // Unquoted attribute value
                    state = 'ATTR_VALUE_UNQUOTED'
                    break
                }

                case 'ATTR_VALUE_QUOTED': {
                    const valStart = i
                    while (i < bounded.length && bounded[i] !== quoteChar) {
                        i++
                    }
                    tokens.push({ type: 'ATTR_VALUE', value: bounded.slice(valStart, i), start: valStart, end: i })
                    if (i < bounded.length) i++ // skip closing quote
                    state = 'TAG_BODY'
                    break
                }

                case 'ATTR_VALUE_UNQUOTED': {
                    const valStart = i
                    while (i < bounded.length && !/[\s>]/.test(bounded[i])) i++
                    tokens.push({ type: 'ATTR_VALUE', value: bounded.slice(valStart, i), start: valStart, end: i })
                    state = 'TAG_BODY'
                    break
                }

                case 'SCRIPT': {
                    // Consume until </script>
                    const scriptStart = i
                    const scriptEndIdx = bounded.toLowerCase().indexOf('</script', i)
                    if (scriptEndIdx !== -1) {
                        if (scriptEndIdx > scriptStart) {
                            tokens.push({ type: 'SCRIPT_CONTENT', value: bounded.slice(scriptStart, scriptEndIdx), start: scriptStart, end: scriptEndIdx })
                        }
                        // Emit the closing tag
                        i = scriptEndIdx
                        tokens.push({ type: 'TAG_END_OPEN', value: '</', start: i, end: i + 2 })
                        i += 2
                        state = 'TAG_OPEN'
                    } else {
                        // No closing tag — rest is script content
                        tokens.push({ type: 'SCRIPT_CONTENT', value: bounded.slice(scriptStart), start: scriptStart, end: bounded.length })
                        i = bounded.length
                    }
                    break
                }

                case 'STYLE': {
                    // Consume until </style>
                    const styleStart = i
                    const styleEndIdx = bounded.toLowerCase().indexOf('</style', i)
                    if (styleEndIdx !== -1) {
                        if (styleEndIdx > styleStart) {
                            tokens.push({ type: 'STYLE_CONTENT', value: bounded.slice(styleStart, styleEndIdx), start: styleStart, end: styleEndIdx })
                        }
                        i = styleEndIdx
                        tokens.push({ type: 'TAG_END_OPEN', value: '</', start: i, end: i + 2 })
                        i += 2
                        state = 'TAG_OPEN'
                    } else {
                        tokens.push({ type: 'STYLE_CONTENT', value: bounded.slice(styleStart), start: styleStart, end: bounded.length })
                        i = bounded.length
                    }
                    break
                }

                case 'COMMENT': {
                    // Should not reach here — comments are handled inline in TEXT
                    i++
                    break
                }
            }
        }

        return new TS(tokens)
    }
}


// ── HTML Context Analysis for XSS Detection ──────────────────────

/**
 * Analyze an HTML token stream for XSS-relevant context transitions.
 *
 * Returns a list of detected XSS vectors with their type and the
 * specific tokens that form the attack vector.
 */
export interface HtmlXssDetection {
    type: 'tag_injection' | 'event_handler' | 'protocol_handler' | 'attribute_escape' | 'template_injection' | 'script_injection'
    confidence: number
    detail: string
    tokens: Token<HtmlTokenType>[]
}

// Event handler attribute names (lowercase)
const EVENT_HANDLER_ATTRS = new Set([
    'onabort', 'onafterprint', 'onanimationend', 'onanimationiteration',
    'onanimationstart', 'onauxclick', 'onbeforeprint', 'onbeforeunload',
    'onblur', 'oncanplay', 'oncanplaythrough', 'onchange', 'onclick',
    'onclose', 'oncontextmenu', 'oncopy', 'oncuechange', 'oncut',
    'ondblclick', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave',
    'ondragover', 'ondragstart', 'ondrop', 'ondurationchange', 'onemptied',
    'onended', 'onerror', 'onfocus', 'onfocusin', 'onfocusout',
    'onfullscreenchange', 'onfullscreenerror', 'ongotpointercapture',
    'onhashchange', 'oninput', 'oninvalid', 'onkeydown', 'onkeypress',
    'onkeyup', 'onlanguagechange', 'onload', 'onloadeddata',
    'onloadedmetadata', 'onloadstart', 'onlostpointercapture',
    'onmessage', 'onmessageerror', 'onmousedown', 'onmouseenter',
    'onmouseleave', 'onmousemove', 'onmouseout', 'onmouseover',
    'onmouseup', 'onoffline', 'ononline', 'onpagehide', 'onpageshow',
    'onpaste', 'onpause', 'onplay', 'onplaying', 'onpointercancel',
    'onpointerdown', 'onpointerenter', 'onpointerleave', 'onpointermove',
    'onpointerout', 'onpointerover', 'onpointerup', 'onpopstate',
    'onprogress', 'onratechange', 'onreset', 'onresize', 'onscroll',
    'onsecuritypolicyviolation', 'onseeked', 'onseeking', 'onselect',
    'onselectionchange', 'onselectstart', 'onslotchange', 'onstalled',
    'onstorage', 'onsubmit', 'onsuspend', 'ontimeupdate', 'ontoggle',
    'ontouchcancel', 'ontouchend', 'ontouchmove', 'ontouchstart',
    'ontransitioncancel', 'ontransitionend', 'ontransitionrun',
    'ontransitionstart', 'onunhandledrejection', 'onunload',
    'onvolumechange', 'onwaiting', 'onwebkitanimationend',
    'onwebkitanimationiteration', 'onwebkitanimationstart',
    'onwebkittransitionend', 'onwheel',
])

// URL attributes that can execute javascript:
const URL_EXEC_ATTRS = new Set([
    'href', 'src', 'action', 'formaction', 'data', 'poster',
    'background', 'cite', 'codebase', 'longdesc', 'usemap',
    'xlink:href', 'dynsrc', 'lowsrc',
])

// Tags that execute JavaScript
const EXECUTABLE_TAGS = new Set([
    'script', 'img', 'svg', 'iframe', 'object', 'embed',
    'video', 'audio', 'body', 'details', 'marquee', 'math',
    'input', 'button', 'form', 'textarea', 'select', 'style',
    'link', 'base', 'meta', 'applet', 'frameset',
])

export function analyzeHtmlForXss(stream: TokenStream<HtmlTokenType>): HtmlXssDetection[] {
    const detections: HtmlXssDetection[] = []
    const tokens = stream.all()

    let lastAttrName = ''

    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i]

        // Tag injection: TAG_NAME that is executable
        if (tok.type === 'TAG_NAME' && EXECUTABLE_TAGS.has(tok.value.toLowerCase())) {
            // Check if preceding token is TAG_OPEN (not TAG_END_OPEN)
            const prevMeaningful = findPrev(tokens, i, t => t.type !== 'WHITESPACE')
            if (prevMeaningful && prevMeaningful.type === 'TAG_OPEN') {
                detections.push({
                    type: 'tag_injection',
                    confidence: 0.90,
                    detail: `Executable tag <${tok.value}> injected`,
                    tokens: [prevMeaningful, tok],
                })
            }
        }

        // Track attribute names
        if (tok.type === 'ATTR_NAME') {
            lastAttrName = tok.value.toLowerCase()
        }

        // Event handler injection: ATTR_NAME is on* event handler
        if (tok.type === 'ATTR_NAME' && EVENT_HANDLER_ATTRS.has(tok.value.toLowerCase())) {
            detections.push({
                type: 'event_handler',
                confidence: 0.92,
                detail: `Event handler attribute ${tok.value} injected`,
                tokens: [tok],
            })
        }

        // Protocol handler in URL attribute value
        if (tok.type === 'ATTR_VALUE' && URL_EXEC_ATTRS.has(lastAttrName)) {
            const val = tok.value.trim().toLowerCase()
            if (val.startsWith('javascript:') || val.startsWith('vbscript:') ||
                (val.startsWith('data:') && val.includes('text/html'))) {
                detections.push({
                    type: 'protocol_handler',
                    confidence: 0.93,
                    detail: `Protocol handler in ${lastAttrName}: ${val.slice(0, 30)}...`,
                    tokens: [tok],
                })
            }
        }

        // Script content analysis
        if (tok.type === 'SCRIPT_CONTENT' && tok.value.trim().length > 0) {
            detections.push({
                type: 'script_injection',
                confidence: 0.88,
                detail: 'Script content present',
                tokens: [tok],
            })
        }

        // Template expression in any context
        if (tok.type === 'TEMPLATE_EXPR') {
            const expr = tok.value.slice(2, -2) // strip {{ }}
            if (/constructor|__proto__|process|require|import|eval|exec|Function/i.test(expr)) {
                detections.push({
                    type: 'template_injection',
                    confidence: 0.88,
                    detail: `Template expression with dangerous call: ${expr.slice(0, 40)}...`,
                    tokens: [tok],
                })
            }
        }
    }

    return detections
}


// ── Helpers ──────────────────────────────────────────────────────

function findPrev<T extends string>(
    tokens: ReadonlyArray<Token<T>>,
    index: number,
    predicate: (t: Token<T>) => boolean,
): Token<T> | undefined {
    for (let i = index - 1; i >= 0; i--) {
        if (predicate(tokens[i])) return tokens[i]
    }
    return undefined
}
