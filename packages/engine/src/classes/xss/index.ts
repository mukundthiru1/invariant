/**
 * XSS Invariant Classes — Barrel Export
 */
import type { InvariantClassModule } from '../types.js'
import { xssTagInjection } from './tag-injection.js'
import { xssEventHandler } from './event-handler.js'
import { xssAttributeEscape } from './attribute-escape.js'
import { xssProtocolHandler } from './protocol-handler.js'
import { xssTemplateExpression } from './template-expression.js'
import { xssDomXss } from './dom-xss.js'
import { xssAngularjsSandboxEscape } from './angularjs-sandbox-escape.js'
import { xssCssInjection } from './css-injection.js'

export const XSS_CLASSES: InvariantClassModule[] = [
    xssTagInjection,
    xssEventHandler,
    xssProtocolHandler,
    xssTemplateExpression,
    xssAttributeEscape,
    xssDomXss,
    xssAngularjsSandboxEscape,
    xssCssInjection,
]

export {
    xssTagInjection,
    xssEventHandler,
    xssAttributeEscape,
    xssProtocolHandler,
    xssTemplateExpression,
    xssDomXss,
    xssAngularjsSandboxEscape,
    xssCssInjection,
}
