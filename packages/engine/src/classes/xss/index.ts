/**
 * XSS Invariant Classes — Barrel Export
 */
import type { InvariantClassModule } from '../types.js'
import { xssTagInjection } from './tag-injection.js'
import { xssEventHandler } from './event-handler.js'
import { xssAttributeEscape } from './attribute-escape.js'
import { xssProtocolHandler } from './protocol-handler.js'
import { xssTemplateExpression } from './template-expression.js'

export const XSS_CLASSES: InvariantClassModule[] = [
    xssTagInjection,
    xssEventHandler,
    xssProtocolHandler,
    xssTemplateExpression,
    xssAttributeEscape,
]

export { xssTagInjection, xssEventHandler, xssAttributeEscape, xssProtocolHandler, xssTemplateExpression }
