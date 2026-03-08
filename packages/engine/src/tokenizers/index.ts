/**
 * Tokenizer Infrastructure — Barrel Export
 *
 * Provides unified access to all language tokenizers:
 *   - SQL tokenizer (from existing L2 evaluator)
 *   - HTML tokenizer (new: context-aware state machine)
 *   - Shell tokenizer (new: command injection detection)
 *   - Template tokenizer (new: multi-engine SSTI detection)
 *
 * Each tokenizer produces a TokenStream<T> that can be analyzed
 * structurally for invariant properties.
 */

// Framework
export {
    type Token,
    type Tokenizer,
    type TokenizeResult,
    TokenStream,
    MAX_TOKENIZER_INPUT,
    MAX_TOKEN_COUNT,
    tokenizeWithDiagnostics,
} from './types.js'

// HTML
export {
    HtmlTokenizer,
    analyzeHtmlForXss,
    type HtmlTokenType,
    type HtmlXssDetection,
} from './html-tokenizer.js'

// Shell
export {
    ShellTokenizer,
    analyzeShellForInjection,
    type ShellTokenType,
    type ShellInjectionDetection,
} from './shell-tokenizer.js'

// Template
export {
    TemplateTokenizer,
    analyzeTemplateForSsti,
    type TemplateTokenType,
    type TemplateEngine,
    type TemplateSstiDetection,
} from './template-tokenizer.js'

// URL
export {
    UrlTokenizer,
    urlTokenize,
    type UrlTokenType,
} from './url-tokenizer.js'

// Path
export {
    PathTokenizer,
    pathTokenize,
    type PathTokenType,
} from './path-tokenizer.js'

// SQL tokenizer is already in evaluators/sql-expression-evaluator.ts
// Re-export for unified access
export {
    sqlTokenize,
    type SqlTokenType,
    type SqlToken,
} from '../evaluators/sql-expression-evaluator.js'
