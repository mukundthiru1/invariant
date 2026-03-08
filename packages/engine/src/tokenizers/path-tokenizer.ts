/**
 * Path Tokenizer — Directory Traversal Detection
 *
 * Tokenizes input as a file path to detect traversal patterns:
 *   - Directory traversal sequences (../, ..\\, encoded variants)
 *   - Sensitive file targets (/etc/passwd, /proc/self/environ, etc.)
 *   - Null byte injection (%00, \x00)
 *   - Extension spoofing (shell.php%00.jpg)
 *   - Path normalization tricks (trailing dots, semicolon params)
 *   - Multi-layer encoding (%252e = double-encoded dot)
 *
 * Path traversal detection becomes: "does the token stream contain
 * TRAVERSAL tokens followed by SENSITIVE_TARGET?" rather than matching
 * regex patterns against known paths.
 */

import type { Token, Tokenizer, TokenStream } from './types.js'
import { MAX_TOKENIZER_INPUT, MAX_TOKEN_COUNT } from './types.js'
import { TokenStream as TS } from './types.js'


// ── Path Token Types ────────────────────────────────────────────

export type PathTokenType =
    | 'SEPARATOR'           // / or \
    | 'TRAVERSAL'           // .. (dotdot)
    | 'CURRENT_DIR'         // . (single dot)
    | 'SEGMENT'             // Normal path segment name
    | 'SENSITIVE_TARGET'    // /etc/passwd, /proc/self/environ, etc.
    | 'NULL_BYTE'           // %00, \x00, \0
    | 'EXTENSION'           // .jpg, .php, etc.
    | 'ENCODING_LAYER'      // %2e, %252e, %c0%ae — encoded special chars
    | 'PARAM_INJECTION'     // ;jsessionid=x (Tomcat path param)
    | 'TRAILING_DOT'        // Trailing dots (IIS normalization)
    | 'WHITESPACE'          // Spaces
    | 'UNKNOWN'             // Malformed content


// ── Sensitive System Paths ──────────────────────────────────────

const SENSITIVE_PATHS: ReadonlyArray<{ pattern: RegExp; description: string }> = [
    // Unix
    { pattern: /^etc\/passwd$/i, description: 'Unix password file' },
    { pattern: /^etc\/shadow$/i, description: 'Unix shadow password file' },
    { pattern: /^etc\/hosts$/i, description: 'Unix hosts file' },
    { pattern: /^etc\/(?:issue|motd|resolv\.conf|crontab|sudoers)$/i, description: 'Unix system config' },
    { pattern: /^proc\/self\/(?:environ|cmdline|maps|status|fd)$/i, description: 'Linux proc filesystem' },
    { pattern: /^proc\/\d+\/(?:environ|cmdline|maps)$/i, description: 'Linux proc PID' },
    // Web
    { pattern: /^\.env$/i, description: 'Environment variables file' },
    { pattern: /^\.git\/(?:config|HEAD|index|objects|refs)$/i, description: 'Git repository internals' },
    { pattern: /^\.ssh\/(?:id_rsa|id_ed25519|authorized_keys|known_hosts)$/i, description: 'SSH keys' },
    { pattern: /^\.aws\/credentials$/i, description: 'AWS credentials' },
    { pattern: /^\.docker\/config\.json$/i, description: 'Docker credentials' },
    // Windows
    { pattern: /^windows\/(?:system32|win\.ini|system\.ini)$/i, description: 'Windows system file' },
    { pattern: /^boot\.ini$/i, description: 'Windows boot configuration' },
    { pattern: /^inetpub\/wwwroot\/web\.config$/i, description: 'IIS web config' },
    // Web frameworks
    { pattern: /^wp-config\.php$/i, description: 'WordPress config' },
    { pattern: /^web\.config$/i, description: 'ASP.NET config' },
    { pattern: /^config\/database\.yml$/i, description: 'Rails database config' },
    { pattern: /^\.htaccess$/i, description: 'Apache config' },
    { pattern: /^\.htpasswd$/i, description: 'Apache password file' },
]


// ── Encoding Detection ──────────────────────────────────────────

function decodePathEncoding(segment: string): { decoded: string; layers: number } {
    let current = segment
    let layers = 0
    const maxLayers = 4 // Prevent infinite loops on pathological input

    while (layers < maxLayers) {
        const decoded = current.replace(/%([0-9a-fA-F]{2})/g, (_, hex) =>
            String.fromCharCode(parseInt(hex, 16)),
        )
        if (decoded === current) break
        current = decoded
        layers++
    }

    return { decoded: current, layers }
}

function isEncodedSpecial(segment: string): boolean {
    // %2e = dot, %2f = /, %5c = \, %00 = null
    return /%(?:2[eEfF]|5[cC]|00|c0%(?:ae|af)|e0%80%ae|252[eEfF])/i.test(segment)
}


// ── Path Tokenizer ──────────────────────────────────────────────

export class PathTokenizer implements Tokenizer<PathTokenType> {
    readonly language = 'path'

    tokenize(input: string): TokenStream<PathTokenType> {
        const bounded = input.length > MAX_TOKENIZER_INPUT
            ? input.slice(0, MAX_TOKENIZER_INPUT)
            : input
        const tokens: Token<PathTokenType>[] = []

        // First, decode the entire input to find the structural path
        const { decoded, layers: encodingLayers } = decodePathEncoding(bounded)
        const workInput = decoded

        let i = 0

        while (i < workInput.length && tokens.length < MAX_TOKEN_COUNT) {
            // Null byte
            if (workInput[i] === '\0' || workInput.slice(i, i + 3) === '%00' || workInput.slice(i, i + 4) === '\\x00') {
                const len = workInput[i] === '\0' ? 1 : workInput.slice(i, i + 3) === '%00' ? 3 : 4
                tokens.push({ type: 'NULL_BYTE', value: workInput.slice(i, i + len), start: i, end: i + len })
                i += len
                continue
            }

            // Path separator
            if (workInput[i] === '/' || workInput[i] === '\\') {
                tokens.push({ type: 'SEPARATOR', value: workInput[i], start: i, end: i + 1 })
                i++
                continue
            }

            // Whitespace
            if (/\s/.test(workInput[i])) {
                const start = i
                while (i < workInput.length && /\s/.test(workInput[i])) i++
                tokens.push({ type: 'WHITESPACE', value: workInput.slice(start, i), start, end: i })
                continue
            }

            // Semicolon (Tomcat path parameter injection)
            if (workInput[i] === ';') {
                const start = i
                i++
                while (i < workInput.length && workInput[i] !== '/' && workInput[i] !== '\\') i++
                tokens.push({ type: 'PARAM_INJECTION', value: workInput.slice(start, i), start, end: i })
                continue
            }

            // Consume a segment (until next separator, null, semicolon, or whitespace)
            const segStart = i
            while (i < workInput.length && !/[\\/;\s\0]/.test(workInput[i])) i++
            const segment = workInput.slice(segStart, i)

            if (segment === '..') {
                tokens.push({ type: 'TRAVERSAL', value: segment, start: segStart, end: i })
            } else if (segment === '.') {
                tokens.push({ type: 'CURRENT_DIR', value: segment, start: segStart, end: i })
            } else if (segment.endsWith('.') && segment.length > 1 && !/\.\w+$/.test(segment.replace(/\.+$/, ''))) {
                // Trailing dots (IIS normalization trick)
                tokens.push({ type: 'TRAILING_DOT', value: segment, start: segStart, end: i })
            } else if (segment.length > 0) {
                // Check if this segment starts a sensitive path sequence
                const remainingPath = this.extractPathFromHere(workInput, segStart)
                const sensitiveMatch = SENSITIVE_PATHS.find(sp => sp.pattern.test(remainingPath))

                if (sensitiveMatch) {
                    // Consume the entire sensitive path as one token
                    const fullEnd = segStart + remainingPath.length
                    const actualEnd = Math.min(fullEnd, workInput.length)
                    tokens.push({
                        type: 'SENSITIVE_TARGET',
                        value: workInput.slice(segStart, actualEnd),
                        start: segStart,
                        end: actualEnd,
                    })
                    i = actualEnd
                } else {
                    // Check for encoding layers in the original input
                    const origSegment = bounded.slice(segStart, i)
                    if (isEncodedSpecial(origSegment) || encodingLayers > 1) {
                        tokens.push({ type: 'ENCODING_LAYER', value: segment, start: segStart, end: i })
                    } else {
                        // Check for file extension
                        const extMatch = segment.match(/\.(\w{1,8})$/)
                        if (extMatch && segStart > 0) {
                            tokens.push({ type: 'SEGMENT', value: segment, start: segStart, end: i })
                        } else {
                            tokens.push({ type: 'SEGMENT', value: segment, start: segStart, end: i })
                        }
                    }
                }
            }
        }

        return new TS(tokens)
    }

    private extractPathFromHere(input: string, start: number): string {
        let end = start
        while (end < input.length && !/[\s?#\0]/.test(input[end])) end++
        // Remove leading separator and normalize backslashes to forward slashes
        let path = input.slice(start, end)
        path = path.replace(/^[\\/]+/, '').replace(/\\/g, '/')
        return path
    }
}

export function pathTokenize(input: string): readonly Token<PathTokenType>[] {
    return new PathTokenizer().tokenize(input).all()
}

export const pathTokenizer = new PathTokenizer()
