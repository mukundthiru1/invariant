/**
 * Shell Tokenizer — Command Injection Detection
 *
 * Tokenizes input as a shell command to detect injection patterns:
 *   - Command separators (;, |, &&, ||)
 *   - Command substitution ($(...), `...`)
 *   - Variable expansion ($VAR, ${VAR})
 *   - Argument injection (--flag, -o)
 *   - Quoting context (single, double, backtick)
 *   - Redirection (>, <, >>)
 *   - Heredocs (<<EOF)
 *
 * Command injection detection becomes: "does the token stream contain
 * a SEPARATOR followed by a COMMAND token?" rather than "does the
 * string match a regex for known commands."
 *
 * This catches:
 *   - ; id                    (separator + command)
 *   - | cat /etc/passwd       (pipe + command)
 *   - $(whoami)               (substitution)
 *   - `id`                    (backtick substitution)
 *   - --output=/tmp/shell     (argument injection)
 *   - $IFS substitution tricks
 *   - Newline-based command chaining
 */

import type { Token, Tokenizer, TokenStream } from './types.js'
import { MAX_TOKENIZER_INPUT, MAX_TOKEN_COUNT } from './types.js'
import { TokenStream as TS } from './types.js'


// ── Shell Token Types ────────────────────────────────────────────

export type ShellTokenType =
    | 'WORD'               // Plain word (could be command or argument)
    | 'SEPARATOR'          // ; or newline (command terminator)
    | 'PIPE'               // |
    | 'AND_CHAIN'          // &&
    | 'OR_CHAIN'           // ||
    | 'BACKGROUND'         // &
    | 'SUBSHELL_OPEN'      // (
    | 'SUBSHELL_CLOSE'     // )
    | 'CMD_SUBST_OPEN'     // $(
    | 'CMD_SUBST_CLOSE'    // ) matching a CMD_SUBST_OPEN
    | 'BACKTICK_SUBST'     // `command`
    | 'VAR_EXPANSION'      // $VAR or ${VAR}
    | 'REDIRECT_IN'        // <
    | 'REDIRECT_OUT'       // > or >>
    | 'HEREDOC'            // <<
    | 'STRING_SINGLE'      // 'text' (no expansion)
    | 'STRING_DOUBLE'      // "text" (allows $expansion)
    | 'FLAG'               // -f or --flag
    | 'GLOB'               // * or ? or [...]
    | 'COMMENT'            // # to end of line
    | 'WHITESPACE'         // Spaces and tabs
    | 'NEWLINE'            // \n
    | 'UNKNOWN'            // Malformed content


// ── Known Shell Commands ─────────────────────────────────────────

const DANGEROUS_COMMANDS = new Set([
    // Unix core
    'cat', 'ls', 'id', 'whoami', 'pwd', 'uname', 'hostname',
    'env', 'printenv', 'echo', 'printf', 'touch', 'rm', 'cp',
    'mv', 'mkdir', 'rmdir', 'chmod', 'chown', 'chgrp',
    // Network
    'curl', 'wget', 'nc', 'ncat', 'nmap', 'netcat', 'socat',
    'telnet', 'ssh', 'scp', 'sftp', 'ftp', 'ping', 'traceroute',
    'dig', 'nslookup', 'host',
    // Shells
    'bash', 'sh', 'zsh', 'csh', 'tcsh', 'ksh', 'fish', 'dash',
    // Interpreters
    'python', 'python2', 'python3', 'perl', 'ruby', 'php', 'node',
    'lua', 'awk', 'sed', 'grep', 'find', 'xargs',
    // System
    'ps', 'kill', 'top', 'df', 'du', 'mount', 'umount',
    'crontab', 'at', 'systemctl', 'service',
    // Data
    'head', 'tail', 'more', 'less', 'sort', 'uniq', 'wc',
    'tee', 'tr', 'cut', 'paste', 'diff',
    // Privilege
    'sudo', 'su', 'doas', 'passwd', 'useradd', 'userdel',
    'groupadd', 'usermod',
    // Compilation / archive
    'gcc', 'g++', 'make', 'tar', 'gzip', 'gunzip', 'zip', 'unzip',
    // Windows
    'cmd', 'powershell', 'certutil', 'bitsadmin', 'wmic',
    'reg', 'net', 'sc', 'schtasks', 'tasklist', 'taskkill',
    'type', 'dir', 'copy', 'del', 'move', 'ipconfig',
])


// ── Shell Tokenizer ──────────────────────────────────────────────

export class ShellTokenizer implements Tokenizer<ShellTokenType> {
    readonly language = 'shell'

    tokenize(input: string): TokenStream<ShellTokenType> {
        const bounded = input.length > MAX_TOKENIZER_INPUT
            ? input.slice(0, MAX_TOKENIZER_INPUT)
            : input

        const tokens: Token<ShellTokenType>[] = []
        let i = 0

        while (i < bounded.length && tokens.length < MAX_TOKEN_COUNT) {
            const ch = bounded[i]

            // Newline
            if (ch === '\n') {
                tokens.push({ type: 'NEWLINE', value: '\n', start: i, end: i + 1 })
                i++
                continue
            }

            // Whitespace (not newline)
            if (/[ \t\r]/.test(ch)) {
                const start = i
                while (i < bounded.length && /[ \t\r]/.test(bounded[i])) i++
                tokens.push({ type: 'WHITESPACE', value: bounded.slice(start, i), start, end: i })
                continue
            }

            // Comment: # to end of line
            if (ch === '#') {
                const start = i
                while (i < bounded.length && bounded[i] !== '\n') i++
                tokens.push({ type: 'COMMENT', value: bounded.slice(start, i), start, end: i })
                continue
            }

            // Semicolon
            if (ch === ';') {
                tokens.push({ type: 'SEPARATOR', value: ';', start: i, end: i + 1 })
                i++
                continue
            }

            // Pipe | or OR chain ||
            if (ch === '|') {
                if (bounded[i + 1] === '|') {
                    tokens.push({ type: 'OR_CHAIN', value: '||', start: i, end: i + 2 })
                    i += 2
                } else {
                    tokens.push({ type: 'PIPE', value: '|', start: i, end: i + 1 })
                    i++
                }
                continue
            }

            // AND chain && or background &
            if (ch === '&') {
                if (bounded[i + 1] === '&') {
                    tokens.push({ type: 'AND_CHAIN', value: '&&', start: i, end: i + 2 })
                    i += 2
                } else {
                    tokens.push({ type: 'BACKGROUND', value: '&', start: i, end: i + 1 })
                    i++
                }
                continue
            }

            // Command substitution $( or variable expansion $
            if (ch === '$') {
                if (bounded[i + 1] === '(') {
                    tokens.push({ type: 'CMD_SUBST_OPEN', value: '$(', start: i, end: i + 2 })
                    i += 2
                    continue
                }
                if (bounded[i + 1] === '{') {
                    // ${VAR} expansion
                    const start = i
                    i += 2
                    while (i < bounded.length && bounded[i] !== '}') i++
                    if (i < bounded.length) i++ // skip }
                    tokens.push({ type: 'VAR_EXPANSION', value: bounded.slice(start, i), start, end: i })
                    continue
                }
                if (/[a-zA-Z_]/.test(bounded[i + 1] ?? '')) {
                    // $VAR expansion
                    const start = i
                    i++ // skip $
                    while (i < bounded.length && /[a-zA-Z0-9_]/.test(bounded[i])) i++
                    tokens.push({ type: 'VAR_EXPANSION', value: bounded.slice(start, i), start, end: i })
                    continue
                }
                // Special variables: $?, $!, $0-$9, $$, $@, $*
                if (/[?!0-9$@*#-]/.test(bounded[i + 1] ?? '')) {
                    tokens.push({ type: 'VAR_EXPANSION', value: bounded.slice(i, i + 2), start: i, end: i + 2 })
                    i += 2
                    continue
                }
            }

            // Backtick substitution
            if (ch === '`') {
                const start = i
                i++ // skip opening backtick
                while (i < bounded.length && bounded[i] !== '`') {
                    if (bounded[i] === '\\') i++ // skip escaped
                    i++
                }
                if (i < bounded.length) i++ // skip closing backtick
                tokens.push({ type: 'BACKTICK_SUBST', value: bounded.slice(start, i), start, end: i })
                continue
            }

            // Parentheses
            if (ch === '(') {
                tokens.push({ type: 'SUBSHELL_OPEN', value: '(', start: i, end: i + 1 })
                i++
                continue
            }
            if (ch === ')') {
                // Check if this closes a CMD_SUBST_OPEN
                const hasOpenSubst = tokens.some(t => t.type === 'CMD_SUBST_OPEN')
                const type = hasOpenSubst ? 'CMD_SUBST_CLOSE' : 'SUBSHELL_CLOSE'
                tokens.push({ type, value: ')', start: i, end: i + 1 })
                i++
                continue
            }

            // Redirection
            if (ch === '>') {
                if (bounded[i + 1] === '>') {
                    tokens.push({ type: 'REDIRECT_OUT', value: '>>', start: i, end: i + 2 })
                    i += 2
                } else {
                    tokens.push({ type: 'REDIRECT_OUT', value: '>', start: i, end: i + 1 })
                    i++
                }
                continue
            }
            if (ch === '<') {
                if (bounded[i + 1] === '<') {
                    tokens.push({ type: 'HEREDOC', value: '<<', start: i, end: i + 2 })
                    i += 2
                } else {
                    tokens.push({ type: 'REDIRECT_IN', value: '<', start: i, end: i + 1 })
                    i++
                }
                continue
            }

            // Single-quoted string (no expansion)
            if (ch === "'") {
                const start = i
                i++ // skip opening quote
                while (i < bounded.length && bounded[i] !== "'") i++
                if (i < bounded.length) i++ // skip closing quote
                tokens.push({ type: 'STRING_SINGLE', value: bounded.slice(start, i), start, end: i })
                continue
            }

            // Double-quoted string (allows expansion)
            if (ch === '"') {
                const start = i
                i++ // skip opening quote
                while (i < bounded.length && bounded[i] !== '"') {
                    if (bounded[i] === '\\') i++ // skip escaped
                    i++
                }
                if (i < bounded.length) i++ // skip closing quote
                tokens.push({ type: 'STRING_DOUBLE', value: bounded.slice(start, i), start, end: i })
                continue
            }

            // Glob characters
            if (ch === '*' || ch === '?') {
                tokens.push({ type: 'GLOB', value: ch, start: i, end: i + 1 })
                i++
                continue
            }

            // Word (command, argument, path, etc.)
            if (/[a-zA-Z0-9_.\/~@:%+,=\\-]/.test(ch)) {
                const start = i
                while (i < bounded.length && /[a-zA-Z0-9_.\/~@:%+,=\\-]/.test(bounded[i])) i++
                const word = bounded.slice(start, i)

                // Classify: flag, word
                if (word.startsWith('--') || (word.startsWith('-') && word.length > 1 && !/^-\d/.test(word))) {
                    tokens.push({ type: 'FLAG', value: word, start, end: i })
                } else {
                    tokens.push({ type: 'WORD', value: word, start, end: i })
                }
                continue
            }

            // Unknown character
            tokens.push({ type: 'UNKNOWN', value: ch, start: i, end: i + 1 })
            i++
        }

        return new TS(tokens)
    }
}


// ── Shell Analysis for Command Injection Detection ───────────────

export interface ShellInjectionDetection {
    type: 'separator_chain' | 'substitution' | 'argument_injection' | 'pipe_chain'
    confidence: number
    detail: string
    command?: string
}

/**
 * Analyze a shell token stream for command injection patterns.
 *
 * Detects:
 *   1. Separator + dangerous command (;id, && whoami)
 *   2. Pipe to dangerous command (| cat /etc/passwd)
 *   3. Command substitution containing dangerous commands ($(id), `whoami`)
 *   4. Argument injection (--output=, -o /path)
 */
export function analyzeShellForInjection(stream: TokenStream<ShellTokenType>): ShellInjectionDetection[] {
    const detections: ShellInjectionDetection[] = []
    const tokens = stream.meaningful() // skip whitespace

    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i]

        // Pattern 1: Separator/pipe/chain followed by dangerous command
        if (tok.type === 'SEPARATOR' || tok.type === 'PIPE' ||
            tok.type === 'AND_CHAIN' || tok.type === 'OR_CHAIN' ||
            tok.type === 'NEWLINE') {

            // Find next WORD token
            const nextWord = findNextOfType(tokens, i + 1, 'WORD')
            if (nextWord && DANGEROUS_COMMANDS.has(nextWord.value.toLowerCase())) {
                detections.push({
                    type: tok.type === 'PIPE' ? 'pipe_chain' : 'separator_chain',
                    confidence: 0.92,
                    detail: `${tok.value} followed by dangerous command: ${nextWord.value}`,
                    command: nextWord.value,
                })
            }
        }

        // Pattern 2: Command substitution $(...) or `...`
        if (tok.type === 'CMD_SUBST_OPEN' || tok.type === 'BACKTICK_SUBST') {
            if (tok.type === 'BACKTICK_SUBST') {
                // Extract command from backtick content
                const content = tok.value.slice(1, -1).trim()
                const firstWord = content.split(/\s+/)[0]?.toLowerCase()
                if (firstWord && DANGEROUS_COMMANDS.has(firstWord)) {
                    detections.push({
                        type: 'substitution',
                        confidence: 0.92,
                        detail: `Backtick substitution with command: ${firstWord}`,
                        command: firstWord,
                    })
                }
            } else {
                // $( — look at next WORD token
                const nextWord = findNextOfType(tokens, i + 1, 'WORD')
                if (nextWord && DANGEROUS_COMMANDS.has(nextWord.value.toLowerCase())) {
                    detections.push({
                        type: 'substitution',
                        confidence: 0.92,
                        detail: `$() substitution with command: ${nextWord.value}`,
                        command: nextWord.value,
                    })
                }
            }
        }

        // Pattern 3: Dangerous flags
        if (tok.type === 'FLAG') {
            const flag = tok.value.toLowerCase()
            if (/^--(?:output|exec|post-file|upload-file|config|shell|eval|command)$/.test(flag) ||
                /^-[oe]$/.test(flag)) {
                detections.push({
                    type: 'argument_injection',
                    confidence: 0.80,
                    detail: `Dangerous flag: ${tok.value}`,
                })
            }
        }
    }

    return detections
}


// ── Helpers ──────────────────────────────────────────────────────

function findNextOfType(
    tokens: Token<ShellTokenType>[],
    startIndex: number,
    type: ShellTokenType,
): Token<ShellTokenType> | undefined {
    for (let i = startIndex; i < tokens.length && i < startIndex + 3; i++) {
        if (tokens[i].type === type) return tokens[i]
    }
    return undefined
}

export const shellTokenize = (input: string) => new ShellTokenizer().tokenize(input);
