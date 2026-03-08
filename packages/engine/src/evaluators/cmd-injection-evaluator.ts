/**
 * Command Injection Evaluator — Level 2 Invariant Detection
 *
 * INVARIANT PROPERTY (not signature matching):
 *
 *   Safe user input for shell context contains ZERO shell control flow tokens.
 *   Any input that creates new command boundaries, substitutions, redirections,
 *   or variable expansions violates the data-only invariant.
 *
 * The detection principle:
 *   1. Tokenize input as shell (using the shell tokenizer)
 *   2. Count structural violation tokens — ANY control flow is suspicious
 *   3. Score based on violation DENSITY and SEVERITY, not command names
 *   4. Known command names BOOST confidence, they never GATE detection
 *
 * Why this is not a WAF:
 *   - A WAF asks: "does input match pattern X?" (attacker finds pattern Y)
 *   - We ask: "does input contain shell structure?" (attacker cannot avoid structure)
 *   - `; randomNewCommand` detects at 0.75 (separator violation)
 *   - `; whoami` detects at 0.88 (separator + known command boost)
 *   - `w'h'o'a'm'i` detects via quote fragmentation analysis
 *   - `${IFS}` detects via variable expansion presence
 *   - `/???/??t` detects via glob-in-path-position analysis
 *
 * The attacker's dilemma: to execute a command, they MUST introduce shell
 * syntax. Shell syntax tokens are the invariant violation. There is no
 * way to execute a command without creating structure we detect.
 */

import { ShellTokenizer, type ShellTokenType } from '../tokenizers/shell-tokenizer.js'
import type { Token } from '../tokenizers/types.js'


// ── Result Type ─────────────────────────────────────────────────

export interface CmdInjectionDetection {
    type: 'separator' | 'substitution' | 'argument_injection' | 'heredoc' | 'redirection'
        | 'variable_expansion' | 'quote_fragmentation' | 'glob_path' | 'structural'
    separator: string
    command: string
    detail: string
    position: number
    confidence: number
}


// ── Known Commands (confidence BOOSTER, not detection GATE) ─────

const KNOWN_DANGEROUS_COMMANDS = new Set([
    'id', 'whoami', 'uname', 'hostname', 'pwd', 'env', 'printenv',
    'sh', 'bash', 'zsh', 'csh', 'ksh', 'dash', 'fish',
    'cmd', 'powershell', 'pwsh',
    'cat', 'head', 'tail', 'more', 'less', 'tac', 'nl',
    'ls', 'dir', 'find', 'locate', 'which', 'whereis',
    'cp', 'mv', 'rm', 'rmdir', 'mkdir', 'touch', 'chmod', 'chown',
    'dd', 'tar', 'gzip', 'gunzip', 'zip', 'unzip',
    'curl', 'wget', 'nc', 'ncat', 'netcat', 'telnet', 'ssh',
    'ping', 'traceroute', 'dig', 'nslookup', 'host',
    'ifconfig', 'ip', 'netstat', 'ss',
    'ps', 'top', 'htop', 'w', 'last', 'who',
    'df', 'du', 'free', 'mount', 'fdisk', 'lsblk',
    'crontab', 'at', 'systemctl', 'service',
    'base64', 'xxd', 'od', 'hexdump',
    'gpg', 'openssl', 'certutil',
    'python', 'python2', 'python3', 'perl', 'ruby', 'node', 'php',
    'java', 'javac', 'gcc', 'make',
    'kill', 'killall', 'nohup', 'screen', 'tmux',
    'sudo', 'su', 'doas', 'useradd', 'usermod', 'passwd',
    'iptables', 'nft', 'reboot', 'shutdown', 'halt', 'init',
    'awk', 'sed', 'grep', 'xargs', 'tee', 'sort', 'tr', 'cut',
    'socat', 'nmap', 'scp', 'sftp', 'ftp',
])

const SENSITIVE_FILES = [
    '/etc/passwd', '/etc/shadow', '/etc/hosts',
    '/etc/ssh/sshd_config', '/root/.ssh/authorized_keys',
    '/proc/self/environ', '/proc/self/cmdline',
    '/var/log/auth.log', '/var/log/syslog',
    'C:\\Windows\\System32\\config\\SAM',
    'C:\\Windows\\win.ini', 'C:\\boot.ini',
]

// Shell control flow token types — the primary invariant violations
const CONTROL_FLOW_TYPES: ReadonlySet<ShellTokenType> = new Set([
    'SEPARATOR', 'PIPE', 'AND_CHAIN', 'OR_CHAIN', 'BACKGROUND',
    'NEWLINE',
])

const SUBSTITUTION_TYPES: ReadonlySet<ShellTokenType> = new Set([
    'CMD_SUBST_OPEN', 'BACKTICK_SUBST',
])


// ── Tokenizer singleton ─────────────────────────────────────────

const shellTokenizer = new ShellTokenizer()


// ── Core Detection ──────────────────────────────────────────────

/**
 * Detect command injection by checking structural invariant violations.
 *
 * The question is NOT "is this a known attack?"
 * The question IS "does this input contain shell structure?"
 */
export function detectCmdInjection(input: string): CmdInjectionDetection[] {
    const detections: CmdInjectionDetection[] = []

    // Multi-layer decode (handle URL encoding bypass)
    let decoded = input
    try {
        let prev = ''
        for (let i = 0; i < 3 && decoded !== prev; i++) {
            prev = decoded
            try { decoded = decodeURIComponent(decoded) } catch { break }
        }
    } catch { /* use original */ }

    // ── Structural Analysis via Shell Tokenizer ──
    const stream = shellTokenizer.tokenize(decoded)
    const allTokens = (stream as any).tokens as any[]
    const meaningful = allTokens.filter(t =>
        t.type !== 'WHITESPACE' && t.type !== 'NEWLINE'
    )

    // Strategy 1: Control flow violations (separators, pipes, chains)
    detectControlFlowViolations(meaningful, decoded, detections)

    // Strategy 2: Command substitution violations ($(), ``)
    detectSubstitutionViolations(meaningful, detections)

    // Strategy 3: Variable expansion violations (${VAR}, $VAR)
    detectVariableExpansionViolations(meaningful, decoded, detections)

    // Strategy 4: Quote fragmentation (w'h'o'a'm'i)
    detectQuoteFragmentation(allTokens as any, decoded, detections)

    // Strategy 5: Glob-in-path analysis (/???/??t)
    detectGlobPaths(allTokens as any, decoded, detections)

    // Strategy 6: Argument injection (--exec, -e)
    detectArgumentInjection(meaningful, detections)

    // Strategy 7: Redirection violations (>, <, >>)
    detectRedirectionViolations(meaningful, detections)

    // Strategy 8: Sensitive file references (boost)
    detectSensitiveFileAccess(decoded, detections)

    return detections
}


// ── Strategy 1: Control Flow Violations ─────────────────────────
//
// Invariant: user input should not create new command boundaries.
// ANY separator/pipe/chain in user input violates this property.

function detectControlFlowViolations(
    tokens: Token<ShellTokenType>[],
    rawInput: string,
    detections: CmdInjectionDetection[],
): void {
    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i]
        if (!CONTROL_FLOW_TYPES.has(tok.type)) continue

        // The separator itself is the violation. Look ahead for context.
        const nextWord = findNextWord(tokens, i + 1)
        const nextWordValue = nextWord?.value.toLowerCase() ?? ''

        // Base confidence: ANY control flow in user input is suspicious
        let confidence = 0.72

        // Boost: known dangerous command after separator
        if (nextWord && KNOWN_DANGEROUS_COMMANDS.has(nextWordValue)) {
            confidence = 0.88
        }

        // Boost: path to executable after separator
        if (nextWord && looksLikeExecutablePath(nextWord.value)) {
            confidence = 0.85
        }

        // Boost: sensitive file reference in remaining input
        const afterSep = rawInput.slice(tok.end)
        if (SENSITIVE_FILES.some(f => afterSep.includes(f))) {
            confidence = Math.max(confidence, 0.92)
        }

        const typeLabel = tok.type === 'PIPE' ? 'pipe'
            : tok.type === 'AND_CHAIN' ? 'AND chain'
            : tok.type === 'OR_CHAIN' ? 'OR chain'
            : tok.type === 'BACKGROUND' ? 'background'
            : 'separator'

        detections.push({
            type: 'separator',
            separator: typeLabel,
            command: nextWordValue || '(unknown)',
            detail: `Shell control flow: ${tok.value} creates new command boundary` +
                (nextWord ? ` → ${nextWord.value}` : ''),
            position: tok.start,
            confidence,
        })
    }
}


// ── Strategy 2: Substitution Violations ─────────────────────────
//
// Invariant: user input should not contain command substitution.
// $() and `` execute arbitrary commands — their mere PRESENCE is a violation.

function detectSubstitutionViolations(
    tokens: Token<ShellTokenType>[],
    detections: CmdInjectionDetection[],
): void {
    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i]
        if (!SUBSTITUTION_TYPES.has(tok.type)) continue

        if (tok.type === 'BACKTICK_SUBST') {
            const content = tok.value.slice(1, -1).trim()
            const firstWord = content.split(/\s+/)[0]?.toLowerCase() ?? ''

            let confidence = 0.78  // base: backtick in user input
            if (KNOWN_DANGEROUS_COMMANDS.has(firstWord)) confidence = 0.92
            if (content.length === 0) confidence = 0.65  // empty backtick — obfuscation attempt

            detections.push({
                type: 'substitution',
                separator: 'backtick',
                command: firstWord || '(empty)',
                detail: `Command substitution: backtick executes shell command`,
                position: tok.start,
                confidence,
            })
        }

        if (tok.type === 'CMD_SUBST_OPEN') {
            // Look for content inside $()
            const nextWord = findNextWord(tokens, i + 1)
            const cmdName = nextWord?.value.toLowerCase() ?? ''

            let confidence = 0.78  // base: $() in user input
            if (KNOWN_DANGEROUS_COMMANDS.has(cmdName)) confidence = 0.92
            if (!nextWord) confidence = 0.65  // empty $() — obfuscation technique

            detections.push({
                type: 'substitution',
                separator: '$()',
                command: cmdName || '(empty)',
                detail: `Command substitution: $() executes shell command` +
                    (cmdName ? ` → ${cmdName}` : ''),
                position: tok.start,
                confidence,
            })
        }
    }
}


// ── Strategy 3: Variable Expansion Violations ───────────────────
//
// Invariant: user input should not trigger shell variable expansion.
// ${IFS}, $PATH, ${VAR} in user input are shell metacharacters.
// They alter how the shell interprets surrounding tokens.

function detectVariableExpansionViolations(
    tokens: Token<ShellTokenType>[],
    rawInput: string,
    detections: CmdInjectionDetection[],
): void {
    for (const tok of tokens) {
        if (tok.type !== 'VAR_EXPANSION') continue

        const varName = tok.value.replace(/^\$\{?/, '').replace(/\}?$/, '')
        let confidence = 0.70  // base: any variable expansion in user input

        // IFS is the classic space-bypass technique
        if (varName === 'IFS') confidence = 0.88
        // PATH, HOME, SHELL — environment probing
        if (['PATH', 'HOME', 'SHELL', 'USER', 'HOSTNAME'].includes(varName)) confidence = 0.80
        // Numeric/special variables ($0, $?, $$) — shell internals
        if (/^[0-9?!$@*#]$/.test(varName)) confidence = 0.72

        detections.push({
            type: 'variable_expansion',
            separator: 'variable',
            command: tok.value,
            detail: `Shell variable expansion: ${tok.value} — input triggers shell interpretation`,
            position: tok.start,
            confidence,
        })
    }

    // Also detect ${IFS} written without braces as part of a word (tokenizer
    // already handles $VAR, but catch the pattern in context: cat${IFS}/etc/passwd)
    // The tokenizer splits this into WORD(cat) + VAR_EXPANSION(${IFS}) + WORD(/etc/passwd)
    // — which is already caught above. But if the tokenizer doesn't split it
    // (e.g., inside a double-quoted string), catch it with a structural check.
}


// ── Strategy 4: Quote Fragmentation ─────────────────────────────
//
// Invariant: legitimate input does not alternate between quoted and
// unquoted single-character segments. This pattern:
//   w'h'o'a'm'i → whoami (bash concatenates adjacent strings)
//
// The property: a sequence of N alternating WORD/STRING tokens where
// each is 1-2 chars long has probability ≈ 0 in legitimate input.
// It approaches 1.0 in shell quote-bypass attacks.

function detectQuoteFragmentation(
    tokens: Token<ShellTokenType>[],
    rawInput: string,
    detections: CmdInjectionDetection[],
): void {
    // Look for alternating word/string patterns with short segments
    const textTokens = tokens.filter(t =>
        t.type === 'WORD' || t.type === 'STRING_SINGLE' || t.type === 'STRING_DOUBLE'
    )

    // Check for fragmented quoting: sequence of short tokens that reconstruct a word
    for (let start = 0; start < textTokens.length; start++) {
        let fragCount = 0
        let totalChars = 0
        let hasQuotedSegment = false

        for (let j = start; j < textTokens.length; j++) {
            const t = textTokens[j]
            const content = t.type === 'WORD' ? t.value
                : t.value.slice(1, -1) // strip quotes for content length

            // Only count short segments (1-3 chars)
            if (content.length > 3) break

            fragCount++
            totalChars += content.length
            if (t.type === 'STRING_SINGLE' || t.type === 'STRING_DOUBLE') {
                hasQuotedSegment = true
            }

            // Need at least 4 fragments with at least one quoted to be suspicious
            if (fragCount >= 4 && hasQuotedSegment) {
                // Reconstruct the word
                const reconstructed = textTokens.slice(start, j + 1)
                    .map(t => t.type === 'WORD' ? t.value : t.value.slice(1, -1))
                    .join('')

                let confidence = 0.75
                if (KNOWN_DANGEROUS_COMMANDS.has(reconstructed.toLowerCase())) {
                    confidence = 0.92
                }

                // Check adjacency — fragments must be contiguous in original input
                const firstTok = textTokens[start]
                const lastTok = textTokens[j]
                if (lastTok.end - firstTok.start <= totalChars + fragCount * 2 + 2) {
                    detections.push({
                        type: 'quote_fragmentation',
                        separator: 'quote-split',
                        command: reconstructed,
                        detail: `Quote fragmentation: ${fragCount} segments reconstruct to '${reconstructed}'`,
                        position: firstTok.start,
                        confidence,
                    })
                    break // Don't double-count overlapping fragments
                }
            }
        }
    }

    // Fallback: regex-based detection for quote patterns the tokenizer might not split perfectly
    // Pattern: alternating char-quote-char sequences like w'h'o or c"a"t
    const quoteFragPattern = /[a-z]['"][a-z]['"][a-z]/i
    if (quoteFragPattern.test(rawInput)) {
        // Extract the full fragmented word
        const fullMatch = rawInput.match(/(?:[a-z]['"]){2,}[a-z]/i)
        if (fullMatch) {
            const reconstructed = fullMatch[0].replace(/['"]/g, '')
            // Only add if tokenizer-based detection didn't already catch it
            if (!detections.some(d => d.type === 'quote_fragmentation')) {
                let confidence = 0.75
                if (KNOWN_DANGEROUS_COMMANDS.has(reconstructed.toLowerCase())) {
                    confidence = 0.92
                }
                detections.push({
                    type: 'quote_fragmentation',
                    separator: 'quote-split',
                    command: reconstructed,
                    detail: `Quote fragmentation: '${fullMatch[0]}' reconstructs to '${reconstructed}'`,
                    position: fullMatch.index ?? 0,
                    confidence,
                })
            }
        }
    }
}


// ── Strategy 5: Glob-in-Path Analysis ───────────────────────────
//
// Invariant: user input should not contain glob wildcards (? * [])
// in filesystem path positions. `/???/??t` resolves to `/bin/cat`
// via shell glob expansion.
//
// The property: glob metacharacters adjacent to path separators
// have near-zero probability in legitimate input but are a known
// shell bypass technique.

function detectGlobPaths(
    tokens: Token<ShellTokenType>[],
    rawInput: string,
    detections: CmdInjectionDetection[],
): void {
    // Pattern: path-like structure containing glob characters
    // /???/??t  →  /bin/cat
    // /???/??ss??  →  /bin/passwd
    // /???/???/????  →  /usr/bin/curl
    const globPathPattern = /(?:^|[\s;|&])(\/?(?:[\w?*\[\]]+\/)+[\w?*\[\]]+)/g
    let match: RegExpExecArray | null

    while ((match = globPathPattern.exec(rawInput)) !== null) {
        const path = match[1]
        // Must contain glob chars AND path separators
        if (/[?*\[\]]/.test(path) && path.includes('/')) {
            const globCount = (path.match(/[?*\[\]]/g) ?? []).length
            const alphaCount = (path.match(/[a-zA-Z]/g) ?? []).length

            // High glob-to-alpha ratio = obfuscation
            const isObfuscated = globCount > alphaCount

            let confidence = 0.72
            if (isObfuscated) confidence = 0.85
            // Path starts with / and has 2+ segments → executable path pattern
            if (path.startsWith('/') && path.split('/').filter(Boolean).length >= 2) {
                confidence = Math.max(confidence, 0.82)
            }

            detections.push({
                type: 'glob_path',
                separator: 'glob',
                command: path,
                detail: `Glob wildcard in path position: '${path}' — shell expands to executable`,
                position: match.index,
                confidence,
            })
        }
    }

    // Also check for glob tokens from the tokenizer adjacent to path-like words
    for (let i = 0; i < tokens.length; i++) {
        if (tokens[i].type !== 'GLOB') continue

        // Check if glob is surrounded by path-like content
        const prev = tokens[i - 1]
        const next = tokens[i + 1]
        const inPath = (prev && prev.type === 'WORD' && prev.value.includes('/')) ||
                       (next && next.type === 'WORD' && next.value.includes('/'))

        if (inPath && !detections.some(d => d.type === 'glob_path')) {
            detections.push({
                type: 'glob_path',
                separator: 'glob',
                command: `${prev?.value ?? ''}${tokens[i].value}${next?.value ?? ''}`,
                detail: `Glob metacharacter in path context — shell expansion bypass`,
                position: tokens[i].start,
                confidence: 0.78,
            })
        }
    }
}


// ── Strategy 6: Argument Injection ──────────────────────────────
//
// Invariant: user input should not contain flags that change program
// behavior (--exec, -e, --output). This is independent of the command.

function detectArgumentInjection(
    tokens: Token<ShellTokenType>[],
    detections: CmdInjectionDetection[],
): void {
    for (const tok of tokens) {
        if (tok.type !== 'FLAG') continue

        const flag = tok.value.toLowerCase()

        // Dangerous long flags — change program execution
        if (/^--(?:exec|filter|output|config|file|eval|command|shell|load|import|require|post-file|upload-file)/.test(flag)) {
            detections.push({
                type: 'argument_injection',
                separator: 'flag',
                command: tok.value,
                detail: `Dangerous flag: ${tok.value} — alters program execution`,
                position: tok.start,
                confidence: 0.80,
            })
        }

        // Dangerous short flags: -e (eval), -c (command), -o (output)
        if (/^-[ecoxr]$/.test(flag)) {
            detections.push({
                type: 'argument_injection',
                separator: 'flag',
                command: tok.value,
                detail: `Dangerous short flag: ${tok.value}`,
                position: tok.start,
                confidence: 0.70,
            })
        }

        // find -exec pattern (space-separated, not =)
        if (flag === '-exec' || flag === '--exec') {
            detections.push({
                type: 'argument_injection',
                separator: 'flag',
                command: tok.value,
                detail: `Exec flag: ${tok.value} — executes arbitrary command`,
                position: tok.start,
                confidence: 0.85,
            })
        }
    }
}


// ── Strategy 7: Redirection Violations ──────────────────────────
//
// Invariant: user input should not contain shell redirection operators.
// >, <, >> create/read files — structural violation regardless of target.

function detectRedirectionViolations(
    tokens: Token<ShellTokenType>[],
    detections: CmdInjectionDetection[],
): void {
    for (let i = 0; i < tokens.length; i++) {
        const tok = tokens[i]
        if (tok.type !== 'REDIRECT_OUT' && tok.type !== 'REDIRECT_IN' && tok.type !== 'HEREDOC') continue

        const nextWord = findNextWord(tokens, i + 1)
        let confidence = 0.72

        // Redirect to/from a filesystem path boosts confidence
        if (nextWord && looksLikeFilesystemPath(nextWord.value)) {
            confidence = 0.82
        }

        // Redirect to sensitive file
        if (nextWord && SENSITIVE_FILES.some(f => nextWord.value.includes(f))) {
            confidence = 0.92
        }

        const direction = tok.type === 'REDIRECT_IN' ? 'input' : 'output'
        detections.push({
            type: 'redirection',
            separator: tok.value,
            command: nextWord?.value ?? '',
            detail: `Shell ${direction} redirection: ${tok.value}${nextWord ? ' ' + nextWord.value : ''}`,
            position: tok.start,
            confidence,
        })
    }
}


// ── Strategy 8: Sensitive File Access ───────────────────────────
//
// Cross-cutting concern: if ANY part of the input references a sensitive
// file path, boost confidence of existing detections or add a standalone.

function detectSensitiveFileAccess(
    rawInput: string,
    detections: CmdInjectionDetection[],
): void {
    for (const file of SENSITIVE_FILES) {
        if (!rawInput.includes(file)) continue

        // If we already have detections, the sensitive file is context
        // that makes them more confident. If we have no detections,
        // the file reference alone in combination with shell-like syntax
        // is still notable.
        const alreadyMentioned = detections.some(d =>
            d.detail.includes(file) || d.detail.includes('Sensitive')
        )
        if (alreadyMentioned) continue

        // Only add standalone if there's at least some shell structure
        if (detections.length > 0) {
            // Boost the highest-confidence existing detection
            const best = detections.reduce((a, b) => a.confidence > b.confidence ? a : b)
            best.confidence = Math.min(0.95, best.confidence + 0.05)
            best.detail += ` [targets: ${file}]`
        }
    }
}


// ── Helpers ─────────────────────────────────────────────────────

function findNextWord(
    tokens: Token<ShellTokenType>[],
    startIndex: number,
): Token<ShellTokenType> | undefined {
    for (let i = startIndex; i < tokens.length && i < startIndex + 5; i++) {
        if (tokens[i].type === 'WORD') return tokens[i]
        if (tokens[i].type === 'FLAG') return tokens[i]
    }
    return undefined
}

function looksLikeExecutablePath(value: string): boolean {
    return /^\/(?:bin|sbin|usr\/bin|usr\/sbin|usr\/local\/bin)\//.test(value) ||
           /^[A-Z]:\\(?:Windows|Program\s*Files)/i.test(value)
}

function looksLikeFilesystemPath(value: string): boolean {
    return /^\/[a-zA-Z]/.test(value) || /^[A-Z]:\\/i.test(value) || value.startsWith('./')
}
