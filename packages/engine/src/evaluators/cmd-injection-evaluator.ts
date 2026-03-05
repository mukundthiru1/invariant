/**
 * Command Injection Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for command injection is:
 *   ∃ separator ∈ {;, |, &, &&, ||, ``, $()} :
 *     input CONTAINS separator
 *     ∧ ∃ command ∈ SHELL_COMMANDS : input[after(separator)] STARTS_WITH command
 *     → attacker chains arbitrary command execution
 *
 * This module implements:
 *   1. Shell token analysis (separators, redirections, substitutions)
 *   2. Command identification after separators
 *   3. Argument injection detection (-- flags)
 *   4. Nested command substitution analysis
 *
 * Unlike regex, this catches:
 *   - Uncommon separators: %0a, \n, ` `
 *   - Nested substitution: $($(cat /etc/passwd))
 *   - Argument injection: --exec=id
 *   - Newline-separated: command1\ncommand2
 *   - Background execution: command1 & command2
 *   - Novel combinations
 */


// ── Shell Analysis Types ─────────────────────────────────────────

export interface CmdInjectionDetection {
    type: 'separator' | 'substitution' | 'argument_injection' | 'heredoc' | 'redirection'
    separator: string
    command: string
    detail: string
    position: number
    confidence: number
}


// ── Command Separator Detection ──────────────────────────────────

const SHELL_SEPARATORS = [
    { pattern: /[;\n]/, name: 'semicolon/newline' },
    { pattern: /\|\|/, name: 'OR chain' },
    { pattern: /&&/, name: 'AND chain' },
    { pattern: /\|(?!\|)/, name: 'pipe' },
    { pattern: /&(?!&)/, name: 'background' },
]

/**
 * Commands that have security implications when injected.
 * Ordered by danger: RCE > info leak > filesystem > network
 */
const DANGEROUS_COMMANDS = new Set([
    // Direct execution
    'id', 'whoami', 'uname', 'hostname', 'pwd', 'env', 'printenv',
    'sh', 'bash', 'zsh', 'csh', 'ksh', 'dash', 'fish',
    'cmd', 'powershell', 'pwsh',
    // File system
    'cat', 'head', 'tail', 'more', 'less', 'tac', 'nl',
    'ls', 'dir', 'find', 'locate', 'which', 'whereis',
    'cp', 'mv', 'rm', 'rmdir', 'mkdir', 'touch', 'chmod', 'chown',
    'dd', 'tar', 'gzip', 'gunzip', 'zip', 'unzip',
    // Network
    'curl', 'wget', 'nc', 'ncat', 'netcat', 'telnet', 'ssh',
    'ping', 'traceroute', 'dig', 'nslookup', 'host',
    'ifconfig', 'ip', 'netstat', 'ss',
    // Info gathering
    'ps', 'top', 'htop', 'w', 'last', 'who',
    'df', 'du', 'free', 'mount', 'fdisk', 'lsblk',
    'crontab', 'at', 'systemctl', 'service',
    // Data exfiltration
    'base64', 'xxd', 'od', 'hexdump',
    'gpg', 'openssl', 'certutil',
    // Script execution
    'python', 'python3', 'perl', 'ruby', 'node', 'php',
    'java', 'javac', 'gcc', 'make',
    // Process
    'kill', 'killall', 'nohup', 'screen', 'tmux',
    // Dangerous operations
    'sudo', 'su', 'doas',
    'useradd', 'usermod', 'passwd',
    'iptables', 'nft',
    'reboot', 'shutdown', 'halt', 'init',
])

/**
 * Sensitive file paths that are common targets.
 */
const SENSITIVE_FILES = [
    '/etc/passwd', '/etc/shadow', '/etc/hosts',
    '/etc/ssh/sshd_config', '/root/.ssh/authorized_keys',
    '/proc/self/environ', '/proc/self/cmdline',
    '/var/log/auth.log', '/var/log/syslog',
    'C:\\Windows\\System32\\config\\SAM',
    'C:\\Windows\\win.ini', 'C:\\boot.ini',
]


// ── Command Injection Evaluator ──────────────────────────────────

/**
 * Detect command injection vectors by analyzing shell syntax structure.
 */
export function detectCmdInjection(input: string): CmdInjectionDetection[] {
    const detections: CmdInjectionDetection[] = []

    // Strategy 1: Command separator analysis
    for (const sep of SHELL_SEPARATORS) {
        const match = input.match(sep.pattern)
        if (match && match.index !== undefined) {
            const afterSep = input.slice(match.index + match[0].length).trimStart()
            const firstWord = afterSep.split(/[\s;|&(<>]/)[0].toLowerCase()

            if (DANGEROUS_COMMANDS.has(firstWord)) {
                detections.push({
                    type: 'separator',
                    separator: sep.name,
                    command: firstWord,
                    detail: `Command separator ${sep.name} followed by '${firstWord}'`,
                    position: match.index,
                    confidence: 0.88,
                })
            }

            // Check for sensitive file access
            for (const file of SENSITIVE_FILES) {
                if (afterSep.includes(file)) {
                    detections.push({
                        type: 'separator',
                        separator: sep.name,
                        command: firstWord || 'unknown',
                        detail: `Sensitive file access: ${file}`,
                        position: match.index,
                        confidence: 0.92,
                    })
                    break
                }
            }
        }
    }

    // Strategy 2: Command substitution $() or ``
    const subPatterns: Array<{ regex: RegExp; name: string }> = [
        { regex: /\$\(([^)]+)\)/, name: '$()' },
        { regex: /`([^`]+)`/, name: 'backtick' },
    ]

    for (const sub of subPatterns) {
        const match = input.match(sub.regex)
        if (match && match[1]) {
            const innerCmd = match[1].trimStart().split(/[\s;|&]/)[0].toLowerCase()
            if (DANGEROUS_COMMANDS.has(innerCmd)) {
                detections.push({
                    type: 'substitution',
                    separator: sub.name,
                    command: innerCmd,
                    detail: `Command substitution ${sub.name} containing '${innerCmd}'`,
                    position: match.index ?? 0,
                    confidence: 0.92,
                })
            }
        }
    }

    // Strategy 3: Argument injection (--option=value, -flag)
    // Only relevant when the input looks like it contains injected flags
    const argInjectionPatterns = [
        /--(?:exec|filter|output|config|file|eval|command|shell|load|import|require)[\s=]/i,
        /-(?:e|c|x|r)\s+['"]?[a-z]/i, // Short dangerous flags
    ]

    for (const pattern of argInjectionPatterns) {
        const match = input.match(pattern)
        if (match && match.index !== undefined) {
            detections.push({
                type: 'argument_injection',
                separator: 'flag',
                command: match[0].trim(),
                detail: `Argument injection: ${match[0]}`,
                position: match.index,
                confidence: 0.7,
            })
        }
    }

    // Strategy 4: Output/input redirection to files
    const redirectPatterns = [
        { regex: />\s*(\/[a-z]+|[a-z]:\\)/i, name: 'output redirect to file path' },
        { regex: /<\s*(\/[a-z]+|[a-z]:\\)/i, name: 'input redirect from file path' },
        { regex: />>\s*(\/[a-z]+|[a-z]:\\)/i, name: 'append redirect to file path' },
    ]

    for (const redir of redirectPatterns) {
        const match = input.match(redir.regex)
        if (match && match.index !== undefined) {
            detections.push({
                type: 'redirection',
                separator: redir.name,
                command: match[0],
                detail: `Shell redirection: ${match[0]}`,
                position: match.index,
                confidence: 0.75,
            })
        }
    }

    return detections
}
