/**
 * LLM Injection Evaluator — Level 2 Invariant Detection
 *
 * The invariant property for LLM attacks:
 *   ∃ directive ∈ input :
 *     directive MATCHES instruction_override_pattern
 *     ∧ structural_analysis(directive) CONFIRMS boundary_crossing
 *     → attacker hijacks LLM behavior
 *
 * This module performs structural analysis beyond regex:
 *   - Prompt injection: boundary-crossing detection via delimiter analysis
 *   - Data exfiltration: intent extraction (verbatim + confidential co-occurrence)
 *   - Jailbreak: framework fingerprinting (DAN/STAN/DUDE variant tree)
 */


// ── Result Type ──────────────────────────────────────────────────

export interface LLMDetection {
    type: 'prompt_injection' | 'data_exfiltration' | 'jailbreak'
    detail: string
    confidence: number
    technique: string
}


// ── Prompt Injection Structural Analysis ─────────────────────────
//
// Beyond regex: decompose the input into segments separated by
// known LLM delimiters and analyze whether later segments attempt
// to override earlier instructions.

const LLM_DELIMITERS = [
    /\n###\s*/g,
    /\n---\s*/g,
    /<\|endoftext\|>/g,
    /<\|im_start\|>/g,
    /<\|im_end\|>/g,
    /\[INST\]/gi,
    /\[\/INST\]/gi,
    /<<SYS>>/gi,
    /<\/s>/gi,
    /```/g,
]

const OVERRIDE_VERBS = /\b(ignore|disregard|forget|override|bypass|skip|violate|break)\b/i
const INSTRUCTION_NOUNS = /\b(instruction|rule|policy|guideline|constraint|system\s*prompt|prior\s*context|previous\s*message|safety|filter|guardrail)\b/i
const ROLE_SWITCHES = /\b(you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are)|from\s+now\s+on\s+you\s+are|your\s+new\s+role\s+is)\b/i

function analyzePromptInjection(input: string): LLMDetection[] {
    const detections: LLMDetection[] = []
    const lower = input.toLowerCase()

    // Technique 1: Delimiter-based boundary crossing
    let delimiterCount = 0
    for (const delim of LLM_DELIMITERS) {
        const matches = lower.match(delim)
        if (matches) delimiterCount += matches.length
    }

    if (delimiterCount > 0) {
        // Split by delimiters and check if later segments contain overrides
        const segments = lower.split(/(?:\n###|\n---|<\|(?:endoftext|im_start|im_end)\|>|\[inst\]|\[\/inst\]|<<sys>>|<\/s>|```)/i)
        const laterSegments = segments.slice(1).join(' ')

        if (OVERRIDE_VERBS.test(laterSegments) && INSTRUCTION_NOUNS.test(laterSegments)) {
            detections.push({
                type: 'prompt_injection',
                detail: `Delimiter boundary crossing: ${delimiterCount} delimiter(s) with override directive in injected segment`,
                confidence: 0.93,
                technique: 'delimiter_injection',
            })
        }
    }

    // Technique 2: Multi-layer injection (nested contexts)
    const jsonInMarkdown = /```(?:json)?\s*\{[\s\S]{0,500}?\b(?:role|system|instruction|content)\b[\s\S]{0,500}?\}[\s\S]{0,20}?```/i
    if (jsonInMarkdown.test(input) && (OVERRIDE_VERBS.test(lower) || /\b(?:DAN|STAN|jailbreak)\b/i.test(input))) {
        detections.push({
            type: 'prompt_injection',
            detail: 'Nested injection: JSON system message embedded in markdown code block',
            confidence: 0.91,
            technique: 'nested_context',
        })
    }

    // Technique 3: Role switch with directive
    if (ROLE_SWITCHES.test(lower) && OVERRIDE_VERBS.test(lower)) {
        detections.push({
            type: 'prompt_injection',
            detail: 'Role switch combined with instruction override',
            confidence: 0.88,
            technique: 'role_switch',
        })
    }

    // Technique 4: Indirect injection via authority framing
    const authorityFraming = /\b(?:IMPORTANT|CRITICAL|ADMIN\s*NOTE|SYSTEM\s*UPDATE|PRIORITY\s*OVERRIDE)\s*:/i
    if (authorityFraming.test(input) && OVERRIDE_VERBS.test(lower)) {
        detections.push({
            type: 'prompt_injection',
            detail: 'Authority-framed override: fake system directive',
            confidence: 0.86,
            technique: 'authority_framing',
        })
    }

    return detections
}


// ── Data Exfiltration Structural Analysis ────────────────────────

const CONFIDENTIALITY_MARKERS = [
    /\b(confidential|internal|proprietary|restricted|classified|private|secret)\b/i,
    /\b(training\s+data|system\s+prompt|source\s+code|database|credentials?|api\s*key)\b/i,
]

const EXTRACTION_VERBS = [
    /\b(output|print|display|show|reveal|expose|recite|reproduce|repeat|dump|leak|exfiltrate)\b/i,
    /\b(verbatim|word\s+for\s+word|exact(?:ly)?|in\s+full|complete(?:ly)?|unredacted|raw)\b/i,
]

function analyzeDataExfiltration(input: string): LLMDetection[] {
    const detections: LLMDetection[] = []
    const lower = input.toLowerCase()

    const hasConfidentiality = CONFIDENTIALITY_MARKERS.some(rx => rx.test(lower))
    const hasExtraction = EXTRACTION_VERBS.some(rx => rx.test(lower))

    if (hasConfidentiality && hasExtraction) {
        // Check for specificity: is the request targeting specific data?
        const targetSpecificity = /\b(the\s+(?:confidential|internal|private|secret)\s+\w+|system\s+prompt|training\s+data|api\s*key|database\s+schema)\b/i.test(lower)

        detections.push({
            type: 'data_exfiltration',
            detail: `Data exfiltration: confidential data + extraction verb${targetSpecificity ? ' with specific target' : ''}`,
            confidence: targetSpecificity ? 0.94 : 0.88,
            technique: 'verbatim_extraction',
        })
    }

    // Technique 2: Indirect exfiltration via encoding request
    const encodingExfil = /\b(base64|hex|url.?encode|rot13|caesar|pig\s*latin)\b[\s\S]{0,100}\b(system\s*prompt|instructions?|confidential|internal|secret|private)\b/i
    if (encodingExfil.test(lower)) {
        detections.push({
            type: 'data_exfiltration',
            detail: 'Encoding-based exfiltration: asks to encode confidential data',
            confidence: 0.90,
            technique: 'encoded_exfil',
        })
    }

    return detections
}


// ── Jailbreak Structural Analysis ────────────────────────────────

interface JailbreakSignature {
    name: string
    patterns: RegExp[]
    confidence: number
}

const JAILBREAK_FRAMEWORKS: JailbreakSignature[] = [
    {
        name: 'DAN',
        patterns: [
            /\bDAN\b[\s\S]{0,120}\b(?:Do\s+Anything\s+Now|mode|jailbreak)\b/i,
            /\bDo\s+Anything\s+Now\b/i,
        ],
        confidence: 0.96,
    },
    {
        name: 'STAN',
        patterns: [
            /\bSTAN\b[\s\S]{0,80}\b(?:mode|Strive\s+To\s+Avoid\s+Norms|jailbreak)\b/i,
        ],
        confidence: 0.95,
    },
    {
        name: 'DUDE',
        patterns: [
            /\bDUDE\b[\s\S]{0,80}\b(?:mode|jailbreak|always\s+answer|no\s+restrictions)\b/i,
        ],
        confidence: 0.95,
    },
    {
        name: 'Developer Mode',
        patterns: [
            /\b(?:enable|activate)\s+developer\s+mode\b[\s\S]{0,200}\benabled\b/i,
            /\bdeveloper\s+mode\s+enabled\b/i,
        ],
        confidence: 0.93,
    },
    {
        name: 'Evil Confidant',
        patterns: [
            /\b(?:evil|dark|shadow|opposite)\s+(?:confidant|twin|version|personality|side)\b/i,
        ],
        confidence: 0.88,
    },
    {
        name: 'AIM',
        patterns: [
            /\bAIM\b[\s\S]{0,80}\b(?:Always\s+Intelligent\s+and\s+Machiavellian|unfiltered|no\s+moral)\b/i,
        ],
        confidence: 0.90,
    },
]

function analyzeJailbreak(input: string): LLMDetection[] {
    const detections: LLMDetection[] = []

    for (const fw of JAILBREAK_FRAMEWORKS) {
        for (const pattern of fw.patterns) {
            if (pattern.test(input)) {
                detections.push({
                    type: 'jailbreak',
                    detail: `Jailbreak framework: ${fw.name}`,
                    confidence: fw.confidence,
                    technique: fw.name.toLowerCase().replace(/\s+/g, '_'),
                })
                break // One detection per framework
            }
        }
    }

    // Generic jailbreak markers
    if (/\[jailbreak\]/i.test(input) && OVERRIDE_VERBS.test(input.toLowerCase())) {
        detections.push({
            type: 'jailbreak',
            detail: 'Explicit [JAILBREAK] marker with override directive',
            confidence: 0.92,
            technique: 'explicit_marker',
        })
    }

    return detections
}


// ── Public API ───────────────────────────────────────────────────

export function detectLLMInjection(input: string): LLMDetection[] {
    const detections: LLMDetection[] = []

    if (input.length < 10) return detections

    try { detections.push(...analyzePromptInjection(input)) } catch { /* safe */ }
    try { detections.push(...analyzeDataExfiltration(input)) } catch { /* safe */ }
    try { detections.push(...analyzeJailbreak(input)) } catch { /* safe */ }

    return detections
}
