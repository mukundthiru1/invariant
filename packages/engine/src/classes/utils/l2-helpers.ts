import { deepDecode } from '../encoding.js'
import type { DetectionLevelResult } from '../types.js'

export const DEFAULT_L2_PATTERN_CONFIDENCE = 0.88

export function l2FromPattern(
    input: string,
    pattern: RegExp,
    explanation: string,
    confidence: number = DEFAULT_L2_PATTERN_CONFIDENCE,
): DetectionLevelResult | null {
    const decoded = deepDecode(input)
    const match = decoded.match(pattern)
    if (!match) return null
    return {
        detected: true,
        confidence,
        explanation,
        evidence: match[0].slice(0, 160),
    }
}
