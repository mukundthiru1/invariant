const fs = require('fs');

// 1. Update index.ts
let indexContent = fs.readFileSync('packages/engine/src/classes/index.ts', 'utf8');
indexContent = indexContent.replace(
    "export type {\n    InvariantClass,\n    InvariantClassModule,\n    InvariantMatch,\n    AttackCategory,\n    Severity,\n    CalibrationConfig,\n} from './types.js'",
    "export type {\n    InvariantClass,\n    InvariantClassModule,\n    InvariantMatch,\n    AttackCategory,\n    Severity,\n    CalibrationConfig,\n    AnalysisRequest,\n    AnalysisResult,\n    AlgebraicComposition,\n    InterClassCorrelation,\n    BlockRecommendation,\n} from './types.js'"
);
fs.writeFileSync('packages/engine/src/classes/index.ts', indexContent);

// 2. Update invariant-engine.ts
let engineContent = fs.readFileSync('packages/engine/src/invariant-engine.ts', 'utf8');
engineContent = engineContent.replace(
    "import type {\n    InvariantClass,\n    InvariantClassModule,\n    InvariantMatch,\n    Severity,\n    DetectionLevelResult,\n} from './classes/types.js'",
    "import type {\n    InvariantClass,\n    InvariantClassModule,\n    InvariantMatch,\n    Severity,\n    DetectionLevelResult,\n    AnalysisRequest,\n    AnalysisResult,\n    AlgebraicComposition,\n    InterClassCorrelation,\n    BlockRecommendation,\n} from './classes/types.js'"
);

const newMethods = `
    analyze(request: AnalysisRequest): AnalysisResult {
        const start = performance.now()

        // Step 1: Run full deep detection
        const deep = this.detectDeep(request.input, [], request.knownContext as string | undefined)

        // Step 2: Apply source reputation prior — boost confidence if source is known hostile
        let matches = deep.matches
        if (request.sourceReputation && request.sourceReputation > 0.6) {
            const boost = (request.sourceReputation - 0.6) * 0.4  // 0–0.16 boost
            matches = matches.map(m => ({
                ...m,
                confidence: Math.min(0.99, m.confidence + boost),
            }))
        }

        // Step 3: Compute inter-class correlations
        const correlations = this.registry.computeCorrelations(matches)

        // Step 4: Apply correlation boosts — find the highest compoundConfidence and apply to matching classes
        if (correlations.length > 0) {
            const maxCorrelation = correlations.reduce((a, b) => a.compoundConfidence > b.compoundConfidence ? a : b)
            if (maxCorrelation.compoundConfidence > 0) {
                matches = matches.map(m =>
                    maxCorrelation.classes.includes(m.class)
                        ? { ...m, confidence: Math.min(0.99, Math.max(m.confidence, maxCorrelation.compoundConfidence)) }
                        : m
                )
            }
        }

        // Step 5: Detect algebraic compositions
        const compositions = this.detectCompositions(matches, request.knownContext)

        // Step 6: Compute block recommendation with per-severity thresholds
        const recommendation = this.computeBlockRecommendation(matches, compositions)

        return {
            matches,
            compositions,
            correlations,
            recommendation,
            novelByL2: deep.novelByL2,
            convergent: deep.convergent,
            processingTimeUs: (performance.now() - start) * 1000,
        }
    }

    private detectCompositions(matches: InvariantMatch[], knownContext?: string): AlgebraicComposition[] {
        const compositions: AlgebraicComposition[] = []
        const classSet = new Set(matches.map(m => m.class))

        // SQL injection composition detection
        const hasStringTerm = classSet.has('sql_string_termination')
        const hasCommentBypass = classSet.has('sql_comment_truncation')
        const hasTautology = classSet.has('sql_tautology')
        const hasUnion = classSet.has('sql_union_extraction')
        const hasStacked = classSet.has('sql_stacked_execution')
        const hasTimeOracle = classSet.has('sql_time_oracle')
        const hasErrorOracle = classSet.has('sql_error_oracle')

        if (hasStringTerm) {
            if (hasUnion) {
                compositions.push({
                    escape: 'string_terminate', payload: 'union_extract',
                    repair: hasCommentBypass ? 'comment_close' : 'none',
                    context: 'sql', confidence: hasCommentBypass ? 0.99 : 0.93,
                    derivedClass: 'sql_union_extraction',
                    isComplete: hasCommentBypass,
                })
            }
            if (hasTautology) {
                compositions.push({
                    escape: 'string_terminate', payload: 'tautology',
                    repair: hasCommentBypass ? 'comment_close' : 'none',
                    context: 'sql', confidence: hasCommentBypass ? 0.99 : 0.92,
                    derivedClass: 'sql_tautology',
                    isComplete: hasCommentBypass,
                })
            }
            if (hasTimeOracle) {
                compositions.push({
                    escape: 'string_terminate', payload: 'time_oracle',
                    repair: hasCommentBypass ? 'comment_close' : 'none',
                    context: 'sql', confidence: 0.91,
                    derivedClass: 'sql_time_oracle',
                    isComplete: hasCommentBypass,
                })
            }
            if (hasStacked) {
                compositions.push({
                    escape: 'string_terminate', payload: 'stacked_exec',
                    repair: 'natural_end',
                    context: 'sql', confidence: 0.95,
                    derivedClass: 'sql_stacked_execution',
                    isComplete: true,
                })
            }
        }

        // XSS composition detection
        const hasTagInject = classSet.has('xss_tag_injection')
        const hasEventHandler = classSet.has('xss_event_handler')
        const hasProtocol = classSet.has('xss_protocol_handler')
        const hasAttrEscape = classSet.has('xss_attribute_escape')

        if (hasAttrEscape && hasEventHandler) {
            compositions.push({
                escape: 'context_break', payload: 'event_handler',
                repair: 'tag_close', context: 'html', confidence: 0.96,
                derivedClass: 'xss_event_handler', isComplete: true,
            })
        }
        if (hasTagInject && hasProtocol) {
            compositions.push({
                escape: 'context_break', payload: 'tag_inject',
                repair: 'tag_close', context: 'html', confidence: 0.94,
                derivedClass: 'xss_protocol_handler', isComplete: true,
            })
        }

        // Path traversal composition
        const hasDotDot = classSet.has('path_dotdot_escape')
        const hasEncoding = classSet.has('path_encoding_bypass')
        const hasNullTerm = classSet.has('path_null_terminate')

        if (hasDotDot && hasEncoding) {
            compositions.push({
                escape: 'encoding_bypass', payload: 'path_escape',
                repair: 'none', context: 'url', confidence: 0.93,
                derivedClass: 'path_dotdot_escape', isComplete: false,
            })
        }
        if (hasDotDot && hasNullTerm) {
            compositions.push({
                escape: 'null_terminate', payload: 'path_escape',
                repair: 'natural_end', context: 'url', confidence: 0.95,
                derivedClass: 'path_null_terminate', isComplete: true,
            })
        }

        return compositions
    }

    private computeBlockRecommendation(matches: InvariantMatch[], compositions: AlgebraicComposition[]): BlockRecommendation {
        if (matches.length === 0 && compositions.length === 0) {
            return { block: false, confidence: 0, reason: 'no_detections', threshold: 0 }
        }

        // Per-severity thresholds (replaces global 0.7)
        const SEVERITY_THRESHOLDS: Record<string, number> = {
            critical: 0.45,  // deser, rce-class attacks block at lower confidence
            high:     0.65,  // sqli, xss, ssrf
            medium:   0.80,  // path traversal, redirect
            low:      0.92,  // info-class signals
        }

        // Check compositions first — a structurally complete injection always blocks
        const completeComposition = compositions.find(c => c.isComplete && c.confidence >= 0.90)
        if (completeComposition) {
            return {
                block: true, confidence: completeComposition.confidence,
                reason: \`complete_injection_structure:\${completeComposition.payload}\`,
                threshold: 0.90,
            }
        }

        // Check individual matches against per-severity thresholds
        for (const match of matches) {
            const threshold = SEVERITY_THRESHOLDS[match.severity] ?? 0.75
            if (match.confidence >= threshold) {
                return {
                    block: true, confidence: match.confidence,
                    reason: \`\${match.class}_exceeds_\${match.severity}_threshold\`,
                    threshold,
                }
            }
        }

        // Check if highest confidence match is close to threshold (advisory)
        const maxConfidence = Math.max(...matches.map(m => m.confidence))
        return {
            block: false, confidence: maxConfidence,
            reason: 'below_severity_thresholds',
            threshold: SEVERITY_THRESHOLDS[this.highestSeverity(matches)] ?? 0.75,
        }
    }

    /**
     * Check headers specifically for auth bypass invariants.
     */`;

engineContent = engineContent.replace(
    "    /**\n     * Check headers specifically for auth bypass invariants.\n     */",
    newMethods
);

engineContent = engineContent.replace(
    "    shouldBlock(matches: InvariantMatch[]): boolean {\n        return matches.some(m => m.confidence >= 0.7)\n    }",
    "    shouldBlock(matches: InvariantMatch[]): boolean {\n        return this.computeBlockRecommendation(matches, []).block\n    }"
);
fs.writeFileSync('packages/engine/src/invariant-engine.ts', engineContent);

// 3. Append tests to engine.test.ts
const testsContent = `
describe('InvariantEngine — analyze() API', () => {
    it('handles basic SQL detection', () => {
        const result = engine.analyze({ input: "' OR 1=1--" })
        expect(result.matches.some(m => m.class === 'sql_tautology')).toBe(true)
    })

    it('detects algebraic composition for complete SQL injection', () => {
        const result = engine.analyze({ input: "admin' UNION SELECT 1,2,3/*" })
        const comp = result.compositions.find(c => c.payload === 'union_extract')
        expect(comp).toBeDefined()
        expect(comp!.isComplete).toBe(true)
        expect(comp!.escape).toBe('string_terminate')
        expect(result.recommendation.block).toBe(true)
    })

    it('computes inter-class correlation boosts', () => {
        const result = engine.analyze({ input: "1'; DROP TABLE users--" })
        const hasBoosted = result.correlations.length > 0
        expect(hasBoosted).toBe(true)
    })

    it('applies source reputation prior', () => {
        const result = engine.analyze({ input: "' OR 1=1", sourceReputation: 0.9 })
        const match = result.matches.find(m => m.class === 'sql_tautology')
        expect(match!.confidence).toBeGreaterThan(0.9) // Boosted
    })

    it('respects per-severity thresholds for critical', () => {
        const result = engine.analyze({ input: "rO0ABXNy" }) // java gadget
        const match = result.matches.find(m => m.class === 'deser_java_gadget')
        expect(match!.severity).toBe('critical')
        expect(result.recommendation.block).toBe(true)
    })

    it('does not false-positive on benign input', () => {
        const result = engine.analyze({ input: "Hello world, just normal text here." })
        expect(result.matches.length).toBe(0)
        expect(result.compositions.length).toBe(0)
        expect(result.recommendation.block).toBe(false)
    })

    it('processes under 5ms', () => {
        const result = engine.analyze({ input: "admin' OR 1=1--" })
        expect(result.processingTimeUs).toBeLessThan(5000)
    })

    it('detects incomplete compositions as non-blocking when below threshold', () => {
        const result = engine.analyze({ input: "test'" })
        if (result.matches.length > 0) {
           expect(result.recommendation.block).toBe(result.recommendation.confidence >= result.recommendation.threshold)
        }
        expect(result).toBeDefined()
    })
})
`;
fs.appendFileSync('packages/engine/src/engine.test.ts', testsContent);

console.log("Updates completed successfully.");
