import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ChainCorrelator, type ChainDefinition, type ChainSignal } from './chain-detector.js'

const TEST_CHAINS: ChainDefinition[] = [
    {
        id: 'three_step_chain',
        name: 'Three Step Chain',
        description: 'Three-step chain for out-of-order and isolation tests.',
        severity: 'high',
        steps: [
            { classes: ['path_dotdot_escape'], description: 'Step 1' },
            { classes: ['sql_string_termination'], description: 'Step 2' },
            { classes: ['auth_header_spoof'], description: 'Step 3' },
        ],
        windowSeconds: 60,
        minimumSteps: 3,
        confidenceBoost: 0.2,
    },
    {
        id: 'partial_complete_chain',
        name: 'Partial Complete Chain',
        description: 'Completes at 2/3 steps to test dedupe behavior.',
        severity: 'critical',
        steps: [
            { classes: ['path_dotdot_escape'], description: 'Phase 1' },
            { classes: ['sql_string_termination'], description: 'Phase 2' },
            { classes: ['auth_header_spoof'], description: 'Phase 3' },
        ],
        windowSeconds: 60,
        minimumSteps: 2,
        confidenceBoost: 0.3,
    },
    {
        id: 'single_step_chain',
        name: 'Single Step Chain',
        description: 'Single-step critical chain that should complete immediately.',
        severity: 'critical',
        steps: [
            { classes: ['deser_java_gadget'], description: 'Critical step' },
        ],
        windowSeconds: 30,
        minimumSteps: 1,
        confidenceBoost: 0.4,
    },
    {
        id: 'behavior_chain',
        name: 'Behavior Chain',
        description: 'Behavioral overlap probability test chain.',
        severity: 'medium',
        steps: [
            { classes: ['xss_tag_injection'], behaviors: ['scanner_detected'], description: 'Behavior or class match' },
            { classes: ['sql_union_extraction'], description: 'Follow-up exploit' },
        ],
        windowSeconds: 120,
        minimumSteps: 2,
        confidenceBoost: 0.1,
    },
]

function makeSignal(params: Partial<ChainSignal> & Pick<ChainSignal, 'sourceHash'>): ChainSignal {
    return {
        sourceHash: params.sourceHash,
        classes: params.classes ?? [],
        behaviors: params.behaviors ?? [],
        confidence: params.confidence ?? 0.9,
        path: params.path ?? '/test',
        method: params.method ?? 'GET',
        timestamp: params.timestamp ?? Date.now(),
    }
}

describe('ChainCorrelator — Petri net state machine behavior', () => {
    beforeEach(() => {
        vi.useFakeTimers()
        vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
    })

    afterEach(() => {
        vi.useRealTimers()
    })

    it('matches out-of-order steps and completes when all required steps are satisfied', () => {
        const correlator = new ChainCorrelator([TEST_CHAINS[0]], 200, 100)
        const source = 'src-out-of-order-1'

        expect(correlator.ingest(makeSignal({ sourceHash: source, classes: ['auth_header_spoof'] }))).toEqual([])
        expect(correlator.ingest(makeSignal({ sourceHash: source, classes: ['path_dotdot_escape'] }))).toEqual([])

        const matches = correlator.ingest(makeSignal({ sourceHash: source, classes: ['sql_string_termination'] }))

        expect(matches).toHaveLength(1)
        expect(matches[0].chainId).toBe('three_step_chain')
        expect(matches[0].stepsMatched).toBe(3)
        expect(matches[0].stepMatches.map(s => s.stepIndex)).toEqual([0, 1, 2])
    })

    it('keeps partial out-of-order matches hidden until minimum steps are met', () => {
        const correlator = new ChainCorrelator([TEST_CHAINS[0]], 200, 100)
        const source = 'src-out-of-order-2'

        expect(correlator.ingest(makeSignal({ sourceHash: source, classes: ['sql_string_termination'] }))).toEqual([])
        expect(correlator.ingest(makeSignal({ sourceHash: source, classes: ['path_dotdot_escape'] }))).toEqual([])
        expect(correlator.getActiveChains(source)).toEqual([])
    })

    it('completes minimumSteps=1 chains on first matching signal', () => {
        const correlator = new ChainCorrelator([TEST_CHAINS[2]], 200, 100)
        const source = 'src-min-1'

        const matches = correlator.ingest(makeSignal({ sourceHash: source, classes: ['deser_java_gadget'] }))

        expect(matches).toHaveLength(1)
        expect(matches[0].chainId).toBe('single_step_chain')
        expect(matches[0].stepsMatched).toBe(1)
        expect(['block', 'lockdown']).toContain(matches[0].recommendedAction)
    })

    it('does not re-fire completed chains on unrelated future signals', () => {
        const correlator = new ChainCorrelator([TEST_CHAINS[2]], 200, 100)
        const source = 'src-dedupe-1'

        expect(correlator.ingest(makeSignal({ sourceHash: source, classes: ['deser_java_gadget'] }))).toHaveLength(1)
        const replay = correlator.ingest(makeSignal({ sourceHash: source, classes: ['path_dotdot_escape'] }))

        expect(replay).toEqual([])
    })

    it('keeps completed chain state stable instead of advancing to additional steps', () => {
        const correlator = new ChainCorrelator([TEST_CHAINS[1]], 200, 100)
        const source = 'src-dedupe-2'

        correlator.ingest(makeSignal({ sourceHash: source, classes: ['path_dotdot_escape'] }))
        const completion = correlator.ingest(makeSignal({ sourceHash: source, classes: ['sql_string_termination'] }))
        expect(completion).toHaveLength(1)
        expect(completion[0].stepsMatched).toBe(2)

        correlator.ingest(makeSignal({ sourceHash: source, classes: ['auth_header_spoof'] }))
        const active = correlator.getActiveChains(source)

        expect(active).toHaveLength(1)
        expect(active[0].stepsMatched).toBe(2)
    })

    it('expires in-progress state when late steps arrive outside chain window', () => {
        const correlator = new ChainCorrelator([TEST_CHAINS[0]], 200, 100)
        const source = 'src-expire-1'

        correlator.ingest(makeSignal({ sourceHash: source, classes: ['path_dotdot_escape'] }))
        vi.advanceTimersByTime(61_000)

        const late = correlator.ingest(makeSignal({ sourceHash: source, classes: ['sql_string_termination'] }))

        expect(late).toEqual([])
        expect(correlator.getActiveChains(source)).toEqual([])
    })

    it('prunes expired state after retention period and removes source visibility', () => {
        const correlator = new ChainCorrelator([TEST_CHAINS[0]], 200, 100)
        const source = 'src-expire-2'

        correlator.ingest(makeSignal({ sourceHash: source, classes: ['path_dotdot_escape'] }))
        vi.advanceTimersByTime(121_000)
        correlator.ingest(makeSignal({ sourceHash: 'trigger-prune', classes: [] }))

        expect(correlator.getActiveChains(source)).toEqual([])
        expect(correlator.getAllActiveChains().some(m => m.sourceHash === source)).toBe(false)
    })

    it('infers attack graph probability and sorts chains by probability descending', () => {
        const correlator = new ChainCorrelator(TEST_CHAINS, 200, 100)

        const inference = correlator.getAttackGraphInference(
            ['path_dotdot_escape', 'sql_string_termination'],
            [],
        )

        expect(inference.length).toBeGreaterThan(0)
        expect(inference[0].chainId).toBe('three_step_chain')
        expect(inference[0].probability).toBeCloseTo(2 / 3, 5)
    })

    it('counts behavior overlap when inferring attack graph probabilities', () => {
        const correlator = new ChainCorrelator(TEST_CHAINS, 200, 100)

        const inference = correlator.getAttackGraphInference([], ['scanner_detected'])
        const behaviorChain = inference.find(item => item.chainId === 'behavior_chain')

        expect(behaviorChain).toBeDefined()
        expect(behaviorChain!.probability).toBeCloseTo(0.5, 5)
    })

    it('flags high-urgency chain velocity when steps accumulate quickly', () => {
        const correlator = new ChainCorrelator([TEST_CHAINS[0]], 200, 100)
        const source = 'src-velocity'

        correlator.ingest(makeSignal({ sourceHash: source, classes: ['path_dotdot_escape'] }))
        vi.advanceTimersByTime(10_000)
        correlator.ingest(makeSignal({ sourceHash: source, classes: ['sql_string_termination'] }))

        const velocity = correlator.getChainVelocity(source)

        expect(velocity).toHaveLength(1)
        expect(velocity[0].chainId).toBe('three_step_chain')
        expect(velocity[0].stepsPerMinute).toBeGreaterThan(2.0)
        expect(velocity[0].latestStep).toBe(2)
    })

    it('enforces source memory bounds when unique sources exceed maxSources', () => {
        const correlator = new ChainCorrelator([TEST_CHAINS[2]], 200, 3)

        for (let i = 0; i < 6; i++) {
            correlator.ingest(makeSignal({ sourceHash: `src-bound-${i}`, classes: ['deser_java_gadget'] }))
        }

        expect(correlator.activeSourceCount).toBeLessThanOrEqual(3)
        const distinctSources = new Set(correlator.getAllActiveChains().map(match => match.sourceHash))
        expect(distinctSources.size).toBeLessThanOrEqual(3)
    })

    it('keeps source state isolated so steps from different sources never combine', () => {
        const correlator = new ChainCorrelator([TEST_CHAINS[0]], 200, 100)

        correlator.ingest(makeSignal({ sourceHash: 'source-A', classes: ['path_dotdot_escape'] }))
        correlator.ingest(makeSignal({ sourceHash: 'source-B', classes: ['sql_string_termination'] }))

        expect(correlator.getActiveChains('source-A')).toEqual([])
        expect(correlator.getActiveChains('source-B')).toEqual([])

        const completionA = correlator.ingest(makeSignal({ sourceHash: 'source-A', classes: ['auth_header_spoof'] }))
        expect(completionA).toEqual([])

        const completion = correlator.ingest(makeSignal({ sourceHash: 'source-A', classes: ['sql_string_termination'] }))
        expect(completion).toHaveLength(1)
        expect(completion[0].sourceHash).toBe('source-A')
        expect(correlator.getActiveChains('source-B')).toEqual([])
    })
})
