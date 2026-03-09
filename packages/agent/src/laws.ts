export interface AgentLawResult {
    law: 1 | 2 | 3 | 4 | 5
    name: string
    passed: boolean
    detail: string
}

export interface AgentLawReport {
    stage: string
    results: AgentLawResult[]
    violations: AgentLawResult[]
}

export interface AgentLawInput {
    autoConfigure: boolean
    captureRuntimeExceptions: boolean
    wrappedIntegrations: number
    hasCoreControllers: boolean
    rescanInterval: number
}

export function evaluateAgentLaws(stage: string, input: AgentLawInput): AgentLawReport {
    const results: AgentLawResult[] = [
        {
            law: 1,
            name: 'No Stubs',
            passed: !input.autoConfigure || input.wrappedIntegrations > 0,
            detail: !input.autoConfigure || input.wrappedIntegrations > 0
                ? 'Runtime hooks are either explicitly disabled or actually installed.'
                : 'Auto-configure enabled but no runtime hooks were installed.',
        },
        {
            law: 2,
            name: 'Backwards Compatibility',
            passed: Number.isFinite(input.rescanInterval) && input.rescanInterval >= 0,
            detail: input.rescanInterval >= 0
                ? 'Rescan contract is additive and non-breaking.'
                : 'Negative rescan interval is not backwards-compatible behavior.',
        },
        {
            law: 3,
            name: 'Architecture Fit',
            passed: input.hasCoreControllers,
            detail: input.hasCoreControllers
                ? 'Core defense, health, and persistence controllers are initialized.'
                : 'One or more core controllers were not initialized.',
        },
        {
            law: 4,
            name: 'Elegance',
            passed: input.wrappedIntegrations <= 32,
            detail: input.wrappedIntegrations <= 32
                ? 'Integration wrapping remains bounded and intentional.'
                : 'Unexpectedly large wrapper surface suggests architectural drift.',
        },
        {
            law: 5,
            name: 'Fail Open Safety',
            passed: input.captureRuntimeExceptions,
            detail: input.captureRuntimeExceptions
                ? 'Internal runtime exceptions are captured to preserve application uptime.'
                : 'Runtime exception capture is disabled; fail-open guarantee is weakened.',
        },
    ]

    const violations = results.filter((law) => !law.passed)
    return { stage, results, violations }
}

