import { ALL_CLASS_MODULES } from './classes/index.js'
import type { InvariantClass, InvariantClassModule, Severity } from './classes/types.js'
import { ATTACK_CHAINS } from './chain-detector.js'
import { MitreMapper, type MitreTactic } from './mitre-mapper.js'

export interface ClassSummary {
    id: InvariantClass
    description: string
    category: string
    severity: Severity
    mitre: string[]
    cwe: string
    hasL2: boolean
    knownPayloadCount: number
    composableWith: string[]
}

export interface ChainSummary {
    id: string
    classes: string[]
    description: string
}

export interface CapabilityIndex {
    totalClasses: number
    byCategory: Record<string, ClassSummary[]>
    byMitre: Record<string, ClassSummary[]>
    bySeverity: Record<'critical' | 'high' | 'medium' | 'low', ClassSummary[]>
    byCwe: Record<string, ClassSummary[]>
    chains: ChainSummary[]
    coverage: {
        mitreAttackTactics: Record<string, string[]>
        uncoveredTactics: string[]
    }
}

const MITRE_TACTICS: MitreTactic[] = [
    'reconnaissance',
    'resource_development',
    'initial_access',
    'execution',
    'persistence',
    'privilege_escalation',
    'defense_evasion',
    'credential_access',
    'discovery',
    'lateral_movement',
    'collection',
    'command_and_control',
    'exfiltration',
    'impact',
]

const SEVERITY_LEVELS: ReadonlyArray<'critical' | 'high' | 'medium' | 'low'> = ['critical', 'high', 'medium', 'low']

function unique<T>(items: Iterable<T>): T[] {
    return [...new Set(items)]
}

function sortClassSummaries(items: ClassSummary[]): ClassSummary[] {
    return [...items].sort((a, b) => a.id.localeCompare(b.id))
}

function buildChainSummariesAndComposability(): {
    chains: ChainSummary[]
    chainComposable: Map<InvariantClass, Set<InvariantClass>>
} {
    const chainComposable = new Map<InvariantClass, Set<InvariantClass>>()
    const chains: ChainSummary[] = ATTACK_CHAINS.map((chain) => {
        const chainClasses = unique(chain.steps.flatMap(step => step.classes))

        for (const cls of chainClasses) {
            if (!chainComposable.has(cls)) {
                chainComposable.set(cls, new Set())
            }
            for (const peer of chainClasses) {
                if (peer !== cls) {
                    chainComposable.get(cls)!.add(peer)
                }
            }
        }

        return {
            id: chain.id,
            classes: chainClasses,
            description: chain.description,
        }
    })

    return { chains, chainComposable }
}

function summarizeClass(
    mod: InvariantClassModule,
    mapper: MitreMapper,
    chainComposable: Map<InvariantClass, Set<InvariantClass>>,
): ClassSummary {
    const mappedMitre = mapper.getTechniques(mod.id).map(tech => tech.id)
    const mitre = unique([...(mod.mitre ?? []), ...mappedMitre]).sort()
    const composable = unique([...(mod.composableWith ?? []), ...(chainComposable.get(mod.id) ?? [])]).sort()

    return {
        id: mod.id,
        description: mod.description,
        category: mod.category,
        severity: mod.severity,
        mitre,
        cwe: mod.cwe ?? 'CWE-UNKNOWN',
        hasL2: typeof mod.detectL2 === 'function',
        knownPayloadCount: mod.knownPayloads.length,
        composableWith: composable,
    }
}

function buildCapabilityIndex(modules: InvariantClassModule[]): CapabilityIndex {
    const mapper = new MitreMapper()
    const byCategory: Record<string, ClassSummary[]> = {}
    const byMitre: Record<string, ClassSummary[]> = {}
    const byCwe: Record<string, ClassSummary[]> = {}
    const bySeverity: CapabilityIndex['bySeverity'] = {
        critical: [],
        high: [],
        medium: [],
        low: [],
    }

    const coverageByTactic: Record<string, string[]> = Object.fromEntries(MITRE_TACTICS.map(tactic => [tactic, []]))
    const { chains, chainComposable } = buildChainSummariesAndComposability()

    const allSummaries = modules.map(mod => summarizeClass(mod, mapper, chainComposable))

    for (const summary of allSummaries) {
        if (!byCategory[summary.category]) byCategory[summary.category] = []
        byCategory[summary.category].push(summary)

        bySeverity[summary.severity].push(summary)

        if (!byCwe[summary.cwe]) byCwe[summary.cwe] = []
        byCwe[summary.cwe].push(summary)

        for (const mitreId of summary.mitre) {
            if (!byMitre[mitreId]) byMitre[mitreId] = []
            byMitre[mitreId].push(summary)
        }

        for (const technique of mapper.getTechniques(summary.id)) {
            coverageByTactic[technique.tactic].push(summary.id)
        }
    }

    for (const category of Object.keys(byCategory)) {
        byCategory[category] = sortClassSummaries(byCategory[category])
    }
    for (const severity of SEVERITY_LEVELS) {
        bySeverity[severity] = sortClassSummaries(bySeverity[severity])
    }
    for (const cwe of Object.keys(byCwe)) {
        byCwe[cwe] = sortClassSummaries(byCwe[cwe])
    }
    for (const mitreId of Object.keys(byMitre)) {
        byMitre[mitreId] = sortClassSummaries(byMitre[mitreId])
    }

    const mitreAttackTactics = Object.fromEntries(
        MITRE_TACTICS.map(tactic => [tactic, unique(coverageByTactic[tactic]).sort()]),
    )
    const uncoveredTactics = MITRE_TACTICS.filter(tactic => mitreAttackTactics[tactic].length === 0)

    return {
        totalClasses: modules.length,
        byCategory,
        byMitre,
        bySeverity,
        byCwe,
        chains,
        coverage: {
            mitreAttackTactics,
            uncoveredTactics,
        },
    }
}

function escapeMarkdownCell(value: string): string {
    return value.replace(/\|/g, '\\|')
}

function allClassRows(index: CapabilityIndex): ClassSummary[] {
    const seen = new Set<string>()
    const rows: ClassSummary[] = []

    for (const category of Object.keys(index.byCategory).sort()) {
        for (const cls of index.byCategory[category]) {
            if (seen.has(cls.id)) continue
            seen.add(cls.id)
            rows.push(cls)
        }
    }
    return rows.sort((a, b) => a.id.localeCompare(b.id))
}

export const CAPABILITY_INDEX: CapabilityIndex = buildCapabilityIndex(ALL_CLASS_MODULES)

export function printCapabilityReport(): void {
    console.log('INVARIANT Capability Report')
    console.log(`Total classes: ${CAPABILITY_INDEX.totalClasses}`)
    console.log(`Attack chains: ${CAPABILITY_INDEX.chains.length}`)

    console.log('\nBy category:')
    for (const category of Object.keys(CAPABILITY_INDEX.byCategory).sort()) {
        console.log(`- ${category}: ${CAPABILITY_INDEX.byCategory[category].length}`)
    }

    console.log('\nBy severity:')
    for (const severity of SEVERITY_LEVELS) {
        console.log(`- ${severity}: ${CAPABILITY_INDEX.bySeverity[severity].length}`)
    }

    if (CAPABILITY_INDEX.coverage.uncoveredTactics.length > 0) {
        console.log(`\nUncovered MITRE tactics: ${CAPABILITY_INDEX.coverage.uncoveredTactics.join(', ')}`)
    } else {
        console.log('\nAll MITRE tactics have coverage.')
    }
}

export function getCapabilityMarkdown(): string {
    const rows = allClassRows(CAPABILITY_INDEX)
    const header = '| Class ID | Category | Severity | MITRE | CWE | L2 | Known Payloads | Composable With | Description |'
    const separator = '|---|---|---|---|---|---|---|---|---|'
    const body = rows.map((cls) => {
        const mitre = cls.mitre.join(', ')
        const composableWith = cls.composableWith.join(', ')
        return [
            cls.id,
            cls.category,
            cls.severity,
            mitre,
            cls.cwe,
            cls.hasL2 ? 'yes' : 'no',
            String(cls.knownPayloadCount),
            composableWith,
            escapeMarkdownCell(cls.description),
        ].join(' | ')
    })

    return [header, separator, ...body.map(line => `| ${line} |`)].join('\n')
}
