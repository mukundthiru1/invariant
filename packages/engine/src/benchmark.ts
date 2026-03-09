import { InvariantEngine } from './invariant-engine.js'
import { ALL_CLASS_MODULES } from './classes/index.js'

const ENGINE_BENCHMARK_SIZE = 1000
const CLASS_PROFILE_INVOCATIONS = 10000
const SLOW_CLASS_THRESHOLD_MS = 0.5

function nowMs(): number {
    return performance.now()
}

function percentile(sortedValues: number[], p: number): number {
    if (sortedValues.length === 0) return 0
    const index = Math.min(sortedValues.length - 1, Math.max(0, Math.ceil((p / 100) * sortedValues.length) - 1))
    return sortedValues[index]
}

function toMs(n: number): string {
    return n.toFixed(4)
}

function normalizePayload(s: string): string {
    return s.replace(/\s+/g, ' ').trim()
}

function mutatePayload(base: string, i: number): string {
    const suffix = `__bench_${i}__`
    const patterns: Array<(v: string) => string> = [
        v => v,
        v => v.toUpperCase(),
        v => v.toLowerCase(),
        v => `${v} ${suffix}`,
        v => `${suffix} ${v}`,
        v => encodeURIComponent(v),
        v => `${v}\t${suffix}`,
        v => `${v}\n${suffix}`,
        v => v.replace(/ /g, '/**/'),
        v => `'${v}'`,
    ]
    return patterns[i % patterns.length](base)
}

function buildPayloadCorpus(size: number): string[] {
    const seeds = ALL_CLASS_MODULES.flatMap(module => module.knownPayloads.map(normalizePayload))
        .filter(Boolean)
    const uniqueSeeds = Array.from(new Set(seeds))
    const fallbackSeeds = ["' OR 1=1--", '<svg onload=alert(1)>', '../../etc/passwd', 'http://169.254.169.254/latest/meta-data/']
    const baseSeeds = uniqueSeeds.length > 0 ? uniqueSeeds : fallbackSeeds

    const payloads: string[] = []
    for (let i = 0; i < size; i++) {
        const base = baseSeeds[i % baseSeeds.length]
        payloads.push(mutatePayload(base, i))
    }
    return payloads
}

function runEngineBenchmark(): void {
    const { engine, skippedModules } = buildBenchmarkEngine()
    const payloads = buildPayloadCorpus(ENGINE_BENCHMARK_SIZE)
    const latenciesMs: number[] = []

    for (const payload of payloads) {
        const start = nowMs()
        engine.detect(payload, [])
        latenciesMs.push(nowMs() - start)
    }

    latenciesMs.sort((a, b) => a - b)
    const p50 = percentile(latenciesMs, 50)
    const p95 = percentile(latenciesMs, 95)
    const p99 = percentile(latenciesMs, 99)

    console.log('=== InvariantEngine.detect() Benchmark (1000 payloads) ===')
    console.log(`p50: ${toMs(p50)} ms`)
    console.log(`p95: ${toMs(p95)} ms`)
    console.log(`p99: ${toMs(p99)} ms`)
    console.log(`min: ${toMs(latenciesMs[0] ?? 0)} ms`)
    console.log(`max: ${toMs(latenciesMs[latenciesMs.length - 1] ?? 0)} ms`)
    if (skippedModules.length > 0) {
        console.log(`skipped modules (registry contract failures): ${skippedModules.join(', ')}`)
    }
    console.log('')
}

type ClassProfile = {
    id: string
    invocations: number
    totalMs: number
    avgMs: number
}

function runClassProfiler(): ClassProfile[] {
    const profiles: ClassProfile[] = []

    for (const module of ALL_CLASS_MODULES) {
        const seeds = module.knownPayloads.length > 0 ? module.knownPayloads : ['test']
        const start = nowMs()

        for (let i = 0; i < CLASS_PROFILE_INVOCATIONS; i++) {
            const payload = seeds[i % seeds.length]
            try {
                module.detect(payload)
            } catch {
                // Keep benchmark progressing even if a module throws for a specific payload.
            }
        }

        const totalMs = nowMs() - start
        const avgMs = totalMs / CLASS_PROFILE_INVOCATIONS
        profiles.push({
            id: module.id,
            invocations: CLASS_PROFILE_INVOCATIONS,
            totalMs,
            avgMs,
        })
    }

    profiles.sort((a, b) => b.avgMs - a.avgMs)

    console.log(`=== Class detect() Profiling (${CLASS_PROFILE_INVOCATIONS} calls/class) ===`)
    console.log('Top 20 slowest by average latency:')
    for (const profile of profiles.slice(0, 20)) {
        console.log(
            `${profile.id.padEnd(36)} avg=${toMs(profile.avgMs)} ms   total=${toMs(profile.totalMs)} ms`,
        )
    }
    console.log('')

    const slow = profiles.filter(profile => profile.avgMs > SLOW_CLASS_THRESHOLD_MS)
    console.log(`Classes above ${SLOW_CLASS_THRESHOLD_MS} ms average: ${slow.length}`)
    for (const profile of slow) {
        console.log(
            `- ${profile.id}: avg=${toMs(profile.avgMs)} ms total=${toMs(profile.totalMs)} ms (${profile.invocations} calls)`,
        )
    }
    console.log('')

    return profiles
}

function buildBenchmarkEngine(): { engine: InvariantEngine; skippedModules: string[] } {
    const skippedModules: string[] = []

    for (;;) {
        try {
            return { engine: new InvariantEngine(), skippedModules }
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            const match = message.match(/\[InvariantRegistry\]\s+([^:]+):\s+detect\(\)\s+(?:misses knownPayloads|false-positives on knownBenign)/)
            const badModuleId = match?.[1]
            if (!badModuleId) throw error

            const index = ALL_CLASS_MODULES.findIndex(module => module.id === badModuleId)
            if (index < 0) throw error

            skippedModules.push(badModuleId)
            ALL_CLASS_MODULES.splice(index, 1)
        }
    }
}

runEngineBenchmark()
runClassProfiler()
