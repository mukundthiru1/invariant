import { Database } from '../lib/postgres'

export interface CollectiveSignalRow {
    id: number
    sensor_id: string
    signal_type: string
    confidence: number
    target_path: string
    http_method: string
    source_ip_hash: string | null
    source_country: string | null
    matched_rule: string | null
    severity: string
    observed_at: string
}

export interface SynthesisCandidate {
    signal_type: string
    count: number
    avg_confidence: number
    sample_paths: string[]
    sample_matched_rules: string[]
    first_seen: string
    last_seen: string
}

/** Attack class + source country grouping for geographically coordinated campaigns */
export interface ClassByCountry {
    signal_type: string
    source_country: string
    count: number
    distinct_sensors: number
}

/** Signals per hour per attack class over last 24h */
export interface AttackVelocityEntry {
    signal_type: string
    signal_count_24h: number
    signals_per_hour: number
}

/** Percentage of sensors that saw this attack class in the window */
export interface SensorConvergenceEntry {
    signal_type: string
    sensors_seeing_class: number
    total_sensors: number
    convergence_pct: number
}

/** Campaign alert when >40% of sensors see same class within 6h */
export interface CampaignAlertEntry {
    signal_type: string
    sensors_seeing_class: number
    total_sensors: number
    convergence_pct: number
    window_hours: number
}

/** Classes with >50% signal volume increase vs previous 24h */
export interface EmergingThreatEntry {
    signal_type: string
    velocity_increase_pct: number
}

export interface ThreatLandscape {
    by_class_and_country: ClassByCountry[]
    attack_velocity: AttackVelocityEntry[]
    sensor_convergence: SensorConvergenceEntry[]
    campaign_alerts: CampaignAlertEntry[]
    emerging_threats: EmergingThreatEntry[]
}

export async function findSynthesisCandidates(db: Database): Promise<SynthesisCandidate[]> {
    const result = await db.query<{
        signal_type: string
        count: number
        avg_confidence: number
        sample_paths: string[]
        sample_matched_rules: string[]
        first_seen: string
        last_seen: string
    }>(`
        SELECT 
            c.signal_type,
            COUNT(c.id)::int as count,
            AVG(c.confidence)::float as avg_confidence,
            COALESCE(array_agg(DISTINCT c.target_path) FILTER (WHERE c.target_path IS NOT NULL), ARRAY[]::text[]) as sample_paths,
            COALESCE(array_agg(DISTINCT c.matched_rule) FILTER (WHERE c.matched_rule IS NOT NULL), ARRAY[]::text[]) as sample_matched_rules,
            MIN(c.observed_at)::text as first_seen,
            MAX(c.observed_at)::text as last_seen
        FROM collective_signals c
        LEFT JOIN detection_rules dr ON dr.signal_subtype = c.signal_type
        WHERE dr.rule_id IS NULL
        GROUP BY c.signal_type
        HAVING COUNT(c.id) >= 5 
           AND AVG(c.confidence) >= 0.78
           AND MIN(c.observed_at) >= NOW() - INTERVAL '30 days'
           AND COUNT(DISTINCT DATE_TRUNC('hour', c.observed_at)) >= 2
           AND COUNT(DISTINCT c.sensor_id) >= 2
        ORDER BY count DESC
        LIMIT 20
    `)

    return result.rows
}

/**
 * Threat landscape synthesis: group by attack class AND source country,
 * attack velocity (signals/hour), sensor convergence (%), and campaign alerts
 * when >40% of sensors see the same class within 6 hours.
 */
export async function getThreatLandscape(db: Database): Promise<ThreatLandscape> {
    const [byClassAndCountry, velocityRows, convergenceRows, totalSensors24, sixHourData, previous24hRows] = await Promise.all([
        db.query<{ signal_type: string; source_country: string; count: number; distinct_sensors: number }>(`
            SELECT signal_type,
                   COALESCE(source_country, 'unknown') AS source_country,
                   COUNT(id)::int AS count,
                   COUNT(DISTINCT sensor_id)::int AS distinct_sensors
            FROM collective_signals
            WHERE observed_at >= NOW() - INTERVAL '24 hours'
            GROUP BY signal_type, COALESCE(source_country, 'unknown')
            ORDER BY count DESC
        `),
        db.query<{ signal_type: string; count_24h: number }>(`
            SELECT signal_type, COUNT(id)::int AS count_24h
            FROM collective_signals
            WHERE observed_at >= NOW() - INTERVAL '24 hours'
            GROUP BY signal_type
        `),
        db.query<{ signal_type: string; sensors_seeing: number }>(`
            SELECT signal_type, COUNT(DISTINCT sensor_id)::int AS sensors_seeing
            FROM collective_signals
            WHERE observed_at >= NOW() - INTERVAL '24 hours'
            GROUP BY signal_type
        `),
        db.queryOne<{ total: number }>(`
            SELECT COUNT(DISTINCT sensor_id)::int AS total
            FROM collective_signals
            WHERE observed_at >= NOW() - INTERVAL '24 hours'
        `),
        db.query<{ signal_type: string; sensors_seeing: number }>(`
            SELECT signal_type, COUNT(DISTINCT sensor_id)::int AS sensors_seeing
            FROM collective_signals
            WHERE observed_at >= NOW() - INTERVAL '6 hours'
            GROUP BY signal_type
        `),
        db.query<{ signal_type: string; count_prev: number }>(`
            SELECT signal_type, COUNT(id)::int AS count_prev
            FROM collective_signals
            WHERE observed_at >= NOW() - INTERVAL '48 hours'
              AND observed_at < NOW() - INTERVAL '24 hours'
            GROUP BY signal_type
        `),
    ])

    const total24 = totalSensors24?.total ?? 0
    const total6 = await db.queryOne<{ total: number }>(`
        SELECT COUNT(DISTINCT sensor_id)::int AS total
        FROM collective_signals
        WHERE observed_at >= NOW() - INTERVAL '6 hours'
    `).then(r => r?.total ?? 0)

    const attack_velocity: AttackVelocityEntry[] = velocityRows.rows.map(r => ({
        signal_type: r.signal_type,
        signal_count_24h: r.count_24h,
        signals_per_hour: Math.round((r.count_24h / 24) * 100) / 100,
    }))

    const sensor_convergence: SensorConvergenceEntry[] = convergenceRows.rows.map(r => ({
        signal_type: r.signal_type,
        sensors_seeing_class: r.sensors_seeing,
        total_sensors: total24,
        convergence_pct: total24 > 0 ? Math.round((r.sensors_seeing / total24) * 10000) / 100 : 0,
    }))

    const campaign_alerts: CampaignAlertEntry[] = []
    if (total6 > 0) {
        for (const r of sixHourData.rows) {
            const pct = (r.sensors_seeing / total6) * 100
            if (pct > 40) {
                campaign_alerts.push({
                    signal_type: r.signal_type,
                    sensors_seeing_class: r.sensors_seeing,
                    total_sensors: total6,
                    convergence_pct: Math.round(pct * 100) / 100,
                    window_hours: 6,
                })
            }
        }
    }

    const prevByType = new Map(previous24hRows.rows.map(r => [r.signal_type, r.count_prev]))
    const emerging_threats: EmergingThreatEntry[] = []
    for (const r of velocityRows.rows) {
        const prev = prevByType.get(r.signal_type) ?? 0
        if (prev > 0) {
            const increasePct = ((r.count_24h - prev) / prev) * 100
            if (increasePct > 50) {
                emerging_threats.push({ signal_type: r.signal_type, velocity_increase_pct: Math.round(increasePct * 100) / 100 })
            }
        }
    }

    return {
        by_class_and_country: byClassAndCountry.rows.map(r => ({
            signal_type: r.signal_type,
            source_country: r.source_country,
            count: r.count,
            distinct_sensors: r.distinct_sensors,
        })),
        attack_velocity,
        sensor_convergence,
        campaign_alerts,
        emerging_threats,
    }
}

/** Threat map by country for last 7 days: country code, attack count, top classes. */
export interface ThreatMapCountry {
    code: string
    attack_count: number
    top_classes: string[]
}

export async function getThreatMapCountries(db: Database): Promise<ThreatMapCountry[]> {
    const byCountry = await db.query<{ source_country: string; signal_type: string; cnt: number }>(`
        SELECT COALESCE(source_country, 'unknown') AS source_country,
               signal_type,
               COUNT(id)::int AS cnt
        FROM collective_signals
        WHERE observed_at >= NOW() - INTERVAL '7 days'
        GROUP BY COALESCE(source_country, 'unknown'), signal_type
        ORDER BY source_country, cnt DESC
    `)

    const byCode = new Map<string, { total: number; byClass: Map<string, number> }>()
    for (const r of byCountry.rows) {
        let entry = byCode.get(r.source_country)
        if (!entry) {
            entry = { total: 0, byClass: new Map() }
            byCode.set(r.source_country, entry)
        }
        entry.total += r.cnt
        entry.byClass.set(r.signal_type, (entry.byClass.get(r.signal_type) ?? 0) + r.cnt)
    }

    return Array.from(byCode.entries()).map(([code, { total, byClass }]) => {
        const top_classes = Array.from(byClass.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([t]) => t)
        return { code, attack_count: total, top_classes }
    }).sort((a, b) => b.attack_count - a.attack_count)
}

export function buildRegexFromSignalType(signalType: string, sampleMatchedRules: string[]): string | null {
    const tokens = signalType.split('_').filter(t => t.length > 0)
    
    for (const rule of sampleMatchedRules) {
        if (typeof rule === 'string') {
            const parts = rule.split(/[^a-zA-Z0-9]+/).filter(t => t.length > 3)
            tokens.push(...parts)
        }
    }

    const benignTokens = new Set(['api', 'users', 'profile', 'data', 'v1', 'v2', 'id', 'user', 'info', 'auth', 'login'])
    const uniqueTokens = Array.from(new Set(tokens.map(t => t.toLowerCase()))).filter(t => !benignTokens.has(t) && t.length > 3)

    if (uniqueTokens.length < 2) {
        return null
    }

    const escapeRegex = (str: string) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const escapedTokens = uniqueTokens.map(escapeRegex)

    const pattern = '(?i)(?:' + escapedTokens.join('|') + ')'

    try {
        new RegExp(pattern)
        return pattern
    } catch {
        return null
    }
}

export async function synthesizeAndInsert(db: Database, candidate: SynthesisCandidate): Promise<boolean> {
    const pattern = buildRegexFromSignalType(candidate.signal_type, candidate.sample_matched_rules)
    if (!pattern) {
        console.log(`Skipping candidate ${candidate.signal_type} - could not build valid regex`)
        return false
    }

    const ruleId = 'collective_' + candidate.signal_type + '_' + Date.now().toString(36)
    const name = 'Collective: ' + candidate.signal_type.replace(/_/g, ' ')
    const signalType = candidate.signal_type.split('_')[0] || candidate.signal_type
    const matchPatterns = JSON.stringify([{ field: 'body', operator: 'regex', value: pattern }])
    const baseConfidence = Math.min(candidate.avg_confidence, 0.92)

    try {
        await db.execute(`
            INSERT INTO detection_rules (
                rule_id, name, signal_type, signal_subtype, match_type, 
                match_patterns, base_confidence, linked_cve_ids, 
                linked_technique_ids, enabled, version
            ) VALUES (
                $1, $2, $3, $4, 'regex', 
                $5::jsonb, $6, '[]'::jsonb, 
                '[]'::jsonb, true, 1
            ) ON CONFLICT (rule_id) DO NOTHING
        `, [
            ruleId,
            name,
            signalType,
            candidate.signal_type,
            matchPatterns,
            baseConfidence
        ])
        return true
    } catch (e) {
        console.error('Failed to insert rule:', e)
        return false
    }
}

export async function runCollectiveSynthesis(db: Database): Promise<{ synthesized: number; skipped: number; candidates: number }> {
    const candidates = await findSynthesisCandidates(db)
    let synthesized = 0
    let skipped = 0

    for (const candidate of candidates) {
        const success = await synthesizeAndInsert(db, candidate)
        if (success) {
            synthesized++
        } else {
            skipped++
        }
    }

    console.log(`[Collective Synthesis] Processed ${candidates.length} candidates. Synthesized: ${synthesized}, Skipped: ${skipped}`)

    return { synthesized, skipped, candidates: candidates.length }
}
