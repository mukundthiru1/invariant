/**
 * Santh Intel — Collective Defense API
 *
 * Endpoints for INVARIANT sensors to pull collective defense data:
 *   - GET /v1/collective/blocklist   — IP hashes flagged by the collective
 *   - GET /v1/collective/rules       — Updated detection rules for sensors
 *   - GET /v1/collective/posture     — Posture report for a sensor
 *   - GET /v1/collective/threat-map  — Threat map by country (last 7 days)
 *
 * Auth: Bearer token (sensor API key) — same as signal ingestion.
 *
 * These endpoints complete the two-way loop:
 *   Sensors push signals TO Intel (signal-ingest.ts)
 *   Sensors pull defense FROM Intel (collective-api.ts)
 */

import { Database } from '../lib/postgres'
import type { Env } from '../lib/types'
import { getThreatLandscape, getThreatMapCountries } from './collective-synthesis'

// ── Helpers ───────────────────────────────────────────────────────

async function authenticateSensor(
    request: Request,
    db: Database,
): Promise<{ id: string; subscriber_id: string | null; status: string; reputation_score: number; rules_version: string | null } | Response> {
    const authHeader = request.headers.get('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
        // SAA-032: Use same status code and similar message for all auth failures
        // to prevent enumeration via response differentiation
        return Response.json({ error: 'Authentication failed' }, { status: 403 })
    }

    const apiKey = authHeader.slice(7)
    if (!apiKey || apiKey.length < 32) {
        return Response.json({ error: 'Authentication failed' }, { status: 403 })
    }

    const keyData = new TextEncoder().encode(apiKey)
    const keyHash = await crypto.subtle.digest('SHA-256', keyData)
    const keyHashHex = Array.from(new Uint8Array(keyHash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')

    const sensor = await db.queryOne<{
        id: string
        subscriber_id: string | null
        status: string
        reputation_score: number
        rules_version: string | null
    }>(`
        SELECT id, subscriber_id, status, reputation_score, rules_version
        FROM collective_sensors
        WHERE api_key_hash = $1 AND status IN ('active', 'probation')
    `, [keyHashHex])

    if (!sensor) {
        return Response.json({ error: 'Authentication failed' }, { status: 403 })
    }

    return sensor
}


// ═══════════════════════════════════════════════════════════════════
// GET /v1/collective/blocklist
// ═══════════════════════════════════════════════════════════════════

export async function handleCollectiveBlocklist(
    request: Request,
    env: Env,
    requestId: string,
): Promise<Response> {
    const db = new Database(env.HYPERDRIVE.connectionString)

    try {
        const sensorOrError = await authenticateSensor(request, db)
        if (sensorOrError instanceof Response) return sensorOrError

        // Get active blocklist entries (not expired)
        const entries = await db.query<{
            source_hash: string
            reason: string
            confidence: number
            reporting_sensors: number
            expires_at: string
        }>(`
            SELECT source_hash, reason, confidence, reporting_sensors, expires_at
            FROM collective_blocklist
            WHERE expires_at > NOW()
              AND confidence >= 0.5
            ORDER BY confidence DESC, reporting_sensors DESC
            LIMIT 10000
        `)

        return Response.json({
            blocklist: entries.rows,
            count: entries.rows.length,
            updated_at: new Date().toISOString(),
        })
    } finally {
        await db.dispose()
    }
}


// ═══════════════════════════════════════════════════════════════════
// GET /v1/collective/rules
// ═══════════════════════════════════════════════════════════════════

export async function handleCollectiveRules(
    request: Request,
    env: Env,
    requestId: string,
): Promise<Response> {
    const db = new Database(env.HYPERDRIVE.connectionString)

    try {
        const sensorOrError = await authenticateSensor(request, db)
        if (sensorOrError instanceof Response) return sensorOrError

        const sensor = sensorOrError

        // Get rules updated since sensor's last known version
        const url = new URL(request.url)
        const sinceParam = url.searchParams.get('since') ?? '1970-01-01T00:00:00Z'
        // SAA-069: Validate timestamp format before SQL to prevent error-based
        // schema leakage and malformed query errors.
        const sinceDate = new Date(sinceParam)
        if (isNaN(sinceDate.getTime())) {
            return Response.json({ error: 'Invalid timestamp format for since parameter' }, { status: 400 })
        }
        const since = sinceDate.toISOString()

        const rules = await db.query<{
            rule_id: string
            rule_type: string
            name: string
            rule_content: string
            confidence: number
            version: number
        }>(`
            SELECT rule_id, rule_type, name, rule_content, confidence, version
            FROM generated_rules
            WHERE status = 'active'
              AND (updated_at > $1 OR created_at > $1)
            ORDER BY rule_type, rule_id
        `, [since])

        // Also get crowdsourced detection rules
        const detectionRules = await db.query<{
            rule_id: string
            name: string
            signal_type: string
            match_type: string
            match_patterns: unknown
            base_confidence: number
        }>(`
            SELECT rule_id, name, signal_type, match_type, match_patterns, base_confidence
            FROM detection_rules
            WHERE enabled = TRUE
              AND (updated_at > $1 OR created_at > $1)
            ORDER BY signal_type, rule_id
        `, [since])

        // Update sensor's rules version
        const rulesVersion = new Date().toISOString()
        await db.execute(`
            UPDATE collective_sensors
            SET rules_version = $2, updated_at = NOW()
            WHERE id = $1
        `, [sensor.id, rulesVersion])

        return Response.json({
            generated_rules: rules.rows,
            detection_rules: detectionRules.rows,
            rules_version: rulesVersion,
            total: rules.rows.length + detectionRules.rows.length,
        })
    } finally {
        await db.dispose()
    }
}


// ═══════════════════════════════════════════════════════════════════
// GET /v1/collective/posture
// ═══════════════════════════════════════════════════════════════════

export async function handleCollectivePosture(
    request: Request,
    env: Env,
    requestId: string,
): Promise<Response> {
    const db = new Database(env.HYPERDRIVE.connectionString)

    try {
        const sensorOrError = await authenticateSensor(request, db)
        if (sensorOrError instanceof Response) return sensorOrError

        const sensor = sensorOrError

        // Get posture score
        const score = await db.queryOne<{
            domain: string
            score: number
            grade: string
            critical_count: number
            high_count: number
            medium_count: number
            low_count: number
            info_count: number
            sampled_paths: number
            assessed_at: string
        }>(`
            SELECT domain, score, grade,
                   critical_count, high_count, medium_count, low_count, info_count,
                   sampled_paths, assessed_at
            FROM posture_scores
            WHERE sensor_id = $1
        `, [sensor.id])

        // Get all findings
        const findings = await db.query<{
            finding: string
            severity: string
            category: string
            remediation: string
            source: string
            confirmed: boolean
        }>(`
            SELECT finding, severity, category, remediation, source, confirmed
            FROM posture_findings
            WHERE sensor_id = $1
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    ELSE 4
                END
        `, [sensor.id])

        // Threat landscape: top attack classes, emerging threats, geographic heatmap
        const landscape = await getThreatLandscape(db)
        const top_attack_classes = landscape.attack_velocity
            .sort((a, b) => b.signal_count_24h - a.signal_count_24h)
            .slice(0, 3)
            .map(({ signal_type, signal_count_24h, signals_per_hour }) => ({
                signal_type,
                signal_count_24h,
                signals_per_hour,
            }))
        const emerging_threats = landscape.emerging_threats.map(({ signal_type, velocity_increase_pct }) => ({
            signal_type,
            velocity_increase_pct,
        }))
        const geographic_heatmap: Record<string, number> = {}
        for (const row of landscape.by_class_and_country) {
            geographic_heatmap[row.source_country] = (geographic_heatmap[row.source_country] ?? 0) + row.count
        }
        const threat_landscape = {
            top_attack_classes,
            emerging_threats,
            geographic_heatmap,
            campaign_alerts: landscape.campaign_alerts.length > 0 ? landscape.campaign_alerts : undefined,
        }

        if (!score) {
            return Response.json({
                message: 'No posture assessment yet. Deploy INVARIANT and let traffic flow.',
                findings: [],
                threat_landscape,
            })
        }

        return Response.json({
            posture: score,
            findings: findings.rows,
            threat_landscape,
        })
    } finally {
        await db.dispose()
    }
}


// ═══════════════════════════════════════════════════════════════════
// GET /v1/collective/threat-map
// ═══════════════════════════════════════════════════════════════════

export async function handleCollectiveThreatMap(
    request: Request,
    env: Env,
    requestId: string,
): Promise<Response> {
    const db = new Database(env.HYPERDRIVE.connectionString)

    try {
        const sensorOrError = await authenticateSensor(request, db)
        if (sensorOrError instanceof Response) return sensorOrError

        const countries = await getThreatMapCountries(db)
        return Response.json({
            countries,
            updated_at: new Date().toISOString(),
        })
    } finally {
        await db.dispose()
    }
}


// ═══════════════════════════════════════════════════════════════════
// GET /v1/collective/stats
// ═══════════════════════════════════════════════════════════════════

export async function handleCollectiveStats(
    request: Request,
    env: Env,
    requestId: string,
): Promise<Response> {
    const db = new Database(env.HYPERDRIVE.connectionString)
    try {
        const stats = await db.queryOne<{
            total_contributors: number
            total_rules_submitted: number
            approved_rules: number
            pending_rules: number
        }>(`
            SELECT 
                (SELECT COUNT(*)::int FROM collective_sensors) as total_contributors,
                (SELECT COUNT(*)::int FROM detection_rules) as total_rules_submitted,
                (SELECT COUNT(*)::int FROM detection_rules WHERE enabled = true) as approved_rules,
                (SELECT COUNT(*)::int FROM detection_rules WHERE enabled = false) as pending_rules
        `) || { total_contributors: 0, total_rules_submitted: 0, approved_rules: 0, pending_rules: 0 };
        
        // SAA-096: Never expose subscriber emails or company names — even masked emails
        // are reversible for short local-parts and expose customer PII. Aggregate
        // counts are safe to publish; individual identity is not.
        return Response.json({
            total_contributors: stats.total_contributors,
            total_rules_submitted: stats.total_rules_submitted,
            approved_rules: stats.approved_rules,
            pending_rules: stats.pending_rules,
        })
    } finally {
        await db.dispose()
    }
}
