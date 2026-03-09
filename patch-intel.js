const fs = require('fs');
const path = require('path');

const apiDir = '/home/mukund-thiru/Santh/intel/src/api';

function patchSignalIngest() {
    const p = path.join(apiDir, 'signal-ingest.ts');
    let content = fs.readFileSync(p, 'utf8');

    // Cross-cutting: add error_code to errors
    content = content.replace(/\{\s*error:\s*'Unauthorized or invalid API key'/g, "{ error_code: 'UNAUTHORIZED', error: 'Unauthorized or invalid API key'");
    content = content.replace(/\{\s*error:\s*'Request body too large'/g, "{ error_code: 'PAYLOAD_TOO_LARGE', error: 'Request body too large'");
    content = content.replace(/\{\s*error:\s*'Invalid JSON body'/g, "{ error_code: 'INVALID_JSON', error: 'Invalid JSON body'");
    content = content.replace(/\{\s*error:\s*validation\.error/g, "{ error_code: 'VALIDATION_FAILED', error: validation.error");
    content = content.replace(/\{\s*error:\s*'Sensor quarantined due to anomalous behavior'/g, "{ error_code: 'QUARANTINED', error: 'Sensor quarantined due to anomalous behavior'");

    // Rewrite handleBatchIngest
    const newHandleBatchIngest = `export async function handleBatchIngest(request: Request, env: Env & { KV?: any }, requestId: string): Promise<Response> {
    let body: unknown;
    try {
        body = await request.json();
    } catch {
        return Response.json({ error_code: 'INVALID_JSON', error: 'Invalid JSON', request_id: requestId }, { status: 400, headers: { 'X-Request-ID': requestId } });
    }
    
    if (!Array.isArray(body)) {
        return Response.json({ error_code: 'EXPECTED_ARRAY', error: 'Expected array', request_id: requestId }, { status: 400, headers: { 'X-Request-ID': requestId } });
    }
    
    const events = body.slice(0, 100) as any[];
    let accepted = 0;
    let dropped = 0;
    const now = Date.now();
    const oneDay = 24 * 60 * 60 * 1000;
    
    for (const event of events) {
        // e. Sanitize all string fields
        if (typeof event.sensor_id === 'string') event.sensor_id = event.sensor_id.replace(/\\0/g, '').slice(0, 64);
        if (typeof event.class === 'string') event.class = event.class.replace(/\\0/g, '').slice(0, 128);
        if (typeof event.payload === 'string') event.payload = event.payload.replace(/\\0/g, '').slice(0, 8192);

        // c. Schema validation
        if (!event.sensor_id || !event.class || typeof event.confidence !== 'number' || !event.timestamp) {
            dropped++;
            continue;
        }
        if (event.confidence < 0.0 || event.confidence > 1.0) {
            dropped++;
            continue;
        }
        const ts = new Date(event.timestamp).getTime();
        if (isNaN(ts) || ts < now - 300000 || ts > now + 300000) { // ±5 minutes
            dropped++;
            continue;
        }
        
        if (env.KV) {
            // d. Sensor authentication check
            const sensorSecret = await env.KV.get("sensor_secret:" + event.sensor_id);
            if (sensorSecret) {
                const sigInput = event.sensor_id + event.timestamp;
                const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(sensorSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
                const expectedSigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(sigInput));
                const expectedSig = Array.from(new Uint8Array(expectedSigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
                const reqSig = request.headers.get('X-Sensor-Signature') || event.signature;
                if (reqSig !== expectedSig) {
                    dropped++;
                    continue;
                }
            }

            // b. Rate limiting per sensor_id
            const rlKey = "rl:sensor:" + event.sensor_id;
            let count = parseInt(await env.KV.get(rlKey) || '0', 10);
            if (count >= 1000) {
                dropped++;
                continue;
            }
            await env.KV.put(rlKey, (count + 1).toString(), { expirationTtl: 60 });

            // a. Replay protection
            const payloadHashInput = (event.payload || '') + event.timestamp;
            const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payloadHashInput));
            const signalId = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
            const dupKey = "dedup_sig:" + signalId;
            if (await env.KV.get(dupKey)) {
                dropped++;
                continue;
            }
            await env.KV.put(dupKey, '1', { expirationTtl: 300 });
        }
        
        accepted++;
    }
    
    return Response.json({ accepted, dropped, request_id: requestId }, { headers: { 'X-Request-ID': requestId } });
}`;

    content = content.replace(/export async function handleBatchIngest[\s\S]*?(?=$)/, newHandleBatchIngest);
    fs.writeFileSync(p, content);
}

function patchRuleDistribution() {
    const p = path.join(apiDir, 'rule-distribution.ts');
    let content = fs.readFileSync(p, 'utf8');

    // Add signature to SensorRule interface
    content = content.replace(/version: number\n\}/, "version: number\n    signature?: string\n}");

    // Replace handleSensorRules
    const oldFnStart = `export async function handleSensorRules(env: Env, requestId: string): Promise<Response> {`;
    const newFnStart = `export async function handleSensorRules(env: Env, requestId: any): Promise<Response> {
    const reqIdStr = typeof requestId === 'string' ? requestId : (requestId?.requestId || crypto.randomUUID());
    const req = typeof requestId === 'object' ? requestId.request : null;

    if (env.KV) {
        const rlKey = 'rl:global_dispatch';
        let count = parseInt(await env.KV.get(rlKey) || '0', 10);
        if (count >= 100) {
            return new Response(JSON.stringify({ error_code: 'RATE_LIMIT', error: 'Too many rule dispatches', request_id: reqIdStr }), { status: 429, headers: { 'X-Request-ID': reqIdStr } });
        }
        await env.KV.put(rlKey, (count + 1).toString(), { expirationTtl: 60 });
    }
    const dispatchKey = env.ADMIN_API_KEY || 'default';
`;
    content = content.replace(oldFnStart, newFnStart);

    // After rules mapping, process them
    const processRules = `
        const tier = req ? (req.headers.get('X-Sensor-Tier') || 'free') : 'free';
        let finalRules = [];

        const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(dispatchKey), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']);

        for (const rule of rules) {
            // b. Rule versioning in KV
            if (env.KV) {
                let ver = await env.KV.get("rule_ver:" + rule.ruleId);
                if (!ver) {
                    ver = rule.version.toString();
                    await env.KV.put("rule_ver:" + rule.ruleId, ver);
                }
                rule.version = parseInt(ver, 10);
            }

            // a. Sign rule
            const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(rule.ruleId + rule.version));
            rule.signature = Array.from(new Uint8Array(sigBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

            // c. Tier filtering
            if (tier !== 'free' || rule.baseConfidence < 0.9) {
                finalRules.push(rule);
            }

            // e. Log dispatch
            console.log(JSON.stringify({
                event: 'rule_dispatch',
                rule_id: rule.ruleId,
                rule_version: rule.version,
                target_sensor_count: 1,
                dispatch_timestamp: new Date().toISOString(),
                dispatch_signature: rule.signature
            }));
        }

        const version = hashRules(finalRules)
        const response: SensorRuleResponse = {
            version,
            rules: finalRules,
            generatedAt: new Date().toISOString(),
            ruleCount: finalRules.length,
            enabledCount: finalRules.filter(r => r.enabled).length,
        }

        return new Response(JSON.stringify(response), {
            headers: {
                'Content-Type': 'application/json',
                'Cache-Control': 'private, max-age=60, s-maxage=300',
                'X-Rules-Version': version,
                'X-Request-ID': reqIdStr
            },
        })
`;
    content = content.replace(/const version = hashRules\(rules\)[\s\S]*?\}\)/, processRules);

    // Patch handleEmergencyRule
    content = content.replace(/return new Response\('Unauthorized', \{ status: 401 \}\);/, "return Response.json({ error_code: 'UNAUTHORIZED', error: 'Unauthorized' }, { status: 401, headers: { 'X-Request-ID': crypto.randomUUID() } });");
    content = content.replace(/return new Response\('Invalid JSON', \{ status: 400 \}\);/, "return Response.json({ error_code: 'INVALID_JSON', error: 'Invalid JSON' }, { status: 400, headers: { 'X-Request-ID': crypto.randomUUID() } });");
    content = content.replace(/return new Response\('Invalid payload', \{ status: 400 \}\);/, "return Response.json({ error_code: 'INVALID_PAYLOAD', error: 'Invalid payload' }, { status: 400, headers: { 'X-Request-ID': crypto.randomUUID() } });");

    fs.writeFileSync(p, content);
}

function patchRuleSubmit() {
    const p = path.join(apiDir, 'rule-submit.ts');
    let content = fs.readFileSync(p, 'utf8');

    // Cross-cutting errors
    content = content.replace(/error:\s*'Missing Bearer token'/g, "error_code: 'UNAUTHORIZED', error: 'Missing Bearer token'");
    content = content.replace(/error:\s*'Invalid or inactive sensor'/g, "error_code: 'FORBIDDEN', error: 'Invalid or inactive sensor'");
    content = content.replace(/error:\s*'Request body too large'/g, "error_code: 'PAYLOAD_TOO_LARGE', error: 'Request body too large'");
    content = content.replace(/error:\s*'Invalid JSON'/g, "error_code: 'INVALID_JSON', error: 'Invalid JSON'");
    content = content.replace(/error:\s*validation\.error/g, "error_code: 'VALIDATION_FAILED', error: validation.error");

    // Add regex quantifiers/length check
    const regexCheck = `
                if (val.length > 500) {
                    return { valid: false, error: 'Regex exceeds 500 characters' }
                }
                const quantifiers = (val.match(/[+*?{]/g) || []).length;
                if (quantifiers > 10) {
                    return { valid: false, error: 'Regex contains more than 10 quantifiers (ReDoS risk)' }
                }
                // Compilation check: syntax errors must not reach the sensor network`;
    content = content.replace(/\/\/ Compilation check: syntax errors must not reach the sensor network/, regexCheck);

    // Modify handleRuleSubmission for duplicate, trust scoring, sandboxing, rate limiting
    const rlCheck = `
    // e. Rate limiting
    if (env.KV) {
        const rlKey = "submit_rl:" + sensor.id;
        let count = parseInt(await env.KV.get(rlKey) || '0', 10);
        if (count >= 10) {
            return new Response(JSON.stringify({ error_code: 'RATE_LIMIT', error: 'Too many submissions', request_id: requestId }), { status: 429, headers: { 'Content-Type': 'application/json', 'X-Request-ID': requestId } });
        }
        await env.KV.put(rlKey, (count + 1).toString(), { expirationTtl: 3600 });
    }
    const results`;

    content = content.replace(/const results/, rlCheck);

    // Duplicate logic
    const dupCheck = `
        // c. Duplicate rule hash
        const hashInput = new TextEncoder().encode(rule.signal_type + JSON.stringify(rule.patterns));
        const sha256Buf = await crypto.subtle.digest('SHA-256', hashInput);
        const dupHash = Array.from(new Uint8Array(sha256Buf)).map(b => b.toString(16).padStart(2, '0')).join('');
        if (env.KV) {
            if (await env.KV.get("rule_dup:" + dupHash)) {
                results.push({ proposed_id: rule.proposed_id, status: 'duplicate', reason: 'Duplicate exact pattern hash' });
                continue;
            }
            await env.KV.put("rule_dup:" + dupHash, '1');
        }

        if (await isDuplicate(db, rule)) {`;
    content = content.replace(/if \(await isDuplicate\(db, rule\)\) \{/, dupCheck);

    // Trust scoring
    const trustLogic = `
        const ruleId = \`crowd-\${sensor.id.slice(0, 8)}-\${rule.signal_type}-\${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}\`

        let status: 'draft' | 'active' | 'quarantine' = 'quarantine'
        let resultStatus: 'accepted' | 'queued' = 'queued'

        const trustScore = sensor.reputation_score / 100;
        const obsCount = rule.observation_count || 1;

        if (trustScore >= 0.7 && obsCount >= 3 && sensor.status === 'active') {
            status = 'active'
            resultStatus = 'accepted'
        } else if (trustScore >= 0.6) {
            status = 'quarantine'
            resultStatus = 'queued'
        } else {
            results.push({
                proposed_id: rule.proposed_id,
                status: 'rejected',
                reason: 'Sensor trust score too low (minimum: 0.6)',
            })
            continue
        }

        // Insert into detection_rules`;
        
    content = content.replace(/const ruleId = \`crowd-\$\{sensor\.id\.slice\(0, 8\)\}-\$\{rule\.signal_type\}-\$\{crypto\.randomUUID\(\)\.replace\(/-/g, ''\)\.slice\(0, 12\)\}\`[\s\S]*?\/\/ Insert into detection_rules/, trustLogic);
    
    // Update the DB query to use status (wait, detection_rules has 'enabled: boolean'. If status is 'active', enabled=true, else false)
    content = content.replace(/status === 'active', \/\/ enabled/g, "status === 'active',");

    fs.writeFileSync(p, content);
}

function patchChallenge() {
    const p = path.join(apiDir, 'challenge.ts');
    let content = fs.readFileSync(p, 'utf8');

    content = content.replace(/error:\s*'Service temporarily unavailable'/g, "error_code: 'SERVICE_UNAVAILABLE', error: 'Service temporarily unavailable'");
    
    fs.writeFileSync(p, content);
}

patchSignalIngest();
patchRuleDistribution();
patchRuleSubmit();
patchChallenge();
console.log('Patch complete.');
