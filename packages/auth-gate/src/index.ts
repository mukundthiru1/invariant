import {
    bindStoreEnv,
    deleteChallenge,
    getChallenge,
    getCredential,
    storeChallenge,
    storeCredential,
} from './store.js'
import { configurePush } from './notifications.js'
import {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    setWebAuthnConfig,
    verifyAuthentication,
    verifyRegistration,
} from './webauthn.js'
import { encodeBase64 } from './webauthn-encoding.js'

interface AuthGateEnv {
    AUTH_GATE_CREDENTIAL_STORE: KVNamespace
    AUTH_GATE_CHALLENGE_STORE: KVNamespace
    DEPLOY_GATE_URL?: string
    WEBAUTHN_RP_NAME?: string
    WEBAUTHN_RP_ID?: string
    WEBAUTHN_ORIGIN?: string
    AUTH_GATE_DEFAULT_USER_ID?: string
    AUTH_DEFAULT_USER_ID?: string
    VAPID_PUBLIC_KEY?: string
    VAPID_PRIVATE_KEY?: string
    VAPID_SUBJECT?: string
}

interface AuthChallengeRequest {
    deployId?: string
    deploy_id?: string
    userId?: string
    platform?: string
    findings?: string | string[]
    diff?: string
    diffUrl?: string
}

interface VerificationRequest {
    deployId?: string
    deploy_id?: string
    userId?: string
    credential?: unknown
    findings?: string | string[]
    platform?: string
}

interface RegisterBeginRequest {
    userId?: string
    userName?: string
}

interface RegisterCompleteRequest {
    userId?: string
    credential?: unknown
}

class HttpError extends Error {
    status: number

    constructor(status: number, message: string) {
        super(message)
        this.status = status
    }
}

const TEXT_HTML = 'text/html; charset=utf-8'
const TEXT_JSON = 'application/json; charset=utf-8'

const SETUP_PAGE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register your passkey</title>
  <style>
    :root { --bg: #0a0a0a; --accent: #e8ff00; --muted: #9aa0a6; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: 'Inter', 'Segoe UI', sans-serif;
      color: #f6f7f8;
      background: linear-gradient(130deg, #050505 0%, #0a0a0a 35%, #121212 100%);
      display: grid;
      place-items: center;
      padding: 24px;
    }
    .panel {
      width: min(680px, 100%);
      border: 1px solid rgba(232, 255, 0, 0.25);
      border-radius: 18px;
      padding: 28px;
      background: rgba(10, 10, 10, 0.84);
      backdrop-filter: blur(2px);
      box-shadow: 0 14px 70px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(232, 255, 0, 0.35);
    }
    h1 { margin: 0 0 12px; font-size: 28px; letter-spacing: 0.02em; }
    p { margin: 8px 0; color: var(--muted); line-height: 1.55; }
    button {
      cursor: pointer;
      margin-top: 18px;
      border: 1px solid var(--accent);
      background: transparent;
      color: var(--accent);
      border-radius: 10px;
      padding: 13px 18px;
      font-size: 16px;
    }
    .ok { color: #d9ff67; border-color: #d9ff67; }
    .err { color: #ff8080; margin-top: 14px; min-height: 24px; }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
</head>
<body>
  <main class="panel">
    <h1>Register your device for Passkey approvals</h1>
    <p>Bind a local biometrics-capable passkey to your deployment approvals.</p>
    <p id="message">Your biometric never leaves your device.</p>
    <button id="register-btn" type="button">Register with Face ID / Touch ID</button>
    <div id="status" class="err"></div>
  </main>
  <script>
    const userId = localStorage.getItem('santh:auth-gate:user-id') || 'operator'
    localStorage.setItem('santh:auth-gate:user-id', userId)
    const statusEl = document.getElementById('status')
    const btn = document.getElementById('register-btn')

    btn.addEventListener('click', async () => {
      if (!window.SimpleWebAuthnBrowser) {
        statusEl.textContent = 'Passkey library failed to load. Check network and retry.'
        return
      }

      btn.disabled = true
      statusEl.className = 'ok'
      statusEl.textContent = 'Requesting enrollment options...'
      try {
        const init = await fetch('/v1/register/begin', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userId, userName: userId })
        })
        const opts = await init.json()
        if (!init.ok) throw new Error(opts?.error || 'Unable to start registration')

        const registration = await window.SimpleWebAuthnBrowser.startRegistration(opts)
        statusEl.textContent = 'Verifying credential with server...'

        const complete = await fetch('/v1/register/complete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userId, credential: registration })
        })
        const result = await complete.json()
        if (!complete.ok) throw new Error(result?.error || 'Registration failed')

        statusEl.textContent = 'Device registered. You can now approve deploys from this browser.'
      } catch (error) {
        statusEl.className = 'err'
        statusEl.textContent = error?.message || 'Registration failed.'
      } finally {
        btn.disabled = false
      }
    })
  </script>
</body>
</html>`

const APPROVE_PAGE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Approve deploy</title>
  <style>
    :root { --bg: #0a0a0a; --accent: #e8ff00; --muted: #a5adbd; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: 'Inter', 'Segoe UI', sans-serif;
      color: #f2f5f7;
      background: radial-gradient(circle at top, #171717 0%, #0a0a0a 55%, #040404 100%);
      display: grid;
      padding: 24px;
    }
    .shell {
      width: min(900px, 100%);
      margin: 0 auto;
      background: rgba(10, 10, 10, 0.88);
      border: 1px solid rgba(232, 255, 0, 0.25);
      border-radius: 16px;
      padding: 22px;
      box-shadow: 0 18px 70px rgba(0, 0, 0, 0.45);
    }
    h1 { margin: 0; font-size: 26px; }
    .muted { color: var(--muted); margin: 8px 0 16px; }
    .row { margin: 12px 0; }
    .label { color: var(--muted); font-size: 0.9rem; }
    .value { font-size: 1rem; font-weight: 600; }
    .preview {
      border: 1px solid rgba(255, 255, 255, 0.09);
      border-radius: 12px;
      min-height: 120px;
      padding: 12px;
      white-space: pre-wrap;
      overflow: auto;
      background: rgba(0, 0, 0, 0.35);
    }
    .actions { display: flex; gap: 12px; margin-top: 18px; flex-wrap: wrap; }
    .btn, .link {
      cursor: pointer;
      display: inline-flex;
      border-radius: 10px;
      padding: 12px 16px;
      text-decoration: none;
      border: 1px solid var(--accent);
      color: var(--accent);
      background: transparent;
    }
    .deny { color: #ffb4b4; border-color: #ff7d7d; }
    .result { margin-top: 14px; min-height: 24px; }
    .ok { color: #d9ff67; }
    .err { color: #ff8080; }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
</head>
<body>
  <section class="shell">
    <h1>Deploy approval</h1>
    <p class="muted">Review and authorize this pending deployment.</p>
    <div class="row"><span class="label">Deploy ID:</span> <span id="deploy" class="value"></span></div>
    <div class="row"><span class="label">Platform:</span> <span id="platform" class="value"></span></div>
    <div class="row"><span class="label">Findings summary:</span>
      <div id="findings" class="preview"></div>
    </div>
    <div class="row"><span class="label">Diff preview:</span>
      <div id="diff" class="preview"></div>
    </div>

    <div class="actions">
      <button id="deny" class="btn deny" type="button">Deny</button>
      <button id="approve" class="btn" type="button">Approve with Passkey</button>
      <a id="full-diff" class="link" target="_blank" rel="noopener">View full diff</a>
    </div>
    <div id="result" class="result"></div>
  </section>

  <script>
    const params = new URLSearchParams(window.location.search)
    const deployId = window.location.pathname.split('/').pop() || 'unknown'
    const platform = params.get('platform') || 'Unknown'
    const findings = params.get('findings') || 'No findings summary available'
    const diff = params.get('diff') || 'No diff preview'
    const diffUrl = params.get('diffUrl') || ''
    const userId = localStorage.getItem('santh:auth-gate:user-id') || 'operator'
    const approveUrl = window.location.href

    document.getElementById('deploy').textContent = deployId
    document.getElementById('platform').textContent = platform
    document.getElementById('findings').textContent = findings
    document.getElementById('diff').textContent = diff

    const fullDiff = document.getElementById('full-diff')
    if (diffUrl) {
      fullDiff.setAttribute('href', diffUrl)
    } else {
      fullDiff.style.display = 'none'
    }

    const statusEl = document.getElementById('result')
    document.getElementById('deny').addEventListener('click', () => {
      statusEl.className = 'result err'
      statusEl.textContent = 'Deploy denied.'
      setTimeout(() => window.close(), 900)
    })

    document.getElementById('approve').addEventListener('click', async () => {
      if (!window.SimpleWebAuthnBrowser) {
        statusEl.className = 'result err'
        statusEl.textContent = 'Passkey library unavailable.'
        return
      }

      statusEl.className = 'result ok'
      statusEl.textContent = 'Generating challenge...'
      try {
        const challengeResponse = await fetch('/v1/auth/challenge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ deployId, userId })
        })
        const challengePayload = await challengeResponse.json()
        if (!challengeResponse.ok) throw new Error(challengePayload?.error || 'Failed to create challenge')

        const assertion = await window.SimpleWebAuthnBrowser.startAuthentication({
          challenge: challengePayload.challenge,
          userVerification: 'preferred'
        })

        const verifyResponse = await fetch('/v1/auth/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deployId,
            userId,
            credential: assertion,
            platform,
            findings,
            approveUrl
          })
        })
        const verifyPayload = await verifyResponse.json()
        if (!verifyResponse.ok) throw new Error(verifyPayload?.error || 'Approval rejected')

        statusEl.className = 'result ok'
        statusEl.textContent = 'Deploy approved ✓'
        setTimeout(() => window.close(), 1200)
      } catch (error) {
        statusEl.className = 'result err'
        statusEl.textContent = error?.message || 'Approval failed.'
      }
    })
  </script>
</body>
</html>`

function createHeaders(contentType: string): Headers {
    return new Headers({
        'content-type': contentType,
        'cache-control': 'no-store',
    })
}

function textResponse(body: string, status = 200, contentType = TEXT_HTML): Response {
    return new Response(body, { status, headers: createHeaders(contentType) })
}

function jsonResponse(payload: unknown, status = 200): Response {
    return new Response(JSON.stringify(payload), { status, headers: createHeaders(TEXT_JSON) })
}

function normalizeText(value: unknown): string | undefined {
    if (typeof value !== 'string') return undefined
    const trimmed = value.trim()
    return trimmed.length > 0 ? trimmed : undefined
}

function toChallengeText(value: unknown): string | null {
    if (typeof value === 'string') return value
    if (value instanceof ArrayBuffer) return encodeBase64(new Uint8Array(value))
    if (value instanceof Uint8Array) return encodeBase64(value)
    return null
}

async function readJsonBody(request: Request): Promise<unknown> {
    const raw = await request.text()
    if (!raw.trim()) return {}
    try {
        return JSON.parse(raw)
    } catch {
        throw new HttpError(400, 'Invalid JSON body')
    }
}

function parseDeployId(payload: AuthChallengeRequest | VerificationRequest): string | null {
    const direct = normalizeText(payload.deployId)
    if (direct) return direct
    return normalizeText(payload.deploy_id) ?? null
}

function parseUserId(payload: AuthChallengeRequest | VerificationRequest | RegisterBeginRequest | RegisterCompleteRequest, env: AuthGateEnv): string {
    return normalizeText(payload.userId)
        ?? normalizeText(env.AUTH_GATE_DEFAULT_USER_ID)
        ?? normalizeText(env.AUTH_DEFAULT_USER_ID)
        ?? 'operator'
}

function configureRuntime(request: Request, env: AuthGateEnv): void {
    bindStoreEnv({
        AUTH_GATE_CREDENTIAL_STORE: env.AUTH_GATE_CREDENTIAL_STORE,
        AUTH_GATE_CHALLENGE_STORE: env.AUTH_GATE_CHALLENGE_STORE,
    })

    const url = new URL(request.url)
    setWebAuthnConfig({
        rpId: normalizeText(env.WEBAUTHN_RP_ID) ?? url.hostname,
        origin: normalizeText(env.WEBAUTHN_ORIGIN) ?? `${url.protocol}//${url.host}`,
        rpName: normalizeText(env.WEBAUTHN_RP_NAME) ?? 'Santh Deploy Gate',
    })

    configurePush({
        vapidPublicKey: env.VAPID_PUBLIC_KEY,
        vapidPrivateKey: env.VAPID_PRIVATE_KEY,
        vapidSubject: env.VAPID_SUBJECT,
    })
}

function buildApprovalPostPayload(userId: string, payload: VerificationRequest): {
    approved: true
    approvedBy: string
    platform?: string
    findings?: string | string[]
} {
    const result: {
        approved: true
        approvedBy: string
        platform?: string
        findings?: string | string[]
    } = {
        approved: true,
        approvedBy: userId,
    }
    const platform = normalizeText(payload.platform)
    if (platform) result.platform = platform
    if (payload.findings !== undefined) result.findings = payload.findings
    return result
}

async function callDeployGateApprove(env: AuthGateEnv, userId: string, deployId: string, payload: VerificationRequest): Promise<boolean> {
    if (!env.DEPLOY_GATE_URL) return true

    const approvalPayload = buildApprovalPostPayload(userId, payload)
    const endpoint = `${env.DEPLOY_GATE_URL.replace(/\/$/, '')}/v1/approve/${encodeURIComponent(deployId)}`
    const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(approvalPayload),
    })

    return response.ok
}

async function handleSetup(request: Request): Promise<Response> {
    if (request.method !== 'GET') {
        throw new HttpError(405, 'Method not allowed')
    }
    return textResponse(SETUP_PAGE)
}

async function handleRegisterBegin(request: Request, env: AuthGateEnv): Promise<Response> {
    if (request.method !== 'POST') {
        throw new HttpError(405, 'Method not allowed')
    }

    const payload = await readJsonBody(request) as RegisterBeginRequest
    const userId = parseUserId(payload, env)
    const userName = normalizeText(payload.userName) ?? userId
    const options = await generateRegistrationOptions(userId, userName)
    const challenge = toChallengeText(options.challenge)
    if (!challenge) throw new HttpError(500, 'Failed to generate registration challenge')

    await storeChallenge(`register:${userId}`, challenge)
    return jsonResponse({ ...options, userId })
}

async function handleRegisterComplete(request: Request, env: AuthGateEnv): Promise<Response> {
    if (request.method !== 'POST') throw new HttpError(405, 'Method not allowed')
    const payload = await readJsonBody(request) as RegisterCompleteRequest
    const userId = parseUserId(payload, env)
    const credential = payload.credential
    if (!credential) throw new HttpError(400, 'Missing credential payload')

    const expectedChallenge = await getChallenge(`register:${userId}`)
    if (!expectedChallenge) throw new HttpError(400, 'Missing registration challenge')

    const result = await verifyRegistration(
        credential as Parameters<typeof verifyRegistration>[0],
        expectedChallenge,
    )
    if (!result.verified || !result.storedCredential) {
        throw new HttpError(400, 'Registration verification failed')
    }

    await storeCredential(userId, {
        id: result.storedCredential.id,
        publicKey: result.storedCredential.publicKey,
        counter: result.storedCredential.counter,
        transports: result.storedCredential.transports,
    })
    await deleteChallenge(`register:${userId}`)
    return jsonResponse({ success: true, userId, credentialId: result.storedCredential.id })
}

async function handleAuthChallenge(request: Request, env: AuthGateEnv): Promise<Response> {
    if (request.method !== 'POST') throw new HttpError(405, 'Method not allowed')
    const payload = await readJsonBody(request) as AuthChallengeRequest
    const deployId = parseDeployId(payload)
    if (!deployId) throw new HttpError(400, 'Missing deploy_id')

    const userId = parseUserId(payload, env)
    const storedCredential = await getCredential(userId)
    if (!storedCredential) throw new HttpError(404, 'No credential on file')

    const options = await generateAuthenticationOptions(storedCredential.id)
    const challenge = toChallengeText(options.challenge)
    if (!challenge) throw new HttpError(500, 'Failed to generate challenge')

    await storeChallenge(deployId, challenge, 300)
    return jsonResponse({ deployId, challenge, ttl: 300, userId })
}

async function handleAuthVerify(request: Request, env: AuthGateEnv): Promise<Response> {
    if (request.method !== 'POST') throw new HttpError(405, 'Method not allowed')

    const payload = await readJsonBody(request) as VerificationRequest
    const deployId = parseDeployId(payload)
    if (!deployId) throw new HttpError(400, 'Missing deploy_id')
    const userId = parseUserId(payload, env)
    const credential = payload.credential
    if (!credential) throw new HttpError(400, 'Missing credential')

    const challenge = await getChallenge(deployId)
    if (!challenge) throw new HttpError(410, 'Challenge not found or expired')

    const credentialRecord = await getCredential(userId)
    if (!credentialRecord) throw new HttpError(404, 'No credential on file')

    const verified = await verifyAuthentication(
        credential as Parameters<typeof verifyAuthentication>[0],
        challenge,
        {
            id: credentialRecord.id,
            publicKey: credentialRecord.publicKey,
            counter: credentialRecord.counter,
            transports: credentialRecord.transports,
        },
    )
    if (!verified) throw new HttpError(401, 'Passkey assertion invalid')

    const approved = await callDeployGateApprove(env, userId, deployId, payload)
    if (!approved) throw new HttpError(502, 'Deploy gate call failed')

    await deleteChallenge(deployId)
    return jsonResponse({ success: true, status: 'approved', message: 'Deploy approved ✓' })
}

async function handleApproveUi(request: Request): Promise<Response> {
    if (request.method !== 'GET') throw new HttpError(405, 'Method not allowed')
    return textResponse(APPROVE_PAGE)
}

async function routeRequest(request: Request, env: AuthGateEnv): Promise<Response> {
    configureRuntime(request, env)
    const url = new URL(request.url)
    const pathname = url.pathname

    if (pathname === '/setup') {
        return handleSetup(request)
    }
    if (pathname === '/v1/register/begin') {
        return handleRegisterBegin(request, env)
    }
    if (pathname === '/v1/register/complete') {
        return handleRegisterComplete(request, env)
    }
    if (pathname === '/v1/auth/challenge') {
        return handleAuthChallenge(request, env)
    }
    if (pathname === '/v1/auth/verify') {
        return handleAuthVerify(request, env)
    }
    if (pathname === '/v1/approve-ui') {
        throw new HttpError(404, 'Missing deploy id')
    }
    if (pathname.startsWith('/v1/approve-ui/')) {
        return handleApproveUi(request)
    }
    if (pathname === '/health') {
        return jsonResponse({ status: 'ok', service: '@santh/auth-gate' })
    }

    throw new HttpError(404, 'Not found')
}

export default {
    async fetch(request: Request, env: AuthGateEnv): Promise<Response> {
        try {
            return await routeRequest(request, env)
        } catch (error) {
            if (error instanceof HttpError) {
                return jsonResponse({ error: error.message }, error.status)
            }
            return jsonResponse({ error: 'Internal server error' }, 500)
        }
    },
}
