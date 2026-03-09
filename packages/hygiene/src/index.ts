import { promises as dns } from 'node:dns'
import tls from 'node:tls'

export type IssueSeverity = 'critical' | 'warning'
export type IssueCategory = 'dns' | 'tls' | 'email' | 'takeover' | 'headers'

export interface HygieneIssue {
  id: string
  severity: IssueSeverity
  category: IssueCategory
  title: string
  details: string
  evidence?: string
}

export interface DmarcStatus {
  present: boolean
  policy: 'reject' | 'quarantine' | 'none' | 'unknown' | null
  record: string | null
}

export interface SpfStatus {
  present: boolean
  enforcement: 'hardfail' | 'softfail' | 'none' | 'unknown'
  record: string | null
}

export interface DkimStatus {
  selectorsChecked: string[]
  foundSelectors: string[]
  records: Record<string, string[]>
}

export interface DnsResult {
  domain: string
  dmarc: DmarcStatus
  spf: SpfStatus
  dkim: DkimStatus
  issues: HygieneIssue[]
}

export interface TlsResult {
  domain: string
  connected: boolean
  protocol: string | null
  cipher: {
    name: string
    standardName: string | null
    version: string | null
  } | null
  certificate: {
    validTo: string | null
    daysRemaining: number | null
    subject: string | null
    issuer: string | null
  }
  issues: HygieneIssue[]
}

export interface TakeoverResult {
  domain: string
  cnameChain: string[]
  potentialTakeover: boolean
  provider: string | null
  fingerprint: string | null
  checkedHost: string | null
  httpStatus: number | null
  issues: HygieneIssue[]
}

export type HeaderName =
  | 'strict-transport-security'
  | 'content-security-policy'
  | 'x-frame-options'
  | 'x-content-type-options'
  | 'referrer-policy'
  | 'permissions-policy'

export type HeaderStatus = 'pass' | 'warn' | 'fail'

export interface HeaderCheck {
  status: HeaderStatus
  value: string | null
  details: string
}

export interface HeaderResult {
  url: string
  statusCode: number | null
  headers: Record<string, string>
  checks: Record<HeaderName, HeaderCheck>
  issues: HygieneIssue[]
}

export interface HygieneReport {
  domain: string
  score: number
  issues: HygieneIssue[]
  timestamp: string
}

const COMMON_DKIM_SELECTORS = ['google', 'mailchimp', 'sendgrid', 'default', 'mail']

const TAKEOVER_FINGERPRINTS: Array<{
  provider: string
  hostPattern: RegExp
  bodyPattern: RegExp
}> = [
  {
    provider: 'GitHub Pages',
    hostPattern: /\.github\.io\.?$/i,
    bodyPattern: /There isn'?t a GitHub Pages site/i,
  },
  {
    provider: 'Heroku',
    hostPattern: /\.herokuapp\.com\.?$/i,
    bodyPattern: /No such app/i,
  },
  {
    provider: 'Netlify',
    hostPattern: /\.netlify(?:\.app|\.com)?\.?$/i,
    bodyPattern: /Not Found - Request ID/i,
  },
  {
    provider: 'Amazon S3',
    hostPattern: /\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\.?$/i,
    bodyPattern: /NoSuchBucket/i,
  },
  {
    provider: 'Fastly',
    hostPattern: /\.fastly(?:lb)?\.net\.?$/i,
    bodyPattern: /Fastly error: unknown domain/i,
  },
]

function toHostname(input: string): string {
  const trimmed = input.trim()
  if (!trimmed) {
    throw new Error('target is empty')
  }

  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  const hostname = new URL(candidate).hostname.toLowerCase().replace(/\.$/, '')
  if (!hostname) {
    throw new Error('target hostname is empty')
  }
  return hostname
}

function toScanUrl(input: string): string {
  const trimmed = input.trim()
  if (!trimmed) {
    throw new Error('target is empty')
  }

  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed
  }
  return `https://${trimmed}`
}

async function resolveTxtRecords(name: string): Promise<string[]> {
  try {
    const records = await dns.resolve(name, 'TXT')
    const flattened: string[] = []
    for (const record of records as string[][]) {
      if (Array.isArray(record)) {
        flattened.push(record.join(''))
      }
    }
    return flattened
  } catch {
    return []
  }
}

function parseDmarcPolicy(record: string | null): DmarcStatus['policy'] {
  if (!record) return null
  const match = record.match(/(?:^|;)\s*p=([a-z]+)/i)
  if (!match) return 'unknown'
  const policy = match[1].toLowerCase()
  if (policy === 'reject' || policy === 'quarantine' || policy === 'none') {
    return policy
  }
  return 'unknown'
}

function parseSpfEnforcement(record: string | null): SpfStatus['enforcement'] {
  if (!record) return 'none'
  if (/\s-all\b/i.test(record)) return 'hardfail'
  if (/\s~all\b/i.test(record)) return 'softfail'
  if (/\s(?:\+all|\?all)\b/i.test(record)) return 'none'
  return 'unknown'
}

function calculateDaysRemaining(validTo: string | null): number | null {
  if (!validTo) return null
  const expiryMs = new Date(validTo).getTime()
  if (!Number.isFinite(expiryMs)) return null
  const remainingMs = expiryMs - Date.now()
  return Math.floor(remainingMs / (1000 * 60 * 60 * 24))
}

function normalizeCertName(value: string | string[] | undefined): string | null {
  if (typeof value === 'string') return value
  if (Array.isArray(value) && typeof value[0] === 'string') return value[0]
  return null
}

function classifyCipherStrength(name: string): 'strong' | 'weak' | 'unknown' {
  const upper = name.toUpperCase()
  if (/(RC4|3DES|DES|NULL|MD5|EXPORT|ANON)/.test(upper)) {
    return 'weak'
  }
  if (/(CHACHA20|AES_256|AES256|AES_128_GCM|AES128-GCM|GCM)/.test(upper)) {
    return 'strong'
  }
  return 'unknown'
}

async function fetchWithTimeout(url: string, timeoutMs = 7000): Promise<Response> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
    })
  } finally {
    clearTimeout(timeout)
  }
}

async function fetchHostMaterial(host: string): Promise<{ host: string; status: number | null; body: string | null }> {
  const urls = [`https://${host}`, `http://${host}`]
  for (const url of urls) {
    try {
      const response = await fetchWithTimeout(url)
      const body = (await response.text()).slice(0, 5000)
      return {
        host,
        status: response.status,
        body,
      }
    } catch {
      continue
    }
  }

  return { host, status: null, body: null }
}

async function resolveCnameChain(domain: string, maxDepth = 6): Promise<string[]> {
  const chain: string[] = []
  const visited = new Set<string>()
  let current = domain

  for (let depth = 0; depth < maxDepth; depth++) {
    if (visited.has(current)) {
      break
    }
    visited.add(current)

    let records: string[]
    try {
      records = await dns.resolveCname(current)
    } catch {
      break
    }

    if (records.length === 0) {
      break
    }

    const next = records[0].toLowerCase().replace(/\.$/, '')
    chain.push(next)
    current = next
  }

  return chain
}

function evaluateHsts(value: string | null): HeaderCheck {
  if (!value) {
    return { status: 'fail', value, details: 'Missing header' }
  }
  const maxAgeMatch = value.match(/max-age=(\d+)/i)
  const maxAge = maxAgeMatch ? Number.parseInt(maxAgeMatch[1], 10) : NaN
  if (!Number.isFinite(maxAge) || maxAge < 15_552_000) {
    return { status: 'warn', value, details: 'Header present but max-age is too low' }
  }
  if (!/includesubdomains/i.test(value)) {
    return { status: 'warn', value, details: 'Header present without includeSubDomains' }
  }
  return { status: 'pass', value, details: 'Header is strong' }
}

function evaluateCsp(value: string | null): HeaderCheck {
  if (!value) {
    return { status: 'fail', value, details: 'Missing header' }
  }
  if (/\bunsafe-inline\b|\bunsafe-eval\b/i.test(value)) {
    return { status: 'warn', value, details: 'Policy allows unsafe script execution' }
  }
  if (!/\bdefault-src\b|\bscript-src\b/i.test(value)) {
    return { status: 'warn', value, details: 'Policy is present but lacks core directives' }
  }
  return { status: 'pass', value, details: 'Header is strong' }
}

function evaluateXFrameOptions(value: string | null): HeaderCheck {
  if (!value) {
    return { status: 'fail', value, details: 'Missing header' }
  }
  if (/^\s*(DENY|SAMEORIGIN)\s*$/i.test(value)) {
    return { status: 'pass', value, details: 'Header is strong' }
  }
  return { status: 'warn', value, details: 'Header present but weak value' }
}

function evaluateXContentTypeOptions(value: string | null): HeaderCheck {
  if (!value) {
    return { status: 'fail', value, details: 'Missing header' }
  }
  if (/^\s*nosniff\s*$/i.test(value)) {
    return { status: 'pass', value, details: 'Header is strong' }
  }
  return { status: 'warn', value, details: 'Header present but value is not nosniff' }
}

function evaluateReferrerPolicy(value: string | null): HeaderCheck {
  if (!value) {
    return { status: 'fail', value, details: 'Missing header' }
  }
  if (/^\s*(no-referrer|strict-origin|strict-origin-when-cross-origin|same-origin)\s*$/i.test(value)) {
    return { status: 'pass', value, details: 'Header is strong' }
  }
  return { status: 'warn', value, details: 'Header present but policy is weak' }
}

function evaluatePermissionsPolicy(value: string | null): HeaderCheck {
  if (!value) {
    return { status: 'fail', value, details: 'Missing header' }
  }
  if (/[*]\s*$|\(\s*[*]\s*\)|=\s*[*]/.test(value)) {
    return { status: 'warn', value, details: 'Header present but grants broad permissions' }
  }
  return { status: 'pass', value, details: 'Header is present' }
}

function headerIssueSeverity(status: HeaderStatus): IssueSeverity | null {
  if (status === 'fail') return 'critical'
  if (status === 'warn') return 'warning'
  return null
}

export async function checkDns(domain: string): Promise<DnsResult> {
  const hostname = toHostname(domain)
  const issues: HygieneIssue[] = []

  const [dmarcTxt, spfTxt] = await Promise.all([
    resolveTxtRecords(`_dmarc.${hostname}`),
    resolveTxtRecords(hostname),
  ])

  const dmarcRecord = dmarcTxt.find((record) => /^v=dmarc1\b/i.test(record)) ?? null
  const dmarcPolicy = parseDmarcPolicy(dmarcRecord)
  const dmarc: DmarcStatus = {
    present: dmarcRecord !== null,
    policy: dmarcPolicy,
    record: dmarcRecord,
  }

  if (!dmarc.present) {
    issues.push({
      id: 'dns-dmarc-missing',
      severity: 'warning',
      category: 'email',
      title: 'DMARC record missing',
      details: `No DMARC TXT record found for _dmarc.${hostname}.`,
    })
  } else if (dmarc.policy === 'none' || dmarc.policy === 'unknown') {
    issues.push({
      id: 'dns-dmarc-weak-policy',
      severity: 'warning',
      category: 'email',
      title: 'DMARC policy is not enforcing',
      details: `DMARC policy is ${dmarc.policy}. Prefer quarantine or reject.`,
      evidence: dmarc.record ?? undefined,
    })
  }

  const spfRecord = spfTxt.find((record) => /^v=spf1\b/i.test(record)) ?? null
  const spfEnforcement = parseSpfEnforcement(spfRecord)
  const spf: SpfStatus = {
    present: spfRecord !== null,
    enforcement: spfEnforcement,
    record: spfRecord,
  }

  if (!spf.present) {
    issues.push({
      id: 'dns-spf-missing',
      severity: 'warning',
      category: 'email',
      title: 'SPF record missing',
      details: `No SPF TXT record found for ${hostname}.`,
    })
  } else if (spf.enforcement !== 'hardfail') {
    issues.push({
      id: 'dns-spf-weak',
      severity: 'warning',
      category: 'email',
      title: 'SPF policy is weak',
      details: `SPF enforcement is ${spf.enforcement}. Prefer -all.`,
      evidence: spf.record ?? undefined,
    })
  }

  const dkimRecords: Record<string, string[]> = {}
  const foundSelectors: string[] = []
  await Promise.all(
    COMMON_DKIM_SELECTORS.map(async (selector) => {
      const recordName = `${selector}._domainkey.${hostname}`
      const records = await resolveTxtRecords(recordName)
      dkimRecords[selector] = records
      if (records.some((record) => /v=dkim1/i.test(record))) {
        foundSelectors.push(selector)
      }
    }),
  )

  if (foundSelectors.length === 0) {
    issues.push({
      id: 'dns-dkim-not-found',
      severity: 'warning',
      category: 'email',
      title: 'No common DKIM selectors resolved',
      details: `Checked selectors: ${COMMON_DKIM_SELECTORS.join(', ')}.`,
    })
  }

  return {
    domain: hostname,
    dmarc,
    spf,
    dkim: {
      selectorsChecked: [...COMMON_DKIM_SELECTORS],
      foundSelectors,
      records: dkimRecords,
    },
    issues,
  }
}

export async function checkTls(domain: string): Promise<TlsResult> {
  const hostname = toHostname(domain)

  return await new Promise<TlsResult>((resolve) => {
    let settled = false
    const finish = (result: TlsResult): void => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(result)
    }

    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 7000,
    })

    socket.once('secureConnect', () => {
      const issues: HygieneIssue[] = []
      const protocol = socket.getProtocol()
      const cipher = socket.getCipher()
      const cert = socket.getPeerCertificate()

      const validTo = typeof cert.valid_to === 'string' ? cert.valid_to : null
      const daysRemaining = calculateDaysRemaining(validTo)

      if (daysRemaining !== null && daysRemaining < 0) {
        issues.push({
          id: 'tls-cert-expired',
          severity: 'critical',
          category: 'tls',
          title: 'TLS certificate expired',
          details: `Certificate expired ${Math.abs(daysRemaining)} day(s) ago.`,
          evidence: validTo ?? undefined,
        })
      } else if (daysRemaining !== null && daysRemaining < 30) {
        issues.push({
          id: 'tls-cert-expiring-soon',
          severity: 'warning',
          category: 'tls',
          title: 'TLS certificate expiring soon',
          details: `Certificate expires in ${daysRemaining} day(s).`,
          evidence: validTo ?? undefined,
        })
      }

      if (protocol === 'TLSv1.2') {
        issues.push({
          id: 'tls-protocol-legacy',
          severity: 'warning',
          category: 'tls',
          title: 'Using TLS 1.2',
          details: 'TLS 1.3 is preferred where supported.',
          evidence: protocol,
        })
      } else if (!protocol || protocol === 'TLSv1.1' || protocol === 'TLSv1' || protocol === 'SSLv3') {
        issues.push({
          id: 'tls-protocol-weak',
          severity: 'critical',
          category: 'tls',
          title: 'Weak TLS protocol negotiated',
          details: `Negotiated protocol: ${protocol ?? 'unknown'}.`,
          evidence: protocol ?? undefined,
        })
      }

      const cipherName = cipher.standardName ?? cipher.name ?? ''
      const strength = classifyCipherStrength(cipherName)
      if (strength === 'weak') {
        issues.push({
          id: 'tls-cipher-weak',
          severity: 'critical',
          category: 'tls',
          title: 'Weak TLS cipher negotiated',
          details: `Negotiated cipher appears weak: ${cipherName}.`,
          evidence: cipherName,
        })
      } else if (strength === 'unknown') {
        issues.push({
          id: 'tls-cipher-unknown-strength',
          severity: 'warning',
          category: 'tls',
          title: 'Cipher strength unknown',
          details: `Unable to classify cipher strength for ${cipherName || 'unknown'}.`,
          evidence: cipherName || undefined,
        })
      }

      finish({
        domain: hostname,
        connected: true,
        protocol: protocol ?? null,
        cipher: {
          name: cipher.name,
          standardName: cipher.standardName ?? null,
          version: cipher.version ?? null,
        },
        certificate: {
          validTo,
          daysRemaining,
          subject: normalizeCertName(cert.subject?.CN),
          issuer: normalizeCertName(cert.issuer?.CN),
        },
        issues,
      })
    })

    socket.once('timeout', () => {
      finish({
        domain: hostname,
        connected: false,
        protocol: null,
        cipher: null,
        certificate: {
          validTo: null,
          daysRemaining: null,
          subject: null,
          issuer: null,
        },
        issues: [
          {
            id: 'tls-timeout',
            severity: 'critical',
            category: 'tls',
            title: 'TLS connection timeout',
            details: `Timed out connecting to ${hostname}:443.`,
          },
        ],
      })
    })

    socket.once('error', (error) => {
      finish({
        domain: hostname,
        connected: false,
        protocol: null,
        cipher: null,
        certificate: {
          validTo: null,
          daysRemaining: null,
          subject: null,
          issuer: null,
        },
        issues: [
          {
            id: 'tls-connection-error',
            severity: 'critical',
            category: 'tls',
            title: 'TLS connection failed',
            details: error.message,
          },
        ],
      })
    })
  })
}

export async function checkSubdomainTakeover(domain: string): Promise<TakeoverResult> {
  const hostname = toHostname(domain)
  const cnameChain = await resolveCnameChain(hostname)
  const issues: HygieneIssue[] = []

  if (cnameChain.length === 0) {
    return {
      domain: hostname,
      cnameChain,
      potentialTakeover: false,
      provider: null,
      fingerprint: null,
      checkedHost: null,
      httpStatus: null,
      issues,
    }
  }

  const hostsToCheck = [hostname, ...cnameChain]
  const uniqueHosts = [...new Set(hostsToCheck)]
  const materials = await Promise.all(uniqueHosts.map((host) => fetchHostMaterial(host)))

  let detectedProvider: string | null = null
  let detectedFingerprint: string | null = null
  let detectedHost: string | null = null
  let detectedStatus: number | null = null

  for (const material of materials) {
    const body = material.body ?? ''
    for (const fingerprint of TAKEOVER_FINGERPRINTS) {
      const cnameMatchesProvider = cnameChain.some((entry) => fingerprint.hostPattern.test(entry))
      if (!cnameMatchesProvider) {
        continue
      }
      if (fingerprint.bodyPattern.test(body)) {
        detectedProvider = fingerprint.provider
        detectedFingerprint = fingerprint.bodyPattern.source
        detectedHost = material.host
        detectedStatus = material.status
        break
      }
    }
    if (detectedProvider) break
  }

  if (detectedProvider) {
    issues.push({
      id: 'subdomain-takeover-potential',
      severity: 'critical',
      category: 'takeover',
      title: 'Potential subdomain takeover detected',
      details: `CNAME chain points to ${detectedProvider} with an unclaimed-service fingerprint.`,
      evidence: `${detectedHost ?? hostname} (${detectedStatus ?? 'no-status'})`,
    })
  } else {
    for (const fingerprint of TAKEOVER_FINGERPRINTS) {
      const cnameMatchesProvider = cnameChain.some((entry) => fingerprint.hostPattern.test(entry))
      if (!cnameMatchesProvider) continue
      const material = materials.find((entry) => entry.host === hostname) ?? materials[0]
      if (material && material.status === 404) {
        issues.push({
          id: 'subdomain-takeover-suspected',
          severity: 'warning',
          category: 'takeover',
          title: 'Possible subdomain takeover condition',
          details: `CNAME points to ${fingerprint.provider} and returns HTTP 404.`,
          evidence: `${hostname} -> ${cnameChain[0]}`,
        })
        break
      }
    }
  }

  return {
    domain: hostname,
    cnameChain,
    potentialTakeover: detectedProvider !== null,
    provider: detectedProvider,
    fingerprint: detectedFingerprint,
    checkedHost: detectedHost,
    httpStatus: detectedStatus,
    issues,
  }
}

export async function checkSecurityHeaders(url: string): Promise<HeaderResult> {
  const normalizedUrl = toScanUrl(url)
  const issues: HygieneIssue[] = []
  let statusCode: number | null = null
  let headerMap: Record<string, string> = {}

  try {
    const response = await fetchWithTimeout(normalizedUrl)
    statusCode = response.status
    response.headers.forEach((value, key) => {
      headerMap[key.toLowerCase()] = value
    })
  } catch (error) {
    const checks: Record<HeaderName, HeaderCheck> = {
      'strict-transport-security': { status: 'fail', value: null, details: 'Request failed' },
      'content-security-policy': { status: 'fail', value: null, details: 'Request failed' },
      'x-frame-options': { status: 'fail', value: null, details: 'Request failed' },
      'x-content-type-options': { status: 'fail', value: null, details: 'Request failed' },
      'referrer-policy': { status: 'fail', value: null, details: 'Request failed' },
      'permissions-policy': { status: 'fail', value: null, details: 'Request failed' },
    }

    issues.push({
      id: 'headers-fetch-failed',
      severity: 'critical',
      category: 'headers',
      title: 'Failed to fetch target URL',
      details: error instanceof Error ? error.message : 'Unknown fetch error',
      evidence: normalizedUrl,
    })

    return {
      url: normalizedUrl,
      statusCode: null,
      headers: {},
      checks,
      issues,
    }
  }

  const checks: Record<HeaderName, HeaderCheck> = {
    'strict-transport-security': evaluateHsts(headerMap['strict-transport-security'] ?? null),
    'content-security-policy': evaluateCsp(headerMap['content-security-policy'] ?? null),
    'x-frame-options': evaluateXFrameOptions(headerMap['x-frame-options'] ?? null),
    'x-content-type-options': evaluateXContentTypeOptions(headerMap['x-content-type-options'] ?? null),
    'referrer-policy': evaluateReferrerPolicy(headerMap['referrer-policy'] ?? null),
    'permissions-policy': evaluatePermissionsPolicy(headerMap['permissions-policy'] ?? null),
  }

  const headerLabels: Record<HeaderName, string> = {
    'strict-transport-security': 'Strict-Transport-Security',
    'content-security-policy': 'Content-Security-Policy',
    'x-frame-options': 'X-Frame-Options',
    'x-content-type-options': 'X-Content-Type-Options',
    'referrer-policy': 'Referrer-Policy',
    'permissions-policy': 'Permissions-Policy',
  }

  ;(Object.keys(checks) as HeaderName[]).forEach((name) => {
    const check = checks[name]
    const severity = headerIssueSeverity(check.status)
    if (!severity) return
    issues.push({
      id: `header-${name}-${check.status}`,
      severity,
      category: 'headers',
      title: `${headerLabels[name]} ${check.status === 'fail' ? 'missing' : 'is weak'}`,
      details: check.details,
      evidence: check.value ?? undefined,
    })
  })

  return {
    url: normalizedUrl,
    statusCode,
    headers: headerMap,
    checks,
    issues,
  }
}

export async function runFullHygieneScan(target: string): Promise<HygieneReport> {
  const domain = toHostname(target)
  const url = toScanUrl(target)

  const [dnsResult, tlsResult, takeoverResult, headerResult] = await Promise.all([
    checkDns(domain),
    checkTls(domain),
    checkSubdomainTakeover(domain),
    checkSecurityHeaders(url),
  ])

  const issues = [...dnsResult.issues, ...tlsResult.issues, ...takeoverResult.issues, ...headerResult.issues]
  const criticalCount = issues.filter((issue) => issue.severity === 'critical').length
  const warningCount = issues.filter((issue) => issue.severity === 'warning').length
  const score = Math.max(0, 100 - (criticalCount * 10) - (warningCount * 5))

  return {
    domain,
    score,
    issues,
    timestamp: new Date().toISOString(),
  }
}
