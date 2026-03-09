export interface WebPushSubscription {
  endpoint: string
  keys?: {
    p256dh?: string
    auth?: string
  }
}

export async function notifyWebPush(subscription: WebPushSubscription, payload: unknown): Promise<boolean> {
  const response = await fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      TTL: '60',
    },
    body: JSON.stringify(payload),
  })

  return response.ok
}

export async function notifyEmail(to: string, deployId: string, findings: unknown): Promise<boolean> {
  const apiKey = (typeof process !== 'undefined' ? process.env['RESEND_API_KEY'] ?? process.env['SENDGRID_API_KEY'] : undefined) ?? ''
  if (!apiKey) return false

  const isResend = !!(typeof process !== 'undefined' && process.env['RESEND_API_KEY'])
  const url = isResend ? 'https://api.resend.com/emails' : 'https://api.sendgrid.com/v3/mail/send'
  const findingsArr = Array.isArray(findings) ? findings : [findings]
  const criticalCount = findingsArr.filter((f: unknown) => (f as Record<string, unknown>)?.['severity'] === 'critical').length
  const rows = findingsArr.slice(0, 20).map((f: unknown) => {
    const fi = f as Record<string, unknown>
    const sev = String(fi['severity'] ?? 'unknown').toUpperCase()
    const msg = String(fi['message'] ?? fi['description'] ?? JSON.stringify(f)).slice(0, 200)
    return `<li><strong>${sev}</strong>: ${msg}</li>`
  }).join('')
  const html = `<h2>Deploy Gate: Action Required</h2><p>Deploy <code>${deployId}</code> blocked — <strong>${findingsArr.length} findings</strong> (${criticalCount} critical).</p><ul>${rows}</ul>${findingsArr.length > 20 ? `<p>...and ${findingsArr.length - 20} more</p>` : ''}<p>Review and approve or reject in your CI dashboard.</p>`

  const body = isResend
    ? JSON.stringify({ from: 'santh@santh.io', to, subject: `[Santh] Deploy blocked: ${deployId}`, html })
    : JSON.stringify({ personalizations: [{ to: [{ email: to }] }], from: { email: 'santh@santh.io' }, subject: `[Santh] Deploy blocked: ${deployId}`, content: [{ type: 'text/html', value: html }] })

  try {
    const res = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' }, body })
    return res.ok
  } catch { return false }
}

export async function notifySlack(webhookUrl: string, deployId: string, findings: unknown): Promise<boolean> {
  const response = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      text: `Deploy ${deployId} requires approval`,
      findings,
    }),
  })

  return response.ok
}
