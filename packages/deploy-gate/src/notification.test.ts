import { afterEach, describe, expect, it, vi } from 'vitest'

import { notifyEmail, notifySlack, notifyWebPush } from './notification.js'

const originalEnv = { ...process.env }

afterEach(() => {
  vi.restoreAllMocks()
  process.env = { ...originalEnv }
})

describe('notification', () => {
  it('notifyWebPush returns true when endpoint accepts payload', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('ok', { status: 200 }))
    await expect(notifyWebPush({ endpoint: 'https://push.example' }, { id: 1 })).resolves.toBe(true)
  })

  it('notifySlack returns false on non-2xx response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('denied', { status: 500 }))
    await expect(notifySlack('https://hooks.slack.test', 'deploy-1', { findings: 2 })).resolves.toBe(false)
  })

  it('notifyEmail returns false when API key is missing', async () => {
    delete process.env.RESEND_API_KEY
    delete process.env.SENDGRID_API_KEY

    await expect(notifyEmail('a@example.com', 'deploy-1', [])).resolves.toBe(false)
  })

  it('notifyEmail uses Resend API when RESEND_API_KEY is set', async () => {
    process.env.RESEND_API_KEY = 'resend-key'
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('ok', { status: 200 }))

    await expect(notifyEmail('a@example.com', 'deploy-2', [{ severity: 'critical', message: 'x' }])).resolves.toBe(true)

    expect(fetchMock).toHaveBeenCalledWith(
      'https://api.resend.com/emails',
      expect.objectContaining({ method: 'POST' }),
    )
  })
})
