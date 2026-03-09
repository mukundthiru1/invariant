interface NotificationConfig {
    vapidPublicKey?: string
    vapidPrivateKey?: string
    vapidSubject?: string
}

export interface PushNotificationPayload {
    deployId: string
    findings: unknown
    approveUrl: string
}

export interface PushSubscriptionEnvelope {
    endpoint: string
    expirationTime?: number | null
    keys: {
        p256dh: string
        auth: string
    }
}

let config: NotificationConfig = {}

export function configurePush(next: NotificationConfig): void {
    config = { ...next }
}

function assertConfig(): { vapidPublicKey: string; vapidPrivateKey: string; vapidSubject: string } {
    const vapidPublicKey = config.vapidPublicKey
    const vapidPrivateKey = config.vapidPrivateKey
    const vapidSubject = config.vapidSubject ?? 'mailto:alerts@santh.io'
    if (!vapidPublicKey || !vapidPrivateKey) {
        throw new Error('Missing VAPID keys')
    }
    return { vapidPublicKey, vapidPrivateKey, vapidSubject }
}

export async function sendPushNotification(
    subscription: PushSubscriptionEnvelope,
    payload: PushNotificationPayload,
): Promise<void> {
    const { vapidPublicKey, vapidPrivateKey, vapidSubject } = assertConfig()
    const webPush = await import('web-push')
    const sender = webPush as typeof import('web-push')

    sender.setVapidDetails(vapidSubject, vapidPublicKey, vapidPrivateKey)
    await sender.sendNotification(
        subscription as Parameters<typeof sender.sendNotification>[0],
        JSON.stringify(payload),
        { TTL: 120 },
    )
}
