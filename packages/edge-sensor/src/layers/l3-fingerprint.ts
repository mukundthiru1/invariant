/**
 * Edge Sensor — Layer 3: Client Fingerprinting
 *
 * Classifies HTTP clients by User-Agent + header presence patterns.
 * Used to adjust threat scoring and detection thresholds.
 */

import type { ClientClass } from './types.js'

export function classifyClient(headers: Headers): ClientClass {
    const ua = (headers.get('user-agent') ?? '').toLowerCase()
    if (!ua || ua.length === 0) return 'empty'
    if (ua.length < 15) return 'suspicious'
    if (/nuclei|sqlmap|nmap|nikto|masscan|zap|burp|dirbuster|gobuster|ffuf|wfuzz|feroxbuster|acunetix/i.test(ua)) return 'scanner'
    if (/googlebot|bingbot|yandexbot|baiduspider|duckduckbot|slurp|facebookexternalhit|twitterbot/i.test(ua)) return 'crawler'
    if (/curl|wget|python|go-http|java\/|okhttp|axios|node-fetch|httpie|libwww|scrapy|aiohttp|requests/i.test(ua)) return 'cli_tool'
    if (/postman|insomnia|paw\//i.test(ua)) return 'api_client'
    if (/mobile|android|iphone|ipad/i.test(ua) && /chrome|safari|firefox/i.test(ua)) return 'mobile_browser'
    if (/chrome|firefox|safari|edge|opera/i.test(ua)) {
        if (!headers.has('accept-language') && !headers.has('accept-encoding')) return 'suspicious'
        return 'browser'
    }
    if (/bot|crawl|spider|scrape|fetch/i.test(ua)) return 'bot'
    return 'suspicious'
}
