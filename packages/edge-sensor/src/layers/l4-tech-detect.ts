/**
 * Edge Sensor — Layer 4: Technology Detection
 *
 * Identifies the backend technology stack from request paths,
 * response headers, and server identification. Used for:
 * - Targeted CVE correlation
 * - Tech-specific rule selection
 * - Reducing false positives
 */

export function detectTechnology(path: string, headers: Headers): string | null {
    const p = path.toLowerCase()
    const poweredBy = (headers.get('x-powered-by') ?? '').toLowerCase()
    const server = (headers.get('server') ?? '').toLowerCase()
    const via = (headers.get('via') ?? '').toLowerCase()

    // CMS detection (path-based)
    if (p.includes('/wp-') || p.includes('/wordpress')) return 'wordpress'
    if (p.includes('/sites/default/') || p.includes('/core/misc/drupal')) return 'drupal'
    if (p.includes('/administrator/') && p.includes('/joomla')) return 'joomla'

    // Framework detection (path-based)
    if (p.includes('/_next/') || p.includes('/__nextjs')) return 'nextjs'
    if (p.includes('/_nuxt/')) return 'nuxt'
    if (p.includes('/actuator/') || p.includes('/spring')) return 'spring'
    if (p.includes('/__debug__') || p.includes('/_debug_toolbar')) return 'django'
    if (p.includes('/telescope/') || p.includes('/laravel')) return 'laravel'
    if (p.includes('/rails/') || p.endsWith('.rb')) return 'rails'

    // Language detection (extension-based)
    if (p.endsWith('.php') || p.includes('.php?') || p.includes('.phtml')) return 'php'
    if (p.endsWith('.aspx') || p.endsWith('.asp') || p.endsWith('.ashx')) return 'aspnet'
    if (p.endsWith('.jsp') || p.endsWith('.do') || p.endsWith('.action')) return 'java'
    if (p.endsWith('.py') || p.includes('/cgi-bin/')) return 'python'

    // Framework detection (header-based)
    if (poweredBy.includes('express')) return 'express'
    if (poweredBy.includes('next.js')) return 'nextjs'
    if (poweredBy.includes('php')) return 'php'
    if (poweredBy.includes('asp.net')) return 'aspnet'
    if (poweredBy.includes('django')) return 'django'
    if (poweredBy.includes('flask')) return 'python'
    if (poweredBy.includes('laravel')) return 'laravel'
    if (poweredBy.includes('rails') || poweredBy.includes('phusion')) return 'rails'

    // Server detection (server header)
    if (server.includes('nginx')) return 'nginx'
    if (server.includes('apache')) return 'apache'
    if (server.includes('cloudflare')) return 'cloudflare'
    if (server.includes('microsoft-iis')) return 'aspnet'
    if (server.includes('gunicorn') || server.includes('uvicorn')) return 'python'
    if (server.includes('openresty')) return 'nginx'

    // CDN/proxy detection
    if (via.includes('cloudflare') || headers.has('cf-ray')) return 'cloudflare'

    // API detection
    if (p.startsWith('/api/') || p.startsWith('/v1/') || p.startsWith('/v2/') || p.startsWith('/v3/')) return 'rest-api'
    if (p.includes('/graphql')) return 'graphql'

    return null
}
