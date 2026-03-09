# INVARIANT Quickstart — 5-Minute Integration Guide

Get INVARIANT protection on your app in under five minutes. This guide shows working code for **Next.js**, **Express**, **Hono**, **Fastify**, and **Koa**.

## Prerequisites

- Node.js 18+
- Your project already uses one of the supported frameworks

```bash
npm install @santh/invariant
# or
pnpm add @santh/invariant
```

## 1. Next.js (App Router / Middleware)

Use the Edge-compatible middleware in `middleware.ts` at the project root. It reads `invariant.config.json` from the project root and supports `monitor`, `sanitize`, `defend`, and `lockdown` modes.

**File: `middleware.ts` (project root)**

```ts
import { invariantNextjs } from '@santh/invariant/middleware/nextjs'

export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] }

const withInvariant = invariantNextjs({
  mode: 'defend',
  configPath: './invariant.config.json',
  verbose: process.env.NODE_ENV === 'development',
  exceptionRules: [
    { path: '/api/health', method: 'GET' },
    { path: /^\/webhooks\/.*/, method: 'POST' },
  ],
  onDetect(_req, match) {
    console.warn('[invariant] detection', match.surface, match.key, match.matches.map(m => m.class))
  },
  onBlock(_req, match) {
    console.error('[invariant] blocked', match.matches.map(m => ({ class: m.class, severity: m.severity })))
  },
})

export default withInvariant
```

**Minimal (monitor only, no blocking):**

```ts
import { invariantNextjs } from '@santh/invariant/middleware/nextjs'
export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] }
export default invariantNextjs({ mode: 'monitor' })
```

The middleware inspects query params, body (JSON), path, cookies, and headers. In `defend` mode it blocks requests when **critical** or **high** severity invariants exceed thresholds; in `lockdown` it blocks on any detection.

---

## 2. Express

Use the Express middleware. It uses `engine.detect()` on string values and `engine.detectHeaderInvariants()` on headers. Config is read from `invariant.config.json`; mode is `monitor` or `enforce`.

**File: `app.js` or `server.js`**

```js
const express = require('express')
const { invariantMiddleware } = require('@santh/invariant/middleware/express')

const app = express()
app.use(express.json())

app.use(invariantMiddleware({
  mode: 'enforce',
  configPath: require('path').join(process.cwd(), 'invariant.config.json'),
  verbose: process.env.NODE_ENV === 'development',
  onDetect(req, detection) {
    console.warn('[invariant]', req.method, req.path, detection.surface, detection.matches.map(m => m.class))
  },
  onBlock(req, detection) {
    console.error('[invariant] blocked', req.ip, detection.matches.map(m => m.class))
  },
}))

app.get('/api/users', (req, res) => res.json({ users: [] }))
app.listen(3000)
```

**Minimal:**

```js
const { invariantMiddleware } = require('@santh/invariant/middleware/express')
app.use(invariantMiddleware({ mode: 'monitor' }))
```

In `enforce` mode, requests that trigger `engine.shouldBlock(matches)` receive **403** with `{ error: 'blocked' }`.

---

## 3. Hono

Use the Hono middleware. It supports `monitor`, `sanitize`, `defend`, and `lockdown`, plus exception rules and optional sanitization of body/query/path/cookies/headers.

**File: `src/index.ts` (or your Hono app entry)**

```ts
import { Hono } from 'hono'
import { invariantHono } from '@santh/invariant/middleware/hono'

const app = new Hono()

app.use('*', invariantHono({
  mode: 'defend',
  configPath: './invariant.config.json',
  verbose: true,
  exceptionRules: [
    { path: '/health', method: 'GET' },
    { path: /^\/internal\/.*/, ip: /^10\./ },
  ],
  onDetect(ctx, match) {
    console.warn('[invariant]', ctx.req.method, ctx.req.path, match.surface, match.matches.map(m => m.class))
  },
  onBlock(ctx, match) {
    console.error('[invariant] blocked', match.matches.map(m => m.class))
  },
}))

app.get('/api/data', (c) => c.json({ data: [] }))
export default app
```

**Minimal:**

```ts
import { invariantHono } from '@santh/invariant/middleware/hono'
app.use('*', invariantHono({ mode: 'monitor' }))
```

All request inputs (query, body, path, cookies, headers) are collected and passed through the engine’s deep detection; in `defend` mode critical/high detections are blocked with **403**.

---

## 4. Fastify

Use the Fastify plugin. It registers `onRequest` and `preHandler` hooks and supports the same modes and exception rules as Hono/Next.js.

**File: `src/server.ts` or `app.js`**

```ts
import Fastify from 'fastify'
import { invariantFastify } from '@santh/invariant/middleware/fastify'

const app = Fastify()

await app.register(invariantFastify, {
  mode: 'defend',
  configPath: `${process.cwd()}/invariant.config.json`,
  verbose: process.env.NODE_ENV === 'development',
  exceptionRules: [
    { path: '/health', method: 'GET' },
  ],
  onDetect(req, match) {
    req.log.warn({ surface: match.surface, classes: match.matches.map(m => m.class) }, 'invariant detect')
  },
  onBlock(req, match) {
    req.log.error({ classes: match.matches.map(m => m.class) }, 'invariant block')
  },
})

app.get('/api/items', async () => ({ items: [] }))
await app.listen({ port: 3000 })
```

**Minimal:**

```ts
await app.register(invariantFastify, { mode: 'monitor' })
```

Blocked requests get **403** and `{ error: 'blocked' }`; security headers (e.g. `x-invariant-protected`, `x-content-type-options`) are applied to responses.

---

## 5. Koa

Use the Koa middleware. Same mode and exception semantics as Hono/Fastify.

**File: `src/app.ts` or `app.js`**

```ts
import Koa from 'koa'
import { invariantKoa } from '@santh/invariant/middleware/koa'

const app = new Koa()

app.use(invariantKoa({
  mode: 'defend',
  configPath: `${process.cwd()}/invariant.config.json`,
  verbose: true,
  exceptionRules: [
    { path: '/health', method: 'GET' },
  ],
  onDetect(ctx, match) {
    console.warn('[invariant]', ctx.method, ctx.path, match.surface, match.matches.map(m => m.class))
  },
  onBlock(ctx, match) {
    console.error('[invariant] blocked', match.matches.map(m => m.class))
  },
}))

app.use((ctx) => {
  ctx.body = { ok: true }
})
app.listen(3000)
```

**Minimal:**

```ts
import { invariantKoa } from '@santh/invariant/middleware/koa'
app.use(invariantKoa({ mode: 'monitor' }))
```

---

## Configuration file

Create `invariant.config.json` in the project root (optional; defaults apply if missing):

```json
{
  "v": 1,
  "category": "saas",
  "framework": "express",
  "mode": "monitor",
  "appType": "web",
  "dataClassification": "none",
  "compliance": []
}
```

- **mode**: `monitor` | `enforce` | `off` (config-level). Middleware may map `enforce` → `defend` and support extra modes like `sanitize` and `lockdown`.
- **category**: e.g. `saas`, `api`, `ecommerce`, `fintech`, `healthcare`, `content`, `devtools`, `gaming`, `education`, `government`, `other`.
- **framework**: e.g. `express`, `next`, `hono`, `fastify`, `koa`.
- **appType**: `web` | `api` | `saas` | `internal`.
- **dataClassification**: `pii` | `payment` | `health` | `none`.

See [Configuration](./configuration.md) for all options, thresholds, and exception rules.

---

## Modes (middleware)

| Mode        | Behavior |
|------------|----------|
| **monitor** | Log/callback only; never block. |
| **sanitize** | Strip dangerous patterns from body/query (e.g. path traversal, template literals); block only on **critical** severity. |
| **defend**   | Block on **critical** or **high** severity above threshold. |
| **lockdown** | Block on any detection. |

Use `monitor` first, tune exception rules and thresholds, then move to `defend` or `sanitize` as needed.

---

## Exception rules

Exception rules skip detection or blocking for matching requests. Options (all optional):

- **path**: string or RegExp — request path.
- **method**: string or string[] — HTTP method(s).
- **ip**: string or RegExp — client IP (from connection; do not use `X-Forwarded-For` for security decisions).
- **surface**: `query_param` | `body_param` | `header` | `cookie` | `path` | `ip` — only this surface is exempt.
- **key**: string or RegExp — parameter/key name.
- **class**: string or string[] — invariant class IDs to exempt for this rule.

Example: skip detection for health checks and a specific webhook path:

```ts
exceptionRules: [
  { path: '/api/health', method: 'GET' },
  { path: /^\/webhooks\/stripe/, method: 'POST' },
]
```

---

## Next steps

- [Detection classes reference](./classes.md)
- [Attack chains](./chains.md)
- [Full configuration](./configuration.md)
- [Codebase scanner](./scanner.md)
- [API reference](./api-reference.md)
