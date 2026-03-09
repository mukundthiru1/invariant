# Route table patch for GET /v1/collective/threat-map

Apply these edits to `/home/mukund-thiru/Santh/intel/src/router/route-table.ts`.

## 1. Add import

Change the collective-api import from:

```ts
import {
    handleCollectiveBlocklist,
    handleCollectiveRules,
    handleCollectivePosture,
    handleCollectiveStats,
} from '../api/collective-api'
```

To:

```ts
import {
    handleCollectiveBlocklist,
    handleCollectiveRules,
    handleCollectivePosture,
    handleCollectiveStats,
    handleCollectiveThreatMap,
} from '../api/collective-api'
```

## 2. Add route (after the posture route, before the stats route)

Insert this block between the `/v1/collective/posture` and `/v1/collective/stats` route entries:

```ts
    {
        method: 'GET',
        pattern: '/v1/collective/threat-map',
        rateLimit: 'signals',
        auth: 'none',
        isPublic: false,
        rateLimitPrefix: 'colt',
        handler: async (env, ctx) =>
            handleCollectiveThreatMap(ctx.request, env, ctx.requestId),
    },
```
