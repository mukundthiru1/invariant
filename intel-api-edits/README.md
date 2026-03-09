# Intel collective intelligence edits

Apply these changes to the Santh Intel repo at `/home/mukund-thiru/Santh/intel`.

## Option A: Apply script (from invariant repo root)

```bash
cd /home/mukund-thiru/Santh/invariant && node intel-api-edits/apply-to-intel.js
```

Then run typecheck (see below).

## Option B: Manual

### 1. Copy synthesis and API files

```bash
cp /home/mukund-thiru/Santh/invariant/intel-api-edits/collective-synthesis.ts /home/mukund-thiru/Santh/intel/src/api/
cp /home/mukund-thiru/Santh/invariant/intel-api-edits/collective-api.ts       /home/mukund-thiru/Santh/intel/src/api/
```

### 2. Patch route table

Edit `/home/mukund-thiru/Santh/intel/src/router/route-table.ts` as described in `route-table-patch.md`:
- Add `handleCollectiveThreatMap` to the collective-api import.
- Add the `GET /v1/collective/threat-map` route entry.

## Verify

```bash
cd /home/mukund-thiru/Santh/intel && npx tsc --noEmit
```
Expect 0 errors.

## Summary of changes

- **collective-synthesis.ts**: `source_country` on `CollectiveSignalRow`; types and `getThreatLandscape()` (by class+country, attack velocity, sensor convergence, campaign alerts when >40% sensors in 6h, emerging threats >50% velocity increase); `getThreatMapCountries()` for 7-day country threat map.
- **collective-api.ts**: Import synthesis helpers; `handleCollectivePosture()` adds `threat_landscape` (top 3 attack classes, emerging threats, geographic heatmap, optional campaign_alerts); new `handleCollectiveThreatMap()` (sensor auth, returns countries with attack_count and top_classes).
- **route-table.ts**: Register `GET /v1/collective/threat-map` with `handleCollectiveThreatMap`.
