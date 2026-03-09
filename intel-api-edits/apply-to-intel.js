#!/usr/bin/env node
/**
 * Apply collective intelligence edits to Santh Intel.
 * Run from repo root: node intel-api-edits/apply-to-intel.js
 * Requires: intel repo at ../intel (sibling of invariant) or set INTEL_ROOT.
 */

const fs = require('fs');
const path = require('path');

const invariantRoot = path.resolve(__dirname, '..');
const intelRoot = process.env.INTEL_ROOT || path.join(path.dirname(invariantRoot), 'intel');
const apiDir = path.join(intelRoot, 'src', 'api');
const routeTablePath = path.join(intelRoot, 'src', 'router', 'route-table.ts');

const editsDir = __dirname;

function main() {
  if (!fs.existsSync(intelRoot)) {
    console.error('Intel repo not found at', intelRoot);
    console.error('Set INTEL_ROOT or ensure ../intel exists.');
    process.exit(1);
  }

  // Copy collective-synthesis.ts and collective-api.ts
  for (const name of ['collective-synthesis.ts', 'collective-api.ts']) {
    const src = path.join(editsDir, name);
    const dest = path.join(apiDir, name);
    if (!fs.existsSync(src)) {
      console.error('Missing', src);
      process.exit(1);
    }
    fs.copyFileSync(src, dest);
    console.log('Copied', name, '->', dest);
  }

  // Patch route-table.ts
  if (!fs.existsSync(routeTablePath)) {
    console.error('Route table not found:', routeTablePath);
    process.exit(1);
  }
  let routeTable = fs.readFileSync(routeTablePath, 'utf8');

  if (routeTable.includes('handleCollectiveThreatMap')) {
    console.log('Route table already patched (handleCollectiveThreatMap present).');
  } else {
    routeTable = routeTable.replace(
      /import \{\s*handleCollectiveBlocklist,\s*handleCollectiveRules,\s*handleCollectivePosture,\s*handleCollectiveStats,\s*\} from '\.\.\/api\/collective-api'/,
      "import {\n    handleCollectiveBlocklist,\n    handleCollectiveRules,\n    handleCollectivePosture,\n    handleCollectiveStats,\n    handleCollectiveThreatMap,\n} from '../api/collective-api'"
    );
    routeTable = routeTable.replace(
      /handleCollectivePosture\(ctx\.request, env, ctx\.requestId\),\s*\}\s*,\s*\{\s*method: 'GET',\s*pattern: '\/v1\/collective\/stats'/,
      `handleCollectivePosture(ctx.request, env, ctx.requestId),
    },
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
    {
        method: 'GET',
        pattern: '/v1/collective/stats'`
    );
    fs.writeFileSync(routeTablePath, routeTable);
    console.log('Patched', routeTablePath);
  }

  console.log('Done. Run: cd', intelRoot, '&& npx tsc --noEmit');
}

main();
