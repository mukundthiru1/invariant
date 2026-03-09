export interface ColdOutreachTemplate {
  subject: string;
  body: string;
}

export function getSecurityEngineerTemplate(repoName: string, framework: string, missingPackages: string[]): ColdOutreachTemplate {
  let attack = 'prototype pollution or injection attacks';
  if (missingPackages.includes('helmet')) {
    attack = 'cross-site scripting (XSS) and clickjacking';
  } else if (missingPackages.includes('csrf') || missingPackages.includes('csurf')) {
    attack = 'cross-site request forgery (CSRF)';
  } else if (missingPackages.includes('express-validator')) {
    attack = 'SQL injection and NoSQL injection due to unvalidated inputs';
  }

  return {
    subject: `Found ${repoName} — impressive stack, one gap I noticed`,
    body: `Hi there,

I was looking at ${repoName} and it's an impressive build. However, I noticed you're using ${framework} without security middleware (missing: ${missingPackages.join(', ')}).

Because of this, your app is vulnerable to ${attack} right now.

INVARIANT fixes this transparently. We caught 847 SQLi attempts across 23 apps last week using collective intelligence.

Want to see if your API is vulnerable? Takes 5 minutes to check.

Best,
The INVARIANT Team`
  };
}

export function getCtoStartupTemplate(): ColdOutreachTemplate {
  return {
    subject: `Security without the security team overhead`,
    body: `Hi,

I know you're moving fast, and security often takes a back seat to shipping features. But the ROI is clear: one breach right now costs 3-6 months of runway in recovery, legal fees, and lost trust.

INVARIANT acts as insurance that costs minutes to deploy, giving you peace of mind without slowing you down.

Add one line to your Cloudflare Worker. I'll send the exact code.

Best,
The INVARIANT Team`
  };
}

export function getDevopsEngineerTemplate(repoName: string, framework: string): ColdOutreachTemplate {
  let snippet = '';
  if (framework === 'express' || framework === 'fastify' || framework === 'next') {
    snippet = `import { invariant } from '@invariant/edge';
app.use(invariant());`;
  } else if (framework === 'hono') {
    snippet = `import { invariant } from '@invariant/edge';
app.use('*', invariant());`;
  } else {
    snippet = `import { invariant } from '@invariant/edge';
invariant(config);`;
  }

  return {
    subject: `${repoName} → security in 2 lines of config`,
    body: `Hi,

I noticed you manage the infrastructure for ${repoName}. You can secure your ${framework} deployment instantly with zero latency overhead. 

INVARIANT runs on the Cloudflare edge — no agents, no extra infra, and it intercepts threats before they hit your origin.

\`\`\`typescript
${snippet}
\`\`\`

Here's the snippet — reply if you want me to help configure it for your stack.

Best,
The INVARIANT Team`
  };
}
