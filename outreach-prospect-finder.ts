/**
 * Real prospect-finder: GitHub repos (Express/Fastify/Hono/Next, >100 stars,
 * no helmet/express-validator/csrf) + npm download signal. GITHUB_TOKEN from /credentials/.env.
 * Rate limit: 1 GitHub API request per second.
 */
import { readFile } from 'node:fs/promises';

export interface ProspectRecord {
  email: string | null;
  name: string | null;
  company: string | null;
  githubHandle: string;
  repoName: string;
  repoUrl: string;
  stars: number;
  framework: string;
  missingSecurityPackages: string[];
  score: number;
}

interface GitHubRepo {
  name: string;
  owner: { login: string };
  full_name: string;
  stargazers_count: number;
  html_url?: string;
}

interface GitHubUser {
  login: string;
  name: string | null;
  email: string | null;
  blog: string | null;
  company: string | null;
}

interface GitHubContents {
  content?: string;
  encoding?: string;
  message?: string;
}

const CSRF_PACKAGES = new Set(['csrf', 'csurf']);
const GITHUB_RATE_LIMIT_MS = 1000;

function parseDotEnv(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const sep = line.indexOf('=');
    if (sep < 0) continue;
    const key = line.slice(0, sep).trim();
    let value = line.slice(sep + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }
  return result;
}

export async function loadGitHubToken(envPath = '/credentials/.env'): Promise<string | null> {
  try {
    const raw = await readFile(envPath, 'utf8');
    const env = parseDotEnv(raw);
    return env.GITHUB_TOKEN?.trim() || null;
  } catch {
    return null;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function ghFetch<T>(pathname: string, token: string | null): Promise<T> {
  const url = pathname.startsWith('http') ? pathname : `https://api.github.com${pathname}`;
  const headers: Record<string, string> = {
    'User-Agent': 'santh-outreach-prospect-finder/1.0',
    Accept: 'application/vnd.github.v3+json'
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`GitHub ${res.status}: ${await res.text()}`);
  return (await res.json()) as T;
}

function createRateLimitedGh(token: string | null) {
  let lastAt = 0;
  return {
    async fetch<T>(path: string): Promise<T> {
      const now = Date.now();
      if (now - lastAt < GITHUB_RATE_LIMIT_MS) await sleep(GITHUB_RATE_LIMIT_MS - (now - lastAt));
      lastAt = Date.now();
      return ghFetch<T>(path, token);
    }
  };
}

async function getNpmWeeklyDownloads(pkg: string): Promise<number> {
  try {
    const res = await fetch(
      `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(pkg)}`,
      { headers: { 'User-Agent': 'santh-outreach/1.0' } }
    );
    if (!res.ok) return 0;
    const d = (await res.json()) as { downloads?: number };
    return typeof d.downloads === 'number' ? d.downloads : 0;
  } catch {
    return 0;
  }
}

async function getRepoDependencies(
  owner: string,
  repo: string,
  gh: { fetch: <T>(p: string) => Promise<T> }
): Promise<Record<string, string> | null> {
  const data = await gh.fetch<GitHubContents>(`/repos/${owner}/${repo}/contents/package.json`);
  if (data.message === 'Not Found' || !data.content || data.encoding !== 'base64') return null;
  const raw = Buffer.from(data.content, 'base64').toString('utf8');
  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(raw);
  } catch {
    return null;
  }
  return { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
}

function missingSecurityPackages(deps: Record<string, string>): string[] {
  const keys = new Set(Object.keys(deps).map((k) => k.toLowerCase()));
  const missing: string[] = [];
  if (!keys.has('helmet')) missing.push('helmet');
  if (!keys.has('express-validator')) missing.push('express-validator');
  if (![...keys].some((k) => CSRF_PACKAGES.has(k))) missing.push('csrf');
  return missing;
}

function hasAnyInvariantSecurity(deps: Record<string, string>): boolean {
  const keys = new Set(Object.keys(deps).map((k) => k.toLowerCase()));
  if (keys.has('helmet')) return true;
  if (keys.has('express-validator')) return true;
  return [...keys].some((k) => CSRF_PACKAGES.has(k));
}

function scoreProspect(stars: number, hasEmail: boolean, npmDownloads: number, missingCount: number): number {
  let s = Math.min(35, Math.floor(stars / 3));
  if (hasEmail) s += 25;
  if (npmDownloads >= 1_000_000) s += 25;
  else if (npmDownloads >= 100_000) s += 15;
  else if (npmDownloads >= 10_000) s += 5;
  s += Math.min(15, missingCount * 5);
  return Math.min(100, s);
}

const FRAMEWORKS: { query: string; framework: string; npmPackage: string }[] = [
  { query: 'express+stars:>100+language:JavaScript', framework: 'express', npmPackage: 'express' },
  { query: 'express+stars:>100+language:TypeScript', framework: 'express', npmPackage: 'express' },
  { query: 'fastify+stars:>100', framework: 'fastify', npmPackage: 'fastify' },
  { query: 'hono+stars:>100', framework: 'hono', npmPackage: 'hono' },
  { query: 'next.js+stars:>100', framework: 'next', npmPackage: 'next' }
];

export async function findProspects(limit: number): Promise<ProspectRecord[]> {
  const token = await loadGitHubToken();
  const gh = createRateLimitedGh(token);
  const seen = new Set<string>();
  const results: ProspectRecord[] = [];

  for (const { query, framework, npmPackage } of FRAMEWORKS) {
    if (results.length >= limit) break;
    const pathname = `/search/repositories?q=${encodeURIComponent(query.replace(/\+/g, ' '))}&sort=stars&order=desc&per_page=30`;
    let searchRes: { items?: GitHubRepo[]; message?: string };
    try {
      searchRes = await gh.fetch<{ items: GitHubRepo[]; message?: string }>(pathname);
    } catch (e) {
      console.error(`GitHub search ${framework}:`, e);
      continue;
    }
    const items = searchRes.items ?? [];
    if (searchRes.message) {
      console.error('GitHub API:', searchRes.message);
      continue;
    }
    for (const repo of items) {
      if (results.length >= limit) break;
      if (seen.has(repo.full_name)) continue;
      seen.add(repo.full_name);
      const deps = await getRepoDependencies(repo.owner.login, repo.name, gh).catch(() => null);
      if (deps === null || hasAnyInvariantSecurity(deps)) continue;
      const missing = missingSecurityPackages(deps);
      const npmDownloads = await getNpmWeeklyDownloads(npmPackage);
      let user: GitHubUser;
      try {
        user = await gh.fetch<GitHubUser>(`/users/${repo.owner.login}`);
      } catch {
        user = { login: repo.owner.login, name: null, email: null, blog: null, company: null };
      }
      const email = user.email?.trim() || null;
      const repoUrl = repo.html_url ?? `https://github.com/${repo.full_name}`;
      const score = scoreProspect(repo.stargazers_count, !!email, npmDownloads, missing.length);
      results.push({
        email,
        name: user.name?.trim() || null,
        company: user.company?.replace(/^@/, '').trim() || null,
        githubHandle: repo.owner.login,
        repoName: repo.name,
        repoUrl,
        stars: repo.stargazers_count,
        framework,
        missingSecurityPackages: missing,
        score
      });
    }
  }
  results.sort((a, b) => b.score - a.score);
  return results.slice(0, limit);
}

// CLI: tsx outreach-prospect-finder.ts [--find N]
async function main(): Promise<void> {
  const findIdx = process.argv.indexOf('--find');
  const limit = findIdx >= 0
    ? Math.min(50, parseInt(process.argv[findIdx + 1] ?? '10', 10) || 10)
    : 0;
  if (limit > 0) {
    const prospects = await findProspects(limit);
    console.log(JSON.stringify(prospects, null, 2));
  }
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
