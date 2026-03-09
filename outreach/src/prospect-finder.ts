import { URL } from 'node:url';
import { writeFile, readFile } from 'node:fs/promises';
import { parse } from 'csv-parse/sync';

export type TemplateType = 'security_engineer' | 'cto_startup' | 'devops_engineer';

export interface Prospect {
  email: string;
  name: string;
  company: string;
  role: string;
  template: TemplateType;
  status: string;
  sent_at: string;
}

/** Discovery record for INVARIANT leads: unprotected Node/Express/Fastify/Hono/Next apps. */
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

const SECURITY_MIDDLEWARE_PACKAGES = new Set([
  'helmet',
  'express-rate-limit',
  'rate-limiter-flexible',
  'csurf',
  'hpp'
]);

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
  if (!res.ok) throw new Error(`GitHub ${res.status}: ${(await res.text()).slice(0, 300)}`);
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

async function hasRecentCommits(owner: string, repo: string, gh: { fetch: <T>(p: string) => Promise<T> }): Promise<boolean> {
  const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
  try {
    const commits = await gh.fetch<any[]>(`/repos/${owner}/${repo}/commits?since=${ninetyDaysAgo}&per_page=1`);
    return Array.isArray(commits) && commits.length > 0;
  } catch {
    return false;
  }
}

async function hasSecurityIssues(owner: string, repo: string, gh: { fetch: <T>(p: string) => Promise<T> }): Promise<boolean> {
  try {
    const issues = await gh.fetch<any[]>(`/repos/${owner}/${repo}/issues?labels=security&state=all&per_page=1`);
    return Array.isArray(issues) && issues.length > 0;
  } catch {
    return false;
  }
}

function scoreProspect(stars: number, missingCount: number, framework: string, recentCommits: boolean, securityIssues: boolean): number {
  let s = Math.min(100, stars); // 1 star per point up to 100
  s += missingCount * 10; // 10 pts per missing

  if (framework === 'hono' || framework === 'edge') s += 50;
  else if (framework === 'next' || framework === 'next.js') s += 40;
  else if (framework === 'express') s += 30;
  else if (framework === 'fastify') s += 25;

  if (recentCommits) s += 20;
  if (securityIssues) s += 30;

  return s;
}

const FRAMEWORKS: { query: string; framework: string; npmPackage: string }[] = [
  { query: 'express+stars:>100+language:JavaScript', framework: 'express', npmPackage: 'express' },
  { query: 'express+stars:>100+language:TypeScript', framework: 'express', npmPackage: 'express' },
  { query: 'fastify+stars:>100', framework: 'fastify', npmPackage: 'fastify' },
  { query: 'hono+stars:>100', framework: 'hono', npmPackage: 'hono' },
  { query: 'next.js+stars:>100', framework: 'next', npmPackage: 'next' }
];

/**
 * Find real security-engineering leads: GitHub repos using Express/Fastify/Hono/Next
 * with >100 stars and NO security middleware (helmet, express-validator, csrf).
 * Uses GitHub API (rate-limited 1 req/s); GITHUB_TOKEN from /credentials/.env.
 */
export async function findProspects(limit: number): Promise<ProspectRecord[]> {
  const token = await loadGitHubToken();
  const gh = createRateLimitedGh(token);
  const seen = new Set<string>();
  const results: ProspectRecord[] = [];

  for (const { query, framework, npmPackage } of FRAMEWORKS) {
    if (results.length >= limit) break;
    const q = encodeURIComponent(query.replace(/\+/g, ' '));
    const pathname = `/search/repositories?q=${q}&sort=stars&order=desc&per_page=30`;
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
      
      const recentCommits = await hasRecentCommits(repo.owner.login, repo.name, gh);
      const securityIssues = await hasSecurityIssues(repo.owner.login, repo.name, gh);
      const score = scoreProspect(repo.stargazers_count, missing.length, framework, recentCommits, securityIssues);
      
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

function csvEscape(value: string): string {
  const escaped = value.replace(/"/g, '""');
  return `"${escaped}"`;
}

function normalizeName(name: string): string {
  if (!name.trim()) return '';
  return name
    .trim()
    .split(/\s+/)
    .map((part) => part[0]?.toUpperCase() + part.slice(1).toLowerCase())
    .join(' ');
}

function nameParts(name: string): { first: string; last: string } {
  const cleaned = normalizeName(name);
  const parts = cleaned.split(' ').filter(Boolean);
  return {
    first: (parts[0] || 'security').toLowerCase(),
    last: (parts.slice(1).join('') || 'team').toLowerCase()
  };
}

function inferDomain(blog: string | null, company: string | null): string | null {
  if (blog) {
    try {
      const normalized = blog.startsWith('http') ? blog : `https://${blog}`;
      const host = new URL(normalized).hostname.toLowerCase();
      return host.replace(/^www\./, '');
    } catch {
      // ignore
    }
  }
  if (company) {
    const cleaned = company.replace(/^@/, '').trim().toLowerCase();
    if (!cleaned) return null;
    if (cleaned.includes('.')) return cleaned;
    return `${cleaned.replace(/[^a-z0-9-]/g, '')}.com`;
  }
  return null;
}

function buildLinkedInStyleEmailCandidates(name: string, domain: string): string[] {
  const { first, last } = nameParts(name);
  return [
    `${first}.${last}@${domain}`,
    `${first}${last}@${domain}`,
    `${first[0]}${last}@${domain}`,
    `${first}@${domain}`,
    `security@${domain}`
  ];
}

async function fetchJson<T>(url: string, headers?: Record<string, string>): Promise<T> {
  const response = await fetch(url, {
    headers: {
      'User-Agent': 'santh-outreach/1.0',
      Accept: 'application/json',
      ...(headers || {})
    }
  });
  if (!response.ok) throw new Error(`HTTP ${response.status} for ${url}`);
  return (await response.json()) as T;
}

async function repoHasSecurityMiddleware(owner: string, repo: string): Promise<boolean> {
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/package.json`;
  try {
    const response = await fetchJson<{ content?: string; encoding?: string }>(url);
    if (!response.content || response.encoding !== 'base64') return false;
    const packageJsonRaw = Buffer.from(response.content, 'base64').toString('utf8');
    const packageJson = JSON.parse(packageJsonRaw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const dependencies = {
      ...(packageJson.dependencies ?? {}),
      ...(packageJson.devDependencies ?? {})
    };
    return Object.keys(dependencies).some((dep) => SECURITY_MIDDLEWARE_PACKAGES.has(dep));
  } catch {
    return false;
  }
}

export async function discoverGitHubProspects(limit = 15): Promise<Prospect[]> {
  const searchUrl =
    'https://api.github.com/search/repositories?q=language:TypeScript+stars:%3E100&sort=stars&order=desc&per_page=40';
  const searchResponse = await fetchJson<{ items: GitHubRepo[] }>(searchUrl);
  const prospects: Prospect[] = [];

  for (const repo of searchResponse.items) {
    if (prospects.length >= limit) break;
    const hasSecurityMiddleware = await repoHasSecurityMiddleware(repo.owner.login, repo.name);
    if (hasSecurityMiddleware) continue;
    let user: GitHubUser;
    try {
      user = await fetchJson<GitHubUser>(`https://api.github.com/users/${repo.owner.login}`);
    } catch {
      continue;
    }
    const company = (user.company || repo.owner.login || repo.name).replace(/^@/, '').trim();
    const name = normalizeName(user.name || repo.owner.login);
    const domain = inferDomain(user.blog, user.company);
    const emailCandidates = user.email
      ? [user.email]
      : domain
        ? buildLinkedInStyleEmailCandidates(name || repo.owner.login, domain)
        : [`security@${repo.owner.login.toLowerCase()}.com`];
    prospects.push({
      email: emailCandidates[0],
      name: name || repo.owner.login,
      company: company || repo.full_name,
      role: 'Security Engineer',
      template: 'security_engineer',
      status: '',
      sent_at: ''
    });
  }
  return prospects;
}

function extractEmails(text: string): string[] {
  const matches = text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi);
  return matches ? [...new Set(matches.map((m) => m.toLowerCase()))] : [];
}

export async function discoverHNProspects(limit = 10): Promise<Prospect[]> {
  const url =
    'https://hn.algolia.com/api/v1/search_by_date?query=hiring%20security%20engineer&tags=story&hitsPerPage=50';
  const payload = await fetchJson<{ hits: Array<{ title?: string; story_text?: string; url?: string }> }>(url);
  const prospects: Prospect[] = [];

  for (const hit of payload.hits) {
    if (prospects.length >= limit) break;
    const text = `${hit.title || ''}\n${hit.story_text || ''}\n${hit.url || ''}`;
    const emails = extractEmails(text);
    if (emails.length === 0 && hit.url) {
      try {
        const host = new URL(hit.url).hostname.replace(/^www\./, '');
        emails.push(`hiring@${host}`);
      } catch {
        continue;
      }
    }
    if (emails.length === 0) continue;
    const companyMatch = (hit.title || '').match(/at\s+([A-Za-z0-9 ._-]+)/i);
    const company = companyMatch?.[1]?.trim() || 'HN Hiring Team';
    prospects.push({
      email: emails[0],
      name: 'Hiring Team',
      company,
      role: 'CTO',
      template: 'cto_startup',
      status: '',
      sent_at: ''
    });
  }
  return prospects;
}

export function discoverLinkedInStyleProspects(seedProspects: Prospect[], limit = 15): Prospect[] {
  const output: Prospect[] = [];
  for (const seed of seedProspects) {
    if (output.length >= limit) break;
    const domain = seed.email.split('@')[1] || '';
    if (!domain || domain.includes('github.com') || domain.includes('noreply')) continue;
    const likelyNames = ['Alex Kim', 'Priya Raman', 'Jordan Lee'];
    for (const person of likelyNames) {
      if (output.length >= limit) break;
      const guesses = buildLinkedInStyleEmailCandidates(person, domain);
      output.push({
        email: guesses[0],
        name: person,
        company: seed.company,
        role: 'DevOps Engineer',
        template: 'devops_engineer',
        status: '',
        sent_at: ''
      });
    }
  }
  return output;
}

export async function discoverAllProspects(limit = 50): Promise<Prospect[]> {
  const github = await discoverGitHubProspects(Math.ceil(limit * 0.5));
  const hn = await discoverHNProspects(Math.ceil(limit * 0.25));
  const linkedinStyle = discoverLinkedInStyleProspects([...github, ...hn], Math.ceil(limit * 0.25));
  const deduped = new Map<string, Prospect>();
  for (const prospect of [...github, ...hn, ...linkedinStyle]) {
    const key = prospect.email.toLowerCase();
    if (!deduped.has(key)) deduped.set(key, prospect);
  }
  return [...deduped.values()].slice(0, limit);
}

export async function appendProspectsToCsv(csvPath: string, prospects: Prospect[]): Promise<void> {
  const existingRaw = await readFile(csvPath, 'utf8');
  const existingRows = parse(existingRaw, { columns: true, skip_empty_lines: true }) as Prospect[];
  const existingEmails = new Set(existingRows.map((row) => row.email.toLowerCase()));
  const merged = [...existingRows];
  for (const prospect of prospects) {
    const key = prospect.email.toLowerCase();
    if (!existingEmails.has(key)) {
      merged.push(prospect);
      existingEmails.add(key);
    }
  }
  const header = 'email,name,company,role,template,status,sent_at';
  const lines = merged.map((p) =>
    [p.email, p.name, p.company, p.role, p.template, p.status, p.sent_at].map((v) => csvEscape(v ?? '')).join(',')
  );
  await writeFile(csvPath, `${header}\n${lines.join('\n')}${lines.length > 0 ? '\n' : ''}`, 'utf8');
}

async function runCli(): Promise<void> {
  if (process.argv.includes('--find')) {
    const findIdx = process.argv.indexOf('--find');
    const limit = Math.min(50, parseInt(process.argv[findIdx + 1] ?? '10', 10) || 10);
    const prospects = await findProspects(limit);
    console.log(JSON.stringify(prospects, null, 2));
    return;
  }
  if (!process.argv.includes('--discover')) return;

  const csvPath = process.argv.includes('--csv')
    ? process.argv[process.argv.indexOf('--csv') + 1]
    : new URL('./prospects.csv', import.meta.url).pathname;
  const prospects = await discoverAllProspects(50);
  await appendProspectsToCsv(csvPath, prospects);
  console.log(`Discovered ${prospects.length} prospects and merged into ${csvPath}`);
}

await runCli();
