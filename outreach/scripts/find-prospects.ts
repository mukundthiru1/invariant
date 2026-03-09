import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';

// Minimal GitHub search client using REST API v3
// Searches for repositories with issues labeled "security" and missing SECURITY.md

const OUT = path.resolve(__dirname, '..', 'prospects.json');

function readEnv(name: string): string | undefined {
  const envPath = path.resolve('/credentials/.env');
  if (!fs.existsSync(envPath)) return process.env[name];
  const content = fs.readFileSync(envPath, 'utf8');
  const m = content.match(new RegExp(`^${name}=(.*)$`, 'm'));
  return m ? m[1].trim() : process.env[name];
}

const GITHUB_TOKEN = readEnv('GITHUB_TOKEN');

function ghRequest(pathname: string): Promise<any> {
  const opts: any = {
    hostname: 'api.github.com',
    path: pathname,
    method: 'GET',
    headers: { 'User-Agent': 'santh-outreach-script' },
  };
  if (GITHUB_TOKEN) opts.headers['Authorization'] = `token ${GITHUB_TOKEN}`;

  return new Promise((resolve, reject) => {
    const req = https.request(opts, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        try {
          const json = JSON.parse(body);
          resolve(json);
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function searchReposWithSecurityIssues(): Promise<Array<any>> {
  // search for issues labeled security and aggregate repo names
  const q = encodeURIComponent('label:security state:open');
  const path = `/search/issues?q=${q}&per_page=100`;
  const res = await ghRequest(path);
  if (!res.items) return [];
  const repos = new Map<string, any>();
  for (const it of res.items) {
    const repoFull = it.repository_url.replace('https://api.github.com/repos/', '');
    repos.set(repoFull, { repo: repoFull, issue: it.title, url: it.html_url });
  }
  return Array.from(repos.values());
}

async function repoHasSecurityMd(fullName: string) {
  try {
    const path = `/repos/${fullName}/contents/SECURITY.md`;
    const res = await ghRequest(path);
    return !(res && res.message === 'Not Found');
  } catch (_) {
    return false;
  }
}

async function findVulnerablePatterns(fullName: string) {
  // simplistic: check for common sensitive keywords in repo tree (search code API)
  const keywords = ['AWS_ACCESS_KEY_ID', 'private_key', 'elastic', 'elasticsearch', 'SECRET_KEY', 'api_key'];
  const found: string[] = [];
  for (const kw of keywords) {
    try {
      const q = encodeURIComponent(`${kw} repo:${fullName}`);
      const res = await ghRequest(`/search/code?q=${q}&per_page=1`);
      if (res.total_count && res.total_count > 0) found.push(kw);
    } catch (_) {
      // ignore
    }
  }
  return found;
}

async function main() {
  const repos = await searchReposWithSecurityIssues();
  const out: any[] = [];
  for (const r of repos.slice(0, 50)) {
    const hasSec = await repoHasSecurityMd(r.repo);
    const patterns = await findVulnerablePatterns(r.repo);
    if (patterns.length === 0 && !hasSec) continue; // prefer repos with signals

    // try to get primary contact via repo owner
    const owner = r.repo.split('/')[0];
    let email: string | undefined;
    try {
      const ownerInfo = await ghRequest(`/users/${owner}`);
      email = ownerInfo.email || undefined;
    } catch (_) {}

    out.push({
      company: owner,
      github: `https://github.com/${r.repo}`,
      email: email || '',
      reason: `issue: ${r.issue} ${patterns.length ? 'patterns:' + patterns.join(',') : ''}`,
      tier: 'warm',
      status: 'new',
    });
  }

  fs.writeFileSync(OUT, JSON.stringify(out, null, 2));
  console.log(`Wrote ${out.length} prospects to ${OUT}`);
}

if (require.main === module) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
