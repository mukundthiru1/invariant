import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';

// Minimal Gmail send via OAuth2 refresh token -> access token -> send message

function readEnv(name: string): string | undefined {
  const envPath = path.resolve('/credentials/.env');
  if (!fs.existsSync(envPath)) return process.env[name];
  const content = fs.readFileSync(envPath, 'utf8');
  const m = content.match(new RegExp(`^${name}=(.*)$`, 'm'));
  return m ? m[1].trim() : process.env[name];
}

const CLIENT_ID = readEnv('GMAIL_CLIENT_ID');
const CLIENT_SECRET = readEnv('GMAIL_CLIENT_SECRET');
const REFRESH_TOKEN = readEnv('GMAIL_REFRESH_TOKEN');

if (!CLIENT_ID || !CLIENT_SECRET || !REFRESH_TOKEN) {
  console.error('Missing GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET / GMAIL_REFRESH_TOKEN in /credentials/.env');
  process.exit(1);
}

function postJson(hostname: string, path: string, data: any, headers: any = {}) {
  const body = JSON.stringify(data);
  const opts: any = { hostname, path, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...headers } };
  return new Promise((resolve, reject) => {
    const req = https.request(opts, (res) => {
      let out = '';
      res.on('data', (c) => (out += c));
      res.on('end', () => {
        try { resolve(JSON.parse(out)); } catch (e) { resolve(out); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function refreshAccessToken() {
  const data = new URLSearchParams({
    client_id: CLIENT_ID as string,
    client_secret: CLIENT_SECRET as string,
    refresh_token: REFRESH_TOKEN as string,
    grant_type: 'refresh_token',
  });

  const body = data.toString();
  const opts: any = { hostname: 'oauth2.googleapis.com', path: '/token', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } };
  return new Promise<any>((resolve, reject) => {
    const req = https.request(opts, (res) => {
      let out = '';
      res.on('data', (c) => (out += c));
      res.on('end', () => { try { resolve(JSON.parse(out)); } catch (e) { reject(e); } });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function makeRawEmail(from: string, to: string, subject: string, body: string) {
  const msg = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    'Content-Type: text/plain; charset="UTF-8"',
    '',
    body,
  ].join('\r\n');
  return Buffer.from(msg).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sendMessage(accessToken: string, raw: string) {
  const postData = JSON.stringify({ raw });
  const opts: any = { hostname: 'www.googleapis.com', path: '/gmail/v1/users/me/messages/send', method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postData) } };
  return new Promise((resolve, reject) => {
    const req = https.request(opts, (res) => {
      let out = '';
      res.on('data', (c) => (out += c));
      res.on('end', () => {
        try { resolve(JSON.parse(out)); } catch (e) { resolve(out); }
      });
    });
    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

async function main() {
  const prospectsPath = path.resolve(__dirname, '..', 'prospects.json');
  if (!fs.existsSync(prospectsPath)) { console.error('prospects.json not found'); process.exit(1); }
  const prospects = JSON.parse(fs.readFileSync(prospectsPath, 'utf8')) as any[];

  const tokenRes: any = await refreshAccessToken();
  const accessToken = tokenRes.access_token;
  if (!accessToken) { console.error('Failed to obtain access token'); process.exit(1); }

  const from = 'me';
  for (const p of prospects) {
    if (p.status === 'sent') continue;
    if (!p.email) { console.log(`Skipping ${p.github} — no email`); continue; }
    // choose template by tier
    const tmplPath = path.resolve(__dirname, '..', 'templates', p.tier === 'warm' ? 'template-startup-scan.md' : 'template-free-hygiene.md');
    const tmpl = fs.readFileSync(tmplPath, 'utf8');
    const subjectLine = tmpl.split('\n')[0].replace('Subject: ', '').trim();
    const body = tmpl.replace('{{contact_name}}', p.company).replace('{{repo}}', p.github);
    const raw = makeRawEmail(from, p.email, subjectLine, body);
    try {
      const res = await sendMessage(accessToken, raw);
      console.log('Sent to', p.email, res);
      p.status = 'sent';
    } catch (e) {
      console.error('Failed to send to', p.email, e);
      p.status = 'error';
    }
  }

  fs.writeFileSync(prospectsPath, JSON.stringify(prospects, null, 2));
}

if (require.main === module) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
