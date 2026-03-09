Santh Outreach Automation
=========================

This folder contains a small outreach automation system that:
- finds open-source projects with security signals on GitHub
- stores prospects in `prospects.json`
- contains short, actionable cold-email templates in `templates/`
- can send personalized emails via the Gmail REST API using OAuth2

Important
---------
- STUBS ARE BANNED. The scripts perform real HTTP requests to GitHub and
  Google's OAuth/Gmail endpoints. Provide credentials in `/credentials/.env`.
- Required environment values (put them in `/credentials/.env`):
  - GITHUB_TOKEN (optional but recommended to avoid low rate limits)
  - GMAIL_CLIENT_ID
  - GMAIL_CLIENT_SECRET
  - GMAIL_REFRESH_TOKEN

Files
-----
- `prospects.json` — list of discovered prospects (array of objects)
- `templates/` — three short cold email templates with placeholders
- `scripts/find-prospects.ts` — searches GitHub for repos with security issues
- `scripts/send-email.ts` — exchanges a refresh token for an access token and
  sends personalized emails using the Gmail REST API; updates `prospects.json`

Usage
-----
1. Fill `/credentials/.env` with required variables.
2. (Optional) Install TypeScript and run a type check: `npx tsc --noEmit scripts/find-prospects.ts`
3. Run discovery: `node --loader ts-node/esm scripts/find-prospects.ts` or compile+run as you prefer.
4. Review `prospects.json`, optionally add `email` values, then run `node scripts/send-email.ts`.

Security & Privacy
------------------
- Do not commit `/credentials/.env` to git. This repository intentionally reads
  credentials at runtime from that file.
- Use the free-scan CTA in the templates — never promise paid work without
  explicit agreement.
