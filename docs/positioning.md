# Santh — Positioning & Go‑to‑Market

This document captures Santh's positioning, target customers, competitive differentiation, pricing, acquisition channels, and a 30‑day GTM sprint to get the first paid customers.

## 1. Problem Statement (the real pain)

- WAFs miss what they don't pattern‑match — they detect known signatures and network anomalies but fail to catch structural API and business‑logic attacks that don't match preexisting rules.
- SIEMs surface alerts days after the fact — telemetry and correlation often lag, leaving teams reacting to breaches instead of preventing or quickly containing them.
- Security reviews happen quarterly, attacks happen daily — sporadic audits and long review cycles mean new regressions land and stay exposed for weeks or months.
- Developer teams can't afford a SOC — high cost, staffing, and operational overhead make 24/7 security monitoring infeasible for most engineering teams at startups and mid‑market companies.

These combine into a single customer pain: APIs and runtime behavior are underprotected by tooling that is either too late (post‑commit), too noisy, or too expensive to operate.

## 2. Target Personas

- Primary: CTOs / Engineering Leads at Series A–C startups (ARR $5M–$50M). They care about moving fast, maintaining uptime, and shipping features without introducing high‑risk security debt.
- Secondary: Platform / DevSecOps teams at mid‑market companies who need lightweight, automated protection that integrates with existing CI/CD and runtime stacks.
- Anti‑persona: Large Fortune 500 enterprises. They are slow to buy, have long procurement cycles, and already have sprawling security estates — not an early go‑to market focus.

Buying triggers:
- Rapid product iteration (weekly releases)
- Public API surface or B2B integratations
- Recent incidents or audit pressure

## 3. Competitive Landscape

- Snyk — SAST/static, post‑commit code scanning. Good at catching known secure coding issues before deployment; misses runtime and structural API attack classes.
- Datadog APM — observability and performance monitoring; not built as a security enforcement/control layer and lacks structural runtime attack detection.
- Cloudflare WAF — network and layer‑7 rules; strong for generic web attacks but limited at structural analysis of API semantics and business‑logic abuse.
- CrowdStrike — endpoint protection and detection; excels on hosts and agents, not API gateway or edge structural analysis.

Why Santh wins
- Structural analysis at the edge — Santh inspects API structure and semantics at runtime, not just network patterns or static code.
- Zero‑config, low touch — deploy and get immediate coverage without tuning rules or maintaining signatures.
- Broad class coverage — built to detect ~66 attack classes (from injection, parameter tampering, to business‑logic abuse) rather than a handful of signatures.
- Developer ergonomics — meaningful signals surfaced where engineers work (GitHub, issue trackers, PRs) with low false positive noise.

## 4. Value Proposition Canvas

- Customer Pains
  - Weeks to realize you were breached or abused
  - High friction and noise from rule‑based systems
  - Security slows delivery or is ignored because it costs velocity

- Customer Gains
  - Milliseconds to detection at edge, not days in SIEM
  - No config, no tuning — immediate value out of the box
  - Actionable alerts integrated into developer workflows

- Jobs To Be Done
  - Protect public and internal APIs without slowing down shipping
  - Reduce mean time to detection (MTTD) and containment (MTTC)
  - Avoid hiring/operationalizing a full SOC while still achieving continuous protection

## 5. Pricing Strategy

- Free tier
  - 1M requests / month, basic hygiene scan and passive detection
  - Ideal for startups evaluating and for open source projects

- Team
  - $200 / month
  - Unlimited sensors across projects/environments
  - Collective defence signals (shared detections across customers)
  - Email + chat support, onboarding guides

- Enterprise
  - Custom pricing
  - White‑glove onboarding, SSO, SLA, dedicated account and incident support

Pricing rationale: keep the Team tier accessible for small engineering orgs while providing a clear upgrade path to enterprise for customers who need guarantees and integrations.

## 6. Acquisition Channels

- GitHub presence: a bot that files security‑labeled issues and comments on PRs explaining detected runtime risks — drives awareness in developer workflows.
- Free hygiene scan: outreach hook (cold email / outreach) offering a no‑cost scan of an exposed API and a short report of findings.
- Hacker News / Product Hunt "Show HN" launch — to reach technical early adopters and collect feedback.
- YC network referrals — target startups in YC cohorts and alumni who match the primary persona.
- Open source INVARIANT engine public release — provide an open engine that drives adoption, trust, and understanding while keeping the productized integrations and orchestration closed source.

Channel notes: focus on developer touchpoints and scalable, low‑cost acquisition methods that convert to trials (GitHub, scans, community signals).

## 7. 30‑day GTM Sprint Plan

Week 1 — Product polish & sales assets
- Finalize the onboarding flow and make sure the free hygiene scan works end‑to‑end.
- Write 3 short case studies (simulated but realistic) highlighting scenarios: credential stuffing, parameter tampering, business‑logic abuse. These serve as demo material for outreach and the website.
- Prepare marketing copy, landing page, HN/PH assets, and GitHub bot README.

Week 2 — Outreach & seeding
- Cold outreach to 50 open source projects and 50 startups that fit the ARR/persona profile offering a free hygiene scan and 30‑minute walkthrough.
- Engage YC alumni and direct intros — prioritize startups with public APIs.
- Launch the GitHub bot in a handful of community repos (opt‑in) to gather early signals.

Week 3 — Public launch
- HN "Show HN" and Product Hunt launch coordinated with social (Twitter/X) and GitHub posts.
- Release the INVARIANT engine as open source with clear docs showing what it detects and how to read outputs.
- Run a webinar/demo highlighting the three case studies and live demo of detection → triage in <1 minute.

Week 4 — Follow up & convert
- Follow up on all inbound leads, schedule demos, and run technical trials.
- Begin converting the first paying customers from warm outreach and trials.
- Collect customer feedback to prioritize the next product improvements (false positive reduction, integrations, reporting).

## Key Metrics to Track

- MTTD (mean time to detection) in production trials
- Conversion rate: free scan → paid Team tier
- Average time from first contact → paid conversion
- Number of active customers and request volume per customer
- False positive rate and triage time per alert

## Next Steps (first 90 days)

1. Close 3 paying Team customers and collect testimonials
2. Harden onboarding and self‑serve billing
3. Build 2 paid integrations (SSO, SIEM export) for enterprise deals
4. Iterate on detection coverage and add 10 more attack class rules prioritized by customer feedback

---

If you want this placed at a different path (for example the absolute path `/home/mukund-thiru/Santh/docs/positioning.md`), tell me and I will copy it there as well.
