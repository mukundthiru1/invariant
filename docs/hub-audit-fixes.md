# Hub audit fixes — apply in `/home/mukund-thiru/Santh/hub`

These fixes address BUG-001, BUG-002, BUG-003, SEO-001, and SEO. Apply them in the **hub** repo (not invariant). Current workspace is invariant; hub is at `../hub` or `/home/mukund-thiru/Santh/hub`.

---

## 1. BUG-001 (CRITICAL) — `src/pages/Collective.tsx`

**Problem:** Uses `stats` without importing `getSiteStats` or defining `stats`.

**Fix:**

- Add import at top (after the sanitize import):
```ts
import { getSiteStats } from '../utils/stats'
```

- At the start of the component (right after `export default function Collective() {`), add:
```ts
const stats = getSiteStats()
```

---

## 2. BUG-002 (HIGH) — `src/pages/Community.tsx`

**Problem:** Hardcoded member count `1,248`. No `communityMembers` in `stats.ts`.

**Fix:** Remove the fake number. Replace the stat block (around lines 63–71) so it only shows the label:

- Change from:
```tsx
<div className="text-2xl font-light">1,248</div>
<div className="text-[10px] tracking-widest text-white/40 uppercase mt-1">Active Researchers</div>
```
- To:
```tsx
<div className="text-[10px] tracking-widest text-white/40 uppercase">Active Researchers</div>
```
(Remove the line with `1,248` and the `mt-1` from the label div.)

---

## 3. BUG-003 (MEDIUM) — `src/components/BlogPost.tsx`

**Problem:** Giscus script uses empty `data-repo-id` and `data-category-id`.

**Fix:** Comment out the Giscus injection until real IDs are configured. Do not remove the code.

- Find the `useEffect` that contains `giscus.app/client.js`, `data-repo-id`, `data-category-id`, and `IntersectionObserver` (lines ~106–140).
- Wrap that entire `useEffect(...)` in a multi-line comment and add a TODO on the line above it:
  - Add before the effect: `/* TODO: configure Giscus with real data-repo-id and data-category-id before enabling */`
  - Then comment out the whole effect (e.g. wrap `useEffect(() => { ... }, [article])` in `/* */`).
- Leave the JSX as-is: keep the `<section className="blog-comments">` and the `<div ref={giscusContainerRef} />` so the Discussion section still appears; only the script injection is disabled.

---

## 4. SEO-001 (MEDIUM) — `src/pages/Home.tsx`

**Problem:** Homepage title is outdated.

**Fix:** In the `<SEO>` component, change the `title` prop from:
```ts
title="Santh — Security Intelligence | Property-Invariant Defense"
```
to:
```ts
title="Santh | Application Security Research & Runtime Defense Engine"
```

---

## 5. SEO — Meta descriptions

All checked pages already pass a `description` prop to `<SEO>`: Home, Collective, Community, Principles, Train, NotFound, BlogList, BlogPost. No change required.

---

## 6. After applying

Run in the hub repo:

```bash
cd /home/mukund-thiru/Santh/hub && npm run build
```

Resolve any TypeScript errors. No stubs; every fix is real.
