# SBOM Workbench — Enterprise Upgrade Plan

## 1. App shell + routing (sidebar becomes real navigation)

Today everything lives in `src/routes/index.tsx` (1278 lines). I'll split it into:

```
src/routes/
  __root.tsx                (unchanged shell)
  _app.tsx                  NEW — auth-gated layout: sidebar + sticky header + AI panel + <Outlet/>
  _app.index.tsx            Dashboard (KPIs, charts, risk card, recent table)
  _app.components.tsx       Component advisory cards (current card grid)
  _app.vulnerabilities.tsx  Vulnerability-only table (filters CVE/CVSS/vendor/status)
  _app.reports.tsx          Executive summary + exports (PDF/XLSX/CSV)
  _app.sbom.tsx             Raw SBOM spreadsheet view (search/sort/edit/delete/append)
  _app.datasets.tsx         Dataset manager (upload, rename, delete, switch)
  auth.tsx                  Sign-in / sign-up (email + Google)
```

Each child route lives under the `_app` layout so the sidebar, header, and AI panel are persistent and not re-rendered on navigation. `<Outlet/>` swaps only the main content area.

Shared cross-route state moves into `src/lib/workbench-store.ts` (Zustand): `activeDatasetId`, `components`, `datasets`, `severityFilter`, `searchQuery`, derived `filteredComponents`, severity counts, risk score. All pages and the AI panel read from this single store so a click on a KPI card filters every view + AI context simultaneously.

## 2. KPI cards = global filter

The Components/Critical/High/Medium/Low tiles become toggle buttons bound to `severityFilter` in the store. Clicking Critical filters cards, the recent-components table, charts, and injects `Active filter: Critical (N of M components)` into the AI system prompt. An active-filter chip with a Reset button sits under the KPI row. "Components" tile resets to `all`.

## 3. Risk card redesign

Replace the SVG half-donut with a compact scorecard:

```
┌─ Security Score ────────────────────────────┐
│  72/100        ▼ -4 since last scan         │
│  ████████████░░░░░░  Risk: ELEVATED         │
│  ● Critical 3   ● High 11   ● Med 24  ● Low │
│  Last scan: 18 Jun 09:42                    │
│  AI: Patch log4j-core 2.14 → 2.17 first     │
└─────────────────────────────────────────────┘
```

Horizontal animated bar, severity dots, trend arrow vs previous-scan snapshot (stored per-dataset in a new `risk_snapshots` field on the dataset row, or derived from current counts if no history exists), and a one-line AI recommendation pulled from the highest-CVSS component.

## 4. AI Security Analyst polish

Same panel, same backend (`/api/chat`). Visual upgrades only:
- Header: avatar + "Security Analyst" + green pulsing LIVE dot + active dataset name + active filter chip
- Suggested-prompt chips below input (rotate based on filter: e.g. when Critical filter active, show "Explain top critical CVEs", "Generate critical remediation plan")
- Thinking state: animated shimmer + "Analyzing dataset…" while `status === 'submitted'`
- Markdown: tighter table styling, code blocks with subtle background, callout blocks for severity mentions
- System prompt re-built each turn from store: dataset name, total components, active severity filter, top 10 highest-CVSS items as JSON

## 5. Security hardening

Currently `datasets` + `components` are world-readable AND world-writable (RLS true/true). Fix:

1. Add Lovable Cloud auth (email/password + Google) on a new `/auth` route. `_app` layout redirects unauthenticated users to `/auth`.
2. Migration:
   - `alter table datasets add column owner_id uuid references auth.users(id)`
   - Drop existing permissive policies on `datasets` and `components`
   - New policies: `owner_id = auth.uid()` for SELECT/INSERT/UPDATE/DELETE on datasets; components scoped via `exists (select 1 from datasets d where d.id = components.dataset_id and d.owner_id = auth.uid())`
   - Grants: `GRANT SELECT, INSERT, UPDATE, DELETE … TO authenticated` (no anon)
3. Existing rows have no owner — they'll become orphaned. Since this is dev data, the migration assigns all existing rows to the first user who signs up (or leaves them orphaned and unreachable; user can re-upload). I'll go with "assign to first authenticated user on first login" via a server function so the user doesn't lose their test data.

## 6. Out of scope (this pass)

- PDF export (CSV + XLSX already work; PDF needs a new lib)
- Drag-and-drop column reordering in SBOM page
- Real-time multi-user collaboration
- Per-user role/permission system beyond ownership

## Files touched

- NEW: `src/routes/_app.tsx`, `_app.index.tsx`, `_app.components.tsx`, `_app.vulnerabilities.tsx`, `_app.reports.tsx`, `_app.sbom.tsx`, `_app.datasets.tsx`, `auth.tsx`
- NEW: `src/lib/workbench-store.ts`, `src/components/workbench/sidebar.tsx`, `header.tsx`, `ai-panel.tsx`, `risk-card.tsx`, `kpi-tiles.tsx`, `component-card.tsx`, `component-drawer.tsx`
- DELETE: monolithic body of `src/routes/index.tsx` (becomes a redirect to `/` under `_app`)
- NEW: migration `add_auth_and_owner_scoped_rls.sql`
- EDIT: `src/routes/api/chat.ts` (accept filter context in body)

Estimated: ~15 new files, one migration, the existing 1278-line route file collapses into shared components.

Confirm and I'll execute. If you'd rather skip auth (keep the app open) say so — but the security findings only clear when RLS is scoped to authenticated users.
