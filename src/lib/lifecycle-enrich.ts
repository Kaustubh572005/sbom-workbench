/**
 * Client-side driver for live enrichment (CISA KEV · OSV.dev · endoflife.date).
 * Runs in batches, deduplicates by component+version so every release is looked
 * up once, and fills every CVE row of that release with the same EOL / EOS data.
 */
import { factsOf } from "@/lib/risk-intel";
import { intelKey, lifeKey, type Enrichment } from "@/lib/vuln-intel";

type Target = { key: string; component: string; version: string; cve: string };
export type EnrichFn = (args: { data: { targets: Target[] } }) => Promise<{ intel: Record<string, Enrichment>; updatedAt: string }>;

const BATCH = 150;
const CAP = 1500;

export async function enrichRows(
  rows: Array<Record<string, unknown>>,
  known: Record<string, Enrichment>,
  enrich: EnrichFn,
  onBatch: (patch: Record<string, Enrichment>, at: string) => void,
  cancelled: () => boolean = () => false,
): Promise<void> {
  const firstOfRelease: Target[] = [];
  const rest: Target[] = [];
  const seenKey = new Set<string>();
  const seenRelease = new Set<string>();
  for (const r of rows) {
    const f = factsOf(r);
    if (!f.component) continue;
    const key = intelKey(r);
    if (seenKey.has(key) || known[key]) continue;
    seenKey.add(key);
    const release = lifeKey(r);
    const t = { key, component: f.component, version: f.version, cve: f.cve };
    if (!seenRelease.has(release) && !known[release]) { seenRelease.add(release); firstOfRelease.push(t); } else rest.push(t);
  }
  // one look-up per release first (EOL/EOS coverage), then the remaining CVE rows (KEV / advisories)
  const queue = [...firstOfRelease, ...rest].slice(0, CAP);
  for (let i = 0; i < queue.length; i += BATCH) {
    if (cancelled()) return;
    const batch = queue.slice(i, i + BATCH);
    try {
      const res = await enrich({ data: { targets: batch } });
      const patch: Record<string, Enrichment> = { ...res.intel };
      for (const t of batch) {
        const e = res.intel[t.key];
        if (!e) continue;
        const lk = lifeKey({ component: t.component, version: t.version });
        patch[lk] = { eolDate: e.eolDate, supportEndDate: e.supportEndDate, latestVersion: e.latestVersion, updatedAt: e.updatedAt, source: e.source };
      }
      if (!cancelled()) onBatch(patch, res.updatedAt);
    } catch {
      /* a failed batch must never block the analysis — dates fall back to uploaded / curated data */
    }
  }
}
