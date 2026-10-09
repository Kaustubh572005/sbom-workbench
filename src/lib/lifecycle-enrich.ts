/**
 * Client-side driver for live enrichment (CISA KEV · OSV.dev · endoflife.date).
 * Runs in batches, deduplicates by component+version so every release is looked
 * up once, and fills every CVE row of that release with the same EOL / EOS data.
 */
import { factsOf } from "@/lib/risk-intel";
import { intelKey, lifeKey, type Enrichment } from "@/lib/vuln-intel";
import { cveIds } from "@/lib/nist-scoring";
import type { NvdRecord } from "@/lib/nist-nvd.functions";

type Target = { key: string; component: string; version: string; cve: string };
export type EnrichFn = (args: { data: { targets: Target[] } }) => Promise<{ intel: Record<string, Enrichment>; updatedAt: string }>;
export type NvdFn = (args: { data: { cves: string[] } }) => Promise<{ records: Record<string, NvdRecord>; fetchedAt: string }>;
export type Enrichers = { enrich: EnrichFn; nvd: NvdFn };

/** field-level merge: a later patch never erases data an earlier patch supplied */
export function mergeIntel(prev: Record<string, Enrichment>, patch: Record<string, Enrichment>): Record<string, Enrichment> {
  const out = { ...prev };
  for (const [k, v] of Object.entries(patch)) {
    const defined = Object.fromEntries(Object.entries(v).filter(([, x]) => x !== undefined));
    out[k] = { ...out[k], ...defined };
  }
  return out;
}

const BATCH = 150;
const CAP = 1500;

export async function enrichRows(
  rows: Array<Record<string, unknown>>,
  known: Record<string, Enrichment>,
  { enrich, nvd }: Enrichers,
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

  /* NIST NVD: authoritative CVSS v3.x score, vector and publish date for every CVE in the file */
  const cveKeys = new Map<string, Set<string>>();
  for (const r of rows) {
    const f = factsOf(r);
    const key = intelKey(r);
    if (known[key]?.cvss) continue;
    for (const id of cveIds(f.cve)) {
      if (!cveKeys.has(id)) cveKeys.set(id, new Set());
      cveKeys.get(id)!.add(key);
    }
  }
  const ids = [...cveKeys.keys()].slice(0, 200);
  for (let i = 0; i < ids.length; i += 40) {
    if (cancelled()) return;
    try {
      const res = await nvd({ data: { cves: ids.slice(i, i + 40) } });
      const patch: Record<string, Enrichment> = {};
      for (const [cve, rec] of Object.entries(res.records)) {
        for (const key of cveKeys.get(cve) ?? []) {
          const cur = patch[key];
          if (cur?.cvss && cur.cvss >= rec.cvss) { if (rec.exploitDate) cur.kev = true; continue; }
          patch[key] = {
            ...(rec.cvss > 0 ? { cvss: rec.cvss, cvssVector: rec.vector } : {}),
            cvePublished: rec.published || cur?.cvePublished,
            ...(rec.exploitDate || cur?.kev ? { kev: true } : {}),
          };
        }
      }
      if (!cancelled()) onBatch(patch, res.fetchedAt);
    } catch {
      /* NVD being unavailable must never block the analysis — uploaded CVSS is used instead */
    }
  }
}
