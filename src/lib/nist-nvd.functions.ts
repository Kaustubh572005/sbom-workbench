import { createServerFn } from "@tanstack/react-start";

/**
 * NIST NVD v2.0 lookup (by CVE ID) + CISA KEV exploit dates.
 * Results are cached per worker instance and requests are rate limited
 * to respect the NVD public tier.
 */
export type NvdRecord = {
  cve: string;
  cvss: number;
  vector: string;
  severity: string;
  published: string;
  lastModified: string;
  description: string;
  exploitDate?: string;
  source: string;
};

const cache = new Map<string, NvdRecord | null>();
let kevDates: { at: number; map: Map<string, string> } | null = null;

async function loadKevDates() {
  if (kevDates && Date.now() - kevDates.at < 6 * 3600_000) return kevDates.map;
  const map = new Map<string, string>();
  try {
    const res = await fetch("https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json");
    if (res.ok) {
      const j = (await res.json()) as { vulnerabilities?: Array<{ cveID?: string; dateAdded?: string }> };
      for (const v of j.vulnerabilities ?? []) if (v.cveID && v.dateAdded) map.set(v.cveID.toUpperCase(), v.dateAdded);
    }
  } catch { /* ignore */ }
  kevDates = { at: Date.now(), map };
  return map;
}

type NvdMetric = { cvssData?: { baseScore?: number; vectorString?: string; baseSeverity?: string } };
type NvdVuln = {
  cve?: {
    id?: string; published?: string; lastModified?: string;
    descriptions?: Array<{ lang?: string; value?: string }>;
    metrics?: { cvssMetricV31?: NvdMetric[]; cvssMetricV30?: NvdMetric[]; cvssMetricV2?: Array<NvdMetric & { baseSeverity?: string }> };
  };
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function fetchCve(id: string): Promise<NvdRecord | null> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const headers: Record<string, string> = {};
      const key = process.env["NVD_API_KEY"];
      if (key) headers.apiKey = key;
      const res = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`, { headers });
      if (res.status === 403 || res.status === 429) { await sleep(1500); continue; }
      if (!res.ok) return null;
      const j = (await res.json()) as { vulnerabilities?: NvdVuln[] };
      const c = j.vulnerabilities?.[0]?.cve;
      if (!c) return null;
      const m = c.metrics?.cvssMetricV31?.[0] ?? c.metrics?.cvssMetricV30?.[0] ?? c.metrics?.cvssMetricV2?.[0];
      const score = Number(m?.cvssData?.baseScore ?? 0);
      return {
        cve: id,
        cvss: score,
        vector: m?.cvssData?.vectorString ?? "",
        severity: sevFromCvss(score),
        published: (c.published ?? "").slice(0, 10),
        lastModified: (c.lastModified ?? "").slice(0, 10),
        description: c.descriptions?.find((d) => d.lang === "en")?.value ?? "",
        source: "NIST NVD",
      };
    } catch { return null; }
  }
  return null;
}

export function sevFromCvss(s: number) {
  return s >= 9 ? "CRITICAL" : s >= 7 ? "HIGH" : s >= 4 ? "MEDIUM" : s > 0 ? "LOW" : "NONE";
}

export const lookupNvd = createServerFn({ method: "POST" })
  .inputValidator((input: { cves: string[] }) => {
    if (!input || !Array.isArray(input.cves)) throw new Error("cves required");
    const ids = [...new Set(input.cves.map((c) => String(c).toUpperCase().trim()).filter((c) => /^CVE-\d{4}-\d{4,}$/.test(c)))];
    return { cves: ids.slice(0, 40) };
  })
  .handler(async ({ data }) => {
    const kev = await loadKevDates();
    const hasKey = Boolean(process.env["NVD_API_KEY"]);
    const out: Record<string, NvdRecord> = {};
    const todo = data.cves.filter((c) => !cache.has(c));
    // rate limit: ~5 req / window without key; process in small batches
    const batch = hasKey ? 10 : 4;
    for (let i = 0; i < todo.length; i += batch) {
      const slice = todo.slice(i, i + batch);
      const res = await Promise.all(slice.map(fetchCve));
      slice.forEach((id, k) => cache.set(id, res[k]));
      if (i + batch < todo.length) await sleep(hasKey ? 700 : 1200);
    }
    for (const id of data.cves) {
      const r = cache.get(id);
      if (r) out[id] = { ...r, exploitDate: kev.get(id) };
      else if (kev.has(id)) out[id] = { cve: id, cvss: 0, vector: "", severity: "NONE", published: "", lastModified: "", description: "", exploitDate: kev.get(id), source: "CISA KEV" };
    }
    return { records: out, fetchedAt: new Date().toISOString() };
  });
