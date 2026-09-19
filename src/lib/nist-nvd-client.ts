/**
 * NIST NVD API v2.0 client.
 *
 * Fetches real CVE identifiers, CVSS v3.1 base scores, vector strings and
 * publication dates for a component + version. Includes an in-memory cache and
 * a token-bucket rate limiter (NVD allows ~5 requests / 30s without a key, so we
 * stay deliberately conservative) plus graceful error handling: every failure
 * resolves to null instead of throwing.
 */

export type NvdRecord = {
  cveId: string;
  cvss: number;
  cvssVector: string;
  cvssSeverity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
  published: string;
  lastModified: string;
  description: string;
  source: string;
};

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CACHE_TTL = 12 * 60 * 60 * 1000;

const cache = new Map<string, { at: number; value: NvdRecord | null }>();

/** max 5 requests per second, spaced evenly */
const MIN_GAP_MS = 220;
let lastCall = 0;
let chain: Promise<void> = Promise.resolve();

function throttle(): Promise<void> {
  chain = chain.then(async () => {
    const wait = Math.max(0, lastCall + MIN_GAP_MS - Date.now());
    if (wait) await new Promise((r) => setTimeout(r, wait));
    lastCall = Date.now();
  });
  return chain;
}

export function severityFromCvss(score: number): NvdRecord["cvssSeverity"] {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

/** Normalise any date-ish value to YYYY-MM-DD. */
export function formatNvdDate(value?: string): string {
  if (!value) return "";
  const t = Date.parse(value);
  return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 10) : "";
}

type NvdMetric = { cvssData?: { baseScore?: number; vectorString?: string; baseSeverity?: string } };

type NvdCve = {
  id?: string;
  published?: string;
  lastModified?: string;
  descriptions?: Array<{ lang?: string; value?: string }>;
  metrics?: {
    cvssMetricV31?: NvdMetric[];
    cvssMetricV30?: NvdMetric[];
    cvssMetricV2?: Array<{ cvssData?: { baseScore?: number; vectorString?: string } }>;
  };
};

function toRecord(cve: NvdCve): NvdRecord | null {
  if (!cve?.id) return null;
  const metric = cve.metrics?.cvssMetricV31?.[0] ?? cve.metrics?.cvssMetricV30?.[0];
  const v2 = cve.metrics?.cvssMetricV2?.[0];
  const score = Number(metric?.cvssData?.baseScore ?? v2?.cvssData?.baseScore ?? 0) || 0;
  return {
    cveId: cve.id.toUpperCase(),
    cvss: score,
    cvssVector: String(metric?.cvssData?.vectorString ?? v2?.cvssData?.vectorString ?? ""),
    cvssSeverity: severityFromCvss(score),
    published: formatNvdDate(cve.published),
    lastModified: formatNvdDate(cve.lastModified),
    description:
      cve.descriptions?.find((d) => d.lang === "en")?.value ?? cve.descriptions?.[0]?.value ?? "",
    source: "NIST NVD v2.0",
  };
}

async function callNvd(params: URLSearchParams, apiKey?: string): Promise<NvdCve[]> {
  await throttle();
  const headers: Record<string, string> = { Accept: "application/json" };
  if (apiKey) headers.apiKey = apiKey;
  const res = await fetch(`${NVD_URL}?${params.toString()}`, { headers });
  if (!res.ok) return [];
  const json = (await res.json()) as { vulnerabilities?: Array<{ cve?: NvdCve }> };
  return (json.vulnerabilities ?? []).map((v) => v.cve).filter((c): c is NvdCve => Boolean(c));
}

/** Look up a single CVE by identifier. */
export async function lookupCve(cveId: string, apiKey?: string): Promise<NvdRecord | null> {
  const id = cveId.toUpperCase().trim();
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return null;
  const cached = cache.get(id);
  if (cached && Date.now() - cached.at < CACHE_TTL) return cached.value;
  try {
    const cves = await callNvd(new URLSearchParams({ cveId: id }), apiKey);
    const value = cves.length ? toRecord(cves[0]) : null;
    cache.set(id, { at: Date.now(), value });
    return value;
  } catch {
    cache.set(id, { at: Date.now(), value: null });
    return null;
  }
}

/**
 * Look up the highest-scoring CVE for a component + version. Prefers a direct
 * CVE lookup when the sheet already names one.
 */
export async function lookupComponent(
  component: string,
  version: string,
  cve?: string,
  apiKey?: string,
): Promise<NvdRecord | null> {
  if (cve) {
    const direct = await lookupCve(cve, apiKey);
    if (direct) return direct;
  }
  const name = component.trim();
  if (!name) return null;
  const key = `kw:${name.toLowerCase()}@${version.trim()}`;
  const cached = cache.get(key);
  if (cached && Date.now() - cached.at < CACHE_TTL) return cached.value;
  try {
    const keyword = [name, version.trim()].filter(Boolean).join(" ");
    const cves = await callNvd(
      new URLSearchParams({ keywordSearch: keyword, resultsPerPage: "20" }),
      apiKey,
    );
    const records = cves.map(toRecord).filter((r): r is NvdRecord => Boolean(r));
    const best = records.sort((a, b) => b.cvss - a.cvss || b.published.localeCompare(a.published))[0] ?? null;
    cache.set(key, { at: Date.now(), value: best });
    return best;
  } catch {
    cache.set(key, { at: Date.now(), value: null });
    return null;
  }
}
