import { createServerFn } from "@tanstack/react-start";

/**
 * Live external threat intelligence.
 * Enriches uploaded SBOM/VAPT rows with public data from CISA KEV, OSV.dev and
 * endoflife.date. Never overwrites uploaded values — the caller merges results
 * into a separate `intel` namespace with a last-updated timestamp.
 */

type Target = { key: string; component: string; version: string; cve: string; ecosystem?: string };

export type EnrichResult = Record<
  string,
  {
    kev?: boolean;
    exploitAvailable?: boolean;
    fixedVersion?: string;
    latestVersion?: string;
    eolDate?: string;
    supportEndDate?: string;
    advisoryIds?: string[];
    summary?: string;
    updatedAt: string;
    source: string;
  }
>;

const KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
const KEV_FALLBACK = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

let kevCache: { at: number; ids: Set<string> } | null = null;

async function loadKev(): Promise<Set<string>> {
  if (kevCache && Date.now() - kevCache.at < 6 * 60 * 60 * 1000) return kevCache.ids;
  for (const url of [KEV_URL, KEV_FALLBACK]) {
    try {
      const res = await fetch(url);
      if (!res.ok) continue;
      const json = (await res.json()) as { vulnerabilities?: Array<{ cveID?: string }> };
      const ids = new Set((json.vulnerabilities ?? []).map((v) => String(v.cveID ?? "").toUpperCase()).filter(Boolean));
      if (ids.size) {
        kevCache = { at: Date.now(), ids };
        return ids;
      }
    } catch {
      /* try next source */
    }
  }
  return kevCache?.ids ?? new Set<string>();
}

type OsvVuln = {
  id?: string;
  summary?: string;
  aliases?: string[];
  affected?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>;
};

async function osvLookup(t: Target): Promise<{ fixedVersion?: string; advisoryIds?: string[]; summary?: string } | null> {
  if (!t.component) return null;
  try {
    const body: Record<string, unknown> = { package: { name: t.component } };
    if (t.ecosystem) (body.package as Record<string, unknown>).ecosystem = t.ecosystem;
    if (t.version) body.version = t.version;
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) return null;
    const json = (await res.json()) as { vulns?: OsvVuln[] };
    const vulns = json.vulns ?? [];
    if (!vulns.length) return null;
    let fixedVersion = "";
    for (const v of vulns) {
      for (const a of v.affected ?? []) {
        for (const r of a.ranges ?? []) {
          for (const e of r.events ?? []) if (e.fixed) fixedVersion = fixedVersion || e.fixed;
        }
      }
    }
    return {
      fixedVersion: fixedVersion || undefined,
      advisoryIds: vulns.slice(0, 5).map((v) => String(v.id ?? "")).filter(Boolean),
      summary: vulns[0]?.summary,
    };
  } catch {
    return null;
  }
}

const eolCache = new Map<string, { latest?: string; eol?: string; support?: string } | null>();

async function eolLookup(product: string, version: string) {
  const slug = product.toLowerCase().trim().replace(/\s+/g, "-").replace(/[^a-z0-9.-]/g, "");
  if (!slug) return null;
  if (eolCache.has(slug)) return eolCache.get(slug) ?? null;
  try {
    const res = await fetch(`https://endoflife.date/api/${encodeURIComponent(slug)}.json`);
    if (!res.ok) {
      eolCache.set(slug, null);
      return null;
    }
    const cycles = (await res.json()) as Array<{ cycle?: string; latest?: string; eol?: string | boolean; support?: string | boolean }>;
    if (!Array.isArray(cycles) || !cycles.length) {
      eolCache.set(slug, null);
      return null;
    }
    const major = version.split(".")[0];
    const match = cycles.find((c) => String(c.cycle ?? "").split(".")[0] === major) ?? cycles[0];
    const out = {
      latest: cycles[0]?.latest ? String(cycles[0].latest) : undefined,
      eol: match?.eol != null && match.eol !== false ? String(match.eol) : undefined,
      support: match?.support != null && match.support !== false ? String(match.support) : undefined,
    };
    eolCache.set(slug, out);
    return out;
  } catch {
    eolCache.set(slug, null);
    return null;
  }
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const i = cursor++;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

export const enrichThreatIntel = createServerFn({ method: "POST" })
  .inputValidator((input: { targets: Target[] }) => {
    if (!input || !Array.isArray(input.targets)) throw new Error("targets required");
    return { targets: input.targets.slice(0, 120) };
  })
  .handler(async ({ data }) => {
    const kev = await loadKev();
    const updatedAt = new Date().toISOString();
    const out: EnrichResult = {};

    await mapLimit(data.targets, 8, async (t) => {
      const cve = t.cve.toUpperCase().trim();
      const isKev = Boolean(cve && kev.has(cve));
      const [osv, eol] = await Promise.all([
        t.component ? osvLookup(t) : Promise.resolve(null),
        t.component ? eolLookup(t.component, t.version) : Promise.resolve(null),
      ]);
      const sources = ["CISA KEV"];
      if (osv) sources.push("OSV.dev");
      if (eol) sources.push("endoflife.date");
      out[t.key] = {
        kev: isKev,
        exploitAvailable: isKev,
        fixedVersion: osv?.fixedVersion,
        latestVersion: eol?.latest,
        eolDate: eol?.eol,
        supportEndDate: eol?.support,
        advisoryIds: osv?.advisoryIds,
        summary: osv?.summary,
        updatedAt,
        source: sources.join(" · "),
      };
    });

    return { intel: out, updatedAt, kevSize: kev.size };
  });
