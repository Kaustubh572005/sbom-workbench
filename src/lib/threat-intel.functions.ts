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

const osvCache = new Map<string, Awaited<ReturnType<typeof osvQuery>>>();
async function osvLookup(t: Target) {
  const k = `${t.component}|${t.version}|${t.ecosystem ?? ""}`.toLowerCase();
  if (!osvCache.has(k)) osvCache.set(k, await osvQuery(t));
  return osvCache.get(k) ?? null;
}

async function osvQuery(t: Target): Promise<{ fixedVersion?: string; advisoryIds?: string[]; summary?: string } | null> {
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

type EolCycle = { cycle?: string; latest?: string; eol?: string | boolean; support?: string | boolean };
/** one fetch per product (all release cycles); the version is matched afterwards */
const eolCache = new Map<string, EolCycle[] | null>();

/** spellings found in SBOMs → endoflife.date product slug */
const EOL_SLUGS: Array<[RegExp, string]> = [
  [/^node(\.?js)?$/, "nodejs"],
  [/^(microsoft\.?)?\.?net framework$/, "dotnetfx"],
  [/^(microsoft\.?)?\.?net( core)?$|^dotnet(-core)?$/, "dotnet"],
  [/^(apache )?tomcat(-embed-core)?$/, "tomcat"],
  [/^postgres(ql)?$/, "postgresql"],
  [/^spring-boot(-starter.*)?$/, "spring-boot"],
  [/^spring(-framework|-core|-web|-webmvc|-context|-beans)?$/, "spring-framework"],
  [/^(apache http server|apache2?|httpd)$/, "apache"],
  [/^angular\.?js$/, "angularjs"],
  [/^(cpython|python3?)$/, "python"],
  [/^(open)?jdk$|^java$/, "oracle-jdk"],
  [/^windows server/, "windows-server"],
  [/^(rhel|red hat enterprise linux)$/, "rhel"],
];

const eolSlug = (product: string) => {
  const n = product.toLowerCase().trim();
  for (const [re, slug] of EOL_SLUGS) if (re.test(n)) return slug;
  return n.replace(/\s+/g, "-").replace(/[^a-z0-9.-]/g, "");
};

const asDate = (v: string | boolean | undefined) =>
  typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : undefined;

async function eolLookup(product: string, version: string) {
  const slug = eolSlug(product);
  if (!slug) return null;
  if (!eolCache.has(slug)) {
    try {
      const res = await fetch(`https://endoflife.date/api/${encodeURIComponent(slug)}.json`);
      const cycles = res.ok ? ((await res.json()) as EolCycle[]) : null;
      eolCache.set(slug, Array.isArray(cycles) && cycles.length ? cycles : null);
    } catch {
      eolCache.set(slug, null);
    }
  }
  const cycles = eolCache.get(slug);
  if (!cycles) return null;

  const nums = version.trim().replace(/^[^0-9]*/, "").split(/[^0-9]+/).filter(Boolean);
  const [major, minor] = nums;
  // exact release line first (3.11), then the major line (18) — never guess another line's dates
  const match =
    (major && minor ? cycles.find((c) => String(c.cycle ?? "") === `${major}.${minor}`) : undefined) ??
    (major ? cycles.find((c) => String(c.cycle ?? "") === major) : undefined);
  return {
    latest: cycles[0]?.latest ? String(cycles[0].latest) : undefined,
    eol: asDate(match?.eol),
    support: asDate(match?.support),
  };
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
    return { targets: input.targets.slice(0, 300) };
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
