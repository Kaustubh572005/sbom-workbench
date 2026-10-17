import { createServerFn } from "@tanstack/react-start";
import { cvssFromVector } from "@/lib/nist-scoring";

/**
 * Live external threat intelligence.
 * Enriches uploaded SBOM/VAPT rows with public data from CISA KEV, OSV.dev and
 * endoflife.date. Never overwrites uploaded values — the caller merges results
 * into a separate `intel` namespace with a last-updated timestamp.
 */

type Target = { key: string; component: string; version: string; cve: string; ecosystem?: string; purl?: string };

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
    /** CVE ids OSV.dev lists for this package release (only when the row carries no CVE of its own) */
    cves?: string[];
    /** highest CVSS v3 base score among those advisories, computed from their vectors with the NIST formula */
    osvCvss?: number;
    osvVector?: string;
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
  severity?: Array<{ type?: string; score?: string }>;
  affected?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>;
};

const osvCache = new Map<string, OsvResult>();
async function osvLookup(t: Target) {
  const k = `${t.purl ?? t.component}|${t.version}|${t.ecosystem ?? ""}`.toLowerCase();
  if (!osvCache.has(k)) osvCache.set(k, await osvQuery(t));
  return osvCache.get(k) ?? null;
}

/** OSV ecosystem names for the ecosystems SBOMs usually declare */
const OSV_ECOSYSTEM: Record<string, string> = {
  npm: "npm", maven: "Maven", pypi: "PyPI", nuget: "NuGet", golang: "Go", go: "Go", cargo: "crates.io",
  gem: "RubyGems", rubygems: "RubyGems", composer: "Packagist", packagist: "Packagist", pub: "Pub", hex: "Hex",
};

type OsvResult = {
  fixedVersion?: string; advisoryIds?: string[]; summary?: string; cves?: string[]; osvCvss?: number; osvVector?: string;
} | null;

async function osvQuery(t: Target): Promise<OsvResult> {
  if (!t.component) return null;
  try {
    // OSV needs either a purl or name + ecosystem — a bare package name is rejected
    const eco = OSV_ECOSYSTEM[(t.ecosystem ?? "").toLowerCase().trim()];
    const body: Record<string, unknown> = {};
    if (t.purl) {
      body.package = { purl: t.purl };
      if (!/@[^/]+$/.test(t.purl) && t.version) body.version = t.version;
    } else if (eco) {
      body.package = { name: t.component, ecosystem: eco };
      if (t.version) body.version = t.version;
    } else {
      return null;
    }
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
    let osvCvss = 0;
    let osvVector = "";
    const cves = new Set<string>();
    for (const v of vulns) {
      for (const a of v.affected ?? []) {
        for (const r of a.ranges ?? []) {
          for (const e of r.events ?? []) if (e.fixed) fixedVersion = fixedVersion || e.fixed;
        }
      }
      for (const id of [v.id, ...(v.aliases ?? [])]) if (id && /^CVE-\d{4}-\d{4,}$/i.test(id)) cves.add(id.toUpperCase());
      for (const sv of v.severity ?? []) {
        const score = sv.score ? cvssFromVector(sv.score) : null;
        if (score && score > osvCvss) { osvCvss = score; osvVector = sv.score ?? ""; }
      }
    }
    return {
      fixedVersion: fixedVersion || undefined,
      advisoryIds: vulns.slice(0, 5).map((v) => String(v.id ?? "")).filter(Boolean),
      summary: vulns[0]?.summary,
      cves: [...cves].slice(0, 20),
      osvCvss: osvCvss || undefined,
      osvVector: osvVector || undefined,
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

/** the enrichment itself — a plain function so it can be exercised without the server-function transport */
export async function enrichTargets(targets: Target[]) {
    const kev = await loadKev();
    const updatedAt = new Date().toISOString();
    const out: EnrichResult = {};

    await mapLimit(targets, 8, async (t) => {
      const cve = t.cve.toUpperCase().trim();
      let isKev = Boolean(cve && kev.has(cve));
      const [osv, eol] = await Promise.all([
        t.component ? osvLookup(t) : Promise.resolve(null),
        t.component ? eolLookup(t.component, t.version) : Promise.resolve(null),
      ]);
      // package-level advisories describe the whole release, so they only score rows that carry no CVE of their own
      const pkgLevel = !cve && osv;
      if (pkgLevel && osv.cves?.some((c) => kev.has(c))) isKev = true;
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
        cves: pkgLevel ? osv.cves : undefined,
        osvCvss: pkgLevel ? osv.osvCvss : undefined,
        osvVector: pkgLevel ? osv.osvVector : undefined,
        summary: osv?.summary,
        updatedAt,
        source: sources.join(" · "),
      };
    });

    return { intel: out, updatedAt, kevSize: kev.size };
}

export const enrichThreatIntel = createServerFn({ method: "POST" })
  .inputValidator((input: { targets: Target[] }) => {
    if (!input || !Array.isArray(input.targets)) throw new Error("targets required");
    return { targets: input.targets.slice(0, 300) };
  })
  .handler(async ({ data }) => enrichTargets(data.targets));
