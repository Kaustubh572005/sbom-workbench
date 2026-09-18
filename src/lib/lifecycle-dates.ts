/**
 * Component lifecycle date catalogue.
 *
 * Curated EOL / EOS / latest-version dates for widely used components, keyed by
 * component name and version prefix. Pure data + pure helpers so it is safe on
 * both the client and the server, and trivial to extend as vendors announce new
 * end-of-life dates.
 *
 * Precedence rule: uploaded SBOM values and live external intelligence always
 * win. This catalogue is only used as a fallback when no date is known.
 */

export type LifecycleDateEntry = {
  /** version prefix this entry applies to; "*" matches any version */
  version: string;
  /** end of life (YYYY-MM-DD) */
  eol?: string;
  /** end of security support (YYYY-MM-DD) */
  eos?: string;
  /** latest known stable version of the line */
  latest?: string;
  note?: string;
};

/** component key -> entries, most specific version prefix first */
export const LIFECYCLE_CATALOG: Record<string, LifecycleDateEntry[]> = {
  jquery: [
    { version: "1.", eol: "2016-05-20", eos: "2016-05-20", latest: "3.7.1", note: "1.x line retired" },
    { version: "2.", eol: "2016-05-20", eos: "2016-05-20", latest: "3.7.1", note: "2.x line retired" },
    { version: "3.4", eol: "2026-01-17", eos: "2026-01-17", latest: "3.7.1" },
    { version: "3.5", eol: "2027-05-04", latest: "3.7.1" },
    { version: "3.6", eol: "2028-03-02", latest: "3.7.1" },
    { version: "3.7", eol: "2030-12-31", latest: "3.7.1" },
    { version: "*", eol: "2026-01-17", latest: "3.7.1" },
  ],
  "jquery-ui": [{ version: "1.12", eol: "2021-10-01", latest: "1.14.1" }, { version: "*", latest: "1.14.1" }],
  angular: [
    { version: "1.", eol: "2021-12-31", eos: "2021-12-31", latest: "1.8.3", note: "AngularJS is end of life" },
    { version: "12", eol: "2022-11-12", latest: "20.0.0" },
    { version: "13", eol: "2023-05-04", latest: "20.0.0" },
    { version: "14", eol: "2023-11-18", latest: "20.0.0" },
    { version: "15", eol: "2024-05-18", latest: "20.0.0" },
    { version: "16", eol: "2024-11-08", latest: "20.0.0" },
    { version: "17", eol: "2025-05-15", latest: "20.0.0" },
    { version: "18", eol: "2025-11-19", latest: "20.0.0" },
    { version: "*", latest: "20.0.0" },
  ],
  angularjs: [{ version: "*", eol: "2021-12-31", eos: "2021-12-31", latest: "1.8.3" }],
  bootstrap: [
    { version: "3.", eol: "2019-07-24", eos: "2019-07-24", latest: "5.3.3" },
    { version: "4.", eol: "2022-04-30", eos: "2022-04-30", latest: "5.3.3" },
    { version: "5.", eol: "2026-12-31", latest: "5.3.3" },
    { version: "*", latest: "5.3.3" },
  ],
  entityframework: [
    { version: "6.", eol: "2022-11-30", eos: "2022-11-30", latest: "6.5.1", note: "EF6 receives no feature work" },
    { version: "*", latest: "6.5.1" },
  ],
  "microsoft.entityframeworkcore": [
    { version: "6.", eol: "2024-11-12", latest: "9.0.0" },
    { version: "7.", eol: "2024-05-14", latest: "9.0.0" },
    { version: "8.", eol: "2026-11-10", latest: "9.0.0" },
    { version: "*", latest: "9.0.0" },
  ],
  dapper: [{ version: "2.0", eol: "2024-12-31", latest: "2.1.66" }, { version: "*", latest: "2.1.66" }],
  epplus: [{ version: "4.", eol: "2020-05-31", latest: "7.5.0" }, { version: "5.", eol: "2024-12-31", latest: "7.5.0" }, { version: "*", latest: "7.5.0" }],
  newtonsoft_json: [{ version: "*", latest: "13.0.3" }],
  "newtonsoft.json": [{ version: "9.", eol: "2018-06-01", latest: "13.0.3" }, { version: "*", latest: "13.0.3" }],
  ".net framework": [
    { version: "4.5", eol: "2016-01-12" },
    { version: "4.6", eol: "2022-04-26" },
    { version: "4.7", eol: "2027-01-12" },
    { version: "4.8", eol: "2026-01-13", note: "Follows Windows host lifecycle" },
    { version: "*", eol: "2026-01-13" },
  ],
  dotnet: [
    { version: "3.1", eol: "2022-12-13", latest: "9.0" },
    { version: "5.", eol: "2022-05-10", latest: "9.0" },
    { version: "6.", eol: "2024-11-12", latest: "9.0" },
    { version: "7.", eol: "2024-05-14", latest: "9.0" },
    { version: "8.", eol: "2026-11-10", latest: "9.0" },
    { version: "*", latest: "9.0" },
  ],
  node: [
    { version: "12", eol: "2022-04-30", latest: "22.11.0" },
    { version: "14", eol: "2023-04-30", latest: "22.11.0" },
    { version: "16", eol: "2023-09-11", latest: "22.11.0" },
    { version: "18", eol: "2025-04-30", latest: "22.11.0" },
    { version: "20", eol: "2026-04-30", latest: "22.11.0" },
    { version: "*", latest: "22.11.0" },
  ],
  python: [
    { version: "2.", eol: "2020-01-01", latest: "3.13" },
    { version: "3.7", eol: "2023-06-27", latest: "3.13" },
    { version: "3.8", eol: "2024-10-07", latest: "3.13" },
    { version: "3.9", eol: "2025-10-31", latest: "3.13" },
    { version: "*", latest: "3.13" },
  ],
  openssl: [
    { version: "1.0", eol: "2019-12-31", latest: "3.4.0" },
    { version: "1.1", eol: "2023-09-11", latest: "3.4.0" },
    { version: "3.0", eol: "2026-09-07", latest: "3.4.0" },
    { version: "*", latest: "3.4.0" },
  ],
  log4j: [{ version: "1.", eol: "2015-08-05", latest: "2.24.1" }, { version: "*", latest: "2.24.1" }],
  "log4j-core": [{ version: "2.0", eol: "2021-12-10", latest: "2.24.1" }, { version: "*", latest: "2.24.1" }],
  spring: [{ version: "4.", eol: "2020-12-31", latest: "6.2.0" }, { version: "5.", eol: "2024-08-31", latest: "6.2.0" }, { version: "*", latest: "6.2.0" }],
  "spring-boot": [{ version: "2.", eol: "2023-11-24", latest: "3.4.0" }, { version: "*", latest: "3.4.0" }],
  tomcat: [{ version: "7.", eol: "2021-03-31", latest: "11.0" }, { version: "8.", eol: "2024-06-30", latest: "11.0" }, { version: "*", latest: "11.0" }],
  react: [{ version: "16", eol: "2022-06-14", latest: "19.0.0" }, { version: "17", eol: "2024-03-01", latest: "19.0.0" }, { version: "*", latest: "19.0.0" }],
  lodash: [{ version: "3.", eol: "2016-01-12", latest: "4.17.21" }, { version: "*", latest: "4.17.21" }],
  moment: [{ version: "*", eol: "2020-09-15", latest: "2.30.1", note: "Project is in maintenance mode" }],
  mysql: [{ version: "5.7", eol: "2023-10-31", latest: "8.4" }, { version: "*", latest: "8.4" }],
  postgresql: [{ version: "11", eol: "2023-11-09", latest: "17" }, { version: "12", eol: "2024-11-14", latest: "17" }, { version: "*", latest: "17" }],
  nginx: [{ version: "1.20", eol: "2022-05-24", latest: "1.27" }, { version: "*", latest: "1.27" }],
  php: [{ version: "7.", eol: "2022-11-28", latest: "8.4" }, { version: "8.0", eol: "2023-11-26", latest: "8.4" }, { version: "8.1", eol: "2025-12-31", latest: "8.4" }, { version: "*", latest: "8.4" }],
};

const normalizeName = (raw: string) =>
  raw
    .toLowerCase()
    .trim()
    .replace(/^@[^/]+\//, "")
    .replace(/^pkg:[a-z]+\//, "")
    .replace(/\.(js|net|dll|nupkg)$/i, "")
    .replace(/\s+/g, " ");

function catalogKeyFor(component: string): string | null {
  const name = normalizeName(component);
  if (!name) return null;
  if (LIFECYCLE_CATALOG[name]) return name;
  const keys = Object.keys(LIFECYCLE_CATALOG);
  const exactWord = keys.find((k) => name === k || name.split(/[ ._-]/).includes(k));
  if (exactWord) return exactWord;
  const contained = keys
    .filter((k) => k.length >= 4 && name.includes(k))
    .sort((a, b) => b.length - a.length)[0];
  return contained ?? null;
}

export type LifecycleDateMatch = LifecycleDateEntry & { component: string; matchedVersion: string; source: string };

/** Look up curated EOL/EOS/latest data for a component + version. */
export function lookupLifecycleDates(component: string, version: string): LifecycleDateMatch | null {
  const key = catalogKeyFor(component);
  if (!key) return null;
  const entries = LIFECYCLE_CATALOG[key];
  const v = String(version ?? "").trim();
  const specific = entries
    .filter((e) => e.version !== "*" && v.startsWith(e.version))
    .sort((a, b) => b.version.length - a.version.length)[0];
  const entry = specific ?? entries.find((e) => e.version === "*");
  if (!entry) return null;
  return { ...entry, component: key, matchedVersion: entry.version, source: "Curated lifecycle catalogue" };
}

const DAY = 86_400_000;

export function parseDate(value?: string | null): Date | null {
  if (!value) return null;
  const t = Date.parse(String(value).trim());
  return Number.isFinite(t) ? new Date(t) : null;
}

export function toIsoDate(value?: string | null): string {
  const d = parseDate(value);
  return d ? d.toISOString().slice(0, 10) : "";
}

/** Whole days between two dates (b - a). */
export function daysBetween(a: Date, b: Date): number {
  return Math.round((b.getTime() - a.getTime()) / DAY);
}

/** Days already elapsed past EOL, or null when not past EOL / unknown. */
export function daysPastEol(eol?: string | null, now = new Date()): number | null {
  const d = parseDate(eol);
  if (!d) return null;
  const diff = daysBetween(d, now);
  return diff > 0 ? diff : null;
}

/** Days remaining until EOL, or null when already past EOL / unknown. */
export function daysToEol(eol?: string | null, now = new Date()): number | null {
  const d = parseDate(eol);
  if (!d) return null;
  const diff = daysBetween(now, d);
  return diff >= 0 ? diff : null;
}

export type LifecycleStage = "Active" | "Security Only" | "Approaching EOL" | "Past EOL" | "Unknown";

export function lifecycleStageFromDates(eol?: string | null, eos?: string | null, now = new Date()): LifecycleStage {
  const past = daysPastEol(eol, now);
  if (past != null) return "Past EOL";
  const toEnd = daysToEol(eol, now);
  if (toEnd != null && toEnd <= 90) return "Approaching EOL";
  const eosPast = daysPastEol(eos, now);
  if (eosPast != null) return "Security Only";
  if (toEnd != null) return "Active";
  return "Unknown";
}
