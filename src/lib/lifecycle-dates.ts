/**
 * Lifecycle (EOL / EOS) date resolution.
 *
 * EOL = End of Life   (no further fixes of any kind from the vendor)
 * EOS = End of Support (end of active / mainstream support — security-only or
 *       paid support may continue after this date)
 *
 * Order of authority for every component:
 *   1. Dates present in the uploaded file (never overwritten)
 *   2. Live vendor feed (endoflife.date) fetched by the server
 *   3. Curated vendor table below (only dates published by the vendor)
 *
 * Only add a curated row when the vendor has published the date. An unknown
 * date must stay unknown — it is shown as "Not published", never guessed.
 */

type Cycle = { eol?: string; eos?: string };

/** key = normalised product, inner key = version prefix ("3.11" matches 3.11.4), "*" = whole product */
const CURATED: Record<string, Record<string, Cycle>> = {
  python: {
    "2.7": { eol: "2020-01-01" }, "3.6": { eol: "2021-12-23" }, "3.7": { eol: "2023-06-27", eos: "2020-06-27" },
    "3.8": { eol: "2024-10-07", eos: "2021-05-03" }, "3.9": { eol: "2025-10-31", eos: "2022-05-17" },
    "3.10": { eol: "2026-10-31", eos: "2023-04-05" }, "3.11": { eol: "2027-10-31", eos: "2024-04-02" },
    "3.12": { eol: "2028-10-31", eos: "2025-04-02" }, "3.13": { eol: "2029-10-31" },
  },
  nodejs: {
    "12": { eol: "2022-04-30" }, "14": { eol: "2023-04-30" }, "16": { eol: "2023-09-11" },
    "18": { eol: "2025-04-30", eos: "2023-10-18" }, "20": { eol: "2026-04-30", eos: "2024-10-22" },
    "22": { eol: "2027-04-30", eos: "2025-10-21" }, "24": { eol: "2028-04-30" },
  },
  ".net": {
    "2.1": { eol: "2021-08-21" }, "3.1": { eol: "2022-12-13" }, "5": { eol: "2022-05-10" },
    "6": { eol: "2024-11-12" }, "7": { eol: "2024-05-14" }, "8": { eol: "2026-11-10" }, "9": { eol: "2026-11-10" },
  },
  ".net framework": {
    "4.5": { eol: "2016-01-12" }, "4.5.1": { eol: "2016-01-12" }, "4.5.2": { eol: "2022-04-26" },
    "4.6": { eol: "2022-04-26" }, "4.6.1": { eol: "2022-04-26" },
  },
  "microsoft.entityframeworkcore": {
    "6": { eol: "2024-11-12" }, "7": { eol: "2024-05-14" }, "8": { eol: "2026-11-10" }, "9": { eol: "2026-11-10" },
  },
  windows: {
    xp: { eol: "2014-04-08" }, vista: { eol: "2017-04-11" }, "7": { eol: "2020-01-14" },
    "8.1": { eol: "2023-01-10" }, "10": { eol: "2025-10-14" },
  },
  openssl: {
    "1.0.2": { eol: "2019-12-31" }, "1.1.0": { eol: "2019-09-11" }, "1.1.1": { eol: "2023-09-11" },
    "3.0": { eol: "2026-09-07" }, "3.1": { eol: "2025-03-14" }, "3.5": { eol: "2030-04-08" },
  },
  log4j: { "1": { eol: "2015-08-05" } },
  tomcat: {
    "7": { eol: "2021-03-31" }, "8.0": { eol: "2018-06-30" }, "8.5": { eol: "2024-03-31" }, "10.0": { eol: "2022-10-31" },
  },
  httpd: { "2.0": { eol: "2013-07-10" }, "2.2": { eol: "2017-12-31" } },
  php: {
    "5.6": { eol: "2018-12-31" }, "7.0": { eol: "2018-12-03" }, "7.1": { eol: "2019-12-01" },
    "7.2": { eol: "2020-11-30" }, "7.3": { eol: "2021-12-06" }, "7.4": { eol: "2022-11-28" },
    "8.0": { eol: "2023-11-26" }, "8.1": { eol: "2025-12-31", eos: "2024-11-25" }, "8.2": { eol: "2026-12-31", eos: "2025-12-31" },
  },
  django: {
    "2.2": { eol: "2022-04-11" }, "3.2": { eol: "2024-04-01" }, "4.1": { eol: "2023-12-01" },
    "4.2": { eol: "2026-04-30" }, "5.0": { eol: "2025-04-30" },
  },
  ruby: { "2.7": { eol: "2023-03-31" }, "3.0": { eol: "2024-04-23" }, "3.1": { eol: "2025-03-31" }, "3.2": { eol: "2026-03-31" } },
  mysql: { "5.7": { eol: "2023-10-31" }, "8.0": { eol: "2026-04-30" } },
  postgresql: {
    "9.6": { eol: "2021-11-11" }, "10": { eol: "2022-11-10" }, "11": { eol: "2023-11-09" }, "12": { eol: "2024-11-21" },
    "13": { eol: "2025-11-13" }, "14": { eol: "2026-11-12" }, "15": { eol: "2027-11-11" },
  },
  angularjs: { "*": { eol: "2021-12-31" } },
  angular: {
    "14": { eol: "2023-11-18" }, "15": { eol: "2024-05-18" }, "16": { eol: "2024-11-08" },
    "17": { eol: "2025-05-15" }, "18": { eol: "2025-11-21" }, "19": { eol: "2026-05-19" },
  },
  bootstrap: { "3": { eol: "2019-07-24" }, "4": { eol: "2023-01-01" } },
  moment: { "*": { eos: "2020-09-15" } }, // project declared "legacy / maintenance only"
  "spring-framework": {
    "5.2": { eol: "2021-12-31" }, "5.3": { eol: "2024-08-31" }, "6.0": { eol: "2024-08-31" },
    "6.1": { eol: "2025-06-30" }, "6.2": { eol: "2026-06-30" },
  },
  "spring-boot": { "2.7": { eol: "2023-11-24" }, "3.0": { eol: "2023-11-24" }, "3.1": { eol: "2024-06-30" } },
};

/** common spellings → curated key */
const ALIASES: Array<[RegExp, string]> = [
  [/^node(\.?js)?$/, "nodejs"],
  [/^(cpython|python3?)$/, "python"],
  [/^(microsoft\.?)?\.?net framework$|^dotnetfx$/, ".net framework"],
  [/^(microsoft\.?)?\.?net( core)?$|^dotnet(-core)?$/, ".net"],
  [/^microsoft\.entityframeworkcore/, "microsoft.entityframeworkcore"],
  [/^(apache )?log4j(-core|-api|-1\.2)?$/, "log4j"],
  [/^(apache )?tomcat(-embed-core)?$/, "tomcat"],
  [/^(apache http server|apache2?|httpd)$/, "httpd"],
  [/^postgres(ql)?$/, "postgresql"],
  [/^spring(-boot)(-starter.*)?$/, "spring-boot"],
  [/^spring(-framework|-core|-web|-webmvc|-context|-beans)?$/, "spring-framework"],
  [/^windows( (7|8\.1|10|xp|vista))?$/, "windows"],
  [/^angular\.?js$/, "angularjs"],
];

export const normalizeProduct = (name: string): string => {
  const n = name.toLowerCase().trim();
  for (const [re, key] of ALIASES) if (re.test(n)) return key;
  return n;
};

/* --------------------------------- dates ---------------------------------- */
const DAY = 86_400_000;

const utc = (y: number, m: number, d: number): Date | null => {
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d ? dt : null;
};
const lastDayOf = (y: number, m: number) => new Date(Date.UTC(y, m, 0)).getUTCDate();

/**
 * Tolerant date parser for vendor / spreadsheet dates.
 * Handles ISO, dd/mm/yyyy (day-first), "15 Jan 2025", "Jan 2025", "2025-06",
 * a bare year and Excel serial numbers. Returns null for anything else.
 */
export function parseLooseDate(input: unknown): Date | null {
  if (input == null || input === false) return null;
  if (input instanceof Date) return Number.isNaN(input.getTime()) ? null : input;
  const s = String(input).trim();
  if (!s || /^(n\/?a|none|null|unknown|tbd|tba|not (published|available)|[-—–]+)$/i.test(s)) return null;

  let m = s.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[T\s].*)?$/);
  if (m) return utc(+m[1], +m[2], +m[3]);

  m = s.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})$/);
  if (m) {
    let d = +m[1], mo = +m[2];
    const y = +m[3] < 100 ? 2000 + +m[3] : +m[3];
    if (mo > 12 && d <= 12) [d, mo] = [mo, d]; // unambiguous mm/dd/yyyy
    return utc(y, mo, d);
  }

  m = s.match(/^(\d{4})[-/](\d{1,2})$/);
  if (m) return utc(+m[1], +m[2], lastDayOf(+m[1], +m[2]));

  if (/^(19|20)\d{2}$/.test(s)) return utc(+s, 12, 31);

  if (/^\d{5}(\.\d+)?$/.test(s)) {
    const serial = Number(s);
    if (serial > 20000 && serial < 80000) return new Date(Date.UTC(1899, 11, 30) + Math.floor(serial) * DAY);
  }

  if (/[a-z]/i.test(s)) {
    const monthOnly = s.match(/^([a-z]{3,9})[\s,-]+(\d{4})$/i);
    const t = Date.parse(monthOnly ? `1 ${monthOnly[1]} ${monthOnly[2]}` : s);
    if (!Number.isFinite(t)) return null;
    const d = new Date(t);
    if (monthOnly) return utc(d.getFullYear(), d.getMonth() + 1, lastDayOf(d.getFullYear(), d.getMonth() + 1));
    return utc(d.getFullYear(), d.getMonth() + 1, d.getDate());
  }
  return null;
}

export const toDate = (s?: string) => parseLooseDate(s);
export const daysBetween = (a: Date, b: Date) => Math.round((b.getTime() - a.getTime()) / DAY);
export const fmtDate = (d: Date | null) => (d ? d.toISOString().slice(0, 10) : "");

/** positive = days until EOL, negative = days past EOL */
export function daysToEol(eol?: string, now = new Date()): number | null {
  const d = toDate(eol);
  return d ? daysBetween(now, d) : null;
}

export function lifecycleStage(days: number | null): "Past EOL" | "Security Only" | "Active" | "Unknown" {
  if (days === null) return "Unknown";
  if (days < 0) return "Past EOL";
  if (days <= 90) return "Security Only";
  return "Active";
}

/* --------------------------------- lookup --------------------------------- */
export function lookupLifecycle(name: string, version: string): Cycle | undefined {
  const table = CURATED[normalizeProduct(name || "")];
  if (!table) return undefined;
  const v = (version || "").trim().replace(/^[^0-9a-z]*/i, "").replace(/^v/i, "").toLowerCase();
  const keys = Object.keys(table).filter((k) => k !== "*").sort((a, b) => b.length - a.length);
  const hit = v ? keys.find((k) => v === k || v.startsWith(k + ".") || v.startsWith(k + "-")) : undefined;
  return hit ? table[hit] : table["*"];
}
export const lookupEolDate = (name: string, version: string) => lookupLifecycle(name, version)?.eol;
export const lookupEosDate = (name: string, version: string) => lookupLifecycle(name, version)?.eos;

/* ------------------------------- resolution ------------------------------- */
export type DateSource = "Uploaded file" | "endoflife.date" | "Curated vendor data";
export type ResolvedLifecycleDates = { eol?: string; eos?: string; eolSource?: DateSource; eosSource?: DateSource };

const EOL_KEY = /(^|[^a-z])(eol|end[\s_-]*of[\s_-]*life)([^a-z]|$)/i;
const EOS_KEY = /(^|[^a-z])(eos|eosl|end[\s_-]*of[\s_-]*(support|service)|support[\s_-]*end|out[\s_-]*of[\s_-]*support)([^a-z]|$)/i;

/** Pull a real date out of an uploaded row's EOL / EOS columns. */
function uploadedDates(row: Record<string, unknown>): { eol?: string; eos?: string } {
  const out: { eol?: string; eos?: string } = {};
  for (const [k, v] of Object.entries(row)) {
    const d = parseLooseDate(v);
    if (!d) continue;
    // a bare number is only a date when the column is clearly an EOL/EOS column
    if (EOS_KEY.test(k) && !out.eos) out.eos = fmtDate(d);
    else if (EOL_KEY.test(k) && !out.eol) out.eol = fmtDate(d);
  }
  return out;
}

export function resolveLifecycleDates(
  row: Record<string, unknown>,
  name: string,
  version: string,
  feed?: { eolDate?: string; supportEndDate?: string },
): ResolvedLifecycleDates {
  const up = uploadedDates(row);
  const cur = lookupLifecycle(name, version);
  const feedEol = feed?.eolDate ? fmtDate(toDate(feed.eolDate)) : "";
  const feedEos = feed?.supportEndDate ? fmtDate(toDate(feed.supportEndDate)) : "";
  const pick = (u?: string, f?: string, c?: string): [string | undefined, DateSource | undefined] =>
    u ? [u, "Uploaded file"] : f ? [f, "endoflife.date"] : c ? [c, "Curated vendor data"] : [undefined, undefined];
  const [eol, eolSource] = pick(up.eol, feedEol, cur?.eol);
  const [eos, eosSource] = pick(up.eos, feedEos, cur?.eos);
  return { eol, eos, eolSource, eosSource };
}
