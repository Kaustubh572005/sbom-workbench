/**
 * Curated component lifecycle (EOL) dates. Keys are lowercase component names;
 * version keys match by prefix ("3.4" matches 3.4.1). "*" is the fallback.
 * Add new entries as vendors announce EOL dates.
 */
export const LIFECYCLE_DATES: Record<string, Record<string, string>> = {
  jquery: { "3.4.1": "2026-01-17", "3.4": "2026-01-17", "3.5": "2026-01-17", "3.6": "2027-12-31", "3.7": "2030-12-31", "2": "2016-06-09", "1": "2016-06-09" },
  angularjs: { "*": "2021-12-31" },
  "angular.js": { "*": "2021-12-31" },
  angular: { "1": "2021-12-31", "14": "2023-11-18", "15": "2024-05-18", "16": "2024-11-08", "17": "2025-05-15", "18": "2025-11-21" },
  bootstrap: { "3": "2019-07-24", "4": "2023-01-01", "4.5": "2022-04-30", "5": "2026-12-31" },
  entityframework: { "6": "2022-11-30", "*": "2022-11-30" },
  "microsoft.entityframeworkcore": { "6": "2024-11-12", "7": "2024-05-14", "8": "2026-11-10" },
  ".net framework": { "4.8": "2026-01-13", "4.6": "2022-04-26", "4.5": "2016-01-12" },
  dapper: { "2.0": "2024-12-31" },
  epplus: { "4": "2020-12-31", "5": "2024-12-31" },
  "log4j": { "1": "2015-08-05" },
  "newtonsoft.json": { "10": "2020-12-31", "11": "2022-12-31" },
  lodash: { "3": "2016-01-01" },
  moment: { "*": "2020-09-15" },
  "spring-framework": { "5.2": "2021-12-31", "5.3": "2024-08-31" },
};

const norm = (s: string) => s.toLowerCase().trim();

export function lookupEolDate(name: string, version: string): string | undefined {
  const table = LIFECYCLE_DATES[norm(name)];
  if (!table) return undefined;
  const keys = Object.keys(table).filter((k) => k !== "*").sort((a, b) => b.length - a.length);
  const v = version.trim().replace(/^v/i, "");
  const hit = keys.find((k) => v === k || v.startsWith(k + "."));
  return hit ? table[hit] : table["*"];
}

const DAY = 86_400_000;
export const toDate = (s?: string) => {
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? new Date(t) : null;
};
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
