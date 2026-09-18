/**
 * NIST-aligned date & risk intelligence.
 *
 * Pure functions that turn CVE / lifecycle / exploit dates into the fields the
 * dashboard, tables, timeline and exports show: CVSS severity bands, day counts
 * around EOL, NIST-weighted risk score, remediation priority with an SLA date,
 * and colour bands driven by dates.
 */

import {
  daysPastEol, daysToEol, lifecycleStageFromDates, lookupLifecycleDates,
  parseDate, toIsoDate, type LifecycleStage,
} from "@/lib/lifecycle-dates";

export type CvssSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
export type DateBand = "red" | "orange" | "yellow" | "green" | "gray";
export type Priority = "P0" | "P1" | "P2" | "P3";

export type NistFindingInput = {
  component: string;
  version: string;
  cve?: string;
  cvss?: number;
  cvssVector?: string;
  cvePublished?: string;
  exploitPublished?: string;
  lastUpdated?: string;
  eolDate?: string;
  eosDate?: string;
  kev?: boolean;
  exploit?: boolean;
  lifecycleStatus?: string;
};

export type NistFinding = {
  cveId: string;
  cvss: number;
  cvssSeverity: CvssSeverity;
  cvssVector: string;
  attackVector: string;
  cvePublished: string;
  cveAgeDays: number | null;
  exploitPublished: string;
  exploitAvailable: boolean;
  lastUpdated: string;
  eolDate: string;
  eosDate: string;
  eolSource: string;
  daysPastEol: number | null;
  daysToEol: number | null;
  lifecycleStage: LifecycleStage;
  /** NIST-weighted composite: CVSS 40% · EOL 30% · exploit 20% · lifecycle 10% */
  nistRisk: number;
  factors: { cvss: number; eol: number; exploit: number; lifecycle: number };
  priority: Priority;
  slaDays: number;
  remediateBy: string;
  cveBand: DateBand;
  eolBand: DateBand;
};

export function cvssSeverityOf(score: number): CvssSeverity {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
}

const AV_LABEL: Record<string, string> = { N: "Network", A: "Adjacent", L: "Local", P: "Physical" };

export function attackVectorOf(vector: string): string {
  const m = /AV:([NALP])/.exec(vector || "");
  return m ? AV_LABEL[m[1]] ?? "" : "";
}

function cveBandOf(ageDays: number | null, hasCve: boolean): DateBand {
  if (!hasCve || ageDays == null) return "gray";
  if (ageDays < 30) return "red";
  if (ageDays <= 180) return "yellow";
  return "green";
}

function eolBandOf(past: number | null, to: number | null): DateBand {
  if (past != null) return past > 365 ? "red" : "orange";
  if (to == null) return "gray";
  if (to < 30) return "orange";
  if (to <= 90) return "yellow";
  return "green";
}

export const BAND_CLASS: Record<DateBand, string> = {
  red: "bg-severity-critical/15 text-severity-critical border-severity-critical/40",
  orange: "bg-severity-high/15 text-severity-high border-severity-high/40",
  yellow: "bg-severity-medium/15 text-severity-medium border-severity-medium/40",
  green: "bg-severity-low/15 text-severity-low border-severity-low/40",
  gray: "bg-muted text-muted-foreground border-border",
};

const addDays = (from: Date, days: number) => new Date(from.getTime() + days * 86_400_000);

export function buildNistFinding(input: NistFindingInput, now = new Date()): NistFinding {
  const catalog = lookupLifecycleDates(input.component, input.version);
  const eolDate = toIsoDate(input.eolDate) || toIsoDate(catalog?.eol);
  const eosDate = toIsoDate(input.eosDate) || toIsoDate(catalog?.eos);
  const eolSource = toIsoDate(input.eolDate)
    ? "Uploaded / live intelligence"
    : catalog?.eol
      ? catalog.source
      : "";

  const cvss = Math.max(0, Math.min(10, Number(input.cvss) || 0));
  const cveId = (input.cve || "").toUpperCase().trim();
  const cvePublished = toIsoDate(input.cvePublished);
  const published = parseDate(cvePublished);
  const cveAgeDays = published ? Math.max(0, Math.round((now.getTime() - published.getTime()) / 86_400_000)) : null;

  const past = daysPastEol(eolDate, now);
  const to = daysToEol(eolDate, now);
  const stage = lifecycleStageFromDates(eolDate, eosDate, now);

  /* ------- NIST-weighted risk: CVSS 40 · EOL 30 · exploit 20 · lifecycle 10 ------- */
  const cvssFactor = (cvss / 10) * 40;
  const eolFactor =
    past != null ? (past > 365 ? 30 : past > 90 ? 25 : 20)
      : to != null ? (to < 30 ? 18 : to <= 90 ? 14 : to <= 365 ? 8 : 3)
        : 6;
  const exploitFactor = input.kev ? 20 : input.exploit ? 14 : cvss >= 9 ? 8 : 0;
  const lifecycleFactor =
    stage === "Past EOL" ? 10
      : stage === "Security Only" ? 8
        : stage === "Approaching EOL" ? 6
          : /legacy|deprecat|obsolete|unsupported/i.test(input.lifecycleStatus ?? "") ? 9
            : stage === "Active" ? 1 : 4;

  const nistRisk = Math.round(Math.min(100, cvssFactor + eolFactor + exploitFactor + lifecycleFactor));

  const priority: Priority =
    cvss >= 9 && (input.kev || input.exploit) ? "P0"
      : cvss >= 7 || (past != null && past > 365) ? "P1"
        : cvss >= 4 || past != null || (to != null && to < 90) ? "P2"
          : "P3";
  const slaDays = priority === "P0" ? 5 : priority === "P1" ? 30 : priority === "P2" ? 90 : 180;

  return {
    cveId,
    cvss,
    cvssSeverity: cvssSeverityOf(cvss),
    cvssVector: input.cvssVector ?? "",
    attackVector: attackVectorOf(input.cvssVector ?? ""),
    cvePublished,
    cveAgeDays,
    exploitPublished: toIsoDate(input.exploitPublished),
    exploitAvailable: Boolean(input.kev || input.exploit),
    lastUpdated: toIsoDate(input.lastUpdated),
    eolDate,
    eosDate,
    eolSource,
    daysPastEol: past,
    daysToEol: to,
    lifecycleStage: stage,
    nistRisk,
    factors: {
      cvss: Math.round(cvssFactor),
      eol: eolFactor,
      exploit: exploitFactor,
      lifecycle: lifecycleFactor,
    },
    priority,
    slaDays,
    remediateBy: addDays(now, slaDays).toISOString().slice(0, 10),
    cveBand: cveBandOf(cveAgeDays, Boolean(cveId)),
    eolBand: eolBandOf(past, to),
  };
}

/* ------------------------------- presentation ------------------------------- */

export function eolDayText(f: NistFinding): string {
  if (f.daysPastEol != null) return `${f.daysPastEol.toLocaleString()} days past EOL`;
  if (f.daysToEol != null) return `${f.daysToEol.toLocaleString()} days to EOL`;
  return "EOL date unknown";
}

export function cveAgeText(f: NistFinding): string {
  if (!f.cvePublished) return "No CVE date";
  if (f.cveAgeDays == null) return f.cvePublished;
  if (f.cveAgeDays === 0) return "Published today";
  return `${f.cveAgeDays.toLocaleString()} days ago`;
}

/* ------------------------------ aggregations ------------------------------ */

export type TimelinePoint = {
  month: string;
  cves: number;
  criticalCves: number;
  exploits: number;
  eolMilestones: number;
  zone: "past" | "soon" | "future";
};

const monthKey = (d: Date) => `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;

/** Monthly CVE / exploit / EOL activity from 12 months back to 12 months ahead. */
export function timelineSeries(findings: NistFinding[], now = new Date(), back = 12, forward = 12): TimelinePoint[] {
  const points = new Map<string, TimelinePoint>();
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - back, 1));
  for (let i = 0; i <= back + forward; i++) {
    const d = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth() + i, 1));
    const diff = (d.getUTCFullYear() - now.getUTCFullYear()) * 12 + (d.getUTCMonth() - now.getUTCMonth());
    points.set(monthKey(d), {
      month: monthKey(d),
      cves: 0,
      criticalCves: 0,
      exploits: 0,
      eolMilestones: 0,
      zone: diff < 0 ? "past" : diff <= 3 ? "soon" : "future",
    });
  }
  const bump = (raw: string, key: "cves" | "criticalCves" | "exploits" | "eolMilestones") => {
    const d = parseDate(raw);
    if (!d) return;
    const p = points.get(monthKey(d));
    if (p) p[key] += 1;
  };
  for (const f of findings) {
    if (f.cvePublished) {
      bump(f.cvePublished, "cves");
      if (f.cvssSeverity === "CRITICAL") bump(f.cvePublished, "criticalCves");
    }
    if (f.exploitPublished) bump(f.exploitPublished, "exploits");
    if (f.eolDate) bump(f.eolDate, "eolMilestones");
  }
  return [...points.values()];
}

export type DateKpis = {
  criticalCount: number;
  newestCve: { id: string; date: string; component: string } | null;
  oldestCve: { id: string; date: string; component: string } | null;
  daysSinceNewestCve: number | null;
  pastEolCount: number;
  avgDaysPastEol: number;
  approachingEolCount: number;
  latestExploit: { id: string; date: string; component: string } | null;
  avgCveAgeDays: number;
  avgDaysToEol: number;
  p0Count: number;
  p1Count: number;
};

export function dateKpis(rows: Array<{ component: string; finding: NistFinding }>): DateKpis {
  const withCve = rows.filter((r) => r.finding.cvePublished);
  const sortedByDate = [...withCve].sort((a, b) => a.finding.cvePublished.localeCompare(b.finding.cvePublished));
  const pastEol = rows.filter((r) => r.finding.daysPastEol != null);
  const approaching = rows.filter((r) => r.finding.daysToEol != null && r.finding.daysToEol <= 90);
  const exploited = rows
    .filter((r) => r.finding.exploitPublished)
    .sort((a, b) => b.finding.exploitPublished.localeCompare(a.finding.exploitPublished));
  const newest = sortedByDate.at(-1);
  const oldest = sortedByDate.at(0);
  const toEol = rows.map((r) => r.finding.daysToEol).filter((v): v is number => v != null);

  const label = (row?: { component: string; finding: NistFinding }, dateKey: "cvePublished" | "exploitPublished" = "cvePublished") =>
    row ? { id: row.finding.cveId || "—", date: row.finding[dateKey], component: row.component } : null;

  return {
    criticalCount: rows.filter((r) => r.finding.cvss >= 9).length,
    newestCve: label(newest),
    oldestCve: label(oldest),
    daysSinceNewestCve: newest?.finding.cveAgeDays ?? null,
    pastEolCount: pastEol.length,
    avgDaysPastEol: pastEol.length
      ? Math.round(pastEol.reduce((s, r) => s + (r.finding.daysPastEol ?? 0), 0) / pastEol.length)
      : 0,
    approachingEolCount: approaching.length,
    latestExploit: label(exploited[0], "exploitPublished"),
    avgCveAgeDays: withCve.length
      ? Math.round(withCve.reduce((s, r) => s + (r.finding.cveAgeDays ?? 0), 0) / withCve.length)
      : 0,
    avgDaysToEol: toEol.length ? Math.round(toEol.reduce((s, v) => s + v, 0) / toEol.length) : 0,
    p0Count: rows.filter((r) => r.finding.priority === "P0").length,
    p1Count: rows.filter((r) => r.finding.priority === "P1").length,
  };
}
