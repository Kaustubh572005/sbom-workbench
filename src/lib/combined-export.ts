/**
 * Combined export — findings of every uploaded file in ONE download.
 * Every row carries the identified Application and the original Source File,
 * so findings from different files can never be confused.
 */
import type { ComponentProfile, PlatformAnalysis } from "@/lib/platform-intel";
import { exportCsv, exportJson, exportXlsx, inventorySheet, type Sheet } from "@/lib/export-analysis";
import { daysToEol } from "@/lib/lifecycle-dates";

export type CombinedSource = {
  /** identified application name (dataset name) */
  application: string;
  /** original uploaded filename */
  sourceFile: string;
  columns: string[];
  analysis: PlatformAnalysis;
  nameConfidence?: string;
};

export const NOT_PUBLISHED = "Not published";

export const eolStage = (days: number | null): string =>
  days === null ? "No date published" : days < 0 ? "Past EOL" : days <= 90 ? "Within 90 days" : days <= 365 ? "Within 1 year" : "Supported";

const eolOf = (p: ComponentProfile) => daysToEol(p.eolDate);
const eosOf = (p: ComponentProfile) => daysToEol(p.eosDate);
const dateSource = (p: ComponentProfile) =>
  [p.eolDate && `EOL: ${p.record.intel.eolSource ?? "—"}`, p.eosDate && `EOS: ${p.record.intel.eosSource ?? "—"}`].filter(Boolean).join(" · ") || "—";

const FINDING_COLUMNS = [
  "Application", "Source File", "Component", "Version", "Supplier", "License", "License Risk", "CVE", "CVSS", "Severity",
  "Risk Score", "Risk Category", "Priority", "Lifecycle Status", "Support Status", "EOL Date", "EOS Date", "Days To EOL",
  "EOL/EOS Source", "Remediation Status", "Recommended Action", "Target Version", "Latest Version", "Known Exploited",
  "Exposure", "Evidence Source",
];

export function findingsSheet(sources: CombinedSource[]): Sheet {
  const rows: Array<{ risk: number; cells: (string | number)[] }> = [];
  for (const s of sources) {
    for (const p of s.analysis.profiles) {
      const d = eolOf(p);
      rows.push({
        risk: p.riskScore,
        cells: [
          s.application, s.sourceFile, p.name || "—", p.version || "—", p.supplier || "—", p.license || "—", p.licenseRisk,
          p.cve || "—", p.cvss || "", p.severity, p.riskScore, p.riskCategory, p.priority, p.lifecycleStatus, p.supportStatus,
          p.eolDate || NOT_PUBLISHED, p.eosDate || NOT_PUBLISHED, d === null ? "" : d, dateSource(p),
          p.remediationStatus, p.recommendedAction, p.targetVersion || "—", p.latestVersion || "—",
          p.kev ? "Yes (CISA KEV)" : p.exploit ? "Exploit available" : "No", p.exposure, p.evidenceSource,
        ],
      });
    }
  }
  rows.sort((a, b) => b.risk - a.risk);
  return { name: "All Findings", columns: FINDING_COLUMNS, rows: rows.map((r) => r.cells) };
}

export function lifecycleCalendarSheet(sources: CombinedSource[]): Sheet {
  const rows: Array<{ sort: string; cells: (string | number)[] }> = [];
  for (const s of sources) {
    for (const p of s.analysis.profiles) {
      if (!p.eolDate && !p.eosDate) continue;
      const de = eolOf(p);
      const ds = eosOf(p);
      rows.push({
        sort: p.eolDate || p.eosDate,
        cells: [
          s.application, s.sourceFile, p.name || "—", p.version || "—", p.eolDate || NOT_PUBLISHED, de === null ? "" : de,
          p.eosDate || NOT_PUBLISHED, ds === null ? "" : ds, eolStage(de), dateSource(p), p.recommendedAction,
        ],
      });
    }
  }
  rows.sort((a, b) => a.sort.localeCompare(b.sort));
  return {
    name: "EOL & EOS Dates",
    columns: ["Application", "Source File", "Component", "Version", "EOL Date", "Days To EOL", "EOS Date", "Days To EOS", "EOL Stage", "Date Source", "Recommended Action"],
    rows: rows.map((r) => r.cells),
  };
}

export function overviewSheet(sources: CombinedSource[]): Sheet {
  const total = { comps: 0, c: 0, h: 0, m: 0, l: 0, past: 0, soon: 0, none: 0, kev: 0 };
  const rows = sources.map((s) => {
    const ps = s.analysis.profiles;
    const past = s.analysis.counts.eol + s.analysis.counts.eos; // identical to the dashboard
    const soon = ps.filter((p) => { const d = eolOf(p); return d !== null && d >= 0 && d <= 90; }).length;
    const none = ps.filter((p) => !p.eolDate && !p.eosDate).length;
    const kev = ps.filter((p) => p.kev).length;
    const { critical, high, medium, low } = s.analysis.counts;
    total.comps += ps.length; total.c += critical; total.h += high; total.m += medium; total.l += low;
    total.past += past; total.soon += soon; total.none += none; total.kev += kev;
    return [s.application, s.sourceFile, s.nameConfidence ?? "—", ps.length, critical, high, medium, low, s.analysis.overallRisk,
      s.analysis.riskCategory, past, soon, none, kev] as (string | number)[];
  });
  rows.push(["ALL FILES", `${sources.length} file(s)`, "", total.comps, total.c, total.h, total.m, total.l, "", "", total.past, total.soon, total.none, total.kev]);
  return {
    name: "Overview",
    columns: ["Application", "Source File", "Name Confidence", "Components", "Critical", "High", "Medium", "Low", "Risk Score", "Risk Category", "Past EOL / EOS", "EOL Within 90 Days", "No EOL/EOS Date", "Known Exploited"],
    rows,
  };
}

function uniqueSheetNames(sources: CombinedSource[]): string[] {
  const used = new Set(["overview", "all findings", "eol & eos dates"]);
  return sources.map((s) => {
    const base = s.application.replace(/[[\]*?/\\:]/g, " ").trim().slice(0, 27) || "Sheet";
    let name = base;
    for (let i = 2; used.has(name.toLowerCase()); i++) name = `${base.slice(0, 25)} ${i}`;
    used.add(name.toLowerCase());
    return name;
  });
}

export async function exportCombinedFindings(sources: CombinedSource[], fmt: "xlsx" | "csv" | "json") {
  const stamp = new Date().toISOString().slice(0, 10);
  const base = `SBOM-combined-findings-${stamp}`;
  const findings = findingsSheet(sources);
  if (fmt === "csv") return exportCsv(findings, base);
  if (fmt === "json") {
    return exportJson({
      generatedAt: new Date().toISOString(),
      files: sources.map((s) => ({ application: s.application, sourceFile: s.sourceFile, components: s.analysis.profiles.length, risk: s.analysis.overallRisk })),
      findings: findings.rows.map((r) => Object.fromEntries(findings.columns.map((c, i) => [c, r[i]]))),
    }, base);
  }
  const names = uniqueSheetNames(sources);
  await exportXlsx([
    overviewSheet(sources),
    findings,
    lifecycleCalendarSheet(sources),
    ...sources.map((s, i) => ({ ...inventorySheet(names[i], s.columns, s.analysis.profiles), name: names[i] })),
  ].filter((s) => s.rows.length > 0), base);
}
