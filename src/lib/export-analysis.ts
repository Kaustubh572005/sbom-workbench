/**
 * Non-destructive analysis export.
 *
 * Rule: every original uploaded column is preserved exactly (name + order).
 * Analysis fields are appended AFTER the original columns. Additional analysis
 * sections that do not map to the row model become separate sheets/files.
 */

import ExcelJS from "exceljs";
import type { ComponentProfile, PlatformAnalysis } from "@/lib/platform-intel";

export const ANALYSIS_COLUMNS = [
  "Estimated Severity",
  "Estimated Confidence",
  "Classification Reason",
  "Risk Score",
  "Risk Category",
  "Business Impact",
  "Exposure",
  "Lifecycle Status",
  "Support Status",
  "Remediation Status",
  "Recommended Action",
  "Target Version",
  "Latest Version",
  "EOL Date",
  "EOS Date",
  "Priority",
  "Confidence",
  "Evidence Source",
  "License Type",
  "License Risk",
  "Known Exploited",
  "Missing Metadata",
] as const;

export function analysisFields(p: ComponentProfile): Record<string, string | number> {
  return {
    "Estimated Severity": p.estimated ? `${p.severity} (estimated)` : p.severity,
    "Estimated Confidence": `${p.estimatedConfidence}%`,
    "Classification Reason": p.classificationReason,
    "Risk Score": p.riskScore,
    "Risk Category": p.riskCategory,
    "Business Impact": p.businessImpact,
    "Exposure": p.exposure,
    "Lifecycle Status": p.lifecycleStatus,
    "Support Status": p.supportStatus,
    "Remediation Status": p.remediationStatus,
    "Recommended Action": p.recommendedAction,
    "Target Version": p.targetVersion,
    "Latest Version": p.latestVersion,
    "EOL Date": p.eolDate,
    "EOS Date": p.eosDate,
    "Priority": p.priority,
    "Confidence": p.confidence,
    "Evidence Source": p.evidenceSource,
    "License Type": p.licenseType,
    "License Risk": p.licenseRisk,
    "Known Exploited": p.kev ? "Yes" : p.exploit ? "Exploit available" : "No",
    "Missing Metadata": p.missing.join(", "),
  };
}

export type Sheet = { name: string; columns: string[]; rows: (string | number)[][] };

function download(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const csvCell = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;

export function exportCsv(sheet: Sheet, filename: string) {
  const lines = [sheet.columns.map(csvCell).join(",")];
  for (const r of sheet.rows) lines.push(r.map(csvCell).join(","));
  download(new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" }), `${filename}.csv`);
}

export function exportJson(data: unknown, filename: string) {
  download(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }), `${filename}.json`);
}

export async function exportXlsx(sheets: Sheet[], filename: string) {
  const wb = new ExcelJS.Workbook();
  wb.creator = "SBOM Workbench";
  wb.created = new Date();
  sheets.forEach((s, i) => {
    const ws = wb.addWorksheet((s.name || `Sheet${i + 1}`).slice(0, 30).replace(/[[\]*?/\\:]/g, " "));
    ws.columns = s.columns.map((c) => ({ header: c, key: c, width: Math.min(46, Math.max(12, c.length + 4)) }));
    const head = ws.getRow(1);
    head.font = { bold: true, color: { argb: "FFFFFFFF" } };
    head.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF1E3A8A" } };
    ws.views = [{ state: "frozen", ySplit: 1 }];
    for (const r of s.rows) ws.addRow(r);
    if (s.columns.length) ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: s.columns.length } };
  });
  const buf = await wb.xlsx.writeBuffer();
  download(new Blob([buf], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }), `${filename}.xlsx`);
}

/** Original dataset rows + appended analysis columns (never overwrites originals). */
export function inventorySheet(
  name: string,
  originalColumns: string[],
  profiles: ComponentProfile[],
): Sheet {
  const extraKeys = new Set<string>();
  profiles.forEach((p) => Object.keys(p.record.raw).forEach((k) => { if (!originalColumns.includes(k)) extraKeys.add(k); }));
  const appended = ANALYSIS_COLUMNS.filter((c) => !originalColumns.includes(c));
  const columns = [...originalColumns, ...extraKeys, ...appended];
  const rows = profiles.map((p) => {
    const fields = analysisFields(p);
    return columns.map((c) => {
      if (c in p.record.raw) return String(p.record.raw[c] ?? "");
      if (c in fields) return fields[c];
      return "";
    });
  });
  return { name: name || "Inventory", columns, rows };
}

/** Extra analysis sheets that do not map onto the original row model. */
export function analysisSheets(a: PlatformAnalysis): Sheet[] {
  return [
    {
      name: "Summary",
      columns: ["Metric", "Value"],
      rows: [
        ["Components", a.profiles.length],
        ["Overall risk score", a.overallRisk],
        ["Risk category", a.riskCategory],
        ["SBOM health score", a.healthScore],
        ["Analysis confidence", `${a.confidence}%`],
        ["Critical", a.counts.critical],
        ["High", a.counts.high],
        ["Medium", a.counts.medium],
        ["Low", a.counts.low],
        ["Informational", a.counts.info],
        ["Applications", a.applications.length],
        ["Applications at risk", a.counts.appsAtRisk],
        ["Vendors", a.vendors.length],
        ["Vendors at risk", a.counts.vendorsAtRisk],
        ["Requiring upgrade", a.counts.upgrade],
        ["End of life", a.counts.eol],
        ["End of support", a.counts.eos],
        ["Deprecated / obsolete", a.counts.deprecated],
        ["Legacy", a.counts.legacy],
        ["Unsupported", a.counts.unsupported],
        ["License risks", a.counts.licenseRisk],
        ["Missing metadata", a.counts.missingMetadata],
        ["Known exploited", a.counts.kev],
        ["Version sprawl", a.counts.multiVersion],
      ],
    },
    {
      name: "Findings",
      columns: ["Finding", "Severity", "Count", "Summary"],
      rows: a.findings.map((f) => [f.title, f.severity, f.count, f.summary]),
    },
    {
      name: "Lifecycle",
      columns: ["Component", "Current Version", "Latest Stable", "Lifecycle Status", "Support Status", "Remediation Status", "Recommended Action", "Target Version", "Priority", "Confidence", "Evidence Source"],
      rows: a.profiles.map((p) => [p.name, p.version, p.latestVersion, p.lifecycleStatus, p.supportStatus, p.remediationStatus, p.recommendedAction, p.targetVersion, p.priority, p.confidence, p.evidenceSource]),
    },
    {
      name: "Licenses",
      columns: ["License", "Type", "Components", "Risk", "Note"],
      rows: a.licenses.entries.map((e) => [e.name, e.type, e.count, e.risk, e.note]),
    },
    {
      name: "Applications at risk",
      columns: ["Application", "Findings", "Critical", "High", "Medium", "Low", "Risk score"],
      rows: a.intel.appsAtRisk.map((g) => [g.name, g.total, g.critical, g.high, g.medium, g.low, g.riskScore]),
    },
    {
      name: "Vendors at risk",
      columns: ["Vendor", "Findings", "Critical", "High", "Medium", "Low", "Risk score"],
      rows: a.intel.vendorsAtRisk.map((g) => [g.name, g.total, g.critical, g.high, g.medium, g.low, g.riskScore]),
    },
    {
      name: "Dependencies",
      columns: ["Component", "Version", "Depth", "Type", "Children", "Parents", "Severity"],
      rows: a.deps.nodes.map((n) => [n.name, n.version, n.depth, n.direct ? "Direct" : "Transitive", n.children.length, n.parents.length, n.severity]),
    },
    {
      name: "Version sprawl",
      columns: ["Component", "Versions", "Count"],
      rows: a.duplicates.map((d) => [d.name, d.versions.join(", "), d.count]),
    },
    {
      name: "Compliance",
      columns: ["Framework", "Control", "Requirement", "Status", "Affected", "Detail"],
      rows: a.intel.compliance.map((c) => [c.framework, c.control, c.requirement, c.status, c.affected, c.detail]),
    },
  ].filter((s) => s.rows.length > 0);
}

export async function exportFullAnalysis(
  datasetName: string,
  originalColumns: string[],
  analysis: PlatformAnalysis,
) {
  await exportXlsx([inventorySheet(datasetName, originalColumns, analysis.profiles), ...analysisSheets(analysis)], `${datasetName}-analysis`);
}
