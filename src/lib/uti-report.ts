/**
 * UTI AMC SBOM report generation.
 * Builds the standard "Software Bill of Material (SBoM)" record for every
 * component plus the ten enterprise report sections, and exports the result as
 * PDF, DOCX, Excel, CSV or JSON. Runs automatically after every upload.
 */
import type { ComponentProfile, PlatformAnalysis } from "@/lib/platform-intel";
import { exportCsv, exportJson, exportXlsx, type Sheet } from "@/lib/export-analysis";

export type UtiField = { field: string; description: string; value: string };
export type UtiSection = { title: string; columns: string[]; rows: (string | number)[][]; narrative?: string[] };
export type RawLayer = { columns: string[]; rows: (string | number)[][] };
export type UtiReport = {
  dataset: string;
  generatedAt: string;
  classification: string;
  records: { component: string; fields: UtiField[] }[];
  sections: UtiSection[];
  /** Untouched imported data, preserved for the "Raw Imported Data" sheet. */
  raw?: RawLayer;
  vulnRows?: (string | number)[][];
  riskRows?: (string | number)[][];
};


const CLASSIFICATION = "Information Classification: UTI AMC - Internal";
const dash = (v: unknown) => {
  const s = String(v ?? "").trim();
  return s ? s : "—";
};
const today = () => new Date().toISOString().slice(0, 10);
const plusMonths = (n: number) => {
  const d = new Date();
  d.setMonth(d.getMonth() + n);
  return d.toISOString().slice(0, 10);
};

/* ------------------------- per-component UTI record ------------------------- */
/**
 * Fallback text used when a field cannot be sourced from the SBOM or the
 * analysis engine, so that exported reports never contain blank cells.
 */
const FALLBACK: Record<string, string> = {
  "Version": "Not declared in SBOM — vendor confirmation required",
  "Description": "Not declared in SBOM — functional description to be supplied by vendor",
  "Supplier": "Not declared in SBOM — provenance to be confirmed with vendor",
  "Release Date": "Not published by vendor",
  "End of Life Date/End of Support": "Not published by vendor — lifecycle validation required",
  "Checksums": "Not provided in SBOM — integrity value to be supplied by vendor",
  "Hashes": "Not provided in SBOM — cryptographic hash to be supplied by vendor",
  "Dependencies": "No dependencies declared in SBOM",
  "PURL (Package URL)": "Not provided in SBOM — to be generated from package coordinates",
  "CPE Identifier (Common Platform Enumeration)": "Not provided in SBOM — NVD mapping pending",
  "CVE ID": "No CVE recorded against this component",
  "Recommended Version": "No newer release identified by the analysis engine",
  "Recommended Action": "No action required at this assessment",
  "Reviewed By (To be filled by UTI)": "Pending UTI AMC review",
};
const filled = (fields: UtiField[]): UtiField[] =>
  fields.map((f) => {
    const v = String(f.value ?? "").trim();
    const empty = !v || v === "—" || v === "-" || /^(n\/?a|unknown|null|undefined)$/i.test(v);
    return empty ? { ...f, value: FALLBACK[f.field] ?? "Not provided in SBOM — vendor confirmation required" } : { ...f, value: v };
  });

export function utiRecord(p: ComponentProfile): UtiField[] {
  return filled(utiRecordRaw(p));
}

function utiRecordRaw(p: ComponentProfile): UtiField[] {
  const rec = p.record;
  const executable = /lib|dll|exe|runtime|jre|jdk|dotnet|\.net|node|python|binary/i.test(`${p.name} ${p.packageName}`)
    ? "Yes" : "Unknown";
  const vulnText = p.cve
    ? `${p.cve} — ${p.severity === "none" ? "Unrated" : p.severity.toUpperCase()}${p.cvss ? ` (CVSS ${p.cvss})` : ""}`
    : p.severity === "none" ? "No vulnerability reported" : `Derived severity: ${p.severity.toUpperCase()}`;
  const free = p.cve || p.kev || p.exploit || p.severity === "critical" || p.severity === "high"
    ? "No — known vulnerabilities present, see Vulnerability Assessment"
    : "No known vulnerabilities, malware, malicious code or covert channels identified";
  const deprecated = /Deprecated|Obsolete|End of Life|End of Support|Legacy/i.test(p.lifecycleStatus)
    ? `Yes — ${p.lifecycleStatus}` : "No";

  return [
    { field: "Component Name & origin", description: "Name of the software component or library", value: `${dash(p.name)} (origin: ${String(p.supplier ?? "").trim() || "Unknown"})` },
    { field: "Version", description: "Version number or identifier of the component", value: dash(p.version) },
    { field: "Description", description: "Brief description of the functionality and purpose of the component", value: dash(String(rec.raw["Description"] ?? rec.raw["description"] ?? "").trim() || `${p.name}${p.version ? ` ${p.version}` : ""} — ${p.licenseType === "Proprietary" ? "commercial" : "open-source"} component in the analysed inventory; business impact assessed as ${p.businessImpact}. Functional description not declared in SBOM.`) },

    { field: "Supplier", description: "Entity or organisation that supplied the component", value: dash(p.supplier) },
    { field: "License Type", description: "License under which the component is distributed", value: `${dash(p.license)} · ${p.licenseType}` },
    { field: "Usage Restriction", description: "Limitations or restrictions on the use of the component", value: p.licenseType === "Strong Copyleft" ? "Source disclosure obligations on distribution" : p.licenseType === "Proprietary" ? "Commercial license terms apply" : p.licenseType === "Unknown" ? "Not declared — legal review required" : "No material restriction identified" },
    { field: "Release Date", description: "Date when this version was released", value: dash(rec.published) },
    { field: "End of Life Date/End of Support", description: "Date after which the component is no longer supported", value: dash([p.eolDate && `EOL ${p.eolDate}`, p.eosDate && `EOS ${p.eosDate}`].filter(Boolean).join(" · ") || p.lifecycleStatus) },
    { field: "Update Frequency", description: "How often the component is updated by the vendor", value: p.latestVersion && p.latestVersion !== p.version ? "Actively maintained — newer release available" : p.supportStatus === "Unsupported" ? "No longer updated by vendor" : "Vendor cadence not published" },
    { field: "Executable Property", description: "Whether the component contains directly executable code", value: executable },
    { field: "Executable Property Description", description: "Describes the executable property of the component", value: executable === "Yes" ? "Component ships compiled libraries, executables or runtime code that execute in the application process." : "No executable payload identified in the SBOM evidence — vendor confirmation required." },

    { field: "Dependencies", description: "Other components or libraries required by this software", value: dash(p.dependsOn.join(", ")) },
    { field: "Dependency Relation with Component", description: "Relationship to the component", value: p.dependencyOf.length ? `Transitive — used by ${p.dependencyOf.join(", ")}` : "Direct dependency" },
    { field: "Encryption Name", description: "Encryption used to secure data in transit or at rest", value: /openssl|boringssl|libsodium|bouncy|crypto|tls|ssl/i.test(p.name) ? "Component provides cryptographic functionality" : "Not applicable / not declared" },
    { field: "Checksums", description: "Integrity verification value", value: dash(p.hash) },
    { field: "Hashes", description: "Cryptographic hash values ensuring authenticity", value: dash(p.hash) },
    { field: "Known Unknown", description: "Dependencies known to exist but not fully described", value: p.missing.length ? `Incomplete metadata: ${p.missing.join(", ")}` : "None" },
    { field: "Access Control", description: "Vendor access model", value: "Vendor access facilitated through Zero Trust Network Access with Privilege Access Management" },
    { field: "Methods for accommodating occasional incident", description: "Incident handling process", value: "Vendor adheres to the UTI AMC Incident Management Process" },
    { field: "Known Security Vulnerability & Criticality", description: "Vulnerability identified and its criticality", value: vulnText },
    { field: "Software/application is free of known vulnerabilities, malwares, malicious/fraudulent code and any covert channels", description: "Malicious code assurance", value: free },
    { field: "Patch status", description: "Whether required patches are applied", value: dash(p.remediationStatus) },
    { field: "Archive Property", description: "Whether archive properties are maintained", value: "Maintained in the SBOM repository with version history" },
    { field: "Deprecated Libraries", description: "Libraries no longer recommended for use", value: deprecated },
    { field: "PURL (Package URL)", description: "Standardised unique identifier string", value: dash(p.purl) },
    { field: "CPE Identifier (Common Platform Enumeration)", description: "NIST standard identifier mapping to the NVD", value: dash(p.cpe) },
    { field: "CVE ID", description: "Specific Common Vulnerabilities and Exposures identifier", value: dash(p.cve) },
    { field: "Recommended Version", description: "Version recommended by the analysis engine", value: dash(p.targetVersion || p.latestVersion) },
    { field: "Recommended Action", description: "Remediation action recommended by the analysis engine", value: dash(p.recommendedAction) },
    { field: "Evidence Source", description: "Authoritative source supporting the assessment", value: `${dash(p.evidenceSource)} (confidence: ${dash(p.confidence)})` },
    { field: "Last Modified Date", description: "When this SBOM record was last modified", value: today() },
    { field: "Last Reviewed Date (To be filled by UTI)", description: "When this SBOM record was last reviewed", value: today() },
    { field: "Next Review Date (To be filled by UTI)", description: "Next review date for the SBOM", value: plusMonths(6) },
    { field: "Prepared By (To be filled by Vendor)", description: "Name of the person who created the record", value: "SBOM Workbench — automated analysis" },
    { field: "Reviewed By (To be filled by UTI)", description: "Name of the person who reviewed and approved the details", value: "—" },
  ];
}

/* ------------------------------ report sections ------------------------------ */
function severitySpread(a: PlatformAnalysis) {
  return `${a.counts.critical}C / ${a.counts.high}H / ${a.counts.medium}M / ${a.counts.low}L`;
}

export function buildUtiReport(dataset: string, a: PlatformAnalysis, raw?: RawLayer): UtiReport {
  const p = a.profiles;
  const top = [...p].sort((x, y) => y.riskScore - x.riskScore);

  const sections: UtiSection[] = [
    {
      title: "1. Executive Summary",
      columns: ["Metric", "Value"],
      rows: [
        ["Dataset", dataset],
        ["Components assessed", p.length],
        ["Overall risk score", `${a.overallRisk}/100 (${a.riskCategory})`],
        ["SBOM health score", `${a.healthScore}/100`],
        ["Analysis confidence", `${a.confidence}%`],
        ["Severity spread", severitySpread(a)],
        ["Applications", a.applications.length],
        ["Suppliers", a.vendors.length],
        ["Known exploited (KEV)", a.counts.kev],
        ["End of life / support", a.counts.eol + a.counts.eos],
        ["Upgrade required", a.counts.upgrade],
        ["License risks", a.counts.licenseRisk],
      ],
      narrative: [
        `${p.length} component(s) were normalised and analysed automatically. The estate carries an overall risk score of ${a.overallRisk}/100 (${a.riskCategory}) with an SBOM health score of ${a.healthScore}/100.`,
        `${a.counts.critical} critical and ${a.counts.high} high severity component(s) require prioritised action; ${a.counts.eol + a.counts.eos} component(s) are beyond vendor life or support.`,
      ],
    },
    {
      title: "2. Technical Assessment",
      columns: ["Component", "Version", "Supplier", "PURL", "CPE", "Checksum", "Executable"],
      rows: p.map((x) => [dash(x.name), dash(x.version), dash(x.supplier), dash(x.purl), dash(x.cpe), dash(x.hash), x.hash ? "Verified" : "Unknown"]),
    },
    {
      title: "3. Vulnerability Assessment",
      columns: ["Component", "Version", "CVE ID", "CVSS", "Severity", "Exploit status", "Patch status", "Recommended version"],
      rows: p.map((x) => [dash(x.name), dash(x.version), dash(x.cve), x.cvss || "—", x.severity.toUpperCase(), x.kev ? "KEV — actively exploited" : x.exploit ? "Public exploit" : "None known", dash(x.remediationStatus), dash(x.targetVersion || x.latestVersion)]),
    },
    {
      title: "4. Lifecycle Analysis",
      columns: ["Component", "Version", "Lifecycle status", "Support status", "EOL", "EOS", "Recommended action", "Confidence"],
      rows: p.map((x) => [dash(x.name), dash(x.version), dash(x.lifecycleStatus), dash(x.supportStatus), dash(x.eolDate), dash(x.eosDate), dash(x.recommendedAction), dash(x.confidence)]),
    },
    {
      title: "5. License Analysis",
      columns: ["Component", "License", "Type", "Risk", "Usage restriction"],
      rows: p.map((x) => [dash(x.name), dash(x.license), x.licenseType, x.licenseRisk.toUpperCase(), x.licenseType === "Strong Copyleft" ? "Source disclosure obligations" : x.licenseType === "Unknown" ? "Legal review required" : "None material"]),
    },
    {
      title: "6. Compliance Analysis",
      columns: ["Control", "Status", "Detail"],
      rows: a.intel.compliance.length
        ? a.intel.compliance.map((c) => [c.control, c.status, c.detail])
        : [["SBOM completeness", a.healthScore >= 80 ? "Pass" : "At risk", `Health score ${a.healthScore}/100`]],
    },
    {
      title: "7. Dependency Analysis",
      columns: ["Component", "Version", "Relation", "Depth", "Depends on", "Used by"],
      rows: a.deps.nodes.map((n) => [dash(n.name), dash(n.version), n.direct ? "Direct" : "Transitive", n.depth, n.children.length, n.parents.length]),
    },
    {
      title: "8. Risk Prioritization",
      columns: ["Rank", "Component", "Version", "Risk score", "Category", "Severity", "Exposure", "Priority"],
      rows: top.map((x, i) => [i + 1, dash(x.name), dash(x.version), x.riskScore, x.riskCategory, x.severity.toUpperCase(), x.exposure, dash(x.priority)]),
    },
    {
      title: "9. Remediation Roadmap",
      columns: ["Priority", "Component", "Current version", "Recommended version", "Action", "Owner", "Target"],
      rows: top
        .filter((x) => /Upgrade|Update|Migration|Replace|Unsupported/i.test(`${x.remediationStatus} ${x.recommendedAction}`))
        .map((x) => [
          x.riskScore >= 80 ? "P0 — 7 days" : x.riskScore >= 60 ? "P1 — 30 days" : x.riskScore >= 35 ? "P2 — 90 days" : "P3 — next cycle",
          dash(x.name), dash(x.version), dash(x.targetVersion || x.latestVersion), dash(x.recommendedAction), dash(x.supplier), x.riskScore >= 80 ? plusMonths(0) : plusMonths(x.riskScore >= 60 ? 1 : 3),
        ]),
    },
  ];

  return {
    dataset,
    generatedAt: new Date().toISOString(),
    classification: CLASSIFICATION,
    records: p.map((x) => ({ component: `${x.name}${x.version ? ` ${x.version}` : ""}`, fields: utiRecord(x) })),
    sections,
    raw,
    vulnRows: p.map((x) => [
      dash(x.name), dash(x.version), dash(x.cve), x.cvss || "—", x.severity.toUpperCase(),
      x.estimated ? "Derived (analysis)" : "Declared (SBOM)",
      x.kev ? "KEV — actively exploited" : x.exploit ? "Public exploit" : "None known",
      dash(x.remediationStatus), dash(x.targetVersion || x.latestVersion), dash(x.evidenceSource), dash(x.confidence),
    ]),
    riskRows: top.map((x, i) => [
      i + 1, dash(x.name), dash(x.version), x.riskScore, x.riskCategory, x.severity.toUpperCase(),
      x.exposure, dash(x.lifecycleStatus), dash(x.supportStatus), dash(x.priority), dash(x.recommendedAction),
    ]),
  };
}

/* --------------------------------- Eway layout --------------------------------- */
/**
 * SBOM-EwayDMS layout: data fields down the rows, components across the
 * columns ("Primary Component", "Component 1", "Component 2", …).
 */
export function ewayColumns(r: UtiReport): string[] {
  return ["Data Field", "Description", ...r.records.map((_, i) => (i === 0 ? "Primary Component" : `Component ${i}`))];
}

export function ewayComponentNames(r: UtiReport): string[] {
  return r.records.map((rec) => rec.component);
}

export function ewayRows(r: UtiReport): string[][] {
  const fields = r.records[0]?.fields ?? [];
  return fields.map((f, i) => [
    f.field,
    f.description,
    ...r.records.map((rec) => rec.fields[i]?.value ?? "Not provided in SBOM — vendor confirmation required"),
  ]);
}

export function ewayMatrixSheet(r: UtiReport): Sheet {
  return { name: "SBOM-EwayDMS", columns: ewayColumns(r), rows: ewayRows(r) };
}

const VULN_COLUMNS = ["Component", "Version", "CVE ID", "CVSS", "Severity", "Severity basis", "Exploit status", "Patch status", "Recommended version", "Evidence source", "Confidence"];
const RISK_COLUMNS = ["Rank", "Component", "Version", "Risk score", "Risk category", "Severity", "Exposure", "Lifecycle status", "Support status", "Priority", "Recommended action"];

/** Only sheets that add information the Eway register cannot carry. */
export function reportSheets(r: UtiReport): Sheet[] {
  const sheets: Sheet[] = [ewayMatrixSheet(r)];
  if (r.vulnRows?.length) sheets.push({ name: "Vulnerability Details", columns: VULN_COLUMNS, rows: r.vulnRows });
  if (r.riskRows?.length) sheets.push({ name: "Risk Analysis", columns: RISK_COLUMNS, rows: r.riskRows });
  if (r.raw?.rows.length) sheets.push({ name: "Raw Imported Data", columns: r.raw.columns, rows: r.raw.rows });
  return sheets;
}

/* ------------------------------- validation ------------------------------- */
export function validateEwayReport(r: UtiReport): { ok: boolean; issues: string[]; components: number; fields: number } {
  const issues: string[] = [];
  const cols = ewayColumns(r);
  const rows = ewayRows(r);
  if (!r.records.length) issues.push("No components were normalised from the uploaded SBOM.");
  if (cols.length - 2 !== r.records.length) issues.push("Component column count does not match the normalised component count.");
  const expected = r.records[0]?.fields.length ?? 0;
  for (const rec of r.records) if (rec.fields.length !== expected) issues.push(`${rec.component}: field set is incomplete.`);
  for (const row of rows) {
    if (row.length !== cols.length) issues.push(`Field "${row[0]}" has a clipped column.`);
    if (row.slice(2).some((v) => !String(v).trim())) issues.push(`Field "${row[0]}" contains an empty component cell.`);
  }
  const seen = new Map<string, number>();
  for (const rec of r.records) seen.set(rec.component, (seen.get(rec.component) ?? 0) + 1);
  for (const [k, v] of seen) if (v > 1) issues.push(`Duplicate component column: ${k} (${v}×).`);
  return { ok: issues.length === 0, issues: issues.slice(0, 25), components: r.records.length, fields: expected };
}

/* --------------------------------- file names --------------------------------- */
export function reportFileName(r: UtiReport): string {
  const slug = (r.dataset || "SBOM").replace(/\.[a-z0-9]+$/i, "").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "") || "SBOM";
  return `${slug}_SBOM-EwayDMS_${new Date(r.generatedAt).toISOString().slice(0, 10)}`;
}

/* --------------------------------- exports --------------------------------- */
const NAVY = "FF0F2A5C";
const BAND = "FF1E3A8A";

export async function exportUtiXlsx(r: UtiReport) {
  const ExcelJS = (await import("exceljs")).default;
  const wb = new ExcelJS.Workbook();
  wb.creator = "SBOM Workbench";
  wb.created = new Date();

  /* primary Eway register */
  const cols = ewayColumns(r);
  const names = ewayComponentNames(r);
  const ws = wb.addWorksheet("SBOM-EwayDMS", { views: [{ state: "frozen", xSplit: 2, ySplit: 3 }], pageSetup: { orientation: "landscape", fitToPage: true, fitToWidth: 1, fitToHeight: 0 } });
  ws.columns = cols.map((_, i) => ({ width: i === 0 ? 34 : i === 1 ? 52 : 40 }));

  const title = ws.addRow(["Software Bill of Material (SBoM) — SBOM-EwayDMS Register"]);
  ws.mergeCells(1, 1, 1, Math.max(cols.length, 3));
  title.font = { bold: true, size: 14, color: { argb: "FFFFFFFF" } };
  title.fill = { type: "pattern", pattern: "solid", fgColor: { argb: NAVY } };
  title.height = 26;
  title.alignment = { vertical: "middle", horizontal: "left" };

  const meta = ws.addRow([`${r.dataset} · generated ${new Date(r.generatedAt).toLocaleString()} · ${r.records.length} component(s) · ${r.classification}`]);
  ws.mergeCells(2, 1, 2, Math.max(cols.length, 3));
  meta.font = { size: 9, color: { argb: "FF555555" } };

  const head = ws.addRow(cols.map((c, i) => (i < 2 ? c : `${c}\n${names[i - 2]}`)));
  head.height = 32;
  head.eachCell((cell) => {
    cell.font = { bold: true, color: { argb: "FFFFFFFF" }, size: 10 };
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: BAND } };
    cell.alignment = { wrapText: true, vertical: "middle" };
    cell.border = { top: { style: "thin", color: { argb: "FFCCCCCC" } }, bottom: { style: "thin", color: { argb: "FFCCCCCC" } }, left: { style: "thin", color: { argb: "FFCCCCCC" } }, right: { style: "thin", color: { argb: "FFCCCCCC" } } };
  });

  ewayRows(r).forEach((row, ri) => {
    const wsRow = ws.addRow(row);
    wsRow.eachCell((cell, ci) => {
      cell.alignment = { wrapText: true, vertical: "top" };
      cell.font = { size: 9, bold: ci === 1 };
      cell.border = { top: { style: "hair", color: { argb: "FFDDDDDD" } }, bottom: { style: "hair", color: { argb: "FFDDDDDD" } }, left: { style: "hair", color: { argb: "FFDDDDDD" } }, right: { style: "hair", color: { argb: "FFDDDDDD" } } };
      if (ci > 2 && ri % 2 === 1) cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFF4F7FC" } };
      if (ci === 1) cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFEAF0FA" } };
    });
  });

  /* supporting sheets only */
  for (const s of reportSheets(r).slice(1)) {
    const sh = wb.addWorksheet(s.name.slice(0, 30), { views: [{ state: "frozen", ySplit: 1 }] });
    sh.columns = s.columns.map((c) => ({ header: c, key: c, width: Math.min(46, Math.max(12, c.length + 6)) }));
    const h = sh.getRow(1);
    h.font = { bold: true, color: { argb: "FFFFFFFF" } };
    h.fill = { type: "pattern", pattern: "solid", fgColor: { argb: BAND } };
    for (const row of s.rows) sh.addRow(row);
    if (s.columns.length) sh.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: s.columns.length } };
  }

  const buf = await wb.xlsx.writeBuffer();
  downloadBlob(new Blob([buf], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }), `${reportFileName(r)}.xlsx`);
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportUtiCsv(r: UtiReport) {
  exportCsv(ewayMatrixSheet(r), reportFileName(r));
}

export function exportUtiJson(r: UtiReport) {
  exportJson(
    {
      dataset: r.dataset,
      generatedAt: r.generatedAt,
      classification: r.classification,
      format: "SBOM-EwayDMS",
      fields: (r.records[0]?.fields ?? []).map((f) => ({ field: f.field, description: f.description })),
      components: r.records.map((rec, i) => ({
        column: i === 0 ? "Primary Component" : `Component ${i}`,
        component: rec.component,
        values: Object.fromEntries(rec.fields.map((f) => [f.field, f.value])),
      })),
      raw: r.raw ?? null,
    },
    reportFileName(r),
  );
}

export async function exportUtiPdf(r: UtiReport) {
  const { default: jsPDF } = await import("jspdf");
  const { default: autoTable } = await import("jspdf-autotable");
  const doc = new jsPDF({ orientation: "landscape", unit: "pt", format: "a4" });
  const width = doc.internal.pageSize.getWidth();
  const height = doc.internal.pageSize.getHeight();
  const MARGIN = 32;
  const FIELD_W = 118;
  const DESC_W = 150;
  const MIN_COL = 108;
  const usable = width - MARGIN * 2 - FIELD_W - DESC_W;
  const perPage = Math.max(2, Math.floor(usable / MIN_COL));

  const cols = ewayColumns(r);
  const names = ewayComponentNames(r);
  const rows = ewayRows(r);

  const banner = (subtitle: string) => {
    doc.setFillColor(15, 42, 92);
    doc.rect(0, 0, width, 58, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(15);
    doc.text("Software Bill of Material (SBoM) — SBOM-EwayDMS Register", MARGIN, 26);
    doc.setFontSize(9);
    doc.text(`${r.dataset} · generated ${new Date(r.generatedAt).toLocaleString()} · ${subtitle}`, MARGIN, 44);
  };

  let first = true;
  for (let start = 2; start < cols.length; start += perPage) {
    const count = Math.min(perPage, cols.length - start);
    const idx = [0, 1, ...Array.from({ length: count }, (_, i) => start + i)];
    if (!first) doc.addPage();
    first = false;
    banner(`components ${start - 1}–${start - 2 + count} of ${r.records.length}`);
    const colWidth = Math.floor(usable / count);
    autoTable(doc, {
      startY: 72,
      head: [idx.map((i) => (i < 2 ? cols[i] : `${cols[i]}\n${names[i - 2]}`))],
      body: rows.map((row) => idx.map((i) => String(row[i] ?? ""))),
      styles: { fontSize: 7, cellPadding: 3, overflow: "linebreak", valign: "top", lineColor: [220, 220, 220], lineWidth: 0.4 },
      headStyles: { fillColor: [30, 58, 138], textColor: 255, fontSize: 7.5, valign: "middle" },
      columnStyles: {
        0: { cellWidth: FIELD_W, fontStyle: "bold", fillColor: [234, 240, 250] },
        1: { cellWidth: DESC_W, textColor: [80, 80, 80] },
        ...Object.fromEntries(idx.slice(2).map((_, i) => [i + 2, { cellWidth: colWidth }])),
      },
      margin: { left: MARGIN, right: MARGIN, top: 72 },
      didDrawPage: () => {
        doc.setFontSize(7.5);
        doc.setTextColor(120, 120, 120);
        doc.text(r.classification, MARGIN, height - 14);
      },
    });
  }

  doc.save(`${reportFileName(r)}.pdf`);
}

export async function exportUtiDocx(r: UtiReport) {
  const {
    Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
    HeadingLevel, WidthType, ShadingType, BorderStyle, AlignmentType, PageOrientation, PageBreak,
  } = await import("docx");

  const border = { style: BorderStyle.SINGLE, size: 1, color: "DDDDDD" };
  const borders = { top: border, bottom: border, left: border, right: border };
  const margins = { top: 60, bottom: 60, left: 100, right: 100 };
  const CONTENT = 14400; // landscape letter, 0.5" margins
  const FIELD_W = 2200;
  const DESC_W = 2900;
  const MIN_COL = 1700;
  const perPage = Math.max(2, Math.floor((CONTENT - FIELD_W - DESC_W) / MIN_COL));

  const cols = ewayColumns(r);
  const names = ewayComponentNames(r);
  const rows = ewayRows(r);

  const cell = (text: string, width: number, kind: "head" | "field" | "desc" | "value", alt = false) =>
    new TableCell({
      borders, margins,
      width: { size: width, type: WidthType.DXA },
      shading: {
        fill: kind === "head" ? "1E3A8A" : kind === "field" ? "EAF0FA" : alt ? "F4F7FC" : "FFFFFF",
        type: ShadingType.CLEAR,
      },
      children: text.split("\n").map((line) => new Paragraph({
        children: [new TextRun({
          text: line,
          bold: kind === "head" || kind === "field",
          color: kind === "head" ? "FFFFFF" : kind === "desc" ? "555555" : "111111",
          size: 15,
        })],
      })),
    });

  type Child = InstanceType<typeof Paragraph> | InstanceType<typeof Table>;
  const children: Child[] = [];

  let first = true;
  for (let start = 2; start < cols.length; start += perPage) {
    const count = Math.min(perPage, cols.length - start);
    const idx = [0, 1, ...Array.from({ length: count }, (_, i) => start + i)];
    const valueW = Math.floor((CONTENT - FIELD_W - DESC_W) / count);
    const widths = [FIELD_W, DESC_W, ...Array.from({ length: count }, () => valueW)];

    if (!first) children.push(new Paragraph({ children: [new PageBreak()] }));
    first = false;
    children.push(new Paragraph({
      heading: HeadingLevel.HEADING_1,
      children: [new TextRun({ text: "Software Bill of Material (SBoM) — SBOM-EwayDMS Register", bold: true, size: 28, color: "0F2A5C" })],
    }));
    children.push(new Paragraph({
      children: [new TextRun({
        text: `${r.dataset} · generated ${new Date(r.generatedAt).toLocaleString()} · components ${start - 1}–${start - 2 + count} of ${r.records.length}`,
        size: 18, color: "555555",
      })],
    }));
    children.push(new Table({
      width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
      columnWidths: widths,
      rows: [
        new TableRow({
          tableHeader: true,
          children: idx.map((i, n) => cell(i < 2 ? cols[i] : `${cols[i]}\n${names[i - 2]}`, widths[n], "head")),
        }),
        ...rows.map((row, ri) => new TableRow({
          children: idx.map((i, n) => cell(String(row[i] ?? ""), widths[n], n === 0 ? "field" : n === 1 ? "desc" : "value", ri % 2 === 1)),
        })),
      ],
    }));
  }

  const docx = new Document({
    styles: { default: { document: { run: { font: "Arial", size: 18 } } } },
    sections: [{
      properties: {
        page: {
          size: { width: 12240, height: 15840, orientation: PageOrientation.LANDSCAPE },
          margin: { top: 720, right: 720, bottom: 720, left: 720 },
        },
      },
      children: [...children, new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: r.classification, size: 15, color: "888888" })] })],
    }],
  });

  downloadBlob(await Packer.toBlob(docx), `${reportFileName(r)}.docx`);
}

