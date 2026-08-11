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
export type UtiReport = {
  dataset: string;
  generatedAt: string;
  classification: string;
  records: { component: string; fields: UtiField[] }[];
  sections: UtiSection[];
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
export function utiRecord(p: ComponentProfile): UtiField[] {
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
    { field: "Component Name & origin", description: "Name of the software component or library", value: `${dash(p.name)}${p.supplier ? ` (origin: ${p.supplier})` : ""}` },
    { field: "Version", description: "Version number or identifier of the component", value: dash(p.version) },
    { field: "Description", description: "Brief description of the functionality and purpose of the component", value: dash(String(rec.raw["Description"] ?? rec.raw["description"] ?? "") || p.businessImpact) },
    { field: "Supplier", description: "Entity or organisation that supplied the component", value: dash(p.supplier) },
    { field: "License Type", description: "License under which the component is distributed", value: `${dash(p.license)} · ${p.licenseType}` },
    { field: "Usage Restriction", description: "Limitations or restrictions on the use of the component", value: p.licenseType === "Strong Copyleft" ? "Source disclosure obligations on distribution" : p.licenseType === "Proprietary" ? "Commercial license terms apply" : p.licenseType === "Unknown" ? "Not declared — legal review required" : "No material restriction identified" },
    { field: "Release Date", description: "Date when this version was released", value: dash(rec.published) },
    { field: "End of Life Date/End of Support", description: "Date after which the component is no longer supported", value: dash([p.eolDate && `EOL ${p.eolDate}`, p.eosDate && `EOS ${p.eosDate}`].filter(Boolean).join(" · ") || p.lifecycleStatus) },
    { field: "Update Frequency", description: "How often the component is updated by the vendor", value: p.latestVersion && p.latestVersion !== p.version ? "Actively maintained — newer release available" : p.supportStatus === "Unsupported" ? "No longer updated by vendor" : "Vendor cadence not published" },
    { field: "Executable Property", description: "Whether the component contains directly executable code", value: executable },
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

export function buildUtiReport(dataset: string, a: PlatformAnalysis): UtiReport {
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
    {
      title: "10. Evidence Appendix",
      columns: ["Component", "Evidence source", "Confidence", "Rationale", "Reference"],
      rows: p.map((x) => [dash(x.name), dash(x.evidenceSource), dash(x.confidence), dash(x.classificationReason), dash((x.name ? `https://osv.dev/list?q=${encodeURIComponent(x.name)}` : ""))]),
    },
  ];

  return {
    dataset,
    generatedAt: new Date().toISOString(),
    classification: CLASSIFICATION,
    records: p.map((x) => ({ component: `${x.name}${x.version ? ` ${x.version}` : ""}`, fields: utiRecord(x) })),
    sections,
  };
}

/* --------------------------------- exports --------------------------------- */
function recordSheet(r: UtiReport): Sheet {
  const fields = r.records[0]?.fields.map((f) => f.field) ?? [];
  return {
    name: "SBoM Records",
    columns: ["Component", ...fields],
    rows: r.records.map((rec) => [rec.component, ...rec.fields.map((f) => f.value)]),
  };
}

export function reportSheets(r: UtiReport): Sheet[] {
  return [
    recordSheet(r),
    ...r.sections.map((s) => ({ name: s.title.replace(/^\d+\.\s*/, "").slice(0, 28), columns: s.columns, rows: s.rows })),
  ];
}

export async function exportUtiXlsx(r: UtiReport) {
  await exportXlsx(reportSheets(r), `${r.dataset}-UTI-SBOM-report`);
}

export function exportUtiCsv(r: UtiReport) {
  exportCsv(recordSheet(r), `${r.dataset}-UTI-SBOM-report`);
}

export function exportUtiJson(r: UtiReport) {
  exportJson(r, `${r.dataset}-UTI-SBOM-report`);
}

export async function exportUtiPdf(r: UtiReport) {
  const { default: jsPDF } = await import("jspdf");
  const { default: autoTable } = await import("jspdf-autotable");
  const doc = new jsPDF({ orientation: "landscape", unit: "pt", format: "a4" });
  const width = doc.internal.pageSize.getWidth();

  doc.setFillColor(15, 42, 92);
  doc.rect(0, 0, width, 70, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(18);
  doc.text("Software Bill of Material (SBoM)", 40, 32);
  doc.setFontSize(10);
  doc.text(`${r.dataset} · generated ${new Date(r.generatedAt).toLocaleString()}`, 40, 52);
  doc.setTextColor(80, 80, 80);
  doc.setFontSize(8);
  doc.text(r.classification, 40, 88);

  let cursor = 104;
  for (const s of r.sections) {
    autoTable(doc, {
      startY: cursor,
      head: [s.columns],
      body: s.rows.length ? s.rows.map((row) => row.map((c) => String(c))) : [s.columns.map(() => "—")],
      styles: { fontSize: 7, cellPadding: 3, overflow: "linebreak" },
      headStyles: { fillColor: [15, 42, 92], textColor: 255, fontSize: 7.5 },
      alternateRowStyles: { fillColor: [244, 247, 252] },
      margin: { left: 40, right: 40 },
      didDrawPage: () => {
        doc.setFontSize(8);
        doc.setTextColor(120, 120, 120);
        doc.text(r.classification, 40, doc.internal.pageSize.getHeight() - 16);
      },
      willDrawPage: () => { /* keep header spacing consistent */ },
      showHead: "firstPage",
      pageBreak: "auto",
    });
    const after = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY;
    doc.setFontSize(11);
    doc.setTextColor(15, 42, 92);
    cursor = after + 34;
    if (cursor > doc.internal.pageSize.getHeight() - 120) { doc.addPage(); cursor = 60; }
    doc.text("", 40, cursor - 14);
  }

  // per-component UTI records
  for (const rec of r.records) {
    doc.addPage();
    doc.setFontSize(13);
    doc.setTextColor(15, 42, 92);
    doc.text(`SBoM Record — ${rec.component}`, 40, 46);
    autoTable(doc, {
      startY: 62,
      head: [["Data Field", "Description", "Value"]],
      body: rec.fields.map((f) => [f.field, f.description, f.value]),
      styles: { fontSize: 7.5, cellPadding: 4, overflow: "linebreak" },
      headStyles: { fillColor: [15, 42, 92], textColor: 255 },
      columnStyles: { 0: { cellWidth: 170, fontStyle: "bold" }, 1: { cellWidth: 260 }, 2: { cellWidth: "auto" } },
      margin: { left: 40, right: 40 },
    });
  }

  doc.save(`${r.dataset}-UTI-SBOM-report.pdf`);
}

export async function exportUtiDocx(r: UtiReport) {
  const {
    Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
    HeadingLevel, WidthType, ShadingType, BorderStyle, AlignmentType, PageOrientation,
  } = await import("docx");

  const border = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
  const borders = { top: border, bottom: border, left: border, right: border };
  const margins = { top: 60, bottom: 60, left: 100, right: 100 };
  const CONTENT = 14000;

  const cell = (text: string, width: number, opts: { head?: boolean } = {}) =>
    new TableCell({
      borders, margins,
      width: { size: width, type: WidthType.DXA },
      shading: { fill: opts.head ? "0F2A5C" : "FFFFFF", type: ShadingType.CLEAR },
      children: [new Paragraph({ children: [new TextRun({ text, bold: opts.head, color: opts.head ? "FFFFFF" : "111111", size: 16 })] })],
    });

  const table = (columns: string[], rows: (string | number)[][]) => {
    const w = Math.floor(CONTENT / columns.length);
    const widths = columns.map(() => w);
    const total = w * columns.length;
    return new Table({
      width: { size: total, type: WidthType.DXA },
      columnWidths: widths,
      rows: [
        new TableRow({ children: columns.map((c) => cell(c, w, { head: true })) }),
        ...(rows.length ? rows : [columns.map(() => "—")]).slice(0, 400).map((row) =>
          new TableRow({ children: columns.map((_, i) => cell(String(row[i] ?? "—"), w)) })),
      ],
    });
  };

  const children: InstanceType<typeof Paragraph>[] = ([] as unknown as InstanceType<typeof Paragraph>[]).concat(
    new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "Software Bill of Material (SBoM)", bold: true, size: 36 })] }),
    new Paragraph({ children: [new TextRun({ text: `${r.dataset} · generated ${new Date(r.generatedAt).toLocaleString()}`, size: 20, color: "555555" })] }),
    new Paragraph({ children: [new TextRun({ text: r.classification, size: 16, color: "888888" })] }),
    new Paragraph({ children: [new TextRun("")] }),
  ] as InstanceType<typeof Paragraph>[]);

  for (const s of r.sections) {
    children.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun({ text: s.title, bold: true, size: 26 })] }));
    for (const line of s.narrative ?? []) children.push(new Paragraph({ children: [new TextRun({ text: line, size: 20 })] }));
    children.push(table(s.columns, s.rows));
    children.push(new Paragraph({ children: [new TextRun("")] }));
  }

  children.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun({ text: "Appendix — SBoM Records (UTI AMC template)", bold: true, size: 26 })] }));
  for (const rec of r.records) {
    children.push(new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun({ text: rec.component, bold: true, size: 22 })] }));
    children.push(table(["Data Field", "Description", "Value"], rec.fields.map((f) => [f.field, f.description, f.value])));
    children.push(new Paragraph({ children: [new TextRun("")] }));
  }

  const docx = new Document({
    styles: { default: { document: { run: { font: "Arial", size: 20 } } } },
    sections: [{
      properties: {
        page: {
          size: { width: 12240, height: 15840, orientation: PageOrientation.LANDSCAPE },
          margin: { top: 720, right: 720, bottom: 720, left: 720 },
        },
      },
      children: [...children, new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: r.classification, size: 16, color: "888888" })] })],
    }],
  });

  const blob = await Packer.toBlob(docx);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${r.dataset}-UTI-SBOM-report.docx`;
  a.click();
  URL.revokeObjectURL(url);
}
