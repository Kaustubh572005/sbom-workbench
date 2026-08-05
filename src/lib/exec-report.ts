/**
 * Bloomberg-terminal-grade executive intelligence report.
 * Pure data layer: builds the report model + all downloadable outputs
 * (Excel workbook, JSON, CSV, Markdown, PDF).
 */

import ExcelJS from "exceljs";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import type { ComponentRisk, Sev } from "./sbom-heuristics";

export type Counted = { key: string; count: number; score: number; detail?: string };

export type ExecReport = {
  dataset: string;
  generatedAt: string;
  totals: {
    components: number;
    suppliers: number;
    ecosystems: number;
    applications: number;
    licenses: number;
    withCve: number;
    estimated: number;
  };
  severity: Record<Sev, number>;
  cyberRiskScore: number;
  sbomQualityScore: number;
  completenessScore: number;
  confidenceScore: number;
  exploitability: number;
  attackSurface: number;
  riskConcentration: number;
  vendorConcentration: number;
  packageFreshness: number;
  riskBand: { label: string; tone: Sev };
  executiveSummary: string[];
  businessImpact: string[];
  complianceStatus: Array<{ framework: string; status: "Compliant" | "At Risk" | "Non-Compliant"; finding: string }>;
  criticalFindings: string[];
  actions: { immediate: string[]; shortTerm: string[]; longTerm: string[] };
  topCriticalComponents: ComponentRisk[];
  topApplications: Counted[];
  topVendors: Counted[];
  topVulnerabilities: Array<{ cve: string; component: string; version: string; cvss: number; severity: Sev; estimated: boolean }>;
  licenseStats: Counted[];
  ecosystemStats: Counted[];
  eol: ComponentRisk[];
  missingData: Counted[];
  loopholes: Array<{ title: string; count: number; impact: Sev; detail: string }>;
  recommendations: Array<{ priority: "P0" | "P1" | "P2" | "P3"; text: string }>;
  patchRecommendations: Array<{ component: string; from: string; to: string; priority: string }>;
  heatmap: Array<{ application: string; critical: number; high: number; medium: number; low: number; info: number }>;
  risks: ComponentRisk[];
};

const SEV_ORDER: Sev[] = ["critical", "high", "medium", "low", "info"];
const sevWeight: Record<Sev, number> = { critical: 10, high: 6, medium: 3, low: 1, info: 0.2 };

const top = (m: Map<string, { count: number; score: number }>, n: number): Counted[] =>
  [...m.entries()].map(([key, v]) => ({ key, ...v })).sort((a, b) => b.score - a.score || b.count - a.count).slice(0, n);

export function buildExecReport(dataset: string, risks: ComponentRisk[]): ExecReport {
  const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Sev, number>;
  const suppliers = new Map<string, { count: number; score: number }>();
  const apps = new Map<string, { count: number; score: number }>();
  const licenses = new Map<string, { count: number; score: number }>();
  const ecosystems = new Map<string, { count: number; score: number }>();
  const heat = new Map<string, { critical: number; high: number; medium: number; low: number; info: number }>();
  const missing = new Map<string, { count: number; score: number }>();

  for (const r of risks) {
    severity[r.severity]++;
    const bump = (m: Map<string, { count: number; score: number }>, k: string) => {
      if (!k) return;
      const cur = m.get(k) ?? { count: 0, score: 0 };
      m.set(k, { count: cur.count + 1, score: cur.score + sevWeight[r.severity] });
    };
    bump(suppliers, r.supplier || "Unknown supplier");
    bump(apps, r.application || "Unassigned application");
    bump(licenses, r.license || "Undeclared license");
    bump(ecosystems, r.ecosystem || "Unknown ecosystem");
    for (const f of r.missing) bump(missing, `Missing ${f}`);
    const app = r.application || "Unassigned application";
    const h = heat.get(app) ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    h[r.severity]++;
    heat.set(app, h);
  }

  const n = Math.max(1, risks.length);
  const weighted = risks.reduce((a, r) => a + sevWeight[r.severity], 0) / n;
  const cyberRiskScore = Math.max(0, Math.min(100, Math.round(100 - weighted * 9.2)));
  const riskBand: ExecReport["riskBand"] =
    cyberRiskScore >= 80 ? { label: "Low exposure", tone: "low" }
      : cyberRiskScore >= 60 ? { label: "Moderate exposure", tone: "medium" }
        : cyberRiskScore >= 40 ? { label: "Elevated exposure", tone: "high" }
          : { label: "Severe exposure", tone: "critical" };

  const withIds = risks.filter((r) => r.purl || r.cpe).length;
  const withVersion = risks.filter((r) => r.version).length;
  const withSupplier = risks.filter((r) => r.supplier).length;
  const withLicense = risks.filter((r) => r.license).length;
  const completenessScore = Math.round(((withIds + withVersion + withSupplier + withLicense) / (n * 4)) * 100);
  const eol = risks.filter((r) => r.eol);
  const sbomQualityScore = Math.max(0, Math.min(100, Math.round(completenessScore * 0.75 + (withIds / n) * 25)));
  const confidenceScore = Math.round(risks.reduce((a, r) => a + r.confidence, 0) / n);
  const exploitability = Math.round((risks.filter((r) => /exploit|Known-exploited/i.test(r.factors.map((f) => f.label).join(" "))).length / n) * 100);
  const attackSurface = Math.round((risks.filter((r) => r.categories.some((c) => /Internet-facing|network|Parser/i.test(c))).length / n) * 100);
  const vendorTop = top(suppliers, 10);
  const vendorConcentration = Math.round(((vendorTop[0]?.count ?? 0) / n) * 100);
  const riskConcentration = Math.round(((severity.critical + severity.high) / n) * 100);
  const packageFreshness = Math.max(0, 100 - Math.round((risks.filter((r) => r.factors.some((f) => /older than|Ageing/i.test(f.label))).length / n) * 100));

  const withCve = risks.filter((r) => r.cve).length;
  const estimated = risks.filter((r) => r.estimated).length;

  const criticalRisks = [...risks].sort((a, b) => b.score - a.score || b.cvss - a.cvss);
  const topCriticalComponents = criticalRisks.slice(0, 10);

  const topVulnerabilities = risks
    .filter((r) => r.cve || r.severity === "critical" || r.severity === "high")
    .sort((a, b) => b.cvss - a.cvss || b.score - a.score)
    .slice(0, 10)
    .map((r) => ({ cve: r.cve || `EST-${r.name.slice(0, 12).toUpperCase()}`, component: r.name, version: r.version, cvss: r.cvss, severity: r.severity, estimated: r.estimated }));

  const loopholes: ExecReport["loopholes"] = ([
    { title: "Components without an exact version", count: risks.filter((r) => !r.version).length, impact: "high", detail: "Advisory correlation is impossible without a pinned version — these are blind spots in the estate." },
    { title: "Components without PURL or CPE", count: risks.filter((r) => !r.purl && !r.cpe).length, impact: "high", detail: "Automated NVD/OSV matching cannot run; risk had to be estimated heuristically." },
    { title: "Undeclared supplier", count: risks.filter((r) => !r.supplier).length, impact: "medium", detail: "No vendor advisory channel can be monitored for these components." },
    { title: "Undeclared license", count: risks.filter((r) => !r.license).length, impact: "medium", detail: "Legal and distribution obligations are unverified." },
    { title: "End-of-Life / unsupported releases", count: eol.length, impact: "critical", detail: "No security patches will ever be issued for these release families." },
    { title: "Security-critical packages (crypto/auth/kernel)", count: risks.filter((r) => r.categories.some((c) => /Cryptography|Authentication|Kernel/i.test(c))).length, impact: "high", detail: "A single flaw here compromises confidentiality or access control across the platform." },
    { title: "Copyleft / restrictive licenses", count: risks.filter((r) => /agpl|gpl|sspl/i.test(r.license)).length, impact: "medium", detail: "Distribution may trigger source-disclosure obligations." },
    { title: "Multiple versions of the same component", count: risks.filter((r) => r.factors.some((f) => /Multiple versions/.test(f.label))).length, impact: "medium", detail: "Divergent versions multiply patch effort and hide vulnerable copies." },
    { title: "Fixes not yet identified", count: risks.filter((r) => !r.fixAvailable && (r.severity === "critical" || r.severity === "high")).length, impact: "critical", detail: "High-severity exposure with no known upgrade path — needs compensating controls." },
  ] as ExecReport["loopholes"]).filter((l) => l.count > 0);

  const complianceStatus: ExecReport["complianceStatus"] = [
    {
      framework: "SEBI CSCRF",
      status: severity.critical > 0 ? "Non-Compliant" : severity.high > 0 ? "At Risk" : "Compliant",
      finding: severity.critical > 0
        ? `${severity.critical} critical exposure(s) breach the requirement to remediate critical vulnerabilities within defined SLAs.`
        : `${severity.high} high-severity item(s) require documented remediation timelines.`,
    },
    {
      framework: "CERT-In Directions 2022",
      status: eol.length > 0 || severity.critical > 0 ? "Non-Compliant" : "At Risk",
      finding: eol.length > 0
        ? `${eol.length} End-of-Life component(s) remain in production; unsupported software must be replaced or isolated.`
        : "Maintain 180-day log retention and 6-hour incident reporting for the findings listed here.",
    },
    {
      framework: "US EO 14028 / NTIA minimum SBOM elements",
      status: completenessScore >= 85 ? "Compliant" : completenessScore >= 60 ? "At Risk" : "Non-Compliant",
      finding: `SBOM completeness is ${completenessScore}% — supplier, version and unique identifier fields must all be present.`,
    },
    {
      framework: "ISO/IEC 27001:2022 A.8.8",
      status: severity.critical + severity.high > 0 ? "At Risk" : "Compliant",
      finding: `${severity.critical + severity.high} technical vulnerability(ies) require documented management action.`,
    },
    {
      framework: "PCI DSS 4.0 (6.3.1 / 6.3.3)",
      status: severity.critical > 0 ? "Non-Compliant" : "At Risk",
      finding: "Critical and high patches must be applied within one month of release; maintain an inventory of bespoke and third-party software.",
    },
    {
      framework: "License / IP compliance",
      status: risks.some((r) => /agpl|sspl/i.test(r.license)) ? "At Risk" : "Compliant",
      finding: `${risks.filter((r) => /agpl|gpl|sspl/i.test(r.license)).length} component(s) carry copyleft obligations.`,
    },
  ];

  const executiveSummary = [
    `${risks.length} software components were normalized from the ingested SBOM for "${dataset}", covering ${suppliers.size} supplier(s), ${ecosystems.size} ecosystem(s) and ${apps.size} application grouping(s).`,
    `The consolidated cyber risk score is ${cyberRiskScore}/100 (${riskBand.label}). Severity distribution: ${SEV_ORDER.map((s) => `${severity[s]} ${s}`).join(", ")}.`,
    withCve === 0
      ? `The uploaded document contained no CVE or CVSS evidence. Rather than reporting "no vulnerabilities found", every component was classified through heuristic supply-chain analysis — version age, support status, package criticality, identifiability, linkage and license exposure — producing ESTIMATED severities at an average confidence of ${confidenceScore}%.`
      : `${withCve} component(s) arrived with vulnerability evidence; the remaining ${estimated} were classified with estimated severities at an average confidence of ${confidenceScore}%.`,
    `SBOM quality is ${sbomQualityScore}/100 with ${completenessScore}% field completeness; ${risks.filter((r) => !r.purl && !r.cpe).length} component(s) cannot be automatically correlated to advisories today.`,
    `Risk concentration is ${riskConcentration}% of the estate in critical/high, and vendor concentration is ${vendorConcentration}% under "${vendorTop[0]?.key ?? "n/a"}".`,
  ];

  const businessImpact = [
    severity.critical > 0
      ? `Critical exposure in ${severity.critical} component(s) creates a credible path to service compromise, data exfiltration or regulatory reporting obligations.`
      : "No critical exposure is currently evidenced; residual risk is dominated by maintainability and identifiability gaps.",
    eol.length > 0
      ? `${eol.length} unsupported component(s) mean future vulnerabilities will have no vendor fix — the remediation cost rises sharply over time.`
      : "All identified release families still appear to receive maintenance.",
    `Operationally, ${risks.filter((r) => r.patchPriority === "P0" || r.patchPriority === "P1").length} item(s) fall into P0/P1 patch priority and should be sized into the current sprint.`,
    `Audit exposure: ${complianceStatus.filter((c) => c.status !== "Compliant").length} of ${complianceStatus.length} assessed control frameworks currently show gaps.`,
  ];

  const criticalFindings = [
    ...topCriticalComponents.slice(0, 6).map((r) =>
      `${r.name}${r.version ? ` ${r.version}` : ""} — ${r.estimated ? "Estimated " : ""}${r.severity.toUpperCase()} (risk ${r.score}/100, confidence ${r.confidence}%)${r.cve ? ` · ${r.cve}` : ""}`),
    ...loopholes.filter((l) => l.impact === "critical").map((l) => `${l.title}: ${l.count} component(s) — ${l.detail}`),
  ];

  const immediate = [
    ...topCriticalComponents.filter((r) => r.severity === "critical").slice(0, 6).map((r) => r.actions[0]),
    ...(eol.length ? [`Isolate or replace ${eol.length} End-of-Life component(s) or place compensating controls in front of them`] : []),
  ].filter(Boolean);
  const shortTerm = [
    ...(risks.filter((r) => !r.version).length ? [`Complete version data for ${risks.filter((r) => !r.version).length} component(s) so advisory matching can run`] : []),
    ...(risks.filter((r) => !r.purl && !r.cpe).length ? [`Add PURL/CPE identifiers to ${risks.filter((r) => !r.purl && !r.cpe).length} component(s)`] : []),
    ...topCriticalComponents.filter((r) => r.severity === "high").slice(0, 5).map((r) => r.actions[0]),
  ].filter(Boolean);
  const longTerm = [
    "Automate SBOM generation in CI so every build publishes a signed, complete CycloneDX/SPDX document",
    "Continuously correlate the component inventory against NVD, CISA KEV, OSV.dev and vendor advisories",
    vendorConcentration > 40 ? `Reduce vendor concentration risk (${vendorConcentration}% under a single supplier)` : "Track supplier diversification as the estate grows",
    "Establish an End-of-Life watch list with dated migration owners",
    "Adopt license policy gates in the build pipeline for copyleft and non-commercial terms",
  ];

  const recommendations: ExecReport["recommendations"] = [
    ...immediate.map((text) => ({ priority: "P0" as const, text })),
    ...shortTerm.map((text) => ({ priority: "P1" as const, text })),
    ...longTerm.map((text) => ({ priority: "P2" as const, text })),
  ];

  const patchRecommendations = risks
    .filter((r) => r.severity === "critical" || r.severity === "high" || r.eol)
    .slice(0, 200)
    .map((r) => ({
      component: r.name,
      from: r.version || "unknown",
      to: r.fixedVersion || "latest supported release (verify with vendor advisory)",
      priority: r.patchPriority,
    }));

  return {
    dataset,
    generatedAt: new Date().toISOString(),
    totals: {
      components: risks.length, suppliers: suppliers.size, ecosystems: ecosystems.size,
      applications: apps.size, licenses: licenses.size, withCve, estimated,
    },
    severity,
    cyberRiskScore, sbomQualityScore, completenessScore, confidenceScore,
    exploitability, attackSurface, riskConcentration, vendorConcentration, packageFreshness,
    riskBand,
    executiveSummary, businessImpact, complianceStatus, criticalFindings,
    actions: { immediate, shortTerm, longTerm },
    topCriticalComponents,
    topApplications: top(apps, 10),
    topVendors: vendorTop,
    topVulnerabilities,
    licenseStats: top(licenses, 12),
    ecosystemStats: top(ecosystems, 12),
    eol: eol.slice(0, 200),
    missingData: top(missing, 10),
    loopholes,
    recommendations,
    patchRecommendations,
    heatmap: [...heat.entries()].map(([application, v]) => ({ application, ...v }))
      .sort((a, b) => b.critical - a.critical || b.high - a.high).slice(0, 15),
    risks,
  };
}

/* ================================== Exports ================================= */
function download(blob: Blob, filename: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

const slug = (s: string) => s.replace(/[^a-z0-9]+/gi, "-").toLowerCase();

export function exportReportJson(r: ExecReport) {
  download(new Blob([JSON.stringify(r, null, 2)], { type: "application/json" }), `${slug(r.dataset)}-sbom-intelligence.json`);
}

export function exportReportCsv(r: ExecReport) {
  const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const head = ["Component", "Version", "Supplier", "Ecosystem", "PURL", "CPE", "License", "Application", "CVE", "CVSS", "Severity", "Estimated", "Risk Score", "Confidence", "Patch Priority", "Fix Available", "Fixed Version", "EOL", "Missing Fields", "Risk Factors", "Rationale", "Recommended Actions"];
  const lines = [head.map(esc).join(",")];
  for (const c of r.risks) {
    lines.push([c.name, c.version, c.supplier, c.ecosystem, c.purl, c.cpe, c.license, c.application, c.cve, c.cvss || "", c.severity, c.estimated ? "Estimated" : "Reported", c.score, `${c.confidence}%`, c.patchPriority, c.fixAvailable ? "Yes" : "No", c.fixedVersion, c.eol ? "Yes" : "No", c.missing.join(" | "), c.factors.map((f) => f.label).join(" | "), c.rationale, c.actions.join(" | ")].map(esc).join(","));
  }
  download(new Blob([lines.join("\n")], { type: "text/csv" }), `${slug(r.dataset)}-components.csv`);
}

export function exportReportMarkdown(r: ExecReport) {
  const L: string[] = [];
  L.push(`# SBOM Intelligence Executive Report — ${r.dataset}`, "", `_Generated ${new Date(r.generatedAt).toUTCString()}_`, "");
  L.push(`**Overall Cyber Risk Score:** ${r.cyberRiskScore}/100 (${r.riskBand.label}) · **SBOM Quality:** ${r.sbomQualityScore}/100 · **Confidence:** ${r.confidenceScore}%`, "");
  L.push("## Executive Summary", ...r.executiveSummary.map((s) => `- ${s}`), "");
  L.push("## Business Impact", ...r.businessImpact.map((s) => `- ${s}`), "");
  L.push("## Compliance Status", "", "| Framework | Status | Finding |", "|---|---|---|",
    ...r.complianceStatus.map((c) => `| ${c.framework} | ${c.status} | ${c.finding} |`), "");
  L.push("## Critical Findings", ...r.criticalFindings.map((s) => `- ${s}`), "");
  L.push("## Immediate Actions", ...r.actions.immediate.map((s) => `1. ${s}`), "");
  L.push("## Short-Term Actions", ...r.actions.shortTerm.map((s) => `1. ${s}`), "");
  L.push("## Long-Term Actions", ...r.actions.longTerm.map((s) => `1. ${s}`), "");
  L.push("## Top 10 Critical Components", "", "| Component | Version | Severity | Risk | Confidence | Basis |", "|---|---|---|---|---|---|",
    ...r.topCriticalComponents.map((c) => `| ${c.name} | ${c.version || "—"} | ${c.severity} | ${c.score} | ${c.confidence}% | ${c.estimated ? "Estimated" : "Reported"} |`), "");
  L.push("## Top 10 Applications at Risk", "", "| Application | Components | Risk weight |", "|---|---|---|",
    ...r.topApplications.map((a) => `| ${a.key} | ${a.count} | ${a.score.toFixed(1)} |`), "");
  L.push("## Top 10 Vendors at Risk", "", "| Supplier | Components | Risk weight |", "|---|---|---|",
    ...r.topVendors.map((a) => `| ${a.key} | ${a.count} | ${a.score.toFixed(1)} |`), "");
  L.push("## Security Loopholes", ...r.loopholes.map((l) => `- **${l.title}** (${l.count}) — ${l.detail}`), "");
  L.push("## Remediation Recommendations", ...r.recommendations.map((x) => `- \`${x.priority}\` ${x.text}`), "");
  download(new Blob([L.join("\n")], { type: "text/markdown" }), `${slug(r.dataset)}-executive-report.md`);
}

export async function exportReportXlsx(r: ExecReport) {
  const wb = new ExcelJS.Workbook();
  wb.creator = "Enterprise SBOM Intelligence Engine";
  wb.created = new Date();

  const addSheet = (name: string, columns: string[], rows: (string | number)[][]) => {
    const ws = wb.addWorksheet(name.slice(0, 31));
    ws.addRow(columns);
    ws.getRow(1).font = { bold: true, color: { argb: "FFFFFFFF" } };
    ws.getRow(1).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF0F172A" } };
    rows.forEach((x) => ws.addRow(x));
    ws.columns.forEach((col, i) => {
      const width = Math.min(60, Math.max(12, ...[columns[i] ?? "", ...rows.map((x) => String(x[i] ?? ""))].map((v) => String(v).length + 2)));
      col.width = width;
    });
    ws.views = [{ state: "frozen", ySplit: 1 }];
    ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
    return ws;
  };

  addSheet("Executive Summary", ["Metric", "Value"], [
    ["Dataset", r.dataset],
    ["Generated (UTC)", new Date(r.generatedAt).toUTCString()],
    ["Overall Cyber Risk Score", `${r.cyberRiskScore}/100 (${r.riskBand.label})`],
    ["SBOM Quality Score", `${r.sbomQualityScore}/100`],
    ["SBOM Completeness", `${r.completenessScore}%`],
    ["Confidence Score", `${r.confidenceScore}%`],
    ["Exploitability index", `${r.exploitability}%`],
    ["Attack surface index", `${r.attackSurface}%`],
    ["Risk concentration", `${r.riskConcentration}%`],
    ["Vendor concentration", `${r.vendorConcentration}%`],
    ["Package freshness", `${r.packageFreshness}%`],
    ["Components", r.totals.components],
    ["Suppliers", r.totals.suppliers],
    ["Applications", r.totals.applications],
    ["Ecosystems", r.totals.ecosystems],
    ["With supplied CVE evidence", r.totals.withCve],
    ["Heuristically estimated", r.totals.estimated],
    ...SEV_ORDER.map((s) => [`${s[0].toUpperCase()}${s.slice(1)} severity`, r.severity[s]] as [string, number]),
    ["", ""],
    ...r.executiveSummary.map((s, i) => [`Narrative ${i + 1}`, s] as [string, string]),
    ...r.businessImpact.map((s, i) => [`Business impact ${i + 1}`, s] as [string, string]),
  ]);

  addSheet("Components", ["Component", "Version", "Supplier", "Ecosystem", "PURL", "CPE", "License", "Application", "Severity", "Basis", "Risk", "Confidence", "Missing fields", "Risk factors"],
    r.risks.map((c) => [c.name, c.version, c.supplier, c.ecosystem, c.purl, c.cpe, c.license, c.application, c.severity, c.estimated ? "Estimated" : "Reported", c.score, `${c.confidence}%`, c.missing.join(", "), c.factors.map((f) => f.label).join("; ")]));

  addSheet("Vulnerabilities", ["CVE / ID", "Component", "Version", "CVSS", "Severity", "Basis", "Fix available", "Fixed version", "Patch priority"],
    r.risks.filter((c) => c.cve || c.severity === "critical" || c.severity === "high")
      .map((c) => [c.cve || `EST-${c.name.slice(0, 12).toUpperCase()}`, c.name, c.version, c.cvss || "", c.severity, c.estimated ? "Estimated" : "Reported", c.fixAvailable ? "Yes" : "No", c.fixedVersion, c.patchPriority]));

  addSheet("Critical Findings", ["Finding"], r.criticalFindings.map((f) => [f]));
  addSheet("Applications at Risk", ["Application", "Components", "Risk weight"], r.topApplications.map((a) => [a.key, a.count, +a.score.toFixed(1)]));
  addSheet("Vendor Risk", ["Supplier", "Components", "Risk weight"], r.topVendors.map((a) => [a.key, a.count, +a.score.toFixed(1)]));
  addSheet("License Analysis", ["License", "Components", "Risk weight"], r.licenseStats.map((a) => [a.key, a.count, +a.score.toFixed(1)]));
  addSheet("Compliance Analysis", ["Framework", "Status", "Finding"], r.complianceStatus.map((c) => [c.framework, c.status, c.finding]));
  addSheet("Dependencies", ["Component", "Version", "Parent", "Dependencies", "Ecosystem"],
    r.risks.map((c) => [c.name, c.version, String(c.raw["Parent Component"] ?? ""), String(c.raw["Dependencies"] ?? ""), c.ecosystem]));
  addSheet("EOL-EOS", ["Component", "Version", "Supplier", "Severity", "Detail"],
    r.eol.map((c) => [c.name, c.version, c.supplier, c.severity, c.factors.map((f) => f.label).join("; ")]));
  addSheet("Recommendations", ["Priority", "Recommendation"], r.recommendations.map((x) => [x.priority, x.text]));
  addSheet("Patch Recommendations", ["Component", "Current", "Target", "Priority"], r.patchRecommendations.map((p) => [p.component, p.from, p.to, p.priority]));
  addSheet("Charts", ["Series", "Label", "Value"], [
    ...SEV_ORDER.map((s) => ["Severity distribution", s, r.severity[s]] as [string, string, number]),
    ...r.ecosystemStats.map((e) => ["Ecosystem spread", e.key, e.count] as [string, string, number]),
    ...r.heatmap.map((h) => ["Heatmap critical+high", h.application, h.critical + h.high] as [string, string, number]),
  ]);
  addSheet("Metadata", ["Field", "Value"], [
    ["Engine", "Enterprise SBOM Intelligence Engine"],
    ["Method", "Format auto-detection → normalization → dedupe → dependency/supplier graphs → evidence correlation → heuristic risk estimation"],
    ["Intelligence sources", "NVD, CISA KEV, GitHub Security Advisories, OSV.dev, endoflife.date, vendor advisories"],
    ["Estimation policy", "Components without CVE evidence are classified with Estimated Severity plus a confidence score — never reported as 'no vulnerabilities found'"],
    ["Generated (UTC)", new Date(r.generatedAt).toUTCString()],
  ]);

  const buf = await wb.xlsx.writeBuffer();
  download(new Blob([buf], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }), `${slug(r.dataset)}-sbom-intelligence.xlsx`);
}

export function exportReportPdf(r: ExecReport) {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const W = doc.internal.pageSize.getWidth();
  let y = 48;

  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, W, 96, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(18);
  doc.text("SBOM Intelligence — Executive Report", 40, 44);
  doc.setFontSize(10);
  doc.text(`${r.dataset} · Generated ${new Date(r.generatedAt).toUTCString()}`, 40, 66);
  doc.text(`Cyber Risk ${r.cyberRiskScore}/100 (${r.riskBand.label}) · SBOM Quality ${r.sbomQualityScore}/100 · Confidence ${r.confidenceScore}%`, 40, 82);
  doc.setTextColor(20, 20, 20);
  y = 128;

  const para = (title: string, lines: string[]) => {
    if (!lines.length) return;
    if (y > 720) { doc.addPage(); y = 56; }
    doc.setFontSize(12); doc.text(title, 40, y); y += 16;
    doc.setFontSize(9);
    for (const l of lines) {
      const wrapped = doc.splitTextToSize(`• ${l}`, W - 80) as string[];
      if (y + wrapped.length * 12 > 780) { doc.addPage(); y = 56; }
      doc.text(wrapped, 40, y);
      y += wrapped.length * 12 + 4;
    }
    y += 10;
  };

  para("Executive Summary", r.executiveSummary);
  para("Business Impact", r.businessImpact);
  para("Critical Findings", r.criticalFindings);
  para("Immediate Actions", r.actions.immediate);
  para("Short-Term Actions", r.actions.shortTerm);
  para("Long-Term Actions", r.actions.longTerm);

  const table = (head: string[], body: (string | number)[][], title: string) => {
    if (!body.length) return;
    doc.addPage(); y = 56;
    doc.setFontSize(12); doc.text(title, 40, y);
    autoTable(doc, { head: [head], body, startY: y + 12, styles: { fontSize: 8 }, headStyles: { fillColor: [15, 23, 42] } });
  };

  table(["Framework", "Status", "Finding"], r.complianceStatus.map((c) => [c.framework, c.status, c.finding]), "Compliance Status");
  table(["Component", "Version", "Severity", "Risk", "Confidence", "Basis"],
    r.topCriticalComponents.map((c) => [c.name, c.version || "—", c.severity, c.score, `${c.confidence}%`, c.estimated ? "Estimated" : "Reported"]), "Top 10 Critical Components");
  table(["CVE / ID", "Component", "Version", "CVSS", "Severity"],
    r.topVulnerabilities.map((v) => [v.cve, v.component, v.version || "—", v.cvss || "—", v.severity]), "Top 10 Vulnerabilities");
  table(["Application", "Components", "Risk weight"], r.topApplications.map((a) => [a.key, a.count, +a.score.toFixed(1)]), "Top 10 Applications at Risk");
  table(["Supplier", "Components", "Risk weight"], r.topVendors.map((a) => [a.key, a.count, +a.score.toFixed(1)]), "Top 10 Vendors at Risk");
  table(["Loophole", "Count", "Impact"], r.loopholes.map((l) => [l.title, l.count, l.impact]), "Security Loopholes");
  table(["Priority", "Recommendation"], r.recommendations.map((x) => [x.priority, x.text]), "Remediation Recommendations");

  doc.save(`${slug(r.dataset)}-executive-report.pdf`);
}
