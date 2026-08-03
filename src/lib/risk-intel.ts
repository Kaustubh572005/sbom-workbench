/**
 * Local risk-intelligence engine.
 * Detects analytical intent in a natural-language question and computes a
 * structured report (KPIs, charts, table, recommendations) from the dataset
 * client-side — no model round trip required, so it scales to 100k+ rows.
 */

export type SevKey = "critical" | "high" | "medium" | "low" | "info" | "none";

export type Kpi = { label: string; value: string | number; sub?: string; tone?: SevKey | "primary" };
export type ChartSpec = {
  kind: "donut" | "bar" | "line";
  title: string;
  data: { name: string; value: number; color?: string }[];
};
export type TableSpec = { title: string; columns: string[]; rows: (string | number)[][] };
export type Recommendation = { priority: "P0" | "P1" | "P2" | "P3"; text: string };

export type AnalysisReport = {
  title: string;
  intent: Intent;
  datasetName: string;
  generatedAt: string;
  summary: string[];
  kpis: Kpi[];
  charts: ChartSpec[];
  tables: TableSpec[];
  recommendations: Recommendation[];
  matchedRows: number;
};

export type Intent =
  | "overview"
  | "exploitable"
  | "eol"
  | "license"
  | "compliance"
  | "remediation"
  | "vendor"
  | "application"
  | "cve"
  | "search";

const SEV_HEX: Record<SevKey, string> = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
  info: "var(--color-severity-info)",
  none: "var(--color-muted-foreground)",
};

const norm = (s: string) => s.toLowerCase().replace(/[\s_-]/g, "");

function pick(row: Record<string, unknown>, candidates: string[]): string {
  const keys = Object.keys(row);
  for (const c of candidates) {
    const k = keys.find((k) => norm(k) === norm(c)) ?? keys.find((k) => norm(k).includes(norm(c)));
    if (k) {
      const v = row[k];
      if (v != null && String(v).trim() !== "") return String(v).trim();
    }
  }
  return "";
}

export function sevOf(value: unknown): SevKey {
  const s = String(value ?? "").toLowerCase().trim();
  if (s.includes("critical") || s.includes("severe")) return "critical";
  if (s.includes("high") || s.includes("major")) return "high";
  if (s.includes("medium") || s.includes("moderate")) return "medium";
  if (s.includes("low") || s.includes("minor")) return "low";
  if (s.includes("info") || s.includes("note")) return "info";
  const n = Number(s);
  if (!Number.isNaN(n) && s !== "") {
    if (n >= 9) return "critical";
    if (n >= 7) return "high";
    if (n >= 4) return "medium";
    if (n > 0) return "low";
  }
  return "none";
}

type Row = Record<string, unknown>;

type Facts = {
  component: string;
  version: string;
  vendor: string;
  application: string;
  cve: string;
  cvss: number;
  severity: SevKey;
  license: string;
  fix: string;
  eol: boolean;
  kev: boolean;
  exploit: boolean;
  status: string;
  blob: string;
};

const EOL_HINTS = ["eol", "end of life", "end-of-life", "unsupported", "deprecated", "obsolete", "out of support"];

export function factsOf(row: Row): Facts {
  const blob = Object.values(row).map((v) => String(v ?? "")).join(" ").toLowerCase();
  const cvssRaw = pick(row, ["cvss", "cvss score", "base score", "score"]);
  const sevRaw = pick(row, ["severity", "risk", "criticality", "priority", "impact", "level"]);
  return {
    component: pick(row, ["component", "package", "library", "product", "name", "asset"]),
    version: pick(row, ["version", "installed version", "current version", "versioninfo"]),
    vendor: pick(row, ["vendor", "publisher", "supplier", "manufacturer", "author", "originator"]),
    application: pick(row, ["application", "app", "service", "project", "system", "host"]),
    cve: pick(row, ["cve", "cve id", "advisory", "vulnerability id", "id"]),
    cvss: Number(cvssRaw) || 0,
    severity: sevOf(sevRaw || cvssRaw),
    license: pick(row, ["license", "licence", "licenseconcluded", "spdx license"]),
    fix: pick(row, ["fix version", "fixed version", "patch", "remediation", "recommendation", "upgrade to"]),
    eol: EOL_HINTS.some((h) => blob.includes(h)),
    kev: /\bkev\b|known exploited|cisa/.test(blob),
    exploit: /exploit(ed|able)?\s*(available|in the wild|yes|true)|poc available|weaponized/.test(blob),
    status: pick(row, ["status", "state", "remediation status", "disposition"]),
    blob,
  };
}

/* ------------------------------- intent detection ------------------------------ */
const INTENT_RULES: { intent: Intent; re: RegExp }[] = [
  { intent: "exploitable", re: /exploit|kev|in the wild|weaponi|actively attacked|poc/i },
  { intent: "eol", re: /\beol\b|end[- ]of[- ]life|unsupported|deprecat|obsolete|out of support/i },
  { intent: "license", re: /licen[cs]e|gpl|copyleft|mit|apache 2|legal exposure/i },
  { intent: "compliance", re: /complian|audit|iso ?27001|soc ?2|pci|nist|hipaa|gdpr|policy|posture report/i },
  { intent: "remediation", re: /remediat|patch|fix|upgrade|mitigat|action plan|sprint/i },
  { intent: "vendor", re: /vendor|publisher|supplier|manufacturer|third[- ]party/i },
  { intent: "application", re: /applicat|which app|per app|service|business unit/i },
  { intent: "cve", re: /\bcve\b|advisory|cvss|top vulnerab|worst vulnerab/i },
  { intent: "overview", re: /overview|summary|posture|executive|dashboard|health|overall risk|report/i },
];

export function detectIntent(q: string): Intent | null {
  const query = q.trim();
  if (query.length < 3) return null;
  for (const r of INTENT_RULES) if (r.re.test(query)) return r.intent;
  if (/\b(how many|count|list|show|which|breakdown|distribut|group by|analyz|analys)\b/i.test(query)) return "search";
  return null;
}

/* ---------------------------- natural-language filter -------------------------- */
const STOP = new Set([
  "show","me","all","the","list","which","what","how","many","are","is","in","of","for","with","and","or","that",
  "have","has","from","to","a","an","components","component","vulnerabilities","vulnerability","dataset","please",
  "give","find","get","report","on","by","top","most","critical","high","medium","low","severity","cve","cves",
  "analyze","analyse","summary","summarize","count","group","breakdown","affected","risk","score","open","fix","fixed",
]);

export function nlFilter(rows: Row[], query: string): { rows: Row[]; describe: string[] } {
  const q = query.toLowerCase();
  const describe: string[] = [];
  let out = rows;

  const sevWanted: SevKey[] = [];
  for (const s of ["critical", "high", "medium", "low"] as SevKey[]) {
    if (new RegExp(`\\b${s}\\b`).test(q)) sevWanted.push(s);
  }
  if (sevWanted.length) {
    out = out.filter((r) => sevWanted.includes(factsOf(r).severity));
    describe.push(`severity in [${sevWanted.join(", ")}]`);
  }

  const cmp = q.match(/cvss\s*(>=|>|<=|<|=)?\s*(\d+(?:\.\d+)?)/);
  if (cmp) {
    const op = cmp[1] ?? ">=";
    const n = Number(cmp[2]);
    out = out.filter((r) => {
      const v = factsOf(r).cvss;
      return op === ">" ? v > n : op === "<" ? v < n : op === "<=" ? v <= n : op === "=" ? v === n : v >= n;
    });
    describe.push(`CVSS ${op} ${n}`);
  }

  const cveIds = q.toUpperCase().match(/CVE-\d{4}-\d{3,7}/g);
  if (cveIds?.length) {
    out = out.filter((r) => cveIds.some((id) => factsOf(r).blob.toUpperCase().includes(id)));
    describe.push(`CVE in [${cveIds.join(", ")}]`);
  }

  const quoted = [...q.matchAll(/"([^"]+)"|'([^']+)'/g)].map((m) => m[1] ?? m[2]).filter(Boolean);
  const terms = quoted.length
    ? quoted
    : q.replace(/[^a-z0-9.\s-]/g, " ").split(/\s+/).filter((w) => w.length > 3 && !STOP.has(w));
  const keywords = terms.slice(0, 4);
  if (keywords.length && !sevWanted.length && !cveIds?.length) {
    const hit = out.filter((r) => keywords.some((k) => factsOf(r).blob.includes(k)));
    if (hit.length) {
      out = hit;
      describe.push(`matching [${keywords.join(", ")}]`);
    }
  }
  return { rows: out, describe };
}

/* ------------------------------------ helpers --------------------------------- */
function counts(rows: Row[]) {
  const c: Record<SevKey, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, none: 0 };
  for (const r of rows) c[factsOf(r).severity]++;
  return c;
}

function groupTop(rows: Row[], key: (f: Facts) => string, limit = 8) {
  const m = new Map<string, number>();
  for (const r of rows) {
    const v = key(factsOf(r));
    if (!v) continue;
    m.set(v, (m.get(v) ?? 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit);
}

export function riskScore(rows: Row[]) {
  const c = counts(rows);
  const total = Math.max(1, rows.length);
  const weighted = c.critical * 10 + c.high * 6 + c.medium * 3 + c.low * 1;
  const score = Math.max(0, Math.min(100, Math.round(100 - (weighted / (total * 10)) * 100)));
  return score;
}

const sevChart = (c: Record<SevKey, number>): ChartSpec => ({
  kind: "donut",
  title: "Severity distribution",
  data: (["critical", "high", "medium", "low", "info", "none"] as SevKey[])
    .filter((k) => c[k] > 0)
    .map((k) => ({ name: k[0].toUpperCase() + k.slice(1), value: c[k], color: SEV_HEX[k] })),
});

const sevKpis = (c: Record<SevKey, number>): Kpi[] => [
  { label: "Critical", value: c.critical, tone: "critical" },
  { label: "High", value: c.high, tone: "high" },
  { label: "Medium", value: c.medium, tone: "medium" },
  { label: "Low", value: c.low, tone: "low" },
];

function tableOf(title: string, rows: Row[], limit = 200): TableSpec {
  const cols = ["Component", "Version", "CVE", "Severity", "CVSS", "Application", "Vendor", "Fix"];
  return {
    title,
    columns: cols,
    rows: rows.slice(0, limit).map((r) => {
      const f = factsOf(r);
      return [f.component || "—", f.version, f.cve, f.severity === "none" ? "" : f.severity, f.cvss || "", f.application, f.vendor, f.fix];
    }),
  };
}

/* ----------------------------------- main entry -------------------------------- */
export function buildReport(
  query: string,
  ctx: { datasetName: string; rows: Row[] },
): AnalysisReport | null {
  const intent = detectIntent(query);
  if (!intent) return null;
  const all = ctx.rows;
  if (!all.length) return null;

  const generatedAt = new Date().toISOString();
  const base = { intent, datasetName: ctx.datasetName, generatedAt } as const;

  const facts = all.map(factsOf);
  const c = counts(all);
  const score = riskScore(all);

  if (intent === "exploitable") {
    const hits = all.filter((_, i) => facts[i].kev || facts[i].exploit || facts[i].cvss >= 9 || facts[i].severity === "critical");
    return {
      ...base,
      title: "Exploitable & Actively Targeted Exposure",
      matchedRows: hits.length,
      summary: [
        `${hits.length} of ${all.length} records show signs of exploitability (KEV/CISA flags, public exploit indicators, or CVSS ≥ 9).`,
        hits.length ? "These represent the highest-probability attack paths and should bypass the normal patch queue." : "No exploit indicators were detected in this dataset.",
      ],
      kpis: [
        { label: "Exploitable", value: hits.length, tone: "critical" },
        { label: "KEV flagged", value: hits.filter((_, i) => factsOf(hits[i]).kev).length, tone: "critical" },
        { label: "CVSS ≥ 9", value: all.filter((_, i) => facts[i].cvss >= 9).length, tone: "high" },
        { label: "Exposure rate", value: `${Math.round((hits.length / all.length) * 100)}%`, tone: "primary" },
      ],
      charts: [sevChart(counts(hits)), { kind: "bar", title: "Exploitable by application", data: groupTop(hits, (f) => f.application).map(([name, value]) => ({ name, value })) }],
      tables: [tableOf("Exploitable findings", hits.sort((a, b) => factsOf(b).cvss - factsOf(a).cvss))],
      recommendations: [
        { priority: "P0", text: "Patch or isolate every KEV-listed component within 72 hours per CISA BOD 22-01 guidance." },
        { priority: "P1", text: "Add virtual patching / WAF rules for internet-facing components pending upgrade." },
        { priority: "P2", text: "Enable exploit-signature monitoring on hosts running the affected components." },
      ],
    };
  }

  if (intent === "eol") {
    const hits = all.filter((_, i) => facts[i].eol);
    const byVendor = groupTop(hits, (f) => f.vendor);
    return {
      ...base,
      title: "End-of-Life & Unsupported Components",
      matchedRows: hits.length,
      summary: [
        `${hits.length} records reference end-of-life, deprecated or unsupported software.`,
        "EOL components receive no security fixes, so every future CVE against them is permanently unpatchable.",
      ],
      kpis: [
        { label: "EOL records", value: hits.length, tone: "critical" },
        { label: "Distinct components", value: new Set(hits.map((r) => factsOf(r).component)).size, tone: "high" },
        { label: "Vendors affected", value: byVendor.length, tone: "medium" },
        { label: "Share of dataset", value: `${Math.round((hits.length / all.length) * 100)}%`, tone: "primary" },
      ],
      charts: [
        { kind: "bar", title: "EOL by vendor", data: byVendor.map(([name, value]) => ({ name, value })) },
        sevChart(counts(hits)),
      ],
      tables: [tableOf("EOL / unsupported inventory", hits)],
      recommendations: [
        { priority: "P0", text: "Define migration targets for EOL components carrying Critical or High findings." },
        { priority: "P1", text: "Freeze new deployments that introduce EOL dependencies via a build-time policy gate." },
        { priority: "P2", text: "Track vendor support calendars to forecast the next 12 months of EOL transitions." },
      ],
    };
  }

  if (intent === "license") {
    const withLic = all.filter((_, i) => facts[i].license);
    const byLic = groupTop(withLic, (f) => f.license, 10);
    const copyleft = withLic.filter((r) => /gpl|agpl|lgpl|sspl|cc-by-sa|epl|mpl/i.test(factsOf(r).license));
    return {
      ...base,
      title: "License & Legal Exposure",
      matchedRows: withLic.length,
      summary: [
        `${withLic.length} components declare a license; ${byLic.length} distinct license identifiers were observed.`,
        copyleft.length
          ? `${copyleft.length} components use copyleft-family licenses that can impose source-disclosure obligations on distributed products.`
          : "No copyleft-family licenses were detected.",
      ],
      kpis: [
        { label: "Licensed", value: withLic.length, tone: "primary" },
        { label: "Unknown license", value: all.length - withLic.length, tone: "medium" },
        { label: "Copyleft", value: copyleft.length, tone: "high" },
        { label: "Distinct licenses", value: byLic.length, tone: "low" },
      ],
      charts: [{ kind: "donut", title: "License distribution", data: byLic.map(([name, value]) => ({ name, value })) }],
      tables: [
        { title: "License breakdown", columns: ["License", "Components"], rows: byLic.map(([n, v]) => [n, v]) },
        tableOf("Copyleft-licensed components", copyleft),
      ],
      recommendations: [
        { priority: "P1", text: "Legal review for copyleft components shipped in distributed artifacts." },
        { priority: "P2", text: "Resolve unknown-license components — unknown licenses block SBOM attestation." },
        { priority: "P3", text: "Publish an approved-license allowlist and enforce it in CI." },
      ],
    };
  }

  if (intent === "compliance") {
    const unpatched = all.filter((_, i) => !facts[i].fix);
    const openItems = all.filter((_, i) => !/closed|resolved|fixed|mitigat|patched/i.test(facts[i].status));
    const licensed = all.filter((_, i) => facts[i].license).length;
    const identified = all.filter((_, i) => facts[i].component && facts[i].version).length;
    const completeness = Math.round((identified / all.length) * 100);
    return {
      ...base,
      title: "Compliance & Control Readiness",
      matchedRows: all.length,
      summary: [
        `SBOM completeness is ${completeness}% (records with both component name and version) — NTIA minimum-elements guidance expects near-100%.`,
        `${c.critical + c.high} Critical/High findings remain, of which ${unpatched.length} records carry no documented fix or remediation owner.`,
        `Overall security score: ${score}/100.`,
      ],
      kpis: [
        { label: "SBOM completeness", value: `${completeness}%`, tone: completeness > 90 ? "low" : "medium" },
        { label: "License coverage", value: `${Math.round((licensed / all.length) * 100)}%`, tone: "primary" },
        { label: "Open findings", value: openItems.length, tone: "high" },
        { label: "No fix documented", value: unpatched.length, tone: "critical" },
      ],
      charts: [
        sevChart(c),
        {
          kind: "bar",
          title: "Control readiness (%)",
          data: [
            { name: "Inventory", value: completeness },
            { name: "License", value: Math.round((licensed / all.length) * 100) },
            { name: "Remediation", value: Math.round(((all.length - unpatched.length) / all.length) * 100) },
            { name: "Risk score", value: score },
          ],
        },
      ],
      tables: [tableOf("Findings without documented remediation", unpatched)],
      recommendations: [
        { priority: "P0", text: "Assign a remediation owner and target date to every Critical/High finding (ISO 27001 A.8.8)." },
        { priority: "P1", text: "Fill missing version and license fields to satisfy NTIA minimum SBOM elements." },
        { priority: "P2", text: "Automate SBOM regeneration per release so evidence stays audit-current." },
        { priority: "P3", text: "Retain quarterly SBOM snapshots as compliance evidence." },
      ],
    };
  }

  if (intent === "remediation") {
    const ranked = [...all]
      .map((r, i) => ({ r, f: facts[i] }))
      .sort((a, b) => {
        const w = (f: Facts) => (f.severity === "critical" ? 4 : f.severity === "high" ? 3 : f.severity === "medium" ? 2 : 1) * 10 + f.cvss + (f.kev || f.exploit ? 15 : 0);
        return w(b.f) - w(a.f);
      });
    const quickWins = ranked.filter((x) => x.f.fix).slice(0, 25);
    return {
      ...base,
      title: "Prioritized Remediation Plan",
      matchedRows: all.length,
      summary: [
        `${c.critical} Critical and ${c.high} High findings drive the current risk score of ${score}/100.`,
        `${quickWins.length} findings already have a known fix version and can be closed immediately.`,
      ],
      kpis: [
        ...sevKpis(c).slice(0, 2),
        { label: "Fix available", value: all.filter((_, i) => facts[i].fix).length, tone: "low" },
        { label: "Risk score", value: `${score}/100`, tone: "primary" },
      ],
      charts: [sevChart(c), { kind: "bar", title: "Workload by application", data: groupTop(all, (f) => f.application).map(([name, value]) => ({ name, value })) }],
      tables: [
        tableOf("Sprint 1 — top 25 by risk weight", ranked.slice(0, 25).map((x) => x.r)),
        tableOf("Quick wins — fix version known", quickWins.map((x) => x.r)),
      ],
      recommendations: [
        { priority: "P0", text: `Remediate the ${c.critical} Critical findings this week; escalate any that are internet-facing.` },
        { priority: "P1", text: `Schedule ${c.high} High findings into the current sprint, batching by application owner.` },
        { priority: "P2", text: "Automate dependency upgrades for the quick-win set to prevent regression." },
        { priority: "P3", text: "Re-scan after deployment and re-import the SBOM to verify closure." },
      ],
    };
  }

  if (intent === "vendor" || intent === "application") {
    const byApp = intent === "vendor";
    const grp = groupTop(all, (f) => (byApp ? f.vendor : f.application), 10);
    const critByGroup = groupTop(all.filter((_, i) => facts[i].severity === "critical" || facts[i].severity === "high"), (f) => (byApp ? f.vendor : f.application), 10);
    const label = byApp ? "Vendor" : "Application";
    return {
      ...base,
      title: `${label} Risk Concentration`,
      matchedRows: all.length,
      summary: [
        grp.length ? `${grp[0][0]} carries the largest share with ${grp[0][1]} records.` : `No ${label.toLowerCase()} field detected in this dataset.`,
        `Risk is spread across ${grp.length}+ ${label.toLowerCase()}s; concentration indicates where a single upgrade removes the most exposure.`,
      ],
      kpis: [
        { label: `${label}s`, value: grp.length, tone: "primary" },
        { label: `Top ${label.toLowerCase()}`, value: grp[0]?.[0] ?? "—", sub: `${grp[0]?.[1] ?? 0} records`, tone: "high" },
        { label: "Critical", value: c.critical, tone: "critical" },
        { label: "High", value: c.high, tone: "high" },
      ],
      charts: [
        { kind: "bar", title: `Records by ${label.toLowerCase()}`, data: grp.map(([name, value]) => ({ name, value })) },
        { kind: "bar", title: `Critical + High by ${label.toLowerCase()}`, data: critByGroup.map(([name, value]) => ({ name, value })) },
      ],
      tables: [{ title: `${label} breakdown`, columns: [label, "Records", "Critical + High"], rows: grp.map(([n, v]) => [n, v, critByGroup.find(([m]) => m === n)?.[1] ?? 0]) }],
      recommendations: [
        { priority: "P1", text: `Open a consolidated upgrade track with ${grp[0]?.[0] ?? "the top " + label.toLowerCase()} to clear multiple findings at once.` },
        { priority: "P2", text: `Require security attestations from ${label.toLowerCase()}s in the top quartile of exposure.` },
      ],
    };
  }

  if (intent === "cve") {
    const withCve = all.filter((_, i) => facts[i].cve);
    const ranked = [...withCve].sort((a, b) => factsOf(b).cvss - factsOf(a).cvss);
    const distinct = new Set(withCve.map((r) => factsOf(r).cve));
    const avg = withCve.length ? withCve.reduce((s, r) => s + factsOf(r).cvss, 0) / withCve.length : 0;
    return {
      ...base,
      title: "Vulnerability (CVE) Analysis",
      matchedRows: withCve.length,
      summary: [
        `${distinct.size} distinct CVEs across ${withCve.length} records; mean CVSS ${avg.toFixed(1)}.`,
        ranked.length ? `Highest scoring: ${factsOf(ranked[0]).cve} (CVSS ${factsOf(ranked[0]).cvss}) on ${factsOf(ranked[0]).component}.` : "",
      ].filter(Boolean),
      kpis: [
        { label: "Distinct CVEs", value: distinct.size, tone: "primary" },
        { label: "Mean CVSS", value: avg.toFixed(1), tone: avg >= 7 ? "high" : "medium" },
        { label: "CVSS ≥ 9", value: withCve.filter((r) => factsOf(r).cvss >= 9).length, tone: "critical" },
        { label: "Critical", value: c.critical, tone: "critical" },
      ],
      charts: [sevChart(c), { kind: "bar", title: "Top components by CVE count", data: groupTop(withCve, (f) => f.component).map(([name, value]) => ({ name, value })) }],
      tables: [tableOf("CVEs ranked by CVSS", ranked)],
      recommendations: [
        { priority: "P0", text: "Triage all CVSS ≥ 9.0 findings against reachability before scheduling." },
        { priority: "P1", text: "Cross-check top CVEs against CISA KEV and EPSS for exploit likelihood." },
      ],
    };
  }

  if (intent === "search") {
    const { rows: hits, describe } = nlFilter(all, query);
    const hc = counts(hits);
    return {
      ...base,
      title: "Query Result",
      matchedRows: hits.length,
      summary: [
        `${hits.length} of ${all.length} records matched${describe.length ? ` (${describe.join("; ")})` : ""}.`,
        `Within the result set: ${hc.critical} Critical, ${hc.high} High, ${hc.medium} Medium, ${hc.low} Low.`,
      ],
      kpis: [{ label: "Matches", value: hits.length, tone: "primary" }, ...sevKpis(hc).slice(0, 3)],
      charts: [sevChart(hc), { kind: "bar", title: "Matches by application", data: groupTop(hits, (f) => f.application).map(([name, value]) => ({ name, value })) }],
      tables: [tableOf("Matching records", hits)],
      recommendations: hc.critical
        ? [{ priority: "P0", text: `${hc.critical} Critical records in this result set need immediate triage.` }]
        : [{ priority: "P2", text: "No Critical findings in this result set — continue routine monitoring." }],
    };
  }

  // overview
  const topComp = groupTop(all, (f) => f.component);
  return {
    ...base,
    title: "Executive Risk Overview",
    matchedRows: all.length,
    summary: [
      `${all.length} records analyzed across ${new Set(facts.map((f) => f.component)).size} distinct components.`,
      `Overall security score is ${score}/100 with ${c.critical} Critical and ${c.high} High findings.`,
      `${all.filter((_, i) => facts[i].eol).length} records flag end-of-life software and ${all.filter((_, i) => facts[i].kev || facts[i].exploit).length} show exploit indicators.`,
    ],
    kpis: [
      { label: "Records", value: all.length, tone: "primary" },
      { label: "Risk score", value: `${score}/100`, tone: score > 70 ? "low" : score > 40 ? "medium" : "critical" },
      { label: "Critical", value: c.critical, tone: "critical" },
      { label: "High", value: c.high, tone: "high" },
    ],
    charts: [
      sevChart(c),
      { kind: "bar", title: "Top components by findings", data: topComp.map(([name, value]) => ({ name, value })) },
    ],
    tables: [tableOf("Highest-risk records", [...all].sort((a, b) => factsOf(b).cvss - factsOf(a).cvss))],
    recommendations: [
      { priority: "P0", text: `Close the ${c.critical} Critical findings; they contribute most to the risk score.` },
      { priority: "P1", text: "Assign owners for High findings and set 30-day SLAs." },
      { priority: "P2", text: "Replace or upgrade end-of-life components to restore patchability." },
      { priority: "P3", text: "Re-import the SBOM after each release to keep the posture current." },
    ],
  };
}
