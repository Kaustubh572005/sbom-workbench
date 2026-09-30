import type { ComponentProfile } from "@/lib/platform-intel";
import type { NvdRecord } from "@/lib/nist-nvd.functions";
import { daysBetween, daysToEol, fmtDate, lifecycleStage, lookupEolDate, toDate } from "@/lib/lifecycle-dates";

export type Finding = {
  id: string;
  application: string;
  component: string;
  version: string;
  cve: string;
  cveCount: number;
  cvss: number;
  vector: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
  cvePublished: string;
  cveAgeDays: number | null;
  eolDate: string;
  daysToEol: number | null;
  lastUpdate: string;
  exploit: boolean;
  exploitDate: string;
  remediationStatus: string;
  lifecycle: string;
  riskScore: number;
  priority: "P0" | "P1" | "P2" | "P3" | "—";
  targetDate: string;
  recommendation: string;
  tone: "red" | "yellow" | "green" | "gray";
  source: string;
};

export const cveIds = (s: string) =>
  [...new Set((s.match(/CVE-\d{4}-\d{4,}/gi) ?? []).map((c) => c.toUpperCase()))];

const sev = (s: number): Finding["severity"] =>
  s >= 9 ? "CRITICAL" : s >= 7 ? "HIGH" : s >= 4 ? "MEDIUM" : s > 0 ? "LOW" : "NONE";

const PRIORITY_DAYS = { P0: 5, P1: 30, P2: 90, P3: 180 } as const;

export function buildFindings(profiles: ComponentProfile[], nvd: Record<string, NvdRecord>, now = new Date()): Finding[] {
  return profiles.map((p) => {
    const ids = cveIds(`${p.cve} ${(p.record.intel.advisoryIds ?? []).join(" ")}`);
    const recs = ids.map((i) => nvd[i]).filter(Boolean) as NvdRecord[];
    const top = [...recs].sort((a, b) => b.cvss - a.cvss)[0];
    const cvss = Math.max(top?.cvss ?? 0, p.cvss || 0);
    const cvePublished = top?.published || (toDate(p.record.published) ? fmtDate(toDate(p.record.published)) : "");
    const pub = toDate(cvePublished);
    const cveAgeDays = pub ? daysBetween(pub, now) : null;
    const eol = p.eolDate || p.record.intel.eolDate || lookupEolDate(p.name, p.version) || "";
    const dte = daysToEol(eol, now);
    const exploitDate = recs.map((r) => r.exploitDate).filter(Boolean).sort().reverse()[0] ?? "";
    const exploit = Boolean(exploitDate) || p.kev || p.exploit;

    // NIST-weighted risk: CVSS 40 / EOL 30 / Exploit 20 / Lifecycle 10
    const cvssF = (cvss / 10) * 40;
    const eolF = dte === null ? 0 : dte < 0 ? 30 * Math.min(1, 0.5 + -dte / 730) : dte <= 90 ? 18 : dte <= 365 ? 8 : 0;
    const expF = exploit ? 20 : 0;
    const stage = lifecycleStage(dte);
    const lcF = stage === "Past EOL" ? 10 : stage === "Security Only" ? 6 : /deprecated|unsupported|legacy/i.test(p.lifecycleStatus) ? 8 : 0;
    const riskScore = Math.round(cvssF + eolF + expF + lcF);

    let priority: Finding["priority"] = "—";
    if (cvss >= 9 && exploit) priority = "P0";
    else if (cvss >= 7 || (dte !== null && dte < -365)) priority = "P1";
    else if (cvss >= 4 || (dte !== null && dte <= 90)) priority = "P2";
    else if (cvss > 0 || dte !== null) priority = "P3";
    const targetDate = priority === "—" ? "" : fmtDate(new Date(now.getTime() + PRIORITY_DAYS[priority] * 86_400_000));

    let tone: Finding["tone"] = "gray";
    if ((cveAgeDays !== null && cveAgeDays < 30) || (dte !== null && dte < -365) || (dte !== null && dte < 0)) tone = "red";
    else if ((cveAgeDays !== null && cveAgeDays <= 180) || (dte !== null && dte < 90)) tone = "yellow";
    else if (cveAgeDays !== null || dte !== null) tone = "green";

    const target = p.targetVersion || p.latestVersion;
    const recommendation =
      priority === "P0" ? `Emergency patch within 5 days${target ? ` → ${target}` : ""}`
      : priority === "P1" ? (dte !== null && dte < -365 ? `Replace/upgrade — ${-dte} days past EOL` : `Patch within 30 days${target ? ` → ${target}` : ""}`)
      : priority === "P2" ? (dte !== null && dte <= 90 && dte >= 0 ? `Plan upgrade — EOL in ${dte} days` : `Remediate within 90 days`)
      : priority === "P3" ? "Track in backlog; review quarterly" : "No action required";

    return {
      id: p.id, application: p.application, component: p.name, version: p.version,
      cve: ids[0] ?? "", cveCount: ids.length, cvss, vector: top?.vector ?? "", severity: sev(cvss),
      cvePublished, cveAgeDays, eolDate: eol ? fmtDate(toDate(eol)) || eol : "", daysToEol: dte,
      lastUpdate: top?.lastModified || p.record.intel.updatedAt?.slice(0, 10) || "",
      exploit, exploitDate, remediationStatus: p.remediationStatus || "—", lifecycle: stage,
      riskScore, priority, targetDate, recommendation, tone,
      source: [top ? "NIST NVD" : "", exploitDate ? "CISA KEV" : "", eol ? "Lifecycle DB" : ""].filter(Boolean).join(" · ") || p.evidenceSource || "Uploaded",
    };
  });
}

export function timelineByMonth(fs: Finding[]) {
  const m = new Map<string, { month: string; cves: number; exploits: number; eol: number }>();
  const add = (d: string, k: "cves" | "exploits" | "eol") => {
    if (!d) return; const key = d.slice(0, 7);
    const e = m.get(key) ?? { month: key, cves: 0, exploits: 0, eol: 0 }; e[k]++; m.set(key, e);
  };
  fs.forEach((f) => { add(f.cvePublished, "cves"); add(f.exploitDate, "exploits"); add(f.eolDate, "eol"); });
  return [...m.values()].sort((a, b) => a.month.localeCompare(b.month));
}

export type ComplianceItem = { framework: "SEBI CSCRF" | "CERT-In"; control: string; status: "Compliant" | "Non-compliant" | "At risk"; detail: string; action: string };

export function complianceCheck(fs: Finding[], now = new Date()): ComplianceItem[] {
  const withCve = fs.filter((f) => f.cve);
  const scored = withCve.filter((f) => f.cvss > 0);
  const dated = fs.filter((f) => f.cvePublished || f.eolDate);
  const tracked = fs.filter((f) => f.remediationStatus && f.remediationStatus !== "—");
  const crit = fs.filter((f) => f.cvss >= 9);
  const critOverdue = crit.filter((f) => f.cveAgeDays !== null && f.cveAgeDays > 30);
  const critSoon = crit.filter((f) => f.cveAgeDays !== null && f.cveAgeDays > 20 && f.cveAgeDays <= 30);
  const kevOpen = fs.filter((f) => f.exploit);
  const pct = (a: number, b: number) => (b ? Math.round((a / b) * 100) : 100);
  void now;
  return [
    { framework: "SEBI CSCRF", control: "Software inventory maintained", status: fs.length ? "Compliant" : "Non-compliant", detail: `${fs.length} components inventoried`, action: fs.length ? "Keep SBOM updated each release" : "Upload SBOM inventory" },
    { framework: "SEBI CSCRF", control: "Vulnerabilities identified", status: withCve.length ? "Compliant" : "At risk", detail: `${withCve.length} components mapped to CVEs`, action: "Run continuous CVE matching" },
    { framework: "SEBI CSCRF", control: "Risk prioritisation (CVSS)", status: pct(scored.length, withCve.length) >= 90 ? "Compliant" : pct(scored.length, withCve.length) >= 60 ? "At risk" : "Non-compliant", detail: `${pct(scored.length, withCve.length)}% of CVEs carry a CVSS score`, action: "Refresh NIST NVD scores" },
    { framework: "SEBI CSCRF", control: "Remediation tracked", status: pct(tracked.length, fs.length) >= 80 ? "Compliant" : "At risk", detail: `${pct(tracked.length, fs.length)}% have a remediation status`, action: "Record remediation status per finding" },
    { framework: "SEBI CSCRF", control: "Audit evidence (dates, sources)", status: pct(dated.length, fs.length) >= 70 ? "Compliant" : "At risk", detail: `${pct(dated.length, fs.length)}% of findings dated`, action: "Capture CVE/EOL dates for all components" },
    { framework: "CERT-In", control: "Known exploited vulnerabilities mitigated", status: kevOpen.length ? "Non-compliant" : "Compliant", detail: `${kevOpen.length} components with public/KEV exploits`, action: kevOpen.length ? "Patch exploited components immediately" : "Continue monitoring KEV" },
    { framework: "CERT-In", control: "CVSS used for prioritisation", status: scored.length ? "Compliant" : "At risk", detail: `${scored.length} CVSS-scored findings`, action: "Prioritise using CVSS v3.1" },
    { framework: "CERT-In", control: "Critical (CVSS ≥ 9) fixed within 30 days", status: critOverdue.length ? "Non-compliant" : critSoon.length ? "At risk" : "Compliant", detail: `${critOverdue.length} overdue · ${critSoon.length} nearing deadline · ${crit.length} critical total`, action: critOverdue.length ? "Escalate overdue critical CVEs" : "Maintain 30-day SLA" },
  ];
}
