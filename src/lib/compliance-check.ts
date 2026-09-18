/**
 * Compliance checking against SEBI CSCRF and CERT-In expectations.
 * Pure evaluation over NIST-scored findings — no IO.
 */

import type { NistFinding } from "@/lib/date-intel";

export type ComplianceState = "compliant" | "at-risk" | "non-compliant";

export type ComplianceControl = {
  id: string;
  framework: "SEBI CSCRF" | "CERT-In";
  requirement: string;
  state: ComplianceState;
  evidence: string;
  gap: string;
  remediation: string;
};

export type ComplianceReport = {
  controls: ComplianceControl[];
  compliant: number;
  atRisk: number;
  nonCompliant: number;
  score: number;
  generatedAt: string;
  summary: string;
};

export type ComplianceRow = {
  component: string;
  version: string;
  application: string;
  license: string;
  supplier: string;
  remediationStatus: string;
  finding: NistFinding;
};

export function checkCompliance(rows: ComplianceRow[], now = new Date()): ComplianceReport {
  const total = rows.length;
  const withCve = rows.filter((r) => r.finding.cveId);
  const withCvss = rows.filter((r) => r.finding.cvss > 0);
  const withDates = rows.filter((r) => r.finding.cvePublished || r.finding.eolDate);
  const missingVersion = rows.filter((r) => !r.version);
  const missingSupplier = rows.filter((r) => !r.supplier);
  const missingLicense = rows.filter((r) => !r.license);
  const pastEol = rows.filter((r) => r.finding.daysPastEol != null);
  const criticals = rows.filter((r) => r.finding.cvss >= 9);
  const criticalsOverdue = criticals.filter((r) => (r.finding.cveAgeDays ?? 0) > 30);
  const untracked = rows.filter((r) => !r.remediationStatus || /unknown/i.test(r.remediationStatus));
  const pct = (n: number) => (total ? Math.round((n / total) * 100) : 0);

  const controls: ComplianceControl[] = [
    {
      id: "SEBI-1",
      framework: "SEBI CSCRF",
      requirement: "Complete software inventory maintained (SBOM)",
      state: total === 0 ? "non-compliant" : missingVersion.length + missingSupplier.length === 0 ? "compliant" : "at-risk",
      evidence: `${total.toLocaleString()} components inventoried`,
      gap: missingVersion.length || missingSupplier.length
        ? `${missingVersion.length} missing version, ${missingSupplier.length} missing supplier`
        : "",
      remediation: "Complete version and supplier metadata for every component in the SBOM.",
    },
    {
      id: "SEBI-2",
      framework: "SEBI CSCRF",
      requirement: "Known vulnerabilities identified with CVE references",
      state: total === 0 ? "non-compliant" : withCve.length ? (pct(withCve.length) >= 60 ? "compliant" : "at-risk") : "non-compliant",
      evidence: `${withCve.length.toLocaleString()} components carry CVE identifiers (${pct(withCve.length)}%)`,
      gap: withCve.length === total ? "" : `${(total - withCve.length).toLocaleString()} components have no CVE lookup result`,
      remediation: "Run NVD enrichment for all components so every finding carries a CVE reference or a clean result.",
    },
    {
      id: "SEBI-3",
      framework: "SEBI CSCRF",
      requirement: "Risk prioritisation using CVSS base scores",
      state: withCvss.length ? (pct(withCvss.length) >= 50 ? "compliant" : "at-risk") : "non-compliant",
      evidence: `${withCvss.length.toLocaleString()} findings scored with CVSS v3.1`,
      gap: withCvss.length === total ? "" : `${(total - withCvss.length).toLocaleString()} findings unscored`,
      remediation: "Fetch CVSS base scores and vectors from NIST NVD for all remaining components.",
    },
    {
      id: "SEBI-4",
      framework: "SEBI CSCRF",
      requirement: "Remediation status tracked per finding",
      state: untracked.length === 0 ? "compliant" : untracked.length > total / 2 ? "non-compliant" : "at-risk",
      evidence: `${(total - untracked.length).toLocaleString()} findings have a remediation status`,
      gap: untracked.length ? `${untracked.length.toLocaleString()} findings without remediation status` : "",
      remediation: "Assign an owner and remediation status to every open finding.",
    },
    {
      id: "SEBI-5",
      framework: "SEBI CSCRF",
      requirement: "Audit evidence retained with dates and sources",
      state: withDates.length ? (pct(withDates.length) >= 60 ? "compliant" : "at-risk") : "non-compliant",
      evidence: `${withDates.length.toLocaleString()} findings carry publication or lifecycle dates`,
      gap: withDates.length === total ? "" : `${(total - withDates.length).toLocaleString()} findings undated`,
      remediation: "Record CVE publication and EOL dates with their evidence source for every finding.",
    },
    {
      id: "CERTIN-1",
      framework: "CERT-In",
      requirement: "Critical vulnerabilities (CVSS ≥ 9) remediated within 30 days",
      state: criticals.length === 0 ? "compliant" : criticalsOverdue.length ? "non-compliant" : "at-risk",
      evidence: `${criticals.length} critical findings, ${criticalsOverdue.length} older than 30 days`,
      gap: criticalsOverdue.length ? `${criticalsOverdue.length} critical findings breach the 30-day window` : "",
      remediation: "Patch or isolate every CVSS ≥ 9 finding immediately; document compensating controls.",
    },
    {
      id: "CERTIN-2",
      framework: "CERT-In",
      requirement: "No end-of-life software in production",
      state: pastEol.length === 0 ? "compliant" : pastEol.length > total / 4 ? "non-compliant" : "at-risk",
      evidence: `${pastEol.length.toLocaleString()} components are past their EOL date`,
      gap: pastEol.length ? `${pastEol.length.toLocaleString()} unsupported components in scope` : "",
      remediation: "Upgrade or replace past-EOL components; document exceptions with a target date.",
    },
    {
      id: "CERTIN-3",
      framework: "CERT-In",
      requirement: "Licence obligations documented for all third-party code",
      state: missingLicense.length === 0 ? "compliant" : missingLicense.length > total / 3 ? "non-compliant" : "at-risk",
      evidence: `${(total - missingLicense.length).toLocaleString()} components have a declared licence`,
      gap: missingLicense.length ? `${missingLicense.length.toLocaleString()} components without licence data` : "",
      remediation: "Resolve undeclared licences with the supplier or package registry.",
    },
  ];

  const compliant = controls.filter((c) => c.state === "compliant").length;
  const atRisk = controls.filter((c) => c.state === "at-risk").length;
  const nonCompliant = controls.filter((c) => c.state === "non-compliant").length;
  const score = Math.round(((compliant + atRisk * 0.5) / controls.length) * 100);

  return {
    controls,
    compliant,
    atRisk,
    nonCompliant,
    score,
    generatedAt: now.toISOString(),
    summary: `${compliant} of ${controls.length} controls met, ${atRisk} at risk, ${nonCompliant} not met — readiness ${score}%.`,
  };
}
