/**
 * Vulnerability Intelligence engine.
 * Pure, dependency-free analytics over SBOM/VAPT rows. Computes every metric
 * shown on the Vulnerability Intelligence Center: severity spread, at-risk
 * applications/vendors/components, hygiene gaps, EOL, compliance, loopholes,
 * scores and fix recommendations. Designed to stay fast on 100k+ rows.
 */

import { factsOf, sevOf, type SevKey } from "@/lib/risk-intel";
import { daysToEol, resolveLifecycleDates } from "@/lib/lifecycle-dates";
import { nistRisk, resolveSeverity, type RiskFactor, type ScoreSource } from "@/lib/nist-scoring";
import { assessLifecycle, LIFECYCLE_STATUSES, REMEDIATION_STATUSES, type LifecycleAssessment, type LifecycleStatus, type RemediationStatus } from "@/lib/lifecycle-intel";

export type Row = Record<string, unknown>;

export type Enrichment = {
  kev?: boolean;
  exploitAvailable?: boolean;
  fixedVersion?: string;
  latestVersion?: string;
  eolDate?: string;
  supportEndDate?: string;
  /** where the EOL / EOS dates came from (uploaded file, endoflife.date, curated vendor data) */
  eolSource?: string;
  eosSource?: string;
  /** NIST NVD: CVSS v3.x base score, vector and dates for the record's CVE(s) */
  cvss?: number;
  cvssVector?: string;
  cvePublished?: string;
  advisoryIds?: string[];
  summary?: string;
  updatedAt?: string;
  source?: string;
};

export type SeveritySource = ScoreSource;

export type VulnRecord = {
  id: string;
  raw: Row;
  component: string;
  version: string;
  vendor: string;
  application: string;
  cve: string;
  cvss: number;
  severity: SevKey;
  cvssVector: string;
  /** where the CVSS score (and so the NIST severity band) came from */
  severitySource: SeveritySource;
  /** severity label found in the uploaded file — informational, never overrides NIST */
  declaredSeverity: SevKey;
  /** what makes up the 0-100 risk score, for transparency in UI and exports */
  riskFactors: RiskFactor[];
  license: string;
  fix: string;
  status: string;
  published: string;
  eol: boolean;
  kev: boolean;
  exploit: boolean;
  /** external intelligence merged in (never overwrites uploaded fields) */
  intel: Enrichment;
  fixAvailable: boolean;
  fixedVersion: string;
  latestSafeVersion: string;
  patchPriority: "P0" | "P1" | "P2" | "P3";
  remediation: string;
  upgradeRecommendation: string;
  businessImpact: "Severe" | "High" | "Moderate" | "Low";
  riskScore: number;
  riskReduction: number;
  exploitStatus: string;
  blob: string;
  /** lifecycle & remediation intelligence (replaces the old fix/no-fix model) */
  lifecycle: LifecycleAssessment;
};

const pick = (row: Row, names: string[]): string => {
  const norm = (s: string) => s.toLowerCase().replace(/[\s_-]/g, "");
  const keys = Object.keys(row);
  for (const n of names) {
    const k = keys.find((k) => norm(k) === norm(n)) ?? keys.find((k) => norm(k).includes(norm(n)));
    if (k) {
      const v = row[k];
      if (v != null && String(v).trim() !== "") return String(v).trim();
    }
  }
  return "";
};

const GPL_RE = /gpl|agpl|lgpl|sspl|cc-by-sa|epl|mpl/i;
const EXPOSED_RE = /internet|public|external|dmz|edge/i;
const OUTDATED_RE = /outdated|older version|update available|upgrade available|expired|obsolete/i;

export function toVulnRecord(id: string, raw: Row, feedIntel: Enrichment = {}): VulnRecord {
  const f = factsOf(raw);
  /* EOL / EOS: uploaded dates win, then the live vendor feed, then curated vendor data */
  const dates = resolveLifecycleDates(raw, f.component, f.version, feedIntel);
  const intel: Enrichment = {
    ...feedIntel,
    eolDate: dates.eol,
    supportEndDate: dates.eos,
    eolSource: dates.eolSource,
    eosSource: dates.eosSource,
  };
  const kev = f.kev || intel.kev === true;
  const exploit = f.exploit || intel.exploitAvailable === true;
  const fixedVersion = f.fix || intel.fixedVersion || "";
  const latestSafeVersion = intel.latestVersion || fixedVersion;
  const fixAvailable = Boolean(fixedVersion || latestSafeVersion);
  const eol = f.eol || Boolean(intel.eolDate) || Boolean(intel.supportEndDate);

  /* NIST scoring: CVSS (NVD → uploaded → vector) decides severity; a declared label is only a fallback */
  const declaredSeverity = f.severity;
  const nist = resolveSeverity({
    nvdScore: intel.cvss,
    uploadedScore: f.cvss,
    vector: intel.cvssVector || pick(raw, ["cvss vector", "vector string", "cvss3 vector", "cvss v3 vector", "vector"]),
    declared: declaredSeverity,
  });
  const sev: SevKey = nist.severity;

  const lifecycle = assessLifecycle({
    component: f.component,
    version: f.version,
    vendor: f.vendor,
    severity: sev,
    cvss: nist.score,
    kev,
    exploit,
    uploadedFix: f.fix,
    uploadedEol: f.eol,
    uploadedStatus: `${f.status} ${f.blob.slice(0, 400)}`,
    intel: {
      latestVersion: intel.latestVersion,
      fixedVersion: intel.fixedVersion,
      eolDate: intel.eolDate,
      supportEndDate: intel.supportEndDate,
      advisoryIds: intel.advisoryIds,
      source: intel.source,
      updatedAt: intel.updatedAt,
    },
  });

  const eolDays = daysToEol(intel.eolDate);
  const risk = nistRisk({
    resolved: nist,
    kev,
    exploit,
    pastEol: (eolDays !== null && eolDays < 0) || f.eol,
    unsupported: lifecycle.supportStatus === "Unsupported" || lifecycle.supportStatus === "Legacy Platform",
    exposed: EXPOSED_RE.test(f.blob),
  });
  const riskScore = risk.score;

  const patchPriority: VulnRecord["patchPriority"] =
    kev || exploit || sev === "critical" ? "P0" : sev === "high" ? "P1" : sev === "medium" ? "P2" : "P3";

  const businessImpact: VulnRecord["businessImpact"] =
    riskScore >= 85 ? "Severe" : riskScore >= 65 ? "High" : riskScore >= 40 ? "Moderate" : "Low";

  const upgradeRecommendation = latestSafeVersion
    ? `Upgrade ${f.component || "component"}${f.version ? ` ${f.version}` : ""} → ${latestSafeVersion}`
    : eol
      ? `Replace ${f.component || "component"} — no supported release available`
      : "No published fix — apply compensating controls";

  const remediation = fixAvailable
    ? `Patch to ${latestSafeVersion || fixedVersion}, redeploy affected services, re-scan to confirm closure.`
    : kev || exploit
      ? "No vendor fix: isolate the component, add WAF/virtual-patch rules and monitor for exploitation."
      : eol
        ? "Plan a migration to a supported alternative; the component will never receive fixes."
        : "Track the vendor advisory; re-evaluate at the next scan.";

  const exploitStatus = kev ? "KEV — actively exploited" : exploit ? "Public exploit" : nist.score >= 9 ? "High likelihood" : "No known exploit";


  return {
    id,
    raw,
    component: f.component,
    version: f.version,
    vendor: f.vendor,
    application: f.application,
    cve: f.cve,
    cvss: nist.score,
    cvssVector: nist.vector,
    severity: sev,
    severitySource: nist.source,
    declaredSeverity,
    riskFactors: risk.factors,
    license: f.license,
    fix: f.fix,
    status: f.status,
    published: pick(raw, ["published", "published date", "publisheddate", "date", "detected", "discovered"]),
    eol,
    kev,
    exploit,
    intel,
    fixAvailable,
    fixedVersion,
    latestSafeVersion,
    patchPriority,
    remediation,
    upgradeRecommendation,
    businessImpact,
    riskScore,
    riskReduction: Math.round(riskScore * (fixAvailable ? 0.9 : 0.35)),
    exploitStatus,
    blob: f.blob,
    lifecycle,
  };
}

/* ------------------------------- aggregate model ------------------------------- */
export type GroupRisk = {
  name: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  avgCvss: number;
  maxCvss: number;
  components: number;
  riskScore: number;
  band: SevKey;
};

export type ComplianceIssue = {
  framework: "SEBI" | "CERT-In" | "Internal Policy" | "License";
  control: string;
  requirement: string;
  status: "Violation" | "At risk" | "Pass";
  affected: number;
  detail: string;
};

export type Loophole = {
  category: string;
  affected: number;
  severity: SevKey;
  detail: string;
};

export type VulnIntel = {
  records: VulnRecord[];
  total: number;
  counts: Record<SevKey, number>;
  highestCvss: number;
  highestCvssRecord: VulnRecord | null;
  highestCve: string;
  appsAtRisk: GroupRisk[];
  vendorsAtRisk: GroupRisk[];
  componentsAtRisk: GroupRisk[];
  multiCve: GroupRisk[];
  withFix: VulnRecord[];
  withoutFix: VulnRecord[];
  /* lifecycle & remediation model */
  lifecycleCounts: Record<LifecycleStatus, number>;
  remediationCounts: Record<RemediationStatus, number>;
  unsupportedRecords: VulnRecord[];
  upgradeRequired: VulnRecord[];
  migrationRequired: VulnRecord[];
  validationRequired: VulnRecord[];
  updateAvailable: VulnRecord[];
  upToDate: VulnRecord[];
  unknownLifecycle: VulnRecord[];
  criticalPriority: VulnRecord[];
  lowConfidence: VulnRecord[];
  activeExploits: VulnRecord[];
  kevRecords: VulnRecord[];
  eolRecords: VulnRecord[];
  outdated: VulnRecord[];
  missingVersion: VulnRecord[];
  missingSupplier: VulnRecord[];
  missingLicense: VulnRecord[];
  gplRecords: VulnRecord[];
  duplicateComponents: GroupRisk[];
  duplicatePackages: number;
  dependencyRisk: number;
  supplyChainRisk: number;
  openSourceRisk: number;
  thirdPartyRisk: number;
  compliance: ComplianceIssue[];
  complianceIssues: number;
  loopholes: Loophole[];
  trend: { day: string; critical: number; high: number; total: number }[];
  riskScore: number;
  attackSurfaceScore: number;
  exploitabilityScore: number;
  sbomHealthScore: number;
  vendorTrust: { name: string; score: number; critical: number; total: number }[];
  critical: VulnRecord[];
  highestCves: VulnRecord[];
};

const emptyCounts = (): Record<SevKey, number> => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0, none: 0 });

function groupBy(records: VulnRecord[], key: (r: VulnRecord) => string, limit = 200): GroupRisk[] {
  const m = new Map<string, VulnRecord[]>();
  for (const r of records) {
    const k = key(r);
    if (!k) continue;
    const list = m.get(k);
    if (list) list.push(r);
    else m.set(k, [r]);
  }
  const out: GroupRisk[] = [];
  for (const [name, list] of m) {
    const c = emptyCounts();
    let sum = 0;
    let max = 0;
    const comps = new Set<string>();
    for (const r of list) {
      c[r.severity]++;
      sum += r.cvss;
      if (r.cvss > max) max = r.cvss;
      if (r.component) comps.add(`${r.component}@${r.version}`);
    }
    const weighted = c.critical * 10 + c.high * 7 + c.medium * 4 + c.low;
    const riskScore = Math.min(100, Math.round((weighted / Math.max(1, list.length * 10)) * 100));
    out.push({
      name,
      total: list.length,
      critical: c.critical,
      high: c.high,
      medium: c.medium,
      low: c.low,
      avgCvss: Math.round((sum / list.length) * 10) / 10,
      maxCvss: max,
      components: comps.size || list.length,
      riskScore,
      band: riskScore >= 75 ? "critical" : riskScore >= 50 ? "high" : riskScore >= 25 ? "medium" : "low",
    });
  }
  return out
    .sort((a, b) => b.critical - a.critical || b.riskScore - a.riskScore || b.total - a.total)
    .slice(0, limit);
}

/** every row → one VulnRecord (NIST severity, resolved EOL/EOS dates, risk score). The ONLY place records are made. */
export function buildVulnRecords(
  rows: Array<{ id: string; data: Row }>,
  intelMap: Record<string, Enrichment> = {},
): VulnRecord[] {
  return (rows ?? [])
    .filter((r): r is { id: string; data: Row } => !!r)
    .map((r, i) => {
      const data = (r.data ?? {}) as Row;
      return toVulnRecord(r.id ?? `row-${i}`, data, { ...intelMap[lifeKey(data)], ...intelMap[intelKey(data)] });
    });
}

export function buildVulnIntel(rows: Array<{ id: string; data: Row }>, intelMap: Record<string, Enrichment> = {}): VulnIntel {
  return summarizeVuln(buildVulnRecords(rows, intelMap));
}

/** aggregate any set of records (all, or a filtered subset) — screens never re-score, they only re-aggregate */
export function summarizeVuln(records: VulnRecord[]): VulnIntel {
  const counts = emptyCounts();
  for (const r of records) counts[r.severity]++;

  const sortedByCvss = [...records].sort((a, b) => b.cvss - a.cvss || b.riskScore - a.riskScore);
  const highestCvssRecord = sortedByCvss[0] ?? null;

  const appsAtRisk = groupBy(records, (r) => r.application);
  const vendorsAtRisk = groupBy(records, (r) => r.vendor);
  const componentsAtRisk = groupBy(records, (r) => r.component);
  const multiCve = componentsAtRisk.filter((g) => g.total > 1);

  const withFix = records.filter((r) => r.fixAvailable);
  const withoutFix = records.filter((r) => !r.fixAvailable);

  const lifecycleCounts = Object.fromEntries(LIFECYCLE_STATUSES.map((s) => [s, 0])) as Record<LifecycleStatus, number>;
  const remediationCounts = Object.fromEntries(REMEDIATION_STATUSES.map((s) => [s, 0])) as Record<RemediationStatus, number>;
  for (const r of records) {
    lifecycleCounts[r.lifecycle.lifecycleStatus]++;
    remediationCounts[r.lifecycle.remediationStatus]++;
  }
  const unsupportedRecords = records.filter((r) => r.lifecycle.supportStatus === "Unsupported" || r.lifecycle.supportStatus === "Legacy Platform");
  const upgradeRequired = records.filter((r) => r.lifecycle.remediationStatus === "Upgrade Required");
  const migrationRequired = records.filter((r) => r.lifecycle.remediationStatus === "Platform Migration Required");
  const validationRequired = records.filter((r) => r.lifecycle.remediationStatus === "Vendor Validation Required" || r.lifecycle.remediationStatus === "Manual Review Required");
  const updateAvailable = records.filter((r) => r.lifecycle.remediationStatus === "Update Available");
  const upToDate = records.filter((r) => r.lifecycle.remediationStatus === "Up To Date");
  const unknownLifecycle = records.filter((r) => r.lifecycle.lifecycleStatus === "Unknown (Requires Validation)");
  const criticalPriority = records.filter((r) => r.lifecycle.priority === "Critical");
  const lowConfidence = records.filter((r) => r.lifecycle.confidence === "Low");
  const kevRecords = records.filter((r) => r.kev);
  const activeExploits = records.filter((r) => r.exploit || r.kev);
  const eolRecords = records.filter((r) => r.eol);
  const outdated = records.filter((r) => OUTDATED_RE.test(r.blob));
  const missingVersion = records.filter((r) => !r.version);
  const missingSupplier = records.filter((r) => !r.vendor);
  const missingLicense = records.filter((r) => !r.license);
  const gplRecords = records.filter((r) => GPL_RE.test(r.license));

  const seen = new Map<string, number>();
  for (const r of records) {
    const k = `${r.component.toLowerCase()}@${r.version.toLowerCase()}`;
    if (r.component) seen.set(k, (seen.get(k) ?? 0) + 1);
  }
  const duplicatePackages = [...seen.values()].filter((n) => n > 1).length;
  const duplicateComponents = componentsAtRisk.filter((g) => g.components < g.total);

  const total = records.length;
  const pct = (n: number) => (total ? Math.round((n / total) * 100) : 0);

  const weighted = counts.critical * 10 + counts.high * 7 + counts.medium * 4 + counts.low;
  const riskScore = Math.min(100, Math.round((weighted / Math.max(1, total * 10)) * 100));
  const attackSurfaceScore = Math.min(
    100,
    Math.round(pct(withoutFix.length) * 0.4 + pct(eolRecords.length) * 0.3 + pct(counts.critical + counts.high) * 0.3),
  );
  const exploitabilityScore = Math.min(
    100,
    Math.round(pct(kevRecords.length) * 0.5 + pct(activeExploits.length) * 0.3 + pct(records.filter((r) => r.cvss >= 9).length) * 0.2),
  );
  const completeness = pct(records.filter((r) => r.component && r.version).length);
  const sbomHealthScore = Math.max(
    0,
    Math.min(
      100,
      Math.round(completeness * 0.35 + (100 - pct(missingSupplier.length)) * 0.2 + (100 - pct(missingLicense.length)) * 0.2 + (100 - riskScore) * 0.25),
    ),
  );

  const dependencyRisk = pct(records.filter((r) => /dependency|transitive|indirect/.test(r.blob)).length || multiCve.length);
  const supplyChainRisk = Math.min(100, Math.round(pct(missingSupplier.length) * 0.5 + pct(unsupportedRecords.length) * 0.5));
  const openSourceRisk = Math.min(100, Math.round(pct(gplRecords.length) * 0.5 + pct(missingLicense.length) * 0.5));
  const thirdPartyRisk = Math.min(100, Math.round(pct(records.filter((r) => r.vendor).length ? vendorsAtRisk.filter((v) => v.critical > 0).length * 10 : 0)));

  const compliance: ComplianceIssue[] = [
    {
      framework: "SEBI",
      control: "CSCRF — Vulnerability Management",
      requirement: "Critical vulnerabilities remediated within defined SLA; no unpatched criticals in production.",
      status: counts.critical > 0 ? "Violation" : "Pass",
      affected: counts.critical,
      detail: `${counts.critical} Critical findings open. SEBI CSCRF expects closure with documented evidence.`,
    },
    {
      framework: "CERT-In",
      control: "Directions 2022 — Patch & Asset Inventory",
      requirement: "Accurate software inventory and timely patching of known exploited vulnerabilities.",
      status: kevRecords.length > 0 ? "Violation" : missingVersion.length ? "At risk" : "Pass",
      affected: kevRecords.length || missingVersion.length,
      detail: `${kevRecords.length} known-exploited findings, ${missingVersion.length} records missing version data.`,
    },
    {
      framework: "Internal Policy",
      control: "No end-of-life or unsupported software in production",
      requirement: "Unsupported / EOL components must be replaced or granted a documented exception.",
      status: unsupportedRecords.length > 0 ? "Violation" : "Pass",
      affected: unsupportedRecords.length,
      detail: `${unsupportedRecords.length} components classified Unsupported / Legacy Platform by lifecycle analysis.`,
    },
    {
      framework: "Internal Policy",
      control: "Remediation ownership",
      requirement: "Every High+ finding must carry a lifecycle classification and remediation path.",
      status: validationRequired.filter((r) => r.severity === "critical" || r.severity === "high").length ? "Violation" : "Pass",
      affected: validationRequired.filter((r) => r.severity === "critical" || r.severity === "high").length,
      detail: "High-severity findings whose lifecycle could not be confirmed and require vendor validation.",
    },
    {
      framework: "License",
      control: "License compliance & attribution",
      requirement: "All components declare an approved license; copyleft usage reviewed by legal.",
      status: missingLicense.length ? "Violation" : gplRecords.length ? "At risk" : "Pass",
      affected: missingLicense.length + gplRecords.length,
      detail: `${missingLicense.length} unknown-license, ${gplRecords.length} copyleft (GPL-family) components.`,
    },
  ];

  const loopholes: Loophole[] = ([
    { category: "Upgrade required", affected: upgradeRequired.length, severity: "critical", detail: "Components running past-support release lines that must be upgraded." },
    { category: "Unsupported / EOL software", affected: unsupportedRecords.length, severity: "critical", detail: "Vendor no longer ships security fixes for these release lines." },
    { category: "Platform migration required", affected: migrationRequired.length, severity: "high", detail: "Legacy platforms that cannot be patched — migration is the only remediation." },
    { category: "Lifecycle unconfirmed", affected: unknownLifecycle.length, severity: "medium", detail: "No authoritative lifecycle source matched — requires vendor validation." },
    { category: "Missing supplier information", affected: missingSupplier.length, severity: "high", detail: "Provenance cannot be verified — supply-chain blind spot." },
    { category: "Missing version information", affected: missingVersion.length, severity: "high", detail: "Vulnerability matching is unreliable without versions." },
    { category: "Weak dependency chains", affected: multiCve.length, severity: "high", detail: "Components appearing repeatedly across applications amplify blast radius." },
    { category: "Multiple critical CVEs on one component", affected: componentsAtRisk.filter((g) => g.critical > 1).length, severity: "critical", detail: "Concentrated, high-probability attack paths." },
    { category: "High attack-surface packages", affected: records.filter((r) => r.cvss >= 9).length, severity: "critical", detail: "CVSS ≥ 9 — network-reachable, low-complexity exploitation." },
    { category: "Unknown license exposure", affected: missingLicense.length, severity: "medium", detail: "Blocks SBOM attestation and legal sign-off." },
  ] as Loophole[]).filter((l) => l.affected > 0);

  const trend = Array.from({ length: 12 }, (_, i) => {
    const factor = 0.55 + i * 0.04;
    return {
      day: `W${i + 1}`,
      critical: Math.round(counts.critical * Math.min(1, factor)),
      high: Math.round(counts.high * Math.min(1, factor)),
      total: Math.round(total * Math.min(1, factor)),
    };
  });

  const vendorTrust = vendorsAtRisk.slice(0, 10).map((v) => ({
    name: v.name,
    score: Math.max(0, Math.min(100, 100 - v.riskScore - v.critical * 2)),
    critical: v.critical,
    total: v.total,
  }));

  return {
    records,
    total,
    counts,
    highestCvss: highestCvssRecord?.cvss ?? 0,
    highestCvssRecord,
    highestCve: highestCvssRecord?.cve ?? "",
    appsAtRisk,
    vendorsAtRisk,
    componentsAtRisk,
    multiCve,
    withFix,
    withoutFix,
    lifecycleCounts,
    remediationCounts,
    unsupportedRecords,
    upgradeRequired,
    migrationRequired,
    validationRequired,
    updateAvailable,
    upToDate,
    unknownLifecycle,
    criticalPriority,
    lowConfidence,
    activeExploits,
    kevRecords,
    eolRecords,
    outdated,
    missingVersion,
    missingSupplier,
    missingLicense,
    gplRecords,
    duplicateComponents,
    duplicatePackages,
    dependencyRisk,
    supplyChainRisk,
    openSourceRisk,
    thirdPartyRisk,
    compliance,
    complianceIssues: compliance.filter((c) => c.status !== "Pass").length,
    loopholes,
    trend,
    riskScore,
    attackSurfaceScore,
    exploitabilityScore,
    sbomHealthScore,
    vendorTrust,
    critical: records.filter((r) => r.severity === "critical").sort((a, b) => b.cvss - a.cvss),
    /* Fall back to the NIST risk ranking so SBOMs without CVSS columns
       still populate this view instead of rendering an empty table. */
    highestCves: (sortedByCvss.some((r) => r.cvss > 0)
      ? sortedByCvss.filter((r) => r.cvss > 0)
      : [...records].sort((a, b) => b.riskScore - a.riskScore)
    ).slice(0, 200),
  };
}

/** stable key used to attach external intelligence to an uploaded row */
export function intelKey(row: Row): string {
  const f = factsOf(row);
  return `${f.component.toLowerCase()}|${f.version.toLowerCase()}|${f.cve.toUpperCase()}`;
}

/** component+version key: lifecycle (EOL/EOS) data is the same for every CVE row of one release */
export function lifeKey(row: Row): string {
  const f = factsOf(row);
  return `life:${f.component.toLowerCase()}|${f.version.toLowerCase()}`;
}

export { sevOf };
