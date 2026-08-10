/**
 * Platform Intelligence layer (SBOM Workbench V2).
 *
 * Sits on top of the vulnerability + lifecycle + heuristic engines and produces
 * everything the Dashboard, Component Inventory, Dependency, License and
 * Comparison views need. Pure functions, no IO — safe for 100k+ rows.
 */

import { assessAll, type ComponentRisk } from "@/lib/sbom-heuristics";
import { buildVulnIntel, intelKey, type Enrichment, type VulnIntel, type VulnRecord } from "@/lib/vuln-intel";
import type { SevKey } from "@/lib/risk-intel";

export type Row = Record<string, unknown>;
export type Item = { id: string; data: Row };

/* ------------------------------- field helpers ------------------------------- */
const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
export function pickField(row: Row, names: string[]): string {
  const keys = Object.keys(row);
  for (const n of names) {
    const k = keys.find((k) => norm(k) === norm(n)) ?? keys.find((k) => norm(k).includes(norm(n)));
    if (k) {
      const v = row[k];
      const s = String(v ?? "").trim();
      if (s && s !== "-" && s.toLowerCase() !== "n/a") return s;
    }
  }
  return "";
}

const splitList = (s: string): string[] =>
  s
    .split(/[;,\n|]+/)
    .map((x) => x.trim())
    .filter((x) => x && x.toLowerCase() !== "none");

/* ================================ License intel ================================ */
export type LicenseType = "Permissive" | "Weak Copyleft" | "Strong Copyleft" | "Proprietary" | "Public Domain" | "Unknown";

export type LicenseEntry = {
  name: string;
  type: LicenseType;
  risk: SevKey;
  count: number;
  components: string[];
  note: string;
};

export type LicenseIntel = {
  entries: LicenseEntry[];
  unknown: number;
  copyleft: number;
  proprietary: number;
  permissive: number;
  conflicts: Array<{ component: string; licenses: string[]; detail: string }>;
  riskyCount: number;
};

export function classifyLicense(raw: string): { type: LicenseType; risk: SevKey; note: string } {
  const s = raw.trim();
  if (!s || /unknown|noassertion|not\s*specified|none/i.test(s))
    return { type: "Unknown", risk: "medium", note: "Undeclared license — legal exposure cannot be assessed." };
  if (/agpl|sspl/i.test(s))
    return { type: "Strong Copyleft", risk: "critical", note: "Network copyleft: distribution or SaaS use can force source disclosure." };
  if (/(^|[^l])gpl/i.test(s) && !/lgpl/i.test(s))
    return { type: "Strong Copyleft", risk: "high", note: "Copyleft obligations propagate to derivative works." };
  if (/lgpl|mpl|epl|cddl|cc-by-sa|osl/i.test(s))
    return { type: "Weak Copyleft", risk: "medium", note: "File/library-level copyleft — keep modifications separable." };
  if (/proprietary|commercial|all rights reserved|eula/i.test(s))
    return { type: "Proprietary", risk: "medium", note: "Commercial terms — verify entitlement and seat counts." };
  if (/public domain|unlicense|cc0/i.test(s))
    return { type: "Public Domain", risk: "low", note: "No obligations." };
  if (/mit|apache|bsd|isc|zlib|python|artistic|boost/i.test(s))
    return { type: "Permissive", risk: "low", note: "Attribution-only obligations." };
  return { type: "Unknown", risk: "medium", note: "License string not recognised — manual legal review recommended." };
}

export function buildLicenseIntel(profiles: ComponentProfile[]): LicenseIntel {
  const m = new Map<string, LicenseEntry>();
  const conflicts: LicenseIntel["conflicts"] = [];
  for (const p of profiles) {
    const names = p.license ? splitList(p.license) : [""];
    const kinds = new Set<LicenseType>();
    for (const n of names) {
      const key = n || "Unknown";
      const c = classifyLicense(n);
      kinds.add(c.type);
      const e = m.get(key) ?? { name: key, type: c.type, risk: c.risk, count: 0, components: [], note: c.note };
      e.count++;
      if (e.components.length < 50) e.components.push(`${p.name}${p.version ? ` ${p.version}` : ""}`);
      m.set(key, e);
    }
    if (kinds.has("Strong Copyleft") && (kinds.has("Proprietary") || kinds.has("Permissive")) && names.length > 1) {
      conflicts.push({
        component: `${p.name}${p.version ? ` ${p.version}` : ""}`,
        licenses: names,
        detail: "Strong copyleft combined with proprietary/permissive terms — incompatible obligations.",
      });
    }
  }
  const entries = [...m.values()].sort((a, b) => b.count - a.count);
  return {
    entries,
    unknown: entries.filter((e) => e.type === "Unknown").reduce((a, e) => a + e.count, 0),
    copyleft: entries.filter((e) => e.type.includes("Copyleft")).reduce((a, e) => a + e.count, 0),
    proprietary: entries.filter((e) => e.type === "Proprietary").reduce((a, e) => a + e.count, 0),
    permissive: entries.filter((e) => e.type === "Permissive").reduce((a, e) => a + e.count, 0),
    conflicts,
    riskyCount: entries.filter((e) => e.risk === "critical" || e.risk === "high").reduce((a, e) => a + e.count, 0),
  };
}

/* ============================== Dependency graph ============================== */
export type DepNode = {
  id: string;
  name: string;
  version: string;
  severity: SevKey;
  riskScore: number;
  depth: number;
  direct: boolean;
  children: string[];
  parents: string[];
};

export type DependencyIntel = {
  nodes: DepNode[];
  byId: Record<string, DepNode>;
  edges: Array<{ from: string; to: string }>;
  maxDepth: number;
  directCount: number;
  transitiveCount: number;
  orphanCount: number;
  vulnerableChains: Array<{ path: string[]; severity: SevKey; riskScore: number }>;
  criticalNodes: DepNode[];
  declared: boolean;
};

export function buildDependencyIntel(profiles: ComponentProfile[]): DependencyIntel {
  const byKey = new Map<string, DepNode>();
  const keyOf = (name: string) => name.toLowerCase().trim();

  for (const p of profiles) {
    const k = keyOf(p.name);
    if (!k) continue;
    if (!byKey.has(k)) {
      byKey.set(k, {
        id: k,
        name: p.name,
        version: p.version,
        severity: p.severity,
        riskScore: p.riskScore,
        depth: 0,
        direct: true,
        children: [],
        parents: [],
      });
    }
  }

  let declared = false;
  const edges: Array<{ from: string; to: string }> = [];
  for (const p of profiles) {
    const self = byKey.get(keyOf(p.name));
    if (!self) continue;
    for (const child of p.dependsOn) {
      declared = true;
      const ck = keyOf(child);
      if (!ck || ck === self.id) continue;
      let node = byKey.get(ck);
      if (!node) {
        node = { id: ck, name: child, version: "", severity: "none", riskScore: 0, depth: 0, direct: false, children: [], parents: [] };
        byKey.set(ck, node);
      }
      if (!self.children.includes(ck)) self.children.push(ck);
      if (!node.parents.includes(self.id)) node.parents.push(self.id);
      edges.push({ from: self.id, to: ck });
    }
    for (const parent of p.dependencyOf) {
      declared = true;
      const pk = keyOf(parent);
      if (!pk || pk === self.id) continue;
      let node = byKey.get(pk);
      if (!node) {
        node = { id: pk, name: parent, version: "", severity: "none", riskScore: 0, depth: 0, direct: true, children: [], parents: [] };
        byKey.set(pk, node);
      }
      if (!node.children.includes(self.id)) node.children.push(self.id);
      if (!self.parents.includes(pk)) self.parents.push(pk);
      edges.push({ from: pk, to: self.id });
    }
  }

  const nodes = [...byKey.values()];
  for (const n of nodes) n.direct = n.parents.length === 0;

  // BFS depth from roots
  const roots = nodes.filter((n) => n.parents.length === 0);
  const seen = new Set<string>();
  let queue = roots.map((r) => ({ node: r, depth: 0 }));
  let maxDepth = 0;
  while (queue.length) {
    const next: typeof queue = [];
    for (const { node, depth } of queue) {
      if (seen.has(node.id)) continue;
      seen.add(node.id);
      node.depth = depth;
      if (depth > maxDepth) maxDepth = depth;
      for (const c of node.children) {
        const cn = byKey.get(c);
        if (cn && !seen.has(c)) next.push({ node: cn, depth: depth + 1 });
      }
    }
    queue = next;
  }

  // Vulnerable chains: root → risky leaf
  const vulnerableChains: DependencyIntel["vulnerableChains"] = [];
  const risky = nodes
    .filter((n) => n.severity === "critical" || n.severity === "high")
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 25);
  for (const target of risky) {
    const path: string[] = [target.name];
    let cur = target;
    const guard = new Set<string>([cur.id]);
    while (cur.parents.length) {
      const parent = byKey.get(cur.parents[0]);
      if (!parent || guard.has(parent.id)) break;
      guard.add(parent.id);
      path.unshift(parent.name);
      cur = parent;
    }
    if (path.length > 1 || target.severity === "critical")
      vulnerableChains.push({ path, severity: target.severity, riskScore: target.riskScore });
  }

  return {
    nodes,
    byId: Object.fromEntries(nodes.map((n) => [n.id, n])),
    edges,
    maxDepth,
    directCount: nodes.filter((n) => n.direct).length,
    transitiveCount: nodes.filter((n) => !n.direct).length,
    orphanCount: nodes.filter((n) => !n.children.length && !n.parents.length).length,
    vulnerableChains,
    criticalNodes: nodes
      .filter((n) => n.children.length >= 2 && (n.severity === "critical" || n.severity === "high"))
      .sort((a, b) => b.children.length - a.children.length)
      .slice(0, 20),
    declared,
  };
}

/* ============================== Component profile ============================== */
export type ComponentProfile = {
  id: string;
  name: string;
  version: string;
  supplier: string;
  packageName: string;
  license: string;
  licenseType: LicenseType;
  licenseRisk: SevKey;
  purl: string;
  cpe: string;
  hash: string;
  application: string;
  cve: string;
  cvss: number;
  severity: SevKey;
  estimated: boolean;
  estimatedConfidence: number;
  classificationReason: string;
  lifecycleStatus: string;
  supportStatus: string;
  remediationStatus: string;
  recommendedAction: string;
  targetVersion: string;
  latestVersion: string;
  eolDate: string;
  eosDate: string;
  priority: string;
  confidence: string;
  evidenceSource: string;
  exposure: "Internet-facing" | "Internal" | "Unknown";
  riskScore: number;
  riskCategory: "Critical" | "High" | "Moderate" | "Low";
  businessImpact: string;
  dependsOn: string[];
  dependencyOf: string[];
  missing: string[];
  kev: boolean;
  exploit: boolean;
  record: VulnRecord;
  risk: ComponentRisk;
};

const EXPOSED_RE = /internet|public|external|edge|dmz|web|api gateway|ingress/i;
const INTERNAL_RE = /internal|private|intranet|backend|offline|air.?gap/i;

function exposureOf(row: Row, blob: string): ComponentProfile["exposure"] {
  const declared = pickField(row, ["exposure", "network", "facing", "environment", "zone"]);
  if (EXPOSED_RE.test(declared) || EXPOSED_RE.test(blob)) return "Internet-facing";
  if (INTERNAL_RE.test(declared)) return "Internal";
  return "Unknown";
}

function riskCategoryOf(score: number): ComponentProfile["riskCategory"] {
  return score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 35 ? "Moderate" : "Low";
}

export function buildProfiles(items: Item[], intelMap: Record<string, Enrichment> = {}): {
  profiles: ComponentProfile[];
  intel: VulnIntel;
} {
  const intel = buildVulnIntel(items, intelMap);
  const risks = assessAll(items);
  const riskById = new Map(risks.map((r) => [r.id, r]));

  const profiles: ComponentProfile[] = intel.records.map((rec) => {
    const risk = riskById.get(rec.id)!;
    const row = rec.raw;
    const blob = rec.blob;
    const lic = classifyLicense(rec.license || risk.license);
    const exposure = exposureOf(row, blob);

    let riskScore = Math.max(rec.riskScore, risk.score);
    if (exposure === "Internet-facing") riskScore = Math.min(100, riskScore + 8);
    if (rec.lifecycle.supportStatus === "Unsupported") riskScore = Math.min(100, riskScore + 6);
    if (lic.risk === "critical") riskScore = Math.min(100, riskScore + 4);
    if (risk.missing.length >= 3) riskScore = Math.min(100, riskScore + 3);

    const dependsOn = splitList(pickField(row, ["dependencies", "dependson", "childdependencies", "requires", "children"]));
    const dependencyOf = splitList(pickField(row, ["parentdependencies", "parent", "dependencyof", "usedby", "parentcomponent"]));

    return {
      id: rec.id,
      name: rec.component || risk.name,
      version: rec.version,
      supplier: rec.vendor || risk.supplier,
      packageName: pickField(row, ["package", "packagename", "artifact", "module"]) || rec.component,
      license: rec.license || risk.license,
      licenseType: lic.type,
      licenseRisk: lic.risk,
      purl: risk.purl,
      cpe: risk.cpe,
      hash: pickField(row, ["hash", "sha256", "sha1", "md5", "checksum", "digest"]),
      application: rec.application,
      cve: rec.cve,
      cvss: rec.cvss,
      severity: rec.severity === "none" ? risk.severity : rec.severity,
      estimated: risk.estimated,
      estimatedConfidence: risk.confidence,
      classificationReason: risk.rationale,
      lifecycleStatus: rec.lifecycle.lifecycleStatus,
      supportStatus: rec.lifecycle.supportStatus,
      remediationStatus: rec.lifecycle.remediationStatus,
      recommendedAction: rec.lifecycle.recommendedAction,
      targetVersion: rec.lifecycle.targetVersion,
      latestVersion: rec.lifecycle.latestStableVersion || rec.latestSafeVersion,
      eolDate: rec.intel.eolDate ?? "",
      eosDate: rec.intel.supportEndDate ?? "",
      priority: rec.lifecycle.priority,
      confidence: rec.lifecycle.confidence,
      evidenceSource: rec.lifecycle.evidenceSource,
      exposure,
      riskScore,
      riskCategory: riskCategoryOf(riskScore),
      businessImpact: rec.businessImpact,
      dependsOn,
      dependencyOf,
      missing: risk.missing,
      kev: rec.kev,
      exploit: rec.exploit,
      record: rec,
      risk,
    };
  });

  return { profiles, intel };
}

/* ============================== Platform analysis ============================== */
export type KpiId =
  | "all" | "critical" | "high" | "medium" | "low" | "info"
  | "upgrade" | "eol" | "eos" | "deprecated" | "legacy" | "unsupported"
  | "appsAtRisk" | "vendorsAtRisk" | "licenseRisk" | "missingMetadata"
  | "kev" | "duplicates" | "multiVersion" | "internetFacing";

export type Finding = {
  id: string;
  title: string;
  severity: SevKey;
  count: number;
  summary: string;
  details: string[];
  kpi?: KpiId;
  columns?: string[];
  rows?: (string | number)[][];
  prompt?: string;
};

export type PlatformAnalysis = {
  profiles: ComponentProfile[];
  intel: VulnIntel;
  licenses: LicenseIntel;
  deps: DependencyIntel;
  applications: string[];
  vendors: string[];
  counts: Record<KpiId, number>;
  duplicates: Array<{ name: string; versions: string[]; count: number }>;
  missingMetadata: ComponentProfile[];
  healthScore: number;
  overallRisk: number;
  riskCategory: string;
  confidence: number;
  findings: Finding[];
};

const KPI_PREDICATES: Record<KpiId, (p: ComponentProfile) => boolean> = {
  all: () => true,
  critical: (p) => p.severity === "critical",
  high: (p) => p.severity === "high",
  medium: (p) => p.severity === "medium",
  low: (p) => p.severity === "low",
  info: (p) => p.severity === "info" || p.severity === "none",
  upgrade: (p) => /Upgrade Required|Update Available|Platform Migration Required/i.test(p.remediationStatus),
  eol: (p) => /End of Life/i.test(p.lifecycleStatus),
  eos: (p) => /End of Support/i.test(p.lifecycleStatus),
  deprecated: (p) => /Deprecated|Obsolete/i.test(p.lifecycleStatus),
  legacy: (p) => /Legacy/i.test(p.lifecycleStatus),
  unsupported: (p) => p.supportStatus === "Unsupported",
  appsAtRisk: (p) => Boolean(p.application) && (p.severity === "critical" || p.severity === "high"),
  vendorsAtRisk: (p) => Boolean(p.supplier) && (p.severity === "critical" || p.severity === "high"),
  licenseRisk: (p) => p.licenseRisk === "critical" || p.licenseRisk === "high" || p.licenseType === "Unknown",
  missingMetadata: (p) => p.missing.length > 0,
  kev: (p) => p.kev || p.exploit,
  duplicates: () => false, // replaced at build time
  multiVersion: () => false, // replaced at build time
  internetFacing: (p) => p.exposure === "Internet-facing",
};

export function kpiPredicate(kpi: KpiId, analysis: PlatformAnalysis): (p: ComponentProfile) => boolean {
  if (kpi === "duplicates" || kpi === "multiVersion") {
    const names = new Set(analysis.duplicates.map((d) => d.name.toLowerCase()));
    return (p) => names.has(p.name.toLowerCase());
  }
  return KPI_PREDICATES[kpi];
}

export function buildPlatformAnalysis(items: Item[], intelMap: Record<string, Enrichment> = {}): PlatformAnalysis {
  const { profiles, intel } = buildProfiles(items, intelMap);
  const licenses = buildLicenseIntel(profiles);
  const deps = buildDependencyIntel(profiles);

  const appMap = new Map<string, number>();
  const vendorMap = new Map<string, number>();
  const versionMap = new Map<string, Set<string>>();
  for (const p of profiles) {
    if (p.application) appMap.set(p.application, (appMap.get(p.application) ?? 0) + 1);
    if (p.supplier) vendorMap.set(p.supplier, (vendorMap.get(p.supplier) ?? 0) + 1);
    const k = p.name.toLowerCase();
    if (!k) continue;
    const set = versionMap.get(k) ?? new Set<string>();
    set.add(p.version || "unversioned");
    versionMap.set(k, set);
  }

  const duplicates = [...versionMap.entries()]
    .filter(([, v]) => v.size > 1)
    .map(([name, v]) => ({
      name: profiles.find((p) => p.name.toLowerCase() === name)?.name ?? name,
      versions: [...v],
      count: v.size,
    }))
    .sort((a, b) => b.count - a.count);

  const missingMetadata = profiles.filter((p) => p.missing.length > 0);

  const count = (fn: (p: ComponentProfile) => boolean) => profiles.filter(fn).length;
  const dupNames = new Set(duplicates.map((d) => d.name.toLowerCase()));

  const counts: Record<KpiId, number> = {
    all: profiles.length,
    critical: count(KPI_PREDICATES.critical),
    high: count(KPI_PREDICATES.high),
    medium: count(KPI_PREDICATES.medium),
    low: count(KPI_PREDICATES.low),
    info: count(KPI_PREDICATES.info),
    upgrade: count(KPI_PREDICATES.upgrade),
    eol: count(KPI_PREDICATES.eol),
    eos: count(KPI_PREDICATES.eos),
    deprecated: count(KPI_PREDICATES.deprecated),
    legacy: count(KPI_PREDICATES.legacy),
    unsupported: count(KPI_PREDICATES.unsupported),
    appsAtRisk: new Set(profiles.filter(KPI_PREDICATES.appsAtRisk).map((p) => p.application)).size,
    vendorsAtRisk: new Set(profiles.filter(KPI_PREDICATES.vendorsAtRisk).map((p) => p.supplier)).size,
    licenseRisk: count(KPI_PREDICATES.licenseRisk),
    missingMetadata: missingMetadata.length,
    kev: count(KPI_PREDICATES.kev),
    duplicates: profiles.filter((p) => dupNames.has(p.name.toLowerCase())).length,
    multiVersion: duplicates.length,
    internetFacing: count(KPI_PREDICATES.internetFacing),
  };

  const total = profiles.length || 1;
  const overallRisk = Math.min(
    100,
    Math.round(
      (counts.critical * 10 + counts.high * 7 + counts.medium * 4 + counts.low * 1) / (total * 10) * 100 +
      Math.min(15, (counts.kev * 3)) +
      Math.min(10, counts.unsupported / total * 40),
    ),
  );

  const healthScore = Math.max(
    0,
    Math.round(
      100 -
      (counts.missingMetadata / total) * 30 -
      (counts.licenseRisk / total) * 15 -
      (counts.unsupported / total) * 25 -
      (counts.critical / total) * 30,
    ),
  );

  const confidence = Math.round(profiles.reduce((a, p) => a + p.estimatedConfidence, 0) / total);

  const topRisk = [...profiles].sort((a, b) => b.riskScore - a.riskScore).slice(0, 10);
  const appRisk = intel.appsAtRisk.slice(0, 10);
  const vendorRisk = intel.vendorsAtRisk.slice(0, 10);

  const findings: Finding[] = [];
  const push = (f: Finding) => { if (f.count > 0 || f.id === "summary") findings.push(f); };

  push({
    id: "summary",
    title: "SBOM analysis complete",
    severity: overallRisk >= 75 ? "critical" : overallRisk >= 50 ? "high" : overallRisk >= 25 ? "medium" : "low",
    count: profiles.length,
    summary: `${profiles.length} components normalized · ${counts.critical} critical · overall risk ${overallRisk}/100 · SBOM health ${healthScore}/100 · analysis confidence ${confidence}%.`,
    details: [
      `${appMap.size} application(s) and ${vendorMap.size} supplier(s) identified.`,
      `${counts.upgrade} component(s) require an upgrade, migration or update.`,
      `${deps.declared ? `${deps.directCount} direct / ${deps.transitiveCount} transitive dependencies, max depth ${deps.maxDepth}.` : "No dependency relationships were declared in the SBOM."}`,
    ],
    prompt: "Summarize this SBOM: posture, top risks and the three actions I should take first.",
  });

  push({
    id: "critical",
    title: "Critical components",
    severity: "critical",
    count: counts.critical,
    summary: `${counts.critical} component(s) classified Critical and requiring immediate remediation.`,
    details: topRisk.filter((p) => p.severity === "critical").slice(0, 6).map((p) => `${p.name} ${p.version} — ${p.recommendedAction}`),
    kpi: "critical",
    columns: ["Component", "Version", "CVE", "CVSS", "Risk", "Action"],
    rows: profiles.filter((p) => p.severity === "critical").slice(0, 25).map((p) => [p.name, p.version, p.cve || "—", p.cvss || "—", p.riskScore, p.recommendedAction]),
    prompt: "List every critical component with its CVE, risk score and recommended remediation.",
  });

  push({
    id: "kev",
    title: "Known exploited / exploitable",
    severity: "critical",
    count: counts.kev,
    summary: `${counts.kev} component(s) are linked to known-exploited or publicly exploitable vulnerabilities.`,
    details: profiles.filter((p) => p.kev || p.exploit).slice(0, 6).map((p) => `${p.name} ${p.version} — ${p.record.exploitStatus}`),
    kpi: "kev",
    prompt: "Which components are actively exploited and how do I mitigate them today?",
  });

  push({
    id: "apps",
    title: "Applications at risk",
    severity: "high",
    count: counts.appsAtRisk,
    summary: `${counts.appsAtRisk} application(s) carry critical or high severity components.`,
    details: appRisk.slice(0, 6).map((a) => `${a.name} — ${a.critical} critical / ${a.high} high (risk ${a.riskScore})`),
    kpi: "appsAtRisk",
    columns: ["Application", "Findings", "Critical", "High", "Risk"],
    rows: appRisk.map((a) => [a.name, a.total, a.critical, a.high, a.riskScore]),
    prompt: "Which applications are most at risk and why?",
  });

  push({
    id: "vendors",
    title: "Vendors at risk",
    severity: "high",
    count: counts.vendorsAtRisk,
    summary: `${counts.vendorsAtRisk} supplier(s) concentrate critical or high severity risk.`,
    details: vendorRisk.slice(0, 6).map((v) => `${v.name} — ${v.critical} critical / ${v.high} high (risk ${v.riskScore})`),
    kpi: "vendorsAtRisk",
    columns: ["Vendor", "Findings", "Critical", "High", "Risk"],
    rows: vendorRisk.map((v) => [v.name, v.total, v.critical, v.high, v.riskScore]),
    prompt: "Which vendors concentrate the most supply-chain risk?",
  });

  push({
    id: "eol",
    title: "EOL / EOS / unsupported components",
    severity: "high",
    count: counts.eol + counts.eos + counts.unsupported,
    summary: `${counts.eol} end-of-life, ${counts.eos} end-of-support and ${counts.unsupported} unsupported component(s) detected.`,
    details: profiles.filter((p) => p.supportStatus === "Unsupported" || /End of/i.test(p.lifecycleStatus)).slice(0, 6)
      .map((p) => `${p.name} ${p.version} — ${p.lifecycleStatus} → ${p.recommendedAction}`),
    kpi: "unsupported",
    columns: ["Component", "Version", "Lifecycle", "Support", "Recommended action"],
    rows: profiles.filter((p) => p.supportStatus === "Unsupported" || /End of/i.test(p.lifecycleStatus)).slice(0, 25)
      .map((p) => [p.name, p.version, p.lifecycleStatus, p.supportStatus, p.recommendedAction]),
    prompt: "Which applications run end-of-life or unsupported software, and what should replace it?",
  });

  push({
    id: "upgrade",
    title: "Top upgrade priorities",
    severity: "high",
    count: counts.upgrade,
    summary: `${counts.upgrade} component(s) have an actionable upgrade, update or migration path.`,
    details: profiles.filter(KPI_PREDICATES.upgrade).sort((a, b) => b.riskScore - a.riskScore).slice(0, 6)
      .map((p) => `${p.name} ${p.version} → ${p.targetVersion || "latest stable"} (${p.priority})`),
    kpi: "upgrade",
    columns: ["Component", "Current", "Target", "Remediation", "Priority"],
    rows: profiles.filter(KPI_PREDICATES.upgrade).sort((a, b) => b.riskScore - a.riskScore).slice(0, 25)
      .map((p) => [p.name, p.version || "—", p.targetVersion || "latest stable", p.remediationStatus, p.priority]),
    prompt: "Generate a prioritized remediation plan with target versions.",
  });

  push({
    id: "license",
    title: "License risks",
    severity: licenses.riskyCount > 0 ? "high" : "medium",
    count: counts.licenseRisk,
    summary: `${licenses.copyleft} copyleft, ${licenses.proprietary} proprietary and ${licenses.unknown} undeclared license(s) detected across the inventory.`,
    details: licenses.entries.filter((e) => e.risk === "critical" || e.risk === "high" || e.type === "Unknown").slice(0, 6)
      .map((e) => `${e.name} (${e.type}) × ${e.count} — ${e.note}`),
    kpi: "licenseRisk",
    columns: ["License", "Type", "Components", "Risk"],
    rows: licenses.entries.slice(0, 25).map((e) => [e.name, e.type, e.count, e.risk]),
    prompt: "Analyze license exposure and copyleft obligations in this SBOM.",
  });

  push({
    id: "metadata",
    title: "Missing metadata",
    severity: "medium",
    count: counts.missingMetadata,
    summary: `${counts.missingMetadata} component(s) are missing fields required for reliable advisory matching.`,
    details: [
      `${profiles.filter((p) => p.missing.includes("Version")).length} missing version`,
      `${profiles.filter((p) => p.missing.includes("Supplier")).length} missing supplier`,
      `${profiles.filter((p) => p.missing.includes("License")).length} missing license`,
      `${profiles.filter((p) => p.missing.includes("PURL")).length} missing PURL`,
    ],
    kpi: "missingMetadata",
    prompt: "Which SBOM metadata gaps most weaken my vulnerability detection?",
  });

  push({
    id: "duplicates",
    title: "Duplicate components & version sprawl",
    severity: "medium",
    count: duplicates.length,
    summary: `${duplicates.length} component(s) appear at multiple versions across the estate.`,
    details: duplicates.slice(0, 6).map((d) => `${d.name} — ${d.versions.join(", ")}`),
    kpi: "duplicates",
    columns: ["Component", "Versions", "Count"],
    rows: duplicates.slice(0, 25).map((d) => [d.name, d.versions.join(", "), d.count]),
    prompt: "Which components run at multiple versions and which version should we standardize on?",
  });

  push({
    id: "dependency",
    title: "Dependency & supply-chain risks",
    severity: "high",
    count: deps.vulnerableChains.length,
    summary: deps.declared
      ? `${deps.vulnerableChains.length} vulnerable dependency chain(s) across ${deps.nodes.length} nodes (max depth ${deps.maxDepth}).`
      : `Dependency relationships are not declared — supply-chain depth cannot be verified.`,
    details: deps.vulnerableChains.slice(0, 6).map((c) => c.path.join(" → ")),
    prompt: "Explain the riskiest dependency chains in this SBOM.",
  });

  push({
    id: "compliance",
    title: "Compliance risks",
    severity: "high",
    count: intel.compliance.filter((c) => c.status !== "Pass").length,
    summary: `${intel.compliance.filter((c) => c.status !== "Pass").length} compliance control(s) are failing or at risk.`,
    details: intel.compliance.filter((c) => c.status !== "Pass").slice(0, 6).map((c) => `${c.framework} · ${c.control} — ${c.detail}`),
    prompt: "Assess SEBI and CERT-In compliance posture for this SBOM.",
  });

  push({
    id: "loopholes",
    title: "Security loopholes",
    severity: "high",
    count: intel.loopholes.length,
    summary: `${intel.loopholes.length} structural security weakness(es) identified in the inventory.`,
    details: intel.loopholes.slice(0, 6).map((l) => `${l.category} (${l.affected}) — ${l.detail}`),
    prompt: "What structural security loopholes exist in this SBOM?",
  });

  push({
    id: "topRisk",
    title: "Highest risk components",
    severity: "critical",
    count: topRisk.length,
    summary: `Top ${topRisk.length} components ranked by weighted risk score.`,
    details: topRisk.slice(0, 6).map((p) => `${p.name} ${p.version} — risk ${p.riskScore} (${p.riskCategory})`),
    columns: ["Component", "Version", "Severity", "Risk", "Exposure", "Action"],
    rows: topRisk.map((p) => [p.name, p.version || "—", p.severity, p.riskScore, p.exposure, p.recommendedAction]),
    prompt: "Why are the highest risk components rated that way?",
  });

  return {
    profiles,
    intel,
    licenses,
    deps,
    applications: [...appMap.keys()].sort(),
    vendors: [...vendorMap.keys()].sort(),
    counts,
    duplicates,
    missingMetadata,
    healthScore,
    overallRisk,
    riskCategory: overallRisk >= 75 ? "Critical" : overallRisk >= 50 ? "Elevated" : overallRisk >= 25 ? "Moderate" : "Healthy",
    confidence,
    findings,
  };
}

/* ============================== SBOM comparison ============================== */
export type CompareResult = {
  added: ComponentProfile[];
  removed: ComponentProfile[];
  updated: Array<{ name: string; from: string; to: string; a: ComponentProfile; b: ComponentProfile }>;
  unchanged: number;
  newVulns: ComponentProfile[];
  resolvedVulns: ComponentProfile[];
  newEol: ComponentProfile[];
  resolvedEol: ComponentProfile[];
  licenseChanges: Array<{ name: string; from: string; to: string }>;
  dependencyChanges: Array<{ name: string; from: number; to: number }>;
  riskDelta: number;
};

export function compareAnalyses(a: PlatformAnalysis, b: PlatformAnalysis): CompareResult {
  const key = (p: ComponentProfile) => p.name.toLowerCase();
  const mapA = new Map(a.profiles.map((p) => [key(p), p]));
  const mapB = new Map(b.profiles.map((p) => [key(p), p]));

  const added = b.profiles.filter((p) => !mapA.has(key(p)));
  const removed = a.profiles.filter((p) => !mapB.has(key(p)));
  const updated: CompareResult["updated"] = [];
  const licenseChanges: CompareResult["licenseChanges"] = [];
  const dependencyChanges: CompareResult["dependencyChanges"] = [];
  let unchanged = 0;

  for (const [k, pa] of mapA) {
    const pb = mapB.get(k);
    if (!pb) continue;
    if ((pa.version || "") !== (pb.version || "")) updated.push({ name: pb.name, from: pa.version || "—", to: pb.version || "—", a: pa, b: pb });
    else unchanged++;
    if ((pa.license || "") !== (pb.license || "")) licenseChanges.push({ name: pb.name, from: pa.license || "—", to: pb.license || "—" });
    if (pa.dependsOn.length !== pb.dependsOn.length) dependencyChanges.push({ name: pb.name, from: pa.dependsOn.length, to: pb.dependsOn.length });
  }

  const risky = (p: ComponentProfile) => p.severity === "critical" || p.severity === "high";
  const isEol = (p: ComponentProfile) => /End of|Obsolete/i.test(p.lifecycleStatus) || p.supportStatus === "Unsupported";

  const newVulns = b.profiles.filter((p) => risky(p) && !(mapA.get(key(p)) && risky(mapA.get(key(p))!)));
  const resolvedVulns = a.profiles.filter((p) => risky(p) && !(mapB.get(key(p)) && risky(mapB.get(key(p))!)));
  const newEol = b.profiles.filter((p) => isEol(p) && !(mapA.get(key(p)) && isEol(mapA.get(key(p))!)));
  const resolvedEol = a.profiles.filter((p) => isEol(p) && !(mapB.get(key(p)) && isEol(mapB.get(key(p))!)));

  return {
    added, removed, updated, unchanged, newVulns, resolvedVulns, newEol, resolvedEol,
    licenseChanges, dependencyChanges,
    riskDelta: b.overallRisk - a.overallRisk,
  };
}

export { intelKey };
