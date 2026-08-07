/**
 * Lifecycle & Remediation Intelligence.
 *
 * Replaces the simplistic "Fix available / Without fix" model with a full
 * lifecycle assessment for every component: lifecycle status, vendor support
 * status, remediation status, recommended action, target version, priority,
 * confidence and evidence source.
 *
 * Order of authority:
 *   1. Uploaded SBOM fields (never overwritten)
 *   2. Curated vendor lifecycle knowledge base (official vendor documentation)
 *   3. External enrichment (endoflife.date / OSV.dev / NVD / GHSA)
 *   4. Heuristic estimated analysis
 * If nothing authoritative is found the component is classified
 * "Unknown (Requires Validation)" with an explicit reason.
 */

export type LifecycleStatus =
  | "Supported"
  | "Maintenance Mode"
  | "Deprecated"
  | "Obsolete"
  | "Legacy"
  | "End of Support (EOS)"
  | "End of Life (EOL)"
  | "Unknown (Requires Validation)";

export type SupportStatus = "Supported" | "Unsupported" | "Legacy Platform" | "Vendor Support Unknown";

export type RemediationStatus =
  | "Up To Date"
  | "Update Available"
  | "Upgrade Required"
  | "Platform Migration Required"
  | "Vendor Validation Required"
  | "Manual Review Required";

export type LifecyclePriority = "Critical" | "High" | "Medium" | "Low";
export type ConfidenceLevel = "High" | "Medium" | "Low";
export type EvidenceSource =
  | "Original SBOM"
  | "Official Vendor Documentation"
  | "NVD"
  | "GitHub Security Advisories"
  | "OSV.dev"
  | "Estimated Analysis";

export type LifecycleAssessment = {
  lifecycleStatus: LifecycleStatus;
  supportStatus: SupportStatus;
  remediationStatus: RemediationStatus;
  recommendedAction: string;
  latestStableVersion: string;
  targetVersion: string;
  priority: LifecyclePriority;
  confidence: ConfidenceLevel;
  confidenceScore: number;
  evidenceSource: EvidenceSource;
  evidenceDetail: string;
  /** why we could not confirm lifecycle, or why this classification was chosen */
  reason: string;
};

/* --------------------------------- versions -------------------------------- */

const parts = (v: string): number[] =>
  String(v)
    .replace(/^[^0-9]*/, "")
    .split(/[^0-9]+/)
    .filter((s) => s !== "")
    .slice(0, 4)
    .map((s) => Number(s));

/** -1 a<b, 0 equal, 1 a>b; NaN-safe */
export function cmpVersion(a: string, b: string): number {
  const A = parts(a);
  const B = parts(b);
  if (!A.length || !B.length) return 0;
  for (let i = 0; i < Math.max(A.length, B.length); i++) {
    const x = A[i] ?? 0;
    const y = B[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
const majorOf = (v: string) => parts(v)[0] ?? -1;
const minorOf = (v: string) => parts(v)[1] ?? 0;

/* ------------------------- vendor lifecycle knowledge ---------------------- */

type Kb = {
  product: string;
  match: RegExp;
  /** current latest stable release line */
  latest: string;
  /** recommended upgrade target phrasing, e.g. "13.x or later" */
  targetLabel?: string;
  /** below this version → End of Life */
  eolBelow?: string;
  /** below this version → Obsolete */
  obsoleteBelow?: string;
  /** below this version → Deprecated */
  deprecatedBelow?: string;
  /** below this version → Maintenance Mode (still patched, not developed) */
  maintenanceBelow?: string;
  /** whole product line is a legacy platform requiring migration */
  legacyPlatform?: { target: string; note: string };
  note?: string;
};

const KB: Kb[] = [
  { product: "Json.NET (Newtonsoft.Json)", match: /^(newtonsoft\.?json|json\.?net)/i, latest: "13.0.3", targetLabel: "Json.NET 13.x or later", eolBelow: "7.0.0", obsoleteBelow: "12.0.0", deprecatedBelow: "13.0.0", note: "Newtonsoft.Json 12.x and older no longer receive fixes; 13.x is the maintained line." },
  { product: "zlib", match: /^zlib(?!-ng)/i, latest: "1.3.1", targetLabel: "zlib 1.3.x or later", eolBelow: "1.2.12", obsoleteBelow: "1.3.0", note: "zlib releases before 1.2.12 are end-of-life and affected by CVE-2018-25032 / CVE-2022-37434." },
  { product: "DirectX", match: /^direct\s?x|^d3d(9|10|11)?$/i, latest: "12", targetLabel: "DirectX 12", legacyPlatform: { target: "DirectX 12 and a supported Windows release", note: "DirectX 10/11 runtimes ship only for backward compatibility on legacy Windows versions." } },
  { product: "SQLite", match: /^sqlite/i, latest: "3.51.1", targetLabel: "SQLite 3.51.1", eolBelow: "3.32.0", obsoleteBelow: "3.40.0", maintenanceBelow: "3.51.0", note: "SQLite is actively maintained; only the newest 3.x point release receives fixes." },
  { product: "OpenSSL", match: /^openssl/i, latest: "3.5.0", targetLabel: "OpenSSL 3.x (LTS)", eolBelow: "1.1.1", obsoleteBelow: "3.0.0", note: "OpenSSL 1.0.x and 1.1.1 are end-of-life; 3.x is the supported line." },
  { product: "Apache Log4j", match: /log4j/i, latest: "2.24.3", targetLabel: "Log4j 2.24.x or later", eolBelow: "2.17.0", obsoleteBelow: "2.20.0", note: "Log4j 1.x is end-of-life; 2.x before 2.17 is vulnerable to Log4Shell family issues." },
  { product: "jQuery", match: /^jquery$/i, latest: "3.7.1", targetLabel: "jQuery 3.7.x", eolBelow: "3.0.0", obsoleteBelow: "3.5.0", note: "jQuery 1.x/2.x are unsupported; XSS fixes landed in 3.5.0." },
  { product: "Node.js", match: /^node(\.?js)?$/i, latest: "24.x", targetLabel: "Node.js 22 LTS or later", eolBelow: "18.0.0", obsoleteBelow: "20.0.0", note: "Node.js lines below 20 are past end-of-life." },
  { product: "Python", match: /^python/i, latest: "3.13", targetLabel: "Python 3.12 or later", eolBelow: "3.9", obsoleteBelow: "3.11", note: "Python 2.x and 3.8 and below are end-of-life." },
  { product: "Microsoft .NET", match: /^(\.net|dotnet|microsoft\.?net)/i, latest: "9.0", targetLabel: ".NET 8 LTS or later", eolBelow: "6.0", obsoleteBelow: "8.0", note: ".NET Framework 4.x is in maintenance; .NET Core lines below 8 are out of support." },
  { product: "Apache Tomcat", match: /tomcat/i, latest: "11.0", targetLabel: "Tomcat 10.1 or later", eolBelow: "9.0", obsoleteBelow: "10.1", note: "Tomcat 7/8.0 are end-of-life." },
  { product: "Spring Framework", match: /^spring(-|\s)?(framework|core|boot)?/i, latest: "6.2", targetLabel: "Spring Boot 3.x / Framework 6.x", eolBelow: "5.3", obsoleteBelow: "6.0", note: "Spring Framework 4.x/5.2 and Spring Boot 2.x are out of OSS support." },
  { product: "OpenSSH", match: /openssh/i, latest: "9.9", targetLabel: "OpenSSH 9.x", eolBelow: "8.0", obsoleteBelow: "9.0" },
  { product: "curl / libcurl", match: /^(lib)?curl/i, latest: "8.12.0", targetLabel: "curl 8.x", eolBelow: "7.80.0", obsoleteBelow: "8.0.0" },
  { product: "Apache HTTP Server", match: /^(apache(2)?$|httpd)/i, latest: "2.4.63", targetLabel: "Apache HTTP Server 2.4.63+", eolBelow: "2.4.0", obsoleteBelow: "2.4.55" },
  { product: "nginx", match: /^nginx/i, latest: "1.27", targetLabel: "nginx 1.27 (mainline) or 1.26 (stable)", eolBelow: "1.20", obsoleteBelow: "1.24" },
  { product: "MySQL", match: /^mysql/i, latest: "8.4", targetLabel: "MySQL 8.4 LTS", eolBelow: "5.8", obsoleteBelow: "8.0" },
  { product: "PostgreSQL", match: /^postgre/i, latest: "17", targetLabel: "PostgreSQL 16 or later", eolBelow: "13", obsoleteBelow: "15" },
  { product: "Windows Server", match: /windows\s?server/i, latest: "2022", targetLabel: "Windows Server 2022 or later", eolBelow: "2016", obsoleteBelow: "2019" },
  { product: "Windows (client)", match: /^windows\s?(7|8|8\.1|10|xp|vista)/i, latest: "11", targetLabel: "Windows 11", legacyPlatform: { target: "Windows 11 (or a supported Windows 10 LTSC channel)", note: "Legacy Windows client releases are outside mainstream support." } },
  { product: "Internet Explorer", match: /internet\s?explorer|^msie/i, latest: "—", targetLabel: "Microsoft Edge (Chromium)", legacyPlatform: { target: "Microsoft Edge", note: "Internet Explorer is retired and permanently unsupported." } },
  { product: "Adobe Flash", match: /flash\s?player|^flash$/i, latest: "—", targetLabel: "HTML5 replacement", legacyPlatform: { target: "an HTML5-based replacement", note: "Flash Player reached end-of-life and is blocked in all browsers." } },
  { product: "Silverlight", match: /silverlight/i, latest: "—", targetLabel: "HTML5 replacement", legacyPlatform: { target: "an HTML5/Blazor replacement", note: "Silverlight is retired." } },
  { product: "AngularJS", match: /^angular\.?js$/i, latest: "—", targetLabel: "Angular (modern)", legacyPlatform: { target: "Angular 17+", note: "AngularJS 1.x reached end-of-life in Jan 2022." } },
  { product: "Bootstrap", match: /^bootstrap/i, latest: "5.3.3", targetLabel: "Bootstrap 5.3.x", eolBelow: "4.0.0", obsoleteBelow: "5.0.0" },
  { product: "Lodash", match: /^lodash/i, latest: "4.17.21", targetLabel: "lodash 4.17.21", eolBelow: "4.17.12", obsoleteBelow: "4.17.21" },
  { product: "Log4Net", match: /log4net/i, latest: "3.0.4", targetLabel: "log4net 3.x", eolBelow: "2.0.10", obsoleteBelow: "3.0.0" },
  { product: "Struts", match: /struts/i, latest: "7.0", targetLabel: "Struts 7.x", eolBelow: "2.5.30", obsoleteBelow: "6.0" },
  { product: "Jackson Databind", match: /jackson-databind/i, latest: "2.18.2", targetLabel: "jackson-databind 2.18.x", eolBelow: "2.12.0", obsoleteBelow: "2.17.0" },
  { product: "Java (OpenJDK/JRE)", match: /^(java|jdk|jre|openjdk)/i, latest: "23", targetLabel: "Java 21 LTS or later", eolBelow: "11", obsoleteBelow: "17" },
];

const findKb = (component: string): Kb | null => {
  const name = component.trim();
  if (!name) return null;
  return KB.find((k) => k.match.test(name)) ?? null;
};

/* --------------------------------- inputs --------------------------------- */

export type LifecycleInput = {
  component: string;
  version: string;
  vendor?: string;
  severity?: string;
  cvss?: number;
  kev?: boolean;
  exploit?: boolean;
  /** uploaded SBOM signals */
  uploadedFix?: string;
  uploadedEol?: boolean;
  uploadedStatus?: string;
  /** merged external intelligence */
  intel?: {
    latestVersion?: string;
    fixedVersion?: string;
    eolDate?: string;
    supportEndDate?: string;
    advisoryIds?: string[];
    source?: string;
    updatedAt?: string;
  };
};

const DEPRECATED_RE = /deprecat|superseded|no longer maintained|discontinued|retired|archived/i;
const EOL_RE = /\beol\b|end[\s-]?of[\s-]?life|unsupported|end[\s-]?of[\s-]?support|\beos\b/i;

const isPast = (d?: string) => {
  if (!d) return false;
  const t = Date.parse(d);
  return Number.isFinite(t) && t < Date.now();
};

function priorityOf(input: LifecycleInput, lifecycle: LifecycleStatus, remediation: RemediationStatus): LifecyclePriority {
  const sev = String(input.severity ?? "").toLowerCase();
  const unsupported =
    lifecycle === "End of Life (EOL)" || lifecycle === "End of Support (EOS)" || lifecycle === "Obsolete";
  if (input.kev || input.exploit || sev === "critical" || (input.cvss ?? 0) >= 9) return "Critical";
  if (unsupported || sev === "high" || (input.cvss ?? 0) >= 7) return unsupported && sev === "high" ? "Critical" : "High";
  if (lifecycle === "Legacy" || remediation === "Platform Migration Required" || sev === "medium") return "High";
  if (remediation === "Update Available" || lifecycle === "Deprecated" || lifecycle === "Maintenance Mode") return "Medium";
  if (remediation === "Vendor Validation Required" || remediation === "Manual Review Required") return "Medium";
  return "Low";
}

const bandOf = (score: number): ConfidenceLevel => (score >= 75 ? "High" : score >= 45 ? "Medium" : "Low");

function evidenceFromIntel(source?: string): EvidenceSource | null {
  if (!source) return null;
  if (/endoflife/i.test(source)) return "Official Vendor Documentation";
  if (/osv/i.test(source)) return "OSV.dev";
  if (/ghsa|github/i.test(source)) return "GitHub Security Advisories";
  if (/nvd|kev|cisa/i.test(source)) return "NVD";
  return null;
}

/* -------------------------------- assessment ------------------------------- */

export function assessLifecycle(input: LifecycleInput): LifecycleAssessment {
  const name = (input.component || "").trim();
  const version = (input.version || "").trim();
  const intel = input.intel ?? {};
  const kb = findKb(name);
  const statusBlob = `${input.uploadedStatus ?? ""}`;

  const latestStableVersion = intel.latestVersion || kb?.latest || intel.fixedVersion || input.uploadedFix || "";
  const targetLabel = kb?.targetLabel || latestStableVersion;

  let lifecycleStatus: LifecycleStatus = "Unknown (Requires Validation)";
  let supportStatus: SupportStatus = "Vendor Support Unknown";
  let remediationStatus: RemediationStatus = "Vendor Validation Required";
  let recommendedAction = "";
  let reason = "";
  let confidenceScore = 30;
  let evidenceSource: EvidenceSource = "Estimated Analysis";
  let evidenceDetail = "Heuristic classification — no authoritative lifecycle record matched.";
  let targetVersion = targetLabel || "";

  const intelEvidence = evidenceFromIntel(intel.source);

  /* 1 — legacy platform lines (DirectX 10, IE, Flash, AngularJS…) */
  if (kb?.legacyPlatform) {
    lifecycleStatus = "Legacy";
    supportStatus = "Legacy Platform";
    remediationStatus = "Platform Migration Required";
    targetVersion = kb.legacyPlatform.target;
    recommendedAction = `Migrate to ${kb.legacyPlatform.target}.`;
    reason = kb.legacyPlatform.note;
    confidenceScore = 88;
    evidenceSource = "Official Vendor Documentation";
    evidenceDetail = `${kb.product} lifecycle policy (vendor documentation).`;
  }
  /* 2 — explicit external EOL / EOS dates */
  else if (isPast(intel.eolDate)) {
    lifecycleStatus = "End of Life (EOL)";
    supportStatus = "Unsupported";
    remediationStatus = "Upgrade Required";
    recommendedAction = latestStableVersion
      ? `Upgrade ${name || "component"} to ${targetLabel}.`
      : `Replace ${name || "component"} — the release line reached end of life on ${intel.eolDate}.`;
    reason = `Vendor lifecycle data records end of life on ${intel.eolDate}.`;
    confidenceScore = 90;
    evidenceSource = intelEvidence ?? "Official Vendor Documentation";
    evidenceDetail = `Lifecycle feed (${intel.source ?? "endoflife.date"}) — EOL ${intel.eolDate}.`;
  } else if (isPast(intel.supportEndDate)) {
    lifecycleStatus = "End of Support (EOS)";
    supportStatus = "Unsupported";
    remediationStatus = "Upgrade Required";
    recommendedAction = `Upgrade ${name || "component"} to ${targetLabel || "a vendor-supported release"}.`;
    reason = `Active vendor support ended on ${intel.supportEndDate}; only the newest line receives fixes.`;
    confidenceScore = 85;
    evidenceSource = intelEvidence ?? "Official Vendor Documentation";
    evidenceDetail = `Lifecycle feed (${intel.source ?? "endoflife.date"}) — support ended ${intel.supportEndDate}.`;
  }
  /* 3 — curated vendor knowledge base version tiers */
  else if (kb && version) {
    const below = (bound?: string) => Boolean(bound && cmpVersion(version, bound) < 0);
    evidenceSource = "Official Vendor Documentation";
    evidenceDetail = `${kb.product} release lifecycle (vendor documentation)${intel.latestVersion ? ` · latest confirmed ${intel.latestVersion}` : ""}.`;
    confidenceScore = 85;
    if (below(kb.eolBelow)) {
      lifecycleStatus = "End of Life (EOL)";
      supportStatus = "Unsupported";
      remediationStatus = "Upgrade Required";
      recommendedAction = `Upgrade to ${targetLabel}.`;
      reason = kb.note ?? `${kb.product} ${version} predates the supported release line.`;
    } else if (below(kb.obsoleteBelow)) {
      lifecycleStatus = "Obsolete";
      supportStatus = "Unsupported";
      remediationStatus = "Upgrade Required";
      recommendedAction = `Upgrade to ${targetLabel}.`;
      reason = kb.note ?? `${kb.product} ${version} is superseded by ${kb.latest} and receives no fixes.`;
    } else if (below(kb.deprecatedBelow)) {
      lifecycleStatus = "Deprecated";
      supportStatus = "Vendor Support Unknown";
      remediationStatus = "Upgrade Required";
      recommendedAction = `Upgrade to ${targetLabel}.`;
      reason = kb.note ?? `${kb.product} ${version} is deprecated in favour of ${kb.latest}.`;
      confidenceScore = 78;
    } else if (below(kb.maintenanceBelow) || (latestStableVersion && cmpVersion(version, latestStableVersion) < 0)) {
      const majorGap = majorOf(latestStableVersion) - majorOf(version);
      lifecycleStatus = majorGap > 0 ? "Maintenance Mode" : "Supported";
      supportStatus = "Supported";
      remediationStatus = majorGap > 0 ? "Upgrade Required" : "Update Available";
      recommendedAction = `Upgrade to ${targetLabel}.`;
      reason = `${kb.product} is actively maintained; ${version} trails the current release ${latestStableVersion}.`;
      confidenceScore = 82;
    } else {
      lifecycleStatus = "Supported";
      supportStatus = "Supported";
      remediationStatus = "Up To Date";
      recommendedAction = `No action required — ${name} ${version} is on the current supported line.`;
      reason = `${kb.product} ${version} matches the latest maintained release.`;
      targetVersion = version;
      confidenceScore = 80;
    }
  }
  /* 4 — uploaded SBOM signals */
  else if (input.uploadedEol || EOL_RE.test(statusBlob)) {
    lifecycleStatus = EOL_RE.test(statusBlob) && /support/i.test(statusBlob) ? "End of Support (EOS)" : "End of Life (EOL)";
    supportStatus = "Unsupported";
    remediationStatus = latestStableVersion ? "Upgrade Required" : "Vendor Validation Required";
    recommendedAction = latestStableVersion
      ? `Upgrade ${name || "component"} to ${targetLabel}.`
      : `Confirm the vendor's supported release for ${name || "this component"} and plan an upgrade or replacement.`;
    reason = "The uploaded SBOM/VAPT record flags this component as end-of-life or unsupported.";
    confidenceScore = 70;
    evidenceSource = "Original SBOM";
    evidenceDetail = "Lifecycle flag present in the uploaded file.";
  } else if (DEPRECATED_RE.test(statusBlob)) {
    lifecycleStatus = "Deprecated";
    supportStatus = "Vendor Support Unknown";
    remediationStatus = "Upgrade Required";
    recommendedAction = latestStableVersion
      ? `Upgrade ${name || "component"} to ${targetLabel}.`
      : `Replace ${name || "component"} with the vendor's maintained successor.`;
    reason = "The uploaded record marks this component as deprecated or discontinued.";
    confidenceScore = 65;
    evidenceSource = "Original SBOM";
    evidenceDetail = "Deprecation note present in the uploaded file.";
  }
  /* 5 — advisory-derived fixed version (OSV / GHSA / NVD) */
  else if (version && (intel.fixedVersion || input.uploadedFix)) {
    const fixed = intel.fixedVersion || input.uploadedFix || "";
    const behind = cmpVersion(version, fixed) < 0;
    const majorGap = majorOf(fixed) - majorOf(version);
    lifecycleStatus = behind ? (majorGap > 0 ? "Obsolete" : "Maintenance Mode") : "Supported";
    supportStatus = behind && majorGap > 0 ? "Unsupported" : "Supported";
    remediationStatus = !behind ? "Up To Date" : majorGap > 0 ? "Upgrade Required" : "Update Available";
    targetVersion = fixed;
    recommendedAction = behind
      ? `Upgrade ${name || "component"} ${version} to ${fixed} or later.`
      : `No upgrade needed — ${version} already includes the published fix (${fixed}).`;
    reason = behind
      ? `A patched release (${fixed}) exists for this component; the deployed version is older.`
      : `Deployed version is at or above the patched release ${fixed}.`;
    confidenceScore = intel.fixedVersion ? 72 : 60;
    evidenceSource = intel.fixedVersion ? (intelEvidence ?? "OSV.dev") : "Original SBOM";
    evidenceDetail = intel.fixedVersion
      ? `Advisory data${intel.advisoryIds?.length ? ` (${intel.advisoryIds.slice(0, 3).join(", ")})` : ""} via ${intel.source ?? "OSV.dev"}.`
      : "Fix version supplied in the uploaded file.";
  }
  /* 6 — latest version known, no lifecycle policy */
  else if (version && latestStableVersion && cmpVersion(version, latestStableVersion) < 0) {
    const majorGap = majorOf(latestStableVersion) - majorOf(version);
    const minorGap = minorOf(latestStableVersion) - minorOf(version);
    lifecycleStatus = majorGap >= 2 ? "Obsolete" : majorGap === 1 ? "Maintenance Mode" : "Supported";
    supportStatus = majorGap >= 2 ? "Unsupported" : "Supported";
    remediationStatus = majorGap >= 1 ? "Upgrade Required" : "Update Available";
    targetVersion = latestStableVersion;
    recommendedAction = `Upgrade ${name || "component"} ${version} to ${latestStableVersion}.`;
    reason = `Current release is ${latestStableVersion}; the deployed build is ${majorGap >= 1 ? `${majorGap} major` : `${Math.max(minorGap, 1)} minor`} version(s) behind.`;
    confidenceScore = 68;
    evidenceSource = intelEvidence ?? "Estimated Analysis";
    evidenceDetail = `Release metadata via ${intel.source ?? "public package data"}.`;
  }
  /* 7 — nothing authoritative */
  else {
    lifecycleStatus = "Unknown (Requires Validation)";
    supportStatus = "Vendor Support Unknown";
    remediationStatus = !version ? "Manual Review Required" : "Vendor Validation Required";
    const missing: string[] = [];
    if (!name) missing.push("component name");
    if (!version) missing.push("version");
    reason = missing.length
      ? `Lifecycle cannot be confirmed: the record is missing ${missing.join(" and ")}, so no vendor release line can be matched.`
      : `No vendor lifecycle record, advisory or release feed matched ${name} ${version}. Public sources (vendor docs, NVD, GHSA, OSV.dev, endoflife.date) returned no authoritative entry.`;
    recommendedAction = missing.length
      ? `Complete the SBOM record (${missing.join(", ")}), then re-run lifecycle analysis.`
      : `Confirm the supported release of ${name} with the vendor, record the lifecycle dates, then upgrade to the latest supported version.`;
    confidenceScore = missing.length ? 20 : 35;
    evidenceSource = "Estimated Analysis";
    evidenceDetail = "No authoritative lifecycle evidence available — requires vendor validation.";
  }

  if (!recommendedAction) recommendedAction = `Review ${name || "this component"} and upgrade to a vendor-supported release.`;
  if (input.kev) confidenceScore = Math.min(95, confidenceScore + 5);

  const priority = priorityOf(input, lifecycleStatus, remediationStatus);

  return {
    lifecycleStatus,
    supportStatus,
    remediationStatus,
    recommendedAction,
    latestStableVersion: latestStableVersion || "",
    targetVersion: targetVersion || latestStableVersion || "",
    priority,
    confidence: bandOf(confidenceScore),
    confidenceScore,
    evidenceSource,
    evidenceDetail,
    reason,
  };
}

/* ------------------------------- presentation ------------------------------ */

export const lifecycleTone: Record<LifecycleStatus, "critical" | "high" | "medium" | "low" | "info"> = {
  Supported: "low",
  "Maintenance Mode": "medium",
  Deprecated: "high",
  Obsolete: "critical",
  Legacy: "high",
  "End of Support (EOS)": "critical",
  "End of Life (EOL)": "critical",
  "Unknown (Requires Validation)": "info",
};

export const supportTone: Record<SupportStatus, "critical" | "high" | "medium" | "low" | "info"> = {
  Supported: "low",
  Unsupported: "critical",
  "Legacy Platform": "high",
  "Vendor Support Unknown": "info",
};

export const remediationTone: Record<RemediationStatus, "critical" | "high" | "medium" | "low" | "info"> = {
  "Up To Date": "low",
  "Update Available": "medium",
  "Upgrade Required": "critical",
  "Platform Migration Required": "high",
  "Vendor Validation Required": "info",
  "Manual Review Required": "info",
};

export const priorityTone: Record<LifecyclePriority, "critical" | "high" | "medium" | "low"> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
};

export const confidenceTone: Record<ConfidenceLevel, "low" | "medium" | "high"> = {
  High: "low",
  Medium: "medium",
  Low: "high",
};

export const LIFECYCLE_STATUSES: LifecycleStatus[] = [
  "Supported", "Maintenance Mode", "Deprecated", "Obsolete", "Legacy",
  "End of Support (EOS)", "End of Life (EOL)", "Unknown (Requires Validation)",
];
export const REMEDIATION_STATUSES: RemediationStatus[] = [
  "Up To Date", "Update Available", "Upgrade Required",
  "Platform Migration Required", "Vendor Validation Required", "Manual Review Required",
];
