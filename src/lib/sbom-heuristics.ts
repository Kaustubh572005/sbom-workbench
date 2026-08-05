/**
 * Heuristic risk estimation.
 *
 * Policy: we NEVER conclude "no vulnerability information available".
 * When an uploaded SBOM carries no CVE/CVSS data and external intelligence is
 * inconclusive, every component is still classified with an ESTIMATED severity,
 * the factors that drove it, a confidence level, and recommended actions.
 */

export type Row = Record<string, unknown>;
export type Sev = "critical" | "high" | "medium" | "low" | "info";

export type RiskFactor = { label: string; weight: number; detail?: string };

export type ComponentRisk = {
  id: string;
  name: string;
  version: string;
  supplier: string;
  ecosystem: string;
  license: string;
  purl: string;
  cpe: string;
  application: string;
  cve: string;
  cvss: number;
  reportedSeverity: Sev | "";
  estimated: boolean;
  severity: Sev;
  score: number;            // 0-100 composite risk
  confidence: number;       // 0-100
  factors: RiskFactor[];
  rationale: string;
  actions: string[];
  fixAvailable: boolean;
  fixedVersion: string;
  patchPriority: "P0" | "P1" | "P2" | "P3";
  eol: boolean;
  missing: string[];
  categories: string[];
  raw: Row;
};

const str = (r: Row, keys: string[]): string => {
  for (const [k, v] of Object.entries(r)) {
    const lk = k.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (keys.some((c) => lk === c || lk.includes(c))) {
      const s = String(v ?? "").trim();
      if (s && s !== "-" && s.toLowerCase() !== "n/a") return s;
    }
  }
  return "";
};

const num = (s: string) => {
  const m = /-?\d+(\.\d+)?/.exec(s);
  return m ? parseFloat(m[0]) : 0;
};

export function sevFromScore(score: number): Sev {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  if (score >= 15) return "low";
  return "info";
}

function sevFromCvss(c: number): Sev {
  if (c >= 9) return "critical";
  if (c >= 7) return "high";
  if (c >= 4) return "medium";
  if (c > 0) return "low";
  return "info";
}

function normalizeSev(s: string): Sev | "" {
  const t = s.toLowerCase();
  if (/crit|sev-?1|p0|blocker/.test(t)) return "critical";
  if (/high|severe|major/.test(t)) return "high";
  if (/med|moderate/.test(t)) return "medium";
  if (/low|minor/.test(t)) return "low";
  if (/info|none|negligible/.test(t)) return "info";
  return "";
}

/* ------------------------------ category signals ----------------------------- */
const CATEGORY_RULES: Array<{ re: RegExp; label: string; weight: number }> = [
  { re: /(openssl|libressl|boringssl|crypto|bcrypt|jwt|jose|rsa|aes|tls|ssl|nacl|gpg)/i, label: "Cryptography package", weight: 14 },
  { re: /(auth|oauth|saml|oidc|passport|keycloak|login|session|identity|ldap|kerberos)/i, label: "Authentication package", weight: 14 },
  { re: /(kernel|glibc|musl|systemd|busybox|libc|driver)/i, label: "Kernel / OS package", weight: 13 },
  { re: /(nginx|apache|httpd|tomcat|jetty|netty|express|flask|django|spring|struts|iis|node|envoy|haproxy)/i, label: "Internet-facing / network package", weight: 13 },
  { re: /(mysql|postgres|mongo|redis|oracle|mssql|sqlite|mariadb|elastic|cassandra|jdbc|hibernate)/i, label: "Database package", weight: 9 },
  { re: /(log4j|logback|jackson|xstream|snakeyaml|struts|commons-collections|spring-core|shiro|fastjson)/i, label: "Known-exploited history", weight: 20 },
  { re: /(python2|jquery\s*1|angularjs|bootstrap\s*3|php\s*5|java\s*7|dotnet\s*framework|struts\s*1|node\s*(0|4|6|8|10|12))/i, label: "Legacy / deprecated software", weight: 16 },
  { re: /(serialize|deserial|xml|yaml|parse|template|regex|zip|tar|image|pdf|font)/i, label: "Parser / untrusted-input surface", weight: 7 },
  { re: /(runtime|jre|jdk|dotnet|python|ruby|perl|php|node)/i, label: "Runtime package", weight: 8 },
];

const RISKY_LICENSES = /(agpl|gpl-3|gpl-2|sspl|cc-by-nc|bsl|commons clause|unlicen|proprietary|custom)/i;
const GPL = /(^|\W)(a?gpl)/i;

const EOL_HINTS: Array<{ re: RegExp; label: string }> = [
  { re: /(python\s*2|node\s*(0|4|6|8|10|12)|java\s*[678]|centos\s*[678]|ubuntu\s*1[0-6]|debian\s*[89]|windows\s*(7|2008|2012)|php\s*[567]\.|angularjs|jquery\s*1)/i, label: "End-of-Life release family" },
];

function ageFactor(version: string, releaseDate: string): RiskFactor | null {
  const d = releaseDate ? Date.parse(releaseDate) : NaN;
  if (!Number.isNaN(d)) {
    const years = (Date.now() - d) / (365.25 * 24 * 3600 * 1000);
    if (years >= 5) return { label: "Version older than 5 years", weight: 16, detail: `${years.toFixed(1)} years old` };
    if (years >= 3) return { label: "Version older than 3 years", weight: 10, detail: `${years.toFixed(1)} years old` };
    if (years >= 1.5) return { label: "Ageing version", weight: 5, detail: `${years.toFixed(1)} years old` };
    return null;
  }
  const major = num(version.split(".")[0] ?? "");
  if (version && major === 0) return { label: "Pre-1.0 / unstable version", weight: 8 };
  return null;
}

/* --------------------------------- main pass -------------------------------- */
export function assessComponent(id: string, raw: Row, versionsSeen = 1, depth = 0): ComponentRisk {
  const name = str(raw, ["component", "packagename", "library", "product", "name", "module", "artifact"]);
  const version = str(raw, ["version", "release"]);
  const supplier = str(raw, ["supplier", "vendor", "publisher", "manufacturer", "author", "originator"]);
  const ecosystem = str(raw, ["ecosystem", "packagemanager", "type"]);
  const license = str(raw, ["license", "licence", "spdx"]);
  const purl = str(raw, ["purl", "packageurl"]);
  const cpe = str(raw, ["cpe"]);
  const application = str(raw, ["application", "app", "project", "service", "system", "parentcomponent"]);
  const cve = str(raw, ["cve", "advisory", "ghsa", "vulnerabilityid", "vulnid"]);
  const releaseDate = str(raw, ["releasedate", "published", "date"]);
  const declaredSev = normalizeSev(str(raw, ["severity", "risk", "criticality", "impact", "priority"]));
  const cvss = num(str(raw, ["cvss", "basescore", "score"]));
  const fixedVersion = str(raw, ["fixedversion", "fixversion", "patchversion", "remediation", "fixavailable"]);
  const blob = `${name} ${version} ${supplier} ${ecosystem} ${JSON.stringify(raw)}`;

  const factors: RiskFactor[] = [];
  const missing: string[] = [];
  const categories: string[] = [];

  for (const rule of CATEGORY_RULES) {
    if (rule.re.test(`${name} ${ecosystem} ${supplier}`)) {
      factors.push({ label: rule.label, weight: rule.weight });
      categories.push(rule.label);
    }
  }

  if (!version) { factors.push({ label: "Missing version — cannot be matched to advisories", weight: 18 }); missing.push("Version"); }
  if (!supplier) { factors.push({ label: "Missing supplier / originator", weight: 10 }); missing.push("Supplier"); }
  if (!license) { factors.push({ label: "Missing license declaration", weight: 8 }); missing.push("License"); }
  if (!purl) missing.push("PURL");
  if (!cpe) missing.push("CPE");
  if (!purl && !cpe) factors.push({ label: "No PURL and no CPE — weak identifiability", weight: 12 });
  if (!name) { factors.push({ label: "Unknown / unnamed package", weight: 20 }); missing.push("Name"); }

  const age = ageFactor(version, releaseDate);
  if (age) factors.push(age);

  const eolHit = EOL_HINTS.find((h) => h.re.test(`${name} ${version}`));
  const eolFlag = /\b(eol|end of life|end-of-life|unsupported|deprecated|expired|obsolete|no longer supported)\b/i.test(blob);
  const eol = Boolean(eolHit) || eolFlag;
  if (eol) factors.push({ label: eolHit?.label ?? "Marked End-of-Life / unsupported", weight: 22 });

  if (versionsSeen > 1) factors.push({ label: `Multiple versions in estate (${versionsSeen})`, weight: 9 });
  if (depth >= 3) factors.push({ label: `Deep transitive dependency (depth ${depth})`, weight: 6 });
  if (/indirect|transitive/i.test(blob)) factors.push({ label: "Transitive dependency — supply-chain exposure", weight: 5 });
  if (/static.?link/i.test(blob)) factors.push({ label: "Statically linked — patching requires rebuild", weight: 7 });
  if (/dynamic.?link/i.test(blob)) factors.push({ label: "Dynamically linked", weight: 3 });
  if (RISKY_LICENSES.test(license)) factors.push({ label: `License obligation risk (${license})`, weight: GPL.test(license) ? 12 : 8 });
  if (/(kev|known exploited|exploit available|in the wild|weaponized|actively exploited)/i.test(blob))
    factors.push({ label: "Known exploited / exploit available", weight: 30 });

  let score = 0;
  let estimated = true;
  let reportedSeverity: Sev | "" = "";

  if (cvss > 0) {
    estimated = false;
    reportedSeverity = sevFromCvss(cvss);
    score = Math.min(100, cvss * 9);
  } else if (declaredSev) {
    estimated = false;
    reportedSeverity = declaredSev;
    score = { critical: 90, high: 72, medium: 48, low: 22, info: 8 }[declaredSev];
  } else if (cve) {
    estimated = false;
    reportedSeverity = "high";
    score = 70;
  }

  const heuristic = factors.reduce((a, f) => a + f.weight, 0);
  score = Math.min(100, Math.round(estimated ? Math.min(96, heuristic * 1.15 + 6) : Math.min(100, score + heuristic * 0.35)));
  const severity = estimated ? sevFromScore(score) : (reportedSeverity as Sev);

  // Confidence: identifiability + evidence quality
  let confidence = estimated ? 45 : 80;
  if (purl) confidence += 12;
  if (cpe) confidence += 8;
  if (version) confidence += 10;
  if (supplier) confidence += 5;
  if (cvss > 0) confidence += 10;
  if (!name) confidence -= 20;
  confidence = Math.max(15, Math.min(98, confidence));

  const fixAvailable = Boolean(fixedVersion) || /(fix|patch)\s*(available|released)|upgrade to/i.test(blob);
  const patchPriority: ComponentRisk["patchPriority"] =
    severity === "critical" ? "P0" : severity === "high" ? "P1" : severity === "medium" ? "P2" : "P3";

  const actions: string[] = [];
  if (fixAvailable && fixedVersion) actions.push(`Upgrade ${name || "component"} to ${fixedVersion}`);
  else if (severity === "critical" || severity === "high") actions.push(`Identify and apply the latest supported release of ${name || "this component"}; if none exists, isolate or replace it`);
  if (eol) actions.push("Plan migration off the End-of-Life release family (no security patches will be issued)");
  if (!version) actions.push("Record the exact version in the SBOM so advisory matching becomes possible");
  if (!purl && !cpe) actions.push("Add a PURL or CPE identifier to enable automated vulnerability correlation");
  if (!supplier) actions.push("Record the supplier/originator for vendor advisory tracking");
  if (RISKY_LICENSES.test(license)) actions.push(`Legal review of ${license} obligations before distribution`);
  if (categories.some((c) => /Cryptography|Authentication/.test(c))) actions.push("Priority review: security-critical package — verify configuration and patch level");
  if (!actions.length) actions.push("Keep under continuous monitoring; re-scan on each SBOM refresh");

  const rationale = estimated
    ? `No CVE/CVSS evidence was supplied for this component and public sources could not be matched deterministically${!purl && !cpe ? " because it carries neither a PURL nor a CPE" : ""}. Severity is therefore ESTIMATED at ${severity.toUpperCase()} (confidence ${confidence}%) from ${factors.length} risk factor(s): ${factors.slice(0, 4).map((f) => f.label).join(", ") || "baseline supply-chain exposure"}.`
    : `Severity ${severity.toUpperCase()} is derived from supplied evidence${cve ? ` (${cve})` : ""}${cvss ? ` with CVSS ${cvss}` : ""}, adjusted for ${factors.length} contextual factor(s).`;

  return {
    id, name: name || "(unnamed component)", version, supplier, ecosystem, license, purl, cpe,
    application, cve, cvss, reportedSeverity, estimated, severity, score, confidence, factors,
    rationale, actions, fixAvailable, fixedVersion, patchPriority, eol, missing, categories, raw,
  };
}

export function assessAll(items: Array<{ id: string; data: Row }>): ComponentRisk[] {
  const versionCount = new Map<string, Set<string>>();
  for (const it of items) {
    const n = str(it.data, ["component", "packagename", "library", "product", "name"]).toLowerCase();
    if (!n) continue;
    const set = versionCount.get(n) ?? new Set<string>();
    set.add(str(it.data, ["version", "release"]));
    versionCount.set(n, set);
  }
  return items.map((it) => {
    const n = str(it.data, ["component", "packagename", "library", "product", "name"]).toLowerCase();
    const depth = (str(it.data, ["dependencies"]).match(/;/g)?.length ?? 0) > 0 ? 1 : 0;
    return assessComponent(it.id, it.data, versionCount.get(n)?.size ?? 1, depth);
  });
}
