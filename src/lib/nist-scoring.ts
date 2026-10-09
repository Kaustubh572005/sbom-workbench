/**
 * NIST scoring — the ONE place severity and risk are decided.
 *
 * Severity follows the NIST NVD qualitative scale for CVSS v3.x
 * (https://nvd.nist.gov/vuln-metrics/cvss):
 *     0.0 None · 0.1–3.9 Low · 4.0–6.9 Medium · 7.0–8.9 High · 9.0–10.0 Critical
 *
 * The CVSS base score is taken from the most authoritative source available:
 *     1. NIST NVD (live lookup by CVE)
 *     2. the CVSS score uploaded in the file
 *     3. computed from an uploaded CVSS v3.x vector using the NIST/FIRST formula
 *     4. a declared severity label (no score) — kept, but flagged as declared
 * A declared label never overrides a CVSS score: NIST bands always win.
 */
import type { SevKey } from "@/lib/risk-intel";

export type ScoreSource = "NIST NVD" | "Uploaded CVSS" | "CVSS vector (computed)" | "Declared severity" | "Unscored";

export const nistSeverity = (score: number): SevKey =>
  score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : score > 0 ? "low" : "none";

export const cveIds = (s: string): string[] =>
  [...new Set((s.match(/CVE-\d{4}-\d{4,}/gi) ?? []).map((c) => c.toUpperCase()))];

/* ------------------------ CVSS v3.0 / v3.1 base score ------------------------ */
const roundUp = (x: number) => {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
};

export function cvssFromVector(vector: string): number | null {
  const m = vector.trim().match(/^CVSS:3\.[01]\/(.+)$/i);
  if (!m) return null;
  const v: Record<string, string> = {};
  for (const part of m[1].split("/")) { const [k, val] = part.split(":"); if (k && val) v[k.toUpperCase()] = val.toUpperCase(); }
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[v.AV ?? ""];
  const AC = { L: 0.77, H: 0.44 }[v.AC ?? ""];
  const UI = { N: 0.85, R: 0.62 }[v.UI ?? ""];
  const cia = (k: string) => ({ H: 0.56, L: 0.22, N: 0 })[v[k] ?? ""];
  const changed = v.S === "C";
  const PR = (changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 })[v.PR ?? ""];
  const [C, I, A] = [cia("C"), cia("I"), cia("A")];
  if ([AV, AC, UI, PR, C, I, A].some((x) => x === undefined) || (v.S !== "C" && v.S !== "U")) return null;
  const iss = 1 - (1 - C!) * (1 - I!) * (1 - A!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * AV! * AC! * PR! * UI!;
  return roundUp(Math.min(changed ? 1.08 * (impact + exploitability) : impact + exploitability, 10));
}

/* ------------------------------- resolution -------------------------------- */
export type ResolvedSeverity = { score: number; severity: SevKey; source: ScoreSource; vector: string };

const validScore = (n: unknown) => (typeof n === "number" && n > 0 && n <= 10 ? Math.round(n * 10) / 10 : 0);

export function resolveSeverity(i: { nvdScore?: number; uploadedScore?: number; vector?: string; declared: SevKey }): ResolvedSeverity {
  const vector = (i.vector ?? "").trim();
  const nvd = validScore(i.nvdScore);
  if (nvd) return { score: nvd, severity: nistSeverity(nvd), source: "NIST NVD", vector };
  const up = validScore(i.uploadedScore);
  if (up) return { score: up, severity: nistSeverity(up), source: "Uploaded CVSS", vector };
  const computed = vector ? validScore(cvssFromVector(vector) ?? 0) : 0;
  if (computed) return { score: computed, severity: nistSeverity(computed), source: "CVSS vector (computed)", vector };
  if (i.declared !== "none") return { score: 0, severity: i.declared, source: "Declared severity", vector };
  return { score: 0, severity: "none", source: "Unscored", vector };
}

/* ----------------------------------- risk ----------------------------------- */
export type RiskFactor = { label: string; points: number; detail: string };

const DECLARED_FLOOR: Record<SevKey, number> = { critical: 90, high: 70, medium: 40, low: 10, info: 0, none: 0 };

/**
 * Risk score 0–100 = CVSS base score × 10 (so it sits inside the NIST band),
 * plus fixed, documented uplifts for conditions NIST scoring does not capture.
 */
export function nistRisk(i: {
  resolved: ResolvedSeverity; kev: boolean; exploit: boolean; pastEol: boolean; unsupported: boolean; exposed: boolean;
}): { score: number; factors: RiskFactor[] } {
  const factors: RiskFactor[] = [];
  const add = (label: string, points: number, detail: string) => { if (points > 0) factors.push({ label, points, detail }); };
  const { resolved: r } = i;

  if (r.score > 0) add("CVSS base score", Math.round(r.score * 10), `${r.source}: CVSS ${r.score} → NIST ${r.severity}`);
  else if (r.severity !== "none") add("Declared severity", DECLARED_FLOOR[r.severity], `Label “${r.severity}” declared without a CVSS score`);
  else if (i.pastEol) add("Lifecycle only", 35, "Past end-of-life — no CVSS score, so lifecycle is the only signal");

  if (i.kev) add("Known exploited (CISA KEV)", 10, "Listed as actively exploited in the wild");
  else if (i.exploit) add("Public exploit", 5, "A public exploit exists");
  if (i.pastEol && r.score > 0) add("Past end-of-life", 5, "Vendor no longer issues fixes");
  if (i.unsupported && !i.pastEol) add("Unsupported release", 3, "Release line is out of vendor support");
  if (i.exposed) add("Externally exposed", 5, "Row indicates internet / external exposure");

  const score = Math.min(100, factors.reduce((s, f) => s + f.points, 0));
  return { score, factors: factors.sort((a, b) => b.points - a.points) };
}

/** Overall posture band for an aggregate 0–100 risk score — the ONE definition used by the header, dashboard and datasets. */
export function postureBand(score: number): { label: "Critical" | "Elevated" | "Moderate" | "Healthy"; tone: "critical" | "high" | "medium" | "low"; desc: string } {
  return score >= 75 ? { label: "Critical", tone: "critical", desc: "Immediate action required" }
    : score >= 50 ? { label: "Elevated", tone: "high", desc: "Prioritize remediation" }
    : score >= 25 ? { label: "Moderate", tone: "medium", desc: "Monitor closely" }
    : { label: "Healthy", tone: "low", desc: "Posture is healthy" };
}
