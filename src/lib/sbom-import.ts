/**
 * JSON SBOM / scanner-report normalization.
 * Supports CycloneDX, SPDX (and SPDX-lite), generic arrays of objects,
 * and nested objects containing an obvious array of records.
 */

export type NormalizedImport = {
  rows: Record<string, unknown>[];
  columns: string[];
  format: string;
};

const flat = (v: unknown): string => {
  if (v == null) return "";
  if (Array.isArray(v)) return v.map(flat).filter(Boolean).join("; ");
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    for (const k of ["name", "id", "value", "url", "text", "version"]) {
      if (o[k] != null) return String(o[k]);
    }
    return JSON.stringify(v);
  }
  return String(v);
};

function severityFromScore(score: number): string {
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  if (score > 0) return "Low";
  return "";
}

/* ---------------------------------- CycloneDX --------------------------------- */
function parseCycloneDX(doc: Record<string, unknown>): Record<string, unknown>[] {
  const comps = (doc.components as Record<string, unknown>[] | undefined) ?? [];
  const vulns = (doc.vulnerabilities as Record<string, unknown>[] | undefined) ?? [];

  const byRef = new Map<string, Record<string, unknown>>();
  for (const c of comps) {
    const ref = String(c["bom-ref"] ?? c.purl ?? c.name ?? "");
    if (ref) byRef.set(ref, c);
  }

  const rows: Record<string, unknown>[] = [];

  // Vulnerability-centric rows first (richer)
  vulns.forEach((v, i) => {
    const affects = (v.affects as Array<{ ref?: string }> | undefined) ?? [];
    const ratings = (v.ratings as Array<Record<string, unknown>> | undefined) ?? [];
    const best = ratings.reduce<{ score: number; sev: string; vector: string }>(
      (acc, r) => {
        const s = Number(r.score) || 0;
        return s > acc.score
          ? { score: s, sev: String(r.severity ?? ""), vector: String(r.vector ?? "") }
          : acc;
      },
      { score: 0, sev: String(ratings[0]?.severity ?? ""), vector: "" },
    );
    const targets = affects.length ? affects : [{ ref: undefined }];
    for (const a of targets) {
      const c = a.ref ? byRef.get(String(a.ref)) : undefined;
      rows.push({
        "Sr No": rows.length + 1,
        Component: flat(c?.name) || flat(v.source) || "—",
        Version: flat(c?.version),
        Type: flat(c?.type),
        Publisher: flat(c?.publisher) || flat(c?.author),
        "Package URL": flat(c?.purl),
        License: flat(c?.licenses),
        CVE: flat(v.id),
        Severity: best.sev || severityFromScore(best.score),
        CVSS: best.score || "",
        "CVSS Vector": best.vector,
        CWE: flat(v.cwes),
        Description: flat(v.description) || flat(v.detail),
        Recommendation: flat(v.recommendation),
        Published: flat(v.published),
        References: flat(v.references),
        Source: "CycloneDX",
      });
    }
    void i;
  });

  // Components without any vulnerability row
  const covered = new Set(rows.map((r) => `${r.Component}@${r.Version}`));
  for (const c of comps) {
    const key = `${flat(c.name)}@${flat(c.version)}`;
    if (covered.has(key)) continue;
    rows.push({
      "Sr No": rows.length + 1,
      Component: flat(c.name),
      Version: flat(c.version),
      Type: flat(c.type),
      Publisher: flat(c.publisher) || flat(c.author),
      "Package URL": flat(c.purl),
      License: flat(c.licenses),
      CVE: "",
      Severity: "",
      CVSS: "",
      Description: flat(c.description),
      Source: "CycloneDX",
    });
  }
  return rows;
}

/* ------------------------------------ SPDX ----------------------------------- */
function parseSpdx(doc: Record<string, unknown>): Record<string, unknown>[] {
  const packages = (doc.packages as Record<string, unknown>[] | undefined) ?? [];
  return packages.map((p, i) => {
    const refs = (p.externalRefs as Array<Record<string, unknown>> | undefined) ?? [];
    const purl = refs.find((r) => String(r.referenceType).toLowerCase() === "purl");
    return {
      "Sr No": i + 1,
      Component: flat(p.name),
      Version: flat(p.versionInfo),
      Supplier: flat(p.supplier) || flat(p.originator),
      "Package URL": flat(purl?.referenceLocator),
      License: flat(p.licenseConcluded) || flat(p.licenseDeclared),
      Copyright: flat(p.copyrightText),
      "Download Location": flat(p.downloadLocation),
      Description: flat(p.description) || flat(p.summary),
      "SPDX ID": flat(p.SPDXID),
      Source: "SPDX",
    };
  });
}

/* --------------------------- Generic JSON flattening -------------------------- */
function flattenRecord(obj: Record<string, unknown>, prefix = "", depth = 0): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    const label = prefix ? `${prefix} ${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v) && depth < 2) {
      Object.assign(out, flattenRecord(v as Record<string, unknown>, label, depth + 1));
    } else {
      out[label] = flat(v);
    }
  }
  return out;
}

function findRecordArray(doc: unknown, depth = 0): Record<string, unknown>[] | null {
  if (Array.isArray(doc)) {
    return doc.every((d) => d && typeof d === "object") ? (doc as Record<string, unknown>[]) : null;
  }
  if (!doc || typeof doc !== "object" || depth > 3) return null;
  const entries = Object.entries(doc as Record<string, unknown>);
  const preferred = ["vulnerabilities", "results", "findings", "components", "packages", "items", "data", "rows"];
  entries.sort((a, b) => preferred.indexOf(b[0].toLowerCase()) - preferred.indexOf(a[0].toLowerCase()));
  for (const [, v] of entries) {
    const found = findRecordArray(v, depth + 1);
    if (found && found.length) return found;
  }
  return null;
}

/* ---------------------------------- Entry point -------------------------------- */
export function normalizeJsonSbom(text: string): NormalizedImport {
  const doc = JSON.parse(text) as unknown;

  let rows: Record<string, unknown>[] = [];
  let format = "JSON";

  if (doc && typeof doc === "object" && !Array.isArray(doc)) {
    const d = doc as Record<string, unknown>;
    if (d.bomFormat === "CycloneDX" || d.specVersion && (d.components || d.vulnerabilities)) {
      rows = parseCycloneDX(d);
      format = `CycloneDX ${flat(d.specVersion)}`.trim();
    } else if (d.spdxVersion || d.SPDXID || d.packages) {
      rows = parseSpdx(d);
      format = `SPDX ${flat(d.spdxVersion)}`.trim();
    }
  }

  if (!rows.length) {
    const arr = findRecordArray(doc);
    if (!arr?.length) throw new Error("Could not find component records in this JSON file");
    rows = arr.map((r, i) => ({ "Sr No": i + 1, ...flattenRecord(r) }));
    format = "Generic JSON";
  }

  // Drop empty columns, preserve first-seen order
  const columns: string[] = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!columns.includes(k)) columns.push(k);
  const useful = columns.filter((c) => rows.some((r) => String(r[c] ?? "").trim() !== ""));
  const cleaned = rows.map((r) => Object.fromEntries(useful.map((c) => [c, r[c] ?? ""])));

  return { rows: cleaned, columns: useful, format };
}

export const isJsonFile = (name: string) => /\.(json|cdx|spdx)$/i.test(name.trim());
