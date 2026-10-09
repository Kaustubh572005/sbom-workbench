/**
 * Smart file naming — identify the APPLICATION an uploaded file belongs to.
 *
 * A file called "bom.json" can be the SBOM of the Pension Fund app, while
 * "Wealth Spectrum.xlsx" already says what it is. The dataset is therefore
 * always named after the application, never after a generic filename, and the
 * original filename is kept next to it so nothing is lost.
 *
 * Evidence, strongest first:
 *   1. Name embedded in the file (CycloneDX metadata.component, SPDX document /
 *      root package, "SBOM of X" title line, workbook title)
 *   2. The file's own "Application" column (dominant value)
 *   3. The filename, after stripping generic words (bom, sbom, final, v2, dates…)
 *   4. A meaningful sheet name
 *   5. Fallback — flagged "Unidentified" so the user can rename it
 */

export type AppHint = { text: string; source: string };
export type AppIdentity = {
  /** application name used for the dataset */
  name: string;
  confidence: "High" | "Medium" | "Low";
  /** human-readable explanation of where the name came from */
  reason: string;
  /** other application names found inside the file */
  alsoFound: string[];
};

/* ------------------------------ name hygiene ------------------------------ */
const GENERIC_WORDS = new Set([
  "bom", "boms", "sbom", "sboms", "cyclonedx", "cdx", "spdx", "bill", "materials", "software", "export", "exported",
  "report", "reports", "scan", "scans", "vapt", "vulnerability", "vulnerabilities", "assessment", "final", "draft",
  "copy", "new", "latest", "updated", "update", "data", "file", "files", "list", "inventory", "component", "components",
  "dependency", "dependencies", "json", "xml", "csv", "xlsx", "xls", "output", "result", "results", "sample", "test",
  "tmp", "untitled", "document", "doc", "docx", "pdf", "sheet", "book", "workbook", "download", "downloaded", "upload",
  "uploaded", "analysis", "findings", "security", "audit", "package", "packages", "manifest", "lock", "tree", "full",
  "version", "ver", "rev", "revision", "backup", "old", "main", "master", "release", "build", "snapshot", "generated",
]);
const CONNECTORS = new Set(["of", "for", "the", "a", "an", "and", "-", "_", "–", "—", "&"]);
const JUNK_NAMES = /^(unknown|unnamed|untitled|n\/?a|none|null|undefined|default|root|app|application|project|sample|test|example|demo|sbom|bom|component|main|sheet\d*|table\s*\d*|data|\d+)$/i;
const VERSIONISH = /^v?\d+([._-]\d+)*$/i;
const UUIDISH = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DATEISH = /^(\d{4}[-_.]?\d{2}[-_.]?\d{2}|\d{8}|\d{2}[-_.]\d{2}[-_.]\d{4})$/;

const stemOf = (filename: string) =>
  filename.replace(/\.(cdx\.zip|sbom\.zip|tar\.gz|spdx\.json|cdx\.json|bom\.json)$/i, "").replace(/\.[^.]+$/, "");

/** Names are kept exactly as written ("retiredpensionfund", "EEway", "KECMS_Application") — only whitespace is tidied. */
export function prettifyName(raw: string): string {
  return raw.replace(/\s+/g, " ").trim();
}

/** Strip generic words, versions, dates and copy-markers from a filename. Empty string = filename says nothing. */
export function nameFromFilename(filename: string): string {
  const tokens = stemOf(filename)
    .replace(/\(\d+\)/g, " ")
    .split(/[\s_.\-–—+,()[\]]+/)
    .filter(Boolean)
    .filter((t) => !GENERIC_WORDS.has(t.toLowerCase()) && !VERSIONISH.test(t) && !DATEISH.test(t) && !/^q[1-4]$/i.test(t));
  while (tokens.length && CONNECTORS.has(tokens[0].toLowerCase())) tokens.shift();
  while (tokens.length && CONNECTORS.has(tokens[tokens.length - 1].toLowerCase())) tokens.pop();
  const joined = tokens.join(" ").trim();
  return joined.length >= 2 && !JUNK_NAMES.test(joined) ? joined : "";
}

const usable = (v: unknown): string => {
  const s = String(v ?? "").replace(/\s+/g, " ").trim();
  if (s.length < 2 || s.length > 80) return "";
  if (JUNK_NAMES.test(s) || VERSIONISH.test(s) || UUIDISH.test(s) || DATEISH.test(s)) return "";
  if (/^https?:\/\//i.test(s)) return "";
  return s;
};

/* --------------------------------- hints ---------------------------------- */
/** "SBOM of Pension Fund", "Software Bill of Materials – Wealth Spectrum", "SBOM: EwayDMS" */
const TITLE_RE = /(?:sbom|s-bom|bill of materials|software bill of materials)\s*(?:of|for|[-–—:|])\s*([A-Za-z0-9][A-Za-z0-9 &._\-/()]{1,60})/i;

export function hintsFromTitleLines(lines: string[], source: string): AppHint[] {
  const out: AppHint[] = [];
  for (const line of lines.slice(0, 15)) {
    const m = line.match(TITLE_RE);
    const cand = m ? usable(m[1].replace(/\s*(report|document|inventory|register|list)\s*$/i, "")) : "";
    if (cand) out.push({ text: cand, source });
  }
  return out;
}

/** Look for the SBOM subject inside JSON / YAML-as-JSON / XML / SPDX tag-value text. */
export function hintsFromStructuredText(text: string): AppHint[] {
  const out: AppHint[] = [];
  const add = (v: unknown, source: string) => { const t = usable(v); if (t) out.push({ text: t, source }); };
  const head = text.slice(0, 200_000);

  if (/^\s*[[{]/.test(head)) {
    try {
      const doc = JSON.parse(text) as Record<string, unknown>;
      const meta = (doc.metadata ?? {}) as Record<string, unknown>;
      const comp = (meta.component ?? {}) as Record<string, unknown>;
      add(comp.name, "CycloneDX metadata component");
      add(((meta.properties as Array<{ name?: string; value?: string }> | undefined) ?? [])
        .find((p) => /application|app.?name|project/i.test(String(p.name)))?.value, "CycloneDX metadata property");
      // SPDX: root package, then document name
      const roots = (doc.documentDescribes as string[] | undefined) ?? [];
      const pkgs = (doc.packages as Array<Record<string, unknown>> | undefined) ?? [];
      const root = pkgs.find((p) => roots.includes(String(p.SPDXID)));
      add(root?.name, "SPDX root package");
      if (typeof doc.name === "string" && !/^SPDX-/i.test(doc.name) && !/^SPDXRef/i.test(doc.name)) add(doc.name, "SPDX document name");
      for (const k of ["application", "applicationName", "appName", "app", "project", "projectName", "system", "service", "title"]) add(doc[k], `JSON field "${k}"`);
    } catch { /* not JSON */ }
  }

  // CycloneDX XML: first <component> inside <metadata>
  const xmlMeta = head.match(/<metadata[\s\S]*?<component[^>]*>\s*(?:<supplier>[\s\S]*?<\/supplier>\s*)?(?:<author>[\s\S]*?<\/author>\s*)?(?:<publisher>[\s\S]*?<\/publisher>\s*)?(?:<group>[\s\S]*?<\/group>\s*)?<name>([^<]+)<\/name>/i);
  if (xmlMeta) add(xmlMeta[1], "CycloneDX XML metadata component");

  // SPDX tag-value
  const tag = head.match(/^DocumentName:\s*(.+)$/m);
  if (tag && !/^SPDX-/i.test(tag[1])) add(tag[1], "SPDX document name");

  return out;
}

/* ------------------------------- identification ------------------------------- */
type RowLike = Record<string, unknown>;

function dominantBy(rows: RowLike[], keyRe: RegExp): { name: string; share: number; others: string[]; distinct: number } | null {
  const counts = new Map<string, { n: number; label: string }>();
  let total = 0;
  for (const r of rows) {
    const raw = Object.entries(r).find(([k]) => keyRe.test(k.trim()))?.[1];
    const v = usable(raw);
    if (!v) continue;
    total++;
    const key = v.toLowerCase();
    const e = counts.get(key);
    if (e) e.n++; else counts.set(key, { n: 1, label: v });
  }
  if (!total) return null;
  const ranked = [...counts.values()].sort((a, b) => b.n - a.n);
  return { name: ranked[0].label, share: ranked[0].n / total, others: ranked.slice(1, 6).map((e) => e.label), distinct: ranked.length };
}
const APP_COL = /^(application|app|application name|app name|project|system|service|solution)$/i;
const PARENT_COL = /^(parent component|root component|parent|main component)$/i;

const sameName = (a: string, b: string) => a.toLowerCase().replace(/[^a-z0-9]/g, "") === b.toLowerCase().replace(/[^a-z0-9]/g, "");

export function identifyApplication(input: { filename: string; rows: RowLike[]; hints?: AppHint[] }): AppIdentity {
  const { filename, rows, hints = [] } = input;
  const fromName = nameFromFilename(filename);
  const embedded = hints.filter((h) => !/^(sheet|folder)/i.test(h.source));
  const sheetHint = hints.find((h) => /^sheet/i.test(h.source));
  const folderHint = hints.find((h) => /^folder/i.test(h.source));
  const fromFolder = folderHint ? nameFromFilename(`${folderHint.text}.zip`) : "";
  const app = dominantBy(rows, APP_COL);
  const parent = dominantBy(rows, PARENT_COL); // the application every component hangs under, e.g. "KECMS_Application"
  const alsoFound = (app?.others ?? []).slice(0, 5);
  const inside = embedded[0]?.text ?? (app && app.share >= 0.6 ? app.name : parent && parent.share >= 0.8 ? parent.name : "");

  // 1 — a filename that names the application wins: EEway.json → "EEway"
  if (fromName) {
    const differs = inside && !sameName(inside, fromName);
    return { name: fromName, confidence: "High", alsoFound,
      reason: `The filename names the application${differs ? ` (the file's contents mention “${inside}”)` : ""}.` };
  }
  // 2 — generic filename (bom.json, sbom.json …): read the application from inside the file
  if (embedded.length) {
    const h = embedded[0];
    return { name: prettifyName(h.text), confidence: "High", alsoFound,
      reason: `Filename is generic — application name read from the file itself (${h.source}).` };
  }
  if (app && app.share >= 0.6) {
    return { name: app.name, confidence: app.distinct === 1 ? "High" : "Medium", alsoFound,
      reason: app.distinct === 1 ? "Filename is generic — every row names this application in the Application column."
        : `Filename is generic — ${Math.round(app.share * 100)}% of rows name this application (${app.distinct} applications in the file).` };
  }
  if (parent && parent.share >= 0.8) {
    return { name: parent.name, confidence: "Medium", alsoFound: parent.others,
      reason: "Filename is generic — taken from the Parent Component that the components belong to." };
  }
  // 3 — the folder the file sat in (ZIP bundles: "pension-fund/bom.json")
  if (fromFolder) {
    return { name: fromFolder, confidence: "Medium", alsoFound,
      reason: `Filename is generic — used the folder it came from (${folderHint!.source}).` };
  }
  if (app && app.distinct > 1) {
    return { name: `Multiple applications (${app.distinct})`, confidence: "Medium", alsoFound,
      reason: `Generic filename; the Application column lists ${app.distinct} different applications.` };
  }
  if (sheetHint && !/^(bom|sbom|sheet\d*)$/i.test(sheetHint.text)) {
    return { name: prettifyName(sheetHint.text), confidence: "Low", alsoFound,
      reason: "Generic filename — used the worksheet name. Please confirm." };
  }
  const stem = stemOf(filename).trim() || "Untitled";
  return { name: `Unidentified — ${stem}`, confidence: "Low", alsoFound,
    reason: "Neither the filename nor the file contents name the application. Rename it so findings stay attributable." };
}

/** Make a dataset name unique without hiding which file it came from. */
export function uniqueDatasetName(name: string, filename: string, existing: string[]): string {
  const taken = new Set(existing.map((n) => n.toLowerCase()));
  if (!taken.has(name.toLowerCase())) return name;
  const withFile = `${name} (${filename})`;
  if (!taken.has(withFile.toLowerCase())) return withFile;
  for (let i = 2; i < 100; i++) {
    const c = `${name} (${filename}) #${i}`;
    if (!taken.has(c.toLowerCase())) return c;
  }
  return withFile;
}

/** Fill the Application column from the dataset name when a row has none, so findings never lose their application. */
export function withApplication<T extends RowLike>(row: T, appName: string): T {
  const has = Object.entries(row).some(([k, v]) => /^(application|app|application name|app name)$/i.test(k.trim()) && String(v ?? "").trim() !== "");
  return has || !appName ? row : ({ ...row, Application: appName } as T);
}
