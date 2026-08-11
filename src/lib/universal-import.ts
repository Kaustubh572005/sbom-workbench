/**
 * Universal SBOM import.
 * Accepts any commonly used SBOM carrier (structured standards, spreadsheets,
 * documents, markup, archives) and normalizes everything into one internal
 * row model before analysis. Never rejects a file outright — it recovers
 * whatever usable component information exists and reports the rest as notes.
 */
import * as XLSX from "xlsx";
import { parseSbomText, normalizeTabularRows, type ParsedSbom } from "@/lib/sbom-parse";

export type ImportResult = ParsedSbom & { sourceFile: string };

const SPREADSHEET_RE = /\.(xlsx|xlsm|xlsb|xls|csv|tsv)$/i;
const DOC_RE = /\.(docx|doc|odt|rtf)$/i;
const HTML_RE = /\.(html?|htm)$/i;
const MD_RE = /\.(md|markdown)$/i;
const PDF_RE = /\.pdf$/i;
const ZIP_RE = /\.(zip|cdx\.zip|sbom\.zip)$/i;
const TAR_RE = /\.(tar|tgz|tar\.gz|gz)$/i;
const PB_RE = /\.(pb|bin|proto)$/i;

/* ------------------------------- field mapping ------------------------------- */
const FIELD_ALIASES: Array<[string, RegExp]> = [
  ["Component", /^(component( name)?( & origin)?|package( name)?|library|module|dependency|software|artifact|product|name)$/i],
  ["Version", /^(version|release|build version|package version|component version|ver)$/i],
  ["Supplier", /^(supplier|vendor|author|publisher|originator|manufacturer|organization|organisation)$/i],
  ["License", /^(license( name| type| id)?|spdx license|licence|licensing)$/i],
  ["Lifecycle Status", /^(lifecycle( status)?|support end|eos|eol|end of life|end of support|support status)$/i],
  ["Severity", /^(severity|criticality|risk level|priority)$/i],
  ["CVE", /^(cve( id)?|vulnerability( id)?|advisory)$/i],
  ["CVSS", /^(cvss( score| v3| v4)?|base score|score)$/i],
  ["PURL", /^(purl|package url)$/i],
  ["CPE", /^(cpe|cpe identifier|cpe23|cpe uri)$/i],
  ["Application", /^(application|app|system|service|solution)$/i],
  ["Description", /^(description|summary|purpose|functionality)$/i],
  ["Dependencies", /^(dependencies|depends on|requires|child dependencies)$/i],
  ["Release Date", /^(release date|released|published( date)?|date released)$/i],
  ["Hash", /^(hash(es)?|checksum(s)?|sha256|sha-256|sha1|md5|digest)$/i],
  ["Patch Status", /^(patch status|patched|patch level|fix status)$/i],
];

/** Map vendor-specific column names onto the common internal schema. */
export function normalizeHeader(header: string): string {
  const h = header.replace(/\s+/g, " ").trim();
  if (!h) return h;
  for (const [canonical, re] of FIELD_ALIASES) if (re.test(h)) return canonical;
  return h;
}

export function normalizeRowKeys(row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) {
    const key = normalizeHeader(k);
    if (out[key] == null || String(out[key]).trim() === "") out[key] = v;
    else if (key !== k) out[k] = v;
  }
  return out;
}

const SBOM_HINT_RE =
  /component|package|library|version|supplier|vendor|license|cve|cvss|purl|cpe|dependency|module|artifact/i;

/* ------------------------------- table helpers ------------------------------- */
type Matrix = string[][];

function matrixToRows(m: Matrix): Record<string, unknown>[] {
  if (m.length < 2) return [];
  const header = m[0].map((h) => normalizeHeader(h));
  return m.slice(1)
    .filter((r) => r.some((c) => c.trim() !== ""))
    .map((r) => Object.fromEntries(header.map((h, i) => [h || `Column ${i + 1}`, r[i] ?? ""])));
}

/** A 2-3 column "Data Field | Description | Value" table describes ONE component. */
function keyValueTable(m: Matrix): Record<string, unknown> | null {
  if (m.length < 4) return null;
  const widths = new Set(m.map((r) => r.length));
  if (![...widths].every((w) => w >= 2 && w <= 3)) return null;
  const firstCol = m.map((r) => (r[0] ?? "").trim()).filter(Boolean);
  if (!firstCol.some((c) => SBOM_HINT_RE.test(c))) return null;
  const out: Record<string, unknown> = {};
  for (const r of m) {
    const field = normalizeHeader((r[0] ?? "").trim());
    if (!field || /^data field$/i.test(field)) continue;
    const value = (r[2] ?? "").trim() || (r.length === 2 ? (r[1] ?? "").trim() : "");
    out[field] = value;
  }
  return Object.keys(out).length >= 3 ? out : null;
}

function tablesFromHtml(html: string): Matrix[] {
  if (typeof DOMParser === "undefined") return [];
  const doc = new DOMParser().parseFromString(html, "text/html");
  return Array.from(doc.querySelectorAll("table")).map((t) =>
    Array.from(t.querySelectorAll("tr")).map((tr) =>
      Array.from(tr.querySelectorAll("th,td")).map((td) => (td.textContent ?? "").replace(/\s+/g, " ").trim()),
    ),
  );
}

function tablesFromMarkdown(md: string): Matrix[] {
  const out: Matrix[] = [];
  let cur: Matrix = [];
  for (const raw of md.split(/\r?\n/)) {
    const line = raw.trim();
    if (/^\|.*\|$/.test(line)) {
      const cells = line.slice(1, -1).split("|").map((c) => c.trim());
      if (cells.every((c) => /^:?-{2,}:?$/.test(c))) continue;
      cur.push(cells);
    } else if (cur.length) { out.push(cur); cur = []; }
  }
  if (cur.length) out.push(cur);
  return out;
}

function rowsFromTables(tables: Matrix[]): { rows: Record<string, unknown>[]; notes: string[] } {
  const rows: Record<string, unknown>[] = [];
  const notes: string[] = [];
  for (const t of tables) {
    const kv = keyValueTable(t);
    if (kv) { rows.push(kv); continue; }
    const r = matrixToRows(t);
    const usable = r.filter((x) => Object.keys(x).some((k) => SBOM_HINT_RE.test(k)));
    rows.push(...(usable.length ? usable : r));
  }
  if (tables.length && !rows.length) notes.push("Tables were found but no SBOM fields could be recognised.");
  return { rows, notes };
}

/** Recover component rows from free-form document text (PDF/RTF fallback). */
function rowsFromPlainText(text: string): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = [];
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  for (const line of lines) {
    const purl = /pkg:[a-z0-9.+-]+\/[^\s,;)"']+/i.exec(line);
    const cve = /CVE-\d{4}-\d{4,7}/i.exec(line);
    const nameVer = /^([A-Za-z][\w.@/+-]{1,60}?)[\s@:]+v?(\d+(?:\.\d+){1,3}[\w.+-]*)/.exec(line);
    if (!purl && !cve && !nameVer) continue;
    const row: Record<string, unknown> = {};
    if (nameVer) { row["Component"] = nameVer[1]; row["Version"] = nameVer[2]; }
    if (purl) {
      row["PURL"] = purl[0];
      if (!row["Component"]) {
        const seg = purl[0].replace(/^pkg:[^/]+\//, "").split("@");
        row["Component"] = seg[0];
        if (seg[1]) row["Version"] = decodeURIComponent(seg[1]);
      }
    }
    if (cve) row["CVE"] = cve[0];
    if (row["Component"]) rows.push(row);
  }
  // de-duplicate by component@version
  const seen = new Set<string>();
  return rows.filter((r) => {
    const k = `${r["Component"]}@${r["Version"] ?? ""}`.toLowerCase();
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function columnsOf(rows: Record<string, unknown>[]): string[] {
  const cols: string[] = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!cols.includes(k)) cols.push(k);
  return cols;
}

/* ------------------------------- per-format readers ------------------------------- */
async function readSpreadsheet(file: File): Promise<ImportResult> {
  const buf = await file.arrayBuffer();
  const wb = XLSX.read(buf, { type: "array" });
  const format = /\.(csv|tsv)$/i.test(file.name) ? "CSV" : "Excel";
  const rows: Record<string, unknown>[] = [];
  const notes: string[] = [];
  for (const name of wb.SheetNames) {
    const sheet = wb.Sheets[name];
    const raw = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, { defval: "" });
    const usable = raw.filter((r) => Object.values(r).some((v) => String(v).trim() !== ""));
    if (!usable.length) continue;
    if (wb.SheetNames.length > 1) notes.push(`Sheet "${name}": ${usable.length} row(s)`);
    rows.push(...usable.map((r) => ({ ...normalizeRowKeys(r), ...(wb.SheetNames.length > 1 ? { Sheet: name } : {}) })));
  }
  const norm = normalizeTabularRows(rows, format);
  return { ...norm, notes: [...norm.notes, ...notes], sourceFile: file.name };
}

async function readDocx(file: File): Promise<ImportResult> {
  const mammoth = await import("mammoth");
  const { value } = await mammoth.convertToHtml({ arrayBuffer: await file.arrayBuffer() });
  const { rows, notes } = rowsFromTables(tablesFromHtml(value));
  const finalRows = rows.length ? rows : rowsFromPlainText(new DOMParser().parseFromString(value, "text/html").body.textContent ?? "");
  return {
    format: "Word document",
    rows: finalRows.map(normalizeRowKeys),
    columns: columnsOf(finalRows.map(normalizeRowKeys)),
    notes: [...notes, ...(rows.length ? [] : ["No SBOM tables detected — components recovered from document text."])],
    sourceFile: file.name,
  };
}

async function readPdf(file: File): Promise<ImportResult> {
  const pdfjs = await import("pdfjs-dist");
  const worker = await import("pdfjs-dist/build/pdf.worker.min.mjs?url");
  (pdfjs as unknown as { GlobalWorkerOptions: { workerSrc: string } }).GlobalWorkerOptions.workerSrc =
    (worker as unknown as { default: string }).default;
  const doc = await pdfjs.getDocument({ data: await file.arrayBuffer() }).promise;
  const lines: string[] = [];
  for (let p = 1; p <= doc.numPages; p++) {
    const page = await doc.getPage(p);
    const content = await page.getTextContent();
    const byRow = new Map<number, string[]>();
    for (const item of content.items as Array<{ str?: string; transform?: number[] }>) {
      if (!item.str || !item.transform) continue;
      const y = Math.round(item.transform[5]);
      const bucket = byRow.get(y) ?? [];
      bucket.push(item.str);
      byRow.set(y, bucket);
    }
    for (const y of [...byRow.keys()].sort((a, b) => b - a)) lines.push(byRow.get(y)!.join(" ").trim());
  }
  const text = lines.join("\n");
  const rows = rowsFromPlainText(text).map(normalizeRowKeys);
  return {
    format: "PDF document",
    rows,
    columns: columnsOf(rows),
    notes: rows.length ? [`Recovered ${rows.length} component(s) from ${doc.numPages} PDF page(s).`]
      : ["No component information could be recovered from this PDF."],
    sourceFile: file.name,
  };
}

async function readMarkup(file: File, kind: "html" | "md"): Promise<ImportResult> {
  const text = await file.text();
  const tables = kind === "html" ? tablesFromHtml(text) : tablesFromMarkdown(text);
  const { rows, notes } = rowsFromTables(tables);
  const finalRows = (rows.length ? rows : rowsFromPlainText(text)).map(normalizeRowKeys);
  return {
    format: kind === "html" ? "HTML document" : "Markdown document",
    rows: finalRows,
    columns: columnsOf(finalRows),
    notes,
    sourceFile: file.name,
  };
}

async function readArchive(file: File): Promise<ImportResult> {
  const JSZip = (await import("jszip")).default;
  const zip = await JSZip.loadAsync(await file.arrayBuffer());
  const entries = Object.values(zip.files).filter((f) => !f.dir && !/^__MACOSX|\/\._/.test(f.name));
  const rows: Record<string, unknown>[] = [];
  const notes: string[] = [];
  const formats: string[] = [];
  for (const entry of entries) {
    if (PB_RE.test(entry.name)) { notes.push(`${entry.name}: protobuf payload skipped (binary encoding).`); continue; }
    try {
      const blob = await entry.async("blob");
      const inner = new File([blob], entry.name.split("/").pop() ?? entry.name);
      const res = await extractFromFile(inner);
      if (res.rows.length) {
        rows.push(...res.rows.map((r) => ({ ...r, "Source File": inner.name })));
        formats.push(res.format);
        notes.push(`${inner.name}: ${res.rows.length} component(s) (${res.format})`);
      } else {
        notes.push(`${inner.name}: no usable SBOM data.`);
      }
    } catch (e) {
      notes.push(`${entry.name}: ${e instanceof Error ? e.message : "could not be parsed"} — skipped.`);
    }
  }
  return {
    format: `Archive (${Array.from(new Set(formats)).join(", ") || "no SBOM found"})`,
    rows,
    columns: columnsOf(rows),
    notes,
    sourceFile: file.name,
  };
}

/* ------------------------------- entry point ------------------------------- */
/**
 * Detect the carrier format and return normalized rows.
 * Errors are converted into notes wherever partial recovery is possible.
 */
export async function extractFromFile(file: File): Promise<ImportResult> {
  const name = file.name;
  try {
    if (ZIP_RE.test(name)) return await readArchive(file);
    if (TAR_RE.test(name)) {
      return {
        format: "TAR archive", rows: [], columns: [],
        notes: ["TAR/GZ archives cannot be expanded in the browser — please upload a ZIP or the SBOM files directly."],
        sourceFile: name,
      };
    }
    if (SPREADSHEET_RE.test(name)) return await readSpreadsheet(file);
    if (/\.docx$/i.test(name)) return await readDocx(file);
    if (DOC_RE.test(name)) {
      const text = await file.text();
      const rows = rowsFromPlainText(text.replace(/\\'([0-9a-f]{2})/gi, " ")).map(normalizeRowKeys);
      return {
        format: name.split(".").pop()!.toUpperCase() + " document", rows, columns: columnsOf(rows),
        notes: rows.length ? [] : ["Legacy document format — convert to DOCX or PDF for reliable extraction."],
        sourceFile: name,
      };
    }
    if (PDF_RE.test(name)) return await readPdf(file);
    if (HTML_RE.test(name)) return await readMarkup(file, "html");
    if (MD_RE.test(name)) return await readMarkup(file, "md");
    if (PB_RE.test(name)) {
      return {
        format: "CycloneDX Protobuf", rows: [], columns: [],
        notes: ["Protobuf encoding is not readable in the browser — please export the SBOM as CycloneDX JSON or XML."],
        sourceFile: name,
      };
    }
    const text = await file.text();
    const parsed = parseSbomText(text, name);
    if (parsed.rows.length) {
      const rows = parsed.rows.map(normalizeRowKeys);
      return { ...parsed, rows, columns: columnsOf(rows), sourceFile: name };
    }
    // last resort: recover anything that looks like a component
    const rows = rowsFromPlainText(text).map(normalizeRowKeys);
    return {
      format: parsed.format || "Plain text",
      rows,
      columns: columnsOf(rows),
      notes: [...parsed.notes, rows.length ? `Recovered ${rows.length} component(s) heuristically.` : "No usable SBOM information found."],
      sourceFile: name,
    };
  } catch (e) {
    return {
      format: "Unrecognised", rows: [], columns: [],
      notes: [`${name} could not be parsed: ${e instanceof Error ? e.message : "unknown error"}`],
      sourceFile: name,
    };
  }
}

export const ACCEPTED_UPLOAD_TYPES =
  ".xlsx,.xlsm,.xlsb,.xls,.csv,.tsv,.json,.cdx,.spdx,.xml,.rdf,.yaml,.yml,.txt,.pom,.mod,.lock,.list," +
  ".docx,.doc,.odt,.rtf,.pdf,.html,.htm,.md,.markdown,.zip,.tag,.swidtag";
