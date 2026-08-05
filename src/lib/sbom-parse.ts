/**
 * Universal SBOM ingestion.
 *
 * Detects and normalizes ANY of the following into one internal SBOM model:
 *  SPDX JSON · SPDX Tag-Value · SPDX RDF/XML · CycloneDX JSON · CycloneDX XML
 *  SWID · JSON · XML · YAML · dependency manifests · lock files · package lists
 *  (Excel/CSV are parsed by the workbench and then normalized through here.)
 *
 * Nothing is ever rejected for "not being SPDX/CycloneDX" — unknown shapes fall
 * through to generic record/flat/line extraction.
 */

import { XMLParser } from "fast-xml-parser";
import YAML from "yaml";
import { normalizeJsonSbom } from "./sbom-import";

export type SbomComponent = {
  "Sr No": number;
  Component: string;
  "Package Name": string;
  Group: string;
  Version: string;
  Supplier: string;
  Ecosystem: string;
  Type: string;
  PURL: string;
  CPE: string;
  SWID: string;
  Hashes: string;
  License: string;
  "External References": string;
  Dependencies: string;
  "Parent Component": string;
  "Child Components": string;
  "Build Information": string;
  "Release Date": string;
  Architecture: string;
  OS: string;
  "Package Manager": string;
  Description: string;
  CVE: string;
  Severity: string;
  CVSS: string | number;
  Metadata: string;
  "Source Format": string;
  [k: string]: unknown;
};

export type ParsedSbom = {
  rows: Record<string, unknown>[];
  columns: string[];
  format: string;
  notes: string[];
};

const S = (v: unknown): string => {
  if (v == null) return "";
  if (Array.isArray(v)) return v.map(S).filter(Boolean).join("; ");
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    for (const k of ["name", "#text", "value", "id", "url", "text", "version", "@_name"]) {
      if (o[k] != null && typeof o[k] !== "object") return String(o[k]);
    }
    return JSON.stringify(v);
  }
  return String(v);
};

const arr = <T,>(v: unknown): T[] => (v == null ? [] : Array.isArray(v) ? (v as T[]) : [v as T]);

const BLANK: Omit<SbomComponent, "Sr No"> = {
  Component: "", "Package Name": "", Group: "", Version: "", Supplier: "", Ecosystem: "",
  Type: "", PURL: "", CPE: "", SWID: "", Hashes: "", License: "", "External References": "",
  Dependencies: "", "Parent Component": "", "Child Components": "", "Build Information": "",
  "Release Date": "", Architecture: "", OS: "", "Package Manager": "", Description: "",
  CVE: "", Severity: "", CVSS: "", Metadata: "", "Source Format": "",
};

const mk = (p: Partial<SbomComponent>, format: string): Record<string, unknown> => ({
  ...BLANK, "Source Format": format, ...p,
});

/* --------------------------- identifier utilities --------------------------- */
export function ecosystemFromPurl(purl: string): string {
  const m = /^pkg:([^/]+)\//.exec(purl.trim());
  if (!m) return "";
  const t = m[1].toLowerCase();
  const map: Record<string, string> = {
    npm: "npm", pypi: "PyPI", maven: "Maven", nuget: "NuGet", golang: "Go", cargo: "crates.io",
    gem: "RubyGems", composer: "Packagist", deb: "Debian", rpm: "RPM", apk: "Alpine",
    docker: "Docker", oci: "OCI", generic: "Generic", conan: "Conan", swift: "Swift", hex: "Hex",
  };
  return map[t] ?? t;
}

export function packageManagerFor(ecosystem: string): string {
  const m: Record<string, string> = {
    npm: "npm/yarn/pnpm", PyPI: "pip", Maven: "maven/gradle", NuGet: "dotnet", Go: "go modules",
    "crates.io": "cargo", RubyGems: "bundler", Packagist: "composer", Debian: "apt",
    RPM: "yum/dnf", Alpine: "apk", Hex: "mix",
  };
  return m[ecosystem] ?? "";
}

function purlName(purl: string): { group: string; name: string; version: string } {
  const m = /^pkg:[^/]+\/(.+)$/.exec(purl.trim());
  if (!m) return { group: "", name: "", version: "" };
  const [pathPart, verPart = ""] = m[1].split("@");
  const segs = pathPart.split("/");
  const name = decodeURIComponent(segs.pop() ?? "");
  return { group: decodeURIComponent(segs.join("/")), name, version: decodeURIComponent(verPart.split("?")[0]) };
}

/* ------------------------------- CycloneDX JSON ------------------------------ */
function fromCycloneDxJson(doc: Record<string, unknown>): Record<string, unknown>[] {
  const format = `CycloneDX ${S(doc.specVersion)}`.trim();
  const comps = arr<Record<string, unknown>>(doc.components);
  const meta = (doc.metadata ?? {}) as Record<string, unknown>;
  const rootComp = (meta.component ?? {}) as Record<string, unknown>;
  const deps = arr<Record<string, unknown>>(doc.dependencies);
  const depMap = new Map<string, string[]>();
  for (const d of deps) depMap.set(S(d.ref), arr<unknown>(d.dependsOn).map(S));
  const parentOf = new Map<string, string>();
  for (const [ref, children] of depMap) for (const c of children) parentOf.set(c, ref);

  const vulnByRef = new Map<string, { cve: string; sev: string; score: number }[]>();
  for (const v of arr<Record<string, unknown>>(doc.vulnerabilities)) {
    const ratings = arr<Record<string, unknown>>(v.ratings);
    const best = ratings.reduce(
      (a, r) => (Number(r.score) || 0) > a.score ? { score: Number(r.score) || 0, sev: S(r.severity) } : a,
      { score: 0, sev: S(ratings[0]?.severity) },
    );
    for (const a of arr<Record<string, unknown>>(v.affects)) {
      const ref = S(a.ref);
      const list = vulnByRef.get(ref) ?? [];
      list.push({ cve: S(v.id), sev: best.sev, score: best.score });
      vulnByRef.set(ref, list);
    }
  }

  const flatten = (c: Record<string, unknown>, parent: string): Record<string, unknown>[] => {
    const ref = S(c["bom-ref"]) || S(c.purl) || S(c.name);
    const purl = S(c.purl);
    const eco = ecosystemFromPurl(purl);
    const vulns = vulnByRef.get(ref) ?? [];
    const kids = arr<Record<string, unknown>>(c.components);
    const row = mk({
      Component: S(c.name),
      "Package Name": purlName(purl).name || S(c.name),
      Group: S(c.group) || purlName(purl).group,
      Version: S(c.version),
      Supplier: S(c.supplier) || S(c.publisher) || S(c.author) || S(c.manufacturer),
      Ecosystem: eco,
      Type: S(c.type),
      PURL: purl,
      CPE: S(c.cpe),
      SWID: S((c.swid as Record<string, unknown> | undefined)?.tagId) || S(c.swid),
      Hashes: arr<Record<string, unknown>>(c.hashes).map((h) => `${S(h.alg)}:${S(h.content)}`).join("; "),
      License: arr<Record<string, unknown>>(c.licenses)
        .map((l) => S((l.license as Record<string, unknown> | undefined)?.id ?? (l.license as Record<string, unknown> | undefined)?.name ?? l.expression))
        .filter(Boolean).join("; "),
      "External References": arr<Record<string, unknown>>(c.externalReferences).map((r) => `${S(r.type)}=${S(r.url)}`).join("; "),
      Dependencies: (depMap.get(ref) ?? []).join("; "),
      "Parent Component": parent || parentOf.get(ref) || S(rootComp.name),
      "Child Components": kids.map((k) => S(k.name)).join("; "),
      "Build Information": S(meta.tools) || S(meta.timestamp),
      "Release Date": S((c.properties as unknown) && arr<Record<string, unknown>>(c.properties).find((p) => /release|date/i.test(S(p.name)))?.value),
      Architecture: arr<Record<string, unknown>>(c.properties).find((p) => /arch/i.test(S(p.name)))?.value as string ?? "",
      OS: arr<Record<string, unknown>>(c.properties).find((p) => /(^|\W)os(\W|$)|platform/i.test(S(p.name)))?.value as string ?? "",
      "Package Manager": packageManagerFor(eco),
      Description: S(c.description),
      CVE: vulns.map((v) => v.cve).join("; "),
      Severity: vulns[0]?.sev ?? "",
      CVSS: vulns.reduce((a, v) => Math.max(a, v.score), 0) || "",
      Metadata: S(c.scope) ? `scope=${S(c.scope)}` : "",
    }, format);
    return [row, ...kids.flatMap((k) => flatten(k, S(c.name)))];
  };

  const rows = comps.flatMap((c) => flatten(c, S(rootComp.name)));
  return rows.map((r, i) => ({ "Sr No": i + 1, ...r }));
}

/* --------------------------------- SPDX JSON -------------------------------- */
function fromSpdxJson(doc: Record<string, unknown>): Record<string, unknown>[] {
  const format = `SPDX ${S(doc.spdxVersion)}`.trim();
  const rels = arr<Record<string, unknown>>(doc.relationships);
  const childrenOf = new Map<string, string[]>();
  const parentOf = new Map<string, string>();
  for (const r of rels) {
    if (!/DEPENDS_ON|CONTAINS|DYNAMIC_LINK|STATIC_LINK/i.test(S(r.relationshipType))) continue;
    const from = S(r.spdxElementId), to = S(r.relatedSpdxElement);
    childrenOf.set(from, [...(childrenOf.get(from) ?? []), to]);
    parentOf.set(to, from);
  }
  return arr<Record<string, unknown>>(doc.packages).map((p, i) => {
    const refs = arr<Record<string, unknown>>(p.externalRefs);
    const purl = S(refs.find((r) => /purl/i.test(S(r.referenceType)))?.referenceLocator);
    const cpe = S(refs.find((r) => /cpe/i.test(S(r.referenceType)))?.referenceLocator);
    const id = S(p.SPDXID);
    const eco = ecosystemFromPurl(purl);
    return {
      "Sr No": i + 1,
      ...mk({
        Component: S(p.name),
        "Package Name": purlName(purl).name || S(p.name),
        Group: purlName(purl).group,
        Version: S(p.versionInfo),
        Supplier: S(p.supplier) || S(p.originator),
        Ecosystem: eco,
        Type: S(p.primaryPackagePurpose),
        PURL: purl,
        CPE: cpe,
        SWID: S(refs.find((r) => /swid/i.test(S(r.referenceType)))?.referenceLocator),
        Hashes: arr<Record<string, unknown>>(p.checksums).map((c) => `${S(c.algorithm)}:${S(c.checksumValue)}`).join("; "),
        License: S(p.licenseConcluded) || S(p.licenseDeclared),
        "External References": refs.map((r) => `${S(r.referenceType)}=${S(r.referenceLocator)}`).join("; "),
        Dependencies: (childrenOf.get(id) ?? []).join("; "),
        "Parent Component": parentOf.get(id) ?? "",
        "Child Components": (childrenOf.get(id) ?? []).join("; "),
        "Build Information": S(p.builtDate) || S((doc.creationInfo as Record<string, unknown> | undefined)?.creators),
        "Release Date": S(p.releaseDate) || S(p.validUntilDate),
        "Package Manager": packageManagerFor(eco),
        Description: S(p.description) || S(p.summary),
        Metadata: [id, S(p.downloadLocation), S(p.copyrightText)].filter(Boolean).join(" | "),
      }, format),
    };
  });
}

/* ------------------------------ SPDX Tag-Value ------------------------------ */
function fromSpdxTagValue(text: string): Record<string, unknown>[] {
  const lines = text.split(/\r?\n/);
  const blocks: Record<string, string[]>[] = [];
  let cur: Record<string, string[]> | null = null;
  let version = "";
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^([A-Za-z0-9]+):\s*(.*)$/.exec(line);
    if (!m) continue;
    const [, tag, val] = m;
    if (tag === "SPDXVersion") version = val;
    if (tag === "PackageName") { cur = {}; blocks.push(cur); }
    if (!cur) continue;
    cur[tag] = [...(cur[tag] ?? []), val];
  }
  const format = `SPDX Tag-Value ${version}`.trim();
  return blocks.map((b, i) => {
    const get = (t: string) => (b[t] ?? []).join("; ");
    const purl = (b.ExternalRef ?? []).map((r) => r.split(/\s+/)).find((p) => /purl/i.test(p[1] ?? ""))?.[2] ?? "";
    const cpe = (b.ExternalRef ?? []).map((r) => r.split(/\s+/)).find((p) => /cpe/i.test(p[1] ?? ""))?.[2] ?? "";
    const eco = ecosystemFromPurl(purl);
    return {
      "Sr No": i + 1,
      ...mk({
        Component: get("PackageName"),
        "Package Name": purlName(purl).name || get("PackageName"),
        Group: purlName(purl).group,
        Version: get("PackageVersion"),
        Supplier: get("PackageSupplier") || get("PackageOriginator"),
        Ecosystem: eco,
        PURL: purl,
        CPE: cpe,
        Hashes: get("PackageChecksum"),
        License: get("PackageLicenseConcluded") || get("PackageLicenseDeclared"),
        "External References": (b.ExternalRef ?? []).join("; "),
        "Release Date": get("ReleaseDate"),
        "Build Information": get("BuiltDate"),
        "Package Manager": packageManagerFor(eco),
        Description: get("PackageDescription") || get("PackageSummary"),
        Metadata: [get("SPDXID"), get("PackageDownloadLocation"), get("PackageCopyrightText")].filter(Boolean).join(" | "),
      }, format),
    };
  });
}

/* ---------------------------------- XML paths -------------------------------- */
const xml = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  removeNSPrefix: true,
  parseTagValue: true,
  trimValues: true,
});

function fromCycloneDxXml(doc: Record<string, unknown>): Record<string, unknown>[] {
  const bom = (doc.bom ?? {}) as Record<string, unknown>;
  const format = `CycloneDX XML ${S(bom["@_version"] ? "" : "")}`.trim() || "CycloneDX XML";
  const comps = arr<Record<string, unknown>>((bom.components as Record<string, unknown> | undefined)?.component);
  const rows = comps.map((c) => {
    const purl = S(c.purl);
    const eco = ecosystemFromPurl(purl);
    return mk({
      Component: S(c.name),
      "Package Name": purlName(purl).name || S(c.name),
      Group: S(c.group) || purlName(purl).group,
      Version: S(c.version),
      Supplier: S(c.supplier) || S(c.publisher) || S(c.author),
      Ecosystem: eco,
      Type: S(c["@_type"]),
      PURL: purl,
      CPE: S(c.cpe),
      SWID: S((c.swid as Record<string, unknown> | undefined)?.["@_tagId"]),
      Hashes: arr<Record<string, unknown>>((c.hashes as Record<string, unknown> | undefined)?.hash)
        .map((h) => `${S(h["@_alg"])}:${S(h["#text"])}`).join("; "),
      License: arr<Record<string, unknown>>((c.licenses as Record<string, unknown> | undefined)?.license)
        .map((l) => S(l.id ?? l.name)).join("; "),
      "External References": arr<Record<string, unknown>>((c.externalReferences as Record<string, unknown> | undefined)?.reference)
        .map((r) => `${S(r["@_type"])}=${S(r.url)}`).join("; "),
      "Package Manager": packageManagerFor(eco),
      Description: S(c.description),
    }, format);
  });
  return rows.map((r, i) => ({ "Sr No": i + 1, ...r }));
}

function fromSpdxRdfXml(doc: Record<string, unknown>): Record<string, unknown>[] {
  const root = (doc.RDF ?? doc.Document ?? doc) as Record<string, unknown>;
  const docNode = (root.SpdxDocument ?? root.Document ?? root) as Record<string, unknown>;
  const packages: Record<string, unknown>[] = [];
  const collect = (node: unknown, depth = 0) => {
    if (!node || typeof node !== "object" || depth > 6) return;
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (/^Package$/i.test(k)) packages.push(...arr<Record<string, unknown>>(v));
      else arr<unknown>(v).forEach((c) => collect(c, depth + 1));
    }
  };
  collect(docNode);
  return packages.map((p, i) => {
    const refs = arr<Record<string, unknown>>(p.externalRef ?? p.ExternalRef);
    const purl = S(refs.find((r) => /purl/i.test(JSON.stringify(r)))?.referenceLocator);
    const eco = ecosystemFromPurl(purl);
    return {
      "Sr No": i + 1,
      ...mk({
        Component: S(p.name),
        "Package Name": purlName(purl).name || S(p.name),
        Version: S(p.versionInfo),
        Supplier: S(p.supplier) || S(p.originator),
        Ecosystem: eco,
        PURL: purl,
        Hashes: S(p.checksum),
        License: S(p.licenseConcluded) || S(p.licenseDeclared),
        "External References": refs.map((r) => S(r.referenceLocator)).join("; "),
        "Package Manager": packageManagerFor(eco),
        Description: S(p.description) || S(p.summary),
        Metadata: S(p["@_about"]) || S(p.downloadLocation),
      }, "SPDX RDF/XML"),
    };
  });
}

function fromGenericXml(doc: Record<string, unknown>, label: string): Record<string, unknown>[] {
  // Maven POM support + any repeated element that looks like a component list.
  const project = (doc.project ?? {}) as Record<string, unknown>;
  const mavenDeps = arr<Record<string, unknown>>(
    ((project.dependencies as Record<string, unknown> | undefined)?.dependency) ??
    (((project.dependencyManagement as Record<string, unknown> | undefined)?.dependencies as Record<string, unknown> | undefined)?.dependency),
  );
  if (mavenDeps.length) {
    return mavenDeps.map((d, i) => ({
      "Sr No": i + 1,
      ...mk({
        Component: S(d.artifactId),
        "Package Name": S(d.artifactId),
        Group: S(d.groupId),
        Version: S(d.version),
        Ecosystem: "Maven",
        "Package Manager": "maven",
        PURL: `pkg:maven/${S(d.groupId)}/${S(d.artifactId)}@${S(d.version)}`,
        "Parent Component": S(project.artifactId),
        Metadata: S(d.scope) ? `scope=${S(d.scope)}` : "",
      }, "Maven POM"),
    }));
  }

  const found: Record<string, unknown>[] = [];
  const walk = (node: unknown, depth = 0) => {
    if (!node || typeof node !== "object" || depth > 8 || found.length) return;
    for (const [, v] of Object.entries(node as Record<string, unknown>)) {
      const list = arr<unknown>(v).filter((x) => x && typeof x === "object");
      if (list.length > 1 && list.every((x) => "name" in (x as object) || "@_name" in (x as object))) {
        found.push(...(list as Record<string, unknown>[]));
        return;
      }
      list.forEach((c) => walk(c, depth + 1));
    }
  };
  walk(doc);
  return found.map((c, i) => ({
    "Sr No": i + 1,
    ...mk({
      Component: S(c.name ?? c["@_name"]),
      "Package Name": S(c.name ?? c["@_name"]),
      Version: S(c.version ?? c["@_version"]),
      Supplier: S(c.supplier ?? c.vendor ?? c.publisher),
      License: S(c.license),
      Description: S(c.description),
      Metadata: JSON.stringify(c).slice(0, 400),
    }, label),
  }));
}

/* ------------------------- Manifests & package lists ------------------------ */
function fromPackageJson(doc: Record<string, unknown>): Record<string, unknown>[] {
  const groups: Array<[string, string]> = [
    ["dependencies", "runtime"], ["devDependencies", "development"],
    ["peerDependencies", "peer"], ["optionalDependencies", "optional"],
  ];
  const rows: Record<string, unknown>[] = [];
  for (const [key, scope] of groups) {
    const dict = (doc[key] ?? {}) as Record<string, string>;
    for (const [name, range] of Object.entries(dict)) {
      rows.push(mk({
        Component: name, "Package Name": name,
        Group: name.startsWith("@") ? name.split("/")[0] : "",
        Version: String(range).replace(/^[\^~>=<\s]+/, ""),
        Ecosystem: "npm", "Package Manager": "npm/yarn/pnpm",
        PURL: `pkg:npm/${name}@${String(range).replace(/^[\^~>=<\s]+/, "")}`,
        "Parent Component": S(doc.name),
        License: S(doc.license), Metadata: `scope=${scope}; range=${range}`,
      }, "npm manifest"));
    }
  }
  return rows.map((r, i) => ({ "Sr No": i + 1, ...r }));
}

const LINE_PATTERNS: Array<{ re: RegExp; eco: string; fmt: string }> = [
  { re: /^([A-Za-z0-9._-]+)\s*[=~<>]=\s*([0-9][^\s;#]*)/, eco: "PyPI", fmt: "requirements.txt" },
  { re: /^([@A-Za-z0-9._/-]+)@(\^?~?[0-9][^\s]*)$/, eco: "npm", fmt: "package list" },
  { re: /^([A-Za-z0-9._/-]+)\s+v?([0-9][^\s]*)$/, eco: "", fmt: "package list" },
  { re: /^([A-Za-z0-9._/-]+):([0-9][^\s]*)$/, eco: "", fmt: "package list" },
];

function fromLines(text: string, filename: string): Record<string, unknown>[] {
  const isGoMod = /go\.mod$/i.test(filename) || /^module\s+\S+/m.test(text);
  const rows: Record<string, unknown>[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim().replace(/^require\s+/, "").replace(/[(),]/g, " ").trim();
    if (!line || line.startsWith("#") || line.startsWith("//") || /^(module|go|toolchain|exclude|replace)\s/.test(line)) continue;
    if (isGoMod) {
      const m = /^([A-Za-z0-9._~/-]+)\s+v([0-9][^\s]*)/.exec(line);
      if (m) {
        rows.push(mk({
          Component: m[1], "Package Name": m[1].split("/").pop() ?? m[1], Group: m[1].split("/").slice(0, -1).join("/"),
          Version: `v${m[2]}`, Ecosystem: "Go", "Package Manager": "go modules",
          PURL: `pkg:golang/${m[1]}@v${m[2]}`, Metadata: /indirect/.test(raw) ? "indirect" : "direct",
        }, "go.mod"));
      }
      continue;
    }
    for (const p of LINE_PATTERNS) {
      const m = p.re.exec(line);
      if (!m) continue;
      const eco = p.eco;
      rows.push(mk({
        Component: m[1], "Package Name": m[1], Version: m[2].replace(/^[\^~]/, ""),
        Ecosystem: eco, "Package Manager": packageManagerFor(eco),
        PURL: eco === "PyPI" ? `pkg:pypi/${m[1].toLowerCase()}@${m[2]}` : eco === "npm" ? `pkg:npm/${m[1]}@${m[2]}` : "",
      }, p.fmt));
      break;
    }
  }
  return rows.map((r, i) => ({ "Sr No": i + 1, ...r }));
}

/* --------------------------------- Detection -------------------------------- */
export const isStructuredTextFile = (name: string) =>
  /\.(json|cdx|spdx|spdx\.json|xml|yaml|yml|txt|lock|mod|tag|rdf|toml|list|md)$/i.test(name.trim());

function clean(rows: Record<string, unknown>[], format: string, notes: string[]): ParsedSbom {
  const columns: string[] = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!columns.includes(k)) columns.push(k);
  const useful = columns.filter((c) => rows.some((r) => String(r[c] ?? "").trim() !== ""));
  const cleaned = rows.map((r) => Object.fromEntries(useful.map((c) => [c, r[c] ?? ""])));
  return { rows: cleaned, columns: useful, format, notes };
}

/**
 * Parse any text-based SBOM/manifest into the unified model.
 * Throws only when the file contains no recognizable component at all.
 */
export function parseSbomText(text: string, filename: string): ParsedSbom {
  const notes: string[] = [];
  const head = text.slice(0, 4000);
  const lower = filename.toLowerCase();

  // 1. JSON family (incl. YAML that is valid JSON)
  const looksJson = /^\s*[[{]/.test(text);
  if (looksJson) {
    try {
      const doc = JSON.parse(text) as Record<string, unknown>;
      const r = fromStructuredDoc(doc, filename, notes);
      if (r) return clean(r.rows, r.format, notes);
    } catch { notes.push("JSON parse failed — falling back to other detectors"); }
  }

  // 2. XML family
  if (/^\s*<\?xml|^\s*<(bom|rdf|RDF|project|SpdxDocument|spdx)/i.test(head) || /\.(xml|rdf|pom)$/i.test(lower)) {
    try {
      const doc = xml.parse(text) as Record<string, unknown>;
      if (doc.bom) return clean(fromCycloneDxXml(doc), "CycloneDX XML", notes);
      if (doc.RDF || doc.SpdxDocument || /spdx/i.test(head)) {
        const rows = fromSpdxRdfXml(doc);
        if (rows.length) return clean(rows, "SPDX RDF/XML", notes);
      }
      const generic = fromGenericXml(doc, "XML");
      if (generic.length) return clean(generic, generic[0]["Source Format"] as string, notes);
    } catch { notes.push("XML parse failed — falling back"); }
  }

  // 3. SPDX Tag-Value
  if (/^\s*SPDXVersion:/m.test(head) || /^PackageName:/m.test(text)) {
    const rows = fromSpdxTagValue(text);
    if (rows.length) return clean(rows, rows[0]["Source Format"] as string, notes);
  }

  // 4. YAML
  if (/\.(ya?ml)$/i.test(lower) || /^\s*[A-Za-z0-9_-]+:\s/m.test(head)) {
    try {
      const doc = YAML.parse(text) as Record<string, unknown>;
      if (doc && typeof doc === "object") {
        const r = fromStructuredDoc(doc, filename, notes);
        if (r) return clean(r.rows, `${r.format} (YAML)`, notes);
      }
    } catch { notes.push("YAML parse failed — falling back"); }
  }

  // 5. Manifests / package lists / free-form lines
  const lineRows = fromLines(text, filename);
  if (lineRows.length) return clean(lineRows, (lineRows[0]["Source Format"] as string) ?? "Package list", notes);

  throw new Error("No software components could be extracted from this file");
}

/** JSON/YAML object → rows, choosing the richest applicable parser. */
function fromStructuredDoc(
  doc: Record<string, unknown>, filename: string, notes: string[],
): { rows: Record<string, unknown>[]; format: string } | null {
  if (Array.isArray(doc)) {
    const generic = normalizeJsonSbom(JSON.stringify(doc));
    return { rows: generic.rows, format: generic.format };
  }
  if (doc.bomFormat === "CycloneDX" || (doc.specVersion && (doc.components || doc.vulnerabilities))) {
    return { rows: fromCycloneDxJson(doc), format: `CycloneDX ${S(doc.specVersion)}`.trim() };
  }
  if (doc.spdxVersion || doc.SPDXID || doc.packages) {
    return { rows: fromSpdxJson(doc), format: `SPDX ${S(doc.spdxVersion)}`.trim() };
  }
  if (doc.dependencies && (doc.name || /package\.json$/i.test(filename)) && !Array.isArray(doc.dependencies)) {
    return { rows: fromPackageJson(doc), format: "npm manifest" };
  }
  if (doc.SoftwareIdentity || doc.softwareIdentity) {
    const si = (doc.SoftwareIdentity ?? doc.softwareIdentity) as Record<string, unknown>;
    return {
      rows: [{ "Sr No": 1, ...mk({
        Component: S(si.name ?? si["@_name"]), "Package Name": S(si.name ?? si["@_name"]),
        Version: S(si.version ?? si["@_version"]), SWID: S(si.tagId ?? si["@_tagId"]),
        Supplier: S(si.Entity ?? si.entity), Metadata: JSON.stringify(si).slice(0, 400),
      }, "SWID") }],
      format: "SWID",
    };
  }
  try {
    const generic = normalizeJsonSbom(JSON.stringify(doc));
    notes.push("Unknown schema — extracted with generic record detection");
    return { rows: generic.rows, format: generic.format };
  } catch {
    return null;
  }
}

/**
 * Normalize already-tabular rows (Excel/CSV) so they expose the same canonical
 * fields as parsed SBOM documents, while preserving every original column.
 */
export function normalizeTabularRows(rows: Record<string, unknown>[], format: string): ParsedSbom {
  const pick = (r: Record<string, unknown>, keys: string[]) => {
    for (const [k, v] of Object.entries(r)) {
      const lk = k.toLowerCase().replace(/[^a-z]/g, "");
      if (keys.some((c) => lk === c || lk.includes(c))) {
        const s = String(v ?? "").trim();
        if (s) return s;
      }
    }
    return "";
  };
  const out = rows.map((r, i) => {
    const purl = pick(r, ["purl", "packageurl"]);
    const eco = pick(r, ["ecosystem"]) || ecosystemFromPurl(purl);
    const canonical: Record<string, unknown> = {
      Component: pick(r, ["component", "packagename", "library", "productname", "name"]),
      "Package Name": pick(r, ["packagename", "artifact", "module"]),
      Group: pick(r, ["group", "namespace", "groupid"]),
      Version: pick(r, ["version", "release"]),
      Supplier: pick(r, ["supplier", "vendor", "publisher", "manufacturer", "author", "originator"]),
      Ecosystem: eco,
      PURL: purl,
      CPE: pick(r, ["cpe"]),
      License: pick(r, ["license"]),
      "Package Manager": packageManagerFor(eco),
    };
    const merged: Record<string, unknown> = { "Sr No": r["Sr No"] ?? i + 1, ...r };
    for (const [k, v] of Object.entries(canonical)) if (v && !String(merged[k] ?? "").trim()) merged[k] = v;
    merged["Source Format"] = merged["Source Format"] || format;
    return merged;
  });
  return clean(out, format, []);
}
