/* eslint-disable react-refresh/only-export-components */
import * as React from "react";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useRouterState, useNavigate } from "@tanstack/react-router";
import * as XLSX from "xlsx";
import ExcelJS from "exceljs";
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import ReactMarkdown from "react-markdown";
import { motion, AnimatePresence } from "framer-motion";
import { supabase } from "@/integrations/supabase/client";
import { extractFromFile, expandArchives, ACCEPTED_UPLOAD_TYPES } from "@/lib/universal-import";
import { useServerFn } from "@tanstack/react-start";
import { enrichThreatIntel } from "@/lib/threat-intel.functions";
import { enrichRows, mergeIntel } from "@/lib/lifecycle-enrich";
import { lookupNvd } from "@/lib/nist-nvd.functions";
import type { Enrichment } from "@/lib/vuln-intel";
import { identifyApplication, uniqueDatasetName, withApplication, type AppHint } from "@/lib/app-identity";
import { exportCombinedFindings, type CombinedSource } from "@/lib/combined-export";
import { buildUtiReport, type UtiReport } from "@/lib/uti-report";
import { buildReport, type AnalysisReport } from "@/lib/risk-intel";
import { AnalysisReportCard } from "@/components/AnalysisReport";
import { buildPlatformAnalysis, kpiPredicate, type ComponentProfile, type KpiId, type PlatformAnalysis } from "@/lib/platform-intel";
import { lifecycleDisplayText } from "@/lib/lifecycle-display";
import { exportCsv, exportJson, exportXlsx, inventorySheet, analysisSheets, type Sheet } from "@/lib/export-analysis";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { Upload, Database, Trash2, Send, Sparkles, ShieldAlert, ShieldCheck, FileSpreadsheet, Loader2, Search, AlertTriangle, AlertCircle, CheckCircle2, Info, X, Package, Activity, Bug, Download, Building2, Tag, Calendar, FileText, Copy, Edit3, ChevronRight, ChevronLeft, Layers, GitBranch, Hash, Shield, FileBarChart, ExternalLink, ListChecks, Boxes, LayoutDashboard, LogOut, ArrowRight, CalendarClock, Scale } from "lucide-react";

/* ============================== Types & helpers ============================== */
export type Dataset = {
  id: string;
  name: string;
  source_filename: string | null;
  columns: string[];
  created_at: string;
};
export type Component = {
  id: string;
  dataset_id: string;
  data: Record<string, unknown>;
  content_hash: string;
};
export type SeverityKey = "critical" | "high" | "medium" | "low" | "info" | "none";

/** Supabase returns at most 1000 rows per request — page through so large SBOMs are never truncated. */
async function fetchAllPages<T>(
  page: (from: number, to: number) => PromiseLike<{ data: unknown[] | null; error: { message: string } | null }>,
): Promise<T[]> {
  const out: T[] = [];
  for (let from = 0; ; from += 1000) {
    const { data, error } = await page(from, from + 999);
    if (error) throw new Error(error.message);
    out.push(...((data ?? []) as T[]));
    if (!data || data.length < 1000) break;
  }
  return out;
}

async function hashString(s: string): Promise<string> {
  const buf = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}


export const severityConfig: Record<SeverityKey, {
  color: string; bg: string; border: string; dot: string; ring: string;
  icon: typeof AlertTriangle; label: string; hex: string;
}> = {
  critical: { color: "text-severity-critical", bg: "bg-severity-critical/15", border: "border-severity-critical/40", dot: "bg-severity-critical", ring: "ring-severity-critical/40", icon: AlertTriangle, label: "Critical", hex: "var(--color-severity-critical)" },
  high:     { color: "text-severity-high", bg: "bg-severity-high/15", border: "border-severity-high/40", dot: "bg-severity-high", ring: "ring-severity-high/40", icon: AlertTriangle, label: "High", hex: "var(--color-severity-high)" },
  medium:   { color: "text-severity-medium", bg: "bg-severity-medium/15", border: "border-severity-medium/40", dot: "bg-severity-medium", ring: "ring-severity-medium/40", icon: AlertCircle, label: "Medium", hex: "var(--color-severity-medium)" },
  low:      { color: "text-severity-low", bg: "bg-severity-low/15", border: "border-severity-low/40", dot: "bg-severity-low", ring: "ring-severity-low/40", icon: CheckCircle2, label: "Low", hex: "var(--color-severity-low)" },
  info:     { color: "text-severity-info", bg: "bg-severity-info/15", border: "border-severity-info/40", dot: "bg-severity-info", ring: "ring-severity-info/40", icon: Info, label: "Info", hex: "var(--color-severity-info)" },
  none:     { color: "text-muted-foreground", bg: "bg-muted/30", border: "border-border", dot: "bg-muted-foreground", ring: "ring-border", icon: Info, label: "Unrated", hex: "var(--color-muted-foreground)" },
};

const AI_METADATA_FIELDS = new Set([
  "epss", "cwe", "exploit available", "exploit_available", "kev",
  "risk explanation", "risk_explanation", "recommendation",
  "package url", "package_url", "purl", "dependency depth", "dependency_depth",
  "published date", "published_date", "fix version", "fix_version", "cvss vector", "cvss_vector",
]);
const isAiMetaField = (col: string) => AI_METADATA_FIELDS.has(col.toLowerCase().trim());

function findKey(data: Record<string, unknown>, candidates: string[]): string | undefined {
  const keys = Object.keys(data);
  for (const c of candidates) {
    const k = keys.find((k) => k.toLowerCase().replace(/[\s_-]/g, "") === c.toLowerCase().replace(/[\s_-]/g, ""));
    if (k && data[k] != null && String(data[k]).trim() !== "") return k;
  }
  return undefined;
}
export const getField = (data: Record<string, unknown>, candidates: string[]): string => {
  const k = findKey(data, candidates);
  return k ? String(data[k]) : "";
};

export function useAnimatedCount(target: number, durationMs = 800) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let raf = 0;
    const start = performance.now();
    const from = val;
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / durationMs);
      const eased = 1 - Math.pow(1 - p, 3);
      setVal(Math.round(from + (target - from) * eased));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, durationMs]);
  return val;
}


const FIELD_ICONS: Array<[RegExp, typeof Package]> = [
  [/component|package|library|module/i, Package],
  [/application|app|service/i, Boxes],
  [/supplier|vendor|publisher|author/i, Building2],
  [/version|release|tag/i, GitBranch],
  [/cve|advisory/i, ShieldAlert],
  [/cvss|score|epss/i, Activity],
  [/license|legal/i, Tag],
  [/status|state/i, ListChecks],
  [/fix|patch|remediation/i, Shield],
  [/date|time|detected|published/i, Calendar],
  [/id|hash|sr|no\b/i, Hash],
  [/cwe/i, Bug],
  [/purl|url|link/i, ExternalLink],
];
const iconFor = (col: string) => {
  for (const [re, Ic] of FIELD_ICONS) if (re.test(col)) return Ic;
  return FileText;
};

/* ============================== AI bridge ============================== */
const ASK_EVENT = "sbom:ask-analyst";
/** Send a question straight to the AI Security Analyst panel from anywhere. */
export function askAnalyst(prompt: string) {
  try {
    localStorage.setItem("sbom:aiMinimized", "0");
  } catch { /* noop */ }
  window.dispatchEvent(new CustomEvent<string>(ASK_EVENT, { detail: prompt }));
}

/* ============================== Context ============================== */
type WorkbenchCtx = {
  datasets: Dataset[];
  active: Dataset | null;
  activeId: string | null;
  setActiveId: (id: string | null) => void;
  components: Component[];
  loading: boolean;
  uploading: boolean;
  searchQuery: string;
  setSearchQuery: (s: string) => void;
  severityFilter: SeverityKey | "all";
  setSeverityFilter: (s: SeverityKey | "all") => void;
  drawerId: string | null;
  setDrawerId: (id: string | null) => void;
  datasetRiskMap: Record<string, { count: number; risk: number }>;
  lastScan: Date;
  severityCounts: Record<SeverityKey, number>;
  riskScore: number;
  riskBand: { label: string; color: string; desc: string; tone: SeverityKey };
  filteredComponents: Component[];
  fileInputRef: React.RefObject<HTMLInputElement | null>;
  searchRef: React.RefObject<HTMLInputElement | null>;
  handleFile: (file: File, targetDatasetId: string | null, opts?: { hints?: AppHint[]; sourceLabel?: string }) => Promise<{ id: string; name: string } | null>;
  updateCell: (rowId: string, col: string, value: string) => Promise<void>;
  addRow: () => Promise<void>;
  deleteRow: (id: string) => Promise<void>;
  deleteDataset: (id: string) => Promise<void>;
  downloadExcel: () => Promise<void>;
  refresh: () => Promise<void>;
  aiMinimized: boolean;
  setAiMinimized: (v: boolean) => void;
  /* --- V2: platform intelligence --- */
  analysis: PlatformAnalysis;
  profileById: Record<string, ComponentProfile>;
  kpiFilter: KpiId | null;
  setKpiFilter: (k: KpiId | null) => void;
  handleFiles: (files: File[], targetDatasetId: string | null) => Promise<void>;
  uploadProgress: { current: number; total: number; name: string } | null;
  uploadHistory: UploadEntry[];
  utiReport: UtiReport;
  exportAnalysis: (fmt: "xlsx" | "csv" | "json") => Promise<void>;
  /** live vendor lifecycle data (EOL / EOS), shared by every page and export */
  intelMap: Record<string, Enrichment>;
  setIntelMap: React.Dispatch<React.SetStateAction<Record<string, Enrichment>>>;
  enriching: boolean;
  intelAt: string | null;
  refreshIntel: () => void;
  renameDataset: (id: string, name: string) => Promise<void>;
  /** one download with the findings of several files (default: every dataset) */
  exportCombined: (ids: string[], fmt: "xlsx" | "csv" | "json") => Promise<void>;
  combining: boolean;
  exportSection: (name: string, sheet: Sheet, fmt: "xlsx" | "csv" | "json") => Promise<void>;
};

export type UploadEntry = {
  id: string;
  filename: string;
  datasetName: string;
  datasetId: string;
  rows: number;
  format: string;
  at: string;
  action: "created" | "appended";
  /** smart file naming: how the application name was identified */
  appConfidence?: "High" | "Medium" | "Low";
  appReason?: string;
};


const WorkbenchContext = createContext<WorkbenchCtx | null>(null);
export const useWorkbench = () => {
  const c = useContext(WorkbenchContext);
  if (!c) throw new Error("useWorkbench must be used inside WorkbenchProvider");
  return c;
};

export function WorkbenchProvider({ children }: { children: ReactNode }) {
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityKey | "all">("all");
  const [drawerId, setDrawerId] = useState<string | null>(null);
  const [datasetRiskMap, setDatasetRiskMap] = useState<Record<string, { count: number; risk: number }>>({});
  const [lastScan, setLastScan] = useState<Date>(new Date());
  const [aiMinimized, setAiMinimized] = useState(() => {
    try { return localStorage.getItem("sbom:aiMinimized") === "1"; } catch { return false; }
  });
  const [kpiFilter, setKpiFilter] = useState<KpiId | null>(null);
  const [uploadProgress, setUploadProgress] = useState<{ current: number; total: number; name: string } | null>(null);
  const [uploadHistory, setUploadHistory] = useState<UploadEntry[]>([]);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const [intelMap, setIntelMap] = useState<Record<string, Enrichment>>({});
  const [intelAt, setIntelAt] = useState<string | null>(null);
  const [enriching, setEnriching] = useState(false);
  const [combining, setCombining] = useState(false);
  const enrichFn = useServerFn(enrichThreatIntel);
  const nvdFn = useServerFn(lookupNvd);
  const [intelNonce, setIntelNonce] = useState(0);

  useEffect(() => {
    try {
      const raw = localStorage.getItem("sbom:uploadHistory");
      if (raw) setUploadHistory(JSON.parse(raw) as UploadEntry[]);
    } catch { /* noop */ }
  }, []);

  const recordUpload = useCallback((entry: UploadEntry) => {
    setUploadHistory((prev) => {
      const next = [entry, ...prev].slice(0, 200);
      try { localStorage.setItem("sbom:uploadHistory", JSON.stringify(next)); } catch { /* noop */ }
      return next;
    });
  }, []);


  const active = datasets.find((d) => d.id === activeId) ?? null;

  /* ---- V2: automatic platform-wide analysis of every uploaded dataset ---- */
  const analysis = useMemo(
    () => buildPlatformAnalysis(components.map((c) => ({ id: c.id, data: withApplication(c.data, active?.name ?? "") })), intelMap),
    [components, intelMap, active?.name],
  );
  const profileById = useMemo(
    () => Object.fromEntries(analysis.profiles.map((p) => [p.id, p])) as Record<string, ComponentProfile>,
    [analysis],
  );

  const severityCounts = useMemo<Record<SeverityKey, number>>(() => ({
    critical: analysis.counts.critical,
    high: analysis.counts.high,
    medium: analysis.counts.medium,
    low: analysis.counts.low,
    info: analysis.profiles.filter((p) => p.severity === "info").length,
    none: analysis.profiles.filter((p) => p.severity === "none").length,
  }), [analysis]);

  const riskScore = analysis.overallRisk;
  const liveRiskMap = useMemo(
    () => (active ? { ...datasetRiskMap, [active.id]: { count: components.length, risk: analysis.overallRisk } } : datasetRiskMap),
    [datasetRiskMap, active, components.length, analysis.overallRisk],
  );

  /* automatic SBOM-EwayDMS report — rebuilt whenever the inventory changes */
  const utiReport = useMemo(() => {
    const cols = active?.columns?.length
      ? active.columns
      : Array.from(new Set(components.flatMap((c) => Object.keys(c.data))));
    const raw = { columns: cols, rows: components.map((c) => cols.map((k) => String(c.data[k] ?? ""))) };
    return buildUtiReport(active?.name ?? "SBOM", analysis, raw);
  }, [active?.name, active?.columns, analysis, components]);



  const riskBand: WorkbenchCtx["riskBand"] =
    riskScore >= 75 ? { label: "CRITICAL", color: "text-severity-critical", desc: "Immediate action required", tone: "critical" } :
    riskScore >= 50 ? { label: "ELEVATED", color: "text-severity-high", desc: "Prioritize remediation", tone: "high" } :
    riskScore >= 25 ? { label: "MODERATE", color: "text-severity-medium", desc: "Monitor closely", tone: "medium" } :
    { label: "HEALTHY", color: "text-severity-low", desc: "Posture is healthy", tone: "low" };




  const filteredComponents = useMemo(() => {
    let list = components;
    if (kpiFilter && kpiFilter !== "all") {
      const pred = kpiPredicate(kpiFilter, analysis);
      const ok = new Set(analysis.profiles.filter(pred).map((p) => p.id));
      list = list.filter((c) => ok.has(c.id));
    }
    if (severityFilter !== "all") {
      list = list.filter((c) => (profileById[c.id]?.severity ?? "none") === severityFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((c) => Object.values(c.data).some((v) => String(v).toLowerCase().includes(q)));
    }
    return list;
  }, [components, searchQuery, severityFilter, kpiFilter, analysis, profileById]);


  const refresh = useCallback(async () => {
    const { data, error } = await supabase.from("datasets").select("*").order("created_at", { ascending: false });
    if (error) { toast.error(error.message); return; }
    const list = (data ?? []) as unknown as Dataset[];
    setDatasets(list);
    setActiveId((prev) => prev && list.some((d) => d.id === prev) ? prev : list[0]?.id ?? null);
    const map: Record<string, { count: number; risk: number }> = {};
    await Promise.all(list.map(async (d) => {
      const all = await fetchAllPages<{ data: Record<string, unknown> }>((from, to) =>
        supabase.from("components").select("data").eq("dataset_id", d.id).order("id").range(from, to)).catch(() => []);
      /* same NIST scorer as every other screen — the active dataset is overlaid with live NVD data below */
      const risk = buildPlatformAnalysis(all.map((r, i) => ({ id: `${d.id}:${i}`, data: withApplication(r.data, d.name) }))).overallRisk;
      map[d.id] = { count: all.length, risk };
    }));
    setDatasetRiskMap(map);
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  useEffect(() => {
    try { localStorage.setItem("sbom:aiMinimized", aiMinimized ? "1" : "0"); } catch { /* noop */ }
  }, [aiMinimized]);

  useEffect(() => {
    if (!activeId) { setComponents([]); return; }
    setLoading(true);
    void (async () => {
      try {
        const rows = await fetchAllPages<Component>((from, to) =>
          supabase.from("components").select("*").eq("dataset_id", activeId).order("created_at").order("id").range(from, to));
        setComponents(rows);
      } catch (e) {
        toast.error(e instanceof Error ? e.message : "Could not load components");
        setComponents([]);
      }
      setLastScan(new Date());
      setLoading(false);
    })();
  }, [activeId]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  /* names of datasets, kept in a ref so files of one batch can see each other's names */
  const datasetsRef = useRef<Dataset[]>([]);
  datasetsRef.current = datasets;

  const exportCombined = useCallback(async (ids: string[], fmt: "xlsx" | "csv" | "json") => {
    const chosen = datasets.filter((d) => ids.includes(d.id));
    if (!chosen.length) { toast.error("Select at least one file"); return; }
    setCombining(true);
    const tid = toast.loading(`Preparing combined findings for ${chosen.length} file(s)…`);
    try {
      const sources: CombinedSource[] = [];
      let live: Record<string, Enrichment> = { ...intelMap };
      for (const d of chosen) {
        const rows = await fetchAllPages<{ id: string; data: Record<string, unknown> }>((from, to) =>
          supabase.from("components").select("id,data").eq("dataset_id", d.id).order("created_at").order("id").range(from, to));
        const items = rows.map((r) => ({ id: r.id, data: withApplication(r.data, d.name) }));
        toast.loading(`Looking up EOL / EOS dates for ${d.name}…`, { id: tid });
        await enrichRows(items.map((i) => i.data), live, { enrich: enrichFn, nvd: nvdFn }, (patch) => { live = mergeIntel(live, patch); });
        sources.push({
          application: d.name,
          sourceFile: d.source_filename ?? d.name,
          columns: d.columns,
          analysis: buildPlatformAnalysis(items, live),
          nameConfidence: uploadHistory.find((u) => u.datasetId === d.id)?.appConfidence,
        });
      }
      setIntelMap((prev) => mergeIntel(prev, live));
      await exportCombinedFindings(sources, fmt);
      toast.success(`Combined findings for ${sources.length} file(s) downloaded`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Combined export failed");
    } finally {
      toast.dismiss(tid);
      setCombining(false);
    }
  }, [datasets, intelMap, enrichFn, nvdFn, uploadHistory]);

  const handleFile = useCallback(async (
    file: File,
    targetDatasetId: string | null,
    opts?: { hints?: AppHint[]; sourceLabel?: string },
  ): Promise<{ id: string; name: string } | null> => {
    setUploading(true);
    try {
      const parsed = await extractFromFile(file);
      let rows = parsed.rows;
      const sheetCols = parsed.columns;
      const format = parsed.format;
      toast.info(`Detected ${format} — ${rows.length} component(s) extracted`);
      parsed.notes.slice(0, 6).forEach((nt: string) => toast.message(nt));

      if (!rows.length) { toast.error(`No usable SBOM information found in ${file.name}`); return null; }

      // duplicate detection inside the uploaded file itself
      const seen = new Set<string>();
      const unique: Record<string, unknown>[] = [];
      let dupes = 0;
      for (const r of rows) {
        const k = JSON.stringify(r);
        if (seen.has(k)) { dupes++; continue; }
        seen.add(k);
        unique.push(r);
      }
      rows = unique;
      if (dupes) toast.message(`${dupes} duplicate row(s) skipped in ${file.name}`);

      let datasetId = targetDatasetId;
      let action: UploadEntry["action"] = "appended";
      let datasetName = datasetsRef.current.find((d) => d.id === targetDatasetId)?.name ?? "";
      let identity: ReturnType<typeof identifyApplication> | null = null;
      if (!datasetId) {
        /* smart file naming: name the dataset after the APPLICATION, not the (maybe generic) filename */
        identity = identifyApplication({ filename: file.name, rows, hints: [...(parsed.hints ?? []), ...(opts?.hints ?? [])] });
        datasetName = uniqueDatasetName(identity.name, file.name, datasetsRef.current.map((d) => d.name));
        const { data, error } = await supabase.from("datasets").insert({
          name: datasetName, source_filename: opts?.sourceLabel ?? file.name, columns: sheetCols,
        }).select().single();
        if (error) throw error;
        datasetId = (data as { id: string }).id;
        datasetsRef.current = [...datasetsRef.current, data as unknown as Dataset];
        action = "created";
        if (identity.confidence === "Low") toast.warning(`Could not identify the application in ${file.name}`, { description: `Saved as “${datasetName}”. ${identity.reason}`, duration: 9000 });
        else toast.message(`${file.name} → ${datasetName}`, { description: identity.reason, duration: 6000 });
      } else {
        const ds = datasetsRef.current.find((d) => d.id === datasetId);
        const merged = Array.from(new Set([...(ds?.columns ?? []), ...sheetCols]));
        await supabase.from("datasets").update({ columns: merged }).eq("id", datasetId);
      }
      const toInsert = await Promise.all(rows.map(async (r) => ({
        dataset_id: datasetId!, data: r as never, content_hash: await hashString(JSON.stringify(r)),
      })));
      // chunk the write so very large SBOMs stay within request limits
      for (let i = 0; i < toInsert.length; i += 500) {
        const { error: insErr } = await supabase.from("components")
          .upsert(toInsert.slice(i, i + 500), { onConflict: "dataset_id,content_hash", ignoreDuplicates: true });
        if (insErr) throw insErr;
      }

      const [{ data: dsAll }, comp] = await Promise.all([
        supabase.from("datasets").select("*").order("created_at", { ascending: false }),
        fetchAllPages<Component>((from, to) =>
          supabase.from("components").select("*").eq("dataset_id", datasetId!).order("created_at").order("id").range(from, to)),
      ]);
      setDatasets(((dsAll ?? []) as unknown) as Dataset[]);
      setComponents(comp);
      setActiveId(datasetId);
      setLastScan(new Date());
      recordUpload({
        id: `${Date.now()}-${file.name}`,
        filename: file.name,
        datasetName: datasetName || file.name,
        datasetId: datasetId!,
        rows: rows.length,
        format,
        at: new Date().toISOString(),
        action,
        appConfidence: identity?.confidence,
        appReason: identity?.reason,
      });
      toast.success(`Imported ${rows.length} components from ${file.name}`);
      return { id: datasetId!, name: datasetName };
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Upload failed");
      return null;
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }, [recordUpload]);

  const handleFiles = useCallback(async (files: File[], targetDatasetId: string | null) => {
    const picked = files.filter(Boolean);
    if (!picked.length) return;
    // appending to an existing dataset keeps files as-is; new uploads unpack ZIP bundles so each app is identified separately
    const items = targetDatasetId ? picked.map((file) => ({ file, hints: [] as AppHint[], sourceLabel: undefined })) : await expandArchives(picked);
    const created: string[] = [];
    for (let i = 0; i < items.length; i++) {
      setUploadProgress({ current: i + 1, total: items.length, name: items[i].file.name });
      // every file becomes its own application-named dataset, so findings are never mixed up
      const res = await handleFile(items[i].file, targetDatasetId, { hints: items[i].hints, sourceLabel: items[i].sourceLabel });
      if (res && !targetDatasetId) created.push(res.id);
    }
    setUploadProgress(null);
    if (created.length > 1) {
      const all = datasetsRef.current.map((d) => d.id);
      toast.success(`${created.length} files imported as separate applications`, {
        description: "Download every file's findings together in one workbook.",
        duration: 20000,
        action: { label: "Download combined findings", onClick: () => void exportCombined(all, "xlsx") },
      });
    }
  }, [handleFile, exportCombined]);

  const renameDataset = useCallback(async (id: string, name: string) => {
    const clean = name.trim();
    if (!clean) { toast.error("Name cannot be empty"); return; }
    const { error } = await supabase.from("datasets").update({ name: clean }).eq("id", id);
    if (error) { toast.error(error.message); return; }
    setDatasets((prev) => prev.map((d) => (d.id === id ? { ...d, name: clean } : d)));
    toast.success("Renamed");
  }, []);

  /* live vendor lifecycle data (EOL / EOS), CISA KEV and OSV advisories — for every page and export */
  const loadedKey = `${components[0]?.dataset_id ?? ""}:${components.length}`;
  useEffect(() => {
    if (!components.length) return;
    let cancelled = false;
    setEnriching(true);
    void enrichRows(
      components.slice(0, 20000).map((c) => c.data),
      intelMap,
      { enrich: enrichFn, nvd: nvdFn },
      (patch, at) => { setIntelMap((prev) => mergeIntel(prev, patch)); setIntelAt(at); },
      () => cancelled,
    ).finally(() => { if (!cancelled) setEnriching(false); });
    return () => { cancelled = true; setEnriching(false); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loadedKey, intelNonce]);

  const refreshIntel = useCallback(() => { setIntelMap({}); setIntelNonce((n) => n + 1); }, []);

  const updateCell = useCallback(async (rowId: string, col: string, value: string) => {
    const row = components.find((c) => c.id === rowId);
    if (!row) return;
    const newData = { ...row.data, [col]: value };
    setComponents((cs) => cs.map((c) => (c.id === rowId ? { ...c, data: newData } : c)));
    const { error } = await supabase.from("components").update({ data: newData as never }).eq("id", rowId);
    if (error) toast.error(error.message);
  }, [components]);

  const addRow = useCallback(async () => {
    if (!active) return;
    const blank = Object.fromEntries(active.columns.map((c) => [c, ""]));
    const hash = await hashString(JSON.stringify(blank) + Date.now());
    const { data, error } = await supabase.from("components")
      .insert({ dataset_id: active.id, data: blank as never, content_hash: hash }).select().single();
    if (error) { toast.error(error.message); return; }
    setComponents((cs) => [...cs, data as unknown as Component]);
  }, [active]);

  const deleteRow = useCallback(async (id: string) => {
    setComponents((cs) => cs.filter((c) => c.id !== id));
    const { error } = await supabase.from("components").delete().eq("id", id);
    if (error) toast.error(error.message);
    if (drawerId === id) setDrawerId(null);
  }, [drawerId]);

  const deleteDataset = useCallback(async (id: string) => {
    if (!confirm("Delete this dataset and all its components?")) return;
    const { error } = await supabase.from("datasets").delete().eq("id", id);
    if (error) { toast.error(error.message); return; }
    setDatasets((prev) => {
      const remaining = prev.filter((d) => d.id !== id);
      if (activeId === id) setActiveId(remaining[0]?.id ?? null);
      return remaining;
    });
    toast.success("Dataset deleted");
  }, [activeId]);

  const downloadExcel = useCallback(async () => {
    if (!active) return;
    try {
      const wb = new ExcelJS.Workbook();
      wb.creator = "SBOM Workbench";
      wb.created = new Date();
      const allKeys = new Set<string>();
      components.forEach((c) => Object.keys(c.data).forEach((k) => allKeys.add(k)));
      const originalCols = active.columns.filter((c) => !isAiMetaField(c));
      const extraCols = Array.from(allKeys).filter((c) => !active.columns.includes(c) && !isAiMetaField(c));
      const mainCols = [...originalCols, ...extraCols];
      const main = wb.addWorksheet(active.name.slice(0, 30) || "Components");
      main.columns = mainCols.map((c) => ({ header: c, key: c, width: Math.min(40, Math.max(12, c.length + 4)) }));
      main.getRow(1).font = { bold: true, color: { argb: "FFFFFFFF" } };
      main.getRow(1).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF1E3A8A" } };
      main.getRow(1).alignment = { vertical: "middle" };
      main.views = [{ state: "frozen", ySplit: 1 }];
      components.forEach((c, idx) => {
        const row: Record<string, unknown> = {};
        for (const col of mainCols) row[col] = c.data[col] ?? "";
        const r = main.addRow(row);
        /* row colour = NIST severity from the shared analysis, never the raw uploaded column */
        const sev = profileById[c.id]?.severity ?? "none";
        const tint: Record<string, string> = {
          critical: "FFFEE2E2", high: "FFFFEDD5", medium: "FFFEF9C3", low: "FFDCFCE7", info: "FFDBEAFE", none: "",
        };
        if (tint[sev]) r.eachCell((cell) => { cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: tint[sev] } }; });
        if (idx % 2 === 1 && sev === "none") {
          r.eachCell((cell) => { cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFF8FAFC" } }; });
        }
      });
      main.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: mainCols.length } };

      const aiFields = Array.from(allKeys).filter(isAiMetaField);
      const hasAiRows = aiFields.length && components.some((c) => aiFields.some((f) => c.data[f] != null && String(c.data[f]).trim() !== ""));
      if (hasAiRows) {
        const meta = wb.addWorksheet("Additional Component Metadata");
        const cols = ["Component ID", "Application", "Component", "Original CVE", "New Field", "New Value", "Source", "Timestamp"];
        meta.columns = cols.map((c) => ({ header: c, key: c, width: 22 }));
        meta.getRow(1).font = { bold: true, color: { argb: "FFFFFFFF" } };
        meta.getRow(1).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF7C3AED" } };
        meta.views = [{ state: "frozen", ySplit: 1 }];
        const ts = new Date().toISOString();
        for (const c of components) {
          for (const f of aiFields) {
            const v = c.data[f];
            if (v == null || String(v).trim() === "") continue;
            meta.addRow({
              "Component ID": c.id,
              "Application": getField(c.data, ["application", "app"]),
              "Component": getField(c.data, ["component", "package", "name"]),
              "Original CVE": getField(c.data, ["cve", "advisory"]),
              "New Field": f, "New Value": String(v),
              "Source": "AI Analyst", "Timestamp": ts,
            });
          }
        }
        meta.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: cols.length } };
      }
      const out = await wb.xlsx.writeBuffer();
      const blob = new Blob([out], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `${active.name}.xlsx`; a.click();
      URL.revokeObjectURL(url);
      toast.success("Export ready");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Export failed");
    }
  }, [active, components, profileById]);

  const exportAnalysis = useCallback(async (fmt: "xlsx" | "csv" | "json") => {
    if (!active) { toast.error("No dataset selected"); return; }
    try {
      const inv = inventorySheet(active.name, active.columns, analysis.profiles);
      const base = `${active.name}-analysis`;
      if (fmt === "csv") exportCsv(inv, base);
      else if (fmt === "json") exportJson({ dataset: active.name, generatedAt: new Date().toISOString(), analysis }, base);
      else await exportXlsx([inv, ...analysisSheets(analysis)], base);
      toast.success(`${fmt.toUpperCase()} export ready`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Export failed");
    }
  }, [active, analysis]);

  const exportSection = useCallback(async (name: string, sheet: Sheet, fmt: "xlsx" | "csv" | "json") => {
    try {
      const base = `${active?.name ?? "sbom"}-${name}`;
      if (fmt === "csv") exportCsv(sheet, base);
      else if (fmt === "json") exportJson(sheet.rows.map((r) => Object.fromEntries(sheet.columns.map((c, i) => [c, r[i]]))), base);
      else await exportXlsx([sheet], base);
      toast.success(`${name} exported`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Export failed");
    }
  }, [active]);

  const value: WorkbenchCtx = {
    datasets, active, activeId, setActiveId, components, loading, uploading,
    searchQuery, setSearchQuery, severityFilter, setSeverityFilter, drawerId, setDrawerId,
    datasetRiskMap: liveRiskMap, lastScan, severityCounts, riskScore, riskBand, filteredComponents,
    fileInputRef, searchRef, handleFile, updateCell, addRow, deleteRow, deleteDataset, downloadExcel, refresh,
    aiMinimized, setAiMinimized,
    analysis, profileById, kpiFilter, setKpiFilter, handleFiles, uploadProgress, uploadHistory, utiReport,
    exportAnalysis, exportSection,
    intelMap, setIntelMap, enriching, intelAt, refreshIntel, renameDataset, exportCombined, combining,
  };

  return <WorkbenchContext.Provider value={value}>{children}</WorkbenchContext.Provider>;
}

/* ============================== UI: Sidebar ============================== */
const NAV_ITEMS = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/vulnerabilities", icon: ShieldAlert, label: "Vulnerability Intelligence" },
  { to: "/lifecycle", icon: CalendarClock, label: "EOL & EOS Dates" },
  { to: "/licenses", icon: Scale, label: "Licenses" },
  { to: "/reports", icon: FileBarChart, label: "Reports" },
  { to: "/sbom", icon: FileSpreadsheet, label: "SBOM" },
  { to: "/datasets", icon: Database, label: "Datasets" },
] as const;


export function Sidebar() {
  const { datasets, datasetRiskMap, activeId, setActiveId, deleteDataset } = useWorkbench();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  return (
    <aside className="hidden w-64 shrink-0 lg:block">
      <div className="sticky top-[84px] space-y-6 rounded-2xl border border-border/60 bg-sidebar/80 p-3 shadow-sm backdrop-blur-xl">
        <div className="flex items-center gap-3 px-2 pt-1">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
            <ShieldAlert className="h-4 w-4" />
          </div>
          <div>
            <div className="font-display text-sm font-semibold text-sidebar-foreground">UTI AMC</div>
            <div className="text-[10px] font-medium uppercase text-muted-foreground">SBOM Workbench</div>
          </div>
        </div>
        <nav className="space-y-1 border-t border-sidebar-border/70 pt-3">
          {NAV_ITEMS.map((it) => {
            const active = it.to === "/" ? pathname === "/" : pathname.startsWith(it.to);
            return (
              <Link key={it.to} to={it.to}
                className={`group relative flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition ${active ? "bg-primary/10 text-primary shadow-sm ring-1 ring-primary/15" : "text-muted-foreground hover:bg-accent/60 hover:text-foreground"}`}>
                <it.icon className="h-4 w-4 shrink-0" />
                <span className="truncate">{it.label}</span>
              </Link>
            );
          })}
        </nav>

        <div>
          <div className="mb-2 flex items-center justify-between px-2">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Datasets</span>
            <span className="text-[10px] text-muted-foreground">{datasets.length}</span>
          </div>
          <div className="space-y-1.5">
            {datasets.length === 0 && (
              <div className="rounded-xl border border-dashed border-border/70 bg-background/50 p-4 text-center text-xs text-muted-foreground">
                No datasets yet.
              </div>
            )}
            {datasets.map((d) => {
              const info = datasetRiskMap[d.id] ?? { count: 0, risk: 0 };
              const band = info.risk >= 75 ? "bg-severity-critical" : info.risk >= 50 ? "bg-severity-high" : info.risk >= 25 ? "bg-severity-medium" : "bg-severity-low";
              const isActive = activeId === d.id;
              return (
                <motion.div key={d.id} whileHover={{ y: -1 }}
                  className={`group rounded-xl border px-2.5 py-2.5 transition ${isActive ? "border-primary/25 bg-primary/[0.07] shadow-sm" : "border-transparent hover:bg-accent/50"}`}>
                  <div className="flex items-start gap-2">
                    <button onClick={() => setActiveId(d.id)} className="flex flex-1 min-w-0 items-start gap-2 text-left">
                      <Database className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${isActive ? "text-primary" : "text-muted-foreground"}`} />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-sm font-medium">{d.name}</div>
                        <div className="mt-1 flex items-center gap-2 text-[10px] text-muted-foreground">
                          <span>{info.count} comp</span>
                          <span className="flex items-center gap-1">
                            <span className={`h-1.5 w-1.5 rounded-full ${band}`} /> risk {info.risk}
                          </span>
                        </div>
                      </div>
                    </button>
                    <button onClick={() => void deleteDataset(d.id)}
                      className="text-muted-foreground opacity-0 transition group-hover:opacity-100 hover:text-destructive"
                      aria-label="Delete dataset">
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </div>
    </aside>
  );
}

/* ============================== UI: Header ============================== */
export function Header({ userEmail, onSignOut }: { userEmail?: string; onSignOut: () => void }) {
  const { datasets, active, lastScan, riskScore, riskBand, uploading, fileInputRef, handleFiles, downloadExcel } = useWorkbench();
  const greeting = useMemo(() => {
    const h = new Date().getHours();
    if (h < 12) return "Good morning";
    if (h < 18) return "Good afternoon";
    return "Good evening";
  }, []);
  const firstName = userEmail?.split("@")[0] ?? "Analyst";

  return (
    <motion.header initial={{ y: -12, opacity: 0 }} animate={{ y: 0, opacity: 1 }}
      className="sticky top-0 z-30 border-b border-border/60 bg-background/80 backdrop-blur-xl">
      <div className="mx-auto flex max-w-[1720px] flex-wrap items-center justify-between gap-4 px-4 py-3 sm:px-6 lg:px-7">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div className="min-w-0">
            <h1 className="font-display truncate text-base font-semibold leading-tight sm:text-lg">
              {greeting}, <span className="capitalize">{firstName}</span>
            </h1>
            <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-muted-foreground">
              <span className="flex items-center gap-1"><Layers className="h-3 w-3" /> {datasets.length} dataset{datasets.length === 1 ? "" : "s"}</span>
              {active && <span className="flex items-center gap-1"><Database className="h-3 w-3" /> {active.name}</span>}
              <span className="flex items-center gap-1"><Calendar className="h-3 w-3" /> Last scan {lastScan.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
              <span className={`flex items-center gap-1 font-semibold ${riskBand.color}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${severityConfig[riskBand.tone].dot} animate-pulse`} />
                {riskBand.label} · {riskScore}
              </span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <input ref={fileInputRef} type="file" accept={ACCEPTED_UPLOAD_TYPES} multiple className="hidden"
            onChange={(e) => { const fs = Array.from(e.target.files ?? []); if (fs.length) void handleFiles(fs, null); }} />
          {active && (
            <Button onClick={() => void downloadExcel()} variant="outline" size="sm" className="rounded-xl border-border/70 bg-card/80 shadow-none">
              <Download className="mr-1 h-4 w-4" /> Export
            </Button>
          )}
          <Button onClick={() => fileInputRef.current?.click()} disabled={uploading}
            className="rounded-xl shadow-sm">
            {uploading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Upload className="mr-2 h-4 w-4" />}
            New dataset
          </Button>
          <Button onClick={onSignOut} title="Sign out" aria-label="Sign out" variant="ghost" size="icon"
            className="rounded-xl text-muted-foreground">
            <LogOut className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </motion.header>
  );
}

export function ActiveFilterChip() {
  const { severityFilter, setSeverityFilter, filteredComponents, components } = useWorkbench();
  if (severityFilter === "all") return null;
  const cfg = severityConfig[severityFilter];
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className={`chip border ${cfg.bg} ${cfg.border} ${cfg.color}`}>
        <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
        Filter · {cfg.label} ({filteredComponents.length} of {components.length})
      </span>
      <button onClick={() => setSeverityFilter("all")} className="text-muted-foreground hover:text-foreground">
        Reset
      </button>
    </div>
  );
}

/* ============================== UI: Search bar ============================== */
export function SearchBar() {
  const { searchQuery, setSearchQuery, searchRef } = useWorkbench();
  return (
    <div className="relative">
      <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input ref={searchRef} value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)}
        placeholder="Search Component, Vendor, CVE, Version, License…"
        className="h-12 rounded-2xl border-border/60 bg-card/60 pl-11 pr-24 text-sm shadow-sm backdrop-blur transition focus-visible:ring-2 focus-visible:ring-primary/40" />
      <div className="pointer-events-none absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-1">
        {searchQuery ? (
          <button onClick={() => setSearchQuery("")} className="pointer-events-auto rounded-md p-1 text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        ) : (
          <><span className="kbd">Ctrl</span><span className="kbd">K</span></>
        )}
      </div>
    </div>
  );
}

/* ============================== UI: Findings panel ============================== */
export function FindingsPanel() {
  const { analysis, setKpiFilter, exportSection } = useWorkbench();
  const navigate = useNavigate();
  if (!analysis.findings.length) return null;
  return (
    <section className="space-y-3">
      <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
        <ShieldAlert className="h-4 w-4 text-primary" /> Automatic findings
      </h2>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {analysis.findings.map((f, i) => {
          const cfg = severityConfig[f.severity];
          return (
            <motion.article key={f.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.03 }}
              className={`card-elevated border p-4 ${cfg.border}`}>
              <div className="flex items-start justify-between gap-2">
                <h3 className="text-sm font-semibold">{f.title}</h3>
                <span className={`chip border ${cfg.bg} ${cfg.border} ${cfg.color} text-[10px]`}>{f.count}</span>
              </div>
              <p className="mt-1.5 text-xs text-muted-foreground">{f.summary}</p>
              {f.details.length > 0 && (
                <ul className="mt-2 space-y-1 text-[11px] text-foreground/80">
                  {f.details.slice(0, 4).map((d, j) => <li key={j} className="truncate">• {d}</li>)}
                </ul>
              )}
              <div className="mt-3 flex flex-wrap gap-1.5">
                {f.kpi && (
                  <Button size="sm" variant="outline" className="h-7 rounded-lg text-[11px]"
                    onClick={() => { setKpiFilter(f.kpi!); void navigate({ to: "/vulnerabilities" }); }}>
                    View components
                  </Button>
                )}
                {f.columns && f.rows && (
                  <Button size="sm" variant="ghost" className="h-7 rounded-lg text-[11px]"
                    onClick={() => void exportSection(f.title, { name: f.title, columns: f.columns!, rows: f.rows! }, "xlsx")}>
                    <Download className="mr-1 h-3 w-3" /> Export
                  </Button>
                )}
              </div>
            </motion.article>
          );
        })}
      </div>
    </section>
  );
}

/* ============================== UI: Component profile intelligence ============================== */
function ProfileIntel({ profile: p }: { profile: ComponentProfile }) {
  const cfg = severityConfig[p.severity];
  const rows: Array<[string, string]> = [
    ["Package", p.packageName || p.name || "—"],
    ["Version", p.version || "—"],
    ["Supplier", p.supplier || "—"],
    ["Application", p.application || "—"],
    ["PURL", p.purl || "—"],
    ["CPE", p.cpe || "—"],
    ["Hash", p.hash || "—"],
    ["License", `${p.license || "Unknown"} (${p.licenseType})`],
    ["CVE", p.cve || "—"],
    ["CVSS", p.cvss ? String(p.cvss) : "—"],
    ["Lifecycle", lifecycleDisplayText(p.lifecycleStatus, p.eolDate, p.eosDate)],
    ["Support", p.supportStatus],
    ["Remediation", p.remediationStatus],
    ["Recommended action", p.recommendedAction],
    ["Target version", p.targetVersion || "—"],
    ["Latest version", p.latestVersion || "—"],
    ["EOL date", p.eolDate || "—"],
    ["EOS date", p.eosDate || "—"],
    ["Priority", p.priority],
    ["Confidence", p.confidence],
    ["Evidence source", p.evidenceSource],
    ["Exposure", p.exposure],
    ["Business impact", p.businessImpact],
    ["Direct dependencies", p.dependsOn.length ? p.dependsOn.join(", ") : "—"],
    ["Used by", p.dependencyOf.length ? p.dependencyOf.join(", ") : "—"],
  ];
  return (
    <div className={`mb-4 rounded-xl border p-4 ${cfg.border} ${cfg.bg}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className={`chip border bg-background/90 ${cfg.border} ${cfg.color} text-[10px]`}>
          {cfg.label}{p.severitySource === "Declared severity" || p.severitySource === "Unscored" ? ` · ${p.severitySource.toLowerCase()}` : ""}
        </span>
        <span className="chip border border-border bg-background/90 text-[10px]">Risk {p.riskScore}/100 · {p.riskCategory}</span>
        {p.kev && <span className="chip border border-severity-critical/40 bg-background/90 text-[10px] text-severity-critical">Known exploited</span>}
        {p.missing.length > 0 && <span className="chip border border-border bg-background/90 text-[10px]">Missing: {p.missing.join(", ")}</span>}
      </div>
      <div className="mt-3 grid gap-x-4 gap-y-1.5 sm:grid-cols-2">
        {rows.map(([k, v]) => (
          <div key={k} className="min-w-0 text-[11px]">
            <span className="text-muted-foreground">{k}: </span>
            <span className="break-words font-medium text-foreground">{v}</span>
          </div>
        ))}
      </div>
      <p className="mt-3 rounded-lg bg-background/70 p-2 text-[11px] text-muted-foreground">
        {p.severitySource === "Declared severity"
          ? "No CVSS score available — the severity label from the uploaded file is shown until NIST NVD data is found."
          : p.severitySource === "Unscored"
            ? "No CVSS score or severity label — this component is not scored. Lifecycle and metadata findings still apply."
            : `Severity follows the NIST NVD scale for the CVSS ${p.cvss} base score (source: ${p.severitySource}).`}
      </p>
    </div>
  );
}

/* ============================== UI: Detail drawer ============================== */
export function DetailDrawer() {
  const { drawerId, setDrawerId, components, active, updateCell, profileById } = useWorkbench();
  const row = drawerId ? components.find((c) => c.id === drawerId) ?? null : null;
  const columns = active?.columns ?? [];
  const profile = row ? profileById[row.id] : undefined;
  const [edit, setEdit] = useState(false);
  useEffect(() => { setEdit(false); }, [row?.id]);
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") setDrawerId(null); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [setDrawerId]);

  const title = row ? (getField(row.data, ["component", "package", "name"]) || "Component") : "";

  return (
    <AnimatePresence>
      {row && (
        <>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-40 bg-slate-900/40 backdrop-blur-sm" onClick={() => setDrawerId(null)} />
          <motion.aside initial={{ x: "100%" }} animate={{ x: 0 }} exit={{ x: "100%" }}
            transition={{ type: "spring", damping: 28, stiffness: 240 }}
            className="fixed right-0 top-0 z-50 flex h-full w-full max-w-xl flex-col border-l border-border/60 bg-card shadow-2xl">
            <div className="flex items-center justify-between gap-3 border-b border-border/60 bg-background/40 px-5 py-4">
              <div className="min-w-0">
                <p className="text-[11px] uppercase tracking-wider text-muted-foreground">Component Details</p>
                <h2 className="truncate text-lg font-semibold">{title}</h2>
              </div>
              <div className="flex shrink-0 items-center gap-1">
                <Button size="sm" variant="outline" className="rounded-lg" onClick={() => {
                  void navigator.clipboard.writeText(JSON.stringify(row.data, null, 2));
                  toast.success("JSON copied");
                }}><Copy className="mr-1 h-3.5 w-3.5" /> Copy</Button>
                <Button size="sm" variant={edit ? "default" : "outline"} className="rounded-lg" onClick={() => setEdit(!edit)}>
                  <Edit3 className="mr-1 h-3.5 w-3.5" /> {edit ? "Done" : "Edit"}
                </Button>
                <button onClick={() => setDrawerId(null)} className="ml-1 rounded-md p-2 text-muted-foreground hover:bg-accent/50 hover:text-foreground" aria-label="Close">
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              {profile && <ProfileIntel profile={profile} />}
              <div className="grid gap-2.5">
                {columns.map((col) => {
                  const Ic = iconFor(col);
                  const val = String(row.data[col] ?? "");
                  return (
                    <div key={col} className="rounded-xl border border-border/60 bg-background/40 p-3">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                          <Ic className="h-3.5 w-3.5" /> {col}
                        </div>
                        <button onClick={() => { void navigator.clipboard.writeText(val); toast.success("Copied"); }}
                          className="text-muted-foreground transition hover:text-foreground" aria-label="Copy">
                          <Copy className="h-3.5 w-3.5" />
                        </button>
                      </div>
                      {edit ? (
                        <input value={val} onChange={(e) => void updateCell(row.id, col, e.target.value)}
                          className="mt-2 w-full rounded-md border border-border bg-background px-2.5 py-1.5 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/30" />
                      ) : (
                        <div className="mt-1.5 text-sm text-foreground break-words">{val || <span className="text-muted-foreground italic">empty</span>}</div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

/* ============================== UI: Empty / Skeleton / NoDataset ============================== */
export function NoDataset() {
  const { fileInputRef } = useWorkbench();
  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
      className="card-elevated flex h-96 items-center justify-center border border-dashed border-border/60">
      <div className="max-w-sm text-center">
        <div className="mx-auto mb-4 flex h-20 w-20 items-center justify-center rounded-3xl bg-gradient-to-br from-primary/30 to-severity-info/20 text-primary shadow-lg shadow-primary/20">
          <Upload className="h-8 w-8" />
        </div>
        <h2 className="text-xl font-bold tracking-tight">Welcome to your SBOM Workbench</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Upload an SBOM or VAPT Excel sheet to start scanning your component inventory for vulnerabilities.
        </p>
        <Button onClick={() => fileInputRef.current?.click()} className="mt-5 rounded-xl bg-gradient-to-r from-primary to-severity-info shadow-lg shadow-primary/30">
          <Upload className="mr-2 h-4 w-4" /> Upload your first dataset
        </Button>
      </div>
    </motion.div>
  );
}

/* ============================== UI: AI Panel ============================== */
const BASE_PROMPTS = [
  { icon: FileBarChart, label: "Executive overview", prompt: "Give me an executive overview of the overall security posture of this dataset." },
  { icon: Bug, label: "Exploitable now", prompt: "Which components are exploitable right now (KEV / known exploited / CVSS 9+)?" },
  { icon: ShieldCheck, label: "Compliance readiness", prompt: "Assess compliance readiness: SBOM completeness, license coverage and remediation status." },
  { icon: Shield, label: "Remediation plan", prompt: "Produce a prioritized remediation plan for the highest-risk components, including fix versions where known." },
  { icon: Calendar, label: "EOL components", prompt: "Which components are end-of-life, deprecated or unsupported?" },
  { icon: FileText, label: "License exposure", prompt: "Analyze license exposure and copyleft legal risk across the dataset." },
  { icon: Activity, label: "Top CVEs", prompt: "Analyze the top CVEs by CVSS in this dataset." },
  { icon: Building2, label: "Vendor concentration", prompt: "Which vendors concentrate the most risk?" },
  { icon: Boxes, label: "Apps at risk", prompt: "Which applications carry the most vulnerabilities?" },
];


export function AIPanel() {
  const { active, components, severityFilter, filteredComponents, severityCounts, aiMinimized, setAiMinimized } = useWorkbench();
  const [input, setInput] = useState("");
  const [reports, setReports] = useState<Record<string, AnalysisReport>>({});

  const transport = useMemo(() => new DefaultChatTransport({ api: "/api/chat" }), []);
  const { messages, sendMessage, status } = useChat({
    transport, onError: (e: Error) => toast.error(e.message),
  });
  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, status]);

  useEffect(() => { if (!aiMinimized) inputRef.current?.focus(); }, [active?.id, aiMinimized]);

  const busy = status === "submitted" || status === "streaming";

  // Build per-call dataset context: respect the active filter
  const contextRows = severityFilter === "all" ? components : filteredComponents;
  const datasetContext = active ? {
    name: active.name + (severityFilter !== "all" ? ` (filtered: ${severityFilter})` : ""),
    columns: active.columns,
    rows: contextRows.map((c) => c.data).slice(0, 300),
  } : null;

  async function submit(text?: string) {
    const t = (text ?? input).trim();
    if (!t || busy) return;
    if (!text) setInput("");

    // Local deterministic analysis over the FULL dataset (scales to 100k+ rows)
    let report: AnalysisReport | null = null;
    if (active) {
      try {
        report = buildReport(t, { datasetName: active.name, rows: contextRows.map((c) => c.data) });
      } catch {
        report = null;
      }
      if (report) setReports((prev) => ({ ...prev, [t.toLowerCase()]: report! }));
    }

    const analysis = report
      ? {
          title: report.title,
          intent: report.intent,
          matchedRows: report.matchedRows,
          summary: report.summary,
          kpis: report.kpis,
          recommendations: report.recommendations,
          sample: report.tables[0]?.rows.slice(0, 25) ?? [],
          sampleColumns: report.tables[0]?.columns ?? [],
        }
      : null;

    await sendMessage({ text: t }, { body: { datasetContext, analysis } });
  }


  useEffect(() => {
    const handler = (e: Event) => {
      const prompt = (e as CustomEvent<string>).detail;
      if (!prompt) return;
      setAiMinimized(false);
      void submit(prompt);
    };
    window.addEventListener(ASK_EVENT, handler);
    return () => window.removeEventListener(ASK_EVENT, handler);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active?.id, components, severityFilter, filteredComponents, busy]);

  const filterChip = severityFilter !== "all" ? severityConfig[severityFilter] : null;

  // Context-aware suggested prompts
  const suggestedPrompts = useMemo(() => {
    if (severityFilter !== "all") {
      const cfg = severityConfig[severityFilter];
      return [
        { icon: AlertTriangle, label: `Explain top ${cfg.label}`, prompt: `Pick the 3 most important ${cfg.label} severity findings in the current filtered view and explain each in plain English with remediation.` },
        { icon: Shield, label: `Remediation plan`, prompt: `Generate a prioritized remediation plan for all ${cfg.label} findings in the current filtered view.` },
        { icon: FileBarChart, label: `Summarize this filter`, prompt: `Summarize the ${cfg.label} findings: how many, which apps/vendors most affected, common root causes.` },
        ...BASE_PROMPTS,
      ];
    }
    return BASE_PROMPTS;
  }, [severityFilter]);

  if (aiMinimized) {
    return (
      <aside className="hidden shrink-0 xl:flex" style={{ width: 56 }}>
        <div className="card-elevated sticky top-[84px] flex h-[calc(100vh-108px)] w-full flex-col items-center border border-border/60 py-4">
          <Button
            onClick={() => setAiMinimized(false)}
            size="icon" className="h-10 w-10 rounded-xl shadow-sm transition hover:-translate-y-0.5"
            title="Expand AI Security Analyst"
            aria-label="Expand AI Security Analyst"
          >
            <Sparkles className="h-4 w-4" />
          </Button>
          <div className="mt-2 text-[9px] font-semibold uppercase tracking-wider text-muted-foreground" style={{ writingMode: "vertical-rl" }}>
            Analyst
          </div>
          <div className="mt-1.5 flex h-2 w-2 rounded-full bg-severity-low animate-pulse" />
          <Button
            onClick={() => setAiMinimized(false)}
            variant="ghost" size="icon" className="mt-auto h-8 w-8 rounded-lg text-muted-foreground"
            title="Expand"
            aria-label="Expand AI panel"
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
        </div>
      </aside>
    );
  }

  return (
    <aside className="hidden w-80 shrink-0 2xl:flex">
      <div className="card-elevated sticky top-[84px] flex h-[calc(100vh-108px)] w-full flex-col border border-border/60">
        {/* Header */}
        <div className="border-b border-border/60 px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
              <Sparkles className="h-4 w-4" />
              <span className="absolute -bottom-0.5 -right-0.5 flex h-3 w-3">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-severity-low opacity-75" />
                <span className="relative inline-flex h-3 w-3 rounded-full bg-severity-low border-2 border-card" />
              </span>
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <div className="text-sm font-semibold">Security Analyst</div>
                <span className="chip border border-severity-low/40 bg-severity-low/15 text-severity-low text-[9px]">
                  <span className="h-1.5 w-1.5 rounded-full bg-severity-low animate-pulse" />
                  LIVE
                </span>
              </div>
              <div className="truncate text-[10px] text-muted-foreground">
                {active ? <>Dataset: <span className="text-foreground font-medium">{active.name}</span></> : "No dataset selected"}
              </div>
            </div>
            <Button
              onClick={() => setAiMinimized(true)}
              variant="ghost" size="icon" className="h-8 w-8 rounded-lg text-muted-foreground"
              title="Minimize AI panel"
              aria-label="Minimize AI panel"
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
          {filterChip && (
            <div className="mt-2 flex items-center gap-2 text-[10px]">
              <span className={`chip border ${filterChip.bg} ${filterChip.border} ${filterChip.color}`}>
                Filter: {filterChip.label} ({filteredComponents.length})
              </span>
            </div>
          )}
        </div>

        {/* Messages */}
        <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto p-4">
          {messages.length === 0 && (
            <div className="space-y-3">
              <div className="rounded-xl border border-dashed border-border/60 p-3 text-xs text-muted-foreground">
                Ask about components, CVEs, severities, or remediations. {active ? <>I'm working with <span className="text-foreground font-medium">{active.name}</span>{severityFilter !== "all" && <>, filtered to <span className="text-foreground font-medium">{severityConfig[severityFilter].label}</span></>}.</> : "Upload or select a dataset to start."}
              </div>
              <div className="grid gap-1.5">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground px-1">Quick actions</div>
                {suggestedPrompts.slice(0, 6).map((s) => (
                  <button key={s.label} onClick={() => void submit(s.prompt)} disabled={busy || !active}
                    className="flex items-center gap-2 rounded-lg border border-border/60 bg-background/40 px-3 py-2 text-xs text-foreground transition hover:border-primary/40 hover:bg-primary/10 disabled:opacity-50">
                    <s.icon className="h-3.5 w-3.5 text-primary" /> {s.label}
                    <ArrowRight className="ml-auto h-3 w-3 opacity-50" />
                  </button>
                ))}
              </div>
              <div className="text-[10px] text-muted-foreground px-1">
                Severity in context · C {severityCounts.critical} · H {severityCounts.high} · M {severityCounts.medium} · L {severityCounts.low}
              </div>
            </div>
          )}
          {messages.map((m, mi) => {
            const text = m.parts.map((p) => (p.type === "text" ? p.text : "")).join("");
            const tools = m.parts.filter((p) => p.type.startsWith("tool-"));
            let report: AnalysisReport | undefined;
            if (m.role === "assistant") {
              for (let j = mi - 1; j >= 0; j--) {
                if (messages[j].role === "user") {
                  const q = messages[j].parts.map((p) => (p.type === "text" ? p.text : "")).join("").trim().toLowerCase();
                  report = reports[q];
                  break;
                }
              }
            }
            return (

              <motion.div key={m.id} initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }}
                className={m.role === "user"
                  ? "ml-6 rounded-2xl bg-primary px-3.5 py-2.5 text-sm text-primary-foreground shadow-md shadow-primary/20"
                  : "mr-6 text-sm text-foreground"}>
                {tools.length > 0 && (
                  <div className="mb-1.5 flex items-center gap-1.5 rounded-lg border border-primary/30 bg-primary/5 px-2 py-1 text-[10px] uppercase tracking-wider text-primary">
                    <Loader2 className="h-2.5 w-2.5 animate-spin" /> Looking up vulnerability data…
                  </div>
                )}
                <div className="prose prose-sm max-w-none prose-p:my-1 prose-pre:my-1.5 prose-table:my-2 prose-table:text-xs prose-headings:mt-2 prose-headings:mb-1 prose-th:bg-muted/40 prose-th:border-border prose-td:border-border prose-th:px-2 prose-th:py-1 prose-td:px-2 prose-td:py-1 prose-code:rounded prose-code:bg-muted/60 prose-code:px-1 prose-code:py-0.5 prose-code:text-[0.85em] prose-code:before:content-none prose-code:after:content-none">
                  <ReactMarkdown>{text || "…"}</ReactMarkdown>
                </div>
                {report && <div className="mt-2"><AnalysisReportCard report={report} /></div>}
              </motion.div>

            );
          })}
          {status === "submitted" && (
            <div className="mr-6 flex items-center gap-2 text-sm text-muted-foreground">
              <div className="skeleton h-2 w-32 rounded-full" />
              <span className="text-xs">Analyzing dataset…</span>
            </div>
          )}
        </div>

        {/* Composer */}
        <div className="border-t border-border/60 p-3">
          {messages.length > 0 && (
            <div className="mb-2 flex gap-1.5 overflow-x-auto pb-1">
              {suggestedPrompts.slice(0, 5).map((s) => (
                <button key={s.label} onClick={() => void submit(s.prompt)} disabled={busy || !active}
                  className="chip shrink-0 border border-border/60 bg-background/60 text-foreground/80 hover:border-primary/40 hover:bg-primary/10 hover:text-foreground disabled:opacity-50">
                  <s.icon className="h-3 w-3" /> {s.label}
                </button>
              ))}
            </div>
          )}
          <form onSubmit={(e) => { e.preventDefault(); void submit(); }} className="flex gap-2">
            <Input ref={inputRef} value={input} onChange={(e) => setInput(e.target.value)}
              placeholder={active ? `Ask about ${active.name}…` : "Select a dataset first…"}
              disabled={busy} className="rounded-xl" />
            <Button type="submit" size="icon" disabled={busy || !input.trim()} className="rounded-xl">
              <Send className="h-4 w-4" />
            </Button>
          </form>
        </div>
      </div>
    </aside>
  );
}
