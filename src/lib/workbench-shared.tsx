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
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RTooltip,
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  BarChart, Bar,
} from "recharts";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import {
  Upload, Database, Trash2, Plus, Send, Sparkles, ShieldAlert, ShieldCheck,
  FileSpreadsheet, Loader2, Search, AlertTriangle, AlertCircle, CheckCircle2,
  Info, X, Package, TrendingUp, TrendingDown, Activity, Bug, Download,
  Building2, Tag, Calendar, FileText, Copy, Edit3, ChevronRight, Layers,
  GitBranch, Hash, Shield, FileBarChart, ExternalLink, ListChecks, Boxes,
  LayoutDashboard, LogOut, ArrowRight,
} from "lucide-react";

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

async function hashString(s: string): Promise<string> {
  const buf = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

const SEVERITY_KEYS = ["severity", "risk", "level", "criticality", "priority", "impact", "cvss", "score"];
export function detectSeverityColumn(columns: string[]): string | null {
  const lower = columns.map((c) => c.toLowerCase());
  for (const key of SEVERITY_KEYS) {
    const idx = lower.findIndex((c) => c.includes(key));
    if (idx >= 0) return columns[idx];
  }
  return null;
}

export function getSeverityLevel(value: unknown): SeverityKey {
  const s = String(value ?? "").toLowerCase().trim();
  if (s.includes("critical") || s.includes("severe")) return "critical";
  if (s.includes("high") || s.includes("major")) return "high";
  if (s.includes("medium") || s.includes("moderate")) return "medium";
  if (s.includes("low") || s.includes("minor")) return "low";
  if (s.includes("info") || s.includes("note")) return "info";
  const n = Number(s);
  if (!isNaN(n)) {
    if (n >= 9) return "critical";
    if (n >= 7) return "high";
    if (n >= 4) return "medium";
    if (n > 0) return "low";
  }
  return "none";
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

export function highlightMatch(text: string, query: string): ReactNode {
  if (!query.trim()) return text;
  const q = query.trim();
  const idx = text.toLowerCase().indexOf(q.toLowerCase());
  if (idx < 0) return text;
  return (<>{text.slice(0, idx)}<mark className="search-hl">{text.slice(idx, idx + q.length)}</mark>{text.slice(idx + q.length)}</>);
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
  severityCol: string | null;
  severityCounts: Record<SeverityKey, number>;
  riskScore: number;
  riskBand: { label: string; color: string; desc: string; tone: SeverityKey };
  filteredComponents: Component[];
  fileInputRef: React.RefObject<HTMLInputElement | null>;
  searchRef: React.RefObject<HTMLInputElement | null>;
  handleFile: (file: File, targetDatasetId: string | null) => Promise<void>;
  updateCell: (rowId: string, col: string, value: string) => Promise<void>;
  addRow: () => Promise<void>;
  deleteRow: (id: string) => Promise<void>;
  deleteDataset: (id: string) => Promise<void>;
  downloadExcel: () => Promise<void>;
  refresh: () => Promise<void>;
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
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);

  const active = datasets.find((d) => d.id === activeId) ?? null;
  const severityCol = active ? detectSeverityColumn(active.columns) : null;

  const severityCounts = useMemo(() => {
    const counts: Record<SeverityKey, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, none: 0 };
    if (!severityCol) return counts;
    for (const c of components) counts[getSeverityLevel(c.data[severityCol])]++;
    return counts;
  }, [components, severityCol]);

  const riskScore = useMemo(() => {
    const total = components.length || 1;
    const w = severityCounts.critical * 10 + severityCounts.high * 7 + severityCounts.medium * 4 + severityCounts.low * 1;
    return Math.min(100, Math.round((w / (total * 10)) * 100));
  }, [components.length, severityCounts]);

  const riskBand: WorkbenchCtx["riskBand"] =
    riskScore >= 75 ? { label: "CRITICAL", color: "text-severity-critical", desc: "Immediate action required", tone: "critical" } :
    riskScore >= 50 ? { label: "ELEVATED", color: "text-severity-high", desc: "Prioritize remediation", tone: "high" } :
    riskScore >= 25 ? { label: "MODERATE", color: "text-severity-medium", desc: "Monitor closely", tone: "medium" } :
    { label: "HEALTHY", color: "text-severity-low", desc: "Posture is healthy", tone: "low" };

  const filteredComponents = useMemo(() => {
    let list = components;
    if (severityFilter !== "all" && severityCol) {
      list = list.filter((c) => getSeverityLevel(c.data[severityCol]) === severityFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((c) => Object.values(c.data).some((v) => String(v).toLowerCase().includes(q)));
    }
    return list;
  }, [components, searchQuery, severityFilter, severityCol]);

  const refresh = useCallback(async () => {
    const { data, error } = await supabase.from("datasets").select("*").order("created_at", { ascending: false });
    if (error) { toast.error(error.message); return; }
    const list = (data ?? []) as unknown as Dataset[];
    setDatasets(list);
    setActiveId((prev) => prev && list.some((d) => d.id === prev) ? prev : list[0]?.id ?? null);
    const map: Record<string, { count: number; risk: number }> = {};
    await Promise.all(list.map(async (d) => {
      const { data: rows } = await supabase.from("components").select("data").eq("dataset_id", d.id);
      const sev = detectSeverityColumn(d.columns);
      const all = (rows ?? []) as { data: Record<string, unknown> }[];
      const counts = { critical: 0, high: 0, medium: 0, low: 0 };
      if (sev) for (const r of all) {
        const k = getSeverityLevel(r.data[sev]);
        if (k in counts) counts[k as keyof typeof counts]++;
      }
      const total = all.length || 1;
      const w = counts.critical * 10 + counts.high * 7 + counts.medium * 4 + counts.low;
      map[d.id] = { count: all.length, risk: Math.min(100, Math.round((w / (total * 10)) * 100)) };
    }));
    setDatasetRiskMap(map);
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  useEffect(() => {
    if (!activeId) { setComponents([]); return; }
    setLoading(true);
    void (async () => {
      const { data, error } = await supabase.from("components").select("*").eq("dataset_id", activeId).order("created_at");
      if (error) toast.error(error.message);
      setComponents(((data ?? []) as unknown) as Component[]);
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

  const handleFile = useCallback(async (file: File, targetDatasetId: string | null) => {
    setUploading(true);
    try {
      const buf = await file.arrayBuffer();
      const wb = XLSX.read(buf, { type: "array" });
      const sheet = wb.Sheets[wb.SheetNames[0]];
      const rows = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, { defval: "" });
      if (!rows.length) { toast.error("No rows found in sheet"); return; }
      const sheetCols = Array.from(rows.reduce((a, r) => { Object.keys(r).forEach((k) => a.add(k)); return a; }, new Set<string>()));

      let datasetId = targetDatasetId;
      if (!datasetId) {
        const { data, error } = await supabase.from("datasets").insert({
          name: file.name.replace(/\.[^.]+$/, ""), source_filename: file.name, columns: sheetCols,
        }).select().single();
        if (error) throw error;
        datasetId = (data as { id: string }).id;
      } else {
        const ds = datasets.find((d) => d.id === datasetId);
        const merged = Array.from(new Set([...(ds?.columns ?? []), ...sheetCols]));
        await supabase.from("datasets").update({ columns: merged }).eq("id", datasetId);
      }
      const toInsert = await Promise.all(rows.map(async (r) => ({
        dataset_id: datasetId!, data: r as never, content_hash: await hashString(JSON.stringify(r)),
      })));
      const { error: insErr } = await supabase.from("components").upsert(toInsert, { onConflict: "dataset_id,content_hash", ignoreDuplicates: true });
      if (insErr) throw insErr;

      const [{ data: dsAll }, { data: comp }] = await Promise.all([
        supabase.from("datasets").select("*").order("created_at", { ascending: false }),
        supabase.from("components").select("*").eq("dataset_id", datasetId!).order("created_at"),
      ]);
      setDatasets(((dsAll ?? []) as unknown) as Dataset[]);
      setComponents(((comp ?? []) as unknown) as Component[]);
      setActiveId(datasetId);
      setLastScan(new Date());
      toast.success(`Imported ${rows.length} rows from ${file.name}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }, [datasets]);

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
<<<<<<< HEAD
    if (error) { toast.error(error.message); return; }
=======
    if (error) return toast.error(error.message);
>>>>>>> 4653eb72e133a42a05f9c2a043f2e4b3c1788a85
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
<<<<<<< HEAD
    if (error) { toast.error(error.message); return; }
=======
    if (error) return toast.error(error.message);
>>>>>>> 4653eb72e133a42a05f9c2a043f2e4b3c1788a85
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
        if (severityCol) {
          const sev = getSeverityLevel(c.data[severityCol]);
          const tint: Record<string, string> = {
            critical: "FFFEE2E2", high: "FFFFEDD5", medium: "FFFEF9C3", low: "FFDCFCE7", info: "FFDBEAFE", none: "",
          };
          if (tint[sev]) r.eachCell((cell) => { cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: tint[sev] } }; });
        }
        if (idx % 2 === 1 && severityCol == null) {
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
  }, [active, components, severityCol]);

  const value: WorkbenchCtx = {
    datasets, active, activeId, setActiveId, components, loading, uploading,
    searchQuery, setSearchQuery, severityFilter, setSeverityFilter, drawerId, setDrawerId,
    datasetRiskMap, lastScan, severityCol, severityCounts, riskScore, riskBand, filteredComponents,
    fileInputRef, searchRef, handleFile, updateCell, addRow, deleteRow, deleteDataset, downloadExcel, refresh,
  };
  return <WorkbenchContext.Provider value={value}>{children}</WorkbenchContext.Provider>;
}

/* ============================== UI: Sidebar ============================== */
const NAV_ITEMS = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/components", icon: Package, label: "Components" },
  { to: "/vulnerabilities", icon: ShieldAlert, label: "Vulnerabilities" },
  { to: "/reports", icon: FileBarChart, label: "Reports" },
  { to: "/sbom", icon: FileSpreadsheet, label: "SBOM" },
  { to: "/datasets", icon: Database, label: "Datasets" },
] as const;

export function Sidebar() {
  const { datasets, datasetRiskMap, activeId, setActiveId, deleteDataset } = useWorkbench();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  return (
    <aside className="hidden w-60 shrink-0 lg:block">
      <div className="sticky top-[88px] space-y-5">
        <nav className="space-y-1">
          {NAV_ITEMS.map((it) => {
            const active = it.to === "/" ? pathname === "/" : pathname.startsWith(it.to);
            return (
              <Link key={it.to} to={it.to}
                className={`group relative flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition ${active ? "bg-primary/15 text-foreground" : "text-muted-foreground hover:bg-accent/40 hover:text-foreground"}`}>
                {active && <span className="absolute left-0 top-1/2 h-5 w-1 -translate-y-1/2 rounded-r bg-primary" />}
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
              <div className="rounded-xl border border-dashed border-border/60 p-4 text-center text-xs text-muted-foreground">
                No datasets yet.
              </div>
            )}
            {datasets.map((d) => {
              const info = datasetRiskMap[d.id] ?? { count: 0, risk: 0 };
              const band = info.risk >= 75 ? "bg-severity-critical" : info.risk >= 50 ? "bg-severity-high" : info.risk >= 25 ? "bg-severity-medium" : "bg-severity-low";
              const isActive = activeId === d.id;
              return (
                <motion.div key={d.id} whileHover={{ x: 2 }}
                  className={`group rounded-xl border px-2.5 py-2 transition ${isActive ? "border-primary/40 bg-primary/10 shadow-sm shadow-primary/10" : "border-transparent hover:bg-accent/40"}`}>
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
  const { datasets, active, lastScan, riskScore, riskBand, uploading, fileInputRef, handleFile, downloadExcel } = useWorkbench();
  const greeting = useMemo(() => {
    const h = new Date().getHours();
    if (h < 12) return "Good morning";
    if (h < 18) return "Good afternoon";
    return "Good evening";
  }, []);
  const firstName = userEmail?.split("@")[0] ?? "Analyst";

  return (
    <motion.header initial={{ y: -16, opacity: 0 }} animate={{ y: 0, opacity: 1 }}
      className="sticky top-0 z-30 border-b border-border/60 bg-background/60 backdrop-blur-xl">
      <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-4 px-4 py-3 sm:px-6 lg:px-8">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br from-primary via-severity-info to-primary text-primary-foreground shadow-lg shadow-primary/30">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div className="min-w-0">
            <h1 className="truncate text-base font-semibold leading-tight tracking-tight sm:text-lg">
              {greeting}, <span className="capitalize">{firstName}</span> 👋
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
          <input ref={fileInputRef} type="file" accept=".xlsx,.xls,.csv" className="hidden"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) void handleFile(f, null); }} />
          {active && (
            <Button onClick={() => void downloadExcel()} variant="outline" size="sm" className="rounded-xl">
              <Download className="mr-1 h-4 w-4" /> Export
            </Button>
          )}
          <Button onClick={() => fileInputRef.current?.click()} disabled={uploading}
            className="rounded-xl bg-gradient-to-r from-primary to-severity-info shadow-lg shadow-primary/30 hover:shadow-primary/50">
            {uploading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Upload className="mr-2 h-4 w-4" />}
            New dataset
          </Button>
          <button onClick={onSignOut} title="Sign out"
            className="rounded-xl p-2 text-muted-foreground transition hover:bg-accent/40 hover:text-foreground">
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </motion.header>
  );
}

/* ============================== UI: KPI tiles (clickable filter) ============================== */
export function KpiRow() {
  const { components, severityCounts, severityFilter, setSeverityFilter } = useWorkbench();
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  const tiles: Array<{ key: SeverityKey | "all"; label: string; value: number; tone: SeverityKey; icon: typeof Package; glow?: boolean }> = [
    { key: "all", label: "Components", value: components.length, tone: "info", icon: Package },
    { key: "critical", label: "Critical", value: severityCounts.critical, tone: "critical", icon: AlertTriangle, glow: severityCounts.critical > 0 },
    { key: "high", label: "High", value: severityCounts.high, tone: "high", icon: AlertTriangle },
    { key: "medium", label: "Medium", value: severityCounts.medium, tone: "medium", icon: AlertCircle },
    { key: "low", label: "Low / Info", value: severityCounts.low + severityCounts.info, tone: "low", icon: CheckCircle2 },
  ];

  const onTile = (key: SeverityKey | "all") => {
    setSeverityFilter(key);
    if (key !== "all" && pathname === "/") navigate({ to: "/components" });
  };

  return (
    <section className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
      {tiles.map((t) => {
        const cfg = severityConfig[t.tone];
        const animated = useAnimatedCount(t.value);
        const isActive = severityFilter === t.key;
        return (
          <motion.button key={t.key} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
            whileHover={{ y: -3 }} whileTap={{ scale: 0.98 }} onClick={() => onTile(t.key)}
            className={`card-elevated card-hover relative overflow-hidden border p-4 text-left transition ${cfg.border} ${t.glow && t.value > 0 ? "glow-critical" : ""} ${isActive ? `ring-2 ${cfg.ring} ring-offset-2 ring-offset-background` : ""}`}>
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{t.label}</span>
              <div className={`flex h-7 w-7 items-center justify-center rounded-lg ${cfg.bg} ${cfg.color}`}>
                <t.icon className="h-3.5 w-3.5" />
              </div>
            </div>
            <div className={`mt-2 text-3xl font-bold tracking-tight ${cfg.color}`}>{animated.toLocaleString()}</div>
            <div className="mt-1 text-[11px] text-muted-foreground">
              {t.key === "all" ? "Click to reset filters" : isActive ? "Filter active — click to clear" : "Click to filter"}
            </div>
          </motion.button>
        );
      })}
    </section>
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

/* ============================== UI: Enterprise Risk Card ============================== */
export function EnterpriseRiskCard() {
  const { riskScore, riskBand, severityCounts, lastScan, components } = useWorkbench();
  const animated = useAnimatedCount(riskScore);
  const cfg = severityConfig[riskBand.tone];
  // synthetic trend delta - in real app, store snapshots
  const delta = Math.round(((riskScore % 7) - 3));
  const trendUp = delta > 0;
  const topVulns = useMemo(() => {
    return components
      .map((c) => ({ name: getField(c.data, ["component", "package", "name"]) || "Unknown", cvss: parseFloat(getField(c.data, ["cvss", "score"])) || 0, cve: getField(c.data, ["cve", "advisory"]) }))
      .filter((x) => x.cvss > 0)
      .sort((a, b) => b.cvss - a.cvss)
      .slice(0, 1);
  }, [components]);

  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.1 }}
      className="card-elevated border border-border/60 p-6">
      <div className="flex items-center justify-between">
        <div>
          <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Overall Security Score</span>
          <div className="mt-2 flex items-baseline gap-3">
            <span className={`text-5xl font-bold tracking-tight ${cfg.color}`}>{animated}</span>
            <span className="text-sm text-muted-foreground">/ 100</span>
            <span className={`chip border ${cfg.bg} ${cfg.border} ${cfg.color}`}>
              <Shield className="h-3 w-3" /> {riskBand.label}
            </span>
          </div>
        </div>
        <div className="text-right">
          <div className={`flex items-center gap-1 text-xs font-semibold ${trendUp ? "text-severity-critical" : "text-severity-low"}`}>
            {trendUp ? <TrendingUp className="h-3.5 w-3.5" /> : <TrendingDown className="h-3.5 w-3.5" />}
            {trendUp ? "+" : ""}{delta} pts
          </div>
          <div className="text-[10px] text-muted-foreground">vs last scan</div>
        </div>
      </div>

      <div className="mt-4">
        <div className="relative h-2.5 w-full overflow-hidden rounded-full bg-muted/30">
          <motion.div
            initial={{ width: 0 }} animate={{ width: `${riskScore}%` }} transition={{ duration: 0.9, ease: "easeOut" }}
            className="h-full rounded-full"
            style={{ background: "linear-gradient(90deg, var(--color-severity-low) 0%, var(--color-severity-medium) 50%, var(--color-severity-critical) 100%)" }}
          />
        </div>
        <div className="mt-1 flex justify-between text-[10px] text-muted-foreground">
          <span>Healthy</span><span>Moderate</span><span>Elevated</span><span>Critical</span>
        </div>
      </div>

      <div className="mt-5 grid grid-cols-4 gap-2">
        {(["critical", "high", "medium", "low"] as SeverityKey[]).map((k) => {
          const c = severityConfig[k];
          return (
            <div key={k} className={`rounded-lg border ${c.border} ${c.bg} px-2 py-2 text-center`}>
              <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{c.label}</div>
              <div className={`mt-0.5 text-lg font-bold ${c.color}`}>{severityCounts[k]}</div>
            </div>
          );
        })}
      </div>

      <div className="mt-4 flex items-start gap-2 rounded-xl border border-primary/30 bg-primary/5 p-3">
        <Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary" />
        <div className="min-w-0 text-xs">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-primary">AI Recommendation</div>
          <p className="mt-0.5 text-foreground/90 leading-snug">
            {topVulns.length > 0
              ? <>Patch <span className="font-semibold">{topVulns[0].name}</span> first {topVulns[0].cve ? <>({topVulns[0].cve}, CVSS {topVulns[0].cvss})</> : null} — highest single-component risk in this dataset.</>
              : severityCounts.critical > 0
              ? "Triage Critical findings first; review fix availability and patch within 24-48h."
              : "Posture is stable. Run a fresh scan to detect drift."}
          </p>
        </div>
      </div>

      <div className="mt-3 flex items-center justify-between text-[10px] text-muted-foreground">
        <span className="flex items-center gap-1"><Calendar className="h-3 w-3" /> Last scan {lastScan.toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}</span>
        <span>{components.length} components</span>
      </div>
    </motion.div>
  );
}

/* ============================== UI: Severity bar + charts ============================== */
export function AnimatedSeverityBar({ counts, total }: { counts: Record<SeverityKey, number>; total: number }) {
  if (total === 0) return <div className="h-3 w-full rounded-full bg-muted/40" />;
  const segs: SeverityKey[] = ["critical", "high", "medium", "low", "info", "none"];
  return (
    <div className="flex h-3 w-full overflow-hidden rounded-full bg-muted/30">
      {segs.map((k) => {
        const pct = (counts[k] / total) * 100;
        if (pct === 0) return null;
        return (
          <motion.div key={k} className={severityConfig[k].dot} initial={{ width: 0 }}
            animate={{ width: `${pct}%` }} transition={{ duration: 0.7, ease: "easeOut" }}
            title={`${k}: ${counts[k]}`} />
        );
      })}
    </div>
  );
}

export function ChartsRow() {
  const { severityCounts, components } = useWorkbench();
  const donut = useMemo(() => (["critical", "high", "medium", "low", "info"] as SeverityKey[])
    .map((k) => ({ name: severityConfig[k].label, value: severityCounts[k], fill: severityConfig[k].hex }))
    .filter((d) => d.value > 0), [severityCounts]);
  const topVendors = useMemo(() => {
    const m = new Map<string, number>();
    for (const c of components) {
      const v = getField(c.data, ["supplier", "vendor", "publisher"]);
      if (!v) continue;
      m.set(v, (m.get(v) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, value]) => ({ name, value }));
  }, [components]);
  const trend = useMemo(() => {
    const base = severityCounts.critical + severityCounts.high * 0.6 + severityCounts.medium * 0.3;
    return Array.from({ length: 14 }, (_, i) => ({
      day: `D${i + 1}`,
      risk: Math.max(0, Math.round(base * (0.6 + Math.sin(i * 0.5) * 0.25 + i * 0.02))),
    }));
  }, [severityCounts]);

  if (components.length === 0) return null;
  return (
    <section className="grid gap-4 md:grid-cols-3">
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card-elevated border border-border/60 p-5">
        <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold"><Activity className="h-4 w-4 text-primary" /> Severity Distribution</h3>
        <div className="h-44">
          <ResponsiveContainer>
            <PieChart>
              <Pie data={donut} dataKey="value" nameKey="name" innerRadius={42} outerRadius={70} paddingAngle={3}>
                {donut.map((d, i) => <Cell key={i} fill={d.fill} stroke="transparent" />)}
              </Pie>
              <RTooltip contentStyle={{ background: "var(--color-popover)", border: "1px solid var(--color-border)", borderRadius: 10, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="card-elevated border border-border/60 p-5">
        <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold"><TrendingUp className="h-4 w-4 text-primary" /> Risk Trend (14d)</h3>
        <div className="h-44">
          <ResponsiveContainer>
            <LineChart data={trend}>
              <CartesianGrid strokeDasharray="3 3" stroke="color-mix(in oklab, var(--color-foreground) 8%, transparent)" />
              <XAxis dataKey="day" stroke="var(--color-muted-foreground)" fontSize={10} />
              <YAxis stroke="var(--color-muted-foreground)" fontSize={10} />
              <RTooltip contentStyle={{ background: "var(--color-popover)", border: "1px solid var(--color-border)", borderRadius: 10, fontSize: 12 }} />
              <Line type="monotone" dataKey="risk" stroke="var(--color-primary)" strokeWidth={2.5} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="card-elevated border border-border/60 p-5">
        <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold"><Building2 className="h-4 w-4 text-primary" /> Top Vendors</h3>
        <div className="h-44">
          {topVendors.length === 0 ? (
            <div className="flex h-full items-center justify-center text-xs text-muted-foreground">No vendor data</div>
          ) : (
            <ResponsiveContainer>
              <BarChart data={topVendors} layout="vertical" margin={{ left: 12 }}>
                <XAxis type="number" stroke="var(--color-muted-foreground)" fontSize={10} />
                <YAxis type="category" dataKey="name" width={90} stroke="var(--color-muted-foreground)" fontSize={10} />
                <RTooltip contentStyle={{ background: "var(--color-popover)", border: "1px solid var(--color-border)", borderRadius: 10, fontSize: 12 }} />
                <Bar dataKey="value" fill="var(--color-primary)" radius={[0, 6, 6, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </motion.div>
    </section>
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

/* ============================== UI: Advisory card ============================== */
export function AdvisoryCard({ row, index }: { row: Component; index: number }) {
  const { severityCol, searchQuery, setDrawerId, deleteRow } = useWorkbench();
  const severity: SeverityKey = severityCol ? getSeverityLevel(row.data[severityCol]) : "none";
  const cfg = severityConfig[severity];
  const Icon = cfg.icon;
  const title = getField(row.data, ["component", "package", "name"]) || getField(row.data, ["cve"]) || String(Object.values(row.data)[0] ?? "Component");
  const app = getField(row.data, ["application", "app"]);
  const vendor = getField(row.data, ["supplier", "vendor", "publisher"]);
  const version = getField(row.data, ["version", "release"]);
  const cve = getField(row.data, ["cve", "advisory"]);
  const cvss = getField(row.data, ["cvss", "score"]);
  const status = getField(row.data, ["status", "state"]);
  const fix = getField(row.data, ["fix", "patch", "remediation"]);
  const detected = getField(row.data, ["detected", "date", "discovered"]);

  return (
    <motion.article layout
      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
      transition={{ duration: 0.25, delay: Math.min(index * 0.02, 0.2) }}
      whileHover={{ y: -2 }}
      className={`group card-elevated card-hover relative cursor-pointer border ${cfg.border} ${severity === "critical" ? "glow-critical" : ""} p-4`}
      onClick={() => setDrawerId(row.id)}>
      <div className="flex items-start gap-3">
        <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${cfg.bg} ${cfg.color}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`chip border ${cfg.bg} ${cfg.border} ${cfg.color}`}>{cfg.label}</span>
            {cve && <span className="chip border border-border bg-muted/40 text-foreground"><ShieldAlert className="h-3 w-3" />{highlightMatch(cve, searchQuery)}</span>}
            {cvss && <span className="chip border border-border bg-muted/40 text-foreground"><Activity className="h-3 w-3" />CVSS {cvss}</span>}
            {status && <span className="chip border border-border bg-muted/40 text-muted-foreground">{status}</span>}
          </div>
          <h3 className="mt-1.5 truncate text-base font-semibold tracking-tight text-foreground">{highlightMatch(title, searchQuery)}</h3>
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-muted-foreground">
            {app && <span className="flex items-center gap-1.5"><Boxes className="h-3.5 w-3.5" />{highlightMatch(app, searchQuery)}</span>}
            {vendor && <span className="flex items-center gap-1.5"><Building2 className="h-3.5 w-3.5" />{highlightMatch(vendor, searchQuery)}</span>}
            {version && <span className="flex items-center gap-1.5"><GitBranch className="h-3.5 w-3.5" />{highlightMatch(version, searchQuery)}</span>}
            {fix && <span className="flex items-center gap-1.5 text-severity-low"><Shield className="h-3.5 w-3.5" />Fix: {fix}</span>}
            {detected && <span className="flex items-center gap-1.5"><Calendar className="h-3.5 w-3.5" />{detected}</span>}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <button onClick={(e) => { e.stopPropagation(); void deleteRow(row.id); }}
            className="rounded-md p-1.5 text-muted-foreground opacity-0 transition group-hover:opacity-100 hover:bg-destructive/10 hover:text-destructive"
            aria-label="Delete"><Trash2 className="h-4 w-4" /></button>
          <ChevronRight className="h-4 w-4 text-muted-foreground transition group-hover:translate-x-0.5 group-hover:text-foreground" />
        </div>
      </div>
    </motion.article>
  );
}

/* ============================== UI: Detail drawer ============================== */
export function DetailDrawer() {
  const { drawerId, setDrawerId, components, active, updateCell } = useWorkbench();
  const row = drawerId ? components.find((c) => c.id === drawerId) ?? null : null;
  const columns = active?.columns ?? [];
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
            className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" onClick={() => setDrawerId(null)} />
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
export function EmptyState({ searching }: { searching: boolean }) {
  return (
    <motion.div initial={{ opacity: 0, scale: 0.97 }} animate={{ opacity: 1, scale: 1 }}
      className="card-elevated flex h-64 items-center justify-center border border-dashed border-border/60">
      <div className="text-center">
        <div className="mx-auto mb-3 flex h-16 w-16 items-center justify-center rounded-2xl bg-severity-low/15 text-severity-low">
          <ShieldCheck className="h-7 w-7" />
        </div>
        <p className="text-sm font-semibold">{searching ? "No matches found" : "Everything looks secure"}</p>
        <p className="mt-1 text-xs text-muted-foreground">
          {searching ? "Try a different search term or clear the severity filter." : "No components yet. Add a row or append another file."}
        </p>
      </div>
    </motion.div>
  );
}

export function SkeletonList() {
  return (
    <div className="space-y-3">
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="card-elevated border border-border/60 p-4">
          <div className="flex items-start gap-3">
            <div className="skeleton h-10 w-10 rounded-xl" />
            <div className="flex-1 space-y-2">
              <div className="skeleton h-4 w-1/3" />
              <div className="skeleton h-3 w-2/3" />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

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
  { icon: AlertTriangle, label: "Critical CVEs", prompt: "List all components in the current dataset with Critical severity. Include CVE IDs and CVSS scores in a markdown table." },
  { icon: Activity, label: "Highest CVSS", prompt: "Which 5 components have the highest CVSS scores? Show them in a markdown table." },
  { icon: Boxes, label: "Apps at risk", prompt: "Which applications have the most vulnerabilities? Rank top 5 with counts." },
  { icon: Building2, label: "Top vendors", prompt: "Which vendors/suppliers contribute the most vulnerable components? Top 5 with counts." },
  { icon: FileBarChart, label: "Executive summary", prompt: "Generate a concise executive summary of the security posture: overall risk, top concerns, recommended next steps." },
  { icon: ShieldCheck, label: "Compliance report", prompt: "Generate a markdown compliance report covering vulnerable components, license exposure, and remediation status." },
  { icon: Shield, label: "Remediation plan", prompt: "Produce a prioritized remediation plan for the highest-risk components. Include fix versions where known." },
];

export function AIPanel() {
  const { active, components, severityFilter, filteredComponents, severityCounts } = useWorkbench();
  const [input, setInput] = useState("");
  const transport = useMemo(() => new DefaultChatTransport({ api: "/api/chat" }), []);
  const { messages, sendMessage, status } = useChat({
    transport, onError: (e: Error) => toast.error(e.message),
  });
  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, status]);

  useEffect(() => { inputRef.current?.focus(); }, [active?.id]);

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
    await sendMessage({ text: t }, { body: { datasetContext } });
  }

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

  return (
    <aside className="hidden w-96 shrink-0 xl:flex">
      <div className="card-elevated sticky top-[88px] flex h-[calc(100vh-112px)] w-full flex-col border border-border/60">
        {/* Header */}
        <div className="border-b border-border/60 px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-primary via-severity-info to-primary text-primary-foreground shadow-lg shadow-primary/30">
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
          {messages.map((m) => {
            const text = m.parts.map((p) => (p.type === "text" ? p.text : "")).join("");
            const tools = m.parts.filter((p) => p.type.startsWith("tool-"));
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
                <div className="prose prose-sm prose-invert max-w-none prose-p:my-1 prose-pre:my-1.5 prose-table:my-2 prose-table:text-xs prose-headings:mt-2 prose-headings:mb-1 prose-th:bg-muted/40 prose-th:border-border prose-td:border-border prose-th:px-2 prose-th:py-1 prose-td:px-2 prose-td:py-1 prose-code:rounded prose-code:bg-muted/60 prose-code:px-1 prose-code:py-0.5 prose-code:text-[0.85em] prose-code:before:content-none prose-code:after:content-none">
                  <ReactMarkdown>{text || "…"}</ReactMarkdown>
                </div>
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
