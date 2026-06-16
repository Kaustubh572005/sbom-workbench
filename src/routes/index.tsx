import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import * as XLSX from "xlsx";
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import ReactMarkdown from "react-markdown";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import {
  Upload,
  Database,
  Trash2,
  Plus,
  Send,
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  FileSpreadsheet,
  Loader2,
  Search,
  AlertTriangle,
  AlertCircle,
  CheckCircle2,
  Info,
  X,
  ChevronDown,
  ChevronUp,
  Package,
  TrendingUp,
  Activity,
  Bug,
} from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "SBOM & VAPT Workbench" },
      {
        name: "description",
        content:
          "Upload SBOM/VAPT Excel sheets, edit components inline, and chat with an AI security analyst.",
      },
    ],
  }),
  component: Workbench,
});

type Dataset = {
  id: string;
  name: string;
  source_filename: string | null;
  columns: string[];
  created_at: string;
};

type Component = {
  id: string;
  dataset_id: string;
  data: Record<string, unknown>;
  content_hash: string;
};

async function hashString(s: string): Promise<string> {
  const buf = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const SEVERITY_KEYS = [
  "severity",
  "risk",
  "level",
  "criticality",
  "priority",
  "impact",
  "cvss",
  "score",
];

function detectSeverityColumn(columns: string[]): string | null {
  const lowerCols = columns.map((c) => c.toLowerCase());
  for (const key of SEVERITY_KEYS) {
    const idx = lowerCols.findIndex((c) => c.includes(key));
    if (idx >= 0) return columns[idx];
  }
  return null;
}

type SeverityKey = "critical" | "high" | "medium" | "low" | "info" | "none";

function getSeverityLevel(value: unknown): SeverityKey {
  const s = String(value).toLowerCase().trim();
  if (s.includes("critical") || s.includes("severe") || s.includes("danger")) return "critical";
  if (s.includes("high") || s.includes("major") || s.includes("important")) return "high";
  if (s.includes("medium") || s.includes("moderate") || s.includes("warning")) return "medium";
  if (s.includes("low") || s.includes("minor") || s.includes("trivial")) return "low";
  if (s.includes("info") || s.includes("informational") || s.includes("note")) return "info";
  if (!isNaN(Number(s))) {
    const n = Number(s);
    if (n >= 9) return "critical";
    if (n >= 7) return "high";
    if (n >= 4) return "medium";
    if (n > 0) return "low";
  }
  return "none";
}

const severityConfig: Record<
  SeverityKey,
  { color: string; bg: string; dot: string; icon: typeof AlertTriangle; label: string; emoji: string }
> = {
  critical: { color: "text-severity-critical", bg: "bg-severity-critical-bg/40 border-severity-critical/50", dot: "bg-severity-critical", icon: AlertTriangle, label: "Critical", emoji: "🟥" },
  high: { color: "text-severity-high", bg: "bg-severity-high-bg/30 border-severity-high/40", dot: "bg-severity-high", icon: AlertTriangle, label: "High", emoji: "🟥" },
  medium: { color: "text-severity-medium", bg: "bg-severity-medium-bg/30 border-severity-medium/40", dot: "bg-severity-medium", icon: AlertCircle, label: "Medium", emoji: "🟨" },
  low: { color: "text-severity-low", bg: "bg-severity-low-bg/25 border-severity-low/40", dot: "bg-severity-low", icon: CheckCircle2, label: "Low", emoji: "🟩" },
  info: { color: "text-severity-info", bg: "bg-severity-info-bg/25 border-severity-info/40", dot: "bg-severity-info", icon: Info, label: "Info", emoji: "🟦" },
  none: { color: "text-muted-foreground", bg: "bg-card border-border", dot: "bg-muted-foreground", icon: Info, label: "Unrated", emoji: "⬜" },
};

function useAnimatedCount(target: number, durationMs = 700) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let raf = 0;
    const start = performance.now();
    const from = 0;
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / durationMs);
      const eased = 1 - Math.pow(1 - p, 3);
      setVal(Math.round(from + (target - from) * eased));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, durationMs]);
  return val;
}

function Workbench() {
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityKey | "all">("all");
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const active = datasets.find((d) => d.id === activeId) ?? null;
  const severityCol = active ? detectSeverityColumn(active.columns) : null;

  const severityCounts = useMemo(() => {
    const counts: Record<SeverityKey, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, none: 0 };
    if (!severityCol) return counts;
    for (const c of components) {
      counts[getSeverityLevel(c.data[severityCol])]++;
    }
    return counts;
  }, [components, severityCol]);

  const riskScore = useMemo(() => {
    const total = components.length || 1;
    const weighted =
      severityCounts.critical * 10 +
      severityCounts.high * 7 +
      severityCounts.medium * 4 +
      severityCounts.low * 1;
    return Math.min(100, Math.round((weighted / (total * 10)) * 100));
  }, [components.length, severityCounts]);

  const riskBand =
    riskScore >= 75 ? { label: "CRITICAL", color: "text-severity-critical" } :
    riskScore >= 50 ? { label: "HIGH", color: "text-severity-high" } :
    riskScore >= 25 ? { label: "MEDIUM", color: "text-severity-medium" } :
    { label: "LOW", color: "text-severity-low" };

  const filteredComponents = useMemo(() => {
    let list = components;
    if (severityFilter !== "all" && severityCol) {
      list = list.filter((c) => getSeverityLevel(c.data[severityCol]) === severityFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((c) =>
        Object.values(c.data).some((v) => String(v).toLowerCase().includes(q)),
      );
    }
    return list;
  }, [components, searchQuery, severityFilter, severityCol]);

  // Load datasets
  useEffect(() => {
    void (async () => {
      const { data, error } = await supabase
        .from("datasets")
        .select("*")
        .order("created_at", { ascending: false });
      if (error) return toast.error(error.message);
      const list = (data ?? []) as unknown as Dataset[];
      setDatasets(list);
      if (!activeId && list.length) setActiveId(list[0].id);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!activeId) {
      setComponents([]);
      return;
    }
    setLoading(true);
    void (async () => {
      const { data, error } = await supabase
        .from("components")
        .select("*")
        .eq("dataset_id", activeId)
        .order("created_at", { ascending: true });
      if (error) toast.error(error.message);
      setComponents(((data ?? []) as unknown) as Component[]);
      setLoading(false);
    })();
  }, [activeId]);

  async function handleFile(file: File, targetDatasetId: string | null) {
    setUploading(true);
    try {
      const buf = await file.arrayBuffer();
      const wb = XLSX.read(buf, { type: "array" });
      const sheet = wb.Sheets[wb.SheetNames[0]];
      const rows = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, { defval: "" });
      if (!rows.length) {
        toast.error("No rows found in sheet");
        return;
      }
      const sheetCols = Array.from(
        rows.reduce((acc, r) => {
          Object.keys(r).forEach((k) => acc.add(k));
          return acc;
        }, new Set<string>()),
      );

      let datasetId = targetDatasetId;
      let mergedCols = sheetCols;

      if (!datasetId) {
        const { data, error } = await supabase
          .from("datasets")
          .insert({
            name: file.name.replace(/\.[^.]+$/, ""),
            source_filename: file.name,
            columns: sheetCols,
          })
          .select()
          .single();
        if (error) throw error;
        datasetId = (data as { id: string }).id;
      } else {
        const ds = datasets.find((d) => d.id === datasetId);
        mergedCols = Array.from(new Set([...(ds?.columns ?? []), ...sheetCols]));
        await supabase.from("datasets").update({ columns: mergedCols }).eq("id", datasetId);
      }

      const toInsert = await Promise.all(
        rows.map(async (r) => ({
          dataset_id: datasetId!,
          data: r as never,
          content_hash: await hashString(JSON.stringify(r)),
        })),
      );

      const { error: insErr } = await supabase
        .from("components")
        .upsert(toInsert, { onConflict: "dataset_id,content_hash", ignoreDuplicates: true });
      if (insErr) throw insErr;

      const [{ data: dsAll }, { data: comp }] = await Promise.all([
        supabase.from("datasets").select("*").order("created_at", { ascending: false }),
        supabase.from("components").select("*").eq("dataset_id", datasetId!).order("created_at"),
      ]);
      setDatasets(((dsAll ?? []) as unknown) as Dataset[]);
      setComponents(((comp ?? []) as unknown) as Component[]);
      setActiveId(datasetId);
      toast.success(`Imported ${rows.length} rows into "${file.name}"`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  async function updateCell(rowId: string, col: string, value: string) {
    const row = components.find((c) => c.id === rowId);
    if (!row) return;
    const newData = { ...row.data, [col]: value };
    setComponents((cs) => cs.map((c) => (c.id === rowId ? { ...c, data: newData } : c)));
    const { error } = await supabase
      .from("components")
      .update({ data: newData as never })
      .eq("id", rowId);
    if (error) toast.error(error.message);
  }

  async function addRow() {
    if (!active) return;
    const blank = Object.fromEntries(active.columns.map((c) => [c, ""]));
    const hash = await hashString(JSON.stringify(blank) + Date.now());
    const { data, error } = await supabase
      .from("components")
      .insert({ dataset_id: active.id, data: blank as never, content_hash: hash })
      .select()
      .single();
    if (error) return toast.error(error.message);
    setComponents((cs) => [...cs, data as unknown as Component]);
  }

  async function deleteRow(id: string) {
    setComponents((cs) => cs.filter((c) => c.id !== id));
    const { error } = await supabase.from("components").delete().eq("id", id);
    if (error) toast.error(error.message);
  }

  async function deleteDataset(id: string) {
    if (!confirm("Delete this dataset and all its components?")) return;
    const { error } = await supabase.from("datasets").delete().eq("id", id);
    if (error) return toast.error(error.message);
    const remaining = datasets.filter((d) => d.id !== id);
    setDatasets(remaining);
    if (activeId === id) setActiveId(remaining[0]?.id ?? null);
    toast.success("Dataset deleted");
  }

  const greeting = (() => {
    const h = new Date().getHours();
    if (h < 12) return "Good morning";
    if (h < 18) return "Good afternoon";
    return "Good evening";
  })();

  return (
    <div className="min-h-screen text-foreground">
      <header className="border-b border-border/60 bg-card/40 backdrop-blur-xl sticky top-0 z-20">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between px-8 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-primary to-severity-info text-primary-foreground shadow-lg shadow-primary/30">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-base font-semibold leading-tight tracking-tight">
                {greeting} 👋
              </h1>
              <p className="text-xs text-muted-foreground">
                SBOM / VAPT Workbench · {datasets.length} dataset{datasets.length === 1 ? "" : "s"}
              </p>
            </div>
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept=".xlsx,.xls,.csv"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handleFile(f, null);
            }}
          />
          <Button
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading}
            className="rounded-xl shadow-lg shadow-primary/25"
          >
            {uploading ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Upload className="mr-2 h-4 w-4" />
            )}
            New dataset
          </Button>
        </div>
      </header>

      <div className="mx-auto flex max-w-[1600px] gap-6 px-8 py-8">
        {/* Sidebar */}
        <aside className="w-60 shrink-0 space-y-6">
          <nav className="space-y-1">
            {[
              { icon: Activity, label: "Dashboard", active: true },
              { icon: Package, label: "Components" },
              { icon: ShieldAlert, label: "Vulnerabilities" },
              { icon: FileSpreadsheet, label: "SBOM" },
            ].map((it) => (
              <button
                key={it.label}
                className={`relative flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition ${
                  it.active
                    ? "bg-primary/15 text-foreground"
                    : "text-muted-foreground hover:bg-accent/40 hover:text-foreground"
                }`}
              >
                {it.active && (
                  <span className="absolute left-0 top-1/2 h-5 w-1 -translate-y-1/2 rounded-r bg-primary" />
                )}
                <it.icon className="h-4 w-4" />
                {it.label}
              </button>
            ))}
          </nav>

          <div>
            <div className="mb-2 flex items-center justify-between px-2">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                Datasets
              </span>
              <span className="text-[10px] text-muted-foreground">{datasets.length}</span>
            </div>
            <div className="space-y-1">
              {datasets.length === 0 && (
                <div className="rounded-xl border border-dashed border-border/60 p-4 text-center text-xs text-muted-foreground">
                  No datasets yet.
                </div>
              )}
              {datasets.map((d) => (
                <div
                  key={d.id}
                  className={`group flex items-center gap-2 rounded-xl border px-2.5 py-2 text-sm transition ${
                    activeId === d.id
                      ? "border-primary/40 bg-primary/10 shadow-sm"
                      : "border-transparent hover:bg-accent/40"
                  }`}
                >
                  <button
                    onClick={() => setActiveId(d.id)}
                    className="flex flex-1 items-center gap-2 truncate text-left"
                  >
                    <Database className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                    <span className="truncate">{d.name}</span>
                  </button>
                  <button
                    onClick={() => deleteDataset(d.id)}
                    className="text-muted-foreground opacity-0 transition group-hover:opacity-100 hover:text-destructive"
                    aria-label="Delete dataset"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </aside>

        {/* Main */}
        <main className="min-w-0 flex-1 space-y-8">
          {active ? (
            <>
              {/* KPI row */}
              <section className="grid grid-cols-2 gap-6 lg:grid-cols-5">
                <KpiCard
                  icon={Package}
                  label="Components"
                  value={components.length}
                  delta="+12%"
                  tone="info"
                />
                <KpiCard
                  icon={AlertTriangle}
                  label="Critical"
                  value={severityCounts.critical}
                  delta={severityCounts.critical > 0 ? "needs action" : "all clear"}
                  tone="critical"
                />
                <KpiCard
                  icon={AlertTriangle}
                  label="High"
                  value={severityCounts.high}
                  delta="↑ 4%"
                  tone="high"
                />
                <KpiCard
                  icon={AlertCircle}
                  label="Medium"
                  value={severityCounts.medium}
                  delta="↓ 2%"
                  tone="medium"
                />
                <KpiCard
                  icon={CheckCircle2}
                  label="Low / Info"
                  value={severityCounts.low + severityCounts.info}
                  delta="stable"
                  tone="low"
                />
              </section>

              {/* Risk meter + dataset header */}
              <section className="grid gap-6 lg:grid-cols-[2fr_1fr]">
                <div className="card-elevated border border-border/60 bg-card p-6">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <h2 className="flex items-center gap-2 text-lg font-semibold">
                        <FileSpreadsheet className="h-4 w-4 text-primary" />
                        <span className="truncate">{active.name}</span>
                      </h2>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {filteredComponents.length} of {components.length} components ·{" "}
                        {active.columns.length} columns
                      </p>
                    </div>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" onClick={addRow} className="rounded-lg">
                        <Plus className="mr-1 h-3.5 w-3.5" /> Row
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="rounded-lg"
                        onClick={() => {
                          const i = document.createElement("input");
                          i.type = "file";
                          i.accept = ".xlsx,.xls,.csv";
                          i.onchange = () => {
                            const f = i.files?.[0];
                            if (f) void handleFile(f, active.id);
                          };
                          i.click();
                        }}
                        disabled={uploading}
                      >
                        <Upload className="mr-1 h-3.5 w-3.5" /> Append
                      </Button>
                    </div>
                  </div>

                  {/* Severity bar (stacked) */}
                  <div className="mt-6">
                    <div className="mb-2 flex items-center justify-between text-[11px] uppercase tracking-wider text-muted-foreground">
                      <span>Severity distribution</span>
                      <span>{components.length} total</span>
                    </div>
                    <SeverityBar counts={severityCounts} total={components.length} />
                    <div className="mt-3 flex flex-wrap gap-2 text-xs">
                      {(["critical", "high", "medium", "low", "info"] as SeverityKey[]).map((k) => (
                        <button
                          key={k}
                          onClick={() => setSeverityFilter(severityFilter === k ? "all" : k)}
                          className={`chip border transition ${severityConfig[k].bg} ${severityConfig[k].color} ${
                            severityFilter === k ? "ring-2 ring-offset-2 ring-offset-background ring-current" : ""
                          }`}
                        >
                          <span className={`h-1.5 w-1.5 rounded-full ${severityConfig[k].dot}`} />
                          {severityConfig[k].label} · {severityCounts[k]}
                        </button>
                      ))}
                      {severityFilter !== "all" && (
                        <button
                          onClick={() => setSeverityFilter("all")}
                          className="chip border border-border text-muted-foreground hover:text-foreground"
                        >
                          <X className="h-3 w-3" /> Clear filter
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                <RiskMeter score={riskScore} band={riskBand} />
              </section>

              {/* Search */}
              <div className="relative">
                <Search className="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="🔍  Search CVE, package, vendor, version…"
                  className="h-12 rounded-2xl border-border/60 bg-card pl-11 text-sm shadow-sm"
                />
                {searchQuery && (
                  <button
                    onClick={() => setSearchQuery("")}
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    <X className="h-4 w-4" />
                  </button>
                )}
              </div>

              {/* Component list */}
              <div className="space-y-4">
                {loading ? (
                  <div className="p-12 text-center text-sm text-muted-foreground">
                    <Loader2 className="mx-auto mb-2 h-5 w-5 animate-spin" />
                    Loading components...
                  </div>
                ) : filteredComponents.length === 0 ? (
                  <EmptyState searching={!!searchQuery || severityFilter !== "all"} />
                ) : (
                  filteredComponents.map((row) => {
                    const severity = severityCol
                      ? getSeverityLevel(row.data[severityCol])
                      : "none";
                    const config = severityConfig[severity];
                    const Icon = config.icon;
                    const isExpanded = expandedRow === row.id;
                    const title =
                      String(
                        row.data["component"] ??
                          row.data["Component"] ??
                          row.data["name"] ??
                          row.data["Name"] ??
                          row.data["package"] ??
                          row.data["Package"] ??
                          row.data["cve"] ??
                          row.data["CVE"] ??
                          Object.values(row.data)[0] ??
                          "Component",
                      );

                    return (
                      <article
                        key={row.id}
                        className={`card-elevated border bg-card p-5 ${config.bg} ${
                          severity === "critical" ? "glow-critical" : ""
                        }`}
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className={`chip border ${config.bg} ${config.color}`}>
                                <Icon className="h-3 w-3" />
                                {config.label}
                              </span>
                              <h3 className="truncate text-base font-semibold tracking-tight text-foreground">
                                {title}
                              </h3>
                              <button
                                onClick={() => setExpandedRow(isExpanded ? null : row.id)}
                                className="ml-auto rounded-md p-1 text-muted-foreground transition hover:bg-accent/50 hover:text-foreground"
                              >
                                {isExpanded ? (
                                  <ChevronUp className="h-4 w-4" />
                                ) : (
                                  <ChevronDown className="h-4 w-4" />
                                )}
                              </button>
                            </div>
                            <div className="mt-4 grid gap-2.5">
                              {active.columns
                                .slice(0, isExpanded ? undefined : 4)
                                .map((col) => (
                                  <div
                                    key={col}
                                    className="grid grid-cols-[minmax(7rem,9rem)_1fr] items-center gap-3 text-sm"
                                  >
                                    <span className="truncate text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                                      {col}
                                    </span>
                                    <input
                                      value={String(row.data[col] ?? "")}
                                      onChange={(e) => updateCell(row.id, col, e.target.value)}
                                      className="min-w-0 rounded-lg border border-border bg-background/70 px-3 py-1.5 font-medium text-foreground shadow-sm outline-none transition focus:border-primary focus:bg-background focus:ring-2 focus:ring-primary/30 placeholder:text-muted-foreground"
                                      placeholder="—"
                                    />
                                  </div>
                                ))}
                              {!isExpanded && active.columns.length > 4 && (
                                <button
                                  onClick={() => setExpandedRow(row.id)}
                                  className="mt-1 text-left text-xs font-semibold text-primary transition hover:underline"
                                >
                                  + {active.columns.length - 4} more fields
                                </button>
                              )}
                            </div>
                          </div>
                          <button
                            onClick={() => deleteRow(row.id)}
                            className="shrink-0 rounded-md p-1.5 text-muted-foreground transition hover:bg-destructive/10 hover:text-destructive"
                            aria-label="Delete row"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </article>
                    );
                  })
                )}
              </div>
            </>
          ) : (
            <div className="card-elevated flex h-96 items-center justify-center border border-dashed border-border/60 bg-card/50">
              <div className="text-center">
                <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-primary/10 text-primary">
                  <Upload className="h-7 w-7" />
                </div>
                <p className="text-base font-semibold">No dataset selected</p>
                <p className="mt-1 text-sm text-muted-foreground">
                  Click "New dataset" to upload your first SBOM / VAPT sheet.
                </p>
              </div>
            </div>
          )}
        </main>

        <ChatPanel
          dataset={
            active
              ? {
                  name: active.name,
                  columns: active.columns,
                  rows: components.map((c) => c.data),
                }
              : null
          }
        />
      </div>
    </div>
  );
}

function KpiCard({
  icon: Icon,
  label,
  value,
  delta,
  tone,
}: {
  icon: typeof Package;
  label: string;
  value: number;
  delta: string;
  tone: "info" | "critical" | "high" | "medium" | "low";
}) {
  const animated = useAnimatedCount(value);
  const toneClass = {
    info: "text-severity-info",
    critical: "text-severity-critical",
    high: "text-severity-high",
    medium: "text-severity-medium",
    low: "text-severity-low",
  }[tone];
  const glow = tone === "critical" && value > 0 ? "glow-critical" : "";
  return (
    <div className={`card-elevated border border-border/60 bg-card p-5 ${glow}`}>
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          {label}
        </span>
        <Icon className={`h-4 w-4 ${toneClass}`} />
      </div>
      <div className={`mt-3 text-3xl font-bold tracking-tight ${toneClass}`}
        style={{ animation: "count-pop 0.4s ease-out" }}
      >
        {animated}
      </div>
      <div className="mt-2 flex items-center gap-1 text-[11px] text-muted-foreground">
        <TrendingUp className="h-3 w-3" />
        {delta}
      </div>
    </div>
  );
}

function SeverityBar({
  counts,
  total,
}: {
  counts: Record<SeverityKey, number>;
  total: number;
}) {
  if (total === 0) {
    return (
      <div className="h-2.5 w-full rounded-full bg-muted/40" />
    );
  }
  const segs: { key: SeverityKey; cls: string }[] = [
    { key: "critical", cls: "bg-severity-critical" },
    { key: "high", cls: "bg-severity-high" },
    { key: "medium", cls: "bg-severity-medium" },
    { key: "low", cls: "bg-severity-low" },
    { key: "info", cls: "bg-severity-info" },
    { key: "none", cls: "bg-muted-foreground/40" },
  ];
  return (
    <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-muted/40">
      {segs.map((s) => {
        const pct = (counts[s.key] / total) * 100;
        if (pct === 0) return null;
        return (
          <div
            key={s.key}
            className={`${s.cls} transition-all`}
            style={{ width: `${pct}%` }}
            title={`${s.key}: ${counts[s.key]}`}
          />
        );
      })}
    </div>
  );
}

function RiskMeter({
  score,
  band,
}: {
  score: number;
  band: { label: string; color: string };
}) {
  const animated = useAnimatedCount(score);
  // SVG gauge — half donut
  const radius = 70;
  const circ = Math.PI * radius;
  const offset = circ - (animated / 100) * circ;
  return (
    <div className="card-elevated border border-border/60 bg-card p-6">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          Overall Risk
        </span>
        <Bug className="h-4 w-4 text-muted-foreground" />
      </div>
      <div className="relative mt-2 flex items-end justify-center">
        <svg viewBox="0 0 200 120" className="w-full max-w-[240px]">
          <defs>
            <linearGradient id="riskGrad" x1="0%" x2="100%">
              <stop offset="0%" stopColor="var(--color-severity-low)" />
              <stop offset="50%" stopColor="var(--color-severity-medium)" />
              <stop offset="100%" stopColor="var(--color-severity-critical)" />
            </linearGradient>
          </defs>
          <path
            d={`M 30 100 A ${radius} ${radius} 0 0 1 170 100`}
            fill="none"
            stroke="var(--color-muted)"
            strokeWidth="14"
            strokeLinecap="round"
          />
          <path
            d={`M 30 100 A ${radius} ${radius} 0 0 1 170 100`}
            fill="none"
            stroke="url(#riskGrad)"
            strokeWidth="14"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 0.6s ease" }}
          />
        </svg>
        <div className="absolute bottom-2 flex flex-col items-center">
          <div className="text-4xl font-bold tracking-tight">{animated}</div>
          <div className="text-[10px] text-muted-foreground">/ 100</div>
        </div>
      </div>
      <div className={`mt-3 text-center text-sm font-bold tracking-wider ${band.color}`}>
        {band.label}
      </div>
    </div>
  );
}

function EmptyState({ searching }: { searching: boolean }) {
  return (
    <div className="card-elevated flex h-64 items-center justify-center border border-dashed border-border/60 bg-card/40">
      <div className="text-center">
        <div className="mx-auto mb-3 flex h-14 w-14 items-center justify-center rounded-2xl bg-severity-low-bg/40 text-severity-low">
          <ShieldCheck className="h-6 w-6" />
        </div>
        <p className="text-sm font-semibold">
          {searching ? "No matches found" : "Everything looks secure!"}
        </p>
        <p className="mt-1 text-xs text-muted-foreground">
          {searching
            ? "Try a different search term or clear the severity filter."
            : "No components yet. Add a row or append another file."}
        </p>
      </div>
    </div>
  );
}

function ChatPanel({
  dataset,
}: {
  dataset: { name: string; columns: string[]; rows: Record<string, unknown>[] } | null;
}) {
  const [input, setInput] = useState("");
  const transport = useMemo(() => new DefaultChatTransport({ api: "/api/chat" }), []);
  const { messages, sendMessage, status } = useChat({
    transport,
    onError: (e: Error) => toast.error(e.message),
  });
  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, status]);

  useEffect(() => {
    inputRef.current?.focus();
  }, [status]);

  const busy = status === "submitted" || status === "streaming";

  async function submit() {
    const text = input.trim();
    if (!text || busy) return;
    setInput("");
    await sendMessage({ text }, { body: { datasetContext: dataset } });
  }

  return (
    <aside className="card-elevated flex w-96 shrink-0 flex-col border border-border/60 bg-card">
      <div className="flex items-center gap-2 border-b border-border/60 px-4 py-3">
        <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-severity-info text-primary-foreground">
          <Sparkles className="h-3.5 w-3.5" />
        </div>
        <span className="text-sm font-semibold">Security Analyst</span>
        <span className={`chip ml-auto border ${dataset ? "border-severity-low/40 bg-severity-low-bg/30 text-severity-low" : "border-border text-muted-foreground"}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${dataset ? "bg-severity-low" : "bg-muted-foreground"}`} />
          {dataset ? "context" : "no ctx"}
        </span>
      </div>

      <div
        ref={scrollRef}
        className="flex-1 space-y-3 overflow-y-auto p-4"
        style={{ maxHeight: "calc(100vh - 220px)" }}
      >
        {messages.length === 0 && (
          <div className="rounded-xl border border-dashed border-border/60 p-3 text-xs text-muted-foreground">
            Ask about components, CVEs, severities, or remediations. Try: "Which components have
            known critical vulnerabilities?"
          </div>
        )}
        {messages.map((m: (typeof messages)[number]) => {
          const text = m.parts.map((p) => (p.type === "text" ? p.text : "")).join("");
          const tools = m.parts.filter((p) => p.type.startsWith("tool-"));
          return (
            <div
              key={m.id}
              className={`rounded-2xl px-3.5 py-2.5 text-sm ${
                m.role === "user"
                  ? "ml-6 bg-primary text-primary-foreground shadow-md shadow-primary/20"
                  : "mr-6 bg-muted/60 backdrop-blur"
              }`}
            >
              {tools.length > 0 && (
                <div className="mb-1 text-[10px] uppercase tracking-wider opacity-70">
                  🔍 Looking up vulnerability data...
                </div>
              )}
              <div className="prose prose-sm max-w-none dark:prose-invert prose-p:my-1 prose-pre:my-1 prose-table:my-1">
                <ReactMarkdown>{text || "..."}</ReactMarkdown>
              </div>
            </div>
          );
        })}
        {status === "submitted" && (
          <div className="mr-6 rounded-2xl bg-muted/60 px-3.5 py-2.5 text-sm text-muted-foreground">
            <Loader2 className="inline h-3 w-3 animate-spin" /> thinking...
          </div>
        )}
      </div>

      <div className="border-t border-border/60 p-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
          className="flex gap-2"
        >
          <Input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={dataset ? `Ask about ${dataset.name}...` : "Ask anything..."}
            disabled={busy}
            autoFocus
            className="rounded-xl"
          />
          <Button
            type="submit"
            size="icon"
            disabled={busy || !input.trim()}
            className="rounded-xl"
          >
            <Send className="h-4 w-4" />
          </Button>
        </form>
      </div>
    </aside>
  );
}
