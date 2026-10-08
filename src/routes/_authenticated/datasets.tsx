import { createFileRoute } from "@tanstack/react-router";
import { useWorkbench } from "@/lib/workbench-shared";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import { Database, Trash2, Upload, ArrowRight, Calendar, Pencil, Check, X, FileText, Download, Loader2, AlertTriangle, ShieldCheck } from "lucide-react";
import { motion } from "framer-motion";

export const Route = createFileRoute("/_authenticated/datasets")({
  head: () => ({
    meta: [
      { title: "SBOM Datasets — SBOM Workbench" },
      { name: "description", content: "Manage uploaded SBOM and VAPT files by application name, and download the findings of all files together." },
      { property: "og:title", content: "SBOM Datasets — SBOM Workbench" },
      { property: "og:description", content: "Manage enterprise SBOM datasets and security assessments." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: DatasetsPage,
});

const CONF_STYLE = {
  High: "border-severity-low/40 bg-severity-low/15 text-severity-low",
  Medium: "border-severity-medium/40 bg-severity-medium/15 text-severity-medium",
  Low: "border-severity-high/40 bg-severity-high/15 text-severity-high",
} as const;

function DatasetsPage() {
  const {
    datasets, activeId, setActiveId, deleteDataset, datasetRiskMap, fileInputRef,
    uploadHistory, renameDataset, exportCombined, combining, uploadProgress,
  } = useWorkbench();
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState("");

  // new uploads are included automatically; untick a file to leave it out of the combined download
  const selected = datasets.filter((d) => !excluded.has(d.id)).map((d) => d.id);
  const toggle = (id: string) =>
    setExcluded((prev) => { const n = new Set(prev); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const totalComponents = datasets.filter((d) => selected.includes(d.id)).reduce((n, d) => n + (datasetRiskMap[d.id]?.count ?? 0), 0);

  const identityOf = (id: string) => uploadHistory.find((u) => u.datasetId === id && u.action === "created");
  const startRename = (id: string, name: string) => { setEditing(id); setDraft(name); };
  const saveRename = async () => { if (editing) await renameDataset(editing, draft); setEditing(null); };

  return (
    <>
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated space-y-4 border border-border/60 p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold">Datasets</h2>
            <p className="text-xs text-muted-foreground">
              Every uploaded file is named after the application it belongs to — the original filename is always shown beside it.
            </p>
          </div>
          <Button onClick={() => fileInputRef.current?.click()} className="rounded-xl bg-gradient-to-r from-primary to-severity-info">
            <Upload className="mr-2 h-4 w-4" /> Upload files
          </Button>
        </div>

        {uploadProgress && (
          <div className="flex items-center gap-2 rounded-xl border border-primary/30 bg-primary/10 px-3 py-2 text-xs text-primary">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> Importing {uploadProgress.current} of {uploadProgress.total} — {uploadProgress.name}
          </div>
        )}

        {datasets.length > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border/60 bg-background/40 px-4 py-3">
            <div className="text-xs">
              <div className="font-semibold">Download findings of all files together</div>
              <div className="text-muted-foreground">
                {selected.length} of {datasets.length} file(s) selected · {totalComponents.toLocaleString()} components · one workbook with an overview, all findings, EOL &amp; EOS dates and a sheet per file
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              <Button size="sm" variant="ghost" className="h-8 rounded-lg text-[11px]"
                onClick={() => setExcluded(selected.length === datasets.length ? new Set(datasets.map((d) => d.id)) : new Set())}>
                {selected.length === datasets.length ? "Select none" : "Select all"}
              </Button>
              {(["xlsx", "csv", "json"] as const).map((f) => (
                <Button key={f} size="sm" variant={f === "xlsx" ? "default" : "outline"} className="h-8 rounded-lg text-[11px] uppercase"
                  disabled={combining || selected.length === 0} onClick={() => void exportCombined(selected, f)}>
                  {combining && f === "xlsx" ? <Loader2 className="mr-1 h-3 w-3 animate-spin" /> : <Download className="mr-1 h-3 w-3" />} {f}
                </Button>
              ))}
            </div>
          </div>
        )}
      </motion.div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {datasets.length === 0 && (
          <div className="card-elevated col-span-full flex h-48 items-center justify-center border border-dashed border-border/60 text-sm text-muted-foreground">
            No datasets yet. Upload one or more SBOM / VAPT files to begin.
          </div>
        )}
        {datasets.map((d) => {
          const info = datasetRiskMap[d.id] ?? { count: 0, risk: 0 };
          const band = info.risk >= 75 ? "text-severity-critical" : info.risk >= 50 ? "text-severity-high" : info.risk >= 25 ? "text-severity-medium" : "text-severity-low";
          const isActive = activeId === d.id;
          const identity = identityOf(d.id);
          const unidentified = d.name.startsWith("Unidentified");
          return (
            <motion.div key={d.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} whileHover={{ y: -2 }}
              className={`card-elevated card-hover border p-4 ${isActive ? "border-primary/40 ring-2 ring-primary/30" : "border-border/60"}`}>
              <div className="flex items-start justify-between gap-2">
                <div className="flex min-w-0 flex-1 items-start gap-2">
                  <input type="checkbox" checked={!excluded.has(d.id)} onChange={() => toggle(d.id)}
                    aria-label={`Include ${d.name} in the combined download`} className="mt-1 h-4 w-4 shrink-0 accent-primary" />
                  <div className="min-w-0 flex-1">
                    {editing === d.id ? (
                      <div className="flex items-center gap-1">
                        <input autoFocus value={draft} onChange={(e) => setDraft(e.target.value)}
                          onKeyDown={(e) => { if (e.key === "Enter") void saveRename(); if (e.key === "Escape") setEditing(null); }}
                          className="w-full rounded-md border border-primary/40 bg-background px-2 py-1 text-sm font-semibold outline-none" />
                        <button onClick={() => void saveRename()} aria-label="Save name" className="rounded p-1 text-severity-low hover:bg-accent"><Check className="h-4 w-4" /></button>
                        <button onClick={() => setEditing(null)} aria-label="Cancel" className="rounded p-1 text-muted-foreground hover:bg-accent"><X className="h-4 w-4" /></button>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5">
                        <Database className="h-4 w-4 shrink-0 text-primary" />
                        <h3 className="truncate font-semibold" title={d.name}>{d.name}</h3>
                        <button onClick={() => startRename(d.id, d.name)} aria-label="Rename application"
                          className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"><Pencil className="h-3 w-3" /></button>
                      </div>
                    )}
                    <p className="mt-1 flex items-center gap-1 truncate text-[11px] text-muted-foreground" title={d.source_filename ?? ""}>
                      <FileText className="h-3 w-3 shrink-0" /> {d.source_filename ?? "—"}
                    </p>
                    {identity?.appConfidence && (
                      <span className={`chip mt-1.5 border text-[10px] ${CONF_STYLE[identity.appConfidence]}`} title={identity.appReason}>
                        {identity.appConfidence === "Low" ? <AlertTriangle className="h-3 w-3" /> : <ShieldCheck className="h-3 w-3" />}
                        Name match: {identity.appConfidence}
                      </span>
                    )}
                    {unidentified && <p className="mt-1 text-[11px] text-severity-high">Application not found in the file — rename it so findings stay attributable.</p>}
                  </div>
                </div>
                <button onClick={() => void deleteDataset(d.id)} aria-label="Delete dataset" className="rounded p-1.5 text-muted-foreground hover:bg-destructive/10 hover:text-destructive">
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
              <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
                <div className="rounded-lg bg-background/40 p-2"><div className="text-[10px] text-muted-foreground">Components</div><div className="font-mono font-bold">{info.count}</div></div>
                <div className="rounded-lg bg-background/40 p-2"><div className="text-[10px] text-muted-foreground">Risk Score</div><div className={`font-mono font-bold ${band}`}>{info.risk}</div></div>
              </div>
              <div className="mt-3 flex items-center justify-between text-[11px] text-muted-foreground">
                <span className="flex items-center gap-1"><Calendar className="h-3 w-3" /> {new Date(d.created_at).toLocaleDateString()}</span>
                <Button size="sm" variant={isActive ? "default" : "outline"} onClick={() => setActiveId(d.id)} className="h-7 rounded-lg text-xs">
                  {isActive ? "Active" : "Open"} <ArrowRight className="ml-1 h-3 w-3" />
                </Button>
              </div>
            </motion.div>
          );
        })}
      </div>
    </>
  );
}
