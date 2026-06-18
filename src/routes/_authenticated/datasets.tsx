import { createFileRoute } from "@tanstack/react-router";
import { useWorkbench } from "@/lib/workbench-shared";
import { Button } from "@/components/ui/button";
import { Database, Trash2, Upload, ArrowRight, Calendar } from "lucide-react";
import { motion } from "framer-motion";

export const Route = createFileRoute("/_authenticated/datasets")({
  head: () => ({ meta: [{ title: "Datasets — SBOM Workbench" }] }),
  component: DatasetsPage,
});

function DatasetsPage() {
  const { datasets, activeId, setActiveId, deleteDataset, datasetRiskMap, fileInputRef } = useWorkbench();

  return (
    <>
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated flex flex-wrap items-center justify-between gap-3 border border-border/60 p-6">
        <div>
          <h2 className="text-lg font-semibold">Datasets</h2>
          <p className="text-xs text-muted-foreground">Manage your uploaded SBOM and VAPT collections.</p>
        </div>
        <Button onClick={() => fileInputRef.current?.click()} className="rounded-xl bg-gradient-to-r from-primary to-severity-info">
          <Upload className="mr-2 h-4 w-4" /> Upload new
        </Button>
      </motion.div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {datasets.length === 0 && (
          <div className="card-elevated col-span-full flex h-48 items-center justify-center border border-dashed border-border/60 text-sm text-muted-foreground">
            No datasets yet. Upload an Excel/CSV to begin.
          </div>
        )}
        {datasets.map((d) => {
          const info = datasetRiskMap[d.id] ?? { count: 0, risk: 0 };
          const band = info.risk >= 75 ? "text-severity-critical" : info.risk >= 50 ? "text-severity-high" : info.risk >= 25 ? "text-severity-medium" : "text-severity-low";
          const isActive = activeId === d.id;
          return (
            <motion.div key={d.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} whileHover={{ y: -2 }}
              className={`card-elevated card-hover border p-4 ${isActive ? "border-primary/40 ring-2 ring-primary/30" : "border-border/60"}`}>
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2">
                  <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary/15 text-primary">
                    <Database className="h-4 w-4" />
                  </div>
                  <div>
                    <h3 className="font-semibold">{d.name}</h3>
                    <p className="text-[11px] text-muted-foreground">{d.source_filename}</p>
                  </div>
                </div>
                <button onClick={() => void deleteDataset(d.id)} className="rounded p-1.5 text-muted-foreground hover:bg-destructive/10 hover:text-destructive">
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
