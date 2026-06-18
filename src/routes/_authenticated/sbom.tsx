import { createFileRoute } from "@tanstack/react-router";
import { useWorkbench, SearchBar, NoDataset } from "@/lib/workbench-shared";
import { Button } from "@/components/ui/button";
import { Plus, Upload, Download, Trash2 } from "lucide-react";
import { motion } from "framer-motion";

export const Route = createFileRoute("/_authenticated/sbom")({
  head: () => ({ meta: [{ title: "SBOM — SBOM Workbench" }] }),
  component: SbomPage,
});

function SbomPage() {
  const { active, filteredComponents, addRow, deleteRow, uploading, handleFile, downloadExcel, updateCell } = useWorkbench();
  if (!active) return <NoDataset />;

  return (
    <>
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated border border-border/60 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold">{active.name}</h2>
            <p className="text-xs text-muted-foreground">
              {filteredComponents.length} rows · {active.columns.length} columns · uploaded format preserved
            </p>
          </div>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={() => void addRow()} className="rounded-xl"><Plus className="mr-1 h-3.5 w-3.5" /> Row</Button>
            <Button size="sm" variant="outline" disabled={uploading} className="rounded-xl"
              onClick={() => {
                const i = document.createElement("input"); i.type = "file"; i.accept = ".xlsx,.xls,.csv";
                i.onchange = () => { const f = i.files?.[0]; if (f) void handleFile(f, active.id); }; i.click();
              }}><Upload className="mr-1 h-3.5 w-3.5" /> Append</Button>
            <Button size="sm" onClick={() => void downloadExcel()} className="rounded-xl bg-gradient-to-r from-primary to-severity-info"><Download className="mr-1 h-3.5 w-3.5" /> Export</Button>
          </div>
        </div>
      </motion.div>

      <SearchBar />

      <div className="card-elevated overflow-hidden border border-border/60">
        <div className="max-h-[70vh] overflow-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
              <tr className="border-b border-border">
                {active.columns.map((c) => (
                  <th key={c} className="whitespace-nowrap px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{c}</th>
                ))}
                <th className="w-10"></th>
              </tr>
            </thead>
            <tbody>
              {filteredComponents.map((row) => (
                <tr key={row.id} className="border-b border-border/40 hover:bg-accent/20">
                  {active.columns.map((col) => (
                    <td key={col} className="px-3 py-1.5">
                      <input value={String(row.data[col] ?? "")} onChange={(e) => void updateCell(row.id, col, e.target.value)}
                        className="w-full min-w-[120px] rounded border-0 bg-transparent px-1.5 py-1 text-xs text-foreground outline-none focus:bg-background focus:ring-1 focus:ring-primary/40" />
                    </td>
                  ))}
                  <td className="px-2">
                    <button onClick={() => void deleteRow(row.id)} className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive">
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
