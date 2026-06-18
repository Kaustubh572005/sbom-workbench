import { createFileRoute } from "@tanstack/react-router";
import { AnimatePresence } from "framer-motion";
import {
  useWorkbench, KpiRow, ActiveFilterChip, EnterpriseRiskCard, AnimatedSeverityBar,
  ChartsRow, SearchBar, AdvisoryCard, EmptyState, SkeletonList, NoDataset, severityConfig,
} from "@/lib/workbench-shared";
import type { SeverityKey } from "@/lib/workbench-shared";
import { motion } from "framer-motion";
import { FileSpreadsheet, Plus, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/_authenticated/")({
  component: DashboardPage,
});

function DashboardPage() {
  const {
    active, components, loading, severityCounts, severityFilter, setSeverityFilter,
    filteredComponents, addRow, handleFile, uploading, searchQuery,
  } = useWorkbench();

  if (!active) return <NoDataset />;

  return (
    <>
      <KpiRow />
      <ActiveFilterChip />

      <section className="grid gap-6 lg:grid-cols-[2fr_1fr]">
        {/* Dataset summary */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}
          className="card-elevated border border-border/60 p-6">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <h2 className="flex items-center gap-2 text-lg font-semibold">
                <FileSpreadsheet className="h-4 w-4 text-primary" />
                <span className="truncate">{active.name}</span>
              </h2>
              <p className="mt-1 text-xs text-muted-foreground">
                {filteredComponents.length} of {components.length} components · {active.columns.length} columns
              </p>
            </div>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={() => void addRow()} className="rounded-lg">
                <Plus className="mr-1 h-3.5 w-3.5" /> Row
              </Button>
              <Button size="sm" variant="outline" disabled={uploading} className="rounded-lg"
                onClick={() => {
                  const i = document.createElement("input"); i.type = "file"; i.accept = ".xlsx,.xls,.csv";
                  i.onchange = () => { const f = i.files?.[0]; if (f) void handleFile(f, active.id); }; i.click();
                }}>
                <Upload className="mr-1 h-3.5 w-3.5" /> Append
              </Button>
            </div>
          </div>

          <div className="mt-5">
            <div className="mb-2 flex items-center justify-between text-[11px] uppercase tracking-wider text-muted-foreground">
              <span>Severity distribution</span><span>{components.length} total</span>
            </div>
            <AnimatedSeverityBar counts={severityCounts} total={components.length} />
            <div className="mt-3 flex flex-wrap gap-2 text-xs">
              {(["critical", "high", "medium", "low", "info"] as SeverityKey[]).map((k) => {
                const cfg = severityConfig[k];
                return (
                  <button key={k} onClick={() => setSeverityFilter(severityFilter === k ? "all" : k)}
                    className={`chip border ${cfg.bg} ${cfg.border} ${cfg.color} transition hover:scale-105 ${severityFilter === k ? `ring-2 ${cfg.ring} ring-offset-2 ring-offset-background` : ""}`}>
                    <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
                    {cfg.label} · {severityCounts[k]}
                  </button>
                );
              })}
            </div>
          </div>
        </motion.div>

        <EnterpriseRiskCard />
      </section>

      <ChartsRow />

      <SearchBar />

      <div className="space-y-3">
        {loading ? <SkeletonList /> :
          filteredComponents.length === 0 ? <EmptyState searching={!!searchQuery || severityFilter !== "all"} /> :
            (<AnimatePresence initial={false}>
              {filteredComponents.slice(0, 25).map((row, i) => <AdvisoryCard key={row.id} row={row} index={i} />)}
            </AnimatePresence>)}
        {filteredComponents.length > 25 && (
          <div className="text-center text-xs text-muted-foreground">
            Showing 25 of {filteredComponents.length}. View all on the <a href="/components" className="text-primary hover:underline">Components</a> page.
          </div>
        )}
      </div>
    </>
  );
}
