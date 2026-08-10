import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { GitCompare, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { supabase } from "@/integrations/supabase/client";
import { useWorkbench, NoDataset, severityConfig } from "@/lib/workbench-shared";
import { buildPlatformAnalysis, compareAnalyses, type PlatformAnalysis } from "@/lib/platform-intel";

export const Route = createFileRoute("/_authenticated/comparison")({
  head: () => ({
    meta: [
      { title: "SBOM Comparison — SBOM Workbench" },
      { name: "description", content: "Compare two SBOM datasets to see added, removed and updated components plus risk delta." },
      { property: "og:title", content: "SBOM Comparison — SBOM Workbench" },
      { property: "og:description", content: "Delta analysis between two software bills of materials." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ComparisonPage,
});

function ComparisonPage() {
  const { datasets, activeId, analysis, exportSection } = useWorkbench();
  const [otherId, setOtherId] = useState<string>("");
  const [other, setOther] = useState<PlatformAnalysis | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!otherId) { setOther(null); return; }
    setLoading(true);
    void supabase.from("components").select("id, data").eq("dataset_id", otherId).order("created_at")
      .then(({ data }) => {
        const items = ((data ?? []) as Array<{ id: string; data: Record<string, unknown> }>)
          .map((c) => ({ id: c.id, data: c.data }));
        setOther(buildPlatformAnalysis(items));
        setLoading(false);
      });
  }, [otherId]);

  const result = useMemo(() => (other ? compareAnalyses(other, analysis) : null), [other, analysis]);

  if (!datasets.length) return <NoDataset />;

  const sheet = result ? {
    name: "Comparison",
    columns: ["Change", "Component", "From", "To", "Severity"],
    rows: [
      ...result.added.map((p) => ["Added", p.name, "—", p.version, p.severity] as (string | number)[]),
      ...result.removed.map((p) => ["Removed", p.name, p.version, "—", p.severity] as (string | number)[]),
      ...result.updated.map((u) => ["Updated", u.name, u.from, u.to, u.b.severity] as (string | number)[]),
    ],
  } : null;

  const tiles = result ? [
    { label: "Added", value: result.added.length, tone: "info" as const },
    { label: "Removed", value: result.removed.length, tone: "low" as const },
    { label: "Updated", value: result.updated.length, tone: "medium" as const },
    { label: "Unchanged", value: result.unchanged, tone: "low" as const },
    { label: "New risks", value: result.newVulns.length, tone: "critical" as const },
    { label: "Resolved risks", value: result.resolvedVulns.length, tone: "low" as const },
    { label: "New EOL/EOS", value: result.newEol.length, tone: "high" as const },
    { label: "Risk delta", value: result.riskDelta, tone: result.riskDelta > 0 ? ("critical" as const) : ("low" as const) },
  ] : [];

  return (
    <>
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated flex flex-wrap items-end justify-between gap-3 border border-border/60 p-6">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold"><GitCompare className="h-5 w-5 text-primary" /> SBOM Comparison</h1>
          <p className="mt-1 text-xs text-muted-foreground">Compare a baseline dataset against the currently active one.</p>
        </div>
        <div className="flex items-end gap-2">
          <label className="text-xs">
            <span className="mb-1 block text-muted-foreground">Baseline dataset</span>
            <select value={otherId} onChange={(e) => setOtherId(e.target.value)}
              className="rounded-xl border border-border bg-background px-3 py-2 text-xs outline-none focus:ring-2 focus:ring-primary/30">
              <option value="">Select…</option>
              {datasets.filter((d) => d.id !== activeId).map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
          </label>
          {sheet && (
            <Button size="sm" className="rounded-xl bg-gradient-to-r from-primary to-severity-info" onClick={() => void exportSection("comparison", sheet, "xlsx")}>
              <Download className="mr-1 h-4 w-4" /> Export
            </Button>
          )}
        </div>
      </motion.div>

      {loading && <p className="text-xs text-muted-foreground">Analyzing baseline…</p>}
      {!otherId && <p className="text-xs text-muted-foreground">Pick a baseline dataset to see the delta.</p>}

      {result && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-8">
            {tiles.map((t) => {
              const cfg = severityConfig[t.tone];
              return (
                <div key={t.label} className={`card-elevated border p-3 ${cfg.border}`}>
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{t.label}</div>
                  <div className={`mt-1 text-xl font-bold ${cfg.color}`}>{t.value}</div>
                </div>
              );
            })}
          </div>

          <div className="card-elevated overflow-hidden border border-border/60">
            <div className="max-h-[55vh] overflow-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                  <tr className="border-b border-border">
                    {["Change", "Component", "From", "To", "Severity"].map((h) => (
                      <th key={h} className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {sheet!.rows.slice(0, 500).map((r, i) => (
                    <tr key={i} className="border-b border-border/40 hover:bg-accent/20">
                      {r.map((c, j) => <td key={j} className="px-3 py-1.5">{String(c)}</td>)}
                    </tr>
                  ))}
                  {sheet!.rows.length === 0 && (
                    <tr><td colSpan={5} className="px-3 py-6 text-center text-muted-foreground">No component-level changes.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </>
  );
}
