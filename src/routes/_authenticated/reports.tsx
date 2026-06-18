import { createFileRoute } from "@tanstack/react-router";
import { useMemo } from "react";
import { useWorkbench, EnterpriseRiskCard, ChartsRow, NoDataset, severityConfig, getField, getSeverityLevel } from "@/lib/workbench-shared";
import type { SeverityKey } from "@/lib/workbench-shared";
import { Button } from "@/components/ui/button";
import { Download, FileBarChart, Building2, Boxes, ShieldAlert } from "lucide-react";
import { motion } from "framer-motion";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/reports")({
  head: () => ({ meta: [{ title: "Reports — SBOM Workbench" }] }),
  component: ReportsPage,
});

function ReportsPage() {
  const { active, components, severityCol, severityCounts, riskScore, riskBand, downloadExcel } = useWorkbench();

  const topApps = useMemo(() => {
    const m = new Map<string, number>();
    for (const c of components) {
      const a = getField(c.data, ["application", "app"]);
      if (!a) continue;
      m.set(a, (m.get(a) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [components]);

  const topCves = useMemo(() => {
    return components
      .map((c) => ({
        cve: getField(c.data, ["cve", "advisory"]),
        comp: getField(c.data, ["component", "package", "name"]),
        cvss: parseFloat(getField(c.data, ["cvss", "score"])) || 0,
        sev: severityCol ? getSeverityLevel(c.data[severityCol]) : "none" as SeverityKey,
      }))
      .filter((x) => x.cve)
      .sort((a, b) => b.cvss - a.cvss)
      .slice(0, 10);
  }, [components, severityCol]);

  function exportCSV() {
    if (!active) return;
    const cols = active.columns;
    const escape = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [cols.map(escape).join(",")];
    for (const c of components) lines.push(cols.map((col) => escape(c.data[col])).join(","));
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = `${active.name}.csv`; a.click();
    URL.revokeObjectURL(a.href);
    toast.success("CSV downloaded");
  }

  if (!active) return <NoDataset />;

  return (
    <>
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated border border-border/60 p-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="flex items-center gap-2 text-lg font-semibold"><FileBarChart className="h-5 w-5 text-primary" /> Executive Report</h2>
            <p className="mt-1 text-sm text-muted-foreground">Posture snapshot for <span className="text-foreground font-medium">{active.name}</span></p>
          </div>
          <div className="flex gap-2">
            <Button onClick={exportCSV} variant="outline" size="sm" className="rounded-xl"><Download className="mr-1 h-4 w-4" /> CSV</Button>
            <Button onClick={() => void downloadExcel()} size="sm" className="rounded-xl bg-gradient-to-r from-primary to-severity-info"><Download className="mr-1 h-4 w-4" /> Excel</Button>
          </div>
        </div>
        <p className="mt-4 text-sm leading-relaxed text-foreground/90">
          The dataset contains <strong>{components.length}</strong> components.
          Overall security score is <strong className={riskBand.color}>{riskScore}/100 ({riskBand.label})</strong>.
          {severityCounts.critical > 0 && <> Immediate attention is required for <strong className="text-severity-critical">{severityCounts.critical} Critical</strong> finding{severityCounts.critical === 1 ? "" : "s"}.</>}
          {severityCounts.high > 0 && <> <strong className="text-severity-high">{severityCounts.high} High</strong>-severity items should be triaged in the current sprint.</>}
        </p>
      </motion.div>

      <section className="grid gap-6 lg:grid-cols-[2fr_1fr]">
        <ChartsRow />
        <EnterpriseRiskCard />
      </section>

      <div className="grid gap-4 md:grid-cols-2">
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="card-elevated border border-border/60 p-5">
          <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold"><ShieldAlert className="h-4 w-4 text-primary" /> Top CVEs by CVSS</h3>
          <div className="space-y-1.5">
            {topCves.length === 0 && <p className="text-xs text-muted-foreground">No CVEs in dataset.</p>}
            {topCves.map((c, i) => {
              const cfg = severityConfig[c.sev];
              return (
                <div key={i} className="flex items-center gap-2 rounded-lg border border-border/40 bg-background/40 px-3 py-2 text-xs">
                  <span className={`chip border ${cfg.bg} ${cfg.border} ${cfg.color} text-[9px]`}>{cfg.label}</span>
                  <span className="font-mono">{c.cve}</span>
                  <span className="truncate text-muted-foreground">{c.comp}</span>
                  <span className={`ml-auto font-mono font-semibold ${cfg.color}`}>{c.cvss}</span>
                </div>
              );
            })}
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}
          className="card-elevated border border-border/60 p-5">
          <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold"><Boxes className="h-4 w-4 text-primary" /> Most vulnerable applications</h3>
          <div className="space-y-1.5">
            {topApps.length === 0 && <p className="text-xs text-muted-foreground">No application data.</p>}
            {topApps.map(([name, count], i) => (
              <div key={i} className="flex items-center gap-2 rounded-lg border border-border/40 bg-background/40 px-3 py-2 text-xs">
                <Building2 className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="truncate">{name}</span>
                <span className="ml-auto font-mono font-semibold text-primary">{count}</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </>
  );
}
