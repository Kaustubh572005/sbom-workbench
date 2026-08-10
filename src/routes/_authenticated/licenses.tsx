import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { Scale, Download, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useWorkbench, NoDataset, severityConfig } from "@/lib/workbench-shared";

export const Route = createFileRoute("/_authenticated/licenses")({
  head: () => ({
    meta: [
      { title: "License Intelligence — SBOM Workbench" },
      { name: "description", content: "Classify SBOM licenses by type and risk, detect conflicts, and export license intelligence." },
      { property: "og:title", content: "License Intelligence — SBOM Workbench" },
      { property: "og:description", content: "License type, risk and conflict analysis across your software bill of materials." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: LicensesPage,
});

function LicensesPage() {
  const { active, analysis, exportSection } = useWorkbench();
  if (!active) return <NoDataset />;
  const lic = analysis.licenses;

  const sheet = {
    name: "Licenses",
    columns: ["License", "Type", "Risk", "Components", "Note"],
    rows: lic.entries.map((e) => [e.name, e.type, e.risk, e.count, e.note] as (string | number)[]),
  };

  const tiles = [
    { label: "Distinct licenses", value: lic.entries.length, tone: "info" as const },
    { label: "Risky licenses", value: lic.riskyCount, tone: "high" as const },
    { label: "Copyleft", value: lic.copyleft, tone: "medium" as const },
    { label: "Proprietary", value: lic.proprietary, tone: "high" as const },
    { label: "Permissive", value: lic.permissive, tone: "low" as const },
    { label: "Unknown / missing", value: lic.unknown, tone: "critical" as const },
  ];

  return (
    <>
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated flex flex-wrap items-center justify-between gap-3 border border-border/60 p-6">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold"><Scale className="h-5 w-5 text-primary" /> License Intelligence</h1>
          <p className="mt-1 text-xs text-muted-foreground">Automatic license classification for {active.name}.</p>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" className="rounded-xl" onClick={() => void exportSection("licenses", sheet, "csv")}>
            <Download className="mr-1 h-4 w-4" /> CSV
          </Button>
          <Button size="sm" className="rounded-xl bg-gradient-to-r from-primary to-severity-info" onClick={() => void exportSection("licenses", sheet, "xlsx")}>
            <Download className="mr-1 h-4 w-4" /> Excel
          </Button>
        </div>
      </motion.div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {tiles.map((t) => {
          const cfg = severityConfig[t.tone];
          return (
            <div key={t.label} className={`card-elevated border p-3 ${cfg.border}`}>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{t.label}</div>
              <div className={`mt-1 text-2xl font-bold ${cfg.color}`}>{t.value}</div>
            </div>
          );
        })}
      </div>

      <div className="card-elevated overflow-hidden border border-border/60">
        <div className="max-h-[60vh] overflow-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
              <tr className="border-b border-border">
                {["License", "Type", "Risk", "Components", "Note"].map((h) => (
                  <th key={h} className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {lic.entries.length === 0 && (
                <tr><td colSpan={5} className="px-3 py-6 text-center text-muted-foreground">No license data found in this dataset.</td></tr>
              )}
              {lic.entries.map((e) => {
                const cfg = severityConfig[e.risk];
                return (
                  <tr key={e.name} className="border-b border-border/40 hover:bg-accent/20">
                    <td className="px-3 py-2 font-medium">{e.name}</td>
                    <td className="px-3 py-2">{e.type}</td>
                    <td className="px-3 py-2">
                      <span className={`chip border ${cfg.bg} ${cfg.border} ${cfg.color} text-[10px]`}>{cfg.label}</span>
                    </td>
                    <td className="px-3 py-2 font-mono">{e.count}</td>
                    <td className="px-3 py-2 text-muted-foreground">{e.note}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card-elevated border border-border/60 p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold">
          <AlertTriangle className="h-4 w-4 text-severity-high" /> License conflicts
        </h2>
        {lic.conflicts.length === 0 ? (
          <p className="text-xs text-muted-foreground">No conflicting license combinations detected.</p>
        ) : (
          <div className="space-y-1.5">
            {lic.conflicts.map((c, i) => (
              <div key={i} className="rounded-lg border border-severity-high/30 bg-severity-high/5 px-3 py-2 text-xs">
                <span className="font-medium">{c.component}</span>
                <span className="ml-2 text-muted-foreground">{c.licenses.join(" + ")} — {c.detail}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
