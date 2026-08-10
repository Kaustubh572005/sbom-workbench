import { createFileRoute } from "@tanstack/react-router";
import { motion } from "framer-motion";
import { Network, Download, GitBranch } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useWorkbench, NoDataset, severityConfig } from "@/lib/workbench-shared";

export const Route = createFileRoute("/_authenticated/dependencies")({
  head: () => ({
    meta: [
      { title: "Dependency Analysis — SBOM Workbench" },
      { name: "description", content: "Direct vs transitive dependency mapping, dependency tree and vulnerable dependency chains." },
      { property: "og:title", content: "Dependency Analysis — SBOM Workbench" },
      { property: "og:description", content: "Explore direct and transitive dependencies and vulnerable chains in your SBOM." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: DependenciesPage,
});

function DependenciesPage() {
  const { active, analysis, exportSection, setDrawerId } = useWorkbench();
  if (!active) return <NoDataset />;
  const deps = analysis.deps;

  const sheet = {
    name: "Dependencies",
    columns: ["Component", "Version", "Type", "Depth", "Severity", "Risk", "Depends On", "Used By"],
    rows: deps.nodes.map((n) => [
      n.name, n.version, n.direct ? "Direct" : "Transitive", n.depth,
      n.severity, n.riskScore, n.children.length, n.parents.length,
    ] as (string | number)[]),
  };

  const tiles = [
    { label: "Total nodes", value: deps.nodes.length, tone: "info" as const },
    { label: "Direct", value: deps.directCount, tone: "low" as const },
    { label: "Transitive", value: deps.transitiveCount, tone: "medium" as const },
    { label: "Max depth", value: deps.maxDepth, tone: "info" as const },
    { label: "Vulnerable chains", value: deps.vulnerableChains.length, tone: "critical" as const },
    { label: "Critical nodes", value: deps.criticalNodes.length, tone: "high" as const },
  ];

  return (
    <>
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated flex flex-wrap items-center justify-between gap-3 border border-border/60 p-6">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold"><Network className="h-5 w-5 text-primary" /> Dependency Analysis</h1>
          <p className="mt-1 text-xs text-muted-foreground">
            {deps.declared
              ? "Relationships resolved from declared SBOM dependency data."
              : "No dependency relationships declared in this SBOM — components are treated as direct."}
          </p>
        </div>
        <Button size="sm" className="rounded-xl bg-gradient-to-r from-primary to-severity-info" onClick={() => void exportSection("dependencies", sheet, "xlsx")}>
          <Download className="mr-1 h-4 w-4" /> Export
        </Button>
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

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="card-elevated border border-border/60 p-5">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold"><GitBranch className="h-4 w-4 text-primary" /> Dependency tree</h2>
          <div className="max-h-[55vh] space-y-1 overflow-auto font-mono text-[11px]">
            {deps.nodes.length === 0 && <p className="text-muted-foreground">No components to map.</p>}
            {deps.nodes.slice(0, 400).map((n) => {
              const cfg = severityConfig[n.severity];
              return (
                <button key={n.id} onClick={() => setDrawerId(n.id)}
                  className="flex w-full items-center gap-2 rounded px-1 py-0.5 text-left hover:bg-accent/30"
                  style={{ paddingLeft: `${Math.min(n.depth, 8) * 14 + 4}px` }}>
                  <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${cfg.dot}`} />
                  <span className="truncate">{n.name}{n.version ? `@${n.version}` : ""}</span>
                  <span className="ml-auto shrink-0 text-[10px] text-muted-foreground">{n.direct ? "direct" : `d${n.depth}`}</span>
                </button>
              );
            })}
            {deps.nodes.length > 400 && <p className="pt-2 text-muted-foreground">Showing first 400 of {deps.nodes.length} nodes.</p>}
          </div>
        </div>

        <div className="card-elevated border border-border/60 p-5">
          <h2 className="mb-3 text-sm font-semibold">Vulnerable dependency chains</h2>
          <div className="max-h-[55vh] space-y-1.5 overflow-auto">
            {deps.vulnerableChains.length === 0 && <p className="text-xs text-muted-foreground">No vulnerable chains detected.</p>}
            {deps.vulnerableChains.slice(0, 100).map((c, i) => {
              const cfg = severityConfig[c.severity];
              return (
                <div key={i} className={`rounded-lg border px-3 py-2 text-[11px] ${cfg.border} ${cfg.bg}`}>
                  <div className="flex items-center gap-2">
                    <span className={`chip border bg-background/90 ${cfg.border} ${cfg.color} text-[10px]`}>{cfg.label}</span>
                    <span className="ml-auto font-mono text-[10px]">risk {c.riskScore}</span>
                  </div>
                  <div className="mt-1 break-words font-mono">{c.path.join(" → ")}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </>
  );
}
