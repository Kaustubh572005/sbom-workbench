import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
  useWorkbench, ActiveFilterChip, SearchBar, KpiRow, NoDataset, severityConfig,
  getField, getSeverityLevel, highlightMatch,
} from "@/lib/workbench-shared";
import type { SeverityKey } from "@/lib/workbench-shared";
import { ChevronRight, ShieldAlert } from "lucide-react";
import { motion } from "framer-motion";

export const Route = createFileRoute("/_authenticated/vulnerabilities")({
  head: () => ({ meta: [{ title: "Vulnerabilities — SBOM Workbench" }] }),
  component: VulnPage,
});

type SortKey = "severity" | "cvss" | "component" | "app" | "cve";

function VulnPage() {
  const { active, filteredComponents, severityCol, setDrawerId, searchQuery } = useWorkbench();
  const [sortKey, setSortKey] = useState<SortKey>("cvss");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const sevRank: Record<SeverityKey, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, none: 0 };

  const rows = useMemo(() => {
    return [...filteredComponents].sort((a, b) => {
      const dir = sortDir === "asc" ? 1 : -1;
      const av = getValue(a, sortKey, severityCol);
      const bv = getValue(b, sortKey, severityCol);
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
    function getValue(row: typeof filteredComponents[number], k: SortKey, sevCol: string | null): string | number {
      if (k === "severity") return sevRank[sevCol ? getSeverityLevel(row.data[sevCol]) : "none"];
      if (k === "cvss") return parseFloat(getField(row.data, ["cvss", "score"])) || 0;
      if (k === "component") return getField(row.data, ["component", "package", "name"]);
      if (k === "app") return getField(row.data, ["application", "app"]);
      return getField(row.data, ["cve", "advisory"]);
    }
  }, [filteredComponents, sortKey, sortDir, severityCol]);

  if (!active) return <NoDataset />;

  const head = (label: string, k: SortKey) => (
    <th onClick={() => { if (sortKey === k) setSortDir(sortDir === "asc" ? "desc" : "asc"); else { setSortKey(k); setSortDir("desc"); } }}
      className="cursor-pointer select-none px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground">
      {label} {sortKey === k ? (sortDir === "asc" ? "↑" : "↓") : ""}
    </th>
  );

  return (
    <>
      <KpiRow />
      <ActiveFilterChip />
      <SearchBar />
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated overflow-hidden border border-border/60">
        <div className="max-h-[70vh] overflow-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
              <tr className="border-b border-border">
                {head("Severity", "severity")}
                {head("Component", "component")}
                {head("Application", "app")}
                {head("CVE", "cve")}
                {head("CVSS", "cvss")}
                <th className="px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Vendor</th>
                <th className="px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Status</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr><td colSpan={8} className="px-3 py-12 text-center text-sm text-muted-foreground">
                  <ShieldAlert className="mx-auto mb-2 h-6 w-6 opacity-50" /> No vulnerabilities match your filters.
                </td></tr>
              )}
              {rows.map((row) => {
                const sev = severityCol ? getSeverityLevel(row.data[severityCol]) : "none";
                const cfg = severityConfig[sev];
                const comp = getField(row.data, ["component", "package", "name"]);
                const app = getField(row.data, ["application", "app"]);
                const cve = getField(row.data, ["cve", "advisory"]);
                const cvss = getField(row.data, ["cvss", "score"]);
                const vendor = getField(row.data, ["supplier", "vendor", "publisher"]);
                const status = getField(row.data, ["status", "state"]);
                return (
                  <tr key={row.id} onClick={() => setDrawerId(row.id)}
                    className="cursor-pointer border-b border-border/40 transition hover:bg-accent/30">
                    <td className="px-3 py-2.5">
                      <span className={`chip border ${cfg.bg} ${cfg.border} ${cfg.color}`}>{cfg.label}</span>
                    </td>
                    <td className="px-3 py-2.5 font-medium">{highlightMatch(comp || "—", searchQuery)}</td>
                    <td className="px-3 py-2.5 text-muted-foreground">{highlightMatch(app || "—", searchQuery)}</td>
                    <td className="px-3 py-2.5 font-mono text-xs">{highlightMatch(cve || "—", searchQuery)}</td>
                    <td className={`px-3 py-2.5 font-mono text-xs ${cfg.color} font-semibold`}>{cvss || "—"}</td>
                    <td className="px-3 py-2.5 text-muted-foreground">{vendor || "—"}</td>
                    <td className="px-3 py-2.5 text-muted-foreground">{status || "—"}</td>
                    <td className="px-3 py-2.5"><ChevronRight className="h-4 w-4 text-muted-foreground" /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </motion.div>
    </>
  );
}
