import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { ArrowUpDown, Download, Table2, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useWorkbench, severityConfig } from "@/lib/workbench-shared";
import type { ComponentProfile } from "@/lib/platform-intel";

type ColKey =
  | "application" | "name" | "version" | "supplier" | "purl" | "cpe" | "license"
  | "lifecycle" | "severity" | "cvss" | "cveCount" | "exploit" | "risk"
  | "recommendedVersion" | "recommendedAction" | "lastUpdated";

const COLUMNS: Array<{ key: ColKey; label: string; numeric?: boolean; wide?: boolean }> = [
  { key: "application", label: "Application" },
  { key: "name", label: "Component" },
  { key: "version", label: "Version" },
  { key: "supplier", label: "Supplier" },
  { key: "purl", label: "PURL", wide: true },
  { key: "cpe", label: "CPE", wide: true },
  { key: "license", label: "License" },
  { key: "lifecycle", label: "Lifecycle" },
  { key: "severity", label: "Severity" },
  { key: "cvss", label: "CVSS", numeric: true },
  { key: "cveCount", label: "CVE Count", numeric: true },
  { key: "exploit", label: "Exploit Status" },
  { key: "risk", label: "Risk Score", numeric: true },
  { key: "recommendedVersion", label: "Recommended Version" },
  { key: "recommendedAction", label: "Recommended Action", wide: true },
  { key: "lastUpdated", label: "Last Updated" },
];

const SEV_ORDER: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, none: 0 };

const cveList = (p: ComponentProfile) =>
  p.cve.split(/[,;\s]+/).map((c) => c.trim()).filter((c) => /^CVE-/i.test(c));

const exploitStatus = (p: ComponentProfile) =>
  p.kev ? "KEV — actively exploited" : p.exploit ? "Public exploit" : p.cve ? "No known exploit" : "—";

function cellValue(p: ComponentProfile, key: ColKey): string | number {
  switch (key) {
    case "application": return p.application || "—";
    case "name": return p.name || "—";
    case "version": return p.version || "—";
    case "supplier": return p.supplier || "—";
    case "purl": return p.purl || "—";
    case "cpe": return p.cpe || "—";
    case "license": return p.license ? `${p.license}` : p.licenseType;
    case "lifecycle": return p.lifecycleStatus || "—";
    case "severity": return p.severity;
    case "cvss": return p.cvss || 0;
    case "cveCount": return cveList(p).length;
    case "exploit": return exploitStatus(p);
    case "risk": return p.riskScore;
    case "recommendedVersion": return p.targetVersion || p.latestVersion || "—";
    case "recommendedAction": return p.recommendedAction || "—";
    case "lastUpdated": return p.record.intel.updatedAt?.slice(0, 10) || p.record.published || "—";
  }
}

export function ComponentTable() {
  const { filteredComponents, profileById, setDrawerId, exportSection } = useWorkbench();
  const [sort, setSort] = useState<{ key: ColKey; dir: "asc" | "desc" }>({ key: "risk", dir: "desc" });
  const [limit, setLimit] = useState(50);

  const profiles = useMemo(
    () => filteredComponents.map((c) => profileById[c.id]).filter(Boolean),
    [filteredComponents, profileById],
  );

  const sorted = useMemo(() => {
    const list = [...profiles];
    list.sort((a, b) => {
      let av: string | number = cellValue(a, sort.key);
      let bv: string | number = cellValue(b, sort.key);
      if (sort.key === "severity") { av = SEV_ORDER[String(av)] ?? 0; bv = SEV_ORDER[String(bv)] ?? 0; }
      const res = typeof av === "number" && typeof bv === "number"
        ? av - bv
        : String(av).localeCompare(String(bv), undefined, { numeric: true });
      return sort.dir === "asc" ? res : -res;
    });
    return list;
  }, [profiles, sort]);

  const sheet = {
    name: "Component Inventory",
    columns: COLUMNS.map((c) => c.label),
    rows: sorted.map((p) => COLUMNS.map((c) => cellValue(p, c.key))),
  };

  return (
    <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
      className="card-elevated overflow-hidden border border-border/60">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/60 px-5 py-3.5">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <Table2 className="h-4 w-4 text-primary" /> Component inventory
          </h2>
          <p className="mt-0.5 text-[11px] text-muted-foreground">
            {sorted.length.toLocaleString()} component(s) in scope · sorted by {COLUMNS.find((c) => c.key === sort.key)?.label} ({sort.dir})
          </p>
        </div>
        <div className="flex gap-1.5">
          {(["xlsx", "csv", "json"] as const).map((f) => (
            <Button key={f} size="sm" variant="outline" className="h-8 rounded-lg text-[11px] uppercase"
              onClick={() => void exportSection("inventory", sheet, f)}>
              <Download className="mr-1 h-3 w-3" /> {f}
            </Button>
          ))}
        </div>
      </div>

      <div className="max-h-[70vh] overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
            <tr className="border-b border-border">
              {COLUMNS.map((c) => (
                <th key={c.key} className="whitespace-nowrap px-3 py-2.5 text-left">
                  <button
                    onClick={() => setSort((s) => ({ key: c.key, dir: s.key === c.key && s.dir === "desc" ? "asc" : "desc" }))}
                    className={`flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider transition ${sort.key === c.key ? "text-primary" : "text-muted-foreground hover:text-foreground"}`}>
                    {c.label} <ArrowUpDown className="h-3 w-3" />
                  </button>
                </th>
              ))}
              <th className="w-8" />
            </tr>
          </thead>
          <tbody>
            {sorted.slice(0, limit).map((p) => {
              const cfg = severityConfig[p.severity];
              return (
                <tr key={p.id} onClick={() => setDrawerId(p.id)}
                  className="cursor-pointer border-b border-border/40 transition hover:bg-accent/25">
                  {COLUMNS.map((c) => {
                    const v = cellValue(p, c.key);
                    if (c.key === "severity") {
                      return (
                        <td key={c.key} className="px-3 py-2">
                          <span className={`chip border ${cfg.bg} ${cfg.border} ${cfg.color} text-[10px]`}>{cfg.label}</span>
                        </td>
                      );
                    }
                    if (c.key === "risk") {
                      return (
                        <td key={c.key} className="px-3 py-2">
                          <span className={`font-semibold ${p.riskScore >= 80 ? "text-severity-critical" : p.riskScore >= 60 ? "text-severity-high" : p.riskScore >= 35 ? "text-severity-medium" : "text-severity-low"}`}>
                            {p.riskScore}
                          </span>
                        </td>
                      );
                    }
                    return (
                      <td key={c.key} className={`px-3 py-2 ${c.wide ? "max-w-[240px] truncate" : "whitespace-nowrap"} ${c.numeric ? "tabular-nums" : ""}`}
                        title={String(v)}>
                        {String(v)}
                      </td>
                    );
                  })}
                  <td className="px-2 text-muted-foreground"><ChevronRight className="h-3.5 w-3.5" /></td>
                </tr>
              );
            })}
            {sorted.length === 0 && (
              <tr><td colSpan={COLUMNS.length + 1} className="px-3 py-10 text-center text-muted-foreground">
                No components match the current filters.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      {sorted.length > limit && (
        <div className="border-t border-border/60 px-5 py-3 text-center">
          <Button size="sm" variant="outline" className="rounded-lg text-xs" onClick={() => setLimit((l) => l + 100)}>
            Load more ({(sorted.length - limit).toLocaleString()} remaining)
          </Button>
        </div>
      )}
    </motion.section>
  );
}
