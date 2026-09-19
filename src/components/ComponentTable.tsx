import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { ArrowUpDown, Download, Table2, ChevronRight, CalendarClock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useWorkbench, severityConfig } from "@/lib/workbench-shared";
import type { ComponentProfile } from "@/lib/platform-intel";
import { lifecycleDisplayText } from "@/lib/lifecycle-display";
import { BAND_CLASS, cveAgeText, eolDayText, type DateBand } from "@/lib/date-intel";

type ColKey =
  | "application" | "name" | "version" | "supplier" | "purl" | "cpe" | "license"
  | "lifecycle" | "severity" | "cveId" | "cvss" | "cvssSeverity" | "cvssVector"
  | "cvePublished" | "cveAge" | "eolDate" | "eolDays" | "exploitPublished"
  | "lastUpdated" | "cveCount" | "exploit" | "risk" | "nistRisk" | "priority" | "remediateBy"
  | "recommendedVersion" | "recommendedAction";

const COLUMNS: Array<{ key: ColKey; label: string; numeric?: boolean; wide?: boolean }> = [
  { key: "application", label: "Application" },
  { key: "name", label: "Component" },
  { key: "version", label: "Version" },
  { key: "cveId", label: "CVE ID" },
  { key: "cvss", label: "CVSS", numeric: true },
  { key: "cvssSeverity", label: "CVSS Severity" },
  { key: "cvssVector", label: "CVSS Vector", wide: true },
  { key: "cvePublished", label: "CVE Published" },
  { key: "cveAge", label: "CVE Age" },
  { key: "eolDate", label: "EOL Date" },
  { key: "eolDays", label: "Days Past / To EOL" },
  { key: "exploitPublished", label: "Exploit Published" },
  { key: "lastUpdated", label: "Last Update" },
  { key: "exploit", label: "Exploit Status" },
  { key: "nistRisk", label: "NIST Risk", numeric: true },
  { key: "priority", label: "Priority" },
  { key: "remediateBy", label: "Remediate By" },
  { key: "severity", label: "Severity" },
  { key: "lifecycle", label: "Lifecycle" },
  { key: "supplier", label: "Supplier" },
  { key: "license", label: "License" },
  { key: "purl", label: "PURL", wide: true },
  { key: "cpe", label: "CPE", wide: true },
  { key: "cveCount", label: "CVE Count", numeric: true },
  { key: "risk", label: "Risk Score", numeric: true },
  { key: "recommendedVersion", label: "Recommended Version" },
  { key: "recommendedAction", label: "Recommended Action", wide: true },
];

const SEV_ORDER: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, none: 0 };
const PRIORITY_ORDER: Record<string, number> = { P0: 4, P1: 3, P2: 2, P3: 1 };

const cveList = (p: ComponentProfile) =>
  p.cve.split(/[,;\s]+/).map((c) => c.trim()).filter((c) => /^CVE-/i.test(c));

const exploitStatus = (p: ComponentProfile) =>
  p.kev ? "KEV — actively exploited" : p.exploit ? "Public exploit" : p.cve ? "No known exploit" : "—";

function cellValue(p: ComponentProfile, key: ColKey): string | number {
  const d = p.dates;
  switch (key) {
    case "application": return p.application || "—";
    case "name": return p.name || "—";
    case "version": return p.version || "—";
    case "supplier": return p.supplier || "—";
    case "purl": return p.purl || "—";
    case "cpe": return p.cpe || "—";
    case "license": return p.license ? `${p.license}` : p.licenseType;
    case "lifecycle": return lifecycleDisplayText(p.lifecycleStatus || "—", p.eolDate, p.eosDate);
    case "severity": return p.severity;
    case "cveId": return d.cveId || p.cve || "—";
    case "cvss": return d.cvss || 0;
    case "cvssSeverity": return d.cvssSeverity;
    case "cvssVector": return d.cvssVector || "—";
    case "cvePublished": return d.cvePublished || "—";
    case "cveAge": return cveAgeText(d);
    case "eolDate": return d.eolDate || "—";
    case "eolDays": return eolDayText(d);
    case "exploitPublished": return d.exploitPublished || "—";
    case "lastUpdated": return d.lastUpdated || p.record.published || "—";
    case "cveCount": return cveList(p).length;
    case "exploit": return exploitStatus(p);
    case "nistRisk": return d.nistRisk;
    case "priority": return d.priority;
    case "remediateBy": return d.remediateBy;
    case "risk": return p.riskScore;
    case "recommendedVersion": return p.targetVersion || p.latestVersion || "—";
    case "recommendedAction": return p.recommendedAction || "—";
  }
}

function sortValue(p: ComponentProfile, key: ColKey): string | number {
  if (key === "severity") return SEV_ORDER[p.severity] ?? 0;
  if (key === "priority") return PRIORITY_ORDER[p.dates.priority] ?? 0;
  if (key === "cveAge") return p.dates.cveAgeDays ?? -1;
  if (key === "eolDays") return p.dates.daysPastEol ?? -(p.dates.daysToEol ?? 100000);
  return cellValue(p, key);
}

function BandCell({ band, children }: { band: DateBand; children: React.ReactNode }) {
  return (
    <span className={`chip whitespace-nowrap border text-[10px] font-semibold ${BAND_CLASS[band]}`}>{children}</span>
  );
}

type DateFilter = "none" | "pastEol" | "eol90" | "cve30" | "cve90" | "exploit90";

const DATE_FILTERS: Array<{ key: DateFilter; label: string; test: (p: ComponentProfile) => boolean }> = [
  { key: "pastEol", label: "Past EOL", test: (p) => p.dates.daysPastEol != null },
  { key: "eol90", label: "EOL in 90 days", test: (p) => p.dates.daysToEol != null && p.dates.daysToEol <= 90 },
  { key: "cve30", label: "CVE last 30 days", test: (p) => (p.dates.cveAgeDays ?? Infinity) <= 30 },
  { key: "cve90", label: "CVE last 90 days", test: (p) => (p.dates.cveAgeDays ?? Infinity) <= 90 },
  {
    key: "exploit90",
    label: "Exploit last 90 days",
    test: (p) => {
      if (!p.dates.exploitPublished) return false;
      const t = Date.parse(p.dates.exploitPublished);
      return Number.isFinite(t) && Date.now() - t <= 90 * 86_400_000;
    },
  },
];

export function ComponentTable() {
  const { filteredComponents, profileById, setDrawerId, exportSection } = useWorkbench();
  const [sort, setSort] = useState<{ key: ColKey; dir: "asc" | "desc" }>({ key: "nistRisk", dir: "desc" });
  const [limit, setLimit] = useState(50);
  const [dateFilter, setDateFilter] = useState<DateFilter>("none");

  const profiles = useMemo(
    () => filteredComponents.map((c) => profileById[c.id]).filter(Boolean),
    [filteredComponents, profileById],
  );

  const scoped = useMemo(() => {
    const f = DATE_FILTERS.find((x) => x.key === dateFilter);
    return f ? profiles.filter(f.test) : profiles;
  }, [profiles, dateFilter]);

  const sorted = useMemo(() => {
    const list = [...scoped];
    list.sort((a, b) => {
      const av = sortValue(a, sort.key);
      const bv = sortValue(b, sort.key);
      const res = typeof av === "number" && typeof bv === "number"
        ? av - bv
        : String(av).localeCompare(String(bv), undefined, { numeric: true });
      return sort.dir === "asc" ? res : -res;
    });
    return list;
  }, [scoped, sort]);

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

      <div className="flex flex-wrap items-center gap-1.5 border-b border-border/60 bg-muted/30 px-5 py-2.5">
        <span className="mr-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          <CalendarClock className="h-3 w-3" /> Date filters
        </span>
        {DATE_FILTERS.map((f) => {
          const active = dateFilter === f.key;
          const count = profiles.filter(f.test).length;
          return (
            <button key={f.key} onClick={() => setDateFilter(active ? "none" : f.key)}
              className={`chip border text-[10px] font-semibold transition ${active ? "border-primary/50 bg-primary/15 text-primary" : "border-border bg-card text-muted-foreground hover:text-foreground"}`}>
              {f.label} · {count.toLocaleString()}
            </button>
          );
        })}
        {dateFilter !== "none" && (
          <button onClick={() => setDateFilter("none")} className="text-[10px] font-semibold text-primary underline">Clear</button>
        )}
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
              const d = p.dates;
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
                    if (c.key === "cvssSeverity") {
                      const tone = d.cvssSeverity === "CRITICAL" ? "red" : d.cvssSeverity === "HIGH" ? "orange"
                        : d.cvssSeverity === "MEDIUM" ? "yellow" : d.cvssSeverity === "LOW" ? "green" : "gray";
                      return <td key={c.key} className="px-3 py-2"><BandCell band={tone}>{d.cvssSeverity}</BandCell></td>;
                    }
                    if (c.key === "cvePublished" || c.key === "cveAge") {
                      return (
                        <td key={c.key} className="px-3 py-2">
                          <BandCell band={d.cveBand}>{String(v)}</BandCell>
                        </td>
                      );
                    }
                    if (c.key === "eolDate" || c.key === "eolDays") {
                      return (
                        <td key={c.key} className="px-3 py-2">
                          <BandCell band={d.eolBand}>{String(v)}</BandCell>
                        </td>
                      );
                    }
                    if (c.key === "priority") {
                      const tone = d.priority === "P0" ? "red" : d.priority === "P1" ? "orange" : d.priority === "P2" ? "yellow" : "green";
                      return (
                        <td key={c.key} className="px-3 py-2">
                          <BandCell band={tone}>{d.priority} · {d.slaDays}d</BandCell>
                        </td>
                      );
                    }
                    if (c.key === "nistRisk" || c.key === "risk") {
                      const score = Number(v);
                      return (
                        <td key={c.key} className="px-3 py-2">
                          <span className={`font-semibold tabular-nums ${score >= 80 ? "text-severity-critical" : score >= 60 ? "text-severity-high" : score >= 35 ? "text-severity-medium" : "text-severity-low"}`}>
                            {score}
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
