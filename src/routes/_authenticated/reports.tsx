import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { FileBarChart, FileText, FileSpreadsheet, FileJson, FileType, CheckCircle2, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useWorkbench, NoDataset } from "@/lib/workbench-shared";
import {
  exportUtiPdf, exportUtiDocx, exportUtiXlsx, exportUtiCsv, exportUtiJson,
  ewayColumns, ewayComponentNames, ewayRows, validateEwayReport, reportFileName,
} from "@/lib/uti-report";

export const Route = createFileRoute("/_authenticated/reports")({
  head: () => ({
    meta: [
      { title: "SBOM-EwayDMS Register — SBOM Workbench" },
      { name: "description", content: "Automatically generated SBOM-EwayDMS register: data fields as rows, every component as a column, downloadable as Excel, Word, PDF, CSV or JSON." },
      { property: "og:title", content: "SBOM-EwayDMS Register — SBOM Workbench" },
      { property: "og:description", content: "Download the standardized SBOM-EwayDMS assessment register in Excel, Word, PDF, CSV or JSON." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ReportsPage,
});

function ReportsPage() {
  const { active, utiReport } = useWorkbench();
  const [busy, setBusy] = useState<string | null>(null);

  const cols = useMemo(() => (active ? ewayColumns(utiReport) : []), [active, utiReport]);
  const names = useMemo(() => (active ? ewayComponentNames(utiReport) : []), [active, utiReport]);
  const rows = useMemo(() => (active ? ewayRows(utiReport) : []), [active, utiReport]);
  const check = useMemo(() => (active ? validateEwayReport(utiReport) : null), [active, utiReport]);

  if (!active || !check) return <NoDataset />;

  const run = async (key: string, fn: () => void | Promise<void>) => {
    setBusy(key);
    try { await fn(); } finally { setBusy(null); }
  };

  const formats = [
    { key: "xlsx", label: "Excel", icon: FileSpreadsheet, fn: () => exportUtiXlsx(utiReport) },
    { key: "docx", label: "Word", icon: FileType, fn: () => exportUtiDocx(utiReport) },
    { key: "pdf", label: "PDF", icon: FileText, fn: () => exportUtiPdf(utiReport) },
    { key: "csv", label: "CSV", icon: FileSpreadsheet, fn: () => exportUtiCsv(utiReport) },
    { key: "json", label: "JSON", icon: FileJson, fn: () => exportUtiJson(utiReport) },
  ];

  const PREVIEW_COLS = Math.min(cols.length, 8);

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated overflow-hidden border border-border/60">
        <div className="flex flex-wrap items-center justify-between gap-4 bg-gradient-to-r from-primary/10 via-primary/5 to-transparent px-7 py-6">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-primary">{utiReport.classification}</p>
            <h1 className="mt-1 flex items-center gap-2 text-2xl font-semibold tracking-tight">
              <FileBarChart className="h-5 w-5 text-primary" /> SBOM-EwayDMS register
            </h1>
            <p className="mt-1 text-xs text-muted-foreground">
              {utiReport.dataset} · generated {new Date(utiReport.generatedAt).toLocaleString()} · {check.components.toLocaleString()} component column(s) · {check.fields} data fields
            </p>
            <p className="mt-1 text-[11px] text-muted-foreground">Downloads are named {reportFileName(utiReport)}.[ext]</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {formats.map((f) => (
              <Button key={f.key} size="sm" variant={f.key === "xlsx" ? "default" : "outline"} className="rounded-xl text-xs"
                disabled={busy !== null} onClick={() => void run(f.key, f.fn)}>
                <f.icon className="mr-1.5 h-3.5 w-3.5" /> {busy === f.key ? "Preparing…" : f.label}
              </Button>
            ))}
          </div>
        </div>
      </motion.div>

      <div className={`card-elevated flex items-start gap-3 border p-4 text-xs ${check.ok ? "border-border/60" : "border-severity-medium/50"}`}>
        {check.ok
          ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-severity-low" />
          : <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-severity-medium" />}
        <div>
          <p className="font-medium">
            {check.ok
              ? "Pre-export validation passed — every component has a column, every canonical field is present and no cell is blank."
              : `Pre-export validation raised ${check.issues.length} item(s).`}
          </p>
          {!check.ok && (
            <ul className="mt-1.5 space-y-1 text-muted-foreground">
              {check.issues.map((i, n) => <li key={n}>· {i}</li>)}
            </ul>
          )}
        </div>
      </div>

      <section className="card-elevated overflow-hidden border border-border/60">
        <div className="flex items-center justify-between gap-3 border-b border-border/60 bg-primary/5 px-5 py-3.5">
          <h2 className="text-sm font-semibold">Register preview — data fields as rows, components as columns</h2>
          <span className="text-[11px] text-muted-foreground">
            showing first {Math.max(0, PREVIEW_COLS - 2)} of {check.components} component column(s) — full matrix included in every download
          </span>
        </div>
        <div className="max-h-[70vh] overflow-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
              <tr className="border-b border-border">
                {cols.slice(0, PREVIEW_COLS).map((c, i) => (
                  <th key={c} className="min-w-[160px] whitespace-normal px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                    {c}
                    {i >= 2 && <span className="mt-0.5 block text-[10px] font-normal normal-case text-foreground/80">{names[i - 2]}</span>}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row[0]} className="border-b border-border/40 align-top hover:bg-accent/20">
                  {row.slice(0, PREVIEW_COLS).map((c, ci) => (
                    <td key={ci} className={`px-3 py-2 ${ci === 0 ? "font-medium" : ci === 1 ? "text-muted-foreground" : ""}`}>{c}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
