import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { motion } from "framer-motion";
import { FileBarChart, Download, FileText, FileSpreadsheet, FileJson, FileType } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useWorkbench, NoDataset } from "@/lib/workbench-shared";
import { exportUtiPdf, exportUtiDocx, exportUtiXlsx, exportUtiCsv, exportUtiJson } from "@/lib/uti-report";

export const Route = createFileRoute("/_authenticated/reports")({
  head: () => ({
    meta: [
      { title: "Enterprise SBOM Reports — SBOM Workbench" },
      { name: "description", content: "Automatically generated UTI AMC format SBOM assessment reports: executive, technical, vulnerability, lifecycle, license, compliance and remediation." },
      { property: "og:title", content: "Enterprise SBOM Reports — SBOM Workbench" },
      { property: "og:description", content: "Download the automatically generated enterprise SBOM assessment in PDF, DOCX, Excel, CSV or JSON." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ReportsPage,
});

function ReportsPage() {
  const { active, utiReport } = useWorkbench();
  const [busy, setBusy] = useState<string | null>(null);
  if (!active) return <NoDataset />;

  const run = async (key: string, fn: () => void | Promise<void>) => {
    setBusy(key);
    try { await fn(); } finally { setBusy(null); }
  };

  const formats = [
    { key: "pdf", label: "PDF", icon: FileText, fn: () => exportUtiPdf(utiReport) },
    { key: "docx", label: "DOCX", icon: FileType, fn: () => exportUtiDocx(utiReport) },
    { key: "xlsx", label: "Excel", icon: FileSpreadsheet, fn: () => exportUtiXlsx(utiReport) },
    { key: "csv", label: "CSV", icon: FileSpreadsheet, fn: () => exportUtiCsv(utiReport) },
    { key: "json", label: "JSON", icon: FileJson, fn: () => exportUtiJson(utiReport) },
  ];

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated overflow-hidden border border-border/60">
        <div className="flex flex-wrap items-center justify-between gap-4 bg-gradient-to-r from-primary/10 via-primary/5 to-transparent px-7 py-6">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-primary">{utiReport.classification}</p>
            <h1 className="mt-1 flex items-center gap-2 text-2xl font-semibold tracking-tight">
              <FileBarChart className="h-5 w-5 text-primary" /> Enterprise SBOM assessment
            </h1>
            <p className="mt-1 text-xs text-muted-foreground">
              {utiReport.dataset} · generated {new Date(utiReport.generatedAt).toLocaleString()} · {utiReport.records.length.toLocaleString()} component records · {utiReport.sections.length} sections
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {formats.map((f) => (
              <Button key={f.key} size="sm" variant={f.key === "pdf" ? "default" : "outline"} className="rounded-xl text-xs"
                disabled={busy !== null} onClick={() => void run(f.key, f.fn)}>
                <f.icon className="mr-1.5 h-3.5 w-3.5" /> {busy === f.key ? "Preparing…" : f.label}
              </Button>
            ))}
          </div>
        </div>
      </motion.div>

      {utiReport.sections.map((s, i) => (
        <motion.section key={s.title} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: Math.min(i * 0.03, 0.3) }}
          className="card-elevated overflow-hidden border border-border/60">
          <div className="flex items-center justify-between gap-3 border-b border-border/60 px-5 py-3.5">
            <h2 className="text-sm font-semibold">{i + 1}. {s.title}</h2>
            <span className="text-[11px] text-muted-foreground">{s.rows.length.toLocaleString()} row(s)</span>
          </div>
          {s.narrative && s.narrative.length > 0 && (
            <ul className="space-y-1.5 border-b border-border/60 px-5 py-4 text-xs leading-relaxed text-foreground/85">
              {s.narrative.map((n, j) => (
                <li key={j} className="flex gap-2"><span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary" />{n}</li>
              ))}
            </ul>
          )}
          {s.rows.length > 0 && (
            <div className="max-h-[45vh] overflow-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                  <tr className="border-b border-border">
                    {s.columns.map((c) => (
                      <th key={c} className="whitespace-nowrap px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{c}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {s.rows.slice(0, 200).map((r, ri) => (
                    <tr key={ri} className="border-b border-border/40 hover:bg-accent/20">
                      {r.map((c, ci) => <td key={ci} className="max-w-[280px] truncate px-3 py-1.5" title={String(c)}>{String(c)}</td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
              {s.rows.length > 200 && (
                <p className="px-5 py-3 text-[11px] text-muted-foreground">Showing first 200 rows — full data included in downloads.</p>
              )}
            </div>
          )}
        </motion.section>
      ))}

      <div className="card-elevated border border-border/60 p-5">
        <h2 className="text-sm font-semibold">Evidence appendix — component records</h2>
        <p className="mt-1 text-[11px] text-muted-foreground">
          Every component is documented in the UTI AMC data-field format (Data Field / Description / Value) inside the downloadable report.
        </p>
        <Button size="sm" variant="outline" className="mt-3 rounded-xl text-xs" disabled={busy !== null}
          onClick={() => void run("docx", () => exportUtiDocx(utiReport))}>
          <Download className="mr-1.5 h-3.5 w-3.5" /> Download full record appendix (DOCX)
        </Button>
      </div>
    </div>
  );
}
