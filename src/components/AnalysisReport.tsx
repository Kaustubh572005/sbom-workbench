import { useMemo, useState } from "react";
import ExcelJS from "exceljs";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import { motion } from "framer-motion";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RTooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from "recharts";
import {
  Download, FileJson, FileSpreadsheet, FileText, Maximize2, Search,
  ArrowUpDown, ChevronLeft, ChevronRight, Sparkles, ListChecks,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { toast } from "sonner";
import type { AnalysisReport, Kpi, ChartSpec, TableSpec } from "@/lib/risk-intel";

const TONE: Record<string, string> = {
  critical: "text-severity-critical border-severity-critical/40 bg-severity-critical/10",
  high: "text-severity-high border-severity-high/40 bg-severity-high/10",
  medium: "text-severity-medium border-severity-medium/40 bg-severity-medium/10",
  low: "text-severity-low border-severity-low/40 bg-severity-low/10",
  info: "text-severity-info border-severity-info/40 bg-severity-info/10",
  none: "text-muted-foreground border-border bg-muted/20",
  primary: "text-primary border-primary/40 bg-primary/10",
};
const PRIO: Record<string, string> = {
  P0: "bg-severity-critical/15 text-severity-critical border-severity-critical/40",
  P1: "bg-severity-high/15 text-severity-high border-severity-high/40",
  P2: "bg-severity-medium/15 text-severity-medium border-severity-medium/40",
  P3: "bg-severity-low/15 text-severity-low border-severity-low/40",
};
const PALETTE = ["#3b82f6", "#8b5cf6", "#06b6d4", "#f59e0b", "#ef4444", "#10b981", "#ec4899", "#84cc16"];

/* ---------------------------------- exports ---------------------------------- */
function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);

export function exportJson(r: AnalysisReport) {
  saveBlob(new Blob([JSON.stringify(r, null, 2)], { type: "application/json" }), `${slug(r.title)}.json`);
  toast.success("JSON downloaded");
}

export function exportCsv(r: AnalysisReport) {
  const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const lines: string[] = [`${esc(r.title)}`, `${esc("Dataset")},${esc(r.datasetName)}`, ""];
  lines.push("Summary");
  r.summary.forEach((s) => lines.push(esc(s)));
  lines.push("", "KPIs", ["Metric", "Value"].map(esc).join(","));
  r.kpis.forEach((k) => lines.push([k.label, k.value].map(esc).join(",")));
  for (const t of r.tables) {
    lines.push("", esc(t.title), t.columns.map(esc).join(","));
    t.rows.forEach((row) => lines.push(row.map(esc).join(",")));
  }
  lines.push("", "Recommendations", ["Priority", "Action"].map(esc).join(","));
  r.recommendations.forEach((x) => lines.push([x.priority, x.text].map(esc).join(",")));
  saveBlob(new Blob([lines.join("\n")], { type: "text/csv" }), `${slug(r.title)}.csv`);
  toast.success("CSV downloaded");
}

export async function exportXlsx(r: AnalysisReport) {
  const wb = new ExcelJS.Workbook();
  wb.creator = "SBOM Workbench — AI Risk Intelligence";
  wb.created = new Date();

  const s = wb.addWorksheet("Summary");
  s.columns = [{ header: "Field", key: "f", width: 24 }, { header: "Value", key: "v", width: 110 }];
  s.getRow(1).font = { bold: true, color: { argb: "FFFFFFFF" } };
  s.getRow(1).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF1E3A8A" } };
  s.addRow({ f: "Report", v: r.title });
  s.addRow({ f: "Dataset", v: r.datasetName });
  s.addRow({ f: "Generated", v: r.generatedAt });
  s.addRow({ f: "Records analyzed", v: r.matchedRows });
  r.summary.forEach((x, i) => s.addRow({ f: i === 0 ? "Findings" : "", v: x }));
  r.kpis.forEach((k) => s.addRow({ f: k.label, v: `${k.value}${k.sub ? ` (${k.sub})` : ""}` }));

  for (const t of r.tables) {
    if (!t.rows.length) continue;
    const ws = wb.addWorksheet(t.title.slice(0, 30));
    ws.columns = t.columns.map((c) => ({ header: c, key: c, width: Math.min(40, Math.max(12, c.length + 6)) }));
    ws.getRow(1).font = { bold: true, color: { argb: "FFFFFFFF" } };
    ws.getRow(1).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF7C3AED" } };
    ws.views = [{ state: "frozen", ySplit: 1 }];
    t.rows.forEach((row) => ws.addRow(Object.fromEntries(t.columns.map((c, i) => [c, row[i] ?? ""]))));
    ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: t.columns.length } };
  }

  const rec = wb.addWorksheet("Recommendations");
  rec.columns = [{ header: "Priority", key: "p", width: 12 }, { header: "Action", key: "a", width: 120 }];
  rec.getRow(1).font = { bold: true, color: { argb: "FFFFFFFF" } };
  rec.getRow(1).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF0F766E" } };
  r.recommendations.forEach((x) => rec.addRow({ p: x.priority, a: x.text }));

  const buf = await wb.xlsx.writeBuffer();
  saveBlob(new Blob([buf], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }), `${slug(r.title)}.xlsx`);
  toast.success("Excel downloaded");
}

export function exportPdf(r: AnalysisReport) {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const W = doc.internal.pageSize.getWidth();
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, W, 90, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(18);
  doc.text(r.title, 40, 44);
  doc.setFontSize(10);
  doc.setTextColor(180, 200, 230);
  doc.text(`${r.datasetName}  ·  ${new Date(r.generatedAt).toLocaleString()}  ·  ${r.matchedRows} records`, 40, 66);

  let y = 120;
  doc.setTextColor(20, 20, 20);
  doc.setFontSize(12);
  doc.text("Executive summary", 40, y);
  y += 16;
  doc.setFontSize(10);
  for (const line of r.summary) {
    const wrapped = doc.splitTextToSize(`• ${line}`, W - 80) as string[];
    doc.text(wrapped, 40, y);
    y += wrapped.length * 13 + 4;
  }

  autoTable(doc, {
    startY: y + 8,
    head: [["Metric", "Value"]],
    body: r.kpis.map((k) => [k.label, `${k.value}${k.sub ? ` (${k.sub})` : ""}`]),
    theme: "grid",
    headStyles: { fillColor: [30, 58, 138] },
    styles: { fontSize: 9 },
  });

  for (const t of r.tables) {
    if (!t.rows.length) continue;
    autoTable(doc, {
      head: [[t.title]],
      body: [],
      theme: "plain",
      headStyles: { fontSize: 11, fontStyle: "bold", textColor: [20, 20, 20] },
    });
    autoTable(doc, {
      head: [t.columns],
      body: t.rows.slice(0, 300).map((row) => row.map((c) => String(c ?? ""))),
      theme: "striped",
      headStyles: { fillColor: [124, 58, 237] },
      styles: { fontSize: 7.5, cellPadding: 3 },
    });
  }

  autoTable(doc, {
    head: [["Priority", "Recommended action"]],
    body: r.recommendations.map((x) => [x.priority, x.text]),
    theme: "grid",
    headStyles: { fillColor: [15, 118, 110] },
    styles: { fontSize: 9 },
  });

  doc.save(`${slug(r.title)}.pdf`);
  toast.success("PDF downloaded");
}

/* ----------------------------------- pieces ---------------------------------- */
function KpiGrid({ kpis }: { kpis: Kpi[] }) {
  return (
    <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
      {kpis.map((k, i) => (
        <motion.div key={i} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
          className={`rounded-xl border p-3 ${TONE[k.tone ?? "primary"]}`}>
          <div className="text-[10px] font-semibold uppercase tracking-wider opacity-80">{k.label}</div>
          <div className="mt-1 truncate text-xl font-bold tabular-nums">{k.value}</div>
          {k.sub && <div className="text-[10px] opacity-70">{k.sub}</div>}
        </motion.div>
      ))}
    </div>
  );
}

function Chart({ spec, height = 200 }: { spec: ChartSpec; height?: number }) {
  if (!spec.data.length) return null;
  return (
    <div className="rounded-xl border border-border/60 bg-background/40 p-3">
      <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{spec.title}</div>
      <div style={{ height }}>
        <ResponsiveContainer width="100%" height="100%">
          {spec.kind === "donut" ? (
            <PieChart>
              <Pie data={spec.data} dataKey="value" nameKey="name" innerRadius="52%" outerRadius="82%" paddingAngle={2} stroke="none">
                {spec.data.map((d, i) => <Cell key={i} fill={d.color ?? PALETTE[i % PALETTE.length]} />)}
              </Pie>
              <RTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 12, fontSize: 12 }} />
            </PieChart>
          ) : (
            <BarChart data={spec.data} margin={{ left: -18, right: 8, top: 4, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" strokeOpacity={0.15} vertical={false} />
              <XAxis dataKey="name" tick={{ fontSize: 9 }} interval={0} angle={-18} textAnchor="end" height={44} />
              <YAxis tick={{ fontSize: 9 }} allowDecimals={false} />
              <RTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 12, fontSize: 12 }} />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                {spec.data.map((d, i) => <Cell key={i} fill={d.color ?? PALETTE[i % PALETTE.length]} />)}
              </Bar>
            </BarChart>
          )}
        </ResponsiveContainer>
      </div>
    </div>
  );
}

const PAGE = 20;
function DataTable({ spec }: { spec: TableSpec }) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<{ i: number; dir: 1 | -1 } | null>(null);
  const [page, setPage] = useState(0);

  const rows = useMemo(() => {
    let r = spec.rows;
    if (q.trim()) {
      const t = q.toLowerCase();
      r = r.filter((row) => row.some((c) => String(c ?? "").toLowerCase().includes(t)));
    }
    if (sort) {
      r = [...r].sort((a, b) => {
        const av = a[sort.i], bv = b[sort.i];
        const an = Number(av), bn = Number(bv);
        if (!Number.isNaN(an) && !Number.isNaN(bn) && String(av).trim() !== "" && String(bv).trim() !== "") return (an - bn) * sort.dir;
        return String(av ?? "").localeCompare(String(bv ?? "")) * sort.dir;
      });
    }
    return r;
  }, [spec.rows, q, sort]);

  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const cur = Math.min(page, pages - 1);
  const view = rows.slice(cur * PAGE, cur * PAGE + PAGE);

  if (!spec.rows.length) return null;

  return (
    <div className="rounded-xl border border-border/60">
      <div className="flex flex-wrap items-center gap-2 border-b border-border/60 px-3 py-2">
        <ListChecks className="h-3.5 w-3.5 text-primary" />
        <span className="text-xs font-semibold">{spec.title}</span>
        <span className="chip border border-border/60 bg-background/60 text-[10px] text-muted-foreground">{rows.length}</span>
        <div className="ml-auto relative">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} placeholder="Filter rows…"
            className="h-7 w-40 rounded-lg pl-7 text-xs" />
        </div>
      </div>
      <div className="max-h-[50vh] overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
            <tr className="border-b border-border">
              {spec.columns.map((c, i) => (
                <th key={c} onClick={() => setSort((s) => (s?.i === i ? { i, dir: s.dir === 1 ? -1 : 1 } : { i, dir: 1 }))}
                  className="cursor-pointer whitespace-nowrap px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground">
                  <span className="inline-flex items-center gap-1">{c}<ArrowUpDown className="h-2.5 w-2.5 opacity-50" /></span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {view.map((row, ri) => (
              <tr key={ri} className="border-b border-border/40 hover:bg-accent/20">
                {row.map((cell, ci) => {
                  const sev = String(cell ?? "").toLowerCase();
                  const tone = spec.columns[ci] === "Severity" && TONE[sev] ? TONE[sev] : "";
                  return (
                    <td key={ci} className="max-w-[220px] truncate px-3 py-1.5">
                      {tone ? <span className={`chip border text-[9px] uppercase ${tone}`}>{String(cell)}</span> : String(cell ?? "")}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {pages > 1 && (
        <div className="flex items-center justify-between border-t border-border/60 px-3 py-1.5 text-[10px] text-muted-foreground">
          <span>Page {cur + 1} / {pages}</span>
          <div className="flex gap-1">
            <button onClick={() => setPage(Math.max(0, cur - 1))} className="rounded p-1 hover:bg-accent/50" aria-label="Previous page"><ChevronLeft className="h-3 w-3" /></button>
            <button onClick={() => setPage(Math.min(pages - 1, cur + 1))} className="rounded p-1 hover:bg-accent/50" aria-label="Next page"><ChevronRight className="h-3 w-3" /></button>
          </div>
        </div>
      )}
    </div>
  );
}

function ExportBar({ report }: { report: AnalysisReport }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      <Button size="sm" variant="outline" className="h-7 rounded-lg text-[11px]" onClick={() => void exportXlsx(report)}>
        <FileSpreadsheet className="mr-1 h-3 w-3" /> Excel
      </Button>
      <Button size="sm" variant="outline" className="h-7 rounded-lg text-[11px]" onClick={() => exportPdf(report)}>
        <FileText className="mr-1 h-3 w-3" /> PDF
      </Button>
      <Button size="sm" variant="outline" className="h-7 rounded-lg text-[11px]" onClick={() => exportCsv(report)}>
        <Download className="mr-1 h-3 w-3" /> CSV
      </Button>
      <Button size="sm" variant="outline" className="h-7 rounded-lg text-[11px]" onClick={() => exportJson(report)}>
        <FileJson className="mr-1 h-3 w-3" /> JSON
      </Button>
    </div>
  );
}

function ReportBody({ report, compact }: { report: AnalysisReport; compact?: boolean }) {
  return (
    <div className="space-y-3">
      <div className="space-y-1.5 text-xs leading-relaxed text-foreground/90">
        {report.summary.map((s, i) => (
          <div key={i} className="flex gap-2"><span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary" />{s}</div>
        ))}
      </div>
      <KpiGrid kpis={report.kpis} />
      <div className={compact ? "space-y-3" : "grid gap-3 md:grid-cols-2"}>
        {report.charts.map((c, i) => <Chart key={i} spec={c} height={compact ? 170 : 230} />)}
      </div>
      {report.tables.map((t, i) => <DataTable key={i} spec={t} />)}
      <div className="rounded-xl border border-border/60 bg-background/40 p-3">
        <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Recommended actions</div>
        <div className="space-y-1.5">
          {report.recommendations.map((r, i) => (
            <div key={i} className="flex items-start gap-2 text-xs">
              <span className={`chip shrink-0 border text-[9px] font-bold ${PRIO[r.priority]}`}>{r.priority}</span>
              <span className="text-foreground/90">{r.text}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------- public component ------------------------------ */
export function AnalysisReportCard({ report }: { report: AnalysisReport }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
        className="rounded-2xl border border-primary/30 bg-gradient-to-b from-primary/[0.07] to-transparent p-3">
        <div className="mb-2 flex items-start gap-2">
          <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-primary/15 text-primary">
            <Sparkles className="h-3 w-3" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="truncate text-xs font-semibold">{report.title}</div>
            <div className="text-[10px] text-muted-foreground">{report.matchedRows} records · {report.datasetName}</div>
          </div>
          <button onClick={() => setOpen(true)} className="rounded-lg border border-border/60 p-1.5 text-muted-foreground transition hover:border-primary/40 hover:text-primary"
            title="Open full report" aria-label="Open full report">
            <Maximize2 className="h-3 w-3" />
          </button>
        </div>
        <ReportBody report={report} compact />
        <div className="mt-3"><ExportBar report={report} /></div>
      </motion.div>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-h-[92vh] max-w-6xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex flex-wrap items-center gap-3">
              <span>{report.title}</span>
              <span className="text-[11px] font-normal text-muted-foreground">
                {report.datasetName} · {report.matchedRows} records · {new Date(report.generatedAt).toLocaleString()}
              </span>
              <div className="ml-auto"><ExportBar report={report} /></div>
            </DialogTitle>
          </DialogHeader>
          <ReportBody report={report} />
        </DialogContent>
      </Dialog>
    </>
  );
}
