import { Fragment, useMemo, useState, type ReactNode } from "react";
import ExcelJS from "exceljs";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import {
  ChevronDown, ChevronLeft, ChevronRight, Copy, Download, FileJson,
  FileSpreadsheet, FileText, Filter, Search, ArrowUpDown, ExternalLink,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";

export type Col<T> = {
  key: string;
  label: string;
  value: (row: T) => string | number;
  render?: (row: T) => ReactNode;
  align?: "left" | "right";
  filterable?: boolean;
  mono?: boolean;
  width?: string;
};

const saveBlob = (blob: Blob, name: string) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
};
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);

export function DataTable<T>({
  title,
  subtitle,
  columns,
  rows,
  getKey,
  onOpen,
  expand,
  pageSize = 25,
  emptyText = "Nothing to show for the current filters.",
  actions,
}: {
  title: string;
  subtitle?: string;
  columns: Col<T>[];
  rows: T[];
  getKey: (row: T) => string;
  onOpen?: (row: T) => void;
  expand?: (row: T) => ReactNode;
  pageSize?: number;
  emptyText?: string;
  actions?: ReactNode;
}) {
  const [q, setQ] = useState("");
  const [colFilters, setColFilters] = useState<Record<string, string>>({});
  const [showFilters, setShowFilters] = useState(false);
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(0);
  const [openRow, setOpenRow] = useState<string | null>(null);

  const filtered = useMemo(() => {
    let list = rows;
    const query = q.trim().toLowerCase();
    if (query) {
      list = list.filter((r) => columns.some((c) => String(c.value(r)).toLowerCase().includes(query)));
    }
    for (const [k, v] of Object.entries(colFilters)) {
      if (!v.trim()) continue;
      const col = columns.find((c) => c.key === k);
      if (!col) continue;
      const needle = v.trim().toLowerCase();
      list = list.filter((r) => String(col.value(r)).toLowerCase().includes(needle));
    }
    if (sortKey) {
      const col = columns.find((c) => c.key === sortKey);
      if (col) {
        const dir = sortDir === "asc" ? 1 : -1;
        list = [...list].sort((a, b) => {
          const av = col.value(a);
          const bv = col.value(b);
          if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
          return String(av).localeCompare(String(bv)) * dir;
        });
      }
    }
    return list;
  }, [rows, q, colFilters, sortKey, sortDir, columns]);

  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const current = Math.min(page, pages - 1);
  const visible = filtered.slice(current * pageSize, current * pageSize + pageSize);

  const matrix = () => filtered.map((r) => columns.map((c) => c.value(r)));
  const headers = columns.map((c) => c.label);

  const exportJson = () => {
    const data = filtered.map((r) => Object.fromEntries(columns.map((c) => [c.label, c.value(r)])));
    saveBlob(new Blob([JSON.stringify({ title, exportedAt: new Date().toISOString(), rows: data }, null, 2)], { type: "application/json" }), `${slug(title)}.json`);
    toast.success("JSON downloaded");
  };
  const exportCsv = () => {
    const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [headers.map(esc).join(","), ...matrix().map((r) => r.map(esc).join(","))];
    saveBlob(new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" }), `${slug(title)}.csv`);
    toast.success("CSV downloaded");
  };
  const exportExcel = async () => {
    const wb = new ExcelJS.Workbook();
    wb.creator = "SBOM Workbench";
    const ws = wb.addWorksheet(title.slice(0, 28) || "Export");
    ws.columns = headers.map((h) => ({ header: h, key: h, width: Math.min(38, Math.max(14, h.length + 6)) }));
    ws.getRow(1).font = { bold: true, color: { argb: "FFFFFFFF" } };
    ws.getRow(1).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF1E3A8A" } };
    ws.views = [{ state: "frozen", ySplit: 1 }];
    matrix().forEach((r) => ws.addRow(Object.fromEntries(headers.map((h, i) => [h, r[i]]))));
    ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: headers.length } };
    const buf = await wb.xlsx.writeBuffer();
    saveBlob(new Blob([buf], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }), `${slug(title)}.xlsx`);
    toast.success("Excel downloaded");
  };
  const exportPdf = () => {
    const doc = new jsPDF({ orientation: "landscape" });
    doc.setFontSize(14);
    doc.text(title, 14, 14);
    doc.setFontSize(9);
    doc.text(`${filtered.length} rows · generated ${new Date().toLocaleString()}`, 14, 20);
    autoTable(doc, {
      head: [headers],
      body: matrix().slice(0, 800).map((r) => r.map((v) => String(v ?? ""))),
      startY: 26,
      styles: { fontSize: 7, cellPadding: 1.6 },
      headStyles: { fillColor: [30, 58, 138] },
    });
    doc.save(`${slug(title)}.pdf`);
    toast.success("PDF downloaded");
  };
  const copyAll = () => {
    void navigator.clipboard.writeText([headers.join("\t"), ...matrix().map((r) => r.join("\t"))].join("\n"));
    toast.success(`${filtered.length} rows copied`);
  };

  return (
    <div className="card-elevated border border-border/60">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/60 px-4 py-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold tracking-tight">{title}</h3>
          <p className="text-[11px] text-muted-foreground">
            {subtitle ? `${subtitle} · ` : ""}{filtered.length.toLocaleString()} of {rows.length.toLocaleString()} rows
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {actions}
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} placeholder="Search…"
              className="h-8 w-40 rounded-lg pl-8 text-xs" />
          </div>
          <Button size="sm" variant={showFilters ? "default" : "outline"} className="h-8 rounded-lg px-2" onClick={() => setShowFilters(!showFilters)} title="Column filters">
            <Filter className="h-3.5 w-3.5" />
          </Button>
          <Button size="sm" variant="outline" className="h-8 rounded-lg px-2" onClick={copyAll} title="Copy filtered rows">
            <Copy className="h-3.5 w-3.5" />
          </Button>
          <Button size="sm" variant="outline" className="h-8 rounded-lg px-2" onClick={() => void exportExcel()} title="Export Excel">
            <FileSpreadsheet className="h-3.5 w-3.5" />
          </Button>
          <Button size="sm" variant="outline" className="h-8 rounded-lg px-2" onClick={exportCsv} title="Export CSV">
            <Download className="h-3.5 w-3.5" />
          </Button>
          <Button size="sm" variant="outline" className="h-8 rounded-lg px-2" onClick={exportJson} title="Export JSON">
            <FileJson className="h-3.5 w-3.5" />
          </Button>
          <Button size="sm" variant="outline" className="h-8 rounded-lg px-2" onClick={exportPdf} title="Export PDF">
            <FileText className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {showFilters && (
        <div className="flex flex-wrap gap-2 border-b border-border/60 bg-muted/30 px-4 py-2.5">
          {columns.filter((c) => c.filterable).map((c) => (
            <Input key={c.key} value={colFilters[c.key] ?? ""}
              onChange={(e) => { setColFilters((f) => ({ ...f, [c.key]: e.target.value })); setPage(0); }}
              placeholder={c.label} className="h-7 w-36 rounded-lg text-xs" />
          ))}
          <Button size="sm" variant="ghost" className="h-7 rounded-lg text-xs" onClick={() => setColFilters({})}>Clear</Button>
        </div>
      )}

      <div className="max-h-[68vh] overflow-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
            <tr className="border-b border-border">
              {expand && <th className="w-8 px-2 py-2" />}
              {columns.map((c) => (
                <th key={c.key} style={{ width: c.width }}
                  onClick={() => { if (sortKey === c.key) setSortDir(sortDir === "asc" ? "desc" : "asc"); else { setSortKey(c.key); setSortDir("desc"); } }}
                  className={`cursor-pointer select-none whitespace-nowrap px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground ${c.align === "right" ? "text-right" : "text-left"}`}>
                  <span className="inline-flex items-center gap-1">
                    {c.label}
                    {sortKey === c.key ? <span>{sortDir === "asc" ? "↑" : "↓"}</span> : <ArrowUpDown className="h-3 w-3 opacity-30" />}
                  </span>
                </th>
              ))}
              {onOpen && <th className="w-8 px-2 py-2" />}
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 && (
              <tr><td colSpan={columns.length + 2} className="px-3 py-10 text-center text-sm text-muted-foreground">{emptyText}</td></tr>
            )}
            {visible.map((row) => {
              const k = getKey(row);
              const isOpen = openRow === k;
              return (
                <Fragment key={k}>
                  <tr className="border-b border-border/40 transition hover:bg-accent/40">
                    {expand && (
                      <td className="px-2 py-2">
                        <button onClick={() => setOpenRow(isOpen ? null : k)} aria-label="Expand row"
                          className="rounded-md p-1 text-muted-foreground hover:bg-accent hover:text-foreground">
                          <ChevronDown className={`h-3.5 w-3.5 transition ${isOpen ? "rotate-180" : ""}`} />
                        </button>
                      </td>
                    )}
                    {columns.map((c) => (
                      <td key={c.key} className={`px-3 py-2.5 ${c.align === "right" ? "text-right" : ""} ${c.mono ? "font-mono text-xs" : ""}`}>
                        {c.render ? c.render(row) : String(c.value(row) || "—")}
                      </td>
                    ))}
                    {onOpen && (
                      <td className="px-2 py-2">
                        <button onClick={() => onOpen(row)} aria-label="Open details"
                          className="rounded-md p-1 text-muted-foreground hover:bg-accent hover:text-foreground">
                          <ExternalLink className="h-3.5 w-3.5" />
                        </button>
                      </td>
                    )}
                  </tr>
                  {expand && isOpen && (
                    <tr className="border-b border-border/40 bg-muted/20">
                      <td colSpan={columns.length + 2} className="px-6 py-4">{expand(row)}</td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border/60 px-4 py-2.5 text-xs text-muted-foreground">
        <span>Page {current + 1} of {pages}</span>
        <div className="flex items-center gap-1">
          <Button size="sm" variant="outline" className="h-7 rounded-lg px-2" disabled={current === 0} onClick={() => setPage(current - 1)}>
            <ChevronLeft className="h-3.5 w-3.5" />
          </Button>
          <Button size="sm" variant="outline" className="h-7 rounded-lg px-2" disabled={current >= pages - 1} onClick={() => setPage(current + 1)}>
            <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
    </div>
  );
}
