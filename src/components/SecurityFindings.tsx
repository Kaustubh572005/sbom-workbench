import { useEffect, useMemo, useRef, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { Area, AreaChart, Bar, CartesianGrid, ComposedChart, Legend, ReferenceArea, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CalendarClock, Download, RefreshCw, ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, XCircle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { useWorkbench } from "@/lib/workbench-shared";
import { lookupNvd, type NvdRecord } from "@/lib/nist-nvd.functions";
import { buildFindings, complianceCheck, cveIds, timelineByMonth, type Finding } from "@/lib/security-findings";
import { fmtDate } from "@/lib/lifecycle-dates";

type SortKey = keyof Finding;
const COLS: Array<{ key: SortKey; label: string }> = [
  { key: "component", label: "Component" }, { key: "version", label: "Version" }, { key: "cve", label: "CVE ID" },
  { key: "cvss", label: "CVSS" }, { key: "vector", label: "CVSS Vector" }, { key: "severity", label: "Severity" },
  { key: "cvePublished", label: "CVE Published" }, { key: "eolDate", label: "EOL Date" }, { key: "daysToEol", label: "Days Past/To EOL" },
  { key: "exploitDate", label: "Exploit" }, { key: "lastUpdate", label: "Last Update" }, { key: "riskScore", label: "Risk" },
  { key: "priority", label: "Priority" }, { key: "targetDate", label: "Target Fix" }, { key: "remediationStatus", label: "Remediation" },
];

const TONE_ROW: Record<Finding["tone"], string> = {
  red: "border-l-4 border-l-severity-critical bg-severity-critical/5",
  yellow: "border-l-4 border-l-severity-medium bg-severity-medium/5",
  green: "border-l-4 border-l-severity-low bg-severity-low/5",
  gray: "border-l-4 border-l-border",
};
const SEV_CHIP: Record<Finding["severity"], string> = {
  CRITICAL: "bg-severity-critical/15 text-severity-critical border-severity-critical/40",
  HIGH: "bg-severity-high/15 text-severity-high border-severity-high/40",
  MEDIUM: "bg-severity-medium/15 text-severity-medium border-severity-medium/40",
  LOW: "bg-severity-low/15 text-severity-low border-severity-low/40",
  NONE: "bg-muted text-muted-foreground border-border",
};
function eolChip(d: number | null) {
  if (d === null) return <span className="text-muted-foreground">—</span>;
  const cls = d < 0 ? "bg-severity-critical/15 text-severity-critical border-severity-critical/40"
    : d < 30 ? "bg-severity-high/15 text-severity-high border-severity-high/40"
    : d <= 90 ? "bg-severity-medium/15 text-severity-medium border-severity-medium/40"
    : "bg-severity-low/15 text-severity-low border-severity-low/40";
  return <span className={`chip border font-semibold tabular-nums ${cls}`}>{d < 0 ? `${-d}d past` : `${d}d left`}</span>;
}

const ago = (d: number | null) => (d === null ? "—" : d <= 0 ? "today" : `${d} days ago`);

export function SecurityFindings() {
  const { filteredComponents, profileById, setDrawerId, active } = useWorkbench();
  const lookup = useServerFn(lookupNvd);
  const [nvd, setNvd] = useState<Record<string, NvdRecord>>({});
  const [loading, setLoading] = useState(false);
  const [fetchedAt, setFetchedAt] = useState<string | null>(null);
  const [tab, setTab] = useState<"findings" | "compliance">("findings");
  const [f, setF] = useState({ pastEol: false, cveDays: 0, exploitDays: 0, eolDays: 0 });
  const [sort, setSort] = useState<{ key: SortKey; dir: "asc" | "desc" }>({ key: "riskScore", dir: "desc" });
  const [limit, setLimit] = useState(50);
  const chartRef = useRef<HTMLDivElement>(null);

  const profiles = useMemo(() => filteredComponents.map((c) => profileById[c.id]).filter(Boolean), [filteredComponents, profileById]);
  const findings = useMemo(() => buildFindings(profiles, nvd), [profiles, nvd]);

  const refresh = async (silent: boolean) => {
    const ids = [...new Set(profiles.sort((a, b) => b.riskScore - a.riskScore).flatMap((p) => cveIds(p.cve)))].filter((i) => !nvd[i]);
    if (!ids.length) { if (!silent) toast.info("All CVEs already enriched from NIST NVD"); return; }
    setLoading(true);
    try {
      for (let i = 0; i < Math.min(ids.length, 160); i += 40) {
        const res = await lookup({ data: { cves: ids.slice(i, i + 40) } });
        setNvd((prev) => ({ ...prev, ...res.records }));
        setFetchedAt(res.fetchedAt);
      }
      if (!silent) toast.success("NIST NVD scores and dates refreshed");
    } catch (e) {
      if (!silent) toast.error(e instanceof Error ? e.message : "NVD lookup failed");
    } finally { setLoading(false); }
  };

  useEffect(() => { setNvd({}); }, [active?.id]);
  useEffect(() => { if (profiles.length) void refresh(true); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [active?.id, profiles.length]);

  const shown = useMemo(() => {
    let l = findings.filter((x) => {
      if (f.pastEol && !(x.daysToEol !== null && x.daysToEol < 0)) return false;
      if (f.cveDays && !(x.cveAgeDays !== null && x.cveAgeDays <= f.cveDays)) return false;
      if (f.exploitDays) { const d = x.exploitDate ? Math.round((Date.now() - Date.parse(x.exploitDate)) / 86_400_000) : null; if (d === null || d > f.exploitDays) return false; }
      if (f.eolDays && !(x.daysToEol !== null && x.daysToEol >= 0 && x.daysToEol <= f.eolDays)) return false;
      return true;
    });
    l = [...l].sort((a, b) => {
      const av = a[sort.key], bv = b[sort.key];
      const na = av === null || av === "" || av === "—", nb = bv === null || bv === "" || bv === "—";
      if (na !== nb) return na ? 1 : -1;
      const r = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv), undefined, { numeric: true });
      return sort.dir === "asc" ? r : -r;
    });
    return l;
  }, [findings, f, sort]);

  const kpi = useMemo(() => {
    const crit = findings.filter((x) => x.cvss >= 9);
    const dated = findings.filter((x) => x.cvePublished);
    const oldest = [...dated].sort((a, b) => a.cvePublished.localeCompare(b.cvePublished))[0];
    const newest = [...dated].sort((a, b) => b.cvePublished.localeCompare(a.cvePublished))[0];
    const past = findings.filter((x) => x.daysToEol !== null && x.daysToEol < 0);
    const avgPast = past.length ? Math.round(past.reduce((s, x) => s + -(x.daysToEol ?? 0), 0) / past.length) : 0;
    const soon = findings.filter((x) => x.daysToEol !== null && x.daysToEol >= 0 && x.daysToEol <= 90);
    const expl = [...findings.filter((x) => x.exploitDate)].sort((a, b) => b.exploitDate.localeCompare(a.exploitDate))[0];
    const newestCrit = [...crit].filter((x) => x.cvePublished).sort((a, b) => b.cvePublished.localeCompare(a.cvePublished))[0];
    return { crit, oldest, newest, past, avgPast, soon, expl, newestCrit };
  }, [findings]);

  const timeline = useMemo(() => timelineByMonth(findings), [findings]);
  const compliance = useMemo(() => complianceCheck(findings), [findings]);
  const nowMonth = fmtDate(new Date()).slice(0, 7);
  const soonMonth = fmtDate(new Date(Date.now() + 90 * 86_400_000)).slice(0, 7);

  const cards = [
    { l: "Critical (CVSS ≥ 9)", v: kpi.crit.length, s: kpi.newestCrit ? `Newest: ${kpi.newestCrit.cvePublished}` : "No dated critical CVE", tone: "text-severity-critical" },
    { l: "Oldest unpatched CVE", v: kpi.oldest?.cvePublished ?? "—", s: kpi.oldest ? `${kpi.oldest.component} · ${kpi.oldest.cve}` : "No dated CVEs", tone: "text-foreground" },
    { l: "Most recent CVE", v: ago(kpi.newest?.cveAgeDays ?? null), s: kpi.newest ? `${kpi.newest.cve} · ${kpi.newest.cvePublished}` : "—", tone: "text-severity-high" },
    { l: "Past EOL", v: kpi.past.length, s: kpi.past.length ? `avg ${kpi.avgPast} days past` : "None past EOL", tone: "text-severity-critical" },
    { l: "Approaching EOL (90d)", v: kpi.soon.length, s: kpi.soon[0] ? `Next: ${kpi.soon.sort((a, b) => (a.daysToEol ?? 0) - (b.daysToEol ?? 0))[0].eolDate}` : "None in 90 days", tone: "text-severity-medium" },
    { l: "Latest exploit", v: kpi.expl?.exploitDate ?? "—", s: kpi.expl ? `${kpi.expl.cve} · ${kpi.expl.component}` : "No KEV exploit dates", tone: "text-severity-high" },
  ];

  /* ---------------- exports ---------------- */
  const rowsFor = (l: Finding[]) => l.map((x) => ({
    Application: x.application, Component: x.component, Version: x.version, "CVE ID": x.cve, "CVE Count": x.cveCount,
    CVSS: x.cvss, "CVSS Vector": x.vector, Severity: x.severity, "CVE Published": x.cvePublished, "EOL Date": x.eolDate,
    "Days Past/To EOL": x.daysToEol ?? "", "Exploit Published": x.exploitDate, "Last Update": x.lastUpdate,
    "Risk Score": x.riskScore, Priority: x.priority, "Target Remediation": x.targetDate, Recommendation: x.recommendation,
    "Remediation Status": x.remediationStatus, Lifecycle: x.lifecycle, Source: x.source,
  }));
  const summary = () => ({
    generatedAt: new Date().toISOString(), dataset: active?.name ?? "", totalFindings: findings.length,
    critical: kpi.crit.length, pastEol: kpi.past.length, avgDaysPastEol: kpi.avgPast, approachingEol: kpi.soon.length,
    oldestCve: kpi.oldest ? { cve: kpi.oldest.cve, component: kpi.oldest.component, published: kpi.oldest.cvePublished } : null,
    newestCve: kpi.newest ? { cve: kpi.newest.cve, component: kpi.newest.component, published: kpi.newest.cvePublished } : null,
    latestExploit: kpi.expl ? { cve: kpi.expl.cve, date: kpi.expl.exploitDate } : null,
    methodology: "Risk = CVSS 40% + EOL 30% + Exploit 20% + Lifecycle 10%. P0 ≤5d, P1 ≤30d, P2 ≤90d, P3 ≤180d.",
  });
  const chartPng = async () => {
    const svg = chartRef.current?.querySelector("svg");
    if (!svg) return null;
    const xml = new XMLSerializer().serializeToString(svg);
    const img = new Image();
    const w = svg.clientWidth || 900, h = svg.clientHeight || 260;
    await new Promise<void>((res, rej) => { img.onload = () => res(); img.onerror = rej; img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(xml); });
    const c = document.createElement("canvas"); c.width = w * 2; c.height = h * 2;
    const ctx = c.getContext("2d")!; ctx.fillStyle = "#ffffff"; ctx.fillRect(0, 0, c.width, c.height); ctx.scale(2, 2); ctx.drawImage(img, 0, 0, w, h);
    return { data: c.toDataURL("image/png"), w, h };
  };
  const download = (blob: Blob, name: string) => { const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); };
  const base = `security-findings-${fmtDate(new Date())}`;

  const exportXlsx = async () => {
    const ExcelJS = (await import("exceljs")).default;
    const wb = new ExcelJS.Workbook();
    const addSheet = (name: string, rows: Record<string, unknown>[]) => {
      const ws = wb.addWorksheet(name);
      if (!rows.length) { ws.addRow(["No data"]); return ws; }
      const keys = Object.keys(rows[0]);
      ws.addRow(keys).font = { bold: true, name: "Arial" };
      rows.forEach((r) => ws.addRow(keys.map((k) => r[k] as string | number)));
      ws.columns.forEach((c) => { c.width = 18; });
      ws.views = [{ state: "frozen", ySplit: 1 }];
      return ws;
    };
    const s1 = addSheet("Vulnerability Summary", rowsFor(shown));
    shown.forEach((x, i) => {
      const color = x.tone === "red" ? "FFFDE2E2" : x.tone === "yellow" ? "FFFEF3C7" : x.tone === "green" ? "FFDCFCE7" : undefined;
      if (color) s1.getRow(i + 2).fill = { type: "pattern", pattern: "solid", fgColor: { argb: color } };
    });
    const s2 = addSheet("Timeline Analysis", timeline.map((t) => ({ Month: t.month, "CVEs Published": t.cves, "Exploits Published": t.exploits, "EOL Milestones": t.eol })));
    const png = await chartPng().catch(() => null);
    if (png) { const id = wb.addImage({ base64: png.data, extension: "png" }); s2.addImage(id, { tl: { col: 5, row: 1 }, ext: { width: png.w, height: png.h } }); }
    addSheet("Remediation Plan", shown.filter((x) => x.priority !== "—").sort((a, b) => a.targetDate.localeCompare(b.targetDate)).map((x) => ({
      Priority: x.priority, "Target Date": x.targetDate, Component: x.component, Version: x.version, CVE: x.cve, CVSS: x.cvss,
      "Days Past/To EOL": x.daysToEol ?? "", Recommendation: x.recommendation, "Risk Score": x.riskScore,
    })));
    addSheet("Compliance Mapping", compliance.map((c) => ({ Framework: c.framework, Requirement: c.control, Status: c.status, Finding: c.detail, "Remediation Step": c.action })));
    addSheet("Analysis Summary", Object.entries(summary()).map(([k, v]) => ({ Field: k, Value: typeof v === "object" ? JSON.stringify(v) : String(v) })));
    download(new Blob([await wb.xlsx.writeBuffer()]), `${base}.xlsx`);
  };

  const exportPdf = async () => {
    const { jsPDF } = await import("jspdf");
    const autoTable = (await import("jspdf-autotable")).default;
    const doc = new jsPDF({ orientation: "landscape", unit: "pt", format: "a4" });
    const s = summary();
    doc.setFontSize(16); doc.text("Security Findings Report", 40, 40);
    doc.setFontSize(9); doc.text(`Dataset: ${s.dataset} · Generated ${s.generatedAt.slice(0, 10)} · ${s.totalFindings} findings`, 40, 58);
    doc.text(`Critical ${s.critical} · Past EOL ${s.pastEol} (avg ${s.avgDaysPastEol}d) · Approaching EOL ${s.approachingEol} · Oldest CVE ${s.oldestCve?.published ?? "—"} · Newest CVE ${s.newestCve?.published ?? "—"}`, 40, 72);
    let y = 86;
    const png = await chartPng().catch(() => null);
    if (png) { const w = 760, h = (png.h / png.w) * w; doc.addImage(png.data, "PNG", 40, y, w, h); y += h + 10; }
    autoTable(doc, {
      startY: y, styles: { fontSize: 6.5 }, headStyles: { fillColor: [30, 41, 59] },
      head: [["Component", "Version", "CVE", "CVSS", "Severity", "CVE Published", "EOL", "Days EOL", "Exploit", "Risk", "Priority", "Target"]],
      body: shown.slice(0, 500).map((x) => [x.component, x.version, x.cve, x.cvss || "", x.severity, x.cvePublished, x.eolDate, x.daysToEol ?? "", x.exploitDate, x.riskScore, x.priority, x.targetDate]),
    });
    doc.addPage();
    autoTable(doc, { startY: 40, styles: { fontSize: 8 }, head: [["Framework", "Requirement", "Status", "Finding", "Remediation"]], body: compliance.map((c) => [c.framework, c.control, c.status, c.detail, c.action]) });
    doc.setFontSize(8); doc.text(s.methodology, 40, doc.internal.pageSize.getHeight() - 30);
    doc.save(`${base}.pdf`);
  };

  const exportJson = () => download(new Blob([JSON.stringify({ summary: summary(), findings: rowsFor(shown), timeline, compliance }, null, 2)], { type: "application/json" }), `${base}.json`);

  const numInput = (k: "cveDays" | "exploitDays" | "eolDays", label: string) => (
    <label className="flex items-center gap-1.5 rounded-lg border border-border/60 bg-card px-2 py-1 text-[11px]">
      {label}
      <input type="number" min={0} value={f[k] || ""} placeholder="any" onChange={(e) => setF((s) => ({ ...s, [k]: Number(e.target.value) || 0 }))}
        className="w-14 rounded border border-border bg-background px-1 py-0.5 text-[11px]" /> days
    </label>
  );

  return (
    <section className="card-elevated space-y-5 border border-border/60 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold"><CalendarClock className="h-4 w-4 text-primary" /> Security findings · NIST scoring & dates</h2>
          <p className="mt-0.5 text-[11px] text-muted-foreground">
            Today <b>{fmtDate(new Date())}</b> · +30d <b>{fmtDate(new Date(Date.now() + 30 * 86_400_000))}</b> · +90d <b>{fmtDate(new Date(Date.now() + 90 * 86_400_000))}</b>
            {" · "}{Object.keys(nvd).length} CVEs from NIST NVD{fetchedAt ? ` · updated ${fetchedAt.slice(11, 16)} UTC` : ""}
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Button size="sm" variant="outline" className="h-8 rounded-lg text-[11px]" disabled={loading} onClick={() => void refresh(false)}>
            <RefreshCw className={`mr-1 h-3 w-3 ${loading ? "animate-spin" : ""}`} /> {loading ? "Fetching NVD…" : "Refresh NVD"}
          </Button>
          <Button size="sm" variant="outline" className="h-8 rounded-lg text-[11px]" onClick={() => void exportXlsx()}><Download className="mr-1 h-3 w-3" /> XLSX</Button>
          <Button size="sm" variant="outline" className="h-8 rounded-lg text-[11px]" onClick={() => void exportPdf()}><Download className="mr-1 h-3 w-3" /> PDF</Button>
          <Button size="sm" variant="outline" className="h-8 rounded-lg text-[11px]" onClick={exportJson}><Download className="mr-1 h-3 w-3" /> JSON</Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {cards.map((c) => (
          <div key={c.l} className="rounded-xl border border-border/60 bg-card px-3 py-3">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{c.l}</div>
            <div className={`mt-1 text-lg font-bold tabular-nums ${c.tone}`}>{c.v}</div>
            <div className="mt-0.5 truncate text-[11px] text-muted-foreground" title={c.s}>{c.s}</div>
          </div>
        ))}
      </div>

      <div ref={chartRef} className="h-64 rounded-xl border border-border/60 bg-card p-3">
        {timeline.length ? (
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="month" tick={{ fontSize: 10 }} />
              <YAxis allowDecimals={false} tick={{ fontSize: 10 }} />
              <Tooltip contentStyle={{ fontSize: 11 }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              {timeline[0].month < nowMonth && <ReferenceArea x1={timeline[0].month} x2={nowMonth} fill="var(--severity-critical)" fillOpacity={0.04} />}
              <ReferenceArea x1={nowMonth} x2={soonMonth} fill="var(--severity-medium)" fillOpacity={0.12} />
              <ReferenceLine x={nowMonth} stroke="var(--primary)" strokeDasharray="4 4" label={{ value: "Today", fontSize: 10 }} />
              <Bar dataKey="cves" name="CVEs published" fill="var(--severity-high)" radius={[3, 3, 0, 0]} />
              <Bar dataKey="exploits" name="Exploits published" fill="var(--severity-critical)" radius={[3, 3, 0, 0]} />
              <Bar dataKey="eol" name="EOL milestones" fill="var(--severity-medium)" radius={[3, 3, 0, 0]} />
            </ComposedChart>
          </ResponsiveContainer>
        ) : <div className="flex h-full items-center justify-center text-xs text-muted-foreground">No dated CVEs or EOL milestones yet.</div>}
        {/* keep recharts tree-shake happy */}
        {false && <AreaChart data={[]}><Area dataKey="x" /></AreaChart>}
      </div>

      <div className="flex gap-1.5">
        {(["findings", "compliance"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`rounded-xl border px-3 py-1.5 text-xs font-medium capitalize ${tab === t ? "border-primary/40 bg-primary/10" : "border-border/60 text-muted-foreground hover:text-foreground"}`}>
            {t === "compliance" ? "Compliance (SEBI CSCRF · CERT-In)" : "Dated findings"}
          </button>
        ))}
      </div>

      {tab === "compliance" ? (
        <div className="grid gap-2 md:grid-cols-2">
          {compliance.map((c) => {
            const Icon = c.status === "Compliant" ? CheckCircle2 : c.status === "At risk" ? AlertTriangle : XCircle;
            const tone = c.status === "Compliant" ? "text-severity-low" : c.status === "At risk" ? "text-severity-medium" : "text-severity-critical";
            return (
              <div key={c.framework + c.control} className="flex gap-3 rounded-xl border border-border/60 bg-card p-3">
                <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${tone}`} />
                <div className="min-w-0 text-xs">
                  <div className="font-semibold">{c.control} <span className="ml-1 text-[10px] font-normal text-muted-foreground">{c.framework}</span></div>
                  <div className={`mt-0.5 font-medium ${tone}`}>{c.status} · <span className="text-muted-foreground">{c.detail}</span></div>
                  <div className="mt-1 text-muted-foreground">→ {c.action}</div>
                </div>
              </div>
            );
          })}
          <div className="md:col-span-2 flex items-center gap-2 text-[11px] text-muted-foreground">
            {compliance.every((c) => c.status === "Compliant") ? <ShieldCheck className="h-4 w-4 text-severity-low" /> : <ShieldAlert className="h-4 w-4 text-severity-high" />}
            {compliance.filter((c) => c.status === "Compliant").length}/{compliance.length} controls compliant
          </div>
        </div>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <label className="flex items-center gap-1.5 rounded-lg border border-border/60 bg-card px-2 py-1 text-[11px]">
              <input type="checkbox" checked={f.pastEol} onChange={(e) => setF((s) => ({ ...s, pastEol: e.target.checked }))} /> Past EOL only
            </label>
            {numInput("cveDays", "CVE published in last")}
            {numInput("exploitDays", "Exploit in last")}
            {numInput("eolDays", "EOL within next")}
            <select className="rounded-lg border border-border/60 bg-card px-2 py-1 text-[11px]"
              value={`${sort.key}:${sort.dir}`} onChange={(e) => { const [k, d] = e.target.value.split(":"); setSort({ key: k as SortKey, dir: d as "asc" | "desc" }); }}>
              <option value="riskScore:desc">Risk (highest)</option>
              <option value="cvePublished:desc">CVE published (newest)</option>
              <option value="cvePublished:asc">CVE published (oldest)</option>
              <option value="eolDate:asc">EOL date (soonest)</option>
              <option value="eolDate:desc">EOL date (latest)</option>
              <option value="cvss:desc">CVSS (highest)</option>
            </select>
            <span className="text-[11px] text-muted-foreground">{shown.length} of {findings.length}</span>
          </div>

          <div className="max-h-[70vh] overflow-auto rounded-xl border border-border/60">
            <table className="w-full text-xs">
              <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                <tr className="border-b border-border">
                  {COLS.map((c) => (
                    <th key={c.key} className="whitespace-nowrap px-3 py-2 text-left">
                      <button onClick={() => setSort((s) => ({ key: c.key, dir: s.key === c.key && s.dir === "desc" ? "asc" : "desc" }))}
                        className={`text-[10px] font-semibold uppercase tracking-wider ${sort.key === c.key ? "text-primary" : "text-muted-foreground hover:text-foreground"}`}>
                        {c.label}{sort.key === c.key ? (sort.dir === "desc" ? " ↓" : " ↑") : ""}
                      </button>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {shown.slice(0, limit).map((x) => (
                  <tr key={x.id} onClick={() => setDrawerId(x.id)} className={`cursor-pointer border-b border-border/40 hover:bg-accent/25 ${TONE_ROW[x.tone]}`}>
                    <td className="whitespace-nowrap px-3 py-2 font-medium">{x.component}</td>
                    <td className="whitespace-nowrap px-3 py-2">{x.version || "—"}</td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono">{x.cve || "—"}{x.cveCount > 1 ? <span className="ml-1 text-muted-foreground">+{x.cveCount - 1}</span> : null}</td>
                    <td className="px-3 py-2 font-semibold tabular-nums">{x.cvss ? x.cvss.toFixed(1) : "—"}</td>
                    <td className="max-w-[220px] truncate px-3 py-2 font-mono text-[10px]" title={x.vector}>{x.vector || "—"}</td>
                    <td className="px-3 py-2"><span className={`chip border text-[10px] ${SEV_CHIP[x.severity]}`}>{x.severity}</span></td>
                    <td className="whitespace-nowrap px-3 py-2 font-semibold tabular-nums">{x.cvePublished || "—"}{x.cveAgeDays !== null && <div className="text-[10px] font-normal text-muted-foreground">{ago(x.cveAgeDays)}</div>}</td>
                    <td className="whitespace-nowrap px-3 py-2 font-semibold tabular-nums">{x.eolDate || "—"}</td>
                    <td className="whitespace-nowrap px-3 py-2">{eolChip(x.daysToEol)}</td>
                    <td className="whitespace-nowrap px-3 py-2">{x.exploitDate ? <span className="font-semibold text-severity-critical">{x.exploitDate}</span> : x.exploit ? "Yes" : "No"}</td>
                    <td className="whitespace-nowrap px-3 py-2 tabular-nums">{x.lastUpdate || "—"}</td>
                    <td className="px-3 py-2 font-bold tabular-nums">{x.riskScore}</td>
                    <td className="px-3 py-2 font-semibold">{x.priority}</td>
                    <td className="whitespace-nowrap px-3 py-2 tabular-nums" title={x.recommendation}>{x.targetDate || "—"}</td>
                    <td className="max-w-[180px] truncate px-3 py-2" title={x.remediationStatus}>{x.remediationStatus}</td>
                  </tr>
                ))}
                {!shown.length && <tr><td colSpan={COLS.length} className="px-3 py-10 text-center text-muted-foreground">No findings match these date filters.</td></tr>}
              </tbody>
            </table>
          </div>
          {shown.length > limit && (
            <div className="text-center"><Button size="sm" variant="outline" className="text-xs" onClick={() => setLimit((l) => l + 100)}>Load more ({shown.length - limit} remaining)</Button></div>
          )}
          <p className="text-[10px] text-muted-foreground">Risk = CVSS 40% + EOL 30% + Exploit 20% + Lifecycle 10%. Priority P0 ≤5 days (CVSS ≥ 9 + exploit), P1 ≤30 days (CVSS ≥ 7 or &gt;1 year past EOL), P2 ≤90 days, P3 ≤180 days.</p>
        </>
      )}
    </section>
  );
}
