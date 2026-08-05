import { createFileRoute } from "@tanstack/react-router";
import { useMemo } from "react";
import { useWorkbench, NoDataset } from "@/lib/workbench-shared";
import { assessAll } from "@/lib/sbom-heuristics";
import type { Sev } from "@/lib/sbom-heuristics";
import {
  buildExecReport, exportReportCsv, exportReportJson, exportReportMarkdown,
  exportReportPdf, exportReportXlsx,
} from "@/lib/exec-report";
import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";
import { toast } from "sonner";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RTooltip, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, RadialBarChart, RadialBar,
} from "recharts";
import {
  Download, FileJson, FileSpreadsheet, FileText, FileCode2, Building2, Boxes,
  ShieldAlert, Gauge, Sparkles, AlertTriangle, ScrollText, Scale, Clock,
} from "lucide-react";

export const Route = createFileRoute("/_authenticated/executive")({
  head: () => ({
    meta: [
      { title: "Executive Intelligence Report — SBOM Workbench" },
      { name: "description", content: "Board-level software supply chain risk report: cyber risk score, compliance status, critical findings and remediation roadmap." },
      { property: "og:title", content: "Executive Intelligence Report — SBOM Workbench" },
      { property: "og:description", content: "Bloomberg-grade SBOM risk intelligence for CISOs and boards." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: ExecutivePage,
});

const SEV_TONE: Record<Sev, { text: string; bg: string; border: string; fill: string }> = {
  critical: { text: "text-severity-critical", bg: "bg-severity-critical/10", border: "border-severity-critical/40", fill: "hsl(0 84% 55%)" },
  high: { text: "text-severity-high", bg: "bg-severity-high/10", border: "border-severity-high/40", fill: "hsl(24 90% 52%)" },
  medium: { text: "text-severity-medium", bg: "bg-severity-medium/10", border: "border-severity-medium/40", fill: "hsl(45 92% 47%)" },
  low: { text: "text-severity-low", bg: "bg-severity-low/10", border: "border-severity-low/40", fill: "hsl(142 66% 40%)" },
  info: { text: "text-severity-info", bg: "bg-severity-info/10", border: "border-severity-info/40", fill: "hsl(210 90% 52%)" },
};

function Panel({ title, icon: Icon, children, className = "" }: { title: string; icon: React.ElementType; children: React.ReactNode; className?: string }) {
  return (
    <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className={`card-elevated border border-border/60 p-5 ${className}`}>
      <h3 className="mb-3 flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.14em] text-muted-foreground">
        <Icon className="h-3.5 w-3.5 text-primary" /> {title}
      </h3>
      {children}
    </motion.section>
  );
}

function Metric({ label, value, sub, tone }: { label: string; value: string | number; sub?: string; tone?: string }) {
  return (
    <div className="rounded-2xl border border-border/60 bg-background/50 px-4 py-3">
      <p className="text-[9px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">{label}</p>
      <p className={`mt-1 font-mono text-xl font-bold ${tone ?? "text-foreground"}`}>{value}</p>
      {sub && <p className="mt-0.5 text-[10px] text-muted-foreground">{sub}</p>}
    </div>
  );
}

function ExecutivePage() {
  const { active, components } = useWorkbench();

  const report = useMemo(() => {
    if (!active) return null;
    const risks = assessAll(components.map((c) => ({ id: c.id, data: c.data })));
    return buildExecReport(active.name, risks);
  }, [active, components]);

  if (!active) return <NoDataset />;
  if (!report) return null;

  const sevData = (["critical", "high", "medium", "low", "info"] as Sev[])
    .map((s) => ({ name: s, value: report.severity[s], fill: SEV_TONE[s].fill }))
    .filter((d) => d.value > 0);

  const gauge = [{ name: "risk", value: report.cyberRiskScore, fill: SEV_TONE[report.riskBand.tone].fill }];

  return (
    <>
      {/* ── Terminal header ─────────────────────────────────────────────── */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated overflow-hidden border border-border/60">
        <div className="flex flex-wrap items-start justify-between gap-4 bg-gradient-to-r from-primary/10 via-severity-info/10 to-transparent p-6">
          <div>
            <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-primary">Enterprise SBOM Intelligence Engine</p>
            <h1 className="mt-1 text-2xl font-bold tracking-tight">Executive Intelligence Report</h1>
            <p className="mt-1 text-xs text-muted-foreground">
              {active.name} · {report.totals.components} components · {report.totals.suppliers} suppliers · generated {new Date(report.generatedAt).toUTCString()}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" className="rounded-xl" onClick={() => { void exportReportXlsx(report); toast.success("Excel workbook generated (13 sheets)"); }}>
              <FileSpreadsheet className="mr-1 h-3.5 w-3.5" /> Excel
            </Button>
            <Button size="sm" variant="outline" className="rounded-xl" onClick={() => { exportReportJson(report); toast.success("JSON report downloaded"); }}>
              <FileJson className="mr-1 h-3.5 w-3.5" /> JSON
            </Button>
            <Button size="sm" variant="outline" className="rounded-xl" onClick={() => { exportReportCsv(report); toast.success("CSV downloaded"); }}>
              <FileText className="mr-1 h-3.5 w-3.5" /> CSV
            </Button>
            <Button size="sm" variant="outline" className="rounded-xl" onClick={() => { exportReportMarkdown(report); toast.success("Markdown report downloaded"); }}>
              <FileCode2 className="mr-1 h-3.5 w-3.5" /> Markdown
            </Button>
            <Button size="sm" className="rounded-xl bg-gradient-to-r from-primary to-severity-info" onClick={() => { exportReportPdf(report); toast.success("PDF executive report generated"); }}>
              <Download className="mr-1 h-3.5 w-3.5" /> PDF
            </Button>
          </div>
        </div>

        <div className="grid gap-3 border-t border-border/60 p-5 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6">
          <Metric label="Cyber Risk Score" value={`${report.cyberRiskScore}/100`} sub={report.riskBand.label} tone={SEV_TONE[report.riskBand.tone].text} />
          <Metric label="SBOM Quality" value={`${report.sbomQualityScore}/100`} sub={`${report.completenessScore}% complete`} />
          <Metric label="Confidence" value={`${report.confidenceScore}%`} sub={`${report.totals.estimated} estimated`} />
          <Metric label="Exploitability" value={`${report.exploitability}%`} />
          <Metric label="Attack Surface" value={`${report.attackSurface}%`} />
          <Metric label="Package Freshness" value={`${report.packageFreshness}%`} />
          <Metric label="Critical" value={report.severity.critical} tone={SEV_TONE.critical.text} />
          <Metric label="High" value={report.severity.high} tone={SEV_TONE.high.text} />
          <Metric label="Medium" value={report.severity.medium} tone={SEV_TONE.medium.text} />
          <Metric label="Low" value={report.severity.low} tone={SEV_TONE.low.text} />
          <Metric label="Risk Concentration" value={`${report.riskConcentration}%`} />
          <Metric label="Vendor Concentration" value={`${report.vendorConcentration}%`} sub={report.topVendors[0]?.key} />
        </div>
      </motion.div>

      {/* ── Summary + gauge ─────────────────────────────────────────────── */}
      <section className="grid gap-5 lg:grid-cols-[1.6fr_1fr]">
        <Panel title="Executive Summary" icon={ScrollText}>
          <ul className="space-y-2 text-sm leading-relaxed text-foreground/90">
            {report.executiveSummary.map((s, i) => (
              <li key={i} className="flex gap-2"><span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />{s}</li>
            ))}
          </ul>
          <h4 className="mt-5 mb-2 text-[11px] font-bold uppercase tracking-[0.14em] text-muted-foreground">Business Impact</h4>
          <ul className="space-y-2 text-sm text-foreground/90">
            {report.businessImpact.map((s, i) => (
              <li key={i} className="flex gap-2"><span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-severity-high" />{s}</li>
            ))}
          </ul>
        </Panel>

        <div className="space-y-5">
          <Panel title="Overall Cyber Risk" icon={Gauge}>
            <div className="relative h-44">
              <ResponsiveContainer width="100%" height="100%">
                <RadialBarChart data={gauge} innerRadius="70%" outerRadius="100%" startAngle={210} endAngle={-30}>
                  <RadialBar dataKey="value" background cornerRadius={12} />
                </RadialBarChart>
              </ResponsiveContainer>
              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                <span className={`font-mono text-3xl font-bold ${SEV_TONE[report.riskBand.tone].text}`}>{report.cyberRiskScore}</span>
                <span className="text-[10px] uppercase tracking-widest text-muted-foreground">{report.riskBand.label}</span>
              </div>
            </div>
          </Panel>
          <Panel title="Severity Distribution" icon={ShieldAlert}>
            <div className="h-40">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={38} outerRadius={64} paddingAngle={3}>
                    {sevData.map((d) => <Cell key={d.name} fill={d.fill} />)}
                  </Pie>
                  <RTooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </Panel>
        </div>
      </section>

      {/* ── Compliance + critical findings ───────────────────────────────── */}
      <section className="grid gap-5 lg:grid-cols-2">
        <Panel title="Compliance Status" icon={Scale}>
          <div className="space-y-2">
            {report.complianceStatus.map((c) => {
              const tone = c.status === "Non-Compliant" ? SEV_TONE.critical : c.status === "At Risk" ? SEV_TONE.medium : SEV_TONE.low;
              return (
                <div key={c.framework} className={`rounded-xl border ${tone.border} ${tone.bg} px-3 py-2`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold">{c.framework}</span>
                    <span className={`chip border ${tone.border} ${tone.text} text-[9px]`}>{c.status}</span>
                  </div>
                  <p className="mt-1 text-[11px] text-muted-foreground">{c.finding}</p>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel title="Critical Findings" icon={AlertTriangle}>
          <div className="space-y-1.5">
            {report.criticalFindings.length === 0 && <p className="text-xs text-muted-foreground">No critical findings — residual risk is documented below.</p>}
            {report.criticalFindings.map((f, i) => (
              <div key={i} className="rounded-lg border border-severity-critical/30 bg-severity-critical/5 px-3 py-2 text-[11px] leading-relaxed">{f}</div>
            ))}
          </div>
        </Panel>
      </section>

      {/* ── Action roadmap ──────────────────────────────────────────────── */}
      <section className="grid gap-5 md:grid-cols-3">
        {([
          ["Immediate Actions (0–7 days)", report.actions.immediate, SEV_TONE.critical],
          ["Short-Term (30 days)", report.actions.shortTerm, SEV_TONE.high],
          ["Long-Term (90+ days)", report.actions.longTerm, SEV_TONE.info],
        ] as const).map(([title, items, tone]) => (
          <Panel key={title} title={title} icon={Clock}>
            <ol className="space-y-1.5 text-[11px]">
              {items.length === 0 && <li className="text-muted-foreground">Nothing outstanding.</li>}
              {items.map((s, i) => (
                <li key={i} className={`rounded-lg border ${tone.border} ${tone.bg} px-3 py-2`}>{s}</li>
              ))}
            </ol>
          </Panel>
        ))}
      </section>

      {/* ── Top 10 tables ───────────────────────────────────────────────── */}
      <section className="grid gap-5 lg:grid-cols-2">
        <Panel title="Top 10 Critical Components" icon={Boxes}>
          <div className="space-y-1.5">
            {report.topCriticalComponents.map((c) => {
              const tone = SEV_TONE[c.severity];
              return (
                <div key={c.id} className="rounded-lg border border-border/40 bg-background/40 px-3 py-2">
                  <div className="flex flex-wrap items-center gap-2 text-[11px]">
                    <span className={`chip border ${tone.border} ${tone.bg} ${tone.text} text-[9px]`}>{c.estimated ? "EST " : ""}{c.severity.toUpperCase()}</span>
                    <span className="font-medium">{c.name}</span>
                    <span className="text-muted-foreground">{c.version || "version unknown"}</span>
                    <span className={`ml-auto font-mono font-semibold ${tone.text}`}>{c.score}</span>
                    <span className="font-mono text-[10px] text-muted-foreground">conf {c.confidence}%</span>
                  </div>
                  <p className="mt-1 text-[10px] leading-relaxed text-muted-foreground">{c.rationale}</p>
                </div>
              );
            })}
          </div>
        </Panel>

        <div className="space-y-5">
          <Panel title="Top 10 Vulnerabilities" icon={ShieldAlert}>
            <div className="space-y-1.5">
              {report.topVulnerabilities.length === 0 && <p className="text-xs text-muted-foreground">No vulnerability identifiers supplied — see estimated severities.</p>}
              {report.topVulnerabilities.map((v, i) => {
                const tone = SEV_TONE[v.severity];
                return (
                  <div key={i} className="flex items-center gap-2 rounded-lg border border-border/40 bg-background/40 px-3 py-2 text-[11px]">
                    <span className={`chip border ${tone.border} ${tone.text} text-[9px]`}>{v.estimated ? "EST" : v.severity.toUpperCase()}</span>
                    <span className="font-mono">{v.cve}</span>
                    <span className="truncate text-muted-foreground">{v.component} {v.version}</span>
                    <span className={`ml-auto font-mono font-semibold ${tone.text}`}>{v.cvss || "—"}</span>
                  </div>
                );
              })}
            </div>
          </Panel>

          <Panel title="Top 10 Vendors at Risk" icon={Building2}>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={report.topVendors.map((v) => ({ name: v.key.slice(0, 16), value: +v.score.toFixed(1) }))}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                  <XAxis dataKey="name" tick={{ fontSize: 9 }} interval={0} angle={-25} textAnchor="end" height={50} />
                  <YAxis tick={{ fontSize: 9 }} />
                  <RTooltip />
                  <Bar dataKey="value" radius={[6, 6, 0, 0]} fill="hsl(210 90% 52%)" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Panel>
        </div>
      </section>

      {/* ── Risk heatmap + statistics ───────────────────────────────────── */}
      <section className="grid gap-5 lg:grid-cols-2">
        <Panel title="Risk Heatmap — Applications" icon={Sparkles}>
          <div className="overflow-x-auto">
            <table className="w-full text-[11px]">
              <thead>
                <tr className="border-b border-border/60 text-[9px] uppercase tracking-wider text-muted-foreground">
                  <th className="px-2 py-1.5 text-left">Application</th>
                  {(["critical", "high", "medium", "low", "info"] as Sev[]).map((s) => <th key={s} className="px-2 py-1.5">{s.slice(0, 4)}</th>)}
                </tr>
              </thead>
              <tbody>
                {report.heatmap.map((h) => (
                  <tr key={h.application} className="border-b border-border/30">
                    <td className="max-w-[180px] truncate px-2 py-1.5">{h.application}</td>
                    {(["critical", "high", "medium", "low", "info"] as Sev[]).map((s) => (
                      <td key={s} className="px-1 py-1 text-center">
                        <span className={`inline-block min-w-6 rounded px-1.5 py-0.5 font-mono ${h[s] ? `${SEV_TONE[s].bg} ${SEV_TONE[s].text}` : "text-muted-foreground/40"}`}>{h[s] || "·"}</span>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-1">
          <Panel title="License Statistics" icon={Scale}>
            <div className="space-y-1">
              {report.licenseStats.map((l) => (
                <div key={l.key} className="flex items-center gap-2 text-[11px]">
                  <span className="truncate">{l.key}</span>
                  <span className="ml-auto font-mono text-muted-foreground">{l.count}</span>
                </div>
              ))}
            </div>
          </Panel>
          <Panel title="Security Loopholes & SBOM Gaps" icon={AlertTriangle}>
            <div className="space-y-1.5">
              {report.loopholes.map((l) => {
                const tone = SEV_TONE[l.impact];
                return (
                  <div key={l.title} className={`rounded-lg border ${tone.border} ${tone.bg} px-3 py-2`}>
                    <div className="flex items-center gap-2 text-[11px] font-medium">
                      {l.title}<span className={`ml-auto font-mono ${tone.text}`}>{l.count}</span>
                    </div>
                    <p className="mt-0.5 text-[10px] text-muted-foreground">{l.detail}</p>
                  </div>
                );
              })}
            </div>
          </Panel>
        </div>
      </section>

      {/* ── Recommendations ─────────────────────────────────────────────── */}
      <Panel title="Remediation, Patch & Upgrade Recommendations" icon={ScrollText}>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-1.5">
            {report.recommendations.slice(0, 18).map((r, i) => (
              <div key={i} className="flex gap-2 rounded-lg border border-border/40 bg-background/40 px-3 py-2 text-[11px]">
                <span className="chip border border-primary/40 text-[9px] text-primary">{r.priority}</span>
                <span>{r.text}</span>
              </div>
            ))}
          </div>
          <div className="overflow-hidden rounded-xl border border-border/40">
            <table className="w-full text-[11px]">
              <thead className="bg-accent/30 text-[9px] uppercase tracking-wider text-muted-foreground">
                <tr><th className="px-2 py-1.5 text-left">Component</th><th className="px-2 py-1.5 text-left">Current</th><th className="px-2 py-1.5 text-left">Target</th><th className="px-2 py-1.5">Priority</th></tr>
              </thead>
              <tbody>
                {report.patchRecommendations.slice(0, 12).map((p, i) => (
                  <tr key={i} className="border-t border-border/30">
                    <td className="px-2 py-1.5">{p.component}</td>
                    <td className="px-2 py-1.5 font-mono text-muted-foreground">{p.from}</td>
                    <td className="px-2 py-1.5 font-mono">{p.to}</td>
                    <td className="px-2 py-1.5 text-center font-mono text-primary">{p.priority}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <p className="mt-4 rounded-xl border border-border/50 bg-accent/20 p-3 text-[10px] leading-relaxed text-muted-foreground">
          <strong className="text-foreground">Method & confidence.</strong> Every uploaded file is auto-detected, normalized into one internal SBOM model
          (identifiers, hashes, licences, references, relationships) and de-duplicated. Components carrying CVE/CVSS evidence are scored from that evidence;
          all others are classified with an <strong className="text-foreground">Estimated Severity</strong> derived from version age, support status,
          package criticality (crypto/auth/kernel/network), identifiability, linkage, dependency depth and licence exposure — never reported as
          "no vulnerability information available". Report confidence for this dataset is {report.confidenceScore}%.
        </p>
      </Panel>
    </>
  );
}
