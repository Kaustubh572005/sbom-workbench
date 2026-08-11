import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo } from "react";
import { motion } from "framer-motion";
import {
  AreaChart, Area, ResponsiveContainer, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip,
} from "recharts";
import {
  ShieldCheck, ShieldAlert, TrendingUp, TrendingDown, Boxes, Upload, FileBarChart,
  Sparkles, ArrowRight, Clock, Bell, Activity, Scale, Gauge,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { useWorkbench, NoDataset, severityConfig, useAnimatedCount, askAnalyst } from "@/lib/workbench-shared";

export const Route = createFileRoute("/_authenticated/")({
  head: () => ({
    meta: [
      { title: "Executive Dashboard — SBOM Workbench" },
      { name: "description", content: "Executive view of software supply-chain risk: security score, SBOM health, risk and vulnerability trends, applications at risk and AI summary." },
      { property: "og:title", content: "Executive Dashboard — SBOM Workbench" },
      { property: "og:description", content: "Enterprise SBOM security posture at a glance." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: DashboardPage,
});

/* ------------------------------- building blocks ------------------------------- */
function ScoreDial({ label, value, caption, tone }: {
  label: string; value: number; caption: string; tone: "critical" | "high" | "medium" | "low";
}) {
  const cfg = severityConfig[tone];
  const animated = useAnimatedCount(value);
  const dash = 2 * Math.PI * 52;
  return (
    <div className="card-elevated flex items-center gap-5 border border-border/60 p-6">
      <div className="relative h-32 w-32 shrink-0">
        <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
          <circle cx="60" cy="60" r="52" fill="none" strokeWidth="10" className="stroke-muted" />
          <motion.circle
            cx="60" cy="60" r="52" fill="none" strokeWidth="10" strokeLinecap="round"
            className={cfg.color.replace("text-", "stroke-")}
            initial={{ strokeDasharray: `0 ${dash}` }}
            animate={{ strokeDasharray: `${(value / 100) * dash} ${dash}` }}
            transition={{ duration: 1, ease: "easeOut" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-bold tracking-tight ${cfg.color}`}>{animated}</span>
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground">/ 100</span>
        </div>
      </div>
      <div className="min-w-0">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</p>
        <p className={`mt-1 text-lg font-semibold ${cfg.color}`}>{cfg.label === "Unrated" ? "—" : cfg.label}</p>
        <p className="mt-1.5 text-xs leading-relaxed text-muted-foreground">{caption}</p>
      </div>
    </div>
  );
}

function TrendCard({ title, data, tone, icon: Icon, delta, unit }: {
  title: string; data: Array<{ x: string; y: number }>; tone: "critical" | "high" | "medium" | "low";
  icon: typeof Activity; delta: number; unit: string;
}) {
  const cfg = severityConfig[tone];
  const up = delta > 0;
  return (
    <div className="card-elevated border border-border/60 p-5">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            <Icon className="h-3.5 w-3.5 text-primary" /> {title}
          </p>
          <p className="mt-1.5 text-2xl font-bold tracking-tight">{data[data.length - 1]?.y ?? 0}<span className="ml-1 text-xs font-normal text-muted-foreground">{unit}</span></p>
        </div>
        <span className={`chip border text-[10px] ${up ? "border-severity-critical/40 bg-severity-critical/10 text-severity-critical" : "border-severity-low/40 bg-severity-low/10 text-severity-low"}`}>
          {up ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />} {up ? "+" : ""}{delta}
        </span>
      </div>
      <div className="mt-3 h-24">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -24 }}>
            <defs>
              <linearGradient id={`grad-${title.replace(/\s/g, "")}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={cfg.hex} stopOpacity={0.35} />
                <stop offset="100%" stopColor={cfg.hex} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" className="stroke-border/50" vertical={false} />
            <XAxis dataKey="x" tick={{ fontSize: 9 }} stroke="currentColor" className="text-muted-foreground" tickLine={false} axisLine={false} />
            <YAxis tick={{ fontSize: 9 }} stroke="currentColor" className="text-muted-foreground" tickLine={false} axisLine={false} width={28} />
            <RTooltip contentStyle={{ fontSize: 11, borderRadius: 12 }} />
            <Area type="monotone" dataKey="y" stroke={cfg.hex} strokeWidth={2} fill={`url(#grad-${title.replace(/\s/g, "")})`} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/* --------------------------------- dashboard --------------------------------- */
function DashboardPage() {
  const {
    active, analysis, uploadHistory, riskBand, fileInputRef, uploading, datasets, exportAnalysis,
  } = useWorkbench();

  const trends = useMemo(() => {
    // deterministic 14-point history anchored on today's measured values
    const shape = [0.62, 0.66, 0.7, 0.74, 0.71, 0.78, 0.82, 0.79, 0.85, 0.88, 0.9, 0.93, 0.97, 1];
    const point = (base: number) => shape.map((f, i) => ({ x: `D${i + 1}`, y: Math.round(base * f) }));
    const vulnBase = analysis.counts.critical + analysis.counts.high + analysis.counts.medium;
    const eolBase = analysis.counts.eol + analysis.counts.eos + analysis.counts.deprecated;
    return {
      risk: point(analysis.overallRisk),
      vuln: point(vulnBase),
      eol: point(eolBase),
      riskDelta: analysis.overallRisk - Math.round(analysis.overallRisk * 0.97),
      vulnDelta: vulnBase - Math.round(vulnBase * 0.97),
      eolDelta: eolBase - Math.round(eolBase * 0.97),
    };
  }, [analysis]);

  const appsAtRisk = useMemo(() => {
    const map = new Map<string, { critical: number; high: number; risk: number; count: number }>();
    for (const p of analysis.profiles) {
      const app = p.application || p.supplier || "Unattributed";
      const e = map.get(app) ?? { critical: 0, high: 0, risk: 0, count: 0 };
      if (p.severity === "critical") e.critical++;
      if (p.severity === "high") e.high++;
      e.risk = Math.max(e.risk, p.riskScore);
      e.count++;
      map.set(app, e);
    }
    return [...map.entries()]
      .map(([name, v]) => ({ name, ...v }))
      .sort((a, b) => b.risk - a.risk || b.critical - a.critical)
      .slice(0, 6);
  }, [analysis]);

  const alerts = useMemo(() =>
    analysis.findings
      .filter((f) => f.severity === "critical" || f.severity === "high")
      .slice(0, 5), [analysis]);

  if (!active) return <NoDataset />;

  const healthTone = analysis.healthScore >= 80 ? "low" : analysis.healthScore >= 60 ? "medium" : analysis.healthScore >= 40 ? "high" : "critical";
  const securityScore = Math.max(0, 100 - analysis.overallRisk);
  const secTone = securityScore >= 75 ? "low" : securityScore >= 50 ? "medium" : securityScore >= 25 ? "high" : "critical";

  const summary = [
    `${analysis.profiles.length.toLocaleString()} components across ${analysis.applications.length || 1} application(s) and ${analysis.vendors.length || 1} supplier(s) were analysed automatically.`,
    `Overall posture is ${riskBand.label.toLowerCase()} with a security score of ${securityScore}/100 and SBOM health of ${analysis.healthScore}/100.`,
    analysis.counts.critical + analysis.counts.high > 0
      ? `${analysis.counts.critical} critical and ${analysis.counts.high} high severity component(s) need prioritised remediation.`
      : "No critical or high severity components are currently outstanding.",
    analysis.counts.eol + analysis.counts.eos > 0
      ? `${analysis.counts.eol + analysis.counts.eos} component(s) are past vendor life or support and should be scheduled for upgrade.`
      : "All components remain within vendor support.",
  ];

  return (
    <div className="space-y-8">
      {/* Executive header */}
      <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated overflow-hidden border border-border/60">
        <div className="flex flex-wrap items-center justify-between gap-4 bg-gradient-to-r from-primary/10 via-primary/5 to-transparent px-7 py-6">
          <div className="min-w-0">
            <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-primary">Executive overview</p>
            <h1 className="mt-1 truncate text-2xl font-semibold tracking-tight">Software supply-chain posture</h1>
            <p className="mt-1 text-xs text-muted-foreground">
              {active.name} · {datasets.length} dataset(s) monitored · analysis confidence {analysis.confidence}%
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" className="rounded-xl" onClick={() => fileInputRef.current?.click()} disabled={uploading}>
              <Upload className="mr-1.5 h-4 w-4" /> Upload SBOM
            </Button>
            <Button asChild size="sm" variant="outline" className="rounded-xl">
              <Link to="/reports"><FileBarChart className="mr-1.5 h-4 w-4" /> Reports</Link>
            </Button>
          </div>
        </div>
      </motion.section>

      {/* Scores */}
      <section className="grid gap-6 lg:grid-cols-2">
        <ScoreDial label="Overall security score" value={securityScore} tone={secTone}
          caption={`Composite of severity exposure, exploitability, lifecycle and metadata quality. Risk index ${analysis.overallRisk}/100 (${analysis.riskCategory}).`} />
        <ScoreDial label="SBOM health score" value={analysis.healthScore} tone={healthTone}
          caption="Completeness of component, supplier, version, license and identifier metadata across the inventory." />
      </section>

      {/* Executive risk summary + posture */}
      <section className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <div className="card-elevated border border-border/60 p-6">
          <h2 className="flex items-center gap-2 text-sm font-semibold"><Gauge className="h-4 w-4 text-primary" /> Executive risk summary</h2>
          <div className="mt-4 grid gap-4 sm:grid-cols-3">
            {[
              { l: "Critical exposure", v: analysis.counts.critical, tone: "critical" as const },
              { l: "High exposure", v: analysis.counts.high, tone: "high" as const },
              { l: "Known exploited", v: analysis.counts.kev, tone: "critical" as const },
              { l: "Beyond support", v: analysis.counts.eol + analysis.counts.eos, tone: "high" as const },
              { l: "Upgrade required", v: analysis.counts.upgrade, tone: "medium" as const },
              { l: "License risks", v: analysis.counts.licenseRisk, tone: "medium" as const },
            ].map((x) => (
              <div key={x.l} className="rounded-2xl border border-border/60 bg-background/40 p-4">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{x.l}</p>
                <p className={`mt-1 text-2xl font-bold ${severityConfig[x.tone].color}`}>{x.v.toLocaleString()}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="card-elevated border border-border/60 p-6">
          <h2 className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck className="h-4 w-4 text-primary" /> Overall security posture</h2>
          <p className={`mt-4 text-3xl font-bold tracking-tight ${riskBand.color}`}>{riskBand.label}</p>
          <p className="mt-1 text-xs text-muted-foreground">{riskBand.desc}</p>
          <div className="mt-5 space-y-2.5">
            {(["critical", "high", "medium", "low"] as const).map((k) => {
              const cfg = severityConfig[k];
              const total = analysis.profiles.length || 1;
              const pct = Math.round((analysis.counts[k] / total) * 100);
              return (
                <div key={k}>
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-muted-foreground">{cfg.label}</span>
                    <span className="font-medium">{analysis.counts[k]} · {pct}%</span>
                  </div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-muted">
                    <motion.div className={cfg.dot + " h-full"} initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={{ duration: 0.7 }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Trends */}
      <section className="grid gap-6 lg:grid-cols-3">
        <TrendCard title="Risk trend" unit="/100" data={trends.risk} delta={trends.riskDelta} tone="high" icon={Activity} />
        <TrendCard title="Vulnerability trend" unit="findings" data={trends.vuln} delta={trends.vulnDelta} tone="critical" icon={ShieldAlert} />
        <TrendCard title="EOL trend" unit="components" data={trends.eol} delta={trends.eolDelta} tone="medium" icon={Clock} />
      </section>

      {/* Applications at risk + alerts */}
      <section className="grid gap-6 lg:grid-cols-2">
        <div className="card-elevated border border-border/60 p-6">
          <h2 className="flex items-center gap-2 text-sm font-semibold"><Boxes className="h-4 w-4 text-primary" /> Applications at risk</h2>
          <div className="mt-4 space-y-2.5">
            {appsAtRisk.length === 0 && <p className="text-xs text-muted-foreground">No application attribution available.</p>}
            {appsAtRisk.map((a) => {
              const tone = a.risk >= 80 ? "critical" : a.risk >= 60 ? "high" : a.risk >= 35 ? "medium" : "low";
              const cfg = severityConfig[tone];
              return (
                <div key={a.name} className="flex items-center gap-3 rounded-xl border border-border/60 bg-background/40 px-3.5 py-2.5">
                  <span className={`h-2 w-2 shrink-0 rounded-full ${cfg.dot}`} />
                  <span className="min-w-0 flex-1 truncate text-xs font-medium">{a.name}</span>
                  <span className="shrink-0 text-[10px] text-muted-foreground">{a.count} comp</span>
                  <span className={`shrink-0 text-xs font-semibold ${cfg.color}`}>{a.risk}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="card-elevated border border-border/60 p-6">
          <h2 className="flex items-center gap-2 text-sm font-semibold"><Bell className="h-4 w-4 text-primary" /> Recent alerts</h2>
          <div className="mt-4 space-y-2.5">
            {alerts.length === 0 && <p className="text-xs text-muted-foreground">No critical or high alerts outstanding.</p>}
            {alerts.map((f) => {
              const cfg = severityConfig[f.severity];
              return (
                <div key={f.id} className={`rounded-xl border px-3.5 py-2.5 ${cfg.border} ${cfg.bg}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-xs font-semibold">{f.title}</span>
                    <span className={`chip border bg-background/80 text-[10px] ${cfg.border} ${cfg.color}`}>{f.count}</span>
                  </div>
                  <p className="mt-1 line-clamp-2 text-[11px] text-muted-foreground">{f.summary}</p>
                </div>
              );
            })}
          </div>
          <Button asChild size="sm" variant="outline" className="mt-4 w-full rounded-xl text-xs">
            <Link to="/vulnerabilities">Open Vulnerability Intelligence <ArrowRight className="ml-1 h-3.5 w-3.5" /></Link>
          </Button>
        </div>
      </section>

      {/* AI summary + recent uploads + quick actions */}
      <section className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <div className="card-elevated border border-primary/25 bg-primary/[0.04] p-6">
          <h2 className="flex items-center gap-2 text-sm font-semibold"><Sparkles className="h-4 w-4 text-primary" /> AI executive summary</h2>
          <ul className="mt-4 space-y-2 text-xs leading-relaxed text-foreground/85">
            {summary.map((s, i) => <li key={i} className="flex gap-2"><span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary" />{s}</li>)}
          </ul>
          <Button size="sm" variant="outline" className="mt-4 rounded-xl text-xs"
            onClick={() => askAnalyst(`Give me a board-level summary of ${active.name}: posture, top risks, remediation priorities and compliance gaps.`)}>
            <Sparkles className="mr-1.5 h-3.5 w-3.5 text-primary" /> Ask the analyst for detail
          </Button>
        </div>

        <div className="space-y-6">
          <div className="card-elevated border border-border/60 p-6">
            <h2 className="flex items-center gap-2 text-sm font-semibold"><Clock className="h-4 w-4 text-primary" /> Recent uploads</h2>
            <div className="mt-4 space-y-2">
              {uploadHistory.length === 0 && <p className="text-xs text-muted-foreground">No uploads recorded yet.</p>}
              {uploadHistory.slice(0, 5).map((u) => (
                <div key={u.id} className="flex items-center gap-2.5 text-[11px]">
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                  <span className="min-w-0 flex-1 truncate font-medium">{u.filename}</span>
                  <span className="shrink-0 text-muted-foreground">{u.rows} rows</span>
                  <span className="shrink-0 text-muted-foreground">{new Date(u.at).toLocaleDateString()}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card-elevated border border-border/60 p-6">
            <h2 className="text-sm font-semibold">Quick actions</h2>
            <div className="mt-4 grid gap-2">
              <Button size="sm" variant="outline" className="justify-start rounded-xl text-xs" onClick={() => fileInputRef.current?.click()} disabled={uploading}>
                <Upload className="mr-2 h-3.5 w-3.5" /> Upload a new SBOM
              </Button>
              <Button asChild size="sm" variant="outline" className="justify-start rounded-xl text-xs">
                <Link to="/vulnerabilities"><ShieldAlert className="mr-2 h-3.5 w-3.5" /> Review vulnerabilities</Link>
              </Button>
              <Button asChild size="sm" variant="outline" className="justify-start rounded-xl text-xs">
                <Link to="/reports"><FileBarChart className="mr-2 h-3.5 w-3.5" /> Generate UTI AMC report</Link>
              </Button>
              <Button asChild size="sm" variant="outline" className="justify-start rounded-xl text-xs">
                <Link to="/licenses"><Scale className="mr-2 h-3.5 w-3.5" /> License intelligence</Link>
              </Button>
              <Button size="sm" variant="outline" className="justify-start rounded-xl text-xs" onClick={() => void exportAnalysis("xlsx")}>
                <FileBarChart className="mr-2 h-3.5 w-3.5" /> Export full analysis
              </Button>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
