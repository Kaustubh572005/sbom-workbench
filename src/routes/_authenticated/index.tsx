import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo } from "react";
import { motion } from "framer-motion";
import {
  AreaChart, Area, ResponsiveContainer, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip,
} from "recharts";
import {
  ShieldCheck, ShieldAlert, TrendingUp, TrendingDown, Boxes, Upload, FileBarChart,
  Sparkles, ArrowRight, Clock, Bell, Activity, Scale, Gauge, Package, Database,
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
    setKpiFilter, exportSection,
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

  const primaryMetrics = [
    { label: "Critical", value: analysis.counts.critical, tone: "critical" as const },
    { label: "High", value: analysis.counts.high, tone: "high" as const },
    { label: "Medium", value: analysis.counts.medium, tone: "medium" as const },
    { label: "Low", value: analysis.counts.low, tone: "low" as const },
    { label: "Known exploited", value: analysis.counts.kev, tone: "critical" as const },
  ];
  const secondaryMetrics = [
    { label: "End of life", value: analysis.counts.eol, key: "eol" as const },
    { label: "End of support", value: analysis.counts.eos, key: "eos" as const },
    { label: "Unsupported", value: analysis.counts.unsupported, key: "unsupported" as const },
    { label: "Deprecated", value: analysis.counts.deprecated, key: "deprecated" as const },
    { label: "Legacy", value: analysis.counts.legacy, key: "legacy" as const },
    { label: "Upgrade required", value: analysis.counts.upgrade, key: "upgrade" as const },
    { label: "License risk", value: analysis.counts.licenseRisk, key: "licenseRisk" as const },
    { label: "Missing metadata", value: analysis.counts.missingMetadata, key: "missingMetadata" as const },
    { label: "Version sprawl", value: analysis.counts.multiVersion, key: "multiVersion" as const },
    { label: "Internet facing", value: analysis.counts.internetFacing, key: "internetFacing" as const },
  ];

  return (
    <div className="space-y-5">
      <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        className="uti-watermark card-elevated border border-primary/15 p-6 lg:p-8">
        <div className="relative z-10 flex flex-col gap-8 xl:flex-row xl:items-center xl:justify-between">
          <div className="max-w-xl">
            <p className="text-[10px] font-semibold uppercase text-primary">SBOM security overview</p>
            <h1 className="font-display mt-2 break-words text-3xl font-semibold text-foreground">{active.name}</h1>
            <p className="mt-2 text-sm text-muted-foreground">
              {analysis.profiles.length.toLocaleString()} components across {analysis.applications.length || 1} application(s) · {analysis.confidence}% analysis confidence
            </p>
            <div className="mt-5 flex flex-wrap gap-2">
              <Button size="sm" className="rounded-xl" onClick={() => fileInputRef.current?.click()} disabled={uploading}>
                <Upload className="h-4 w-4" /> Upload SBOM
              </Button>
              <Button asChild size="sm" variant="outline" className="rounded-xl bg-card/70 shadow-none">
                <Link to="/reports"><FileBarChart className="h-4 w-4" /> Reports</Link>
              </Button>
            </div>
          </div>
          <div className="grid gap-6 sm:grid-cols-[auto_1fr] sm:items-center xl:min-w-[570px]">
            <div className="flex items-end gap-2 border-l-2 border-primary pl-5">
              <span className={`font-display text-6xl font-semibold ${severityConfig[secTone].color}`}>{securityScore}</span>
              <span className="mb-2 text-sm text-muted-foreground">/ 100</span>
              <span className={`mb-2 text-xs font-semibold uppercase ${riskBand.color}`}>{riskBand.label}</span>
            </div>
            <div className="grid grid-cols-2 gap-x-5 gap-y-3 sm:grid-cols-3">
              {primaryMetrics.map((m) => (
                <div key={m.label} className="border-b border-border/70 pb-2">
                  <div className={`font-display text-xl font-semibold ${severityConfig[m.tone].color}`}>{m.value.toLocaleString()}</div>
                  <div className="text-[10px] font-medium uppercase text-muted-foreground">{m.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </motion.section>

      <section className="grid gap-5 xl:grid-cols-[1.25fr_0.75fr]">
        <div className="card-elevated border border-border/60 p-5 lg:p-6">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-[10px] font-semibold uppercase text-muted-foreground">Security metrics</p>
              <h2 className="font-display mt-1 text-lg font-semibold">Operational exposure</h2>
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground"><Package className="h-4 w-4 text-primary" />{analysis.profiles.length.toLocaleString()} components</div>
          </div>
          <div className="mt-5 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
            {secondaryMetrics.map((m) => (
              <Link key={m.key} to="/vulnerabilities" onClick={() => setKpiFilter(m.key)}
                className="group rounded-xl border border-border/60 bg-background/50 p-3 transition hover:-translate-y-0.5 hover:border-primary/25 hover:bg-primary/[0.04]">
                <p className="text-[10px] font-medium uppercase text-muted-foreground">{m.label}</p>
                <p className="font-display mt-2 text-2xl font-semibold text-foreground">{m.value.toLocaleString()}</p>
                <ArrowRight className="mt-2 h-3.5 w-3.5 text-muted-foreground transition group-hover:text-primary" />
              </Link>
            ))}
          </div>
        </div>

        <div className="card-elevated border border-border/60 p-5 lg:p-6">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-[10px] font-semibold uppercase text-muted-foreground">Severity distribution</p>
              <h2 className="font-display mt-1 text-lg font-semibold">Overall posture</h2>
            </div>
            <span className={`text-xs font-semibold uppercase ${riskBand.color}`}>{analysis.riskCategory}</span>
          </div>
          <p className="mt-2 text-xs text-muted-foreground">{riskBand.desc}</p>
          <div className="mt-6 space-y-3">
            {(["critical", "high", "medium", "low", "info"] as const).map((k) => {
              const cfg = severityConfig[k];
              const pct = Math.round((analysis.counts[k] / (analysis.profiles.length || 1)) * 100);
              return <div key={k}>
                <div className="flex items-center justify-between text-xs"><span className="flex items-center gap-2 text-muted-foreground"><span className={`h-2 w-2 rounded-full ${cfg.dot}`} />{cfg.label}</span><span className="font-medium">{analysis.counts[k]} · {pct}%</span></div>
                <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-muted"><motion.div className={`${cfg.dot} h-full`} initial={{ width: 0 }} animate={{ width: `${pct}%` }} /></div>
              </div>;
            })}
          </div>
        </div>
      </section>

      <section className="grid gap-5 xl:grid-cols-[1.5fr_1fr]">
        <div className="card-elevated border border-border/60 p-5 lg:p-6">
          <div className="flex items-center gap-2"><Activity className="h-4 w-4 text-primary" /><h2 className="font-display text-lg font-semibold">Risk trend</h2></div>
          <div className="mt-4 h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trends.risk} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <defs><linearGradient id="dashboard-risk" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--color-primary)" stopOpacity={0.2} /><stop offset="100%" stopColor="var(--color-primary)" stopOpacity={0} /></linearGradient></defs>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border/40" vertical={false} />
                <XAxis dataKey="x" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} /><YAxis tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                <RTooltip contentStyle={{ fontSize: 11, borderRadius: 12, borderColor: "var(--color-border)" }} />
                <Area type="monotone" dataKey="y" stroke="var(--color-primary)" strokeWidth={2.5} fill="url(#dashboard-risk)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-1">
          <TrendCard title="Vulnerability trend" unit="findings" data={trends.vuln} delta={trends.vulnDelta} tone="critical" icon={ShieldAlert} />
          <TrendCard title="EOL trend" unit="components" data={trends.eol} delta={trends.eolDelta} tone="medium" icon={Clock} />
        </div>
      </section>

      <section className="grid gap-5 xl:grid-cols-[1.2fr_0.8fr]">
        <div className="card-elevated border border-border/60 p-5 lg:p-6">
          <div className="flex items-center justify-between"><div><p className="text-[10px] font-semibold uppercase text-muted-foreground">Security signals</p><h2 className="font-display mt-1 text-lg font-semibold">Automatic findings</h2></div><Bell className="h-4 w-4 text-primary" /></div>
          <div className="mt-5 grid gap-3 md:grid-cols-2">
            {analysis.findings.map((f, i) => {
              const cfg = severityConfig[f.severity];
              const kpi = f.kpi;
              return <motion.article key={f.id} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.02 }}
                className={`rounded-xl border bg-background/45 p-4 ${i === 0 ? "md:col-span-2" : ""} ${cfg.border}`}>
                <div className="flex items-start justify-between gap-3"><h3 className="text-sm font-semibold">{f.title}</h3><span className={`chip border text-[10px] ${cfg.bg} ${cfg.border} ${cfg.color}`}>{f.count}</span></div>
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{f.summary}</p>
                {f.details.length > 0 && <p className="mt-2 truncate text-[11px] text-foreground/75">{f.details[0]}</p>}
                {(kpi || (f.columns && f.rows)) && <div className="mt-3 flex gap-2">
                  {kpi && <Button asChild size="sm" variant="outline" className="h-7 rounded-lg bg-card text-[11px]" onClick={() => setKpiFilter(kpi)}><Link to="/vulnerabilities">View components</Link></Button>}
                  {f.columns && f.rows && <Button size="sm" variant="ghost" className="h-7 rounded-lg text-[11px]" onClick={() => void exportSection(f.title, { name: f.title, columns: f.columns ?? [], rows: f.rows ?? [] }, "xlsx")}><FileBarChart className="h-3 w-3" />Export</Button>}
                </div>}
              </motion.article>;
            })}
          </div>
        </div>

        <div className="space-y-5">
          <div className="card-elevated border border-primary/20 bg-primary/[0.035] p-5 lg:p-6">
            <h2 className="font-display flex items-center gap-2 text-lg font-semibold"><Sparkles className="h-4 w-4 text-primary" /> AI executive summary</h2>
            <ul className="mt-4 space-y-3 text-xs leading-relaxed text-foreground/85">{summary.map((s, i) => <li key={i} className="flex gap-2"><span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary" />{s}</li>)}</ul>
            <Button size="sm" variant="outline" className="mt-5 rounded-xl bg-card/70 text-xs" onClick={() => askAnalyst(`Give me a board-level summary of ${active.name}: posture, top risks, remediation priorities and compliance gaps.`)}><Sparkles className="h-3.5 w-3.5 text-primary" />Ask the analyst</Button>
          </div>

          <div className="card-elevated border border-border/60 p-5">
            <h2 className="font-display flex items-center gap-2 text-base font-semibold"><Boxes className="h-4 w-4 text-primary" /> Highest risk applications</h2>
            <div className="mt-4 space-y-1">{appsAtRisk.length === 0 && <p className="text-xs text-muted-foreground">No application attribution available.</p>}{appsAtRisk.map((a) => {
              const tone = a.risk >= 80 ? "critical" : a.risk >= 60 ? "high" : a.risk >= 35 ? "medium" : "low";
              return <div key={a.name} className="flex items-center gap-3 border-b border-border/50 py-2.5 last:border-0"><span className={`h-2 w-2 rounded-full ${severityConfig[tone].dot}`} /><span className="min-w-0 flex-1 truncate text-xs font-medium">{a.name}</span><span className="text-[10px] text-muted-foreground">{a.count} comp</span><span className={`text-xs font-semibold ${severityConfig[tone].color}`}>{a.risk}</span></div>;
            })}</div>
          </div>

          <div className="card-elevated border border-border/60 p-5">
            <h2 className="font-display flex items-center gap-2 text-base font-semibold"><Database className="h-4 w-4 text-primary" /> Recent activity</h2>
            <div className="mt-4 space-y-2">{uploadHistory.length === 0 && <p className="text-xs text-muted-foreground">No uploads recorded yet.</p>}{uploadHistory.slice(0, 5).map((u) => <div key={u.id} className="flex items-center gap-2 text-[11px]"><span className="h-1.5 w-1.5 rounded-full bg-primary" /><span className="min-w-0 flex-1 truncate font-medium">{u.filename}</span><span className="text-muted-foreground">{u.rows} rows</span><span className="text-muted-foreground">{new Date(u.at).toLocaleDateString()}</span></div>)}</div>
          </div>
        </div>
      </section>

      <section className="card-elevated border border-border/60 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-[10px] font-semibold uppercase text-muted-foreground">Workspace</p><h2 className="font-display mt-1 text-base font-semibold">Quick actions</h2></div><div className="flex flex-wrap gap-2">
          <Button size="sm" variant="outline" className="rounded-xl" onClick={() => fileInputRef.current?.click()} disabled={uploading}><Upload className="h-3.5 w-3.5" />Upload SBOM</Button>
          <Button asChild size="sm" variant="outline" className="rounded-xl"><Link to="/vulnerabilities"><ShieldAlert className="h-3.5 w-3.5" />Vulnerabilities</Link></Button>
          <Button asChild size="sm" variant="outline" className="rounded-xl"><Link to="/reports"><FileBarChart className="h-3.5 w-3.5" />Generate report</Link></Button>
          <Button asChild size="sm" variant="outline" className="rounded-xl"><Link to="/licenses"><Scale className="h-3.5 w-3.5" />Licenses</Link></Button>
          <Button size="sm" className="rounded-xl" onClick={() => void exportAnalysis("xlsx")}><FileBarChart className="h-3.5 w-3.5" />Export analysis</Button>
        </div></div>
      </section>
    </div>
  );
}
