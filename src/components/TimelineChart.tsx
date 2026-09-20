import { useMemo } from "react";
import {
  Area, Bar, CartesianGrid, ComposedChart, Legend, Line, ReferenceLine,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { CalendarRange } from "lucide-react";
import { timelineSeries, type NistFinding } from "@/lib/date-intel";

/**
 * Vulnerability & lifecycle timeline: CVE publications, exploit publications and
 * EOL milestones by month, from 12 months back to 12 months ahead. Past months
 * shaded as the red zone, the next 3 months as the amber (approaching) zone.
 */
export function TimelineChart({ findings }: { findings: NistFinding[] }) {
  const now = useMemo(() => new Date(), []);
  const data = useMemo(() => timelineSeries(findings, now), [findings, now]);

  const stats = useMemo(() => {
    const ages = findings.map((f) => f.cveAgeDays).filter((v): v is number => v != null);
    const toEol = findings.map((f) => f.daysToEol).filter((v): v is number => v != null);
    const busiest = [...data].sort((a, b) => b.cves + b.eolMilestones - (a.cves + a.eolMilestones))[0];
    return {
      avgAge: ages.length ? Math.round(ages.reduce((s, v) => s + v, 0) / ages.length) : 0,
      avgToEol: toEol.length ? Math.round(toEol.reduce((s, v) => s + v, 0) / toEol.length) : 0,
      cluster: busiest && busiest.cves + busiest.eolMilestones > 0
        ? `${busiest.month} (${busiest.cves} CVE, ${busiest.eolMilestones} EOL)`
        : "No clustered events",
      pastEol: findings.filter((f) => f.daysPastEol != null).length,
      soonEol: findings.filter((f) => f.daysToEol != null && f.daysToEol <= 90).length,
    };
  }, [findings, data]);

  const currentMonth = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;

  return (
    <section className="card-elevated border border-border/60 p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <CalendarRange className="h-4 w-4 text-primary" /> Vulnerability & lifecycle timeline
          </h2>
          <p className="mt-0.5 text-[11px] text-muted-foreground">
            CVE publications, public exploits and end-of-life milestones by month · 12 months back to 12 months ahead
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5 text-[10px] font-semibold">
          <span className="chip border border-severity-critical/40 bg-severity-critical/15 text-severity-critical">Past EOL · {stats.pastEol}</span>
          <span className="chip border border-severity-medium/40 bg-severity-medium/15 text-severity-medium">EOL ≤ 90 days · {stats.soonEol}</span>
        </div>
      </div>

      <div className="mt-4 h-72 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
            <defs>
              <linearGradient id="cveArea" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.35} />
                <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
            <XAxis dataKey="month" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" interval={1} />
            <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" allowDecimals={false} />
            <Tooltip
              contentStyle={{
                background: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: 12,
                fontSize: 11,
              }}
            />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            <ReferenceLine x={currentMonth} stroke="hsl(var(--primary))" strokeDasharray="4 4" label={{ value: "today", fontSize: 10 }} />
            <Area type="monotone" dataKey="cves" name="CVEs published" stroke="hsl(var(--primary))" fill="url(#cveArea)" strokeWidth={2} />
            <Bar dataKey="eolMilestones" name="EOL milestones" fill="hsl(var(--severity-critical))" radius={[3, 3, 0, 0]} barSize={10} />
            <Line type="monotone" dataKey="criticalCves" name="Critical CVEs" stroke="hsl(var(--severity-critical))" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="exploits" name="Exploits published" stroke="hsl(var(--severity-high))" strokeWidth={2} dot={{ r: 2 }} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>

      <div className="mt-3 grid gap-2 sm:grid-cols-3">
        {[
          { l: "Average vulnerability age", v: `${stats.avgAge.toLocaleString()} days` },
          { l: "Average days to EOL remaining", v: `${stats.avgToEol.toLocaleString()} days` },
          { l: "Busiest month", v: stats.cluster },
        ].map((s) => (
          <div key={s.l} className="rounded-xl border border-border/60 bg-muted/30 px-3 py-2">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{s.l}</div>
            <div className="mt-0.5 text-sm font-semibold">{s.v}</div>
          </div>
        ))}
      </div>
    </section>
  );
}
