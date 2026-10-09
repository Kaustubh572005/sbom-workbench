import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { CalendarClock, Download, Loader2, Search, Info } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useWorkbench, NoDataset, severityConfig, type SeverityKey } from "@/lib/workbench-shared";
import { daysToEol } from "@/lib/lifecycle-dates";
import { eolStage, NOT_PUBLISHED } from "@/lib/combined-export";
import type { ComponentProfile } from "@/lib/platform-intel";

export const Route = createFileRoute("/_authenticated/lifecycle")({
  head: () => ({
    meta: [
      { title: "EOL & EOS Lifecycle — SBOM Workbench" },
      { name: "description", content: "Every component's end-of-life and end-of-support date, with days remaining, source and recommended action." },
      { property: "og:title", content: "EOL & EOS Lifecycle — SBOM Workbench" },
      { property: "og:description", content: "Track end-of-life and end-of-support dates across your SBOM." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: LifecyclePage,
});

const STAGES = ["Past EOL / EOS", "Within 90 days", "Within 1 year", "Supported", "No date published"] as const;
type Stage = (typeof STAGES)[number];
const STAGE_TONE: Record<Stage, SeverityKey> = {
  "Past EOL / EOS": "critical", "Within 90 days": "high", "Within 1 year": "medium", "Supported": "low", "No date published": "info",
};

/** the stage is driven by whichever date comes first: EOL, else EOS */
function stageOf(p: ComponentProfile): Stage {
  // same rule as the dashboard: whichever of EOL / EOS comes first decides, and a status of End of Life / Support counts even without a date
  const days = [daysToEol(p.eolDate), daysToEol(p.eosDate)].filter((n): n is number => n !== null);
  const d = days.length ? Math.min(...days) : null;
  if ((d !== null && d < 0) || /End of Life|End of Support/i.test(p.lifecycleStatus)) return "Past EOL / EOS";
  return eolStage(d) as Stage;
}

type Row = {
  key: string; application: string; component: string; version: string; eol: string; eos: string;
  daysEol: number | null; daysEos: number | null; stage: Stage; source: string; action: string; findings: number;
};

const rel = (d: number | null) => (d === null ? "" : d < 0 ? `${-d} days past` : d === 0 ? "today" : `in ${d} days`);

function LifecyclePage() {
  const { active, analysis, enriching, exportSection } = useWorkbench();
  const [stage, setStage] = useState<Stage | "all">("all");
  const [q, setQ] = useState("");

  const rows = useMemo<Row[]>(() => {
    const map = new Map<string, Row>();
    for (const p of analysis.profiles) {
      const key = `${p.application}|${p.name}|${p.version}`.toLowerCase();
      const hit = map.get(key);
      if (hit) { hit.findings++; continue; }
      map.set(key, {
        key, application: p.application || "—", component: p.name || "—", version: p.version || "—",
        eol: p.eolDate, eos: p.eosDate, daysEol: daysToEol(p.eolDate), daysEos: daysToEol(p.eosDate), stage: stageOf(p),
        source: [p.eolDate && `EOL: ${p.record.intel.eolSource ?? "—"}`, p.eosDate && `EOS: ${p.record.intel.eosSource ?? "—"}`].filter(Boolean).join(" · ") || "—",
        action: p.recommendedAction, findings: 1,
      });
    }
    // soonest / most overdue first, undated last
    return [...map.values()].sort((a, b) => (a.daysEol ?? a.daysEos ?? 1e9) - (b.daysEol ?? b.daysEos ?? 1e9));
  }, [analysis.profiles]);

  if (!active) return <NoDataset />;

  // tiles count components (findings), exactly like the dashboard; the table lists each release once with ×N
  const counts = Object.fromEntries(STAGES.map((s) => [s, rows.filter((r) => r.stage === s).reduce((n, r) => n + r.findings, 0)])) as Record<Stage, number>;
  const needle = q.trim().toLowerCase();
  const shown = rows.filter((r) => (stage === "all" || r.stage === stage) &&
    (!needle || `${r.component} ${r.version} ${r.application}`.toLowerCase().includes(needle)));

  const sheet = {
    name: "EOL & EOS Dates",
    columns: ["Application", "Component", "Version", "EOL Date", "Days To EOL", "EOS Date", "Days To EOS", "Stage", "Date Source", "Recommended Action"],
    rows: shown.map((r) => [r.application, r.component, r.version, r.eol || NOT_PUBLISHED, r.daysEol ?? "", r.eos || NOT_PUBLISHED, r.daysEos ?? "", r.stage, r.source, r.action]),
  };

  return (
    <>
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="card-elevated space-y-3 border border-border/60 p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="flex items-center gap-2 text-lg font-semibold"><CalendarClock className="h-5 w-5 text-primary" /> EOL &amp; EOS lifecycle — {active.name}</h2>
            <p className="text-xs text-muted-foreground">
              {rows.length.toLocaleString()} distinct component release(s) · dates come from your file first, then the vendor feed (endoflife.date), then curated vendor data
            </p>
          </div>
          <div className="flex items-center gap-1.5">
            {enriching && <span className="flex items-center gap-1 text-[11px] text-primary"><Loader2 className="h-3 w-3 animate-spin" /> Checking vendor lifecycle feeds…</span>}
            {(["xlsx", "csv", "json"] as const).map((f) => (
              <Button key={f} size="sm" variant="outline" className="h-8 rounded-lg text-[11px] uppercase" onClick={() => void exportSection("eol-eos-dates", sheet, f)}>
                <Download className="mr-1 h-3 w-3" /> {f}
              </Button>
            ))}
          </div>
        </div>
        <p className="flex items-start gap-1.5 text-[11px] text-muted-foreground">
          <Info className="mt-0.5 h-3 w-3 shrink-0" />
          <span><b>EOS</b> (end of support) is when active vendor support stops; <b>EOL</b> (end of life) is when the release gets no fixes at all. “Not published” means the vendor has not announced a date — it is never guessed.</span>
        </p>
      </motion.div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {STAGES.map((s) => {
          const cfg = severityConfig[STAGE_TONE[s]];
          const on = stage === s;
          return (
            <button key={s} onClick={() => setStage(on ? "all" : s)}
              className={`card-elevated border p-4 text-left transition ${on ? `${cfg.border} ring-2 ${cfg.ring}` : "border-border/60 hover:bg-accent/30"}`}>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{s}</div>
              <div className={`mt-1 text-2xl font-bold ${cfg.color}`}>{counts[s]}</div>
              <div className="text-[10px] text-muted-foreground">{on ? "components · click to clear" : "components · click to filter"}</div>
            </button>
          );
        })}
      </div>

      <div className="card-elevated overflow-hidden border border-border/60">
        <div className="flex items-center gap-2 border-b border-border/60 px-4 py-3">
          <Search className="h-4 w-4 text-muted-foreground" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search component, version or application…"
            className="w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground" />
          <span className="whitespace-nowrap text-[11px] text-muted-foreground">{shown.length.toLocaleString()} shown</span>
        </div>
        <div className="max-h-[65vh] overflow-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
              <tr className="border-b border-border text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                {["Component", "Version", "Application", "EOL date", "EOS date", "Stage", "Date source", "Recommended action"].map((h) => (
                  <th key={h} className="whitespace-nowrap px-3 py-2.5">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shown.slice(0, 500).map((r) => {
                const cfg = severityConfig[STAGE_TONE[r.stage]];
                return (
                  <tr key={r.key} className="border-b border-border/40 hover:bg-accent/20">
                    <td className="px-3 py-2 font-medium">{r.component}{r.findings > 1 && <span className="ml-1 text-[10px] text-muted-foreground">×{r.findings}</span>}</td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono">{r.version}</td>
                    <td className="px-3 py-2">{r.application}</td>
                    <td className="whitespace-nowrap px-3 py-2 tabular-nums">
                      {r.eol ? <><div className="font-semibold">{r.eol}</div><div className="text-[10px] text-muted-foreground">{rel(r.daysEol)}</div></> : <span className="text-muted-foreground">{NOT_PUBLISHED}</span>}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 tabular-nums">
                      {r.eos ? <><div className="font-semibold">{r.eos}</div><div className="text-[10px] text-muted-foreground">{rel(r.daysEos)}</div></> : <span className="text-muted-foreground">{NOT_PUBLISHED}</span>}
                    </td>
                    <td className="px-3 py-2"><span className={`chip whitespace-nowrap border ${cfg.bg} ${cfg.border} ${cfg.color}`}>{r.stage}</span></td>
                    <td className="px-3 py-2 text-[11px] text-muted-foreground">{r.source}</td>
                    <td className="max-w-[320px] px-3 py-2">{r.action}</td>
                  </tr>
                );
              })}
              {shown.length === 0 && <tr><td colSpan={8} className="px-3 py-10 text-center text-muted-foreground">No components match.</td></tr>}
            </tbody>
          </table>
        </div>
        {shown.length > 500 && <div className="border-t border-border/60 px-4 py-2 text-center text-[11px] text-muted-foreground">Showing the first 500 — use the export for the full list.</div>}
      </div>
    </>
  );
}
