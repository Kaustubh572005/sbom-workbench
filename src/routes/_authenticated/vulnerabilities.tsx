import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { motion } from "framer-motion";
import {
  Activity, AlertCircle, AlertTriangle, Boxes, Building2, Bug, Calendar,
  CheckCircle2, Gauge, Info, Package, RefreshCw, Satellite, Shield, ShieldAlert,
  ShieldCheck, Sparkles, Wrench, XCircle, LifeBuoy, ArrowUpCircle, HelpCircle, Replace,
} from "lucide-react";
import {
  useWorkbench, ActiveFilterChip, SearchBar, NoDataset, severityConfig,
  askAnalyst, useAnimatedCount,
} from "@/lib/workbench-shared";
import type { SeverityKey } from "@/lib/workbench-shared";
import { buildVulnIntel, intelKey, type Enrichment, type GroupRisk, type VulnRecord } from "@/lib/vuln-intel";
import {
  lifecycleTone, supportTone, remediationTone, priorityTone, confidenceTone,
} from "@/lib/lifecycle-intel";
import { enrichThreatIntel } from "@/lib/threat-intel.functions";
import { DataTable, type Col } from "@/components/VulnTable";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/vulnerabilities")({
  head: () => ({
    meta: [
      { title: "Vulnerability Intelligence Center — SBOM Workbench" },
      { name: "description", content: "Automatic SBOM vulnerability analysis: critical CVEs, EOL components, vendor risk, compliance gaps and live threat intelligence." },
      { property: "og:title", content: "Vulnerability Intelligence Center" },
      { property: "og:description", content: "Proactive CVE, EOL, compliance and exploit intelligence for your software bill of materials." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: VulnPage,
});

type Facet =
  | "all" | "critical" | "high" | "medium" | "low" | "info"
  | "kev" | "exploit" | "eol" | "apps" | "vendors" | "components" | "compliance"
  | "unsupported" | "upgrade" | "migration" | "validation" | "update" | "uptodate" | "unknownLifecycle";

type Section =
  | "all" | "lifecycle" | "criticalCves" | "highest" | "apps" | "vendors" | "eol" | "compliance" | "loopholes";

const SECTIONS: Array<{ key: Section; label: string; icon: typeof Shield }> = [
  { key: "all", label: "All findings", icon: ShieldAlert },
  { key: "lifecycle", label: "Lifecycle & remediation", icon: LifeBuoy },
  { key: "criticalCves", label: "Critical CVEs", icon: AlertTriangle },
  { key: "highest", label: "Highest CVEs", icon: Activity },
  { key: "apps", label: "Applications at risk", icon: Boxes },
  { key: "vendors", label: "Vendor risk", icon: Building2 },
  { key: "eol", label: "End of life", icon: Calendar },
  { key: "compliance", label: "Compliance", icon: ShieldCheck },
  { key: "loopholes", label: "Security loopholes", icon: Bug },
];

function SevChip({ sev }: { sev: SeverityKey }) {
  const cfg = severityConfig[sev];
  return <span className={`chip border ${cfg.bg} ${cfg.border} ${cfg.color}`}>{cfg.label}</span>;
}

type Tone = SeverityKey;
function Badge({ text, tone }: { text: string; tone: Tone }) {
  const cfg = severityConfig[tone];
  return <span className={`chip whitespace-nowrap border ${cfg.bg} ${cfg.border} ${cfg.color}`}>{text}</span>;
}

function ScoreTile({ label, value, sub, tone, icon: Icon }: { label: string; value: number | string; sub: string; tone: SeverityKey | "primary"; icon: typeof Gauge }) {
  const cls = tone === "primary" ? "text-primary" : severityConfig[tone].color;
  const bg = tone === "primary" ? "bg-primary/10" : severityConfig[tone].bg;
  return (
    <div className="card-elevated border border-border/60 p-4">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</span>
        <span className={`flex h-7 w-7 items-center justify-center rounded-lg ${bg} ${cls}`}><Icon className="h-3.5 w-3.5" /></span>
      </div>
      <div className={`mt-2 text-2xl font-bold tracking-tight ${cls}`}>{value}</div>
      <div className="mt-0.5 text-[11px] text-muted-foreground">{sub}</div>
    </div>
  );
}

function KpiTile({ label, value, tone, icon: Icon, active, onClick, glow }: {
  label: string; value: number | string; tone: SeverityKey | "primary"; icon: typeof Shield;
  active: boolean; onClick: () => void; glow?: boolean;
}) {
  const cls = tone === "primary" ? "text-primary" : severityConfig[tone].color;
  const bg = tone === "primary" ? "bg-primary/10" : severityConfig[tone].bg;
  const border = tone === "primary" ? "border-primary/30" : severityConfig[tone].border;
  const ring = tone === "primary" ? "ring-primary/40" : severityConfig[tone].ring;
  const numeric = typeof value === "number";
  const animated = useAnimatedCount(numeric ? (value as number) : 0);
  return (
    <motion.button whileHover={{ y: -3 }} whileTap={{ scale: 0.98 }} onClick={onClick}
      className={`card-elevated card-hover border p-3.5 text-left ${border} ${glow ? "glow-critical" : ""} ${active ? `ring-2 ${ring} ring-offset-2 ring-offset-background` : ""}`}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</span>
        <span className={`flex h-6 w-6 items-center justify-center rounded-md ${bg} ${cls}`}><Icon className="h-3 w-3" /></span>
      </div>
      <div className={`mt-1.5 text-2xl font-bold tracking-tight ${cls}`}>{numeric ? animated.toLocaleString() : value}</div>
      <div className="mt-0.5 text-[10px] text-muted-foreground">{active ? "Filter active — click to clear" : "Click to filter"}</div>
    </motion.button>
  );
}

function VulnPage() {
  const { active, filteredComponents, setDrawerId, components } = useWorkbench();
  const [facet, setFacet] = useState<Facet>("all");
  const [section, setSection] = useState<Section>("all");
  const [intelMap, setIntelMap] = useState<Record<string, Enrichment>>({});
  const [enriching, setEnriching] = useState(false);
  const [intelAt, setIntelAt] = useState<string | null>(null);
  const enrich = useServerFn(enrichThreatIntel);

  const intel = useMemo(
    () => buildVulnIntel(filteredComponents.map((c) => ({ id: c.id, data: c.data })), intelMap),
    [filteredComponents, intelMap],
  );

  /* ---------- automatic live external threat-intelligence enrichment ---------- */
  const runEnrichment = useMemo(() => {
    return async (records: VulnRecord[], silent: boolean) => {
      if (!records.length) return;
      setEnriching(true);
      try {
        const seen = new Set<string>();
        const targets = [...records]
          .sort((a, b) => b.riskScore - a.riskScore)
          .filter((r) => {
            const k = intelKey(r.raw);
            if (seen.has(k) || (!r.component && !r.cve)) return false;
            seen.add(k);
            return true;
          })
          .slice(0, 120)
          .map((r) => ({ key: intelKey(r.raw), component: r.component, version: r.version, cve: r.cve }));
        if (!targets.length) return;
        const res = await enrich({ data: { targets } });
        setIntelMap((prev) => ({ ...prev, ...res.intel }));
        setIntelAt(res.updatedAt);
        if (!silent) toast.success(`Threat intelligence refreshed for ${targets.length} findings`);
      } catch (e) {
        if (!silent) toast.error(e instanceof Error ? e.message : "Enrichment failed");
      } finally {
        setEnriching(false);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    setIntelMap({});
    setIntelAt(null);
  }, [active?.id]);

  useEffect(() => {
    if (!active || !components.length) return;
    const base = buildVulnIntel(components.slice(0, 4000).map((c) => ({ id: c.id, data: c.data })));
    void runEnrichment(base.records, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active?.id, components.length]);

  if (!active) return <NoDataset />;

  /* --------------------------------- faceting --------------------------------- */
  const facetRecords = (): VulnRecord[] => {
    switch (facet) {
      case "critical": return intel.records.filter((r) => r.severity === "critical");
      case "high": return intel.records.filter((r) => r.severity === "high");
      case "medium": return intel.records.filter((r) => r.severity === "medium");
      case "low": return intel.records.filter((r) => r.severity === "low");
      case "info": return intel.records.filter((r) => r.severity === "info");
      case "kev": return intel.kevRecords;
      case "exploit": return intel.activeExploits;
      case "eol": return intel.eolRecords;
      case "unsupported": return intel.unsupportedRecords;
      case "upgrade": return intel.upgradeRequired;
      case "migration": return intel.migrationRequired;
      case "validation": return intel.validationRequired;
      case "update": return intel.updateAvailable;
      case "uptodate": return intel.upToDate;
      case "unknownLifecycle": return intel.unknownLifecycle;
      case "compliance": return intel.unsupportedRecords.concat(intel.validationRequired, intel.missingLicense);
      default: return intel.records;
    }
  };
  const scoped = facetRecords();

  const toggle = (f: Facet) => setFacet((prev) => (prev === f ? "all" : f));

  const kpis: Array<{ key: Facet; label: string; value: number | string; tone: SeverityKey | "primary"; icon: typeof Shield; glow?: boolean }> = [
    { key: "all", label: "Total vulnerabilities", value: intel.total, tone: "primary", icon: ShieldAlert },
    { key: "critical", label: "Critical", value: intel.counts.critical, tone: "critical", icon: AlertTriangle, glow: intel.counts.critical > 0 },
    { key: "high", label: "High", value: intel.counts.high, tone: "high", icon: AlertTriangle },
    { key: "medium", label: "Medium", value: intel.counts.medium, tone: "medium", icon: AlertCircle },
    { key: "low", label: "Low", value: intel.counts.low, tone: "low", icon: CheckCircle2 },
    { key: "info", label: "Informational", value: intel.counts.info, tone: "info", icon: Info },
    { key: "all", label: "Highest CVSS", value: intel.highestCvss || "—", tone: "critical", icon: Activity },
    { key: "apps", label: "Applications at risk", value: intel.appsAtRisk.length, tone: "high", icon: Boxes },
    { key: "vendors", label: "Vendors at risk", value: intel.vendorsAtRisk.length, tone: "high", icon: Building2 },
    { key: "components", label: "Components at risk", value: intel.componentsAtRisk.length, tone: "medium", icon: Package },
    { key: "eol", label: "End of life", value: intel.eolRecords.length, tone: "critical", icon: Calendar },
    { key: "compliance", label: "Compliance issues", value: intel.complianceIssues, tone: "high", icon: ShieldCheck },
    { key: "unsupported", label: "Unsupported / legacy", value: intel.unsupportedRecords.length, tone: "critical", icon: XCircle },
    { key: "upgrade", label: "Upgrade required", value: intel.upgradeRequired.length, tone: "critical", icon: ArrowUpCircle },
    { key: "migration", label: "Platform migration", value: intel.migrationRequired.length, tone: "high", icon: Replace },
    { key: "update", label: "Update available", value: intel.updateAvailable.length, tone: "medium", icon: Wrench },
    { key: "uptodate", label: "Up to date", value: intel.upToDate.length, tone: "low", icon: CheckCircle2 },
    { key: "validation", label: "Vendor validation", value: intel.validationRequired.length, tone: "info", icon: HelpCircle },
    { key: "unknownLifecycle", label: "Lifecycle unknown", value: intel.unknownLifecycle.length, tone: "info", icon: HelpCircle },
    { key: "exploit", label: "Active exploits", value: intel.activeExploits.length, tone: "critical", icon: Bug, glow: intel.activeExploits.length > 0 },
  ];

  /* ---------------------------------- columns --------------------------------- */
  const lifecycleColumns: Col<VulnRecord>[] = [
    { key: "component", label: "Component", value: (r) => r.component || "—", filterable: true },
    { key: "version", label: "Current version", value: (r) => r.version, mono: true, filterable: true },
    {
      key: "latestStable", label: "Latest stable version", value: (r) => r.lifecycle.latestStableVersion,
      mono: true,
      render: (r) => r.lifecycle.latestStableVersion
        ? <Badge text={r.lifecycle.latestStableVersion} tone="info" />
        : <span className="text-muted-foreground">Unconfirmed</span>,
    },
    {
      key: "lifecycleStatus", label: "Lifecycle status", value: (r) => r.lifecycle.lifecycleStatus, filterable: true,
      render: (r) => <Badge text={r.lifecycle.lifecycleStatus} tone={lifecycleTone[r.lifecycle.lifecycleStatus]} />,
    },
    {
      key: "supportStatus", label: "Support status", value: (r) => r.lifecycle.supportStatus, filterable: true,
      render: (r) => <Badge text={r.lifecycle.supportStatus} tone={supportTone[r.lifecycle.supportStatus]} />,
    },
    {
      key: "remediationStatus", label: "Remediation status", value: (r) => r.lifecycle.remediationStatus, filterable: true,
      render: (r) => <Badge text={r.lifecycle.remediationStatus} tone={remediationTone[r.lifecycle.remediationStatus]} />,
    },
    { key: "recommendedAction", label: "Recommended action", value: (r) => r.lifecycle.recommendedAction, width: "22rem" },
    {
      key: "targetVersion", label: "Target version", value: (r) => r.lifecycle.targetVersion, mono: true,
      render: (r) => r.lifecycle.targetVersion ? <span className="font-mono text-xs">{r.lifecycle.targetVersion}</span> : <span className="text-muted-foreground">—</span>,
    },
    {
      key: "priority", label: "Priority", value: (r) => r.lifecycle.priority, filterable: true,
      render: (r) => <Badge text={r.lifecycle.priority} tone={priorityTone[r.lifecycle.priority]} />,
    },
    {
      key: "confidence", label: "Confidence", value: (r) => r.lifecycle.confidence, filterable: true,
      render: (r) => <Badge text={`${r.lifecycle.confidence} · ${r.lifecycle.confidenceScore}%`} tone={confidenceTone[r.lifecycle.confidence]} />,
    },
    {
      key: "evidenceSource", label: "Evidence source", value: (r) => r.lifecycle.evidenceSource, filterable: true,
      render: (r) => <Badge text={r.lifecycle.evidenceSource} tone={r.lifecycle.evidenceSource === "Estimated Analysis" ? "medium" : "info"} />,
    },
  ];

  const recordCols: Col<VulnRecord>[] = [
    { key: "component", label: "Component", value: (r) => r.component || "—", filterable: true },
    { key: "application", label: "Application", value: (r) => r.application, filterable: true },
    { key: "vendor", label: "Vendor", value: (r) => r.vendor, filterable: true },
    { key: "version", label: "Version", value: (r) => r.version, mono: true },
    { key: "cve", label: "CVE", value: (r) => r.cve, mono: true, filterable: true },
    { key: "cvss", label: "CVSS", value: (r) => r.cvss, align: "right", mono: true },
    { key: "published", label: "Published", value: (r) => r.published },
    { key: "severity", label: "Severity", value: (r) => r.severity, render: (r) => <SevChip sev={r.severity} />, filterable: true },
    ...lifecycleColumns.filter((c) => c.key !== "component" && c.key !== "version"),
    {
      key: "exploitStatus", label: "Exploit status", value: (r) => r.exploitStatus,
      render: (r) => r.kev
        ? <span className="chip border border-severity-critical/40 bg-severity-critical/15 text-severity-critical">KEV</span>
        : <span className="text-xs text-muted-foreground">{r.exploitStatus}</span>,
    },
    { key: "riskScore", label: "Risk score", value: (r) => r.riskScore, align: "right", mono: true },
    { key: "remediation", label: "Remediation", value: (r) => r.remediation },
  ];

  const groupCols = (unit: string): Col<GroupRisk>[] => [
    { key: "name", label: unit, value: (g) => g.name, filterable: true },
    { key: "total", label: "Vulnerabilities", value: (g) => g.total, align: "right" },
    { key: "components", label: "Components", value: (g) => g.components, align: "right" },
    { key: "critical", label: "Critical", value: (g) => g.critical, align: "right", render: (g) => <span className="font-semibold text-severity-critical">{g.critical}</span> },
    { key: "high", label: "High", value: (g) => g.high, align: "right" },
    { key: "avgCvss", label: "Avg CVSS", value: (g) => g.avgCvss, align: "right", mono: true },
    { key: "maxCvss", label: "Highest CVSS", value: (g) => g.maxCvss, align: "right", mono: true },
    { key: "risk", label: "Risk", value: (g) => g.riskScore, align: "right", render: (g) => <span className={severityConfig[g.band].color}>{g.riskScore}</span> },
  ];

  const eolCols: Col<VulnRecord>[] = [
    ...lifecycleColumns,
    { key: "eolDate", label: "End of life", value: (r) => r.intel.eolDate ?? "" },
    { key: "supportEnd", label: "End of support", value: (r) => r.intel.supportEndDate ?? "" },
    { key: "why", label: "Analysis rationale", value: (r) => r.lifecycle.reason },
  ];

  const expandRecord = (r: VulnRecord) => (
    <div className="grid gap-3 text-xs md:grid-cols-2">
      <div className="space-y-1.5">
        <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Lifecycle & remediation analysis</div>
        <div className="flex flex-wrap gap-1.5">
          <Badge text={r.lifecycle.lifecycleStatus} tone={lifecycleTone[r.lifecycle.lifecycleStatus]} />
          <Badge text={r.lifecycle.supportStatus} tone={supportTone[r.lifecycle.supportStatus]} />
          <Badge text={r.lifecycle.remediationStatus} tone={remediationTone[r.lifecycle.remediationStatus]} />
          <Badge text={`Priority ${r.lifecycle.priority}`} tone={priorityTone[r.lifecycle.priority]} />
          <Badge text={`Confidence ${r.lifecycle.confidence} (${r.lifecycle.confidenceScore}%)`} tone={confidenceTone[r.lifecycle.confidence]} />
        </div>
        <div><span className="font-semibold">Recommended action:</span> {r.lifecycle.recommendedAction}</div>
        <div><span className="font-semibold">Latest stable version:</span> {r.lifecycle.latestStableVersion || "Unconfirmed"}</div>
        <div><span className="font-semibold">Target version:</span> {r.lifecycle.targetVersion || "—"}</div>
        <div><span className="font-semibold">Evidence source:</span> {r.lifecycle.evidenceSource} — {r.lifecycle.evidenceDetail}</div>
        <div><span className="font-semibold">Why this classification:</span> {r.lifecycle.reason}</div>
        <div><span className="font-semibold">Patch priority:</span> {r.patchPriority}</div>
        <div><span className="font-semibold">Remediation steps:</span> {r.remediation}</div>
        <div><span className="font-semibold">Upgrade recommendation:</span> {r.upgradeRecommendation}</div>
        <div><span className="font-semibold">Business impact:</span> {r.businessImpact}</div>
        <div><span className="font-semibold">Estimated risk reduction:</span> {r.riskReduction} pts</div>
      </div>
      <div className="space-y-1.5">
        <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">External intelligence</div>
        {r.intel.updatedAt ? (
          <>
            <div><span className="font-semibold">Source:</span> {r.intel.source}</div>
            <div><span className="font-semibold">KEV:</span> {r.intel.kev ? "Listed (CISA)" : "Not listed"}</div>
            {r.intel.advisoryIds?.length ? <div><span className="font-semibold">Advisories:</span> {r.intel.advisoryIds.join(", ")}</div> : null}
            {r.intel.summary ? <div><span className="font-semibold">Summary:</span> {r.intel.summary}</div> : null}
            <div className="text-muted-foreground">Enriched {new Date(r.intel.updatedAt).toLocaleString()} — uploaded values were not overwritten.</div>
          </>
        ) : (
          <div className="text-muted-foreground">No external intelligence merged for this record yet.</div>
        )}
        <div className="flex flex-wrap gap-1.5 pt-1">
          <Button size="sm" variant="outline" className="h-7 rounded-lg text-[11px]"
            onClick={() => askAnalyst(`Why is ${r.component} ${r.version} (${r.cve || "no CVE id"}) critical? Explain the CVE, exploitability, KEV status and business impact.`)}>
            <Sparkles className="mr-1 h-3 w-3" /> Why is this critical?
          </Button>
          <Button size="sm" variant="outline" className="h-7 rounded-lg text-[11px]"
            onClick={() => askAnalyst(`Lifecycle status is ${r.lifecycle.lifecycleStatus}, support status ${r.lifecycle.supportStatus}, remediation status ${r.lifecycle.remediationStatus}. Generate step-by-step remediation and mitigation for ${r.component} ${r.version} (${r.cve || "no CVE id"}), including fixed version, vendor advisory guidance and compensating controls.`)}>
            <Wrench className="mr-1 h-3 w-3" /> How do I fix this?
          </Button>
          <Button size="sm" variant="outline" className="h-7 rounded-lg text-[11px]" onClick={() => setDrawerId(r.id)}>
            Open record
          </Button>
        </div>
      </div>
    </div>
  );

  const askSection = (label: string, prompt: string) => (
    <Button size="sm" variant="outline" className="h-8 rounded-lg text-xs" onClick={() => askAnalyst(prompt)}>
      <Sparkles className="mr-1 h-3.5 w-3.5 text-primary" /> {label}
    </Button>
  );

  return (
    <div className="space-y-5">
      {/* Intelligence header */}
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
        className="card-elevated flex flex-wrap items-center justify-between gap-3 border border-border/60 p-4">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-bold tracking-tight">
            <ShieldAlert className="h-5 w-5 text-primary" /> Vulnerability Intelligence Center
          </h2>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Automatic analysis of <span className="font-medium text-foreground">{active.name}</span> · {intel.total.toLocaleString()} findings analysed
            {intelAt && <> · external intel updated {new Date(intelAt).toLocaleTimeString()}</>}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className={`chip border ${enriching ? "border-primary/40 bg-primary/10 text-primary" : "border-severity-low/40 bg-severity-low/15 text-severity-low"}`}>
            <Satellite className="h-3 w-3" /> {enriching ? "Enriching…" : "Live intel"}
          </span>
          <Button size="sm" variant="outline" className="h-8 rounded-lg text-xs" disabled={enriching}
            onClick={() => void runEnrichment(intel.records, false)}>
            <RefreshCw className={`mr-1 h-3.5 w-3.5 ${enriching ? "animate-spin" : ""}`} /> Refresh intelligence
          </Button>
          {askSection("Ask the analyst", `Summarise the vulnerability posture of ${active.name}: critical CVEs, exploitable findings, EOL components and compliance gaps, then give a prioritised action plan.`)}
        </div>
      </motion.div>

      {/* Scores */}
      <section className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <ScoreTile label="Risk score" value={intel.riskScore} sub="Weighted severity exposure" tone={intel.riskScore >= 75 ? "critical" : intel.riskScore >= 50 ? "high" : intel.riskScore >= 25 ? "medium" : "low"} icon={Gauge} />
        <ScoreTile label="Attack surface" value={intel.attackSurfaceScore} sub="Unpatched + EOL + high severity" tone={intel.attackSurfaceScore >= 60 ? "critical" : "medium"} icon={Activity} />
        <ScoreTile label="Exploitability" value={intel.exploitabilityScore} sub="KEV, public exploits, CVSS ≥ 9" tone={intel.exploitabilityScore >= 40 ? "critical" : "high"} icon={Bug} />
        <ScoreTile label="SBOM health" value={intel.sbomHealthScore} sub="Completeness, supplier, license" tone={intel.sbomHealthScore >= 70 ? "low" : "medium"} icon={ShieldCheck} />
      </section>

      {/* Secondary risk indices */}
      <section className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-8">
        {[
          { l: "Dependency risk", v: intel.dependencyRisk },
          { l: "Supply chain", v: intel.supplyChainRisk },
          { l: "Open source", v: intel.openSourceRisk },
          { l: "Third party", v: intel.thirdPartyRisk },
          { l: "Multi-CVE comps", v: intel.multiCve.length },
          { l: "Duplicate packages", v: intel.duplicatePackages },
          { l: "Missing version", v: intel.missingVersion.length },
          { l: "Missing supplier", v: intel.missingSupplier.length },
        ].map((x) => (
          <div key={x.l} className="card-elevated border border-border/60 px-3 py-2.5">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{x.l}</div>
            <div className="mt-1 text-lg font-bold">{x.v}</div>
          </div>
        ))}
      </section>

      {/* KPI grid */}
      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {kpis.map((k, i) => (
          <KpiTile key={`${k.label}-${i}`} label={k.label} value={k.value} tone={k.tone} icon={k.icon} glow={k.glow}
            active={facet === k.key && k.key !== "all"} onClick={() => toggle(k.key)} />
        ))}
      </section>

      <ActiveFilterChip />
      <SearchBar />

      {facet !== "all" && (
        <div className="flex items-center gap-2 text-xs">
          <span className="chip border border-primary/40 bg-primary/10 text-primary">Page facet · {facet} ({scoped.length})</span>
          <button onClick={() => setFacet("all")} className="text-muted-foreground hover:text-foreground">Clear facet</button>
        </div>
      )}

      {/* Section tabs */}
      <div className="flex flex-wrap gap-1.5">
        {SECTIONS.map((s) => (
          <button key={s.key} onClick={() => setSection(s.key)}
            className={`flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-medium transition ${section === s.key ? "border-primary/40 bg-primary/10 text-foreground" : "border-border/60 text-muted-foreground hover:bg-accent/40 hover:text-foreground"}`}>
            <s.icon className="h-3.5 w-3.5" /> {s.label}
          </button>
        ))}
      </div>

      {section === "all" && (
        <DataTable title="All vulnerability findings" subtitle={facet === "all" ? "Full analysed scope" : `Facet: ${facet}`}
          columns={recordCols} rows={scoped} getKey={(r) => r.id} onOpen={(r) => setDrawerId(r.id)} expand={expandRecord} />
      )}

      {section === "lifecycle" && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-8">
            {(Object.entries(intel.lifecycleCounts) as Array<[keyof typeof intel.lifecycleCounts, number]>).map(([status, count]) => {
              const cfg = severityConfig[lifecycleTone[status]];
              return (
                <div key={status} className={`card-elevated border p-3 ${cfg.border}`}>
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{status}</div>
                  <div className={`mt-1 text-xl font-bold ${cfg.color}`}>{count.toLocaleString()}</div>
                </div>
              );
            })}
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
            {(Object.entries(intel.remediationCounts) as Array<[keyof typeof intel.remediationCounts, number]>).map(([status, count]) => {
              const cfg = severityConfig[remediationTone[status]];
              return (
                <div key={status} className={`card-elevated border p-3 ${cfg.border}`}>
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{status}</div>
                  <div className={`mt-1 text-xl font-bold ${cfg.color}`}>{count.toLocaleString()}</div>
                </div>
              );
            })}
          </div>
          <DataTable title="Lifecycle & remediation analysis"
            subtitle="Vendor lifecycle, support state, remediation path, priority, confidence and evidence source for every component"
            columns={lifecycleColumns} rows={scoped} getKey={(r) => r.id}
            onOpen={(r) => setDrawerId(r.id)} expand={expandRecord}
            actions={askSection("Remediation roadmap", "Using the lifecycle and remediation analysis, build a prioritised remediation roadmap: which components need upgrades, which need platform migration, and which need vendor validation.")} />
        </div>
      )}

      {section === "criticalCves" && (
        <DataTable title="Critical CVEs" subtitle="Severity = Critical" columns={recordCols}
          rows={intel.critical} getKey={(r) => r.id} onOpen={(r) => setDrawerId(r.id)} expand={expandRecord}
          actions={askSection("Explain top criticals", "Explain the three most dangerous Critical CVEs in this dataset and how to remediate each.")} />
      )}

      {section === "highest" && (
        <DataTable title="Highest CVEs by CVSS" subtitle="Sorted by CVSS descending" columns={recordCols}
          rows={intel.highestCves} getKey={(r) => r.id} onOpen={(r) => setDrawerId(r.id)} expand={expandRecord} />
      )}

      {section === "apps" && (
        <DataTable title="Applications at risk" subtitle="Grouped by application" columns={groupCols("Application")}
          rows={intel.appsAtRisk} getKey={(g) => g.name}
          actions={askSection("Which app first?", "Which application should we remediate first and why? Consider critical count, CVSS and exploitability.")} />
      )}

      {section === "vendors" && (
        <>
          <DataTable title="Vendor risk ranking" subtitle="Ranked by critical then overall risk" columns={groupCols("Vendor")}
            rows={intel.vendorsAtRisk} getKey={(g) => g.name} />
          <div className="card-elevated mt-4 border border-border/60 p-4">
            <h3 className="mb-3 text-sm font-semibold">Vendor trust score</h3>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {intel.vendorTrust.map((v) => (
                <div key={v.name} className="rounded-xl border border-border/60 bg-background/50 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium">{v.name}</span>
                    <span className={`text-sm font-bold ${v.score >= 70 ? "text-severity-low" : v.score >= 40 ? "text-severity-medium" : "text-severity-critical"}`}>{v.score}</span>
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground">{v.critical} critical · {v.total} findings</div>
                </div>
              ))}
              {intel.vendorTrust.length === 0 && <div className="text-xs text-muted-foreground">No vendor data in this dataset.</div>}
            </div>
          </div>
        </>
      )}

      {section === "eol" && (
        <DataTable title="End-of-life & unsupported components" subtitle="Uploaded flags enriched with endoflife.date"
          columns={eolCols} rows={intel.eolRecords} getKey={(r) => r.id} onOpen={(r) => setDrawerId(r.id)} expand={expandRecord}
          emptyText="No end-of-life components detected in the current scope."
          actions={askSection("Migration plan", "Build a migration plan for the end-of-life and unsupported components in this dataset, including replacement recommendations.")} />
      )}

      {section === "compliance" && (
        <div className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            {intel.compliance.map((c) => {
              const tone: SeverityKey = c.status === "Violation" ? "critical" : c.status === "At risk" ? "medium" : "low";
              const cfg = severityConfig[tone];
              return (
                <div key={`${c.framework}-${c.control}`} className={`card-elevated border p-4 ${cfg.border}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-semibold">{c.framework} · {c.control}</span>
                    <span className={`chip border ${cfg.bg} ${cfg.border} ${cfg.color}`}>{c.status}</span>
                  </div>
                  <p className="mt-1.5 text-xs text-muted-foreground">{c.requirement}</p>
                  <p className="mt-1.5 text-xs">{c.detail}</p>
                  <div className="mt-2 text-[11px] text-muted-foreground">Affected records: <span className="font-semibold text-foreground">{c.affected}</span></div>
                </div>
              );
            })}
          </div>
          <DataTable title="Compliance evidence" subtitle="SEBI / CERT-In / Internal / License controls"
            columns={[
              { key: "framework", label: "Framework", value: (c) => c.framework, filterable: true },
              { key: "control", label: "Control", value: (c) => c.control, filterable: true },
              { key: "requirement", label: "Requirement", value: (c) => c.requirement },
              { key: "status", label: "Status", value: (c) => c.status, filterable: true },
              { key: "affected", label: "Affected", value: (c) => c.affected, align: "right" },
              { key: "detail", label: "Detail", value: (c) => c.detail },
            ]}
            rows={intel.compliance} getKey={(c) => `${c.framework}-${c.control}`}
            actions={askSection("Audit narrative", "Write an audit-ready compliance narrative for SEBI CSCRF and CERT-In directions based on this dataset, listing violations and remediation commitments.")} />
        </div>
      )}

      {section === "loopholes" && (
        <div className="space-y-4">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {intel.loopholes.map((l) => {
              const cfg = severityConfig[l.severity];
              return (
                <div key={l.category} className={`card-elevated border p-4 ${cfg.border}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{l.category}</span>
                    <span className={`flex h-6 w-6 items-center justify-center rounded-md ${cfg.bg} ${cfg.color}`}><Bug className="h-3 w-3" /></span>
                  </div>
                  <div className={`mt-1.5 text-2xl font-bold ${cfg.color}`}>{l.affected}</div>
                  <p className="mt-1 text-[11px] text-muted-foreground">{l.detail}</p>
                </div>
              );
            })}
            {intel.loopholes.length === 0 && <div className="text-xs text-muted-foreground">No structural loopholes detected.</div>}
          </div>
          <DataTable title="Security loopholes" subtitle="Structural weaknesses detected automatically"
            columns={[
              { key: "category", label: "Category", value: (l) => l.category, filterable: true },
              { key: "affected", label: "Affected", value: (l) => l.affected, align: "right" },
              { key: "severity", label: "Severity", value: (l) => l.severity, render: (l) => <SevChip sev={l.severity} />, filterable: true },
              { key: "detail", label: "Detail", value: (l) => l.detail },
            ]}
            rows={intel.loopholes} getKey={(l) => l.category}
            actions={askSection("Close the gaps", "Give a prioritised plan to close the structural security loopholes found in this SBOM (unpatched, unsupported, missing metadata, weak dependency chains).")} />
        </div>
      )}
    </div>
  );
}
