export type LifecycleDateLine = {
  kind: "EOL" | "EOS";
  date: string;
  context: string;
};

function parseLifecycleDate(value?: string): Date | null {
  if (!value) return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? new Date(timestamp) : null;
}

function approximateDuration(from: Date, to: Date): string {
  const months = Math.max(0, Math.round(Math.abs(to.getTime() - from.getTime()) / 2_629_746_000));
  if (months === 0) return "less than 1 month";
  const years = Math.floor(months / 12);
  const remainder = months % 12;
  return [years ? `${years} year${years === 1 ? "" : "s"}` : "", remainder ? `${remainder} month${remainder === 1 ? "" : "s"}` : ""]
    .filter(Boolean)
    .join(" ");
}

export function lifecycleDateLines(eolDate?: string, eosDate?: string, now = new Date()): LifecycleDateLine[] {
  return ([
    ["EOL", eolDate],
    ["EOS", eosDate],
  ] as const).flatMap(([kind, raw]) => {
    const date = parseLifecycleDate(raw);
    if (!date) return [];
    const formatted = new Intl.DateTimeFormat("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      timeZone: "UTC",
    }).format(date);
    const past = date.getTime() < now.getTime();
    return [{
      kind,
      date: formatted,
      context: `~${approximateDuration(now, date)} ${past ? `past ${kind}` : `until ${kind}`}`,
    }];
  });
}

export function lifecycleDisplayText(status: string, eolDate?: string, eosDate?: string): string {
  const dates = lifecycleDateLines(eolDate, eosDate);
  return [status, ...dates.flatMap((item) => [`${item.kind} — ${item.date}`, item.context])].filter(Boolean).join(" · ");
}