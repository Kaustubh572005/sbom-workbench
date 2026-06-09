import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import * as XLSX from "xlsx";
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import ReactMarkdown from "react-markdown";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import {
  Upload,
  Database,
  Trash2,
  Plus,
  Send,
  Sparkles,
  ShieldAlert,
  FileSpreadsheet,
  Loader2,
} from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "SBOM & VAPT Workbench" },
      {
        name: "description",
        content:
          "Upload SBOM/VAPT Excel sheets, edit components inline, and chat with an AI security analyst.",
      },
    ],
  }),
  component: Workbench,
});

type Dataset = {
  id: string;
  name: string;
  source_filename: string | null;
  columns: string[];
  created_at: string;
};

type Component = {
  id: string;
  dataset_id: string;
  data: Record<string, unknown>;
  content_hash: string;
};

async function hashString(s: string): Promise<string> {
  const buf = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function Workbench() {
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [components, setComponents] = useState<Component[]>([]);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const active = datasets.find((d) => d.id === activeId) ?? null;

  // Load datasets
  useEffect(() => {
    void (async () => {
      const { data, error } = await supabase
        .from("datasets")
        .select("*")
        .order("created_at", { ascending: false });
      if (error) return toast.error(error.message);
      const list = (data ?? []) as unknown as Dataset[];
      setDatasets(list);
      if (!activeId && list.length) setActiveId(list[0].id);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Load components for active dataset
  useEffect(() => {
    if (!activeId) {
      setComponents([]);
      return;
    }
    setLoading(true);
    void (async () => {
      const { data, error } = await supabase
        .from("components")
        .select("*")
        .eq("dataset_id", activeId)
        .order("created_at", { ascending: true });
      if (error) toast.error(error.message);
      setComponents(((data ?? []) as unknown) as Component[]);
      setLoading(false);
    })();
  }, [activeId]);

  async function handleFile(file: File, targetDatasetId: string | null) {
    setUploading(true);
    try {
      const buf = await file.arrayBuffer();
      const wb = XLSX.read(buf, { type: "array" });
      const sheet = wb.Sheets[wb.SheetNames[0]];
      const rows = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, { defval: "" });
      if (!rows.length) {
        toast.error("No rows found in sheet");
        return;
      }
      const sheetCols = Array.from(
        rows.reduce((acc, r) => {
          Object.keys(r).forEach((k) => acc.add(k));
          return acc;
        }, new Set<string>()),
      );

      let datasetId = targetDatasetId;
      let mergedCols = sheetCols;

      if (!datasetId) {
        const { data, error } = await supabase
          .from("datasets")
          .insert({
            name: file.name.replace(/\.[^.]+$/, ""),
            source_filename: file.name,
            columns: sheetCols,
          })
          .select()
          .single();
        if (error) throw error;
        datasetId = (data as { id: string }).id;
      } else {
        const ds = datasets.find((d) => d.id === datasetId);
        mergedCols = Array.from(new Set([...(ds?.columns ?? []), ...sheetCols]));
        await supabase.from("datasets").update({ columns: mergedCols }).eq("id", datasetId);
      }

      // Build insert rows with content hash for dedupe (append-only)
      const toInsert = await Promise.all(
        rows.map(async (r) => ({
          dataset_id: datasetId!,
          data: r,
          content_hash: await hashString(JSON.stringify(r)),
        })),
      );

      // Use upsert on (dataset_id, content_hash) to skip duplicates
      const { error: insErr } = await supabase
        .from("components")
        .upsert(toInsert, { onConflict: "dataset_id,content_hash", ignoreDuplicates: true });
      if (insErr) throw insErr;

      // Refresh
      const [{ data: dsAll }, { data: comp }] = await Promise.all([
        supabase.from("datasets").select("*").order("created_at", { ascending: false }),
        supabase.from("components").select("*").eq("dataset_id", datasetId!).order("created_at"),
      ]);
      setDatasets(((dsAll ?? []) as unknown) as Dataset[]);
      setComponents(((comp ?? []) as unknown) as Component[]);
      setActiveId(datasetId);
      toast.success(`Imported ${rows.length} rows into "${file.name}"`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  async function updateCell(rowId: string, col: string, value: string) {
    const row = components.find((c) => c.id === rowId);
    if (!row) return;
    const newData = { ...row.data, [col]: value };
    setComponents((cs) => cs.map((c) => (c.id === rowId ? { ...c, data: newData } : c)));
    const { error } = await supabase
      .from("components")
      .update({ data: newData })
      .eq("id", rowId);
    if (error) toast.error(error.message);
  }

  async function addRow() {
    if (!active) return;
    const blank = Object.fromEntries(active.columns.map((c) => [c, ""]));
    const hash = await hashString(JSON.stringify(blank) + Date.now());
    const { data, error } = await supabase
      .from("components")
      .insert({ dataset_id: active.id, data: blank, content_hash: hash })
      .select()
      .single();
    if (error) return toast.error(error.message);
    setComponents((cs) => [...cs, data as unknown as Component]);
  }

  async function deleteRow(id: string) {
    setComponents((cs) => cs.filter((c) => c.id !== id));
    const { error } = await supabase.from("components").delete().eq("id", id);
    if (error) toast.error(error.message);
  }

  async function deleteDataset(id: string) {
    if (!confirm("Delete this dataset and all its components?")) return;
    const { error } = await supabase.from("datasets").delete().eq("id", id);
    if (error) return toast.error(error.message);
    const remaining = datasets.filter((d) => d.id !== id);
    setDatasets(remaining);
    if (activeId === id) setActiveId(remaining[0]?.id ?? null);
    toast.success("Dataset deleted");
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b border-border bg-card/50 backdrop-blur">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight">SBOM / VAPT Workbench</h1>
              <p className="text-xs text-muted-foreground">
                Upload, edit & query security component sheets
              </p>
            </div>
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept=".xlsx,.xls,.csv"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handleFile(f, null);
            }}
          />
          <Button onClick={() => fileInputRef.current?.click()} disabled={uploading}>
            {uploading ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Upload className="mr-2 h-4 w-4" />
            )}
            New dataset
          </Button>
        </div>
      </header>

      <div className="mx-auto flex max-w-[1600px] gap-4 px-6 py-4">
        {/* Sidebar: datasets */}
        <aside className="w-64 shrink-0">
          <div className="mb-2 flex items-center justify-between px-1">
            <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Datasets
            </span>
            <span className="text-xs text-muted-foreground">{datasets.length}</span>
          </div>
          <div className="space-y-1">
            {datasets.length === 0 && (
              <div className="rounded-md border border-dashed border-border p-4 text-center text-xs text-muted-foreground">
                No datasets yet. Upload an Excel file to begin.
              </div>
            )}
            {datasets.map((d) => (
              <div
                key={d.id}
                className={`group flex items-center gap-2 rounded-md border px-2 py-2 text-sm transition ${
                  activeId === d.id
                    ? "border-primary bg-primary/10"
                    : "border-transparent hover:bg-accent"
                }`}
              >
                <button
                  onClick={() => setActiveId(d.id)}
                  className="flex flex-1 items-center gap-2 truncate text-left"
                >
                  <Database className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  <span className="truncate">{d.name}</span>
                </button>
                <button
                  onClick={() => deleteDataset(d.id)}
                  className="text-muted-foreground opacity-0 transition group-hover:opacity-100 hover:text-destructive"
                  aria-label="Delete dataset"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
          </div>
        </aside>

        {/* Main: table */}
        <main className="min-w-0 flex-1">
          {active ? (
            <>
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h2 className="flex items-center gap-2 text-base font-semibold">
                    <FileSpreadsheet className="h-4 w-4 text-muted-foreground" />
                    {active.name}
                  </h2>
                  <p className="text-xs text-muted-foreground">
                    {components.length} components · {active.columns.length} columns
                  </p>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={addRow}>
                    <Plus className="mr-1 h-3.5 w-3.5" /> Row
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      const i = document.createElement("input");
                      i.type = "file";
                      i.accept = ".xlsx,.xls,.csv";
                      i.onchange = () => {
                        const f = i.files?.[0];
                        if (f) void handleFile(f, active.id);
                      };
                      i.click();
                    }}
                    disabled={uploading}
                  >
                    <Upload className="mr-1 h-3.5 w-3.5" /> Append file
                  </Button>
                </div>
              </div>

              <div className="overflow-auto rounded-lg border border-border bg-card">
                {loading ? (
                  <div className="p-12 text-center text-sm text-muted-foreground">
                    <Loader2 className="mx-auto mb-2 h-5 w-5 animate-spin" />
                    Loading components...
                  </div>
                ) : components.length === 0 ? (
                  <div className="p-12 text-center text-sm text-muted-foreground">
                    No components yet. Add a row or append another file.
                  </div>
                ) : (
                  <table className="w-full border-collapse text-sm">
                    <thead className="sticky top-0 bg-muted/50 backdrop-blur">
                      <tr>
                        <th className="w-10 border-b border-border px-2 py-2 text-left text-xs font-medium text-muted-foreground">
                          #
                        </th>
                        {active.columns.map((col) => (
                          <th
                            key={col}
                            className="min-w-[140px] border-b border-l border-border px-3 py-2 text-left text-xs font-medium text-muted-foreground"
                          >
                            {col}
                          </th>
                        ))}
                        <th className="w-10 border-b border-l border-border" />
                      </tr>
                    </thead>
                    <tbody>
                      {components.map((row, idx) => (
                        <tr key={row.id} className="group hover:bg-accent/40">
                          <td className="border-b border-border px-2 py-1 text-xs text-muted-foreground">
                            {idx + 1}
                          </td>
                          {active.columns.map((col) => (
                            <td key={col} className="border-b border-l border-border p-0">
                              <input
                                value={String(row.data[col] ?? "")}
                                onChange={(e) => updateCell(row.id, col, e.target.value)}
                                className="w-full bg-transparent px-3 py-1.5 text-sm outline-none focus:bg-background focus:ring-1 focus:ring-ring"
                              />
                            </td>
                          ))}
                          <td className="border-b border-l border-border px-2 text-center">
                            <button
                              onClick={() => deleteRow(row.id)}
                              className="text-muted-foreground opacity-0 transition group-hover:opacity-100 hover:text-destructive"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </>
          ) : (
            <div className="flex h-96 items-center justify-center rounded-lg border border-dashed border-border">
              <div className="text-center">
                <Upload className="mx-auto mb-3 h-10 w-10 text-muted-foreground" />
                <p className="text-sm font-medium">No dataset selected</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  Click "New dataset" to upload your first SBOM/VAPT sheet.
                </p>
              </div>
            </div>
          )}
        </main>

        {/* Chat */}
        <ChatPanel
          dataset={
            active
              ? {
                  name: active.name,
                  columns: active.columns,
                  rows: components.map((c) => c.data),
                }
              : null
          }
        />
      </div>
    </div>
  );
}

function ChatPanel({
  dataset,
}: {
  dataset: { name: string; columns: string[]; rows: Record<string, unknown>[] } | null;
}) {
  const [input, setInput] = useState("");
  const transport = useMemo(() => new DefaultChatTransport({ api: "/api/chat" }), []);
  const { messages, sendMessage, status } = useChat({
    transport,
    onError: (e) => toast.error(e.message),
  });
  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, status]);

  useEffect(() => {
    inputRef.current?.focus();
  }, [status]);

  const busy = status === "submitted" || status === "streaming";

  async function submit() {
    const text = input.trim();
    if (!text || busy) return;
    setInput("");
    await sendMessage({ text }, { body: { datasetContext: dataset } });
  }

  return (
    <aside className="flex w-96 shrink-0 flex-col rounded-lg border border-border bg-card">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2.5">
        <Sparkles className="h-4 w-4 text-primary" />
        <span className="text-sm font-semibold">Security Analyst</span>
        <span className="ml-auto text-[10px] uppercase tracking-wider text-muted-foreground">
          {dataset ? "ctx active" : "no ctx"}
        </span>
      </div>

      <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto p-3" style={{ maxHeight: "calc(100vh - 200px)" }}>
        {messages.length === 0 && (
          <div className="rounded-md border border-dashed border-border p-3 text-xs text-muted-foreground">
            Ask about components, CVEs, severities, or remediations. Try: "Which components have
            known critical vulnerabilities?"
          </div>
        )}
        {messages.map((m) => {
          const text = m.parts
            .map((p) => (p.type === "text" ? p.text : ""))
            .join("");
          const tools = m.parts.filter((p) => p.type.startsWith("tool-"));
          return (
            <div
              key={m.id}
              className={`rounded-md px-3 py-2 text-sm ${
                m.role === "user"
                  ? "ml-6 bg-primary text-primary-foreground"
                  : "mr-6 bg-muted"
              }`}
            >
              {tools.length > 0 && (
                <div className="mb-1 text-[10px] uppercase tracking-wider opacity-70">
                  🔍 Looking up vulnerability data...
                </div>
              )}
              <div className="prose prose-sm max-w-none dark:prose-invert prose-p:my-1 prose-pre:my-1 prose-table:my-1">
                <ReactMarkdown>{text || "..."}</ReactMarkdown>
              </div>
            </div>
          );
        })}
        {status === "submitted" && (
          <div className="mr-6 rounded-md bg-muted px-3 py-2 text-sm text-muted-foreground">
            <Loader2 className="inline h-3 w-3 animate-spin" /> thinking...
          </div>
        )}
      </div>

      <div className="border-t border-border p-2">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
          className="flex gap-2"
        >
          <Input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={dataset ? `Ask about ${dataset.name}...` : "Ask anything..."}
            disabled={busy}
            autoFocus
          />
          <Button type="submit" size="icon" disabled={busy || !input.trim()}>
            <Send className="h-4 w-4" />
          </Button>
        </form>
      </div>
    </aside>
  );
}
