import { createLovableAiGatewayProvider } from "@/lib/ai-gateway.server";
import { createFileRoute } from "@tanstack/react-router";
import { convertToModelMessages, streamText, tool, stepCountIs, type UIMessage } from "ai";
import { z } from "zod";

type ChatRequestBody = {
  messages?: unknown;
  datasetContext?: { name: string; columns: string[]; rows: Record<string, unknown>[] };
  analysis?: Record<string, unknown> | null;
};

export const Route = createFileRoute("/api/chat")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { messages, datasetContext, analysis } = (await request.json()) as ChatRequestBody;
        if (!Array.isArray(messages)) return new Response("Messages required", { status: 400 });

        const key = process.env.LOVABLE_API_KEY;
        if (!key) return new Response("Missing LOVABLE_API_KEY", { status: 500 });

        const gateway = createLovableAiGatewayProvider(key);

        const ctxText = datasetContext
          ? `\n\nACTIVE DATASET: "${datasetContext.name}"\nColumns: ${datasetContext.columns.join(", ")}\nSample rows (${datasetContext.rows.length}):\n${JSON.stringify(datasetContext.rows.slice(0, 150))}`
          : "\n\nNo dataset currently loaded.";

        const analysisText = analysis
          ? `\n\nPRE-COMPUTED ANALYSIS (authoritative — computed deterministically over the FULL dataset, not just the sample above; the UI is already rendering these KPIs, charts and tables next to your reply):\n${JSON.stringify(analysis)}\n\nWrite a tight narrative that INTERPRETS this analysis: what it means for the business, what is most urgent, what to do next. Do NOT restate every number and do NOT reproduce the full table — the UI shows it. Never contradict these figures.`
          : "";

        const system = `You are an enterprise AI Cyber Risk Analyst for SBOM (Software Bill of Materials) and VAPT data. You reason like a senior security architect: prioritize by exploitability and business impact, name concrete versions and CVE IDs, and always end with clear next actions.

When asked about CVEs, exploitability, KEV status or advisories for specific components/versions, use the lookup_vulnerability tool to fetch current public data from OSV.dev. Use markdown (short paragraphs, bold labels, small tables only when the UI is not already showing one).${analysisText}${ctxText}`;

        const result = streamText({
          model: gateway("openai/gpt-5.6-sol"),
          system,
          messages: await convertToModelMessages(messages as UIMessage[]),
          stopWhen: stepCountIs(8),
          providerOptions: { lovable: { reasoningEffort: "none" } },

          tools: {
            lookup_vulnerability: tool({
              description:
                "Look up known vulnerabilities/CVEs for a software component from the OSV.dev public vulnerability database.",
              inputSchema: z.object({
                package_name: z.string().describe("Component/package name, e.g. 'lodash', 'openssl'"),
                version: z.string().optional().describe("Optional specific version"),
                ecosystem: z
                  .string()
                  .optional()
                  .describe("Optional ecosystem: npm, PyPI, Maven, Go, RubyGems, NuGet, etc."),
              }),
              execute: async ({ package_name, version, ecosystem }) => {
                try {
                  const body: Record<string, unknown> = { package: { name: package_name } };
                  if (ecosystem) (body.package as Record<string, unknown>).ecosystem = ecosystem;
                  if (version) body.version = version;
                  const res = await fetch("https://api.osv.dev/v1/query", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(body),
                  });
                  if (!res.ok) return { error: `OSV lookup failed: ${res.status}` };
                  const json = (await res.json()) as { vulns?: Array<Record<string, unknown>> };
                  const vulns = (json.vulns ?? []).slice(0, 10).map((v) => ({
                    id: v.id,
                    summary: v.summary,
                    aliases: v.aliases,
                    severity: v.severity,
                    published: v.published,
                    references: (v.references as Array<{ url: string }> | undefined)
                      ?.slice(0, 3)
                      .map((r) => r.url),
                  }));
                  return { count: vulns.length, vulnerabilities: vulns };
                } catch (e) {
                  return { error: e instanceof Error ? e.message : "Unknown error" };
                }
              },
            }),
          },
        });

        return result.toUIMessageStreamResponse({ originalMessages: messages as UIMessage[] });
      },
    },
  },
});
