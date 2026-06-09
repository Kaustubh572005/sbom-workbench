import { createLovableAiGatewayProvider } from "@/lib/ai-gateway.server";
import { createFileRoute } from "@tanstack/react-router";
import { convertToModelMessages, streamText, tool, stepCountIs, type UIMessage } from "ai";
import { z } from "zod";

type ChatRequestBody = {
  messages?: unknown;
  datasetContext?: { name: string; columns: string[]; rows: Record<string, unknown>[] };
};

export const Route = createFileRoute("/api/chat")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { messages, datasetContext } = (await request.json()) as ChatRequestBody;
        if (!Array.isArray(messages)) return new Response("Messages required", { status: 400 });

        const key = process.env.LOVABLE_API_KEY;
        if (!key) return new Response("Missing LOVABLE_API_KEY", { status: 500 });

        const gateway = createLovableAiGatewayProvider(key);

        const ctxText = datasetContext
          ? `\n\nACTIVE DATASET: "${datasetContext.name}"\nColumns: ${datasetContext.columns.join(", ")}\nRows (${datasetContext.rows.length}):\n${JSON.stringify(datasetContext.rows.slice(0, 200), null, 2)}`
          : "\n\nNo dataset currently loaded.";

        const system = `You are a security analyst assistant for SBOM (Software Bill of Materials) and VAPT (Vulnerability Assessment & Penetration Testing) data. Help the user understand components, identify vulnerabilities, suggest remediations, and answer questions about the loaded dataset.

When asked about CVEs, vulnerabilities, or security advisories for specific components/versions, use the lookup_vulnerability tool to fetch the latest public knowledge from the NVD/OSV databases. Cite versions and CVE IDs precisely. Render tables in markdown when helpful.${ctxText}`;

        const result = streamText({
          model: gateway("google/gemini-3-flash-preview"),
          system,
          messages: await convertToModelMessages(messages as UIMessage[]),
          stopWhen: stepCountIs(8),
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
