import { afterEach, expect, mock, test } from "bun:test";
import { cvssFromVector, resolveSeverity } from "./nist-scoring";
import { buildPlatformAnalysis, kpiPredicate } from "./platform-intel";
import { enrichRows, mergeIntel } from "./lifecycle-enrich";
import { intelKey } from "./vuln-intel";

mock.module("@tanstack/react-start", () => ({
  createServerFn: () => ({ inputValidator: () => ({ handler: (fn) => fn }) }),
}));
const { enrichTargets } = await import("./threat-intel.functions");
const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

test("OSV vector scoring gives inventory records critical CVSS 9.8 and confidence 85", () => {
  expect(cvssFromVector(vector)).toBe(9.8);
  const row = { component: "example", version: "1.0", ecosystem: "npm" };
  const result = buildPlatformAnalysis([{ id: "one", data: row }], {
    [intelKey(row)]: { osvCvss: 9.8, osvVector: vector },
  });
  expect(result.profiles[0]?.severity).toBe("critical");
  expect(result.profiles[0]?.cvss).toBe(9.8);
  expect(result.profiles[0]?.scoreConfidence).toBe(85);
  expect(row).toEqual({ component: "example", version: "1.0", ecosystem: "npm" });
});

test("NVD, uploaded scores and uploaded vectors each take precedence over OSV", () => {
  expect(resolveSeverity({ nvdScore: 7.5, uploadedScore: 8, osvScore: 9.8, declared: "none" }).score).toBe(7.5);
  expect(resolveSeverity({ uploadedScore: 4, osvScore: 9.8, declared: "none" }).score).toBe(4);
  expect(resolveSeverity({ vector, osvScore: 4, declared: "none" }).score).toBe(9.8);
});

test("multi-version count equals the three components displayed by its filter", () => {
  const analysis = buildPlatformAnalysis([
    { id: "1", data: { component: "lib", version: "1" } },
    { id: "2", data: { component: "lib", version: "2" } },
    { id: "3", data: { component: "lib", version: "2" } },
    { id: "4", data: { component: "other", version: "1" } },
  ]);
  expect(analysis.counts.multiVersion).toBe(3);
  expect(analysis.profiles.filter(kpiPredicate("multiVersion", analysis))).toHaveLength(3);
});

test("inventory enrichment passes package identifiers and sends unscored OSV CVEs to NVD", async () => {
  const row = { component: "sample", version: "1", ecosystem: "npm", purl: "pkg:npm/sample@1" };
  const key = intelKey(row);
  let merged = {};
  await enrichRows([row], {}, {
    enrich: async ({ data }) => {
      expect(data.targets[0]?.purl).toBe("pkg:npm/sample@1");
      expect(data.targets[0]?.ecosystem).toBe("npm");
      return { intel: { [key]: { cves: ["CVE-2024-12345"] } }, updatedAt: "2026-10-17" };
    },
    nvd: async ({ data }) => {
      expect(data.cves).toEqual(["CVE-2024-12345"]);
      return { records: { "CVE-2024-12345": { cvss: 9.8, vector, published: "2024-01-01", exploitDate: "", cve: "CVE-2024-12345", severity: "critical" } }, fetchedAt: "2026-10-17" };
    },
  }, (patch) => { merged = mergeIntel(merged, patch); });
  expect(merged).toMatchObject({ [key]: { cvss: 9.8, cves: ["CVE-2024-12345"] } });
});

test("OSV package queries score the worst vector, detect KEV, and never replace a CVE-specific score", async () => {
  const queries = [];
  globalThis.fetch = mock(async (input, init) => {
    const url = String(input);
    if (url.includes("known_exploited")) return Response.json({ vulnerabilities: [{ cveID: "CVE-2024-12345" }] });
    if (url.includes("api.osv.dev")) {
      queries.push(JSON.parse(String(init?.body)));
      return Response.json({ vulns: [{ id: "GHSA-test", aliases: ["CVE-2024-12345"], severity: [{ type: "CVSS_V3", score: vector }] }] });
    }
    return Response.json([], { status: 404 });
  });
  const result = await enrichTargets([
    { key: "inventory", component: "test-package", version: "1", cve: "", purl: "pkg:npm/test-package@1" },
    { key: "specific", component: "another-package", version: "2", cve: "CVE-2025-54321", ecosystem: "pypi" },
  ]);
  expect(queries).toContainEqual({ package: { purl: "pkg:npm/test-package@1" } });
  expect(queries).toContainEqual({ package: { name: "another-package", ecosystem: "PyPI" }, version: "2" });
  expect(result.intel.inventory).toMatchObject({ osvCvss: 9.8, kev: true, cves: ["CVE-2024-12345"] });
  expect(result.intel.specific?.osvCvss).toBeUndefined();
  expect(result.intel.specific?.kev).toBe(false);
});