import { describe, it, expect, vi } from "vitest";
import { buildAiPayload, enrichWithAI, mergeAiData } from "../src/ai.js";

const sampleVulns = [
  {
    id: "GHSA-1",
    package: "chalk",
    version: "5.3.0",
    severity: "HIGH",
    summary: "summary text",
    details: "x".repeat(900),
    fixedIn: "5.3.1",
    aliases: ["CVE-2021-1"],
  },
];

function mockResponse(body, ok = true, status = 200) {
  return {
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    json: async () => body,
  };
}

describe("buildAiPayload", () => {
  it("truncates details to 600 chars and keeps key fields", () => {
    const [p] = buildAiPayload(sampleVulns);
    expect(p.details).toHaveLength(600);
    expect(p).toMatchObject({
      id: "GHSA-1",
      package: "chalk",
      installedVersion: "5.3.0",
      severity: "HIGH",
      fixedIn: "5.3.1",
    });
  });

  it("tolerates missing details", () => {
    const [p] = buildAiPayload([{ id: "x" }]);
    expect(p.details).toBe("");
  });
});

describe("enrichWithAI", () => {
  it("returns [] for empty input without calling fetch", async () => {
    const fetchImpl = vi.fn();
    expect(await enrichWithAI([], { apiKey: "k", fetchImpl })).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("throws when no API key is provided", async () => {
    await expect(enrichWithAI(sampleVulns, { apiKey: "" })).rejects.toThrow(
      /ANTHROPIC_API_KEY is required/
    );
  });

  it("parses a clean JSON array response", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      mockResponse({
        content: [
          {
            type: "text",
            text: '[{"id":"GHSA-1","humanSummary":"hs","remediationStep":"rs"}]',
          },
        ],
      })
    );
    const out = await enrichWithAI(sampleVulns, { apiKey: "k", fetchImpl });
    expect(out).toEqual([
      { id: "GHSA-1", humanSummary: "hs", remediationStep: "rs" },
    ]);

    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toContain("api.anthropic.com");
    expect(init.headers["x-api-key"]).toBe("k");
  });

  it("strips markdown fences before parsing", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      mockResponse({
        content: [{ type: "text", text: '```json\n[{"id":"a"}]\n```' }],
      })
    );
    const out = await enrichWithAI(sampleVulns, { apiKey: "k", fetchImpl });
    expect(out).toEqual([{ id: "a" }]);
  });

  it("throws on a non-ok API response", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(mockResponse({}, false, 429));
    await expect(
      enrichWithAI(sampleVulns, { apiKey: "k", fetchImpl })
    ).rejects.toThrow(/Anthropic API 429/);
  });

  it("throws a descriptive error on unparseable model output", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      mockResponse({ content: [{ type: "text", text: "not json at all" }] })
    );
    await expect(
      enrichWithAI(sampleVulns, { apiKey: "k", fetchImpl })
    ).rejects.toThrow(/Failed to parse AI response/);
  });

  it("defaults to an empty array when content has no text blocks", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(mockResponse({ content: [] }));
    const out = await enrichWithAI(sampleVulns, { apiKey: "k", fetchImpl });
    expect(out).toEqual([]);
  });
});

describe("mergeAiData", () => {
  it("merges AI summaries by id", () => {
    const merged = mergeAiData(sampleVulns, [
      { id: "GHSA-1", humanSummary: "human", remediationStep: "do this" },
    ]);
    expect(merged[0].humanSummary).toBe("human");
    expect(merged[0].remediationStep).toBe("do this");
  });

  it("falls back to OSV summary and fix command when AI is missing", () => {
    const merged = mergeAiData(sampleVulns, []);
    expect(merged[0].humanSummary).toBe("summary text");
    expect(merged[0].remediationStep).toBe("Run: npm install chalk@5.3.1");
  });

  it("reports no fix when none is available", () => {
    const merged = mergeAiData([{ ...sampleVulns[0], fixedIn: null }], []);
    expect(merged[0].remediationStep).toBe("No fix available");
  });

  it("tolerates null aiData", () => {
    const merged = mergeAiData(sampleVulns, null);
    expect(merged[0].humanSummary).toBe("summary text");
  });
});
