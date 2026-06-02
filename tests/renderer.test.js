import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  countBySeverity,
  renderTable,
  renderSummary,
  renderAdvisoryLinks,
} from "../src/renderer.js";

const enriched = [
  {
    package: "lodash",
    version: "4.17.0",
    id: "GHSA-bbb",
    aliases: ["CVE-2020-2"],
    severity: "CRITICAL",
    summary: "s1",
    humanSummary: "human 1",
    remediationStep: "Run: npm install lodash@4.17.21",
    references: ["https://a", "https://b"],
  },
  {
    package: "chalk",
    version: "5.3.0",
    id: "GHSA-aaa",
    aliases: [],
    severity: "MEDIUM",
    summary: "s2",
    humanSummary: "",
    remediationStep: "",
    fixedIn: null,
    references: [],
  },
];

describe("countBySeverity", () => {
  it("tallies by severity label", () => {
    expect(countBySeverity(enriched)).toEqual({ CRITICAL: 1, MEDIUM: 1 });
  });
});

describe("renderers (output capture)", () => {
  let logs;
  beforeEach(() => {
    logs = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      logs.push(args.join(" "));
    });
  });
  afterEach(() => vi.restoreAllMocks());

  it("renderTable prints package names and ids", () => {
    renderTable(enriched);
    const output = logs.join("\n");
    expect(output).toContain("lodash");
    expect(output).toContain("chalk");
    expect(output).toContain("GHSA-bbb");
  });

  it("renderSummary prints a Summary line with counts", () => {
    renderSummary(enriched);
    const output = logs.join("\n");
    expect(output).toContain("Summary");
    expect(output).toContain("CRITICAL");
    expect(output).toContain("×1");
  });

  it("renderAdvisoryLinks prints links only for vulns that have them", () => {
    renderAdvisoryLinks(enriched);
    const output = logs.join("\n");
    expect(output).toContain("Advisory Links");
    expect(output).toContain("https://a");
    expect(output).toContain("https://b");
  });

  it("renderAdvisoryLinks prints nothing when no references exist", () => {
    renderAdvisoryLinks([{ ...enriched[1] }]);
    expect(logs).toHaveLength(0);
  });
});
