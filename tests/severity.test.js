import { describe, it, expect } from "vitest";
import {
  severityFromScore,
  extractSeverity,
  minSeverityRank,
  meetsMinSeverity,
  colourSeverity,
} from "../src/severity.js";

describe("severityFromScore", () => {
  it("maps CVSS numbers to qualitative labels", () => {
    expect(severityFromScore(9.8)).toBe("CRITICAL");
    expect(severityFromScore(9.0)).toBe("CRITICAL");
    expect(severityFromScore(7.5)).toBe("HIGH");
    expect(severityFromScore(7.0)).toBe("HIGH");
    expect(severityFromScore(5.0)).toBe("MEDIUM");
    expect(severityFromScore(4.0)).toBe("MEDIUM");
    expect(severityFromScore(2.1)).toBe("LOW");
    expect(severityFromScore(0)).toBe("LOW");
  });
});

describe("extractSeverity", () => {
  it("returns UNKNOWN for missing/invalid input", () => {
    expect(extractSeverity(null)).toBe("UNKNOWN");
    expect(extractSeverity(undefined)).toBe("UNKNOWN");
    expect(extractSeverity({})).toBe("UNKNOWN");
    expect(extractSeverity({ severity: [] })).toBe("UNKNOWN");
  });

  it("reads qualitative labels from the severity array", () => {
    expect(extractSeverity({ severity: [{ score: "high" }] })).toBe("HIGH");
    expect(extractSeverity({ severity: [{ score: "CRITICAL" }] })).toBe("CRITICAL");
  });

  it("converts numeric CVSS scores in the severity array", () => {
    expect(extractSeverity({ severity: [{ score: "9.1" }] })).toBe("CRITICAL");
    expect(extractSeverity({ severity: [{ score: "5.5" }] })).toBe("MEDIUM");
  });

  it("falls back to database_specific.severity", () => {
    expect(
      extractSeverity({ database_specific: { severity: "MODERATE-but-7.2" } })
    ).toBe("UNKNOWN"); // not a clean label nor number
    expect(extractSeverity({ database_specific: { severity: "8.0" } })).toBe("HIGH");
    expect(extractSeverity({ database_specific: { severity: "low" } })).toBe("LOW");
  });

  it("prefers the first usable candidate", () => {
    const vuln = {
      severity: [{ score: "MEDIUM" }],
      database_specific: { severity: "CRITICAL" },
    };
    expect(extractSeverity(vuln)).toBe("MEDIUM");
  });
});

describe("minSeverityRank", () => {
  it("resolves levels case-insensitively", () => {
    expect(minSeverityRank("critical")).toBe(4);
    expect(minSeverityRank("HIGH")).toBe(3);
    expect(minSeverityRank("medium")).toBe(2);
    expect(minSeverityRank("low")).toBe(1);
  });

  it("defaults to LOW for unknown or missing levels", () => {
    expect(minSeverityRank()).toBe(1);
    expect(minSeverityRank("bogus")).toBe(1);
  });
});

describe("meetsMinSeverity", () => {
  it("compares ranks correctly", () => {
    expect(meetsMinSeverity("CRITICAL", 3)).toBe(true);
    expect(meetsMinSeverity("HIGH", 3)).toBe(true);
    expect(meetsMinSeverity("MEDIUM", 3)).toBe(false);
    expect(meetsMinSeverity("UNKNOWN", 1)).toBe(false);
  });
});

describe("colourSeverity", () => {
  it("includes the label text for every level", () => {
    for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]) {
      expect(colourSeverity(sev)).toContain(sev);
    }
  });
});
