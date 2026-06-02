import { describe, it, expect, vi } from "vitest";
import { queryOSV, extractFixedVersion, buildVulnList } from "../src/osv.js";

function mockResponse(body, ok = true, status = 200) {
  return {
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    json: async () => body,
  };
}

describe("queryOSV", () => {
  it("posts queries and returns aligned results", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      mockResponse({ results: [{ vulns: [] }, { vulns: [{ id: "X" }] }] })
    );

    const results = await queryOSV(
      [
        ["chalk", "5.3.0"],
        ["ora", "8.0.1"],
      ],
      { fetchImpl }
    );

    expect(results).toHaveLength(2);
    expect(fetchImpl).toHaveBeenCalledOnce();

    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toContain("api.osv.dev");
    const sent = JSON.parse(init.body);
    expect(sent.queries[0]).toEqual({
      version: "5.3.0",
      package: { name: "chalk", ecosystem: "npm" },
    });
  });

  it("throws on a non-ok response", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(mockResponse({}, false, 500));
    await expect(queryOSV([["a", "1.0.0"]], { fetchImpl })).rejects.toThrow(
      /OSV API 500/
    );
  });

  it("batches large package lists", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(mockResponse({ results: [] }));
    const many = Array.from({ length: 1500 }, (_, i) => [`p${i}`, "1.0.0"]);
    await queryOSV(many, { fetchImpl });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("tolerates a response without a results field", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(mockResponse({}));
    const results = await queryOSV([["a", "1.0.0"]], { fetchImpl });
    expect(results).toEqual([]);
  });
});

describe("extractFixedVersion", () => {
  it("returns the first fixed version found", () => {
    const vuln = {
      affected: [
        {
          ranges: [
            {
              events: [{ introduced: "0" }, { fixed: "1.2.3" }],
            },
          ],
        },
      ],
    };
    expect(extractFixedVersion(vuln)).toBe("1.2.3");
  });

  it("returns null when no fix is advertised", () => {
    expect(extractFixedVersion({})).toBeNull();
    expect(extractFixedVersion({ affected: [{ ranges: [] }] })).toBeNull();
  });
});

describe("buildVulnList", () => {
  const packages = [
    ["chalk", "5.3.0"],
    ["lodash", "4.17.0"],
    ["clean", "1.0.0"],
  ];

  const osvResults = [
    {
      vulns: [
        {
          id: "GHSA-aaa",
          severity: [{ score: "MEDIUM" }],
          summary: "chalk issue",
          aliases: ["CVE-2021-1", "GHSA-aaa"],
          affected: [{ ranges: [{ events: [{ fixed: "5.3.1" }] }] }],
          references: [{ url: "https://a" }, { url: "https://b" }, { url: "https://c" }],
        },
      ],
    },
    {
      vulns: [
        {
          id: "GHSA-bbb",
          severity: [{ score: "CRITICAL" }],
          summary: "lodash prototype pollution",
        },
      ],
    },
    null, // a clean package with no result
  ];

  it("normalises vulns, keeps only CVE aliases, and caps references", () => {
    const vulns = buildVulnList(packages, osvResults);
    const chalkVuln = vulns.find((v) => v.package === "chalk");
    expect(chalkVuln.aliases).toEqual(["CVE-2021-1"]);
    expect(chalkVuln.references).toEqual(["https://a", "https://b"]);
    expect(chalkVuln.fixedIn).toBe("5.3.1");
  });

  it("sorts by severity desc then package name", () => {
    const vulns = buildVulnList(packages, osvResults);
    expect(vulns.map((v) => v.package)).toEqual(["lodash", "chalk"]);
  });

  it("filters out vulns below the minimum rank", () => {
    // minRank 4 = CRITICAL only
    const vulns = buildVulnList(packages, osvResults, 4);
    expect(vulns).toHaveLength(1);
    expect(vulns[0].severity).toBe("CRITICAL");
  });

  it("provides defaults for missing summary/fix", () => {
    const vulns = buildVulnList([["x", "1.0.0"]], [{ vulns: [{ id: "Z" }] }]);
    expect(vulns[0].summary).toBe("No summary available");
    expect(vulns[0].fixedIn).toBeNull();
    expect(vulns[0].aliases).toEqual([]);
    expect(vulns[0].references).toEqual([]);
  });

  it("returns an empty list when nothing is vulnerable", () => {
    expect(buildVulnList(packages, [null, null, null])).toEqual([]);
  });
});
