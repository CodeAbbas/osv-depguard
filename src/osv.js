/**
 * OSV.dev querying and vulnerability list construction.
 */

import {
  OSV_API_URL,
  OSV_BATCH_SIZE,
  OSV_ECOSYSTEM,
} from "./constants.js";
import { extractSeverity, meetsMinSeverity } from "./severity.js";
import { rankOf } from "./utils.js";

/**
 * Query the OSV.dev batch endpoint for a list of packages.
 *
 * Results are returned in the same order as the input `packages`, so the
 * caller can correlate `results[i]` with `packages[i]`.
 *
 * @param {Array<[string, string]>} packages    Array of [name, version] pairs.
 * @param {object}   [deps]
 * @param {Function} [deps.fetchImpl]            Injectable fetch (defaults to global).
 * @returns {Promise<Array<object>>} OSV result objects.
 */
export async function queryOSV(packages, { fetchImpl = globalThis.fetch } = {}) {
  const queries = packages.map(([name, version]) => ({
    version,
    package: { name, ecosystem: OSV_ECOSYSTEM },
  }));

  const allResults = [];

  for (let i = 0; i < queries.length; i += OSV_BATCH_SIZE) {
    const batch = queries.slice(i, i + OSV_BATCH_SIZE);
    const res = await fetchImpl(OSV_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: batch }),
    });

    if (!res.ok) {
      throw new Error(`OSV API ${res.status}: ${res.statusText}`);
    }

    const data = await res.json();
    allResults.push(...(data.results || []));
  }

  return allResults;
}

/**
 * Extract the first "fixed" version advertised by an OSV vuln record.
 *
 * @param {object} vuln
 * @returns {string|null}
 */
export function extractFixedVersion(vuln) {
  const fixed = (vuln.affected || [])
    .flatMap((a) => a.ranges || [])
    .flatMap((r) => r.events || [])
    .map((e) => e.fixed)
    .filter(Boolean);
  return fixed[0] || null;
}

/**
 * Build a flat, normalised, sorted list of vulnerabilities from OSV results.
 *
 * @param {Array<[string, string]>} packages   Array of [name, version] pairs.
 * @param {Array<object>}           osvResults  Results aligned with `packages`.
 * @param {number}                  [minRank]   Minimum severity rank to include.
 * @returns {Array<object>} Normalised vulnerability objects.
 */
export function buildVulnList(packages, osvResults, minRank = 0) {
  const vulns = [];

  packages.forEach(([name, version], idx) => {
    const result = osvResults[idx];
    if (!result?.vulns?.length) return;

    for (const vuln of result.vulns) {
      const severity = extractSeverity(vuln);
      if (!meetsMinSeverity(severity, minRank)) continue;

      vulns.push({
        package: name,
        version,
        id: vuln.id,
        aliases: (vuln.aliases || []).filter((a) => a.startsWith("CVE-")),
        severity,
        summary: vuln.summary || "No summary available",
        details: vuln.details || "",
        fixedIn: extractFixedVersion(vuln),
        references: (vuln.references || []).map((r) => r.url).slice(0, 2),
      });
    }
  });

  // Sort: highest severity first, then alphabetically by package name.
  vulns.sort(
    (a, b) =>
      rankOf(b.severity) - rankOf(a.severity) ||
      a.package.localeCompare(b.package)
  );

  return vulns;
}
