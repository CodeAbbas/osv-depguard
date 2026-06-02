/**
 * Terminal rendering — vulnerability table, severity summary, advisory links.
 */

import chalk from "chalk";
import Table from "cli-table3";
import { SEVERITY_ORDER } from "./constants.js";
import { colourSeverity } from "./severity.js";

/**
 * Render the main vulnerability table to stdout.
 *
 * @param {Array<object>} enriched
 */
export function renderTable(enriched) {
  const table = new Table({
    head: [
      chalk.bold.white("Package"),
      chalk.bold.white("Installed"),
      chalk.bold.white("ID / CVE"),
      chalk.bold.white("Severity"),
      chalk.bold.white("Human Summary"),
      chalk.bold.white("Remediation"),
    ],
    colWidths: [20, 11, 22, 12, 44, 34],
    wordWrap: true,
    style: { head: [], border: ["gray"] },
  });

  for (const v of enriched) {
    const cveLabel = v.aliases?.length
      ? chalk.gray("\n" + v.aliases.join(", "))
      : "";

    table.push([
      chalk.bold.white(v.package),
      chalk.gray(v.version),
      chalk.cyan(v.id) + cveLabel,
      colourSeverity(v.severity),
      v.humanSummary || v.summary,
      v.remediationStep ||
        (v.fixedIn
          ? chalk.green(`npm i ${v.package}@${v.fixedIn}`)
          : chalk.gray("No fix available")),
    ]);
  }

  console.log(table.toString());
}

/**
 * Tally vulnerabilities by severity.
 *
 * @param {Array<object>} enriched
 * @returns {Record<string, number>}
 */
export function countBySeverity(enriched) {
  return enriched.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {});
}

/**
 * Render the one-line severity summary to stdout.
 *
 * @param {Array<object>} enriched
 */
export function renderSummary(enriched) {
  const counts = countBySeverity(enriched);
  const parts = SEVERITY_ORDER.filter((s) => counts[s]).map(
    (s) => colourSeverity(s) + chalk.gray(` ×${counts[s]}`)
  );

  console.log(
    "\n  " + chalk.bold("Summary   ") + parts.join(chalk.gray("   ")) + "\n"
  );
}

/**
 * Render advisory reference links grouped by vulnerability ID.
 *
 * @param {Array<object>} enriched
 */
export function renderAdvisoryLinks(enriched) {
  const withRefs = enriched.filter((v) => v.references?.length);
  if (withRefs.length === 0) return;

  console.log(chalk.bold.gray("  Advisory Links"));
  for (const v of withRefs) {
    console.log(chalk.gray(`  ${chalk.cyan(v.id)}`));
    v.references.forEach((url) =>
      console.log(chalk.gray("    → ") + chalk.underline(url))
    );
  }
  console.log();
}
