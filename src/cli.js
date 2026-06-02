/**
 * CLI entry point — argument parsing and pipeline orchestration.
 *
 * Pipeline:
 *   1. Parse package-lock.json  →  exact installed versions
 *   2. Batch query OSV.dev API  →  deterministic, real CVE data
 *   3. Send OSV results to AI    →  human-readable summaries & remediation
 *   4. Render colour-coded table via chalk + cli-table3
 */

import "dotenv/config";
import chalk from "chalk";
import ora from "ora";
import { Command } from "commander";

import { DEFAULT_MIN_SEVERITY } from "./constants.js";
import { loadLockfile, resolveLockPath, extractPackages } from "./lockfile.js";
import { queryOSV, buildVulnList } from "./osv.js";
import { minSeverityRank } from "./severity.js";
import { enrichWithAI, mergeAiData } from "./ai.js";
import {
  renderTable,
  renderSummary,
  renderAdvisoryLinks,
} from "./renderer.js";
import { checkGitignore } from "./gitignore.js";
import * as log from "./logger.js";

/** Build the commander program (kept separate for testability). */
export function buildProgram(argv = process.argv) {
  const program = new Command();
  program
    .name("depguard")
    .description("Deterministic hybrid dependency vulnerability scanner")
    .version("1.0.0")
    .argument("[path]", "Directory containing package-lock.json", ".")
    .option("--no-dev", "Skip devDependencies")
    .option(
      "--min-severity <level>",
      "Minimum severity to show: low | medium | high | critical",
      DEFAULT_MIN_SEVERITY
    )
    .option("--json", "Output raw JSON instead of table")
    .parse(argv);
  return program;
}

/** Exit with an error message. */
function fail(message, hint) {
  log.blank();
  log.error(message);
  if (hint) log.info(hint);
  log.blank();
  process.exit(1);
}

export async function main(argv = process.argv) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error(
      chalk.red("\n  ✖ ANTHROPIC_API_KEY is not set.\n") +
        chalk.gray("  Add it to a .env file or export it in your shell:\n\n") +
        chalk.white("    echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env\n") +
        chalk.yellow("\n  ⚠  Make sure .env is listed in your .gitignore!\n")
    );
    process.exit(1);
  }

  const program = buildProgram(argv);
  const opts = program.opts();
  const [scanDir] = program.args.length ? program.args : ["."];
  const lockPath = resolveLockPath(scanDir);

  // ── Load lockfile ──────────────────────────────────────────────────────────
  let lock, lockVersion;
  try {
    ({ lock, lockVersion } = loadLockfile(lockPath));
  } catch (err) {
    return fail(err.message, "Run `npm install` first to generate a lockfile.");
  }

  const packageMap = extractPackages(lock, opts.dev !== false);
  const packageEntries = Object.entries(packageMap);

  if (packageEntries.length === 0) {
    console.log(chalk.yellow("\n  No packages found in lockfile.\n"));
    process.exit(0);
  }

  const minRank = minSeverityRank(opts.minSeverity);

  // ── Banner ───────────────────────────────────────────────────────────────
  console.log(
    "\n" +
      chalk.bold.cyan("  DepGuard") +
      chalk.bold.gray(" v2") +
      chalk.gray("  ·  Deterministic Hybrid Scanner\n") +
      chalk.gray(`  Lockfile  : `) + chalk.white(lockPath) + "\n" +
      chalk.gray(`  Packages  : `) + chalk.white(packageEntries.length) +
      chalk.gray(`  (lockfileVersion ${lockVersion})\n`)
  );

  checkGitignore(scanDir);

  // ── Step 1: Query OSV.dev ──────────────────────────────────────────────────
  const osvSpinner = ora({
    text: chalk.gray(`Querying OSV.dev for ${packageEntries.length} packages…`),
    color: "cyan",
  }).start();

  let osvResults;
  try {
    osvResults = await queryOSV(packageEntries);
    osvSpinner.succeed(chalk.green("OSV.dev scan complete — deterministic results"));
  } catch (err) {
    osvSpinner.fail(chalk.red("OSV.dev query failed: " + err.message));
    process.exit(1);
  }

  // ── Step 2: Build vuln list ────────────────────────────────────────────────
  const vulns = buildVulnList(packageEntries, osvResults, minRank);

  if (vulns.length === 0) {
    console.log(
      chalk.green(
        "\n  ✔ No vulnerabilities found" +
          (opts.minSeverity !== DEFAULT_MIN_SEVERITY
            ? ` at or above ${opts.minSeverity} severity`
            : "") +
          ".\n"
      )
    );
    process.exit(0);
  }

  console.log(
    chalk.gray(`\n  Found `) +
      chalk.bold.red(vulns.length) +
      chalk.gray(` vulnerabilit${vulns.length === 1 ? "y" : "ies"}`) +
      chalk.gray(" — sending to AI for interpretation…\n")
  );

  // ── Step 3: AI enrichment ──────────────────────────────────────────────────
  const aiSpinner = ora({
    text: chalk.gray("Generating human-readable summaries & remediation steps…"),
    color: "cyan",
  }).start();

  let aiData = [];
  try {
    aiData = await enrichWithAI(vulns, { apiKey });
    aiSpinner.succeed(chalk.green("AI interpretation complete"));
  } catch (err) {
    aiSpinner.warn(
      chalk.yellow("AI enrichment failed — falling back to raw OSV summaries\n  ") +
        chalk.gray(err.message)
    );
  }

  const enriched = mergeAiData(vulns, aiData);

  // ── Step 4: Output ─────────────────────────────────────────────────────────
  if (opts.json) {
    console.log(JSON.stringify(enriched, null, 2));
    return;
  }

  console.log();
  renderTable(enriched);
  renderSummary(enriched);
  renderAdvisoryLinks(enriched);
}
