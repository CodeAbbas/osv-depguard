#!/usr/bin/env node

/**
 * OSV - DepGuard — Deterministic Hybrid Vulnerability Scanner
 *
 * Pipeline:
 *   1. Parse package-lock.json  →  exact installed versions 
 *   2. Batch query OSV.dev API  →  deterministic, real CVE data
 *   3. Send OSV results to AI   →  human-readable summaries & remediation steps only
 *   4. Render colour-coded table via chalk + cli-table3
 */

import "dotenv/config";
import chalk from "chalk";
import ora from "ora";
import { Command } from "commander";
import Table from "cli-table3";
import fs from "fs";
import path from "path";

// ─── API key guard ────────────────────────────────────────────────────────────
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
if (!ANTHROPIC_API_KEY) {
  console.error(
    chalk.red("\n  ✖ ANTHROPIC_API_KEY is not set.\n") +
      chalk.gray("  Add it to a .env file or export it in your shell:\n\n") +
      chalk.white("    echo 'ANTHROPIC_API_KEY=sk-ant-...' >> .env\n") +
      chalk.yellow("\n  ⚠  Make sure .env is listed in your .gitignore!\n")
  );
  process.exit(1);
}

// ─── CLI ──────────────────────────────────────────────────────────────────────
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
    "low"
  )
  .option("--json", "Output raw JSON instead of table")
  .parse(process.argv);

const opts = program.opts();
const [scanDir] = program.args.length ? program.args : ["."];
const lockPath = path.resolve(scanDir, "package-lock.json");

// ─── Load package-lock.json ───────────────────────────────────────────────────
if (!fs.existsSync(lockPath)) {
  console.error(
    chalk.red(`\n  ✖ Cannot find package-lock.json at: ${lockPath}`) +
      chalk.gray("\n  Run `npm install` first to generate a lockfile.\n")
  );
  process.exit(1);
}

const lock = JSON.parse(fs.readFileSync(lockPath, "utf-8"));
const lockVersion = lock.lockfileVersion || 1;

/**
 * Extract exact installed package versions from the lockfile.
 * Supports lockfileVersion 1, 2, and 3.
 */
function extractPackages(lock, includeDev) {
  const packages = {};

  if (lockVersion >= 2 && lock.packages) {
    // v2 / v3: "packages" map — keys like "node_modules/chalk"
    for (const [key, meta] of Object.entries(lock.packages)) {
      if (!key || key === "") continue; // skip the root project entry
      if (!includeDev && meta.dev) continue;
      const name = key.replace(/^.*node_modules\//, "");
      if (name && meta.version) packages[name] = meta.version;
    }
  } else if (lock.dependencies) {
    for (const [name, meta] of Object.entries(lock.dependencies)) {
      if (!includeDev && meta.dev) continue;
      if (meta.version) packages[name] = meta.version;
    }
  }

  return packages;
}

const packageMap = extractPackages(lock, opts.dev !== false);
const packageEntries = Object.entries(packageMap);

if (packageEntries.length === 0) {
  console.log(chalk.yellow("\n  No packages found in lockfile.\n"));
  process.exit(0);
}

// ─── OSV.dev batch query ──────────────────────────────────────────────────────
/**
 * OSV batch endpoint — up to 1000 queries per call.
 * https://google.github.io/osv.dev/post-v1-querybatch
 */
async function queryOSV(packages) {
  const queries = packages.map(([name, version]) => ({
    version,
    package: { name, ecosystem: "npm" },
  }));

  const BATCH_SIZE = 1000;
  const allResults = [];

  for (let i = 0; i < queries.length; i += BATCH_SIZE) {
    const batch = queries.slice(i, i + BATCH_SIZE);
    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: batch }),
    });

    if (!res.ok) throw new Error(`OSV API ${res.status}: ${res.statusText}`);

    const data = await res.json();
    allResults.push(...(data.results || []));
  }

  return allResults;
}

// ─── Severity helpers ─────────────────────────────────────────────────────────
const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
const MIN_RANK =
  SEVERITY_RANK[(opts.minSeverity || "low").toUpperCase()] ?? 1;

function extractSeverity(vuln) {
  const candidates = [
    ...(vuln.severity || []),
    ...(vuln.database_specific?.severity
      ? [{ score: vuln.database_specific.severity }]
      : []),
  ];

  for (const s of candidates) {
    const score = (s.score || "").toUpperCase();
    if (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(score)) return score;
    const num = parseFloat(score);
    if (!isNaN(num)) {
      if (num >= 9.0) return "CRITICAL";
      if (num >= 7.0) return "HIGH";
      if (num >= 4.0) return "MEDIUM";
      return "LOW";
    }
  }
  return "UNKNOWN";
}

function colourSeverity(sev) {
  switch (sev) {
    case "CRITICAL": return chalk.bgRed.white.bold(` ${sev} `);
    case "HIGH":     return chalk.red.bold(sev);
    case "MEDIUM":   return chalk.yellow.bold(sev);
    case "LOW":      return chalk.blue(sev);
    default:         return chalk.gray(sev);
  }
}

// ─── Build vulnerability list from OSV data ───────────────────────────────────
function buildVulnList(packages, osvResults) {
  const vulns = [];

  packages.forEach(([name, version], idx) => {
    const result = osvResults[idx];
    if (!result?.vulns?.length) return;

    for (const vuln of result.vulns) {
      const severity = extractSeverity(vuln);
      if ((SEVERITY_RANK[severity] ?? 0) < MIN_RANK) continue;

      // Extract fixed version from affected ranges
      const fixedVersions = (vuln.affected || [])
        .flatMap((a) => a.ranges || [])
        .flatMap((r) => r.events || [])
        .map((e) => e.fixed)
        .filter(Boolean);

      vulns.push({
        package: name,
        version,
        id: vuln.id,
        aliases: (vuln.aliases || []).filter((a) => a.startsWith("CVE-")),
        severity,
        summary: vuln.summary || "No summary available",
        details: vuln.details || "",
        fixedIn: fixedVersions[0] || null,
        references: (vuln.references || []).map((r) => r.url).slice(0, 2),
      });
    }
  });

  // Sort: highest severity first, then alphabetically by package name
  vulns.sort(
    (a, b) =>
      (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) ||
      a.package.localeCompare(b.package)
  );

  return vulns;
}

// ─── AI enrichment (interpretation only — no web search) ─────────────────────
/**
 * Claude (or any other AI model) receives only the verified OSV data and produces:
 *   - humanSummary: plain English explanation of the real risk
 *   - remediationStep: concrete actionable fix command
 *
 * No tools, no web search — Claude cannot invent vulnerabilities.
 */
async function enrichWithAI(vulns) {
  if (vulns.length === 0) return [];

  const payload = vulns.map((v) => ({
    id: v.id,
    package: v.package,
    installedVersion: v.version,
    severity: v.severity,
    summary: v.summary,
    details: v.details.slice(0, 600), // keep prompt size reasonable
    fixedIn: v.fixedIn,
    aliases: v.aliases,
  }));

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1000,
      system: `You are a security advisor. You will receive structured vulnerability data sourced directly from the OSV.dev database.
Your only job is to interpret this data and produce output that is easier for developers to act on.
Do NOT invent, assume, or add any information not present in the input.
Respond ONLY with a valid JSON array (no markdown, no backticks, no preamble):
[
  {
    "id": "<OSV id from input>",
    "humanSummary": "2-3 sentences in plain English describing the risk, attack vector, and potential impact",
    "remediationStep": "A single specific command or action the developer should take (e.g. 'Run: npm install packageName@X.Y.Z')"
  }
]`,
      messages: [
        {
          role: "user",
          content: `Generate human-readable summaries and remediation steps for these verified vulnerabilities:\n\n${JSON.stringify(payload, null, 2)}`,
        },
      ],
    }),
  });

  if (!res.ok) throw new Error(`Anthropic API ${res.status}: ${res.statusText}`);

  const data = await res.json();
  const text =
    data.content
      ?.filter((b) => b.type === "text")
      .map((b) => b.text)
      .join("") || "[]";

  const clean = text.replace(/```json|```/g, "").trim();
  return JSON.parse(clean);
}

// ─── Render table ─────────────────────────────────────────────────────────────
function renderTable(enriched) {
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

// ─── .gitignore check ────────────────────────────────────────────────────────
function checkGitignore(dir) {
  const gitignorePath = path.resolve(dir, ".gitignore");
  if (!fs.existsSync(gitignorePath)) {
    console.log(
      chalk.yellow("  ⚠  No .gitignore found.\n") +
        chalk.gray('     Create one and add .env:\n') +
        chalk.white('     echo ".env" >> .gitignore\n')
    );
    return;
  }
  const content = fs.readFileSync(gitignorePath, "utf-8");
  if (!content.split("\n").some((l) => l.trim() === ".env")) {
    console.log(
      chalk.yellow("  ⚠  .env is not in your .gitignore — your API key could be exposed!\n") +
        chalk.white('     Fix it now: echo ".env" >> .gitignore\n')
    );
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
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

  // ── Step 1: Query OSV.dev ─────────────────────────────────────────────────
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

  // ── Step 2: Build vuln list ───────────────────────────────────────────────
  const vulns = buildVulnList(packageEntries, osvResults);

  if (vulns.length === 0) {
    console.log(
      chalk.green(
        "\n  ✔ No vulnerabilities found" +
          (opts.minSeverity !== "low" ? ` at or above ${opts.minSeverity} severity` : "") +
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

  // ── Step 3: AI enrichment ─────────────────────────────────────────────────
  const aiSpinner = ora({
    text: chalk.gray("Generating human-readable summaries & remediation steps…"),
    color: "cyan",
  }).start();

  let aiData = [];
  try {
    aiData = await enrichWithAI(vulns);
    aiSpinner.succeed(chalk.green("AI interpretation complete"));
  } catch (err) {
    aiSpinner.warn(
      chalk.yellow("AI enrichment failed — falling back to raw OSV summaries\n  ") +
        chalk.gray(err.message)
    );
  }

  // Merge AI data into vuln objects
  const aiMap = Object.fromEntries((aiData || []).map((a) => [a.id, a]));
  const enriched = vulns.map((v) => ({
    ...v,
    humanSummary: aiMap[v.id]?.humanSummary || v.summary,
    remediationStep:
      aiMap[v.id]?.remediationStep ||
      (v.fixedIn ? `Run: npm install ${v.package}@${v.fixedIn}` : "No fix available"),
  }));

  // ── Step 4: Output ────────────────────────────────────────────────────────
  if (opts.json) {
    console.log(JSON.stringify(enriched, null, 2));
    return;
  }

  console.log();
  renderTable(enriched);

  // Summary bar
  const counts = enriched.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {});

  const summaryParts = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    .filter((s) => counts[s])
    .map((s) => colourSeverity(s) + chalk.gray(` ×${counts[s]}`));

  console.log(
    "\n  " + chalk.bold("Summary   ") + summaryParts.join(chalk.gray("   ")) + "\n"
  );

  // Advisory references
  const withRefs = enriched.filter((v) => v.references?.length);
  if (withRefs.length > 0) {
    console.log(chalk.bold.gray("  Advisory Links"));
    for (const v of withRefs) {
      console.log(chalk.gray(`  ${chalk.cyan(v.id)}`));
      v.references.forEach((url) =>
        console.log(chalk.gray("    → ") + chalk.underline(url))
      );
    }
    console.log();
  }
}

main().catch((err) => {
  console.error(chalk.red("\n  Unexpected error: " + err.message));
  process.exit(1);
});