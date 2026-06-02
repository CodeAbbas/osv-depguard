/**
 * Severity extraction and presentation.
 */

import chalk from "chalk";
import {
  CVSS_THRESHOLDS,
  DEFAULT_MIN_SEVERITY,
  NAMED_SEVERITIES,
} from "./constants.js";
import { rankOf } from "./utils.js";

/**
 * Map a CVSS numeric score (0–10) to a qualitative severity label.
 *
 * @param {number} score
 * @returns {"CRITICAL"|"HIGH"|"MEDIUM"|"LOW"}
 */
export function severityFromScore(score) {
  if (score >= CVSS_THRESHOLDS.CRITICAL) return "CRITICAL";
  if (score >= CVSS_THRESHOLDS.HIGH) return "HIGH";
  if (score >= CVSS_THRESHOLDS.MEDIUM) return "MEDIUM";
  return "LOW";
}

/**
 * Determine the severity of an OSV vulnerability record.
 *
 * Looks at both the structured `severity` array and the
 * `database_specific.severity` field, accepting either qualitative
 * labels (e.g. "HIGH") or numeric CVSS scores.
 *
 * @param {object} vuln OSV vulnerability object.
 * @returns {"CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"UNKNOWN"}
 */
export function extractSeverity(vuln) {
  if (!vuln || typeof vuln !== "object") return "UNKNOWN";

  const candidates = [
    ...(Array.isArray(vuln.severity) ? vuln.severity : []),
    ...(vuln.database_specific?.severity
      ? [{ score: vuln.database_specific.severity }]
      : []),
  ];

  for (const candidate of candidates) {
    const score = String(candidate?.score ?? "").toUpperCase();
    if (NAMED_SEVERITIES.includes(score)) return score;

    const num = parseFloat(score);
    if (!Number.isNaN(num)) return severityFromScore(num);
  }

  return "UNKNOWN";
}

/**
 * Resolve a user-supplied minimum severity into a numeric rank.
 * Unknown values fall back to the default (LOW).
 *
 * @param {string} [level]
 * @returns {number}
 */
export function minSeverityRank(level = DEFAULT_MIN_SEVERITY) {
  return rankOf(String(level).toUpperCase()) || rankOf(DEFAULT_MIN_SEVERITY.toUpperCase());
}

/**
 * Whether `severity` meets or exceeds the given minimum rank.
 *
 * @param {string} severity
 * @param {number} minRank
 * @returns {boolean}
 */
export function meetsMinSeverity(severity, minRank) {
  return rankOf(severity) >= minRank;
}

/**
 * Colour-code a severity label for terminal display.
 *
 * @param {string} severity
 * @returns {string}
 */
export function colourSeverity(severity) {
  switch (severity) {
    case "CRITICAL":
      return chalk.bgRed.white.bold(` ${severity} `);
    case "HIGH":
      return chalk.red.bold(severity);
    case "MEDIUM":
      return chalk.yellow.bold(severity);
    case "LOW":
      return chalk.blue(severity);
    default:
      return chalk.gray(severity);
  }
}
