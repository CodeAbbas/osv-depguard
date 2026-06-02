/**
 * Shared constants used across DepGuard modules.
 */

/** Numeric ranking for severities — higher means more severe. */
export const SEVERITY_RANK = Object.freeze({
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
});

/** Severities ordered from most to least severe (for summaries). */
export const SEVERITY_ORDER = Object.freeze([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "UNKNOWN",
]);

/** Named severity levels (excludes UNKNOWN). */
export const NAMED_SEVERITIES = Object.freeze(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);

/** Default minimum severity when the user does not pass --min-severity. */
export const DEFAULT_MIN_SEVERITY = "low";

/** CVSS numeric score thresholds → qualitative severity. */
export const CVSS_THRESHOLDS = Object.freeze({
  CRITICAL: 9.0,
  HIGH: 7.0,
  MEDIUM: 4.0,
});

/** OSV.dev batch query endpoint — accepts up to 1000 queries per call. */
export const OSV_API_URL = "https://api.osv.dev/v1/querybatch";
export const OSV_BATCH_SIZE = 1000;
export const OSV_ECOSYSTEM = "npm";

/** Anthropic Messages API configuration. */
export const ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages";
export const ANTHROPIC_VERSION = "2023-06-01";
export const ANTHROPIC_MODEL = "claude-sonnet-4-20250514";
export const ANTHROPIC_MAX_TOKENS = 1000;
