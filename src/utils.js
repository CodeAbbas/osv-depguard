/**
 * Small, dependency-free utility and validation helpers.
 */

import fs from "fs";
import { SEVERITY_RANK } from "./constants.js";

/**
 * Parse JSON, throwing a descriptive error on failure.
 *
 * @param {string} text     Raw JSON string.
 * @param {string} [label]  Human-readable name for the source (used in errors).
 * @returns {*} The parsed value.
 */
export function safeJsonParse(text, label = "data") {
  if (typeof text !== "string") {
    throw new TypeError(`Cannot parse ${label}: expected a string, got ${typeof text}`);
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`Failed to parse ${label} as JSON: ${err.message}`);
  }
}

/**
 * Parse JSON, returning a fallback value instead of throwing on failure.
 * Useful for best-effort parsing where a graceful fallback exists.
 *
 * @param {string} text       Raw JSON string.
 * @param {*}      [fallback] Value to return when parsing fails.
 * @returns {*} The parsed value, or `fallback`.
 */
export function tryParseJson(text, fallback = null) {
  try {
    return JSON.parse(text);
  } catch {
    return fallback;
  }
}

/**
 * Read a UTF-8 file and parse it as JSON, with clear errors for the
 * common failure modes (missing file, malformed JSON).
 *
 * @param {string} filePath Absolute or relative path to a JSON file.
 * @param {string} [label]  Human-readable name for error messages.
 * @returns {*} The parsed value.
 */
export function readJsonFile(filePath, label = "file") {
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf-8");
  } catch (err) {
    throw new Error(`Cannot read ${label} at ${filePath}: ${err.message}`);
  }
  return safeJsonParse(raw, label);
}

/**
 * Strip Markdown code-fence wrappers (```json … ```) from a model response.
 *
 * @param {string} text
 * @returns {string}
 */
export function stripCodeFences(text) {
  if (typeof text !== "string") return "";
  return text.replace(/```json|```/g, "").trim();
}

/**
 * Numeric rank for a severity label, defaulting to 0 (UNKNOWN) for
 * anything unrecognised.
 *
 * @param {string} severity
 * @returns {number}
 */
export function rankOf(severity) {
  return SEVERITY_RANK[severity] ?? 0;
}

/**
 * Whether `value` is a non-empty string.
 * @param {*} value
 * @returns {boolean}
 */
export function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}
