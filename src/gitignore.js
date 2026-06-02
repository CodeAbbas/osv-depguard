/**
 * .gitignore safety check — warns when .env is not ignored so API keys
 * are not accidentally committed.
 */

import fs from "fs";
import path from "path";
import * as log from "./logger.js";

/**
 * Whether a .gitignore body ignores the `.env` file.
 *
 * @param {string} content Raw .gitignore contents.
 * @returns {boolean}
 */
export function isEnvIgnored(content) {
  if (typeof content !== "string") return false;
  return content.split("\n").some((line) => line.trim() === ".env");
}

/**
 * Inspect a directory's .gitignore and warn (via the logger) if `.env`
 * is missing or unignored. Returns the status so callers/tests can assert.
 *
 * @param {string} dir Directory to check.
 * @returns {"missing"|"unignored"|"ok"}
 */
export function checkGitignore(dir) {
  const gitignorePath = path.resolve(dir, ".gitignore");

  if (!fs.existsSync(gitignorePath)) {
    log.warn("No .gitignore found.");
    log.info("   Create one and add .env:");
    log.info('   echo ".env" >> .gitignore');
    return "missing";
  }

  const content = fs.readFileSync(gitignorePath, "utf-8");
  if (!isEnvIgnored(content)) {
    log.warn(".env is not in your .gitignore — your API key could be exposed!");
    log.info('   Fix it now: echo ".env" >> .gitignore');
    return "unignored";
  }

  return "ok";
}
