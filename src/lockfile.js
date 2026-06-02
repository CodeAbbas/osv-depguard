/**
 * package-lock.json discovery, loading, and package extraction.
 */

import fs from "fs";
import path from "path";
import { readJsonFile } from "./utils.js";

/**
 * Resolve the path to a project's package-lock.json.
 *
 * @param {string} dir Directory to scan.
 * @returns {string} Absolute path to the expected lockfile.
 */
export function resolveLockPath(dir) {
  return path.resolve(dir, "package-lock.json");
}

/**
 * Load and parse a lockfile, returning the parsed object plus its version.
 * Throws a descriptive error if the file is missing or malformed.
 *
 * @param {string} lockPath Absolute path to package-lock.json.
 * @returns {{ lock: object, lockVersion: number }}
 */
export function loadLockfile(lockPath) {
  if (!fs.existsSync(lockPath)) {
    throw new Error(`Cannot find package-lock.json at: ${lockPath}`);
  }
  const lock = readJsonFile(lockPath, "package-lock.json");
  return { lock, lockVersion: lock.lockfileVersion || 1 };
}

/**
 * Extract exact installed package versions from a parsed lockfile.
 * Supports lockfileVersion 1, 2, and 3.
 *
 * @param {object}  lock         Parsed lockfile object.
 * @param {boolean} [includeDev] Whether to include devDependencies.
 * @returns {Record<string, string>} Map of package name → exact version.
 */
export function extractPackages(lock, includeDev = true) {
  const packages = {};
  if (!lock || typeof lock !== "object") return packages;

  const lockVersion = lock.lockfileVersion || 1;

  if (lockVersion >= 2 && lock.packages) {
    // v2 / v3: "packages" map — keys like "node_modules/chalk"
    for (const [key, meta] of Object.entries(lock.packages)) {
      if (!key) continue; // skip the root project entry ("")
      if (!includeDev && meta.dev) continue;
      const name = key.replace(/^.*node_modules\//, "");
      if (name && meta.version) packages[name] = meta.version;
    }
  } else if (lock.dependencies) {
    // v1: nested "dependencies" map
    for (const [name, meta] of Object.entries(lock.dependencies)) {
      if (!includeDev && meta.dev) continue;
      if (meta.version) packages[name] = meta.version;
    }
  }

  return packages;
}
