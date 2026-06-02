/**
 * Standardized logging helpers.
 *
 * Centralising console output here keeps message styling consistent and
 * makes it easy to silence or redirect output in tests.
 */

import chalk from "chalk";

/** Print a raw, already-formatted line to stdout. */
export function raw(message = "") {
  console.log(message);
}

/** A blank spacer line. */
export function blank() {
  console.log();
}

/** Neutral informational message. */
export function info(message) {
  console.log(chalk.gray(`  ${message}`));
}

/** Success message (green check). */
export function success(message) {
  console.log(chalk.green(`  ✔ ${message}`));
}

/** Warning message (yellow). */
export function warn(message) {
  console.log(chalk.yellow(`  ⚠  ${message}`));
}

/** Error message (red) — written to stderr. */
export function error(message) {
  console.error(chalk.red(`  ✖ ${message}`));
}

export default { raw, blank, info, success, warn, error };
