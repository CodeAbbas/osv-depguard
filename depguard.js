#!/usr/bin/env node

/**
 * OSV - DepGuard — Deterministic Hybrid Vulnerability Scanner
 *
 * Thin executable entry point. All logic lives in ./src.
 */

import chalk from "chalk";
import { main } from "./src/cli.js";

main().catch((err) => {
  console.error(chalk.red("\n  Unexpected error: " + err.message));
  process.exit(1);
});
