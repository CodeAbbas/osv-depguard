import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { isEnvIgnored, checkGitignore } from "../src/gitignore.js";

describe("isEnvIgnored", () => {
  it("detects an exact .env entry (with surrounding whitespace)", () => {
    expect(isEnvIgnored(".env")).toBe(true);
    expect(isEnvIgnored("node_modules\n.env\n*.log")).toBe(true);
    expect(isEnvIgnored("node_modules\n  .env  \n")).toBe(true);
  });

  it("returns false when .env is absent or only a partial match", () => {
    expect(isEnvIgnored("node_modules\n*.log")).toBe(false);
    expect(isEnvIgnored(".env.local")).toBe(false);
    expect(isEnvIgnored("")).toBe(false);
  });

  it("returns false for non-string input", () => {
    expect(isEnvIgnored(null)).toBe(false);
    expect(isEnvIgnored(undefined)).toBe(false);
  });
});

describe("checkGitignore", () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "depguard-gi-"));
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it("reports 'missing' when there is no .gitignore", () => {
    expect(checkGitignore(tmpDir)).toBe("missing");
  });

  it("reports 'unignored' when .env is not listed", () => {
    fs.writeFileSync(path.join(tmpDir, ".gitignore"), "node_modules\n*.log\n");
    expect(checkGitignore(tmpDir)).toBe("unignored");
  });

  it("reports 'ok' when .env is ignored", () => {
    fs.writeFileSync(path.join(tmpDir, ".gitignore"), "node_modules\n.env\n");
    expect(checkGitignore(tmpDir)).toBe("ok");
  });
});
