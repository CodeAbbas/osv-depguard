import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import {
  safeJsonParse,
  tryParseJson,
  readJsonFile,
  stripCodeFences,
  rankOf,
  isNonEmptyString,
} from "../src/utils.js";

describe("safeJsonParse", () => {
  it("parses valid JSON", () => {
    expect(safeJsonParse('{"a":1}', "thing")).toEqual({ a: 1 });
  });

  it("throws with the label on invalid JSON", () => {
    expect(() => safeJsonParse("{bad", "lockfile")).toThrow(
      /Failed to parse lockfile as JSON/
    );
  });

  it("throws a TypeError for non-string input", () => {
    expect(() => safeJsonParse(42, "thing")).toThrow(TypeError);
  });
});

describe("tryParseJson", () => {
  it("returns the parsed value when valid", () => {
    expect(tryParseJson("[1,2]")).toEqual([1, 2]);
  });

  it("returns the fallback when invalid", () => {
    expect(tryParseJson("nope")).toBeNull();
    expect(tryParseJson("nope", [])).toEqual([]);
  });
});

describe("readJsonFile", () => {
  let tmpDir;
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "depguard-utils-"));
  });
  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("reads and parses a JSON file", () => {
    const p = path.join(tmpDir, "x.json");
    fs.writeFileSync(p, '{"ok":true}');
    expect(readJsonFile(p, "x")).toEqual({ ok: true });
  });

  it("throws a read error for a missing file", () => {
    expect(() => readJsonFile(path.join(tmpDir, "nope.json"), "x")).toThrow(
      /Cannot read x/
    );
  });

  it("throws a parse error for malformed content", () => {
    const p = path.join(tmpDir, "bad.json");
    fs.writeFileSync(p, "{bad");
    expect(() => readJsonFile(p, "bad")).toThrow(/Failed to parse bad as JSON/);
  });
});

describe("stripCodeFences", () => {
  it("removes ```json fences", () => {
    expect(stripCodeFences('```json\n[{"a":1}]\n```')).toBe('[{"a":1}]');
  });
  it("removes bare ``` fences and trims", () => {
    expect(stripCodeFences("```\nhello\n```")).toBe("hello");
  });
  it("returns empty string for non-strings", () => {
    expect(stripCodeFences(null)).toBe("");
  });
});

describe("rankOf", () => {
  it("returns numeric ranks and defaults unknowns to 0", () => {
    expect(rankOf("CRITICAL")).toBe(4);
    expect(rankOf("LOW")).toBe(1);
    expect(rankOf("nonsense")).toBe(0);
  });
});

describe("isNonEmptyString", () => {
  it("validates non-empty strings", () => {
    expect(isNonEmptyString("x")).toBe(true);
    expect(isNonEmptyString("  ")).toBe(false);
    expect(isNonEmptyString("")).toBe(false);
    expect(isNonEmptyString(5)).toBe(false);
  });
});
