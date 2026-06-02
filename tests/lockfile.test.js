import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import {
  resolveLockPath,
  loadLockfile,
  extractPackages,
} from "../src/lockfile.js";

let tmpDir;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "depguard-lock-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("resolveLockPath", () => {
  it("appends package-lock.json to the directory", () => {
    expect(resolveLockPath("/foo/bar")).toBe(
      path.resolve("/foo/bar", "package-lock.json")
    );
  });
});

describe("loadLockfile", () => {
  it("throws a clear error when the lockfile is missing", () => {
    const missing = path.join(tmpDir, "package-lock.json");
    expect(() => loadLockfile(missing)).toThrow(/Cannot find package-lock.json/);
  });

  it("throws a clear error when the lockfile is malformed JSON", () => {
    const p = path.join(tmpDir, "package-lock.json");
    fs.writeFileSync(p, "{ not valid json ");
    expect(() => loadLockfile(p)).toThrow(/Failed to parse package-lock.json/);
  });

  it("loads and reports the lockfile version", () => {
    const p = path.join(tmpDir, "package-lock.json");
    fs.writeFileSync(p, JSON.stringify({ lockfileVersion: 3, packages: {} }));
    const { lock, lockVersion } = loadLockfile(p);
    expect(lockVersion).toBe(3);
    expect(lock.packages).toEqual({});
  });

  it("defaults lockVersion to 1 when absent", () => {
    const p = path.join(tmpDir, "package-lock.json");
    fs.writeFileSync(p, JSON.stringify({ dependencies: {} }));
    const { lockVersion } = loadLockfile(p);
    expect(lockVersion).toBe(1);
  });
});

describe("extractPackages", () => {
  it("returns an empty map for invalid input", () => {
    expect(extractPackages(null)).toEqual({});
    expect(extractPackages(undefined)).toEqual({});
    expect(extractPackages("nope")).toEqual({});
  });

  it("parses lockfileVersion 2/3 packages map", () => {
    const lock = {
      lockfileVersion: 3,
      packages: {
        "": { name: "root" },
        "node_modules/chalk": { version: "5.3.0" },
        "node_modules/ora": { version: "8.0.1" },
        "node_modules/@scope/pkg": { version: "1.2.3" },
      },
    };
    expect(extractPackages(lock)).toEqual({
      chalk: "5.3.0",
      ora: "8.0.1",
      "@scope/pkg": "1.2.3",
    });
  });

  it("strips nested node_modules paths to the leaf package name", () => {
    const lock = {
      lockfileVersion: 3,
      packages: {
        "node_modules/a/node_modules/b": { version: "2.0.0" },
      },
    };
    expect(extractPackages(lock)).toEqual({ b: "2.0.0" });
  });

  it("excludes dev dependencies when includeDev is false (v3)", () => {
    const lock = {
      lockfileVersion: 3,
      packages: {
        "node_modules/prod": { version: "1.0.0" },
        "node_modules/devtool": { version: "2.0.0", dev: true },
      },
    };
    expect(extractPackages(lock, false)).toEqual({ prod: "1.0.0" });
    expect(extractPackages(lock, true)).toEqual({
      prod: "1.0.0",
      devtool: "2.0.0",
    });
  });

  it("skips entries without a version", () => {
    const lock = {
      lockfileVersion: 3,
      packages: {
        "node_modules/novers": { license: "MIT" },
        "node_modules/good": { version: "1.0.0" },
      },
    };
    expect(extractPackages(lock)).toEqual({ good: "1.0.0" });
  });

  it("parses lockfileVersion 1 dependencies map", () => {
    const lock = {
      lockfileVersion: 1,
      dependencies: {
        chalk: { version: "4.1.2" },
        eslint: { version: "8.0.0", dev: true },
      },
    };
    expect(extractPackages(lock)).toEqual({
      chalk: "4.1.2",
      eslint: "8.0.0",
    });
    expect(extractPackages(lock, false)).toEqual({ chalk: "4.1.2" });
  });
});
