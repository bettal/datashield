import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { discoverConfigFiles } from "../../src/scanner/discovery.js";
import { DEFAULT_SCAN_CONFIG } from "../../src/config/scan-config.js";

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "datashield-discovery-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe("discoverConfigFiles (config-driven)", () => {
  it("recurses into skills subdirectories", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "skills", "deep-skill"), { recursive: true });
    writeFileSync(join(dir, "skills", "deep-skill", "SKILL.md"), "# Deep skill");

    const result = discoverConfigFiles(dir);
    const skill = result.files.find((file) => file.path === "skills/deep-skill/SKILL.md");
    expect(skill?.type).toBe("skill-md");
  });

  it("discovers nested OpenCode skills", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, ".opencode", "skills", "nested"), { recursive: true });
    writeFileSync(join(dir, ".opencode", "skills", "nested", "SKILL.md"), "# Nested");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((file) => file.path === ".opencode/skills/nested/SKILL.md")).toBe(true);
  });

  it("generically discovers arbitrary markdown, env and nested config files", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "notes.md"), "# Notes with a secret");
    writeFileSync(join(dir, ".env"), "API_KEY=abc");
    mkdirSync(join(dir, "infra"), { recursive: true });
    writeFileSync(join(dir, "infra", "settings.yaml"), "password: hunter2");

    const result = discoverConfigFiles(dir);
    const byPath = new Map(result.files.map((file) => [file.path, file.type]));

    expect(byPath.get("notes.md")).toBe("markdown-generic");
    expect(byPath.get(".env")).toBe("env-file");
    expect(byPath.get("infra/settings.yaml")).toBe("config-generic");
  });

  it("skips example-like subtrees in the generic scan by default", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "docs"), { recursive: true });
    writeFileSync(join(dir, "docs", "guide.md"), "# Guide");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((file) => file.path === "docs/guide.md")).toBe(false);
  });

  it("includes example-like subtrees when genericScanExamples is enabled", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "docs"), { recursive: true });
    writeFileSync(join(dir, "docs", "guide.md"), "# Guide");

    const result = discoverConfigFiles(dir, { ...DEFAULT_SCAN_CONFIG, genericScanExamples: true });
    expect(result.files.some((file) => file.path === "docs/guide.md")).toBe(true);
  });

  it("does not let a project config disable the generic scan", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "notes.md"), "# Notes");
    writeFileSync(join(dir, "datashield.config.json"), JSON.stringify({ genericScan: false }));

    const result = discoverConfigFiles(dir);
    // Project config is additive-only: the generic scan stays enabled.
    expect(result.files.some((file) => file.path === "notes.md")).toBe(true);
  });

  it("does not let a project config redirect discovery outside the scan root", () => {
    const dir = createTempDir();
    writeFileSync(
      join(dir, "datashield.config.json"),
      JSON.stringify({ directories: [{ path: "../../etc", type: "text-generic", recursive: true }] })
    );

    // The unsafe path is rejected by the schema, so loading throws.
    expect(() => discoverConfigFiles(dir)).toThrow();
  });

  it("honours a project config file that adds a custom directory rule", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "leaks", "nested"), { recursive: true });
    writeFileSync(join(dir, "leaks", "nested", "dump.txt"), "secret");
    writeFileSync(
      join(dir, "datashield.config.json"),
      JSON.stringify({
        genericScan: false,
        directories: [{ path: "leaks", type: "text-generic", recursive: true }],
      })
    );

    const result = discoverConfigFiles(dir);
    expect(result.files.some((file) => file.path === "leaks/nested/dump.txt")).toBe(true);
  });

  it("ignores configured directories during the generic walk", () => {
    const dir = createTempDir();
    mkdirSync(join(dir, "node_modules", "pkg"), { recursive: true });
    writeFileSync(join(dir, "node_modules", "pkg", "index.md"), "# dep");

    const result = discoverConfigFiles(dir);
    expect(result.files.some((file) => file.path.startsWith("node_modules/"))).toBe(false);
  });

  it("accepts an explicit config object and does not read from disk", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "notes.md"), "# Notes");

    const result = discoverConfigFiles(dir, { ...DEFAULT_SCAN_CONFIG, genericScan: false });
    expect(result.files.some((file) => file.path === "notes.md")).toBe(false);
  });
});
