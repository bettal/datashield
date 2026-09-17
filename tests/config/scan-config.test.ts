import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  DEFAULT_SCAN_CONFIG,
  ScanConfigError,
  loadScanConfig,
  mergeScanConfig,
  resolveScanConfigPaths,
} from "../../src/config/scan-config.js";

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "datashield-config-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe("DEFAULT_SCAN_CONFIG", () => {
  it("enables recursion and the generic content scan by default", () => {
    expect(DEFAULT_SCAN_CONFIG.genericScan).toBe(true);
    expect(DEFAULT_SCAN_CONFIG.genericScanExamples).toBe(false);
    expect(DEFAULT_SCAN_CONFIG.directories.some((rule) => rule.recursive === true)).toBe(true);
  });

  it("maps generic extensions for markdown, text, env and config files", () => {
    const byExtension = new Map(
      DEFAULT_SCAN_CONFIG.extensions.map((rule) => [rule.extension, rule.type])
    );
    expect(byExtension.get(".md")).toBe("markdown-generic");
    expect(byExtension.get(".txt")).toBe("text-generic");
    expect(byExtension.get(".env")).toBe("env-file");
    expect(byExtension.get(".json")).toBe("config-generic");
  });

  it("registers OpenCode surfaces for discovery", () => {
    const paths = DEFAULT_SCAN_CONFIG.directories.map((rule) => rule.path);
    expect(paths).toContain(".opencode/agents");
    expect(paths).toContain(".opencode/skills");
    expect(DEFAULT_SCAN_CONFIG.files.some((rule) => rule.name === "AGENTS.md")).toBe(true);
  });
});

describe("mergeScanConfig", () => {
  it("appends new directories and keeps existing ones", () => {
    const merged = mergeScanConfig(DEFAULT_SCAN_CONFIG, {
      directories: [{ path: "custom-skills", type: "skill-md", recursive: true }],
    });

    const paths = merged.directories.map((rule) => rule.path);
    expect(paths).toContain("skills");
    expect(paths).toContain("custom-skills");
  });

  it("overrides a directory rule with the same path and type", () => {
    const merged = mergeScanConfig(DEFAULT_SCAN_CONFIG, {
      directories: [{ path: "skills", type: "skill-md", recursive: false }],
    });

    const skillsRule = merged.directories.find((rule) => rule.path === "skills");
    expect(skillsRule?.recursive).toBe(false);
  });

  it("unions ignored dirs without duplicating", () => {
    const merged = mergeScanConfig(DEFAULT_SCAN_CONFIG, {
      ignoredDirs: ["node_modules", "custom-ignore"],
    });

    expect(merged.ignoredDirs.filter((dir) => dir === "node_modules")).toHaveLength(1);
    expect(merged.ignoredDirs).toContain("custom-ignore");
  });

  it("overrides scalar toggles", () => {
    const merged = mergeScanConfig(DEFAULT_SCAN_CONFIG, { genericScan: false });
    expect(merged.genericScan).toBe(false);
  });
});

describe("resolveScanConfigPaths", () => {
  it("orders global, project and env override last", () => {
    const scanRoot = createTempDir();
    const home = createTempDir();
    const envPath = join(createTempDir(), "explicit.json");

    const paths = resolveScanConfigPaths(scanRoot, {
      HOME: home,
      DATASHIELD_SCAN_CONFIG: envPath,
    } as NodeJS.ProcessEnv);

    expect(paths).toContain(join(home, ".config", "datashield", "scan.json"));
    expect(paths).toContain(join(scanRoot, "datashield.config.json"));
    expect(paths[paths.length - 1]).toBe(envPath);
  });
});

describe("loadScanConfig", () => {
  it("returns defaults when no override file exists", () => {
    const scanRoot = createTempDir();
    const home = createTempDir();

    const config = loadScanConfig({ scanRoot, env: { HOME: home } as NodeJS.ProcessEnv });

    expect(config.genericScan).toBe(DEFAULT_SCAN_CONFIG.genericScan);
    expect(config.directories).toHaveLength(DEFAULT_SCAN_CONFIG.directories.length);
  });

  it("merges a project override file", () => {
    const scanRoot = createTempDir();
    const home = createTempDir();
    writeFileSync(
      join(scanRoot, "datashield.config.json"),
      JSON.stringify({
        directories: [{ path: "leaks", type: "text-generic", recursive: true }],
        genericScan: false,
      })
    );

    const config = loadScanConfig({ scanRoot, env: { HOME: home } as NodeJS.ProcessEnv });

    expect(config.directories.some((rule) => rule.path === "leaks")).toBe(true);
    expect(config.genericScan).toBe(false);
  });

  it("lets the env override win over the project file", () => {
    const scanRoot = createTempDir();
    const home = createTempDir();
    const overrideDir = createTempDir();

    writeFileSync(
      join(scanRoot, "datashield.config.json"),
      JSON.stringify({ genericScan: false })
    );
    const envPath = join(overrideDir, "scan.json");
    writeFileSync(envPath, JSON.stringify({ genericScan: true }));

    const config = loadScanConfig({
      scanRoot,
      env: { HOME: home, DATASHIELD_SCAN_CONFIG: envPath } as NodeJS.ProcessEnv,
    });

    expect(config.genericScan).toBe(true);
  });

  it("re-reads the configuration on every call so runtime changes are picked up", () => {
    const scanRoot = createTempDir();
    const home = createTempDir();
    const configPath = join(scanRoot, "datashield.config.json");

    writeFileSync(configPath, JSON.stringify({ directories: [{ path: "a", type: "text-generic" }] }));
    const first = loadScanConfig({ scanRoot, env: { HOME: home } as NodeJS.ProcessEnv });
    expect(first.directories.some((rule) => rule.path === "a")).toBe(true);

    writeFileSync(configPath, JSON.stringify({ directories: [{ path: "b", type: "text-generic" }] }));
    const second = loadScanConfig({ scanRoot, env: { HOME: home } as NodeJS.ProcessEnv });
    expect(second.directories.some((rule) => rule.path === "b")).toBe(true);
    expect(second.directories.some((rule) => rule.path === "a")).toBe(false);
  });

  it("fails closed on invalid JSON", () => {
    const scanRoot = createTempDir();
    const home = createTempDir();
    writeFileSync(join(scanRoot, "datashield.config.json"), "{ not json");

    expect(() =>
      loadScanConfig({ scanRoot, env: { HOME: home } as NodeJS.ProcessEnv })
    ).toThrow(ScanConfigError);
  });

  it("fails closed on schema violations", () => {
    const scanRoot = createTempDir();
    const home = createTempDir();
    writeFileSync(
      join(scanRoot, "datashield.config.json"),
      JSON.stringify({ directories: [{ path: "x", type: "not-a-real-type" }] })
    );

    expect(() =>
      loadScanConfig({ scanRoot, env: { HOME: home } as NodeJS.ProcessEnv })
    ).toThrow(ScanConfigError);
  });

  it("reads a global override from ~/.config/datashield/scan.json", () => {
    const scanRoot = createTempDir();
    const home = createTempDir();
    mkdirSync(join(home, ".config", "datashield"), { recursive: true });
    writeFileSync(
      join(home, ".config", "datashield", "scan.json"),
      JSON.stringify({ genericScan: false })
    );

    const config = loadScanConfig({ scanRoot, env: { HOME: home } as NodeJS.ProcessEnv });
    expect(config.genericScan).toBe(false);
  });
});
