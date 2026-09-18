import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  DEFAULT_SCAN_CONFIG,
  ScanConfigError,
  loadScanConfig,
  mergeAdditiveScanConfig,
  mergeScanConfig,
  resolveScanConfigSources,
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

  it("defines a bounded scan budget", () => {
    expect(DEFAULT_SCAN_CONFIG.maxFiles).toBeGreaterThan(0);
    expect(DEFAULT_SCAN_CONFIG.maxTotalBytes).toBeGreaterThan(0);
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

describe("resolveScanConfigSources", () => {
  it("separates trusted sources from project sources", () => {
    const scanRoot = createTempDir();
    const home = createTempDir();
    const envPath = join(createTempDir(), "explicit.json");

    const { trusted, project } = resolveScanConfigSources(scanRoot, {
      HOME: home,
      DATASHIELD_SCAN_CONFIG: envPath,
    } as NodeJS.ProcessEnv);

    expect(trusted).toContain(join(home, ".config", "datashield", "scan.json"));
    expect(trusted[trusted.length - 1]).toBe(envPath);
    expect(project).toContain(join(scanRoot, "datashield.config.json"));
    expect(project).not.toContain(envPath);
  });
});

describe("mergeAdditiveScanConfig", () => {
  it("adds new targets but cannot override existing rules or toggles", () => {
    const merged = mergeAdditiveScanConfig(DEFAULT_SCAN_CONFIG, {
      genericScan: false,
      ignoredDirs: ["secrets-dir"],
      maxFiles: 1,
      directories: [
        { path: "skills", type: "unknown" },
        { path: "extra", type: "text-generic", recursive: true },
      ],
    });

    expect(merged.genericScan).toBe(DEFAULT_SCAN_CONFIG.genericScan);
    expect(merged.maxFiles).toBe(DEFAULT_SCAN_CONFIG.maxFiles);
    expect(merged.ignoredDirs).not.toContain("secrets-dir");
    expect(merged.directories.find((rule) => rule.path === "skills")?.type).toBe("skill-md");
    expect(merged.directories.some((rule) => rule.path === "extra")).toBe(true);
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

  it("adds discovery targets from a project override file (additive-only)", () => {
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
    // The repository-local config cannot disable the generic scan.
    expect(config.genericScan).toBe(true);
  });

  it("does not let a project config retype an existing directory", () => {
    const scanRoot = createTempDir();
    const home = createTempDir();
    writeFileSync(
      join(scanRoot, "datashield.config.json"),
      JSON.stringify({ directories: [{ path: "skills", type: "unknown" }] })
    );

    const config = loadScanConfig({ scanRoot, env: { HOME: home } as NodeJS.ProcessEnv });
    expect(config.directories.find((rule) => rule.path === "skills")?.type).toBe("skill-md");
  });

  it("fails closed on unknown config keys", () => {
    const scanRoot = createTempDir();
    const home = createTempDir();
    writeFileSync(join(scanRoot, "datashield.config.json"), JSON.stringify({ genericScans: false }));

    expect(() =>
      loadScanConfig({ scanRoot, env: { HOME: home } as NodeJS.ProcessEnv })
    ).toThrow(ScanConfigError);
  });

  it("rejects project config paths that escape the scan root", () => {
    const scanRoot = createTempDir();
    const home = createTempDir();
    writeFileSync(
      join(scanRoot, "datashield.config.json"),
      JSON.stringify({ directories: [{ path: "../../etc", type: "text-generic" }] })
    );

    expect(() =>
      loadScanConfig({ scanRoot, env: { HOME: home } as NodeJS.ProcessEnv })
    ).toThrow(ScanConfigError);
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
