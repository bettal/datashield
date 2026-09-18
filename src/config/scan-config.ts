import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { z } from "zod";
import type { ConfigFileType } from "../types.js";

/**
 * Config-driven scan configuration.
 *
 * DataShield reads a scan configuration before it does anything else. The
 * configuration describes which files/directories to discover, how to classify
 * them, and whether to fall back to a generic content scan. It is resolved on
 * every scan (never cached) so an operator or a running agent can change it
 * between runs — or even mid-session — and have the next scan pick it up.
 *
 * Resolution order (lowest to highest priority):
 *   1. built-in defaults (reproduce the historical AgentShield behaviour)
 *   2. ~/.config/datashield/scan.json (global)
 *   3. <scanRoot>/datashield.config.json (project)
 *   4. $DATASHIELD_SCAN_CONFIG (explicit override)
 *
 * Arrays are merged additively (new dir/subdir/file entries extend the set),
 * while scalar toggles are overridden by the higher-priority source.
 */

export const CONFIG_FILE_TYPES = [
  "claude-md",
  "settings-json",
  "mcp-json",
  "agent-md",
  "skill-md",
  "command-md",
  "hook-script",
  "hook-code",
  "package-manager-config",
  "rule-md",
  "context-md",
  "agents-md",
  "codex-toml",
  "hermes-yaml",
  "harness-json",
  "plugin-manifest",
  "markdown-generic",
  "text-generic",
  "env-file",
  "config-generic",
  "unknown",
] as const satisfies ReadonlyArray<ConfigFileType>;

export const ConfigFileTypeSchema = z.enum(CONFIG_FILE_TYPES);

/**
 * A configured path must stay inside the scan root: reject absolute paths,
 * Windows drive paths, NUL bytes, and any `..` segment. This blocks a
 * repository-local config from redirecting discovery outside the scan root.
 */
export function isSafeRelativePath(value: string): boolean {
  if (value.length === 0) return false;
  if (value.includes("\0")) return false;
  if (value.startsWith("/") || value.startsWith("\\")) return false;
  if (/^[A-Za-z]:[\\/]/.test(value)) return false;
  const segments = value.split(/[\\/]/);
  return segments.every((segment) => segment !== "..");
}

const safeRelativePath = (label: string) =>
  z
    .string()
    .min(1)
    .refine(isSafeRelativePath, {
      message: `${label} must be a relative path inside the scan root (no absolute paths or '..')`,
    });

export const DirectoryRuleSchema = z.object({
  /** Directory path relative to the scan root (may contain "/"). */
  path: safeRelativePath("path"),
  /** File type assigned to every file discovered under this directory. */
  type: ConfigFileTypeSchema,
  /** Recurse into nested subdirectories (default: false). */
  recursive: z.boolean().optional(),
  /** Optional extension allow-list (e.g. [".md", ".markdown"]). */
  extensions: z.array(z.string()).optional(),
});

export const FileRuleSchema = z.object({
  /** Exact file name (may contain "/" for a relative path). */
  name: safeRelativePath("name"),
  type: ConfigFileTypeSchema,
});

export const ExtensionRuleSchema = z.object({
  /** File extension including the leading dot (e.g. ".md"). */
  extension: z.string().regex(/^\.[A-Za-z0-9]+$/, "extension must look like \".md\""),
  type: ConfigFileTypeSchema,
});

// `.strict()` so typos in override keys fail closed instead of being ignored.
const ScanConfigOverrideSchema = z
  .object({
    version: z.literal(1).optional(),
    ignoredDirs: z.array(z.string()).optional(),
    rootMarkers: z.array(z.string()).optional(),
    harnessRootDirs: z.array(z.string()).optional(),
    files: z.array(FileRuleSchema).optional(),
    directories: z.array(DirectoryRuleSchema).optional(),
    extensions: z.array(ExtensionRuleSchema).optional(),
    genericScan: z.boolean().optional(),
    genericScanExamples: z.boolean().optional(),
    maxFiles: z.number().int().positive().optional(),
    maxTotalBytes: z.number().int().positive().optional(),
  })
  .strict();

export const ScanConfigSchema = z.object({
  version: z.literal(1),
  ignoredDirs: z.array(z.string()),
  rootMarkers: z.array(z.string()),
  harnessRootDirs: z.array(z.string()),
  files: z.array(FileRuleSchema),
  directories: z.array(DirectoryRuleSchema),
  extensions: z.array(ExtensionRuleSchema),
  genericScan: z.boolean(),
  genericScanExamples: z.boolean(),
  /** Hard cap on the number of files read in one scan. */
  maxFiles: z.number().int().positive(),
  /** Hard cap on the total bytes read in one scan. */
  maxTotalBytes: z.number().int().positive(),
});

export type DirectoryRule = z.infer<typeof DirectoryRuleSchema>;
export type FileRule = z.infer<typeof FileRuleSchema>;
export type ExtensionRule = z.infer<typeof ExtensionRuleSchema>;
export type ScanConfig = z.infer<typeof ScanConfigSchema>;
export type ScanConfigOverride = z.infer<typeof ScanConfigOverrideSchema>;

/** Directories that are never traversed. */
const DEFAULT_IGNORED_DIRS: ReadonlyArray<string> = [
  ".dmux",
  ".git",
  "node_modules",
  ".next",
  ".nuxt",
  ".turbo",
  ".cache",
  "coverage",
  "dist",
  "build",
  "out",
  "target",
  "vendor",
];

/** File names that make their containing directory a scan root. */
const DEFAULT_ROOT_MARKERS: ReadonlyArray<string> = [
  "claude.md",
  "settings.json",
  "settings.local.json",
  "mcp.json",
  ".mcp.json",
  ".claude.json",
  "agents.md",
  "opencode.json",
];

/** Directories whose presence makes their parent a scan root. */
const DEFAULT_HARNESS_ROOT_DIRS: ReadonlyArray<string> = [
  ".codex",
  ".claude-plugin",
  ".cursor",
  ".gemini",
  ".opencode",
];

/**
 * Exact file names discovered inside every scan root. Mirrors the historical
 * hard-coded `directFiles` table so default behaviour is unchanged.
 */
const DEFAULT_FILES: ReadonlyArray<FileRule> = [
  { name: "CLAUDE.md", type: "claude-md" },
  { name: ".claude/CLAUDE.md", type: "claude-md" },
  { name: "settings.json", type: "settings-json" },
  { name: "settings.local.json", type: "settings-json" },
  { name: ".claude/settings.json", type: "settings-json" },
  { name: ".claude/settings.local.json", type: "settings-json" },
  { name: ".claude/router_runtime.js", type: "hook-code" },
  { name: ".claude/setup.mjs", type: "hook-code" },
  { name: ".vscode/tasks.json", type: "settings-json" },
  { name: ".zed/settings.json", type: "settings-json" },
  { name: ".zed/tasks.json", type: "settings-json" },
  { name: "package.json", type: "package-manager-config" },
  { name: "package-lock.json", type: "package-manager-config" },
  { name: ".npmrc", type: "package-manager-config" },
  { name: ".pnpmrc", type: "package-manager-config" },
  { name: ".yarnrc", type: "package-manager-config" },
  { name: ".yarnrc.yml", type: "package-manager-config" },
  { name: "pnpm-workspace.yaml", type: "package-manager-config" },
  { name: "pnpm-workspace.yml", type: "package-manager-config" },
  { name: ".github/workflows/codeql_analysis.yml", type: "settings-json" },
  { name: ".github/workflows/codeql_analysis.yaml", type: "settings-json" },
  { name: ".config/gh-token-monitor/token", type: "hook-script" },
  { name: ".config/systemd/user/gh-token-monitor.service", type: "hook-script" },
  { name: ".local/bin/gh-token-monitor.sh", type: "hook-script" },
  { name: "Library/LaunchAgents/com.user.gh-token-monitor.plist", type: "settings-json" },
  { name: "mcp.json", type: "mcp-json" },
  { name: ".mcp.json", type: "mcp-json" },
  { name: ".claude/mcp.json", type: "mcp-json" },
  { name: ".claude.json", type: "mcp-json" },
  { name: "CLAUDE.local.md", type: "claude-md" },
  { name: ".claude-plugin/plugin.json", type: "plugin-manifest" },
  { name: ".claude-plugin/marketplace.json", type: "plugin-manifest" },
  { name: "AGENTS.md", type: "agents-md" },
  { name: "AGENTS.override.md", type: "agents-md" },
  { name: ".codex/AGENTS.md", type: "agents-md" },
  { name: "GEMINI.md", type: "agents-md" },
  { name: ".gemini/GEMINI.md", type: "agents-md" },
  { name: ".github/copilot-instructions.md", type: "agents-md" },
  { name: ".cursorrules", type: "agents-md" },
  { name: ".windsurfrules", type: "agents-md" },
  { name: ".clinerules", type: "agents-md" },
  { name: "config.toml", type: "codex-toml" },
  { name: ".codex/config.toml", type: "codex-toml" },
  { name: ".codex/hooks.json", type: "harness-json" },
  { name: "config.yaml", type: "hermes-yaml" },
  { name: ".cursor/mcp.json", type: "mcp-json" },
  { name: ".codeium/windsurf/mcp_config.json", type: "mcp-json" },
  { name: "mcp_config.json", type: "mcp-json" },
  { name: ".roo/mcp.json", type: "mcp-json" },
  { name: ".cline/mcp.json", type: "mcp-json" },
  { name: "cline_mcp_settings.json", type: "mcp-json" },
  { name: "mcp_settings.json", type: "mcp-json" },
  { name: ".cursor/hooks.json", type: "harness-json" },
  { name: ".gemini/settings.json", type: "harness-json" },
  { name: "opencode.json", type: "harness-json" },
  { name: "opencode.jsonc", type: "harness-json" },
  { name: ".opencode/opencode.json", type: "harness-json" },
  { name: ".opencode/AGENTS.md", type: "agents-md" },
];

/**
 * Directories discovered inside every scan root. `recursive: true` walks
 * nested subdirectories so skills/agents/commands that keep per-item folders
 * are found. Mirrors and extends the historical `subdirs` table.
 */
const DEFAULT_DIRECTORIES: ReadonlyArray<DirectoryRule> = [
  { path: "agents", type: "agent-md", recursive: true },
  { path: ".claude/agents", type: "agent-md", recursive: true },
  { path: "subagents", type: "agent-md", recursive: true },
  { path: ".claude/subagents", type: "agent-md", recursive: true },
  { path: "mcp-configs", type: "mcp-json" },
  { path: ".claude/mcp-configs", type: "mcp-json" },
  { path: "mcp", type: "mcp-json" },
  { path: ".claude/mcp", type: "mcp-json" },
  { path: "configs/mcp", type: "mcp-json" },
  { path: "config/mcp", type: "mcp-json" },
  { path: "skills", type: "skill-md", recursive: true },
  { path: ".claude/skills", type: "skill-md", recursive: true },
  { path: "hooks", type: "hook-script" },
  { path: ".claude/hooks", type: "hook-script" },
  { path: ".vscode", type: "hook-script" },
  { path: ".zed", type: "hook-script" },
  { path: "rules", type: "rule-md", recursive: true },
  { path: ".claude/rules", type: "rule-md", recursive: true },
  { path: "contexts", type: "context-md", recursive: true },
  { path: ".claude/contexts", type: "context-md", recursive: true },
  { path: "commands", type: "command-md", recursive: true },
  { path: ".claude/commands", type: "command-md", recursive: true },
  { path: "slash-commands", type: "command-md", recursive: true },
  { path: ".claude/slash-commands", type: "command-md", recursive: true },
  { path: ".github/agents", type: "agents-md" },
  { path: ".github/instructions", type: "agents-md" },
  { path: ".cursor/rules", type: "agents-md" },
  { path: ".windsurf/rules", type: "agents-md" },
  { path: ".roo/rules", type: "agents-md" },
  { path: ".clinerules", type: "agents-md" },
  { path: ".codex/agents", type: "codex-toml" },
  // OpenCode harness surfaces.
  { path: ".opencode/agents", type: "agent-md", recursive: true },
  { path: ".opencode/commands", type: "command-md", recursive: true },
  { path: ".opencode/skills", type: "skill-md", recursive: true },
  { path: ".opencode/plugins", type: "hook-code", recursive: true },
];

/**
 * Extension → type map used by the generic content scan. It catches leaks in
 * arbitrary notes, docs, env files and configs that are not in a known
 * harness directory.
 */
const DEFAULT_EXTENSIONS: ReadonlyArray<ExtensionRule> = [
  { extension: ".md", type: "markdown-generic" },
  { extension: ".markdown", type: "markdown-generic" },
  { extension: ".txt", type: "text-generic" },
  { extension: ".text", type: "text-generic" },
  { extension: ".env", type: "env-file" },
  { extension: ".json", type: "config-generic" },
  { extension: ".jsonc", type: "config-generic" },
  { extension: ".yaml", type: "config-generic" },
  { extension: ".yml", type: "config-generic" },
  { extension: ".toml", type: "config-generic" },
  { extension: ".ini", type: "config-generic" },
  { extension: ".cfg", type: "config-generic" },
  { extension: ".conf", type: "config-generic" },
];

export const DEFAULT_SCAN_CONFIG: ScanConfig = {
  version: 1,
  ignoredDirs: [...DEFAULT_IGNORED_DIRS],
  rootMarkers: [...DEFAULT_ROOT_MARKERS],
  harnessRootDirs: [...DEFAULT_HARNESS_ROOT_DIRS],
  files: [...DEFAULT_FILES],
  directories: [...DEFAULT_DIRECTORIES],
  extensions: [...DEFAULT_EXTENSIONS],
  genericScan: true,
  genericScanExamples: false,
  maxFiles: 20_000,
  maxTotalBytes: 100_000_000,
};

function addUnique(base: ReadonlyArray<string>, extra: ReadonlyArray<string>): string[] {
  const seen = new Set(base);
  const result = [...base];
  for (const item of extra) {
    if (seen.has(item)) continue;
    seen.add(item);
    result.push(item);
  }
  return result;
}

function mergeByKey<T>(base: ReadonlyArray<T>, override: ReadonlyArray<T> | undefined, key: (item: T) => string): T[] {
  if (!override || override.length === 0) return [...base];
  const byKey = new Map<string, T>();
  for (const item of base) byKey.set(key(item), item);
  for (const item of override) byKey.set(key(item), item);
  return [...byKey.values()];
}

/**
 * Append only entries whose key is not already present. Used for
 * repository-local (untrusted) config: it may add new discovery targets but
 * must not override, retype, or remove existing ones.
 */
function appendNewByKey<T>(base: ReadonlyArray<T>, extra: ReadonlyArray<T> | undefined, key: (item: T) => string): T[] {
  if (!extra || extra.length === 0) return [...base];
  const seen = new Set(base.map(key));
  const result = [...base];
  for (const item of extra) {
    const itemKey = key(item);
    if (seen.has(itemKey)) continue;
    seen.add(itemKey);
    result.push(item);
  }
  return result;
}

/** Merge a trusted override on top of a fully-resolved config (override wins). */
export function mergeScanConfig(base: ScanConfig, override: ScanConfigOverride): ScanConfig {
  return {
    version: 1,
    ignoredDirs: addUnique(base.ignoredDirs, override.ignoredDirs ?? []),
    rootMarkers: addUnique(base.rootMarkers, override.rootMarkers ?? []),
    harnessRootDirs: addUnique(base.harnessRootDirs, override.harnessRootDirs ?? []),
    files: mergeByKey(base.files, override.files, (rule) => rule.name),
    directories: mergeByKey(base.directories, override.directories, (rule) => rule.path),
    extensions: mergeByKey(base.extensions, override.extensions, (rule) => rule.extension),
    genericScan: override.genericScan ?? base.genericScan,
    genericScanExamples: override.genericScanExamples ?? base.genericScanExamples,
    maxFiles: override.maxFiles ?? base.maxFiles,
    maxTotalBytes: override.maxTotalBytes ?? base.maxTotalBytes,
  };
}

/**
 * Merge a repository-local (untrusted) override. It is additive-only: it may
 * add new files/directories/extensions/markers, but cannot disable the generic
 * scan, change existing rule types, or add ignore directories. This prevents a
 * scanned repository from silencing the scanner via its own config.
 */
export function mergeAdditiveScanConfig(base: ScanConfig, override: ScanConfigOverride): ScanConfig {
  return {
    version: 1,
    ignoredDirs: [...base.ignoredDirs],
    rootMarkers: appendNewByKey(base.rootMarkers, override.rootMarkers, (marker) => marker),
    harnessRootDirs: appendNewByKey(base.harnessRootDirs, override.harnessRootDirs, (dir) => dir),
    files: appendNewByKey(base.files, override.files, (rule) => rule.name),
    directories: appendNewByKey(base.directories, override.directories, (rule) => rule.path),
    extensions: appendNewByKey(base.extensions, override.extensions, (rule) => rule.extension),
    genericScan: base.genericScan,
    genericScanExamples: base.genericScanExamples,
    maxFiles: base.maxFiles,
    maxTotalBytes: base.maxTotalBytes,
  };
}

function cloneScanConfig(config: ScanConfig): ScanConfig {
  return {
    version: 1,
    ignoredDirs: [...config.ignoredDirs],
    rootMarkers: [...config.rootMarkers],
    harnessRootDirs: [...config.harnessRootDirs],
    files: config.files.map((rule) => ({ ...rule })),
    directories: config.directories.map((rule) => ({ ...rule })),
    extensions: config.extensions.map((rule) => ({ ...rule })),
    genericScan: config.genericScan,
    genericScanExamples: config.genericScanExamples,
    maxFiles: config.maxFiles,
    maxTotalBytes: config.maxTotalBytes,
  };
}

export interface ResolveScanConfigOptions {
  readonly scanRoot: string;
  readonly env?: NodeJS.ProcessEnv;
}

export interface ScanConfigSources {
  /** Operator-controlled, fully-trusted sources (may override anything). */
  readonly trusted: ReadonlyArray<string>;
  /** Repository-local sources (additive-only). */
  readonly project: ReadonlyArray<string>;
}

/**
 * Resolve override sources. Trusted sources (global config + explicit env
 * override) are applied with full override semantics; project sources are
 * applied additively only.
 */
export function resolveScanConfigSources(
  scanRoot: string,
  env: NodeJS.ProcessEnv = process.env
): ScanConfigSources {
  const home = env.HOME ?? env.USERPROFILE ?? homedir();

  const trusted: string[] = [
    join(home, ".config", "datashield", "scan.json"),
    join(home, ".config", "datashield", "config.json"),
  ];
  if (env.DATASHIELD_SCAN_CONFIG && env.DATASHIELD_SCAN_CONFIG.trim() !== "") {
    trusted.push(resolve(env.DATASHIELD_SCAN_CONFIG));
  }

  const project: string[] = [
    join(scanRoot, "datashield.config.json"),
    join(scanRoot, "datashield.scan.json"),
  ];

  return { trusted, project };
}

/** Flat list of candidate override paths (trusted first, project last). */
export function resolveScanConfigPaths(
  scanRoot: string,
  env: NodeJS.ProcessEnv = process.env
): ReadonlyArray<string> {
  const { trusted, project } = resolveScanConfigSources(scanRoot, env);
  return [...trusted, ...project];
}

export class ScanConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanConfigError";
  }
}

function readOverrideFile(path: string): ScanConfigOverride {
  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch (error) {
    throw new ScanConfigError(
      `Failed to read scan config "${path}": ${(error as Error).message}`
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new ScanConfigError(
      `Scan config "${path}" is not valid JSON: ${(error as Error).message}`
    );
  }

  const result = ScanConfigOverrideSchema.safeParse(parsed);
  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
      .join("; ");
    throw new ScanConfigError(`Scan config "${path}" failed validation: ${details}`);
  }

  return result.data;
}

/**
 * Load the effective scan configuration. Reads from disk on every call so
 * changes made while an agent is running are picked up by the next scan.
 */
export function loadScanConfig(options: ResolveScanConfigOptions): ScanConfig {
  const env = options.env ?? process.env;
  const { trusted, project } = resolveScanConfigSources(options.scanRoot, env);

  let config = cloneScanConfig(DEFAULT_SCAN_CONFIG);

  for (const path of trusted) {
    if (!existsSync(path)) continue;
    config = mergeScanConfig(config, readOverrideFile(path));
  }

  // Repository-local config is untrusted: additive-only.
  for (const path of project) {
    if (!existsSync(path)) continue;
    config = mergeAdditiveScanConfig(config, readOverrideFile(path));
  }

  return config;
}
