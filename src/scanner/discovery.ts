import {
  readFileSync,
  existsSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  statSync,
  lstatSync,
} from "node:fs";
import type { Stats, Dirent } from "node:fs";
import { join, basename, extname, relative, isAbsolute } from "node:path";
import type { ConfigFile, ConfigFileType, DanglingSymlink, ScanTarget } from "../types.js";
import { isExampleLikePath } from "../source-context.js";
import { loadScanConfig } from "../config/scan-config.js";
import type { ScanConfig, DirectoryRule } from "../config/scan-config.js";
import { toPosixPath } from "./paths.js";

const CLAUDE_RUNTIME_COMPANION_NAMES: ReadonlyArray<string> = [
  "settings.json",
  "settings.local.json",
  "mcp.json",
  ".mcp.json",
  ".claude.json",
];

const HOOK_SHELL_EXTENSIONS = new Set([
  ".sh",
  ".bash",
  ".zsh",
]);

const HOOK_CODE_EXTENSIONS = new Set([
  ".js",
  ".cjs",
  ".mjs",
  ".ts",
  ".cts",
  ".mts",
  ".py",
  ".rb",
]);

const HOOK_IMPLEMENTATION_EXTENSIONS = new Set([
  ...HOOK_SHELL_EXTENSIONS,
  ...HOOK_CODE_EXTENSIONS,
]);

const PACKAGE_MANAGER_CONFIG_FILES = new Set([
  "package.json",
  "package-lock.json",
  ".npmrc",
  ".pnpmrc",
  ".yarnrc",
  ".yarnrc.yml",
  "pnpm-workspace.yaml",
  "pnpm-workspace.yml",
]);

const PROJECT_ROOT_HOOK_VARS = new Set([
  "CLAUDE_PLUGIN_ROOT",
  "CLAUDE_PROJECT_DIR",
  "PWD",
]);

/**
 * Resolved, read-once view of a `ScanConfig` used during a single discovery
 * pass. Building the Sets/Maps once keeps the recursive walk cheap while still
 * reading the config fresh on every scan.
 */
interface DiscoveryEnv {
  readonly config: ScanConfig;
  readonly ignoredDirs: ReadonlySet<string>;
  readonly harnessRootDirs: ReadonlySet<string>;
  readonly rootMarkers: ReadonlySet<string>;
  readonly runtimeCompanions: ReadonlySet<string>;
  readonly extensionTypes: ReadonlyMap<string, ConfigFileType>;
  /** Real (symlink-resolved) scan root, used for containment checks. */
  readonly realScanRoot: string;
  /** Real directory paths already visited by the configured-directory pass. */
  readonly visitedConfiguredDirs: Set<string>;
  /** Real directory paths already visited by the generic scan pass. */
  readonly visitedGenericDirs: Set<string>;
}

function buildDiscoveryEnv(config: ScanConfig, realScanRoot: string): DiscoveryEnv {
  return {
    config,
    ignoredDirs: new Set(config.ignoredDirs),
    harnessRootDirs: new Set(config.harnessRootDirs),
    rootMarkers: new Set(config.rootMarkers.map((marker) => marker.toLowerCase())),
    runtimeCompanions: new Set(CLAUDE_RUNTIME_COMPANION_NAMES),
    extensionTypes: new Map(
      config.extensions.map((rule) => [rule.extension.toLowerCase(), rule.type])
    ),
    realScanRoot,
    visitedConfiguredDirs: new Set<string>(),
    visitedGenericDirs: new Set<string>(),
  };
}

function safeRealpath(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

/** True when `candidate` is the root or lives inside it (lexically or via realpath). */
function isWithinRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/**
 * Discover all configuration files in a directory.
 *
 * The first step is always to resolve the scan configuration (defaults merged
 * with any global/project/env overrides). Discovery is then driven entirely by
 * that configuration: exact file names, directory rules (with optional
 * recursion), and an optional generic content scan by extension.
 */
export function discoverConfigFiles(rootPath: string, config?: ScanConfig): ScanTarget {
  const realScanRoot = safeRealpath(rootPath);
  const env = buildDiscoveryEnv(config ?? loadScanConfig({ scanRoot: rootPath }), realScanRoot);
  const files: ConfigFile[] = [];
  const danglingSymlinks: DanglingSymlink[] = [];
  const seenFiles = new Set<string>();
  const claudeRoots = new Set<string>([rootPath]);
  const exampleClaudeFiles = new Set<string>();

  walkForClaudeRoots(rootPath, rootPath, claudeRoots, exampleClaudeFiles, env);

  for (const exampleClaudeFile of [...exampleClaudeFiles].sort()) {
    addDiscoveredFile(rootPath, exampleClaudeFile, "claude-md", files, seenFiles, env);
  }

  for (const claudeRoot of [...claudeRoots].sort()) {
    scanClaudeRoot(rootPath, claudeRoot, files, seenFiles, danglingSymlinks, env);
  }

  discoverGenericContent(rootPath, rootPath, files, seenFiles, danglingSymlinks, env);

  return { path: rootPath, files, danglingSymlinks };
}

/**
 * statSync that follows symlinks but never throws. Returns null when the
 * path is missing, a dangling symlink, or otherwise unreadable.
 */
function statOrNull(path: string): Stats | null {
  try {
    return statSync(path);
  } catch {
    return null;
  }
}

const MAX_GENERIC_FILE_BYTES = 5_000_000;

function safeReaddir(dirPath: string): ReadonlyArray<string> {
  try {
    return readdirSync(dirPath);
  } catch {
    return [];
  }
}

function safeReaddirDirents(dirPath: string): ReadonlyArray<Dirent> {
  try {
    return readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return [];
  }
}

function isDanglingSymlink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

function readSymlinkTarget(path: string): string {
  try {
    return readlinkSync(path);
  } catch {
    return "";
  }
}

/**
 * Record a dangling symlink once. Multiple discovery passes (configured dirs
 * and the generic scan) can reach the same broken link; dedup by path keeps
 * the report stable.
 */
function addDanglingSymlink(
  danglingSymlinks: DanglingSymlink[],
  path: string,
  target: string,
  type: ConfigFileType
): void {
  if (danglingSymlinks.some((entry) => entry.path === path)) return;
  danglingSymlinks.push({ path, target, type });
}

function walkForClaudeRoots(
  scanRoot: string,
  dirPath: string,
  claudeRoots: Set<string>,
  exampleClaudeFiles: Set<string>,
  env: DiscoveryEnv
): void {
  if (!statOrNull(dirPath)?.isDirectory()) return;

  const entries = safeReaddirDirents(dirPath);
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (env.ignoredDirs.has(entry.name)) continue;
      if (env.harnessRootDirs.has(entry.name)) {
        claudeRoots.add(dirPath);
      }
      if (entry.name === ".claude") {
        claudeRoots.add(dirPath);
        continue;
      }
      walkForClaudeRoots(scanRoot, join(dirPath, entry.name), claudeRoots, exampleClaudeFiles, env);
      continue;
    }

    if (!entry.isFile()) continue;
    if (env.rootMarkers.has(entry.name.toLowerCase())) {
      if (isExampleOnlyClaudeRoot(scanRoot, dirPath, entry.name, env)) {
        exampleClaudeFiles.add(join(dirPath, entry.name));
        continue;
      }
      claudeRoots.add(dirPath);
    }
  }
}

function isExampleOnlyClaudeRoot(
  scanRoot: string,
  dirPath: string,
  markerName: string,
  env: DiscoveryEnv
): boolean {
  if (markerName.toLowerCase() !== "claude.md") return false;

  const relativeDir = relative(scanRoot, dirPath);
  const segments = relativeDir
    .split(/[\\/]/)
    .filter(Boolean)
    .map((segment) => segment.toLowerCase())
    .join("/");

  if (!isExampleLikePath(segments)) {
    return false;
  }

  const hasRuntimeCompanion = [...env.runtimeCompanions].some((name) =>
    existsSync(join(dirPath, name))
  ) || existsSync(join(dirPath, ".claude"));

  return !hasRuntimeCompanion;
}

function scanClaudeRoot(
  scanRoot: string,
  claudeRoot: string,
  files: ConfigFile[],
  seenFiles: Set<string>,
  danglingSymlinks: DanglingSymlink[],
  env: DiscoveryEnv
): void {
  // Direct config files (exact names from the scan configuration).
  for (const rule of env.config.files) {
    const fullPath = join(claudeRoot, rule.name);
    if (existsSync(fullPath)) {
      addDiscoveredFile(scanRoot, fullPath, rule.type, files, seenFiles, env);
    }
  }

  // Directory rules, optionally recursive.
  for (const rule of env.config.directories) {
    const dirPath = join(claudeRoot, rule.path);
    if (!statOrNull(dirPath)?.isDirectory()) continue;
    collectDirectoryFiles(scanRoot, dirPath, rule, files, seenFiles, danglingSymlinks, env);
  }

  discoverHermesProfiles(scanRoot, claudeRoot, files, seenFiles, env);
  discoverReferencedHookScripts(scanRoot, claudeRoot, files, seenFiles, env);
}

/**
 * Collect files under a configured directory. When the rule is recursive the
 * walk descends into nested subdirectories (still honouring ignored dirs), so
 * skills/agents/commands that use per-item folders are discovered.
 */
function collectDirectoryFiles(
  scanRoot: string,
  dirPath: string,
  rule: DirectoryRule,
  files: ConfigFile[],
  seenFiles: Set<string>,
  danglingSymlinks: DanglingSymlink[],
  env: DiscoveryEnv
): void {
  const realDir = safeRealpath(dirPath);
  if (!isWithinRoot(env.realScanRoot, realDir)) return;
  const visitKey = `${rule.path}\u0000${realDir}`;
  if (env.visitedConfiguredDirs.has(visitKey)) return;
  env.visitedConfiguredDirs.add(visitKey);

  const entries = safeReaddir(dirPath);
  for (const entry of entries) {
    const entryPath = join(dirPath, entry);
    const entryStat = statOrNull(entryPath);

    if (entryStat === null) {
      if (isDanglingSymlink(entryPath)) {
        addDanglingSymlink(
          danglingSymlinks,
          toPosixPath(relative(scanRoot, entryPath)),
          readSymlinkTarget(entryPath),
          rule.type
        );
      }
      continue;
    }

    if (entryStat.isDirectory()) {
      if (rule.recursive && !env.ignoredDirs.has(entry)) {
        collectDirectoryFiles(scanRoot, entryPath, rule, files, seenFiles, danglingSymlinks, env);
      }
      continue;
    }

    if (!entryStat.isFile()) continue;
    if (rule.extensions && !rule.extensions.includes(extname(entry).toLowerCase())) continue;

    addDiscoveredFile(scanRoot, entryPath, inferType(entry, rule.type), files, seenFiles, env);
  }
}

/**
 * Generic content scan: walk the whole tree and classify any file whose
 * extension is mapped in the configuration. This catches leaks in arbitrary
 * notes, docs, env files, and configs that live outside known harness
 * directories. Disabled when `genericScan` is false.
 */
function discoverGenericContent(
  scanRoot: string,
  dirPath: string,
  files: ConfigFile[],
  seenFiles: Set<string>,
  danglingSymlinks: DanglingSymlink[],
  env: DiscoveryEnv
): void {
  if (!env.config.genericScan) return;
  if (!statOrNull(dirPath)?.isDirectory()) return;

  const realDir = safeRealpath(dirPath);
  if (!isWithinRoot(env.realScanRoot, realDir)) return;
  if (env.visitedGenericDirs.has(realDir)) return;
  env.visitedGenericDirs.add(realDir);

  const entries = safeReaddir(dirPath);
  for (const entry of entries) {
    const entryPath = join(dirPath, entry);
    const entryStat = statOrNull(entryPath);

    if (entryStat === null) {
      if (isDanglingSymlink(entryPath)) {
        addDanglingSymlink(
          danglingSymlinks,
          toPosixPath(relative(scanRoot, entryPath)),
          readSymlinkTarget(entryPath),
          "unknown"
        );
      }
      continue;
    }

    if (entryStat.isDirectory()) {
      if (env.ignoredDirs.has(entry)) continue;
      const relativeDir = toPosixPath(relative(scanRoot, entryPath));
      if (!env.config.genericScanExamples && isExampleLikePath(relativeDir)) continue;
      discoverGenericContent(scanRoot, entryPath, files, seenFiles, danglingSymlinks, env);
      continue;
    }

    if (!entryStat.isFile()) continue;

    const relativePath = toPosixPath(relative(scanRoot, entryPath));
    if (seenFiles.has(relativePath)) continue;

    const type = classifyGenericFile(entry, env);
    if (type === null) continue;

    addDiscoveredFile(scanRoot, entryPath, type, files, seenFiles, env);
  }
}

/**
 * Classify a file by extension for the generic content scan. `.env` files are
 * matched by name because `extname(".env")` is empty.
 */
function classifyGenericFile(filename: string, env: DiscoveryEnv): ConfigFileType | null {
  const lower = filename.toLowerCase();
  if (/^\.env(\.|$)/.test(lower) || lower === ".env") {
    return "env-file";
  }

  const ext = extname(lower);
  if (ext === "") return null;
  return env.extensionTypes.get(ext) ?? null;
}

function discoverHermesProfiles(
  scanRoot: string,
  claudeRoot: string,
  files: ConfigFile[],
  seenFiles: Set<string>,
  env: DiscoveryEnv
): void {
  const profilesDir = join(claudeRoot, "profiles");
  if (!statOrNull(profilesDir)?.isDirectory()) return;
  for (const entry of safeReaddir(profilesDir)) {
    const configPath = join(profilesDir, entry, "config.yaml");
    if (statOrNull(configPath)?.isFile()) {
      addDiscoveredFile(scanRoot, configPath, "hermes-yaml", files, seenFiles, env);
    }
  }
}

function inferType(filename: string, defaultType: ConfigFileType): ConfigFileType {
  const ext = extname(filename).toLowerCase();
  const name = basename(filename).toLowerCase();

  if (PACKAGE_MANAGER_CONFIG_FILES.has(name)) return "package-manager-config";
  if (name === "claude.md") return "claude-md";
  if (name === "settings.json" || name === "settings.local.json") return "settings-json";
  if (name === "mcp.json" || name === ".mcp.json" || name === ".claude.json")
    return "mcp-json";

  if (HOOK_SHELL_EXTENSIONS.has(ext) && defaultType === "hook-script") return "hook-script";
  if (HOOK_CODE_EXTENSIONS.has(ext) && defaultType === "hook-script") return "hook-code";
  if (ext === ".sh" || ext === ".bash" || ext === ".zsh") return "hook-script";
  if (defaultType === "hook-script" && (ext === ".md" || ext === ".markdown")) {
    return "unknown";
  }
  if (defaultType === "mcp-json" && ext === ".json") return "mcp-json";
  if (defaultType === "mcp-json" && (ext === ".md" || ext === ".markdown")) {
    return "unknown";
  }
  if (defaultType === "agent-md" && ext === ".json") return "agent-md";
  if (defaultType === "skill-md" && ext === ".json") return "skill-md";
  if (defaultType === "command-md" && ext === ".json") return "command-md";
  if (defaultType === "agents-md" && (ext === ".md" || ext === ".mdc" || ext === ".markdown" || ext === ""))
    return "agents-md";
  if (defaultType === "codex-toml") return ext === ".toml" ? "codex-toml" : "unknown";
  if (defaultType === "hermes-yaml") return ext === ".yaml" || ext === ".yml" ? "hermes-yaml" : "unknown";
  if (defaultType === "harness-json") return ext === ".json" || ext === ".jsonc" ? "harness-json" : "unknown";
  if (ext === ".json") return "settings-json";
  if (ext === ".md" || ext === ".markdown") return defaultType;

  return "unknown";
}

function discoverReferencedHookScripts(
  scanRoot: string,
  claudeRoot: string,
  files: ConfigFile[],
  seenFiles: Set<string>,
  env: DiscoveryEnv
): void {
  const hookConfigPaths = [
    "settings.json",
    "settings.local.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    "hooks/hooks.json",
    ".claude/hooks/hooks.json",
  ];

  for (const relativeConfigPath of hookConfigPaths) {
    const fullPath = join(claudeRoot, relativeConfigPath);
    if (!statOrNull(fullPath)?.isFile()) continue;

    let content: string;
    try {
      content = readFileSync(fullPath, "utf-8");
    } catch {
      continue;
    }

    for (const candidate of extractHookReferencedPaths(content)) {
      const resolvedPath = resolveHookReferencedPath(scanRoot, claudeRoot, candidate);
      if (!resolvedPath) continue;
      addDiscoveredFile(scanRoot, resolvedPath, inferType(resolvedPath, "hook-script"), files, seenFiles, env);
    }
  }
}

function extractHookReferencedPaths(content: string): ReadonlyArray<string> {
  const referencedPaths = new Set<string>();

  for (const command of extractHookCommands(content)) {
    for (const candidate of extractCommandPathCandidates(command)) {
      referencedPaths.add(candidate);
    }
  }

  return [...referencedPaths];
}

function extractHookCommands(content: string): ReadonlyArray<string> {
  try {
    const config = JSON.parse(content);
    const hookGroups = config?.hooks;
    if (!hookGroups || typeof hookGroups !== "object") return [];

    const commands: string[] = [];

    for (const group of Object.values(hookGroups)) {
      if (!Array.isArray(group)) continue;

      for (const entry of group) {
        commands.push(...extractHookEntryCommands(entry));
      }
    }

    return commands;
  } catch {
    return [];
  }
}

function extractHookEntryCommands(entry: unknown): ReadonlyArray<string> {
  if (!entry || typeof entry !== "object") return [];

  const record = entry as {
    hook?: unknown;
    command?: unknown;
    hooks?: unknown;
  };
  const commands: string[] = [];

  if (typeof record.hook === "string" && record.hook.length > 0) {
    commands.push(record.hook);
  }

  if (typeof record.command === "string" && record.command.length > 0) {
    commands.push(record.command);
  }

  if (Array.isArray(record.hooks)) {
    for (const nestedEntry of record.hooks) {
      if (!nestedEntry || typeof nestedEntry !== "object") continue;
      const nestedCommand = (nestedEntry as { command?: unknown }).command;
      if (typeof nestedCommand === "string" && nestedCommand.length > 0) {
        commands.push(nestedCommand);
      }
    }
  }

  return commands;
}

function extractCommandPathCandidates(command: string): ReadonlyArray<string> {
  const pathPattern = /(?:(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)\/)?(?:\.{1,2}\/)?(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+\.(?:sh|bash|zsh|js|cjs|mjs|ts|cts|mts|py|rb)/gi;
  const candidates: string[] = [];

  for (const match of command.matchAll(pathPattern)) {
    const index = match.index ?? 0;
    if (command.slice(Math.max(0, index - 3), index) === "://") {
      continue;
    }
    candidates.push(match[0]);
  }

  return candidates;
}

function resolveHookReferencedPath(
  scanRoot: string,
  claudeRoot: string,
  candidate: string
): string | null {
  let normalized = candidate.replace(/\\/g, "/");

  if (/^https?:\/\//i.test(normalized) || normalized.startsWith("/") || normalized.startsWith("~")) {
    return null;
  }

  const envVarMatch = normalized.match(/^(?:\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*))\/(.*)$/);
  if (envVarMatch) {
    const varName = envVarMatch[1] ?? envVarMatch[2];
    if (!PROJECT_ROOT_HOOK_VARS.has(varName)) {
      return null;
    }
    normalized = envVarMatch[3];
  }

  if (normalized.startsWith("/")) return null;

  const fullPath = join(claudeRoot, normalized);
  if (!statOrNull(fullPath)?.isFile()) {
    return null;
  }

  const ext = extname(fullPath).toLowerCase();
  if (!HOOK_IMPLEMENTATION_EXTENSIONS.has(ext)) {
    return null;
  }

  const relativePath = relative(scanRoot, fullPath);
  if (relativePath.startsWith("..")) {
    return null;
  }

  return fullPath;
}

function addDiscoveredFile(
  scanRoot: string,
  fullPath: string,
  type: ConfigFileType,
  files: ConfigFile[],
  seenFiles: Set<string>,
  env: DiscoveryEnv
): void {
  const relativePath = toPosixPath(relative(scanRoot, fullPath));
  if (relativePath.startsWith("..") || isAbsolute(relativePath)) return;
  if (seenFiles.has(relativePath)) return;

  // Containment: never follow a symlink that resolves outside the scan root.
  let realPath: string;
  try {
    realPath = realpathSync(fullPath);
  } catch {
    return;
  }
  if (!isWithinRoot(env.realScanRoot, realPath)) return;

  const stats = statOrNull(fullPath);
  if (stats !== null && stats.size > MAX_GENERIC_FILE_BYTES) return;

  let content: string;
  try {
    content = readFileSync(fullPath, "utf-8");
  } catch {
    // Unreadable (permissions, race, binary) — skip rather than abort the scan.
    return;
  }

  files.push({ path: relativePath, type, content });
  seenFiles.add(relativePath);
}
