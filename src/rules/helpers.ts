import type { ConfigFile, ConfigFileType } from "../types.js";
import { isExampleLikePath as isExampleLikePathString } from "../source-context.js";
import { maskSensitive } from "../detection/index.js";
import { isInsideCodeFenceAt, lineNumberAt } from "./file-context.js";

/**
 * Shared helpers for detection rules. Kept here so the secrets, PII,
 * credentials, and codes modules share one implementation of line numbers,
 * match iteration, file classification, and false-positive suppression.
 */

export function findLineNumber(file: ConfigFile, matchIndex: number): number {
  return lineNumberAt(file, matchIndex);
}

export function findAllMatches(content: string, pattern: RegExp): Array<RegExpMatchArray> {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  return [...content.matchAll(new RegExp(pattern.source, flags))];
}

export function maskSecretValue(value: string): string {
  return maskSensitive(value);
}

/**
 * File types that carry free-form text or configuration. Detection rules use
 * this to cover skills, agents, commands, rules, contexts, and generic
 * markdown/text/env/config files — not just CLAUDE.md and agent.md.
 */
export const TEXT_LIKE_FILE_TYPES: ReadonlySet<ConfigFileType> = new Set([
  "claude-md",
  "agent-md",
  "skill-md",
  "command-md",
  "agents-md",
  "rule-md",
  "context-md",
  "markdown-generic",
  "text-generic",
  "env-file",
  "config-generic",
  "harness-json",
  "settings-json",
  "mcp-json",
  "codex-toml",
  "hermes-yaml",
  // Hook implementations are security-relevant surfaces too.
  "hook-script",
  "hook-code",
]);

const MARKDOWN_LIKE_FILE_TYPES: ReadonlySet<ConfigFileType> = new Set([
  "claude-md",
  "agent-md",
  "skill-md",
  "command-md",
  "agents-md",
  "rule-md",
  "context-md",
  "markdown-generic",
]);

export function isTextLikeFile(file: ConfigFile): boolean {
  return TEXT_LIKE_FILE_TYPES.has(file.type);
}

export function isMarkdownLikeFile(file: ConfigFile): boolean {
  return MARKDOWN_LIKE_FILE_TYPES.has(file.type);
}

export function isExampleLikePath(file: ConfigFile): boolean {
  return isExampleLikePathString(file.path);
}

/**
 * True when the match position sits inside an open fenced code block. Uses the
 * per-file fence index (O(log n)) instead of rescanning the prefix.
 */
export function isInsideCodeFence(file: ConfigFile, matchIndex: number): boolean {
  return isInsideCodeFenceAt(file, matchIndex);
}

export function hasNearbyCodeFence(content: string, matchIndex: number): boolean {
  const windowStart = Math.max(0, matchIndex - 800);
  const windowEnd = Math.min(content.length, matchIndex + 800);
  const window = content.slice(windowStart, windowEnd);
  return /```|~~~/.test(window);
}

export function hasExampleOrTestContext(content: string, matchIndex: number): boolean {
  const windowStart = Math.max(0, matchIndex - 1200);
  const windowEnd = Math.min(content.length, matchIndex + 400);
  const window = content.slice(windowStart, windowEnd).toLowerCase();

  return [
    "example",
    "sample",
    "fixture",
    "test(",
    "shouldbe",
    "returns invalid",
    "returns valid",
    " passed",
    " failed",
    "funspec",
    "stringspec",
    "behaviorspec",
  ].some((marker) => window.includes(marker));
}

/**
 * Generic suppression for markdown-like files inside example-like paths where a
 * nearby code fence or example/test wording suggests the value is illustrative.
 */
export function isLikelyExampleValue(file: ConfigFile, matchIndex: number): boolean {
  if (!isMarkdownLikeFile(file)) return false;
  if (!isExampleLikePath(file)) return false;
  return (
    isInsideCodeFence(file, matchIndex) ||
    hasExampleOrTestContext(file.content, matchIndex)
  );
}
