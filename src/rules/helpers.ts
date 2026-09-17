import type { ConfigFile, ConfigFileType } from "../types.js";
import { isExampleLikePath as isExampleLikePathString } from "../source-context.js";
import { maskSensitive } from "../detection/index.js";

/**
 * Shared helpers for detection rules. Kept here so the secrets, PII,
 * credentials, and codes modules share one implementation of line numbers,
 * match iteration, file classification, and false-positive suppression.
 */

export function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split("\n").length;
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
]);

export function isTextLikeFile(file: ConfigFile): boolean {
  return TEXT_LIKE_FILE_TYPES.has(file.type);
}

export function isMarkdownLikeFile(file: ConfigFile): boolean {
  return [
    "claude-md",
    "agent-md",
    "skill-md",
    "command-md",
    "agents-md",
    "rule-md",
    "context-md",
    "markdown-generic",
  ].includes(file.type);
}

export function isExampleLikePath(file: ConfigFile): boolean {
  return isExampleLikePathString(file.path);
}

/**
 * True when the match position sits inside an open fenced code block. Used to
 * suppress generic/context heuristics on documentation code examples while
 * leaving high-signal vendor and checksum-validated detections active.
 */
export function isInsideCodeFence(content: string, matchIndex: number): boolean {
  const before = content.slice(0, matchIndex);
  const fences = before.match(/```|~~~/g);
  return fences !== null && fences.length % 2 === 1;
}

export function hasNearbyCodeFence(content: string, matchIndex: number): boolean {
  const windowStart = Math.max(0, matchIndex - 800);
  const windowEnd = Math.min(content.length, matchIndex + 800);
  const window = content.slice(windowStart, windowEnd);
  return /```|~~~~/.test(window);
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
    hasNearbyCodeFence(file.content, matchIndex) ||
    hasExampleOrTestContext(file.content, matchIndex)
  );
}
