import type { Finding } from "../types.js";
import { maskSensitive } from "../detection/index.js";

/**
 * Categories whose findings can carry a live secret or personal identifier.
 * As a defense-in-depth guard, the reporter redacts `fix.before` for these
 * categories so a rule that forgets to mask cannot leak through JSON/HTML.
 */
const SENSITIVE_CATEGORIES: ReadonlySet<string> = new Set([
  "secrets",
  "pii",
  "credentials",
  "codes",
]);

export function isSensitiveCategory(category: string): boolean {
  return SENSITIVE_CATEGORIES.has(category);
}

/**
 * Return a copy of the finding with `fix.before` masked when the finding is in
 * a sensitive category. Non-sensitive findings and findings without a fix are
 * returned unchanged.
 */
export function redactSensitiveFinding(finding: Finding): Finding {
  if (!finding.fix || !isSensitiveCategory(finding.category)) return finding;
  return {
    ...finding,
    fix: { ...finding.fix, before: maskSensitive(finding.fix.before) },
  };
}
