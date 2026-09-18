/**
 * Redact a sensitive value for report evidence.
 *
 * Unlike a naive prefix/suffix mask, this never returns short values verbatim:
 * values of four characters or fewer are fully masked, and short values keep
 * only their first/last character. The goal is that evidence can identify the
 * finding without re-leaking the secret into logs, CI output, or tickets.
 */
export function maskSensitive(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0) return "";

  if (trimmed.length <= 4) return "*".repeat(trimmed.length);

  if (trimmed.length <= 12) {
    return trimmed.slice(0, 1) + "*".repeat(trimmed.length - 2) + trimmed.slice(-1);
  }

  return trimmed.slice(0, 8) + "..." + trimmed.slice(-4);
}
