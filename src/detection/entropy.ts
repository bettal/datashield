/**
 * Shannon entropy over a string's character distribution, in bits per symbol.
 *
 * Used to flag high-entropy blobs that look like keys/secrets even when they do
 * not match a known vendor prefix. Ordinary prose in English/Russian sits well
 * below ~3.5 bits/char; random base64/hex secrets sit well above it.
 */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;

  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

/**
 * Placeholder markers matched on token boundaries, so a random secret that
 * merely contains "test"/"token"/"secret" as a substring is not rejected.
 */
const COMMON_WORD_PATTERN =
  /(?:^|[^a-z0-9])(?:example|sample|placeholder|changeme|dummy|foobar|lorem|ipsum|test|password|secret|token|replace)(?:[^a-z0-9]|$)/;

/**
 * Heuristic for whether a value is a plausible high-entropy secret rather than
 * an ordinary word, path, UUID, hash, or placeholder.
 */
export function looksLikeHighEntropySecret(value: string, minLength = 20, threshold = 3.5): boolean {
  const trimmed = value.trim();
  if (trimmed.length < minLength) return false;

  // Reject strings without enough character variety (e.g. "aaaaaaaaaaaaaaaa").
  if (new Set(trimmed).size < 8) return false;

  // Reject pure decimal sequences (timestamps, ids, phone numbers).
  if (/^\d+$/.test(trimmed)) return false;

  // Reject purely alphabetic values (words, camelCase identifiers, enum names).
  // Real secrets essentially always contain a digit or a symbol.
  if (/^[A-Za-z]+$/.test(trimmed)) return false;

  // Reject obvious placeholder/example words (on token boundaries).
  const lower = trimmed.toLowerCase();
  if (COMMON_WORD_PATTERN.test(lower)) return false;
  if (lower.includes("your_") || lower.includes("your-")) return false;

  // Reject well-known non-secret shapes.
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(trimmed)) {
    return false; // UUID
  }
  if (/^(?:\/|\.\/|~\/)[\w./-]+$/.test(trimmed)) return false; // path
  if (/^[a-z]+:\/\//i.test(trimmed)) return false; // URL

  return shannonEntropy(trimmed) >= threshold;
}
