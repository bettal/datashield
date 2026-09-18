import type { ConfigFile } from "../types.js";

/**
 * Per-file analysis cache.
 *
 * Rules run many matches against the same file content, and the naive helpers
 * (`content.slice(0, index)` for line numbers, counting code fences up to the
 * match) are O(n) per call — O(n·m) per file. For very large files with many
 * matches this dominates the scan.
 *
 * `FileContext` is built once per `ConfigFile` (a single linear pass) and
 * memoized in a `WeakMap`, so line numbers and fence membership become
 * O(log n) binary searches. The WeakMap key means the cache is released with
 * the file object and never leaks across scans.
 */

export interface FileContext {
  /** Byte offsets where each line starts (lineStarts[0] === 0). */
  readonly lineStarts: ReadonlyArray<number>;
  /** Sorted offsets of code-fence markers (``` or ~~~). */
  readonly fenceMarkers: ReadonlyArray<number>;
}

const cache = new WeakMap<ConfigFile, FileContext>();

const FENCE_PATTERN = /```|~~~/g;
const NEWLINE = 0x0a;

function buildContext(content: string): FileContext {
  const lineStarts: number[] = [0];
  for (let i = 0; i < content.length; i += 1) {
    if (content.charCodeAt(i) === NEWLINE) lineStarts.push(i + 1);
  }

  const fenceMarkers: number[] = [];
  FENCE_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = FENCE_PATTERN.exec(content)) !== null) {
    fenceMarkers.push(match.index);
  }

  return { lineStarts, fenceMarkers };
}

export function getFileContext(file: ConfigFile): FileContext {
  const cached = cache.get(file);
  if (cached !== undefined) return cached;
  const built = buildContext(file.content);
  cache.set(file, built);
  return built;
}

/** Number of sorted values <= target (upper bound via binary search). */
function countUpTo(sorted: ReadonlyArray<number>, target: number): number {
  let low = 0;
  let high = sorted.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (sorted[mid] <= target) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }
  return low;
}

/** 1-based line number containing `matchIndex`. */
export function lineNumberAt(file: ConfigFile, matchIndex: number): number {
  const { lineStarts } = getFileContext(file);
  return countUpTo(lineStarts, matchIndex);
}

/**
 * True when `matchIndex` sits inside an open fenced code block. A position is
 * inside when an odd number of fence markers strictly precede it (a match at
 * the fence delimiter itself is not "inside").
 */
export function isInsideCodeFenceAt(file: ConfigFile, matchIndex: number): boolean {
  const { fenceMarkers } = getFileContext(file);
  return countUpTo(fenceMarkers, matchIndex - 1) % 2 === 1;
}
