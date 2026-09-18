import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { discoverConfigFiles } from "../../src/scanner/discovery.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "datashield-symlink-test-"));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe("discoverConfigFiles symlink containment", () => {
  it("does not read through a symlinked directory that escapes the scan root", () => {
    const root = createTempDir();
    const outside = createTempDir();
    writeFileSync(join(outside, "leaked.md"), "# leaked secret");
    symlinkSync(outside, join(root, "escape"));

    const result = discoverConfigFiles(root);
    expect(result.files.some((file) => file.path.includes("leaked.md"))).toBe(false);
  });

  it("does not read through a symlinked file that escapes the scan root", () => {
    const root = createTempDir();
    const outside = createTempDir();
    writeFileSync(join(outside, "leaked.md"), "# leaked secret");
    symlinkSync(join(outside, "leaked.md"), join(root, "link.md"));

    const result = discoverConfigFiles(root);
    expect(result.files.some((file) => file.path === "link.md")).toBe(false);
  });

  it("terminates on a self-referential directory symlink", () => {
    const root = createTempDir();
    mkdirSync(join(root, "skills"));
    writeFileSync(join(root, "skills", "SKILL.md"), "# ok");
    symlinkSync(join(root, "skills"), join(root, "skills", "loop"));

    const result = discoverConfigFiles(root);
    expect(result.files.some((file) => file.path === "skills/SKILL.md")).toBe(true);
  });
});
