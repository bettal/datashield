import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scan } from "../../src/scanner/index.js";
import { calculateScore } from "../../src/reporter/score.js";
import { renderJsonReport } from "../../src/reporter/json.js";
import { redactSensitiveFinding } from "../../src/reporter/redact.js";
import type { Finding } from "../../src/types.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "datashield-redact-test-"));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "test",
    severity: "critical",
    category: "secrets",
    title: "test",
    description: "test",
    file: "CLAUDE.md",
    ...overrides,
  };
}

describe("redactSensitiveFinding", () => {
  it("masks fix.before for sensitive categories", () => {
    const finding = makeFinding({
      category: "secrets",
      fix: { description: "x", before: "sk-ant-supersecretvalue123456", after: "${KEY}", auto: false },
    });
    const redacted = redactSensitiveFinding(finding);
    expect(redacted.fix?.before).not.toContain("supersecretvalue");
    expect(redacted.fix?.before).toContain("...");
  });

  it("leaves non-sensitive categories untouched", () => {
    const finding = makeFinding({
      category: "permissions",
      fix: { description: "x", before: "Bash(*)", after: "Bash(git *)", auto: false },
    });
    expect(redactSensitiveFinding(finding).fix?.before).toBe("Bash(*)");
  });
});

describe("report redaction (end to end)", () => {
  it("never serializes a raw secret into the JSON report", () => {
    const secret = "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789";
    const dir = createTempDir();
    writeFileSync(join(dir, "CLAUDE.md"), `ANTHROPIC_API_KEY=${secret}`);

    const json = renderJsonReport(calculateScore(scan(dir)));
    expect(json).not.toContain(secret);
  });

  it("never serializes a raw credential pair into the JSON report", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "CLAUDE.md"), 'username = "alice"\npassword = "S3cretP@ss"');

    const json = renderJsonReport(calculateScore(scan(dir)));
    expect(json).not.toContain("S3cretP@ss");
  });
});
