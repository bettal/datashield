import { describe, it, expect } from "vitest";
import type { ConfigFile, ConfigFileType } from "../../src/types.js";
import { codeRules } from "../../src/rules/codes.js";

function makeFile(content: string, type: ConfigFileType = "claude-md", path = "CLAUDE.md"): ConfigFile {
  return { path, type, content };
}

function run(file: ConfigFile) {
  return codeRules.flatMap((rule) => rule.check(file));
}

function has(file: ConfigFile, idPart: string): boolean {
  return run(file).some((finding) => finding.id.includes(idPart));
}

describe("otp / 2fa codes", () => {
  it("flags an otp assignment", () => {
    expect(has(makeFile("otp = 123456"), "codes-otp")).toBe(true);
  });

  it("flags a totp assignment", () => {
    expect(has(makeFile("totp: 654321"), "codes-otp")).toBe(true);
  });

  it("flags a verification code", () => {
    expect(has(makeFile("verification code: 998877"), "codes-otp")).toBe(true);
  });

  it("does not flag unlabeled numbers", () => {
    expect(has(makeFile("year 2024"), "codes-otp")).toBe(false);
    expect(has(makeFile("status 404"), "codes-otp")).toBe(false);
    expect(has(makeFile("port 8080"), "codes-otp")).toBe(false);
  });

  it("masks the code in evidence", () => {
    const finding = run(makeFile("otp = 123456")).find((f) => f.id.includes("codes-otp"));
    expect(finding?.evidence).not.toBe("123456");
    expect(finding?.evidence).toContain("*");
  });
});

describe("recovery / backup codes", () => {
  it("flags a list of backup codes", () => {
    expect(has(makeFile("backup codes: ABCD-1234, EFGH-5678, IJKL-9012"), "codes-recovery")).toBe(true);
  });

  it("flags a single recovery code", () => {
    expect(has(makeFile("recovery_code = abcd-efgh-1234"), "codes-recovery")).toBe(true);
  });

  it("does not flag a single recovery-shaped word without a label", () => {
    expect(has(makeFile("value = abcd-efgh-1234"), "codes-recovery")).toBe(false);
  });
});

describe("pin codes", () => {
  it("flags a pin assignment", () => {
    expect(has(makeFile("pin = 1234"), "codes-pin")).toBe(true);
  });

  it("does not flag the word pinned without an assignment", () => {
    expect(has(makeFile("the item is pinned"), "codes-pin")).toBe(false);
  });
});

describe("codes file coverage", () => {
  it("scans skill files", () => {
    expect(has(makeFile("otp = 123456", "skill-md", "skills/x/SKILL.md"), "codes-otp")).toBe(true);
  });

  it("does not scan non-text files", () => {
    expect(has(makeFile("otp = 123456", "unknown", "x.unknown"), "codes-otp")).toBe(false);
  });
});
