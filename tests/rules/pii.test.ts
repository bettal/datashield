import { describe, it, expect } from "vitest";
import type { ConfigFile, ConfigFileType } from "../../src/types.js";
import { piiRules } from "../../src/rules/pii.js";

function makeFile(content: string, type: ConfigFileType = "claude-md", path = "CLAUDE.md"): ConfigFile {
  return { path, type, content };
}

function run(file: ConfigFile) {
  return piiRules.flatMap((rule) => rule.check(file));
}

function has(file: ConfigFile, idPart: string): boolean {
  return run(file).some((finding) => finding.id.includes(idPart));
}

describe("pii email", () => {
  it("flags a personal email", () => {
    expect(has(makeFile("Contact john.doe@acme-corp.io for access"), "pii-email")).toBe(true);
  });

  it("ignores placeholder emails", () => {
    expect(has(makeFile("Contact user@example.com"), "pii-email")).toBe(false);
    expect(has(makeFile("Contact admin@test.com"), "pii-email")).toBe(false);
  });

  it("ignores scp-style git remotes", () => {
    expect(has(makeFile("clone git@github.com:org/repo.git"), "pii-email")).toBe(false);
  });

  it("masks the local part in evidence", () => {
    const finding = run(makeFile("mail: john.doe@acme-corp.io")).find((f) => f.id.includes("pii-email"));
    expect(finding?.evidence).toContain("@acme-corp.io");
    expect(finding?.evidence).not.toContain("john.doe");
  });
});

describe("pii phones", () => {
  it("flags +7 and 8 formatted numbers", () => {
    expect(has(makeFile("Call +7 916 123-45-67"), "pii-phone-ru")).toBe(true);
    expect(has(makeFile("Call 8 (916) 123-45-67"), "pii-phone-ru")).toBe(true);
  });

  it("flags international numbers", () => {
    expect(has(makeFile("Call +14155552671"), "pii-phone-intl")).toBe(true);
  });

  it("does not double-report +7 as international", () => {
    expect(has(makeFile("Call +7 916 123-45-67"), "pii-phone-intl")).toBe(false);
  });
});

describe("pii russian identifiers", () => {
  it("flags a checksum-valid СНИЛС", () => {
    expect(has(makeFile("СНИЛС 112-233-445 95"), "pii-snils")).toBe(true);
  });

  it("ignores an invalid СНИЛС checksum", () => {
    expect(has(makeFile("СНИЛС 112-233-445 94"), "pii-snils")).toBe(false);
  });

  it("flags an ИНН near its label", () => {
    expect(has(makeFile("ИНН 7707083893"), "pii-inn")).toBe(true);
  });

  it("ignores an ИНН-shaped number without a label", () => {
    expect(has(makeFile("order 7707083893"), "pii-inn")).toBe(false);
  });

  it("flags an ОГРН near its label", () => {
    expect(has(makeFile("ОГРН 1027700132195"), "pii-ogrn")).toBe(true);
  });

  it("flags a passport number near its label", () => {
    expect(has(makeFile("паспорт 45 06 123456"), "pii-ru-document")).toBe(true);
  });

  it("ignores a passport-shaped number without a label", () => {
    expect(has(makeFile("value 45 06 123456"), "pii-ru-document")).toBe(false);
  });
});

describe("pii financial identifiers", () => {
  it("flags a Luhn-valid card number", () => {
    expect(has(makeFile("card 4111 1111 1111 1111"), "pii-bank-card")).toBe(true);
  });

  it("ignores a card number that fails Luhn", () => {
    expect(has(makeFile("card 4111 1111 1111 1112"), "pii-bank-card")).toBe(false);
  });

  it("ignores a 13-digit epoch timestamp that passes Luhn without a card label", () => {
    expect(has(makeFile('"start": 1710000029200'), "pii-bank-card")).toBe(false);
  });

  it("flags a valid IBAN", () => {
    expect(has(makeFile("IBAN GB82 WEST 1234 5698 7654 32"), "pii-iban")).toBe(true);
  });

  it("ignores an invalid IBAN", () => {
    expect(has(makeFile("IBAN GB82 WEST 1234 5698 7654 33"), "pii-iban")).toBe(false);
  });

  it("flags a BIK near its label", () => {
    expect(has(makeFile("БИК 044525225"), "pii-bik")).toBe(true);
  });

  it("flags a settlement account near its label", () => {
    expect(has(makeFile("р/с 40702810600000000123"), "pii-account-ru")).toBe(true);
  });
});

describe("pii international identifiers", () => {
  it("flags a formatted US SSN", () => {
    expect(has(makeFile("SSN 123-45-6789"), "pii-ssn")).toBe(true);
  });

  it("ignores a reserved SSN area", () => {
    expect(has(makeFile("SSN 000-45-6789"), "pii-ssn")).toBe(false);
  });
});

describe("pii robustness", () => {
  it(
    "handles adversarial email-like input without quadratic backtracking",
    () => {
      const file = makeFile("a.".repeat(50000));
      const start = Date.now();
      run(file);
      expect(Date.now() - start).toBeLessThan(3000);
    },
    10000
  );
});

describe("pii file coverage", () => {
  it("scans skill files", () => {
    expect(has(makeFile("email: john.doe@acme-corp.io", "skill-md", "skills/x/SKILL.md"), "pii-email")).toBe(true);
  });

  it("does not scan non-text files", () => {
    expect(has(makeFile("email: john.doe@acme-corp.io", "unknown", "x.unknown"), "pii-email")).toBe(false);
  });
});
