import { describe, it, expect } from "vitest";
import type { ConfigFile, ConfigFileType } from "../../src/types.js";
import { credentialRules } from "../../src/rules/credentials.js";

function makeFile(content: string, type: ConfigFileType = "claude-md", path = "CLAUDE.md"): ConfigFile {
  return { path, type, content };
}

function run(file: ConfigFile) {
  return credentialRules.flatMap((rule) => rule.check(file));
}

function has(file: ConfigFile, idPart: string): boolean {
  return run(file).some((finding) => finding.id.includes(idPart));
}

describe("login/password pairs", () => {
  it("flags a login and password assigned together", () => {
    const file = makeFile('username = "alice"\npassword = "S3cretP@ss"');
    expect(has(file, "login-password-pair")).toBe(true);
  });

  it("flags .env style credentials", () => {
    const file = makeFile("LOGIN=deploy\nPASSWORD=Pr0d-Pass-99", "env-file", ".env");
    expect(has(file, "login-password-pair")).toBe(true);
  });

  it("ignores environment variable references", () => {
    const file = makeFile("username = alice\npassword = ${DB_PASSWORD}");
    expect(has(file, "login-password-pair")).toBe(false);
  });

  it("ignores a password with no nearby login", () => {
    const file = makeFile('password = "S3cretP@ss"');
    expect(has(file, "login-password-pair")).toBe(false);
  });

  it("ignores credential-shaped code inside a fenced code block", () => {
    const file = makeFile(
      "```python\nuser = User.objects.get(email=payload.email, password=payload.password)\n```",
      "skill-md",
      "skills/x/SKILL.md"
    );
    expect(has(file, "login-password-pair")).toBe(false);
  });

  it("ignores code-expression values", () => {
    const file = makeFile("email=User.objects.get\npassword=User.objects.get");
    expect(has(file, "login-password-pair")).toBe(false);
  });

  it("masks the credentials in evidence", () => {
    const file = makeFile('username = "alice"\npassword = "S3cretP@ss"');
    const finding = run(file).find((f) => f.id.includes("login-password-pair"));
    expect(finding?.evidence).not.toContain("S3cretP@ss");
    expect(finding?.evidence).not.toContain("alice");
  });
});

describe("HTTP Basic auth", () => {
  it("decodes and flags a Basic auth header", () => {
    const encoded = Buffer.from("alice:s3cret").toString("base64");
    const file = makeFile(`Authorization: Basic ${encoded}`);
    expect(has(file, "basic-auth")).toBe(true);
  });

  it("ignores a Basic value that does not decode to user:pass", () => {
    const encoded = Buffer.from("not-a-pair").toString("base64");
    const file = makeFile(`Authorization: Basic ${encoded}`);
    expect(has(file, "basic-auth")).toBe(false);
  });
});

describe("weak passwords", () => {
  it("flags a common password", () => {
    expect(has(makeFile("password=123456"), "weak-password")).toBe(true);
  });

  it("does not flag a strong password", () => {
    expect(has(makeFile("password=S3cretP@ss-9x"), "weak-password")).toBe(false);
  });
});

describe("credentials file coverage", () => {
  it("scans skill files", () => {
    const file = makeFile('username = "alice"\npassword = "S3cretP@ss"', "skill-md", "skills/x/SKILL.md");
    expect(has(file, "login-password-pair")).toBe(true);
  });

  it("does not scan non-text files", () => {
    const file = makeFile('username = "alice"\npassword = "S3cretP@ss"', "hook-code", "hook.ts");
    expect(has(file, "login-password-pair")).toBe(false);
  });
});
