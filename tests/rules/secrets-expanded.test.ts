import { describe, it, expect } from "vitest";
import type { ConfigFile, ConfigFileType } from "../../src/types.js";
import { secretRules } from "../../src/rules/secrets.js";

function makeFile(content: string, type: ConfigFileType = "claude-md", path = "CLAUDE.md"): ConfigFile {
  return { path, type, content };
}

function run(file: ConfigFile) {
  return secretRules.flatMap((rule) => rule.check(file));
}

function hasFinding(file: ConfigFile, idPart: string): boolean {
  return run(file).some((finding) => finding.id.includes(idPart));
}

describe("expanded secret patterns", () => {
  // Tokens are assembled at runtime so no complete token literal exists in the
  // source tree (keeps GitHub secret-scanning push protection happy).
  const cases: ReadonlyArray<readonly [string, string]> = [
    ["gitlab-pat", `glpat-${"a".repeat(20)}`],
    ["gitlab-runner-token", `glrt-${"a".repeat(20)}`],
    ["github-oauth", `gho_${"a".repeat(36)}`],
    ["github-app-token", `ghs_${"a".repeat(36)}`],
    ["shopify-access-token", `shpat_${"0".repeat(32)}`],
    ["telegram-bot-token", `123456789:AA${"a".repeat(33)}`],
    ["supabase-service-role", `sbp_${"a".repeat(40)}`],
    ["openrouter-api-key", `sk-or-v1-${"a".repeat(64)}`],
    ["gcp-oauth-token", `ya29.${"a".repeat(20)}`],
    ["newrelic-api-key", `NRAK-${"A".repeat(27)}`],
    ["pypi-token", `pypi-AgEIcHlwaS5vcmc${"a".repeat(60)}`],
    ["groq-api-key", `gsk_${"a".repeat(52)}`],
    ["replicate-token", `r8_${"a".repeat(37)}`],
    ["age-secret-key", `AGE-SECRET-KEY-1${"A".repeat(58)}`],
    ["azure-storage-account-key", `AccountKey=${"A".repeat(88)}`],
  ];

  for (const [name, secret] of cases) {
    it(`detects ${name}`, () => {
      expect(hasFinding(makeFile(`Config value: ${secret}`), name)).toBe(true);
    });
  }

  it("detects a Sentry DSN", () => {
    const dsn = `https://${"a".repeat(32)}@o123.ingest.sentry.io/1`;
    expect(hasFinding(makeFile(dsn), "sentry-dsn")).toBe(true);
  });

  it("detects an encrypted private key header", () => {
    expect(hasFinding(makeFile("-----BEGIN ENCRYPTED PRIVATE KEY-----"), "encrypted-private-key")).toBe(true);
  });

  it("detects an AWS temporary session key", () => {
    expect(hasFinding(makeFile(`ASIA${"IOSFODNN7EXAMPLE"}`), "aws-session-token")).toBe(true);
  });

  it("detects MongoDB+srv connection strings", () => {
    const user = "admin";
    const pass = "s3cretP4ss";
    expect(
      hasFinding(makeFile(`mongodb+srv://${user}:${pass}@cluster.acme.net/prod`), "connection-string")
    ).toBe(true);
  });
});

describe("generic secret assignment", () => {
  it("flags a high-entropy value assigned to api_key", () => {
    const file = makeFile('api_key = "xJ8kL2mN9pQ4rS7tU1vW5yZ3aB6cD0eF"');
    expect(hasFinding(file, "generic-assignment")).toBe(true);
  });

  it("flags a high-entropy token assignment in an env file", () => {
    const file = makeFile("CLIENT_SECRET=xJ8kL2mN9pQ4rS7tU1vW5yZ3aB6cD0eF", "env-file", ".env");
    expect(hasFinding(file, "generic-assignment")).toBe(true);
  });

  it("ignores low-entropy values", () => {
    const file = makeFile("api_key = your_api_key_here_1234567890");
    expect(hasFinding(file, "generic-assignment")).toBe(false);
  });

  it("ignores environment variable references", () => {
    const file = makeFile("api_key = ${MY_API_KEY}");
    expect(hasFinding(file, "generic-assignment")).toBe(false);
  });

  it("does not scan non-text file types", () => {
    const file = makeFile('api_key = "xJ8kL2mN9pQ4rS7tU1vW5yZ3aB6cD0eF"', "unknown", "x.unknown");
    expect(hasFinding(file, "generic-assignment")).toBe(false);
  });

  it("still flags a real high-entropy secret inside a fenced code block", () => {
    const file = makeFile(
      '```bash\nexport api_key="xJ8kL2mN9pQ4rS7tU1vW5yZ3aB6cD0eF"\n```',
      "skill-md",
      "skills/x/SKILL.md"
    );
    expect(hasFinding(file, "generic-assignment")).toBe(true);
  });
});

describe("high-entropy detection", () => {
  it("flags an unlabelled high-entropy string", () => {
    const file = makeFile('value: "xJ8kL2mN9pQ4rS7tU1vW5yZ3aB6cD0eF"');
    expect(hasFinding(file, "high-entropy")).toBe(true);
  });

  it("ignores short quoted strings", () => {
    const file = makeFile('value: "shortvalue"');
    expect(hasFinding(file, "high-entropy")).toBe(false);
  });

  it("ignores 64-char hex hashes", () => {
    const file = makeFile(`sha: "${"a1b2c3d4".repeat(8)}"`);
    expect(hasFinding(file, "high-entropy")).toBe(false);
  });
});

describe("skill-md coverage", () => {
  it("scans SKILL.md files for credential-file references", () => {
    const file = makeFile("Read ~/.aws/credentials before running", "skill-md", "skills/x/SKILL.md");
    expect(hasFinding(file, "cred-file-ref")).toBe(true);
  });

  it("scans SKILL.md files for generic secret assignments", () => {
    const file = makeFile('api_key = "xJ8kL2mN9pQ4rS7tU1vW5yZ3aB6cD0eF"', "skill-md", "skills/x/SKILL.md");
    expect(hasFinding(file, "generic-assignment")).toBe(true);
  });
});
