import type { ConfigFile, Finding, Rule } from "../types.js";
import {
  findAllMatches,
  findLineNumber,
  isTextLikeFile,
  isLikelyExampleValue,
  maskSecretValue,
} from "./helpers.js";

/**
 * Credential detection: login/password pairs, HTTP Basic auth headers, and
 * weak/common passwords. Complements the vendor-token detection in secrets.ts.
 */

const PASSWORD_ASSIGNMENT =
  /(?:password|passwd|pwd|pass)\s*[=:]\s*["']?([^\s"'#]{3,})["']?/gi;

const LOGIN_ASSIGNMENT =
  /(?:username|user[_-]?name|login|user|email|логин|пользователь)\s*[=:]\s*["']?([^\s"'#]{2,})["']?/gi;

const PLACEHOLDER_VALUES = new Set([
  "password",
  "passwd",
  "changeme",
  "change_me",
  "your_password",
  "yourpassword",
  "example",
  "sample",
  "test",
  "todo",
  "xxx",
  "******",
  "secret",
  // Common database defaults and code type names that show up in docs.
  "postgres",
  "postgresql",
  "mysql",
  "mariadb",
  "redis",
  "mongo",
  "mongodb",
  "guest",
]);

/** Language type names / keywords that are never credentials. */
const CODE_KEYWORDS = new Set([
  "string",
  "boolean",
  "number",
  "integer",
  "int",
  "long",
  "float",
  "double",
  "object",
  "array",
  "list",
  "map",
  "set",
  "null",
  "undefined",
  "true",
  "false",
  "nil",
  "none",
  "void",
  "any",
]);

const COMMON_PASSWORDS = new Set([
  "123456",
  "1234567",
  "12345678",
  "123456789",
  "1234567890",
  "111111",
  "123123",
  "abc123",
  "qwerty",
  "qwerty123",
  "password",
  "passw0rd",
  "admin",
  "admin123",
  "root",
  "toor",
  "letmein",
  "welcome",
  "changeme",
  "iloveyou",
  "monkey",
  "dragon",
  "master",
]);

function isReferenceOrPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  if (value.startsWith("$") || value.startsWith("${")) return true;
  if (value.includes("process.env")) return true;
  return PLACEHOLDER_VALUES.has(lower);
}

/** Code punctuation that marks a captured "value" as a code expression, not a credential. */
const CODE_PUNCTUATION = /[(){}[\]<>=,;:./\\|]/;

function isPlausibleCredentialValue(value: string, minLength: number): boolean {
  if (value.length < minLength) return false;
  if (CODE_PUNCTUATION.test(value)) return false;
  if (CODE_KEYWORDS.has(value.toLowerCase())) return false;
  return true;
}

/** True when a login-like assignment appears shortly before `index`. */
function hasNearbyLogin(content: string, index: number): boolean {
  const window = content.slice(Math.max(0, index - 200), index);
  return findAllMatches(window, LOGIN_ASSIGNMENT).length > 0;
}

function decodeBase64(value: string): string | null {
  try {
    const decoded = Buffer.from(value, "base64").toString("utf-8");
    // Require printable output and a user:pass shape.
    if (!/^[\x20-\x7E]+$/.test(decoded)) return null;
    return decoded;
  } catch {
    return null;
  }
}

export const credentialRules: ReadonlyArray<Rule> = [
  {
    id: "credentials-login-password-pair",
    name: "Login/Password Pair",
    description: "Detects a login and password assigned together in the same block",
    severity: "high",
    category: "credentials",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];

      for (const passwordMatch of findAllMatches(file.content, PASSWORD_ASSIGNMENT)) {
        const index = passwordMatch.index ?? 0;
        const password = passwordMatch[1];
        if (isReferenceOrPlaceholder(password)) continue;
        if (!isPlausibleCredentialValue(password, 6)) continue;
        if (isLikelyExampleValue(file, index)) continue;

        const windowStart = Math.max(0, index - 200);
        const window = file.content.slice(windowStart, index);
        const loginMatches = findAllMatches(window, LOGIN_ASSIGNMENT);
        if (loginMatches.length === 0) continue;

        const login = loginMatches[loginMatches.length - 1][1];
        if (isReferenceOrPlaceholder(login)) continue;
        if (!isPlausibleCredentialValue(login, 3)) continue;

        findings.push({
          id: `credentials-login-password-pair-${index}`,
          severity: "high",
          category: "credentials",
          title: "Login/password pair found",
          description: `Found a login ("${login}") and password assigned together in ${file.path}. Hardcoded credential pairs grant direct account access and must be moved to a secret manager.`,
          file: file.path,
          line: findLineNumber(file.content, index),
          evidence: `login=${maskSecretValue(login)} password=${maskSecretValue(password)}`,
          fix: {
            description: "Move credentials to environment variables or a secret manager",
            before: `login=${maskSecretValue(login)} password=${maskSecretValue(password)}`,
            after: "# load credentials from the environment at runtime",
            auto: false,
          },
        });
      }

      return findings;
    },
  },
  {
    id: "credentials-basic-auth",
    name: "HTTP Basic Auth Credentials",
    description: "Detects Authorization: Basic headers and decodes them to confirm user:pass",
    severity: "critical",
    category: "credentials",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];

      const pattern = /(?:authorization\s*[:=]\s*)?["']?Basic\s+([A-Za-z0-9+/=]{8,})["']?/gi;

      for (const match of findAllMatches(file.content, pattern)) {
        const index = match.index ?? 0;
        const encoded = match[1];
        const decoded = decodeBase64(encoded);
        if (decoded === null) continue;

        const separator = decoded.indexOf(":");
        if (separator <= 0 || separator === decoded.length - 1) continue;

        const login = decoded.slice(0, separator);
        const password = decoded.slice(separator + 1);

        findings.push({
          id: `credentials-basic-auth-${index}`,
          severity: "critical",
          category: "credentials",
          title: "HTTP Basic auth credentials found",
          description: `Found a decodable HTTP Basic auth header in ${file.path}. Base64 is not encryption — the login and password are exposed in plain text to anyone who reads the file.`,
          file: file.path,
          line: findLineNumber(file.content, index),
          evidence: `login=${maskSecretValue(login)} password=${maskSecretValue(password)}`,
          fix: {
            description: "Remove the header and load credentials at runtime",
            before: "Authorization: Basic <redacted>",
            after: "# provide credentials via environment/secret manager",
            auto: false,
          },
        });
      }

      return findings;
    },
  },
  {
    id: "credentials-weak-password",
    name: "Weak or Common Password",
    description: "Detects commonly used weak passwords assigned in configuration",
    severity: "medium",
    category: "credentials",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];

      for (const match of findAllMatches(file.content, PASSWORD_ASSIGNMENT)) {
        const index = match.index ?? 0;
        const password = match[1];
        if (!COMMON_PASSWORDS.has(password.toLowerCase())) continue;
        if (isLikelyExampleValue(file, index)) continue;
        // Do not duplicate a finding already produced by the quoted-password
        // detection (secrets) or the login/password pair rule (credentials).
        if (/["']/.test(match[0])) continue;
        if (hasNearbyLogin(file.content, index)) continue;

        findings.push({
          id: `credentials-weak-password-${index}`,
          severity: "medium",
          category: "credentials",
          title: "Weak password found",
          description: `Found a commonly used weak password in ${file.path}. Weak credentials are trivially guessed and should be replaced with a strong, unique secret.`,
          file: file.path,
          line: findLineNumber(file.content, index),
          evidence: `password=${maskSecretValue(password)}`,
        });
      }

      return findings;
    },
  },
];
