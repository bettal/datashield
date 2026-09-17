import type { ConfigFile, Finding, Rule, Severity } from "../types.js";
import {
  findAllMatches,
  findLineNumber,
  isTextLikeFile,
  isLikelyExampleValue,
  maskSecretValue,
} from "./helpers.js";
import {
  luhnValid,
  ibanValid,
  snilsValid,
  innValid,
  ogrnValid,
  ssnPlausible,
} from "../detection/index.js";

/**
 * Personal-data (PII) detection.
 *
 * Covers Russian and international identifiers. Precision comes from checksum
 * validators (Luhn, IBAN mod-97, СНИЛС/ИНН/ОГРН control digits) and, where no
 * checksum exists, from a nearby context label. Evidence is always masked.
 */

// Bounded quantifiers avoid the quadratic backtracking of the classic
// `[A-Za-z0-9._%+-]+@...` form on adversarial input (ReDoS). The domain must
// start with a letter and end with an alphabetic TLD, which rejects npm-style
// `pkg@1.2.3` and asset names like `file@2x.png`.
const EMAIL_PATTERN =
  /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63}){0,3}\.[A-Za-z]{2,24}\b/g;

const PLACEHOLDER_EMAIL_LOCALS = new Set([
  "user",
  "username",
  "name",
  "email",
  "your",
  "yourname",
  "someone",
  "test",
  "example",
  "sample",
  "demo",
  "noreply",
  "no-reply",
]);

const PLACEHOLDER_EMAIL_DOMAINS = [
  "example.com",
  "example.org",
  "example.net",
  "test.com",
  "localhost",
  ".invalid",
  ".test",
  ".example",
];

const PLACEHOLDER_EMAIL_DOMAIN_LABELS = new Set([
  "example",
  "test",
  "localhost",
  "invalid",
  "sample",
  "demo",
]);

function hasNearbyLabel(content: string, index: number, labels: ReadonlyArray<string>): boolean {
  const window = content.slice(Math.max(0, index - 80), index + 100).toLowerCase();
  return labels.some((label) => {
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // Word-boundary match so "inn" does not fire inside "beginning".
    const pattern = new RegExp(
      `(?:^|[^\\p{L}\\p{N}])${escaped}(?:[^\\p{L}\\p{N}]|$)`,
      "u"
    );
    return pattern.test(window);
  });
}

function isPlaceholderEmail(email: string): boolean {
  const [local, domain = ""] = email.toLowerCase().split("@");
  if (PLACEHOLDER_EMAIL_LOCALS.has(local)) return true;
  if (PLACEHOLDER_EMAIL_DOMAINS.some((placeholder) => domain.endsWith(placeholder))) return true;
  if (domain.split(".").some((label) => PLACEHOLDER_EMAIL_DOMAIN_LABELS.has(label))) return true;
  // scp-like git remote, e.g. git@github.com:org/repo
  if (local === "git" && /^(?:github|gitlab|bitbucket)\.com$/.test(domain)) return true;
  return false;
}

interface PiiFindingInput {
  readonly id: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly file: ConfigFile;
  readonly index: number;
  readonly evidence: string;
}

function makePiiFinding(input: PiiFindingInput): Finding {
  return {
    id: `${input.id}-${input.index}`,
    severity: input.severity,
    category: "pii",
    title: input.title,
    description: input.description,
    file: input.file.path,
    line: findLineNumber(input.file.content, input.index),
    evidence: input.evidence,
  };
}

export const piiRules: ReadonlyArray<Rule> = [
  {
    id: "pii-email",
    name: "Email Address",
    description: "Detects personal email addresses in configuration and agent files",
    severity: "medium",
    category: "pii",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];

      for (const match of findAllMatches(file.content, EMAIL_PATTERN)) {
        const index = match.index ?? 0;
        const email = match[0];
        if (isPlaceholderEmail(email)) continue;
        if (isLikelyExampleValue(file, index)) continue;

        const [local, domain] = email.split("@");
        findings.push(
          makePiiFinding({
            id: "pii-email",
            severity: "medium",
            title: "Email address found",
            description: `Found an email address in ${file.path}. Email addresses are personal data and should not be stored in agent configuration, skills, or committed notes.`,
            file,
            index,
            evidence: `${maskSecretValue(local)}@${domain}`,
          })
        );
      }

      return findings;
    },
  },
  {
    id: "pii-phone-ru",
    name: "Russian Phone Number",
    description: "Detects Russian phone numbers (+7 / 8 formats)",
    severity: "high",
    category: "pii",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];
      const pattern = /(?<!\d)(?:\+7|8)[\s\-().]{0,2}\d{3}[\s\-().]{0,2}\d{3}[\s\-().]{0,2}\d{2}[\s\-().]{0,2}\d{2}(?!\d)/g;

      for (const match of findAllMatches(file.content, pattern)) {
        const index = match.index ?? 0;
        if (isLikelyExampleValue(file, index)) continue;
        findings.push(
          makePiiFinding({
            id: "pii-phone-ru",
            severity: "high",
            title: "Russian phone number found",
            description: `Found a Russian phone number in ${file.path}. Phone numbers are personal data; remove them or replace with a placeholder.`,
            file,
            index,
            evidence: maskSecretValue(match[0]),
          })
        );
      }

      return findings;
    },
  },
  {
    id: "pii-phone-intl",
    name: "International Phone Number",
    description: "Detects E.164-style international phone numbers",
    severity: "medium",
    category: "pii",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];
      const pattern = /(?<!\d)\+[1-9]\d{7,14}(?!\d)/g;

      for (const match of findAllMatches(file.content, pattern)) {
        const index = match.index ?? 0;
        if (match[0].startsWith("+7")) continue; // handled by pii-phone-ru
        if (isLikelyExampleValue(file, index)) continue;
        findings.push(
          makePiiFinding({
            id: "pii-phone-intl",
            severity: "medium",
            title: "International phone number found",
            description: `Found an international phone number in ${file.path}. Phone numbers are personal data; remove them or replace with a placeholder.`,
            file,
            index,
            evidence: maskSecretValue(match[0]),
          })
        );
      }

      return findings;
    },
  },
  {
    id: "pii-snils",
    name: "СНИЛС",
    description: "Detects Russian SNILS numbers with checksum validation",
    severity: "high",
    category: "pii",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];
      const pattern = /(?<!\d)\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2}(?!\d)/g;

      for (const match of findAllMatches(file.content, pattern)) {
        const index = match.index ?? 0;
        if (!snilsValid(match[0])) continue;
        findings.push(
          makePiiFinding({
            id: "pii-snils",
            severity: "high",
            title: "СНИЛС found",
            description: `Found a checksum-valid СНИЛС in ${file.path}. This is sensitive personal data and must not be stored in configuration or notes.`,
            file,
            index,
            evidence: maskSecretValue(match[0]),
          })
        );
      }

      return findings;
    },
  },
  {
    id: "pii-inn",
    name: "ИНН",
    description: "Detects Russian INN (10/12 digits) with checksum and context validation",
    severity: "high",
    category: "pii",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];
      const pattern = /(?<!\d)(?:\d{12}|\d{10})(?!\d)/g;

      for (const match of findAllMatches(file.content, pattern)) {
        const index = match.index ?? 0;
        if (!innValid(match[0])) continue;
        if (!hasNearbyLabel(file.content, index, ["инн", "inn", "tax id", "taxpayer", "налог"])) continue;
        findings.push(
          makePiiFinding({
            id: "pii-inn",
            severity: "high",
            title: "ИНН found",
            description: `Found a checksum-valid ИНН near a tax-identifier label in ${file.path}. Tax identifiers are personal data.`,
            file,
            index,
            evidence: maskSecretValue(match[0]),
          })
        );
      }

      return findings;
    },
  },
  {
    id: "pii-ogrn",
    name: "ОГРН/ОГРНИП",
    description: "Detects Russian OGRN/OGRNIP numbers with checksum and context validation",
    severity: "medium",
    category: "pii",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];
      const pattern = /(?<!\d)(?:\d{15}|\d{13})(?!\d)/g;

      for (const match of findAllMatches(file.content, pattern)) {
        const index = match.index ?? 0;
        if (!ogrnValid(match[0])) continue;
        if (!hasNearbyLabel(file.content, index, ["огрн", "ogrn", "огрнип"])) continue;
        findings.push(
          makePiiFinding({
            id: "pii-ogrn",
            severity: "medium",
            title: "ОГРН/ОГРНИП found",
            description: `Found a checksum-valid ОГРН/ОГРНИП near its label in ${file.path}. Registration identifiers are business personal data.`,
            file,
            index,
            evidence: maskSecretValue(match[0]),
          })
        );
      }

      return findings;
    },
  },
  {
    id: "pii-ru-document",
    name: "Russian Passport / Driver License",
    description: "Detects Russian passport or driver-license numbers (series + number) with context",
    severity: "high",
    category: "pii",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];
      const pattern = /(?<!\d)\d{2}\s?\d{2}\s?\d{6}(?!\d)/g;

      for (const match of findAllMatches(file.content, pattern)) {
        const index = match.index ?? 0;
        const isPassport = hasNearbyLabel(file.content, index, ["паспорт", "passport", "серия", "series"]);
        const isLicense = hasNearbyLabel(file.content, index, ["водительск", "driver", "вод. уд", "ву "]);
        if (!isPassport && !isLicense) continue;
        findings.push(
          makePiiFinding({
            id: "pii-ru-document",
            severity: "high",
            title: isPassport ? "Russian passport number found" : "Driver license number found",
            description: `Found a Russian document number near an identifying label in ${file.path}. Government document numbers are highly sensitive personal data.`,
            file,
            index,
            evidence: maskSecretValue(match[0]),
          })
        );
      }

      return findings;
    },
  },
  {
    id: "pii-bank-card",
    name: "Bank Card Number",
    description: "Detects credit/debit card numbers that pass the Luhn checksum",
    severity: "critical",
    category: "pii",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];
      const pattern = /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g;

      for (const match of findAllMatches(file.content, pattern)) {
        const index = match.index ?? 0;
        const digits = match[0].replace(/\D/g, "");
        if (digits.length < 13 || digits.length > 19) continue;
        if (!luhnValid(digits)) continue;

        // Short Luhn-valid runs are usually timestamps/ids; require an explicit
        // card label for anything below the common 16-digit card length.
        if (
          digits.length < 16 &&
          !hasNearbyLabel(file.content, index, [
            "card",
            "visa",
            "mastercard",
            "maestro",
            "amex",
            "american express",
            "cvv",
            "cvc",
            "pan",
            "credit",
            "карта",
            "карты",
          ])
        ) {
          continue;
        }
        findings.push(
          makePiiFinding({
            id: "pii-bank-card",
            severity: "critical",
            title: "Bank card number found",
            description: `Found a Luhn-valid bank card number in ${file.path}. Card numbers are regulated financial personal data and must never be stored in plain text.`,
            file,
            index,
            evidence: maskSecretValue(digits),
          })
        );
      }

      return findings;
    },
  },
  {
    id: "pii-iban",
    name: "IBAN",
    description: "Detects IBAN account numbers with mod-97 validation",
    severity: "high",
    category: "pii",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];
      const pattern = /(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){10,30}(?![A-Z0-9])/g;

      for (const match of findAllMatches(file.content, pattern)) {
        const index = match.index ?? 0;
        if (!ibanValid(match[0])) continue;
        findings.push(
          makePiiFinding({
            id: "pii-iban",
            severity: "high",
            title: "IBAN found",
            description: `Found a checksum-valid IBAN in ${file.path}. Bank account numbers are financial personal data.`,
            file,
            index,
            evidence: maskSecretValue(match[0]),
          })
        );
      }

      return findings;
    },
  },
  {
    id: "pii-bank-ru",
    name: "Russian Bank Details",
    description: "Detects Russian BIK and 20-digit settlement account numbers near their labels",
    severity: "medium",
    category: "pii",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];

      const bikPattern = /(?<!\d)\d{9}(?!\d)/g;
      for (const match of findAllMatches(file.content, bikPattern)) {
        const index = match.index ?? 0;
        if (!hasNearbyLabel(file.content, index, ["бик", "bik"])) continue;
        findings.push(
          makePiiFinding({
            id: "pii-bik",
            severity: "medium",
            title: "Russian BIK found",
            description: `Found a BIK (bank identification code) near its label in ${file.path}.`,
            file,
            index,
            evidence: maskSecretValue(match[0]),
          })
        );
      }

      const accountPattern = /(?<!\d)\d{20}(?!\d)/g;
      for (const match of findAllMatches(file.content, accountPattern)) {
        const index = match.index ?? 0;
        if (!hasNearbyLabel(file.content, index, ["р/с", "расчетн", "расчётн", "account", "счет", "счёт"])) continue;
        findings.push(
          makePiiFinding({
            id: "pii-account-ru",
            severity: "medium",
            title: "Russian settlement account found",
            description: `Found a 20-digit settlement account near its label in ${file.path}.`,
            file,
            index,
            evidence: maskSecretValue(match[0]),
          })
        );
      }

      return findings;
    },
  },
  {
    id: "pii-ssn-us",
    name: "US Social Security Number",
    description: "Detects US SSNs in the canonical XXX-XX-XXXX format",
    severity: "high",
    category: "pii",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];
      const pattern = /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g;

      for (const match of findAllMatches(file.content, pattern)) {
        const index = match.index ?? 0;
        if (!ssnPlausible(match[0])) continue;
        findings.push(
          makePiiFinding({
            id: "pii-ssn",
            severity: "high",
            title: "US Social Security Number found",
            description: `Found a plausible US SSN in ${file.path}. SSNs are sensitive personal identifiers.`,
            file,
            index,
            evidence: maskSecretValue(match[0]),
          })
        );
      }

      return findings;
    },
  },
];
