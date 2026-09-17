import type { ConfigFile, Finding, Rule } from "../types.js";
import {
  findAllMatches,
  findLineNumber,
  isTextLikeFile,
  isLikelyExampleValue,
  maskSecretValue,
} from "./helpers.js";

/**
 * One-time and recovery code detection.
 *
 * These are short-lived secrets: a leaked OTP or recovery code can be replayed
 * to take over an account even when the underlying password is strong. All
 * rules require a nearby label, which keeps false positives (years, status
 * codes, ports) near zero.
 */

export const codeRules: ReadonlyArray<Rule> = [
  {
    id: "codes-otp",
    name: "One-Time / 2FA Code",
    description: "Detects OTP, TOTP, 2FA/MFA, and verification codes",
    severity: "high",
    category: "codes",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];

      const pattern =
        /(?:otp|totp|2fa|mfa|one[-\s]?time(?:\s+code)?|verification\s*code|verification[_-]?code|auth(?:entication)?\s*code|sms[-\s]?code|код\s+подтверждения|смс[-\s]?код)\s*[=:]?\s*["']?(\d{4,8})["']?/gi;

      for (const match of findAllMatches(file.content, pattern)) {
        const index = match.index ?? 0;
        const code = match[1];
        if (isLikelyExampleValue(file, index)) continue;

        findings.push({
          id: `codes-otp-${index}`,
          severity: "high",
          category: "codes",
          title: "One-time / 2FA code found",
          description: `Found a one-time/2FA code in ${file.path}. One-time codes can be replayed within their validity window to bypass multi-factor authentication.`,
          file: file.path,
          line: findLineNumber(file.content, index),
          evidence: maskSecretValue(code),
        });
      }

      return findings;
    },
  },
  {
    id: "codes-recovery",
    name: "Recovery / Backup Codes",
    description: "Detects lists of account recovery or backup codes",
    severity: "high",
    category: "codes",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];

      const listPattern =
        /(?:recovery|backup|резервн\w*)\s*(?:codes?|коды?)\s*[=:]?\s*([A-Za-z0-9-]{4,}(?:[,\s]+[A-Za-z0-9-]{4,}){2,})/gi;

      for (const match of findAllMatches(file.content, listPattern)) {
        const index = match.index ?? 0;
        if (isLikelyExampleValue(file, index)) continue;

        const codes = match[1].split(/[,\s]+/).filter(Boolean);

        findings.push({
          id: `codes-recovery-${index}`,
          severity: "high",
          category: "codes",
          title: `Recovery/backup codes found (${codes.length})`,
          description: `Found ${codes.length} account recovery/backup codes in ${file.path}. Recovery codes bypass MFA entirely and must be stored in a password manager, never in configuration or notes.`,
          file: file.path,
          line: findLineNumber(file.content, index),
          evidence: `${codes.length} codes: ${maskSecretValue(codes[0])}, …`,
        });
      }

      const singlePattern = /(?:recovery|backup)[_-]?code\s*[=:]\s*["']?([A-Za-z0-9-]{6,})["']?/gi;
      for (const match of findAllMatches(file.content, singlePattern)) {
        const index = match.index ?? 0;
        if (isLikelyExampleValue(file, index)) continue;
        findings.push({
          id: `codes-recovery-single-${index}`,
          severity: "high",
          category: "codes",
          title: "Recovery code found",
          description: `Found a recovery code in ${file.path}. Recovery codes bypass MFA and must not be stored in plain text.`,
          file: file.path,
          line: findLineNumber(file.content, index),
          evidence: maskSecretValue(match[1]),
        });
      }

      return findings;
    },
  },
  {
    id: "codes-pin",
    name: "PIN Code",
    description: "Detects PIN codes assigned to a labeled key",
    severity: "medium",
    category: "codes",
    check(file: ConfigFile): ReadonlyArray<Finding> {
      if (!isTextLikeFile(file)) return [];
      const findings: Finding[] = [];

      const pattern = /(?:pin|пин)[-\s]?(?:code|код)?\s*[=:]\s*["']?(\d{4,8})["']?/gi;

      for (const match of findAllMatches(file.content, pattern)) {
        const index = match.index ?? 0;
        if (isLikelyExampleValue(file, index)) continue;

        findings.push({
          id: `codes-pin-${index}`,
          severity: "medium",
          category: "codes",
          title: "PIN code found",
          description: `Found a PIN code in ${file.path}. PINs are short secrets that must not be stored in configuration or notes.`,
          file: file.path,
          line: findLineNumber(file.content, index),
          evidence: maskSecretValue(match[1]),
        });
      }

      return findings;
    },
  },
];
