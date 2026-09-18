import { describe, it, expect } from "vitest";
import { shannonEntropy, looksLikeHighEntropySecret } from "../../src/detection/entropy.js";
import { maskSensitive } from "../../src/detection/mask.js";

describe("shannonEntropy", () => {
  it("is zero for a single repeated character", () => {
    expect(shannonEntropy("aaaaaaaa")).toBe(0);
  });

  it("is higher for a random-looking string than for a word", () => {
    expect(shannonEntropy("xJ8kL2mN9pQ4rS7tU1vW5yZ3aB6cD0eF")).toBeGreaterThan(
      shannonEntropy("passwordpasswordpassword")
    );
  });
});

describe("looksLikeHighEntropySecret", () => {
  it("accepts a random base64-like secret", () => {
    expect(looksLikeHighEntropySecret("xJ8kL2mN9pQ4rS7tU1vW5yZ3aB6cD0eF")).toBe(true);
  });

  it("rejects short strings", () => {
    expect(looksLikeHighEntropySecret("abc123")).toBe(false);
  });

  it("rejects placeholders and common words", () => {
    expect(looksLikeHighEntropySecret("your_api_key_goes_here_1234567890")).toBe(false);
    expect(looksLikeHighEntropySecret("example-secret-value-1234567890")).toBe(false);
  });

  it("rejects pure digit strings and UUIDs", () => {
    expect(looksLikeHighEntropySecret("123456789012345678901234")).toBe(false);
    expect(looksLikeHighEntropySecret("123e4567-e89b-12d3-a456-426614174000")).toBe(false);
  });

  it("rejects purely alphabetic identifiers", () => {
    expect(looksLikeHighEntropySecret("disableBypassPermissionsMode")).toBe(false);
    expect(looksLikeHighEntropySecret("abcdefghijklmnopqrstuvwx")).toBe(false);
  });
});

describe("maskSensitive", () => {
  it("fully masks very short values instead of leaking them", () => {
    expect(maskSensitive("abcd")).toBe("****");
    expect(maskSensitive("ab")).toBe("**");
  });

  it("keeps only first/last char for short values", () => {
    expect(maskSensitive("abcdefgh")).toBe("a******h");
  });

  it("keeps a prefix/suffix for long values", () => {
    const masked = maskSensitive("sk-ant-abcdefghijklmnop");
    expect(masked.startsWith("sk-ant-a")).toBe(true);
    expect(masked).toContain("...");
    expect(masked).not.toContain("ijklmnop");
  });
});
