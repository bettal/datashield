import { describe, it, expect } from "vitest";
import {
  luhnValid,
  ibanValid,
  snilsValid,
  innValid,
  ogrnValid,
  ssnPlausible,
} from "../../src/detection/validators.js";

describe("luhnValid", () => {
  it("accepts known-valid card numbers", () => {
    expect(luhnValid("4111111111111111")).toBe(true);
    expect(luhnValid("5500005555555559")).toBe(true);
    expect(luhnValid("378282246310005")).toBe(true);
  });

  it("rejects numbers that fail the checksum", () => {
    expect(luhnValid("4111111111111112")).toBe(false);
  });

  it("rejects wrong lengths", () => {
    expect(luhnValid("123456789")).toBe(false);
  });
});

describe("ibanValid", () => {
  it("accepts known-valid IBANs", () => {
    expect(ibanValid("GB82 WEST 1234 5698 7654 32")).toBe(true);
    expect(ibanValid("DE89370400440532013000")).toBe(true);
  });

  it("rejects invalid IBANs", () => {
    expect(ibanValid("GB82WEST12345698765433")).toBe(false);
  });
});

describe("snilsValid", () => {
  it("accepts a checksum-valid СНИЛС", () => {
    expect(snilsValid("112-233-445 95")).toBe(true);
  });

  it("rejects a bad control digit", () => {
    expect(snilsValid("112-233-445 94")).toBe(false);
  });

  it("rejects wrong length", () => {
    expect(snilsValid("11223344")).toBe(false);
  });
});

describe("innValid", () => {
  it("accepts a valid 10-digit ИНН", () => {
    expect(innValid("7707083893")).toBe(true);
  });

  it("accepts a valid 12-digit ИНН", () => {
    expect(innValid("500100732259")).toBe(true);
  });

  it("rejects a bad 10-digit ИНН", () => {
    expect(innValid("7707083894")).toBe(false);
  });

  it("rejects a bad 12-digit ИНН", () => {
    expect(innValid("500100732258")).toBe(false);
  });
});

describe("ogrnValid", () => {
  it("accepts a valid ОГРН", () => {
    expect(ogrnValid("1027700132195")).toBe(true);
  });

  it("rejects a bad ОГРН", () => {
    expect(ogrnValid("1027700132196")).toBe(false);
  });
});

describe("ssnPlausible", () => {
  it("accepts a plausible SSN", () => {
    expect(ssnPlausible("123-45-6789")).toBe(true);
  });

  it("rejects reserved areas and zero groups", () => {
    expect(ssnPlausible("000-45-6789")).toBe(false);
    expect(ssnPlausible("666-45-6789")).toBe(false);
    expect(ssnPlausible("900-45-6789")).toBe(false);
    expect(ssnPlausible("123-00-6789")).toBe(false);
  });
});
