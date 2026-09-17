/**
 * Checksum validators for structured identifiers. These dramatically reduce
 * false positives: a 16-digit number is only reported as a bank card if it
 * passes Luhn, and a СНИЛС/ИНН/ОГРН only if its control digit checks out.
 */

function digitsOnly(value: string): string {
  return value.replace(/\D/g, "");
}

/** Luhn mod-10 check (credit/debit cards). */
export function luhnValid(value: string): boolean {
  const digits = digitsOnly(value);
  if (digits.length < 12 || digits.length > 19) return false;

  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let digit = Number(digits[i]);
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }

  return sum % 10 === 0;
}

/** IBAN mod-97 check (ISO 13616). */
export function ibanValid(value: string): boolean {
  const compact = value.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(compact)) return false;

  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const char of rearranged) {
    const code = char >= "A" && char <= "Z" ? String(char.charCodeAt(0) - 55) : char;
    for (const digit of code) {
      remainder = (remainder * 10 + Number(digit)) % 97;
    }
  }

  return remainder === 1;
}

/** СНИЛС (RF pension insurance) checksum over 11 digits. */
export function snilsValid(value: string): boolean {
  const digits = digitsOnly(value);
  if (digits.length !== 11) return false;

  const number = Number(digits.slice(0, 9));
  const control = Number(digits.slice(9));

  if (number < 1001998) {
    const expected = number % 101;
    return (expected === 100 ? 0 : expected) === control;
  }

  let sum = 0;
  for (let i = 0; i < 9; i += 1) {
    sum += Number(digits[i]) * (9 - i);
  }
  const expected = sum % 101;
  return (expected === 100 ? 0 : expected) === control;
}

const INN10_WEIGHTS = [2, 4, 10, 3, 5, 9, 4, 6, 8];
const INN12_WEIGHTS_11 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
const INN12_WEIGHTS_12 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8];

function weightedCheck(digits: string, weights: ReadonlyArray<number>): number {
  let sum = 0;
  for (let i = 0; i < weights.length; i += 1) {
    sum += Number(digits[i]) * weights[i];
  }
  return (sum % 11) % 10;
}

/** ИНН (RF taxpayer id), 10 or 12 digits. */
export function innValid(value: string): boolean {
  const digits = digitsOnly(value);
  if (digits.length === 10) {
    return weightedCheck(digits, INN10_WEIGHTS) === Number(digits[9]);
  }
  if (digits.length === 12) {
    const check11 = weightedCheck(digits, INN12_WEIGHTS_11) === Number(digits[10]);
    const check12 = weightedCheck(digits, INN12_WEIGHTS_12) === Number(digits[11]);
    return check11 && check12;
  }
  return false;
}

/** ОГРН (13 digits) / ОГРНИП (15 digits) checksum. */
export function ogrnValid(value: string): boolean {
  const digits = digitsOnly(value);
  if (digits.length === 13) {
    return (Number(digits.slice(0, 12)) % 11) % 10 === Number(digits[12]);
  }
  if (digits.length === 15) {
    return (Number(digits.slice(0, 14)) % 13) % 10 === Number(digits[14]);
  }
  return false;
}

/** US Social Security Number shape + basic sanity (no checksum exists). */
export function ssnPlausible(value: string): boolean {
  const digits = digitsOnly(value);
  if (digits.length !== 9) return false;
  const area = Number(digits.slice(0, 3));
  const group = Number(digits.slice(3, 5));
  const serial = Number(digits.slice(5));
  if (area === 0 || area === 666 || area >= 900) return false;
  if (group === 0) return false;
  if (serial === 0) return false;
  return true;
}
