/**
 * ============================================================================
 * PAYMENT CARD HELPERS — all local, all offline
 * ============================================================================
 * Mirrors frontend/vaultly-ui/src/services/cards.js so a card looks and reads
 * the same in the extension as it does in the web app. Nothing here touches a
 * network: brand detection and grouping come from the digits alone, because a
 * card number must never be sent somewhere to be "validated".
 * ============================================================================
 */

const BRANDS = [
  { id: 'amex', label: 'American Express', re: /^3[47]/, lengths: [15], cvvLength: 4 },
  { id: 'diners', label: 'Diners Club', re: /^3(?:0[0-5]|[68])/, lengths: [14, 16, 19], cvvLength: 3 },
  { id: 'jcb', label: 'JCB', re: /^35(?:2[89]|[3-8])/, lengths: [16, 17, 18, 19], cvvLength: 3 },
  { id: 'unionpay', label: 'UnionPay', re: /^62/, lengths: [16, 17, 18, 19], cvvLength: 3 },
  { id: 'rupay', label: 'RuPay', re: /^(6521|6522|8172|8173|8174|8175|6069|6080|6081|6082)/, lengths: [16], cvvLength: 3 },
  { id: 'discover', label: 'Discover', re: /^(6011|64[4-9]|65)/, lengths: [16, 19], cvvLength: 3 },
  { id: 'mastercard', label: 'Mastercard', re: /^(5[1-5]|2[2-7])/, lengths: [16], cvvLength: 3 },
  { id: 'visa', label: 'Visa', re: /^4/, lengths: [13, 16, 19], cvvLength: 3 },
];

const OTHER = { id: 'other', label: 'Card', lengths: [12, 13, 14, 15, 16, 17, 18, 19], cvvLength: 3 };

/**
 * The plate palette, matching the web app: a dark, text-safe `base` covering
 * the card and the bright brand hue used only as a corner bloom. Those base
 * values were solved against WCAG AA with every gradient layer composited —
 * they are not free-hand picks, so keep them in step with Cards.jsx.
 */
export const BRAND_COLORS = {
  visa: { base: '27 42 122', accent: '59 107 255' },
  mastercard: { base: '51 38 42', accent: '247 158 27' },
  amex: { base: '4 38 55', accent: '127 212 245' },
  rupay: { base: '9 64 44', accent: '246 148 30' },
  discover: { base: '74 42 18', accent: '247 107 28' },
  diners: { base: '12 61 100', accent: '77 159 224' },
  jcb: { base: '18 58 107', accent: '224 51 74' },
  unionpay: { base: '0 74 99', accent: '224 51 74' },
  other: { base: '53 59 77', accent: '139 147 168' },
};

export function digitsOnly(value) {
  return String(value || '').replace(/\D+/g, '');
}

export function detectBrand(number) {
  const digits = digitsOnly(number);
  return BRANDS.find((b) => b.re.test(digits)) || OTHER;
}

export function brandLabel(id) {
  return (BRANDS.find((b) => b.id === id) || OTHER).label;
}

/** Short, uppercase name for a chip/badge — the long ones crowd a 360px popup. */
export function brandShort(id) {
  return id === 'amex' ? 'AMEX' : id === 'unionpay' ? 'UNIONPAY' : brandLabel(id).toUpperCase();
}

/**
 * How a scheme breaks its digits into printed groups, for a PAN of THIS length.
 * Derived rather than tabulated: a fixed gap list breaks the moment a card is
 * not 16 digits, printing a 19-digit UnionPay as 4-4-4-7.
 */
function groupSizes(brandId, length) {
  if (brandId === 'amex') return [4, 6, 5];
  if (brandId === 'diners' && length === 14) return [4, 6, 4];

  const out = [];
  let left = length;
  while (left > 4) {
    out.push(4);
    left -= 4;
  }
  if (left > 0) {
    // A trailing one or two digits reads as a typo, not a group.
    if (left <= 2 && out.length) out[out.length - 1] += left;
    else out.push(left);
  }
  return out;
}

function regroup(chars, sizes) {
  const out = [];
  let i = 0;
  for (const size of sizes) {
    if (i >= chars.length) break;
    out.push(chars.slice(i, i + size));
    i += size;
  }
  if (i < chars.length) out.push(chars.slice(i));
  return out.join(' ');
}

function nominalLength(brandId) {
  const b = BRANDS.find((x) => x.id === brandId) || OTHER;
  return b.lengths.includes(16) ? 16 : b.lengths[0];
}

export function formatCardNumber(number) {
  const digits = digitsOnly(number);
  return regroup(digits, groupSizes(detectBrand(digits).id, digits.length));
}

/**
 * "•••• •••• •••• 4242". `totalLength` is the real digit count when known, so
 * the mask has the same shape AND width as the number it hides.
 */
export function maskedNumber(last4, brand = 'other', totalLength) {
  const tail = last4 || '';
  const len = Math.max(totalLength || nominalLength(brand), tail.length);
  const chars = '•'.repeat(Math.max(0, len - tail.length)) + tail;
  return regroup(chars, groupSizes(brand, len));
}

/**
 * The Luhn check digit. Every real card number satisfies it, so it is the one
 * cheap test that separates a finished number from a half-typed one — which is
 * what stops the save prompt from firing while someone is still typing, and
 * what stops a mistyped digit from being stored as a card that will never work.
 *
 * It is a checksum, NOT proof the card exists, and it is computed locally: a
 * card number must never be sent somewhere to be validated.
 */
export function passesLuhn(number) {
  const digits = digitsOnly(number);
  if (digits.length < 12) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

export function formatExpiry(month, year) {
  if (!month || !year) return '';
  return `${String(month).padStart(2, '0')}/${String(year).slice(-2)}`;
}

/** A card expires at the END of its printed month. */
export function isExpired(month, year) {
  const m = Number(month);
  const y = Number(year);
  if (!m || !y) return false;
  const fullYear = y < 100 ? 2000 + y : y;
  return new Date(fullYear, m, 1) <= new Date();
}

export function expiresSoon(month, year, months = 2) {
  const m = Number(month);
  const y = Number(year);
  if (!m || !y || isExpired(m, y)) return false;
  const fullYear = y < 100 ? 2000 + y : y;
  const cutoff = new Date();
  cutoff.setMonth(cutoff.getMonth() + months);
  return new Date(fullYear, m, 1) <= cutoff;
}
