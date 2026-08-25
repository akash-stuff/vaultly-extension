/**
 * ============================================================================
 * PASSWORD GENERATOR (Feature 8) + STRENGTH METER (Feature 9)
 * ============================================================================
 * Two important correctness notes vs. the old generateStrongPassword():
 *
 *  1. UNBIASED SELECTION. The old code did `charset[value % charset.length]`.
 *     When the charset length does not evenly divide 2^32, `% length`
 *     makes the low-indexed characters slightly more likely — a real (if
 *     small) bias that weakens the output. We use rejection sampling so
 *     every character in the set is exactly equiprobable.
 *
 *  2. GUARANTEED CLASS COVERAGE. If the user asks for symbols+numbers, a
 *     naive random draw can (rarely) produce a password with none. We seed
 *     one guaranteed character from each enabled class, then fill the rest,
 *     then shuffle — so "include symbols" actually means "contains a symbol".
 * ============================================================================
 */

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.<>?';

// Characters that are easy to confuse in most fonts. Removed when the user
// opts into "avoid ambiguous characters".
const AMBIGUOUS = new Set(['I', 'l', '1', 'O', '0', 'o', 'B', '8', 'S', '5', 'Z', '2', 'G', '6']);

/**
 * Cryptographically secure, UNBIASED random integer in [0, max).
 * Uses rejection sampling to discard values in the biased tail of the
 * 32-bit range. Works in both browser and Node (globalThis.crypto).
 */
function secureRandomInt(max) {
  const cryptoObj = globalThis.crypto;
  const limit = Math.floor(0xffffffff / max) * max; // largest multiple of max
  const buf = new Uint32Array(1);
  let x;
  do {
    cryptoObj.getRandomValues(buf);
    x = buf[0];
  } while (x >= limit); // reject the biased tail
  return x % max;
}

/** Fisher–Yates shuffle using the unbiased RNG above. */
function secureShuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/**
 * Generate a password.
 * @param {object} opts
 * @param {number}  opts.length            desired length (default 20, min 4)
 * @param {boolean} opts.uppercase         include A–Z (default true)
 * @param {boolean} opts.lowercase         include a–z (default true)
 * @param {boolean} opts.numbers           include 0–9 (default true)
 * @param {boolean} opts.symbols           include punctuation (default true)
 * @param {boolean} opts.avoidAmbiguous    drop confusable chars (default false)
 * @returns {string}
 */
export function generatePassword(opts = {}) {
  const {
    length = 20,
    uppercase = true,
    lowercase = true,
    numbers = true,
    symbols = true,
    avoidAmbiguous = false,
  } = opts;

  const len = Math.max(4, Math.floor(length));

  // Build the enabled character classes, filtering ambiguous chars if asked.
  const filter = (s) => (avoidAmbiguous ? [...s].filter((c) => !AMBIGUOUS.has(c)).join('') : s);
  const classes = [];
  if (uppercase) classes.push(filter(UPPER));
  if (lowercase) classes.push(filter(LOWER));
  if (numbers) classes.push(filter(NUMBERS));
  if (symbols) classes.push(filter(SYMBOLS));

  // Nothing selected -> fall back to lowercase so we never throw.
  if (classes.length === 0) classes.push(LOWER);

  const pool = classes.join('');

  const chars = [];
  // Guarantee at least one char from each enabled class (if length allows).
  for (const cls of classes) {
    if (chars.length < len) chars.push(cls[secureRandomInt(cls.length)]);
  }
  // Fill the remainder from the full pool.
  while (chars.length < len) {
    chars.push(pool[secureRandomInt(pool.length)]);
  }

  return secureShuffle(chars).join('');
}

/**
 * Estimate password strength. Returns a label + a 0–4 score + the estimated
 * entropy in bits, so callers can drive a colored meter (Feature 9).
 *
 * This is a lightweight entropy estimate based on the character space and a
 * few common-weakness penalties — good enough for a UX meter. For a rigorous
 * score (dictionary/l33t/keyboard-walk aware) swap in `zxcvbn`; see NOTE.
 *
 * @returns {{score:number, label:string, bits:number}}
 *   score: 0..4  label: 'Weak' | 'Medium' | 'Strong' | 'Very Strong'
 */
export function estimateStrength(password) {
  if (!password) return { score: 0, label: 'Weak', bits: 0 };

  // Size of the character space actually used.
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 32; // rough symbol space

  let bits = password.length * Math.log2(pool || 1);

  // Penalize obvious weaknesses that raw entropy math misses.
  if (/(.)\1\1/.test(password)) bits -= 10; // 3+ repeated chars ("aaa")
  if (/^(?:0123|1234|2345|abcd|qwer|asdf)/i.test(password)) bits -= 15; // sequences
  const unique = new Set(password).size;
  if (unique <= password.length / 2) bits -= 10; // low character variety
  bits = Math.max(0, bits);

  let score;
  if (bits < 40) score = 0;
  else if (bits < 60) score = 1;
  else if (bits < 80) score = 2;
  else if (bits < 100) score = 3;
  else score = 4;

  // Map 0..4 -> the four labels the spec asks for (collapse 0/1 -> Weak/Medium).
  const label = ['Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'][score];
  // Normalize score to 0..4 with Weak occupying 0-1 visually.
  return { score: Math.max(0, score), label, bits: Math.round(bits) };
}

/**
 * NOTE — for production-grade strength scoring, replace estimateStrength with
 * `zxcvbn` (`import zxcvbn from 'zxcvbn'`). It detects dictionary words, dates,
 * names, keyboard patterns, and l33t substitutions that a pure entropy formula
 * treats as strong. The version above is intentionally dependency-free for the
 * content script; zxcvbn adds ~400KB, so bundle it only in the popup/web app.
 */
