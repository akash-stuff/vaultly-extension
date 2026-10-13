/**
 * ============================================================================
 * TOTP — the six digits, generated here (RFC 6238)
 * ============================================================================
 * A saved login is only half a sign-in once a site has two-factor auth on it.
 * This module turns a shared secret into the current code, so Vaultly can fill
 * the second field as well as the first.
 *
 * WHERE THE SECRET LIVES
 *
 * Inside the login's existing encrypted blob, as a `totp` field beside
 * `password` and `notes`. That blob is AES-256-GCM ciphertext the server
 * cannot read, so a TOTP secret gets exactly the same protection the password
 * does, the backend needs no changes, and it learns nothing new.
 *
 * WHAT A SECRET LOOKS LIKE, AND WHY WE ACCEPT ANY OF THEM
 *
 * Sites hand out the secret in several shapes: a bare Base32 string, the same
 * string in readable four-character groups, a full `otpauth://` URI from
 * behind the QR code, or that URI with parameters that are not the defaults
 * (SHA256, 8 digits, a 60-second step — all legal, all rare). Someone copying
 * from a setup page should not have to know which one they were handed, so
 * `parseTotp` takes all of them and returns one normalised shape.
 *
 * It is equally tolerant about WHERE it finds one, because this extension is
 * not the only thing writing these blobs: the web vault may use a different
 * field name, and people paste `otpauth://` URIs into the notes. All of those
 * are read; only `totp` is ever written.
 *
 * THE CODE NEVER COMES FROM THE PAGE SIDE OF THE FENCE
 *
 * Generation happens in the service worker, which already holds the vault. A
 * page is handed six digits that expire within the minute — never the secret,
 * which would let it mint codes forever. Same rule as the card number: the
 * page gets the one value it needs, at the moment it needs it.
 * ============================================================================
 */

const g = globalThis;

export const DEFAULTS = { algorithm: 'SHA-1', digits: 6, period: 30 };

/** RFC 4648 Base32, case-insensitive, padding and human spacing ignored. */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input) {
  const clean = String(input).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (!clean || /[^A-Z2-7]/.test(clean)) return null;
  const out = new Uint8Array(Math.floor((clean.length * 5) / 8));
  let bits = 0, value = 0, i = 0;
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out[i++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return i ? out.subarray(0, i) : null;
}

/** Web Crypto spells these with a hyphen; otpauth URIs do not. */
function normaliseAlgorithm(name) {
  const key = String(name || '').toUpperCase().replace('-', '');
  if (key === 'SHA256') return 'SHA-256';
  if (key === 'SHA512') return 'SHA-512';
  if (key === 'SHA1' || !key) return 'SHA-1';
  return null; // SHA-224 and friends: not something Web Crypto will sign with
}

const tidySecret = (s) => String(s).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');

/**
 * Normalise whatever was stored into
 * { secret, algorithm, digits, period, issuer, account }, or null when there
 * is no usable secret in it. Accepts a bare Base32 secret or an otpauth:// URI.
 */
export function parseTotp(input) {
  if (!input) return null;
  const raw = String(input).trim();
  if (!raw) return null;

  if (/^otpauth:\/\//i.test(raw)) return parseOtpauth(raw);

  // A bare secret. Anything that is not decodable Base32 is rejected rather
  // than silently turned into codes from garbage — a wrong code is worse than
  // a missing one, because the site counts it as a failed attempt.
  const bytes = base32Decode(raw);
  if (!bytes || bytes.length < 10) return null;
  return { secret: tidySecret(raw), ...DEFAULTS, issuer: '', account: '' };
}

function parseOtpauth(uri) {
  let url;
  try {
    url = new URL(uri);
  } catch {
    return null;
  }
  // otpauth://totp/Issuer:account?secret=... — `hotp` is driven by a counter
  // rather than a clock, and nothing here could keep that counter in sync.
  if (url.host.toLowerCase() !== 'totp') return null;

  const q = url.searchParams;
  const bytes = base32Decode(q.get('secret') || '');
  if (!bytes || bytes.length < 10) return null;

  const algorithm = normaliseAlgorithm(q.get('algorithm'));
  if (!algorithm) return null;

  // The path is "/Issuer:account", or just "/account", percent-encoded.
  const label = decodeURIComponent(url.pathname.replace(/^\//, ''));
  const [maybeIssuer, maybeAccount] = label.includes(':') ? label.split(/:(.+)/) : ['', label];

  return {
    secret: tidySecret(q.get('secret')),
    algorithm,
    digits: clampInt(q.get('digits'), DEFAULTS.digits, 6, 10),
    period: clampInt(q.get('period'), DEFAULTS.period, 15, 300),
    issuer: q.get('issuer') || maybeIssuer || '',
    account: (maybeAccount || '').trim(),
  };
}

function clampInt(value, fallback, min, max) {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n) || n < min || n > max) return fallback;
  return n;
}

/**
 * Find a secret in a decrypted login blob. This extension writes `totp`; the
 * other names are what the same vault may hold if the web app or an import
 * filled it in, and an `otpauth://` URI pasted into the notes is common enough
 * to be worth picking up.
 */
export function totpFromBlob(blob) {
  if (!blob) return '';
  for (const field of ['totp', 'totpSecret', 'otpauth', 'otpAuthUrl', 'secret']) {
    const v = blob[field];
    if (typeof v === 'string' && parseTotp(v)) return v.trim();
  }
  const inNotes = typeof blob.notes === 'string' && blob.notes.match(/otpauth:\/\/totp\/\S+/i);
  if (inNotes && parseTotp(inNotes[0])) return inNotes[0];
  return '';
}

/**
 * The code for a point in time, plus how long it stays valid. `remaining` is
 * what a countdown renders, and what tells a caller whether a code is about to
 * expire rather than worth submitting.
 */
export async function generateTotp(input, nowMs = Date.now()) {
  const cfg = typeof input === 'string' ? parseTotp(input) : input;
  if (!cfg || !cfg.secret) return null;

  const bytes = base32Decode(cfg.secret);
  if (!bytes) return null;

  const period = cfg.period || DEFAULTS.period;
  const digits = cfg.digits || DEFAULTS.digits;
  const counter = Math.floor(nowMs / 1000 / period);

  // 64-bit big-endian counter, written as two 32-bit halves: a single
  // >>> 32 is a no-op in JS and would silently truncate the clock.
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);

  const key = await g.crypto.subtle.importKey(
    'raw',
    bytes,
    { name: 'HMAC', hash: { name: cfg.algorithm || DEFAULTS.algorithm } },
    false,
    ['sign']
  );
  const mac = new Uint8Array(await g.crypto.subtle.sign('HMAC', key, buf));

  // Dynamic truncation (RFC 4226 section 5.4): the low nibble of the last byte
  // picks the 4-byte window; the top bit is masked off so the result is
  // positive.
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);

  const code = String(binary % 10 ** digits).padStart(digits, '0');
  const elapsed = (nowMs / 1000) % period;
  return { code, period, digits, remaining: Math.max(1, Math.ceil(period - elapsed)) };
}

/** Display form: "123 456". The grouping is for reading it off the screen. */
export function prettyCode(code) {
  if (!code) return '';
  if (code.length === 6) return code.slice(0, 3) + ' ' + code.slice(3);
  if (code.length === 8) return code.slice(0, 4) + ' ' + code.slice(4);
  return code;
}
