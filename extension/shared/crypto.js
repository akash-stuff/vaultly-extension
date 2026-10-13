/**
 * ============================================================================
 * ZERO-KNOWLEDGE CLIENT-SIDE CRYPTO  (context-safe version)
 * ============================================================================
 * Identical crypto to the original crypto/cryptoUtils.js, with ONE change:
 * it references `globalThis` instead of `window`. A Manifest V3 background
 * service worker has NO `window` object, so the original module throws there.
 * `globalThis.crypto` / `globalThis.btoa` resolve correctly in BOTH the popup
 * (a document) and the service worker, letting popup.js and background.js
 * share a single crypto implementation with no behavioural difference.
 *
 * Invariants preserved:
 *  - Keys are non-extractable and never leave the extension's JS memory.
 *  - Nothing here is ever sent to the server; the server sees only Base64
 *    ciphertext + IV.
 *  - A fresh random 96-bit IV is generated for every encryption.
 * ============================================================================
 */

const PBKDF2_ITERATIONS_DEFAULT = 210000; // OWASP 2023+ for PBKDF2-SHA256
const AES_KEY_LENGTH = 256;
const IV_LENGTH_BYTES = 12; // 96-bit nonce, recommended for AES-GCM

const g = globalThis;

export function generateSalt(byteLength = 16) {
  const salt = g.crypto.getRandomValues(new Uint8Array(byteLength));
  return arrayBufferToBase64(salt);
}

/**
 * Derive a non-extractable AES-256-GCM key from the master password via
 * PBKDF2. Same password + salt + iterations always yields the same key.
 */
export async function deriveMasterKey(masterPassword, saltBase64, iterations = PBKDF2_ITERATIONS_DEFAULT) {
  const enc = new TextEncoder();
  const salt = base64ToArrayBuffer(saltBase64);

  const keyMaterial = await g.crypto.subtle.importKey(
    'raw',
    enc.encode(masterPassword),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return g.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    false, // non-extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt any JSON-serialisable object into Base64 ciphertext + IV.
 *
 * The primitive every item type is built on. Bundling an item's secret fields
 * into ONE payload matters: AES-GCM's auth tag then covers the whole object, so
 * a field of one card cannot be swapped for a field of another — each blob is
 * authenticated as a unit rather than field by field.
 *
 * Mirrors encryptJson in the web app's crypto/cryptoUtils.js, so a card written
 * by either side opens on the other.
 */
export async function encryptJson(obj, masterKey) {
  const iv = g.crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const enc = new TextEncoder();

  const ciphertextBuffer = await g.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    masterKey,
    enc.encode(JSON.stringify(obj))
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertextBuffer),
    iv: arrayBufferToBase64(iv),
  };
}

/** Decrypt a blob produced by encryptJson(). Throws on any tampering. */
export async function decryptJson(ciphertextBase64, ivBase64, masterKey) {
  const iv = base64ToArrayBuffer(ivBase64);
  const ciphertext = base64ToArrayBuffer(ciphertextBase64);
  try {
    const plainBuffer = await g.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, masterKey, ciphertext);
    return JSON.parse(new TextDecoder().decode(plainBuffer));
  } catch {
    throw new Error('Decryption failed: incorrect master password or corrupted data');
  }
}

/**
 * Encrypt { password, notes, totp } into Base64 ciphertext + IV.
 * A thin wrapper that pins the payload shape, because that shape IS the
 * on-the-wire format for logins and TOTP secrets — changing it would make
 * every existing blob undecryptable.
 *
 * `totp` is a two-factor secret: a bare Base32 string or a full otpauth:// URI
 * (shared/totp.js takes either). It rides inside the SAME encrypted blob as
 * the password, which is the whole point — the server stores a TOTP secret
 * under exactly the protection it already gives the password, and learns
 * nothing new. An older blob simply has no `totp` key, and reads back as ''.
 *
 * Callers that re-encrypt an existing item MUST pass the secret back in.
 * Leaving it out does not clear a field, it silently destroys the user's
 * second factor — which is why every call site here passes it explicitly.
 */
export async function encryptPassword(plainTextPassword, masterKey, notes = '', totp = '') {
  return encryptJson({ password: plainTextPassword, notes, totp }, masterKey);
}

/** Decrypt a blob produced by encryptPassword(). Throws on any tampering. */
export async function decryptPassword(ciphertextBase64, ivBase64, masterKey) {
  return decryptJson(ciphertextBase64, ivBase64, masterKey);
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return g.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = g.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
