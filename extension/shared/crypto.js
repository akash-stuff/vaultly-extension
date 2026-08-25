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

/** Encrypt { password, notes } into Base64 ciphertext + IV. */
export async function encryptPassword(plainTextPassword, masterKey, notes = '') {
  const iv = g.crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const enc = new TextEncoder();
  const payload = JSON.stringify({ password: plainTextPassword, notes });

  const ciphertextBuffer = await g.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    masterKey,
    enc.encode(payload)
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertextBuffer),
    iv: arrayBufferToBase64(iv),
  };
}

/** Decrypt a blob produced by encryptPassword(). Throws on any tampering. */
export async function decryptPassword(ciphertextBase64, ivBase64, masterKey) {
  const iv = base64ToArrayBuffer(ivBase64);
  const ciphertext = base64ToArrayBuffer(ciphertextBase64);
  try {
    const plainBuffer = await g.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, masterKey, ciphertext);
    return JSON.parse(new TextDecoder().decode(plainBuffer));
  } catch {
    throw new Error('Decryption failed: incorrect master password or corrupted data');
  }
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
