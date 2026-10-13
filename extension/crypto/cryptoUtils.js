/**
 * ============================================================================
 * ZERO-KNOWLEDGE CLIENT-SIDE CRYPTO
 * ============================================================================
 * Everything in this file runs ONLY in the browser using the native
 * window.crypto.subtle (Web Crypto API). Nothing here is ever sent to the
 * server. The server only ever receives Base64 ciphertext + IV.
 *
 * Flow:
 *   1. User enters their MASTER (vault) password — NOT the login password.
 *   2. deriveMasterKey() runs PBKDF2-HMAC-SHA256 (>=210,000 iterations) over
 *      that password + a per-user salt to produce a non-extractable AES-256
 *      CryptoKey that lives only in memory for this session.
 *   3. encryptPassword()/decryptPassword() use that key with AES-GCM (which
 *      provides both confidentiality AND integrity/authenticity via its
 *      built-in auth tag) to encrypt/decrypt individual vault entries.
 *   4. The derived key is kept in memory (e.g. React state / a JS closure)
 *      and is cleared on logout / tab close. It is never written to
 *      localStorage, IndexedDB, or any persistent storage.
 * ============================================================================
 */

const PBKDF2_ITERATIONS_DEFAULT = 210000; // OWASP 2023+ recommendation for PBKDF2-SHA256
const AES_KEY_LENGTH = 256; // bits
const IV_LENGTH_BYTES = 12; // 96 bits — the recommended IV size for AES-GCM

/** Generates a cryptographically secure random salt for PBKDF2 (Base64). */
export function generateSalt(byteLength = 16) {
  const salt = window.crypto.getRandomValues(new Uint8Array(byteLength));
  return arrayBufferToBase64(salt);
}

/**
 * Derives a non-extractable AES-256-GCM CryptoKey from the user's master
 * password using PBKDF2. The same password + salt + iterations ALWAYS
 * produces the same key, which is what lets the vault be decrypted on any
 * device without ever transmitting the key itself.
 *
 * @param {string} masterPassword - the user's MASTER (vault) password, never sent to the server
 * @param {string} saltBase64 - Base64 salt (fetched from /api/auth/login, public/non-secret)
 * @param {number} iterations - PBKDF2 iteration count (>= 100,000; default 210,000)
 * @returns {Promise<CryptoKey>} a non-extractable AES-GCM key usable only for encrypt/decrypt
 */
export async function deriveMasterKey(masterPassword, saltBase64, iterations = PBKDF2_ITERATIONS_DEFAULT) {
  const enc = new TextEncoder();
  const salt = base64ToArrayBuffer(saltBase64);

  // Import the raw password as PBKDF2 key material (not directly usable for encryption).
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(masterPassword),
    { name: 'PBKDF2' },
    false, // not extractable
    ['deriveKey']
  );

  // Stretch it into a real AES-GCM 256-bit key. `extractable: false` ensures
  // the raw key bytes can never be read out of the CryptoKey object, even by
  // malicious code running in the same page (mitigates XSS key theft).
  const derivedKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    false, // extractable = false
    ['encrypt', 'decrypt']
  );

  return derivedKey;
}

/**
 * Encrypts a plaintext password (and optional notes) with AES-256-GCM.
 * A fresh random IV is generated for EVERY call — reusing an IV with the
 * same key would catastrophically break AES-GCM's security guarantees.
 *
 * @param {string} plainTextPassword
 * @param {CryptoKey} masterKey - key returned by deriveMasterKey()
 * @param {string} [notes] - optional extra field encrypted alongside the password
 * @returns {Promise<{ciphertext: string, iv: string}>} Base64 ciphertext + Base64 IV
 */
export async function encryptPassword(plainTextPassword, masterKey, notes = '') {
  const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const enc = new TextEncoder();

  // Bundle password + notes into one JSON payload so both are protected
  // (and integrity-checked together) under a single AES-GCM auth tag.
  const payload = JSON.stringify({ password: plainTextPassword, notes });

  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    masterKey,
    enc.encode(payload)
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertextBuffer),
    iv: arrayBufferToBase64(iv),
  };
}

/**
 * Decrypts a ciphertext blob previously produced by encryptPassword().
 * AES-GCM will THROW if the ciphertext, IV, or key is wrong/tampered with
 * (the built-in auth tag fails verification) — this doubles as a tamper
 * detection / integrity check, not just confidentiality.
 *
 * @param {string} ciphertextBase64
 * @param {string} ivBase64
 * @param {CryptoKey} masterKey
 * @returns {Promise<{password: string, notes: string}>}
 */
export async function decryptPassword(ciphertextBase64, ivBase64, masterKey) {
  const iv = base64ToArrayBuffer(ivBase64);
  const ciphertext = base64ToArrayBuffer(ciphertextBase64);

  try {
    const plainBuffer = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, masterKey, ciphertext);
    const dec = new TextDecoder();
    const json = dec.decode(plainBuffer);
    return JSON.parse(json);
  } catch (err) {
    // Wrong master password, corrupted data, or tampering — never leak details.
    throw new Error('Decryption failed: incorrect master password or corrupted data');
  }
}

/**
 * Client-side password strength / generator helper (defense-in-depth UX,
 * not a security boundary by itself).
 */
export function generateStrongPassword(length = 20) {
  const charset =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}';
  const randomValues = window.crypto.getRandomValues(new Uint32Array(length));
  return Array.from(randomValues, (v) => charset[v % charset.length]).join('');
}

// ---- Base64 <-> ArrayBuffer helpers ----

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
