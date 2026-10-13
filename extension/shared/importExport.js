/**
 * ============================================================================
 * FILE 2/5 — IMPORT / EXPORT  (Feature 21)
 * ============================================================================
 * Pure parsing/serialization. NO crypto here on purpose — see the loud warning.
 *
 * ⚠️ SECURITY: every function in this file deals in PLAINTEXT credentials.
 *    - On EXPORT, the caller must have already decrypted the items, and the
 *      resulting file is unencrypted plaintext. Warn the user before download.
 *      For "Encrypted Vault Export", wrap the JSON from `toVaultlyJson()` with
 *      encryptPassword() using the master key before writing to disk.
 *    - On IMPORT, the parsed rows are plaintext; encrypt each with the master
 *      key (encryptPassword) BEFORE POSTing to /api/vault. Never send plaintext
 *      passwords to the backend.
 *
 * Normalized item shape used across all formats:
 *   { websiteName, websiteUrl, username, password, notes }
 * ============================================================================
 */

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/** Serialize items to CSV (header: name,url,username,password,notes). */
export function toCsv(items) {
  const header = ['name', 'url', 'username', 'password', 'notes'];
  const rows = items.map((it) => [
    it.websiteName || '', it.websiteUrl || '', it.username || '', it.password || '', it.notes || '',
  ]);
  return [header, ...rows].map((r) => r.map(csvEscape).join(',')).join('\r\n');
}

function csvEscape(field) {
  const s = String(field ?? '');
  // Quote if it contains a comma, quote, CR or LF; double internal quotes.
  if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

/**
 * Parse CSV into normalized items. A proper RFC-4180-ish parser that handles
 * quoted fields, escaped quotes (""), and commas/newlines inside quotes.
 * Recognizes common column aliases from Chrome/Bitwarden/LastPass exports.
 */
export function fromCsv(text) {
  const records = parseCsvRecords(text);
  if (records.length === 0) return [];

  const header = records[0].map((h) => h.trim().toLowerCase());
  const idx = (aliases) => header.findIndex((h) => aliases.includes(h));
  const iName = idx(['name', 'title', 'account']);
  const iUrl = idx(['url', 'website', 'uri', 'login_uri']);
  const iUser = idx(['username', 'user', 'login', 'login_username', 'email']);
  const iPass = idx(['password', 'login_password', 'pass']);
  const iNotes = idx(['notes', 'note', 'extra']);

  return records.slice(1)
    .filter((r) => r.length && r.some((c) => c !== ''))
    .map((r) => ({
      websiteName: iName >= 0 ? r[iName] || '' : '',
      websiteUrl: iUrl >= 0 ? r[iUrl] || '' : '',
      username: iUser >= 0 ? r[iUser] || '' : '',
      password: iPass >= 0 ? r[iPass] || '' : '',
      notes: iNotes >= 0 ? r[iNotes] || '' : '',
    }));
}

/** Tokenize CSV text into an array of records (each an array of fields). */
function parseCsvRecords(text) {
  const records = [];
  let field = '', record = [], inQuotes = false;
  const src = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n'); // normalize EOLs

  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (inQuotes) {
      if (c === '"') {
        if (src[i + 1] === '"') { field += '"'; i++; } // escaped quote
        else inQuotes = false;
      } else field += c;
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      record.push(field); field = '';
    } else if (c === '\n') {
      record.push(field); records.push(record); field = ''; record = [];
    } else field += c;
  }
  // Flush trailing field/record (file may not end with a newline).
  if (field !== '' || record.length) { record.push(field); records.push(record); }
  return records;
}

// ---------------------------------------------------------------------------
// Vaultly JSON (our own portable format)
// ---------------------------------------------------------------------------

export function toVaultlyJson(items) {
  return JSON.stringify({
    format: 'vaultly',
    version: 1,
    exportedAt: new Date().toISOString(),
    items: items.map((it) => ({
      websiteName: it.websiteName || '',
      websiteUrl: it.websiteUrl || '',
      username: it.username || '',
      password: it.password || '',
      notes: it.notes || '',
    })),
  }, null, 2);
}

export function fromVaultlyJson(text) {
  const data = JSON.parse(text);
  const items = Array.isArray(data) ? data : data.items;
  if (!Array.isArray(items)) throw new Error('Not a Vaultly export');
  return items.map(normalize);
}

// ---------------------------------------------------------------------------
// Bitwarden JSON (unencrypted export)
// ---------------------------------------------------------------------------

/**
 * Bitwarden's unencrypted JSON export looks like:
 *   { "items": [ { "name": "...", "login": { "username": "...",
 *                  "password": "...", "uris": [ { "uri": "..." } ] },
 *                  "notes": "..." }, ... ] }
 * Folders and non-login items (cards, identities) are skipped.
 */
export function fromBitwardenJson(text) {
  const data = JSON.parse(text);
  const items = data.items || [];
  return items
    .filter((it) => it.login) // only login items
    .map((it) => ({
      websiteName: it.name || '',
      websiteUrl: (it.login.uris && it.login.uris[0] && it.login.uris[0].uri) || '',
      username: it.login.username || '',
      password: it.login.password || '',
      notes: it.notes || '',
    }));
}

/** Auto-detect format from text and parse. */
export function parseAny(text, filename = '') {
  const trimmed = text.trim();
  if (/\.csv$/i.test(filename) || (!trimmed.startsWith('{') && !trimmed.startsWith('['))) {
    return fromCsv(text);
  }
  const data = JSON.parse(trimmed);
  if (data.format === 'vaultly' || Array.isArray(data)) return fromVaultlyJson(text);
  if (data.items && data.items.some && data.items.some((i) => i.login)) return fromBitwardenJson(text);
  if (data.items) return fromVaultlyJson(text);
  throw new Error('Unrecognized import format');
}

function normalize(it) {
  return {
    websiteName: it.websiteName || it.name || '',
    websiteUrl: it.websiteUrl || it.url || '',
    username: it.username || '',
    password: it.password || '',
    notes: it.notes || '',
  };
}
