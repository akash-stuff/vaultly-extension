/**
 * ============================================================================
 * BACKGROUND SERVICE WORKER (Manifest V3)  — unlocked-session vault broker
 * ============================================================================
 * WHY THIS CHANGED (read before judging the security model):
 *
 * The original popup-only design derived the AES key inside the popup and
 * destroyed it when the popup closed. Great for isolation, but it makes
 * page-driven features impossible: the content script can't offer autofill
 * suggestions or "Save login?" prompts because the popup (and its key) isn't
 * open while you're browsing.
 *
 * Real password managers (Bitwarden included) solve this by holding the
 * unlocked vault in a background/service-worker context for the duration of
 * the unlocked session. We do the same. The invariants that actually matter
 * are all still intact:
 *
 *   - The master key is derived and lives ONLY in this worker's memory. It is
 *     a non-extractable CryptoKey and is NEVER written to any chrome.storage,
 *     disk, or the network.
 *   - Plaintext credentials live only in this worker's memory. The PAGE only
 *     ever receives the single credential the user explicitly chose to fill.
 *   - The server still only ever sees Base64 ciphertext + IV.
 *   - MV3 service workers are killed when idle -> the in-memory key/vault die
 *     with them -> effective auto-lock; the popup re-derives on next unlock.
 *
 * The popup hands us the master password over the INTERNAL extension messaging
 * channel (never HTTP) exactly once, at unlock, so we can derive the key here.
 * ============================================================================
 */

import {
  deriveMasterKey,
  encryptPassword,
  decryptPassword,
  encryptJson,
  decryptJson,
} from './shared/crypto.js';
import { getRootDomain, isSameSite } from './shared/domainUtils.js';
import { generateTotp, parseTotp, totpFromBlob } from './shared/totp.js';
import { initAutoLock, noteActivity, cancelAutoLock } from './shared/autoLock.js';
import { apiFetch, saveSession, clearSession, getStoredIdentity } from './shared/session.js';
import {
  hardenSessionStorage,
  getPinMode,
  setPinMode,
  rememberPin,
  getRememberedPin,
  forgetPin,
} from './shared/stayUnlocked.js';
import {
  maskedNumber,
  formatExpiry,
  isExpired,
  brandShort,
  brandLabel,
  detectBrand,
  digitsOnly,
  passesLuhn,
} from './shared/cards.js';

// ---- In-memory unlocked-session state (dies with the worker = auto-lock) ----
let masterKey = null;            // non-extractable CryptoKey, memory only
// The PIN itself, held for exactly as long as the key is. The derived key is
// non-extractable and cannot be turned back into a PIN, so a remembering mode
// needs the string itself to store — and Settings can only be reached from an
// unlocked vault, so changing the mode mid-session has to find the PIN
// somewhere. Dropped by lock(), like everything else here.
let masterPin = null;
let userMeta = null;             // { id, email, kdfSalt, kdfIterations }
let vault = new Map();           // Map<itemId, {id,websiteName,websiteUrl,username,password}> DECRYPTED, memory only
// Cards live beside the logins under exactly the same rules: decrypted in this
// worker's memory only, dying with it. A card is not domain-scoped the way a
// login is — you may pay for anything anywhere — so the whole set is offered
// at a checkout, and the PAGE still only ever receives the one the user picks.
let cards = new Map();           // Map<cardId, {id,label,brand,last4,number,cvv,cardholderName,expMonth,expYear,pin}>
// When the set was last pulled. A card added in the web app after unlock
// would otherwise be invisible at a checkout for the rest of the browser
// session, which reads as "my card isn't there" rather than "the cache is
// stale". Revalidated lazily, only when a page actually asks.
let cardsLoadedAt = 0;
const CARDS_TTL_MS = 5 * 60_000;
// WHY the card set is empty, when it is. Every failure here used to be
// swallowed into the same blank list, so "the route 404s", "the session is
// dead", "the blob will not decrypt" and "you have no cards" were
// indistinguishable in the UI — which is exactly the state you cannot debug.
let cardsError = null;

/**
 * A card read off a checkout page, waiting for the user to answer the save
 * prompt. It lives HERE rather than in the page for two reasons: the frame
 * that can read the fields is often a payment iframe far too small to render a
 * prompt in, and relaying the number to the top frame so it could hold it
 * would put a PAN in a second page context for no benefit. This worker already
 * holds every saved card, so it is the one place that learns nothing new.
 *
 * Expires on its own: an unanswered prompt must not leave a card number
 * sitting in memory for the rest of the session.
 */
let pendingCard = null;         // { tabId, card, display, at }
const PENDING_CARD_TTL_MS = 3 * 60_000;

// "Never for this site", per root domain, for as long as this worker lives.
const cardPromptSuppressed = new Set();

const isUnlocked = () => masterKey !== null;

// ---------------------------------------------------------------------------
// Backend helper
// ---------------------------------------------------------------------------
/**
 * All backend calls go through shared/session.js, which renews the 15-minute
 * access token behind our back and replays the request. This worker can outlive
 * that token many times over, so an expired one is routine — the vault is only
 * dropped when the SERVER rejects the refresh token, i.e. the session really is
 * over. Previously any 401 locked the vault, which meant saving a password
 * twenty minutes after unlocking signed you out.
 */
async function api(path, options = {}) {
  try {
    return await apiFetch(path, options);
  } catch (err) {
    if (err.sessionDead) {
      lock({ reason: 'session-expired' });
      await clearSession();
      notify('Vault locked', 'Your session expired. Open Vaultly to sign in again.');
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Unlock / lock
// ---------------------------------------------------------------------------
async function unlock({ token, refreshToken, user, masterPassword, items }) {
  // The popup has just signed in or refreshed; persist whatever it hands us so
  // this worker and the popup always read the same (rotating) tokens.
  if (token || refreshToken) await saveSession({ token, refreshToken, user });
  userMeta = user;
  masterKey = await deriveMasterKey(masterPassword, user.kdfSalt, user.kdfIterations);

  vault = new Map();
  for (const item of items) {
    try {
      const blob = await decryptPassword(item.encryptedDataBlob, item.iv, masterKey);
      vault.set(item._id, {
        id: item._id,
        websiteName: item.websiteName,
        websiteUrl: item.websiteUrl,
        username: item.username,
        password: blob.password,
        // The two-factor secret, if this login has one. Stays in this worker
        // exactly like the password: codes are minted here and handed out one
        // at a time, and the secret itself never reaches a page.
        totp: totpFromBlob(blob),
        notes: blob.notes || '',
      });
    } catch {
      // A single corrupt item shouldn't blow up the whole unlock.
    }
  }
  chrome.storage.local.remove(LOCK_REASON_KEY).catch(() => {});
  masterPin = masterPassword;
  // Keeps the PIN where the user's chosen mode says to keep it — nowhere at
  // all under the default. See shared/stayUnlocked.js.
  await rememberPin(masterPassword);
  await loadCards();
  await refreshBadgeForActiveTab();
  noteActivity(); // start/refresh the idle-lock countdown for this session
}

/**
 * Pull the vault and decrypt it here, in the worker. The unlock path above is
 * handed already-fetched items by the popup; the resume path below has no
 * popup to hand it anything, so it needs its own way in.
 *
 * Returns the number of items the key actually opened. Zero out of a non-empty
 * set means the key is wrong for these blobs — worth distinguishing from an
 * empty vault, which opens trivially.
 */
async function loadVaultFromApi() {
  const { items = [] } = await api('/vault');
  const next = new Map();
  let opened = 0;
  for (const item of items) {
    try {
      const blob = await decryptPassword(item.encryptedDataBlob, item.iv, masterKey);
      next.set(item._id, {
        id: item._id,
        websiteName: item.websiteName,
        websiteUrl: item.websiteUrl,
        username: item.username,
        password: blob.password,
        totp: totpFromBlob(blob),
        notes: blob.notes || '',
      });
      opened += 1;
    } catch {
      // A single corrupt item shouldn't cost the user the rest of the vault.
    }
  }
  vault = next;
  return { total: items.length, opened };
}

/**
 * ---------------------------------------------------------------------------
 * RESUME — the point of the master PIN modes
 * ---------------------------------------------------------------------------
 * Chrome kills this worker after about thirty seconds of quiet, taking the key
 * and the decrypted vault with it. Under the default 'always' mode that IS the
 * auto-lock, and the user types their PIN again. Under 'session' or 'never'
 * the PIN is waiting in storage and we rebuild the whole session from scratch
 * right here — so the popup opens straight into the vault, and a page's
 * autofill request is answered instead of meeting a locked worker.
 *
 * Resolves true when the vault is open afterwards. Deliberately quiet on
 * failure: a resume that cannot happen is never worse than the PIN screen.
 */
let resuming = null;

function ensureUnlocked() {
  if (isUnlocked()) return Promise.resolve(true);
  // Single-flight. Opening the popup fires several messages at once, and every
  // one of them would otherwise start its own PBKDF2 run and its own /vault
  // fetch against the same woken worker.
  if (!resuming) resuming = resumeFromRememberedPin().finally(() => { resuming = null; });
  return resuming;
}

async function resumeFromRememberedPin() {
  const pin = await getRememberedPin();
  if (!pin) return false;

  const { user, refreshToken } = await getStoredIdentity();
  if (!user || !refreshToken) {
    // Signed out in another context. The PIN is of no use and shouldn't linger.
    await forgetPin();
    return false;
  }

  let restored = false;
  try {
    userMeta = user;
    masterKey = await deriveMasterKey(pin, user.kdfSalt, user.kdfIterations);
    const { total, opened } = await loadVaultFromApi();
    if (total > 0 && opened === 0) {
      // The PIN that unlocked this session no longer opens the vault — the
      // master PIN was changed elsewhere. Keeping it would mean silently
      // resuming into a vault of blank passwords, so: forget it and fall back
      // to the PIN screen, which is where that change needs to be noticed.
      await forgetPin();
      throw new Error('stored PIN no longer opens this vault');
    }
    masterPin = pin;
    restored = true;
    await loadCards();
    await refreshBadgeForActiveTab();
    noteActivity();
  } catch (err) {
    if (!restored) {
      masterKey = null;
      userMeta = null;
      vault = new Map();
    }
    // Offline keeps the PIN: the next request retries, and a flaky network is
    // not a reason to make someone re-authenticate. A dead session has already
    // been cleaned up by api().
    console.warn('[Vaultly] could not resume unlocked session:', err && err.message);
    return false;
  }
  return true;
}

/**
 * Fetch and decrypt the card set. Done HERE rather than handed over by the
 * popup because the worker already holds the master key, and a checkout can
 * happen at any point in a session — long after the popup that unlocked it
 * closed. A failure is non-fatal: logins still work, cards just stay empty.
 */
async function loadCards() {
  cards = new Map();
  cardsLoadedAt = 0;
  cardsError = null;
  if (!isUnlocked()) {
    cardsError = 'locked';
    return;
  }
  let undecryptable = 0;
  try {
    const { items = [] } = await api('/cards');
    for (const c of items) {
      try {
        const data = await decryptJson(c.encryptedDataBlob, c.iv, masterKey);
        cards.set(c._id, {
          id: c._id,
          label: c.label,
          brand: c.brand || 'other',
          last4: c.last4 || '',
          number: data.number || '',
          cvv: data.cvv || '',
          cardholderName: data.cardholderName || '',
          expMonth: data.expMonth || null,
          expYear: data.expYear || null,
          pin: data.pin || '',
        });
      } catch {
        // One undecryptable card shouldn't cost the user the others.
        undecryptable += 1;
      }
    }
    // Some opened, some didn't: partial success, and the list shows what it
    // has. NONE opened out of a non-empty set means the key is wrong for
    // these blobs, which is a different problem from having no cards.
    if (items.length > 0 && cards.size === 0) cardsError = 'decrypt';
    else if (undecryptable > 0) cardsError = 'partial:' + undecryptable;
    cardsLoadedAt = Date.now();
  } catch (err) {
    // Offline or a dead session — api() has already handled the latter.
    // cardsLoadedAt stays 0 so the next request retries rather than
    // serving an empty list as though it were the truth.
    cardsError = err && err.status ? 'http:' + err.status : 'network';
    console.warn('[Vaultly] could not load cards:', cardsError, err);
  }
}

/** Pull again if the cached set is older than the TTL (or never loaded). */
async function ensureFreshCards() {
  if (!isUnlocked()) return;
  if (Date.now() - cardsLoadedAt > CARDS_TTL_MS) await loadCards();
}

/**
 * What the PAGE is allowed to see: enough to recognise a card in a list and
 * nothing that could be used to charge it. No number, no CVV, no PIN. The real
 * values are handed over one card at a time, only on an explicit click.
 */
function cardSummaries() {
  if (!isUnlocked()) return [];
  return [...cards.values()]
    .map((c) => ({
      id: c.id,
      label: c.label,
      brand: c.brand,
      brandName: brandShort(c.brand),
      last4: c.last4,
      masked: maskedNumber(c.last4, c.brand, c.number.length || undefined),
      expiry: formatExpiry(c.expMonth, c.expYear),
      expired: isExpired(c.expMonth, c.expYear),
      cardholderName: c.cardholderName,
    }))
    // Expired cards sink to the bottom rather than vanish — you may still want
    // the number for a refund or a dispute.
    .sort((a, b) => a.expired - b.expired || a.label.localeCompare(b.label));
}

/**
 * Lock, not sign out. The master key and every decrypted secret are dropped;
 * the stored identity and refresh token are deliberately left alone so the
 * popup reopens on the PIN screen rather than the full email + password form.
 * Signing out is a separate, explicit act — see the SIGN_OUT message.
 */
/**
 * `keepStoredPin` separates the two things that both arrive here as "lock".
 *
 * A deliberate lock — the Lock button, an idle timeout, a screen lock, a
 * sign-out, a refresh token the server rejected — means "ask me again", so the
 * stored PIN goes with the key whatever mode is set. The user can always have
 * it back by typing it once; the mode then stores it again.
 *
 * A browser startup is not that. Nothing was unlocked, nobody asked for
 * anything, and under the 'never' mode the stored PIN surviving a restart is
 * the entire point of the mode. Forgetting it here was a real bug: it made
 * 'never' behave exactly like 'session' from the second launch onwards.
 */
/**
 * Why the vault is locked, kept across worker restarts so the PIN screen can
 * say it. "Why is it asking me AGAIN?" is the single most common thing to
 * wonder at this screen, and the honest answers are all different: the browser
 * restarted, the extension updated, you locked it, it idled out. Without this
 * they are indistinguishable, and every one of them reads as a bug.
 */
const LOCK_REASON_KEY = 'vaultly_lock_reason';
function recordLockReason(reason) {
  chrome.storage.local.set({ [LOCK_REASON_KEY]: reason || 'locked' }).catch(() => {});
}

function lock({ keepStoredPin = false, reason = 'locked' } = {}) {
  recordLockReason(reason);
  masterKey = null;
  masterPin = null;
  if (!keepStoredPin) forgetPin().catch(() => {});
  resuming = null;
  userMeta = null;
  vault = new Map();
  cards = new Map();
  cardsLoadedAt = 0;
  cardsError = null;
  // A card awaiting a save prompt is plaintext like any other, so locking
  // has to drop it too.
  pendingCard = null;
  chrome.action.setBadgeText({ text: '' });
}

// Wire the (previously unused) auto-lock module. Timeout is read from
// chrome.storage.local, set by the Settings screen. Default 0 = "until browser
// closes" (matches the chosen session-unlock behavior); a positive value adds
// an idle lock on top. The worker dying already locks us; this adds a timed
// lock for long-lived workers and locks on OS screen-lock.
// A remembered PIN is the single most sensitive thing this extension ever
// stores. Pin session storage to trusted contexts before anything can write to
// it, rather than relying on that being the default.
hardenSessionStorage();

initAutoLock({
  onLock: (reason) => {
    // A startup "lock" is just this worker starting clean. It must not throw
    // away a PIN the user asked us to keep across restarts.
    lock({ keepStoredPin: reason === 'startup', reason });
    if (reason === 'idle') notify('Vault locked', 'Locked after inactivity.');
    else if (reason === 'screen-lock') notify('Vault locked', 'Locked when the screen locked.');
  },
  getTimeoutMinutes: async () => {
    const { autoLockMins } = await chrome.storage.local.get('autoLockMins');
    return autoLockMins ?? 0;
  },
});

// ---------------------------------------------------------------------------
// Domain-scoped lookups (Feature 5 matching, powered by domainUtils)
// ---------------------------------------------------------------------------
function matchesForUrl(url) {
  if (!isUnlocked() || !url) return [];
  return [...vault.values()].filter((v) => isSameSite(v.websiteUrl, url));
}

// ---------------------------------------------------------------------------
// Save / update (Features 3 & 4). Encryption happens HERE, in the worker.
// ---------------------------------------------------------------------------
async function saveCredential({ url, websiteName, username, password, totp = '' }) {
  if (!isUnlocked()) throw new Error('Vault is locked');
  const { ciphertext, iv } = await encryptPassword(password, masterKey, '', totp);
  const root = getRootDomain(url);
  const { item } = await api('/vault', {
    method: 'POST',
    body: JSON.stringify({
      websiteName: websiteName || root,
      websiteUrl: root,      // Feature 5: store only the root domain
      username,
      encryptedDataBlob: ciphertext,
      iv,
    }),
  });
  vault.set(item._id, {
    id: item._id, websiteName: item.websiteName, websiteUrl: item.websiteUrl,
    username, password, totp, notes: '',
  });
  await refreshBadgeForActiveTab();
  notify('Password saved', root + ' \u00b7 ' + username);
  return { id: item._id };
}

/**
 * Re-encrypting an item rewrites the WHOLE blob, so everything in it has to be
 * written back — not just the field that changed. The notes and the two-factor
 * secret are carried over from the copy this worker already holds; forgetting
 * them here would mean that accepting a routine "password changed, update it?"
 * prompt silently destroyed the user's second factor, with nothing on screen
 * to say so. `totp` may be passed explicitly to set or clear it.
 */
async function updateCredential({ id, password, totp }) {
  if (!isUnlocked()) throw new Error('Vault is locked');
  const existing = vault.get(id) || {};
  const nextPassword = password != null ? password : existing.password;
  const nextTotp = totp !== undefined ? totp : (existing.totp || '');
  const { ciphertext, iv } = await encryptPassword(
    nextPassword, masterKey, existing.notes || '', nextTotp
  );
  const { item } = await api('/vault/' + id, {
    method: 'PUT',
    body: JSON.stringify({ encryptedDataBlob: ciphertext, iv }),
  });
  vault.set(id, { ...existing, id, password: nextPassword, totp: nextTotp });
  if (password != null) notify('Password updated', item.websiteUrl || '');
  return { id };
}

/**
 * The current code for a saved login, or null when it has no secret. Minted
 * here, where the secret already is; callers get six digits and the seconds
 * they have left, never the secret itself.
 */
async function totpCodeFor(id) {
  const v = vault.get(id);
  if (!v || !v.totp) return null;
  try {
    return await generateTotp(v.totp);
  } catch {
    // A secret that will not parse is a broken item, not a broken vault.
    return null;
  }
}

/**
 * Given a submitted credential, decide what prompt (if any) the content
 * script should show: 'none' (already saved, unchanged), 'save' (new), or
 * 'update' (same site+username, different password).
 */
/**
 * Should we offer to save the card just submitted? Deliberately takes only the
 * BRAND and LAST FOUR, not the number: that is all a duplicate check needs, and
 * it means the page tells us nothing chargeable until the user has actually said
 * yes. Unlike a password there is no 'update' verdict — a card number does not
 * change, so a card we already hold is simply not worth asking about.
 */
function classifyCardSubmission({ url, brand, last4 }) {
  if (!isUnlocked()) return { action: 'none', reason: 'locked' };
  const root = getRootDomain(url);
  if (root && cardPromptSuppressed.has(root)) return { action: 'none', reason: 'suppressed' };
  const known = [...cards.values()].some(
    (c) => c.last4 === last4 && (c.brand || 'other') === (brand || 'other')
  );
  return known ? { action: 'none', reason: 'exists' } : { action: 'save' };
}

/**
 * Encrypt and store the card the user accepted. Same envelope as the web app's
 * AddCardModal — one AES-GCM blob over every secret field — so a card saved from
 * a checkout is indistinguishable from one typed into the vault.
 */
async function saveCard(card) {
  if (!isUnlocked()) throw new Error('Vault is locked');

  const digits = digitsOnly(card.number);
  const brand = detectBrand(digits).id;
  const last4 = digits.slice(-4);

  const { ciphertext, iv } = await encryptJson(
    {
      number: digits,
      cvv: card.cvv || '',
      cardholderName: card.cardholderName || '',
      expMonth: card.expMonth || null,
      expYear: card.expYear || null,
      // Neither is available from a checkout page; the fields exist so the blob
      // has the same shape the web app writes and reads.
      pin: '',
      notes: '',
    },
    masterKey
  );

  const { item } = await api('/cards', {
    method: 'POST',
    body: JSON.stringify({
      label: `${brandLabel(brand)} ${last4}`,
      brand,
      last4,
      encryptedDataBlob: ciphertext,
      iv,
    }),
  });

  cards.set(item._id, {
    id: item._id,
    label: item.label,
    brand,
    last4,
    number: digits,
    cvv: card.cvv || '',
    cardholderName: card.cardholderName || '',
    expMonth: card.expMonth || null,
    expYear: card.expYear || null,
    pin: '',
  });

  notify('Card saved', `${brandLabel(brand)} \u2022\u2022\u2022\u2022 ${last4}`);
  return { id: item._id, label: item.label };
}

function classifySubmission({ url, username, password }) {
  if (!isUnlocked()) return { action: 'none', reason: 'locked' };
  const sameSite = matchesForUrl(url);
  const sameUser = sameSite.find((v) => v.username.toLowerCase() === (username || '').toLowerCase());
  if (!sameUser) return { action: 'save' };
  if (sameUser.password !== password) return { action: 'update', id: sameUser.id };
  return { action: 'none', reason: 'exists' }; // Feature 3: don't ask if unchanged
}

// ---------------------------------------------------------------------------
// Badge (Feature 6): count of saved logins for the active tab's site
// ---------------------------------------------------------------------------
async function refreshBadgeForActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  updateBadgeForTab(tab);
}

function updateBadgeForTab(tab) {
  if (!tab || !tab.url) return;
  const count = matchesForUrl(tab.url).length;
  chrome.action.setBadgeText({ tabId: tab.id, text: count ? String(count) : '' });
  chrome.action.setBadgeBackgroundColor({ color: '#4f46e5' });
}

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  updateBadgeForTab(tab);
});
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') updateBadgeForTab(tab);
});

// ---------------------------------------------------------------------------
// Browser notifications (Feature 20)
// ---------------------------------------------------------------------------
function notify(title, message) {
  try {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Vaultly \u2014 ' + title,
      message: message || '',
    });
  } catch {
    /* notifications permission may be absent; non-fatal */
  }
}

// ---------------------------------------------------------------------------
// Context menu (Feature 7)
// ---------------------------------------------------------------------------
chrome.runtime.onInstalled.addListener((details) => {
  // chrome.storage.session is cleared on reload/update, so a PIN remembered
  // for the browser session is gone and the user is about to be asked again.
  if (details && (details.reason === 'update' || details.reason === 'install')) {
    recordLockReason(details.reason === 'install' ? 'installed' : 'updated');
  }
  console.log('Vaultly extension installed.');
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'vaultly_autofill', title: 'Vaultly: Autofill', contexts: ['editable'] });
    chrome.contextMenus.create({ id: 'vaultly_generate', title: 'Vaultly: Generate password', contexts: ['editable'] });
    chrome.contextMenus.create({ id: 'vaultly_open', title: 'Vaultly: Open vault', contexts: ['all'] });
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'vaultly_open') {
    if (chrome.action.openPopup) chrome.action.openPopup();
    return;
  }
  if (!tab || !tab.id) return;
  if (info.menuItemId === 'vaultly_autofill') chrome.tabs.sendMessage(tab.id, { type: 'SHOW_AUTOFILL_MENU' });
  if (info.menuItemId === 'vaultly_generate') chrome.tabs.sendMessage(tab.id, { type: 'GENERATE_INTO_FIELD' });
});

// Keyboard command (Feature 23): Ctrl+Shift+V -> quick autofill menu on page.
if (chrome.commands) {
  chrome.commands.onCommand.addListener((command, tab) => {
    if (command === 'quick_autofill' && tab && tab.id) {
      chrome.tabs.sendMessage(tab.id, { type: 'SHOW_AUTOFILL_MENU' });
    }
  });
}

// ---------------------------------------------------------------------------
// Message router (popup <-> worker <-> content script)
// ---------------------------------------------------------------------------
/**
 * Messages that are meaningless against a locked vault. Each one gets a chance
 * to resume first, so a worker that Chrome recycled thirty seconds ago answers
 * them exactly as the worker that unlocked would have — provided the user asked
 * for that with "Stay signed in". Without the setting, ensureUnlocked() finds
 * no stored PIN, returns false immediately, and every handler below behaves as
 * it always did.
 */
const NEEDS_UNLOCKED_VAULT = new Set([
  'IS_UNLOCKED',
  'GET_TOTP',
  'SET_TOTP',
  'NOTE_ACTIVITY',
  'GET_VAULT',
  'GET_MATCHES',
  'GET_CREDENTIAL',
  'GET_CARDS',
  'GET_CARD_MATCHES',
  'GET_CARD',
  'CLASSIFY_SUBMISSION',
  'SAVE_CREDENTIAL',
  'UPDATE_CREDENTIAL',
  'CLASSIFY_CARD_SUBMISSION',
  'OFFER_SAVE_CARD',
]);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (NEEDS_UNLOCKED_VAULT.has(message.type)) await ensureUnlocked();
      switch (message.type) {
        case 'GET_ACTIVE_TAB': {
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          sendResponse({ url: tab ? tab.url : null, tabId: tab ? tab.id : null });
          break;
        }
        case 'FILL_CREDENTIALS_ON_TAB':
          // Legacy relay: popup's "Fill" button forwards already-decrypted
          // plaintext to the content script over the internal channel.
          chrome.tabs.sendMessage(message.payload.tabId, {
            type: 'AUTOFILL',
            username: message.payload.username,
            password: message.payload.password,
          });
          sendResponse({ ok: true });
          break;
        case 'UNLOCK':
          await unlock(message.payload);
          sendResponse({ ok: true });
          break;
        case 'LOCK':
          // Drops the key only. The session survives, so reopening asks for the
          // PIN and nothing else.
          lock({ reason: 'manual' });
          cancelAutoLock();
          notify('Vault locked', '');
          sendResponse({ ok: true });
          break;
        case 'SIGN_OUT':
          // The popup revokes the refresh token server-side; here we just make
          // sure nothing decrypted outlives it.
          lock({ reason: 'signed-out' });
          cancelAutoLock();
          sendResponse({ ok: true });
          break;
        case 'IS_UNLOCKED':
          sendResponse({ unlocked: isUnlocked() });
          break;
        case 'GET_PIN_MODE':
          sendResponse({ mode: await getPinMode() });
          break;
        case 'SET_PIN_MODE': {
          // Choosing a remembering mode while unlocked must take effect NOW,
          // not at the next unlock: the user changed it precisely so that THIS
          // session stops asking. Switching back to 'always' drops the stored
          // PIN inside setPinMode() but leaves the vault open — it changes what
          // outlives the worker, not whether you are signed in right now.
          const mode = await setPinMode(message.mode);
          let armed = false;
          if (isUnlocked() && masterPin) armed = await rememberPin(masterPin);
          sendResponse({ ok: true, mode, armed });
          break;
        }
        case 'NOTE_ACTIVITY':
          // Settings changed the timeout, or the popup wants to refresh the
          // idle countdown. Only meaningful while unlocked.
          if (isUnlocked()) noteActivity();
          sendResponse({ ok: true });
          break;
        case 'GET_VAULT': {
          // Lets the popup resume an already-unlocked session WITHOUT re-asking
          // for the master PIN. The worker still holds the decrypted vault in
          // memory for this browser session; we hand back the full list (incl.
          // plaintext) over the internal extension channel only — never HTTP,
          // never to a page. If locked, the popup falls back to the unlock view.
          if (!isUnlocked()) {
            const { [LOCK_REASON_KEY]: lockReason } = await chrome.storage.local.get(LOCK_REASON_KEY);
            sendResponse({ unlocked: false, lockReason: lockReason || null });
          } else {
            noteActivity(); // opening the popup counts as activity
            sendResponse({
              unlocked: true,
              user: userMeta,
              items: [...vault.values()],
            });
          }
          break;
        }
        case 'CACHE_ITEM': {
          // Popup saved/edited an item and already has the plaintext; mirror it
          // into the worker's unlocked cache so autofill sees it immediately.
          // Whatever the popup sends wins, so it sends `totp` too: a mirror
          // that dropped it would make the code vanish until the next unlock.
          if (isUnlocked() && message.item && message.item.id) {
            vault.set(message.item.id, { ...message.item });
            await refreshBadgeForActiveTab();
          }
          sendResponse({ ok: true });
          break;
        }

        // --- content-script driven ---
        case 'GET_MATCHES': {
          // Return usernames/labels only \u2014 NEVER passwords \u2014 for the suggestion UI.
          // `hasTotp` is a yes/no, which is all the dropdown needs to decide
          // whether to offer a code; the code itself is asked for separately,
          // at the moment one is actually going to be filled.
          const url = message.url || (sender.tab && sender.tab.url);
          const list = matchesForUrl(url).map((v) => ({
            id: v.id, username: v.username, websiteName: v.websiteName, hasTotp: !!v.totp,
          }));
          sendResponse({ unlocked: isUnlocked(), matches: list });
          break;
        }
        case 'GET_CREDENTIAL': {
          // Hand over the ONE credential the user explicitly selected to fill.
          const v = vault.get(message.id);
          const tabUrl = (sender.tab && sender.tab.url) || '';
          if (!v || !isSameSite(v.websiteUrl, tabUrl)) sendResponse({ ok: false });
          else {
            // Six digits that die within the minute, never the secret that
            // mints them. The two-factor field is usually on the NEXT page, so
            // the content script keeps the id and asks again when it gets
            // there rather than holding a code that will have expired.
            const totp = await totpCodeFor(message.id);
            sendResponse({
              ok: true, username: v.username, password: v.password,
              hasTotp: !!v.totp, totp,
            });
          }
          break;
        }
        case 'GET_TOTP': {
          // The live code: for a countdown in the popup, or for a two-factor
          // field that appeared after the password page. Scoped to the asking
          // tab's site for page callers, exactly like GET_CREDENTIAL; the popup
          // has no sender.tab and is trusted as an extension context.
          const v = vault.get(message.id);
          const tabUrl2 = (sender.tab && sender.tab.url) || '';
          if (!v || (sender.tab && !isSameSite(v.websiteUrl, tabUrl2))) {
            sendResponse({ ok: false });
          } else {
            const totp = await totpCodeFor(message.id);
            sendResponse(totp ? { ok: true, ...totp } : { ok: false, reason: 'no-totp' });
          }
          break;
        }
        case 'SET_TOTP': {
          // Attach, replace or clear a login's two-factor secret. It is
          // validated before it is written: storing a secret that cannot
          // produce a code only moves the failure to the moment you need it.
          try {
            const secret = (message.secret || '').trim();
            if (secret && !parseTotp(secret)) {
              sendResponse({ ok: false, error: 'That is not a valid two-factor secret or otpauth:// link.' });
              break;
            }
            await updateCredential({ id: message.id, totp: secret });
            sendResponse({ ok: true, hasTotp: !!secret });
          } catch (err) {
            sendResponse({ ok: false, error: err.message });
          }
          break;
        }

        // --- cards ---
        case 'GET_CARDS': {
          await ensureFreshCards();
          // Popup listing. Summaries only, even here: the popup renders masked
          // plates and asks for a single card's real values on click, so the
          // full set never sits in a second context waiting to be scraped.
          if (!isUnlocked()) sendResponse({ unlocked: false, cards: [], cardsApi: true });
          else {
            noteActivity();
            // cardsApi is a handshake: a worker built before cards existed
            // answers the default branch instead, and the popup can tell the
            // difference between "no cards" and "this worker is stale".
            sendResponse({ unlocked: true, cards: cardSummaries(), error: cardsError, cardsApi: true });
          }
          break;
        }
        case 'REFRESH_CARDS': {
          // The popup changed the card set server-side; re-pull so autofill and
          // the next popup open agree with the vault.
          await loadCards();
          sendResponse({ ok: true, cards: cardSummaries(), error: cardsError, cardsApi: true });
          break;
        }
        case 'CACHE_CARD': {
          // Popup saved/edited a card and already holds the plaintext. Mirror it
          // in so a checkout in the next tab sees it without a round trip.
          if (isUnlocked() && message.card && message.card.id) {
            cards.set(message.card.id, { ...message.card });
          }
          sendResponse({ ok: true });
          break;
        }
        case 'DROP_CARD': {
          if (message.id) cards.delete(message.id);
          sendResponse({ ok: true });
          break;
        }
        case 'FILL_CARD_ON_TAB': {
          // The popup's per-card Fill button. The card goes worker -> content
          // script directly: the popup asks by id and never sees the number,
          // which is one fewer context that has ever held it.
          const { tabId, id } = message.payload || {};
          const c = isUnlocked() ? cards.get(id) : null;
          if (!c || !tabId) {
            sendResponse({ ok: false });
            break;
          }
          const tab = await chrome.tabs.get(tabId).catch(() => null);
          if (!tab || !/^https:/i.test(tab.url || '')) {
            sendResponse({ ok: false, error: 'insecure-page' });
            break;
          }
          // Sent to every frame: on a real checkout the fields are usually in a
          // payment iframe, not the top document. Frames without card fields
          // answer ok:false and are ignored.
          const reply = await chrome.tabs
            .sendMessage(tabId, {
              type: 'AUTOFILL_CARD',
              card: {
                id: c.id, label: c.label, brand: c.brand, number: c.number, cvv: c.cvv,
                cardholderName: c.cardholderName, expMonth: c.expMonth, expYear: c.expYear,
              },
            })
            .catch(() => null);
          noteActivity();
          sendResponse({ ok: !!(reply && reply.ok) });
          break;
        }
        case 'GET_CARD_MATCHES': {
          await ensureFreshCards();
          // Every card is offered at a checkout: unlike a login, a card is not
          // bound to one site. Labels, brand and last4 only.
          sendResponse({ unlocked: isUnlocked(), matches: cardSummaries() });
          break;
        }
        case 'GET_CARD': {
          // The one card the user explicitly clicked, with the values a payment
          // form actually needs. The PIN is never included — no online
          // checkout asks for an ATM PIN, so a page has no legitimate use for
          // it and handing it over would only widen the blast radius.
          const c = isUnlocked() ? cards.get(message.id) : null;
          if (!c) {
            sendResponse({ ok: false });
            break;
          }
          // Refuse to put card details into a page served over plain HTTP.
          // A card number typed into an http:// checkout is compromised the
          // moment it is submitted; filling it for the user would just make
          // that faster. Popup-initiated requests have no sender.tab.
          const pageUrl = sender.tab ? sender.url || sender.tab.url || '' : '';
          if (pageUrl && !/^https:/i.test(pageUrl)) {
            sendResponse({ ok: false, error: 'insecure-page' });
            break;
          }
          noteActivity();
          sendResponse({
            ok: true,
            card: {
              id: c.id,
              label: c.label,
              brand: c.brand,
              number: c.number,
              cvv: c.cvv,
              cardholderName: c.cardholderName,
              expMonth: c.expMonth,
              expYear: c.expYear,
            },
          });
          break;
        }

        // --- save-card prompt (checkout -> vault) ---
        case 'CLASSIFY_CARD_SUBMISSION': {
          // Brand + last4 only. See classifyCardSubmission().
          sendResponse(
            classifyCardSubmission({
              url: (sender.tab && sender.tab.url) || '',
              ...message.payload,
            })
          );
          break;
        }
        case 'OFFER_SAVE_CARD': {
          // The frame that could READ the card is often a payment iframe a few
          // hundred pixels wide, so the prompt is rendered by the tab's TOP
          // frame instead. The card itself stops here rather than travelling to
          // that frame: frame 0 receives only brand, last4 and expiry.
          const tab = sender.tab;
          if (!isUnlocked() || !tab) {
            sendResponse({ ok: false });
            break;
          }
          if (!/^https:/i.test(sender.url || tab.url || '')) {
            sendResponse({ ok: false, error: 'insecure-page' });
            break;
          }
          pendingCard = {
            tabId: tab.id,
            card: message.payload.card,
            display: message.payload.display,
            at: Date.now(),
          };
          chrome.tabs
            .sendMessage(tab.id, { type: 'PROMPT_SAVE_CARD', display: message.payload.display }, { frameId: 0 })
            .catch(() => {
              // No content script in the top frame (a PDF viewer, say). Drop the
              // card rather than leave it stashed for a prompt nobody will see.
              pendingCard = null;
            });
          sendResponse({ ok: true });
          break;
        }
        case 'RESOLVE_SAVE_CARD': {
          const tab = sender.tab;
          const p = pendingCard;
          pendingCard = null; // one answer per offer, whatever the answer is

          if (message.never) {
            const root = getRootDomain((tab && tab.url) || '');
            if (root) cardPromptSuppressed.add(root);
          }
          if (!message.accept || !p || (tab && p.tabId !== tab.id)) {
            sendResponse({ ok: true, saved: false });
            break;
          }
          if (Date.now() - p.at > PENDING_CARD_TTL_MS) {
            sendResponse({ ok: false, error: 'expired' });
            break;
          }
          try {
            const saved = await saveCard(p.card);
            sendResponse({ ok: true, saved: true, label: saved.label });
          } catch (err) {
            sendResponse({ ok: false, error: err.message });
          }
          break;
        }

        case 'CLASSIFY_SUBMISSION':
          sendResponse(classifySubmission({ url: sender.tab && sender.tab.url, ...message.payload }));
          break;
        case 'SAVE_CREDENTIAL':
          sendResponse(await saveCredential({ url: sender.tab && sender.tab.url, ...message.payload }));
          break;
        case 'UPDATE_CREDENTIAL':
          sendResponse(await updateCredential(message.payload));
          break;

        default:
          sendResponse({ error: 'unknown message type' });
      }
    } catch (err) {
      sendResponse({ error: err.message });
    }
  })();
  return true; // keep the channel open for the async work above
});
