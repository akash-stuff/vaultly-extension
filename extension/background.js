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

import { deriveMasterKey, encryptPassword, decryptPassword, decryptJson } from './shared/crypto.js';
import { getRootDomain, isSameSite } from './shared/domainUtils.js';
import { initAutoLock, noteActivity, cancelAutoLock } from './shared/autoLock.js';
import { apiFetch, saveSession, clearSession } from './shared/session.js';
import { maskedNumber, formatExpiry, isExpired, brandShort } from './shared/cards.js';

// ---- In-memory unlocked-session state (dies with the worker = auto-lock) ----
let masterKey = null;            // non-extractable CryptoKey, memory only
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
      lock();
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
      const { password } = await decryptPassword(item.encryptedDataBlob, item.iv, masterKey);
      vault.set(item._id, {
        id: item._id,
        websiteName: item.websiteName,
        websiteUrl: item.websiteUrl,
        username: item.username,
        password,
      });
    } catch {
      // A single corrupt item shouldn't blow up the whole unlock.
    }
  }
  await loadCards();
  await refreshBadgeForActiveTab();
  noteActivity(); // start/refresh the idle-lock countdown for this session
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
function lock() {
  masterKey = null;
  userMeta = null;
  vault = new Map();
  cards = new Map();
  cardsLoadedAt = 0;
  cardsError = null;
  chrome.action.setBadgeText({ text: '' });
}

// Wire the (previously unused) auto-lock module. Timeout is read from
// chrome.storage.local, set by the Settings screen. Default 0 = "until browser
// closes" (matches the chosen session-unlock behavior); a positive value adds
// an idle lock on top. The worker dying already locks us; this adds a timed
// lock for long-lived workers and locks on OS screen-lock.
initAutoLock({
  onLock: () => {
    lock();
    notify('Vault locked', 'Locked after inactivity.');
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
async function saveCredential({ url, websiteName, username, password }) {
  if (!isUnlocked()) throw new Error('Vault is locked');
  const { ciphertext, iv } = await encryptPassword(password, masterKey);
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
  vault.set(item._id, { id: item._id, websiteName: item.websiteName, websiteUrl: item.websiteUrl, username, password });
  await refreshBadgeForActiveTab();
  notify('Password saved', root + ' \u00b7 ' + username);
  return { id: item._id };
}

async function updateCredential({ id, password }) {
  if (!isUnlocked()) throw new Error('Vault is locked');
  const { ciphertext, iv } = await encryptPassword(password, masterKey);
  const { item } = await api('/vault/' + id, {
    method: 'PUT',
    body: JSON.stringify({ encryptedDataBlob: ciphertext, iv }),
  });
  const existing = vault.get(id) || {};
  vault.set(id, { ...existing, id, password });
  notify('Password updated', item.websiteUrl || '');
  return { id };
}

/**
 * Given a submitted credential, decide what prompt (if any) the content
 * script should show: 'none' (already saved, unchanged), 'save' (new), or
 * 'update' (same site+username, different password).
 */
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
chrome.runtime.onInstalled.addListener(() => {
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
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
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
          lock();
          cancelAutoLock();
          notify('Vault locked', '');
          sendResponse({ ok: true });
          break;
        case 'SIGN_OUT':
          // The popup revokes the refresh token server-side; here we just make
          // sure nothing decrypted outlives it.
          lock();
          cancelAutoLock();
          sendResponse({ ok: true });
          break;
        case 'IS_UNLOCKED':
          sendResponse({ unlocked: isUnlocked() });
          break;
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
            sendResponse({ unlocked: false });
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
          const url = message.url || (sender.tab && sender.tab.url);
          const list = matchesForUrl(url).map((v) => ({ id: v.id, username: v.username, websiteName: v.websiteName }));
          sendResponse({ unlocked: isUnlocked(), matches: list });
          break;
        }
        case 'GET_CREDENTIAL': {
          // Hand over the ONE credential the user explicitly selected to fill.
          const v = vault.get(message.id);
          const tabUrl = (sender.tab && sender.tab.url) || '';
          if (!v || !isSameSite(v.websiteUrl, tabUrl)) sendResponse({ ok: false });
          else sendResponse({ ok: true, username: v.username, password: v.password });
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
