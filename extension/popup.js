import { WEB_APP_URL } from './config.js';
import {
  apiFetch,
  saveSession,
  clearSession,
  revokeSession,
  getStoredIdentity,
} from './shared/session.js';
import { deriveMasterKey, encryptPassword, decryptPassword } from './shared/crypto.js';
import { generatePassword, estimateStrength } from './shared/passwordUtils.js';
import { searchItems } from './shared/search.js';
import { scanVault, scanBreaches } from './shared/vaultHealth.js';
import { BRAND_COLORS, brandShort, expiresSoon } from './shared/cards.js';
import { getPinMode, setPinMode as persistPinMode } from './shared/stayUnlocked.js';
import { generateTotp, parseTotp, totpFromBlob, prettyCode } from './shared/totp.js';

/**
 * Popup state (memory-only). When the background worker already holds an
 * unlocked session, we RESUME from it via GET_VAULT — no PIN re-prompt. The
 * worker hands back the decrypted vault over the internal channel, so the
 * popup never needs the master key just to browse/copy/fill. We only derive a
 * key in this context when the user is actively unlocking or adding an item.
 */
let masterKey = null;      // derived only during an explicit unlock/add
let userMeta = null;       // identity only; tokens live in shared/session.js
let vaultItems = [];       // full objects incl. decrypted password when resumed
let activeTabUrl = null;
let activeTabId = null;
let favorites = new Set(); // ids, persisted in chrome.storage.local
let query = '';
// Card SUMMARIES only (masked number, brand, expiry). The popup deliberately
// never holds a full card: number, CVV and cardholder name are fetched from the
// worker one card at a time, on the click that needs them, and the fill path
// does not route them through here at all.
let cardSummaries = [];
let cardsError = null;   // why the list is empty, when it is
let activePane = 'loginsPane';

const $ = (id) => document.getElementById(id);

function showView(id) {
  ['loginView', 'unlockView', 'vaultView', 'settingsView'].forEach((v) =>
    $(v).classList.toggle('hidden', v !== id)
  );
  const inVault = id === 'vaultView' || id === 'settingsView';
  $('settingsBtn').classList.toggle('hidden', id !== 'vaultView');
  // Also offered on the unlock screen: without it a user whose token has gone
  // stale has no way back to the login form.
  $('lockBtn').classList.toggle('hidden', !inVault && id !== 'unlockView');
  $('lockBtn').title = inVault ? 'Lock vault' : 'Sign out';
  $('lockBtn').setAttribute('aria-label', $('lockBtn').title);
}

/**
 * The refresh token was rejected — this is the only case that is genuinely a
 * dead session now, since an expired access token is renewed silently inside
 * shared/session.js. Drop everything and ask for a full sign-in.
 */
async function handleUnauthorized(message = 'Your session expired. Sign in again.') {
  userMeta = null; masterKey = null; vaultItems = [];
  await clearSession();
  chrome.runtime.sendMessage({ type: 'SIGN_OUT' }).catch(() => {});
  $('unlockError').classList.add('hidden');
  $('loginError').textContent = message;
  $('loginError').classList.remove('hidden');
  showView('loginView');
}

function extractDomain(url) {
  try { return new URL(url.startsWith('http') ? url : `https://${url}`).hostname.replace(/^www\./, ''); }
  catch { return ''; }
}
function favicon(item) {
  return `https://www.google.com/s2/favicons?domain=${encodeURIComponent(extractDomain(item.websiteUrl) || item.websiteName)}&sz=64`;
}

/* ---------------- toast ---------------- */
let toastTimer = null;
function toast(msg) {
  const host = $('toastHost');
  host.innerHTML = `<div class="toast"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>${msg}</div>`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (host.innerHTML = ''), 1800);
}

/* ---------------- reveal toggles ---------------- */
document.querySelectorAll('.reveal-btn').forEach((btn) => {
  btn.innerHTML = eyeSvg(false);
  btn.addEventListener('click', () => {
    const input = $(btn.dataset.reveal);
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.innerHTML = eyeSvg(show);
  });
});
function eyeSvg(open) {
  return open
    ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 10 8 10 8a13.16 13.16 0 0 1-1.67 2.68M6.61 6.61A13.5 13.5 0 0 0 2 12s3 8 10 8a9.12 9.12 0 0 0 5.39-1.61M14.12 14.12A3 3 0 1 1 9.88 9.88"/><path d="M1 1l22 22"/></svg>'
    : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-8 10-8 10 8 10 8-3 8-10 8-10-8-10-8Z"/><circle cx="12" cy="12" r="3"/></svg>';
}

/* ---------------- init: resume unlocked session if possible ---------------- */
async function init() {
  const tabInfo = await chrome.runtime.sendMessage({ type: 'GET_ACTIVE_TAB' });
  activeTabUrl = (tabInfo && tabInfo.url) || '';
  activeTabId = (tabInfo && tabInfo.tabId) || null;

  const favData = await chrome.storage.local.get('favorites');
  favorites = new Set(favData.favorites || []);

  // Both auth screens carry the "Stay signed in" checkbox; show the setting as
  // it actually stands rather than defaulting them to unchecked, which would
  // read as "off" to someone who turned it on last week.
  await syncPinModeUI();

  // Try to resume an already-unlocked session from the worker — this is the
  // "don't re-ask for the PIN every time" behavior.
  let resumed = false;
  let lockReason = null;
  try {
    const res = await chrome.runtime.sendMessage({ type: 'GET_VAULT' });
    if (res && !res.unlocked) lockReason = res.lockReason || null;
    if (res && res.unlocked) {
      userMeta = res.user;
      vaultItems = res.items.map((v) => ({
        _id: v.id, websiteName: v.websiteName, websiteUrl: v.websiteUrl,
        username: v.username, password: v.password, totp: v.totp || '',
        updatedAt: v.updatedAt,
      }));
      renderVault();
      showView('vaultView');
      resumed = true;
    }
  } catch { /* worker asleep or unreachable; fall through */ }
  if (resumed) return;

  // The worker is asleep or locked. A stored refresh token means the session is
  // still ours even if the 15-minute access token died days ago, so the only
  // thing missing is the PIN. This is what stops the extension demanding a full
  // email + password sign-in every time it is left alone for a quarter of an
  // hour. Identity lives in chrome.storage.local, so it survives a browser
  // restart too — it holds no key and can decrypt nothing.
  const { user, refreshToken } = await getStoredIdentity();
  if (user && refreshToken) {
    userMeta = user;
    $('unlockEmail').textContent = userMeta.email;
    showLockReason(lockReason);
    showView('unlockView');
  } else {
    showView('loginView');
  }
}

/**
 * Why the PIN is being asked for. The worker records the reason when it locks;
 * saying it out loud is what separates "this is working as you set it up" from
 * "this thing keeps forgetting me".
 */
const LOCK_REASONS = {
  manual: 'You locked Vaultly.',
  idle: 'Locked after inactivity. You can change this under Auto-lock.',
  'screen-lock': 'Locked when your screen locked.',
  'session-expired': 'Your sign-in expired, so the vault was locked.',
  'signed-out': 'You signed out.',
  updated: 'Vaultly was updated, which clears a PIN kept for this browser session.',
  installed: 'First unlock on this device.',
  startup: 'The browser was restarted.',
};

function showLockReason(reason) {
  const el = $('unlockReason');
  if (!el) return;
  const text = LOCK_REASONS[reason];
  el.textContent = text || '';
  el.classList.toggle('hidden', !text);
}

/* ---------------- master PIN mode ---------------- */
/**
 * 'always' | 'session' | 'never' — how long one unlock should last. See
 * shared/stayUnlocked.js for what each mode does with the PIN.
 *
 * The BACKGROUND worker owns the change, because only it holds the PIN of the
 * session already open and so only it can make a new mode take effect now
 * rather than at the next unlock. The popup just asks.
 */
let pinMode = 'always';

const PIN_MODE_HINT = {
  always: 'Vaultly asks for your master PIN again whenever Chrome puts the extension to sleep, which can be every few minutes. The PIN is never stored anywhere.',
  session: 'Your PIN is kept in memory until the browser closes, so autofill keeps working and the popup stops asking. It is never written to disk. Locking, signing out, an auto-lock, or updating Vaultly all forget it.',
  never: 'The PIN is saved on this computer, so Vaultly opens without asking — even after a restart. Anyone who can use this browser profile can open your vault. Lock or sign out to be asked again.',
};

async function setPinMode(mode) {
  try {
    const res = await chrome.runtime.sendMessage({ type: 'SET_PIN_MODE', mode });
    if (res && res.ok) { pinMode = res.mode; return pinMode; }
  } catch { /* worker asleep — fall through and write it ourselves */ }
  // Pre-unlock, or the worker is not answering: write the mode directly.
  // unlock() reads it when it runs, so a checkbox ticked on the sign-in screen
  // still arms the session it is about to open.
  pinMode = await persistPinMode(mode);
  return pinMode;
}

async function syncPinModeUI() {
  pinMode = await getPinMode();
  // The auth screens ask the simple version of the question: anything that is
  // not "always" means you will not be asked again next time.
  ['loginStayUnlocked', 'unlockStayUnlocked'].forEach((id) => {
    const el = $(id);
    if (el) el.checked = pinMode !== 'always';
  });
  document.querySelectorAll('#pinModeSeg button').forEach((b) => {
    const on = b.dataset.mode === pinMode;
    b.classList.toggle('active', on);
    b.setAttribute('aria-checked', String(on));
  });
  const hint = $('pinModeHint');
  if (hint) {
    hint.textContent = PIN_MODE_HINT[pinMode];
    hint.classList.toggle('warn', pinMode === 'never');
  }
  return pinMode;
}

['loginStayUnlocked', 'unlockStayUnlocked'].forEach((id) => {
  const el = $(id);
  if (!el) return;
  el.addEventListener('change', async () => {
    // Unticking from 'never' means "ask me again", not "ask me a bit less
    // often", so both remembering modes collapse back to 'always'.
    await setPinMode(el.checked ? 'session' : 'always');
    await syncPinModeUI();
  });
});

/* ---------------- unlock flows ---------------- */
async function pushUnlockToBackground(masterPassword, session = {}) {
  await chrome.runtime.sendMessage({
    type: 'UNLOCK',
    payload: { ...session, user: userMeta, masterPassword, items: vaultItems },
  });
}

$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('loginError').classList.add('hidden');
  try {
    const email = $('loginEmail').value.trim();
    const authPassword = $('loginAuthPassword').value;
    const masterPassword = $('loginMasterPassword').value;
    const data = await apiFetch('/auth/login', { method: 'POST', body: JSON.stringify({ email, authPassword }) });
    userMeta = data.user;
    // Stores the refresh token too — that is what keeps this sign-in good for
    // longer than the fifteen minutes the access token lasts.
    await saveSession(data);
    masterKey = await deriveMasterKey(masterPassword, userMeta.kdfSalt, userMeta.kdfIterations);
    await loadVaultFromApi();
    await pushUnlockToBackground(masterPassword, { token: data.token, refreshToken: data.refreshToken });
    renderVault();
    showView('vaultView');
  } catch (err) {
    $('loginError').textContent = err.message;
    $('loginError').classList.remove('hidden');
  }
});

$('unlockForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('unlockError').classList.add('hidden');
  try {
    const masterPassword = $('unlockMasterPassword').value;
    masterKey = await deriveMasterKey(masterPassword, userMeta.kdfSalt, userMeta.kdfIterations);
    await loadVaultFromApi();
    // Deriving a key always "succeeds" — PBKDF2 turns any string into one — so
    // a wrong PIN used to sail through and land on a vault whose every entry
    // had a blank password. Prove the key actually opens this vault first.
    if (!vaultDecrypted()) {
      throw Object.assign(new Error('Incorrect master PIN'), { wrongPin: true });
    }
    await pushUnlockToBackground(masterPassword);
    renderVault();
    showView('vaultView');
  } catch (err) {
    // Only a refresh token the server refused ends the session now; an expired
    // access token was already renewed underneath us. Reporting either as
    // "Incorrect master PIN" sent users round in circles retyping a PIN that
    // was correct all along.
    if (err.sessionDead) {
      await handleUnauthorized();
      return;
    }
    masterKey = null;
    vaultItems = [];
    $('unlockError').textContent = err.wrongPin
      ? 'Incorrect master PIN'
      : err.message || 'Could not open the vault';
    $('unlockError').classList.remove('hidden');
  }
});

/** Did the derived key actually open the vault? An empty vault trivially has. */
function vaultDecrypted() {
  return vaultItems.length === 0 || decryptedCount > 0;
}

/**
 * Lock: forget the key, keep the session. Reopening asks only for the PIN.
 * This used to clear the session outright, so "Lock vault" was really a sign
 * out and cost you a full email + password round trip to get back in.
 */
function doLock() {
  masterKey = null; vaultItems = [];
  chrome.runtime.sendMessage({ type: 'LOCK' }).catch(() => {});
  if (userMeta) {
    $('unlockEmail').textContent = userMeta.email;
    showLockReason('manual');
    $('unlockMasterPassword').value = '';
    $('unlockError').classList.add('hidden');
    showView('unlockView');
  } else {
    showView('loginView');
  }
}

/** Sign out: revoke the refresh token server-side and forget the identity. */
async function doSignOut() {
  masterKey = null; userMeta = null; vaultItems = [];
  chrome.runtime.sendMessage({ type: 'SIGN_OUT' }).catch(() => {});
  await revokeSession();
  $('loginError').classList.add('hidden');
  showView('loginView');
}

// The header button is dual-purpose: inside the vault it locks, on the unlock
// screen it is the way back out to a different account.
$('lockBtn').addEventListener('click', () => {
  if ($('unlockView').classList.contains('hidden')) doLock();
  else doSignOut();
});
$('settingsLockBtn').addEventListener('click', doLock);

/* ---------------- load + decrypt (only when we have the key) ---------------- */
// How many items the current key actually opened on the last load. Tracked
// explicitly rather than inferred from a blank password, because a stored
// password could legitimately be an empty string — and treating that as a
// failed decryption would reject a correct PIN.
let decryptedCount = 0;

async function loadVaultFromApi() {
  const data = await apiFetch('/vault');
  // Decrypt each so the popup has plaintext for health + copy + fill.
  const out = [];
  decryptedCount = 0;
  for (const item of data.items) {
    let password = '', totp = '';
    try {
      const blob = await decryptPassword(item.encryptedDataBlob, item.iv, masterKey);
      password = blob.password;
      // The two-factor secret rides in the same blob. The popup holds it for
      // the same reason it holds the password: it is an extension context that
      // already has every plaintext, and generating the code here rather than
      // asking the worker once a second is what makes the countdown cheap.
      totp = totpFromBlob(blob);
      decryptedCount += 1;
    } catch { /* skip undecryptable */ }
    out.push({ ...item, password, totp });
  }
  vaultItems = out;
}

/* ---------------- rendering ---------------- */
function renderVault() {
  renderHealth();
  applyFilterAndRender();
  // Fire-and-forget: the worker answers from memory, and the cards pane is
  // usually not the one on screen, so nothing should wait on it.
  refreshCardsPane();
}

function renderHealth() {
  const strip = $('healthStrip');
  if (vaultItems.length === 0) { strip.classList.add('hidden'); return; }
  const report = scanVault(vaultItems.map((i) => ({
    id: i._id, websiteName: i.websiteName, websiteUrl: i.websiteUrl,
    username: i.username, password: i.password, updatedAt: i.updatedAt,
  })));
  strip.classList.remove('hidden');
  $('hTotal').textContent = report.total;
  $('hWeak').textContent = report.weak.length;
  $('hReused').textContent = report.reused.length;
  const score = report.healthScore;
  $('healthScore').textContent = score;
  const ring = $('healthRing');
  const c = 2 * Math.PI * 22;
  ring.style.strokeDasharray = String(c);
  ring.style.strokeDashoffset = String(c - (score / 100) * c);
  const color = score >= 80 ? '#10b981' : score >= 55 ? '#f59e0b' : score >= 30 ? '#f97316' : '#ef4444';
  ring.style.stroke = color;
  $('healthScore').style.color = color;

  // Breach check runs async in the background (limited to 50 items)
  scanBreaches(vaultItems.map((i) => ({ id: i._id, password: i.password })), 50)
    .then((breachedIds) => {
      $('hBreached').textContent = breachedIds.size;
    })
    .catch(() => {
      $('hBreached').textContent = '—';
    });
}

function applyFilterAndRender() {
  const domain = extractDomain(activeTabUrl);
  const matches = vaultItems.filter((i) => {
    const d = extractDomain(i.websiteUrl);
    return d && domain && (d.includes(domain) || domain.includes(d));
  });
  // Sort: favorites first, then by name.
  const sortFav = (a, b) => (favorites.has(b._id) - favorites.has(a._id)) || a.websiteName.localeCompare(b.websiteName);

  renderItemList($('matchList'), matches.slice().sort(sortFav), true);
  $('matchesSection').classList.toggle('hidden', matches.length === 0 && !query);

  let all = query ? searchItems(vaultItems, query) : vaultItems.slice().sort(sortFav);
  renderItemList($('allList'), all, false);
  $('allCount').textContent = `${all.length}`;
}

function strengthColor(pw) {
  const { score } = estimateStrength(pw || '');
  return ['#ef4444', '#ef4444', '#f59e0b', '#10b981', '#059669'][score];
}

/**
 * Every visible code is repainted by ONE timer, not one timer each. Each chip
 * registers what it needs; the tick counts down locally and only regenerates
 * when a step actually rolls over, so a list of ten logins is ten cheap
 * decrements a second rather than ten HMACs.
 */
let totpChips = [];
let totpTimer = null;

function registerTotpChip(chip) {
  totpChips.push(chip);
  paintTotpChip(chip);
  if (!totpTimer) totpTimer = setInterval(tickTotpChips, 1000);
}

async function paintTotpChip(chip) {
  const res = await generateTotp(chip.secret);
  if (!res) { chip.codeEl.textContent = 'invalid'; chip.secsEl.textContent = ''; chip.code = ''; return; }
  chip.code = res.code;
  chip.remaining = res.remaining;
  chip.codeEl.textContent = prettyCode(res.code);
  chip.secsEl.textContent = res.remaining + 's';
  chip.secsEl.classList.toggle('soon', res.remaining <= 5);
}

function tickTotpChips() {
  // Chips whose row has been re-rendered away are dropped rather than painted.
  totpChips = totpChips.filter((c) => c.codeEl.isConnected);
  if (totpChips.length === 0) { clearInterval(totpTimer); totpTimer = null; return; }
  for (const chip of totpChips) {
    chip.remaining -= 1;
    if (chip.remaining <= 0) { paintTotpChip(chip); continue; }
    chip.secsEl.textContent = chip.remaining + 's';
    chip.secsEl.classList.toggle('soon', chip.remaining <= 5);
  }
}

function renderItemList(container, items, isMatch) {
  container.innerHTML = '';
  // Chips in the container being replaced are gone; tickTotpChips() drops any
  // that are no longer in the document, so this just keeps the list short.
  totpChips = totpChips.filter((c) => c.codeEl.isConnected);
  if (items.length === 0) {
    container.innerHTML = isMatch
      ? '<p class="muted" style="padding:4px 2px">No saved logins for this site.</p>'
      : `<div class="empty"><div class="empty-icon"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div><div class="empty-title">${query ? 'No matches' : 'Your vault is empty'}</div><p>${query ? 'Nothing matches “' + escapeHtml(query) + '”.' : 'Add your first login above.'}</p></div>`;
    return;
  }
  for (const item of items) {
    const row = document.createElement('div');
    row.className = 'item-card';

    const fav = document.createElement('div');
    fav.className = 'favicon';
    const img = document.createElement('img');
    img.src = favicon(item);
    img.onerror = () => { fav.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20"/></svg>'; };
    fav.appendChild(img);

    const info = document.createElement('div');
    info.className = 'info';
    const dot = `<span class="strength-dot" style="background:${strengthColor(item.password)}"></span>`;
    info.innerHTML = `<div class="site">${escapeHtml(item.websiteName)}</div><div class="user">${escapeHtml(item.username)}</div><div class="pw-line" data-pw>${dot}••••••••••</div>`;

    const actions = document.createElement('div');
    actions.className = 'card-actions';

    // reveal
    const revealBtn = iconBtn(eyeSvg(false), 'Reveal password');
    let shown = false;
    revealBtn.addEventListener('click', () => {
      shown = !shown;
      const line = info.querySelector('[data-pw]');
      line.innerHTML = shown ? escapeHtml(item.password || '') : `${dot}••••••••••`;
      revealBtn.innerHTML = eyeSvg(shown);
    });

    // copy username
    const copyUserBtn = iconBtn(svgUser(), 'Copy username');
    copyUserBtn.addEventListener('click', () => copy(item.username, copyUserBtn, 'Username copied'));

    // copy password
    const copyPwBtn = iconBtn(svgCopy(), 'Copy password');
    copyPwBtn.addEventListener('click', () => copy(item.password, copyPwBtn, 'Password copied', true));

    // favorite
    const favBtn = iconBtn(svgStar(favorites.has(item._id)), 'Favorite');
    favBtn.classList.add('fav');
    if (favorites.has(item._id)) favBtn.classList.add('active');
    favBtn.addEventListener('click', async () => {
      if (favorites.has(item._id)) favorites.delete(item._id); else favorites.add(item._id);
      await chrome.storage.local.set({ favorites: [...favorites] });
      applyFilterAndRender();
    });

    // Two-factor. A login that HAS a secret already shows a code line below,
    // and its 2FA tag is the way into the editor — so no icon button for it.
    // Only a login WITHOUT one spends a slot here, because otherwise there is
    // nowhere to start from. Six icons plus Fill crushed the username column
    // to 70px of a 326px row, which is how "alexandra.whitfield@example.com"
    // became "alexandra....".
    actions.append(revealBtn, copyUserBtn, copyPwBtn);
    if (!item.totp) {
      const addTotpBtn = iconBtn(svgShield(), 'Add two-factor');
      addTotpBtn.addEventListener('click', () => toggleTotpEditor(row, item));
      actions.appendChild(addTotpBtn);
    }
    actions.appendChild(favBtn);

    if (isMatch) {
      const fillBtn = document.createElement('button');
      fillBtn.className = 'icon-btn fill';
      fillBtn.textContent = 'Fill';
      fillBtn.addEventListener('click', () => handleFill(item));
      actions.appendChild(fillBtn);
    }

    row.append(fav, info, actions);

    // The live code sits under the row rather than in it: six digits plus a
    // countdown do not fit beside four icon buttons at 380px, and this is
    // something you read, not something you squint at.
    if (item.totp) {
      const line = document.createElement('div');
      line.className = 'totp-line';
      const codeEl = node('span', 'totp-code', '------');
      const secsEl = node('span', 'totp-secs', '');
      const copyCode = document.createElement('button');
      copyCode.className = 'totp-copy';
      copyCode.textContent = 'Copy';
      const chip = { secret: item.totp, codeEl, secsEl, code: '', remaining: 0 };
      copyCode.addEventListener('click', () => {
        if (chip.code) copy(chip.code, copyCode, 'Code copied', true);
      });
      const tag = node('button', 'totp-tag', '2FA');
      tag.type = 'button';
      tag.title = 'Change or remove the two-factor secret';
      tag.addEventListener('click', () => toggleTotpEditor(row, item));
      line.append(tag, codeEl, secsEl, copyCode);
      if (isMatch) {
        const fillCode = document.createElement('button');
        fillCode.className = 'totp-copy fill';
        fillCode.textContent = 'Fill code';
        fillCode.addEventListener('click', () => handleFillCode(chip));
        line.appendChild(fillCode);
      }
      row.appendChild(line);
      registerTotpChip(chip);
    }

    container.appendChild(row);
  }
}

function iconBtn(svg, label) {
  const b = document.createElement('button');
  b.className = 'icon-btn';
  b.title = label; b.setAttribute('aria-label', label);
  b.innerHTML = svg;
  return b;
}
function svgUser() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'; }
function svgCopy() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>'; }
function svgCheck() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>'; }
function svgStar(filled) { return `<svg viewBox="0 0 24 24" fill="${filled ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 15.09 8.26 22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14l-5-4.87 6.91-1.01L12 2Z"/></svg>`; }

async function copy(text, btn, msg, clearLater) {
  try {
    await navigator.clipboard.writeText(text || '');
    const original = btn.innerHTML;
    btn.innerHTML = svgCheck(); btn.classList.add('copied');
    setTimeout(() => { btn.innerHTML = original; btn.classList.remove('copied'); }, 1200);
    toast(msg);
    if (clearLater) {
      setTimeout(async () => {
        try { const cur = await navigator.clipboard.readText(); if (cur === text) await navigator.clipboard.writeText(''); }
        catch { /* clipboard read blocked; non-fatal */ }
      }, 20000);
    }
  } catch { toast('Copy failed'); }
}

async function handleFill(item) {
  await chrome.runtime.sendMessage({
    type: 'FILL_CREDENTIALS_ON_TAB',
    payload: { tabId: activeTabId, username: item.username, password: item.password },
  });
  window.close();
}

/** Put the code on the page. Only the six digits are relayed, never the secret. */
async function handleFillCode(chip) {
  if (!chip.code || !activeTabId) return;
  try {
    const res = await chrome.tabs.sendMessage(activeTabId, { type: 'AUTOFILL_TOTP', code: chip.code });
    if (res && res.ok) { window.close(); return; }
  } catch { /* no content script on this page (chrome://, PDF viewer, ...) */ }
  // Nowhere to put it: the code is still what the user came for, so hand it
  // over the other way rather than failing silently.
  await navigator.clipboard.writeText(chip.code).catch(() => {});
  toast('No code field found - copied instead');
}

/* ---------------- two-factor setup ---------------- */
/** Small DOM helper; the content script has its own copy of this idea. */
function node(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text != null) el.textContent = text;
  return el;
}

/**
 * The inline editor for a login's two-factor secret: paste what the site gave
 * you (a Base32 secret or the otpauth:// link behind its QR code), or clear it.
 * Built on demand and torn down on close, so the list stays a list.
 */
function toggleTotpEditor(row, item) {
  const existing = row.querySelector('.totp-edit');
  if (existing) { existing.remove(); return; }

  const box = node('div', 'totp-edit');
  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = item.totp ? 'Replace secret or otpauth:// link' : 'Secret key or otpauth:// link';
  input.autocomplete = 'off';
  input.spellcheck = false;

  const hint = node('p', 'totp-hint',
    'From the site: "can’t scan the QR code?" shows this key. It is encrypted with your vault, like your passwords.');
  const err = node('p', 'totp-err hidden');

  const save = node('button', 'primary-btn totp-save', 'Save secret');
  save.type = 'button';
  const actions = node('div', 'totp-edit-actions');
  actions.appendChild(save);

  if (item.totp) {
    const remove = node('button', 'ghost-btn totp-remove', 'Remove');
    remove.type = 'button';
    remove.addEventListener('click', () => applyTotpSecret(item, '', err, box));
    actions.appendChild(remove);
  }

  save.addEventListener('click', () => {
    const secret = input.value.trim();
    if (!secret) { showTotpError(err, 'Paste the secret the site gave you.'); return; }
    // Checked here as well as in the worker so the message is immediate and
    // attached to the field, rather than arriving as a toast after a round trip.
    if (!parseTotp(secret)) {
      showTotpError(err, 'That is not a valid two-factor secret or otpauth:// link.');
      return;
    }
    applyTotpSecret(item, secret, err, box);
  });
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); save.click(); } });

  box.append(input, hint, err, actions);
  row.appendChild(box);
  input.focus();
}

function showTotpError(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

async function applyTotpSecret(item, secret, errEl, box) {
  box.classList.add('busy');
  try {
    // The worker owns the write: it holds the key, and it has to re-encrypt
    // the WHOLE blob so the password and notes survive the change.
    const res = await chrome.runtime.sendMessage({ type: 'SET_TOTP', id: item._id, secret });
    if (!res || !res.ok) throw new Error((res && res.error) || 'Could not save the secret');
    item.totp = secret;
    toast(secret ? 'Two-factor secret saved' : 'Two-factor removed');
    applyFilterAndRender();
  } catch (err) {
    box.classList.remove('busy');
    showTotpError(errEl, err.message);
  }
}

function escapeHtml(str) { const d = document.createElement('div'); d.textContent = str || ''; return d.innerHTML; }

/* ---------------- search ---------------- */
$('searchInput').addEventListener('input', (e) => {
  query = e.target.value;
  if (activePane === 'cardsPane') renderCards();
  else applyFilterAndRender();
});

/* ---------------- panes: logins / cards ---------------- */
$('paneTabs').addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-pane]');
  if (!btn) return;
  activePane = btn.dataset.pane;
  for (const b of $('paneTabs').querySelectorAll('button')) {
    const on = b === btn;
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', String(on));
  }
  $('loginsPane').classList.toggle('hidden', activePane !== 'loginsPane');
  $('cardsPane').classList.toggle('hidden', activePane !== 'cardsPane');
  // The query means different things in the two lists, so it starts clean
  // rather than silently filtering a list the user has not seen yet.
  query = '';
  $('searchInput').value = '';
  $('searchInput').placeholder = activePane === 'cardsPane' ? 'Search cards…' : 'Search logins…';
  if (activePane === 'cardsPane') {
    // First visit re-pulls from the server, so a card added in the web app a
    // minute ago is here rather than missing until the next unlock.
    if (!cardsReloaded) { cardsReloaded = true; refreshCardsPane(true); }
    else renderCards();
  } else {
    applyFilterAndRender();
  }
});

let cardsReloaded = false;

/** `reload` makes the worker re-pull from the server instead of answering
 *  from the copy it decrypted at unlock. */
async function refreshCardsPane(reload = false) {
  let res = null;
  try {
    res = await chrome.runtime.sendMessage({ type: reload ? 'REFRESH_CARDS' : 'GET_CARDS' });
  } catch {
    // The worker is gone and could not be woken. Note that the popup can
    // still show LOGINS in this state, because it decrypts those itself — so
    // "logins work, cards are empty" is the signature of a broken worker,
    // not of an empty card list.
    cardSummaries = [];
    cardsError = 'unreachable';
    renderCards();
    return;
  }
  cardSummaries = (res && res.cards) || [];
  if (!res || !res.cardsApi) cardsError = 'stale-worker';
  else if (!res.unlocked) cardsError = 'locked';
  else cardsError = res.error || null;
  renderCards();
}

/** The plate: brand base + corner bloom + chip, same recipe as the web app. */
function miniPlate(c) {
  const palette = BRAND_COLORS[c.brand] || BRAND_COLORS.other;
  const plate = document.createElement('div');
  plate.className = 'mini-plate';
  plate.style.setProperty('--plate-base', palette.base);
  plate.style.setProperty('--plate-accent', palette.accent);
  // Decorative: everything it says is also in the row as real text, and at
  // 6.5px none of it is readable anyway.
  plate.setAttribute('aria-hidden', 'true');
  plate.innerHTML =
    '<span class="chip"></span>' +
    '<span class="plate-last4">' + escapeHtml(c.last4 || '') + '</span>' +
    '<span class="plate-brand">' + escapeHtml(c.brandName || brandShort(c.brand)) + '</span>';
  return plate;
}

function span(cls, text) {
  const n = document.createElement('span');
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

function renderCards() {
  const list = $('cardList');
  const q = query.trim().toLowerCase();
  const items = q
    ? cardSummaries.filter((c) =>
        [c.label, c.brandName, c.last4, c.cardholderName].some((f) => (f || '').toLowerCase().includes(q))
      )
    : cardSummaries;

  $('cardCount').textContent = String(items.length);
  list.innerHTML = '';

  if (items.length === 0) {
    renderCardsEmpty(list, q);
    return;
  }

  for (const c of items) {
    const row = document.createElement('div');
    row.className = 'card-item' + (c.expired ? ' expired' : '');
    row.appendChild(miniPlate(c));

    const info = document.createElement('div');
    info.className = 'info';
    info.appendChild(span('label', c.label));
    // "•••• 8891", not the full 19-character mask. The text column here is
    // ~115px wide once the plate and the three action buttons have taken their
    // share, and the last four digits are the whole identifying payload — the
    // full grouped mask belongs on the plate, where there is room for it.
    info.appendChild(span('pan', c.last4 ? '\u2022\u2022\u2022\u2022 ' + c.last4 : c.masked));

    // Expiry FIRST and brand last: brand names run to ten characters
    // ("MASTERCARD") and this line has ~115px, so the brand is the part allowed
    // to ellipsize. The expiry is four digits and must never be the casualty.
    // Brand as text at all, rather than only as the plate's colour and its
    // 6.5px legend, because "is this the Visa or the Amex" has to be answerable.
    const sub = document.createElement('div');
    sub.className = 'sub';
    if (c.expiry) sub.appendChild(span('exp', c.expiry));
    // The expiry badge lives INSIDE this line rather than as a sibling of the
    // text column. As a sibling it claimed a fixed ~54px and halved the space
    // left for the card's name, so on an expired card the one thing you could
    // no longer read was which card it was.
    if (c.expired) {
      if (sub.childNodes.length) sub.appendChild(span('dot'));
      sub.appendChild(span('pill', 'Expired'));
    } else if (expiresSoon(monthOf(c.expiry), yearOf(c.expiry))) {
      if (sub.childNodes.length) sub.appendChild(span('dot'));
      sub.appendChild(span('pill soon', 'Expires soon'));
    }
    if (c.brandName) {
      if (sub.childNodes.length) sub.appendChild(span('dot'));
      sub.appendChild(span('brand', c.brandName));
    }
    if (sub.childNodes.length) info.appendChild(sub);
    row.appendChild(info);

    const actions = document.createElement('div');
    actions.className = 'card-actions';

    const fill = iconBtn(svgFill(), 'Fill this card on the page');
    fill.classList.add('fill');
    fill.addEventListener('click', () => fillCardOnTab(c));

    const copyNum = iconBtn(svgCopy(), 'Copy card number');
    copyNum.addEventListener('click', () => copyCardField(c, 'number', copyNum, 'Card number copied'));

    const copyCvv = iconBtn(svgShield(), 'Copy security code');
    copyCvv.addEventListener('click', () => copyCardField(c, 'cvv', copyCvv, 'Security code copied'));

    actions.append(fill, copyNum, copyCvv);
    row.appendChild(actions);
    list.appendChild(row);
  }
}

/**
 * The empty state has to say WHICH kind of empty this is. "No cards saved"
 * on a vault that has cards sends the user looking in the wrong place, so
 * every failure mode gets its own sentence and, where one exists, a button
 * that fixes it.
 */
function renderCardsEmpty(list, q) {
  const ICON = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/></svg>';
  const WARN = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 9v4"/><path d="M12 17h.01"/><circle cx="12" cy="12" r="9"/></svg>';

  let icon = ICON;
  let title;
  let body;
  let action = null; // { label, onClick }

  if (q) {
    title = 'No matching cards';
    body = 'Nothing matches “' + escapeHtml(query) + '”.';
  } else if (cardsError === 'stale-worker' || cardsError === 'unreachable') {
    icon = WARN;
    title = 'Extension needs a reload';
    body = cardsError === 'stale-worker'
      ? 'Vaultly\u2019s background worker is running an older build that does not know about cards yet. Reloading picks up the new one.'
      : 'Vaultly\u2019s background worker is not responding, so it cannot reach your cards.';
    action = {
      label: 'Reload Vaultly',
      // Restarting the extension drops the in-memory key, so the PIN is
      // asked for again. Said plainly rather than sprung on the user.
      note: 'You will re-enter your PIN.',
      onClick: () => chrome.runtime.reload(),
    };
  } else if (cardsError === 'locked') {
    icon = WARN;
    title = 'Vault is locked';
    body = 'Unlock Vaultly to see your cards.';
  } else if (cardsError === 'network') {
    icon = WARN;
    title = 'Could not reach Vaultly';
    body = 'Your cards are stored on the server. Check your connection and try again.';
    action = { label: 'Try again', onClick: () => refreshCardsPane(true) };
  } else if (cardsError === 'decrypt') {
    icon = WARN;
    title = 'Cards could not be decrypted';
    body = 'The vault has cards, but this master PIN does not open them. If you changed your PIN recently, sign in on the web vault once so the cards are re-encrypted.';
  } else if (cardsError && cardsError.startsWith('http:')) {
    icon = WARN;
    const code = cardsError.slice(5);
    title = 'Server error ' + escapeHtml(code);
    body = code === '404'
      ? 'This Vaultly server has no /cards endpoint — it is running a build from before cards existed.'
      : 'The server refused the request for your cards.';
    action = { label: 'Try again', onClick: () => refreshCardsPane(true) };
  } else {
    title = 'No cards saved';
    body = 'Add a card in the web vault and it will autofill at checkout.';
  }

  list.innerHTML =
    '<div class="empty"><div class="empty-icon">' + icon + '</div>' +
    '<div class="empty-title">' + title + '</div><p>' + body + '</p></div>';

  if (action) {
    const btn = document.createElement('button');
    btn.className = 'ghost-btn';
    btn.style.marginTop = '10px';
    btn.textContent = action.label;
    btn.addEventListener('click', action.onClick);
    list.appendChild(btn);
    if (action.note) {
      const note = document.createElement('p');
      note.className = 'helper';
      note.style.textAlign = 'center';
      note.textContent = action.note;
      list.appendChild(note);
    }
  }
}

/* "03/28" is all the popup has; expiresSoon() wants the parts back. */
function monthOf(expiry) { return expiry ? Number(expiry.slice(0, 2)) : 0; }
function yearOf(expiry) { return expiry ? Number(expiry.slice(-2)) : 0; }

/**
 * The fill path never brings the plaintext card into the popup: the worker
 * already holds it, checks the tab is https, and relays it straight to the
 * content script. One fewer context that has ever seen the number.
 */
async function fillCardOnTab(c) {
  const res = await chrome.runtime
    .sendMessage({ type: 'FILL_CARD_ON_TAB', payload: { tabId: activeTabId, id: c.id } })
    .catch(() => null);
  if (res && res.ok) { window.close(); return; }
  toast(res && res.error === 'insecure-page'
    ? 'Not filled — this page is not https'
    : 'No card fields found on this page');
}

async function copyCardField(c, field, btn, msg) {
  const res = await chrome.runtime.sendMessage({ type: 'GET_CARD', id: c.id }).catch(() => null);
  if (!res || !res.ok || !res.card[field]) { toast('Could not read that card'); return; }
  // clearLater: the clipboard is wiped after 20s if it still holds this value,
  // the same treatment a password gets.
  await copy(res.card[field], btn, msg, true);
}

function svgFill() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 3 14h8l-1 8 10-12h-8l1-8Z"/></svg>'; }
function svgShield() { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/></svg>'; }

/* ---------------- add form + generator ---------------- */
$('showAddFormBtn').addEventListener('click', () => {
  $('addForm').classList.toggle('hidden');
  if (!$('addWebsiteUrl').value) $('addWebsiteUrl').value = extractDomain(activeTabUrl);
  if (!$('addWebsiteName').value) $('addWebsiteName').value = extractDomain(activeTabUrl);
});
function generatorOptions() {
  return {
    length: Number($('genLength').value),
    uppercase: $('genUpper').checked, lowercase: $('genLower').checked,
    numbers: $('genNumbers').checked, symbols: $('genSymbols').checked,
    avoidAmbiguous: $('genAmbiguous').checked,
  };
}
function refreshStrength() {
  const { score, label } = estimateStrength($('addPassword').value);
  const bar = $('strengthBar');
  bar.style.width = [10, 30, 55, 80, 100][score] + '%';
  bar.style.background = ['#ef4444', '#ef4444', '#f59e0b', '#10b981', '#059669'][score];
  $('strengthLabel').textContent = $('addPassword').value ? label : '';
}
$('genLength').addEventListener('input', () => { $('genLengthVal').textContent = $('genLength').value; });
$('generateBtn').addEventListener('click', () => { $('addPassword').value = generatePassword(generatorOptions()); refreshStrength(); });
$('addPassword').addEventListener('input', refreshStrength);

$('addForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('addError').classList.add('hidden');
  try {
    const websiteName = $('addWebsiteName').value.trim();
    const websiteUrl = $('addWebsiteUrl').value.trim();
    const username = $('addUsername').value.trim();
    const password = $('addPassword').value;
    const totp = $('addTotp').value.trim();
    // Rejected before anything is saved: a secret that cannot make a code is
    // worse than no secret, because you only find out at the sign-in screen.
    if (totp && !parseTotp(totp)) {
      throw new Error('That is not a valid two-factor secret or otpauth:// link.');
    }
    // Adding requires the key. If we resumed a session, we don't have it —
    // ask the worker to save (it holds the key). Otherwise encrypt locally.
    let saved;
    if (masterKey) {
      const { ciphertext, iv } = await encryptPassword(password, masterKey, '', totp);
      const data = await apiFetch('/vault', { method: 'POST', body: JSON.stringify({ websiteName, websiteUrl, username, encryptedDataBlob: ciphertext, iv }) });
      saved = { ...data.item, password, totp };
      await chrome.runtime.sendMessage({ type: 'CACHE_ITEM', item: { id: data.item._id, websiteName, websiteUrl, username, password, totp } }).catch(() => {});
    } else {
      const res = await chrome.runtime.sendMessage({ type: 'SAVE_CREDENTIAL', payload: { websiteName, username, password, url: websiteUrl, totp } });
      if (res && res.error) throw new Error(res.error);
      saved = { _id: res.id, websiteName, websiteUrl, username, password, totp, updatedAt: new Date().toISOString() };
    }
    vaultItems.unshift(saved);
    renderVault();
    $('addForm').classList.add('hidden');
    e.target.reset();
    $('genLengthVal').textContent = '20';
    refreshStrength();
    toast('Login saved');
  } catch (err) {
    // Only a refused refresh token ends the session; a plain 401 here would
    // already have been retried with a fresh access token.
    if (err.sessionDead) {
      await handleUnauthorized();
      return;
    }
    $('addError').textContent = err.message;
    $('addError').classList.remove('hidden');
  }
});

/* ---------------- settings ---------------- */
$('settingsBtn').addEventListener('click', () => { showView('settingsView'); loadSettings(); });
$('settingsBackBtn').addEventListener('click', () => showView('vaultView'));
$('openWebVault').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: WEB_APP_URL });
});
$('openWebVaultCards').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: WEB_APP_URL + '/cards' });
});

async function loadSettings() {
  const manifest = chrome.runtime.getManifest();
  $('aboutVersion').textContent = 'v' + manifest.version;
  hidePinModeConfirm();
  await syncPinModeUI();
  const { autoLockMins = 0 } = await chrome.storage.local.get('autoLockMins');
  document.querySelectorAll('#autoLockSeg button').forEach((b) =>
    b.classList.toggle('active', Number(b.dataset.mins) === Number(autoLockMins))
  );
}
/**
 * 'Never' is the one choice that writes the PIN to disk, so it is the one
 * choice that does not happen on a single press: the panel states the cost and
 * waits. The other two apply immediately, as a setting should.
 */
function hidePinModeConfirm() {
  $('pinModeConfirm').classList.add('hidden');
}

const PIN_MODE_TOAST = {
  always: 'PIN will be asked again',
  session: 'Staying signed in',
  never: 'Master PIN turned off',
};

async function applyPinMode(mode) {
  await setPinMode(mode);
  await syncPinModeUI();
  toast(PIN_MODE_TOAST[mode]);
}

document.querySelectorAll('#pinModeSeg button').forEach((b) => {
  b.addEventListener('click', async () => {
    const mode = b.dataset.mode;
    if (mode === pinMode) { hidePinModeConfirm(); return; }
    if (mode === 'never') {
      $('pinModeConfirm').classList.remove('hidden');
      return;
    }
    hidePinModeConfirm();
    await applyPinMode(mode);
  });
});
$('pinModeCancel').addEventListener('click', async () => {
  hidePinModeConfirm();
  await syncPinModeUI();   // put the segment back on the mode still in force
});
$('pinModeConfirmBtn').addEventListener('click', async () => {
  hidePinModeConfirm();
  await applyPinMode('never');
});

document.querySelectorAll('#autoLockSeg button').forEach((b) => {
  b.addEventListener('click', async () => {
    const mins = Number(b.dataset.mins);
    await chrome.storage.local.set({ autoLockMins: mins });
    document.querySelectorAll('#autoLockSeg button').forEach((x) => x.classList.toggle('active', x === b));
    // Nudge the worker to reschedule with the new timeout.
    chrome.runtime.sendMessage({ type: 'NOTE_ACTIVITY' }).catch(() => {});
    toast(mins === 0 ? 'Auto-lock off' : `Auto-lock: ${mins}m`);
  });
});

init();
