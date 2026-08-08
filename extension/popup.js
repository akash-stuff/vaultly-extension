import { API_BASE_URL } from './config.js';
import { deriveMasterKey, encryptPassword, decryptPassword } from './shared/crypto.js';
import { generatePassword, estimateStrength } from './shared/passwordUtils.js';
import { searchItems } from './shared/search.js';
import { scanVault } from './shared/vaultHealth.js';

/**
 * Popup state (memory-only). When the background worker already holds an
 * unlocked session, we RESUME from it via GET_VAULT — no PIN re-prompt. The
 * worker hands back the decrypted vault over the internal channel, so the
 * popup never needs the master key just to browse/copy/fill. We only derive a
 * key in this context when the user is actively unlocking or adding an item.
 */
let masterKey = null;      // derived only during an explicit unlock/add
let authToken = null;
let userMeta = null;
let vaultItems = [];       // full objects incl. decrypted password when resumed
let activeTabUrl = null;
let activeTabId = null;
let favorites = new Set(); // ids, persisted in chrome.storage.local
let query = '';

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

async function apiFetch(path, options = {}) {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      ...(options.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // Carry the status so callers can tell "your JWT died" apart from "your
    // input was wrong". Access tokens last 15 minutes but chrome.storage.session
    // keeps them for the whole browser session, so an expired token on the
    // unlock screen is the common case, not an edge case.
    const err = new Error(data.message || 'Request failed');
    err.status = res.status;
    throw err;
  }
  return data;
}

/**
 * The token is dead. Drop every trace of the session and send the user back to
 * the login form — mirrors the web app's `vaultly:unauthorized` handling.
 */
async function handleUnauthorized(message = 'Your session expired. Sign in again.') {
  authToken = null; userMeta = null; masterKey = null; vaultItems = [];
  await chrome.storage.session.clear();
  chrome.runtime.sendMessage({ type: 'LOCK' }).catch(() => {});
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

  // Try to resume an already-unlocked session from the worker — this is the
  // "don't re-ask for the PIN every time" behavior.
  let resumed = false;
  try {
    const res = await chrome.runtime.sendMessage({ type: 'GET_VAULT' });
    if (res && res.unlocked) {
      userMeta = res.user;
      authToken = null; // popup doesn't need the token for browsing when resumed
      vaultItems = res.items.map((v) => ({
        _id: v.id, websiteName: v.websiteName, websiteUrl: v.websiteUrl,
        username: v.username, password: v.password, updatedAt: v.updatedAt,
      }));
      renderVault();
      showView('vaultView');
      resumed = true;
    }
  } catch { /* worker asleep or unreachable; fall through */ }
  if (resumed) return;

  const session = await chrome.storage.session.get(['authToken', 'userMeta']);
  if (session.authToken && session.userMeta) {
    authToken = session.authToken;
    userMeta = session.userMeta;
    $('unlockEmail').textContent = userMeta.email;
    showView('unlockView');
  } else {
    showView('loginView');
  }
}

/* ---------------- unlock flows ---------------- */
async function pushUnlockToBackground(masterPassword) {
  await chrome.runtime.sendMessage({
    type: 'UNLOCK',
    payload: { token: authToken, user: userMeta, masterPassword, items: vaultItems },
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
    authToken = data.token;
    userMeta = data.user;
    await chrome.storage.session.set({ authToken, userMeta });
    masterKey = await deriveMasterKey(masterPassword, userMeta.kdfSalt, userMeta.kdfIterations);
    await loadVaultFromApi();
    await pushUnlockToBackground(masterPassword);
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
    // Verify the PIN actually decrypts before declaring success.
    await pushUnlockToBackground(masterPassword);
    renderVault();
    showView('vaultView');
  } catch (err) {
    // A 401 here is the stored JWT expiring, not a bad PIN — reporting it as
    // "Incorrect master PIN" sent users round in circles retyping a PIN that
    // was correct all along.
    if (err.status === 401) {
      await handleUnauthorized();
      return;
    }
    $('unlockError').textContent = 'Incorrect master PIN';
    $('unlockError').classList.remove('hidden');
  }
});

function doLock() {
  authToken = null; userMeta = null; masterKey = null; vaultItems = [];
  chrome.storage.session.clear();
  chrome.runtime.sendMessage({ type: 'LOCK' }).catch(() => {});
  showView('loginView');
}
$('lockBtn').addEventListener('click', doLock);
$('settingsLockBtn').addEventListener('click', doLock);

/* ---------------- load + decrypt (only when we have the key) ---------------- */
async function loadVaultFromApi() {
  const data = await apiFetch('/vault');
  // Decrypt each so the popup has plaintext for health + copy + fill.
  const out = [];
  for (const item of data.items) {
    let password = '';
    try { ({ password } = await decryptPassword(item.encryptedDataBlob, item.iv, masterKey)); }
    catch { /* skip undecryptable */ }
    out.push({ ...item, password });
  }
  vaultItems = out;
}

/* ---------------- rendering ---------------- */
function renderVault() {
  renderHealth();
  applyFilterAndRender();
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

function renderItemList(container, items, isMatch) {
  container.innerHTML = '';
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

    actions.append(revealBtn, copyUserBtn, copyPwBtn, favBtn);

    if (isMatch) {
      const fillBtn = document.createElement('button');
      fillBtn.className = 'icon-btn fill';
      fillBtn.textContent = 'Fill';
      fillBtn.addEventListener('click', () => handleFill(item));
      actions.appendChild(fillBtn);
    }

    row.append(fav, info, actions);
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

function escapeHtml(str) { const d = document.createElement('div'); d.textContent = str || ''; return d.innerHTML; }

/* ---------------- search ---------------- */
$('searchInput').addEventListener('input', (e) => { query = e.target.value; applyFilterAndRender(); });

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
    // Adding requires the key. If we resumed a session, we don't have it —
    // ask the worker to save (it holds the key). Otherwise encrypt locally.
    let saved;
    if (masterKey) {
      const { ciphertext, iv } = await encryptPassword(password, masterKey);
      const data = await apiFetch('/vault', { method: 'POST', body: JSON.stringify({ websiteName, websiteUrl, username, encryptedDataBlob: ciphertext, iv }) });
      saved = { ...data.item, password };
      await chrome.runtime.sendMessage({ type: 'CACHE_ITEM', item: { id: data.item._id, websiteName, websiteUrl, username, password } }).catch(() => {});
    } else {
      const res = await chrome.runtime.sendMessage({ type: 'SAVE_CREDENTIAL', payload: { websiteName, username, password, url: websiteUrl } });
      if (res && res.error) throw new Error(res.error);
      saved = { _id: res.id, websiteName, websiteUrl, username, password, updatedAt: new Date().toISOString() };
    }
    vaultItems.unshift(saved);
    renderVault();
    $('addForm').classList.add('hidden');
    e.target.reset();
    $('genLengthVal').textContent = '20';
    refreshStrength();
    toast('Login saved');
  } catch (err) {
    if (err.status === 401) {
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
  const base = API_BASE_URL.replace(/\/api\/?$/, '');
  chrome.tabs.create({ url: base || 'https://vaultly-ui.netlify.app' });
});
async function loadSettings() {
  const manifest = chrome.runtime.getManifest();
  $('aboutVersion').textContent = 'v' + manifest.version;
  const { autoLockMins = 0 } = await chrome.storage.local.get('autoLockMins');
  document.querySelectorAll('#autoLockSeg button').forEach((b) =>
    b.classList.toggle('active', Number(b.dataset.mins) === Number(autoLockMins))
  );
}
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
