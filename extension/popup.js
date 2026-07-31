import { API_BASE_URL } from './config.js';
import { deriveMasterKey, encryptPassword, decryptPassword } from './shared/crypto.js';
import { generatePassword, estimateStrength } from './shared/passwordUtils.js';

/**
 * In-memory-only state. `masterKey` is a non-extractable CryptoKey that lives
 * only for the lifetime of this popup's JS context. On unlock we ALSO hand the
 * unlocked vault to the background worker (over the internal messaging channel,
 * never HTTP) so page-driven autofill/save prompts work while browsing — see
 * background.js for the security rationale.
 */
let masterKey = null;
let authToken = null;
let userMeta = null;
let vaultItems = [];
let activeTabUrl = null;
let activeTabId = null;

const $ = (id) => document.getElementById(id);

function showView(id) {
  ['loginView', 'unlockView', 'vaultView'].forEach((v) => $(v).classList.toggle('hidden', v !== id));
  $('logoutBtn').classList.toggle('hidden', id === 'loginView');
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
  if (!res.ok) throw new Error(data.message || 'Request failed');
  return data;
}

function extractDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return ''; }
}

// Push the unlocked vault to the background worker so autofill works page-side.
async function pushUnlockToBackground(masterPassword) {
  await chrome.runtime.sendMessage({
    type: 'UNLOCK',
    payload: { token: authToken, user: userMeta, masterPassword, items: vaultItems },
  });
}

async function init() {
  const tabInfo = await chrome.runtime.sendMessage({ type: 'GET_ACTIVE_TAB' });
  activeTabUrl = (tabInfo && tabInfo.url) || '';
  activeTabId = (tabInfo && tabInfo.tabId) || null;

  const session = await chrome.storage.session.get(['authToken', 'userMeta']);
  if (session.authToken && session.userMeta) {
    authToken = session.authToken;
    userMeta = session.userMeta;
    $('unlockEmail').textContent = ` (${userMeta.email})`;
    showView('unlockView');
  } else {
    showView('loginView');
  }
}

$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('loginError').classList.add('hidden');
  try {
    const email = $('loginEmail').value.trim();
    const authPassword = $('loginAuthPassword').value;
    const masterPassword = $('loginMasterPassword').value;

    const data = await apiFetch('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, authPassword }),
    });

    authToken = data.token;
    userMeta = data.user;
    await chrome.storage.session.set({ authToken, userMeta });

    masterKey = await deriveMasterKey(masterPassword, userMeta.kdfSalt, userMeta.kdfIterations);
    await loadVault();
    await pushUnlockToBackground(masterPassword);
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
    await loadVault();
    await pushUnlockToBackground(masterPassword);
    showView('vaultView');
  } catch (err) {
    $('unlockError').textContent = 'Incorrect master password';
    $('unlockError').classList.remove('hidden');
  }
});

$('logoutBtn').addEventListener('click', async () => {
  authToken = null; userMeta = null; masterKey = null; vaultItems = [];
  await chrome.storage.session.clear();
  await chrome.runtime.sendMessage({ type: 'LOCK' });
  showView('loginView');
});

async function loadVault() {
  const data = await apiFetch('/vault');
  vaultItems = data.items;
  renderLists();
}

function renderLists() {
  const domain = extractDomain(activeTabUrl);
  const matches = vaultItems.filter(
    (i) => extractDomain(i.websiteUrl).includes(domain) || domain.includes(extractDomain(i.websiteUrl))
  );
  renderItemList($('matchList'), matches, true);
  renderItemList($('allList'), vaultItems, false);
  $('allCount').textContent = vaultItems.length;
}

function renderItemList(container, items, showFillButton) {
  container.innerHTML = '';
  if (items.length === 0) {
    container.innerHTML = '<p class="muted">No entries.</p>';
    return;
  }
  items.forEach((item) => {
    const row = document.createElement('div');
    row.className = 'item-card';
    // Feature 11: favicon beside each saved login.
    const fav = document.createElement('img');
    fav.className = 'favicon';
    fav.src = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(extractDomain(item.websiteUrl) || item.websiteName)}&sz=32`;
    fav.onerror = () => { fav.style.visibility = 'hidden'; };
    const info = document.createElement('div');
    info.className = 'info';
    info.innerHTML = `<div class="site">${escapeHtml(item.websiteName)}</div><div class="user">${escapeHtml(item.username)}</div>`;
    const btn = document.createElement('button');
    btn.textContent = showFillButton ? 'Fill' : 'Copy';
    btn.addEventListener('click', () => (showFillButton ? handleFill(item) : handleCopy(item)));
    row.append(fav, info, btn);
    container.appendChild(row);
  });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

async function handleFill(item) {
  try {
    const decrypted = await decryptPassword(item.encryptedDataBlob, item.iv, masterKey);
    await chrome.runtime.sendMessage({
      type: 'FILL_CREDENTIALS_ON_TAB',
      payload: { tabId: activeTabId, username: item.username, password: decrypted.password },
    });
    window.close();
  } catch (err) {
    alert('Failed to decrypt/fill: ' + err.message);
  }
}

async function handleCopy(item) {
  const decrypted = await decryptPassword(item.encryptedDataBlob, item.iv, masterKey);
  await navigator.clipboard.writeText(decrypted.password);
  // Feature 14: clear clipboard after 30s (best-effort; only if still ours).
  setTimeout(async () => {
    try {
      const current = await navigator.clipboard.readText();
      if (current === decrypted.password) await navigator.clipboard.writeText('');
    } catch { /* clipboard read may be blocked; non-fatal */ }
  }, 30000);
}

// ---- Add-login form + generator (Features 8 & 9) ----
$('showAddFormBtn').addEventListener('click', () => {
  $('addForm').classList.toggle('hidden');
  if (!$('addWebsiteUrl').value) $('addWebsiteUrl').value = activeTabUrl;
  if (!$('addWebsiteName').value) $('addWebsiteName').value = extractDomain(activeTabUrl);
});

function generatorOptions() {
  return {
    length: Number($('genLength').value),
    uppercase: $('genUpper').checked,
    lowercase: $('genLower').checked,
    numbers: $('genNumbers').checked,
    symbols: $('genSymbols').checked,
    avoidAmbiguous: $('genAmbiguous').checked,
  };
}

function refreshStrength() {
  const { score, label } = estimateStrength($('addPassword').value);
  const bar = $('strengthBar');
  const pct = [10, 30, 55, 80, 100][score];
  const color = ['#ef4444', '#ef4444', '#f59e0b', '#10b981', '#059669'][score];
  bar.style.width = pct + '%';
  bar.style.background = color;
  $('strengthLabel').textContent = $('addPassword').value ? label : '';
}

$('genLength').addEventListener('input', () => { $('genLengthVal').textContent = $('genLength').value; });
$('generateBtn').addEventListener('click', () => {
  $('addPassword').value = generatePassword(generatorOptions());
  refreshStrength();
});
$('addPassword').addEventListener('input', refreshStrength);

$('addForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('addError').classList.add('hidden');
  try {
    const websiteName = $('addWebsiteName').value.trim();
    const websiteUrl = $('addWebsiteUrl').value.trim();
    const username = $('addUsername').value.trim();
    const password = $('addPassword').value;

    const { ciphertext, iv } = await encryptPassword(password, masterKey);
    const data = await apiFetch('/vault', {
      method: 'POST',
      body: JSON.stringify({ websiteName, websiteUrl, username, encryptedDataBlob: ciphertext, iv }),
    });

    vaultItems.unshift(data.item);
    renderLists();
    // Keep the background worker's unlocked cache in sync (single item, no re-derive).
    await chrome.runtime.sendMessage({
      type: 'CACHE_ITEM',
      item: { id: data.item._id, websiteName, websiteUrl, username, password },
    }).catch(() => {});
    $('addForm').classList.add('hidden');
    e.target.reset();
    $('genLengthVal').textContent = $('genLength').value;
    refreshStrength();
  } catch (err) {
    $('addError').textContent = err.message;
    $('addError').classList.remove('hidden');
  }
});

init();
