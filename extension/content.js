/**
 * ============================================================================
 * CONTENT SCRIPT — form detection + in-page autofill UI + save prompts
 * ============================================================================
 * SECURITY POSTURE:
 *   - This script never holds the vault, the master key, or more than the ONE
 *     credential the user actively chose to fill. It asks the background worker
 *     for matches (labels only) and fetches a single plaintext credential only
 *     on an explicit user click.
 *   - All Vaultly UI is rendered inside a closed-ish Shadow DOM host so the
 *     page's CSS can't restyle it and page scripts can't easily walk into it.
 *   - Note the inherent limit of ALL autofill: once a value is placed in a
 *     page <input>, page JavaScript can read that field. That's unavoidable
 *     for any autofill tool; we mitigate by filling only on explicit action
 *     and only the chosen item — never the whole vault.
 *
 * Content scripts run as classic scripts (no ES module import), so the small
 * password generator below is inlined and mirrors shared/passwordUtils.js.
 * ============================================================================
 */
(() => {
  'use strict';

  // ---- inlined, unbiased generator (mirror of shared/passwordUtils.js) ----
  const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', LOWER = 'abcdefghijklmnopqrstuvwxyz';
  const NUM = '0123456789', SYM = '!@#$%^&*()-_=+[]{};:,.<>?';
  function secureInt(max) {
    const limit = Math.floor(0xffffffff / max) * max, b = new Uint32Array(1);
    let x; do { crypto.getRandomValues(b); x = b[0]; } while (x >= limit);
    return x % max;
  }
  function genPassword(len = 20) {
    const classes = [UPPER, LOWER, NUM, SYM], pool = classes.join('');
    const out = classes.map((c) => c[secureInt(c.length)]);
    while (out.length < len) out.push(pool[secureInt(pool.length)]);
    for (let i = out.length - 1; i > 0; i--) { const j = secureInt(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
    return out.join('');
  }

  // ---- field detection (Feature 1) ----
  const USERNAME_SELECTORS = [
    'input[type="email"]',
    'input[type="text"][name*="email" i]',
    'input[type="text"][name*="user" i]',
    'input[type="text"][name*="login" i]',
    'input[type="text"][id*="email" i]',
    'input[type="text"][id*="user" i]',
    'input[autocomplete="username"]',
    'input[autocomplete="email"]',
  ].join(',');

  function isVisible(el) {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
  }

  function findLoginFields(root = document) {
    const passwordFields = Array.from(root.querySelectorAll('input[type="password"]')).filter(isVisible);
    const usernameFields = Array.from(root.querySelectorAll(USERNAME_SELECTORS)).filter(isVisible);
    return { passwordFields, usernameFields };
  }

  /** Pick the username field most likely paired with a given password field. */
  function nearestUsernameField(passwordField, usernameFields) {
    if (usernameFields.length === 0) return null;
    if (usernameFields.length === 1) return usernameFields[0];
    // Prefer the last username field that appears before the password field in DOM order.
    const before = usernameFields.filter(
      (u) => u.compareDocumentPosition(passwordField) & Node.DOCUMENT_POSITION_FOLLOWING
    );
    return (before.length ? before[before.length - 1] : usernameFields[0]);
  }

  // React/Vue-safe value setter.
  function setNativeValue(input, value) {
    const proto = Object.getPrototypeOf(input);
    const desc = Object.getOwnPropertyDescriptor(proto, 'value');
    desc.set.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function fillCredentials(username, password) {
    const { passwordFields, usernameFields } = findLoginFields();
    const pw = passwordFields[0] || null;
    const user = pw ? nearestUsernameField(pw, usernameFields) : usernameFields[0];
    if (user && username != null) setNativeValue(user, username);
    if (pw && password != null) setNativeValue(pw, password);
  }

  // =========================================================================
  // Shadow-DOM UI host (all Vaultly overlays render inside here)
  // =========================================================================
  let host = null, shadow = null;
  function ensureHost() {
    if (host && document.documentElement.contains(host)) return;
    host = document.createElement('div');
    host.style.cssText = 'all:initial;position:fixed;z-index:2147483647;top:0;left:0;width:0;height:0;';
    shadow = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = `
      .vy-pop, .vy-toast { position: fixed; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background:#fff; color:#111827; border:1px solid #e5e7eb; border-radius:12px;
        box-shadow:0 10px 30px rgba(0,0,0,.18); overflow:hidden; }
      .vy-pop { min-width:240px; max-width:320px; }
      .vy-head { display:flex; align-items:center; gap:8px; padding:10px 12px; background:#4f46e5; color:#fff; font-weight:600; font-size:13px; }
      .vy-site { padding:6px 12px; font-size:11px; color:#6b7280; border-bottom:1px solid #f3f4f6; }
      .vy-row { display:flex; align-items:center; gap:10px; padding:10px 12px; cursor:pointer; font-size:13px; }
      .vy-row:hover { background:#f5f3ff; }
      .vy-row img { width:16px; height:16px; border-radius:3px; }
      .vy-row .vy-user { font-weight:500; }
      .vy-empty { padding:12px; font-size:12px; color:#6b7280; }
      .vy-toast { min-width:280px; max-width:340px; right:16px; bottom:16px; padding:14px; }
      .vy-toast h4 { margin:0 0 6px; font-size:14px; }
      .vy-toast .vy-meta { font-size:12px; color:#6b7280; margin:2px 0; word-break:break-all; }
      .vy-actions { display:flex; gap:8px; margin-top:12px; }
      .vy-btn { flex:1; border:none; border-radius:8px; padding:8px 10px; font-size:13px; font-weight:600; cursor:pointer; }
      .vy-btn.primary { background:#4f46e5; color:#fff; }
      .vy-btn.ghost { background:#f3f4f6; color:#374151; }
      @media (prefers-color-scheme: dark) {
        .vy-pop, .vy-toast { background:#1f2937; color:#f9fafb; border-color:#374151; }
        .vy-row:hover { background:#312e81; }
        .vy-site, .vy-toast .vy-meta, .vy-empty { color:#9ca3af; }
        .vy-btn.ghost { background:#374151; color:#e5e7eb; }
      }`;
    shadow.appendChild(style);
    document.documentElement.appendChild(host);
  }

  function clearShadowRegion(cls) {
    if (!shadow) return;
    shadow.querySelectorAll(cls).forEach((n) => n.remove());
  }

  function favicon(name) {
    return `https://www.google.com/s2/favicons?domain=${encodeURIComponent(name)}&sz=32`;
  }

  // ---- autofill suggestion popup (Feature 2) ----
  let popupOpen = false;
  function closePopup() {
    clearShadowRegion('.vy-pop');
    popupOpen = false;
    document.removeEventListener('mousedown', onOutside, true);
    document.removeEventListener('scroll', closePopup, true);
    document.removeEventListener('keydown', onEsc, true);
  }
  function onOutside(e) {
    // host is in the light DOM; clicks inside the shadow won't reach here as `host`
    if (e.target !== host) closePopup();
  }
  function onEsc(e) { if (e.key === 'Escape') closePopup(); }

  async function openSuggestions(anchorEl) {
    ensureHost();
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: 'GET_MATCHES' });
    } catch { return; } // extension context invalidated (e.g. reloaded)
    if (!res) return;

    clearShadowRegion('.vy-pop');
    const pop = document.createElement('div');
    pop.className = 'vy-pop';

    const head = document.createElement('div');
    head.className = 'vy-head';
    head.textContent = '🔐 Vaultly';
    pop.appendChild(head);

    const site = document.createElement('div');
    site.className = 'vy-site';
    site.textContent = location.hostname.replace(/^www\./, '');
    pop.appendChild(site);

    if (!res.unlocked) {
      const empty = document.createElement('div');
      empty.className = 'vy-empty';
      empty.textContent = 'Vault locked — open the Vaultly popup to unlock.';
      pop.appendChild(empty);
    } else if (!res.matches || res.matches.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'vy-empty';
      empty.textContent = 'No saved logins for this site.';
      pop.appendChild(empty);
    } else {
      for (const m of res.matches) {
        const row = document.createElement('div');
        row.className = 'vy-row';
        const img = document.createElement('img');
        img.src = favicon(site.textContent);
        img.onerror = () => { img.style.visibility = 'hidden'; };
        const label = document.createElement('span');
        label.className = 'vy-user';
        label.textContent = m.username;
        row.append(img, label);
        row.addEventListener('mousedown', async (e) => {
          e.preventDefault();
          const cred = await chrome.runtime.sendMessage({ type: 'GET_CREDENTIAL', id: m.id });
          if (cred && cred.ok) fillCredentials(cred.username, cred.password);
          closePopup();
        });
        pop.appendChild(row);
      }
    }

    // Position under the anchor field.
    const r = anchorEl.getBoundingClientRect();
    pop.style.left = Math.max(8, Math.min(r.left, window.innerWidth - 328)) + 'px';
    pop.style.top = Math.min(r.bottom + 6, window.innerHeight - 20) + 'px';
    shadow.appendChild(pop);
    popupOpen = true;

    document.addEventListener('mousedown', onOutside, true);
    document.addEventListener('scroll', closePopup, true);
    document.addEventListener('keydown', onEsc, true);
  }

  // ---- save / update prompt (Features 3 & 4) ----
  const suppressedSites = new Set(); // "Never" for this site, this session
  function showToast({ title, meta, primaryLabel, ghostLabel, onPrimary, onGhost }) {
    ensureHost();
    clearShadowRegion('.vy-toast');
    const toast = document.createElement('div');
    toast.className = 'vy-toast';
    const h = document.createElement('h4');
    h.textContent = title;
    toast.appendChild(h);
    for (const line of meta) {
      const p = document.createElement('div');
      p.className = 'vy-meta';
      p.textContent = line;
      toast.appendChild(p);
    }
    const actions = document.createElement('div');
    actions.className = 'vy-actions';
    const primary = document.createElement('button');
    primary.className = 'vy-btn primary';
    primary.textContent = primaryLabel;
    primary.addEventListener('click', () => { clearShadowRegion('.vy-toast'); onPrimary && onPrimary(); });
    const ghost = document.createElement('button');
    ghost.className = 'vy-btn ghost';
    ghost.textContent = ghostLabel;
    ghost.addEventListener('click', () => { clearShadowRegion('.vy-toast'); onGhost && onGhost(); });
    actions.append(primary, ghost);
    toast.appendChild(actions);
    shadow.appendChild(toast);
    // Auto-dismiss after 20s so it never lingers forever.
    setTimeout(() => clearShadowRegion('.vy-toast'), 20000);
  }

  let lastSubmit = { username: '', password: '', at: 0 };
  async function handlePotentialSubmit() {
    const { passwordFields, usernameFields } = findLoginFields();
    const pw = passwordFields[0];
    if (!pw || !pw.value) return;
    const userField = nearestUsernameField(pw, usernameFields);
    const username = userField ? userField.value : '';
    const password = pw.value;

    const host = location.hostname.replace(/^www\./, '');
    if (suppressedSites.has(host)) return;

    // Debounce duplicate fires (submit + click + Enter can all trigger).
    const now = Date.now();
    if (username === lastSubmit.username && password === lastSubmit.password && now - lastSubmit.at < 2000) return;
    lastSubmit = { username, password, at: now };

    let verdict;
    try {
      verdict = await chrome.runtime.sendMessage({ type: 'CLASSIFY_SUBMISSION', payload: { username, password } });
    } catch { return; }
    if (!verdict || verdict.action === 'none') return;

    if (verdict.action === 'save') {
      showToast({
        title: 'Save login?',
        meta: [`Website: ${host}`, `Username: ${username || '(none)'}`, 'Password: ••••••••'],
        primaryLabel: 'Save',
        ghostLabel: 'Never',
        onPrimary: () => chrome.runtime.sendMessage({ type: 'SAVE_CREDENTIAL', payload: { websiteName: host, username, password } }),
        onGhost: () => suppressedSites.add(host),
      });
    } else if (verdict.action === 'update') {
      showToast({
        title: 'Update saved password?',
        meta: [`Website: ${host}`, `Username: ${username}`, 'Password changed'],
        primaryLabel: 'Update',
        ghostLabel: 'Cancel',
        onPrimary: () => chrome.runtime.sendMessage({ type: 'UPDATE_CREDENTIAL', payload: { id: verdict.id, password } }),
        onGhost: () => {},
      });
    }
  }

  // ---- wiring: focus opens suggestions; submit-like events trigger save ----
  function isLoginInput(el) {
    if (!(el instanceof HTMLInputElement)) return false;
    if (el.type === 'password') return true;
    return el.matches(USERNAME_SELECTORS);
  }

  document.addEventListener('focusin', (e) => {
    if (isLoginInput(e.target)) openSuggestions(e.target);
  }, true);

  // Submit detection (Feature 10 subset): real form submit + Enter-in-password.
  document.addEventListener('submit', () => setTimeout(handlePotentialSubmit, 0), true);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target instanceof HTMLInputElement && e.target.type === 'password') {
      setTimeout(handlePotentialSubmit, 50);
    }
  }, true);
  // SPA logins that never fire submit: also watch for a URL change after creds present.
  let lastHref = location.href;
  const urlWatcher = () => {
    if (location.href !== lastHref) { lastHref = location.href; setTimeout(handlePotentialSubmit, 200); }
  };
  window.addEventListener('popstate', urlWatcher);

  // ---- MutationObserver: (re)detect forms rendered after load (Feature 1) ----
  let scanScheduled = false;
  const observer = new MutationObserver(() => {
    if (scanScheduled) return;
    scanScheduled = true;
    // Debounce bursts of DOM changes into one scan.
    requestAnimationFrame(() => {
      scanScheduled = false;
      urlWatcher();
      // Detection is on-demand (on focus), so the scan here just keeps the
      // URL watcher honest for SPA route changes; no heavy work needed.
    });
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  // ---- messages from background (context menu / command) ----
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'AUTOFILL') {
      // Legacy path retained for the popup's "Fill" button.
      fillCredentials(message.username, message.password);
      sendResponse({ ok: true });
    }
    if (message.type === 'SHOW_AUTOFILL_MENU') {
      const { passwordFields, usernameFields } = findLoginFields();
      const anchor = document.activeElement && isLoginInput(document.activeElement)
        ? document.activeElement
        : (usernameFields[0] || passwordFields[0]);
      if (anchor) openSuggestions(anchor);
      sendResponse({ ok: !!anchor });
    }
    if (message.type === 'GENERATE_INTO_FIELD') {
      const el = document.activeElement;
      if (el instanceof HTMLInputElement && (el.type === 'password' || el.type === 'text')) {
        setNativeValue(el, genPassword(20));
        sendResponse({ ok: true });
      } else {
        sendResponse({ ok: false });
      }
    }
    return true;
  });
})();
