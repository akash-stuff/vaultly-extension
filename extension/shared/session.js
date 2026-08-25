/**
 * ============================================================================
 * SESSION — identity that outlives a 15-minute access token
 * ============================================================================
 * THE BUG THIS EXISTS TO FIX
 *
 * The backend issues a 15-minute JWT. Both the popup and the service worker
 * used to treat a 401 as "the session is over": the worker called lock() and
 * the popup threw the user back to the email + password form. But a service
 * worker can stay alive far longer than fifteen minutes, and the popup is
 * opened days apart — so the *normal* case was being handled as a failure.
 * Save a password twenty minutes after unlocking and you were signed out.
 *
 * The server now issues a refresh token alongside the JWT. This module is the
 * single place that knows about it: every call goes through `apiFetch`, a 401
 * transparently mints a new access token and replays the request, and the
 * session is only declared dead when the SERVER rejects the refresh token.
 *
 * WHAT IS STORED, AND WHY IT IS SAFE
 *   chrome.storage.local    refresh token + user identity (id, email, kdfSalt,
 *                           kdfIterations). Survives a browser restart, which
 *                           is what lets the popup open straight to the PIN
 *                           screen instead of a full sign-in.
 *   chrome.storage.session  the access token. Short-lived by nature; no reason
 *                           to persist it past the browser session.
 *   NOWHERE                 the master key and the master PIN. Neither token
 *                           can decrypt anything — the vault still opens only
 *                           when the PIN is typed and the key is derived in
 *                           memory. That invariant is unchanged by this file.
 * ============================================================================
 */

import { API_BASE_URL } from '../config.js';

const REFRESH_KEY = 'vaultly_refresh';
const USER_KEY = 'vaultly_user';
const TOKEN_KEY = 'vaultly_token';

/**
 * Endpoints that establish or replace a session. A 401 from one of these is a
 * real answer ("wrong password", "dead refresh token"), not an expired access
 * token, so it must never trigger a refresh-and-retry.
 */
const SESSION_PATHS = ['/auth/login', '/auth/register', '/auth/refresh', '/auth/logout'];
const isSessionPath = (path) => SESSION_PATHS.some((p) => path.startsWith(p));

/* ---------------------------------------------------------------- storage -- */

export async function getStoredIdentity() {
  const { [USER_KEY]: user, [REFRESH_KEY]: refreshToken } = await chrome.storage.local.get([
    USER_KEY,
    REFRESH_KEY,
  ]);
  return { user: user || null, refreshToken: refreshToken || null };
}

async function getAccessToken() {
  const { [TOKEN_KEY]: token } = await chrome.storage.session.get(TOKEN_KEY);
  return token || null;
}

/** Adopt a freshly issued session (from login, or from a refresh). */
export async function saveSession({ token, refreshToken, user }) {
  const local = {};
  if (refreshToken) local[REFRESH_KEY] = refreshToken;
  if (user) local[USER_KEY] = user;
  if (Object.keys(local).length) await chrome.storage.local.set(local);
  if (token) await chrome.storage.session.set({ [TOKEN_KEY]: token });
}

/** Forget everything. Identity included — this is a sign-out, not a lock. */
export async function clearSession() {
  await chrome.storage.local.remove([REFRESH_KEY, USER_KEY]);
  await chrome.storage.session.remove(TOKEN_KEY);
  // Keys used before this module existed; drop them so a stale token from an
  // older build can't be picked up after an update.
  await chrome.storage.session.remove(['authToken', 'userMeta']);
}

/** Sign out server-side too, so the refresh token dies with this device. */
export async function revokeSession() {
  const { [REFRESH_KEY]: refreshToken } = await chrome.storage.local.get(REFRESH_KEY);
  if (refreshToken) {
    // Fire and forget: a network failure must never block signing out.
    try {
      await fetch(`${API_BASE_URL}/auth/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
      });
    } catch {
      /* offline; the token expires on its own */
    }
  }
  await clearSession();
}

/* ---------------------------------------------------------------- refresh -- */

// Single-flight per context. Opening the popup fires several requests at once;
// if the access token has expired they all 401 together, and without this each
// would refresh — rotation would then make every response but the first
// invalidate the others, which is the exact race that logs people out.
let inFlight = null;

export function refreshSession() {
  if (!inFlight) {
    inFlight = requestNewAccessToken().finally(() => {
      inFlight = null;
    });
  }
  return inFlight;
}

async function requestNewAccessToken() {
  // Read from storage rather than a cached variable: the other context (popup
  // vs worker) may have rotated the token since we last looked.
  const { [REFRESH_KEY]: refreshToken } = await chrome.storage.local.get(REFRESH_KEY);
  if (!refreshToken) {
    const err = new Error('No refresh token');
    err.code = 'NO_REFRESH_TOKEN';
    throw err;
  }

  const res = await fetch(`${API_BASE_URL}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken }),
  });
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const err = new Error(data.message || 'Session expired');
    err.status = res.status;
    throw err;
  }

  await saveSession(data);
  return data.token;
}

/**
 * True when a failed refresh means the session is genuinely over, rather than
 * the network being unavailable. Dropping a still-valid session because a
 * request timed out is how you sign someone out on a train.
 */
export function isSessionDead(err) {
  return err?.code === 'NO_REFRESH_TOKEN' || err?.status === 401;
}

/* ------------------------------------------------------------------ fetch -- */

/**
 * The only way this extension should talk to the API. On a 401 it refreshes
 * once and replays the request; callers see the eventual success and never
 * learn that the token had expired.
 *
 * Throws with `.status` set. If the refresh itself fails, the thrown error
 * carries `.sessionDead = true` so the caller can decide what that means in
 * its own context (the worker locks; the popup routes to a sign-in screen).
 */
export async function apiFetch(path, options = {}, retried = false) {
  const token = await getAccessToken();

  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });

  if (res.status === 401 && !retried && !isSessionPath(path)) {
    try {
      await refreshSession();
    } catch (refreshErr) {
      const err = new Error(
        isSessionDead(refreshErr)
          ? 'Your session expired. Sign in again.'
          : "Couldn't reach Vaultly. Check your connection."
      );
      err.status = 401;
      err.sessionDead = isSessionDead(refreshErr);
      throw err;
    }
    return apiFetch(path, options, true);
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.message || 'Request failed');
    err.status = res.status;
    // A 401 that survived the retry means the fresh token was rejected too.
    if (res.status === 401 && retried) err.sessionDead = true;
    throw err;
  }
  return data;
}
