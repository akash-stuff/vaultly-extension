/**
 * ============================================================================
 * MASTER PIN MODE — how often Vaultly asks for the PIN
 * ============================================================================
 * THE PROBLEM
 *
 * An MV3 service worker is killed after ~30 seconds of inactivity, and the
 * master key lives only in that worker's memory. So the "unlocked session"
 * the rest of this extension talks about is, in practice, about half a minute
 * long. Every consequence of that lands on the user:
 *
 *   - the popup opens on the PIN screen again and again, minutes apart;
 *   - the content script's autofill suggestions and "Save login?" prompt go
 *     quiet mid-browse, because the worker that answers them woke up locked.
 *
 * THE PIN CANNOT BE "TURNED OFF" IN THE LITERAL SENSE — it IS the key. Nothing
 * decrypts without it. What the user can choose is WHERE IT IS KEPT, which is
 * the same thing from where they sit, and three honest answers exist:
 *
 *   'always'             Kept nowhere. Typed whenever the worker has died.
 *                        Zero-knowledge in the strictest sense.
 *   'session' (default)  Kept in chrome.storage.session: memory-backed, never
 *                        written to disk, wiped when the browser closes AND
 *                        whenever the extension is reloaded or updated. The
 *                        vault survives the worker, not the browser.
 *   'never'              Kept in chrome.storage.local: survives restarts, so
 *                        the PIN prompt is gone until you lock or sign out.
 *                        This writes the PIN TO DISK — see the warning below.
 *
 * WHAT 'never' ACTUALLY COSTS, stated plainly
 *
 * The PIN sits in the extension's storage inside the Chrome profile folder. It
 * is not encrypted there, because anything that could decrypt it would have to
 * live on the same disk beside it; a lock whose key is taped to the door is
 * theatre, and we would rather say the true thing. So in this mode:
 *
 *   - anyone who can use this computer while logged into this OS account can
 *     open the vault;
 *   - anyone who can read the Chrome profile directory — a backup, a stolen
 *     laptop with no disk encryption, another admin account — can recover the
 *     PIN and therefore everything in the vault.
 *
 * The server still never sees the PIN, the key, or any plaintext, and the
 * vault on the server is still ciphertext we cannot read. The zero-knowledge
 * promise to the SERVER is intact; the promise to anyone holding the DEVICE is
 * what this mode gives up. That is a reasonable trade on a machine only you
 * can log into, and a bad one on a shared one, which is why it is a choice,
 * off by default, and spelled out at the point of turning it on.
 * ============================================================================
 */

/** The mode. Survives restarts — it is a choice, not a secret. */
const MODE_KEY = 'vaultly_pin_mode';
/** The preference this replaced: true meant what 'session' now means. */
const LEGACY_KEY = 'vaultly_stay_unlocked';
/** The PIN itself, in session or local storage depending on the mode. */
const PIN_KEY = 'vaultly_session_pin';

export const PIN_MODES = ['always', 'session', 'never'];
/**
 * 'session', not 'always'. Chrome kills the worker after about 30 seconds, so
 * 'always' means "type your PIN every few minutes" — which reads as a bug
 * rather than as a security posture, and sends people looking for a setting
 * they should not have had to find. 'session' keeps one unlock alive for one
 * browser session, writes nothing to disk, and still forgets everything when
 * the browser closes or the vault is locked. 'always' remains one tap away in
 * Settings for anyone who wants the strictest behaviour.
 */
export const DEFAULT_PIN_MODE = 'session';

/**
 * Pages must never be able to read the PIN. TRUSTED_CONTEXTS is already the
 * default for session storage; saying so out loud costs one call and removes
 * the dependency on that staying true.
 */
export function hardenSessionStorage() {
  try {
    // Promise-returning in current Chrome, throwing in older builds: both
    // failure shapes end the same way, and the default is TRUSTED_CONTEXTS
    // anyway, so there is nothing to recover from.
    const r = chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
    if (r && typeof r.catch === 'function') r.catch(() => {});
  } catch {
    /* older Chrome: the default is already TRUSTED_CONTEXTS */
  }
}

export async function getPinMode() {
  const stored = await chrome.storage.local.get([MODE_KEY, LEGACY_KEY]);
  const mode = stored[MODE_KEY];
  if (PIN_MODES.includes(mode)) return mode;
  // Carried over from the boolean this setting used to be, so an existing
  // choice is not silently reset by an update — in EITHER direction. Someone
  // who deliberately turned "stay signed in" off still means 'always', even
  // though 'always' is no longer what a fresh install gets.
  if (stored[LEGACY_KEY] === true) return 'session';
  if (stored[LEGACY_KEY] === false) return 'always';
  return DEFAULT_PIN_MODE;
}

/**
 * Change the mode. Any PIN held under the old mode is dropped first: both
 * other modes mean "stop keeping it where it was", and "from the next lock
 * onwards" is not what anyone means by that. The vault stays unlocked either
 * way — this changes what survives, not whether you are signed in right now.
 */
export async function setPinMode(mode) {
  const next = PIN_MODES.includes(mode) ? mode : DEFAULT_PIN_MODE;
  await forgetPin();
  await chrome.storage.local.set({ [MODE_KEY]: next });
  await chrome.storage.local.remove(LEGACY_KEY);
  return next;
}

/** Which storage area the PIN belongs in, or null when it belongs nowhere. */
function areaFor(mode) {
  if (mode === 'session') return chrome.storage.session;
  if (mode === 'never') return chrome.storage.local;
  return null;
}

/** Keep the PIN for later, per the current mode. A no-op under 'always'. */
export async function rememberPin(pin) {
  if (!pin) return false;
  const area = areaFor(await getPinMode());
  if (!area) return false;
  await area.set({ [PIN_KEY]: pin });
  return true;
}

/**
 * The PIN to re-derive with, or null. Reads only the area the CURRENT mode
 * allows, so a value left behind by a mode that has since been switched off
 * can never unlock a vault the user has told us not to keep open.
 */
export async function getRememberedPin() {
  const mode = await getPinMode();
  const area = areaFor(mode);
  if (!area) {
    await forgetPin();
    return null;
  }
  const { [PIN_KEY]: pin } = await area.get(PIN_KEY);
  return pin || null;
}

/** Drop the PIN from BOTH areas — callers mean "it is kept nowhere now". */
export async function forgetPin() {
  try {
    await chrome.storage.session.remove(PIN_KEY);
  } catch {
    /* session storage unavailable */
  }
  try {
    await chrome.storage.local.remove(PIN_KEY);
  } catch {
    /* nothing stored */
  }
}
