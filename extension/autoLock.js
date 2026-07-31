/**
 * ============================================================================
 * FILE 4/5 — AUTO-LOCK  (Feature 15)
 * ============================================================================
 * Locks the in-memory vault after a configurable idle period, on browser
 * startup, and (best-effort) on system sleep. Imported by the background
 * service worker; it does NOT hold any secrets itself — it just calls the
 * `onLock` callback you provide, which should clear the worker's key/vault.
 *
 * Why chrome.alarms and not setTimeout: MV3 service workers are frequently
 * suspended, which would silently cancel a setTimeout. chrome.alarms survives
 * suspension and wakes the worker to fire — the correct primitive here.
 *
 * Timeout options the spec asks for: 5 / 10 / 30 / 60 min, plus "on restart"
 * (handled by onStartup) and "on sleep" (handled via chrome.idle).
 *
 * Usage (background.js):
 *   import { initAutoLock, noteActivity } from './shared/autoLock.js';
 *   initAutoLock({
 *     onLock: () => lock(),                       // your existing lock()
 *     getTimeoutMinutes: async () => (await chrome.storage.local.get('autoLockMins')).autoLockMins ?? 15,
 *   });
 *   // call noteActivity() whenever the user interacts (unlock, autofill, save).
 * ============================================================================
 */

const ALARM_NAME = 'vaultly_autolock';
let cfg = { onLock: () => {}, getTimeoutMinutes: async () => 15 };

export function initAutoLock(options) {
  cfg = { ...cfg, ...options };

  // Fire the lock when the alarm elapses.
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === ALARM_NAME) cfg.onLock();
  });

  // Lock on browser startup / fresh install of the worker (Feature 15: "restart").
  if (chrome.runtime.onStartup) chrome.runtime.onStartup.addListener(() => cfg.onLock());

  // Lock when the OS goes idle/locked (Feature 15: "sleep"), if available.
  if (chrome.idle && chrome.idle.onStateChanged) {
    // 60s detection threshold; 'locked' = screen locked, 'idle' = no input.
    try { chrome.idle.setDetectionInterval(60); } catch { /* optional */ }
    chrome.idle.onStateChanged.addListener((state) => {
      if (state === 'locked') cfg.onLock();
    });
  }
}

/** (Re)start the idle countdown. Call on any meaningful user activity. */
export async function noteActivity() {
  const mins = Math.max(1, Number(await cfg.getTimeoutMinutes()) || 15);
  // A single non-repeating alarm; scheduling again replaces the old one.
  chrome.alarms.create(ALARM_NAME, { delayInMinutes: mins });
}

/** Cancel the countdown (e.g. after an explicit manual lock). */
export function cancelAutoLock() {
  chrome.alarms.clear(ALARM_NAME);
}

/*
 * NOTE — the chrome.idle sleep hook needs the "idle" permission in manifest.json:
 *   "permissions": [ ..., "idle" ]
 * chrome.alarms needs the "alarms" permission:
 *   "permissions": [ ..., "alarms" ]
 * Both are low-risk. Without "idle" the module still works (idle hook is guarded);
 * without "alarms" the timed lock won't schedule.
 */
