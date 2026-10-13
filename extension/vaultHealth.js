/**
 * ============================================================================
 * FILE 1/5 — VAULT HEALTH SCANNER  (Features 18 "Security Dashboard" & 19)
 * ============================================================================
 * Pure logic. Input is the DECRYPTED vault (the background worker already holds
 * this when unlocked); output is a report the popup/dashboard renders. No
 * network, no DOM, no chrome.* — so it's trivially unit-testable.
 *
 * Definitions:
 *   weak      — estimateStrength score < 2 (i.e. "Weak")
 *   reused    — the same password used across 2+ DIFFERENT sites (registrable
 *               domain differs). This is the dangerous one: one breach → many.
 *   duplicate — 2+ vault entries that are identical (same site + username +
 *               password). Usually accidental double-saves; safe to merge.
 *   old       — not updated in `oldAfterDays` (default 365).
 *
 * Usage:
 *   import { scanVault } from './shared/vaultHealth.js';
 *   const report = scanVault(decryptedItems);
 * ============================================================================
 */

import { estimateStrength } from './passwordUtils.js';
import { getRootDomain } from './domainUtils.js';

/**
 * @param {Array<{id,websiteName,websiteUrl,username,password,updatedAt}>} items
 * @param {object} [opts]
 * @param {number} [opts.oldAfterDays=365]
 * @param {number} [opts.now=Date.now()]  injectable clock for testing
 * @returns {{
 *   total:number,
 *   weak:string[], reused:string[], duplicate:string[], old:string[],
 *   healthScore:number,             // 0..100, higher is healthier
 *   perItem: Record<string,{strength:string, bits:number, isWeak:boolean, isReused:boolean, isDuplicate:boolean, isOld:boolean}>
 * }}
 */
export function scanVault(items, opts = {}) {
  const oldAfterDays = opts.oldAfterDays ?? 365;
  const now = opts.now ?? Date.now();
  const oldCutoff = now - oldAfterDays * 24 * 60 * 60 * 1000;

  const list = Array.isArray(items) ? items : [];
  const perItem = {};

  // --- password -> set of registrable domains it's used on (for "reused") ---
  const domainsByPassword = new Map();
  // --- exact (site|user|pw) signature -> [ids] (for "duplicate") ---
  const bySignature = new Map();

  for (const it of list) {
    const root = getRootDomain(it.websiteUrl || it.websiteName || '');
    if (!domainsByPassword.has(it.password)) domainsByPassword.set(it.password, new Set());
    domainsByPassword.get(it.password).add(root);

    const sig = `${root}\u0000${(it.username || '').toLowerCase()}\u0000${it.password}`;
    if (!bySignature.has(sig)) bySignature.set(sig, []);
    bySignature.get(sig).push(it.id);
  }

  const weak = [], reused = [], duplicate = [], old = [];

  for (const it of list) {
    const s = estimateStrength(it.password || '');
    const isWeak = s.score < 2;

    // Reused: this exact password appears on 2+ distinct registrable domains.
    const domains = domainsByPassword.get(it.password);
    const isReused = !!it.password && domains && domains.size > 1;

    // Duplicate: its exact signature group has more than one entry.
    const root = getRootDomain(it.websiteUrl || it.websiteName || '');
    const sig = `${root}\u0000${(it.username || '').toLowerCase()}\u0000${it.password}`;
    const isDuplicate = (bySignature.get(sig) || []).length > 1;

    // Old: updatedAt older than the cutoff (missing timestamp => not counted).
    const ts = it.updatedAt ? new Date(it.updatedAt).getTime() : null;
    const isOld = ts != null && ts < oldCutoff;

    perItem[it.id] = { strength: s.label, bits: s.bits, isWeak, isReused, isDuplicate, isOld };
    if (isWeak) weak.push(it.id);
    if (isReused) reused.push(it.id);
    if (isDuplicate) duplicate.push(it.id);
    if (isOld) old.push(it.id);
  }

  // Simple 0..100 health score: start at 100, subtract weighted penalties.
  const total = list.length;
  let healthScore = 100;
  if (total > 0) {
    const pct = (n) => n / total;
    healthScore -= pct(weak.length) * 40;      // weak passwords hurt most
    healthScore -= pct(reused.length) * 35;    // reuse is nearly as bad
    healthScore -= pct(duplicate.length) * 10;
    healthScore -= pct(old.length) * 15;
    healthScore = Math.max(0, Math.round(healthScore));
  }

  return { total, weak, reused, duplicate, old, healthScore, perItem };
}

/*
 * WIRING (background.js):
 *   import { scanVault } from './shared/vaultHealth.js';
 *   // add a message case:
 *   case 'GET_HEALTH':
 *     sendResponse(scanVault([...vault.values()]));
 *     break;
 * Then render report.healthScore + the four count lists in a dashboard view.
 *
 * NOTE — "Compromised" (Feature 19, future): check passwords against Have I
 * Been Pwned using k-anonymity (SHA-1 the password, send only the first 5 hex
 * chars to api.pwnedpasswords.com/range/<prefix>, compare suffixes locally).
 * The full password never leaves the device. Add as `breached` once ready.
 */
