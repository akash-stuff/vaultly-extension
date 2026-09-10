/**
 * ============================================================================
 * FILE 3/5 — SEARCH & SORT  (Feature 12 "Search" + Feature 13 "Recent")
 * ============================================================================
 * Pure functions for the popup's instant filter box and the Recent/Most/Last
 * views. No DOM, no chrome.* — unit-testable.
 *
 * Feature 13 needs usage metadata that the current backend doesn't track yet.
 * These helpers read optional `useCount` and `lastUsedAt` fields and degrade
 * gracefully when they're absent (treated as 0 / epoch). See the WIRING note
 * for the small backend migration that lights them up.
 * ============================================================================
 */

/**
 * Instant, case-insensitive filter across website name, URL, and username.
 * Ranks better matches first: exact > startsWith > word-boundary > substring.
 *
 * @param {Array<{websiteName,websiteUrl,username}>} items
 * @param {string} query
 * @returns {Array} filtered + ranked copy (original array untouched)
 */
export function searchItems(items, query) {
  const q = (query || '').trim().toLowerCase();
  if (!q) return items.slice();

  const scored = [];
  for (const it of items) {
    const fields = [it.websiteName, it.websiteUrl, it.username].map((f) => (f || '').toLowerCase());
    let best = Infinity;
    for (const f of fields) {
      if (!f.includes(q)) continue;
      if (f === q) best = Math.min(best, 0);
      else if (f.startsWith(q)) best = Math.min(best, 1);
      else if (new RegExp('\\b' + escapeRegExp(q)).test(f)) best = Math.min(best, 2);
      else best = Math.min(best, 3);
    }
    if (best !== Infinity) scored.push({ it, best });
  }
  // Stable sort by rank, then alphabetically by site name.
  scored.sort((a, b) => a.best - b.best || (a.it.websiteName || '').localeCompare(b.it.websiteName || ''));
  return scored.map((s) => s.it);
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---------------------------------------------------------------------------
// Feature 13 — Recent / Most / Last used
// ---------------------------------------------------------------------------

const ts = (v) => (v ? new Date(v).getTime() : 0);

/** Most recently CREATED/UPDATED first (uses updatedAt; always available). */
export function sortByRecent(items) {
  return items.slice().sort((a, b) => ts(b.updatedAt) - ts(a.updatedAt));
}

/** Most FREQUENTLY used first (needs useCount; falls back to 0). */
export function sortByMostUsed(items) {
  return items.slice().sort((a, b) => (b.useCount || 0) - (a.useCount || 0) || ts(b.lastUsedAt) - ts(a.lastUsedAt));
}

/** Most recently USED first (needs lastUsedAt; falls back to updatedAt). */
export function sortByLastUsed(items) {
  return items.slice().sort((a, b) => (ts(b.lastUsedAt) || ts(b.updatedAt)) - (ts(a.lastUsedAt) || ts(a.updatedAt)));
}

/** Convenience: top-N of any view. */
export function topN(items, n = 5) {
  return items.slice(0, n);
}

/*
 * WIRING to make Feature 13 fully live (small backend change):
 *
 * 1) models/VaultItem.js — add:
 *      useCount:   { type: Number, default: 0 },
 *      lastUsedAt: { type: Date, default: null },
 *
 * 2) routes/vault.js — add an endpoint the extension calls on fill:
 *      router.post('/:id/used', async (req, res) => {
 *        await VaultItem.updateOne(
 *          { _id: req.params.id, userId: req.user.id },
 *          { $inc: { useCount: 1 }, $set: { lastUsedAt: new Date() } }
 *        );
 *        res.json({ ok: true });
 *      });
 *
 * 3) background.js — after a successful autofill (GET_CREDENTIAL), fire:
 *      api(`/vault/${id}/used`, { method: 'POST' });   // non-blocking
 *
 * Until then, sortByRecent works today; the other two just group everything
 * with equal (zero) usage and fall back to updatedAt order.
 */
