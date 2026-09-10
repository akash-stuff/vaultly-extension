/**
 * ============================================================================
 * FILE 5/5 — PRIVACY-PRESERVING FAVICON CACHE  (Feature 11, hardened)
 * ============================================================================
 * Problem this fixes: calling https://www.google.com/s2/favicons?domain=<site>
 * for every vault row leaks your list of saved sites to Google — a real
 * metadata leak for a zero-knowledge product. This module:
 *
 *   1. Serves favicons from a local cache in chrome.storage.local (as data
 *      URLs), so a given domain is fetched at most once.
 *   2. Prefers the SITE'S OWN /favicon.ico (no third party sees your vault),
 *      falling back to the Google s2 service only if you opt in.
 *   3. De-duplicates concurrent requests for the same domain.
 *
 * Because the extension has host_permissions for http/https, fetching a site's
 * own favicon from the background/popup avoids page-context CORS issues.
 *
 * Usage:
 *   import { getFaviconDataUrl } from './shared/faviconCache.js';
 *   img.src = await getFaviconDataUrl('github.com');   // data: URL, cached
 * ============================================================================
 */

const CACHE_PREFIX = 'favicon:';
const TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const inflight = new Map(); // domain -> Promise (de-dupe concurrent fetches)

// Set to true to allow the Google s2 fallback (leaks domain to Google).
const ALLOW_GOOGLE_FALLBACK = false;

/** Transparent 1x1 PNG used when no favicon can be found. */
const BLANK =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

export async function getFaviconDataUrl(domain) {
  const host = normalize(domain);
  if (!host) return BLANK;

  const key = CACHE_PREFIX + host;
  const cached = await readCache(key);
  if (cached && Date.now() - cached.at < TTL_MS) return cached.data;

  if (inflight.has(host)) return inflight.get(host);
  const p = fetchAndCache(host, key).catch(() => BLANK);
  inflight.set(host, p);
  try { return await p; } finally { inflight.delete(host); }
}

async function fetchAndCache(host, key) {
  const candidates = [
    `https://${host}/favicon.ico`,
    `https://${host}/apple-touch-icon.png`,
  ];
  if (ALLOW_GOOGLE_FALLBACK) {
    candidates.push(`https://www.google.com/s2/favicons?domain=${encodeURIComponent(host)}&sz=32`);
  }

  for (const url of candidates) {
    try {
      const res = await fetch(url, { credentials: 'omit', redirect: 'follow' });
      if (!res.ok) continue;
      const blob = await res.blob();
      if (!blob.type.startsWith('image/') || blob.size === 0) continue;
      const dataUrl = await blobToDataUrl(blob);
      await writeCache(key, { at: Date.now(), data: dataUrl });
      return dataUrl;
    } catch { /* try next candidate */ }
  }
  await writeCache(key, { at: Date.now(), data: BLANK }); // cache misses too
  return BLANK;
}

function normalize(d) {
  return String(d || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split(/[/?#:]/)[0];
}

function blobToDataUrl(blob) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => resolve(fr.result);
    fr.onerror = reject;
    fr.readAsDataURL(blob);
  });
}

async function readCache(key) {
  try { const o = await chrome.storage.local.get(key); return o[key] || null; } catch { return null; }
}
async function writeCache(key, value) {
  try { await chrome.storage.local.set({ [key]: value }); } catch { /* quota/absent: non-fatal */ }
}

/** Clear all cached favicons (e.g. from a settings "clear cache" button). */
export async function clearFaviconCache() {
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter((k) => k.startsWith(CACHE_PREFIX));
  if (keys.length) await chrome.storage.local.remove(keys);
}

/*
 * WIRING: replace the direct Google URLs in popup.js and content.js.
 *   popup.js:   fav.src = await getFaviconDataUrl(domain);
 *   content.js: content scripts can't import ES modules, so either (a) ask the
 *     background for the data URL via a message, or (b) keep the direct favicon
 *     there and only privacy-harden the popup/dashboard, which is where the
 *     full site list is actually rendered.
 */
