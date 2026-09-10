/**
 * ============================================================================
 * DOMAIN MATCHING (Feature 5)
 * ============================================================================
 * A password manager must decide "does saved entry X belong to the page the
 * user is currently on?". Getting this wrong is a security problem in BOTH
 * directions:
 *   - Too loose  -> you offer google.com credentials on evil-google.com.
 *   - Too strict -> mail.google.com won't match a login saved on
 *                   accounts.google.com and the user thinks autofill is broken.
 *
 * We match on the *registrable domain* (a.k.a. eTLD+1): the domain one label
 * below the public suffix. e.g. the registrable domain of
 * `accounts.google.co.uk` is `google.co.uk`, not `co.uk`.
 *
 * A fully correct implementation uses the Public Suffix List (PSL). Shipping
 * the entire ~10k-entry PSL into a content script is heavy, so we embed the
 * common multi-part suffixes that cover the overwhelming majority of real
 * traffic, and fall back to "last two labels" otherwise. This is a pragmatic
 * subset — see NOTE at the bottom for how to upgrade to the full PSL.
 * ============================================================================
 */

// Common multi-label public suffixes. Not exhaustive, but covers the sites
// people actually log into. Kept as a Set for O(1) lookups.
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'net.uk', 'sch.uk',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.za', 'org.za', 'net.za',
  'com.mx', 'com.sg', 'com.hk', 'com.tw', 'com.tr', 'com.ua', 'com.ar',
  'co.kr', 'or.kr',
  'com.ph', 'com.my', 'com.vn', 'com.pk', 'com.ng', 'com.eg',
]);

/**
 * Normalize a raw URL/host string into a bare, lowercased hostname.
 * Accepts full URLs ("https://mail.google.com/inbox?x=1"), bare hosts
 * ("mail.google.com"), or hosts with a leading "www.".
 * Returns '' for anything unparseable.
 */
export function normalizeHost(input) {
  if (!input || typeof input !== 'string') return '';
  let host = input.trim().toLowerCase();

  // If it looks like a URL, let the URL parser pull the hostname out.
  if (host.includes('://')) {
    try {
      host = new URL(host).hostname;
    } catch {
      return '';
    }
  } else {
    // Bare host possibly with a path/port glued on: strip everything after
    // the first '/', '?', '#', or ':'.
    host = host.split(/[/?#:]/)[0];
  }

  // Drop a single leading "www." — it is never security-significant.
  host = host.replace(/^www\./, '');

  // Strip a trailing dot (fully-qualified form: "google.com.").
  host = host.replace(/\.$/, '');

  return host;
}

/**
 * Return the registrable domain (eTLD+1) for a URL or host.
 *   accounts.google.com      -> google.com
 *   mail.google.co.uk        -> google.co.uk
 *   github.com               -> github.com
 *   localhost                -> localhost   (single label, returned as-is)
 *   192.168.0.1              -> 192.168.0.1 (IP literals returned as-is)
 */
export function getRootDomain(input) {
  const host = normalizeHost(input);
  if (!host) return '';

  // IP literals and single-label hosts (localhost) have no registrable
  // domain concept — return them unchanged so they still match themselves.
  if (isIpLiteral(host)) return host;

  const labels = host.split('.');
  if (labels.length <= 2) return host;

  // Check whether the last two labels form a known multi-label public suffix
  // (e.g. "co.uk"); if so the registrable domain is the last THREE labels.
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) {
    return labels.slice(-3).join('.');
  }

  // Default: registrable domain is the last two labels.
  return labels.slice(-2).join('.');
}

/**
 * Do two URLs/hosts belong to the same registrable domain?
 * This is the check used to decide whether a saved credential should be
 * offered on the current page. Subdomains of the same site match; unrelated
 * sites (and look-alikes like "google.com.evil.com") do not.
 */
export function isSameSite(a, b) {
  const rootA = getRootDomain(a);
  const rootB = getRootDomain(b);
  return rootA !== '' && rootA === rootB;
}

/** True for IPv4/IPv6 literals, which have no registrable-domain concept. */
function isIpLiteral(host) {
  // IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
  // IPv6 (brackets already stripped by URL parsing; also handle bare form)
  if (host.includes(':')) return true;
  return false;
}

/**
 * NOTE — upgrading to the full Public Suffix List:
 * Replace MULTI_LABEL_SUFFIXES + getRootDomain with the `tldts` package
 * (`import { getDomain } from 'tldts'`). It bundles the full PSL and handles
 * private suffixes (e.g. *.github.io, *.vercel.app) correctly, which the
 * subset above does not. Kept out here to avoid a heavy content-script
 * dependency; swap it in if you bundle the extension with a build step.
 */
