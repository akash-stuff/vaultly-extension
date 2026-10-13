/**
 * ============================================================================
 * CONTENT SCRIPT — form detection + in-page autofill UI + save prompts
 * ============================================================================
 * SECURITY POSTURE:
 *   - This script never holds the vault, the master key, or more than the ONE
 *     credential or card the user actively chose to fill. It asks the background
 *     worker for matches (labels only) and fetches a single plaintext secret
 *     only on an explicit user click.
 *   - All Vaultly UI is rendered inside a closed-ish Shadow DOM host so the
 *     page's CSS can't restyle it and page scripts can't easily walk into it.
 *   - Note the inherent limit of ALL autofill: once a value is placed in a
 *     page <input>, page JavaScript can read that field. That's unavoidable
 *     for any autofill tool; we mitigate by filling only on explicit action
 *     and only the chosen item — never the whole vault. For cards the worker
 *     additionally refuses to hand anything to an http:// page, and never
 *     hands over the card's ATM PIN at all.
 *
 * Content scripts run as classic scripts (no ES module import), so the small
 * password generator and the card brand palette below are inlined and mirror
 * shared/passwordUtils.js and shared/cards.js.
 * ============================================================================
 */
(() => {
  'use strict';

  // This script runs in EVERY frame (manifest: all_frames), because card fields
  // usually live in a cross-origin payment iframe — Stripe Elements and friends
  // — and without that, card autofill silently does nothing on most real
  // checkouts. The save-login prompt is a page-level thing, so it stays gated to
  // the top frame; the suggestion dropdown anchors inside whichever frame the
  // user is actually typing in.
  const IS_TOP = window.top === window;

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

  // ---- brand palette (mirror of shared/cards.js BRAND_COLORS) -------------
  // Dark, text-safe base + the bright brand hue used only as a corner bloom,
  // exactly as the web app's card plate does it, so a card is recognisable by
  // colour in the dropdown before you have read a single character.
  const BRAND_COLORS = {
    visa: ['27 42 122', '59 107 255'],
    mastercard: ['51 38 42', '247 158 27'],
    amex: ['4 38 55', '127 212 245'],
    rupay: ['9 64 44', '246 148 30'],
    discover: ['74 42 18', '247 107 28'],
    diners: ['12 61 100', '77 159 224'],
    jcb: ['18 58 107', '224 51 74'],
    unionpay: ['0 74 99', '224 51 74'],
    other: ['53 59 77', '139 147 168'],
  };

  // ---- login field detection (Feature 1) ----
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
  // TWO-FACTOR (TOTP) FIELDS
  // =========================================================================
  /**
   * The code box is harder to find than a password box: there is no input type
   * for it, and the markup ranges from one <input maxlength="6"> to six
   * single-character boxes in a row.
   *
   *  1. autocomplete="one-time-code" is the spec's answer and is trusted
   *     wherever it appears.
   *  2. Otherwise a name/id/placeholder/label pattern, AND a shape that could
   *     hold a code (short, or numeric). A bare "code" field on a checkout is
   *     a discount box, so the shape test is what keeps this off it.
   *  3. Card fields are excluded outright. A CVV is a short numeric input
   *     called "security code" — every word of the pattern above — and
   *     putting a login code into one would be both wrong and expensive.
   */
  // "security code" is deliberately NOT in here: it is the CVV's own phrase,
  // and a few banks using it for a login code is not worth the chance of
  // typing a one-time code into a payment field. "verification code" IS both,
  // and is disambiguated below by whether a card form surrounds it.
  const OTP_NAME_RE = /(otp|totp|mfa|2fa|twofactor|two[-_. ]?factor|authenticator|auth[-_. ]?code|one[-_. ]?time|onetime|verification[-_. ]?code|verify[-_. ]?code|sms[-_. ]?code|login[-_. ]?code|passcode|pin[-_. ]?code)/i;

  function hasOneTimeCodeToken(el) {
    return (el.getAttribute('autocomplete') || '')
      .toLowerCase().split(/\s+/).includes('one-time-code');
  }

  /** Could this input hold a 6-to-8 character code? */
  function codeShaped(el) {
    const len = parseInt(el.getAttribute('maxlength') || '0', 10);
    if (len >= 4 && len <= 10) return true;
    const mode = (el.getAttribute('inputmode') || '').toLowerCase();
    if (mode === 'numeric' || mode === 'tel') return true;
    return el.type === 'tel' || el.type === 'number';
  }

  /** Shared guard: something a code could actually be typed into. */
  function fillableCodeInput(el) {
    if (!(el instanceof HTMLInputElement)) return false;
    if (!isVisible(el) || el.disabled || el.readOnly) return false;
    // A password box is the first factor, never the second.
    if (el.type === 'password') return false;
    return ['text', 'tel', 'number', 'search', ''].includes(el.type);
  }

  function isOtpInput(el) {
    if (!fillableCodeInput(el)) return false;
    if (hasOneTimeCodeToken(el)) return true;
    if (!OTP_NAME_RE.test(fieldHaystack(el)) || !codeShaped(el)) return false;
    // The card detector also claims "verification code", because at a checkout
    // that is the CVV. What tells the two apart is the company it keeps: a CVV
    // has a card number, an expiry or another declared cc-* field somewhere
    // around it, and a login code has none of that.
    if (isCardInput(el)) {
      const f = findCardFields(el, false);
      if (f.numbers.length > 0 || f.exp || f.month || f.year || f.name) return false;
    }
    return true;
  }

  /**
   * Six boxes of one character each, which is how most modern sites render it.
   * Recognised as a GROUP rather than individually, because no single box of
   * the six carries a name worth matching — their shape and their shared
   * parent are the only signal there is.
   */
  function segmentGroupFor(el) {
    const parent = el && el.parentElement;
    if (!parent) return null;
    const sibs = Array.from(parent.querySelectorAll('input')).filter(
      (i) => fillableCodeInput(i) && parseInt(i.getAttribute('maxlength') || '0', 10) === 1
    );
    return sibs.length >= 4 && sibs.length <= 10 && sibs.includes(el) ? sibs : null;
  }

  function findOtpTarget(root = document) {
    const inputs = Array.from(root.querySelectorAll('input')).filter(fillableCodeInput);
    // A declared one-time-code field wins over anything inferred.
    const declared = inputs.find(hasOneTimeCodeToken);
    const single = declared || inputs.find(isOtpInput);
    if (single) {
      const group = segmentGroupFor(single);
      return group ? { segments: group } : { single };
    }
    // Nothing named like a code: a row of single-character boxes still is one.
    for (const el of inputs) {
      if (parseInt(el.getAttribute('maxlength') || '0', 10) !== 1) continue;
      const group = segmentGroupFor(el);
      if (group) return { segments: group };
    }
    return null;
  }

  /** True when the code went in. */
  function fillOtp(code, target) {
    const t = target || findOtpTarget();
    if (!t || !code) return false;
    if (t.segments) {
      const boxes = t.segments;
      if (boxes.length < code.length) return false;
      code.split('').forEach((ch, i) => setNativeValue(boxes[i], ch));
      // Some implementations only advance (and only submit) on key events in
      // the last box, so leave the caret where a human would have left it.
      const last = boxes[Math.min(code.length, boxes.length) - 1];
      try { last.focus(); } catch { /* detached */ }
      return true;
    }
    setNativeValue(t.single, code);
    try { t.single.focus(); } catch { /* detached */ }
    return true;
  }

  /**
   * A site asks for the code on the page AFTER the password, so the fill that
   * matters happens on a page the dropdown was never open on. Choosing a login
   * that has a second factor arms this; the next two-factor field to appear is
   * filled from it, once, and only for a couple of minutes.
   *
   * It holds an ID, not a code: by the time the second page renders, a code
   * captured on the first would often already have expired.
   */
  let armedTotp = null;         // { id, until }
  const ARMED_TOTP_MS = 3 * 60_000;

  function armTotp(id) {
    if (id) armedTotp = { id, until: Date.now() + ARMED_TOTP_MS };
  }
  function takeArmedTotp() {
    if (!armedTotp) return null;
    if (Date.now() > armedTotp.until) { armedTotp = null; return null; }
    return armedTotp.id;
  }

  async function autofillArmedTotp(target) {
    const id = takeArmedTotp();
    if (!id) return false;
    const t = target || findOtpTarget();
    if (!t) return false;
    // Don't overwrite something the user has already typed.
    const current = t.segments ? t.segments.map((b) => b.value).join('') : t.single.value;
    if (current && current.trim()) return false;

    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: 'GET_TOTP', id });
    } catch { return false; }
    if (!res || !res.ok) return false;
    if (!fillOtp(res.code, t)) return false;

    armedTotp = null;
    showToast({
      title: 'Two-factor code filled',
      meta: [`Valid for ${res.remaining}s. Vaultly generated it from your saved secret.`],
      primaryLabel: 'OK', ghostLabel: 'Dismiss',
    });
    return true;
  }

  // =========================================================================
  // CARD FIELD DETECTION
  // =========================================================================
  /**
   * Checkout forms are far less standardised than login forms, so detection is
   * layered rather than a single selector list:
   *
   *  1. `autocomplete` tokens (cc-number, cc-exp, cc-csc, ...) are the spec's
   *     answer and are authoritative wherever present. They can be prefixed
   *     ("section-pay billing cc-number"), so we token-split rather than
   *     compare the whole attribute.
   *  2. Failing that, STRICT name/id/placeholder/label patterns — ones that can
   *     only mean a card field ("cardnumber", "cvv", "expmonth").
   *  3. Only once step 1 or 2 has proved this really is a payment form do the
   *     LOOSE patterns run ("expiry", "name") on what's left. Running them
   *     unconditionally would claim a shipping "name" field on every page.
   *
   * That layering is why a bare <input name="number"> is ignored on a
   * newsletter page but picked up next to a CVV box.
   */
  const AC_TOKENS = {
    'cc-number': 'number',
    'cc-name': 'name',
    'cc-given-name': 'name',
    'cc-family-name': 'name',
    'cc-exp': 'exp',
    'cc-exp-month': 'month',
    'cc-exp-year': 'year',
    'cc-csc': 'csc',
  };

  const STRICT_RULES = [
    ['csc', /(cvv|cvc|csc|cvn|\bcid\b|securitycode|security[-_. ]code|card[-_. ]?code|verification[-_. ]?(code|number))/],
    ['month', /(exp[a-z_. -]*month|month[a-z_. -]*exp|ccmonth|cc[-_. ]?exp[-_. ]?mo|expiry[-_. ]?m\b)/],
    ['year', /(exp[a-z_. -]*year|year[a-z_. -]*exp|ccyear|cc[-_. ]?exp[-_. ]?yr?\b|expiry[-_. ]?y\b)/],
    ['number', /(cardnumber|card[-_. ]number|ccnumber|cc[-_. ]?num|credit[-_. ]?card|debit[-_. ]?card|\bpan\b|acct[-_. ]?num|card[-_. ]?no\b)/],
    ['name', /(cardholder|card[-_. ]?holder|name[-_. ]?on[-_. ]?card|card[-_. ]?name|ccname|holder[-_. ]?name)/],
  ];

  const LOOSE_RULES = [
    ['exp', /(expir|expiry|\bexp\b|mm[/ -]*yy)/],
    ['month', /\bmm\b|\bmonth\b/],
    ['year', /\byy(yy)?\b|\byear\b/],
    ['number', /\b(number|card)\b/],
    ['name', /\bname\b/],
  ];

  /** Everything a human would read to know what a field is for. */
  function fieldHaystack(el) {
    const bits = [
      el.name, el.id, el.getAttribute('placeholder'), el.getAttribute('aria-label'),
      el.getAttribute('autocomplete'), el.getAttribute('data-testid'), el.getAttribute('title'),
    ];
    // The visible label is often the ONLY hint on framework-generated forms
    // where name and id are hashes.
    if (el.labels) for (const l of el.labels) bits.push(l.textContent);
    return bits.filter(Boolean).join(' ').toLowerCase();
  }

  function isCardCandidate(el) {
    if (el instanceof HTMLSelectElement) return isVisible(el) && !el.disabled;
    if (!(el instanceof HTMLInputElement)) return false;
    const t = (el.type || 'text').toLowerCase();
    // `password` shows up for CVV boxes on a few banks; `month` is the native
    // expiry control.
    if (!['text', 'tel', 'number', 'password', 'month', 'search', ''].includes(t)) return false;
    return isVisible(el) && !el.disabled && !el.readOnly;
  }

  function matchRules(rules, hay) {
    for (const [kind, re] of rules) if (re.test(hay)) return kind;
    return null;
  }

  function assign(found, kind, el) {
    if (kind === 'number') { found.numbers.push(el); return; }
    // First match wins: on a page with several sections the one nearest the top
    // of the scanned scope is the one being filled in.
    if (!found[kind]) found[kind] = el;
  }

  /**
   * Classify every card-ish control under `root`.
   * Returns { numbers: [], name, exp, month, year, csc, confident }.
   */
  function collectCardFields(root) {
    const found = { numbers: [], name: null, exp: null, month: null, year: null, csc: null };
    const undecided = [];
    let confident = false;

    for (const el of root.querySelectorAll('input, select')) {
      if (!isCardCandidate(el)) continue;

      const ac = (el.getAttribute('autocomplete') || '').toLowerCase().split(/\s+/);
      let kind = null;
      for (const token of ac) if (AC_TOKENS[token]) { kind = AC_TOKENS[token]; break; }
      if (kind) confident = true;

      const hay = fieldHaystack(el);
      if (!kind) {
        kind = matchRules(STRICT_RULES, hay);
        // "cvv" or "cardnumber" in a field's own metadata is proof enough.
        if (kind === 'csc' || kind === 'number') confident = true;
        else if (kind) confident = confident || /card|credit|debit|payment/.test(hay);
      }

      if (kind) assign(found, kind, el);
      else undecided.push([el, hay]);
    }

    // Second pass: loose patterns, but only on a form we already believe is a
    // payment form. `exp` is where this earns its keep — "Expiry date" is a
    // single combined field on most gateways and matches nothing strict.
    if (confident) {
      for (const [el, hay] of undecided) {
        const kind = matchRules(LOOSE_RULES, hay);
        if (kind) assign(found, kind, el);
      }
    }

    found.confident = confident;
    return found;
  }

  /**
   * Card fields for a given anchor. Scoped to the anchor's own form first, so a
   * page with both a "saved card" block and a "new card" block fills the block
   * the user is actually typing in; falls back to the whole document for
   * gateways that omit <form> entirely (most of them, in practice).
   */
  function findCardFields(anchor, strictScope) {
    const form = anchor && anchor.closest ? anchor.closest('form') : null;
    if (form) {
      const scoped = collectCardFields(form);
      // `strictScope` stops at the anchor's own form even when that form turns
      // out NOT to be a payment form. Without it, a newsletter <form> with a
      // "Phone number" box inherited the confidence of the checkout form
      // elsewhere on the page and opened a card dropdown on it. The
      // document-wide fallback is for the common case of a gateway that renders
      // its fields with no <form> element at all.
      if (scoped.confident || strictScope) return scoped;
    }
    return collectCardFields(document);
  }

  function isCardInput(el) {
    if (!isCardCandidate(el)) return false;
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase().split(/\s+/);
    for (const token of ac) if (AC_TOKENS[token]) return true;
    const hay = fieldHaystack(el);
    if (matchRules(STRICT_RULES, hay)) return true;
    // A loose match only counts if the surrounding form is a payment form —
    // otherwise every "Name" input on the web would open a card dropdown.
    if (!matchRules(LOOSE_RULES, hay)) return false;
    const fields = findCardFields(el, true);
    return fields.confident && (
      fields.numbers.includes(el) || fields.name === el || fields.exp === el ||
      fields.month === el || fields.year === el || fields.csc === el
    );
  }

  // =========================================================================
  // CARD FILL
  // =========================================================================
  const fullYear = (y) => (Number(y) < 100 ? 2000 + Number(y) : Number(y));

  const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'];
  function monthName(m, short) {
    const name = MONTHS[Number(m) - 1] || '';
    return short ? name.slice(0, 3) : name;
  }

  function maxLen(el) {
    const n = el.maxLength;
    return n && n > 0 ? n : 0;
  }

  /**
   * Set a value on either an <input> or a <select>, trying each candidate
   * spelling until one of a select's options actually matches. Month and year
   * dropdowns are spelled every way imaginable — "3", "03", "March", "Mar",
   * "2028", "28" — so we hand over the alternatives rather than guess.
   */
  function setChoice(el, candidates) {
    const list = candidates.filter((v) => v != null && v !== '');
    if (!list.length) return false;

    if (el instanceof HTMLSelectElement) {
      const norm = (s) => String(s).trim().toLowerCase();
      const pick = (opt) => {
        el.value = opt.value;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
      };
      for (const want of list) {
        const w = norm(want);
        const opt = Array.from(el.options).find(
          (o) => norm(o.value) === w || norm(o.textContent) === w
        );
        if (opt) return pick(opt);
      }
      // Numeric fallback: an option whose digits match (handles "03 - March").
      const digits = String(list[0]).replace(/\D+/g, '');
      const opt = digits && Array.from(el.options).find(
        (o) => o.value.replace(/\D+/g, '') === digits || o.textContent.replace(/\D+/g, '') === digits
      );
      return opt ? pick(opt) : false;
    }

    setNativeValue(el, String(list[0]));
    return true;
  }

  /**
   * Render a combined expiry field the way THAT field wants it. The shape is
   * read off the control rather than assumed: a maxlength of 4 means "MMYY"
   * with no separator, type="month" means "YYYY-MM", and a placeholder
   * mentioning YYYY means the full year. Getting this wrong is the classic
   * autofill failure — "03/2028" into a 5-char box silently becomes "03/20".
   */
  function expiryString(el, month, year) {
    const mm = String(month).padStart(2, '0');
    const y4 = String(fullYear(year));
    const y2 = y4.slice(-2);
    if (el instanceof HTMLInputElement && el.type === 'month') return y4 + '-' + mm;

    const hint = ((el.getAttribute('placeholder') || '') + ' ' + (el.getAttribute('pattern') || '')).toLowerCase();
    const cap = maxLen(el);

    // Candidates in order of preference, narrowing as they go. The first one
    // that FITS wins — a maxlength is a hard wall, so "03 / 28" in a 5-char
    // box has to degrade to "03/28" rather than be chopped to "03 / ".
    const seps = [];
    if (/\s\/\s/.test(hint)) seps.push(' / ');
    if (hint.includes('-') && !hint.includes('/')) seps.push('-');
    seps.push('/', '');

    const wantsFullYear = /yyyy/.test(hint) || cap >= 7;
    const years = wantsFullYear ? [y4, y2] : [y2, y4];

    for (const y of years) {
      for (const sep of seps) {
        const out = mm + sep + y;
        if (!cap || out.length <= cap) return out;
      }
    }
    return mm + y2;
  }

  /**
   * Put a chosen card into the page. Returns the list of parts that took a
   * value, or null if nothing did — silence after a click reads as a broken
   * extension, so the caller says so instead.
   */
  function fillCard(card, anchor) {
    const f = findCardFields(anchor);
    const digits = String(card.number || '').replace(/\D+/g, '');
    const filled = [];

    // Some bank forms split the PAN across four 4-digit boxes.
    const split = f.numbers.length > 1 && f.numbers.every((el) => {
      const c = maxLen(el);
      return c > 0 && c <= 6;
    });
    if (split && digits) {
      let i = 0;
      for (const el of f.numbers) {
        const take = maxLen(el) || 4;
        setNativeValue(el, digits.slice(i, i + take));
        i += take;
      }
      filled.push('number');
    } else if (f.numbers[0] && digits) {
      // Digits only, never the spaced form: a box with maxlength="16" would
      // truncate "4242 4242 4242 4242" to "4242 4242 4242 4". Fields that
      // pretty-print do it themselves from the input events we dispatch.
      setNativeValue(f.numbers[0], digits);
      filled.push('number');
    }

    if (f.name && card.cardholderName) {
      setNativeValue(f.name, card.cardholderName);
      filled.push('name');
    }

    if (card.expMonth && card.expYear) {
      const mm = String(card.expMonth).padStart(2, '0');
      const y4 = String(fullYear(card.expYear));
      if (f.month && setChoice(f.month, [mm, String(Number(card.expMonth)), monthName(card.expMonth), monthName(card.expMonth, true)])) {
        filled.push('month');
      }
      if (f.year && setChoice(f.year, [y4, y4.slice(-2)])) filled.push('year');
      // A combined field is filled only when there is no month/year pair, so a
      // form offering both never receives two conflicting answers.
      if (f.exp && !f.month && !f.year) {
        setChoice(f.exp, [expiryString(f.exp, card.expMonth, card.expYear)]);
        filled.push('expiry');
      }
    }

    if (f.csc && card.cvv) {
      setNativeValue(f.csc, card.cvv);
      filled.push('security code');
    }

    return filled.length ? filled : null;
  }

  // =========================================================================
  // READING A CARD BACK OFF THE PAGE  (the "Save card?" prompt)
  // =========================================================================
  /* Mirrors passesLuhn() in shared/cards.js. Content scripts cannot import, and
     this is the gate that decides whether a prompt appears at all: without it
     the prompt fires at every keystroke and offers to save half-typed numbers. */
  function luhnOk(digits) {
    if (digits.length < 12) return false;
    let sum = 0;
    let double = false;
    for (let i = digits.length - 1; i >= 0; i -= 1) {
      let d = digits.charCodeAt(i) - 48;
      if (double) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      double = !double;
    }
    return sum % 10 === 0;
  }

  /* Display-only brand detection, so the prompt can say "Visa •••• 4242"
     without asking the worker first. The worker re-derives the brand from the
     digits when it saves, so this can never be what gets stored. */
  const BRAND_PATTERNS = [
    [/^3[47]/, 'amex', 'Amex'],
    [/^3(?:0[0-5]|[68])/, 'diners', 'Diners Club'],
    [/^35(?:2[89]|[3-8])/, 'jcb', 'JCB'],
    [/^62/, 'unionpay', 'UnionPay'],
    [/^(6521|6522|8172|8173|8174|8175|6069|6080|6081|6082)/, 'rupay', 'RuPay'],
    [/^(6011|64[4-9]|65)/, 'discover', 'Discover'],
    [/^(5[1-5]|2[2-7])/, 'mastercard', 'Mastercard'],
    [/^4/, 'visa', 'Visa'],
  ];
  function brandOf(digits) {
    for (const [re, id, label] of BRAND_PATTERNS) if (re.test(digits)) return { id, label };
    return { id: 'other', label: 'Card' };
  }

  const MONTH_NAMES = MONTHS.map((m) => m.toLowerCase());
  function monthFromValue(v) {
    const raw = String(v || '').trim().toLowerCase();
    if (!raw) return null;
    const digits = raw.replace(/\D+/g, '');
    if (digits) {
      const n = Number(digits.length > 2 ? digits.slice(-2) : digits);
      return n >= 1 && n <= 12 ? n : null;
    }
    const i = MONTH_NAMES.findIndex((m) => m === raw || m.slice(0, 3) === raw.slice(0, 3));
    return i >= 0 ? i + 1 : null;
  }
  function yearFromValue(v) {
    const digits = String(v || '').replace(/\D+/g, '');
    if (digits.length === 2) return 2000 + Number(digits);
    if (digits.length === 4) return Number(digits);
    return null;
  }

  /* An expiry is only believable if it is a real month within a sane window.
     A card that expired years ago, or in 2087, is a misread field. */
  function plausibleExpiry(m, y) {
    if (!m || !y || m < 1 || m > 12) return false;
    const thisYear = new Date().getFullYear();
    return y >= thisYear - 1 && y <= thisYear + 25;
  }

  function readExpiry(f) {
    if (f.month || f.year) {
      const m = monthFromValue(f.month && f.month.value);
      const y = yearFromValue(f.year && f.year.value);
      if (plausibleExpiry(m, y)) return { expMonth: m, expYear: y };
    }
    if (f.exp) {
      const v = String(f.exp.value || '').trim();
      const iso = v.match(/^(\d{4})-(\d{1,2})$/); // <input type="month">
      if (iso) {
        const m = Number(iso[2]);
        const y = Number(iso[1]);
        if (plausibleExpiry(m, y)) return { expMonth: m, expYear: y };
      }
      const digits = v.replace(/\D+/g, '');
      if (digits.length === 4 || digits.length === 6) {
        const m = Number(digits.slice(0, 2));
        const y = yearFromValue(digits.slice(2));
        if (plausibleExpiry(m, y)) return { expMonth: m, expYear: y };
      }
    }
    return { expMonth: null, expYear: null };
  }

  /**
   * What this page currently holds, or null if it isn't a finished card. Reads
   * the same fields fillCard() writes, so anything Vaultly can fill it can also
   * offer to save.
   */
  function readCardFromPage() {
    const f = collectCardFields(document);
    if (!f.confident) return null;

    // A split PAN is four boxes in DOM order; a single box is just itself.
    const digits = f.numbers.map((el) => String(el.value || '').replace(/\D+/g, '')).join('');
    if (!luhnOk(digits)) return null;

    const { expMonth, expYear } = readExpiry(f);
    const brand = brandOf(digits);
    const cvv = f.csc ? String(f.csc.value || '').replace(/\D+/g, '') : '';

    return {
      card: {
        number: digits,
        cvv,
        cardholderName: f.name ? String(f.name.value || '').trim() : '',
        expMonth,
        expYear,
      },
      // Everything the prompt needs, and nothing that could charge the card.
      display: {
        brand: brand.id,
        brandLabel: brand.label,
        last4: digits.slice(-4),
        expiry: expMonth && expYear ? `${String(expMonth).padStart(2, '0')}/${String(expYear).slice(-2)}` : '',
      },
    };
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
      :host { color-scheme: light dark; }
      .vy-pop, .vy-toast {
        position: fixed;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
        font-size: 13px; line-height: 1.45; color: #0f172a;
        background: #ffffff;
        border: 1px solid rgba(15, 23, 42, .10);
        border-radius: 16px;
        box-shadow: 0 1px 2px rgba(15,23,42,.06), 0 12px 28px -6px rgba(15,23,42,.22), 0 32px 64px -24px rgba(15,23,42,.28);
        overflow: hidden;
        -webkit-font-smoothing: antialiased;
      }
      .vy-pop { min-width: 268px; max-width: 344px; animation: vy-in .18s cubic-bezier(.2,.9,.3,1) both; }
      @keyframes vy-in { from { opacity: 0; transform: translateY(-6px) scale(.98); } to { opacity: 1; transform: none; } }

      /* Header: a single brand gradient band, the one saturated surface in the
         whole popup, so the rows below can stay quiet and legible. */
      .vy-head {
        display: flex; align-items: center; gap: 8px;
        padding: 10px 13px;
        background: linear-gradient(105deg, #4f46e5 0%, #6d5ef0 52%, #7c3aed 100%);
        color: #fff; font-weight: 650; font-size: 12.5px; letter-spacing: .01em;
      }
      .vy-head .vy-mark { display: grid; place-items: center; width: 18px; height: 18px; border-radius: 6px;
        background: rgba(255,255,255,.22); font-size: 11px; }
      .vy-head .vy-grow { flex: 1; }
      .vy-head .vy-count { font-weight: 600; font-size: 11px; padding: 2px 7px; border-radius: 999px;
        background: rgba(255,255,255,.18); }

      .vy-site { padding: 7px 13px; font-size: 11px; font-weight: 550; letter-spacing: .02em;
        color: #64748b; background: #f8fafc; border-bottom: 1px solid rgba(15,23,42,.06); }

      .vy-list { max-height: 316px; overflow-y: auto; padding: 4px; scrollbar-width: thin; }
      .vy-list::-webkit-scrollbar { width: 8px; }
      .vy-list::-webkit-scrollbar-thumb { background: rgba(15,23,42,.18); border-radius: 99px;
        border: 2px solid transparent; background-clip: content-box; }

      .vy-row { display: flex; align-items: center; gap: 10px; padding: 8px 9px; cursor: pointer;
        border-radius: 10px; transition: background .12s ease; }
      .vy-row:hover, .vy-row.is-active { background: #f1f0fe; }
      .vy-row.is-active { box-shadow: inset 0 0 0 1px rgba(79,70,229,.28); }
      .vy-row img { width: 18px; height: 18px; border-radius: 4px; flex: none; }
      .vy-meta-col { min-width: 0; flex: 1; }
      .vy-label { font-weight: 600; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .vy-sub { display: flex; align-items: center; gap: 6px; margin-top: 1px;
        font-size: 11.5px; color: #64748b; font-variant-numeric: tabular-nums; }
      .vy-sub .vy-dot { width: 3px; height: 3px; border-radius: 99px; background: currentColor; opacity: .5; flex: none; }
      .vy-sub .vy-brandname { font-weight: 700; letter-spacing: .03em; flex: none; }
      .vy-sub > span:nth-last-child(1) { min-width: 0; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
      .vy-badge { flex: none; font-size: 9.5px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase;
        padding: 2px 6px; border-radius: 5px; background: #fee2e2; color: #b42318; }
      .vy-badge.vy-2fa { background: #e0e7ff; color: #4338ca; }

      /* The code is the thing being chosen, so it is set like a value, not a
         label: tabular figures so the digits do not jitter as it ticks over. */
      .vy-code { flex: none; display: flex; align-items: center; gap: 7px; }
      .vy-code .vy-digits { font-variant-numeric: tabular-nums; font-feature-settings: "tnum";
        font-size: 15px; font-weight: 700; letter-spacing: .06em; color: #4338ca; }
      .vy-code .vy-secs { font-variant-numeric: tabular-nums; font-size: 10.5px; font-weight: 700;
        min-width: 20px; text-align: right; color: #64748b; }
      .vy-code .vy-secs.vy-soon { color: #b42318; }

      /* Mini card plate: the web app's plate at dropdown scale — same base plus
         corner bloom plus chip, so a card is recognised by colour and shape
         before a single digit is read. */
      .vy-plate { position: relative; flex: none; width: 46px; height: 29px; border-radius: 5px;
        overflow: hidden; background: rgb(var(--vy-base));
        box-shadow: 0 1px 2px rgba(15,23,42,.28), inset 0 0 0 .5px rgba(255,255,255,.14); }
      .vy-plate::before { content: ""; position: absolute; inset: 0;
        background:
          radial-gradient(120% 130% at 108% -22%, rgb(var(--vy-accent) / .58) 0%, transparent 62%),
          linear-gradient(146deg, rgba(255,255,255,.16) 0%, transparent 44%); }
      .vy-plate .vy-chip { position: absolute; left: 5px; top: 10px; width: 8px; height: 6px; border-radius: 1.5px;
        background: linear-gradient(150deg, #f7e3a1, #c9a54a 58%, #f2dc9a);
        box-shadow: inset 0 0 0 .5px rgba(0,0,0,.28); }
      .vy-plate .vy-brand { position: absolute; right: 4px; bottom: 3px; font-size: 6px; font-weight: 800;
        letter-spacing: .04em; color: rgba(255,255,255,.94); text-shadow: 0 1px 1px rgba(0,0,0,.4); }
      .vy-row.is-expired .vy-plate { filter: grayscale(.7) brightness(.86); }

      .vy-empty { padding: 16px 14px; font-size: 12px; color: #64748b; text-align: center; }
      .vy-empty strong { display: block; color: #0f172a; font-size: 13px; margin-bottom: 3px; }

      .vy-foot { display: flex; align-items: center; gap: 6px; padding: 7px 12px;
        border-top: 1px solid rgba(15,23,42,.06); background: #f8fafc;
        font-size: 10.5px; color: #94a3b8; }
      .vy-key { font: inherit; font-weight: 650; padding: 1px 5px; border-radius: 4px;
        background: #fff; border: 1px solid rgba(15,23,42,.12); color: #475569; }

      .vy-toast { min-width: 288px; max-width: 348px; right: 16px; bottom: 16px; padding: 14px; }
      .vy-toast h4 { margin: 0 0 6px; font-size: 14px; font-weight: 650; }
      .vy-toast .vy-meta { font-size: 12px; color: #64748b; margin: 2px 0; word-break: break-all; }
      .vy-actions { display: flex; gap: 8px; margin-top: 12px; }
      .vy-btn { flex: 1; border: none; border-radius: 9px; padding: 8px 10px; font: inherit; font-size: 13px;
        font-weight: 620; cursor: pointer; }
      .vy-btn.primary { background: linear-gradient(105deg, #4f46e5, #6d5ef0); color: #fff; }
      .vy-btn.ghost { background: #f1f5f9; color: #334155; }

      @media (prefers-reduced-motion: reduce) { .vy-pop { animation: none; } }

      @media (prefers-color-scheme: dark) {
        .vy-pop, .vy-toast { background: #131a2a; color: #f1f5f9; border-color: rgba(255,255,255,.09);
          box-shadow: 0 12px 28px -6px rgba(0,0,0,.6), 0 32px 64px -24px rgba(0,0,0,.7); }
        .vy-site, .vy-foot { background: #0f1523; border-color: rgba(255,255,255,.07); color: #94a3b8; }
        .vy-row:hover, .vy-row.is-active { background: rgba(109,94,240,.18); }
        .vy-sub, .vy-toast .vy-meta, .vy-empty { color: #94a3b8; }
        .vy-empty strong { color: #f1f5f9; }
        .vy-badge { background: rgba(180,35,24,.24); color: #fca5a5; }
        .vy-badge.vy-2fa { background: rgba(99,102,241,.26); color: #c7d2fe; }
        .vy-code .vy-digits { color: #c7d2fe; }
        .vy-code .vy-secs { color: #94a3b8; }
        .vy-code .vy-secs.vy-soon { color: #fca5a5; }
        .vy-key { background: #1c2536; border-color: rgba(255,255,255,.12); color: #cbd5e1; }
        .vy-btn.ghost { background: #1c2536; color: #e2e8f0; }
        .vy-list::-webkit-scrollbar-thumb { background: rgba(255,255,255,.18); background-clip: content-box; }
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

  function node(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  /** The dropdown's mini plate for one card summary. */
  function cardPlate(summary) {
    const [base, accent] = BRAND_COLORS[summary.brand] || BRAND_COLORS.other;
    const plate = node('div', 'vy-plate');
    plate.style.setProperty('--vy-base', base);
    plate.style.setProperty('--vy-accent', accent);
    plate.appendChild(node('span', 'vy-chip'));
    plate.appendChild(node('span', 'vy-brand', summary.brandName || ''));
    return plate;
  }

  // ---- autofill suggestion popup (Feature 2) ----
  let popupOpen = false;
  let rows = [], activeIdx = -1;
  // setInterval handles for the ticking codes in a two-factor dropdown. They
  // are owned by the popup, not by the rows, so that closing it for ANY reason
  // stops them — including the paths that never touch a row again.
  let codeTimers = [];

  function closePopup() {
    clearShadowRegion('.vy-pop');
    popupOpen = false;
    for (const t of codeTimers) clearInterval(t);
    codeTimers = [];
    rows = [];
    activeIdx = -1;
    document.removeEventListener('mousedown', onOutside, true);
    document.removeEventListener('scroll', onScroll, true);
    document.removeEventListener('keydown', onPopupKey, true);
  }
  function onOutside(e) {
    // host is in the light DOM; clicks inside the shadow won't reach here as `host`
    if (e.target !== host) closePopup();
  }
  /**
   * The page scrolling out from under an anchored dropdown should dismiss it —
   * but this listener is on `document` in the CAPTURE phase, so it also saw the
   * dropdown's OWN list scrolling. Arrow-keying to a row below the fold called
   * scrollIntoView, which closed the very popup being navigated. Events from
   * inside a closed shadow root retarget to the host, so that is the test.
   */
  function onScroll(e) {
    if (e.target === host) return;
    closePopup();
  }
  /**
   * Arrow keys move through the list and Enter picks — without this the whole
   * feature is mouse-only, which is exactly backwards for a field the user is
   * already typing in. Focus stays in the page's own input the entire time, so
   * the highlight is tracked here rather than by the browser.
   */
  function onPopupKey(e) {
    if (!popupOpen) return;
    if (e.key === 'Escape') { closePopup(); return; }
    if (!rows.length) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const step = e.key === 'ArrowDown' ? 1 : -1;
      activeIdx = (activeIdx + step + rows.length) % rows.length;
      rows.forEach((r, i) => r.node.classList.toggle('is-active', i === activeIdx));
      rows[activeIdx].node.scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter' && activeIdx >= 0) {
      e.preventDefault();
      rows[activeIdx].choose();
    } else if (e.key === 'Tab') {
      closePopup();
    }
  }

  function emptyState(title, detail) {
    const wrap = node('div', 'vy-empty');
    wrap.appendChild(node('strong', null, title));
    if (detail) wrap.appendChild(document.createTextNode(detail));
    return wrap;
  }

  function footHint(text) {
    const foot = node('div', 'vy-foot');
    foot.appendChild(node('kbd', 'vy-key', '↑↓'));
    foot.appendChild(node('kbd', 'vy-key', '↵'));
    foot.appendChild(node('span', null, text));
    return foot;
  }

  /**
   * `mode` is 'login' or 'card'. One popup shell, two payloads: the shape and
   * the keyboard behaviour are identical, only the row contents and the
   * background message differ.
   */
  async function openSuggestions(anchorEl, mode = 'login') {
    ensureHost();
    let res;
    try {
      res = await chrome.runtime.sendMessage({
        type: mode === 'card' ? 'GET_CARD_MATCHES' : 'GET_MATCHES',
      });
    } catch { return; } // extension context invalidated (e.g. reloaded)
    if (!res) return;

    // A two-factor field can only be answered by a login that HAS a second
    // factor, so the others are not choices here; offering them would be a
    // menu of things that do nothing.
    if (mode === 'totp' && res.matches) {
      res = { ...res, matches: res.matches.filter((m) => m.hasTotp) };
    }

    clearShadowRegion('.vy-pop');
    for (const t of codeTimers) clearInterval(t);
    codeTimers = [];
    rows = [];
    activeIdx = -1;

    const pop = node('div', 'vy-pop');
    const siteName = location.hostname.replace(/^www\./, '');

    const head = node('div', 'vy-head');
    head.appendChild(node('span', 'vy-mark', '🔐'));
    head.appendChild(node('span', 'vy-grow',
      mode === 'card' ? 'Vaultly cards' : mode === 'totp' ? 'Vaultly codes' : 'Vaultly'));
    const list = node('div', 'vy-list');

    if (!res.unlocked) {
      pop.append(head, node('div', 'vy-site', siteName));
      pop.appendChild(emptyState('Vault locked', 'Open the Vaultly popup and enter your PIN to autofill here.'));
    } else if (!res.matches || res.matches.length === 0) {
      pop.append(head, node('div', 'vy-site', siteName));
      pop.appendChild(
        mode === 'card'
          ? emptyState('No cards saved', 'Add a card in Vaultly and it shows up here at checkout.')
          : mode === 'totp'
            ? emptyState('No two-factor secret', `No login saved for ${siteName} has a two-factor secret yet. Add one from the Vaultly popup and codes appear here.`)
            : emptyState('No saved logins', `Nothing saved for ${siteName} yet.`)
      );
    } else {
      head.appendChild(node('span', 'vy-count', String(res.matches.length)));
      pop.append(head, node('div', 'vy-site', siteName));

      for (const m of res.matches) {
        const row = node('div', 'vy-row');
        let choose;

        if (mode === 'card') {
          if (m.expired) row.classList.add('is-expired');
          const plateEl = cardPlate(m);
          plateEl.setAttribute('aria-hidden', 'true');
          row.appendChild(plateEl);
          const col = node('div', 'vy-meta-col');
          col.appendChild(node('div', 'vy-label', m.label));
          const sub = node('div', 'vy-sub');
          // Brand as text too: the plate's colour and its 6px legend are not
          // something you can read, and "which card is this" has to be
          // answerable at a glance.
          if (m.brandName) sub.appendChild(node('span', 'vy-brandname', m.brandName));
          sub.appendChild(node('span', 'vy-dot'));
          sub.appendChild(node('span', null, m.masked));
          if (m.expiry) {
            sub.appendChild(node('span', 'vy-dot'));
            sub.appendChild(node('span', null, m.expiry));
          }
          col.appendChild(sub);
          row.appendChild(col);
          if (m.expired) row.appendChild(node('span', 'vy-badge', 'Expired'));

          choose = async () => {
            let got;
            try {
              got = await chrome.runtime.sendMessage({ type: 'GET_CARD', id: m.id });
            } catch { closePopup(); return; }
            closePopup();
            if (!got || !got.ok) {
              if (got && got.error === 'insecure-page') {
                showToast({
                  title: 'Not filled — insecure page',
                  meta: ['This page is served over plain HTTP.', 'Vaultly will not put card details into it.'],
                  primaryLabel: 'OK', ghostLabel: 'Dismiss',
                });
              }
              return;
            }
            if (!fillCard(got.card, anchorEl)) {
              showToast({
                title: 'No card fields found',
                meta: ['Vaultly could not identify the payment fields on this page.'],
                primaryLabel: 'OK', ghostLabel: 'Dismiss',
              });
            }
          };
        } else if (mode === 'totp') {
          const img = document.createElement('img');
          img.src = favicon(siteName);
          img.onerror = () => { img.style.visibility = 'hidden'; };
          const col = node('div', 'vy-meta-col');
          col.appendChild(node('div', 'vy-label', m.username || '(no username)'));
          col.appendChild(node('div', 'vy-sub', m.websiteName || siteName));

          // The live code, shown in the row: the user can read it off here
          // even on a page whose field this script cannot fill.
          const codeWrap = node('div', 'vy-code');
          const digits = node('span', 'vy-digits', '------');
          const secs = node('span', 'vy-secs', '');
          codeWrap.append(digits, secs);
          row.append(img, col, codeWrap);

          const paint = (res) => {
            if (!res || !res.ok) { digits.textContent = '------'; secs.textContent = ''; return; }
            digits.textContent = res.code.length === 6
              ? res.code.slice(0, 3) + ' ' + res.code.slice(3) : res.code;
            secs.textContent = res.remaining + 's';
            secs.classList.toggle('vy-soon', res.remaining <= 5);
          };
          const tick = async () => {
            if (!popupOpen) return;
            try { paint(await chrome.runtime.sendMessage({ type: 'GET_TOTP', id: m.id })); }
            catch { /* worker asleep; the row keeps its last value */ }
          };
          tick();
          // One timer per row, cleared with the popup. A code that keeps
          // counting down after the dropdown closed is a leak of both memory
          // and attention.
          const timer = setInterval(tick, 1000);
          codeTimers.push(timer);

          choose = async () => {
            let got;
            try { got = await chrome.runtime.sendMessage({ type: 'GET_TOTP', id: m.id }); }
            catch { closePopup(); return; }
            closePopup();
            if (!got || !got.ok) return;
            if (!fillOtp(got.code, findOtpTarget() || { single: anchorEl })) {
              showToast({
                title: 'No code field found',
                meta: ['Vaultly could not identify the two-factor field on this page.'],
                primaryLabel: 'OK', ghostLabel: 'Dismiss',
              });
            }
          };
        } else {
          const img = document.createElement('img');
          img.src = favicon(siteName);
          img.onerror = () => { img.style.visibility = 'hidden'; };
          const col = node('div', 'vy-meta-col');
          col.appendChild(node('div', 'vy-label', m.username || '(no username)'));
          if (m.websiteName) col.appendChild(node('div', 'vy-sub', m.websiteName));
          row.append(img, col);
          // Says, before the click, that the second factor is covered too.
          if (m.hasTotp) row.appendChild(node('span', 'vy-badge vy-2fa', '2FA'));

          choose = async () => {
            let cred;
            try {
              cred = await chrome.runtime.sendMessage({ type: 'GET_CREDENTIAL', id: m.id });
            } catch { closePopup(); return; }
            if (cred && cred.ok) {
              fillCredentials(cred.username, cred.password);
              if (cred.hasTotp) {
                // The code field is usually on the next page. Arm it, then try
                // here anyway for the sites that show both at once.
                armTotp(m.id);
                if (findOtpTarget()) setTimeout(() => { autofillArmedTotp(); }, 60);
              }
            }
            closePopup();
          };
        }

        // mousedown, not click: a click would blur the field first, and some
        // frameworks tear the form down on blur before the fill lands.
        row.addEventListener('mousedown', (e) => { e.preventDefault(); choose(); });
        rows.push({ node: row, choose });
        list.appendChild(row);
      }

      pop.appendChild(list);
      pop.appendChild(footHint(
        mode === 'card' ? 'to fill this card'
          : mode === 'totp' ? 'to fill this code'
            : 'to fill this login'));
    }

    // Measure before placing: the popup's width depends on its longest row, and
    // a hardcoded guess pushed it off-screen next to a right-aligned field.
    pop.style.visibility = 'hidden';
    pop.style.left = '0px';
    pop.style.top = '0px';
    shadow.appendChild(pop);

    const r = anchorEl.getBoundingClientRect();
    const w = pop.offsetWidth || 300;
    const h = pop.offsetHeight || 200;
    const left = Math.max(8, Math.min(r.left, window.innerWidth - w - 8));
    // Flip above the field when there isn't room below it — a checkout's card
    // row is often the last thing on a short page.
    const below = r.bottom + 6;
    const top = below + h > window.innerHeight - 8 && r.top - 6 - h > 8 ? r.top - 6 - h : below;
    pop.style.left = left + 'px';
    pop.style.top = Math.max(8, top) + 'px';
    pop.style.visibility = 'visible';

    popupOpen = true;
    document.addEventListener('mousedown', onOutside, true);
    document.addEventListener('scroll', onScroll, true);
    document.addEventListener('keydown', onPopupKey, true);
  }

  // ---- save / update prompt (Features 3 & 4) ----
  const suppressedSites = new Set(); // "Never" for this site, this session
  function showToast({ title, meta, primaryLabel, ghostLabel, onPrimary, onGhost }) {
    ensureHost();
    clearShadowRegion('.vy-toast');
    const toast = node('div', 'vy-toast');
    toast.appendChild(node('h4', null, title));
    for (const line of meta) toast.appendChild(node('div', 'vy-meta', line));
    const actions = node('div', 'vy-actions');
    const primary = node('button', 'vy-btn primary', primaryLabel);
    primary.addEventListener('click', () => { clearShadowRegion('.vy-toast'); onPrimary && onPrimary(); });
    const ghost = node('button', 'vy-btn ghost', ghostLabel);
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

    const siteHost = location.hostname.replace(/^www\./, '');
    if (suppressedSites.has(siteHost)) return;

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
        meta: [`Website: ${siteHost}`, `Username: ${username || '(none)'}`, 'Password: ••••••••'],
        primaryLabel: 'Save',
        ghostLabel: 'Never',
        onPrimary: () => chrome.runtime.sendMessage({ type: 'SAVE_CREDENTIAL', payload: { websiteName: siteHost, username, password } }),
        onGhost: () => suppressedSites.add(siteHost),
      });
    } else if (verdict.action === 'update') {
      showToast({
        title: 'Update saved password?',
        meta: [`Website: ${siteHost}`, `Username: ${username}`, 'Password changed'],
        primaryLabel: 'Update',
        ghostLabel: 'Cancel',
        onPrimary: () => chrome.runtime.sendMessage({ type: 'UPDATE_CREDENTIAL', payload: { id: verdict.id, password } }),
        onGhost: () => {},
      });
    }
  }

  /**
   * Offer to save the card on the page, if there is one worth saving.
   *
   * Runs in whichever frame owns the fields — usually a payment iframe — and
   * hands the decision to the worker, which renders the prompt via the tab's top
   * frame. Two messages, not one: the first carries only brand and last4, so a
   * card we already hold is ruled out before anything chargeable leaves the page.
   */
  let lastCardOffer = { last4: '', at: 0 };
  async function handlePotentialCardSubmit() {
    const read = readCardFromPage();
    if (!read) return;

    // Every trigger below can fire for the same click; one offer is enough.
    const now = Date.now();
    if (read.display.last4 === lastCardOffer.last4 && now - lastCardOffer.at < 8000) return;
    lastCardOffer = { last4: read.display.last4, at: now };

    let verdict;
    try {
      verdict = await chrome.runtime.sendMessage({
        type: 'CLASSIFY_CARD_SUBMISSION',
        payload: { brand: read.display.brand, last4: read.display.last4 },
      });
    } catch {
      return;
    }
    if (!verdict || verdict.action !== 'save') return;

    try {
      await chrome.runtime.sendMessage({ type: 'OFFER_SAVE_CARD', payload: read });
    } catch {
      /* worker went away between the two calls; nothing stashed, nothing to do */
    }
  }

  /* Most checkouts never fire a `submit` event — they collect the fields with
     JS and call a gateway. So a click on something that reads like a pay button
     counts as a submission too. The regex stays tight, and a false positive is
     silent anyway: readCardFromPage() returns null unless a Luhn-valid number is
     actually sitting on the page. */
  const PAY_BUTTON_RE = /\b(pay|payment|purchase|buy|order|checkout|complete|confirm|submit|continue|subscribe|donate|add card|save card)\b/i;

  function looksLikePayButton(el) {
    const btn = el && el.closest ? el.closest('button,[role="button"],input[type="submit"],input[type="button"],a') : null;
    if (!btn) return false;
    const text = `${btn.textContent || ''} ${btn.value || ''} ${btn.getAttribute('aria-label') || ''} ${btn.getAttribute('name') || ''} ${btn.id || ''}`;
    return PAY_BUTTON_RE.test(text);
  }

  // ---- wiring: focus opens suggestions; submit-like events trigger save ----
  function isLoginInput(el) {
    if (!(el instanceof HTMLInputElement)) return false;
    if (el.type === 'password') return true;
    return el.matches(USERNAME_SELECTORS);
  }

  document.addEventListener('focusin', (e) => {
    const t = e.target;
    // Cards are checked FIRST: a CVV box is sometimes <input type="password">,
    // which the login test would claim, and offering logins at a checkout is
    // both useless and confusing.
    if (isCardInput(t)) openSuggestions(t, 'card');
    else if (isOtpInput(t) || segmentGroupFor(t)) {
      // Armed by a login fill a moment ago: just put the code in. Otherwise
      // offer the codes, which is also the way in on a site whose second
      // factor is reached without filling the password first.
      autofillArmedTotp(segmentGroupFor(t) ? { segments: segmentGroupFor(t) } : { single: t })
        .then((filled) => { if (!filled) openSuggestions(t, 'totp'); });
    } else if (isLoginInput(t)) openSuggestions(t, 'login');
  }, true);

  // Submit detection (Feature 10 subset): real form submit + Enter-in-password.
  // Top frame only — a "Save login?" prompt belongs to the page, not to
  // whichever payment iframe happens to be mounted inside it.
  if (IS_TOP) {
    document.addEventListener('submit', () => setTimeout(handlePotentialSubmit, 0), true);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && e.target instanceof HTMLInputElement && e.target.type === 'password') {
        setTimeout(handlePotentialSubmit, 50);
      }
    }, true);
  }

  /* Card submissions are watched in EVERY frame, unlike login submissions: the
     fields live wherever the gateway put them, and only that frame can read
     them. The prompt still surfaces once, in the top frame. */
  document.addEventListener('submit', () => setTimeout(handlePotentialCardSubmit, 0), true);
  document.addEventListener(
    'keydown',
    (e) => {
      if (e.key === 'Enter' && isCardCandidate(e.target)) setTimeout(handlePotentialCardSubmit, 60);
    },
    true
  );
  document.addEventListener(
    'click',
    (e) => {
      // After the click, not before: the page may only write the last field's
      // value on its own click handler.
      if (looksLikePayButton(e.target)) setTimeout(handlePotentialCardSubmit, 120);
    },
    true
  );
  // SPA logins that never fire submit: also watch for a URL change after creds present.
  let lastHref = location.href;
  const urlWatcher = () => {
    if (location.href !== lastHref) {
      lastHref = location.href;
      if (IS_TOP) setTimeout(handlePotentialSubmit, 200);
    }
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
      //
      // The exception is the two-factor step: it is usually a fresh page or a
      // freshly rendered form, and its field is often focused by the site
      // itself before this script could have seen it. Only does anything when
      // a login with a second factor was filled in the last couple of minutes.
      if (armedTotp) autofillArmedTotp();
    });
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  // ---- messages from background (context menu / command / popup) ----
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'AUTOFILL') {
      // Legacy path retained for the popup's "Fill" button.
      fillCredentials(message.username, message.password);
      sendResponse({ ok: true });
    }
    if (message.type === 'AUTOFILL_CARD') {
      // The popup's per-card "Fill" button: it already fetched the one card the
      // user clicked and relays it over the internal channel.
      const filled = fillCard(message.card, document.activeElement);
      sendResponse({ ok: !!filled, filled: filled || [] });
    }
    if (message.type === 'AUTOFILL_TOTP') {
      // The popup's per-item "Fill code": it asked the worker for the code and
      // relays only the six digits, never the secret.
      const filled = fillOtp(message.code, findOtpTarget());
      sendResponse({ ok: filled });
    }
    if (message.type === 'SHOW_AUTOFILL_MENU') {
      const active = document.activeElement;
      if (isCardInput(active)) {
        openSuggestions(active, 'card');
        sendResponse({ ok: true });
      } else if (active && (isOtpInput(active) || segmentGroupFor(active))) {
        openSuggestions(active, 'totp');
        sendResponse({ ok: true });
      } else {
        const { passwordFields, usernameFields } = findLoginFields();
        const anchor = active && isLoginInput(active) ? active : (usernameFields[0] || passwordFields[0]);
        if (anchor) {
          openSuggestions(anchor, 'login');
          sendResponse({ ok: true });
        } else {
          // No login field either — fall back to cards when this looks like a
          // checkout, so the keyboard shortcut is never a dead key.
          const cardFields = collectCardFields(document);
          const cardAnchor = cardFields.confident
            ? (cardFields.numbers[0] || cardFields.csc || cardFields.exp || cardFields.name)
            : null;
          if (cardAnchor) openSuggestions(cardAnchor, 'card');
          sendResponse({ ok: !!cardAnchor });
        }
      }
    }
    if (message.type === 'PROMPT_SAVE_CARD') {
      // Relayed by the worker, which holds the card while this prompt is open.
      // Note what is NOT in this message: no number, no CVV, no cardholder name.
      const d = message.display || {};
      const meta = [`${d.brandLabel || 'Card'} \u2022\u2022\u2022\u2022 ${d.last4 || ''}`];
      if (d.expiry) meta.push(`Expires ${d.expiry}`);
      meta.push('Saved encrypted with your master PIN.');
      showToast({
        title: 'Save this card?',
        meta,
        primaryLabel: 'Save card',
        ghostLabel: 'Never',
        onPrimary: () =>
          chrome.runtime.sendMessage({ type: 'RESOLVE_SAVE_CARD', accept: true }).catch(() => {}),
        onGhost: () =>
          chrome.runtime
            .sendMessage({ type: 'RESOLVE_SAVE_CARD', accept: false, never: true })
            .catch(() => {}),
      });
      sendResponse({ ok: true });
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
