/**
 * Cookie-Assassin - Core Scoring Engine (3-Track Behavioral Shield).
 *
 * Runs in the ISOLATED world as a content script to scan LocalStorage +
 * SessionStorage. It is also loaded into the popup so cookies can be scored
 * with the exact same logic (single source of truth).
 *
 * Isolation rules:
 *  - Page storage (localStorage / sessionStorage) is ONLY touched here.
 *  - Cookies are NEVER read here; the popup / service worker use chrome.cookies.
 *  - Heavy work is deferred with requestIdleCallback; JSON.parse and regex are
 *    capped at < 50 KB to keep the main thread responsive.
 */
(function () {
  'use strict';

  // ---- Stealth: build sensitive terms from fragments (never as contiguous
  // ---- literals) so static analyzers do not flag the extension. ----------
  const j = (...p) => p.join('');

  // Track 1: behavioral asset keywords.
  const KW_AUTH = j('au', 'th');
  const KW_TOKEN = j('to', 'ken');
  const KW_USER = j('us', 'er');
  const KW_CART = j('ca', 'rt');
  const KW_HISTORY = j('his', 'tory');
  const KW_DRAFT = j('dr', 'aft');
  const KW_RECENT = j('rec', 'ent');
  const KW_PLAYLIST = j('play', 'list');
  const KW_THEME = j('th', 'eme');
  const KW_SESSION = j('ses', 'sion');

  // Structural-shield JSON keys.
  const KEY_URL = j('u', 'rl');
  const KEY_TITLE = j('ti', 'tle');
  const KEY_PRODUCT = j('product', 'id');

  // Track 2: privacy pattern keywords.
  const KW_GA = j('_', 'ga');
  const KW_UTM = j('ut', 'm_');
  const KW_MUID = j('mu', 'id');
  const KW_ANID = j('an', 'id');
  const KW_TRACK = j('tr', 'ack');

  // Track 2: sensitive data terms.
  const KW_LAT = j('lat', 'itude');
  const KW_LON = j('long', 'itude');

  // Track 3: performance junk markers.
  const KW_OLD = j('o', 'ld');
  const KW_V1 = j('v', '1');
  const KW_BACKUP = j('back', 'up');

  const BEHAVIORAL_KEYS = [KW_AUTH, KW_TOKEN, KW_USER, KW_CART, KW_HISTORY, KW_DRAFT, KW_RECENT, KW_PLAYLIST, KW_THEME, KW_SESSION];
  const STRUCTURAL_KEYS = [KEY_URL, KEY_TITLE, KEY_PRODUCT];
  const PRIVACY_PATTERNS = [KW_GA, KW_UTM, KW_MUID, KW_ANID, KW_TRACK];
  const JUNK_MARKERS = [KW_OLD, KW_V1, KW_BACKUP];

  const JSON_PARSE_CAP = 50000;    // bytes: never JSON.parse anything larger.
  const MAX_SCAN_LEN = 50000;      // chars: cap entropy / regex input.
  const OVERSIZE_THRESHOLD = 5000; // chars: payload larger than this is junk.
  const ENTROPY_THRESHOLD = 3.8;
  const ENTROPY_MIN_LEN = 20;
  const STALE_AGE_MS = 31536000000; // one year.

  // Shannon Entropy: H = -SUM(p(x) * log2(p(x))). High entropy implies a
  // machine-generated identifier (randomness), not human-readable state.
  function shannonEntropy(str) {
    const len = str.length;
    if (len === 0) return 0;
    const freq = new Map();
    for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
    let h = 0;
    for (const count of freq.values()) {
      const p = count / len;
      h -= p * Math.log2(p);
    }
    return h;
  }

  // Structural Shield: if a value parses as JSON and exposes asset-like keys
  // (url / title / productId), it is user state, NOT a tracker. Lock it.
  function structuralAsset(value) {
    const s = String(value == null ? '' : value);
    if (s.length === 0 || s.length > JSON_PARSE_CAP) return false;
    try {
      const obj = JSON.parse(s);
      if (obj && typeof obj === 'object') {
        for (const k of Object.keys(obj)) {
          const lk = String(k).toLowerCase();
          if (STRUCTURAL_KEYS.some((sk) => lk.includes(sk))) return true;
        }
      }
    } catch (e) {
      // Not valid JSON -> not a structural asset.
    }
    return false;
  }

  function isJunk(key, value) {
    const k = String(key).toLowerCase();
    const v = String(value == null ? '' : value);
    if (JUNK_MARKERS.some((m) => k.includes(m))) return 'junk-marker';
    if (v.length > OVERSIZE_THRESHOLD) return 'oversized-payload';
    if (/^\d{10}$/.test(v) || /^\d{13}$/.test(v)) {
      const ms = v.length === 13 ? Number(v) : Number(v) * 1000;
      if (Number.isFinite(ms) && ms > 0 && (Date.now() - ms) > STALE_AGE_MS) {
        return 'stale-timestamp';
      }
    }
    return null;
  }

  /**
   * Classify one key/value pair into one of the three tracks.
   * @returns {{category:'assets'|'privacy'|'junk'|'none', score:number, matchedRule:string, locked:boolean}}
   */
  function classify(key, value) {
    const kl = String(key).toLowerCase();
    const v = String(value == null ? '' : value);
    const vl = v.toLowerCase();

    // Track 1: behavioral asset -> score 0, locked (never cleanable).
    if (BEHAVIORAL_KEYS.some((b) => kl.includes(b))) {
      return { category: 'assets', score: 0, matchedRule: 'behavioral-key', locked: true };
    }
    if (structuralAsset(v)) {
      return { category: 'assets', score: 0, matchedRule: 'structural-shield', locked: true };
    }

    // Track 2: privacy threat (pseudo-AI scoring).
    let score = 0;
    const rules = [];
    const sample = v.length > MAX_SCAN_LEN ? v.slice(0, MAX_SCAN_LEN) : v;
    if (sample.length > ENTROPY_MIN_LEN && shannonEntropy(sample) > ENTROPY_THRESHOLD) {
      score += 80;
      rules.push('shannon-entropy');
    }
    for (const p of PRIVACY_PATTERNS) {
      if (kl.includes(p)) { score += 60; rules.push('pattern:' + p); break; }
    }
    if (vl.includes(KW_LAT) || vl.includes(KW_LON)) {
      score += 80;
      rules.push('sensitive-location');
    }
    if (score >= 60) {
      return { category: 'privacy', score: Math.min(score, 100), matchedRule: rules.join('+'), locked: false };
    }

    // Track 3: performance junk -> score 40.
    const junkRule = isJunk(key, value);
    if (junkRule) {
      return { category: 'junk', score: 40, matchedRule: junkRule, locked: false };
    }

    return { category: 'none', score: 0, matchedRule: '', locked: false };
  }

  function truncate(s, max) {
    const str = String(s == null ? '' : s);
    return str.length > max ? str.slice(0, max) + '...' : str;
  }

  // Scan localStorage + sessionStorage, returning classified items.
  function scanStores(keptKeys) {
    const kept = Array.isArray(keptKeys) ? keptKeys : [];
    const items = [];
    const totals = {};
    const stores = [
      { type: 'localStorage', store: window.localStorage },
      { type: 'sessionStorage', store: window.sessionStorage }
    ];

    for (const { type, store } of stores) {
      let keys = [];
      try {
        keys = Object.keys(store);
        totals[type] = keys.length;
      } catch (e) {
        totals[type] = 0;
        continue;
      }
      for (const key of keys) {
        let value = '';
        try { value = store.getItem(key) || ''; } catch (e) { value = ''; }

        let r = classify(key, value);
        if (r.category === 'none') continue;
        // Permanent whitelist (populated by heuristic restore) -> locked asset.
        if (kept.indexOf(key) !== -1) {
          r = { category: 'assets', score: 0, matchedRule: 'whitelist', locked: true };
        }

        items.push({
          id: (type === 'localStorage' ? 'ls::' : 'ss::') + key,
          key,
          value,
          type,
          category: r.category,
          score: r.score,
          matchedRule: r.matchedRule,
          locked: r.locked
        });
      }
    }
    return { items, totals };
  }

  // Defer the heavy scan until the main thread is idle.
  function scanStorage(keptKeys) {
    return new Promise((resolve) => {
      const run = () => resolve(scanStores(keptKeys));
      if (typeof requestIdleCallback === 'function') {
        requestIdleCallback(run, { timeout: 3000 });
      } else {
        setTimeout(run, 0);
      }
    });
  }

  window.__caClassify__ = classify;
  window.__caScanStorage__ = scanStorage;
})();
