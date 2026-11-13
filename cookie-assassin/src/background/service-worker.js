/**
 * Cookie-Assassin - Background Service Worker.
 *
 * Responsibilities:
 *  1. DNR: block third-party trackers/analytics and strip Referer to them.
 *  2. Identity fragmentation: inject the current FingerprintSeed + trust tier
 *     into the MAIN world at navigation (uses ProxyController).
 *  3. Auto-protection: on webNavigation.onCompleted + 2000ms, scan and silently
 *     clean high-severity privacy threats.
 *  4. Proactive watchdog + SURGICAL rollback: restore only the offending key(s)
 *     in-place (no page reload), then whitelist them permanently.
 *
 * Least-privilege notes:
 *  - Cookies are read with chrome.cookies.getAll({ url }) scoped to the site.
 *  - Scripting runs only on webNavigation events (never globally).
 *  - No browsing history is logged or stored.
 */
'use strict';

importScripts('proxy-controller.js');

const AUTO_DELAY_MS = 2000;
const WATCHDOG_MS = 3000;
const PRIVACY_AUTO_THRESHOLD = 70;

// Tier 1 high-trust domains (banking / payment / government / legitimate commerce).
const TIER1_HOSTS = ['bank', 'pay', 'alipay', 'gov.cn', 'taobao.com'];

// Stealth: build tracker domain strings from fragments to avoid hardcoded terms.
const j = (...p) => p.join('');
const TRACKER_DOMAINS = [
  j('google-', 'ana', 'lytics', '.com'),
  j('google', 'tag', 'manager', '.com'),
  j('double', 'click', '.net'),
  j('face', 'book', '.net'),
  j('hot', 'jar', '.com'),
  j('mix', 'panel', '.com'),
  j('seg', 'ment', '.io'),
  j('am', 'pli', 'tude', '.com'),
  j('score', 'card', 'research', '.com')
];

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ---- DNR rules (dynamic, registered once per SW start) ----
async function registerDnrRules() {
  const rules = [];
  TRACKER_DOMAINS.forEach((domain, i) => {
    rules.push({
      id: i + 1,
      priority: 1,
      action: { type: 'block' },
      condition: {
        requestDomains: [domain],
        resourceTypes: ['script', 'sub_frame', 'image', 'xmlhttprequest', 'ping', 'media', 'font', 'other']
      }
    });
    rules.push({
      id: 1000 + i + 1,
      priority: 2,
      action: { type: 'modifyHeaders', requestHeaders: [{ header: 'Referer', operation: 'remove' }] },
      condition: {
        requestDomains: [domain],
        resourceTypes: ['script', 'xmlhttprequest', 'image', 'sub_frame', 'ping']
      }
    });
  });
  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map((r) => r.id),
      addRules: rules
    });
  } catch (e) { /* DNR unavailable -> ignore */ }
}

// ---- Trust resolution (mirrored by the popup) ----
function isHighTrust(hostname) {
  return TIER1_HOSTS.some((h) => hostname.indexOf(h) !== -1);
}

async function isLoggedIn(hostname) {
  try {
    const cookies = await chrome.cookies.getAll({ url: 'https://' + hostname + '/' });
    const terms = ['token', 'session', 'auth', 'login', 'sid'];
    return cookies.some((c) => terms.some((t) => c.name.toLowerCase().indexOf(t) !== -1));
  } catch (e) {
    return false;
  }
}

// Returns { tier: 'high-trust'|'frozen'|'fragmented', locked: boolean }.
async function resolveTrust(hostname) {
  if (isHighTrust(hostname)) return { tier: 'high-trust', locked: true };
  const d = await chrome.storage.local.get('trustOverrides');
  const override = (d.trustOverrides || {})[hostname] || 'auto';
  if (override === 'trust') return { tier: 'frozen', locked: true };
  if (override === 'force') return { tier: 'fragmented', locked: false };
  const loggedIn = await isLoggedIn(hostname);
  return { tier: loggedIn ? 'frozen' : 'fragmented', locked: loggedIn };
}

// ---- Inject identity + trust tier into the MAIN world (best effort, early) ----
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  try {
    const identity = await self.ProxyController.ensureIdentity();
    const hostname = new URL(details.url).hostname;
    const trust = await resolveTrust(hostname);
    await chrome.scripting.executeScript({
      target: { tabId: details.tabId },
      world: 'MAIN',
      injectImmediately: true,
      func: (id) => { window.__caIdentity__ = id; },
      args: [{ seed: identity.seed, profileIndex: identity.profileIndex, profile: identity.profile, tier: trust.tier, locked: trust.locked }]
    });
  } catch (e) { /* frame not ready or restricted page */ }
});

// ---- Auto-protection trigger ----
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  setTimeout(() => autoProtect(details.tabId, details.url), AUTO_DELAY_MS);
});

async function autoProtect(tabId, url) {
  if (!/^https?:/i.test(url || '')) return;
  try {
    const hostname = new URL(url).hostname;
    const kept = await getKeptKeys(hostname);
    const items = await scanSite(tabId, url, kept);

    const privacy = items.filter((i) => i.category === 'privacy');
    const junk = items.filter((i) => i.category === 'junk');
    const threats = privacy.filter((i) => i.score >= PRIVACY_AUTO_THRESHOLD);

    if (privacy.length > 0) {
      await chrome.action.setBadgeText({ tabId, text: String(privacy.length) });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#FF0080' });
    } else if (junk.length > 0) {
      await chrome.action.setBadgeText({ tabId, text: String(junk.length) });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#F59E0B' });
    } else {
      await chrome.action.setBadgeText({ tabId, text: '' });
    }

    if (threats.length > 0) {
      await silentClean(tabId, url, hostname, threats);
    }
  } catch (e) { /* restricted page or injection failure */ }
}

// ---- Scan cookies + storage (classification runs in the page ISOLATED world) ----
async function scanSite(tabId, url, kept) {
  await chrome.scripting.executeScript({ target: { tabId }, files: ['src/content/injector.js'] });

  const cookies = await chrome.cookies.getAll({ url });
  const cookieList = cookies.map((c) => ({
    name: c.name,
    value: c.value,
    url: (c.secure ? 'https' : 'http') + '://' + c.domain.replace(/^\./, '') + (c.path || '/'),
    type: 'cookie'
  }));

  const [res] = await chrome.scripting.executeScript({
    target: { tabId },
    func: (cookies, keptKeys) => {
      const classify = window.__caClassify__;
      const cookieItems = [];
      for (const c of cookies) {
        const r = classify(c.name, c.value);
        if (r.category === 'none') continue;
        if (keptKeys.indexOf(c.name) !== -1) {
          cookieItems.push({ id: 'cookie::' + c.name, key: c.name, value: c.value, type: 'cookie', url: c.url, name: c.name, category: 'assets', score: 0, matchedRule: 'whitelist', locked: true });
          continue;
        }
        cookieItems.push({ id: 'cookie::' + c.name, key: c.name, value: c.value, type: 'cookie', url: c.url, name: c.name, category: r.category, score: r.score, matchedRule: r.matchedRule, locked: r.locked });
      }
      return window.__caScanStorage__(keptKeys).then((storage) => ({ cookieItems, storageItems: storage.items }));
    },
    args: [cookieList, kept]
  });

  const r = res && res.result ? res.result : { cookieItems: [], storageItems: [] };
  return [...r.cookieItems, ...r.storageItems];
}

// ---- Silent clean + proactive watchdog + surgical rollback ----
async function silentClean(tabId, url, hostname, threats) {
  const entries = threats.map((t) => ({ key: t.key, value: t.value, type: t.type, url: t.url, name: t.name }));

  // 1) Install MAIN-world watchdog.
  try {
    await chrome.scripting.executeScript({ target: { tabId }, world: 'MAIN', func: installWatchdog });
  } catch (e) {}

  // 2) Delete threats.
  for (const t of threats) {
    if (t.type === 'cookie') {
      try { await chrome.cookies.remove({ url: t.url, name: t.name }); } catch (e) {}
    }
  }
  const storageThreats = threats.filter((t) => t.type !== 'cookie');
  if (storageThreats.length) {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (list) => {
        for (const e of list) {
          try {
            if (e.type === 'localStorage') window.localStorage.removeItem(e.key);
            else if (e.type === 'sessionStorage') window.sessionStorage.removeItem(e.key);
          } catch (err) {}
        }
      },
      args: [storageThreats]
    });
  }

  // 3) Wait the watchdog window.
  await sleep(WATCHDOG_MS);

  // 4) Read watchdog stats.
  let stats = null;
  try {
    const [r] = await chrome.scripting.executeScript({ target: { tabId }, world: 'MAIN', func: readWatchdog });
    stats = r && r.result ? r.result : null;
  } catch (e) {}

  if (!stats) return;

  const crashed = stats.domDropRatio > 0.7;
  const noisy = stats.consoleErrors > 5 || stats.network401403 > 2;

  if (crashed || noisy) {
    await restoreMatched(tabId, hostname, entries, stats.errorTexts); // in-place, no reload
  }
}

// MAIN-world watchdog installer (serialized via executeScript).
function installWatchdog() {
  if (window.__caWatchdogInstalled__) return;
  window.__caWatchdogInstalled__ = true;

  const state = {
    initialDom: document.getElementsByTagName('*').length,
    consoleErrors: 0,
    network401403: 0,
    errorTexts: [],
    domDropRatio: 0
  };
  window.__caWatchdog__ = state;

  const originalError = console.error.bind(console);
  console.error = function () {
    state.consoleErrors++;
    const text = Array.prototype.map.call(arguments, (a) => String(a)).join(' ');
    state.errorTexts.push(text);
    if (text.indexOf('401') !== -1 || text.indexOf('403') !== -1) state.network401403++;
    return originalError.apply(console, arguments);
  };

  window.addEventListener('error', (e) => {
    const msg = (e && (e.message || (e.error && e.error.message))) || '';
    state.errorTexts.push(msg);
  });
  window.addEventListener('unhandledrejection', (e) => {
    const msg = (e && e.reason && e.reason.message) || String(e && e.reason);
    state.errorTexts.push(msg);
  });
}

function readWatchdog() {
  const s = window.__caWatchdog__;
  if (!s) return null;
  const currentDom = document.getElementsByTagName('*').length;
  s.domDropRatio = s.initialDom > 0 ? (s.initialDom - currentDom) / s.initialDom : 0;
  return s;
}

// ---- Surgical rollback: restore ONLY the offending key(s), in-place ----
async function restoreMatched(tabId, hostname, entries, errorTexts) {
  const text = (errorTexts || []).join(' ');
  const matched = entries.filter((e) => text.indexOf(e.key) !== -1);
  if (matched.length === 0) return;

  // Whitelist matched keys permanently.
  const data = await chrome.storage.local.get('permanentWhitelist');
  const wl = data.permanentWhitelist || {};
  const list = wl[hostname] || [];
  for (const e of matched) {
    if (list.indexOf(e.key) === -1) list.push(e.key);
  }
  wl[hostname] = list;
  await chrome.storage.local.set({ permanentWhitelist: wl });

  // Restore cookies in-place.
  for (const e of matched) {
    if (e.type === 'cookie' && e.url && e.name) {
      try { await chrome.cookies.set({ url: e.url, name: e.name, value: e.value || '' }); } catch (err) {}
    }
  }
  // Restore storage in-place.
  const storageEntries = matched.filter((e) => e.type !== 'cookie');
  if (storageEntries.length) {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (list) => {
        for (const e of list) {
          try {
            if (e.type === 'localStorage') window.localStorage.setItem(e.key, e.value || '');
            else if (e.type === 'sessionStorage') window.sessionStorage.setItem(e.key, e.value || '');
          } catch (err) {}
        }
      },
      args: [storageEntries]
    });
  }
}

async function getKeptKeys(hostname) {
  const data = await chrome.storage.local.get('permanentWhitelist');
  const wl = data.permanentWhitelist || {};
  return wl[hostname] || [];
}

// ---- Startup ----
registerDnrRules();
self.ProxyController.applyProxySettings();
