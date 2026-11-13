'use strict';

// ---- i18n helper ----
function t(key, subs) {
  return chrome.i18n.getMessage(key, subs) || key;
}

// ---- DOM references ----
const domainLabel = document.getElementById('domain-label');
const identityCard = document.getElementById('identity-card');
const identityStatus = document.getElementById('identity-status');
const trustSelect = document.getElementById('trust-select');
const statBounty = document.getElementById('stat-bounty');
const statBlocked = document.getElementById('stat-blocked');
const statFreed = document.getElementById('stat-freed');
const btnScan = document.getElementById('btn-scan');
const stateInitial = document.getElementById('state-initial');
const stateScanning = document.getElementById('state-scanning');
const stateResult = document.getElementById('state-result');
const stateDone = document.getElementById('state-done');
const accordionEl = document.getElementById('accordion');
const btnClean = document.getElementById('btn-clean');
const btnBackResult = document.getElementById('btn-back-result');
const btnBackDone = document.getElementById('btn-back-done');
const doneText = document.getElementById('done-text');

// ---- State ----
let currentTab = null;
let currentUrl = '';
let currentHostname = '';
let currentItems = [];
const cookieMap = new Map(); // id -> { url, name }

// Tier 1 high-trust domains (mirrors the service worker).
const TIER1_HOSTS = ['bank', 'pay', 'alipay', 'gov.cn', 'taobao.com'];

// ---- Helpers ----
function showState(name) {
  stateInitial.hidden = name !== 'initial';
  stateScanning.hidden = name !== 'scanning';
  stateResult.hidden = name !== 'result';
  stateDone.hidden = name !== 'done';
}

async function getActiveTab() {
  let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  }
  return tab;
}

function truncate(s, max) {
  const str = s == null ? '' : String(s);
  return str.length > max ? str.slice(0, max) + '...' : str;
}

// Safe DOM builder: always textContent, never innerHTML with page data.
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// ---- Stats ----
async function getStats() {
  const d = await chrome.storage.local.get('stats');
  return d.stats || { bounty: 0, blocked: 0, freedKB: 0 };
}
async function saveStats(s) {
  await chrome.storage.local.set({ stats: s });
}
async function renderStats() {
  const s = await getStats();
  statBounty.textContent = s.bounty;
  statBlocked.textContent = s.blocked;
  statFreed.textContent = (s.freedKB || 0).toFixed(1) + ' KB';
}

// ---- Whitelist ----
async function getKeptKeys(hostname) {
  const d = await chrome.storage.local.get('permanentWhitelist');
  const wl = d.permanentWhitelist || {};
  return wl[hostname] || [];
}

// ---- Identity resolution (mirrors the service worker) ----
async function isLoggedIn(hostname) {
  try {
    const cookies = await chrome.cookies.getAll({ url: 'https://' + hostname + '/' });
    const terms = ['token', 'session', 'auth', 'login', 'sid'];
    return cookies.some((c) => terms.some((term) => c.name.toLowerCase().indexOf(term) !== -1));
  } catch (e) {
    return false;
  }
}

async function resolveIdentity(hostname) {
  if (TIER1_HOSTS.some((h) => hostname.indexOf(h) !== -1)) {
    return { status: 'high-trust' };
  }
  const d = await chrome.storage.local.get('trustOverrides');
  const override = (d.trustOverrides || {})[hostname] || 'auto';
  if (override === 'trust') return { status: 'frozen' };
  if (override === 'force') return { status: 'fragmented' };
  const loggedIn = await isLoggedIn(hostname);
  return { status: loggedIn ? 'frozen' : 'fragmented' };
}

function renderIdentity(status) {
  identityCard.className = 'identity-card ' + status;
  const map = {
    fragmented: '🟢 ' + t('identityFragmented'),
    frozen: '🔒 ' + t('identityFrozen'),
    'high-trust': '🛡️ ' + t('identityHighTrust')
  };
  identityStatus.textContent = map[status] || '—';
}

async function refreshIdentity() {
  if (!currentHostname) return;
  const id = await resolveIdentity(currentHostname);
  renderIdentity(id.status);
}

async function syncTrustSelect() {
  const d = await chrome.storage.local.get('trustOverrides');
  const override = (d.trustOverrides || {})[currentHostname] || 'auto';
  trustSelect.value = override;
}

// ---- Scan cookies scoped to the current URL ----
async function scanCookies(url, kept) {
  let all = [];
  if (/^https?:/i.test(url)) {
    all = await chrome.cookies.getAll({ url });
  }
  const items = [];
  for (const c of all) {
    let r = window.__caClassify__(c.name, c.value);
    if (r.category === 'none') continue;
    if (kept.indexOf(c.name) !== -1) {
      r = { category: 'assets', score: 0, matchedRule: 'whitelist', locked: true };
    }
    const id = 'cookie::' + c.name;
    const removeUrl = (c.secure ? 'https' : 'http') + '://' + c.domain.replace(/^\./, '') + (c.path || '/');
    items.push({
      id, key: c.name, value: c.value, type: 'cookie',
      category: r.category, score: r.score, matchedRule: r.matchedRule, locked: r.locked
    });
    cookieMap.set(id, { url: removeUrl, name: c.name });
  }
  return { items, total: all.length };
}

// ---- Scan storage via injection ----
async function scanStorage(kept) {
  await chrome.scripting.executeScript({ target: { tabId: currentTab.id }, files: ['src/content/injector.js'] });
  const [res] = await chrome.scripting.executeScript({
    target: { tabId: currentTab.id },
    func: (keptKeys) => window.__caScanStorage__(keptKeys),
    args: [kept]
  });
  const data = res && res.result ? res.result : { items: [], totals: {} };
  return { items: data.items || [], totals: data.totals || {} };
}

// ---- Full scan ----
async function runScan() {
  const tab = await getActiveTab();
  const url = tab && tab.url ? tab.url : '';
  if (!/^(https?|file):/i.test(url)) {
    throw new Error(t('restrictedPage'));
  }
  currentTab = tab;
  currentUrl = url;
  currentHostname = new URL(url).hostname;
  domainLabel.textContent = currentHostname;

  await syncTrustSelect();
  await refreshIdentity();

  const kept = await getKeptKeys(currentHostname);
  const [cookieRes, storageRes] = await Promise.all([
    scanCookies(currentUrl, kept),
    scanStorage(kept)
  ]);

  const allItems = [...cookieRes.items, ...storageRes.items];
  allItems.sort((a, b) => b.score - a.score);
  currentItems = allItems;

  return {
    cookieTotal: cookieRes.total,
    storageTotal: (storageRes.totals.localStorage || 0) + (storageRes.totals.sessionStorage || 0)
  };
}

// ---- Render accordion with tri-state checkboxes (safe DOM only) ----
const CATEGORY_META = {
  privacy: { icon: '🚨', nameKey: 'catPrivacy' },
  junk: { icon: '🗑️', nameKey: 'catJunk' },
  assets: { icon: '🛡️', nameKey: 'catAssets' }
};
const TYPE_LABEL_KEY = { cookie: 'typeCookie', localStorage: 'typeLocal', sessionStorage: 'typeSession' };
const TYPE_ICON = { cookie: '🍪', localStorage: '🗄️', sessionStorage: '📋' };

function syncCategory(section) {
  const items = Array.from(section.querySelectorAll('.item-check:not(:disabled)'));
  const header = section.querySelector('.cat-check');
  if (items.length === 0) {
    header.checked = false;
    header.indeterminate = false;
    return;
  }
  const checked = items.filter((c) => c.checked).length;
  header.checked = checked === items.length;
  header.indeterminate = checked > 0 && checked < items.length;
}

function renderAccordion() {
  accordionEl.textContent = '';
  const groups = { privacy: [], junk: [], assets: [] };
  currentItems.forEach((it, idx) => {
    (groups[it.category] || groups.junk).push({ it, idx });
  });

  ['privacy', 'junk', 'assets'].forEach((catId) => {
    const meta = CATEGORY_META[catId];
    const entries = groups[catId];
    if (entries.length === 0) return;

    const section = el('section', 'category open');

    const head = el('div', 'cat-head');
    const headCheck = el('input', 'cat-check');
    headCheck.type = 'checkbox';
    headCheck.checked = catId !== 'assets';
    head.appendChild(headCheck);
    head.appendChild(el('span', 'cat-name', meta.icon + ' ' + t(meta.nameKey)));
    head.appendChild(el('span', 'cat-count', String(entries.length)));
    section.appendChild(head);

    const body = el('div', 'cat-body');

    entries.forEach(({ it, idx }) => {
      const row = el('div', 'item');
      const cb = el('input', 'item-check');
      cb.type = 'checkbox';
      cb.dataset.index = String(idx);
      // Behavioral assets are visually "safe" (score 0) but NOT locked: the
      // user may still manually select and delete them. They start unchecked.
      cb.checked = !it.locked;

      const bodyEl = el('div', 'item-body');
      const keyRow = el('div', 'item-key-row');
      keyRow.appendChild(el('span', 'type-badge', (TYPE_ICON[it.type] || '') + ' ' + t(TYPE_LABEL_KEY[it.type] || it.type)));
      keyRow.appendChild(el('span', 'item-key', it.key));

      bodyEl.appendChild(keyRow);
      bodyEl.appendChild(el('span', 'item-rule', it.matchedRule));
      if (it.value) bodyEl.appendChild(el('div', 'item-value', truncate(it.value, 60)));

      // Non-blocking hint shown only when the user manually checks a locked asset.
      let warnEl = null;
      if (it.locked) {
        warnEl = el('div', 'item-warn', '⚠️ ' + t('warnManualOverride'));
        warnEl.hidden = true;
        bodyEl.appendChild(warnEl);
      }

      const scoreClass = it.locked ? 'locked' : (it.score >= 60 ? 'high' : 'mid');
      const scoreEl = el('span', 'item-score ' + scoreClass, String(it.score));

      row.appendChild(cb);
      row.appendChild(bodyEl);
      row.appendChild(scoreEl);
      body.appendChild(row);

      // Show the manual-override hint while a locked asset is checked.
      cb.addEventListener('change', () => {
        if (warnEl) warnEl.hidden = !cb.checked;
        syncCategory(section);
      });
    });

    section.appendChild(body);
    accordionEl.appendChild(section);

    headCheck.addEventListener('change', () => {
      body.querySelectorAll('.item-check:not(:disabled)').forEach((c) => { c.checked = headCheck.checked; });
      syncCategory(section);
    });
    body.addEventListener('change', () => syncCategory(section));
    head.addEventListener('click', (e) => {
      if (e.target === headCheck) return;
      section.classList.toggle('open');
    });

    syncCategory(section);
  });
}

// ---- Post-deletion verification: only grant bounty for actually-deleted keys ----
async function deleteStorage(tabId, entries) {
  const [res] = await chrome.scripting.executeScript({
    target: { tabId },
    func: (list) => list.map((e) => {
      try {
        const store = e.type === 'localStorage' ? window.localStorage : window.sessionStorage;
        store.removeItem(e.key);
        return { key: e.key, type: e.type, deleted: store.getItem(e.key) === null };
      } catch (err) {
        return { key: e.key, type: e.type, deleted: false };
      }
    }),
    args: [entries]
  });
  return res && res.result ? res.result : [];
}

// ---- Events ----
btnScan.addEventListener('click', async () => {
  showState('scanning');
  try {
    await runScan();
    if (currentItems.length === 0) {
      doneText.textContent = t('noTrackers');
      showState('done');
    } else {
      renderAccordion();
      showState('result');
    }
  } catch (err) {
    doneText.textContent = t('scanFailed', [err && err.message ? err.message : String(err)]);
    showState('done');
  }
});

btnClean.addEventListener('click', async () => {
  const selected = [];
  document.querySelectorAll('.item-check:not(:disabled)').forEach((cb) => {
    if (!cb.checked) return;
    const it = currentItems[Number(cb.dataset.index)];
    if (it) selected.push(it);
  });
  if (selected.length === 0) return;

  const cookies = selected.filter((i) => i.type === 'cookie');
  const storage = selected.filter((i) => i.type !== 'cookie');

  let bountyGain = 0;
  let blocked = 0;
  let freedBytes = 0;
  let failed = 0;

  for (const it of cookies) {
    const info = cookieMap.get(it.id);
    if (!info) { failed++; continue; }
    try { await chrome.cookies.remove({ url: info.url, name: info.name }); } catch (e) {}
    const still = await chrome.cookies.get({ url: info.url, name: info.name });
    if (still) {
      failed++;
    } else {
      blocked++;
      bountyGain += it.score || 0;
      freedBytes += it.key.length + (it.value ? it.value.length : 0);
    }
  }

  if (storage.length) {
    const results = await deleteStorage(currentTab.id, storage);
    for (const r of results) {
      if (r && r.deleted) {
        blocked++;
        const it = storage.find((s) => s.key === r.key && s.type === r.type);
        if (it) {
          bountyGain += it.score || 0;
          freedBytes += it.key.length + (it.value ? it.value.length : 0);
        }
      } else {
        failed++;
      }
    }
  }

  const stats = await getStats();
  stats.bounty += bountyGain;
  stats.blocked += blocked;
  stats.freedKB += freedBytes / 1024;
  await saveStats(stats);
  await renderStats();

  let msg = t('reaped', [String(blocked), String(bountyGain)]);
  if (failed > 0) msg += ' ' + t('warningHttpOnly', [String(failed)]);
  doneText.textContent = msg;
  showState('done');
});

function backToInitial() { showState('initial'); }
btnBackResult.addEventListener('click', backToInitial);
btnBackDone.addEventListener('click', backToInitial);

// Trust override change.
trustSelect.addEventListener('change', async () => {
  if (!currentHostname) return;
  const d = await chrome.storage.local.get('trustOverrides');
  const overrides = d.trustOverrides || {};
  overrides[currentHostname] = trustSelect.value;
  await chrome.storage.local.set({ trustOverrides: overrides });
  await refreshIdentity();
});

// ---- Init: apply i18n + render stats + resolve domain/identity ----
function applyI18n() {
  document.querySelectorAll('[data-i18n]').forEach((node) => {
    node.textContent = t(node.getAttribute('data-i18n'));
  });
}

(async () => {
  applyI18n();
  await renderStats();
  try {
    const tab = await getActiveTab();
    if (tab && tab.url && /^(https?|file):/i.test(tab.url)) {
      currentHostname = new URL(tab.url).hostname;
      domainLabel.textContent = currentHostname;
      await syncTrustSelect();
      await refreshIdentity();
    } else {
      domainLabel.textContent = t('restrictedPage');
    }
  } catch (e) {
    domainLabel.textContent = '—';
  }
})();
