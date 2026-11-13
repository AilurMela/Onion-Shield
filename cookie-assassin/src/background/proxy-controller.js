/**
 * Cookie-Assassin - Proxy Controller & Identity Fragmentation Engine.
 *
 * Loaded into the service worker via importScripts(). Owns the source of truth
 * for the current "identity" (FingerprintSeed + a logically consistent hardware
 * profile). Responsibilities:
 *  1. Generate and persist an identity in chrome.storage.session.
 *  2. Monitor public-IP changes; rotate the identity (new seed + new profile)
 *     when the IP changes, so fragments cannot be re-linked across networks.
 *  3. Apply proxy settings ONLY if the user has explicitly configured a proxy.
 *     It never forces connections and never touches the system proxy otherwise.
 *
 * Least-privilege: chrome.proxy is only mutated after an explicit opt-in; no
 * connection is ever forced by this module.
 */
'use strict';

(function () {
  const STORAGE_KEY = 'identity';
  const IP_ECHO_URL = 'https://api.ipify.org?format=json';
  const IP_CHECK_THROTTLE_MS = 5 * 60 * 1000; // 5 minutes

  // Curated hardware profiles: each entry is a realistic, internally
  // consistent combination of core count, RAM and GPU. A single seed selects
  // ONE profile atomically, so we can never produce an impossible pairing
  // (e.g. 64 GB RAM with a decade-old GPU).
  const HARDWARE_PROFILES = [
    { cores: 4, memoryGB: 4, vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel(R) UHD Graphics 620, OpenGL 4.1)' },
    { cores: 8, memoryGB: 8, vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics, OpenGL 4.6)' },
    { cores: 8, memoryGB: 16, vendor: 'Google Inc. (Apple)', renderer: 'ANGLE (Apple, Apple M1, OpenGL 4.1)' },
    { cores: 12, memoryGB: 16, vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Ti, OpenGL 4.6)' },
    { cores: 16, memoryGB: 32, vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon RX 6800, OpenGL 4.6)' }
  ];

  let lastIpCheck = 0;

  function randomSeed() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  function hashCode(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) | 0;
    return Math.abs(h);
  }

  async function getIdentity() {
    const d = await chrome.storage.session.get(STORAGE_KEY);
    return d[STORAGE_KEY] || null;
  }

  async function rotateIdentity() {
    const seed = randomSeed();
    const profileIndex = hashCode(seed) % HARDWARE_PROFILES.length;
    const identity = {
      seed,
      profileIndex,
      profile: HARDWARE_PROFILES[profileIndex],
      createdAt: Date.now()
    };
    await chrome.storage.session.set({ [STORAGE_KEY]: identity });
    return identity;
  }

  // Best-effort public-IP lookup. Returns null on any failure (offline,
  // blocked, or the echo service is down) so we never break on network errors.
  async function detectPublicIp() {
    try {
      const res = await fetch(IP_ECHO_URL, { cache: 'no-store' });
      if (!res.ok) return null;
      const data = await res.json();
      return data && data.ip ? String(data.ip) : null;
    } catch (e) {
      return null;
    }
  }

  async function maybeRotateOnIpChange(identity) {
    const now = Date.now();
    if (now - lastIpCheck < IP_CHECK_THROTTLE_MS) return identity;
    lastIpCheck = now;

    const ip = await detectPublicIp();
    if (!ip) return identity;

    const ipHash = hashCode(ip).toString();
    if (identity.ipHash && identity.ipHash !== ipHash) {
      // Network changed -> new identity so fragments cannot be linked.
      return rotateIdentity();
    }
    identity.ipHash = ipHash;
    await chrome.storage.session.set({ [STORAGE_KEY]: identity });
    return identity;
  }

  async function ensureIdentity() {
    let identity = await getIdentity();
    if (!identity) identity = await rotateIdentity();
    return maybeRotateOnIpChange(identity);
  }

  // Apply proxy settings ONLY when explicitly configured. Never force.
  async function applyProxySettings() {
    const d = await chrome.storage.local.get('proxyConfig');
    const cfg = d.proxyConfig;
    if (!cfg || !cfg.enabled || !cfg.mode) return; // no explicit opt-in -> no-op

    try {
      const value = { mode: cfg.mode };
      if (cfg.mode === 'fixed_servers') {
        value.rules = {
          singleProxy: {
            scheme: cfg.scheme || 'http',
            host: cfg.host,
            port: Number(cfg.port) || 8080
          }
        };
      }
      await chrome.proxy.settings.set({ value, scope: 'regular' });
    } catch (e) {
      // Invalid config or proxy unavailable -> leave settings untouched.
    }
  }

  self.ProxyController = {
    HARDWARE_PROFILES,
    ensureIdentity,
    rotateIdentity,
    getIdentity,
    applyProxySettings
  };
})();
