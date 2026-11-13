/**
 * Cookie-Assassin - Trust Tiers & Fingerprint Spoofing (MAIN world, document_start).
 *
 * Installed before any page script so hooks are in place before fingerprinters
 * run. Behavior is decided lazily by window.__caIdentity__, which the service
 * worker injects on navigation:
 *   - locked === true  -> HIGH-TRUST / FROZEN: no spoofing at all (zero disruption).
 *   - locked === false -> FRAGMENTED: spoof a stable, seed-derived hardware
 *     profile (cores / RAM / WebGL) and add subtle Canvas/Audio noise, plus a
 *     WebRTC guard to block local-IP leaks.
 *
 * Tier 1 (bank / pay / alipay / gov.cn / taobao.com) is detected statically and
 * always returns early, guaranteeing zero disruption on critical pages.
 */
(function () {
  'use strict';

  // Tier 1 high-trust domains (static, synchronous).
  const TIER1_HOSTS = ['bank', 'pay', 'alipay', 'gov.cn', 'taobao.com'];
  const host = String((window.location && window.location.hostname) || '').toLowerCase();
  const isTier1 = TIER1_HOSTS.some((h) => host.indexOf(h) !== -1);
  if (isTier1) return; // High-trust: no fingerprint changes, no WebRTC changes.

  function identity() {
    return window.__caIdentity__ || null;
  }
  function isFragmenting() {
    const id = identity();
    return !!(id && id.locked === false && id.profile);
  }

  function jitter() {
    const r = Math.random();
    if (r < 1 / 3) return -1;
    if (r > 2 / 3) return 1;
    return 0;
  }
  function clampByte(v) {
    return Math.max(0, Math.min(255, v));
  }

  // ---- Hardware fingerprint spoofing (stable, seed-derived profile) ----
  function spoofHardware() {
    try {
      const proto = Navigator.prototype;
      const cc = Object.getOwnPropertyDescriptor(proto, 'hardwareConcurrency');
      Object.defineProperty(proto, 'hardwareConcurrency', {
        configurable: true,
        get: function () {
          const id = identity();
          if (id && id.locked === false && id.profile && id.profile.cores) return id.profile.cores;
          return cc && cc.get ? cc.get.call(this) : (cc ? cc.value : undefined);
        }
      });
    } catch (e) { /* unsupported */ }

    try {
      const proto = Navigator.prototype;
      if (!('deviceMemory' in proto)) return;
      const dm = Object.getOwnPropertyDescriptor(proto, 'deviceMemory');
      Object.defineProperty(proto, 'deviceMemory', {
        configurable: true,
        get: function () {
          const id = identity();
          if (id && id.locked === false && id.profile && id.profile.memoryGB) return id.profile.memoryGB;
          return dm && dm.get ? dm.get.call(this) : (dm ? dm.value : undefined);
        }
      });
    } catch (e) { /* unsupported */ }
  }

  // ---- Canvas fingerprint noise (per-call jitter, only while fragmenting) ----
  function spoofCanvas() {
    try {
      const original = HTMLCanvasElement.prototype.toDataURL;
      HTMLCanvasElement.prototype.toDataURL = function () {
        if (isFragmenting()) {
          try {
            const ctx = this.getContext('2d');
            if (ctx) {
              const w = this.width;
              const h = this.height;
              if (w > 0 && h > 0) {
                const img = ctx.getImageData(0, 0, w, h);
                const d = img.data;
                for (let i = 0; i < d.length; i += 4) {
                  if (Math.random() < 0.03) {
                    d[i] = clampByte(d[i] + jitter());
                    d[i + 1] = clampByte(d[i + 1] + jitter());
                    d[i + 2] = clampByte(d[i + 2] + jitter());
                  }
                }
                ctx.putImageData(img, 0, 0);
              }
            }
          } catch (e) {
            // Tainted canvas -> fall through to the original method.
          }
        }
        return original.apply(this, arguments);
      };
    } catch (e) { /* Canvas unavailable */ }
  }

  // ---- WebGL renderer / vendor spoofing (stable per identity) ----
  function spoofWebGL() {
    try {
      if (typeof WebGLRenderingContext === 'undefined') return;
      const original = WebGLRenderingContext.prototype.getParameter;
      const RENDERER = [WebGLRenderingContext.RENDERER, WebGLRenderingContext.UNMASKED_RENDERER_WEBGL];
      const VENDOR = [WebGLRenderingContext.VENDOR, WebGLRenderingContext.UNMASKED_VENDOR_WEBGL];
      WebGLRenderingContext.prototype.getParameter = function (pname) {
        const id = identity();
        if (id && id.locked === false && id.profile) {
          if (RENDERER.indexOf(pname) !== -1) return id.profile.renderer;
          if (VENDOR.indexOf(pname) !== -1) return id.profile.vendor;
        }
        return original.call(this, pname);
      };
    } catch (e) { /* WebGL unavailable */ }
  }

  // ---- Web Audio (AudioContext) noise ----
  function spoofAudio() {
    const poison = (proto, method) => {
      if (!proto || typeof proto[method] !== 'function') return;
      const original = proto[method];
      proto[method] = function (array) {
        original.call(this, array);
        if (isFragmenting()) {
          try {
            if (array && array.length) {
              for (let i = 0; i < array.length; i += 512) array[i] = (array[i] || 0) + jitter();
            }
          } catch (e) { /* ignore */ }
        }
      };
    };
    try {
      if (typeof AnalyserNode !== 'undefined' && AnalyserNode.prototype) {
        poison(AnalyserNode.prototype, 'getFloatFrequencyData');
        poison(AnalyserNode.prototype, 'getByteFrequencyData');
      }
    } catch (e) { /* Web Audio unavailable */ }
  }

  // ---- WebRTC guard: block local-IP leaks while fragmenting ----
  function isPrivateIp(candidateStr) {
    const m = String(candidateStr).match(/(\d{1,3}(?:\.\d{1,3}){3})/);
    if (m) {
      const ip = m[1];
      return /^(10\.|127\.|192\.168\.|169\.254\.|0\.)/.test(ip) ||
             /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
    }
    return /(::1|fe80:|fc00:|fd00:)/i.test(candidateStr);
  }

  function guardWebRTC() {
    const Original = window.RTCPeerConnection;
    if (!Original) return;
    window.RTCPeerConnection = function (config, constraints) {
      const pc = new Original(config, constraints);
      const origAddEventListener = pc.addEventListener.bind(pc);
      pc.addEventListener = function (type, listener, options) {
        if (type === 'icecandidate' && typeof listener === 'function') {
          const wrapped = function (event) {
            if (isFragmenting()) {
              const cand = event && event.candidate;
              if (cand && cand.candidate && isPrivateIp(cand.candidate)) return; // drop local IP
            }
            return listener.call(this, event);
          };
          return origAddEventListener(type, wrapped, options);
        }
        return origAddEventListener(type, listener, options);
      };
      return pc;
    };
    window.RTCPeerConnection.prototype = Original.prototype;
  }

  spoofHardware();
  spoofCanvas();
  spoofWebGL();
  spoofAudio();
  guardWebRTC();
})();
