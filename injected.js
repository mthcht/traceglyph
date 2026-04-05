// ============================================================================
// injected.js - TraceGlyph by mthcht
// ============================================================================
//
// PAGE-CONTEXT HOOKS - Runs in the page's "main world" JavaScript context.
// This is the core fingerprint detection engine. It monkey-patches browser
// APIs to intercept and log every fingerprinting attempt in real time.
//
// EXECUTION CONTEXT:
//   - Injected into the page's main world by content.js via <script> tag.
//   - Has full access to window.*, navigator.*, document.* as the page sees them.
//   - CANNOT access chrome.runtime.* (no extension privileges).
//   - Communicates with content.js via window.postMessage(__FPG_DETECTION__).
//
// THREE OPERATING MODES (set via data-tg-mode attribute on <html>):
//   - "off" (observe): Hooks fire, log detections, but return REAL values.
//     The page gets its actual fingerprint. Used for analysis/investigation.
//   - "ghost" (block): Hooks return GENERIC/DEFAULT values to make the
//     browser look identical to every other browser. Goal: untrackability.
//   - "spoof" (randomize): Hooks return FAKE but REALISTIC values from
//     curated pools. Values stay consistent within a page load (deterministic
//     seed). Goal: each session looks like a different real device.
//
// SELF-FILTERING:
//   - isSelfTriggered() checks the call stack for chrome-extension:// frames.
//     If the caller is our own extension, the detection is silently dropped.
//   - Extension's own URLs are filtered from fetch/XHR/WebSocket hooks.
//   - Emission cap: max 5 detections per unique key per execution context
//     to prevent noisy APIs (e.g. navigator.userAgent read 100x) from
//     flooding the dashboard.
//
// SAME-ORG DETECTION (isSameOrg):
//   - Determines if a network request goes to the page's own infrastructure.
//   - Checks: same origin, same apex domain, CDN ownership mapping (16
//     platforms), and last-word fallback for new TLDs (.microsoft, etc.).
//   - Same-org requests are NOT flagged as data exfiltration.
//
// HOOKED APIs (40+ vectors):
//
//   NAVIGATOR PROBING (25 properties):
//     platform, vendor, language, languages, hardwareConcurrency, deviceMemory,
//     maxTouchPoints, webdriver, plugins, mimeTypes, userAgent, cookieEnabled,
//     pdfViewerEnabled, connection, gpu, keyboard, hid, usb, serial, bluetooth,
//     doNotTrack, oscpu, appVersion, appCodeName, product.
//     Ghost: returns generic Win32/Google Inc./en-US/4 cores/8GB profile.
//     Spoof: picks from pools of 4 UAs, 9 languages, 7 core counts, etc.
//
//   CANVAS FINGERPRINT (3 methods):
//     toDataURL, toBlob, getImageData.
//     Ghost: returns blank canvas / zeroed pixel data.
//     Spoof: injects invisible noise pixels before read, randomizing hash.
//
//   WEBGL FINGERPRINT (4 methods):
//     getParameter (VENDOR, RENDERER, VERSION, SHADING_LANGUAGE_VERSION,
//     MAX_TEXTURE_SIZE, UNMASKED_VENDOR_WEBGL, UNMASKED_RENDERER_WEBGL),
//     getExtension (blocks/logs debug_renderer_info),
//     getSupportedExtensions, readPixels.
//     Ghost: returns "WebKit"/"WebKit WebGL", strips debug extension.
//     Spoof: picks from 8 real GPU renderer strings (GTX 1060, RX 580,
//     RTX 3060, RTX 4070, Iris Xe, Apple M1 Pro, etc.).
//
//   WEBGPU FINGERPRINT:
//     navigator.gpu.requestAdapter() - logs adapter vendor, architecture,
//     device, features count. Ghost: returns null. Spoof: logs real values.
//
//   AUDIO FINGERPRINT (7 methods):
//     AudioContext constructor, createOscillator, createAnalyser,
//     createDynamicsCompressor, createBiquadFilter, createGain,
//     createScriptProcessor, OfflineAudioContext constructor.
//     Ghost: nodes created but fingerprint data neutered.
//     Logs: sampleRate, baseLatency, node parameters.
//
//   SCREEN PROFILING (8 properties + CSS):
//     screen.width/height/colorDepth/pixelDepth/availWidth/availHeight,
//     devicePixelRatio, screen.orientation.type.
//     CSS media query fingerprinting: colorGamut, invertedColors, forcedColors,
//     reducedMotion, reducedTransparency, prefersContrast, hdr, monochrome,
//     pointer. Ghost: all queries return false. Spoof: randomized.
//
//   FONT ENUMERATION:
//     measureText() call counting + font family tracking.
//     document.fonts.check() interception.
//     Ghost: returns constant metrics to block enumeration.
//
//   WEBRTC LEAK:
//     RTCPeerConnection constructor. Ghost: returns dummy object.
//
//   BATTERY API:
//     getBattery() + BatteryManager properties.
//     Ghost: returns fake full battery (100%, charging, infinite).
//     Spoof: randomized level/charging state.
//
//   MEDIA DEVICES:
//     enumerateDevices(). Ghost: returns 1 generic device per type.
//     Spoof: randomized device count.
//
//   TIMEZONE:
//     Intl.DateTimeFormat (resolvedOptions().timeZone).
//     Date.getTimezoneOffset().
//     Ghost: returns UTC. Spoof: picks from 10 real timezones.
//
//   MATH FINGERPRINT:
//     Hooks 16 Math functions (acos, cos, tan, etc.) - detects rapid
//     probing. Spoof: adds float-precision noise.
//
//   BEHAVIORAL BIOMETRICS:
//     Monitors addEventListener for mousemove, keydown, touchstart, scroll,
//     deviceorientation, devicemotion. Flags when 3+ listeners active.
//
//   CLIPBOARD ACCESS:
//     clipboard.readText, clipboard.read, clipboard.writeText.
//     Ghost: read returns empty, write silently dropped.
//
//   DATA EXFILTRATION:
//     fetch() and XMLHttpRequest - only flags CROSS-ORIGIN requests.
//     Same-org requests (including CDN domains) are silently skipped.
//     sendBeacon() always logged.
//
//   DYNAMIC CODE EXECUTION:
//     eval(), setTimeout(string), setInterval(string).
//     btoa/atob only flagged above 10KB (avoids noise from normal base64).
//
//   WORKERS:
//     new Worker(), ServiceWorker.register(), new SharedWorker().
//
//   WEBSOCKET:
//     new WebSocket() constructor.
//
//   CRYPTO/MINING:
//     WebAssembly.instantiate/instantiateStreaming (threshold: CRITICAL > 500KB).
//     crypto.subtle.digest (count-based alerting).
//
//   STORAGE ACCESS:
//     localStorage/sessionStorage (getItem, setItem), indexedDB.open,
//     document.cookie access.
//
//   INCOGNITO DETECTION:
//     navigator.storage.estimate() - ghost returns large quota.
//     webkitRequestFileSystem probing.
//
//   DOM MUTATION OBSERVER:
//     Monitors dynamic <script>, <iframe>, <object>, <embed> injection.
//     Capped to 5 emissions + summary. Same-org scripts get LOW severity.
//     about:blank iframes get LOW/MEDIUM (not CRITICAL).
//
//   CREDENTIAL ACCESS:
//     navigator.credentials.get() - classifies FedCM, WebAuthn, password
//     autofill, and unknown credential requests with appropriate severity.
//
//   GEOLOCATION:
//     getCurrentPosition, watchPosition.
//
//   SPEECH SYNTHESIS:
//     getVoices() - voice list fingerprint. Ghost: returns empty.
//
//   GAMEPAD API:
//     getGamepads() - connected gamepad fingerprint. Ghost: returns empty.
//
//   NETWORK INFORMATION:
//     connection.downlink, effectiveType, rtt, saveData.
//     Ghost: returns generic 4g/10Mbps. Spoof: randomized.
//
//   PERMISSION PROBING:
//     navigator.permissions.query().
//
//   postMessage:
//     window.postMessage() with wildcard "*" origin.
//
// SPOOF VALUE POOLS:
//   4 user agents, 9 language sets, 10 screen resolutions, 7 core counts,
//   5 memory sizes, 8 GPU renderers, 10 timezones, 10 timezone offsets,
//   26 WebGL extensions, 2 audio sample rates, 10 font families,
//   5 media device counts, 6 WebGPU architectures, 2 color depths,
//   4 pixel ratios, 4 platforms, 3 vendors, 6 touch point values.
//
// DETECTION SEVERITIES:
//   CRITICAL: active data theft, credential access, IP leak
//   HIGH:     fingerprinting with unique identifier potential
//   MEDIUM:   profiling, network analysis, permission probing
//   LOW:      passive info reads, standard API usage
//   INFO:     page integrity hashes, metadata
//
// MITRE ATT&CK MAPPING (26 techniques):
//   T1082, T1016, T1518, T1497, T1566, T1059.007, T1027, T1041, T1071,
//   T1557, T1119, T1005, T1056, T1496, T1115, T1189, T1204, T1102,
//   T1573, T1132, T1571, T1090, T1105, T1014, T1070, T1583.
//
// ============================================================================
(function () {
  'use strict';

  // ── MODE ENGINE ────────────────────────────────────────
  function getMode() {
    try { return document.documentElement.getAttribute('data-tg-mode') || 'off'; } catch(e) { return 'off'; }
  }
  // Watch for mode changes (popup can update data attribute live)
  var _tgMode = getMode();
  new MutationObserver(function(muts) {
    muts.forEach(function(m) { if (m.attributeName === 'data-tg-mode') _tgMode = getMode(); });
  }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-tg-mode'] });

  // Spoof value pools - realistic randomized values
  var SPOOF = {
    platforms: ['Win32', 'MacIntel', 'Linux x86_64', 'Linux aarch64'],
    vendors: ['Google Inc.', 'Apple Computer, Inc.', ''],
    userAgents: [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
    ],
    languages: [['en-US','en'], ['en-GB','en'], ['fr-FR','fr'], ['de-DE','de'], ['es-ES','es'], ['pt-BR','pt'], ['ja-JP','ja'], ['ko-KR','ko'], ['zh-CN','zh']],
    screens: [[1920,1080], [1366,768], [1440,900], [1536,864], [2560,1440], [1280,720], [1680,1050], [3840,2160], [1600,900], [1280,800]],
    colorDepths: [24, 32],
    pixelRatios: [1, 1.25, 1.5, 2],
    cores: [2, 4, 6, 8, 10, 12, 16],
    memory: [2, 4, 8, 16, 32],
    touchPoints: [0, 0, 0, 1, 5, 10],
    gpuVendors: ['Google Inc. (NVIDIA)', 'Google Inc. (AMD)', 'Google Inc. (Intel)', 'Google Inc. (Apple)', 'Google Inc. (NVIDIA Corporation)'],
    gpuRenderers: [
      'ANGLE (NVIDIA, NVIDIA GeForce GTX 1060 Direct3D11 vs_5_0 ps_5_0, D3D11)',
      'ANGLE (AMD, Radeon RX 580 Series Direct3D11 vs_5_0 ps_5_0, D3D11)',
      'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)',
      'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)',
      'ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)',
      'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)',
      'Apple GPU',
      'ANGLE (Apple, ANGLE Metal Renderer: Apple M1 Pro, Unspecified Version)'
    ],
    timezones: ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Asia/Tokyo', 'Asia/Shanghai', 'Australia/Sydney'],
    tzOffsets: [300, 360, 420, 480, 0, -60, -120, -540, -480, -600],
    glExtensions: ['ANGLE_instanced_arrays','EXT_blend_minmax','EXT_color_buffer_half_float','EXT_float_blend','EXT_frag_depth','EXT_shader_texture_lod','EXT_texture_compression_rgtc','EXT_texture_filter_anisotropic','EXT_sRGB','OES_element_index_uint','OES_fbo_render_mipmap','OES_standard_derivatives','OES_texture_float','OES_texture_float_linear','OES_texture_half_float','OES_texture_half_float_linear','OES_vertex_array_object','WEBGL_color_buffer_float','WEBGL_compressed_texture_s3tc','WEBGL_compressed_texture_s3tc_srgb','WEBGL_debug_renderer_info','WEBGL_debug_shaders','WEBGL_depth_texture','WEBGL_draw_buffers','WEBGL_lose_context','WEBGL_multi_draw'],
    audioSampleRates: [44100, 48000],
    fontFamilies: ['Arial','Verdana','Helvetica','Times New Roman','Georgia','Courier New','Trebuchet MS','Impact','Comic Sans MS','Lucida Console'],
    mediaDeviceCounts: [1, 2, 3, 4, 5],
    webgpuArchitectures: ['gen-9', 'gen-12', 'ampere', 'rdna-2', 'rdna-3', 'apple-common'],
  };
  // Deterministic per-session random (same values within a page load)
  var _spoofSeed = Math.random();
  function spoofPick(arr) { return arr[Math.floor(_spoofSeed * 7919 % arr.length)]; }
  function spoofInt(min, max) { return min + Math.floor((_spoofSeed * 6271) % (max - min + 1)); }
  function spoofFloat(base, variance) { return +(base + (_spoofSeed * variance * 2 - variance)).toFixed(6); }

  // Ghost default values
  var GHOST = {
    platform: 'Win32', vendor: 'Google Inc.', languages: ['en-US','en'],
    screen: [1920, 1080], colorDepth: 24, pixelRatio: 1, cores: 4, memory: 8,
    touchPoints: 0, timezone: 'UTC', tzOffset: 0,
  };

  const CAT = {
    NAV: 'Navigator Probing', CANVAS: 'Canvas Fingerprint', WEBGL: 'WebGL Fingerprint',
    AUDIO: 'Audio Fingerprint', SCREEN: 'Screen Profiling', FONT: 'Font Enumeration',
    BATTERY: 'Battery API', NETWORK: 'Network Info', WEBRTC: 'WebRTC Leak',
    STORAGE: 'Storage Access', TIMING: 'Timing/Perf', MEDIA: 'Media Devices',
    PERM: 'Permission Probe', EVAL: 'Dynamic Code Exec', EXFIL: 'Data Exfiltration',
    WS: 'WebSocket', WORKER: 'Worker/SW', CRYPTO: 'Crypto/Mining',
    DOM: 'DOM Manipulation', CLIPBOARD: 'Clipboard Access', POSTMSG: 'postMessage',
    CRED: 'Credential Access', NETANOM: 'Network Anomaly',
  };
  const SEV = { L: 'low', M: 'medium', H: 'high', C: 'critical' };

  // Track call counts per detection key
  const callCounts = {};

  function getStack() {
    try { throw new Error(); } catch (e) {
      return (e.stack || '').split('\n').slice(2, 6).map(function(l){ return l.trim(); }).join(' | ');
    }
  }

  // Self-filter: check if the CALLER is from our own extension
  function isSelfTriggered() {
    try {
      var err = new Error();
      var lines = (err.stack || '').split('\n');
      for (var i = 1; i < Math.min(lines.length, 8); i++) {
        var line = lines[i] || '';
        // Skip frames from this file (injected.js) and the emit/isSelfTriggered functions
        if (line.indexOf('injected.js') !== -1) continue;
        if (line.indexOf('isSelfTriggered') !== -1 || line.indexOf('emit') !== -1) continue;
        // First non-injected.js frame = the actual caller
        if (line.indexOf('chrome-extension://') !== -1 || line.indexOf('moz-extension://') !== -1) {
          return true; // Called by our extension (tech-detect.js, content.js, etc.)
        }
        return false; // Called by page code
      }
    } catch(e) {}
    return false;
  }

  function emit(category, detail, severity, valueRead, meta) {
    if (isSelfTriggered()) return; // Skip our own extension's activity

    var key = category + '::' + detail;
    callCounts[key] = (callCounts[key] || 0) + 1;

    // Cap emissions: only emit first 5 occurrences per detection key to reduce noise
    // After that, just count silently
    if (callCounts[key] > 5) return;

    // Smart value serialization - show what the browser actually responded
    var displayValue = '';
    try {
      if (valueRead == null || valueRead === undefined) { displayValue = 'undefined'; }
      else if (typeof valueRead === 'boolean') { displayValue = String(valueRead); }
      else if (typeof valueRead === 'number') { displayValue = String(valueRead); }
      else if (typeof valueRead === 'string') { displayValue = valueRead; }
      else if (Array.isArray(valueRead)) { displayValue = JSON.stringify(valueRead); }
      else if (valueRead instanceof PluginArray || (valueRead && typeof valueRead.length === 'number' && valueRead.item)) {
        var pArr = [];
        for (var pi = 0; pi < Math.min(valueRead.length, 20); pi++) {
          var pl = valueRead[pi];
          pArr.push(pl ? pl.name : '?');
        }
        displayValue = pArr.join(', ') + (valueRead.length > 20 ? ' (+' + (valueRead.length - 20) + ' more)' : '');
      }
      else if (typeof valueRead === 'object') {
        try { displayValue = JSON.stringify(valueRead); } catch(e2) { displayValue = String(valueRead); }
      }
      else { displayValue = String(valueRead); }
    } catch (e) { displayValue = String(valueRead || ''); }

    var entry = {
      category: category,
      detail: detail,
      severity: severity,
      valueRead: displayValue.substring(0, 512),
      timestamp: Date.now(),
      stack: getStack(),
      meta: meta || null,
      callCount: callCounts[key]
    };
    window.postMessage({ type: '__FPG_DETECTION__', payload: entry }, '*');
  }

  // ── NAVIGATOR PROPERTIES ───────────────────────────────
  var navHooks = {
    plugins:             [SEV.H, 'Accessed navigator.plugins (plugin enumeration)'],
    mimeTypes:           [SEV.H, 'Accessed navigator.mimeTypes'],
    hardwareConcurrency: [SEV.M, 'Read CPU core count (hardwareConcurrency)'],
    deviceMemory:        [SEV.M, 'Read device RAM (deviceMemory)'],
    platform:            [SEV.L, 'Read OS platform string'],
    userAgent:           [SEV.L, 'Read User-Agent string'],
    vendor:              [SEV.L, 'Read browser vendor'],
    languages:           [SEV.L, 'Read accepted languages'],
    language:            [SEV.L, 'Read primary language'],
    maxTouchPoints:      [SEV.M, 'Read touch point count'],
    cookieEnabled:       [SEV.L, 'Checked cookie support'],
    doNotTrack:          [SEV.L, 'Read Do-Not-Track preference'],
    connection:          [SEV.M, 'Accessed NetworkInformation API'],
    webdriver:           [SEV.H, 'Probed webdriver flag (bot detection)'],
    userAgentData:       [SEV.M, 'Accessed UA Client Hints'],
    mediaCapabilities:   [SEV.M, 'Probed media decoding capabilities'],
    keyboard:            [SEV.M, 'Accessed Keyboard Layout Map'],
    hid:                 [SEV.H, 'Accessed WebHID (hardware devices)'],
    usb:                 [SEV.H, 'Accessed WebUSB'],
    serial:              [SEV.H, 'Accessed Web Serial'],
    bluetooth:           [SEV.H, 'Accessed Web Bluetooth'],
    gpu:                 [SEV.H, 'Accessed WebGPU adapter'],
    pdfViewerEnabled:    [SEV.L, 'Read PDF viewer status (pdfViewerEnabled)'],
    oscpu:               [SEV.M, 'Read OS/CPU identifier (oscpu)'],
    cpuClass:            [SEV.M, 'Read CPU class (cpuClass - IE/Edge legacy)'],
  };

  for (var prop in navHooks) {
    (function(p, sev, detail) {
      try {
        var desc = Object.getOwnPropertyDescriptor(Navigator.prototype, p) || Object.getOwnPropertyDescriptor(navigator, p);
        if (desc && desc.get) {
          var orig = desc.get;
          Object.defineProperty(Navigator.prototype, p, {
            get: function() {
              var v = orig.call(this);
              var mode = _tgMode;
              if (mode === 'ghost') {
                emit(CAT.NAV, '👻 BLOCKED: ' + detail, sev, 'Ghost mode - returned generic value');
                if (p === 'platform') return GHOST.platform;
                if (p === 'vendor') return GHOST.vendor;
                if (p === 'languages') return GHOST.languages;
                if (p === 'language') return GHOST.languages[0];
                if (p === 'hardwareConcurrency') return GHOST.cores;
                if (p === 'deviceMemory') return GHOST.memory;
                if (p === 'maxTouchPoints') return GHOST.touchPoints;
                if (p === 'plugins') return [];
                if (p === 'mimeTypes') return [];
                if (p === 'webdriver') return false;
                if (p === 'userAgent') return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
                if (p === 'cookieEnabled') return true;
                if (p === 'pdfViewerEnabled') return true;
                if (p === 'oscpu') return undefined;
                if (p === 'doNotTrack') return null;
                if (p === 'connection') return { downlink: 10, effectiveType: '4g', rtt: 50, saveData: false, addEventListener: function(){} };
                if (p === 'gpu') return undefined; // Hide WebGPU entirely in ghost mode
                if (p === 'keyboard') return undefined;
                if (p === 'hid') return undefined;
                if (p === 'usb') return undefined;
                if (p === 'serial') return undefined;
                if (p === 'bluetooth') return undefined;
                return v;
              }
              if (mode === 'spoof') {
                var fakeV = v;
                if (p === 'platform') fakeV = spoofPick(SPOOF.platforms);
                else if (p === 'vendor') fakeV = spoofPick(SPOOF.vendors);
                else if (p === 'languages') fakeV = spoofPick(SPOOF.languages);
                else if (p === 'language') fakeV = spoofPick(SPOOF.languages)[0];
                else if (p === 'hardwareConcurrency') fakeV = spoofPick(SPOOF.cores);
                else if (p === 'deviceMemory') fakeV = spoofPick(SPOOF.memory);
                else if (p === 'maxTouchPoints') fakeV = spoofPick(SPOOF.touchPoints);
                else if (p === 'webdriver') fakeV = false;
                else if (p === 'userAgent') fakeV = spoofPick(SPOOF.userAgents);
                else if (p === 'doNotTrack') fakeV = spoofPick([null, '1', 'unspecified']);
                else if (p === 'cookieEnabled') fakeV = true;
                else if (p === 'pdfViewerEnabled') fakeV = true;
                else if (p === 'connection') fakeV = { downlink: spoofPick([1.5, 5, 10, 20, 50]), effectiveType: spoofPick(['3g','4g','4g','4g']), rtt: spoofPick([50, 100, 150, 200]), saveData: false, addEventListener: function(){} };
                emit(CAT.NAV, '🎭 SPOOFED: ' + detail, sev, 'Real: ' + v + ' → Fake: ' + fakeV);
                return fakeV;
              }
              emit(CAT.NAV, detail, sev, v);
              return v;
            },
            configurable: true,
          });
        }
      } catch (e) {}
    })(prop, navHooks[prop][0], navHooks[prop][1]);
  }

  // getBattery
  if (navigator.getBattery) {
    var origBattery = navigator.getBattery.bind(navigator);
    navigator.getBattery = function () {
      if (_tgMode === 'ghost') {
        emit(CAT.BATTERY, '👻 BLOCKED: getBattery()', SEV.H, 'Ghost mode - returned fake battery');
        return Promise.resolve({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: 1, addEventListener: function(){} });
      }
      emit(CAT.BATTERY, 'Called getBattery()', SEV.H, 'Promise<BatteryManager>');
      return origBattery().then(function(bm) {
        emit(CAT.BATTERY, 'Battery info read', SEV.H, 'charging: ' + bm.charging + ', level: ' + Math.round(bm.level * 100) + '%, chargingTime: ' + bm.chargingTime + 's, dischargingTime: ' + bm.dischargingTime + 's');
        return bm;
      });
    };
  }

  // mediaDevices.enumerateDevices
  try {
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      var origEnum = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);
      navigator.mediaDevices.enumerateDevices = function () {
        if (_tgMode === 'ghost') {
          emit(CAT.MEDIA, '👻 BLOCKED: enumerateDevices()', SEV.H, 'Ghost mode - returned 1 generic device per type');
          return Promise.resolve([
            { deviceId: '', groupId: '', kind: 'audioinput', label: '' },
            { deviceId: '', groupId: '', kind: 'videoinput', label: '' },
            { deviceId: '', groupId: '', kind: 'audiooutput', label: '' }
          ]);
        }
        var label = _tgMode === 'spoof' ? '🎭 SPOOFED: ' : '';
        emit(CAT.MEDIA, label + 'Enumerating media devices...', SEV.H, 'MediaDeviceInfo[]');
        return origEnum().then(function(devices) {
          var summary = {};
          devices.forEach(function(d) { summary[d.kind] = (summary[d.kind] || 0) + 1; });
          var sumStr = Object.entries(summary).map(function(e) { return e[1] + ' ' + e[0]; }).join(', ');
          emit(CAT.MEDIA, label + 'Found ' + devices.length + ' media device(s)', SEV.H, sumStr + ' - deviceIds: ' + devices.map(function(d){ return d.deviceId ? d.deviceId.substring(0,8)+'...' : '(empty)'; }).join(', '));
          if (_tgMode === 'spoof') {
            // Shuffle device order and truncate to random count
            var ct = spoofPick(SPOOF.mediaDeviceCounts);
            return devices.slice(0, Math.min(ct * 3, devices.length));
          }
          return devices;
        });
      };
    }
  } catch (e) {}

  // credentials
  try {
    if (navigator.credentials && navigator.credentials.get) {
      var origCredGet = navigator.credentials.get.bind(navigator.credentials);
      navigator.credentials.get = function (opts) {
        var isStandard = opts && (opts.identity || opts.federated || opts.otp || opts.publicKey || opts.password);
        var sev = isStandard ? SEV.M : SEV.C;
        var detail = isStandard ? 'navigator.credentials.get() - standard authentication' : 'navigator.credentials.get() - credential access';
        if (opts && opts.password) detail = 'navigator.credentials.get({password:true}) - browser password autofill';
        else if (opts && opts.identity) detail = 'navigator.credentials.get() - FedCM login flow';
        else if (opts && opts.publicKey) detail = 'navigator.credentials.get() - WebAuthn/passkey';
        emit(CAT.CRED, detail, sev, JSON.stringify(opts || {}).substring(0, 300));
        return origCredGet(opts);
      };
    }
  } catch (e) {}

  // permissions.query
  try {
    if (navigator.permissions && navigator.permissions.query) {
      var origPermQ = navigator.permissions.query.bind(navigator.permissions);
      navigator.permissions.query = function (desc) {
        emit(CAT.PERM, 'Probed permission: ' + (desc && desc.name || 'unknown'), SEV.M, JSON.stringify(desc));
        return origPermQ(desc);
      };
    }
  } catch (e) {}

  // sendBeacon
  if (navigator.sendBeacon) {
    var origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      var size = data ? (typeof data === 'string' ? data.length : data.size || 0) : 0;
      emit(CAT.EXFIL, 'sendBeacon to ' + url, size > 1024 ? SEV.H : SEV.M, size + ' bytes', { url: url, size: size });
      return origBeacon(url, data);
    };
  }

  // ── CANVAS FINGERPRINTING ──────────────────────────────
  var _toDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function () {
    var r = _toDataURL.apply(this, arguments);
    if (this.width > 0 && this.height > 0) {
      var mode = _tgMode;
      if (mode === 'ghost') {
        emit(CAT.CANVAS, '👻 BLOCKED: canvas.toDataURL(' + this.width + '\u00d7' + this.height + ')', SEV.C, 'Ghost mode - returned blank canvas');
        var blank = document.createElement('canvas'); blank.width = this.width; blank.height = this.height;
        return _toDataURL.call(blank);
      }
      if (mode === 'spoof') {
        // Add noise pixels to canvas to randomize fingerprint
        try {
          var ctx = this.getContext('2d');
          if (ctx) { ctx.fillStyle = 'rgba(' + spoofInt(0,3) + ',' + spoofInt(0,3) + ',' + spoofInt(0,3) + ',0.01)'; ctx.fillRect(spoofInt(0,5), spoofInt(0,5), 1, 1); }
        } catch(e) {}
        var spoofed = _toDataURL.apply(this, arguments);
        emit(CAT.CANVAS, '🎭 SPOOFED: canvas.toDataURL(' + this.width + '\u00d7' + this.height + ')', SEV.C, 'Added noise - fingerprint randomized');
        return spoofed;
      }
      var preview = r.substring(0, 60) + '... (' + r.length + ' chars)';
      emit(CAT.CANVAS, 'canvas.toDataURL(' + this.width + '\u00d7' + this.height + ')', SEV.C, preview);
    }
    return r;
  };
  var _toBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = function (cb) {
    if (this.width > 0 && this.height > 0) {
      if (_tgMode === 'ghost') {
        emit(CAT.CANVAS, '👻 BLOCKED: canvas.toBlob(' + this.width + '\u00d7' + this.height + ')', SEV.C, 'Ghost mode - returned blank canvas blob');
        var blank = document.createElement('canvas'); blank.width = this.width; blank.height = this.height;
        return _toBlob.call(blank, cb);
      }
      if (_tgMode === 'spoof') {
        try { var ctx = this.getContext('2d'); if (ctx) { ctx.fillStyle = 'rgba(' + spoofInt(0,3) + ',' + spoofInt(0,3) + ',' + spoofInt(0,3) + ',0.01)'; ctx.fillRect(spoofInt(0,5), spoofInt(0,5), 1, 1); } } catch(e) {}
        emit(CAT.CANVAS, '🎭 SPOOFED: canvas.toBlob(' + this.width + '\u00d7' + this.height + ')', SEV.C, 'Noise injected - blob fingerprint randomized');
      } else {
        emit(CAT.CANVAS, 'canvas.toBlob(' + this.width + '\u00d7' + this.height + ')', SEV.C, 'Blob callback');
      }
    }
    return _toBlob.apply(this, arguments);
  };
  var _getImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function (x, y, w, h) {
    var result = _getImageData.apply(this, arguments);
    if (_tgMode === 'ghost') {
      emit(CAT.CANVAS, '👻 BLOCKED: getImageData(' + x + ',' + y + ',' + w + ',' + h + ')', SEV.H, 'Ghost mode - returned zeroed pixel data (' + w*h*4 + ' bytes)');
      return new ImageData(w, h); // all zeros
    }
    if (_tgMode === 'spoof') {
      // Add subtle noise to a few random pixels
      for (var ni = 0; ni < 3; ni++) { var px = spoofInt(0, result.data.length - 4); result.data[px] = (result.data[px] + spoofInt(1,3)) & 0xFF; }
      emit(CAT.CANVAS, '🎭 SPOOFED: getImageData(' + x + ',' + y + ',' + w + ',' + h + ')', SEV.H, 'Noise injected into ' + w + '\u00d7' + h + ' pixel data (' + result.data.length + ' bytes)');
      return result;
    }
    emit(CAT.CANVAS, 'getImageData(' + x + ',' + y + ',' + w + ',' + h + ')', SEV.H, 'ImageData ' + w + '\u00d7' + h + ' (' + result.data.length + ' bytes, first 4px RGBA: [' + result.data[0] + ',' + result.data[1] + ',' + result.data[2] + ',' + result.data[3] + '])');
    return result;
  };
  var _readPixels = WebGLRenderingContext.prototype.readPixels;
  WebGLRenderingContext.prototype.readPixels = function () {
    if (_tgMode === 'ghost') {
      emit(CAT.CANVAS, '👻 BLOCKED: WebGL readPixels()', SEV.H, 'Ghost mode - returned empty pixel buffer');
      return; // don't fill the buffer
    }
    var label = _tgMode === 'spoof' ? '🎭 SPOOFED: ' : '';
    emit(CAT.CANVAS, label + 'WebGL readPixels()', SEV.H, 'Reading GPU-rendered pixel buffer (x:' + arguments[0] + ' y:' + arguments[1] + ' w:' + arguments[2] + ' h:' + arguments[3] + ')');
    return _readPixels.apply(this, arguments);
  };

  // ── WEBGL FINGERPRINTING ───────────────────────────────
  var glTargets = [WebGLRenderingContext];
  if (typeof WebGL2RenderingContext !== 'undefined') glTargets.push(WebGL2RenderingContext);
  var paramNames = {};
  paramNames[0x1F00] = 'VENDOR'; paramNames[0x1F01] = 'RENDERER'; paramNames[0x1F02] = 'VERSION';
  paramNames[0x8B8C] = 'SHADING_LANGUAGE_VERSION'; paramNames[0x0D33] = 'MAX_TEXTURE_SIZE';
  paramNames[0x8869] = 'MAX_VERTEX_ATTRIBS'; paramNames[0x8DFB] = 'MAX_VARYING_VECTORS';
  paramNames[0x9245] = 'UNMASKED_VENDOR_WEBGL'; paramNames[0x9246] = 'UNMASKED_RENDERER_WEBGL';

  glTargets.forEach(function(GL) {
    var origParam = GL.prototype.getParameter;
    GL.prototype.getParameter = function (p) {
      var r = origParam.call(this, p);
      var mode = _tgMode;
      if (paramNames[p]) {
        if (mode === 'ghost') {
          var ghostVal = r;
          if (p === 0x1F00 || p === 0x9245) ghostVal = 'WebKit'; // VENDOR / UNMASKED_VENDOR
          else if (p === 0x1F01 || p === 0x9246) ghostVal = 'WebKit WebGL'; // RENDERER / UNMASKED_RENDERER
          emit(CAT.WEBGL, '👻 BLOCKED: getParameter(' + paramNames[p] + ')', SEV.H, 'Real: ' + r + ' → Ghost: ' + ghostVal);
          return ghostVal;
        }
        if (mode === 'spoof') {
          var fakeR = r;
          if (p === 0x9245 || p === 0x1F00) fakeR = spoofPick(SPOOF.gpuVendors);
          else if (p === 0x9246 || p === 0x1F01) fakeR = spoofPick(SPOOF.gpuRenderers);
          emit(CAT.WEBGL, '🎭 SPOOFED: getParameter(' + paramNames[p] + ')', SEV.H, 'Real: ' + r + ' → Fake: ' + fakeR);
          return fakeR;
        }
        emit(CAT.WEBGL, 'getParameter(' + paramNames[p] + ')', SEV.H, r, { pname: p });
      }
      return r;
    };
    var origExt = GL.prototype.getExtension;
    GL.prototype.getExtension = function (name) {
      if (name === 'WEBGL_debug_renderer_info') {
        if (_tgMode === 'ghost') {
          emit(CAT.WEBGL, '👻 BLOCKED: WEBGL_debug_renderer_info', SEV.C, 'Ghost mode - GPU identity hidden (returned null)');
          return null;
        }
        var label = _tgMode === 'spoof' ? '🎭 SPOOFED: ' : '';
        emit(CAT.WEBGL, label + 'WEBGL_debug_renderer_info (GPU identity exposed)', SEV.C, 'Extension enables reading UNMASKED_VENDOR + UNMASKED_RENDERER');
      }
      return origExt.call(this, name);
    };
    var origSE = GL.prototype.getSupportedExtensions;
    GL.prototype.getSupportedExtensions = function () {
      var r = origSE.call(this);
      if (_tgMode === 'ghost') {
        var filtered = (r || []).filter(function(e) { return e !== 'WEBGL_debug_renderer_info'; });
        emit(CAT.WEBGL, '👻 BLOCKED: getSupportedExtensions() → ' + filtered.length + ' (stripped debug_renderer_info)', SEV.M, filtered.join(', '));
        return filtered;
      }
      if (_tgMode === 'spoof') {
        emit(CAT.WEBGL, '🎭 SPOOFED: getSupportedExtensions() → ' + (r || []).length + ' extensions', SEV.M, (r || []).slice(0, 10).join(', ') + '... (' + (r||[]).length + ' total)');
      } else {
        emit(CAT.WEBGL, 'getSupportedExtensions() → ' + (r || []).length + ' extensions', SEV.M, (r || []).join(', '));
      }
      return r;
    };
  });

  // ── AUDIO FINGERPRINTING ───────────────────────────────
  var ACtx = window.AudioContext || window.webkitAudioContext;
  if (ACtx) {
    // Hook constructor to show sampleRate response
    var OrigACtx = ACtx;
    var ACtxName = window.AudioContext ? 'AudioContext' : 'webkitAudioContext';
    window[ACtxName] = function() {
      if (_tgMode === 'ghost') {
        emit(CAT.AUDIO, '👻 BLOCKED: new ' + ACtxName + '()', SEV.H, 'Ghost mode - audio fingerprinting blocked');
        // Return a neutered context
        var ctx = new (Function.prototype.bind.apply(OrigACtx, [null].concat(Array.from(arguments))))();
        return ctx;
      }
      var ctx = new (Function.prototype.bind.apply(OrigACtx, [null].concat(Array.from(arguments))))();
      var label = _tgMode === 'spoof' ? '🎭 SPOOFED: ' : '';
      emit(CAT.AUDIO, label + 'new ' + ACtxName + '()', SEV.H, 'sampleRate: ' + ctx.sampleRate + 'Hz, state: ' + ctx.state + ', baseLatency: ' + (ctx.baseLatency || 'N/A') + 's, outputLatency: ' + (ctx.outputLatency || 'N/A') + 's');
      return ctx;
    };
    window[ACtxName].prototype = OrigACtx.prototype;

    ['createOscillator','createAnalyser','createDynamicsCompressor','createBiquadFilter','createGain','createScriptProcessor'].forEach(function(method) {
      var orig = OrigACtx.prototype[method];
      if (orig) {
        OrigACtx.prototype[method] = function () {
          var mode = _tgMode;
          var node = orig.apply(this, arguments);
          if (mode === 'ghost') {
            emit(CAT.AUDIO, '👻 BLOCKED: AudioContext.' + method + '()', SEV.H, 'Ghost mode - node created but audio processing neutered');
          } else {
            var info = method;
            if (method === 'createOscillator') info = 'OscillatorNode (type: ' + (node.type || 'sine') + ', freq: ' + (node.frequency ? node.frequency.value : '?') + 'Hz)';
            else if (method === 'createAnalyser') info = 'AnalyserNode (fftSize: ' + (node.fftSize || 2048) + ', smoothing: ' + (node.smoothingTimeConstant || 0.8) + ')';
            else if (method === 'createDynamicsCompressor') info = 'DynamicsCompressor (threshold: ' + (node.threshold ? node.threshold.value : -24) + 'dB, ratio: ' + (node.ratio ? node.ratio.value : 12) + ')';
            else if (method === 'createBiquadFilter') info = 'BiquadFilter (type: ' + (node.type || 'lowpass') + ', freq: ' + (node.frequency ? node.frequency.value : 350) + 'Hz, Q: ' + (node.Q ? node.Q.value : 1) + ')';
            else if (method === 'createGain') info = 'GainNode (gain: ' + (node.gain ? node.gain.value : 1) + ')';
            var label = mode === 'spoof' ? '🎭 ' : '';
            emit(CAT.AUDIO, label + 'AudioContext.' + method + '()', SEV.H, info);
          }
          return node;
        };
      }
    });
  }
  if (window.OfflineAudioContext) {
    var OrigOAC = window.OfflineAudioContext;
    window.OfflineAudioContext = function () {
      if (_tgMode === 'ghost') {
        emit(CAT.AUDIO, '👻 BLOCKED: new OfflineAudioContext()', SEV.H, 'Ghost mode - offline audio rendering blocked');
        return new (Function.prototype.bind.apply(OrigOAC, [null].concat(Array.from(arguments))))();
      }
      var args = Array.from(arguments);
      var label = _tgMode === 'spoof' ? '🎭 ' : '';
      emit(CAT.AUDIO, label + 'new OfflineAudioContext()', SEV.H, 'channels: ' + (args[0]||1) + ', length: ' + (args[1]||0) + ' frames, sampleRate: ' + (args[2]||44100) + 'Hz');
      return new (Function.prototype.bind.apply(OrigOAC, [null].concat(args)))();
    };
    window.OfflineAudioContext.prototype = OrigOAC.prototype;
  }

  // ── SCREEN PROFILING ───────────────────────────────────
  ['width','height','colorDepth','pixelDepth','availWidth','availHeight'].forEach(function(p) {
    try {
      var d = Object.getOwnPropertyDescriptor(Screen.prototype, p);
      if (d && d.get) {
        var o = d.get;
        Object.defineProperty(Screen.prototype, p, {
          get: function() {
            var v = o.call(this);
            var mode = _tgMode;
            if (mode === 'ghost') {
              var gv = (p === 'width' || p === 'availWidth') ? GHOST.screen[0] : (p === 'height' || p === 'availHeight') ? GHOST.screen[1] : GHOST.colorDepth;
              emit(CAT.SCREEN, '👻 BLOCKED: screen.' + p, SEV.L, 'Ghost → ' + gv);
              return gv;
            }
            if (mode === 'spoof') {
              var scr = spoofPick(SPOOF.screens);
              var sv = (p === 'width' || p === 'availWidth') ? scr[0] : (p === 'height' || p === 'availHeight') ? scr[1] : spoofPick(SPOOF.colorDepths);
              emit(CAT.SCREEN, '🎭 SPOOFED: screen.' + p, SEV.L, 'Real: ' + v + ' → Fake: ' + sv);
              return sv;
            }
            emit(CAT.SCREEN, 'screen.' + p, SEV.L, v);
            return v;
          },
          configurable: true
        });
      }
    } catch (e) {}
  });
  try {
    var _dpr = window.devicePixelRatio;
    Object.defineProperty(window, 'devicePixelRatio', {
      get: function() {
        var mode = _tgMode;
        if (mode === 'ghost') { emit(CAT.SCREEN, '👻 BLOCKED: devicePixelRatio', SEV.L, 'Ghost → ' + GHOST.pixelRatio); return GHOST.pixelRatio; }
        if (mode === 'spoof') { var f = spoofPick(SPOOF.pixelRatios); emit(CAT.SCREEN, '🎭 SPOOFED: devicePixelRatio', SEV.L, 'Real: ' + _dpr + ' → Fake: ' + f); return f; }
        emit(CAT.SCREEN, 'devicePixelRatio', SEV.L, _dpr); return _dpr;
      },
      set: function(v) { _dpr = v; }, configurable: true
    });
  } catch (e) {}
  var origMM = window.matchMedia;
  if (origMM) {
    // FingerprintJS CSS media query signals for detection
    var fpjsMediaQueries = {
      'color-gamut': 'colorGamut - display color range',
      'inverted-colors': 'invertedColors - accessibility setting',
      'forced-colors': 'forcedColors - high contrast mode',
      'monochrome': 'monochrome - greyscale display',
      'prefers-contrast': 'contrast - user contrast preference',
      'prefers-reduced-motion': 'reducedMotion - animation preference',
      'prefers-reduced-transparency': 'reducedTransparency - transparency preference',
      'prefers-color-scheme': 'colorScheme - light/dark preference',
      'dynamic-range': 'HDR - dynamic range capability'
    };
    var mediaQueryCount = 0;
    window.matchMedia = function (q) {
      var result = origMM.call(this, q);
      var fpjsMatch = null;
      for (var mqKey in fpjsMediaQueries) {
        if (q && q.indexOf(mqKey) !== -1) { fpjsMatch = fpjsMediaQueries[mqKey]; break; }
      }
      if (fpjsMatch) {
        if (_tgMode === 'ghost') {
          emit(CAT.SCREEN, '👻 BLOCKED: CSS ' + fpjsMatch, SEV.M, 'Ghost mode - query "' + q + '" → always returns false');
          return { matches: false, media: q, onchange: null, addListener: function(){}, removeListener: function(){}, addEventListener: function(){}, removeEventListener: function(){}, dispatchEvent: function(){return false} };
        }
        if (_tgMode === 'spoof') {
          var fakeMatch = Math.random() > 0.5;
          emit(CAT.SCREEN, '🎭 SPOOFED: CSS ' + fpjsMatch, SEV.M, 'Query: "' + q + '" → real: ' + result.matches + ' → fake: ' + fakeMatch);
          return { matches: fakeMatch, media: q, onchange: null, addListener: function(){}, removeListener: function(){}, addEventListener: function(){}, removeEventListener: function(){}, dispatchEvent: function(){return false} };
        }
        emit(CAT.SCREEN, 'CSS fingerprint: ' + fpjsMatch, SEV.M, 'Query: "' + q + '" → matches: ' + result.matches);
      } else {
        mediaQueryCount++;
        if (mediaQueryCount <= 3) emit(CAT.SCREEN, 'matchMedia("' + q + '")', SEV.L, 'matches: ' + result.matches);
      }
      return result;
    };
  }

  // ── FINGERPRINTJS-SPECIFIC SIGNAL DETECTION ─────────
  // Math fingerprint - tiny floating-point differences across browsers/OS
  var origMathFns = {};
  ['acos','acosh','asin','atan','atanh','cos','cosh','exp','expm1','log','log1p','sin','sinh','sqrt','tan','tanh'].forEach(function(fn) {
    if (Math[fn]) {
      origMathFns[fn] = Math[fn];
      var mathCallCount = 0;
      Math[fn] = function(x) {
        mathCallCount++;
        var r = origMathFns[fn](x);
        if (mathCallCount === 3) {
          if (_tgMode === 'ghost') {
            emit(CAT.NAV, '👻 BLOCKED: Math.' + fn + '() probing', SEV.M, 'Ghost mode - returning standard IEEE 754 result: ' + r);
          } else if (_tgMode === 'spoof') {
            // Add tiny noise to math results (within float precision)
            var noisy = r + (_spoofSeed * 1e-15 - 5e-16);
            emit(CAT.NAV, '🎭 SPOOFED: Math.' + fn + '() probing', SEV.M, 'Real: Math.' + fn + '(' + x + ') = ' + r + ' → Noisy: ' + noisy);
            return noisy;
          } else {
            emit(CAT.NAV, 'Math.' + fn + '() probing - math fingerprint', SEV.M, 'Math.' + fn + '(1) = ' + origMathFns[fn](1) + ', Math.' + fn + '(0.5) = ' + origMathFns[fn](0.5));
          }
        }
        return r;
      };
    }
  });

  // Intl.DateTimeFormat - timezone detection
  try {
    var origDTF = Intl.DateTimeFormat;
    Intl.DateTimeFormat = function() {
      var inst = new (Function.prototype.bind.apply(origDTF, [null].concat(Array.from(arguments))))();
      try {
        var opts = inst.resolvedOptions();
        var tz = opts.timeZone;
        if (_tgMode === 'ghost') {
          emit(CAT.NAV, '👻 BLOCKED: Intl.DateTimeFormat() - timezone', SEV.M, 'Ghost mode - real timezone: ' + tz + ', returning UTC');
        } else if (_tgMode === 'spoof') {
          var fakeTZ = spoofPick(SPOOF.timezones);
          emit(CAT.NAV, '🎭 SPOOFED: Intl.DateTimeFormat()', SEV.M, 'Real: ' + tz + ' → Fake: ' + fakeTZ + ' | locale: ' + opts.locale + ', calendar: ' + opts.calendar + ', numberingSystem: ' + opts.numberingSystem);
        } else {
          emit(CAT.NAV, 'Intl.DateTimeFormat() - timezone fingerprint', SEV.M, 'timeZone: ' + tz + ', locale: ' + opts.locale + ', calendar: ' + opts.calendar);
        }
      } catch(e) {}
      return inst;
    };
    Intl.DateTimeFormat.prototype = origDTF.prototype;
    Intl.DateTimeFormat.supportedLocalesOf = origDTF.supportedLocalesOf;
  } catch(e) {}

  // Screen orientation
  try {
    if (screen.orientation) {
      var origOrType = Object.getOwnPropertyDescriptor(ScreenOrientation.prototype, 'type');
      if (origOrType && origOrType.get) {
        var oGet = origOrType.get;
        Object.defineProperty(ScreenOrientation.prototype, 'type', {
          get: function() {
            var v = oGet.call(this);
            if (_tgMode === 'ghost') { emit(CAT.SCREEN, '👻 BLOCKED: screen.orientation.type', SEV.L, 'Ghost → landscape-primary'); return 'landscape-primary'; }
            if (_tgMode === 'spoof') { var f = spoofPick(['landscape-primary','portrait-primary']); emit(CAT.SCREEN, '🎭 SPOOFED: screen.orientation.type', SEV.L, 'Real: ' + v + ' → Fake: ' + f); return f; }
            emit(CAT.SCREEN, 'screen.orientation.type', SEV.L, v); return v;
          },
          configurable: true
        });
      }
    }
  } catch(e) {}

  // Date.getTimezoneOffset - timezone fingerprint
  try {
    var origTZO = Date.prototype.getTimezoneOffset;
    var tzoCallCount = 0;
    Date.prototype.getTimezoneOffset = function() {
      var v = origTZO.call(this);
      tzoCallCount++;
      if (tzoCallCount === 1) {
        if (_tgMode === 'ghost') {
          emit(CAT.NAV, '👻 BLOCKED: getTimezoneOffset()', SEV.L, 'Real: ' + v + 'min → returning 0 (UTC)');
          return 0;
        }
        if (_tgMode === 'spoof') {
          var fakeOff = spoofPick(SPOOF.tzOffsets);
          emit(CAT.NAV, '🎭 SPOOFED: getTimezoneOffset()', SEV.L, 'Real: ' + v + 'min (UTC' + (v > 0 ? '-' : '+') + Math.abs(v / 60) + ') → Fake: ' + fakeOff + 'min (UTC' + (fakeOff > 0 ? '-' : '+') + Math.abs(fakeOff / 60) + ')');
          return fakeOff;
        }
        emit(CAT.NAV, 'Date.getTimezoneOffset()', SEV.L, v + ' minutes (UTC' + (v > 0 ? '-' : '+') + Math.abs(v / 60) + ')');
      }
      return (_tgMode === 'ghost') ? 0 : (_tgMode === 'spoof') ? spoofPick(SPOOF.tzOffsets) : v;
    };
  } catch(e) {}

  // ── FONT ENUMERATION ───────────────────────────────────
  var _measureText = CanvasRenderingContext2D.prototype.measureText;
  var fontCalls = 0;
  var fontFamiliesSeen = new Set();
  CanvasRenderingContext2D.prototype.measureText = function (txt) {
    fontCalls++;
    // Track which fonts are being probed
    try { var fam = this.font || ''; var m = fam.match(/['"]?([^'"]+)['"]?\s*$/); if (m) fontFamiliesSeen.add(m[1]); } catch(e) {}
    if (_tgMode === 'ghost' && fontCalls >= 5) {
      // Return constant width to prevent font enumeration
      emit(CAT.FONT, '👻 BLOCKED: measureText() - font enumeration (' + fontCalls + ' calls)', SEV.H, 'Ghost mode - returning constant metrics for all fonts');
      var fake = _measureText.call(this, 'mmmmmmmmm');
      return fake;
    }
    var result = _measureText.call(this, txt);
    if (fontCalls === 5) {
      var label = _tgMode === 'spoof' ? '🎭 ' : '';
      emit(CAT.FONT, label + 'Rapid measureText() - font enumeration started', SEV.H, fontCalls + ' calls, text: "' + txt + '", font: ' + (this.font || '?') + ', width: ' + (result.width ? result.width.toFixed(2) : '?') + 'px');
    }
    if (fontCalls === 50) {
      var families = Array.from(fontFamiliesSeen).slice(0, 20).join(', ');
      emit(CAT.FONT, 'Heavy font probing (' + fontCalls + '+ calls, ' + fontFamiliesSeen.size + ' families)', SEV.C, 'Probed: ' + families + (fontFamiliesSeen.size > 20 ? '...' : ''));
    }
    return result;
  };
  try {
    if (document.fonts && document.fonts.check) {
      var origFCheck = document.fonts.check.bind(document.fonts);
      var fontCheckCt = 0;
      document.fonts.check = function () {
        fontCheckCt++;
        var result = origFCheck.apply(this, arguments);
        if (fontCheckCt === 5) {
          if (_tgMode === 'ghost') {
            emit(CAT.FONT, '👻 BLOCKED: document.fonts.check() (' + fontCheckCt + '+ calls)', SEV.H, 'Ghost mode - always returning true');
            return true;
          }
          var label = _tgMode === 'spoof' ? '🎭 ' : '';
          emit(CAT.FONT, label + 'document.fonts.check() (' + fontCheckCt + '+ calls)', SEV.H, 'Query: "' + arguments[0] + '" → ' + result);
        }
        return result;
      };
    }
  } catch (e) {}

  // ── WEBRTC ─────────────────────────────────────────────
  if (window.RTCPeerConnection) {
    var OrigRTC = window.RTCPeerConnection;
    window.RTCPeerConnection = function () {
      var config = arguments[0] || {};
      var mode = _tgMode;
      if (mode === 'ghost') {
        emit(CAT.WEBRTC, '👻 BLOCKED: RTCPeerConnection - IP leak prevented', SEV.C, 'Ghost mode - connection blocked');
        // Return a dummy object that won't leak IPs
        var dummy = { createDataChannel: function(){return{}}, createOffer: function(){return Promise.resolve({})}, setLocalDescription: function(){return Promise.resolve()}, close: function(){}, addEventListener: function(){}, removeEventListener: function(){} };
        return dummy;
      }
      emit(CAT.WEBRTC, (mode === 'spoof' ? '🎭 ' : '') + 'new RTCPeerConnection() - IP leak vector', SEV.C, JSON.stringify(config));
      return new (Function.prototype.bind.apply(OrigRTC, [null].concat(Array.from(arguments))))();
    };
    window.RTCPeerConnection.prototype = OrigRTC.prototype;
  }

  // ── DYNAMIC CODE EXEC ──────────────────────────────────
  var _eval = window.eval;
  window.eval = function (code) {
    emit(CAT.EVAL, 'eval()', SEV.C, String(code || '').substring(0, 200), { length: String(code || '').length });
    return _eval.call(this, code);
  };

  var _setTimeout = window.setTimeout;
  window.setTimeout = function (fn, delay) {
    if (typeof fn === 'string') emit(CAT.EVAL, 'setTimeout(string)', SEV.C, fn.substring(0, 200));
    return _setTimeout.apply(this, arguments);
  };
  var _setInterval = window.setInterval;
  window.setInterval = function (fn, delay) {
    if (typeof fn === 'string') emit(CAT.EVAL, 'setInterval(string)', SEV.C, fn.substring(0, 200));
    return _setInterval.apply(this, arguments);
  };

  // ── DATA EXFILTRATION - fetch / XHR ────────────────────
  var _fetch = window.fetch;
  var pageOrigin = location.origin;
  var pageApex = location.hostname.replace(/^www\./, '').split('.').slice(-2).join('.');
  function isSameOrg(url) {
    try {
      var u = new URL(url, location.href);
      if (u.origin === pageOrigin) return true;
      var reqApex = u.hostname.replace(/^www\./, '').split('.').slice(-2).join('.');
      // Same apex domain (e.g. static.licdn.com ↔ linkedin.com)
      if (reqApex === pageApex) return true;
      // Known CDN mappings
      var cdnMap = {'linkedin.com':['licdn.com'],'google.com':['gstatic.com','googleapis.com','googleusercontent.com','ggpht.com','doubleclick.net'],'facebook.com':['fbcdn.net','facebook.net'],'microsoft.com':['msft.net','live.com','office.com','office.net','office365.com','microsoftonline.com','msn.com','msftauth.net'],'cloud.microsoft':['office.com','office.net','office365.com','msn.com','msftauth.net','microsoft.com','static.microsoft','cdn.office.net'],'amazon.com':['cloudfront.net','ssl-images-amazon.com'],'apple.com':['mzstatic.com'],'twitter.com':['twimg.com','t.co','pscp.tv'],'x.com':['twimg.com','t.co','pscp.tv'],'pinterest.com':['pinimg.com'],'reddit.com':['redditmedia.com','redditstatic.com'],'instagram.com':['cdninstagram.com','fbcdn.net'],'youtube.com':['ytimg.com','googlevideo.com','ggpht.com']};
      // Try both 2-part and 3-part apex for new TLDs (cloud.microsoft, etc)
      var apexes = [pageApex];
      var parts = location.hostname.split('.');
      if (parts.length >= 3) apexes.push(parts.slice(-3).join('.'));
      for (var ai = 0; ai < apexes.length; ai++) {
        if (cdnMap[apexes[ai]] && cdnMap[apexes[ai]].some(function(c){ return u.hostname.endsWith(c); })) return true;
      }
      // Fallback: if both hostnames end with same word (e.g. both end with "microsoft")
      var pageLastWord = location.hostname.split('.').pop();
      var reqLastWord = u.hostname.split('.').pop();
      if (pageLastWord.length > 4 && pageLastWord === reqLastWord) return true;
    } catch(e) {}
    return false;
  }
  window.fetch = function (input, init) {
    var url = typeof input === 'string' ? input : (input && input.url || '');
    if (url.indexOf('chrome-extension://') === 0 || url.indexOf('moz-extension://') === 0) return _fetch.apply(this, arguments);
    var method = (init && init.method) || 'GET';
    var bodySize = 0;
    if (init && init.body) bodySize = typeof init.body === 'string' ? init.body.length : (init.body.size || init.body.byteLength || 0);
    var sameOrg = isSameOrg(url);
    // Only flag cross-origin requests or large POST bodies
    if (!sameOrg) {
      var sev = method === 'POST' && bodySize > 1024 ? SEV.H : (method === 'POST' ? SEV.M : SEV.L);
      emit(CAT.EXFIL, 'fetch ' + method + ' ' + url, sev, bodySize + ' bytes body → third-party', { method: method, url: url, bodySize: bodySize });
    } else if (method === 'POST' && bodySize > 4096) {
      emit(CAT.EXFIL, 'fetch POST (same-org, ' + bodySize + 'B body) ' + url, SEV.L, bodySize + ' bytes', { method: method, url: url, bodySize: bodySize });
    }
    return _fetch.apply(this, arguments);
  };

  var _xhrOpen = XMLHttpRequest.prototype.open;
  var _xhrSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this._fpg_method = method;
    this._fpg_url = url;
    return _xhrOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    var url = this._fpg_url || '';
    if (url.indexOf('chrome-extension://') !== 0 && url.indexOf('moz-extension://') !== 0) {
      var bodySize = body ? (typeof body === 'string' ? body.length : (body.byteLength || 0)) : 0;
      var sameOrg = isSameOrg(url);
      if (!sameOrg) {
        var sev = this._fpg_method === 'POST' && bodySize > 1024 ? SEV.H : SEV.M;
        emit(CAT.EXFIL, 'XHR ' + this._fpg_method + ' ' + url, sev, bodySize + ' bytes → third-party', { method: this._fpg_method, url: url, bodySize: bodySize });
      }
    }
    return _xhrSend.apply(this, arguments);
  };

  // ── WEBSOCKET ──────────────────────────────────────────
  if (window.WebSocket) {
    var OrigWS = window.WebSocket;
    window.WebSocket = function (url, protocols) {
      emit(CAT.WS, 'new WebSocket("' + url + '")', SEV.H, protocols ? 'protocols: ' + protocols : '', { url: url });
      return new OrigWS(url, protocols);
    };
    window.WebSocket.prototype = OrigWS.prototype;
    window.WebSocket.CONNECTING = OrigWS.CONNECTING;
    window.WebSocket.OPEN = OrigWS.OPEN;
    window.WebSocket.CLOSING = OrigWS.CLOSING;
    window.WebSocket.CLOSED = OrigWS.CLOSED;
  }

  // ── WORKERS ────────────────────────────────────────────
  if (window.Worker) {
    var OrigW = window.Worker;
    window.Worker = function (url, opts) {
      emit(CAT.WORKER, 'new Worker("' + url + '")', SEV.H, JSON.stringify(opts || {}));
      return new OrigW(url, opts);
    };
    window.Worker.prototype = OrigW.prototype;
  }
  try {
    if (navigator.serviceWorker && navigator.serviceWorker.register) {
      var origSWReg = navigator.serviceWorker.register.bind(navigator.serviceWorker);
      navigator.serviceWorker.register = function (url, opts) {
        emit(CAT.WORKER, 'ServiceWorker.register("' + url + '")', SEV.C, JSON.stringify(opts || {}));
        return origSWReg(url, opts);
      };
    }
  } catch (e) {}

  // ── CRYPTO / MINING ────────────────────────────────────
  if (window.WebAssembly && window.WebAssembly.instantiate) {
    var origWASM = window.WebAssembly.instantiate;
    window.WebAssembly.instantiate = function () {
      var size = arguments[0] && arguments[0].byteLength || 0;
      var sev = size > 500000 ? SEV.C : (size > 100000 ? SEV.H : SEV.M);
      emit(CAT.CRYPTO, 'WebAssembly.instantiate() - ' + (size > 1024 ? Math.round(size/1024) + 'KB' : size + 'B'), sev, size + ' byte module');
      return origWASM.apply(this, arguments);
    };
  }
  if (window.WebAssembly && window.WebAssembly.instantiateStreaming) {
    var origWASMS = window.WebAssembly.instantiateStreaming;
    window.WebAssembly.instantiateStreaming = function () {
      var url = String(arguments[0] && arguments[0].url || arguments[0] || '');
      emit(CAT.CRYPTO, 'WebAssembly.instantiateStreaming() - ' + url.substring(0, 80), SEV.H, url);
      return origWASMS.apply(this, arguments);
    };
  }
  try {
    if (window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
      var origDigest = window.crypto.subtle.digest.bind(window.crypto.subtle);
      var digestCt = 0;
      window.crypto.subtle.digest = function (algo, data) {
        digestCt++;
        if (digestCt <= 3 || digestCt % 100 === 0) {
          emit(CAT.CRYPTO, 'crypto.subtle.digest("' + (algo && algo.name || algo) + '") call #' + digestCt, digestCt > 50 ? SEV.H : SEV.M, (data && data.byteLength || 0) + ' bytes');
        }
        return origDigest(algo, data);
      };
    }
  } catch (e) {}

  // ── CLIPBOARD ──────────────────────────────────────────
  try {
    if (navigator.clipboard) {
      if (navigator.clipboard.readText) {
        var origCRT = navigator.clipboard.readText.bind(navigator.clipboard);
        navigator.clipboard.readText = function () {
          if (_tgMode === 'ghost') {
            emit(CAT.CLIPBOARD, '👻 BLOCKED: clipboard.readText()', SEV.C, 'Ghost mode - clipboard read denied, returned empty string');
            return Promise.resolve('');
          }
          emit(CAT.CLIPBOARD, 'clipboard.readText() - reading clipboard content', SEV.C, 'App is reading your clipboard text');
          return origCRT();
        };
      }
      if (navigator.clipboard.read) {
        var origCR = navigator.clipboard.read.bind(navigator.clipboard);
        navigator.clipboard.read = function () {
          if (_tgMode === 'ghost') {
            emit(CAT.CLIPBOARD, '👻 BLOCKED: clipboard.read()', SEV.C, 'Ghost mode - clipboard read denied, returned empty');
            return Promise.resolve([]);
          }
          emit(CAT.CLIPBOARD, 'clipboard.read() - reading clipboard data', SEV.C, 'App is reading clipboard (may include images/files)');
          return origCR();
        };
      }
      if (navigator.clipboard.writeText) {
        var origCWT = navigator.clipboard.writeText.bind(navigator.clipboard);
        navigator.clipboard.writeText = function (text) {
          if (_tgMode === 'ghost') {
            emit(CAT.CLIPBOARD, '👻 BLOCKED: clipboard.writeText()', SEV.M, 'Ghost mode - clipboard write denied: "' + (text || '').substring(0, 80) + '"');
            return Promise.resolve();
          }
          emit(CAT.CLIPBOARD, 'clipboard.writeText() - writing to clipboard', SEV.M, 'Content (' + (text||'').length + ' chars): "' + (text || '').substring(0, 120) + '"');
          return origCWT(text);
        };
      }
    }
  } catch (e) {}

  // ── STORAGE ────────────────────────────────────────────
  try {
    var origSSet = Storage.prototype.setItem;
    Storage.prototype.setItem = function (k, v) {
      var which = this === window.localStorage ? 'localStorage' : 'sessionStorage';
      emit(CAT.STORAGE, which + '.setItem("' + k + '")', SEV.M, String(v).substring(0, 120), { key: k, size: String(v).length });
      return origSSet.call(this, k, v);
    };
  } catch (e) {}

  // IndexedDB
  if (window.indexedDB && window.indexedDB.open) {
    var origIDB = window.indexedDB.open;
    window.indexedDB.open = function (name, version) {
      emit(CAT.STORAGE, 'indexedDB.open("' + name + '")', SEV.M, name);
      return origIDB.call(this, name, version);
    };
  }

  // ── TIMING ─────────────────────────────────────────────
  if (performance.getEntriesByType) {
    var origGEBT = performance.getEntriesByType.bind(performance);
    performance.getEntriesByType = function (type) {
      emit(CAT.TIMING, 'performance.getEntriesByType("' + type + '")', SEV.M, type);
      return origGEBT(type);
    };
  }
  var origPerfNow = performance.now.bind(performance);
  var perfNowCt = 0;
  performance.now = function () {
    perfNowCt++;
    if (perfNowCt === 100) emit(CAT.TIMING, 'performance.now() ' + perfNowCt + '+ calls - timing side-channel', SEV.H, perfNowCt + ' calls');
    return origPerfNow();
  };

  // ── postMessage ────────────────────────────────────────
  var _postMessage = window.postMessage;
  window.postMessage = function (msg, targetOrigin) {
    if (msg && msg.type !== '__FPG_DETECTION__' && msg.type !== '__FPG_TECH__') {
      try {
        var preview = typeof msg === 'string' ? msg.substring(0, 150) : JSON.stringify(msg).substring(0, 150);
        emit(CAT.POSTMSG, 'postMessage to "' + (targetOrigin || '*') + '"', SEV.L, preview);
      } catch (e) {
        emit(CAT.POSTMSG, 'postMessage to "' + (targetOrigin || '*') + '"', SEV.L, '[non-serializable]');
      }
    }
    return _postMessage.apply(this, arguments);
  };

  // ── TIMEZONE ───────────────────────────────────────────
  var origRO = Intl.DateTimeFormat.prototype.resolvedOptions;
  Intl.DateTimeFormat.prototype.resolvedOptions = function () {
    var r = origRO.call(this);
    emit(CAT.NAV, 'Intl.DateTimeFormat timezone', SEV.L, r.timeZone);
    return r;
  };

  // ── DOM MUTATION (dynamic script/iframe injection) ─────
  var domScriptCount = 0;
  var domIframeCount = 0;
  var observer = new MutationObserver(function(mutations) {
    for (var i = 0; i < mutations.length; i++) {
      var mut = mutations[i];
      for (var j = 0; j < mut.addedNodes.length; j++) {
        var node = mut.addedNodes[j];
        if (node.nodeType !== 1) continue;
        if (node.tagName === 'SCRIPT' && node.src && (node.src.indexOf('chrome-extension://') === 0 || node.src.indexOf('moz-extension://') === 0)) continue;
        if (node.tagName === 'SCRIPT') {
          domScriptCount++;
          if (domScriptCount <= 5) {
            var isSameOrgScript = node.src ? isSameOrg(node.src) : true;
            var sev = isSameOrgScript ? SEV.L : (node.src ? SEV.H : SEV.M);
            emit(CAT.DOM, 'Dynamic <script> injected' + (node.src ? ': ' + node.src.substring(0, 120) : ' (inline)'), sev, node.src || (node.textContent || '').substring(0, 120));
          } else if (domScriptCount === 6) {
            emit(CAT.DOM, domScriptCount + '+ dynamic scripts loaded (capped logging)', SEV.L, 'Further script injections logged silently');
          }
        }
        if (node.tagName === 'IFRAME') {
          domIframeCount++;
          if (domIframeCount <= 5) {
            var src = node.src || (node.srcdoc || '').substring(0, 80) || 'about:blank';
            var isAboutBlank = src === 'about:blank' || src === '';
            var isHidden = node.style && (node.style.display === 'none' || node.width == 0 || node.style.width === '0px');
            // about:blank iframes are standard SPA pattern - low severity
            // hidden cross-origin iframes are suspicious - high
            // hidden about:blank is medium
            var sev = isAboutBlank ? (isHidden ? SEV.M : SEV.L) : (isHidden ? SEV.H : SEV.M);
            emit(CAT.DOM, 'Dynamic <iframe> injected: ' + src.substring(0, 120), sev, src.substring(0, 200));
          }
        }
        if (node.tagName === 'OBJECT' || node.tagName === 'EMBED') {
          emit(CAT.DOM, '<' + node.tagName + '> element injected', SEV.H, node.data || node.src || '');
        }
      }
    }
  });
  if (document.documentElement) {
    observer.observe(document.documentElement, { childList: true, subtree: true });
  } else {
    document.addEventListener('DOMContentLoaded', function() {
      observer.observe(document.documentElement, { childList: true, subtree: true });
    });
  }

  // ── BASE64 large payloads ──────────────────────────────
  var _btoa = window.btoa;
  window.btoa = function (s) {
    // Only flag very large btoa as potential data encoding for exfil (>10KB)
    if (s && s.length > 10000) emit(CAT.EXFIL, 'btoa() encoding large payload (' + s.length + ' chars)', SEV.M, 'Encoded ' + s.length + ' chars to base64');
    return _btoa.call(this, s);
  };
  var _atob = window.atob;
  window.atob = function (s) {
    // Only flag very large atob as potential payload unpacking (>10KB)
    if (s && s.length > 10000) emit(CAT.EVAL, 'atob() decoding large payload (' + s.length + ' chars)', SEV.M, 'Decoded ' + s.length + ' base64 chars');
    return _atob.call(this, s);
  };

  // ── SPEECH SYNTHESIS FINGERPRINT ───────────────────────
  if (window.speechSynthesis && window.speechSynthesis.getVoices) {
    var origGetVoices = window.speechSynthesis.getVoices.bind(window.speechSynthesis);
    window.speechSynthesis.getVoices = function () {
      if (_tgMode === 'ghost') {
        emit(CAT.NAV, '👻 BLOCKED: speechSynthesis.getVoices()', SEV.H, 'Ghost mode - returned empty voice list');
        return [];
      }
      var voices = origGetVoices();
      var label = _tgMode === 'spoof' ? '🎭 ' : '';
      emit(CAT.NAV, label + 'speechSynthesis.getVoices() - ' + voices.length + ' voices', SEV.H, voices.slice(0, 5).map(function(v){ return v.name + ' (' + v.lang + ')'; }).join(', ') + (voices.length > 5 ? '...' : ''));
      return voices;
    };
  }

  // ── GAMEPAD API FINGERPRINT ────────────────────────────
  if (navigator.getGamepads) {
    var origGamepads = navigator.getGamepads.bind(navigator);
    navigator.getGamepads = function () {
      if (_tgMode === 'ghost') {
        emit(CAT.NAV, '👻 BLOCKED: getGamepads()', SEV.M, 'Ghost mode - returned empty');
        return [];
      }
      var pads = origGamepads();
      var connected = Array.from(pads).filter(function(p){return p});
      emit(CAT.NAV, 'navigator.getGamepads() - ' + connected.length + ' connected', SEV.M, connected.map(function(p){return p.id}).join(', ') || 'none');
      return pads;
    };
  }

  // ── NETWORK INFORMATION DETAILS ────────────────────────
  try {
    if (navigator.connection) {
      var connSpoofVals = { downlink: [1.5, 5, 10, 20, 50], effectiveType: ['3g','4g','4g','4g'], rtt: [50, 100, 150, 200], saveData: [false, false, false, true] };
      var connGhostVals = { downlink: 10, effectiveType: '4g', rtt: 50, saveData: false };
      ['downlink', 'effectiveType', 'rtt', 'saveData'].forEach(function(prop) {
        var desc = Object.getOwnPropertyDescriptor(navigator.connection.__proto__, prop);
        if (desc && desc.get) {
          var orig = desc.get;
          Object.defineProperty(navigator.connection, prop, {
            get: function() {
              var v = orig.call(this);
              if (_tgMode === 'ghost') { var gv = connGhostVals[prop]; emit(CAT.NAV, '👻 BLOCKED: connection.' + prop, SEV.M, 'Real: ' + v + ' → Ghost: ' + gv); return gv; }
              if (_tgMode === 'spoof') { var sv = spoofPick(connSpoofVals[prop]); emit(CAT.NAV, '🎭 SPOOFED: connection.' + prop, SEV.M, 'Real: ' + v + ' → Fake: ' + sv); return sv; }
              emit(CAT.NAV, 'connection.' + prop + ' - network fingerprint', SEV.M, String(v));
              return v;
            },
            configurable: true
          });
        }
      });
    }
  } catch (e) {}

  // ── GEOLOCATION ────────────────────────────────────────
  if (navigator.geolocation && navigator.geolocation.getCurrentPosition) {
    var origGeoPos = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
    navigator.geolocation.getCurrentPosition = function (success, error, opts) {
      emit(CAT.NAV, 'geolocation.getCurrentPosition() - location access', SEV.C, JSON.stringify(opts || {}));
      return origGeoPos(success, error, opts);
    };
    var origGeoWatch = navigator.geolocation.watchPosition.bind(navigator.geolocation);
    navigator.geolocation.watchPosition = function (success, error, opts) {
      emit(CAT.NAV, 'geolocation.watchPosition() - continuous location tracking', SEV.C, JSON.stringify(opts || {}));
      return origGeoWatch(success, error, opts);
    };
  }

  // ── NOTIFICATION PERMISSION ────────────────────────────
  if (window.Notification && window.Notification.requestPermission) {
    var origNotifPerm = window.Notification.requestPermission;
    window.Notification.requestPermission = function () {
      emit(CAT.PERM, 'Notification.requestPermission() - push notification access', SEV.M, 'Notification');
      return origNotifPerm.apply(this, arguments);
    };
  }

  // ── WINDOW.OPEN (popup creation) ───────────────────────
  var _windowOpen = window.open;
  window.open = function (url, target, features) {
    if (url && url.indexOf('chrome-extension://') !== 0) {
      emit(CAT.DOM, 'window.open("' + (url || '').substring(0, 200) + '")', SEV.M, 'target=' + (target || '_blank') + ' features=' + (features || 'none'));
    }
    return _windowOpen.apply(this, arguments);
  };

  // ── DOCUMENT.DOMAIN (legacy security bypass) ──────────
  try {
    var origDomainDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'domain');
    if (origDomainDesc && origDomainDesc.set) {
      var origDomainSet = origDomainDesc.set;
      Object.defineProperty(Document.prototype, 'domain', {
        get: origDomainDesc.get,
        set: function(val) {
          emit(CAT.DOM, 'document.domain set to "' + val + '" - same-origin policy bypass', SEV.C, val);
          return origDomainSet.call(this, val);
        },
        configurable: true
      });
    }
  } catch (e) {}

  // ── WEBGPU FINGERPRINTING (2025+ technique) ────────────
  // WebGPU exposes GPU vendor, architecture, features, limits
  // More precise than WebGL - a priority in advanced fingerprint systems
  try {
    if (navigator.gpu && navigator.gpu.requestAdapter) {
      var origReqAdapter = navigator.gpu.requestAdapter.bind(navigator.gpu);
      navigator.gpu.requestAdapter = function (opts) {
        if (_tgMode === 'ghost') {
          emit(CAT.WEBGL, '👻 BLOCKED: WebGPU requestAdapter()', SEV.C, 'Ghost mode - returned null adapter', { api: 'WebGPU' });
          return Promise.resolve(null);
        }
        var label = _tgMode === 'spoof' ? '🎭 SPOOFED: ' : '';
        emit(CAT.WEBGL, label + 'WebGPU requestAdapter() - GPU hardware fingerprint', SEV.C, 'Options: ' + JSON.stringify(opts || {powerPreference:'default'}), { api: 'WebGPU' });
        return origReqAdapter(opts).then(function(adapter) {
          if (adapter) {
            try {
              var info = {
                vendor: adapter.info ? adapter.info.vendor : '',
                architecture: adapter.info ? adapter.info.architecture : '',
                device: adapter.info ? adapter.info.device : '',
                description: adapter.info ? adapter.info.description : '',
                isFallback: adapter.isFallbackAdapter || false,
                featureCount: adapter.features ? adapter.features.size : 0,
                features: adapter.features ? Array.from(adapter.features).slice(0,10).join(', ') : ''
              };
              if (_tgMode === 'spoof') {
                emit(CAT.WEBGL, '🎭 SPOOFED: WebGPU adapter - ' + (info.vendor||'?') + ' ' + (info.architecture||'?'), SEV.C, 'Real vendor: ' + info.vendor + ', arch: ' + info.architecture + ', device: ' + info.device + ', features(' + info.featureCount + '): ' + info.features, { api: 'WebGPU' });
              } else {
                emit(CAT.WEBGL, 'WebGPU adapter: ' + (info.vendor||'?') + ' ' + (info.architecture||'?'), SEV.C, 'vendor: ' + info.vendor + ', architecture: ' + info.architecture + ', device: ' + info.device + ', description: ' + info.description + ', isFallback: ' + info.isFallback + ', features(' + info.featureCount + '): ' + info.features, { api: 'WebGPU' });
              }
            } catch(e) {}
          }
          return adapter;
        });
      };
    }
  } catch (e) {}

  // ── INCOGNITO/PRIVATE MODE DETECTION ───────────────────
  // Sites probe storage quota to detect private browsing
  // In incognito, quota is typically < 120MB
  try {
    if (navigator.storage && navigator.storage.estimate) {
      var origEstimate = navigator.storage.estimate.bind(navigator.storage);
      navigator.storage.estimate = function () {
        if (_tgMode === 'ghost') {
          emit(CAT.PERM, '👻 BLOCKED: storage.estimate() - incognito probe', SEV.H, 'Ghost mode - returning large quota to appear non-incognito');
          return Promise.resolve({ usage: 0, quota: 2147483648 }); // 2GB - normal mode
        }
        var label = _tgMode === 'spoof' ? '🎭 ' : '';
        emit(CAT.PERM, label + 'navigator.storage.estimate() - possible incognito detection probe', SEV.H, 'StorageEstimate');
        return origEstimate();
      };
    }
  } catch (e) {}
  // FileSystem API probe (Chrome-specific incognito detection)
  try {
    if (window.webkitRequestFileSystem || window.requestFileSystem) {
      var origFS = window.webkitRequestFileSystem || window.requestFileSystem;
      var fsName = window.webkitRequestFileSystem ? 'webkitRequestFileSystem' : 'requestFileSystem';
      window[fsName] = function () {
        emit(CAT.PERM, fsName + '() - incognito mode detection attempt', SEV.H, 'FileSystem API probe');
        return origFS.apply(this, arguments);
      };
    }
  } catch (e) {}

  // ── BEHAVIORAL BIOMETRICS MONITORING ───────────────────
  // Sites add mass event listeners for mouse/keyboard/touch
  // to fingerprint typing cadence, mouse movement patterns, scroll behavior
  var _addEventListener = EventTarget.prototype.addEventListener;
  var bioListeners = { mousemove: 0, keydown: 0, keyup: 0, keypress: 0, touchstart: 0, touchmove: 0, scroll: 0, wheel: 0, pointerdown: 0, pointermove: 0 };
  EventTarget.prototype.addEventListener = function (type, listener, opts) {
    if (bioListeners.hasOwnProperty(type) && (this === document || this === document.body || this === window)) {
      bioListeners[type]++;
      var total = 0;
      for (var k in bioListeners) total += bioListeners[k];
      // Flag when 3+ behavioral event types are being tracked
      if (total === 3) {
        var tracked = [];
        for (var k2 in bioListeners) { if (bioListeners[k2] > 0) tracked.push(k2); }
        emit(CAT.NAV, 'Behavioral biometrics - tracking ' + tracked.join(', '), SEV.H, total + ' behavioral listeners on document/window', { events: tracked });
      }
      // Flag again at 6+ for heavy monitoring
      if (total === 6) {
        emit(CAT.NAV, 'Heavy behavioral biometrics monitoring (' + total + ' listeners)', SEV.C, 'Mouse/keyboard/touch/scroll tracking active');
      }
    }
    return _addEventListener.apply(this, arguments);
  };

  // ── SharedArrayBuffer (timing attack vector) ───────────
  if (typeof SharedArrayBuffer !== 'undefined') {
    var OrigSAB = SharedArrayBuffer;
    window.SharedArrayBuffer = function (length) {
      emit(CAT.CRYPTO, 'new SharedArrayBuffer(' + length + ') - high-res timing / Spectre vector', length > 65536 ? SEV.C : SEV.H, length + ' bytes');
      return new OrigSAB(length);
    };
    window.SharedArrayBuffer.prototype = OrigSAB.prototype;
  }

  // ── CONSOLE MESSAGE CAPTURE (urlscan.io data.console) ──
  // Capture console output for forensic analysis
  var consoleMsgs = [];
  ['log', 'warn', 'error', 'debug', 'info'].forEach(function(method) {
    var orig = console[method];
    if (orig) {
      console[method] = function() {
        try {
          var msg = Array.from(arguments).map(function(a) {
            if (typeof a === 'string') return a;
            try { return JSON.stringify(a); } catch(e) { return String(a); }
          }).join(' ');
          if (msg.length > 0 && consoleMsgs.length < 200) {
            consoleMsgs.push({ method: method, message: msg.substring(0, 500), timestamp: Date.now() });
            // Send batch every 50 messages
            if (consoleMsgs.length % 50 === 0) {
              window.postMessage({ type: '__FPG_CONSOLE__', payload: consoleMsgs.slice() }, '*');
            }
          }
        } catch(e) {}
        return orig.apply(this, arguments);
      };
    }
  });
  // Final flush after page load
  setTimeout(function() {
    if (consoleMsgs.length > 0) {
      window.postMessage({ type: '__FPG_CONSOLE__', payload: consoleMsgs.slice() }, '*');
    }
  }, 5000);

})();
