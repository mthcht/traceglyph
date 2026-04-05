# TraceGlyph

**Website security analyzer**

TraceGlyph is a free, open-source Chrome/Edge/Brave extension that performs real-time security analysis on every website you visit. It detects browser fingerprinting, identifies phishing indicators, spots JavaScript obfuscation, audits security headers, maps findings to MITRE ATT&CK techniques, and exports IOCs - all without sending any data externally.

> Think of it as urlscan.io + Wappalyzer + a fingerprint detector, running live in your browser.

<img width="652" height="587" alt="Capture d&#39;écran 2026-04-05 235307" src="https://github.com/user-attachments/assets/f5db7249-4be2-48f3-a596-f05ed78c777b" />
<img width="652" height="526" alt="Capture d&#39;écran 2026-04-05 235425" src="https://github.com/user-attachments/assets/0594b29a-19e5-49e8-a487-92624e2e1989" />
<img width="656" height="522" alt="Capture d&#39;écran 2026-04-05 235442" src="https://github.com/user-attachments/assets/2a3d4cda-0b0a-4723-970b-dbe779b8ef14" />
<img width="656" height="589" alt="Capture d&#39;écran 2026-04-06 000525" src="https://github.com/user-attachments/assets/3db8c5d1-44fb-471a-9891-4031473c7f92" />
<img width="627" height="520" alt="Capture d&#39;écran 2026-04-06 000538" src="https://github.com/user-attachments/assets/8cf7213e-8e4b-438a-a8a7-4bd505f29526" />
<img width="636" height="597" alt="Capture d&#39;écran 2026-04-06 000607" src="https://github.com/user-attachments/assets/f4ff7d93-be2e-4754-b346-9e2433b794d7" />


## Features

### Fingerprint Detection - 40+ API hooks
Intercepts Canvas, WebGL, WebGPU, Audio, Font, WebRTC, Battery, Media Devices, Screen, Navigator (22 properties), Geolocation, Speech Synthesis, Gamepad, behavioral biometrics (mouse/keyboard/scroll), and incognito mode probing.

### Phishing Analysis - 47 detection rules
Credential harvesting forms (cross-origin, mailto, orphan password fields), brand impersonation (30+ tracked brands), anti-analysis evasion (DevTools blocking, debugger traps, console.clear), social engineering urgency detection (19 phrases), exfiltration channels (Telegram bots, Discord webhooks), and suspicious page structure (overlay login, hidden iframes, minimal pages).

### JS Obfuscation Detection - 12 patterns
Eval packers, Base64+XOR combos (Whisper 2FA / BlackForce signatures), hex/unicode encoding, string array rotation (obfuscator.io), `document.write(unescape())`, Function constructor abuse, cache-busting hash filenames.

### Network Intelligence
All domains with resolved IPs, redirect chains, 60+ tracker signatures, HTTP/HTTPS stats, resource type breakdown, page timing (DNS, TLS, TTFB, DOM loaded), and network anomaly detection (unusual ports, POST to raw IP, suspicious file extensions, base64 URL params).

### Security Audit
12+ HTTP security headers, cookie flags, form risk assessment, iframe analysis.

### Technology Detection - 120+ technologies
Wappalyzer-class detection via DOM selectors + window globals + URL/header pattern matching across 25+ categories.

### MITRE ATT&CK Mapping
Every detection category maps to technique IDs: T1082, T1566, T1059.007, T1496, T1115, T1027, T1041, T1036, and 20+ more.

### IOC Export
One-click export of domains, IPs, domain→IP map, redirect chains, trackers, script hashes, network anomalies, and critical detections. Structured DFIR report with ATT&CK IDs.

## Install

### From Chrome Web Store
*(publication in progress)*

### From source
```bash
git clone https://github.com/mthcht/traceglyph.git
```
1. Open `chrome://extensions` (or `edge://extensions`)
2. Enable "Developer mode"
3. Click "Load unpacked" and select the cloned folder
4. Pin the extension via the puzzle icon

## Architecture

| File | Lines | Purpose |
|------|-------|---------|
| `manifest.json` | 47 | MV3 manifest |
| `background.js` | 198 | Service worker: network monitoring, IP resolution, scoring, tech detection |
| `content.js` | 620 | DOM analysis: phishing indicators, obfuscation, forms, links, timing |
| `injected.js` | 758 | Page-context API hooks: 40+ fingerprint vectors, self-filtering |
| `tech-detect.js` | 76 | Window globals detection + JS globals enumeration (CSP-safe) |
| `popup/popup.html` | 193 | Dashboard UI with light/dark theme |
| `popup/popup.js` | 66 | Dashboard logic, rendering, theme toggle, export |
| `welcome.html` | 167 | Install page with full capabilities documentation |

## Self-Filtering

The extension excludes its own activity from analysis:
- `isSelfTriggered()` checks call stack - drops detections from extension frames
- Network listeners skip all `chrome-extension://` URLs
- DOM observer ignores extension-origin script nodes
- fetch/XHR hooks skip extension URLs

## Scoring

| Category | Max | Signals |
|----------|-----|---------|
| Fingerprinting | 35 | Canvas, WebGL, Audio, Font, WebRTC, Battery - bonus at 3+ types |
| Tracking | 20 | Known trackers, tracking pixels, session replay |
| Behavior | 20 | eval, exfiltration, WebSocket, cryptomining, clipboard |
| Phishing | 15 | Phishing indicators, JS obfuscation, suspicious URLs |
| Security | 12 | Missing CSP/HSTS, weak headers, tech disclosure |
| Infrastructure | 10 | Suspicious TLDs, DGA domains, excess redirects |
| Anomalies | 8 | Network anomalies |
| Forms | 10 | Critical-risk forms, hidden cross-origin iframes |
| Cookies | 3 | Tracking cookies |

## Privacy

- Everything runs locally - zero external data transmission
- No analytics, no telemetry, no cloud processing
- Open source for full code audit
- `<all_urls>` permission used solely for webRequest monitoring

## License

MIT

## Author

[mthcht](https://github.com/mthcht)

## Ghost & Spoof Modes

TraceGlyph includes two active protection modes, toggled per-site or globally from the popup header:

### 👻 Ghost Mode - Block fingerprinting
Returns generic/default values. Sites see a standard browser profile instead of your real one.

| API | Ghost returns |
|-----|-------------|
| Navigator | Win32, Google Inc., en-US, 4 cores, 8GB RAM, no plugins |
| Canvas | Blank canvas (zeroed pixels) |
| WebGL | Generic "WebKit WebGL", strips debug_renderer_info |
| WebGPU | null adapter (no GPU info) |
| Screen | 1920×1080, 24-bit, 1x pixel ratio |
| CSS media queries | All fingerprint queries → false |
| Audio | Nodes created but data neutered |
| Font | Constant metrics (blocks enumeration) |
| WebRTC | Completely blocked - dummy object, no IP leaks |
| Battery | Fake full battery (100%, charging) |
| Timezone | UTC (offset 0) |
| Incognito probe | Large quota (appears non-incognito) |

### 🎭 Spoof Mode - Randomize fingerprinting
Returns realistic fake values from curated pools. Values stay consistent within a page load.

| API | Spoof behavior |
|-----|---------------|
| Navigator | Random from real platform/vendor/language/core pools |
| Canvas | Invisible noise pixels injected before reading |
| WebGL | Random GPU from pool of 8 real renderer strings |
| Screen | Random from 10 common resolutions |
| CSS media queries | Randomized true/false |
| Timezone | Random from 10 real timezones |
| Media devices | Randomized device count |

## Page IOC Extractor

Automatically extracts IOCs from visible page text - ideal for analysts reading threat reports, advisories, and blog posts.

| IOC Type | Pattern |
|----------|---------|
| IPv4 | Standard + defanged `[.]` notation |
| IPv6 | Standard notation |
| Domains | Standard + defanged `[dot]` notation |
| URLs | Standard + `hxxp`/`hxxps` defanged |
| SHA-256 | 64-char hex strings |
| SHA-1 | 40-char hex strings |
| MD5 | 32-char hex strings |
| CVE IDs | `CVE-YYYY-NNNNN` |
| MITRE ATT&CK | `T1xxx`, `T1xxx.xxx` |
| Emails | Standard + `[at]` defanged |
| Files | `.exe`, `.dll`, `.ps1`, `.bat`, `.vbs`, `.hta`, `.jar`, etc. |
| Registry | `HKLM\`, `HKCU\`, etc. |
| Bitcoin | P2PKH, P2SH, bech32 addresses |
| Ethereum | `0x` + 40 hex chars |

Features: auto-refanging, deduplication, private IP filtering, hash hierarchy dedup, one-click copy per category, included in Copy Report.

## Tracking Pixel Decoder

Automatically detects hidden tracking pixels and beacons in the DOM, decodes their URL parameters, and reveals exactly what data each pixel transmits about you.

**Detection:** Finds 1x1 images, zero-size images, `display:none`/`visibility:hidden`/`opacity:0` images, and prefetch/preload pixel-like resources.

**35+ identified tracking networks:**
Meta Pixel, Google Analytics, Google Ads, DoubleClick, Google Tag Manager, Microsoft Ads, Microsoft Clarity, LinkedIn Insight, X/Twitter Analytics, TikTok Pixel, Pinterest Tag, Snapchat Pixel, WordPress Stats, Yandex Metrica, Comscore, Quantcast, Matomo, Hotjar, Mouseflow, FullStory, LogRocket, Segment, Mixpanel, Amplitude, Heap, Plausible, PostHog, Sentry, HubSpot, Salesforce Pardot, Marketo, Xandr/AppNexus, Criteo, Taboola, Outbrain, Adobe Analytics, New Relic.

**9 data categories classified:**

| Category | Example parameters |
|----------|-------------------|
| User ID | `uid`, `cid`, `_ga`, `fpid`, `visitorid` |
| Session | `sid`, `session`, `token`, `nonce` |
| Page info | `url`, `referrer`, `utm_source`, `utm_campaign` |
| Device | `ua`, `browser`, `screen`, `viewport`, `lang` |
| Timing | `timestamp`, `ttfb`, `load`, `duration` |
| Tracking events | `event`, `action`, `category`, `hit`, `ec`, `ea` |
| Geolocation | `country`, `region`, `city`, `timezone` |
| Revenue | `revenue`, `price`, `order`, `product`, `sku` |
| Consent | `consent`, `gdpr`, `ccpa`, `dnt` |

Each decoded pixel is shown in the Network tab with the tracker name, all decoded parameters, and highlighted data type categories. Included in Copy Report output.
