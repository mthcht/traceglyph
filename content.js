// ============================================================================
// content.js - TraceGlyph by mthcht
// ============================================================================
//
// CONTENT SCRIPT - Runs in the "isolated world" of every web page.
// Performs DOM-level forensics that require access to the page's document
// but cannot access page-context JS globals (that's injected.js's job).
//
// EXECUTION CONTEXT:
//   - Injected by Chrome/Edge into every page matching <all_urls>.
//   - Runs in an isolated JS context (cannot see window.* page globals).
//   - Has access to the DOM, can read elements, attributes, styles.
//   - Communicates with background.js via chrome.runtime.sendMessage().
//   - Communicates with injected.js via window.postMessage().
//
// RESPONSIBILITIES:
//
//   1. INJECTED.JS BRIDGE
//      - Injects injected.js into the page's main world via <script> tag.
//      - Relays detection events from injected.js (via window.postMessage)
//        to background.js (via chrome.runtime.sendMessage).
//      - Passes ghost/spoof mode setting to injected.js via data-tg-mode
//        attribute on <html>.
//
//   2. PHISHING DETECTION (47 rules, 7 categories)
//      - External favicon from non-CDN domain (with 16-platform CDN mapping).
//      - Brand impersonation: favicon from brand X on non-brand-X domain.
//      - Login form analysis: cross-origin form actions, hidden/overlaid forms,
//        autocomplete=off on login fields, data: URI form actions.
//      - Brand images from brand domains on non-brand pages.
//      - Infinite debugger loops (anti-analysis watchdog).
//      - DevTools keyboard shortcut blocking (F12, Ctrl+Shift+I/J/C).
//      - Credential harvesting form patterns (hidden fields, unusual targets).
//      - Third-party form services (formspree.io, getform.io, etc.).
//
//   3. SUSPICIOUS URL ANALYSIS (10 rules)
//      - Brand name in non-brand hostname (e.g. "paypal" in evil-paypal.tk).
//        Handles new TLDs (.microsoft, .google).
//      - Homograph attacks (Cyrillic/Latin lookalike characters).
//      - Suspicious path keywords (/login, /verify, /secure, /wallet, etc.).
//      - Free hosting platform detection (.pages.dev, .netlify.app, etc.).
//
//   4. JS OBFUSCATION DETECTION (12 patterns, size-scaled)
//      - Hex encoding density (scaled by script size - large bundles tolerated).
//      - Unicode escape density (scaled).
//      - Dean Edwards packer (eval(function(p,a,c,k...))).
//      - Base64 decode chains (atob() count).
//      - document.write(unescape()) - classic phishing obfuscation.
//      - XOR decryption patterns (only in small scripts < 50KB).
//      - String array rotation (obfuscator.io patterns, density-based).
//      - Function constructor obfuscation.
//      - Multi-layer eval() chains.
//      - Base64+XOR combo (Whisper/BlackForce signature, only scripts < 30KB).
//      - Cache-busting hash filenames from non-CDN sources.
//      - Scripts loaded from raw IP addresses or data: URIs.
//
//   5. TECHNOLOGY DETECTION (120+ technologies)
//      - Detects frameworks, libraries, CMS, analytics, CDNs, and more
//        by scanning script URLs, meta tags, and DOM patterns.
//      - Categories: JS frameworks, CSS frameworks, CMS, analytics,
//        CDNs, payment, chat, A/B testing, tag managers, and more.
//
//   6. DATA COLLECTION (sent to background.js)
//      - Cookies (name, flags, tracking classification).
//      - Forms (action URL, method, field types, risk level).
//      - Iframes (src, hidden status, cross-origin, sandbox).
//      - Storage contents (localStorage, sessionStorage snapshots).
//      - Script hashes (SHA-256 of inline script content).
//      - Page links (all <a> hrefs, internal vs external).
//      - Page timing (Navigation Timing API: DNS, TLS, TTFB, DOM load).
//      - JS globals (enumerated window properties, capped at 300).
//      - Console messages (intercepted via console.log/warn/error hooks).
//      - DOM content hash (SHA-256 of document.documentElement.outerHTML).
//
//   7. PAGE IOC EXTRACTOR (14 IOC types)
//      - Extracts indicators of compromise from visible page text.
//      - IPv4/IPv6, domains, URLs, MD5/SHA1/SHA256 hashes, CVE IDs,
//        MITRE ATT&CK IDs, email addresses, suspicious filenames,
//        Windows registry keys, Bitcoin/Ethereum addresses.
//      - Auto-refangs defanged indicators: hxxp->[http, [.]->.,[at]->@.
//      - Deduplicates, filters private IPs, handles hash hierarchy.
//
//   8. TRACKING PIXEL DECODER (35+ networks, 9 data categories)
//      - Detects hidden/tiny images (1x1, 0x0, display:none, opacity:0).
//      - Identifies 35+ tracking networks by hostname matching.
//      - Decodes URL parameters and classifies leaked data:
//        user_id, session, page, device, timing, tracking, geo, revenue, consent.
//
// CDN OWNERSHIP MAPPING (used in favicon + obfuscation checks):
//   linkedin.com <-> licdn.com
//   google.com   <-> gstatic.com, googleapis.com, googleusercontent.com
//   facebook.com <-> fbcdn.net, facebook.net
//   x.com        <-> twimg.com, t.co, pscp.tv
//   microsoft.com <-> office.com, office.net, msftauth.net, static.microsoft
//   pinterest.com <-> pinimg.com
//   (+ 10 more platforms)
//
// ============================================================================
(function () {
  'use strict';

  // ── Load ghost/spoof mode settings BEFORE injecting hooks ──
  var host = location.hostname;
  try {
    chrome.storage.local.get(['tg_mode_global', 'tg_mode_sites'], function(r) {
      var sites = r.tg_mode_sites || {};
      var mode = sites[host] || r.tg_mode_global || 'off';
      document.documentElement.setAttribute('data-tg-mode', mode);
    });
  } catch(e) {}

  // Set default immediately (storage callback may be async)
  document.documentElement.setAttribute('data-tg-mode', 'off');

  // Listen for mode changes from popup
  try {
    chrome.runtime.onMessage.addListener(function(msg) {
      if (msg && msg.action === 'setMode' && msg.mode) {
        document.documentElement.setAttribute('data-tg-mode', msg.mode);
      }
    });
  } catch(e) {}

  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('injected.js');
  script.onload = () => script.remove();
  (document.head || document.documentElement).prepend(script);

  function safeSend(msg) {
    try { chrome.runtime.sendMessage(msg, () => void chrome.runtime.lastError); } catch (e) {}
  }

  // Relay detections and console messages to background
  window.addEventListener('message', (event) => {
    if (event.source !== window || !event.data) return;
    if (event.data.type === '__FPG_DETECTION__') safeSend({ action: 'detection', payload: event.data.payload, url: location.href, hostname: location.hostname });
    if (event.data.type === '__FPG_CONSOLE__') safeSend({ action: 'console_messages', payload: event.data.payload, hostname: location.hostname });
    if (event.data.type === '__FPG_GLOBALS__') safeSend({ action: 'js_globals', payload: event.data.payload, hostname: location.hostname });
  });

  function runScans() {
    scanCookies(); scanThirdPartyScripts(); scanTrackingPixels(); scanHiddenElements();
    scanSecurityMeta(); scanForms(); scanResourceHints(); scanIframes();
    scanExternalStylesheets(); scanLocalStorageContents(); scanServiceWorkers();
    scanShadowRoots(); scanDataAttributes(); scanTechStack(); scanScriptHashes();
    scanPageLinks(); scanPageTiming(); scanJSGlobals();
    scanPhishingIndicators(); scanJSObfuscation(); scanDOMHash(); scanSuspiciousURL();
    scanPageIOCs(); scanTrackingPixelData();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => setTimeout(runScans, 1200));
  else setTimeout(runScans, 1200);

  function scanTechStack() {
    const domTech = [];
    const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
    const links = Array.from(document.querySelectorAll('link[href]')).map(l => l.href);
    const metas = {};
    document.querySelectorAll('meta').forEach(m => { const k = m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv') || ''; if (k) metas[k.toLowerCase()] = m.content || ''; });
    const gen = metas['generator'] || '';
    const qs = sel => { try { return !!document.querySelector(sel); } catch { return false; } };
    const sm = pat => scripts.some(s => pat.test(s));
    const lm = pat => links.some(l => pat.test(l));
    const add = (n,c,i,v) => domTech.push({name:n,cat:c,icon:i,ver:v||''});

    // CMS
    if (/wordpress/i.test(gen) || qs('meta[name="generator"][content*="WordPress"]') || sm(/wp-content|wp-includes/)) add('WordPress','CMS','W',gen.match(/WordPress\s*([\d.]+)/i)?.[1]);
    if (/drupal/i.test(gen) || sm(/drupal\.js/)) add('Drupal','CMS','D',gen.match(/Drupal\s*([\d.]+)/i)?.[1]);
    if (/joomla/i.test(gen)) add('Joomla','CMS','J','');
    if (/ghost/i.test(gen)) add('Ghost','CMS','G','');
    if (qs('[data-wf-site]') || sm(/webflow/)) add('Webflow','CMS','Wf','');
    if (qs('.sqs-block') || sm(/squarespace/)) add('Squarespace','CMS','Sq','');
    if (qs('[data-wix-]') || sm(/parastorage|wixstatic/)) add('Wix','CMS','Wx','');

    // JS Frameworks
    if (qs('[data-reactroot],[data-reactid]')) add('React','JS Framework','Re','');
    if (qs('#__next') || metas['next-head-count']) add('Next.js','JS Framework','Nx','');
    if (qs('#__nuxt,[data-n-head],[data-v-]')) add('Nuxt.js','JS Framework','Nu','');
    if (qs('#___gatsby')) add('Gatsby','SSG','Ga','');
    if (qs('[data-astro-cid]')) add('Astro','SSG','As','');
    if (qs('[ng-app],[ng-controller]')) add('AngularJS','JS Framework','Ag','');
    if (qs('[_ngcontent],[ng-version]')) add('Angular','JS Framework','Ag',document.querySelector('[ng-version]')?.getAttribute('ng-version'));
    if (qs('[data-svelte]')) add('Svelte','JS Framework','Sv','');
    if (qs('[x-data]') || sm(/alpine/i)) add('Alpine.js','JS Framework','Al','');
    if (qs('[hx-get],[hx-post]')) add('htmx','JS Library','Hx','');

    // CSS
    if (lm(/bootstrap/) || qs('.navbar-expand,.btn-primary')) add('Bootstrap','CSS Framework','Bs','');
    var twC = Array.from(document.querySelectorAll('[class]')).slice(0,40).some(function(el) { return typeof el.className==='string' && /\b(flex|text-sm|bg-white|p-[0-9]|rounded-|shadow-)\b/.test(el.className); });
    if (twC || lm(/tailwind/)) add('Tailwind CSS','CSS Framework','Tw','');

    // UI libs
    if (qs('.MuiBox-root,.MuiButton-root')) add('Material UI','UI Library','Mu','');
    if (qs('.ant-btn,.ant-layout')) add('Ant Design','UI Library','Ad','');
    if (qs('.chakra-')) add('Chakra UI','UI Library','Ch','');
    if (qs('[data-radix-collection-item],[data-radix-popper-content-wrapper]') || sm(/radix-ui/)) add('Radix UI','UI Library','Rx','');
    if (qs('[data-slot],[data-sidebar]') || sm(/shadcn/)) add('shadcn/ui','UI Library','Sh','');
    if (qs('[data-headlessui-state]') || sm(/headlessui/)) add('Headless UI','UI Library','Hu','');
    if (sm(/vaul|sonner/)) add('shadcn/ui','UI Library','Sh','');
    if (sm(/lucide/)) add('Lucide Icons','UI Library','Lu','');

    // 2025 frameworks
    if (qs('[data-qwik]') || sm(/qwik/)) add('Qwik','JS Framework','Qw','');
    if (sm(/solid-js|solid[\.-]/)) add('SolidJS','JS Framework','So','');
    if (sm(/lit[\.-]|lit-element/)) add('Lit','JS Framework','Lt','');
    if (sm(/stimulus/)) add('Stimulus','JS Framework','St','');
    if (sm(/turbo[\.-]/)) add('Turbo','JS Library','Tu','');
    if (sm(/unpoly/)) add('Unpoly','JS Library','Up','');

    // Hosting / Analytics
    if (sm(/vercel[\.-]|_vercel/)) add('Vercel Analytics','Analytics','VA','');
    if (sm(/vitals\.vercel/)) add('Vercel Speed Insights','Monitoring','VS','');
    if (sm(/partytown/)) add('Partytown','JS Library','Pt','');

    // Headless CMS
    if (sm(/prismic/)) add('Prismic','CMS','Pr','');
    if (sm(/sanity\.io|cdn\.sanity/)) add('Sanity','CMS','Sa','');
    if (sm(/contentful/)) add('Contentful','CMS','Cf','');
    if (sm(/strapi/)) add('Strapi','CMS','St','');
    if (sm(/storyblok/)) add('Storyblok','CMS','Sb','');

    // JS libs
    if (sm(/jquery[\.-]|jquery\.min/)) add('jQuery','JS Library','jQ','');
    if (sm(/lodash/)) add('Lodash','JS Library','Lo','');
    if (sm(/d3[\.-]/)) add('D3.js','JS Library','D3','');
    if (sm(/three[\.-]/)) add('Three.js','JS Library','3j','');
    if (sm(/gsap|TweenMax/)) add('GSAP','JS Library','GS','');
    if (sm(/chart[\.-]/i)) add('Chart.js','JS Library','Ch','');
    if (sm(/socket\.io/)) add('Socket.IO','JS Library','IO','');

    // Ecommerce
    if (sm(/shopify/) || qs('[data-shopify]')) add('Shopify','Ecommerce','Sh','');
    if (sm(/woocommerce/) || qs('.woocommerce')) add('WooCommerce','Ecommerce','Wc','');
    if (qs('[data-mage-init]')) add('Magento','Ecommerce','Mg','');

    // Analytics/Tags
    if (sm(/googletagmanager\.com\/gtm/)) add('Google Tag Manager','Tag Manager','GT','');
    if (sm(/google-analytics|gtag\/js/)) add('Google Analytics','Analytics','GA',sm(/gtag\/js/)?'GA4':'UA');
    if (sm(/segment\.com|cdn\.segment/)) add('Segment','Tag Manager','Sg','');
    if (sm(/mixpanel/)) add('Mixpanel','Analytics','Mx','');
    if (sm(/amplitude/)) add('Amplitude','Analytics','Am','');
    if (sm(/heap[\.-]|heapanalytics/)) add('Heap','Analytics','Hp','');
    if (sm(/plausible/)) add('Plausible','Analytics','Pl','');
    if (sm(/posthog/)) add('PostHog','Analytics','PH','');

    // Ads
    if (sm(/googlesyndication|adsbygoogle/)) add('Google AdSense','Advertising','As','');
    if (sm(/connect\.facebook\.net/)) add('Meta Pixel','Advertising','FB','');
    if (sm(/snap\.licdn/)) add('LinkedIn Insight','Advertising','Li','');
    if (sm(/analytics\.tiktok/)) add('TikTok Pixel','Advertising','TT','');
    if (sm(/criteo/)) add('Criteo','Advertising','Cr','');
    if (sm(/taboola/)) add('Taboola','Advertising','Tb','');

    // Session replay
    if (sm(/hotjar|static\.hotjar/)) add('Hotjar','Session Replay','Hj','');
    if (sm(/clarity\.ms/)) add('MS Clarity','Session Replay','Cl','');
    if (sm(/fullstory/)) add('FullStory','Session Replay','FS','');
    if (sm(/logrocket/)) add('LogRocket','Session Replay','LR','');
    if (sm(/mouseflow/)) add('Mouseflow','Session Replay','Mf','');

    // Error/Monitor
    if (sm(/sentry/)) add('Sentry','Error Tracking','Se','');
    if (sm(/bugsnag/)) add('Bugsnag','Error Tracking','Bg','');
    if (sm(/newrelic|nr-data/)) add('New Relic','Monitoring','NR','');
    if (sm(/datadoghq/)) add('Datadog','Monitoring','DD','');

    // A/B
    if (sm(/optimizely/)) add('Optimizely','A/B Testing','Op','');
    if (sm(/launchdarkly/)) add('LaunchDarkly','Feature Flags','LD','');

    // Payment
    if (sm(/js\.stripe/)) add('Stripe','Payment','St','');
    if (sm(/paypal\.com\/sdk|paypalobjects/)) add('PayPal','Payment','PP','');

    // Chat
    if (sm(/intercom/) || qs('#intercom-frame')) add('Intercom','Chat','Ic','');
    if (sm(/drift/) || qs('#drift-widget')) add('Drift','Chat','Dr','');
    if (sm(/zendesk/) || qs('#ze-snippet')) add('Zendesk','Chat','Zd','');
    if (sm(/crisp\.chat/)) add('Crisp','Chat','Cr','');
    if (sm(/tawk\.to/)) add('Tawk.to','Chat','Tw','');
    if (sm(/tidio/)) add('Tidio','Chat','Td','');
    if (sm(/hubspot|hs-scripts/)) add('HubSpot','Marketing','HS','');

    // Fonts
    if (lm(/fonts\.googleapis/)) add('Google Fonts','Fonts','GF','');
    if (lm(/use\.typekit|fonts\.adobe/)) add('Adobe Fonts','Fonts','AF','');
    if (sm(/fontawesome/) || lm(/font-awesome|fontawesome/)) add('Font Awesome','Fonts','FA','');

    // Cookie consent
    if (sm(/cookiebot/) || qs('#CybotCookiebotDialog')) add('Cookiebot','Cookie Consent','CB','');
    if (sm(/onetrust/) || qs('#onetrust-consent-sdk')) add('OneTrust','Cookie Consent','OT','');
    if (qs('.cky-consent-container')) add('CookieYes','Cookie Consent','CY','');

    // Security
    if (sm(/recaptcha/)) add('reCAPTCHA','Security','rC','');
    if (sm(/hcaptcha/)) add('hCaptcha','Security','hC','');
    if (sm(/turnstile/)) add('CF Turnstile','Security','Ts','');

    // Maps/Video
    if (sm(/maps\.googleapis/)) add('Google Maps','Maps','GM','');
    if (sm(/mapbox/)) add('Mapbox','Maps','Mb','');
    if (qs('iframe[src*="youtube"]')) add('YouTube','Video','YT','');
    if (qs('iframe[src*="vimeo"]')) add('Vimeo','Video','Vi','');
    if (sm(/disqus/) || qs('#disqus_thread')) add('Disqus','Social','Dq','');
    if (sm(/onesignal/)) add('OneSignal','Push','OS','');

    // Misc / Wappalyzer common
    if (qs('link[rel="manifest"]')) add('PWA','Misc','PW','');
    if (qs('meta[property="og:title"],meta[property="og:type"]')) add('Open Graph','Misc','OG','');
    if (qs('meta[name="twitter:card"]')) add('Twitter Cards','Misc','TC','');
    if (sm(/core-js/)) { var cjv = ''; scripts.forEach(function(s) { var m = s.match(/core-js[\/\-@]([\d.]+)/); if (m) cjv = m[1]; }); add('core-js','JS Library','CJ',cjv); }
    if (sm(/react-native-web|react-native/)) add('React Native for Web','JS Framework','RN','');
    if (sm(/framer-motion|motion/)) add('Framer Motion','JS Library','FM','');
    if (sm(/styled-components/)) add('styled-components','CSS Framework','SC','');
    if (sm(/emotion/)) add('Emotion','CSS Framework','Em','');
    if (sm(/webpack/i) || qs('script[src*="bundle"]')) add('webpack','Build','WP','');
    if (sm(/polyfill/)) add('Polyfill.io','JS Library','Pf','');
    if (sm(/cloudflare.*challenge|cdn-cgi\/challenge/)) add('Cloudflare Bot Management','Security','CF','');
    if (lm(/cdn\.cloudflare|cdnjs\.cloudflare/)) add('Cloudflare CDN','CDN','CF','');
    if (sm(/vercel/i) || qs('meta[name="generator"][content*="Vercel"]')) add('Vercel','Hosting','Vc','');
    if (qs('link[rel="preconnect"][href*="gstatic"]') || sm(/gstatic/)) add('Google CDN','CDN','GC','');
    if (sm(/unpkg\.com/)) add('unpkg','CDN','Up','');
    if (sm(/jsdelivr/)) add('jsDelivr','CDN','JD','');
    if (qs('script[type="application/ld+json"]')) add('JSON-LD','Misc','JL','');
    if (sm(/lazysizes|lazyload/i)) add('Lazy Loading','JS Library','Lz','');

    // Globals via EXTERNAL script (bypasses CSP - no inline execution)
    var ds = document.createElement('script');
    ds.src = chrome.runtime.getURL('tech-detect.js');
    ds.onload = function() { ds.remove(); };
    ds.onerror = function() {
      ds.remove();
      // Fallback: send DOM-only tech if script fails
      safeSend({ action: 'tech_stack', payload: domTech, hostname: location.hostname });
    };
    (document.head || document.documentElement).appendChild(ds);

    window.addEventListener('message', function handler(event) {
      if (event.source !== window || !event.data || event.data.type !== '__FPG_TECH__') return;
      window.removeEventListener('message', handler);
      var globals = event.data.payload || [];
      var merged = {};
      domTech.forEach(function(t) { merged[t.name] = t; });
      globals.forEach(function(t) { if (!merged[t.name]) merged[t.name] = t; else if (t.ver && !merged[t.name].ver) merged[t.name].ver = t.ver; });
      safeSend({ action: 'tech_stack', payload: Object.values(merged), hostname: location.hostname });
    });
  }

  // Script SHA-256 hashing for threat intel
  function scanScriptHashes() {
    if (!crypto || !crypto.subtle) return;
    var hashes = [];
    var pending = 0;
    function done() { if (pending <= 0 && hashes.length > 0) safeSend({ action: 'script_hashes', payload: hashes, hostname: location.hostname }); }

    // Inline scripts
    var inlines = Array.from(document.querySelectorAll('script:not([src])')).slice(0, 20);
    inlines.forEach(function(s) {
      if (s.textContent.length > 10 && s.textContent.length < 500000) {
        pending++;
        var data = new TextEncoder().encode(s.textContent);
        crypto.subtle.digest('SHA-256', data).then(function(buf) {
          var hash = Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
          hashes.push({ type: 'inline', hash: hash, size: s.textContent.length, preview: s.textContent.substring(0, 80) });
          pending--; done();
        }).catch(function() { pending--; done(); });
      }
    });
    // External scripts (hash URL as identifier)
    var externals = Array.from(document.querySelectorAll('script[src]')).slice(0, 30);
    externals.forEach(function(s) {
      if (s.src) {
        pending++;
        var data = new TextEncoder().encode(s.src);
        crypto.subtle.digest('SHA-256', data).then(function(buf) {
          var hash = Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
          hashes.push({ type: 'external', hash: hash, url: s.src, integrity: s.integrity || null });
          pending--; done();
        }).catch(function() { pending--; done(); });
      }
    });
    setTimeout(done, 3000);
  }

  // Existing scans
  function scanCookies(){var raw=document.cookie;if(!raw)return;var cookies=raw.split(';').map(function(c){return c.trim()}).filter(Boolean).map(function(c){var parts=c.split('=');var n=parts[0];var v=parts.slice(1).join('=');return{name:n.trim(),value:v.substring(0,80),isTracking:/(_ga|_gid|_fbp|_fbc|_gcl|_uet|__utm|_clck|hubspot|ajs_|mp_|amplitude|optimizely|__hstc|__hssc|_tt_|li_)/i.test(n.trim()),size:v.length}});safeSend({action:'cookies_detected',payload:{count:cookies.length,cookies:cookies},hostname:location.hostname})}
  function scanThirdPartyScripts(){var host=location.hostname;var db={'google-analytics.com':'Google Analytics','googletagmanager.com':'GTM','googlesyndication.com':'Google Ads','doubleclick.net':'DoubleClick','facebook.net':'Meta','facebook.com':'Meta','hotjar.com':'Hotjar','clarity.ms':'Clarity','fullstory.com':'FullStory','mouseflow.com':'Mouseflow','logrocket.com':'LogRocket','segment.com':'Segment','mixpanel.com':'Mixpanel','amplitude.com':'Amplitude','heap.io':'Heap','heapanalytics.com':'Heap','optimizely.com':'Optimizely','newrelic.com':'New Relic','nr-data.net':'New Relic','sentry.io':'Sentry','criteo.com':'Criteo','taboola.com':'Taboola','outbrain.com':'Outbrain','linkedin.com':'LinkedIn','tiktok.com':'TikTok','pinterest.com':'Pinterest','twitter.com':'Twitter/X','intercom.io':'Intercom','intercomcdn.com':'Intercom','drift.com':'Drift','zendesk.com':'Zendesk','hubspot.com':'HubSpot','hs-scripts.com':'HubSpot','hs-analytics.net':'HubSpot','marketo.net':'Marketo','pardot.com':'Pardot','amazon-adsystem.com':'Amazon Ads','plausible.io':'Plausible','onesignal.com':'OneSignal','snap.com':'Snapchat'};var tp=[];Array.from(document.querySelectorAll('script[src]')).forEach(function(s){try{var u=new URL(s.src,location.origin);if(u.hostname!==host&&!u.hostname.endsWith('.'+host)){var tn=null;Object.keys(db).forEach(function(d){if(u.hostname.indexOf(d)!==-1)tn=db[d]});tp.push({src:s.src,domain:u.hostname,isTracker:!!tn,trackerName:tn,async:s.async,defer:s.defer,integrity:s.integrity||null})}}catch(e){}});if(tp.length>0)safeSend({action:'third_party_scripts',payload:tp,hostname:host})}
  function scanTrackingPixels(){var px=[];Array.from(document.querySelectorAll('img')).forEach(function(img){if(((img.width<=2&&img.height<=2)||(img.naturalWidth<=2&&img.naturalHeight<=2)||/pixel|beacon|track|1x1/i.test(img.src))&&img.src){try{var u=new URL(img.src,location.origin);px.push({src:img.src,domain:u.hostname,dimensions:img.width+'x'+img.height})}catch(e){}}});if(px.length>0)safeSend({action:'tracking_pixels',payload:px,hostname:location.hostname})}
  function scanHiddenElements(){var h=Array.from(document.querySelectorAll('canvas')).filter(function(c){var s=getComputedStyle(c);return s.display==='none'||s.visibility==='hidden'||c.offsetWidth===0});if(h.length>0)safeSend({action:'detection',payload:{category:'Canvas Fingerprint',detail:h.length+' hidden <canvas>',severity:'high',valueRead:'',timestamp:Date.now(),stack:''},hostname:location.hostname})}
  function scanSecurityMeta(){var m=[];function a(n,s){var el=document.querySelector(s);m.push({name:n,value:el?el.content||'':'',status:el?'present':'missing'})}a('CSP (meta)','meta[http-equiv="Content-Security-Policy"]');a('Referrer','meta[name="referrer"]');a('X-Frame-Options','meta[http-equiv="X-Frame-Options"]');safeSend({action:'security_meta',payload:{meta:m},hostname:location.hostname})}
  function scanForms(){var fd=[];Array.from(document.querySelectorAll('form')).forEach(function(f){var inp=Array.from(f.querySelectorAll('input,select,textarea'));var pw=inp.filter(function(i){return i.type==='password'}).length;var em=inp.filter(function(i){return i.type==='email'||/email/i.test(i.name+i.id)}).length;var cc=inp.filter(function(i){return/card|cc|credit|cvv|cvc|expir|billing/i.test(i.name+i.id+i.className+(i.autocomplete||''))}).length;var ssn=inp.filter(function(i){return/ssn|social.?sec|tax.?id/i.test(i.name+i.id+(i.placeholder||''))}).length;var hid=inp.filter(function(i){return i.type==='hidden'});var action=f.action||'';var xo=action&&action.indexOf(location.origin)!==0&&action.charAt(0)!=='/'&&action.charAt(0)!=='.';var risk='low';if(pw)risk='medium';if(cc||ssn)risk='high';if(xo&&(pw||cc))risk='critical';fd.push({action:action,method:f.method||'GET',risk:risk,isCrossOrigin:xo,inputCount:inp.length,passwordFields:pw,emailFields:em,ccFields:cc,ssnFields:ssn,hiddenInputs:hid.map(function(i){return{name:i.name,value:i.value.substring(0,60)}})})});if(fd.length>0)safeSend({action:'forms_detected',payload:fd,hostname:location.hostname})}
  function scanResourceHints(){var h=[];Array.from(document.querySelectorAll('link[rel="dns-prefetch"],link[rel="preconnect"],link[rel="prefetch"],link[rel="preload"]')).forEach(function(l){h.push({rel:l.rel,href:l.href})});if(h.length>0)safeSend({action:'resource_hints',payload:h,hostname:location.hostname})}
  function scanIframes(){var d=Array.from(document.querySelectorAll('iframe')).map(function(f){var s=getComputedStyle(f);return{src:f.src||'(srcdoc)',sandbox:f.sandbox?f.sandbox.value:null,allow:f.allow||null,isHidden:s.display==='none'||s.visibility==='hidden'||f.width==0||f.height==0,dimensions:f.width+'x'+f.height,crossOrigin:f.src?f.src.indexOf(location.origin)!==0:false}});if(d.length>0)safeSend({action:'iframes_detected',payload:d,hostname:location.hostname})}
  function scanExternalStylesheets(){var host=location.hostname;var ext=[];Array.from(document.querySelectorAll('link[rel="stylesheet"]')).forEach(function(l){try{var u=new URL(l.href,location.origin);if(u.hostname!==host&&u.hostname.indexOf('.'+host)===-1)ext.push({href:l.href,domain:u.hostname,integrity:l.integrity||null})}catch(e){}});if(ext.length>0)safeSend({action:'external_stylesheets',payload:ext,hostname:host})}
  function scanLocalStorageContents(){var ls=[],ss=[];try{for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);var v=localStorage.getItem(k);ls.push({key:k,value:(v||'').substring(0,120),size:(v||'').length})}}catch(e){}try{for(var j=0;j<sessionStorage.length;j++){var k2=sessionStorage.key(j);var v2=sessionStorage.getItem(k2);ss.push({key:k2,value:(v2||'').substring(0,120),size:(v2||'').length})}}catch(e){}safeSend({action:'storage_contents',payload:{localStorage:ls,sessionStorage:ss},hostname:location.hostname})}
  function scanServiceWorkers(){if(!navigator.serviceWorker)return;navigator.serviceWorker.getRegistrations().then(function(r){var d=r.map(function(r){return{scope:r.scope,scriptURL:r.active?r.active.scriptURL:r.installing?r.installing.scriptURL:''}});if(d.length>0)safeSend({action:'service_workers',payload:d,hostname:location.hostname})}).catch(function(){})}
  function scanShadowRoots(){var ct=0;(function w(n){if(n.shadowRoot){ct++;w(n.shadowRoot)}var ch=n.children||[];for(var i=0;i<ch.length;i++)w(ch[i])})(document.body||document.documentElement);if(ct>0)safeSend({action:'detection',payload:{category:'DOM Manipulation',detail:ct+' Shadow DOM root(s)',severity:'medium',valueRead:'',timestamp:Date.now(),stack:''},hostname:location.hostname})}
  function scanDataAttributes(){var sus=[];var els=document.querySelectorAll('[data-config],[data-payload],[data-encoded],[data-json],[data-init]');for(var i=0;i<els.length;i++){var el=els[i];for(var j=0;j<el.attributes.length;j++){var a=el.attributes[j];if(a.name.indexOf('data-')===0&&a.value.length>200)sus.push({element:el.tagName,attr:a.name,size:a.value.length})}}if(sus.length>0)safeSend({action:'detection',payload:{category:'Data Exfiltration',detail:sus.length+' large data-* attribute(s)',severity:'medium',valueRead:JSON.stringify(sus).substring(0,300),timestamp:Date.now(),stack:''},hostname:location.hostname})}

  // ═══════ PAGE LINKS (urlscan.io data.links equivalent) ═══════
  function scanPageLinks() {
    var links = [];
    var seen = new Set();
    Array.from(document.querySelectorAll('a[href]')).forEach(function(a) {
      var href = a.href || '';
      if (href && !seen.has(href) && href.indexOf('javascript:') !== 0) {
        seen.add(href);
        var text = (a.textContent || '').trim().substring(0, 120);
        var isExternal = false;
        try { isExternal = new URL(href).hostname !== location.hostname; } catch(e) {}
        links.push({ href: href, text: text, isExternal: isExternal });
      }
    });
    if (links.length > 0) safeSend({ action: 'page_links', payload: links.slice(0, 500), hostname: location.hostname });
  }

  // ═══════ PAGE TIMING (urlscan.io data.timing equivalent) ═══════
  function scanPageTiming() {
    try {
      var nav = performance.getEntriesByType('navigation')[0];
      var timing = {};
      if (nav) {
        timing.dnsLookup = Math.round(nav.domainLookupEnd - nav.domainLookupStart);
        timing.tcpConnect = Math.round(nav.connectEnd - nav.connectStart);
        timing.tlsHandshake = Math.round(nav.secureConnectionStart > 0 ? nav.connectEnd - nav.secureConnectionStart : 0);
        timing.ttfb = Math.round(nav.responseStart - nav.requestStart);
        timing.download = Math.round(nav.responseEnd - nav.responseStart);
        timing.domInteractive = Math.round(nav.domInteractive);
        timing.domContentLoaded = Math.round(nav.domContentLoadedEventEnd);
        timing.loadComplete = Math.round(nav.loadEventEnd);
        timing.transferSize = nav.transferSize || 0;
        timing.encodedBodySize = nav.encodedBodySize || 0;
        timing.decodedBodySize = nav.decodedBodySize || 0;
        timing.protocol = nav.nextHopProtocol || '';
      }
      safeSend({ action: 'page_timing', payload: timing, hostname: location.hostname });
    } catch(e) {}
  }

  // ═══════ JS GLOBALS (urlscan.io data.globals equivalent) ═══════
  function scanJSGlobals() {
    var ds = document.createElement('script');
    ds.src = chrome.runtime.getURL('tech-detect.js');
    ds.onload = function() { ds.remove(); };
    (document.head || document.documentElement).appendChild(ds);

    // Also enumerate non-standard globals via inline-safe method
    // We'll use a second external script approach
    // But for now, enumerate what we can from content script
    // by checking the globals list that tech-detect.js sends
  }

  // ═══════ PHISHING INDICATORS ═══════
  function scanPhishingIndicators() {
    var emit = function(detail, severity, type) {
      safeSend({ action: 'detection', payload: { category: 'Phishing Indicator', detail: detail, severity: severity, valueRead: type, timestamp: Date.now(), stack: '' }, url: location.href, hostname: location.hostname });
    };
    var host = location.hostname;

    // ─── 1. CREDENTIAL HARVESTING FORMS ──────────────────
    var forms = document.querySelectorAll('form');
    var pwFields = document.querySelectorAll('input[type="password"]');
    forms.forEach(function(f) {
      var hasPw = f.querySelector('input[type="password"]');
      var hasEmail = f.querySelector('input[type="email"],input[name*="email"],input[name*="user"],input[autocomplete="username"]');
      var action = f.action || '';
      // Cross-origin credential submission
      if (hasPw && action && action.indexOf(location.origin) !== 0 && action.charAt(0) !== '/' && action !== '')
        emit('Password form submits to external domain: ' + action, 'critical', 'cross_origin_login');
      // Empty/blank action (JS-intercepted form)
      if (hasPw && (!action || action === '' || action === 'about:blank'))
        emit('Password form with empty/blank action (JS-intercepted submission)', 'high', 'empty_form_handler');
      // mailto: exfiltration
      if (action && action.indexOf('mailto:') === 0)
        emit('Form submits via mailto: ' + action, 'critical', 'mailto_form');
      // Autocomplete disabled on password/email (hides from browser password manager)
      if (hasPw && hasPw.getAttribute('autocomplete') === 'off')
        emit('Password field has autocomplete="off" (evades password manager)', 'high', 'autocomplete_off_pw');
      if (hasEmail && hasEmail.getAttribute('autocomplete') === 'off')
        emit('Email/username field has autocomplete="off"', 'medium', 'autocomplete_off_email');
      // Hidden fields that may carry victim identifiers
      var hiddens = f.querySelectorAll('input[type="hidden"]');
      var susHidden = Array.from(hiddens).filter(function(h) { var n = (h.name || '').toLowerCase(); return /token|key|session|victim|target|uid|redirect/i.test(n); });
      if (susHidden.length >= 2)
        emit('Form contains ' + susHidden.length + ' suspicious hidden fields: ' + susHidden.map(function(h){return h.name}).join(', '), 'high', 'suspicious_hidden_fields');
    });
    // Password fields outside any form (JS-only credential capture)
    if (pwFields.length > 0) {
      var orphanPw = Array.from(pwFields).filter(function(p) { return !p.closest('form'); });
      if (orphanPw.length > 0)
        emit(orphanPw.length + ' password field(s) outside any <form> (JS-only credential capture)', 'critical', 'orphan_password_field');
    }

    // ─── 2. BRAND IMPERSONATION ──────────────────────────
    // Favicon from major brand domains
    var brandDomains = {'microsoft.com':'Microsoft','google.com':'Google','apple.com':'Apple','paypal.com':'PayPal','amazon.com':'Amazon','facebook.com':'Facebook','netflix.com':'Netflix','instagram.com':'Instagram','linkedin.com':'LinkedIn','twitter.com':'Twitter/X','dropbox.com':'Dropbox','adobe.com':'Adobe','chase.com':'Chase','wellsfargo.com':'Wells Fargo','bankofamerica.com':'BoA','dhl.com':'DHL','ups.com':'UPS','fedex.com':'FedEx','usps.com':'USPS','office.com':'Microsoft 365','live.com':'Microsoft','outlook.com':'Microsoft','onedrive.com':'Microsoft','icloud.com':'Apple','github.com':'GitHub','slack.com':'Slack','zoom.us':'Zoom','docusign.com':'DocuSign','salesforce.com':'Salesforce','stripe.com':'Stripe','shopify.com':'Shopify'};
    var isLegitBrand = Object.keys(brandDomains).some(function(d) { return host.endsWith(d); });

    document.querySelectorAll('link[rel*="icon"]').forEach(function(f) {
      if (f.href) { try {
        var fHost = new URL(f.href).hostname;
        if (fHost !== host && !fHost.endsWith('.' + host)) {
          // Check if favicon domain is a CDN/asset domain of the same org
          var pageApex = host.replace(/^www\./, '').split('.').slice(-2).join('.');
          var favApex = fHost.split('.').slice(-2).join('.');
          // Known CDN patterns for same-org - try 2-part and 3-part apex
          var isSameOrg = false;
          var pageApexes = [pageApex];
          var hostParts = host.split('.');
          if (hostParts.length >= 3) pageApexes.push(hostParts.slice(-3).join('.'));
          var cdnMappings = {
            'linkedin.com': ['licdn.com','linkedin.cn'],
            'google.com': ['gstatic.com','googleapis.com','googleusercontent.com','ggpht.com'],
            'facebook.com': ['fbcdn.net','fbsbx.com','facebook.net'],
            'twitter.com': ['twimg.com','t.co'],
            'x.com': ['twimg.com','t.co','pscp.tv'],
            'microsoft.com': ['msft.net','msecnd.net','azureedge.net','live.com','office.com','office.net','office365.com','onecdn.static.microsoft','microsoftonline.com','msn.com'],
            'outlook.cloud.microsoft': ['office.com','office.net','office365.com','onecdn.static.microsoft','static.microsoft','cdn.office.net','microsoft.com','msn.com','msftauth.net'],
            'amazon.com': ['ssl-images-amazon.com','media-amazon.com','cloudfront.net'],
            'apple.com': ['mzstatic.com','icloud-content.com'],
            'github.com': ['githubassets.com','githubusercontent.com'],
            'pinterest.com': ['pinimg.com'],
            'reddit.com': ['redditmedia.com','redditstatic.com'],
            'instagram.com': ['cdninstagram.com','fbcdn.net'],
            'tiktok.com': ['tiktokcdn.com','musical.ly'],
            'youtube.com': ['ytimg.com','googlevideo.com','ggpht.com'],
          };
          for (var ai = 0; ai < pageApexes.length && !isSameOrg; ai++) {
            if (cdnMappings[pageApexes[ai]]) { isSameOrg = cdnMappings[pageApexes[ai]].some(function(cdn) { return fHost.endsWith(cdn); }); }
          }
          // Also check if they share a root word (e.g. licdn → linkedin)
          if (!isSameOrg) { var pageWord = pageApex.split('.')[0]; var favWord = favApex.split('.')[0]; if (favWord.indexOf(pageWord.substring(0,4)) !== -1 || pageWord.indexOf(favWord.substring(0,4)) !== -1) isSameOrg = true; }

          if (!isSameOrg) {
            var impBrand = null;
            Object.keys(brandDomains).forEach(function(d) { if (fHost.endsWith(d)) impBrand = brandDomains[d]; });
            if (impBrand && !isLegitBrand)
              emit('Favicon loaded from ' + impBrand + ' (' + fHost + ') on non-' + impBrand + ' domain - brand impersonation', 'critical', 'brand_favicon_' + impBrand);
            else
              emit('Favicon loaded from unrelated external domain: ' + fHost, 'medium', 'external_favicon');
          }
          // Same-org CDN favicons are NOT flagged (e.g. static.licdn.com for linkedin.com)
        }
      } catch(e) {} }
    });
    // Images from brand CDNs on non-brand pages
    if (!isLegitBrand) {
      var brandImgs = [];
      document.querySelectorAll('img[src]').forEach(function(img) {
        Object.keys(brandDomains).forEach(function(d) {
          if (img.src.indexOf(d) !== -1 && !host.endsWith(d)) brandImgs.push(brandDomains[d]);
        });
      });
      var uniqBrands = brandImgs.filter(function(v,i,a){return a.indexOf(v)===i});
      if (uniqBrands.length > 0)
        emit('Images loaded from brand CDN(s): ' + uniqBrands.join(', ') + ' - possible impersonation', 'high', 'brand_images');
    }
    // Title/heading brand keyword analysis
    var title = (document.title || '').toLowerCase();
    var h1 = (document.querySelector('h1') || {}).textContent || '';
    var pageText = (title + ' ' + h1).toLowerCase();
    var brandKeywords = ['paypal','microsoft','office 365','microsoft 365','outlook','onedrive','apple','icloud','google','gmail','amazon','facebook','meta','instagram','netflix','bank of america','chase','wells fargo','citibank','hsbc','barclays','dhl','ups','fedex','usps','docusign','dropbox','adobe','github','linkedin','slack','zoom','steam','epic games','coinbase','binance','metamask','blockchain','crypto'];
    var actionKeywords = ['sign in','log in','login','signin','verify','confirm','update','secure','suspended','locked','unusual activity','unauthorized','expired','re-verify','validate','restore','recover','reactivate','billing'];
    var matchedBrands = brandKeywords.filter(function(b) { return pageText.indexOf(b) !== -1; });
    var matchedActions = actionKeywords.filter(function(b) { return pageText.indexOf(b) !== -1; });
    if (matchedBrands.length > 0 && matchedActions.length > 0 && !isLegitBrand)
      emit('Brand + action keywords in title/heading: ' + matchedBrands.join(', ') + ' + ' + matchedActions.join(', '), 'critical', 'brand_action_keywords');
    else if (matchedBrands.length >= 2 && !isLegitBrand)
      emit('Multiple brand keywords in title: ' + matchedBrands.join(', '), 'high', 'multi_brand_keywords');

    // ─── 3. ANTI-ANALYSIS / DEVTOOLS EVASION ─────────────
    // Right-click disabled
    if (document.oncontextmenu !== null || document.querySelector('[oncontextmenu*="return false"],[oncontextmenu*="preventDefault"]'))
      emit('Right-click context menu disabled - anti-analysis technique', 'high', 'context_menu_disabled');
    // Check inline scripts for anti-debug patterns
    document.querySelectorAll('script:not([src])').forEach(function(s) {
      var code = s.textContent || '';
      if (code.length < 30) return;
      // DevTools keyboard shortcut blocking (F12, Ctrl+Shift+I/J/C, Ctrl+U)
      if (/keyCode\s*={2,3}\s*(123|73|74|67|85)\b/.test(code) || /F12|Ctrl\+Shift\+I|Ctrl\+Shift\+J|Ctrl\+U/i.test(code))
        emit('Script blocks DevTools keyboard shortcuts (F12/Ctrl+Shift+I)', 'high', 'devtools_shortcut_block');
      // Infinite debugger loop (watchdog)
      if (/function.*\bconstructor\b.*\bdebugger\b|setInterval.*debugger|while.*true.*debugger/s.test(code))
        emit('Infinite debugger loop detected (anti-analysis watchdog)', 'critical', 'debugger_trap');
      // DevTools size detection (outerWidth - innerWidth threshold)
      if (/outer(Width|Height)\s*-\s*inner(Width|Height)|window\.(outerWidth|outerHeight)/.test(code) && /threshold|>.*160|>.*100/.test(code))
        emit('DevTools window size detection (viewport monitoring)', 'high', 'devtools_size_detect');
      // console.clear spam
      if ((code.match(/console\.clear\(\)/g) || []).length >= 2)
        emit('Repeated console.clear() - anti-forensics', 'high', 'console_clear_spam');
      // History manipulation (prevents back button)
      if (/history\.(pushState|replaceState)\s*\(/.test(code) && /setInterval|setTimeout/.test(code))
        emit('Repeated history manipulation (back button trap)', 'high', 'history_trap');
      // Clipboard interception on the page
      if (/addEventListener\s*\(\s*['"]paste['"]/.test(code) && /preventDefault/.test(code))
        emit('Paste event intercepted - possible pastejacking or input control', 'high', 'paste_intercept');
    });

    // ─── 4. SUSPICIOUS PAGE STRUCTURE ────────────────────
    // Login form is the only content on page (minimal DOM)
    var bodyChildren = document.body ? document.body.children.length : 0;
    if (pwFields.length > 0 && bodyChildren <= 5)
      emit('Login form on minimal page (' + bodyChildren + ' body elements) - possible phishing page', 'high', 'minimal_login_page');
    // Page has very little text content relative to forms
    var textLen = (document.body ? document.body.innerText : '').length;
    if (pwFields.length > 0 && textLen < 200)
      emit('Login form on page with very little text (' + textLen + ' chars) - stripped phishing page', 'high', 'low_text_login');
    // Overlay/modal login (absolute/fixed positioned form covering page)
    forms.forEach(function(f) {
      if (f.querySelector('input[type="password"]')) {
        var st = getComputedStyle(f);
        if (st.position === 'fixed' || st.position === 'absolute') {
          if (parseInt(st.zIndex) > 100 || st.zIndex === 'auto')
            emit('Login form uses fixed/absolute positioning (overlay phishing technique)', 'high', 'overlay_login_form');
        }
      }
    });
    // Hidden iframe with login (clickjacking vector)
    document.querySelectorAll('iframe').forEach(function(ifr) {
      var st = getComputedStyle(ifr);
      if ((st.opacity === '0' || parseFloat(st.opacity) < 0.1 || st.visibility === 'hidden') && ifr.src)
        emit('Hidden/transparent iframe: ' + ifr.src.substring(0, 200) + ' - clickjacking vector', 'critical', 'hidden_iframe_clickjack');
    });
    // Meta refresh redirect (auto-redirect after delay)
    var metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
    if (metaRefresh) {
      var content = metaRefresh.content || '';
      emit('Meta refresh redirect detected: ' + content.substring(0, 200), 'high', 'meta_refresh_redirect');
    }
    // Data URI page
    if (location.href.indexOf('data:text/html') === 0)
      emit('Page loaded from data: URI - embedded phishing page', 'critical', 'data_uri_page');
    // Blob URL page
    if (location.href.indexOf('blob:') === 0)
      emit('Page loaded from blob: URL - dynamically generated content', 'high', 'blob_url_page');

    // ─── 5. CREDENTIAL EXFILTRATION PATTERNS ─────────────
    // Input fields with keydown/keyup listeners (keylogger pattern)
    var inputsWithKeyLog = 0;
    document.querySelectorAll('input[type="password"],input[type="email"],input[type="text"]').forEach(function(inp) {
      if (inp.onkeydown || inp.onkeyup || inp.onkeypress || inp.oninput) inputsWithKeyLog++;
    });
    if (inputsWithKeyLog >= 2)
      emit(inputsWithKeyLog + ' input fields have inline key event handlers - possible keylogger', 'critical', 'inline_keylogger');

    // ─── 6. URGENCY / SOCIAL ENGINEERING CUES ────────────
    var bodyText = (document.body ? document.body.innerText : '').toLowerCase();
    var urgencyPhrases = ['your account has been','account will be closed','verify your identity','confirm your information','unusual sign-in','unauthorized access','suspended','click here to restore','within 24 hours','within 48 hours','immediate action required','failure to verify','will result in','permanently disabled','limited time','act now','verify immediately','update your payment','billing information expired'];
    var matchedUrgency = urgencyPhrases.filter(function(p) { return bodyText.indexOf(p) !== -1; });
    if (matchedUrgency.length >= 2)
      emit('Social engineering urgency cues (' + matchedUrgency.length + '): ' + matchedUrgency.slice(0, 3).join('; '), 'critical', 'urgency_social_engineering');
    else if (matchedUrgency.length === 1)
      emit('Urgency language detected: "' + matchedUrgency[0] + '"', 'medium', 'urgency_single');

    // ─── 7. SUSPICIOUS SCRIPTS/RESOURCES ─────────────────
    // Check for Telegram/Discord bot exfiltration endpoints
    document.querySelectorAll('script:not([src])').forEach(function(s) {
      var code = s.textContent || '';
      if (/api\.telegram\.org\/bot/.test(code)) emit('Telegram Bot API endpoint in script - credential exfiltration to Telegram', 'critical', 'telegram_exfil');
      if (/discord\.com\/api\/webhooks|discordapp\.com\/api\/webhooks/.test(code)) emit('Discord webhook in script - credential exfiltration to Discord', 'critical', 'discord_exfil');
      if (/formspree\.io|formsubmit\.co|getform\.io|formspark\.io/.test(code)) emit('Third-party form submission service in script - possible credential relay', 'high', 'form_service_exfil');
    });
  }

  // ═══════ JS OBFUSCATION DETECTION (enhanced) ═══════
  function scanJSObfuscation() {
    var emit = function(detail, severity, size) {
      safeSend({ action: 'detection', payload: { category: 'JS Obfuscation', detail: detail, severity: severity, valueRead: size + ' bytes', timestamp: Date.now(), stack: '' }, url: location.href, hostname: location.hostname });
    };
    document.querySelectorAll('script:not([src])').forEach(function(s) {
      var code = s.textContent || '';
      if (code.length < 50) return;
      var L = code.length;
      // Scale thresholds by code size - large production bundles have legitimate uses of these patterns
      var isLargeBundle = L > 50000;
      // Hex encoding density (percentage-based for large scripts)
      var hexMatches = (code.match(/\\x[0-9a-f]{2}/gi) || []).length;
      var hexDensity = hexMatches / (L / 1000);
      if (hexDensity > 5 && hexMatches > 30) emit('Script with ' + hexMatches + ' hex-encoded chars (density: ' + hexDensity.toFixed(1) + '/KB)', isLargeBundle ? 'medium' : 'high', L);
      // Unicode escape density
      var uniMatches = (code.match(/\\u[0-9a-f]{4}/gi) || []).length;
      var uniDensity = uniMatches / (L / 1000);
      if (uniDensity > 3 && uniMatches > 40) emit('Script with ' + uniMatches + ' unicode escapes (density: ' + uniDensity.toFixed(1) + '/KB)', isLargeBundle ? 'medium' : 'high', L);
      // eval packer (always suspicious regardless of size)
      if (/eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k/.test(code)) emit('Dean Edwards packer (eval(function(p,a,c,k,...)))', 'critical', L);
      // Base64 decode chains - need high density to be suspicious
      var atobCount = (code.match(/atob\s*\(/g) || []).length;
      if (atobCount >= 3 && !isLargeBundle) emit('Script with ' + atobCount + ' atob() calls - base64 decode chain', 'high', L);
      if (atobCount >= 8) emit('Script with ' + atobCount + ' atob() calls - heavy base64 decode chain', 'high', L);
      // document.write(unescape()) - always suspicious
      if (/document\.write\s*\(\s*unescape\s*\(/.test(code)) emit('document.write(unescape()) - classic phishing obfuscation', 'critical', L);
      // XOR decryption - only flag in SMALL scripts where the ratio is meaningful
      // Large production bundles legitimately use charCodeAt + XOR for string processing
      if (!isLargeBundle && /charCodeAt|fromCharCode/.test(code) && /\^\s*\d|\bxor\b|XOR/i.test(code))
        emit('XOR decryption pattern in small script (' + L + 'B)', 'high', L);
      // String array rotation - need high array index density
      var arrayIdxCount = (code.match(/\[\d+\]/g) || []).length;
      var arrayDensity = arrayIdxCount / (L / 1000);
      if (/\[['"][^'"]{2,}['"],\s*['"]/.test(code) && arrayDensity > 15 && !isLargeBundle) emit('String array rotation pattern (obfuscator.io)', 'high', L);
      // Single-line blob (only small-to-medium scripts)
      if (code.indexOf('\n') === -1 && L > 5000 && L < 50000) emit('Single-line script blob (' + L + ' chars)', 'medium', L);
      // Function constructor obfuscation
      if (/Function\s*\(\s*['"]/.test(code) && /return|eval|call|apply/.test(code) && !isLargeBundle) emit('Function constructor used for code generation', 'high', L);
      // Multi-eval (only if high density)
      var evalCount = (code.match(/\beval\s*\(/g) || []).length;
      if (evalCount >= 2 && !isLargeBundle) emit('Multiple eval() calls (' + evalCount + ') - multi-layer obfuscation', 'critical', L);
      // Base64+XOR combo - TRUE phishing kit signature: requires ALL of atob + charCodeAt + XOR in a SMALL script
      if (atobCount >= 2 && /charCodeAt/.test(code) && /\^\s*\d/.test(code) && L < 30000)
        emit('Base64 + XOR encoding combo in small script - possible phishing kit', 'critical', L);
    });
    // External scripts with suspicious characteristics
    document.querySelectorAll('script[src]').forEach(function(s) {
      var src = s.src || '';
      // Cache-busting hash in filename (only flag if not from known CDNs)
      if (/index-[a-f0-9]{8,}\.js/i.test(src) && !/cdn|static|assets|webpack|chunk/i.test(src))
        emit('Script with cache-busting hash filename: ' + src.substring(src.lastIndexOf('/')) + ' - phishing kit pattern', 'high', 0);
      // Script from raw IP
      try { var u = new URL(src); if (/^[0-9.]+$/.test(u.hostname)) emit('External script loaded from raw IP: ' + u.hostname, 'critical', 0); } catch(e) {}
      // Script from data: URI
      if (src.indexOf('data:') === 0) emit('Script loaded from data: URI - inline payload', 'critical', 0);
    });
  }

  // ═══════ DOM CONTENT HASH ═══════
  function scanDOMHash() {
    try {
      var html = document.documentElement.outerHTML || '';
      if (html.length > 100 && crypto && crypto.subtle) {
        var data = new TextEncoder().encode(html);
        crypto.subtle.digest('SHA-256', data).then(function(buf) {
          var hash = Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
          safeSend({ action: 'detection', payload: { category: 'Page Integrity', detail: 'DOM SHA-256: ' + hash, severity: 'info', valueRead: html.length + ' bytes', timestamp: Date.now(), stack: '' }, url: location.href, hostname: location.hostname });
        });
      }
    } catch(e) {}
  }

  // ═══════ SUSPICIOUS URL ANALYSIS (enhanced) ═══════
  function scanSuspiciousURL() {
    try {
      var u = new URL(location.href);
      var host = u.hostname;
      var emit = function(detail, severity) {
        safeSend({ action: 'detection', payload: { category: 'Suspicious URL', detail: detail, severity: severity, valueRead: location.href, timestamp: Date.now(), stack: '' }, url: location.href, hostname: host });
      };
      // Raw IP hosting
      if (/^[0-9.]+$/.test(host)) emit('Page served from raw IP: ' + host, 'high');
      if (/^[0-9a-f:]+$/i.test(host)) emit('Page served from IPv6 address: ' + host, 'high');
      // Punycode/IDN homograph
      if (/xn--/.test(host)) emit('Punycode/IDN domain - potential homograph attack: ' + host, 'critical');
      // Excessive subdomains
      var dotCount = (host.match(/\./g) || []).length;
      if (dotCount >= 4) emit('Excessive subdomains (' + (dotCount + 1) + ' levels): ' + host, 'high');
      // Very long hostname
      if (host.length > 50) emit('Unusually long hostname (' + host.length + ' chars)', 'medium');
      // Homograph-like patterns (rn→m, vv→w, 1→l, 0→o)
      var homoglyphs = [['rn','m'],['vv','w'],['cl','d'],['nn','m']];
      var brandNames = ['microsoft','paypal','apple','google','amazon','facebook','netflix','instagram','linkedin','github','dropbox','coinbase','binance','metamask','chase','wellsfargo','bankofamerica'];
      brandNames.forEach(function(brand) {
        homoglyphs.forEach(function(pair) {
          var fake = brand.replace(pair[1], pair[0]);
          if (fake !== brand && host.indexOf(fake) !== -1) emit('Possible homograph: "' + fake + '" mimics "' + brand + '" in hostname', 'critical');
        });
        // Brand in subdomain - check if this is actually the brand's own domain
        var isBrandOwned = host.endsWith(brand + '.com') || host.endsWith(brand + '.net') || host.endsWith(brand + '.org') || host.endsWith(brand + '.io') || host.endsWith('.' + brand) || host === brand;
        if (host.indexOf(brand) !== -1 && !isBrandOwned)
          emit('Brand name "' + brand + '" in non-brand hostname: ' + host, 'high');
      });
      // Suspicious keywords in URL path
      var pathKW = /\/(secure|login|signin|sign-in|verify|update|confirm|account|banking|webscr|auth|oauth|sso|identity|credential|wallet|checkout|payment|invoice|reset|recover|unlock)/i;
      var isLegit = brandNames.some(function(b) { return host.endsWith(b + '.com') || host.endsWith('.' + b); });
      if (pathKW.test(u.pathname) && !isLegit) emit('Authentication keyword in URL path on non-brand domain: ' + (u.pathname.match(pathKW) || [''])[0], 'high');
      // HTTP page with password field
      if (u.protocol === 'http:' && document.querySelector('input[type="password"]')) emit('Password field on non-HTTPS page - credentials sent in cleartext', 'critical');
      // Very long URL (common in phishing with encoded params)
      if (location.href.length > 500) emit('Unusually long URL (' + location.href.length + ' chars) - possible encoded payload', 'medium');
      // Multiple redirects encoded in URL params
      if ((u.search.match(/https?%3A/gi) || []).length >= 2) emit('Multiple encoded URLs in query parameters - redirect chain', 'high');
      // Suspicious TLDs commonly used for phishing
      var phishTLDs = ['.tk','.ml','.ga','.cf','.gq','.top','.xyz','.buzz','.click','.loan','.work','.surf','.icu','.cam','.fun','.monster','.rest','.beauty','.hair'];
      phishTLDs.forEach(function(tld) { if (host.endsWith(tld)) emit('Suspicious TLD commonly used for phishing: ' + tld, 'high'); });
      // Recently popular phishing hosting patterns
      if (/\.pages\.dev$|\.workers\.dev$|\.web\.app$|\.firebaseapp\.com$|\.netlify\.app$|\.vercel\.app$|\.herokuapp\.com$|\.glitch\.me$|\.render\.com$/.test(host))
        emit('Page hosted on free platform: ' + host + ' - commonly abused for phishing', 'medium');
    } catch(e) {}
  }

  // ═══════ PAGE IOC EXTRACTOR ═══════
  // Automatically extracts indicators of compromise from visible page text
  // Useful for analysts reading threat reports, advisories, blog posts
  function scanPageIOCs() {
    try {
      var text = (document.body ? document.body.innerText : '');
      if (text.length < 100 || text.length > 500000) return; // Skip trivial or huge pages
      var iocs = { ipv4: [], ipv6: [], domains: [], urls: [], hashes_md5: [], hashes_sha1: [], hashes_sha256: [], emails: [], cves: [], mitre: [], files: [], registryKeys: [], btc: [], eth: [] };
      var seen = new Set();
      function addUnique(arr, val) { val = val.trim(); if (val && !seen.has(val)) { seen.add(val); arr.push(val); } }

      // Refang defanged indicators first
      var refanged = text
        .replace(/\[(\.)]/g, '.').replace(/\[\.\]/g, '.')             // [.] → .
        .replace(/hxxp/gi, 'http')                                       // hxxp → http
        .replace(/\[:\]/g, ':').replace(/\[\/\//g, '://')               // [:] → :
        .replace(/\[at\]/gi, '@').replace(/\(at\)/gi, '@')             // [at] → @
        .replace(/\[dot\]/gi, '.').replace(/\(dot\)/gi, '.');          // [dot] → .

      // IPv4 addresses
      var ipv4Re = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
      (refanged.match(ipv4Re) || []).forEach(function(ip) {
        if (!/^(?:0\.0\.0\.0|127\.0\.0\.1|10\.\d|172\.(?:1[6-9]|2\d|3[01])|192\.168\.|255\.255)/.test(ip)) addUnique(iocs.ipv4, ip);
      });

      // IPv6 addresses (simplified)
      var ipv6Re = /\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:\b|\b::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}\b/gi;
      (refanged.match(ipv6Re) || []).forEach(function(ip) { if (ip !== '::' && ip !== '::1') addUnique(iocs.ipv6, ip); });

      // File hashes
      var sha256Re = /\b[0-9a-f]{64}\b/gi;
      (refanged.match(sha256Re) || []).forEach(function(h) { addUnique(iocs.hashes_sha256, h.toLowerCase()); });
      var sha1Re = /\b[0-9a-f]{40}\b/gi;
      (refanged.match(sha1Re) || []).forEach(function(h) { if (!iocs.hashes_sha256.some(function(s){return s.indexOf(h.toLowerCase())!==-1})) addUnique(iocs.hashes_sha1, h.toLowerCase()); });
      var md5Re = /\b[0-9a-f]{32}\b/gi;
      (refanged.match(md5Re) || []).forEach(function(h) { if (!iocs.hashes_sha1.some(function(s){return s.indexOf(h.toLowerCase())!==-1}) && !iocs.hashes_sha256.some(function(s){return s.indexOf(h.toLowerCase())!==-1})) addUnique(iocs.hashes_md5, h.toLowerCase()); });

      // CVE IDs
      var cveRe = /CVE-\d{4}-\d{4,}/gi;
      (refanged.match(cveRe) || []).forEach(function(c) { addUnique(iocs.cves, c.toUpperCase()); });

      // MITRE ATT&CK technique IDs
      var mitreRe = /\bT\d{4}(?:\.\d{3})?\b/g;
      (refanged.match(mitreRe) || []).forEach(function(t) { addUnique(iocs.mitre, t); });

      // Email addresses
      var emailRe = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;
      (refanged.match(emailRe) || []).forEach(function(e) { addUnique(iocs.emails, e.toLowerCase()); });

      // URLs
      var urlRe = /https?:\/\/[^\s"'<>\]\)}{,]+/gi;
      (refanged.match(urlRe) || []).forEach(function(u) { addUnique(iocs.urls, u.replace(/[.)]+$/, '')); });

      // Domains (after URLs, extract unique domains from text - alphanumeric.tld patterns)
      var domRe = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|biz|xyz|tk|ml|ga|cf|gq|top|cc|pw|ru|cn|de|uk|fr|br|in|jp|me|co|ly|us|ca|au|nl|ch|it|se|no|fi|be|at|es|pt|pl|cz|hu|ro|bg|hr|sk|si|lt|lv|ee|is|ie|dk|gov|edu|mil|int|eu|asia|pro|aero|museum|coop)\b/gi;
      (refanged.match(domRe) || []).forEach(function(d) {
        d = d.toLowerCase();
        if (d.length > 5 && !['example.com','google.com','w3.org','github.com','mozilla.org','microsoft.com','apple.com','schema.org','jquery.com','cloudflare.com','googleapis.com','gstatic.com','jquery.org'].includes(d))
          addUnique(iocs.domains, d);
      });

      // Suspicious file names/paths
      var fileRe = /\b[\w\-\.]+\.(?:exe|dll|sys|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|msi|scr|cpl|hta|pif|com|jar|war|apk|elf|bin|sh|py|rb|php|asp|aspx|jsp)\b/gi;
      (refanged.match(fileRe) || []).forEach(function(f) { addUnique(iocs.files, f); });

      // Registry keys
      var regRe = /\b(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"'<>]+/g;
      (text.match(regRe) || []).forEach(function(r) { addUnique(iocs.registryKeys, r); });

      // Bitcoin addresses (base58 P2PKH/P2SH, bech32)
      var btcRe = /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/g;
      (text.match(btcRe) || []).forEach(function(a) { addUnique(iocs.btc, a); });

      // Ethereum addresses
      var ethRe = /\b0x[0-9a-fA-F]{40}\b/g;
      (text.match(ethRe) || []).forEach(function(a) { addUnique(iocs.eth, a); });

      // Count total IOCs found
      var totalIOCs = 0;
      for (var cat in iocs) totalIOCs += iocs[cat].length;

      if (totalIOCs > 0) {
        safeSend({ action: 'page_iocs', payload: iocs, hostname: location.hostname, totalCount: totalIOCs });
      }
    } catch(e) {}
  }

  // ======= TRACKING PIXEL DECODER =======
  // Finds tiny/hidden images and beacons, decodes their URL params
  // to reveal exactly what data is being transmitted about the user
  function scanTrackingPixelData() {
    try {
      var pixels = [];
      var knownTrackers = {
        'facebook.com': 'Meta Pixel', 'facebook.net': 'Meta Pixel',
        'google-analytics.com': 'Google Analytics', 'analytics.google.com': 'Google Analytics',
        'googleads.g.doubleclick.net': 'Google Ads', 'doubleclick.net': 'DoubleClick',
        'googlesyndication.com': 'Google AdSense', 'googleadservices.com': 'Google Ads',
        'googletagmanager.com': 'Google Tag Manager',
        'bat.bing.com': 'Microsoft Ads', 'clarity.ms': 'Microsoft Clarity',
        'px.ads.linkedin.com': 'LinkedIn Insight', 'snap-analytics.appspot.com': 'LinkedIn',
        'analytics.twitter.com': 'X/Twitter Analytics', 'ads-api.twitter.com': 'X/Twitter Ads',
        't.co': 'X/Twitter', 'analytics.tiktok.com': 'TikTok Pixel',
        'ct.pinterest.com': 'Pinterest Tag', 'tr.snapchat.com': 'Snapchat Pixel',
        'pixel.wp.com': 'WordPress Stats', 'stats.wp.com': 'WordPress Stats',
        'mc.yandex.ru': 'Yandex Metrica', 'counter.yadro.ru': 'LiveInternet',
        'sb.scorecardresearch.com': 'Comscore', 'b.scorecardresearch.com': 'Comscore',
        'pixel.quantserve.com': 'Quantcast', 'secure.quantserve.com': 'Quantcast',
        'matomo': 'Matomo', 'piwik': 'Matomo',
        'hotjar.com': 'Hotjar', 'mouseflow.com': 'Mouseflow',
        'fullstory.com': 'FullStory', 'logrocket.com': 'LogRocket',
        'segment.io': 'Segment', 'segment.com': 'Segment',
        'mixpanel.com': 'Mixpanel', 'amplitude.com': 'Amplitude',
        'heapanalytics.com': 'Heap', 'cdn.heapanalytics.com': 'Heap',
        'plausible.io': 'Plausible', 'app.posthog.com': 'PostHog',
        'sentry.io': 'Sentry', 'hubspot.com': 'HubSpot',
        'pardot.com': 'Salesforce Pardot', 'pi.pardot.com': 'Salesforce Pardot',
        'munchkin.marketo.net': 'Marketo', 'adnxs.com': 'Xandr/AppNexus',
        'criteo.com': 'Criteo', 'criteo.net': 'Criteo',
        'taboola.com': 'Taboola', 'outbrain.com': 'Outbrain',
        'demdex.net': 'Adobe Audience Manager', 'omtrdc.net': 'Adobe Analytics',
        'nr-data.net': 'New Relic', 'newrelic.com': 'New Relic',
      };
      // Classify URL parameter names to data types
      var paramCategories = {
        user_id: /uid|userid|user_id|cid|clientid|client_id|visitorid|visitor_id|_ga|_gid|tid|uuid|mid|fpid/i,
        session: /sid|session|sess|ssid|token|nonce|auth/i,
        page: /url|page|path|location|href|landing|referr|referer|ref|origin|source|utm_source|utm_medium|utm_campaign/i,
        device: /ua|useragent|browser|os|platform|device|screen|resolution|viewport|dpr|lang|language|locale/i,
        timing: /time|ts|timestamp|date|_t|t=|dt=|ht=|plt|dns|tcp|ttfb|load|duration|latency/i,
        tracking: /track|event|action|category|label|value|hit|type|ec=|ea=|el=|ev=|en=|ep\./i,
        geo: /geo|country|region|city|zip|lat|lon|loc|tz|timezone/i,
        revenue: /revenue|price|value|currency|order|transaction|purchase|product|item|sku/i,
        consent: /consent|gdpr|ccpa|opt|privacy|dnt/i,
      };

      // Scan DOM for tiny/hidden images
      document.querySelectorAll('img').forEach(function(img) {
        var w = img.naturalWidth || img.width || parseInt(img.getAttribute('width')) || 999;
        var h = img.naturalHeight || img.height || parseInt(img.getAttribute('height')) || 999;
        var isHidden = img.style.display === 'none' || img.style.visibility === 'hidden' || img.style.opacity === '0';
        var isTiny = (w <= 3 && h <= 3);
        if ((isTiny || isHidden) && img.src && img.src.indexOf('http') === 0) {
          var pixel = decodePixelURL(img.src);
          if (pixel) pixels.push(pixel);
        }
      });

      // Also check for link[rel=preload/prefetch] pixel-like resources and script-generated Image()
      document.querySelectorAll('link[rel="prefetch"][as="image"],link[rel="preload"][as="image"]').forEach(function(link) {
        if (link.href) {
          var pixel = decodePixelURL(link.href);
          if (pixel) { pixel.method = 'prefetch'; pixels.push(pixel); }
        }
      });

      function decodePixelURL(src) {
        try {
          var u = new URL(src);
          if (u.hostname === location.hostname) return null; // skip same-origin
          var trackerName = null;
          for (var domain in knownTrackers) {
            if (u.hostname.indexOf(domain) !== -1) { trackerName = knownTrackers[domain]; break; }
          }
          var params = {};
          var dataTypes = new Set();
          u.searchParams.forEach(function(v, k) {
            params[k] = v.substring(0, 100);
            for (var cat in paramCategories) {
              if (paramCategories[cat].test(k) || paramCategories[cat].test(k + '=' + v.substring(0, 30))) {
                dataTypes.add(cat);
              }
            }
          });
          var paramCount = Object.keys(params).length;
          if (paramCount === 0 && !trackerName) return null;
          return {
            url: src.substring(0, 300),
            hostname: u.hostname,
            tracker: trackerName || 'Unknown',
            paramCount: paramCount,
            dataTypes: Array.from(dataTypes),
            params: params,
            method: 'img'
          };
        } catch(e) { return null; }
      }

      if (pixels.length > 0) {
        safeSend({ action: 'tracking_pixels', payload: pixels.slice(0, 50), hostname: location.hostname });
      }
    } catch(e) {}
  }
})();
