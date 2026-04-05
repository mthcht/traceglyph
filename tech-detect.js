// ============================================================================
// tech-detect.js - TraceGlyph by mthcht
// ============================================================================
//
// TECHNOLOGY DETECTION VIA WINDOW GLOBALS - Runs in the page's main world.
//
// PURPOSE:
//   Detects JavaScript libraries, frameworks, and services by checking
//   for their characteristic global variables on the window object.
//   This complements content.js's URL-based tech detection with runtime
//   evidence that the library is actually loaded and active.
//
// EXECUTION:
//   - Loaded by content.js as an external script via chrome.runtime.getURL().
//   - Runs in the page's main world (same context as injected.js).
//   - This approach is CSP-safe because the script is loaded from the
//     extension's own origin, not injected inline.
//   - Results are sent back to content.js via window.postMessage(__FPG_TECH__).
//
// DETECTION METHOD:
//   Each check uses a try/catch wrapper around a window property access.
//   If the global exists and is truthy, the technology is recorded with:
//     - name: display name (e.g. "React", "jQuery")
//     - cat: category (e.g. "JS Framework", "Analytics")
//     - icon: 2-char abbreviation for the dashboard badge
//     - ver: version string extracted from the library's VERSION property
//
// DETECTED TECHNOLOGIES (50+ globals checked):
//   JS Frameworks:  React, Angular, Vue, Svelte, Next.js, Nuxt, Ember,
//                   Backbone, Preact, Lit, Alpine.js, Stimulus
//   JS Libraries:   jQuery, Lodash, Moment.js, D3.js, Three.js, GSAP,
//                   Axios, RxJS, Anime.js
//   Analytics:      Google Analytics (ga/gtag), Matomo, Plausible, Amplitude,
//                   Mixpanel, Heap, PostHog, Segment, Hotjar
//   Tag Managers:   Google Tag Manager (dataLayer)
//   CMS:            WordPress, Drupal, Shopify, Wix, Squarespace, Webflow
//   A/B Testing:    Optimizely
//   Error Tracking: Sentry, Bugsnag, Rollbar, LogRocket, FullStory
//   CDN/Infra:      Cloudflare, Akamai
//   Payment:        Stripe
//   Chat:           Intercom, Drift, Crisp, Tawk.to, Zendesk
//   Ads:            Google AdSense, Google Publisher Tag
//   Maps:           Google Maps, Mapbox, Leaflet
//
// DEDUPLICATION:
//   The popup.js mergeTech() function deduplicates by name across all
//   three tech sources (content.js URL patterns, tech-detect.js globals,
//   and background.js header detection). Version info is preserved when
//   available from any source.
//
// ============================================================================
(function(){
  var t=[];
  function chk(test,name,cat,icon,ver){try{if(test())t.push({name:name,cat:cat,icon:icon,ver:ver||''})}catch(e){}}
  chk(function(){return window.React},'React','JS Framework','Re',function(){try{return window.React.version}catch(e){return ''}}());
  chk(function(){return window.Vue},'Vue.js','JS Framework','Vu',function(){try{return window.Vue.version}catch(e){return ''}}());
  chk(function(){return window.angular},'AngularJS','JS Framework','Ag',function(){try{return window.angular.version?window.angular.version.full:''}catch(e){return ''}}());
  chk(function(){return window.jQuery||window.$&&window.$.fn&&window.$.fn.jquery},'jQuery','JS Library','jQ',function(){try{return window.jQuery?window.jQuery.fn.jquery:window.$.fn.jquery}catch(e){return ''}}());
  chk(function(){return window.Shopify},'Shopify','Ecommerce','Sh','');
  chk(function(){return window.Stripe},'Stripe','Payment','St','');
  chk(function(){return window.gtag||window.dataLayer},'GTM/gtag','Tag Manager','GT','');
  chk(function(){return window.ga},'Google Analytics','Analytics','GA','UA');
  chk(function(){return window.fbq},'Meta Pixel','Advertising','FB','');
  chk(function(){return window.hj},'Hotjar','Session Replay','Hj','');
  chk(function(){return window.clarity},'MS Clarity','Session Replay','Cl','');
  chk(function(){return window.Sentry},'Sentry','Error Tracking','Se','');
  chk(function(){return window.Intercom},'Intercom','Chat','Ic','');
  chk(function(){return window.zE},'Zendesk','Chat','Zd','');
  chk(function(){return window.Tawk_API},'Tawk.to','Chat','Tw','');
  chk(function(){return window.$crisp},'Crisp','Chat','Cr','');
  chk(function(){return window.firebase||window.__FIREBASE_DEFAULTS__},'Firebase','Backend','Fb','');
  chk(function(){return window.gsap},'GSAP','JS Library','GS',function(){try{return window.gsap.version||''}catch(e){return ''}}());
  chk(function(){return window.THREE},'Three.js','JS Library','3j',function(){try{return window.THREE.REVISION?'r'+window.THREE.REVISION:''}catch(e){return ''}}());
  chk(function(){return window.wp},'WordPress','CMS','WP','');
  chk(function(){return window.Webflow},'Webflow','CMS','Wf','');
  chk(function(){return window.wixBiSession},'Wix','CMS','Wx','');
  chk(function(){return window.grecaptcha},'reCAPTCHA','Security','rC','');
  chk(function(){return window.hcaptcha},'hCaptcha','Security','hC','');
  chk(function(){return window.posthog},'PostHog','Analytics','PH','');
  chk(function(){return window.mixpanel},'Mixpanel','Analytics','Mx','');
  chk(function(){return window.amplitude},'Amplitude','Analytics','Am','');
  chk(function(){return window.optimizely},'Optimizely','A/B Testing','Op','');
  chk(function(){return window.Cookiebot},'Cookiebot','Cookie Consent','CB','');
  chk(function(){return window.OneTrust},'OneTrust','Cookie Consent','OT','');
  chk(function(){return window.newrelic},'New Relic','Monitoring','NR','');
  chk(function(){return window.DD_RUM},'Datadog RUM','Monitoring','DD','');
  chk(function(){return window.drift},'Drift','Chat','Dr','');
  chk(function(){return window._satellite},'Adobe Launch','Tag Manager','AL','');
  chk(function(){return window.HubSpotConversations},'HubSpot Chat','Chat','HC','');
  chk(function(){return window.rudderanalytics},'RudderStack','Analytics','RS','');
  chk(function(){return window.LogRocket},'LogRocket','Session Replay','LR','');
  chk(function(){return window.FullStory},'FullStory','Session Replay','FS','');
  chk(function(){return window.Preact},'Preact','JS Framework','Pr',function(){try{return window.Preact.version||''}catch(e){return ''}}());
  chk(function(){return window.Svelte},'Svelte','JS Framework','Sv','');
  chk(function(){return window.Backbone},'Backbone.js','JS Framework','Bb',function(){try{return window.Backbone.VERSION||''}catch(e){return ''}}());
  chk(function(){return window.Ember},'Ember.js','JS Framework','Em',function(){try{return window.Ember.VERSION||''}catch(e){return ''}}());
  chk(function(){return window.io},'Socket.IO','JS Library','IO','');
  chk(function(){return window.Chart},'Chart.js','JS Library','Cj',function(){try{return window.Chart.version||''}catch(e){return ''}}());
  chk(function(){return window.d3},'D3.js','JS Library','D3',function(){try{return window.d3.version||''}catch(e){return ''}}());
  chk(function(){return window._},'Lodash','JS Library','Lo',function(){try{return window._.VERSION||''}catch(e){return ''}}());
  chk(function(){return window.paypal},'PayPal','Payment','PP','');
  window.postMessage({type:'__FPG_TECH__',payload:t},'*');

  // Enumerate ALL non-standard JS globals (urlscan.io data.globals equivalent)
  try {
    var stdProps = new Set(['undefined','Infinity','NaN','eval','isFinite','isNaN','parseFloat','parseInt','decodeURI','decodeURIComponent','encodeURI','encodeURIComponent','Array','ArrayBuffer','Atomics','BigInt','BigInt64Array','BigUint64Array','Boolean','DataView','Date','Error','EvalError','FinalizationRegistry','Float32Array','Float64Array','Function','Generator','GeneratorFunction','Int8Array','Int16Array','Int32Array','JSON','Map','Math','Number','Object','Promise','Proxy','RangeError','ReferenceError','Reflect','RegExp','Set','SharedArrayBuffer','String','Symbol','SyntaxError','TypeError','URIError','Uint8Array','Uint8ClampedArray','Uint16Array','Uint32Array','WeakMap','WeakRef','WeakSet','globalThis','console','window','self','document','location','navigator','history','screen','alert','confirm','prompt','fetch','XMLHttpRequest','setTimeout','setInterval','clearTimeout','clearInterval','requestAnimationFrame','cancelAnimationFrame','queueMicrotask','atob','btoa','performance','crypto','caches','indexedDB','localStorage','sessionStorage','postMessage','addEventListener','removeEventListener','dispatchEvent','close','closed','focus','blur','open','stop','print','getComputedStyle','matchMedia','scrollTo','scrollBy','scroll','moveTo','moveBy','resizeTo','resizeBy','getSelection','find','frames','parent','top','length','name','status','customElements','visualViewport','origin','isSecureContext','crossOriginIsolated','scheduler','structuredClone','reportError','requestIdleCallback','cancelIdleCallback','createImageBitmap','speechSynthesis','onbeforeunload','onhashchange','onlanguagechange','onmessage','onmessageerror','onoffline','ononline','onpagehide','onpageshow','onpopstate','onrejectionhandled','onstorage','onunhandledrejection','onunload','chrome','webkitRequestAnimationFrame','webkitCancelAnimationFrame','getScreenDetails','queryLocalFonts','showDirectoryPicker','showOpenFilePicker','showSaveFilePicker','originAgentCluster','navigation','documentPictureInPicture','launchQueue','oncontentvisibilityautostatechange','onscrollend','onpageswap','onpagereveal','onbeforetoggle','Iterator','DocumentPictureInPicture','onscrollsnapchange','onscrollsnapchanging','onmovesstart','oncommand','getDigitalGoodsService','fetchLater','model','windowControlsOverlay','fence','HTMLDialogElement','HTMLElement','Event','EventTarget','Node','Element','HTMLDocument','HTMLCanvasElement','CanvasRenderingContext2D','WebGLRenderingContext','WebGL2RenderingContext','AudioContext','webkitAudioContext','OfflineAudioContext']);
    var globals = [];
    var keys = Object.getOwnPropertyNames(window);
    for (var i = 0; i < keys.length && globals.length < 300; i++) {
      var k = keys[i];
      if (!stdProps.has(k) && k.indexOf('__') !== 0 && k.indexOf('on') !== 0 && k.indexOf('webkit') !== 0) {
        try {
          var val = window[k];
          var type = typeof val;
          if (type === 'function') type = 'function()';
          else if (type === 'object' && val !== null) type = Array.isArray(val) ? 'array[' + val.length + ']' : 'object';
          globals.push({ name: k, type: type });
        } catch(e) {
          globals.push({ name: k, type: 'error' });
        }
      }
    }
    window.postMessage({type:'__FPG_GLOBALS__',payload:globals},'*');
  } catch(e) {}
})();
