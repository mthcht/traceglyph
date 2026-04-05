// ============================================================================
// background.js - TraceGlyph by mthcht
// ============================================================================
//
// SERVICE WORKER - Runs persistently in the background (Manifest V3).
// This is the central data hub for the extension. It collects, stores,
// scores, and serves all analysis data for each browser tab.
//
// RESPONSIBILITIES:
//   1. TAB DATA MANAGEMENT
//      - Maintains a per-tab data store (tabData{}) holding all detections,
//        network requests, cookies, domains, IOCs, and metadata.
//      - Resets tab data on new top-level navigations via webNavigation.onBeforeNavigate.
//      - Cleans up on tab close via tabs.onRemoved.
//
//   2. THREAT SCORING (v2, category-capped)
//      - Calculates a 0-100 threat score from 9 weighted categories:
//        fingerprinting (max 35), tracking (20), behavior (20), phishing (15),
//        security (12), infrastructure (10), forms (10), anomalies (8), cookies (3).
//      - Each category has its own cap to prevent single-vector inflation.
//      - Scoring uses severity weighting: only critical/high findings contribute
//        meaningfully; medium/low add smaller increments.
//      - Trusted iframe allowlist prevents auth providers (Google, Microsoft,
//        Facebook, reCAPTCHA, Cloudflare) from inflating the forms score.
//
//   3. NETWORK MONITORING (webRequest API)
//      - onBeforeRequest: logs every network request (URL, method, type, timestamp).
//      - onCompleted: captures server IP, status code, resolves domain-to-IP mapping.
//      - onHeadersReceived: extracts security headers (CSP, HSTS, X-Frame-Options,
//        Referrer-Policy, Permissions-Policy, COOP, COEP, etc.), detects HTTP
//        protocol version from Alt-Svc, identifies server/tech disclosure.
//      - onBeforeRedirect: tracks redirect chains with status codes and IPs.
//
//   4. NETWORK ANOMALY DETECTION
//      - Flags unusual ports, POST to raw IPs, suspicious file extensions (.exe,
//        .dll, .ps1, etc.), cross-origin long query strings, and base64-encoded
//        URL parameters (with trusted auth domain exclusions).
//
//   5. DOMAIN CLASSIFICATION
//      - Classifies domains by TLD risk (suspicious TLDs: .tk, .ml, .xyz, etc.),
//        known malware domains, raw IP hosting, deep subdomains, punycode IDN,
//        and DGA-suspect patterns.
//
//   6. MESSAGE HANDLING
//      - Receives messages from content.js (detections, cookies, tech stack, forms,
//        iframes, IOCs, tracking pixels, console messages, page timing, etc.).
//      - Serves data to popup.js on request (get_data, export_data).
//
//   7. BADGE MANAGEMENT
//      - Updates the extension badge with detection count and threat-level color
//        (green < 20, yellow < 45, orange < 70, red >= 70).
//
// DATA FLOW:
//   content.js/injected.js --> background.js (store) --> popup.js (display)
//   webRequest listeners ----^                          ^--- chrome.runtime.sendMessage
//
// PERMISSIONS USED:
//   webRequest, webNavigation, tabs, scripting, cookies, storage, activeTab
//
// ============================================================================
const tabData={};
chrome.runtime.onInstalled.addListener(function(d){if(d.reason==='install')chrome.tabs.create({url:chrome.runtime.getURL('welcome.html')})});

function ensureTab(id){if(!tabData[id])tabData[id]={detections:[],cookies:null,thirdPartyScripts:[],trackingPixels:[],hostname:'',url:'',threatScore:0,scoreBreakdown:{},networkRequests:[],redirectChains:[],securityHeaders:null,securityMeta:null,forms:[],resourceHints:[],iframes:[],externalStylesheets:[],storageContents:null,serviceWorkers:[],timeline:[],domains:{},domainIPs:{},connectionInfo:{},techStack:[],headerTech:[],urlTech:[],scriptHashes:[],networkAnomalies:[],consoleMsgs:[],pageLinks:[],pageTiming:null,jsGlobals:[],pageIOCs:null,trackingPixelData:[],pageLoadTime:Date.now()};return tabData[id]}
function tl(d,c,t,s){d.timeline.push({ts:Date.now(),category:c,detail:t,severity:s})}

// ── SCORING v2 ───────────────────────────────────────────
function calcThreatScore(data){
  var bd={};var seen=new Set();var uq=[];
  for(var i=0;i<data.detections.length;i++){var d=data.detections[i];var k=d.category+'::'+d.detail;if(!seen.has(k)){seen.add(k);uq.push(d)}}
  var cats={};uq.forEach(function(d){(cats[d.category]=cats[d.category]||[]).push(d)});

  var fp=0,fpt=[];
  if((cats['Canvas Fingerprint']||[]).length){fp+=8;fpt.push('c')}
  if((cats['WebGL Fingerprint']||[]).some(function(d){return d.severity==='critical'})){fp+=8;fpt.push('w')}else if((cats['WebGL Fingerprint']||[]).length){fp+=4;fpt.push('w')}
  if((cats['Audio Fingerprint']||[]).length){fp+=6;fpt.push('a')}
  if((cats['Font Enumeration']||[]).length){fp+=5;fpt.push('f')}
  if((cats['WebRTC Leak']||[]).length){fp+=8;fpt.push('r')}
  if((cats['Battery API']||[]).length){fp+=3;fpt.push('b')}
  if(fpt.length>=3)fp+=5;
  bd.fingerprinting=Math.min(fp,35);

  var tr=0;var trackers=(data.thirdPartyScripts||[]).filter(function(s){return s.isTracker});
  tr+=Math.min(trackers.length*1.5,12);tr+=Math.min((data.trackingPixels||[]).length,5);tr+=Math.min((data.trackingPixelData||[]).length,5);
  if(trackers.some(function(s){return /session.?replay/i.test(s.trackerName||'')}))tr+=5;
  bd.tracking=Math.min(Math.round(tr),20);

  var bh=0;
  if((cats['Dynamic Code Exec']||[]).length)bh+=6;
  var exfilHigh=(cats['Data Exfiltration']||[]).filter(function(d){return d.severity==='high'||d.severity==='critical'});
  var exfilDests=new Set();exfilHigh.forEach(function(d){if(d.meta&&d.meta.url)exfilDests.add(d.meta.url)});
  bh+=Math.min(exfilDests.size*4,12);
  if((cats['WebSocket']||[]).length)bh+=2;
  if((cats['Crypto/Mining']||[]).length)bh+=8;
  if((cats['Clipboard Access']||[]).some(function(d){return d.detail.indexOf('read')!==-1}))bh+=6;
  bd.behavior=Math.min(bh,20);

  var sh=0;
  if(data.securityHeaders){var h=data.securityHeaders;
    ['Content-Security-Policy','Strict-Transport-Security (HSTS)','X-Content-Type-Options'].forEach(function(c){if(h[c]&&h[c].status==='missing')sh+=2});
    var otherMissing=0;Object.values(h).forEach(function(v){if(v.status==='missing')otherMissing++});
    sh+=Math.min(otherMissing*0.5,4);
    var weakCt=0;Object.values(h).forEach(function(v){if(v.status==='weak')weakCt++});
    sh+=Math.min(weakCt,3);
  }
  bd.security=Math.min(Math.round(sh),12);

  var inf=0;var df=Object.values(data.domains||{});
  if(df.some(function(d){return d.flags&&d.flags.indexOf('known_malware')!==-1}))inf=10;
  else{
    inf+=Math.min(df.filter(function(d){return d.flags&&d.flags.indexOf('suspicious_tld')!==-1}).length*3,6);
    inf+=Math.min(df.filter(function(d){return d.flags&&d.flags.indexOf('dga_suspect')!==-1}).length*4,8);
    if((data.redirectChains||[]).filter(function(r){return r.type==='redirect'}).length>3)inf+=3;
  }
  bd.infrastructure=Math.min(inf,10);

  // Network anomalies
  var na=(data.networkAnomalies||[]).length;
  bd.anomalies=Math.min(na*2,8);

  var fm=0;
  fm+=Math.min((data.forms||[]).filter(function(f){return f.risk==='critical'}).length*8,10);
  // Hidden cross-origin iframes - exclude trusted auth providers
  var trustedIframeDomains=['accounts.google.com','login.microsoftonline.com','edge-auth.microsoft.com','appleid.apple.com','facebook.com','platform.linkedin.com','auth0.com','login.live.com','connect.facebook.net','www.gstatic.com','recaptcha.net','challenges.cloudflare.com'];
  var susIframes=(data.iframes||[]).filter(function(f){return f.isHidden&&f.crossOrigin&&!trustedIframeDomains.some(function(d){return (f.src||'').indexOf(d)!==-1})});
  fm+=Math.min(susIframes.length*5,10);
  bd.forms=Math.min(fm,10);

  bd.cookies=Math.min(Math.round((data.cookies&&data.cookies.cookies||[]).filter(function(c){return c.isTracking}).length*0.5),3);
  // Phishing/obfuscation detection - severity-weighted
  var phish=0;
  var phishCats=(cats['Phishing Indicator']||[]);
  phishCats.forEach(function(p){
    if(p.severity==='critical')phish+=5;
    else if(p.severity==='high')phish+=3;
    else if(p.severity==='medium')phish+=1;
  });
  // JS obfuscation only contributes if CRITICAL severity AND script is small (real phishing kit)
  var obfCats=(cats['JS Obfuscation']||[]);
  var obfCrit=obfCats.filter(function(d){return d.severity==='critical'});
  if(obfCrit.length)phish+=Math.min(obfCrit.length*3,8);
  // Suspicious URL
  var susCats=(cats['Suspicious URL']||[]);
  if(susCats.some(function(d){return d.severity==='critical'}))phish+=8;
  else if(susCats.filter(function(d){return d.severity==='high'}).length>=2)phish+=4;
  bd.phishing=Math.min(phish,15);
  data.scoreBreakdown=bd;
  return Math.min(Object.values(bd).reduce(function(a,b){return a+b},0),100);
}

function updateBadge(tabId){try{var d=tabData[tabId];if(!d)return;var s=d.threatScore;var u=new Set(d.detections.map(function(d){return d.category+':'+d.detail})).size;var c='#4ade80';if(s>20)c='#facc15';if(s>45)c='#f97316';if(s>70)c='#ef4444';chrome.action.setBadgeText({text:u>0?String(u):'',tabId:tabId}).catch(function(){});chrome.action.setBadgeBackgroundColor({color:c,tabId:tabId}).catch(function(){})}catch(e){}}

// ── DOMAIN CLASSIFICATION ────────────────────────────────
var susTLDs=['.tk','.ml','.ga','.cf','.gq','.top','.xyz','.buzz','.club','.work','.click','.loan','.racing','.win','.bid'];
var malDom=['coinhive.com','coin-hive.com','crypto-loot.com','jsecoin.com','webminepool.com','minero.cc'];
function classifyDomain(h){var f=[];if(susTLDs.some(function(t){return h.endsWith(t)}))f.push('suspicious_tld');if(malDom.some(function(d){return h.indexOf(d)!==-1}))f.push('known_malware');if(/^[0-9.]+$/.test(h))f.push('raw_ip');if(h.length>40)f.push('long_domain');if((h.match(/\./g)||[]).length>4)f.push('deep_subdomain');if(/xn--/.test(h))f.push('punycode_idn');if(/^[a-z0-9]{16,}\./i.test(h))f.push('dga_suspect');return f}

// ── NETWORK ANOMALY DETECTION ────────────────────────────
function checkNetworkAnomaly(data, details) {
  try {
    var url = new URL(details.url);
    var anomalies = [];
    // Unusual ports
    if (url.port && url.port !== '80' && url.port !== '443' && url.port !== '') {
      anomalies.push({ type: 'unusual_port', detail: 'Request to port ' + url.port + ': ' + url.hostname, severity: 'high', url: details.url });
    }
    // POST to raw IP
    if (details.method === 'POST' && /^[0-9.]+$/.test(url.hostname)) {
      anomalies.push({ type: 'post_to_ip', detail: 'POST to raw IP: ' + url.hostname, severity: 'high', url: details.url });
    }
    // Suspicious file extensions in URL
    var susExt = /\.(exe|dll|ps1|bat|cmd|vbs|scr|msi|hta|wsf|jar|py|sh)\b/i;
    if (susExt.test(url.pathname)) {
      anomalies.push({ type: 'suspicious_extension', detail: 'Suspicious file type in URL: ' + url.pathname.match(susExt)[0], severity: 'critical', url: details.url });
    }
    // Very long query strings - only flag cross-origin (GraphQL APIs use long params)
    if (url.search.length > 2000 && url.hostname !== data.hostname) {
      anomalies.push({ type: 'long_query', detail: 'Very long query string (' + url.search.length + ' chars) to ' + url.hostname, severity: 'medium', url: details.url });
    }
    // Base64 in URL params - only flag if not from trusted auth domains
    var trustedParamDomains = ['accounts.google.com','login.microsoftonline.com','appleid.apple.com','login.live.com','auth0.com','okta.com','signin.aws.amazon.com'];
    var isTrustedParamDomain = trustedParamDomains.some(function(d) { return url.hostname.indexOf(d) !== -1; });
    if (!isTrustedParamDomain && /[?&][^=]+=(?:[A-Za-z0-9+/]{80,}={0,2})/.test(url.search)) {
      anomalies.push({ type: 'base64_param', detail: 'Possible base64-encoded URL parameter', severity: 'low', url: details.url });
    }
    for (var i = 0; i < anomalies.length; i++) {
      data.networkAnomalies.push(anomalies[i]);
      tl(data, 'Network Anomaly', anomalies[i].detail, anomalies[i].severity);
    }
  } catch(e) {}
}

// ── URL-BASED TECH DETECTION ─────────────────────────────
function detectTechFromURL(url){var t=[];var u=url.toLowerCase();var m=function(p,n,c,i){if(p.test(u))t.push({name:n,cat:c,icon:i,ver:''})};m(/react[\.-]/,'React','JS Framework','Re');m(/vue[\.-]/,'Vue.js','JS Framework','Vu');m(/angular/,'Angular','JS Framework','Ag');m(/next[\.-]|_next\//,'Next.js','JS Framework','Nx');m(/jquery/,'jQuery','JS Library','jQ');m(/bootstrap/,'Bootstrap','CSS Framework','Bs');m(/tailwind/,'Tailwind CSS','CSS Framework','Tw');m(/gsap|tweenmax/,'GSAP','JS Library','GS');m(/three[\.-]/,'Three.js','JS Library','3j');m(/stripe/,'Stripe','Payment','St');m(/googletagmanager/,'GTM','Tag Manager','GT');m(/google-analytics|gtag\/js/,'Google Analytics','Analytics','GA');m(/segment\.com/,'Segment','Tag Manager','Sg');m(/mixpanel/,'Mixpanel','Analytics','Mx');m(/amplitude/,'Amplitude','Analytics','Am');m(/hotjar|static\.hotjar/,'Hotjar','Session Replay','Hj');m(/clarity\.ms/,'MS Clarity','Session Replay','Cl');m(/fullstory/,'FullStory','Session Replay','FS');m(/sentry/,'Sentry','Error Tracking','Se');m(/newrelic|nr-data/,'New Relic','Monitoring','NR');m(/intercom/,'Intercom','Chat','Ic');m(/zendesk/,'Zendesk','Chat','Zd');m(/hubspot|hs-scripts/,'HubSpot','Marketing','HS');m(/connect\.facebook\.net/,'Meta Pixel','Advertising','FB');m(/googlesyndication/,'Google AdSense','Advertising','AS');m(/criteo/,'Criteo','Advertising','Cr');m(/recaptcha/,'reCAPTCHA','Security','rC');m(/cookiebot/,'Cookiebot','Cookie Consent','CB');m(/onetrust/,'OneTrust','Cookie Consent','OT');m(/wp-content|wp-includes/,'WordPress','CMS','WP');m(/shopify/,'Shopify','Ecommerce','Sh');m(/fontawesome/,'Font Awesome','Fonts','FA');m(/fonts\.googleapis/,'Google Fonts','Fonts','GF');return t}

// ── HEADER TECH ──────────────────────────────────────────
function detectHeaderTech(headers){var t=[];var h=function(n){return headers[n.toLowerCase()]||''};var sv=h('server');var xp=h('x-powered-by');if(/nginx/i.test(sv))t.push({name:'Nginx',cat:'Web Server',icon:'Ng',ver:((sv.match(/nginx\/([\d.]+)/i)||[])[1])||''});if(/apache/i.test(sv))t.push({name:'Apache',cat:'Web Server',icon:'Ap',ver:((sv.match(/Apache\/([\d.]+)/i)||[])[1])||''});if(/microsoft-iis/i.test(sv))t.push({name:'IIS',cat:'Web Server',icon:'II',ver:''});if(/cloudflare/i.test(sv))t.push({name:'Cloudflare',cat:'CDN',icon:'CF',ver:''});if(/gunicorn/i.test(sv))t.push({name:'Gunicorn',cat:'Web Server',icon:'Gu',ver:''});if(/php/i.test(xp))t.push({name:'PHP',cat:'Language',icon:'PH',ver:((xp.match(/PHP\/([\d.]+)/i)||[])[1])||''});if(/asp\.net/i.test(xp))t.push({name:'ASP.NET',cat:'Language',icon:'AS',ver:''});if(/express/i.test(xp))t.push({name:'Express.js',cat:'Framework',icon:'Ex',ver:''});if(h('cf-ray'))t.push({name:'Cloudflare',cat:'CDN',icon:'CF',ver:''});if(h('x-vercel-id'))t.push({name:'Vercel',cat:'Hosting',icon:'Vc',ver:''});if(h('x-nf-request-id'))t.push({name:'Netlify',cat:'Hosting',icon:'Nf',ver:''});if(h('x-amz-cf-id'))t.push({name:'AWS CloudFront',cat:'CDN',icon:'AW',ver:''});if(h('x-github-request-id'))t.push({name:'GitHub Pages',cat:'Hosting',icon:'GH',ver:''});if(h('x-shopify-stage'))t.push({name:'Shopify',cat:'Ecommerce',icon:'Sh',ver:''});if(h('x-heroku-request-id'))t.push({name:'Heroku',cat:'Hosting',icon:'He',ver:''});var names=new Set();return t.filter(function(x){if(names.has(x.name))return false;names.add(x.name);return true})}

// ── NETWORK MONITORING (skip extension URLs) ─────────────
chrome.webRequest.onBeforeRequest.addListener(function(d){
  if(d.tabId<0)return;
  // SELF-FILTER: skip our own extension resources
  if(d.url.indexOf('chrome-extension://')===0||d.url.indexOf('moz-extension://')===0)return;
  var data=ensureTab(d.tabId);var hn='';try{hn=new URL(d.url).hostname}catch(e){return}
  if(data.networkRequests.length<500)data.networkRequests.push({requestId:d.requestId,url:d.url,hostname:hn,method:d.method,type:d.type,timestamp:d.timeStamp,ip:null,statusCode:null});
  if(!data.domains[hn])data.domains[hn]={count:0,types:new Set(),flags:classifyDomain(hn),firstSeen:d.timeStamp,ips:new Set()};
  data.domains[hn].count++;data.domains[hn].types.add(d.type);
  if(d.type==='script'){var ut=detectTechFromURL(d.url);ut.forEach(function(t){if(!data.urlTech.some(function(x){return x.name===t.name}))data.urlTech.push(t)})}
  // Network anomaly check
  checkNetworkAnomaly(data, d);
},{urls:['<all_urls>']},['requestBody']);

chrome.webRequest.onResponseStarted.addListener(function(d){
  if(d.tabId<0)return;if(d.url.indexOf('chrome-extension://')===0)return;
  var data=tabData[d.tabId];if(!data)return;var hn='';try{hn=new URL(d.url).hostname}catch(e){return}
  var ip=d.ip||null;
  for(var i=data.networkRequests.length-1;i>=0;i--){if(data.networkRequests[i].requestId===d.requestId){data.networkRequests[i].ip=ip;data.networkRequests[i].statusCode=d.statusCode;break}}
  if(ip){if(data.domains[hn])data.domains[hn].ips.add(ip);if(!data.domainIPs[hn])data.domainIPs[hn]=[];if(data.domainIPs[hn].indexOf(ip)===-1)data.domainIPs[hn].push(ip)}
  if(d.type==='main_frame'){data.connectionInfo={ip:ip,statusCode:d.statusCode,protocol:null,timestamp:d.timeStamp};if(ip)tl(data,'Network','IP: '+ip+' (HTTP '+d.statusCode+')','info')}
},{urls:['<all_urls>']},['responseHeaders']);

chrome.webRequest.onHeadersReceived.addListener(function(d){
  if(d.tabId<0)return;if(d.url.indexOf('chrome-extension://')===0)return;
  var data=ensureTab(d.tabId);var headers={};(d.responseHeaders||[]).forEach(function(h){headers[h.name.toLowerCase()]=h.value});
  if(d.type==='main_frame'){
    data.headerTech=detectHeaderTech(headers);
    if(headers['alt-svc']){if(/h3/.test(headers['alt-svc']))data.connectionInfo.protocol='HTTP/3';else if(/h2/.test(headers['alt-svc']))data.connectionInfo.protocol='HTTP/2'}
    var sec={};
    [['content-security-policy','Content-Security-Policy'],['strict-transport-security','Strict-Transport-Security (HSTS)'],['x-content-type-options','X-Content-Type-Options'],['x-frame-options','X-Frame-Options'],['referrer-policy','Referrer-Policy'],['permissions-policy','Permissions-Policy'],['cross-origin-opener-policy','COOP'],['cross-origin-embedder-policy','COEP'],['nel','NEL'],['report-to','Report-To']].forEach(function(pair){
      var k=pair[0],l=pair[1],v=headers[k];sec[l]={value:v||'',status:v?'present':'missing'};
      if(k==='strict-transport-security'&&v){var ma=parseInt(((v.match(/max-age=(\d+)/)||[])[1])||'0');sec[l].note='max-age='+ma+(v.indexOf('includeSubDomains')!==-1?' +subdomains':'')+(v.indexOf('preload')!==-1?' +preload':'')}
      if(k==='referrer-policy'&&v==='unsafe-url'){sec[l].status='weak';sec[l].note='Leaks full URL'}
    });
    if(headers['server'])sec['Server']={value:headers['server'],status:'info',note:'Version disclosure'};
    if(headers['x-powered-by'])sec['X-Powered-By']={value:headers['x-powered-by'],status:'weak',note:'Tech disclosure'};
    if(headers['set-cookie']){var sc=headers['set-cookie'];var f=[];if(!/secure/i.test(sc))f.push('No Secure');if(!/httponly/i.test(sc))f.push('No HttpOnly');if(!/samesite/i.test(sc))f.push('No SameSite');if(f.length)sec['Set-Cookie Flags']={value:f.join(', '),status:'weak',note:'Missing flags'}}
    if(headers['cf-ray'])sec['CF-Ray']={value:headers['cf-ray'],status:'info',note:'Cloudflare'};
    data.securityHeaders=sec;data.threatScore=calcThreatScore(data);updateBadge(d.tabId);
  }
},{urls:['<all_urls>']},['responseHeaders']);

// Redirects
// Redirects (onBeforeNavigate handled by reset listener above)
chrome.webRequest.onBeforeRedirect.addListener(function(d){if(d.tabId<0)return;if(d.url.indexOf('chrome-extension://')===0)return;var data=ensureTab(d.tabId);data.redirectChains.push({from:d.url,to:d.redirectUrl,statusCode:d.statusCode,timestamp:d.timeStamp,ip:d.ip||null,type:'redirect'});tl(data,'Redirect',d.statusCode+' '+d.url+' -> '+d.redirectUrl,'medium')},{urls:['<all_urls>']},['responseHeaders']);

// Messages
chrome.runtime.onMessage.addListener(function(msg,sender,sendResponse){
  if(msg.action==='get_data'||msg.action==='export_data'){var raw=tabData[msg.tabId];if(!raw){sendResponse(null);return false}sendResponse(JSON.parse(JSON.stringify(raw,function(k,v){return v instanceof Set?Array.from(v):v})));return false}
  if(!sender.tab)return false;var tabId=sender.tab.id;var data=ensureTab(tabId);
  switch(msg.action){
    case 'detection':data.detections.push(msg.payload);data.hostname=msg.hostname||data.hostname;data.url=msg.url||data.url;tl(data,msg.payload.category,msg.payload.detail,msg.payload.severity);break;
    case 'cookies_detected':data.cookies=msg.payload;data.hostname=msg.hostname||data.hostname;break;
    case 'third_party_scripts':data.thirdPartyScripts=msg.payload;data.hostname=msg.hostname||data.hostname;break;
    case 'tracking_pixels':data.trackingPixels=msg.payload;break;
    case 'security_meta':data.securityMeta=msg.payload;break;
    case 'forms_detected':data.forms=msg.payload;break;
    case 'resource_hints':data.resourceHints=msg.payload;break;
    case 'iframes_detected':data.iframes=msg.payload;break;
    case 'external_stylesheets':data.externalStylesheets=msg.payload;break;
    case 'storage_contents':data.storageContents=msg.payload;break;
    case 'service_workers':data.serviceWorkers=msg.payload;break;
    case 'tech_stack':data.techStack=msg.payload;break;
    case 'script_hashes':data.scriptHashes=msg.payload;break;
    case 'console_messages':data.consoleMsgs=(data.consoleMsgs||[]).concat(msg.payload).slice(-200);break;
    case 'page_links':data.pageLinks=msg.payload;break;
    case 'page_timing':data.pageTiming=msg.payload;break;
    case 'js_globals':data.jsGlobals=msg.payload;break;
    case 'page_iocs':data.pageIOCs=msg.payload;break;
    case 'tracking_pixels':data.trackingPixelData=(data.trackingPixelData||[]).concat(msg.payload).slice(0,50);break;
    default:return false;
  }
  data.threatScore=calcThreatScore(data);updateBadge(tabId);return false;
});
// Reset tab data on new navigation, BEFORE network listeners fire
chrome.webNavigation.onBeforeNavigate.addListener(function(d){
  if(d.tabId<0||d.frameId!==0)return;
  // Full reset for new top-level navigation
  delete tabData[d.tabId];
  var data=ensureTab(d.tabId);
  data.url=d.url;
  try{data.hostname=new URL(d.url).hostname}catch(e){}
  chrome.action.setBadgeText({text:'',tabId:d.tabId}).catch(function(){});
});
chrome.tabs.onRemoved.addListener(function(id){delete tabData[id]});
