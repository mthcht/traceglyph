// ============================================================================
// popup/popup.js - TraceGlyph by mthcht
// ============================================================================
//
// DASHBOARD LOGIC - Controls the popup UI that appears when clicking the
// extension icon in the browser toolbar.
//
// RESPONSIBILITIES:
//
//   1. THEME MANAGEMENT
//      - Light theme (default) / dark theme toggle.
//      - Persisted via chrome.storage.local key "tg_theme".
//      - Applied via data-theme="dark" attribute on <body>.
//
//   2. GHOST / SPOOF MODE CONTROL
//      - Ghost mode (block): returns generic values for all fingerprint APIs.
//      - Spoof mode (randomize): returns fake values from curated pools.
//      - Scope: per-site (current hostname) or global (all sites).
//      - Persisted via chrome.storage.local keys "tg_mode_global" and
//        "tg_mode_sites" (object mapping hostname -> mode).
//      - Mode pushed to content script via chrome.scripting.executeScript()
//        which sets the data-tg-mode attribute on document.documentElement.
//
//   3. DATA RETRIEVAL
//      - Requests tab data from background.js via chrome.runtime.sendMessage
//        with action "get_data" and the active tab's ID.
//      - Receives the full tabData object (detections, scores, network, etc.).
//      - Re-polls every 2 seconds to show live updates.
//
//   4. RENDERING ENGINE
//      - render(data): main entry point, deduplicates detections, calculates
//        category counts, renders all 8 dashboard tabs.
//      - renderOverview(): score breakdown bars, page timing, resource stats,
//        technology list, network anomalies, redirect chains, top findings.
//      - renderNetwork(): domain list with IP mapping and flags, tracking pixel
//        decoder output, redirect chains, page links, raw request log.
//      - renderStorage(): cookies, localStorage, sessionStorage contents.
//      - renderSecurity(): security header audit (CSP, HSTS, etc.), forms.
//      - renderIOC(): network IOCs (domains, IPs, hashes) + extracted page
//        IOCs (IPv4, SHA-256, CVEs, MITRE IDs, emails, files, crypto wallets).
//      - renderTimeline(): chronological event log.
//
//   5. COPY REPORT
//      - Generates a structured plaintext incident report containing:
//        score breakdown, technologies, critical/high detections with MITRE
//        ATT&CK mappings, trackers, tracking pixels decoded, domain-to-IP
//        mapping, network anomalies, and extracted page IOCs.
//      - Copied to clipboard via navigator.clipboard.writeText().
//
//   6. JSON EXPORT
//      - Exports the complete raw tabData object as JSON.
//      - Filename: traceglyph-{hostname}-{timestamp}.json
//      - Downloaded via Blob URL and programmatic <a> click.
//
//   7. TECHNOLOGY MERGE
//      - mergeTech(stack, headers, urls): deduplicates technologies from
//        3 sources by name, preserving version info when available.
//
//   8. MITRE ATT&CK MAPPING
//      - Maps 26 detection categories to ATT&CK technique IDs.
//      - Displayed in detection cards and included in Copy Report.
//
// UI STRUCTURE (8 tabs):
//   Overview | Fingerprints | Network | Behavior | Storage | Security | IOC | Timeline
//
// ============================================================================

// ─── THEME TOGGLE ───────────────────────────────────
(function initTheme() {
  try {
    chrome.storage.local.get('tg_theme', function(r) {
      if (r && r.tg_theme === 'dark') {
        document.body.setAttribute('data-theme', 'dark');
        var btn = document.getElementById('btnTheme');
        if (btn) btn.textContent = '\u2600\ufe0f';
      }
    });
  } catch(e) {}
})();
document.addEventListener('DOMContentLoaded', function() {
  var btn = document.getElementById('btnTheme');
  if (btn) btn.addEventListener('click', function() {
    var isDark = document.body.getAttribute('data-theme') === 'dark';
    if (isDark) {
      document.body.removeAttribute('data-theme');
      btn.textContent = '\ud83c\udf19';
      try { chrome.storage.local.set({ tg_theme: 'light' }); } catch(e) {}
    } else {
      document.body.setAttribute('data-theme', 'dark');
      btn.textContent = '\u2600\ufe0f';
      try { chrome.storage.local.set({ tg_theme: 'dark' }); } catch(e) {}
    }
  });
});

// ─── GHOST / SPOOF MODE TOGGLE ──────────────────────
var _currentMode = 'off';
var _currentHost = '';
var _modeScope = 'site'; // 'site' or 'global'
(function initMode() {
  try {
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs[0] && tabs[0].url) {
        try { _currentHost = new URL(tabs[0].url).hostname; } catch(e) {}
      }
      chrome.storage.local.get(['tg_mode_global', 'tg_mode_sites'], function(r) {
        var sites = r.tg_mode_sites || {};
        if (sites[_currentHost]) {
          _currentMode = sites[_currentHost];
          _modeScope = 'site';
        } else if (r.tg_mode_global && r.tg_mode_global !== 'off') {
          _currentMode = r.tg_mode_global;
          _modeScope = 'global';
        }
        updateModeUI();
      });
    });
  } catch(e) {}
})();

function updateModeUI() {
  var btnG = document.getElementById('btnGhost');
  var btnS = document.getElementById('btnSpoof');
  var bar = document.getElementById('modeBar');
  if (!btnG || !btnS || !bar) return;
  btnG.classList.remove('active', 'ghost-on');
  btnS.classList.remove('active', 'spoof-on');
  if (_currentMode === 'ghost') {
    btnG.classList.add('active', 'ghost-on');
    bar.style.display = 'flex';
    bar.className = 'mode-bar ghost';
    bar.querySelector('.mode-icon').textContent = '\ud83d\udc7b';
    bar.querySelector('.mode-lbl').textContent = 'Ghost Mode';
    bar.querySelector('.mode-lbl').style.color = 'var(--cyan)';
  } else if (_currentMode === 'spoof') {
    btnS.classList.add('active', 'spoof-on');
    bar.style.display = 'flex';
    bar.className = 'mode-bar spoof';
    bar.querySelector('.mode-icon').textContent = '\ud83c\udfad';
    bar.querySelector('.mode-lbl').textContent = 'Spoof Mode';
    bar.querySelector('.mode-lbl').style.color = 'var(--purple)';
  } else {
    bar.style.display = 'none';
  }
  var hostEl = document.getElementById('modeHost');
  var scopeBtn = document.getElementById('modeScope');
  if (hostEl) hostEl.textContent = _currentMode !== 'off' ? (_modeScope === 'site' ? _currentHost : 'all sites') : '';
  if (scopeBtn) {
    scopeBtn.textContent = _modeScope === 'site' ? 'This site only' : 'All sites';
    scopeBtn.style.display = _currentMode !== 'off' ? 'inline-block' : 'none';
  }
}

function setMode(mode) {
  if (_currentMode === mode) mode = 'off'; // toggle off
  _currentMode = mode;
  var data = {};
  if (_modeScope === 'site' && _currentHost) {
    chrome.storage.local.get('tg_mode_sites', function(r) {
      var sites = r.tg_mode_sites || {};
      if (mode === 'off') { delete sites[_currentHost]; } else { sites[_currentHost] = mode; }
      chrome.storage.local.set({ tg_mode_sites: sites });
    });
  } else {
    chrome.storage.local.set({ tg_mode_global: mode });
  }
  // Push mode to active tab's content script
  try {
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
      if (tabs[0]) {
        chrome.scripting.executeScript({
          target: { tabId: tabs[0].id },
          func: function(m) { document.documentElement.setAttribute('data-tg-mode', m); },
          args: [mode]
        }).catch(function(){});
      }
    });
  } catch(e) {}
  updateModeUI();
}

document.addEventListener('DOMContentLoaded', function() {
  var btnG = document.getElementById('btnGhost');
  var btnS = document.getElementById('btnSpoof');
  var scopeBtn = document.getElementById('modeScope');
  if (btnG) btnG.addEventListener('click', function() { setMode('ghost'); });
  if (btnS) btnS.addEventListener('click', function() { setMode('spoof'); });
  if (scopeBtn) scopeBtn.addEventListener('click', function() {
    _modeScope = _modeScope === 'site' ? 'global' : 'site';
    setMode(_currentMode); // re-save with new scope
  });
});

(function(){
'use strict';
var $=function(id){return document.getElementById(id)};
var esc=function(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML};
var escA=function(s){return String(s).replace(/"/g,'&quot;').replace(/</g,'&lt;')};
var DESC={'Canvas Fingerprint':'Canvas fingerprinting renders hidden text/shapes and reads pixel data to generate a unique device hash via GPU/driver/font rendering differences.','WebGL Fingerprint':'WebGL/WebGPU fingerprinting queries GPU renderer, vendor, extensions, shader precision, and adapter info. WebGPU (2025+) exposes even more hardware detail than WebGL including GPU architecture, device name, features, and compute limits.','Audio Fingerprint':'Audio fingerprinting processes sound through AudioContext and reads output differences caused by hardware/driver variations.','Font Enumeration':'Font enumeration measures text across many font families to detect installed fonts.','Navigator Probing':'Enumeration of navigator properties and behavioral biometrics (mouse patterns, typing cadence, scroll behavior) to build a persistent identity profile.','Screen Profiling':'Reading display properties (resolution, color depth, pixel ratio, orientation) to narrow device identification.','Battery API':'Battery API reveals charge level and timing to create a short-term cross-session identifier.','WebRTC Leak':'WebRTC exposes local/public IPs through ICE candidates, even behind VPN.','Media Devices':'enumerateDevices() lists cameras/mics/speakers with persistent device IDs.','Dynamic Code Exec':'eval(), new Function(), setTimeout(string) execute dynamically generated code common in obfuscated malware.','Data Exfiltration':'Large outbound data transfers to third-party domains may indicate data exfiltration or C2.','WebSocket':'Persistent bidirectional channels that can serve as covert C2 channels.','Worker/SW':'Service Workers persist after page close, can intercept requests or mine crypto.','Crypto/Mining':'WebAssembly, crypto.subtle, and SharedArrayBuffer usage may indicate cryptojacking or timing attacks (Spectre).','Clipboard Access':'Clipboard read can steal passwords/crypto addresses.','DOM Manipulation':'Dynamic injection of scripts/iframes can introduce malicious code.','Credential Access':'navigator.credentials API may target stored passwords.','Timing/Perf':'Rapid performance.now() calls can enable timing side-channel attacks.','Storage Access':'Storage APIs persist tracking identifiers when cookies are blocked.','Network Anomaly':'Unusual network patterns: requests to raw IPs, unusual ports, suspicious file extensions, or base64-encoded parameters.','Permission Probe':'Probing browser permissions and storage quota (incognito mode detection via storage.estimate() or FileSystem API).','postMessage':'Cross-origin postMessage can leak data between frames/windows.','Phishing Indicator':'Suspicious page characteristics: cross-origin login forms, external favicons, brand keyword stuffing, mailto form actions, or data URI pages.','JS Obfuscation':'Obfuscated JavaScript code: hex encoding, eval packing, base64 chains, document.write(unescape()), or string array rotation patterns common in malware and phishing kits.','Page Integrity':'SHA-256 hash of the full DOM content for page integrity monitoring and comparison across scans.','Suspicious URL':'URL-level risk indicators: raw IP hosting, punycode/IDN homograph attacks, excessive subdomains, brand keywords in non-brand domains, or HTTP pages with password fields.'};
var MITRE={'Canvas Fingerprint':'T1082 System Info Discovery, T1217 Browser Info Discovery','WebGL Fingerprint':'T1082 System Info Discovery, T1082.001 Hardware','Audio Fingerprint':'T1082 System Info Discovery','Font Enumeration':'T1082 System Info Discovery','Navigator Probing':'T1082 System Info Discovery, T1016 System Network Config','Screen Profiling':'T1082 System Info Discovery','Battery API':'T1082 System Info Discovery','WebRTC Leak':'T1016 Network Config Discovery, T1590.005 IP Addresses','Media Devices':'T1120 Peripheral Device Discovery','Dynamic Code Exec':'T1059.007 JavaScript, T1027 Obfuscated Files','Data Exfiltration':'T1041 Exfil Over C2, T1567 Exfil Over Web Service','WebSocket':'T1071.001 Web Protocols, T1573 Encrypted Channel','Worker/SW':'T1176 Browser Extensions, T1546 Event Triggered Execution','Crypto/Mining':'T1496 Resource Hijacking','Clipboard Access':'T1115 Clipboard Data','DOM Manipulation':'T1059.007 JavaScript, T1189 Drive-by Compromise','Credential Access':'T1555 Credentials from Password Stores, T1539 Steal Web Session Cookie','Storage Access':'T1539 Steal Web Session Cookie, T1005 Data from Local System','Network Anomaly':'T1071 Application Layer Protocol, T1041 Exfil Over C2','Timing/Perf':'T1082 System Info Discovery, T1124 System Time Discovery','Permission Probe':'T1082 System Info Discovery','postMessage':'T1185 Browser Session Hijacking','Phishing Indicator':'T1566.002 Spearphishing Link, T1598.003 Spearphishing Link (Recon)','JS Obfuscation':'T1027 Obfuscated Files, T1059.007 JavaScript','Page Integrity':'T1565.001 Stored Data Manipulation','Suspicious URL':'T1566.002 Spearphishing Link, T1036.005 Match Legitimate Name'};
var TABS=[{id:'overview',label:'Overview'},{id:'fingerprints',label:'Fingerprints'},{id:'network',label:'Network'},{id:'behavior',label:'Behavior'},{id:'storage',label:'Storage'},{id:'security',label:'Security'},{id:'ioc',label:'IOC Export'},{id:'timeline',label:'Timeline'}];
var tabBar=$('tabBar');TABS.forEach(function(t,i){var el=document.createElement('div');el.className='tab'+(i===0?' active':'');el.dataset.tab=t.id;el.innerHTML=t.label+' <span class="b" id="b-'+t.id+'">0</span>';el.addEventListener('click',function(){document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('active')});document.querySelectorAll('.pnl').forEach(function(x){x.classList.remove('active')});el.classList.add('active');$('p-'+t.id).classList.add('active')});tabBar.appendChild(el)});
var FP=['Canvas Fingerprint','WebGL Fingerprint','Audio Fingerprint','Font Enumeration','Navigator Probing','Screen Profiling','Battery API','WebRTC Leak','Media Devices','Permission Probe','Timing/Perf'];
var BH=['Dynamic Code Exec','Data Exfiltration','WebSocket','Worker/SW','Crypto/Mining','Clipboard Access','postMessage','DOM Manipulation','Credential Access','Network Anomaly','Phishing Indicator','JS Obfuscation','Page Integrity','Suspicious URL'];
var catColors={'Web Server':'c-srv','Language':'c-lang','Framework':'c-fw','JS Framework':'c-fw','SSG':'c-ssg','CSS Framework':'c-css','UI Library':'c-ui','JS Library':'c-lib','CMS':'c-cms','Ecommerce':'c-ec','Analytics':'c-an','Tag Manager':'c-tag','Advertising':'c-ad','Session Replay':'c-sr','A/B Testing':'c-ab','Error Tracking':'c-err','Monitoring':'c-mon','CDN':'c-cdn','Hosting':'c-host','Security':'c-sec','Payment':'c-pay','Chat':'c-chat','Marketing':'c-mkt','Fonts':'c-font','Cookie Consent':'c-cc','Maps':'c-map','Video':'c-vid','Push':'c-push','Social':'c-soc','Backend':'c-be','Build':'c-build','Misc':'c-misc'};
var _tabId=null,_data=null;
chrome.tabs.query({active:true,currentWindow:true},function(tabs){if(!tabs[0])return;_tabId=tabs[0].id;chrome.runtime.sendMessage({action:'get_data',tabId:_tabId},function(data){if(chrome.runtime.lastError||!data){TABS.forEach(function(t){$('p-'+t.id).innerHTML=emptyH('','Navigate to a page and reopen.')});return}_data=data;render(data)})});
$('btnExport').addEventListener('click',function(){if(!_tabId)return;chrome.runtime.sendMessage({action:'export_data',tabId:_tabId},function(data){if(!data)return;var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));a.download='traceglyph-'+(data.hostname||'report')+'-'+Date.now()+'.json';a.click()})});
$('btnRefresh').addEventListener('click',function(){if(_tabId)chrome.tabs.reload(_tabId,function(){window.close()})});
$('btnReport').addEventListener('click',function(){if(!_data)return;var d=_data;var L=['TRACEGLYPH REPORT','Date: '+new Date().toISOString(),'URL: '+(d.url||'N/A'),'Host: '+(d.hostname||'N/A')];if(d.connectionInfo&&d.connectionInfo.ip)L.push('Server IP: '+d.connectionInfo.ip);L.push('Threat Score: '+d.threatScore+'/100');L.push('');var bd=d.scoreBreakdown||{};L.push('SCORE BREAKDOWN');Object.entries(bd).forEach(function(e){if(e[1]>0)L.push('  '+e[0]+': '+e[1])});L.push('');var allTech=mergeTech(d.techStack||[],d.headerTech||[],d.urlTech||[]);if(allTech.length){L.push('TECHNOLOGIES');allTech.forEach(function(t){L.push('  ['+t.cat+'] '+t.name+(t.ver?' '+t.ver:''))});L.push('')}var seen=new Map();d.detections.forEach(function(det){var k=det.category+'::'+det.detail;if(!seen.has(k))seen.set(k,Object.assign({},det,{count:1}));else seen.get(k).count++});var unique=Array.from(seen.values());var crit=unique.filter(function(x){return x.severity==='critical'||x.severity==='high'});if(crit.length){L.push('CRITICAL/HIGH');crit.forEach(function(x){var m=MITRE[x.category]||'';L.push('  ['+x.severity.toUpperCase()+'] '+x.category+': '+x.detail+(x.count>1?' (x'+x.count+')':'')+(m?' | ATT&CK: '+m:''))});L.push('')}var trackers=(d.thirdPartyScripts||[]).filter(function(s){return s.isTracker});if(trackers.length){L.push('TRACKERS');trackers.forEach(function(s){L.push('  '+(s.trackerName||s.domain)+': '+s.src)});L.push('')}var tpxr=d.trackingPixelData||[];if(tpxr.length){L.push('TRACKING PIXELS DECODED ('+tpxr.length+')');tpxr.forEach(function(px){L.push('  ['+px.tracker+'] '+px.hostname);L.push('    Data types: '+(px.dataTypes.length?px.dataTypes.join(', '):'unknown'));L.push('    Params ('+px.paramCount+'): '+Object.entries(px.params).slice(0,8).map(function(e){return e[0]+'='+e[1].substring(0,30)}).join(', '))});L.push('')}var domIPs=Object.entries(d.domainIPs||{});if(domIPs.length){L.push('DOMAIN > IP');domIPs.forEach(function(e){L.push('  '+e[0]+' > '+e[1].join(', '))});L.push('')}var anomalies=d.networkAnomalies||[];if(anomalies.length){L.push('NETWORK ANOMALIES');anomalies.forEach(function(a){L.push('  ['+a.severity.toUpperCase()+'] '+a.detail)});L.push('')}var pi=d.pageIOCs;if(pi){var hasAny=false;for(var pk in pi){if(pi[pk]&&pi[pk].length)hasAny=true}if(hasAny){L.push('EXTRACTED PAGE IOCs');if(pi.ipv4&&pi.ipv4.length){L.push('  IPv4: '+pi.ipv4.join(', '))}if(pi.domains&&pi.domains.length){L.push('  Domains: '+pi.domains.join(', '))}if(pi.urls&&pi.urls.length){L.push('  URLs:');pi.urls.forEach(function(u){L.push('    '+u)})}if(pi.hashes_sha256&&pi.hashes_sha256.length){L.push('  SHA-256:');pi.hashes_sha256.forEach(function(h){L.push('    '+h)})}if(pi.hashes_sha1&&pi.hashes_sha1.length){L.push('  SHA-1: '+pi.hashes_sha1.join(', '))}if(pi.hashes_md5&&pi.hashes_md5.length){L.push('  MD5: '+pi.hashes_md5.join(', '))}if(pi.cves&&pi.cves.length){L.push('  CVEs: '+pi.cves.join(', '))}if(pi.mitre&&pi.mitre.length){L.push('  ATT&CK: '+pi.mitre.join(', '))}if(pi.emails&&pi.emails.length){L.push('  Emails: '+pi.emails.join(', '))}if(pi.files&&pi.files.length){L.push('  Files: '+pi.files.join(', '))}if(pi.registryKeys&&pi.registryKeys.length){L.push('  Registry:');pi.registryKeys.forEach(function(r){L.push('    '+r)})}if(pi.btc&&pi.btc.length){L.push('  BTC: '+pi.btc.join(', '))}if(pi.eth&&pi.eth.length){L.push('  ETH: '+pi.eth.join(', '))}L.push('')}}navigator.clipboard.writeText(L.join('\n')).then(function(){$('btnReport').textContent='Copied!';setTimeout(function(){$('btnReport').textContent='Report'},1500)})});
function render(d){var seen=new Map();d.detections.forEach(function(det){var k=det.category+'::'+det.detail;if(!seen.has(k))seen.set(k,Object.assign({},det,{count:1,maxCallCount:det.callCount||1}));else{var ex=seen.get(k);ex.count++;ex.maxCallCount=Math.max(ex.maxCallCount,det.callCount||1)}});var unique=Array.from(seen.values());var fpD=unique.filter(function(x){return FP.indexOf(x.category)!==-1});var bhD=unique.filter(function(x){return BH.indexOf(x.category)!==-1});var otD=unique.filter(function(x){return FP.indexOf(x.category)===-1&&BH.indexOf(x.category)===-1});var allTech=mergeTech(d.techStack||[],d.headerTech||[],d.urlTech||[]);var ci=d.connectionInfo||{};var cb='';if(d.url){try{var u=new URL(d.url);cb+='<span class="conn-item"><span style="color:var(--t3)">Host</span> <span style="color:var(--t2)">'+esc(u.hostname)+'</span></span><span class="conn-item"><span class="dot" style="background:'+(u.protocol==='https:'?'var(--green)':'var(--red)')+'"></span><span style="color:'+(u.protocol==='https:'?'var(--green)':'var(--red)')+'">'+(u.protocol==='https:'?'HTTPS':'HTTP')+'</span></span>'}catch(e){}}if(ci.ip)cb+='<span class="conn-item"><span style="color:var(--t3)">IP</span> <span style="color:var(--cyan)">'+esc(ci.ip)+'</span></span>';if(ci.statusCode)cb+='<span class="conn-item"><span style="color:var(--t3)">Status</span> <span style="color:'+(ci.statusCode>=400?'var(--red)':'var(--green)')+'">'+ci.statusCode+'</span></span>';if(ci.protocol)cb+='<span class="conn-item"><span style="color:var(--green)">'+esc(ci.protocol)+'</span></span>';var rCt=(d.redirectChains||[]).filter(function(r){return r.type==='redirect'}).length;if(rCt)cb+='<span class="conn-item"><span style="color:var(--t3)">Redirects</span> <span style="color:var(--orange)">'+rCt+'</span></span>';$('connBar').innerHTML=cb||'<span style="color:var(--t3)">Collecting...</span>';renderTechBar(allTech);var score=d.threatScore||0;var color='var(--green)';if(score>20)color='var(--yellow)';if(score>45)color='var(--orange)';if(score>70)color='var(--red)';$('tScore').textContent=score;$('tScore').style.color=color;$('tFill').style.width=score+'%';$('tFill').style.background=color;$('sF').textContent=fpD.length;$('sT').textContent=(d.thirdPartyScripts||[]).filter(function(s){return s.isTracker}).length;$('sD').textContent=Object.keys(d.domains||{}).length;$('sR').textContent=(d.networkRequests||[]).length;$('b-overview').textContent=unique.length;$('b-fingerprints').textContent=fpD.length;$('b-network').textContent=Object.keys(d.domains||{}).length;$('b-behavior').textContent=bhD.length+otD.length;$('b-storage').textContent=(d.cookies?d.cookies.count:0)+((d.storageContents?(d.storageContents.localStorage||[]).length:0))+((d.storageContents?(d.storageContents.sessionStorage||[]).length:0));$('b-security').textContent=(d.securityHeaders?Object.keys(d.securityHeaders).length:0)+(d.forms||[]).length;$('b-ioc').textContent=(d.pageIOCs?Object.values(d.pageIOCs).reduce(function(s,a){return s+(a?a.length:0)},0):0)||'E';$('b-timeline').textContent=(d.timeline||[]).length;renderOverview(d,unique,allTech);$('p-fingerprints').innerHTML=fpD.length?groupedH(fpD):emptyH('','No fingerprinting detected.');wireCards($('p-fingerprints'));wireGroups($('p-fingerprints'));renderNetwork(d);$('p-behavior').innerHTML=(bhD.length+otD.length)?groupedH(bhD.concat(otD)):emptyH('','No suspicious behavior.');wireCards($('p-behavior'));wireGroups($('p-behavior'));renderStorage(d);renderSecurity(d);renderIOC(d,unique);renderTimeline(d)}
function mergeTech(s,h,u){var m=new Map();[s,h,u].forEach(function(a){a.forEach(function(t){var ex=m.get(t.name);if(!ex)m.set(t.name,Object.assign({},t));else if(t.ver&&!ex.ver)ex.ver=t.ver})});return Array.from(m.values())}
function renderTechBar(tech){var bar=$('techBar');if(!tech.length){bar.style.display='none';return}bar.style.display='flex';var h='';var sorted=tech.slice().sort(function(a,b){return a.cat<b.cat?-1:a.cat>b.cat?1:0});var show=Math.min(sorted.length,14);for(var i=0;i<show;i++){var t=sorted[i];var cc=catColors[t.cat]||'c-misc';var abbr=t.icon&&t.icon.length<=3?t.icon:t.name.substring(0,2);h+='<span class="tech-tag '+cc+'" title="'+escA(t.cat+': '+t.name+(t.ver?' v'+t.ver:''))+'"><span class="ti">'+esc(abbr)+'</span>'+esc(t.name)+(t.ver?'<span class="tv">'+esc(t.ver)+'</span>':'')+'</span>'}if(sorted.length>show)h+='<span class="tech-more">+'+(sorted.length-show)+' more</span>';bar.innerHTML=h}
function renderOverview(d,unique,tech){var p=$('p-overview');var h='';var bd=d.scoreBreakdown||{};var mx={fingerprinting:35,tracking:20,behavior:20,security:12,infrastructure:10,anomalies:8,phishing:15,forms:10,cookies:3};h+='<div class="sec-title">Score breakdown</div>';Object.keys(mx).forEach(function(k){var max=mx[k];var v=bd[k]||0;var pct=Math.round(v/max*100);var c='var(--green)';if(pct>30)c='var(--yellow)';if(pct>60)c='var(--orange)';if(pct>80)c='var(--red)';h+='<div class="sb-row"><div class="sb-lbl">'+k.charAt(0).toUpperCase()+k.slice(1)+'</div><div class="sb-bar"><div class="sb-fill" style="width:'+pct+'%;background:'+c+'"></div></div><div class="sb-val">'+v+'/'+max+'</div></div>'});h+='<div style="height:10px"></div>';var pt=d.pageTiming;if(pt&&pt.ttfb){h+='<div class="sec-title">Page timing</div>';h+='<div class="sb-row"><div class="sb-lbl">DNS</div><div class="sb-bar"><div class="sb-fill" style="width:'+Math.min(pt.dnsLookup,100)+'%;background:var(--blue)"></div></div><div class="sb-val">'+pt.dnsLookup+'ms</div></div>';h+='<div class="sb-row"><div class="sb-lbl">TLS</div><div class="sb-bar"><div class="sb-fill" style="width:'+Math.min(pt.tlsHandshake,100)+'%;background:var(--purple)"></div></div><div class="sb-val">'+pt.tlsHandshake+'ms</div></div>';h+='<div class="sb-row"><div class="sb-lbl">TTFB</div><div class="sb-bar"><div class="sb-fill" style="width:'+Math.min(pt.ttfb/10,100)+'%;background:var(--cyan)"></div></div><div class="sb-val">'+pt.ttfb+'ms</div></div>';h+='<div class="sb-row"><div class="sb-lbl">DOM loaded</div><div class="sb-bar"><div class="sb-fill" style="width:'+Math.min(pt.domContentLoaded/30,100)+'%;background:var(--green)"></div></div><div class="sb-val">'+pt.domContentLoaded+'ms</div></div>';if(pt.transferSize)h+='<div class="sb-row"><div class="sb-lbl">Transfer</div><div class="sb-bar"></div><div class="sb-val">'+fmtB(pt.transferSize)+'</div></div>';if(pt.protocol)h+='<div class="sb-row"><div class="sb-lbl">Protocol</div><div class="sb-bar"></div><div class="sb-val">'+pt.protocol+'</div></div>';h+='<div style="height:10px"></div>'}var reqs=d.networkRequests||[];if(reqs.length>0){var types={};var secureCount=0;reqs.forEach(function(r){types[r.type]=(types[r.type]||0)+1;if(r.url&&r.url.indexOf('https://')===0)secureCount++});var secPct=Math.round(secureCount/reqs.length*100);h+='<div class="sec-title">Resource stats <span class="cnt">'+reqs.length+' requests</span></div>';h+='<div class="sb-row"><div class="sb-lbl">HTTPS</div><div class="sb-bar"><div class="sb-fill" style="width:'+secPct+'%;background:'+(secPct===100?'var(--green)':secPct>80?'var(--yellow)':'var(--red)')+'"></div></div><div class="sb-val">'+secPct+'%</div></div>';Object.entries(types).sort(function(a,b){return b[1]-a[1]}).forEach(function(e){h+='<div class="sb-row"><div class="sb-lbl">'+e[0]+'</div><div class="sb-bar"><div class="sb-fill" style="width:'+Math.round(e[1]/reqs.length*100)+'%;background:var(--t3)"></div></div><div class="sb-val">'+e[1]+'</div></div>'});h+='<div style="height:10px"></div>'}if(tech.length>14){h+='<div class="sec-title">All technologies <span class="cnt">'+tech.length+'</span></div><div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:12px">';tech.forEach(function(t){var cc=catColors[t.cat]||'c-misc';var abbr=t.icon&&t.icon.length<=3?t.icon:t.name.substring(0,2);h+='<span class="tech-tag '+cc+'"><span class="ti">'+esc(abbr)+'</span>'+esc(t.name)+(t.ver?'<span class="tv">'+esc(t.ver)+'</span>':'')+'</span>'});h+='</div>'}var anomalies=d.networkAnomalies||[];if(anomalies.length){h+='<div class="sec-title">Network anomalies <span class="cnt">'+anomalies.length+'</span></div>';anomalies.forEach(function(a){h+=cardH({category:'Network Anomaly',detail:a.detail,severity:a.severity,valueRead:a.url,count:1,callCount:1,maxCallCount:1})})}var redirs=(d.redirectChains||[]).filter(function(r){return r.type==='redirect'});if(redirs.length){h+='<div class="sec-title">Redirect chain <span class="cnt">'+redirs.length+'</span></div>';redirs.forEach(function(r){h+=redirH(r,d.domainIPs)})}var bySev={critical:[],high:[]};unique.forEach(function(det){if(det.severity==='critical')bySev.critical.push(det);if(det.severity==='high')bySev.high.push(det)});if(bySev.critical.length){h+='<div class="sec-title">Critical <span class="cnt">'+bySev.critical.length+'</span></div>';bySev.critical.slice(0,8).forEach(function(det){h+=cardH(det)})}if(bySev.high.length){h+='<div class="sec-title">High severity <span class="cnt">'+bySev.high.length+'</span></div>';bySev.high.slice(0,8).forEach(function(det){h+=cardH(det)})}var susD=Object.entries(d.domains||{}).filter(function(e){return e[1].flags&&e[1].flags.length>0});if(susD.length){h+='<div class="sec-title">Suspicious domains <span class="cnt">'+susD.length+'</span></div>';susD.slice(0,8).forEach(function(e){h+=domH(e[0],e[1],d.domainIPs)})}if(h.indexOf('sec-title')===-1)h=emptyH('','No significant findings.');p.innerHTML=h;wireCards(p)}
function renderNetwork(d){var p=$('p-network');var h='';var doms=Object.entries(d.domains||{}).sort(function(a,b){return b[1].count-a[1].count});if(doms.length){h+='<div class="sec-title">Domains <span class="cnt">'+doms.length+'</span></div>';doms.forEach(function(e){h+=domH(e[0],e[1],d.domainIPs)})}var redirs=(d.redirectChains||[]).filter(function(r){return r.type==='redirect'});if(redirs.length){h+='<div class="sec-title">Redirects <span class="cnt">'+redirs.length+'</span></div>';redirs.forEach(function(r){h+=redirH(r,d.domainIPs)})}var tpx=d.trackingPixelData||[];if(tpx.length){h+='<div class="sec-title">Tracking pixels decoded <span class="cnt">'+tpx.length+'</span></div>';tpx.forEach(function(px){var dataStr=px.dataTypes.length?px.dataTypes.join(', '):'unknown';h+='<div class="card"><div class="card-top"><div class="dot critical"></div><div class="card-d"><span style="color:var(--purple);font-weight:600">'+esc(px.tracker)+'</span> - '+px.paramCount+' params</div><div class="sev high">'+esc(px.method)+'</div></div><div class="card-v"><span style="color:var(--accent);font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-right:6px">Data types leaked:</span>'+esc(dataStr)+'</div><div class="card-detail"><div class="cd-label">Pixel URL</div><div class="cd-stack">'+esc(px.url)+'</div><div class="cd-label" style="margin-top:6px">Decoded parameters</div><div class="cd-stack">';Object.entries(px.params).forEach(function(e){h+=esc(e[0])+' = '+esc(e[1])+'\\n'});h+='</div></div></div>'})}var pageLinks=d.pageLinks||[];if(pageLinks.length){var extLinks=pageLinks.filter(function(l){return l.isExternal});h+='<div class="sec-title">Page links <span class="cnt">'+pageLinks.length+' total, '+extLinks.length+' external</span></div>';pageLinks.slice(0,80).forEach(function(l){h+='<div class="dom-row"><div class="dom-name" style="color:'+(l.isExternal?'var(--orange)':'var(--t2)')+'">'+esc(l.href)+'</div><div class="dom-right"><span class="dom-count">'+esc(l.text||'(no text)').substring(0,40)+'</span>'+(l.isExternal?'<div class="dom-flags"><span class="flag suspicious_tld">external</span></div>':'')+'</div></div>'})}var reqs=(d.networkRequests||[]).slice(-60).reverse();if(reqs.length){h+='<div class="sec-title">Requests <span class="cnt">'+d.networkRequests.length+'</span></div>';reqs.forEach(function(r){h+='<div class="net-row"><div class="net-type '+r.type+'">'+r.type+'</div><div class="net-m">'+r.method+'</div><div class="net-url">'+esc(r.url)+'</div>'+(r.ip?'<div class="net-ip">'+esc(r.ip)+'</div>':'')+'</div>'})}if(!h)h=emptyH('','No data.');p.innerHTML=h}
function renderStorage(d){var p=$('p-storage');var h='';var cks=(d.cookies?d.cookies.cookies:[])||[];if(cks.length){h+='<div class="sec-title">Cookies <span class="cnt">'+cks.length+'</span></div>';cks.forEach(function(c){h+='<div class="ck-row"><div class="ck-n">'+esc(c.name)+'</div><div class="ck-v">'+esc(c.value)+'</div>'+(c.isTracking?'<div class="ck-tag tr">tracker</div>':'<div class="ck-tag" style="color:var(--t3)">'+c.size+'b</div>')+'</div>'})}var ls=(d.storageContents?d.storageContents.localStorage:[])||[];if(ls.length){h+='<div class="sec-title">localStorage <span class="cnt">'+ls.length+'</span></div>';ls.forEach(function(i){h+='<div class="stor-row"><div class="stor-k">'+esc(i.key)+'</div><div class="stor-v">'+esc(i.value)+'</div><div class="stor-sz">'+fmtB(i.size)+'</div></div>'})}var sh=d.scriptHashes||[];if(sh.length){h+='<div class="sec-title">Script hashes <span class="cnt">'+sh.length+'</span></div>';sh.forEach(function(s){h+='<div class="stor-row"><div class="stor-k">'+esc(s.type==='external'?(s.url||'external'):(s.preview||'').substring(0,30)||'inline')+'</div><div class="stor-v">'+esc(s.hash)+'</div><div class="stor-sz">'+s.type+'</div></div>'})}var consoleMsgs=d.consoleMsgs||[];if(consoleMsgs.length){h+='<div class="sec-title">Console output <span class="cnt">'+consoleMsgs.length+'</span></div>';consoleMsgs.slice(0,100).forEach(function(m){var color=m.method==='error'?'var(--red)':m.method==='warn'?'var(--yellow)':'var(--t3)';h+='<div class="stor-row"><div class="stor-k" style="color:'+color+';min-width:50px">'+m.method+'</div><div class="stor-v">'+esc(m.message)+'</div><div class="stor-sz"></div></div>'})}var globals=d.jsGlobals||[];if(globals.length){h+='<div class="sec-title">JS globals <span class="cnt">'+globals.length+'</span></div>';globals.slice(0,100).forEach(function(g){h+='<div class="stor-row"><div class="stor-k">'+esc(g.name)+'</div><div class="stor-v" style="color:var(--purple)">'+esc(g.type)+'</div><div class="stor-sz"></div></div>'})}if(!h)h=emptyH('','No data.');p.innerHTML=h}
function renderSecurity(d){var p=$('p-security');var h='';var hdr=d.securityHeaders;if(hdr){var ent=Object.entries(hdr).sort(function(a,b){var o=['missing','weak','info','present'];return o.indexOf(a[1].status)-o.indexOf(b[1].status)});h+='<div class="sec-title">Response headers <span class="cnt">'+ent.length+'</span></div>';ent.forEach(function(e){h+='<div class="sec-row"><div class="sec-name">'+esc(e[0])+'</div><div class="sec-st '+e[1].status+'">'+e[1].status+'</div><div class="sec-v">'+esc(e[1].note||e[1].value||'\u2014')+'</div></div>'})}var forms=d.forms||[];if(forms.length){h+='<div class="sec-title">Forms <span class="cnt">'+forms.length+'</span></div>';forms.forEach(function(f){h+=formH(f)})}var ifs=d.iframes||[];if(ifs.length){h+='<div class="sec-title">Iframes <span class="cnt">'+ifs.length+'</span></div>';ifs.forEach(function(f){h+=ifH(f)})}if(!h)h=emptyH('','No data.');p.innerHTML=h}
function renderIOC(d,unique){var p=$('p-ioc');var h='';var domains=Object.keys(d.domains||{}).sort();var ips=[];var ipSeen={};Object.values(d.domainIPs||{}).forEach(function(arr){arr.forEach(function(ip){if(!ipSeen[ip]){ipSeen[ip]=1;ips.push(ip)}})});ips.sort();var mapping=Object.entries(d.domainIPs||{}).map(function(e){return e[0]+' > '+e[1].join(', ')});var trackers=(d.thirdPartyScripts||[]).filter(function(s){return s.isTracker}).map(function(s){return s.src});var susD=Object.entries(d.domains||{}).filter(function(e){return e[1].flags&&e[1].flags.length>0}).map(function(e){return e[0]+' ('+e[1].flags.join(', ')+')'});var anomalies=(d.networkAnomalies||[]).map(function(a){return '['+a.severity.toUpperCase()+'] '+a.detail+' | '+a.url});var critDets=unique.filter(function(x){return x.severity==='critical'}).map(function(x){return '['+x.category+'] '+x.detail});var sh=(d.scriptHashes||[]).map(function(s){return '['+s.type+'] '+s.hash+(s.url?' | '+s.url:'')});function sec(t,id,data,color){return '<div class="sec-title" style="display:flex">'+t+' <span class="cnt">'+data.length+'</span><button class="ioc-copy" data-target="'+id+'">Copy</button></div><div class="ioc-box" id="'+id+'" style="'+(color?'color:'+color:'')+'">'+(data.join('\n')||'(none)')+'</div>'}h+=sec('Domains','ioc-d',domains);h+=sec('IP addresses','ioc-i',ips);h+=sec('Domain > IP','ioc-m',mapping);if(sh.length)h+=sec('Script hashes','ioc-sh',sh);if(anomalies.length)h+=sec('Network anomalies','ioc-a',anomalies);if(susD.length)h+=sec('Suspicious domains','ioc-s',susD);if(trackers.length)h+=sec('Trackers','ioc-t',trackers);if(critDets.length)h+=sec('Critical detections','ioc-c',critDets);var pi=d.pageIOCs;if(pi){h+='<div class="sec-title" style="margin-top:16px;border-top:2px solid var(--accent);padding-top:10px;color:var(--accent)">Extracted IOCs from page text</div>';if(pi.ipv4&&pi.ipv4.length)h+=sec('IPv4 addresses (from text)','ioc-eip4',pi.ipv4,'var(--cyan)');if(pi.ipv6&&pi.ipv6.length)h+=sec('IPv6 addresses (from text)','ioc-eip6',pi.ipv6,'var(--cyan)');if(pi.domains&&pi.domains.length)h+=sec('Domains (from text)','ioc-edom',pi.domains,'var(--accent)');if(pi.urls&&pi.urls.length)h+=sec('URLs (from text)','ioc-eurl',pi.urls,'var(--purple)');if(pi.hashes_sha256&&pi.hashes_sha256.length)h+=sec('SHA-256 hashes','ioc-esha256',pi.hashes_sha256,'var(--orange)');if(pi.hashes_sha1&&pi.hashes_sha1.length)h+=sec('SHA-1 hashes','ioc-esha1',pi.hashes_sha1,'var(--orange)');if(pi.hashes_md5&&pi.hashes_md5.length)h+=sec('MD5 hashes','ioc-emd5',pi.hashes_md5,'var(--orange)');if(pi.cves&&pi.cves.length)h+=sec('CVE IDs','ioc-ecve',pi.cves,'var(--red)');if(pi.mitre&&pi.mitre.length)h+=sec('MITRE ATT&CK IDs','ioc-emitre',pi.mitre,'var(--orange)');if(pi.emails&&pi.emails.length)h+=sec('Email addresses','ioc-eemail',pi.emails,'var(--purple)');if(pi.files&&pi.files.length)h+=sec('Suspicious files','ioc-efile',pi.files,'var(--red)');if(pi.registryKeys&&pi.registryKeys.length)h+=sec('Registry keys','ioc-ereg',pi.registryKeys,'var(--yellow)');if(pi.btc&&pi.btc.length)h+=sec('Bitcoin addresses','ioc-ebtc',pi.btc,'var(--yellow)');if(pi.eth&&pi.eth.length)h+=sec('Ethereum addresses','ioc-eeth',pi.eth,'var(--purple)');}p.innerHTML=h||emptyH('','No IOCs found.');p.querySelectorAll('.ioc-copy').forEach(function(btn){btn.addEventListener('click',function(){var box=$(btn.dataset.target);if(box)navigator.clipboard.writeText(box.textContent).then(function(){btn.textContent='Copied!';setTimeout(function(){btn.textContent='Copy'},1200)})})})}
function renderTimeline(d){var p=$('p-timeline');var ev=(d.timeline||[]).slice().reverse();if(!ev.length){p.innerHTML=emptyH('','No events.');return}var h='<div class="sec-title">Event timeline <span class="cnt">'+ev.length+'</span></div>';ev.slice(0,300).forEach(function(e){var dt=new Date(e.ts);var utc=dt.getUTCFullYear()+'-'+String(dt.getUTCMonth()+1).padStart(2,'0')+'-'+String(dt.getUTCDate()).padStart(2,'0')+' '+String(dt.getUTCHours()).padStart(2,'0')+':'+String(dt.getUTCMinutes()).padStart(2,'0')+':'+String(dt.getUTCSeconds()).padStart(2,'0')+'.'+String(dt.getUTCMilliseconds()).padStart(3,'0')+' UTC';h+='<div class="tl-row"><div class="tl-ts">'+utc+'</div><div class="tl-cat">'+esc(e.category)+'</div><div class="tl-det">'+esc(e.detail)+'</div></div>'});p.innerHTML=h}
function cardH(det){var desc=DESC[det.category]||'';var mitre=MITRE[det.category]||'';var stackLines=parseStack(det.stack);var callInfo=(det.maxCallCount||0)>1?' <span style="color:var(--cyan);font-family:var(--mono);font-size:9px">called '+det.maxCallCount+'x</span>':'';var countInfo=(det.count||0)>1?' <span style="color:var(--t3);font-family:var(--mono);font-size:9px">\u00d7'+det.count+' types</span>':'';var h='<div class="card"><div class="card-top"><div class="dot '+det.severity+'"></div><div class="card-d">'+esc(det.detail)+callInfo+countInfo+'</div><div class="sev '+det.severity+'">'+det.severity+'</div></div>';if(det.valueRead&&det.valueRead!=='undefined'&&det.valueRead!=='null'&&det.valueRead.length>0){var isFingerprint=['Canvas Fingerprint','WebGL Fingerprint','Audio Fingerprint','Font Enumeration','Navigator Probing','Screen Profiling','Battery API','WebRTC Leak','Media Devices','Permission Probe'].indexOf(det.category)!==-1;var lbl=isFingerprint?'\ud83d\udcbb Browser responded':'Value';h+='<div class="card-v"><span style="color:var(--accent);font-weight:600;font-size:9px;text-transform:uppercase;letter-spacing:.5px;margin-right:6px">'+lbl+':</span>'+esc(det.valueRead)+'</div>'}h+='<div class="card-detail">';if(mitre)h+='<div class="cd-label">MITRE ATT&CK</div><div style="font-family:var(--mono);font-size:10px;color:var(--orange);margin-bottom:8px;line-height:1.6">'+esc(mitre)+'</div>';if(desc)h+='<div class="cd-label">What this means</div><div class="cd-desc">'+esc(desc)+'</div>';if(det.callCount)h+='<div class="cd-label">Total calls intercepted</div><div style="font-family:var(--mono);font-size:11px;color:var(--cyan);margin-bottom:6px">'+det.callCount+' call(s)</div>';if(stackLines.length){h+='<div class="cd-label">Source (file : line)</div><div class="cd-stack">';stackLines.forEach(function(l){h+=esc(l)+'\n'});h+='</div>'}h+='</div></div>';return h}
function parseStack(stack){if(!stack)return[];return stack.split(' | ').map(function(l){var m=l.match(/at\s+(.+?)(?:\s+\((.+?):(\d+):(\d+)\))?$/)||l.match(/(https?:\/\/.+?):(\d+):(\d+)/);if(m){if(m[2])return m[1]+' > '+m[2]+':'+m[3];return m[1]+':'+m[2]+':'+m[3]}return l.replace(/^\s*at\s*/,'')}).filter(function(l){return l&&l.indexOf('__FPG')===-1})}
function wireCards(container){container.querySelectorAll('.card').forEach(function(c){c.addEventListener('click',function(){c.classList.toggle('expanded')})})}
function wireGroups(container){container.querySelectorAll('.grp-h').forEach(function(gh){gh.addEventListener('click',function(e){e.stopPropagation();gh.classList.toggle('collapsed');var body=gh.nextElementSibling;if(body)body.style.display=gh.classList.contains('collapsed')?'none':'block'})});container.querySelectorAll('.grp-toggle-all').forEach(function(btn){btn.addEventListener('click',function(){var panel=btn.closest('[id^="p-"]')||btn.parentElement.parentElement;var groups=panel.querySelectorAll('.grp');var allCollapsed=Array.from(groups).every(function(g){return g.querySelector('.grp-h').classList.contains('collapsed')});groups.forEach(function(g){var gh=g.querySelector('.grp-h');var body=gh.nextElementSibling;if(allCollapsed){gh.classList.remove('collapsed');if(body)body.style.display='block'}else{gh.classList.add('collapsed');if(body)body.style.display='none'}});btn.textContent=allCollapsed?'Collapse all':'Expand all'})})}
function groupedH(dets){var groups={};var so={critical:0,high:1,medium:2,low:3};dets.forEach(function(d){(groups[d.category]=groups[d.category]||[]).push(d)});var sorted=Object.entries(groups).sort(function(a,b){var aMin=Math.min.apply(null,a[1].map(function(x){return so[x.severity]!=null?so[x.severity]:3}));var bMin=Math.min.apply(null,b[1].map(function(x){return so[x.severity]!=null?so[x.severity]:3}));return aMin-bMin});var h='<div style="display:flex;justify-content:flex-end;margin-bottom:6px"><button class="grp-toggle-all">Collapse all</button></div>';sorted.forEach(function(pair){var cat=pair[0],items=pair[1];items.sort(function(a,b){return(so[a.severity]!=null?so[a.severity]:3)-(so[b.severity]!=null?so[b.severity]:3)});h+='<div class="grp"><div class="grp-h"><span class="arr">\u25bc</span> '+esc(cat)+' <span class="grp-ct">'+items.length+'</span></div><div class="grp-body">';items.forEach(function(det){h+=cardH(det)});h+='</div></div>'});return h}
function domH(name,info,ips){var ipL=(ips&&ips[name])||(info.ips)||[];var ipStr=Array.isArray(ipL)?ipL.join(', '):'';var fl=info.flags||[];return '<div class="dom-row"><div class="dom-name">'+esc(name)+(ipStr?' <span class="dom-ip">'+esc(ipStr)+'</span>':'')+'</div><div class="dom-right"><span class="dom-count">'+info.count+' req</span><div class="dom-flags">'+fl.map(function(f){return '<span class="flag '+f+'">'+f.replace(/_/g,' ')+'</span>'}).join('')+'</div></div></div>'}
function redirH(r,dI){var sc=r.statusCode===301?'301':r.statusCode===302?'302':r.statusCode===307?'307':'other';var fH='',tH='';try{fH=new URL(r.from).hostname}catch(e){}try{tH=new URL(r.to).hostname}catch(e){}var fIP=r.ip||((dI&&dI[fH])||[])[0]||'';var tIP=((dI&&dI[tH])||[])[0]||'';return '<div class="redir-row"><div class="redir-top"><span class="redir-status redir-'+sc+'">'+r.statusCode+'</span><span style="color:var(--t2)">'+esc(fH)+'</span>'+(fIP?'<span class="redir-ip">['+esc(fIP)+']</span>':'')+'<span class="redir-arrow">\u2192</span><span style="color:var(--t1)">'+esc(tH)+'</span>'+(tIP?'<span class="redir-ip">['+esc(tIP)+']</span>':'')+'</div><div class="redir-url">'+esc(r.from)+'</div><div class="redir-url" style="color:var(--t2)">\u2192 '+esc(r.to)+'</div></div>'}
function formH(f){return '<div class="form-card"><span class="form-risk '+f.risk+'">'+f.risk+'</span><span style="font-family:var(--mono);font-size:10px;color:var(--t2)">'+esc(f.method)+' > '+esc(f.action||'(same page)')+'</span>'+(f.isCrossOrigin?' <span class="if-fl" style="background:rgba(249,115,22,.12);color:var(--orange)">cross-origin</span>':'')+'<div class="form-f">'+(f.passwordFields?'password:'+f.passwordFields+' ':'')+(f.emailFields?'email:'+f.emailFields+' ':'')+(f.ccFields?'cc:'+f.ccFields+' ':'')+'| '+f.inputCount+' inputs, '+f.hiddenInputs.length+' hidden</div></div>'}
function ifH(f){return '<div class="if-row"><div class="if-src">'+esc(f.src)+'</div><div class="if-meta">'+(f.isHidden?'<span class="if-fl hidden">hidden</span>':'')+(f.crossOrigin?'<span class="if-fl xo">cross-origin</span>':'')+'<span>'+f.dimensions+'</span></div></div>'}
function emptyH(i,t){return '<div class="empty"><div class="empty-t">'+t+'</div></div>'}
function fmtB(n){if(n<1024)return n+'b';if(n<1048576)return(n/1024).toFixed(1)+'K';return(n/1048576).toFixed(1)+'M'}
})();
