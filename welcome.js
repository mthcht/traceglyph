(function() {
  var ua = navigator.userAgent || '';
  var extUrl = 'chrome://extensions';
  if (ua.indexOf('Edg/') !== -1) extUrl = 'edge://extensions';
  else if (navigator.brave && typeof navigator.brave.isBrave === 'function') extUrl = 'brave://extensions';
  else if (ua.indexOf('OPR/') !== -1) extUrl = 'opera://extensions';
  else if (ua.indexOf('Vivaldi/') !== -1) extUrl = 'vivaldi://extensions';
  var el = document.getElementById('extUrl');
  el.textContent = extUrl;
  el.addEventListener('click', function() { try { chrome.tabs.create({ url: extUrl }); } catch(e) {} });
})();
