function parseDNField(dn, key) {
  if (!dn) { return ''; }
  var regex = new RegExp('(?:^|, )' + key + '=([^,]+)');
  var match = dn.match(regex);
  return match ? match[1].trim() : '';
}

function searchTable() {
  try {
    var input = document.getElementById('searchInput');
    var filter = (input && input.value ? input.value : '').toUpperCase();
    var listContainer = document.getElementById('certList');
    var items = listContainer ? listContainer.getElementsByClassName('ios-list-item-container') : [];
    var i;

    for (i = 0; i < items.length; i++) {
      var item = items[i];
      var name = item.getAttribute('data-name') || '';
      var issuer = item.getAttribute('data-issuer') || '';
      var valid = item.getAttribute('data-valid') || '';
      var textToSearch = (name + ' ' + issuer + ' ' + valid).toUpperCase();
      
      if (textToSearch.indexOf(filter) > -1) {
        item.style.display = '';
      } else {
        item.style.display = 'none';
        // Hide card if parent item is hidden
        var card = document.getElementById(item.id.replace('container_', 'card_'));
        if (card) { card.style.display = 'none'; }
        // Remove expanded class from container
        item.className = item.className.replace(/\bexpanded\b/, '');
      }
    }
  } catch (e) {
    try {
      var listContainer2 = document.getElementById('certList');
      var items2 = listContainer2 ? listContainer2.getElementsByClassName('ios-list-item-container') : [];
      var k;
      for (k = 0; k < items2.length; k++) {
        items2[k].style.display = '';
      }
    } catch (e2) {}
  }
  try { updateRoundedCorners(); } catch (err) {}
}

function filterTableByRoot(rootCN, rootOrg) {
  var listContainer = document.getElementById('certList');
  if (!listContainer) { return false; }

  var items = listContainer.getElementsByClassName('ios-list-item-container');
  var hasMatch = false;
  var i;

  for (i = 0; i < items.length; i++) {
    var item = items[i];
    var name = (item.getAttribute('data-name') || '').toLowerCase();
    var issuer = (item.getAttribute('data-issuer') || '').toLowerCase();
    var found = false;

    if (rootCN) {
      var cnNeedle = rootCN.toLowerCase();
      found = found || name.indexOf(cnNeedle) > -1 || issuer.indexOf(cnNeedle) > -1;
    }

    if (rootOrg) {
      var orgNeedle = rootOrg.toLowerCase();
      found = found || name.indexOf(orgNeedle) > -1 || issuer.indexOf(orgNeedle) > -1;
    }

    if (found) {
      item.style.display = '';
    } else {
      item.style.display = 'none';
      var card = document.getElementById(item.id.replace('container_', 'card_'));
      if (card) { card.style.display = 'none'; }
      item.className = item.className.replace(/\bexpanded\b/, '');
    }
    hasMatch = hasMatch || found;
  }

  try { updateRoundedCorners(); } catch (err) {}
  return hasMatch;
}

function normalizeIssuerCandidates(issuer) {
  if (!issuer) { return []; }
  var cleaned = issuer;
  var parts;
  var candidates = [];
  var seen = {};
  var output = [];
  var i;

  cleaned = cleaned.replace(/\b(DV|EV|TLS|RSA|ECC|CA|Root|ROOT|G[0-9]|S?N|Class)\b/gi, ' ');
  cleaned = cleaned.replace(/\b(20\d{2}|19\d{2})\b/g, ' ');
  cleaned = cleaned.replace(/[\(\)\[\]\"\'\`]/g, '');
  cleaned = cleaned.replace(/[^\w\u4e00-\u9fa5]+/g, ' ');
  cleaned = cleaned.replace(/^\s+|\s+$/g, '');

  parts = cleaned ? cleaned.split(/\s+/) : [];

  candidates.push(issuer);
  if (cleaned) { candidates.push(cleaned); }

  for (i = 0; i < parts.length; i++) {
    candidates.push(parts.slice(i).join(' '));
    candidates.push(parts[i]);
  }

  for (i = 0; i < candidates.length && output.length < 8; i++) {
    var item = candidates[i];
    var key;
    if (!item) { continue; }
    item = item.replace(/^\s+|\s+$/g, '');
    if (!item) { continue; }

    key = item.toLowerCase();
    if (!seen[key]) {
      seen[key] = true;
      output.push(item);
    }
  }

  return output;
}

function tryMatchByIssuerCandidates(cn, org) {
  var tried = {};
  var candidates = [];
  var i;
  var key;

  if (cn) { candidates = candidates.concat(normalizeIssuerCandidates(cn)); }
  if (org) { candidates = candidates.concat(normalizeIssuerCandidates(org)); }

  for (i = 0; i < candidates.length; i++) {
    if (!candidates[i]) { continue; }
    key = candidates[i].toLowerCase();
    if (tried[key]) { continue; }
    tried[key] = true;

    if (filterTableByRoot(candidates[i], candidates[i])) {
      return true;
    }
  }

  return false;
}

var corsProxyBuilders = [
  function(url) { return url; },
  function(url) { return 'http://cors-proxy.cf.miniproj.stevezmt.top/?url=' + encodeURIComponent(url); },
  function(url) { return 'https://cors.isomorphic-git.org/' + url; },
  function(url) { return 'https://corsproxy.io/?' + url; },
  function(url) { return 'https://api.allorigins.win/raw?url=' + encodeURIComponent(url); },
  function(url) { return 'https://thingproxy.freeboard.io/fetch/' + url; }
];
var preferredProxy = 0;
var cfWorkerBase = 'https://ca-check.cf.miniproj.stevezmt.top';

function fetchJsonWithCorsFallback(url) {
  return new Promise(function(resolve, reject) {
    var lastError = null;

    function tryProxy(indexOffset) {
      if (indexOffset >= corsProxyBuilders.length) {
        reject(lastError || new Error('请求失败：远程接口不可用或被浏览器拦截。'));
        return;
      }

      var index = (preferredProxy + indexOffset) % corsProxyBuilders.length;
      var target = corsProxyBuilders[index](url);

      fetch(target).then(function(response) {
        if (!response.ok) {
          throw new Error('网络错误(' + response.status + ')');
        }

        return response.text().then(function(bodyText) {
          try {
            var json = JSON.parse(bodyText);
            preferredProxy = index;
            resolve(json);
          } catch (parseErr) {
            var snippet = bodyText.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').replace(/^\s+|\s+$/g, '').slice(0, 160);
            throw new Error('响应不是 JSON：' + (snippet || '未知内容'));
          }
        });
      }).catch(function(err) {
        lastError = err;
        tryProxy(indexOffset + 1);
      });
    }

    tryProxy(0);
  });
}

function callCrtSh(domain) {
  return new Promise(function(resolve, reject) {
    try {
      var probeUrl = cfWorkerBase + '/probe?host=' + encodeURIComponent(domain);

      fetch(probeUrl).then(function(probeResp) {
        if (probeResp && probeResp.ok) { return probeResp.json(); }
        return null;
      }).then(function(probeJson) {
        if (probeJson && (probeJson.rootCN || probeJson.rootOrg)) {
          resolve({ rootCN: probeJson.rootCN || '', rootOrg: probeJson.rootOrg || '' });
          return;
        }

        var endpoint = 'https://crt.sh/?q=' + encodeURIComponent(domain) + '&output=json';
        return fetchJsonWithCorsFallback(endpoint).then(function(payload) {
          if (!payload || typeof payload.length === 'undefined' || payload.length === 0) {
            throw new Error('crt.sh 未返回证书数据');
          }

          var latestCert = payload[0];
          var issuerName = latestCert.issuer_name || '';
          resolve({
            rootCN: parseDNField(issuerName, 'CN'),
            rootOrg: parseDNField(issuerName, 'O')
          });
        });
      }).catch(function() {
        var endpointFallback = 'https://crt.sh/?q=' + encodeURIComponent(domain) + '&output=json';
        fetchJsonWithCorsFallback(endpointFallback).then(function(payload2) {
          if (!payload2 || typeof payload2.length === 'undefined' || payload2.length === 0) {
            throw new Error('crt.sh 未返回证书数据');
          }

          var latestCert2 = payload2[0];
          var issuerName2 = latestCert2.issuer_name || '';
          resolve({
            rootCN: parseDNField(issuerName2, 'CN'),
            rootOrg: parseDNField(issuerName2, 'O')
          });
        }).catch(function(err2) {
          reject(err2);
        });
      });
    } catch (e) {
      var endpointDirect = 'https://crt.sh/?q=' + encodeURIComponent(domain) + '&output=json';
      fetchJsonWithCorsFallback(endpointDirect).then(function(payload3) {
        if (!payload3 || typeof payload3.length === 'undefined' || payload3.length === 0) {
          throw new Error('crt.sh 未返回证书数据');
        }

        var latestCert3 = payload3[0];
        var issuerName3 = latestCert3.issuer_name || '';
        resolve({
          rootCN: parseDNField(issuerName3, 'CN'),
          rootOrg: parseDNField(issuerName3, 'O')
        });
      }).catch(function(err3) {
        reject(err3);
      });
    }
  });
}

function checkCertChain() {
  var resultEl = document.getElementById('chainResults');
  if (!resultEl) { return; }
  resultEl.style.display = '';
  try { updateRoundedCorners(); } catch (err) {}

  try {
    var urlInput = document.getElementById('urlInput');
    var rawValue = '';
    var domain;

    if (urlInput && typeof urlInput.value === 'string') {
      rawValue = urlInput.value.replace(/^\s+|\s+$/g, '');
    }

    if (!rawValue) {
      resultEl.innerHTML = '请输入有效的 URL。';
      return;
    }

    domain = rawValue.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    if (!domain) {
      resultEl.innerHTML = '请输入有效的 URL。';
      return;
    }

    resultEl.innerHTML = '<img src="//passwordreset.microsoftonline.com/images/wait_animation.gif" alt="加载中" width="16" height="16"> 正在查询证书链，这可能需要几分钟...';

    callCrtSh(domain).then(function(rootInfo) {
      var rootCN = rootInfo.rootCN;
      var rootOrg = rootInfo.rootOrg;
      var matched;

      if (!rootCN && !rootOrg) {
        resultEl.innerHTML = '未找到根证书信息。';
        try { updateRoundedCorners(); } catch (err) {}
        return;
      }

      matched = tryMatchByIssuerCandidates(rootCN, rootOrg);
      if (matched) {
        resultEl.innerHTML = '已筛选出可能需要安装的根证书：' + (rootCN || rootOrg || '未知');
      } else {
        resultEl.innerHTML = '未在本库中找到匹配的根证书：' + (rootCN || rootOrg || '未知');
      }
      try { updateRoundedCorners(); } catch (err) {}
    }).catch(function(err) {
      var msg = err && err.message ? err.message : String(err);
      resultEl.innerHTML = '检测失败：' + msg + '。建议稍后重试或在桌面环境通过 openssl s_client 检查。';
      try { updateRoundedCorners(); } catch (err) {}
    });
  } catch (ex) {
    resultEl.innerHTML = '检测失败：' + String(ex);
    try { updateRoundedCorners(); } catch (err) {}
  }
}

function resetTable() {
  var listContainer = document.getElementById('certList');
  var items = listContainer ? listContainer.getElementsByClassName('ios-list-item-container') : [];
  var i;

  for (i = 0; i < items.length; i++) {
    items[i].style.display = '';
    var card = document.getElementById(items[i].id.replace('container_', 'card_'));
    if (card) { card.style.display = 'none'; }
    items[i].className = items[i].className.replace(/\bexpanded\b/, '');
  }

  var resultEl = document.getElementById('chainResults');
  if (resultEl) {
    resultEl.innerHTML = '';
    resultEl.style.display = 'none';
  }

  var urlInput = document.getElementById('urlInput');
  if (urlInput) { urlInput.value = ''; }

  var searchInput = document.getElementById('searchInput');
  if (searchInput) { searchInput.value = ''; }

  try { updateRoundedCorners(); } catch (err) {}
}

function toggleCard(certId, forceState) {
  var card = document.getElementById('card_' + certId);
  var container = document.getElementById('container_' + certId);
  if (!card) { return; }
  
  var isHidden = card.style.display === 'none';
  var targetState = (typeof forceState !== 'undefined') ? forceState : isHidden;
  
  card.style.display = targetState ? '' : 'none';
  
  if (container) {
    if (targetState) {
      if (container.className.indexOf('expanded') === -1) {
        container.className += ' expanded';
      }
    } else {
      container.className = container.className.replace(/\bexpanded\b/, '');
    }
  }
  try { updateRoundedCorners(); } catch (err) {}
}

function handleItemClick(event, certId) {
  if (event && event.preventDefault) {
    event.preventDefault();
  } else if (window.event) {
    window.event.returnValue = false;
  }
  toggleCard(certId);
  return false;
}

function isMobileOrLegacyDevice() {
  var ua = navigator.userAgent || '';
  // Check iOS
  if (/iPad|iPhone|iPod/.test(ua)) {
    return true;
  }
  // Check Android < 9
  var androidMatch = ua.match(/Android\s+([0-9\.]+)/);
  if (androidMatch) {
    var version = parseFloat(androidMatch[1]);
    if (!isNaN(version) && version < 9.0) {
      return true;
    }
  }
  // Check narrow screen
  var width = window.innerWidth || document.documentElement.clientWidth || document.body.clientWidth || 0;
  if (width > 0 && width < 768) {
    return true;
  }
  return false;
}

function updateRoundedCorners() {
  if (!document.getElementsByClassName) { return; }

  var groups = document.getElementsByClassName('ios-group');
  var i, j;
  for (i = 0; i < groups.length; i++) {
    var group = groups[i];
    if (group.className.indexOf('rounded') === -1) { continue; }

    var children = [];
    var listContainer = document.getElementById('certList');

    // Check if the current group is the list group
    var isListGroup = false;
    var current = listContainer;
    while (current) {
      if (current === group) {
        isListGroup = true;
        break;
      }
      current = current.parentNode;
    }

    if (isListGroup && listContainer) {
      var items = listContainer.getElementsByClassName('ios-list-item-container');
      for (j = 0; j < items.length; j++) {
        children.push(items[j]);
      }
    } else {
      var cells = group.getElementsByClassName('ios-cell');
      for (j = 0; j < cells.length; j++) {
        if (cells[j].parentNode === group) {
          children.push(cells[j]);
        }
      }
    }

    var firstVisible = null;
    var lastVisible = null;

    for (j = 0; j < children.length; j++) {
      var child = children[j];
      child.className = child.className.replace(/\bios-first-visible\b/g, '').replace(/\bios-last-visible\b/g, '').replace(/^\s+|\s+$/g, '').replace(/\s+/g, ' ');

      var isVisible = child.style.display !== 'none';
      if (isVisible) {
        if (!firstVisible) {
          firstVisible = child;
        }
        lastVisible = child;
      }
    }

    if (firstVisible) {
      if (firstVisible.className.indexOf('ios-first-visible') === -1) {
        firstVisible.className += ' ios-first-visible';
      }
    }
    if (lastVisible) {
      if (lastVisible.className.indexOf('ios-last-visible') === -1) {
        lastVisible.className += ' ios-last-visible';
      }
    }
  }
}

function updateDownloadButtons() {
  var isMobile = isMobileOrLegacyDevice();
  var buttons = document.getElementsByClassName('cert-card-btn');
  var i;
  for (i = 0; i < buttons.length; i++) {
    buttons[i].textContent = isMobile ? '安装' : '下载';
  }
}

(function() {
  if (document.body) {
    document.body.className = document.body.className.replace(/\bno-js\b/, '') + ' js-enabled';
  }

  var yearSpan = document.getElementById('copyright-year');
  if (yearSpan) {
    yearSpan.innerHTML = String((new Date()).getFullYear());
  }

  var chainResults = document.getElementById('chainResults');
  if (chainResults) {
    chainResults.style.display = 'none';
  }
  
  updateDownloadButtons();
  try { updateRoundedCorners(); } catch (err) {}
})();
