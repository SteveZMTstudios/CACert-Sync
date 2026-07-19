var currentLang = 'zh';
var lastUpdatedVal = '';
var certCountVal = '';

function initLang() {
  // Extract dynamic values on load
  var luCell = document.getElementById('lastUpdatedCell');
  if (luCell) {
    var text = luCell.textContent || luCell.innerText || '';
    var match = text.match(/最后更新日期：\s*(.+)/);
    if (match) { lastUpdatedVal = match[1]; }
  }

  var ccCell = document.getElementById('certCountCell');
  if (ccCell) {
    var text = ccCell.textContent || ccCell.innerText || '';
    var match = text.match(/当前包含\s*(\d+)\s*个证书/);
    if (match) { certCountVal = match[1]; }
  }

  // Load language choice
  var saved = null;
  try {
    saved = localStorage.getItem('lang');
  } catch (e) { }

  if (!saved) {
    var navLang = navigator.language || navigator.userLanguage || '';
    if (navLang.toLowerCase().indexOf('en') === 0) {
      saved = 'en';
    } else {
      saved = 'zh';
    }
  }

  setLanguage(saved);

  // Bind mutation observer to dynamically update check results
  var resultEl = document.getElementById('chainResults');
  if (resultEl && typeof MutationObserver !== 'undefined') {
    var observer = new MutationObserver(function () {
      observer.disconnect();
      translateChainResults(currentLang);
      observer.observe(resultEl, { childList: true, subtree: true });
    });
    observer.observe(resultEl, { childList: true, subtree: true });
  }
}

function setLanguage(lang) {
  currentLang = lang;
  try {
    localStorage.setItem('lang', lang);
  } catch (e) { }

  var isEn = (lang === 'en');

  // Update nav button text
  var btn = document.getElementById('langSwitchBtn');
  if (btn) {
    btn.textContent = isEn ? '简体中文' : 'English';
  }

  // Translate static UI elements
  updateText('pageNavTitle', isEn ? 'Trusted CA Store' : '可信CA证书库');
  updateText('heroTitle', isEn ? 'Certificate Settings' : '证书管理');
  updateText('statusHeader', isEn ? 'Status' : '状态');
  updateText('downloadHeader', isEn ? 'Certificate Bundle Downloads' : '证书聚合下载');
  updateText('chainHeader', isEn ? 'Certificate Chain Diagnostics' : '证书链检测');
  updateText('searchHeader', isEn ? 'Search Certificates' : '搜索证书');
  updateText('listHeader', isEn ? 'Downloadable Certificates' : '可下载证书');

  updateText('packLabel', isEn ? 'Combined Certificate Bundles:' : '聚合证书包：');
  updateText('winLabel', isEn ? 'Windows Trusted Root List:' : 'Windows 受信任根列表：');
  updateText('mozLabel', isEn ? 'Mozilla Trusted Root List:' : 'Mozilla 受信任根列表：');

  updateText('btnDownloadPem', isEn ? 'Download PEM' : '下载 PEM');
  updateText('btnDownloadCrt', isEn ? 'Download CRT' : '下载 CRT');
  updateText('btnDownloadP12', isEn ? 'Download P12' : '下载 P12');
  updateText('btnDownloadDer', isEn ? 'Download DER' : '下载 DER');
  updateText('btnDownloadWin', isEn ? 'Download authrootstl.cab' : '下载 authrootstl.cab');
  updateText('btnDownloadMoz', isEn ? 'Download Mozilla CA Certificate (PEM)' : '下载 Mozilla CA 证书（PEM）');

  updateText('btnCheckChain', isEn ? 'Check' : '检测');
  updateText('btnResetChain', isEn ? 'Reset' : '重置');

  // Input placeholders
  var urlInput = document.getElementById('urlInput');
  if (urlInput) {
    urlInput.placeholder = isEn ? 'e.g. https://example.com' : '例如: https://example.com';
  }
  var searchInput = document.getElementById('searchInput');
  if (searchInput) {
    searchInput.placeholder = isEn ? 'Search certificate name, issuer, validity...' : '搜索证书名称、颁发者、有效期...';
  }

  // Hero Descriptions
  var heroDesc1 = document.getElementById('heroDesc1');
  if (heroDesc1) {
    heroDesc1.textContent = isEn
      ? 'This repository aggregates trusted Root CA certificates from Debian repositories and Mozilla trust stores, suitable for updating legacy browsers and system certificate stores.'
      : '此处收集来自 Debian Repo 和 Mozilla PEM 证书链的根证书颁发机构证书，可用于旧式浏览器和系统证书库更新。';
  }

  var heroDesc2 = document.getElementById('heroDesc2');
  if (heroDesc2) {
    if (isEn) {
      heroDesc2.innerHTML = 'The certificate database is refreshed annually from multiple upstreams. Please star us on our <a href="https://github.com/stevezmtstudios/CACert-Sync" target="_blank" id="heroGithubLink">GitHub Repository</a>.';
    } else {
      heroDesc2.innerHTML = '证书库每年从多个上游刷新，请在 <a href="https://github.com/stevezmtstudios/CACert-Sync" target="_blank" id="heroGithubLink">GitHub 仓库</a>上给我们星标。';
    }
  }

  var luCell = document.getElementById('lastUpdatedCell');
  if (luCell) {
    // 提取日期（假设格式固定为“最后更新日期：YYYY-MM-DD”或“Last Updated: YYYY-MM-DD”）
    var dateMatch = luCell.textContent.match(/\d{4}-\d{2}-\d{2}/);
    var dateStr = dateMatch ? dateMatch[0] : '未知日期';
    luCell.textContent = isEn ? ('Last Updated: ' + dateStr) : ('最后更新日期：' + dateStr);
  }

  var ccCell = document.getElementById('certCountCell');
  if (ccCell) {
    // 提取数字
    var numMatch = ccCell.textContent.match(/\d+/);
    var count = numMatch ? numMatch[0] : '?';
    ccCell.textContent = isEn ? ('Currently containing ' + count + ' certificates') : ('当前包含 ' + count + ' 个证书');
  }

  // Translate Footer
  translateFooter(lang);

  // Translate dynamically rendered cards & toggle labels
  translateCardDetails(lang);

  // Translate check results if currently visible
  translateChainResults(lang);

  // Update download/install buttons
  if (typeof updateDownloadButtonsLang === 'function') {
    updateDownloadButtonsLang();
  }
}

function toggleLanguage() {
  if (currentLang === 'zh') {
    setLanguage('en');
  } else {
    setLanguage('zh');
  }
}

function updateText(id, text) {
  var el = document.getElementById(id);
  if (el) {
    el.textContent = text;
  }
}

function translateFooter(lang) {
  var footerEl = document.getElementById('pageFooter');
  if (!footerEl) { return; }
  var yearSpan = document.getElementById('copyright-year');
  var year = yearSpan ? (yearSpan.textContent || yearSpan.innerText || '2026') : '2026';

  if (lang === 'en') {
    footerEl.innerHTML = 'This project only aggregates and stores publicly available CA certificates and makes no guarantees regarding their currency or authenticity.<br>Importing CA certificates of unknown origin may expose your device to risks, including but not limited to network traffic interception.<br>Page design &copy; <span id="copyright-year">' + year + '</span> SteveZMT';
  } else {
    footerEl.innerHTML = '该项目仅收集和存储来自网络上公开的CA证书，不对其即时性和真实性做出保证。<br>导入未知来源的CA证书可能会使您的设备陷入风险，包括但不限于网络流量被监视等。<br>页面设计版权所有 &copy; <span id="copyright-year">' + year + '</span> SteveZMT';
  }
}

function translateChainResults(lang) {
  var resultEl = document.getElementById('chainResults');
  if (!resultEl || resultEl.style.display === 'none') { return; }

  var html = resultEl.innerHTML || '';
  if (lang === 'en') {
    html = html.replace('正在查询证书链，这可能需要几分钟...', 'Querying certificate chain, this may take a few minutes...');
    html = html.replace('已筛选出可能需要安装的根证书：', 'Filtered root CA that may need to be installed: ');
    html = html.replace('未在本库中找到匹配的根证书：', 'No matching root CA found in this store: ');
    html = html.replace('检测失败：', 'Check failed: ');
    html = html.replace('未知', 'Unknown');
    html = html.replace('。建议稍后重试或在桌面环境通过 openssl s_client 检查。', '. Try again later or inspect via "openssl s_client" on a desktop.');
  } else {
    html = html.replace('Querying certificate chain, this may take a few minutes...', '正在查询证书链，这可能需要几分钟...');
    html = html.replace('Filtered root CA that may need to be installed: ', '已筛选出可能需要安装的根证书：');
    html = html.replace('No matching root CA found in this store: ', '未在本库中找到匹配的根证书：');
    html = html.replace('Check failed: ', '检测失败：');
    html = html.replace('Unknown', '未知');
    html = html.replace('. Try again later or inspect via "openssl s_client" on a desktop.', '。建议稍后重试或在桌面环境通过 openssl s_client 检查。');
  }
  resultEl.innerHTML = html;
}

function translateCardDetails(lang) {
  var labels = document.getElementsByClassName('meta-label');
  var values = document.getElementsByClassName('meta-value');
  var i;

  var labelMap = {
    '包含': { 'en': 'Includes', 'zh': '包含' },
    '有效期至': { 'en': 'Expires on', 'zh': '有效期至' },
    '文件名': { 'en': 'Filename', 'zh': '文件名' },
    '版本': { 'en': 'Version', 'zh': '版本' },
    '序列号': { 'en': 'Serial Number', 'zh': '序列号' },
    '签名算法': { 'en': 'Signature Algorithm', 'zh': '签名算法' },
    '颁发者': { 'en': 'Issuer', 'zh': '颁发者' },
    '有效期': { 'en': 'Validity', 'zh': '有效期' },
    '使用者': { 'en': 'Subject', 'zh': '使用者' },
    '公钥': { 'en': 'Public Key', 'zh': '公钥' },
    '密钥用途': { 'en': 'Key Usage', 'zh': '密钥用途' },
    '基本约束': { 'en': 'Basic Constraints', 'zh': '基本约束' },
    'SHA-1指纹': { 'en': 'SHA-1 Fingerprint', 'zh': 'SHA-1指纹' },
    'SHA-256指纹': { 'en': 'SHA-256 Fingerprint', 'zh': 'SHA-256指纹' },
    'MD5指纹': { 'en': 'MD5 Fingerprint', 'zh': 'MD5指纹' }
  };

  var valueMap = {
    '根证书': { 'en': 'Root Certificate', 'zh': '根证书' },
    '无': { 'en': 'None', 'zh': '无' },
    '未知': { 'en': 'Unknown', 'zh': '未知' }
  };

  for (i = 0; i < labels.length; i++) {
    var txt = labels[i].textContent || labels[i].innerText || '';
    txt = txt.replace(/^\s+|\s+$/g, '');
    for (var zhKey in labelMap) {
      if (txt === zhKey || txt === labelMap[zhKey]['en'] || txt === labelMap[zhKey]['zh']) {
        labels[i].textContent = labelMap[zhKey][lang];
        break;
      }
    }
  }

  for (i = 0; i < values.length; i++) {
    var txt = values[i].textContent || values[i].innerText || '';
    txt = txt.replace(/^\s+|\s+$/g, '');
    for (var zhKey in valueMap) {
      if (txt === zhKey || txt === valueMap[zhKey]['en'] || txt === valueMap[zhKey]['zh']) {
        values[i].textContent = valueMap[zhKey][lang];
        break;
      }
    }
  }

  // var badges = document.getElementsByClassName('trusted-badge');
  // for (i = 0; i < badges.length; i++) {
  //   if (lang === 'en') {
  //     badges[i].innerHTML = '&#10003; Trusted';
  //   } else {
  //     badges[i].innerHTML = '&#10003; 可信';
  //   }
  // }
  var trusted_text = document.getElementsByClassName('trusted-text');
  for (i = 0; i < trusted_text.length; i++) {
    if (lang === 'en') {
      trusted_text[i].textContent = 'Trusted';
    } else {
      trusted_text[i].textContent = '可信';
    }
  }

  var moreTitles = document.getElementsByClassName('more-toggle-title');
  for (i = 0; i < moreTitles.length; i++) {
    if (lang === 'en') {
      moreTitles[i].textContent = 'More Details';
    } else {
      moreTitles[i].textContent = '更多详细信息';
    }
  }
}

function updateDownloadButtonsLang() {
  var isMobile = false;
  if (typeof isMobileOrLegacyDevice === 'function') {
    isMobile = isMobileOrLegacyDevice();
  }
  var buttons = document.getElementsByClassName('cert-card-btn');
  var isEn = (currentLang === 'en');
  var i;
  for (i = 0; i < buttons.length; i++) {
    if (isEn) {
      buttons[i].textContent = isMobile ? 'Install' : 'Download';
    } else {
      buttons[i].textContent = isMobile ? '安装' : '下载';
    }
  }
}

// Run initialization
if (document.readyState === 'complete' || document.readyState === 'interactive') {
  initLang();
} else if (window.addEventListener) {
  window.addEventListener('DOMContentLoaded', initLang, false);
} else if (window.attachEvent) {
  window.attachEvent('onload', initLang);
}
