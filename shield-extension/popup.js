// Shield – Popup Script

let blocklist = [];
let whitelist = [];
let enabled = true;
let activeTab = 'blocklist';

const blocklistEl    = document.getElementById("blocklist");
const whitelistEl    = document.getElementById("whitelist");
const listCountEl    = document.getElementById("list-count");
const whiteCountEl   = document.getElementById("white-count");
const statBlockedEl  = document.getElementById("stat-blocked");
const statCountEl    = document.getElementById("stat-count");
const siteInput      = document.getElementById("site-input");
const errorMsg       = document.getElementById("error-msg");
const btnAdd         = document.getElementById("btn-add");
const enabledToggle  = document.getElementById("enabled-toggle");
const toggleStatus   = document.getElementById("toggle-status");
const mainContent    = document.getElementById("main-content");
const tabBlock       = document.getElementById("tab-blocklist");
const tabWhite       = document.getElementById("tab-whitelist");
const inputLabel     = document.getElementById("input-label");

// Load initial state
chrome.runtime.sendMessage({ type: "GET_STATUS" }, (res) => {
  if (!res) return;
  blocklist = res.blocklist || [];
  whitelist = res.whitelist || [];
  enabled   = res.enabled !== false;

  enabledToggle.checked     = enabled;
  toggleStatus.textContent  = enabled ? "ON" : "OFF";
  statBlockedEl.textContent = res.totalBlocked || 0;

  renderLists();
  updateStats();
  if (!enabled) showDisabledOverlay();
});

// Tab switching
tabBlock.addEventListener("click", () => switchTab('blocklist'));
tabWhite.addEventListener("click", () => switchTab('whitelist'));

function switchTab(tab) {
  activeTab = tab;
  tabBlock.classList.toggle('tab-active',   tab === 'blocklist');
  tabWhite.classList.toggle('tab-active',   tab === 'whitelist');
  tabBlock.classList.toggle('tab-inactive', tab !== 'blocklist');
  tabWhite.classList.toggle('tab-inactive', tab !== 'whitelist');

  document.getElementById("blocklist-section").style.display = tab === 'blocklist' ? '' : 'none';
  document.getElementById("whitelist-section").style.display = tab === 'whitelist' ? '' : 'none';

  inputLabel.textContent = tab === 'blocklist' ? 'ADD SITE TO BLOCK' : 'ADD SITE TO ALLOW';
  btnAdd.textContent     = tab === 'blocklist' ? 'Block' : 'Allow';
  siteInput.placeholder  = tab === 'blocklist' ? 'e.g. example.com' : 'e.g. trusted-site.com';
  errorMsg.textContent   = '';
  siteInput.classList.remove('error');
}

// Toggle enabled
enabledToggle.addEventListener("change", () => {
  enabled = enabledToggle.checked;
  toggleStatus.textContent = enabled ? "ON" : "OFF";
  chrome.runtime.sendMessage({ type: "SET_ENABLED", value: enabled });
  if (!enabled) showDisabledOverlay(); else removeDisabledOverlay();
});

function showDisabledOverlay() {
  if (document.getElementById("disabled-overlay")) return;
  const el = document.createElement("div");
  el.className = "disabled-overlay";
  el.id = "disabled-overlay";
  el.textContent = "Protection Paused";
  mainContent.appendChild(el);
}
function removeDisabledOverlay() {
  const el = document.getElementById("disabled-overlay");
  if (el) el.remove();
}

// Add site
function addSite() {
  const val = siteInput.value.trim();
  errorMsg.textContent = "";
  siteInput.classList.remove("error");
  if (!val) { showError("Please enter a website."); return; }

  if (activeTab === 'blocklist') {
    chrome.runtime.sendMessage({ type: "ADD_SITE", site: val }, (res) => {
      if (res && res.ok) {
        blocklist = res.blocklist;
        siteInput.value = "";
        renderLists(); updateStats();
      } else { showError(res && res.error ? res.error : "Could not add site."); }
    });
  } else {
    chrome.runtime.sendMessage({ type: "ADD_WHITELIST", site: val }, (res) => {
      if (res && res.ok) {
        whitelist = res.whitelist;
        siteInput.value = "";
        renderLists(); updateStats();
      } else { showError(res && res.error ? res.error : "Could not add site."); }
    });
  }
}

btnAdd.addEventListener("click", addSite);
siteInput.addEventListener("keydown", (e) => { if (e.key === "Enter") addSite(); });

function showError(msg) {
  errorMsg.textContent = msg;
  siteInput.classList.add("error");
  setTimeout(() => { errorMsg.textContent = ""; siteInput.classList.remove("error"); }, 2500);
}

// Remove
function removeSite(site) {
  chrome.runtime.sendMessage({ type: "REMOVE_SITE", site }, (res) => {
    if (res && res.ok) { blocklist = res.blocklist; renderLists(); updateStats(); }
  });
}
function removeWhitelist(site) {
  chrome.runtime.sendMessage({ type: "REMOVE_WHITELIST", site }, (res) => {
    if (res && res.ok) { whitelist = res.whitelist; renderLists(); updateStats(); }
  });
}

// Render
function renderLists() {
  renderList(blocklistEl, listCountEl, blocklist, 'block');
  renderList(whitelistEl, whiteCountEl, whitelist, 'white');
}

function renderList(el, countEl, list, type) {
  countEl.textContent = list.length;
  if (list.length === 0) {
    el.innerHTML = '<div class="empty-state"><div class="empty-icon">' +
      (type === 'block' ? '🔓' : '✅') + '</div>' +
      (type === 'block' ? 'No sites blocked yet' : 'No sites whitelisted yet') +
      '</div>';
    return;
  }
  el.innerHTML = list.map(function(site) {
    return '<div class="site-item">' +
      '<div class="site-info">' +
        '<div class="site-dot ' + (type === 'white' ? 'dot-green' : '') + '"></div>' +
        '<span class="site-name" title="' + site + '">' + site + '</span>' +
      '</div>' +
      '<button class="btn-remove" data-site="' + site + '" data-type="' + type + '" title="Remove">✕</button>' +
    '</div>';
  }).join("");

  el.querySelectorAll(".btn-remove").forEach(function(btn) {
    btn.addEventListener("click", function() {
      if (btn.dataset.type === 'block') removeSite(btn.dataset.site);
      else removeWhitelist(btn.dataset.site);
    });
  });
}

function updateStats() {
  statCountEl.textContent = blocklist.length;
}

