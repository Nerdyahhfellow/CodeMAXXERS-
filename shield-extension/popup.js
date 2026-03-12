// Shield – Popup Script

let blocklist = [];
let whitelist = [];
let enabled = true;
let activeTab = "block"; // "block" or "allow"

const blocklistEl    = document.getElementById("blocklist");
const whitelistEl    = document.getElementById("whitelist");
const listCountEl    = document.getElementById("list-count");
const wlistCountEl   = document.getElementById("wlist-count");
const statBlockedEl  = document.getElementById("stat-blocked");
const statCountEl    = document.getElementById("stat-count");
const siteInput      = document.getElementById("site-input");
const errorMsg       = document.getElementById("error-msg");
const btnAdd         = document.getElementById("btn-add");
const enabledToggle  = document.getElementById("enabled-toggle");
const toggleStatus   = document.getElementById("toggle-status");
const mainContent    = document.getElementById("main-content");
const tabBlock       = document.getElementById("tab-block");
const tabAllow       = document.getElementById("tab-allow");
const panelBlock     = document.getElementById("panel-block");
const panelAllow     = document.getElementById("panel-allow");

// Load initial state
chrome.runtime.sendMessage({ type: "GET_STATUS" }, (res) => {
  if (!res) return;
  blocklist = res.blocklist || [];
  whitelist = res.whitelist || [];
  enabled = res.enabled !== false;
  enabledToggle.checked = enabled;
  toggleStatus.textContent = enabled ? "ON" : "OFF";
  statBlockedEl.textContent = res.totalBlocked || 0;
  renderBlocklist();
  renderWhitelist();
  updateStats();
});

// Tab switching
tabBlock.addEventListener("click", () => switchTab("block"));
tabAllow.addEventListener("click", () => switchTab("allow"));

function switchTab(tab) {
  activeTab = tab;
  tabBlock.classList.toggle("active", tab === "block");
  tabAllow.classList.toggle("active", tab === "allow");
  panelBlock.style.display = tab === "block" ? "block" : "none";
  panelAllow.style.display = tab === "allow" ? "block" : "none";
  siteInput.placeholder = tab === "block" ? "e.g. example.com" : "e.g. mybank.com";
  btnAdd.textContent = tab === "block" ? "Block" : "Allow";
  btnAdd.className = tab === "block" ? "btn-add btn-add-block" : "btn-add btn-add-allow";
  errorMsg.textContent = "";
}

// Toggle enabled
enabledToggle.addEventListener("change", () => {
  enabled = enabledToggle.checked;
  toggleStatus.textContent = enabled ? "ON" : "OFF";
  chrome.runtime.sendMessage({ type: "SET_ENABLED", value: enabled });
  const overlay = document.getElementById("disabled-overlay");
  if (!enabled) {
    if (!overlay) {
      const el = document.createElement("div");
      el.className = "disabled-overlay";
      el.id = "disabled-overlay";
      el.textContent = "Protection Paused";
      mainContent.appendChild(el);
    }
  } else {
    if (overlay) overlay.remove();
  }
});

// Add site (block or whitelist depending on active tab)
function addSite() {
  const val = siteInput.value.trim();
  errorMsg.textContent = "";
  siteInput.classList.remove("error");
  if (!val) { showError("Please enter a website."); return; }

  const msgType = activeTab === "block" ? "ADD_SITE" : "ADD_WHITELIST";
  chrome.runtime.sendMessage({ type: msgType, site: val }, (res) => {
    if (res && res.ok) {
      if (activeTab === "block") {
        blocklist = res.blocklist;
        renderBlocklist();
      } else {
        whitelist = res.whitelist;
        renderWhitelist();
      }
      siteInput.value = "";
      updateStats();
    } else {
      showError(res?.error || "Could not add site.");
    }
  });
}

btnAdd.addEventListener("click", addSite);
siteInput.addEventListener("keydown", (e) => { if (e.key === "Enter") addSite(); });

function showError(msg) {
  errorMsg.textContent = msg;
  siteInput.classList.add("error");
  setTimeout(() => { errorMsg.textContent = ""; siteInput.classList.remove("error"); }, 2500);
}

// Remove from blocklist
function removeSite(site) {
  chrome.runtime.sendMessage({ type: "REMOVE_SITE", site }, (res) => {
    if (res && res.ok) { blocklist = res.blocklist; renderBlocklist(); updateStats(); }
  });
}

// Remove from whitelist
function removeWhitesite(site) {
  chrome.runtime.sendMessage({ type: "REMOVE_WHITELIST", site }, (res) => {
    if (res && res.ok) { whitelist = res.whitelist; renderWhitelist(); }
  });
}

// Render blocklist
function renderBlocklist() {
  listCountEl.textContent = blocklist.length;
  if (blocklist.length === 0) {
    blocklistEl.innerHTML = `<div class="empty-state"><div class="empty-icon">🔓</div>No sites blocked yet</div>`;
    return;
  }
  blocklistEl.innerHTML = blocklist.map(site => `
    <div class="site-item">
      <div class="site-info"><div class="site-dot" style="background:#ef4444"></div>
        <span class="site-name" title="${site}">${site}</span></div>
      <button class="btn-remove" data-site="${site}" title="Remove">✕</button>
    </div>`).join("");
  blocklistEl.querySelectorAll(".btn-remove").forEach(btn =>
    btn.addEventListener("click", () => removeSite(btn.dataset.site)));
}

// Render whitelist
function renderWhitelist() {
  wlistCountEl.textContent = whitelist.length;
  if (whitelist.length === 0) {
    whitelistEl.innerHTML = `<div class="empty-state"><div class="empty-icon">✅</div>No sites whitelisted yet</div>`;
    return;
  }
  whitelistEl.innerHTML = whitelist.map(site => `
    <div class="site-item">
      <div class="site-info"><div class="site-dot" style="background:#22c55e"></div>
        <span class="site-name" title="${site}">${site}</span></div>
      <button class="btn-remove" data-site="${site}" title="Remove">✕</button>
    </div>`).join("");
  whitelistEl.querySelectorAll(".btn-remove").forEach(btn =>
    btn.addEventListener("click", () => removeWhitesite(btn.dataset.site)));
}

function updateStats() {
  statCountEl.textContent = blocklist.length;
}
