// Shield – Popup Script

let blocklist = [];
let enabled = true;

const blocklistEl = document.getElementById("blocklist");
const listCountEl = document.getElementById("list-count");
const statBlockedEl = document.getElementById("stat-blocked");
const statGsbEl = document.getElementById("stat-gsb");
const statCountEl = document.getElementById("stat-count");
const siteInput = document.getElementById("site-input");
const errorMsg = document.getElementById("error-msg");
const btnAdd = document.getElementById("btn-add");
const enabledToggle = document.getElementById("enabled-toggle");
const toggleStatus = document.getElementById("toggle-status");
const mainContent = document.getElementById("main-content");
const apiKeyInput = document.getElementById("api-key-input");
const btnSaveKey = document.getElementById("btn-save-key");
const apiStatus = document.getElementById("api-status");

// Load initial state
chrome.runtime.sendMessage({ type: "GET_STATUS" }, (res) => {
  if (!res) return;
  blocklist = res.blocklist || [];
  enabled = res.enabled !== false;
  enabledToggle.checked = enabled;
  toggleStatus.textContent = enabled ? "ON" : "OFF";

  // Show API key status
  if (res.safeBrowsingApiKey) {
    apiKeyInput.value = res.safeBrowsingApiKey;
    setApiStatus(true);
  } else {
    setApiStatus(false);
  }

  statBlockedEl.textContent = res.totalBlocked || 0;
  renderList();
  updateStats();
});

// API key status badge
function setApiStatus(active) {
  if (active) {
    apiStatus.textContent = "✓ Active";
    apiStatus.className = "api-status active";
    statGsbEl.textContent = "✓ On";
    statGsbEl.style.color = "#22c55e";
  } else {
    apiStatus.textContent = "Not configured";
    apiStatus.className = "api-status inactive";
    statGsbEl.textContent = "⚠ Off";
    statGsbEl.style.color = "#f59e0b";
  }
}

// Save API key
btnSaveKey.addEventListener("click", () => {
  const key = apiKeyInput.value.trim();
  chrome.runtime.sendMessage({ type: "SET_API_KEY", key }, (res) => {
    if (res && res.ok) {
      setApiStatus(!!key);
      btnSaveKey.textContent = "✓";
      btnSaveKey.style.color = "#22c55e";
      setTimeout(() => { btnSaveKey.textContent = "Save"; btnSaveKey.style.color = ""; }, 1500);
    }
  });
});

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

// Add site
function addSite() {
  const val = siteInput.value.trim();
  errorMsg.textContent = "";
  siteInput.classList.remove("error");

  if (!val) {
    showError("Please enter a website.");
    return;
  }

  chrome.runtime.sendMessage({ type: "ADD_SITE", site: val }, (res) => {
    if (res && res.ok) {
      blocklist = res.blocklist;
      siteInput.value = "";
      renderList();
      updateStats();
    } else {
      showError(res?.error || "Could not add site.");
    }
  });
}

btnAdd.addEventListener("click", addSite);
siteInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") addSite();
});

function showError(msg) {
  errorMsg.textContent = msg;
  siteInput.classList.add("error");
  setTimeout(() => {
    errorMsg.textContent = "";
    siteInput.classList.remove("error");
  }, 2500);
}

// Remove site
function removeSite(site) {
  chrome.runtime.sendMessage({ type: "REMOVE_SITE", site }, (res) => {
    if (res && res.ok) {
      blocklist = res.blocklist;
      renderList();
      updateStats();
    }
  });
}

// Render blocklist
function renderList() {
  listCountEl.textContent = blocklist.length;

  if (blocklist.length === 0) {
    blocklistEl.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🔓</div>
        No sites blocked yet
      </div>`;
    return;
  }

  blocklistEl.innerHTML = blocklist
    .map(
      (site) => `
    <div class="site-item">
      <div class="site-info">
        <div class="site-dot"></div>
        <span class="site-name" title="${site}">${site}</span>
      </div>
      <button class="btn-remove" data-site="${site}" title="Remove">✕</button>
    </div>`
    )
    .join("");

  blocklistEl.querySelectorAll(".btn-remove").forEach((btn) => {
    btn.addEventListener("click", () => removeSite(btn.dataset.site));
  });
}

function updateStats() {
  statCountEl.textContent = blocklist.length;
}
