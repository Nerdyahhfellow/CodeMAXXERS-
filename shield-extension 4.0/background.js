// Shield – Background Service Worker

const PHISHING_PATTERNS = [
  // Lookalike domains / common phishing signals
  /paypa1\.com/i,
  /paypall\./i,
  /appleid-verify\./i,
  /apple-id-login\./i,
  /secure-bankofamerica\./i,
  /bankofamerica-secure\./i,
  /amazon-security-alert\./i,
  /netflix-billing-update\./i,
  /microsoft-alert\./i,
  /google-security-alert\./i,
  /irs-refund\./i,
  /login-facebook\./i,
  /facebook-login-secure\./i,
  /instagram-verify\./i,
  /wellsfargo-secure\./i,
  /chase-verify\./i,
  /account-verify-secure\./i,
  // Suspicious URL patterns
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/.*login/i,
  /free-gift-claim\./i,
  /you-have-won\./i,
  /prize-claim\./i,
  /click-here-now\./i,
];

// Check if URL matches any phishing pattern
function isPhishingUrl(url) {
  return PHISHING_PATTERNS.some((pattern) => pattern.test(url));
}

// --- Google Safe Browsing Integration ---
// Checks a URL against Google's real-time threat database.
// Covers: malware, phishing, unwanted software, social engineering.
const GSB_API_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

const BUILT_IN_API_KEY = "AIzaSyC-7Q6moS7I5d3p8eAY1ewOcJMHvILYAHw";

async function checkGoogleSafeBrowsing(url) {
  const { safeBrowsingApiKey } = await new Promise((resolve) =>
    chrome.storage.local.get({ safeBrowsingApiKey: "" }, resolve)
  );

  const apiKey = safeBrowsingApiKey || BUILT_IN_API_KEY;

  try {
    const response = await fetch(`${GSB_API_ENDPOINT}?key=${apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "shield-extension", clientVersion: "1.1.0" },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL", "EXECUTABLE"],
          threatEntries: [{ url }, { url: url.split("?")[0] }],
        },
      }),
    });

    if (!response.ok) return { threat: false, reason: null };

    const data = await response.json();

    if (data.matches && data.matches.length > 0) {
      const threatType = data.matches[0].threatType;
      // Map GSB threat type to a friendly reason string
      const reasonMap = {
        MALWARE: "malware",
        SOCIAL_ENGINEERING: "phishing",
        UNWANTED_SOFTWARE: "unwanted-software",
        POTENTIALLY_HARMFUL_APPLICATION: "harmful-app",
      };
      return { threat: true, reason: reasonMap[threatType] || "malware" };
    }

    return { threat: false, reason: null };
  } catch (err) {
    // Network error or API issue — fail open (don't block)
    console.warn("[Shield] Safe Browsing API error:", err);
    return { threat: false, reason: null };
  }
}

// Normalize a hostname (strip www.)
function normalizeHost(input) {
  try {
    let val = input.trim().toLowerCase();
    if (!val.startsWith("http")) val = "https://" + val;
    const url = new URL(val);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return input.trim().toLowerCase().replace(/^www\./, "");
  }
}

// Get stored data
async function getStorage() {
  return new Promise((resolve) => {
    chrome.storage.local.get(
      { blocklist: [], enabled: true },
      resolve
    );
  });
}

// Proceed-anyway whitelist — keyed by tabId, stores expiry timestamp
// Using chrome.storage.session so it survives service worker sleep but not browser restart
// Falls back to in-memory map if session storage unavailable
const proceedTabExpiry = new Map(); // tabId -> expiry ms

function allowTabProceed(tabId) {
  const expiry = Date.now() + 10000; // 10 seconds — plenty of time
  proceedTabExpiry.set(tabId, expiry);
  console.log("[Shield] allowTabProceed: tabId", tabId, "allowed until", new Date(expiry).toISOString());
}

function isTabProceeded(tabId) {
  const expiry = proceedTabExpiry.get(tabId);
  if (!expiry) return false;
  if (Date.now() < expiry) {
    console.log("[Shield] isTabProceeded: tabId", tabId, "IS in proceed list");
    return true;
  }
  proceedTabExpiry.delete(tabId);
  return false;
}

// Track previous URL per tab for the Go Back button
// Stores { current, prev } so we always know where the user came from
const tabUrlHistory = new Map();

function recordNavigation(tabId, url) {
  if (!url || url.startsWith("chrome") || url.startsWith("about:") ||
      url.startsWith("data:") || url.startsWith("blob:") || url.includes("blocked.html")) return;
  const existing = tabUrlHistory.get(tabId) || { current: "", prev: "" };
  if (url !== existing.current) {
    tabUrlHistory.set(tabId, { current: url, prev: existing.current });
  }
}

function getPrevUrl(tabId) {
  return (tabUrlHistory.get(tabId) || {}).prev || "";
}

// URLs currently being checked to avoid double-processing
const urlsBeingChecked = new Set();

// Core check-and-block function — used by multiple event listeners
async function checkAndBlock(tabId, url, frameId) {
  // Only main frame for blocking (frameId 0), but check all frames for GSB
  const isMainFrame = (frameId === 0);

  // Skip internal pages
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://") ||
      url.startsWith("about:") || url.startsWith("data:") || url.startsWith("blob:")) return;



  // Check proceed whitelist FIRST — before dedup or any other checks
  if (isTabProceeded(tabId)) {
    console.log("[Shield] checkAndBlock: tab", tabId, "is in proceed list, skipping", url);
    return;
  }

  // Avoid re-checking same URL simultaneously
  const checkKey = tabId + "|" + url;
  if (urlsBeingChecked.has(checkKey)) return;
  urlsBeingChecked.add(checkKey);

  try {
    const { blocklist, enabled } = await getStorage();
    if (!enabled) return;

    let shouldBlock = false;
    let reason = "";

    // 1. Custom blocklist (main frame only)
    if (isMainFrame) {
      try {
        const urlObj = new URL(url);
        const host = urlObj.hostname.replace(/^www\./, "");
        if (blocklist.some(entry => host === normalizeHost(entry) || host.endsWith("." + normalizeHost(entry)))) {
          shouldBlock = true;
          reason = "blocklist";
        }
      } catch {}
    }

    // 2. Local phishing patterns
    if (!shouldBlock && isPhishingUrl(url)) {
      shouldBlock = true;
      reason = "phishing";
    }

    // 3. Google Safe Browsing — check every URL including subframes and redirects
    if (!shouldBlock) {
      const gsbResult = await checkGoogleSafeBrowsing(url);
      if (gsbResult.threat) {
        shouldBlock = true;
        reason = gsbResult.reason;
      }
    }

    if (shouldBlock && isMainFrame) {
      chrome.storage.local.get({ totalBlocked: 0 }, ({ totalBlocked }) => {
        chrome.storage.local.set({ totalBlocked: totalBlocked + 1 });
      });
      const prevUrl = getPrevUrl(tabId);
      const blockPage = chrome.runtime.getURL(
        `blocked.html?url=${encodeURIComponent(url)}&reason=${reason}&prev=${encodeURIComponent(prevUrl)}`
      );
      chrome.tabs.update(tabId, { url: blockPage });
    } else if (shouldBlock && !isMainFrame) {
      // Malicious subframe/iframe — block the whole tab
      chrome.storage.local.get({ totalBlocked: 0 }, ({ totalBlocked }) => {
        chrome.storage.local.set({ totalBlocked: totalBlocked + 1 });
      });
      const prevUrl = getPrevUrl(tabId);
      // For subframe blocks, pass the tab's current main URL as the "proceed" target
      // and the subresource URL separately so the UI can show what was detected
      chrome.tabs.get(tabId, (tab) => {
        if (chrome.runtime.lastError) return;
        const mainUrl = (tab && tab.url) ? tab.url : prevUrl;
        const blockPage = chrome.runtime.getURL(
          `blocked.html?url=${encodeURIComponent(mainUrl)}&subresource=${encodeURIComponent(url)}&reason=${reason}&prev=${encodeURIComponent(prevUrl)}&tabId=${tabId}`
        );
        chrome.tabs.update(tabId, { url: blockPage });
      });
    }
  } finally {
    urlsBeingChecked.delete(checkKey);
  }
}

// 1. Catch navigation before it starts (main frame + subframes)
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Record the CURRENT page as "prev" before we navigate away from it.
  // We do this here, before checkAndBlock, so even if the new page gets blocked
  // we still know where the user was.
  if (details.frameId === 0) {
    chrome.tabs.get(details.tabId, (tab) => {
      if (chrome.runtime.lastError) return;
      if (tab && tab.url) recordNavigation(details.tabId, tab.url);
    });
  }
  checkAndBlock(details.tabId, details.url, details.frameId);
});

// 2. Catch AFTER redirects are resolved — this catches redirect chains
chrome.webNavigation.onCommitted.addListener((details) => {
  // Only re-check if this was a redirect (not the original navigation, already caught above)
  if (details.transitionQualifiers && details.transitionQualifiers.includes("server_redirect")) {
    checkAndBlock(details.tabId, details.url, details.frameId);
  }
});

// 3. Catch history.pushState / client-side navigation (SPAs)
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId === 0) {
    checkAndBlock(details.tabId, details.url, details.frameId);
  }
});

// Clean up tab history when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabUrlHistory.delete(tabId);
});

// --- Download Protection ---
// Intercept downloads and check the source URL against Safe Browsing
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const { enabled } = await getStorage();
  if (!enabled) return;

  const downloadUrl = downloadItem.url || downloadItem.finalUrl;
  if (!downloadUrl) return;

  // Check the download URL against GSB
  const gsbResult = await checkGoogleSafeBrowsing(downloadUrl);
  if (gsbResult.threat) {
    // Cancel the download immediately
    chrome.downloads.cancel(downloadItem.id, () => {
      chrome.downloads.erase({ id: downloadItem.id });
    });

    // Increment blocked counter
    chrome.storage.local.get({ totalBlocked: 0 }, ({ totalBlocked }) => {
      chrome.storage.local.set({ totalBlocked: totalBlocked + 1 });
    });

    // Open block page in the active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        const blockPage = chrome.runtime.getURL(
          `blocked.html?url=${encodeURIComponent(downloadUrl)}&reason=download`
        );
        chrome.tabs.update(tabs[0].id, { url: blockPage });
      }
    });
  }
});

// Message handler for popup
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "PROCEED_ANYWAY") {
    const url = msg.url;
    const tabId = msg.tabId || _sender.tab.id;
    // 1. Whitelist the tab for 10s so all nav events pass through
    allowTabProceed(tabId);
    // 2. Clear any pending dedup keys for this tab so urlsBeingChecked doesn't block it
    for (const key of urlsBeingChecked) {
      if (key.startsWith(tabId + "|")) urlsBeingChecked.delete(key);
    }
    console.log("[Shield] PROCEED_ANYWAY: navigating tabId", tabId, "to", url);
    chrome.tabs.update(tabId, { url: url });
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === "GO_BACK") {
    // Go back 2: skip blocked.html AND the malicious site
    chrome.tabs.goBack(_sender.tab.id, () => {
      if (chrome.runtime.lastError) return;
      setTimeout(() => chrome.tabs.goBack(_sender.tab.id), 100);
    });
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === "GET_STATUS") {
    chrome.storage.local.get(
      { blocklist: [], enabled: true, safeBrowsingApiKey: "", totalBlocked: 0 },
      sendResponse
    );
    return true;
  }

  if (msg.type === "SET_ENABLED") {
    chrome.storage.local.set({ enabled: msg.value }, () => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === "SET_API_KEY") {
    chrome.storage.local.set({ safeBrowsingApiKey: msg.key }, () => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === "ADD_SITE") {
    getStorage().then(({ blocklist }) => {
      const host = normalizeHost(msg.site);
      if (!host || blocklist.includes(host)) {
        sendResponse({ ok: false, error: "Already exists or invalid" });
        return;
      }
      const updated = [...blocklist, host];
      chrome.storage.local.set({ blocklist: updated }, () =>
        sendResponse({ ok: true, blocklist: updated })
      );
    });
    return true;
  }

  if (msg.type === "REMOVE_SITE") {
    getStorage().then(({ blocklist }) => {
      const updated = blocklist.filter((s) => s !== msg.site);
      chrome.storage.local.set({ blocklist: updated }, () =>
        sendResponse({ ok: true, blocklist: updated })
      );
    });
    return true;
  }

  if (msg.type === "CHECK_PHISHING") {
    sendResponse({ isPhishing: isPhishingUrl(msg.url) });
    return true;
  }

  // New: scan a link URL for badge display in content script
  if (msg.type === "SCAN_LINK") {
    const url = msg.url;
    const localUnsafe = isPhishingUrl(url);
    if (localUnsafe) {
      sendResponse({ unsafe: true, threats: [{ label: 'Phishing URL', type: 'phishing' }] });
      return true;
    }
    checkGoogleSafeBrowsing(url).then(gsbResult => {
      if (gsbResult.threat) {
        const labelMap = {
          malware: 'Malware',
          phishing: 'Phishing',
          'unwanted-software': 'Unwanted Software',
          'harmful-app': 'Harmful Application',
        };
        sendResponse({
          unsafe: true,
          threats: [{ label: labelMap[gsbResult.reason] || 'Threat Detected', type: gsbResult.reason }]
        });
      } else {
        sendResponse({ unsafe: false, threats: [] });
      }
    }).catch(() => sendResponse({ unsafe: false, threats: [] }));
    return true; // async
  }
});
