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
const GSB_API_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
const BUILT_IN_API_KEY = "AIzaSyC-7Q6moS7I5d3p8eAY1ewOcJMHvILYAHw";

// --- Optimization 1: Trusted domain whitelist ---
const TRUSTED_DOMAINS = new Set([
  "google.com","googleapis.com","gstatic.com","googleusercontent.com","gmail.com",
  "youtube.com","youtu.be","ytimg.com","ggpht.com",
  "microsoft.com","bing.com","live.com","outlook.com","office.com","microsoft365.com",
  "apple.com","icloud.com",
  "amazon.com","amazonaws.com","cloudfront.net",
  "facebook.com","instagram.com","fbcdn.net","meta.com",
  "twitter.com","x.com","twimg.com",
  "linkedin.com","licdn.com",
  "wikipedia.org","wikimedia.org",
  "reddit.com","redd.it","redditstatic.com",
  "netflix.com","nflxso.net",
  "spotify.com","scdn.co",
  "github.com","githubusercontent.com","githubassets.com",
  "stackoverflow.com","sstatic.net",
  "cloudflare.com","cloudflareinsights.com",
  "akamaized.net","akamai.com",
  "whatsapp.com","whatsapp.net",
  "zoom.us","zoomgov.com",
  "dropbox.com","dropboxstatic.com",
  "adobe.com","typekit.net",
  "paypal.com","paypalobjects.com",
  "stripe.com","stripecdn.com",
  "yahoo.com","yimg.com",
  "opera.com","operacdn.com",
]);

function isTrustedDomain(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    for (const trusted of TRUSTED_DOMAINS) {
      if (host === trusted || host.endsWith("." + trusted)) return true;
    }
  } catch {}
  return false;
}

// --- Optimization 2: Domain result cache (1 hour TTL) ---
const CACHE_TTL_MS = 60 * 60 * 1000;
const domainCache = new Map();

function getCachedResult(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    const entry = domainCache.get(host);
    if (entry && (Date.now() - entry.timestamp) < CACHE_TTL_MS) return entry.result;
    domainCache.delete(host);
  } catch {}
  return null;
}

function setCachedResult(url, result) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    domainCache.set(host, { result, timestamp: Date.now() });
    if (domainCache.size > 500) {
      const oldest = [...domainCache.entries()].sort((a, b) => a[1].timestamp - b[1].timestamp)[0];
      domainCache.delete(oldest[0]);
    }
  } catch {}
}

// --- Optimization 3: Per-tab subframe domain dedup ---
const checkedDomainsPerTab = new Map();

async function checkGoogleSafeBrowsing(url) {
  // Check cache first — skip API call if we already know this domain's status
  const cached = getCachedResult(url);
  if (cached !== null) return cached;

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
      const threatResult = { threat: true, reason: reasonMap[threatType] || "malware" };
      setCachedResult(url, threatResult);
      return threatResult;
    }

    const safeResult = { threat: false, reason: null };
    setCachedResult(url, safeResult);
    return safeResult;
  } catch (err) {
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
      { blocklist: [], whitelist: [], enabled: true },
      resolve
    );
  });
}

// URLs temporarily allowed by "Proceed Anyway" (persisted in storage so it survives service worker sleep)
async function isAllowedOnce(url) {
  return new Promise((resolve) => {
    chrome.storage.local.get({ allowOnceList: [] }, (data) => {
      const idx = data.allowOnceList.indexOf(url);
      if (idx === -1) return resolve(false);
      // Remove it so it only works once
      const updated = data.allowOnceList.filter((u) => u !== url);
      chrome.storage.local.set({ allowOnceList: updated }, () => resolve(true));
    });
  });
}

// Track previous URL per tab for the Go Back button
const tabPrevUrl = new Map();

// URLs currently being checked to avoid double-processing
const urlsBeingChecked = new Set();

// Core check-and-block function — used by multiple event listeners
async function checkAndBlock(tabId, url, frameId) {
  // Only main frame for blocking (frameId 0), but check all frames for GSB
  const isMainFrame = (frameId === 0);

  // Skip internal pages
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://") ||
      url.startsWith("about:") || url.startsWith("data:") || url.startsWith("blob:")) return;

  // Skip trusted well-known domains entirely — no API call needed
  if (isTrustedDomain(url)) return;

  // Skip user-whitelisted domains
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    const { whitelist } = await new Promise(r => chrome.storage.local.get({ whitelist: [] }, r));
    if (whitelist.some(entry => host === entry || host.endsWith("." + entry))) return;
  } catch {}

  // For subframes: skip if we already checked this domain for this tab
  if (!isMainFrame) {
    try {
      const host = new URL(url).hostname.replace(/^www\./, "");
      if (!checkedDomainsPerTab.has(tabId)) checkedDomainsPerTab.set(tabId, new Set());
      const checked = checkedDomainsPerTab.get(tabId);
      if (checked.has(host)) return;
      checked.add(host);
    } catch {}
  }

  // Handle allow-once flag
  if (url.includes("__shield_allow=1")) {
    if (isMainFrame) {
      tabPrevUrl.delete(tabId);
      const cleanUrl = url.replace(/[?&]__shield_allow=1/, "").replace(/\?$/, "");
      if (cleanUrl !== url) chrome.tabs.update(tabId, { url: cleanUrl });
    }
    return;
  }

  // Avoid re-checking same URL simultaneously
  const checkKey = tabId + "|" + url;
  if (urlsBeingChecked.has(checkKey)) return;
  urlsBeingChecked.add(checkKey);

  try {
    const { blocklist, enabled } = await getStorage();
    if (!enabled) return;

    if (await isAllowedOnce(url)) {
      tabPrevUrl.delete(tabId);
      return;
    }

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
      const prevUrl = tabPrevUrl.get(tabId) || "";
      const blockPage = chrome.runtime.getURL(
        `blocked.html?url=${encodeURIComponent(url)}&reason=${reason}&prev=${encodeURIComponent(prevUrl)}`
      );
      chrome.tabs.update(tabId, { url: blockPage });
    } else if (shouldBlock && !isMainFrame) {
      // Malicious subframe/iframe — block the whole tab
      chrome.storage.local.get({ totalBlocked: 0 }, ({ totalBlocked }) => {
        chrome.storage.local.set({ totalBlocked: totalBlocked + 1 });
      });
      const prevUrl = tabPrevUrl.get(tabId) || "";
      const blockPage = chrome.runtime.getURL(
        `blocked.html?url=${encodeURIComponent(url)}&reason=${reason}&prev=${encodeURIComponent(prevUrl)}`
      );
      chrome.tabs.update(tabId, { url: blockPage });
    } else if (!shouldBlock && isMainFrame) {
      tabPrevUrl.set(tabId, url);
    }
  } finally {
    urlsBeingChecked.delete(checkKey);
  }
}

// 1. Catch navigation before it starts (main frame + subframes)
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
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

// Clean up tab tracking when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabPrevUrl.delete(tabId);
  checkedDomainsPerTab.delete(tabId);
});

// Reset per-tab subframe dedup on new main-frame navigation
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) checkedDomainsPerTab.delete(details.tabId);
}, { urls: ["<all_urls>"] });

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
  if (msg.type === "GET_STATUS") {
    chrome.storage.local.get(
      { blocklist: [], whitelist: [], enabled: true, safeBrowsingApiKey: "", totalBlocked: 0 },
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

  if (msg.type === "ADD_WHITELIST") {
    chrome.storage.local.get({ whitelist: [] }, ({ whitelist }) => {
      const host = normalizeHost(msg.site);
      if (!host || whitelist.includes(host)) {
        sendResponse({ ok: false, error: "Already exists or invalid" });
        return;
      }
      const updated = [...whitelist, host];
      chrome.storage.local.set({ whitelist: updated }, () =>
        sendResponse({ ok: true, whitelist: updated })
      );
    });
    return true;
  }

  if (msg.type === "REMOVE_WHITELIST") {
    chrome.storage.local.get({ whitelist: [] }, ({ whitelist }) => {
      const updated = whitelist.filter(s => s !== msg.site);
      chrome.storage.local.set({ whitelist: updated }, () =>
        sendResponse({ ok: true, whitelist: updated })
      );
    });
    return true;
  }

  if (msg.type === "CHECK_PHISHING") {
    sendResponse({ isPhishing: isPhishingUrl(msg.url) });
    return true;
  }
});
