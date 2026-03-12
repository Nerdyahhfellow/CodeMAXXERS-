// Shield – Content Script
// Scans links on hover for phishing patterns and homoglyph/unicode spoofing
// + inline safe/unsafe badges on all links (Google Search & general pages)

(() => {
  // ─── Homoglyph Map ───────────────────────────────────────────────────────────
  const HOMOGLYPH_MAP = {
    // Cyrillic lookalikes
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H',
    'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
    // Greek lookalikes
    'ο': 'o', 'ρ': 'p', 'ν': 'v', 'υ': 'u', 'κ': 'k', 'τ': 't',
    'ω': 'w', 'ι': 'i', 'η': 'n', 'α': 'a', 'β': 'b', 'γ': 'y',
    // Latin extended
    'ā': 'a', 'á': 'a', 'à': 'a', 'ä': 'a', 'â': 'a', 'ã': 'a',
    'ē': 'e', 'é': 'e', 'è': 'e', 'ë': 'e', 'ê': 'e',
    'ī': 'i', 'í': 'i', 'ì': 'i', 'ï': 'i', 'î': 'i',
    'ō': 'o', 'ó': 'o', 'ò': 'o', 'ö': 'o', 'ô': 'o', 'õ': 'o',
    'ū': 'u', 'ú': 'u', 'ù': 'u', 'ü': 'u', 'û': 'u',
    'ñ': 'n', 'ń': 'n', 'ç': 'c', 'ć': 'c',
    'ž': 'z', 'ź': 'z', 'š': 's', 'ś': 's',
    // Number/letter confusables
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',
    // Zero-width / invisible chars
    '\u200b': '', '\u200c': '', '\u200d': '', '\ufeff': '',
    // IPA / phonetic
    'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i', 'ɪ': 'i',
  };

  const BRAND_TARGETS = [
    'google', 'gmail', 'youtube', 'facebook', 'instagram', 'whatsapp', 'meta',
    'twitter', 'linkedin', 'apple', 'icloud', 'microsoft', 'outlook', 'office',
    'azure', 'amazon', 'aws', 'netflix', 'paypal', 'ebay', 'dropbox', 'github',
    'steam', 'discord', 'reddit', 'tiktok', 'snapchat', 'spotify',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'barclays',
    'coinbase', 'binance', 'kraken',
  ];

  const PHISHING_PATTERNS = [
    /paypa1\.com/i, /paypall\./i,
    /appleid-verify\./i, /apple-id-login\./i,
    /secure-bankofamerica\./i, /bankofamerica-secure\./i,
    /amazon-security-alert\./i, /netflix-billing-update\./i,
    /microsoft-alert\./i, /google-security-alert\./i,
    /irs-refund\./i, /login-facebook\./i,
    /facebook-login-secure\./i, /instagram-verify\./i,
    /wellsfargo-secure\./i, /chase-verify\./i,
    /account-verify-secure\./i,
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/.*login/i,
    /free-gift-claim\./i, /you-have-won\./i,
    /prize-claim\./i, /click-here-now\./i,
    /verify.*account/i, /confirm.*identity/i,
    /update.*billing/i, /suspended.*account/i,
  ];

  // ─── Detection ───────────────────────────────────────────────────────────────

  function normalizeHomoglyphs(str) {
    return str.split('').map(ch => HOMOGLYPH_MAP[ch] ?? ch).join('');
  }

  function levenshtein(a, b) {
    const dp = Array.from({ length: a.length + 1 }, (_, i) =>
      Array.from({ length: b.length + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
    );
    for (let i = 1; i <= a.length; i++)
      for (let j = 1; j <= b.length; j++)
        dp[i][j] = a[i-1] === b[j-1]
          ? dp[i-1][j-1]
          : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    return dp[a.length][b.length];
  }

  function detectHomoglyph(hostname) {
    const host = hostname.replace(/^www\./, '').toLowerCase();
    const normalized = normalizeHomoglyphs(host);
    const domainLabel = normalized.split('.')[0];
    const originalLabel = host.split('.')[0];

    // IDN punycode
    if (host.includes('xn--')) {
      return { detected: true, idn: true, original: host };
    }

    for (const brand of BRAND_TARGETS) {
      // Exact match after normalization but not before = spoofed
      if (domainLabel === brand && originalLabel !== brand) {
        return { detected: true, spoofed: brand, original: originalLabel };
      }
      // Close after normalization (edit distance <= 1)
      if (domainLabel !== brand && originalLabel !== brand &&
          levenshtein(domainLabel, brand) <= 1 && domainLabel.length >= brand.length - 1) {
        return { detected: true, spoofed: brand, original: originalLabel };
      }
    }
    return { detected: false };
  }

  function analyzeUrl(url) {
    const threats = [];
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname;
      const parts = hostname.split('.');

      // 1. Phishing patterns
      if (PHISHING_PATTERNS.some(p => p.test(url))) {
        threats.push({ type: 'phishing', label: 'Phishing URL', detail: 'Matches known phishing pattern' });
      }

      // 2. Homoglyph / unicode spoof
      const hg = detectHomoglyph(hostname);
      if (hg.detected) {
        threats.push({
          type: 'homoglyph',
          label: hg.idn ? 'IDN Homoglyph Attack' : 'Domain Spoofing',
          detail: hg.spoofed
            ? `"${hg.original}" visually impersonates "${hg.spoofed}.com"`
            : 'Domain uses deceptive Unicode characters'
        });
      }

      // 3. Subdomain abuse: brand used as subdomain on different root
      if (parts.length > 3) {
        const root = parts.slice(-2).join('.');
        const subparts = parts.slice(0, -2);
        for (const brand of BRAND_TARGETS) {
          if (subparts.includes(brand) && !root.startsWith(brand)) {
            threats.push({
              type: 'subdomain',
              label: 'Subdomain Abuse',
              detail: `"${brand}" used as subdomain — real domain is "${root}"`
            });
            break;
          }
        }
      }

      // 4. Raw IP address
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        threats.push({ type: 'ip', label: 'Raw IP Address', detail: 'Legitimate sites rarely use IP addresses directly' });
      }

      // 5. Embedded credentials trick
      if (parsed.username || parsed.password) {
        threats.push({ type: 'phishing', label: 'Credential Trick', detail: 'URL embeds fake credentials (common phishing tactic)' });
      }

      // 6. Excessive subdomains
      if (parts.length > 5) {
        threats.push({ type: 'suspicious', label: 'Suspicious Structure', detail: 'Unusually deep subdomain nesting' });
      }

    } catch { /* unparseable URL */ }
    return threats;
  }

  // ─── Tooltip ─────────────────────────────────────────────────────────────────

  let tooltip = null;
  let hideTimer = null;

  function ensureTooltip() {
    if (tooltip) return tooltip;
    tooltip = document.createElement('div');
    tooltip.id = '__shield_tooltip__';
    Object.assign(tooltip.style, {
      position: 'fixed',
      zIndex: '2147483647',
      maxWidth: '300px',
      minWidth: '220px',
      background: '#0f1117',
      border: '1px solid rgba(239,68,68,0.6)',
      borderRadius: '10px',
      padding: '10px 13px',
      boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      fontSize: '12px',
      color: '#e2e8f0',
      pointerEvents: 'none',
      opacity: '0',
      transition: 'opacity 0.15s ease, transform 0.15s ease',
      transform: 'translateY(4px)',
      display: 'none',
      lineHeight: '1.4',
    });
    document.documentElement.appendChild(tooltip);
    return tooltip;
  }

  const TYPE_COLOR = { phishing:'#ef4444', homoglyph:'#f59e0b', subdomain:'#f59e0b', ip:'#f97316', suspicious:'#a78bfa' };
  const TYPE_ICON  = { phishing:'🎣', homoglyph:'🔤', subdomain:'⚠️', ip:'🌐', suspicious:'🔍' };

  function showTooltip(anchor, threats) {
    clearTimeout(hideTimer);
    const tip = ensureTooltip();

    const header = `<div style="display:flex;align-items:center;gap:7px;margin-bottom:8px;padding-bottom:7px;border-bottom:1px solid #1e2a3a">
      <span style="font-size:14px">🛡️</span>
      <span style="font-weight:700;color:#f0f4ff;font-size:12px">Shield Warning</span>
      <span style="margin-left:auto;background:rgba(239,68,68,0.15);color:#ef4444;font-size:10px;padding:1px 6px;border-radius:10px;font-weight:700">${threats.length} threat${threats.length > 1 ? 's' : ''}</span>
    </div>`;

    const rows = threats.map(t => `
      <div style="display:flex;gap:7px;align-items:flex-start;margin-bottom:5px">
        <span style="font-size:12px;flex-shrink:0;margin-top:1px">${TYPE_ICON[t.type] || '⚠️'}</span>
        <div>
          <div style="font-weight:600;color:${TYPE_COLOR[t.type] || '#94a3b8'};font-size:11px">${t.label}</div>
          <div style="color:#64748b;font-size:11px">${t.detail}</div>
        </div>
      </div>`).join('');

    tip.innerHTML = header + rows;
    tip.style.display = 'block';

    // Position: above the link, centered
    const rect = anchor.getBoundingClientRect();
    const tipW = 300;
    let left = rect.left + rect.width / 2 - tipW / 2;
    left = Math.max(8, Math.min(left, window.innerWidth - tipW - 8));
    tip.style.left = left + 'px';
    tip.style.top = '0px';

    requestAnimationFrame(() => {
      const tipH = tip.offsetHeight;
      const above = rect.top - tipH - 10;
      tip.style.top = (above < 8 ? rect.bottom + 10 : above) + 'px';
      tip.style.opacity = '1';
      tip.style.transform = 'translateY(0)';
    });
  }

  function hideTooltip() {
    if (!tooltip) return;
    tooltip.style.opacity = '0';
    tooltip.style.transform = 'translateY(4px)';
    hideTimer = setTimeout(() => { if (tooltip) tooltip.style.display = 'none'; }, 160);
  }

  // ─── Badge Rendering ─────────────────────────────────────────────────────────

  // Inject shared badge styles once
  function injectBadgeStyles() {
    if (document.getElementById('__shield_badge_styles__')) return;
    const style = document.createElement('style');
    style.id = '__shield_badge_styles__';
    style.textContent = `
      .__shield_badge__ {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 16px;
        height: 16px;
        border-radius: 50%;
        font-size: 10px;
        line-height: 1;
        margin-left: 5px;
        vertical-align: middle;
        flex-shrink: 0;
        cursor: default;
        position: relative;
        top: -1px;
        font-style: normal;
        font-weight: normal;
        text-decoration: none !important;
        box-shadow: 0 1px 3px rgba(0,0,0,0.25);
        transition: transform 0.12s ease;
        z-index: 9999;
      }
      .__shield_badge__:hover { transform: scale(1.25); }
      .__shield_badge_safe__ {
        background: #16a34a;
        color: #fff;
        border: 1.5px solid #15803d;
        font-size: 9px;
      }
      .__shield_badge_unsafe__ {
        background: #dc2626;
        color: #fff;
        border: 1.5px solid #b91c1c;
        font-size: 11px;
      }
      .__shield_badge_checking__ {
        background: #94a3b8;
        color: #fff;
        border: 1.5px solid #64748b;
        font-size: 8px;
        animation: __shield_pulse__ 1s infinite;
      }
      @keyframes __shield_pulse__ {
        0%,100% { opacity: 1; }
        50% { opacity: 0.4; }
      }
    `;
    document.documentElement.appendChild(style);
  }

  // Create a badge element
  function createBadge(state) {
    const span = document.createElement('span');
    span.className = `__shield_badge__ __shield_badge_${state}__`;
    span.setAttribute('data-shield-badge', state);
    if (state === 'safe')     { span.textContent = '✓'; span.title = 'Shield: Link appears safe'; }
    if (state === 'unsafe')   { span.textContent = '✕'; span.title = 'Shield: Unsafe link detected!'; }
    if (state === 'checking') { span.textContent = '…'; span.title = 'Shield: Checking link…'; }
    return span;
  }

  // Check a URL via background (GSB + local patterns)
  const gsbCache = new Map(); // url → { safe: bool, threats: [] }

  async function checkUrlFull(url) {
    if (gsbCache.has(url)) return gsbCache.get(url);

    // Local check first (instant)
    const localThreats = analyzeUrl(url);
    if (localThreats.length > 0) {
      const result = { safe: false, threats: localThreats };
      gsbCache.set(url, result);
      return result;
    }

    // Ask background worker for GSB result
    return new Promise(resolve => {
      try {
        chrome.runtime.sendMessage({ type: 'SCAN_LINK', url }, response => {
          if (chrome.runtime.lastError || !response) {
            const r = { safe: true, threats: [] };
            gsbCache.set(url, r);
            resolve(r);
            return;
          }
          const r = { safe: !response.unsafe, threats: response.threats || [] };
          gsbCache.set(url, r);
          resolve(r);
        });
      } catch {
        const r = { safe: true, threats: [] };
        gsbCache.set(url, r);
        resolve(r);
      }
    });
  }

  // Should we badge this link?
  function shouldBadge(link) {
    const url = link.href;
    if (!url) return false;
    if (url.startsWith('javascript:') || url.startsWith('mailto:') ||
        url.startsWith('tel:') || url.startsWith('#') ||
        url.startsWith('chrome-extension://') || url.startsWith('chrome://')) return false;
    // Skip Shield's own blocked page
    if (url.includes('blocked.html')) return false;
    return true;
  }

  // Insert badge right after the link (or inside for Google result titles)
  function insertBadge(link, badge) {
    // For Google Search result title links, insert inside the link at the end
    // to keep layout intact
    const isGoogleTitle = link.closest('h3') || link.closest('[data-ved]');
    if (isGoogleTitle) {
      // Wrap in a non-breaking inline span inside link
      link.appendChild(badge);
    } else {
      // Insert after the link in the DOM
      if (link.nextSibling) {
        link.parentNode.insertBefore(badge, link.nextSibling);
      } else {
        link.parentNode.appendChild(badge);
      }
    }
  }

  async function addBadgeToLink(link) {
    if (link.__shieldBadged) return;
    link.__shieldBadged = true;
    if (!shouldBadge(link)) return;

    injectBadgeStyles();

    const url = link.href;

    // Instantly show checking state
    const badge = createBadge('checking');
    try {
      insertBadge(link, badge);
    } catch { return; }

    const result = await checkUrlFull(url);

    if (result.safe) {
      badge.className = `__shield_badge__ __shield_badge_safe__`;
      badge.textContent = '✓';
      badge.title = 'Shield: Link appears safe';
      badge.setAttribute('data-shield-badge', 'safe');
    } else {
      badge.className = `__shield_badge__ __shield_badge_unsafe__`;
      badge.textContent = '✕';
      badge.setAttribute('data-shield-badge', 'unsafe');
      const labels = result.threats.map(t => t.label).join(', ');
      badge.title = `Shield: UNSAFE — ${labels}`;

      // Also add red border on the link itself for visibility
      link.style.outline = '1.5px solid #dc2626';
      link.style.outlineOffset = '1px';
      link.style.borderRadius = '2px';
    }
  }

  function badgeAll(root) {
    root.querySelectorAll('a[href]').forEach(addBadgeToLink);
  }

  // ─── Attach Listeners ────────────────────────────────────────────────────────

  const analysisCache = new WeakMap();

  function onEnter(e) {
    const link = e.currentTarget;
    const url = link.href;
    if (!url || url.startsWith('javascript:') || url.startsWith('mailto:')) return;
    let threats = analysisCache.has(link) ? analysisCache.get(link) : analyzeUrl(url);
    analysisCache.set(link, threats);
    if (threats.length > 0) showTooltip(link, threats);
  }

  function attachLink(link) {
    if (link.__shieldOK) return;
    link.__shieldOK = true;
    link.addEventListener('mouseenter', onEnter);
    link.addEventListener('mouseleave', hideTooltip);
  }

  function attachAll(root) {
    root.querySelectorAll('a[href]').forEach(attachLink);
  }

  // Check enabled state first
  chrome.storage.local.get({ enabled: true }, ({ enabled }) => {
    if (!enabled) return;

    injectBadgeStyles();
    attachAll(document);
    badgeAll(document);

    // Watch for dynamically injected links (SPAs, Google search pagination, etc.)
    new MutationObserver(mutations => {
      for (const m of mutations)
        for (const node of m.addedNodes)
          if (node.nodeType === 1) {
            if (node.tagName === 'A' && node.href) {
              attachLink(node);
              addBadgeToLink(node);
            }
            attachAll(node);
            badgeAll(node);
          }
    }).observe(document.body, { childList: true, subtree: true });
  });

})();
