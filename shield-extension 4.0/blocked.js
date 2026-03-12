(function() {
  // Parse URL params
  var params  = new URLSearchParams(window.location.search);
  var reason  = params.get("reason") || "blocklist";
  var blocked = params.get("url")  ? decodeURIComponent(params.get("url"))  : "";
  var prevUrl = params.get("prev") ? decodeURIComponent(params.get("prev")) : "";

  // Populate URL box right away
  document.getElementById("blocked-url").textContent = blocked || "Unknown URL";

  var configs = {
    phishing: {
      icon: "\uD83C\uDFA3", color: "red", badge: "Phishing Attack",
      title: "This site is trying to steal your info",
      subtitle: "It's disguised as a real website to trick you into handing over your passwords, credit card, or personal details.",
      cardTitle: "WHAT IS PHISHING?",
      what: "Phishing sites are fake pages that look identical to real ones — like your bank, Google, or PayPal. The goal is to get you to type in your login or payment details, which the attackers then steal.",
      risks: [
        { icon: "\uD83D\uDD11", text: "Your passwords and login credentials could be stolen" },
        { icon: "\uD83D\uDCB3", text: "Credit card or banking details could be harvested" },
        { icon: "\uD83D\uDC64", text: "Your identity could be used to open accounts or take out loans" },
        { icon: "\uD83D\uDCE7", text: "Your email could be hijacked to attack your contacts" }
      ],
      advice: [
        "Do not enter any login details or personal info on this site",
        "If you were already on it, change your passwords immediately",
        "Verify the real site by typing its URL manually in a new tab",
        "Contact your bank if it was impersonating a financial service"
      ],
      source: "Detected by Google Safe Browsing \u2014 Social Engineering / Phishing",
      urlLabel: "Phishing URL"
    },
    malware: {
      icon: "\u2623\uFE0F", color: "red", badge: "Malware Threat",
      title: "This site distributes viruses",
      subtitle: "Visiting or downloading from this site could silently infect your device with malicious software.",
      cardTitle: "WHAT IS MALWARE?",
      what: "Malware is malicious software \u2014 viruses, trojans, ransomware, spyware. This site is known to install it on visitors' devices, often without you clicking anything. It runs silently in the background.",
      risks: [
        { icon: "\uD83D\uDD12", text: "Ransomware could encrypt your files and demand payment to unlock them" },
        { icon: "\uD83D\uDC41\uFE0F", text: "Spyware could monitor everything you type, including passwords" },
        { icon: "\uD83D\uDCBB", text: "Your device could be secretly recruited into a botnet" },
        { icon: "\uD83D\uDCC1", text: "Personal files, photos and documents could be stolen or deleted" }
      ],
      advice: [
        "Do not visit this site or download anything from it",
        "If you already visited it, run a full antivirus scan immediately",
        "Check your browser extensions for anything you didn't install",
        "Change passwords for important accounts as a precaution"
      ],
      source: "Detected by Google Safe Browsing \u2014 Malware",
      urlLabel: "Malware Site URL"
    },
    "unwanted-software": {
      icon: "\u26A0\uFE0F", color: "amber", badge: "Unwanted Software",
      title: "This site pushes deceptive software",
      subtitle: "This site tricks you into installing software that does things you never agreed to.",
      cardTitle: "WHAT IS UNWANTED SOFTWARE?",
      what: "Unwanted software (adware/PUPs) disguises itself as something useful \u2014 a free tool, video player, or browser extension. Once installed it hijacks your browser, injects ads, tracks your activity, or installs more junk.",
      risks: [
        { icon: "\uD83C\uDF10", text: "Your browser homepage and search engine could be changed without permission" },
        { icon: "\uD83D\uDCE2", text: "Intrusive ads could be injected into every website you visit" },
        { icon: "\uD83D\uDCCA", text: "Your browsing habits could be tracked and sold to advertisers" },
        { icon: "\uD83D\uDD27", text: "It may be very hard to uninstall and could reinstall itself automatically" }
      ],
      advice: [
        "Do not download or install anything from this site",
        "If you already installed something, remove it via your system's app manager",
        "Check your browser extensions and remove anything unfamiliar",
        "Reset your browser settings if your homepage or search engine changed"
      ],
      source: "Detected by Google Safe Browsing \u2014 Unwanted Software",
      urlLabel: "Suspicious URL"
    },
    "harmful-app": {
      icon: "\uD83D\uDC80", color: "red", badge: "Harmful Application",
      title: "This download can damage your device",
      subtitle: "This site hosts an app flagged as harmful \u2014 it likely contains spyware, ransomware, or a trojan.",
      cardTitle: "WHAT IS A HARMFUL APP?",
      what: "Harmful apps look useful but secretly perform malicious actions \u2014 recording your screen, stealing files, locking your device for ransom, or giving attackers full remote access to your computer.",
      risks: [
        { icon: "\uD83C\uDFA5", text: "Could secretly activate your webcam or microphone" },
        { icon: "\uD83D\uDD11", text: "Keyloggers may record every keystroke including passwords" },
        { icon: "\uD83C\uDFE6", text: "Banking trojans can intercept and redirect your transactions" },
        { icon: "\uD83D\uDD12", text: "Ransomware can permanently lock all your files" }
      ],
      advice: [
        "Do not download or run any file from this site",
        "If you already ran it, disconnect from the internet and run antivirus",
        "In severe cases, a full OS reinstall may be necessary",
        "Report it to IT support if this happened on a work device"
      ],
      source: "Detected by Google Safe Browsing \u2014 Potentially Harmful Application",
      urlLabel: "Harmful App URL"
    },
    download: {
      icon: "\u26D4", color: "red", badge: "Dangerous Download Blocked",
      title: "This file was flagged as malicious",
      subtitle: "Shield cancelled this download before it reached your device. The file is known to contain malware.",
      cardTitle: "WHAT WAS IN THIS FILE?",
      what: "The download URL matched Google Safe Browsing's database of known malicious files. These are typically trojans, ransomware, or spyware bundled inside something that looks harmless \u2014 a PDF, installer, zip, or document.",
      risks: [
        { icon: "\uD83D\uDD12", text: "Could encrypt all your files and demand a ransom to unlock them" },
        { icon: "\uD83D\uDC41\uFE0F", text: "Could silently spy on your activity and steal credentials" },
        { icon: "\uD83D\uDCBB", text: "Could give an attacker full remote access to your device" },
        { icon: "\uD83D\uDCC1", text: "Could delete or secretly upload your sensitive files" }
      ],
      advice: [
        "The download was cancelled \u2014 your device is safe this time",
        "Do not try to re-download this file from any source",
        "If you got the link via email or message, treat the sender as compromised",
        "If you downloaded it before Shield was installed, run a virus scan now"
      ],
      source: "Detected by Google Safe Browsing \u2014 Malicious Download",
      urlLabel: "Download URL"
    },
    blocklist: {
      icon: "\uD83D\uDEAB", color: "gray", badge: "Manually Blocked",
      title: "You've blocked this site",
      subtitle: "This website is on your personal blocklist. Shield stopped you from visiting it.",
      cardTitle: "WHY IS THIS BLOCKED?",
      what: "You manually added this site to Shield's blocklist. No automatic threat was detected \u2014 this is a block you set yourself. You can remove it from the Shield popup, or click 'Proceed at own risk' below to visit it just this once.",
      risks: [],
      advice: [
        "To unblock it permanently, open the Shield popup and remove it from your blocklist",
        "Or click 'Proceed at own risk' below to visit it this one time"
      ],
      source: "Blocked by your personal Shield blocklist",
      urlLabel: "Blocked URL"
    }
  };

  var cfg = configs[reason] || configs.blocklist;

  // Populate all elements
  document.getElementById("threat-icon").textContent     = cfg.icon;
  document.getElementById("reason-badge").className      = "badge " + cfg.color;
  document.getElementById("badge-text").textContent      = cfg.badge;
  document.getElementById("title").textContent           = cfg.title;
  document.getElementById("subtitle").textContent        = cfg.subtitle;
  document.getElementById("url-label").textContent       = cfg.urlLabel;
  document.getElementById("source-row").textContent      = cfg.source;

  // ---- GO BACK BUTTON ----
  document.getElementById("btn-back").onclick = function() {
    if (prevUrl && prevUrl.indexOf("http") === 0) {
      window.location.href = prevUrl;
    } else if (history.length > 1) {
      history.back();
    } else {
      // Ask the background to navigate the tab back
      chrome.runtime.sendMessage({ type: "GO_BACK" });
    }
  };

  // ---- PROCEED BUTTON ----
  // Chrome extensions block window.confirm() — use an inline confirm overlay instead
  function proceedNow() {
    if (!blocked) return;
    chrome.runtime.sendMessage({ type: "PROCEED_ANYWAY", url: blocked });
  }

  function showConfirmOverlay() {
    var overlay = document.createElement("div");
    overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;padding:20px;";
    overlay.innerHTML =
      '<div style="background:#0f1117;border:1px solid rgba(239,68,68,0.5);border-radius:14px;padding:28px 24px;max-width:400px;width:100%;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',sans-serif;color:#e2e8f0;">' +
        '<div style="font-size:28px;text-align:center;margin-bottom:12px;">⚠️</div>' +
        '<div style="font-size:15px;font-weight:700;color:#ef4444;margin-bottom:10px;text-align:center;">Dangerous Site Warning</div>' +
        '<div style="font-size:13px;color:#94a3b8;line-height:1.6;margin-bottom:20px;text-align:center;">' +
          'Google Safe Browsing flagged this site as <strong style="color:#ef4444;">' + cfg.badge + '</strong>.<br>' +
          'Proceeding may expose your device and personal data to serious risk.' +
        '</div>' +
        '<div style="display:flex;gap:10px;">' +
          '<button id="overlay-cancel" style="flex:1;padding:11px;border-radius:8px;border:1px solid #1e2a3a;background:#131820;color:#94a3b8;font-size:13px;font-weight:600;cursor:pointer;">Cancel</button>' +
          '<button id="overlay-proceed" style="flex:1;padding:11px;border-radius:8px;border:none;background:#dc2626;color:#fff;font-size:13px;font-weight:600;cursor:pointer;">Proceed Anyway</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(overlay);
    document.getElementById("overlay-cancel").onclick = function() { document.body.removeChild(overlay); };
    document.getElementById("overlay-proceed").onclick = function() { proceedNow(); };
  }

  document.getElementById("btn-proceed").onclick = function() {
    if (reason !== "blocklist") {
      showConfirmOverlay();
    } else {
      proceedNow();
    }
  };

})();
