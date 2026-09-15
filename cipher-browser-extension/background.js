/**
 * CIPHER Browser Guard — Background Service Worker
 * Manifest V3 compliant service worker connecting exclusively to the local CIPHER backend.
 * Zero telemetry, zero external cloud dependencies.
 */

const DEFAULT_SETTINGS = {
  backendUrl: "http://127.0.0.1:8000",
  warningThreshold: 75,
  enableInterstitial: false
};

// URL schemes that must NEVER be analyzed
const BYPASS_SCHEMES = [
  "chrome://",
  "edge://",
  "about:",
  "chrome-extension://",
  "extension://",
  "devtools://",
  "view-source:",
  "file://"
];

/**
 * Retrieves user configuration from Chrome storage with fallback to defaults.
 */
async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(DEFAULT_SETTINGS, (items) => {
      resolve(items || DEFAULT_SETTINGS);
    });
  });
}

/**
 * Validates if a URL is an inspectable web page.
 */
function isInspectableUrl(url) {
  if (!url || typeof url !== "string") return false;
  const lower = url.toLowerCase();
  for (const scheme of BYPASS_SCHEMES) {
    if (lower.startsWith(scheme)) return false;
  }
  return lower.startsWith("http://") || lower.startsWith("https://");
}

/**
 * Sends URL to local CIPHER backend phishing detector with strict timeout.
 */
async function inspectUrl(targetUrl) {
  if (!isInspectableUrl(targetUrl)) {
    return {
      status: "BYPASS",
      classification: "SAFE",
      risk_score: 0,
      confidence: 1.0,
      reasons: ["Internal browser or unsupported URL scheme (analysis bypassed)"],
      recommendation: "Internal browser page. Safe to navigate."
    };
  }

  const settings = await getSettings();
  const endpoint = `${settings.backendUrl.replace(/\/+$/, "")}/api/phishing/analyze`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 4000);

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({ url: targetUrl }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        status: "ERROR",
        classification: "UNKNOWN",
        risk_score: 0,
        reasons: [`Backend responded with HTTP ${response.status}`],
        recommendation: "Unable to complete threat analysis."
      };
    }

    const data = await response.json();
    return {
      status: "OK",
      classification: data.classification || "UNKNOWN",
      risk_score: typeof data.risk_score === "number" ? data.risk_score : 0,
      severity: data.severity || "LOW",
      confidence: data.confidence || 0.0,
      reasons: data.reasons || [],
      recommendation: data.recommendation || ""
    };
  } catch (err) {
    clearTimeout(timeoutId);
    return {
      status: "UNAVAILABLE",
      classification: "UNAVAILABLE",
      risk_score: 0,
      reasons: ["Local CIPHER backend is offline or unreachable at " + settings.backendUrl],
      recommendation: "Ensure CIPHER backend is running: python -m uvicorn app.main:app"
    };
  }
}

/**
 * Sends email content to local CIPHER backend email detector.
 */
async function inspectEmail(emailPayload) {
  const settings = await getSettings();
  const endpoint = `${settings.backendUrl.replace(/\/+$/, "")}/api/email/analyze`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 6000);

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify(emailPayload),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        status: "ERROR",
        classification: "UNKNOWN",
        risk_score: 0,
        evidence: [`Backend error: HTTP ${response.status}`]
      };
    }

    const data = await response.json();
    return {
      status: "OK",
      ...data
    };
  } catch (err) {
    clearTimeout(timeoutId);
    return {
      status: "UNAVAILABLE",
      classification: "UNAVAILABLE",
      risk_score: 0,
      evidence: ["CIPHER backend is offline or unreachable at " + settings.backendUrl]
    };
  }
}

/**
 * Updates action badge based on inspection result.
 */
function updateBadge(tabId, result) {
  if (!tabId || !result) return;

  if (result.status === "UNAVAILABLE") {
    chrome.action.setBadgeText({ tabId, text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#64748b" });
  } else if (result.risk_score >= 70 || result.classification === "LIKELY_PHISHING") {
    chrome.action.setBadgeText({ tabId, text: "RISK" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
  } else if (result.risk_score >= 35 || result.classification === "SUSPICIOUS") {
    chrome.action.setBadgeText({ tabId, text: "WARN" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#f59e0b" });
  } else if (result.status === "OK") {
    chrome.action.setBadgeText({ tabId, text: "SAFE" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#10b981" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "" });
  }
}

// Runtime message dispatcher
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "CHECK_URL") {
    inspectUrl(message.url).then((result) => {
      if (sender.tab && sender.tab.id) {
        updateBadge(sender.tab.id, result);
      }
      sendResponse(result);
    });
    return true; // Keep message channel open for async response
  }

  if (message.type === "CHECK_EMAIL") {
    inspectEmail(message.payload).then((result) => {
      sendResponse(result);
    });
    return true;
  }

  if (message.type === "GET_SETTINGS") {
    getSettings().then((s) => sendResponse(s));
    return true;
  }

  if (message.type === "SAVE_SETTINGS") {
    chrome.storage.local.set(message.settings, () => {
      sendResponse({ status: "OK" });
    });
    return true;
  }
});
