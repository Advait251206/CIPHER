/**
 * CIPHER Browser Guard — Popup Interface Controller
 * Handles active tab URL inspection, webmail analysis dispatching,
 * and real-time security telemetry rendering.
 */

document.addEventListener("DOMContentLoaded", async () => {
  // Elements
  const backendStatusEl = document.getElementById("backendStatus");
  const backendStatusText = document.getElementById("backendStatusText");
  const targetUrlEl = document.getElementById("targetUrl");
  const verdictBadge = document.getElementById("verdictBadge");
  const riskScoreVal = document.getElementById("riskScoreVal");
  const confidenceVal = document.getElementById("confidenceVal");
  const riskProgressBar = document.getElementById("riskProgressBar");
  const evidenceList = document.getElementById("evidenceList");
  const reAnalyzeBtn = document.getElementById("reAnalyzeBtn");
  const openDashboardBtn = document.getElementById("openDashboardBtn");

  // Tabs
  const tabWebsiteBtn = document.getElementById("tabWebsiteBtn");
  const tabEmailBtn = document.getElementById("tabEmailBtn");
  const tabWebsiteContent = document.getElementById("tabWebsiteContent");
  const tabEmailContent = document.getElementById("tabEmailContent");

  // Email Tab Elements
  const webmailIndicatorText = document.getElementById("webmailIndicatorText");
  const scanEmailBtn = document.getElementById("scanEmailBtn");
  const emailResultCard = document.getElementById("emailResultCard");
  const emailVerdictBadge = document.getElementById("emailVerdictBadge");
  const emailRiskVal = document.getElementById("emailRiskVal");
  const emailSeverityVal = document.getElementById("emailSeverityVal");
  const emailEvidenceList = document.getElementById("emailEvidenceList");
  const embeddedUrlsBox = document.getElementById("embeddedUrlsBox");
  const urlPillsList = document.getElementById("urlPillsList");

  // Settings Elements
  const settingsToggleBtn = document.getElementById("settingsToggleBtn");
  const settingsDrawer = document.getElementById("settingsDrawer");
  const closeSettingsBtn = document.getElementById("closeSettingsBtn");
  const backendUrlInput = document.getElementById("backendUrlInput");
  const saveSettingsBtn = document.getElementById("saveSettingsBtn");

  let currentTab = null;

  // Initialize tabs query
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tabs && tabs.length > 0) {
    currentTab = tabs[0];
  }

  // Load Settings
  chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, (settings) => {
    if (settings && settings.backendUrl) {
      backendUrlInput.value = settings.backendUrl;
    }
  });

  // Tab Switching
  tabWebsiteBtn.addEventListener("click", () => {
    tabWebsiteBtn.classList.add("active");
    tabEmailBtn.classList.remove("active");
    tabWebsiteContent.classList.add("active");
    tabEmailContent.classList.remove("active");
  });

  tabEmailBtn.addEventListener("click", () => {
    tabEmailBtn.classList.add("active");
    tabWebsiteBtn.classList.remove("active");
    tabEmailContent.classList.add("active");
    tabWebsiteContent.classList.remove("active");
  });

  // Settings Drawer Toggle
  settingsToggleBtn.addEventListener("click", () => {
    settingsDrawer.classList.toggle("hidden");
  });

  closeSettingsBtn.addEventListener("click", () => {
    settingsDrawer.classList.add("hidden");
  });

  saveSettingsBtn.addEventListener("click", () => {
    const url = backendUrlInput.value.trim();
    chrome.runtime.sendMessage({
      type: "SAVE_SETTINGS",
      settings: { backendUrl: url }
    }, () => {
      settingsDrawer.classList.add("hidden");
      analyzeCurrentWebsite();
    });
  });

  // Open SOC Dashboard Action
  openDashboardBtn.addEventListener("click", () => {
    chrome.tabs.create({ url: "http://localhost:5173" });
  });

  // Re-Analyze Action
  reAnalyzeBtn.addEventListener("click", () => {
    analyzeCurrentWebsite();
  });

  // Detect Webmail Provider
  function checkWebmailSupport(url) {
    if (!url) return null;
    const lower = url.toLowerCase();
    if (lower.includes("mail.google.com")) return "Gmail";
    if (lower.includes("outlook.live.com") || lower.includes("outlook.office.com") || lower.includes("outlook.office365.com")) return "Outlook Web";
    if (lower.includes("mail.yahoo.com")) return "Yahoo Mail";
    return null;
  }

  // Website Inspection Renderer
  function renderWebsiteVerdict(data) {
    if (data.status === "UNAVAILABLE") {
      backendStatusEl.className = "backend-status offline";
      backendStatusText.textContent = "Backend Offline";
      verdictBadge.className = "verdict-badge";
      verdictBadge.textContent = "OFFLINE";
      riskScoreVal.textContent = "--";
      confidenceVal.textContent = "--";
      riskProgressBar.style.width = "0%";
      evidenceList.innerHTML = `<li>Local CIPHER backend is not reachable. Start with: <code>python -m uvicorn app.main:app</code></li>`;
      return;
    }

    backendStatusEl.className = "backend-status online";
    backendStatusText.textContent = "127.0.0.1 Connected";

    const score = data.risk_score || 0;
    const cls = data.classification || "UNKNOWN";
    const conf = Math.round((data.confidence || 0) * 100);

    riskScoreVal.textContent = `${score} / 100`;
    confidenceVal.textContent = `${conf}%`;
    riskProgressBar.style.width = `${score}%`;

    verdictBadge.className = "verdict-badge";
    if (score >= 70 || cls === "LIKELY_PHISHING") {
      verdictBadge.classList.add("risk");
      verdictBadge.textContent = "PHISHING DETECTED";
      riskProgressBar.style.backgroundColor = "var(--color-risk)";
    } else if (score >= 35 || cls === "SUSPICIOUS") {
      verdictBadge.classList.add("warn");
      verdictBadge.textContent = "SUSPICIOUS SITE";
      riskProgressBar.style.backgroundColor = "var(--color-warn)";
    } else {
      verdictBadge.classList.add("safe");
      verdictBadge.textContent = "SAFE WEBSITE";
      riskProgressBar.style.backgroundColor = "var(--color-safe)";
    }

    evidenceList.innerHTML = "";
    const reasons = data.reasons && data.reasons.length > 0 ? data.reasons : ["URL structure adheres to legitimate standard patterns."];
    reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      evidenceList.appendChild(li);
    });
  }

  // Trigger Website Inspection
  function analyzeCurrentWebsite() {
    if (!currentTab || !currentTab.url) {
      targetUrlEl.textContent = "No active tab detected";
      return;
    }

    targetUrlEl.textContent = currentTab.url;
    verdictBadge.className = "verdict-badge";
    verdictBadge.textContent = "ANALYZING...";
    riskProgressBar.style.width = "40%";
    riskProgressBar.style.backgroundColor = "var(--color-accent)";

    chrome.runtime.sendMessage({
      type: "CHECK_URL",
      url: currentTab.url
    }, (result) => {
      if (chrome.runtime.lastError || !result) {
        renderWebsiteVerdict({ status: "UNAVAILABLE" });
      } else {
        renderWebsiteVerdict(result);
      }
    });
  }

  // Initial Website Inspection Trigger
  if (currentTab && currentTab.url) {
    analyzeCurrentWebsite();
    const provider = checkWebmailSupport(currentTab.url);
    if (provider) {
      webmailIndicatorText.textContent = `✓ ${provider} active in tab`;
      tabEmailBtn.style.color = "#38bdf8";
    } else {
      webmailIndicatorText.textContent = "No supported webmail detected in active tab";
    }
  }

  // Email Scan Action
  scanEmailBtn.addEventListener("click", () => {
    if (!currentTab || !currentTab.id) return;

    scanEmailBtn.disabled = true;
    scanEmailBtn.textContent = "Extracting Visible Email...";

    chrome.tabs.sendMessage(currentTab.id, { type: "EXTRACT_VISIBLE_EMAIL" }, (extracted) => {
      scanEmailBtn.disabled = false;
      scanEmailBtn.innerHTML = `
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
          <polyline points="22,6 12,13 2,6"/>
        </svg>
        Analyze Visible Email
      `;

      if (chrome.runtime.lastError || !extracted || !extracted.success) {
        emailResultCard.classList.remove("hidden");
        emailVerdictBadge.className = "verdict-badge warn";
        emailVerdictBadge.textContent = "NO MESSAGE FOUND";
        emailRiskVal.textContent = "--";
        emailSeverityVal.textContent = "N/A";
        emailEvidenceList.innerHTML = `<li>${extracted?.reason || "Please open an email message in this tab first."}</li>`;
        embeddedUrlsBox.classList.add("hidden");
        return;
      }

      // Dispatch to background for local CIPHER API analysis
      emailVerdictBadge.className = "verdict-badge";
      emailVerdictBadge.textContent = "INSPECTING...";
      emailResultCard.classList.remove("hidden");

      chrome.runtime.sendMessage({
        type: "CHECK_EMAIL",
        payload: {
          subject: extracted.subject,
          sender: extracted.sender,
          body: extracted.body,
          urls: extracted.urls
        }
      }, (res) => {
        if (!res || res.status === "UNAVAILABLE") {
          emailVerdictBadge.className = "verdict-badge";
          emailVerdictBadge.textContent = "OFFLINE";
          emailEvidenceList.innerHTML = "<li>CIPHER backend is unavailable. Ensure port 8000 is online.</li>";
          return;
        }

        const risk = res.risk_score || 0;
        const cls = res.classification || "UNKNOWN";
        const sev = res.severity || "LOW";

        emailVerdictBadge.className = "verdict-badge";
        if (risk >= 60 || cls === "MALICIOUS_EMAIL") {
          emailVerdictBadge.classList.add("risk");
          emailVerdictBadge.textContent = "MALICIOUS EMAIL";
        } else if (risk >= 35 || cls === "SUSPICIOUS") {
          emailVerdictBadge.classList.add("warn");
          emailVerdictBadge.textContent = "SUSPICIOUS EMAIL";
        } else {
          emailVerdictBadge.classList.add("safe");
          emailVerdictBadge.textContent = "BENIGN EMAIL";
        }

        emailRiskVal.textContent = `${risk} / 100`;
        emailSeverityVal.textContent = sev;

        emailEvidenceList.innerHTML = "";
        const evList = res.evidence && res.evidence.length > 0 ? res.evidence : ["Email text conforms to standard legitimate patterns."];
        evList.forEach((e) => {
          const li = document.createElement("li");
          li.textContent = e;
          emailEvidenceList.appendChild(li);
        });

        // Embedded URLs
        if (res.urls_analyzed && res.urls_analyzed.length > 0) {
          embeddedUrlsBox.classList.remove("hidden");
          urlPillsList.innerHTML = "";
          res.urls_analyzed.forEach((u) => {
            const pill = document.createElement("div");
            pill.className = `url-pill ${u.risk_score >= 50 ? "risk" : ""}`;
            pill.innerHTML = `<span>${u.url.length > 35 ? u.url.slice(0, 35) + "..." : u.url}</span><strong>${u.classification} (${u.risk_score})</strong>`;
            urlPillsList.appendChild(pill);
          });
        } else {
          embeddedUrlsBox.classList.add("hidden");
        }
      });
    });
  });
});
