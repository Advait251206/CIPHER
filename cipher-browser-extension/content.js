/**
 * CIPHER Browser Guard — Webmail Content Script
 * Safely extracts visible email components on supported webmail platforms
 * ONLY when explicitly requested by user via the extension popup.
 * Never accesses passwords, auth cookies, or unrelated browsing content.
 */

function extractGmail() {
  // 1. Subject
  const subjEl = document.querySelector("h2.hP") || document.querySelector("h2[data-thread-perm-id]");
  const subject = subjEl ? subjEl.innerText.trim() : (document.title.replace(/ - Gmail$/i, "").trim() || "");

  // 2. Sender
  const senderEl = document.querySelector("span.gD") || document.querySelector("[email]");
  let sender = "";
  if (senderEl) {
    const name = senderEl.getAttribute("name") || senderEl.innerText.trim();
    const email = senderEl.getAttribute("email") || "";
    sender = email ? `${name} <${email}>` : name;
  }

  // 3. Body
  // In Gmail, open message bodies are housed in div.a3s
  const bodyEls = document.querySelectorAll("div.a3s.aiL, div.a3s");
  let bodyText = "";
  const urls = new Set();

  if (bodyEls && bodyEls.length > 0) {
    // Pick the most recent open message
    const targetBody = bodyEls[bodyEls.length - 1];
    bodyText = targetBody.innerText || "";

    // Extract links
    const linkEls = targetBody.querySelectorAll("a[href]");
    linkEls.forEach((a) => {
      const href = a.getAttribute("href");
      if (href && !href.startsWith("#") && !href.startsWith("javascript:")) {
        urls.add(href);
      }
    });
  }

  return {
    provider: "Gmail",
    subject,
    sender,
    body: bodyText.slice(0, 100_000), // Cap extraction to safe limit
    urls: Array.from(urls)
  };
}

function extractOutlook() {
  const subjEl = document.querySelector("[role='heading'][aria-level='1'], [data-testid='messageSubject']");
  const subject = subjEl ? subjEl.innerText.trim() : (document.title.replace(/ - Outlook$/i, "").trim() || "");

  const senderEl = document.querySelector("[data-testid='senderPersona'], [aria-label*='From:']");
  const sender = senderEl ? senderEl.innerText.trim() : "";

  const bodyEl = document.querySelector("[aria-label='Message body'], div.ReadingPaneContainer");
  let bodyText = "";
  const urls = new Set();

  if (bodyEl) {
    bodyText = bodyEl.innerText || "";
    bodyEl.querySelectorAll("a[href]").forEach((a) => {
      const href = a.getAttribute("href");
      if (href && !href.startsWith("#")) urls.add(href);
    });
  }

  return {
    provider: "Outlook",
    subject,
    sender,
    body: bodyText.slice(0, 100_000),
    urls: Array.from(urls)
  };
}

function extractYahoo() {
  const subjEl = document.querySelector("[data-test-id='message-subject'], h2.msg-subject");
  const subject = subjEl ? subjEl.innerText.trim() : (document.title.replace(/ - Yahoo Mail$/i, "").trim() || "");

  const senderEl = document.querySelector("[data-test-id='message-from'], div.from-container");
  const sender = senderEl ? senderEl.innerText.trim() : "";

  const bodyEl = document.querySelector("[data-test-id='message-body'], div.msg-body");
  let bodyText = "";
  const urls = new Set();

  if (bodyEl) {
    bodyText = bodyEl.innerText || "";
    bodyEl.querySelectorAll("a[href]").forEach((a) => {
      const href = a.getAttribute("href");
      if (href && !href.startsWith("#")) urls.add(href);
    });
  }

  return {
    provider: "Yahoo Mail",
    subject,
    sender,
    body: bodyText.slice(0, 100_000),
    urls: Array.from(urls)
  };
}

/**
 * Main dispatcher executed on message request.
 */
function extractActiveEmail() {
  const host = window.location.hostname.toLowerCase();
  let result = null;

  if (host.includes("mail.google.com")) {
    result = extractGmail();
  } else if (host.includes("outlook.live.com") || host.includes("outlook.office.com") || host.includes("outlook.office365.com")) {
    result = extractOutlook();
  } else if (host.includes("mail.yahoo.com")) {
    result = extractYahoo();
  }

  if (!result || (!result.body && !result.subject)) {
    return {
      success: false,
      reason: "No active email message detected in the current view. Please open an email first."
    };
  }

  return {
    success: true,
    ...result
  };
}

// Runtime listener for extraction requests
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "EXTRACT_VISIBLE_EMAIL") {
    const extracted = extractActiveEmail();
    sendResponse(extracted);
  }
  return true;
});
