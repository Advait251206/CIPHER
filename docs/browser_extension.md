# CIPHER Browser Guard — Chromium Extension Architecture

## 1. Executive Summary

**CIPHER Browser Guard** is a Manifest V3 browser extension for Chromium-based browsers (Google Chrome, Brave, Microsoft Edge, Opera). It brings the protection capabilities of the local CIPHER security platform directly into the user's web browsing and webmail workflow.

It operates with an uncompromising **privacy invariant**:
- **Zero Cloud Communication**: The extension never transmits URLs, emails, or telemetry to external third parties or cloud servers.
- **Strict Host Permissions**: Outbound network requests are strictly constrained in `manifest.json` to `http://127.0.0.1:8000/*` and `http://localhost:8000/*`.
- **Zero Credential Scraping**: The extension does not read form passwords, authentication tokens, cookies, or session storage.

---

## 2. Manifest V3 Architecture

The extension consists of 5 core architectural components:

```
cipher-browser-extension/
├── manifest.json         # Manifest V3 configuration, permissions, and service worker declaration
├── background.js         # Event-driven service worker for URL routing, badges, and alarms
├── content.js            # Isolated DOM script for Gmail, Outlook, and Yahoo webmail scanning
├── popup.html / .js      # SOC-styled action popup for real-time site score and manual scanner
├── warning.html / .js    # Active protective interstitial screen for high-risk phishing sites
└── icons/                # High-contrast 16x16, 48x48, 128x128 security shield icons
```

### Manifest Configuration & Permissions

| Permission | Purpose |
| :--- | :--- |
| `activeTab` | Inspects the URL of the currently focused tab only upon navigation or explicit user action. |
| `storage` | Persists user preferences locally (e.g., auto-blocking toggle, custom local backend URL). |
| `alarms` | Schedules periodic health checks (every 60s) to verify backend connectivity. |
| `host_permissions` | Strictly limited to `http://127.0.0.1:8000/*` and `http://localhost:8000/*`. |

---

## 3. Webmail DOM Extraction & Scanning (`content.js`)

`content.js` runs in an isolated world on webmail domains:
- `https://mail.google.com/*` (Gmail)
- `https://outlook.live.com/*` (Outlook Personal)
- `https://outlook.office.com/*` (Outlook Enterprise / M365)
- `https://mail.yahoo.com/*` (Yahoo Mail)

### Extraction Flow:
1. **Dynamic Trigger**: When an email is opened, a non-intrusive floating badge (`#cipher-mail-badge`) appears in the top-right corner of the webmail viewport.
2. **Safe Text Extraction**:
   - **Gmail**: Targets `.hP` (subject line), `.gD` (sender address), and `.ii.gt` / `.a3s` (message body).
   - **Outlook**: Targets `[role="heading"]` (subject), `[data-hovercard-id]` / `.sender` (sender), and `[role="document"]` / `.rps_` (message body).
   - **Yahoo Mail**: Targets `[data-test-id="message-view-subject"]`, `[data-test-id="message-view-from"]`, and `[data-test-id="message-view-body"]`.
3. **Local Dispatch**: The extracted text is dispatched via `chrome.runtime.sendMessage` to `background.js`, which posts to `http://127.0.0.1:8000/api/email/analyze`.
4. **Visual Result Banner**: The badge updates in real time to display the verdict (`LEGITIMATE`, `SUSPICIOUS`, or `MALICIOUS_EMAIL`) and risk score. If malicious, an in-page warning banner alerts the user before links are clicked.

---

## 4. Real-Time URL Protection & Interstitial Guard

### Navigation Monitoring (`background.js`)
- Listens to `chrome.webNavigation.onBeforeNavigate` and `chrome.tabs.onUpdated`.
- Internal browser URLs (`chrome://*`, `edge://*`, `about:*`, `localhost`, `127.0.0.1`) are bypassed immediately.
- For public web URLs, a fast threat query is dispatched to `http://127.0.0.1:8000/api/phishing/detect`.
- **Badge Indicators**:
  - `OK` (Green, `#10b981`): Score < 35 (Benign).
  - `WARN` (Amber, `#f59e0b`): Score 35–69 (Suspicious).
  - `ALERT` (Red, `#ef4444`): Score $\ge 70$ (Phishing).
  - `OFF` (Gray, `#64748b`): Backend offline or internal URL.

### Active Protective Interstitial (`warning.html`)
When a URL returns a high-risk phishing verdict (risk score $\ge 80$ or explicit known threat IOC match), and automatic blocking is enabled:
- The tab is redirected to `warning.html?url=<target>&score=<score>&reason=<reason>`.
- The user is presented with a red high-risk screen explaining the detected indicators.
- Users may choose to navigate back to safety, inspect details, or explicitly bypass the block.

---

## 5. Installation Guide (Developer Mode)

### Step 1: Verify CIPHER Backend is Active
Ensure the CIPHER FastAPI service is running locally on port 8000:
```bash
# In backend directory:
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Verify readiness: `curl http://127.0.0.1:8000/api/email/health` -> `{"status":"ok","model_loaded":true}`.

### Step 2: Open Extensions in Chromium Browser
- **Google Chrome / Brave**: Open URL `chrome://extensions`
- **Microsoft Edge**: Open URL `edge://extensions`

### Step 3: Enable Developer Mode
Toggle the **Developer mode** switch in the top-right corner of the Extensions page.

### Step 4: Load Unpacked Extension
1. Click the **Load unpacked** button in the top navigation bar.
2. Select the folder:
   `d:\Advait251206\College\5th Sem\IDPS\Project\cipher-browser-extension`
3. The extension card **CIPHER Browser Guard** will appear with version 1.0.0 and active shield icon.

### Step 5: Pin Extension to Toolbar
Click the puzzle piece icon in the browser toolbar and pin **CIPHER Browser Guard** for one-click access.

---

## 6. Privacy Guarantees & SOC Auditability

1. **Audit Logs in CIPHER**: When high-risk phishing or email attacks are detected via the extension, a structured security event is logged in CIPHER's SQLite database (`source='browser_extension'`).
2. **Zero Storage of Body Content**: Like the backend API, the extension discards email body text after inference; only metadata (risk score, classification, timestamp, host) is persisted.
3. **Air-Gap Compatible**: Can operate completely offline in isolated network environments, provided the local CIPHER backend is running.
