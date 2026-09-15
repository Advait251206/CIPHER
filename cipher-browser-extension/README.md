# CIPHER Browser Guard — Chromium Extension

**CIPHER Browser Guard** is a lightweight, privacy-preserving Manifest V3 extension that pairs with the local CIPHER security platform.

## Features
- **Real-Time Phishing Protection**: Evaluates active tabs against CIPHER's Random Forest phishing detection engine (`/api/phishing/detect`) and Threat Intelligence IOC cache.
- **Webmail Security Assistant**: Integrates seamlessly with Gmail, Outlook Live, and Yahoo Mail. Adds a floating "Scan Email with CIPHER" badge to inspect suspect emails before clicking attachments or hyperlinks.
- **Automatic High-Risk Interstitial**: Redirects known malicious / high-confidence phishing sites to a protective warning screen before credentials can be stolen.
- **Strict Privacy Invariant**: Zero cloud calls, zero external analytics, zero credential scraping. All telemetry and analysis stay strictly on `http://127.0.0.1:8000`.

---

## Installation in Chrome / Brave / Edge

1. **Start the CIPHER Backend**:
   Ensure the CIPHER FastAPI backend is running locally on port 8000:
   ```bash
   cd backend
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

2. **Open Extension Management**:
   - In Google Chrome / Brave, navigate to: `chrome://extensions`
   - In Microsoft Edge, navigate to: `edge://extensions`

3. **Enable Developer Mode**:
   - Toggle the switch in the top right corner labelled **"Developer mode"**.

4. **Load Unpacked Extension**:
   - Click the button labelled **"Load unpacked"** in the top left header.
   - Select the `cipher-browser-extension` folder located at the root of this project:
     `d:\Advait251206\College\5th Sem\IDPS\Project\cipher-browser-extension`

5. **Pin Extension**:
   - Click the puzzle piece icon in the browser toolbar and pin **CIPHER Browser Guard**.

---

## Architecture & Permissions
- **Manifest V3**: Uses standard background service workers (`background.js`) and isolated content scripts (`content.js`).
- **Permissions**:
  - `activeTab`: Only inspects the currently active tab URL when requested or navigated.
  - `storage`: Stores user preferences (e.g., auto-block toggle, backend URL override).
  - `alarms`: Periodic background health heartbeat to verify connection to CIPHER backend.
  - `host_permissions`: Strictly constrained to `http://127.0.0.1:8000/*` and `http://localhost:8000/*`.
