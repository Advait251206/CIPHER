# Changelog

## v1.3.0 — Publication hardening (2026-10-31)

### Security
- **API authentication.** State-changing requests need `X-CIPHER-Token` (auto-generated in `backend/.cipher_token`, or `CIPHER_API_TOKEN`). Browser requests must come from the dashboard or an extension `Origin`. The Vite dev proxy attaches the token server-side.
- **CORS** restricted to the dashboard origins and browser extensions (was `*` with credentials, which let any website drive the API).
- **Network exposure.** Backend and dashboard bind to `127.0.0.1`. `run.bat` no longer opens port 5173 and asks before exposing the vulnerable demo app; the demo app now runs **without** admin rights.
- **`/api/extension/launch`** accepts only absolute `http(s)` URLs and passes them after a `--` switch terminator (fixes Chromium argument injection).
- **Browser extension popup** builds email-derived URL pills with `textContent` (was `innerHTML`).
- **C++ sensor** bounds-checks every header against `caplen`.

### Prevention engine
- Missing or invalid `CIPHER_PREVENTION_MODE` now falls back to **`detect_only`** (was `enforce`).
- `netsh` is called **only in `enforce` mode** (previously also in `simulate`, on manual blocks and on WAF hits).
- Every block target is validated with `ipaddress`; loopback, link-local, multicast, the host's own addresses and `CIPHER_PROTECTED_IPS` are never blocked (`POST /api/network/blocklist/any` used to block all inbound traffic).
- Expired TTL blocks now **remove their firewall rule**.
- One **shared `PreventionEngine`** for the API, live sensor, WAF and correlation layer, so the dashboard's mode switch applies everywhere. Correlation re-evaluation no longer double-counts flows in the rate limiter.
- Automatic threat-intel IOCs for blocked IPs are now opt-in (`CIPHER_AUTO_THREAT_INTEL_FROM_BLOCKS`).
- `ML_WEIGHT`, `HEURISTIC_WEIGHT` and `DEFAULT_TEMP_BLOCK_MINUTES` are now read; unused variables were removed from `.env.example`.
- Phase 10 validation intercepts all firewall calls and reports the measured count (the "no firewall modified" check was hard-coded `True`).

### Detection logic
- Live sensor tracks **all ports** by default (the 5174/8000/8080 allow-list made port-scan detection impossible).
- WAF no longer inspects CIPHER's own API (port 8000) and uses syntax-anchored signatures: fixes false positives on `#`, `-- `, "update … set", and catches `' OR 'a'='a`, `</script >`, double encoding, stacked queries and time-based payloads. Inspected ports: `CIPHER_WAF_PORTS`.
- `HEUR-DDOS-001` now also requires aggregate volume (`CIPHER_HEURISTIC_DDOS_AGGREGATE_PPS`, default 10,000 pkts/s); three ordinary clients are no longer a DDoS.
- Port 5174 removed from SSH/RDP-style auth ports; web-login ports use a 30-connection threshold.
- Removed built-in DoS/DDoS suppression for source ports 80/443/8080/8443/53 and for 10/8, 192.168/16, 20/8, 140.82/16 (trivially spoofable; hid LAN attacks). Replaced by an explicit `CIPHER_TRUSTED_SOURCES` allow-list.
- Broadcast detection uses local subnet routes instead of "ends with .255".
- `DOS_BYTE_RATE_THRESHOLD` default is 5 MB/s, matching the documentation (was 50 MB/s).
- Phishing trusted-domain list no longer whitelists user-content hosts (Google Sites/Docs/Forms, OneDrive, GitHub Pages, …). Private LAN IPs are no longer auto-trusted.

### Reproducibility and docs
- Pinned `requirements.txt` (scikit-learn 1.7.2 matches the pickled models); added missing `requests`.
- Dataset-dependent and libpcap-dependent tests skip cleanly when the data/driver is absent.
- GitHub Actions CI for backend (Python 3.12/3.13) and frontend (tsc, vitest, build).
- `scripts/generate_docs_metrics.py` generates every metric table from the committed artifacts; CI fails on drift. README and docs reconciled (phishing: 15 features, 98.75% accuracy, 0.90% FPR; network test set 404,442 flows, macro-F1 0.900).
- `training/probe_phishing.py` and its baseline CSV document the PhiUSIIL shortcut (raw model flags 15/15 legitimate deep links).
- SQLite: connections are closed, WAL enabled, migrations run once per process.
- Added `SECURITY.md`, `CITATION.cff`, this changelog; local `file:///` links replaced with relative links.

### Tests
- New: `test_security.py`, `test_prevention_safety.py`, `test_waf_signatures.py`, `test_detection_regressions.py`, shared `conftest.py` (isolated DB and token).

### Not done in this release (needs datasets or Windows)
- Retraining the phishing model on legitimate URLs with paths.
- Day-held-out and cross-dataset (CSE-CIC-IDS2018) network evaluation; leave-one-corpus-out email evaluation.
- Aligning live flow features with CICFlowMeter (payload lengths, timeouts) and validating against a reference pcap.
- On-host verification of `run.bat`, Npcap capture and `netsh` rules on Windows.
