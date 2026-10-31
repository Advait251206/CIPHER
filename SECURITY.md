# Security Policy

CIPHER is a research prototype of a host-level intrusion detection and prevention system. It can change the host firewall, so its own control plane is treated as security-critical.

## Threat model

| Asset | Threat | Control |
| --- | --- | --- |
| Backend API (`127.0.0.1:8000`) | A web page in the analyst's browser calling the local API (CSRF / DNS-rebinding style) | CORS allow-list (dashboard + browser extensions only); `Origin` check on every state-changing request; `X-CIPHER-Token` required on every POST/PUT/PATCH/DELETE |
| Backend API | Other hosts on the LAN | Backend binds to `127.0.0.1` only |
| Host firewall | Unintended or attacker-induced blocking (spoofed source addresses) | Default mode `detect_only`; invalid modes fall back to `detect_only`; `netsh` is called only in `enforce`; IPs are validated and loopback, link-local, multicast, this host and `CIPHER_PROTECTED_IPS` are never blocked; expired blocks remove their rule |
| Browser launch endpoint | Argument injection into Chromium | URL must be absolute `http(s)`; passed after a `--` switch terminator |
| Analyst workstation | Compromise through the deliberately vulnerable demo app | Demo app runs **without** admin rights and binds to `127.0.0.1` unless you explicitly expose it in `run.bat` |

## The API token

On first start the backend creates `backend/.cipher_token` (gitignored, owner-readable only) unless `CIPHER_API_TOKEN` is set. The Vite dev proxy reads it and adds the header server-side, so the dashboard works without pasting the token anywhere. For scripts:

```bash
curl -X POST -H "X-CIPHER-Token: $(cat backend/.cipher_token)" \
     -H "Content-Type: application/json" -d '{"mode":"simulate"}' \
     http://127.0.0.1:8000/api/network/prevention-mode
```

The browser extension uses only the URL/email analysis endpoints, which are token-exempt but still require an allowed `Origin`.

## The vulnerable demo app

`vulnerable_app/` is intentionally exploitable (SQL injection via `executescript`, stored XSS, plaintext passwords). It exists only as an attack target for live demonstrations.

- Run it in a VM or on an isolated lab network whenever possible.
- Never run it with administrator rights: `executescript` permits `ATTACH DATABASE`, which can write files anywhere the process can.
- Only expose it to the LAN (the `run.bat` prompt) on a network you control, and close the port afterwards.

## Known limitations

- The WAF inspects single TCP segments of plaintext HTTP. It does not reassemble streams or see HTTPS.
- TCP RST injection is best-effort teardown from a passive tap. The request has already reached the application by the time the RST is sent.
- `RATE_LIMIT` is an advisory recommendation; CIPHER does not throttle traffic.

## Reporting a vulnerability

Please open a private security advisory on GitHub (Security tab → "Report a vulnerability") rather than a public issue. Include steps to reproduce and the commit you tested.
