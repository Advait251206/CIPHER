"""
CIPHER API access control.

Two independent layers protect every state-changing request:

1. Origin check (CSRF defence). Browsers attach an ``Origin`` header to
   cross-site POST/PUT/PATCH/DELETE requests. If one is present it must be in
   the allow-list (the dashboard, or a Chromium extension). This stops a
   malicious web page from driving the local API through the analyst's browser.

2. API token. Every state-changing request must carry ``X-CIPHER-Token``.
   The token comes from ``CIPHER_API_TOKEN`` or, if unset, is generated once and
   stored in ``backend/.cipher_token`` (gitignored, readable only by the owner).
   The Vite dev proxy reads that file and attaches the header server-side, so
   the token never has to be pasted into the browser.

A small set of read-only analysis endpoints (URL / email analysis used by the
browser extension) is exempt from the token but still subject to the Origin check.
"""

import os
import hmac
import secrets
import logging
from pathlib import Path
from typing import Iterable, List, Optional

logger = logging.getLogger("cipher.security")

BACKEND_ROOT = Path(__file__).resolve().parent.parent
TOKEN_FILE = BACKEND_ROOT / ".cipher_token"
TOKEN_HEADER = "X-CIPHER-Token"

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# Analysis-only endpoints the browser extension calls without a token.
# They never change prevention state; they still require an allowed Origin.
TOKEN_EXEMPT_PATHS = {
    "/api/phishing/analyze",
    "/api/email/analyze",
    "/api/email/analyze-text",
}

_cached_token: Optional[str] = None


def get_allowed_origins() -> List[str]:
    raw = os.getenv("CIPHER_ALLOWED_ORIGINS", "")
    extra = [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]
    return DEFAULT_ALLOWED_ORIGINS + extra


def is_origin_allowed(origin: Optional[str], allowed: Optional[Iterable[str]] = None) -> bool:
    """No Origin header (curl, scripts, same-process tests) is allowed; a browser Origin must match."""
    if not origin:
        return True
    origin = origin.rstrip("/")
    if origin.startswith("chrome-extension://") or origin.startswith("moz-extension://"):
        return True
    return origin in set(allowed if allowed is not None else get_allowed_origins())


def get_api_token() -> str:
    """Returns the API token, creating and persisting one on first use."""
    global _cached_token
    env_token = os.getenv("CIPHER_API_TOKEN", "").strip()
    if env_token:
        return env_token
    if _cached_token:
        return _cached_token
    try:
        if TOKEN_FILE.exists():
            token = TOKEN_FILE.read_text(encoding="utf-8").strip()
            if token:
                _cached_token = token
                return token
        token = secrets.token_urlsafe(32)
        TOKEN_FILE.write_text(token, encoding="utf-8")
        try:
            os.chmod(TOKEN_FILE, 0o600)
        except OSError:
            pass
        logger.warning(f"Generated new CIPHER API token in {TOKEN_FILE} (keep it private).")
        _cached_token = token
        return token
    except OSError as e:
        # Fall back to a process-lifetime token; nothing can authenticate without reading logs.
        logger.error(f"Could not persist API token ({e}); using an ephemeral token.")
        _cached_token = secrets.token_urlsafe(32)
        return _cached_token


def is_token_valid(presented: Optional[str]) -> bool:
    if not presented:
        return False
    return hmac.compare_digest(presented.strip(), get_api_token())


def requires_token(method: str, path: str) -> bool:
    if method.upper() not in STATE_CHANGING_METHODS:
        return False
    if not path.startswith("/api/"):
        return False
    return path.rstrip("/") not in TOKEN_EXEMPT_PATHS
