"""
Shared pytest configuration.

- Isolates the SQLite database and API token from the developer's real ones.
- Makes every FastAPI TestClient send the API token by default, so existing tests
  exercise the authenticated API. Tests that check the auth layer itself pass
  ``headers={"X-CIPHER-Token": ""}`` or build a client with ``raw_client()``.
"""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="cipher-tests-")
os.environ.setdefault("DATABASE_PATH", os.path.join(_TMP, "cipher_test.db"))
os.environ["CIPHER_API_TOKEN"] = "test-token-0123456789"
# Tests must never touch the host firewall, whatever the developer's shell has set.
os.environ.pop("CIPHER_PREVENTION_MODE", None)

TEST_TOKEN = os.environ["CIPHER_API_TOKEN"]

from fastapi.testclient import TestClient  # noqa: E402

_original_init = TestClient.__init__


def _init_with_token(self, *args, **kwargs):
    _original_init(self, *args, **kwargs)
    self.headers.setdefault("X-CIPHER-Token", TEST_TOKEN)


TestClient.__init__ = _init_with_token


def raw_client(app):
    """A TestClient without the default API token."""
    client = TestClient(app)
    client.headers.pop("X-CIPHER-Token", None)
    return client
