"""Regression tests for the local API's hardening.

The API listens on 127.0.0.1, but any web page the analyst has open can make
the browser send requests to it. These tests pin down what such a page must
not be able to do.
"""

import subprocess

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.prevention.prevention_engine import PreventionEngine

client = TestClient(app)


@pytest.fixture
def no_process_spawn(monkeypatch):
    """Fail the test if anything tries to start a process."""
    def forbidden(*args, **kwargs):
        raise AssertionError(f"process spawned: {args[0] if args else kwargs}")
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.parametrize("target_url", [
    "--renderer-cmd-prefix=calc.exe",      # would be parsed as a Chrome flag
    "--gpu-launcher=cmd /c whoami",
    "file:///C:/Windows/System32/drivers/etc/hosts",
    "javascript:alert(1)",
    "localhost:5173",                       # no scheme
    "",
])
def test_launch_rejects_anything_but_http_urls(target_url, no_process_spawn):
    response = client.post("/api/extension/launch", json={"target_url": target_url})
    assert response.status_code == 400
    assert "http(s)" in response.json()["detail"]


def test_cors_rejects_foreign_origins():
    """A random website must not be allowed to call the API from the browser."""
    response = client.options(
        "/api/extension/launch",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.headers.get("access-control-allow-origin") is None


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:5173"])
def test_cors_allows_the_dashboard(origin):
    response = client.options(
        "/api/system/status",
        headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
    )
    assert response.headers.get("access-control-allow-origin") == origin


def test_prevention_defaults_to_detect_only(monkeypatch):
    monkeypatch.delenv("CIPHER_PREVENTION_MODE", raising=False)
    assert PreventionEngine().mode == "detect_only"


def test_invalid_prevention_mode_fails_safe(monkeypatch):
    """A typo in the environment must never switch blocking on."""
    monkeypatch.setenv("CIPHER_PREVENTION_MODE", "enforcee")
    assert PreventionEngine().mode == "detect_only"
