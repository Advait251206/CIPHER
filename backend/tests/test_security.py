"""
Security regression tests for the CIPHER API control plane.
Covers CORS, the API token, Origin (CSRF) checks and the browser-launch endpoint.
"""

from unittest import mock

from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import TEST_TOKEN, raw_client

EVIL = "https://evil.example"


def test_cors_preflight_from_untrusted_origin_is_not_allowed():
    client = raw_client(app)
    r = client.options(
        "/api/extension/launch",
        headers={"Origin": EVIL, "Access-Control-Request-Method": "POST",
                 "Access-Control-Request-Headers": "content-type"},
    )
    assert r.headers.get("access-control-allow-origin") != EVIL
    assert r.headers.get("access-control-allow-origin") != "*"


def test_cors_preflight_from_dashboard_is_allowed():
    client = raw_client(app)
    r = client.options(
        "/api/network/prevention-mode",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST",
                 "Access-Control-Request-Headers": "content-type,x-cipher-token"},
    )
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_state_changing_request_without_token_is_rejected():
    client = raw_client(app)
    for method, path in [
        ("post", "/api/network/blocklist/203.0.113.10"),
        ("post", "/api/waf/config"),
        ("post", "/api/network/prevention-mode"),
        ("post", "/api/extension/launch"),
        ("delete", "/api/network/blocklist/203.0.113.10"),
    ]:
        r = getattr(client, method)(path)
        assert r.status_code == 401, (method, path, r.status_code)


def test_wrong_token_is_rejected():
    client = raw_client(app)
    r = client.post("/api/network/prevention-mode", json={"mode": "detect_only"},
                    headers={"X-CIPHER-Token": "wrong"})
    assert r.status_code == 401


def test_untrusted_origin_is_rejected_even_with_token():
    client = TestClient(app)
    r = client.post("/api/network/prevention-mode", json={"mode": "detect_only"},
                    headers={"Origin": EVIL, "X-CIPHER-Token": TEST_TOKEN})
    assert r.status_code == 403


def test_extension_analysis_endpoint_needs_no_token_but_checks_origin():
    client = raw_client(app)
    ok = client.post("/api/phishing/analyze", json={"url": "https://example.com"},
                     headers={"Origin": "chrome-extension://abcdefghijklmnop"})
    assert ok.status_code != 401
    bad = client.post("/api/phishing/analyze", json={"url": "https://example.com"},
                      headers={"Origin": EVIL})
    assert bad.status_code == 403


def test_get_requests_do_not_need_token():
    client = raw_client(app)
    assert client.get("/api/health").status_code == 200


def test_launch_rejects_argument_injection():
    client = TestClient(app)
    with mock.patch("app.api.extension.subprocess.Popen") as popen:
        for bad in ["--gpu-launcher=calc.exe", "-x", "javascript:alert(1)", "file:///etc/passwd",
                    "http://a b", ""]:
            r = client.post("/api/extension/launch", json={"target_url": bad})
            assert r.status_code == 400, bad
        assert not popen.called


def test_launch_puts_url_after_switch_terminator():
    client = TestClient(app)
    with mock.patch("app.api.extension.shutil.which", return_value="/usr/bin/google-chrome"), \
         mock.patch("app.api.extension.platform.system", return_value="Linux"), \
         mock.patch("app.api.extension.subprocess.Popen") as popen:
        r = client.post("/api/extension/launch", json={"target_url": "http://localhost:5173"})
        assert r.status_code == 200
        argv = popen.call_args[0][0]
        assert argv[-2:] == ["--", "http://localhost:5173"]
