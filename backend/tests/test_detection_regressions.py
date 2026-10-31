"""Regression tests for detection-logic fixes (false positives and trivial evasions)."""

import pytest

from app.rules.engine import RuleEngine
from app.network.net_utils import is_broadcast_or_multicast, is_trusted_source
from app.services.phishing_service import PhishingService


def _matches(engine, ev):
    return {m.rule_id for m in engine.evaluate(ev)}


def test_three_ordinary_clients_are_not_a_ddos():
    engine = RuleEngine()
    hits = set()
    for i in range(5):
        hits |= _matches(engine, {"source_ip": f"198.51.100.{i + 1}", "destination_ip": "203.0.113.10",
                                  "destination_port": 443, "features": {"Flow Packets/s": 12.0}})
    assert "HEUR-DDOS-001" not in hits


def test_high_volume_from_many_sources_is_a_ddos():
    engine = RuleEngine()
    hits = set()
    for i in range(4):
        hits |= _matches(engine, {"source_ip": f"198.51.100.{i + 1}", "destination_ip": "203.0.113.11",
                                  "destination_port": 80, "features": {"Flow Packets/s": 5000.0}})
    assert "HEUR-DDOS-001" in hits


def test_normal_browsing_of_web_login_port_is_not_brute_force():
    engine = RuleEngine()
    hits = set()
    for _ in range(8):  # a page load opens several connections
        hits |= _matches(engine, {"source_ip": "198.51.100.5", "destination_ip": "203.0.113.12",
                                  "destination_port": 5174, "features": {}})
    assert "HEUR-BRUTEFORCE-001" not in hits


def test_ssh_storm_is_still_brute_force():
    engine = RuleEngine()
    hits = set()
    for _ in range(6):
        hits |= _matches(engine, {"source_ip": "198.51.100.6", "destination_ip": "203.0.113.13",
                                  "destination_port": 22, "features": {}})
    assert "HEUR-BRUTEFORCE-001" in hits


def test_broadcast_detection_is_not_a_suffix_check():
    assert is_broadcast_or_multicast("224.0.0.251")
    assert is_broadcast_or_multicast("255.255.255.255")
    assert not is_broadcast_or_multicast("8.8.8.8")
    # In a /16 this is an ordinary host; it is only a broadcast if a local route says so.
    from app.network.net_utils import _local_directed_broadcasts
    assert is_broadcast_or_multicast("172.31.4.255") == ("172.31.4.255" in _local_directed_broadcasts())


def test_no_builtin_trusted_sources(monkeypatch):
    monkeypatch.delenv("CIPHER_TRUSTED_SOURCES", raising=False)
    for ip in ["192.168.1.66", "10.0.0.5", "20.1.2.3", "140.82.112.3"]:
        assert not is_trusted_source(ip)
    monkeypatch.setenv("CIPHER_TRUSTED_SOURCES", "10.9.0.0/16")
    assert is_trusted_source("10.9.1.1")


def test_spoofed_source_port_does_not_hide_a_flood():
    from app.network.service import NetworkService
    from app.network.schemas import NetworkFlowAnalyzeRequest
    svc = NetworkService()
    features = {"Flow Packets/s": 80000.0, "Fwd Packets/s": 80000.0, "Flow Bytes/s": 9_000_000.0,
                "Total Fwd Packets": 5000.0, "Total Backward Packets": 0.0, "Destination Port": 80.0,
                "Flow Duration": 60000.0}
    res = svc.analyze_flow(NetworkFlowAnalyzeRequest(
        source_ip="198.51.100.77", destination_ip="203.0.113.20", source_port=80,
        destination_port=80, protocol="TCP", features=features))
    assert res.attack_type in ("DOS", "DDOS")


@pytest.mark.parametrize("domain,expected", [
    ("github.com", True),
    ("www.google.com", True),
    ("sites.google.com", False),
    ("docs.google.com", False),
    ("evil.github.io", False),
    ("forms.office.com", False),
    ("google.com.evil.top", False),
])
def test_whitelist_excludes_user_content_hosts(domain, expected):
    assert PhishingService.is_whitelisted_domain(domain) is expected


def test_lan_phishing_page_is_not_auto_trusted():
    from fastapi.testclient import TestClient
    from app.main import app
    r = TestClient(app).post("/api/phishing/analyze", json={"url": "http://192.168.1.66/paypal/login.php"})
    assert r.status_code == 200
    assert r.json()["model_version"] != "cipher-whitelist-v1"


def test_tranco_domain_two_tier_whitelist():
    sample_domain = "example-tranco-partner.org"
    original_tranco = PhishingService.TRANCO_DOMAINS.copy()
    try:
        PhishingService.TRANCO_DOMAINS.add(sample_domain)
        # Exact domain trusted
        assert PhishingService.is_whitelisted_domain(sample_domain) is True
        # www.<domain> trusted
        assert PhishingService.is_whitelisted_domain(f"www.{sample_domain}") is True
        # Arbitrary subdomain NOT trusted
        assert PhishingService.is_whitelisted_domain(f"evil.{sample_domain}") is False
        assert PhishingService.is_whitelisted_domain(f"sub.sub2.{sample_domain}") is False
    finally:
        PhishingService.TRANCO_DOMAINS = original_tranco


def test_user_content_hosts_never_trusted_even_if_in_tranco():
    original_tranco = PhishingService.TRANCO_DOMAINS.copy()
    try:
        PhishingService.TRANCO_DOMAINS.add("sites.google.com")
        PhishingService.TRANCO_DOMAINS.add("phish.github.io")
        assert PhishingService.is_whitelisted_domain("sites.google.com") is False
        assert PhishingService.is_whitelisted_domain("phish.github.io") is False
    finally:
        PhishingService.TRANCO_DOMAINS = original_tranco


def test_service_robust_without_tranco_file():
    original_tranco = PhishingService.TRANCO_DOMAINS.copy()
    try:
        PhishingService.TRANCO_DOMAINS = set()
        # Curated tier-1 domains must still work with subdomain matching
        assert PhishingService.is_whitelisted_domain("google.com") is True
        assert PhishingService.is_whitelisted_domain("mail.google.com") is True
        assert PhishingService.is_whitelisted_domain("github.com") is True
        # User content hosts still blocked
        assert PhishingService.is_whitelisted_domain("docs.google.com") is False
    finally:
        PhishingService.TRANCO_DOMAINS = original_tranco
