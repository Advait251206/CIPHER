"""
CIPHER Detection Unit Tests
Validates FeatureExtractor, HeuristicEngine, and ThreatScorer across core attack vectors.
"""

import pytest
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
backend_root = os.path.dirname(current_dir)
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app.ml.feature_extractor import FeatureExtractor
from app.detection.heuristic_engine import HeuristicEngine
from app.detection.threat_scorer import ThreatScorer


@pytest.fixture
def extractor():
    return FeatureExtractor()


@pytest.fixture
def heuristics():
    return HeuristicEngine()


@pytest.fixture
def scorer():
    return ThreatScorer()


# 1. Legitimate URL
def test_legitimate_url(extractor, heuristics, scorer):
    url = "https://www.wikipedia.org"
    feats = extractor.extract_features(url)
    assert feats["IsHTTPS"] == 1
    assert feats["IsDomainIP"] == 0
    assert feats["SuspiciousKeywordCount"] == 0

    h_res = heuristics.analyze_url(url)
    assert h_res["heuristic_score"] == 0
    assert "No overt structural" in h_res["reasons"][0]

    risk, severity, classification, conf = scorer.calculate_risk(0.01, h_res["heuristic_score"])
    assert classification == "LEGITIMATE"
    assert severity == "LOW"
    assert risk < 20


# 2. Clearly Suspicious URL
def test_clearly_suspicious_url(extractor, heuristics, scorer):
    url = "http://secure-login-update.account-verification-alert.xyz/auth/token?session=982348"
    feats = extractor.extract_features(url)
    assert feats["IsHTTPS"] == 0
    assert feats["SuspiciousKeywordCount"] >= 3
    assert feats["IsSuspiciousTLD"] == 1

    h_res = heuristics.analyze_url(url)
    assert h_res["heuristic_score"] >= 50
    assert any("High-abuse top-level domain" in r for r in h_res["reasons"])

    risk, severity, classification, conf = scorer.calculate_risk(0.95, h_res["heuristic_score"])
    assert classification == "LIKELY_PHISHING"
    assert severity in ["HIGH", "CRITICAL"]
    assert risk >= 75


# 3. URL containing IP Address
def test_url_containing_ip_address(extractor, heuristics, scorer):
    url = "http://192.168.1.105/admin/login.php?user=admin"
    feats = extractor.extract_features(url)
    assert feats["IsDomainIP"] == 1

    h_res = heuristics.analyze_url(url)
    assert h_res["indicators"]["is_domain_ip"] is True
    assert any("Raw IPv4 address" in r for r in h_res["reasons"])
    assert h_res["heuristic_score"] >= 45


# 4. Lookalike / Brand Impersonation Domain
def test_lookalike_brand_domain(heuristics, scorer):
    url = "http://paypal-account-security-update.com/signin"
    h_res = heuristics.analyze_url(url)
    assert h_res["indicators"]["brand_impersonation"] == "paypal"
    assert any("Potential brand impersonation" in r for r in h_res["reasons"])
    assert h_res["heuristic_score"] >= 40


# 5. Suspicious Login URL
def test_suspicious_login_url(extractor, heuristics):
    url = "http://client-verification-portal.net/update-password"
    feats = extractor.extract_features(url)
    assert feats["SuspiciousKeywordCount"] >= 2
    h_res = heuristics.analyze_url(url)
    assert len(h_res["indicators"]["credential_keywords"]) >= 2


# 6. Long / Suspicious URL
def test_long_suspicious_url(extractor, heuristics):
    url = "http://target-subdomain.portal-access.com/" + "a" * 150 + "/login.php?id=987293847293847"
    feats = extractor.extract_features(url)
    assert feats["URLLength"] > 120
    h_res = heuristics.analyze_url(url)
    assert h_res["indicators"]["excessive_length"] is True


# 7. URL with @ Character (Credential Spoofing)
def test_url_with_at_character(extractor, heuristics, scorer):
    url = "http://google.com@attacker-site.com/fake-login"
    feats = extractor.extract_features(url)
    assert feats["NoOfAtInURL"] == 1
    assert feats["HasObfuscation"] == 1

    h_res = heuristics.analyze_url(url)
    assert h_res["indicators"]["has_at_symbol"] is True
    assert h_res["heuristic_score"] >= 50
    assert any("@' symbol" in r for r in h_res["reasons"])

    risk, severity, classification, conf = scorer.calculate_risk(0.60, h_res["heuristic_score"])
    # Critical override ensures risk cannot be suppressed
    assert risk >= 70


# 8. Punycode / Homograph Domain
def test_punycode_url(heuristics):
    url = "http://xn--pple-43d.com/login"
    h_res = heuristics.analyze_url(url)
    assert h_res["indicators"]["is_punycode"] is True
    assert any("Punycode" in r for r in h_res["reasons"])
