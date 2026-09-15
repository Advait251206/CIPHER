"""
CIPHER Email Detection Unit Tests
Tests EmailFeatureExtractor, EmailFeaturePipeline, ThreatScorer email methods,
and EmailExplanationService.
"""

import pytest
import numpy as np

from app.ml.email_feature_extractor import EmailFeatureExtractor, EmailFeaturePipeline
from app.detection.threat_scorer import ThreatScorer
from app.services.email_explanation_service import EmailExplanationService


class TestEmailFeatureExtractor:
    """Validates 32-feature extraction logic, regex parsers, and edge cases."""

    def setup_method(self):
        self.extractor = EmailFeatureExtractor()

    def test_feature_count_and_names(self):
        assert self.extractor.feature_count == 32
        assert len(self.extractor.feature_names) == 32
        assert "urgency_term_count" in self.extractor.feature_names
        assert "credential_term_count" in self.extractor.feature_names
        assert "url_count" in self.extractor.feature_names
        assert "sender_display_name_mismatch" in self.extractor.feature_names

    def test_url_extraction(self):
        text = "Visit https://secure.bank.com/login and http://192.168.1.1/admin or www.paypal-verify.xyz/update."
        urls = self.extractor.extract_urls(text)
        assert len(urls) == 3
        assert "https://secure.bank.com/login" in urls
        assert "http://192.168.1.1/admin" in urls
        assert any("paypal-verify.xyz" in u for u in urls)

    def test_lexical_urgency_and_threat_features(self):
        subject = "URGENT NOTICE: Final deadline to avoid suspension!"
        body = "Your account will be terminated and suspended within 24 hours due to unauthorized access. Act immediately!"
        feats = self.extractor.extract_features(subject=subject, body=body)

        assert feats["urgency_term_count"] >= 2
        assert feats["threat_term_count"] >= 2
        assert feats["exclamation_count"] == 2
        assert feats["has_urls"] == 0.0

    def test_credential_and_financial_features(self):
        body = "Please confirm your password and login credentials to receive your wire transfer refund of $5,000 USD."
        feats = self.extractor.extract_features(body=body)

        assert feats["credential_term_count"] >= 2
        assert feats["financial_term_count"] >= 2
        assert feats["currency_symbol_count"] >= 1.0

    def test_sender_brand_mismatch(self):
        # Display name claims PayPal, but domain is bad-domain.com
        feats = self.extractor.extract_features(
            body="Normal body",
            sender='"PayPal Account Security" <alert@bad-domain.com>'
        )
        assert feats["sender_display_name_mismatch"] == 1.0
        assert feats["is_freemail_sender"] == 0.0

        # Legitimate sender: domain matches brand
        feats_legit = self.extractor.extract_features(
            body="Normal body",
            sender='"PayPal Support" <support@paypal.com>'
        )
        assert feats_legit["sender_display_name_mismatch"] == 0.0

    def test_freemail_sender_detection(self):
        feats = self.extractor.extract_features(
            body="Please reply with password",
            sender="CEO Office <ceo.exec@gmail.com>"
        )
        assert feats["is_freemail_sender"] == 1.0

    def test_empty_and_null_inputs(self):
        feats = self.extractor.extract_features(subject=None, body=None, sender=None)
        assert len(feats) == 32
        for k, v in feats.items():
            assert not np.isnan(v)
            assert not np.isinf(v)


class TestEmailFeaturePipeline:
    """Tests input sanitization and feature array transformation."""

    def test_pipeline_transform_dict(self):
        extractor = EmailFeatureExtractor()
        pipeline = EmailFeaturePipeline(extractor.feature_names)
        feats = extractor.extract_features(subject="Test", body="Hello world")
        pipeline.fit(feats)
        arr = pipeline.transform(feats)

        assert isinstance(arr, np.ndarray)
        assert arr.shape == (1, 32)
        assert not np.isnan(arr).any()
        assert not np.isinf(arr).any()


class TestThreatScorerEmail:
    """Tests calibrated email threat scoring, URL synthesis, and recommendation."""

    def setup_method(self):
        self.scorer = ThreatScorer()

    def test_benign_email_scoring(self):
        risk, severity, classification, conf = self.scorer.calculate_email_risk(
            ml_phishing_prob=0.05,
            heuristic_score=0,
            url_risk_scores=[10],
            ti_matches=[]
        )
        assert risk <= 24
        assert severity == "LOW"
        assert classification == "LEGITIMATE"
        assert conf >= 0.90

    def test_malicious_email_with_weaponized_url(self):
        risk, severity, classification, conf = self.scorer.calculate_email_risk(
            ml_phishing_prob=0.85,
            heuristic_score=60,
            url_risk_scores=[95],
            ti_matches=[]
        )
        assert risk >= 75
        assert severity == "CRITICAL"
        assert classification == "MALICIOUS_EMAIL"

    def test_recommendation_strings(self):
        rec_crit = self.scorer.get_email_recommendation("CRITICAL", "MALICIOUS_EMAIL", has_malicious_urls=True)
        assert "DANGER" in rec_crit
        assert "weaponized" in rec_crit

        rec_safe = self.scorer.get_email_recommendation("LOW", "LEGITIMATE", has_malicious_urls=False)
        assert "SAFE" in rec_safe


class TestEmailExplanationService:
    """Tests explainable evidence generation."""

    def setup_method(self):
        self.service = EmailExplanationService()

    def test_evidence_generation_matches_triggers(self):
        features = {
            "urgency_term_count": 3.0,
            "credential_term_count": 2.0,
            "sender_display_name_mismatch": 1.0,
            "ip_url_count": 1.0
        }
        url_results = [
            {"url": "http://192.168.1.5/login", "classification": "LIKELY_PHISHING", "risk_score": 92}
        ]

        evidence = self.service.generate_explanations(
            features=features,
            url_results=url_results,
            classification="MALICIOUS_EMAIL"
        )

        assert any("Weaponized URL" in e for e in evidence)
        assert any("Urgent" in e for e in evidence)
        assert any("Credential" in e for e in evidence)
        assert any("mismatch" in e for e in evidence)
        assert any("raw IP address" in e for e in evidence)
