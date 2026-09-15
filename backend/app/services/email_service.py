"""
CIPHER Email Phishing Detection Service
Orchestrates end-to-end email threat analysis combining:
1. 32-feature extraction from email parts
2. Local Email Random Forest inference
3. Embedded URL extraction and authoritative inspection via CIPHER PhishingService
4. Threat Intelligence IOC correlation on sender and link domains
5. Calibrated risk synthesis via ThreatScorer
6. Feature-grounded explainability via EmailExplanationService
7. Privacy-preserving event persistence (never storing raw email bodies).
"""

import os
import re
import json
import uuid
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import joblib
import numpy as np

from app.ml.email_feature_extractor import EmailFeatureExtractor
from app.detection.threat_scorer import ThreatScorer
from app.services.email_explanation_service import EmailExplanationService
from app.services.phishing_service import PhishingService
from app.threat_intel.service import ThreatIntelService
from app.database.database import Database
from app.schemas.email import (
    EmailAnalyzeRequest,
    EmailAnalyzeResponse,
    EmailUrlAnalysisResult,
    EmailModelInfoResponse,
    EmailHealthResponse
)
from app.schemas.phishing import PhishingAnalyzeRequest

logger = logging.getLogger("cipher.services.email")


class EmailService:
    """Core detection engine orchestrator for Email Phishing."""

    def __init__(
        self,
        extractor: Optional[EmailFeatureExtractor] = None,
        threat_scorer: Optional[ThreatScorer] = None,
        explanation_service: Optional[EmailExplanationService] = None,
        phishing_service: Optional[PhishingService] = None,
        threat_intel: Optional[ThreatIntelService] = None,
        db: Optional[Database] = None,
        models_dir: Optional[str] = None
    ):
        self.extractor = extractor or EmailFeatureExtractor()
        self.threat_scorer = threat_scorer or ThreatScorer()
        self.explanation_service = explanation_service or EmailExplanationService()
        self.phishing_service = phishing_service or PhishingService()
        self.threat_intel = threat_intel or ThreatIntelService()
        self.db = db or Database()

        # Locate models directory
        if models_dir is None:
            backend_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            models_dir = os.path.join(backend_root, "models", "email")
        self.models_dir = models_dir

        self.model = None
        self.pipeline = None
        self.metadata = {}
        self.model_version = "cipher-email-rf-v1"
        self._load_model()

    def _load_model(self):
        """Loads trained email model, feature pipeline, and metadata from disk."""
        model_path = os.path.join(self.models_dir, "email_phishing_model.joblib")
        pipeline_path = os.path.join(self.models_dir, "email_feature_pipeline.joblib")
        meta_path = os.path.join(self.models_dir, "email_model_metadata.json")

        if os.path.exists(model_path) and os.path.exists(pipeline_path):
            try:
                self.model = joblib.load(model_path)
                self.pipeline = joblib.load(pipeline_path)
                logger.info(f"Loaded CIPHER Email Phishing Model from {model_path}")
            except Exception as e:
                logger.error(f"Failed to load email model: {e}")

        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                    self.model_version = self.metadata.get("model_version", "cipher-email-rf-v1")
            except Exception as e:
                logger.warning(f"Could not load email model metadata: {e}")

    @property
    def is_ready(self) -> bool:
        """Returns True if the ML model and pipeline are fully loaded."""
        return self.model is not None and self.pipeline is not None

    @staticmethod
    def _extract_sender_domain(sender_str: str) -> str:
        """Sanitizes and extracts the sender's domain."""
        if not sender_str:
            return "unknown-sender"
        m = re.search(r'[\w\.-]+@([\w\.-]+)', sender_str)
        if m:
            return m.group(1).lower().strip()
        return "unparseable-sender"

    def _calculate_heuristic_score(self, features: Dict[str, float]) -> int:
        """
        Computes deterministic heuristic penalty score (0-100)
        from active behavioral, semantic, and structural triggers.
        """
        score = 0

        # Behavioral triggers
        score += int(features.get("urgency_term_count", 0)) * 15
        score += int(features.get("threat_term_count", 0)) * 20
        score += int(features.get("credential_term_count", 0)) * 25
        score += int(features.get("financial_term_count", 0)) * 15
        score += int(features.get("suspicious_cta_count", 0)) * 15

        # Structural & sender anomalies
        if features.get("sender_display_name_mismatch", 0) > 0:
            score += 35
        if features.get("has_ip_sender", 0) > 0:
            score += 30
        if features.get("ip_url_count", 0) > 0:
            score += 30
        if features.get("at_symbol_url_count", 0) > 0:
            score += 25
        if features.get("suspicious_tld_url_count", 0) > 0:
            score += 25
        if features.get("hidden_text_indicators", 0) > 0:
            score += 20

        return min(100, max(0, score))

    def analyze_email(self, request: EmailAnalyzeRequest) -> EmailAnalyzeResponse:
        """
        Executes end-to-end email threat analysis.
        Follows local-first privacy rules: raw body content is never stored.
        """
        if not self.is_ready:
            raise RuntimeError("CIPHER Email Phishing model is not loaded or unavailable.")

        subject = request.subject or ""
        body = request.body or ""
        sender = request.sender or ""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Feature Extraction (Deterministic, 32 features)
        features = self.extractor.extract_features(
            subject=subject,
            body=body,
            sender=sender
        )

        # 2. Local ML Inference
        X = self.pipeline.transform(features)
        ml_prob = float(self.model.predict_proba(X)[0, 1])

        # 3. Deterministic Heuristic Engine
        heuristic_score = self._calculate_heuristic_score(features)

        # 4. Embedded URL Extraction & Authoritative Inspection
        found_urls = self.extractor.extract_urls(f"{subject} {body}")
        if request.urls:
            found_urls.extend(request.urls)
        found_urls = list(dict.fromkeys(found_urls))[:25]  # Deduplicate & cap to 25 URLs

        urls_analyzed: List[EmailUrlAnalysisResult] = []
        url_risk_scores: List[int] = []

        for u in found_urls:
            try:
                url_res = self.phishing_service.analyze_url(PhishingAnalyzeRequest(url=u))
                urls_analyzed.append(EmailUrlAnalysisResult(
                    url=u,
                    classification=url_res.classification,
                    risk_score=url_res.risk_score,
                    severity=url_res.severity,
                    confidence=url_res.confidence,
                    reasons=url_res.reasons
                ))
                url_risk_scores.append(url_res.risk_score)
            except Exception as e:
                logger.warning(f"URL analysis error for '{u}': {e}")

        # 5. Threat Intelligence Correlation
        ti_matches = []
        safe_sender_domain = self._extract_sender_domain(sender)
        if safe_sender_domain and safe_sender_domain not in ("unknown-sender", "unparseable-sender"):
            match = self.threat_intel.check_indicator(safe_sender_domain, ioc_type="DOMAIN")
            if match:
                ti_matches.append(match)

        for u in found_urls:
            u_match = self.threat_intel.check_indicator(u, ioc_type="URL")
            if u_match:
                ti_matches.append(u_match)
            try:
                parsed_u = urllib.parse.urlparse(u if "://" in u else f"http://{u}")
                domain_u = parsed_u.netloc.split(':')[0].lower()
                if domain_u:
                    d_match = self.threat_intel.check_indicator(domain_u, ioc_type="DOMAIN")
                    if d_match:
                        ti_matches.append(d_match)
            except Exception:
                pass

        # 6. Threat Scoring & Calibrated Decision Synthesis
        risk_score, severity, classification, confidence = self.threat_scorer.calculate_email_risk(
            ml_phishing_prob=ml_prob,
            heuristic_score=heuristic_score,
            url_risk_scores=url_risk_scores,
            ti_matches=ti_matches
        )

        has_malicious_urls = any(r >= 70 for r in url_risk_scores)
        recommendation = self.threat_scorer.get_email_recommendation(
            severity=severity,
            classification=classification,
            has_malicious_urls=has_malicious_urls
        )

        # 7. Explainability Generation
        evidence = self.explanation_service.generate_explanations(
            features=features,
            url_results=[u.model_dump() for u in urls_analyzed],
            ti_matches=ti_matches,
            ml_prob=ml_prob,
            classification=classification
        )

        # 8. Privacy-Preserving Event Persistence
        # Extracts only domain hostname - NEVER logs raw email body or query strings
        event_id = str(uuid.uuid4())
        try:
            event_data = {
                "event_id": event_id,
                "timestamp": timestamp,
                "classification": classification,
                "risk_score": risk_score,
                "confidence": confidence,
                "severity": severity,
                "ml_score": ml_prob,
                "heuristic_score": heuristic_score,
                "domain": safe_sender_domain,
                "reasons": evidence,
                "recommendation": recommendation,
                "model_version": self.model_version,
                "source": "EMAIL",
                "event_type": "EMAIL_PHISHING",
                "attack_type": "PHISHING" if classification != "LEGITIMATE" else None,
                "detection_method": "HYBRID",
                "action": "ALERT" if severity in ("HIGH", "CRITICAL") else "MONITOR",
                "status": "NEW",
                "metadata": {
                    "sender_domain": safe_sender_domain,
                    "url_count": len(urls_analyzed),
                    "subject_preview": (subject[:80] + "...") if len(subject) > 80 else subject,
                    "has_malicious_urls": has_malicious_urls
                }
            }
            self.db.save_event(event_data)
            try:
                from app.correlation.service import get_correlation_service
                get_correlation_service().process_event(event_data)
            except Exception:
                pass
        except Exception as db_err:
            logger.error(f"Failed to persist email security event: {db_err}")

        return EmailAnalyzeResponse(
            classification=classification,
            risk_score=risk_score,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            recommendation=recommendation,
            urls_analyzed=urls_analyzed,
            features=features,
            event_id=event_id,
            model_version=self.model_version,
            timestamp=timestamp
        )

    def get_model_info(self) -> EmailModelInfoResponse:
        """Returns model metadata and held-out test evaluation benchmarks."""
        return EmailModelInfoResponse(
            model_name=self.metadata.get("model_name", "Random Forest (100 trees, depth=20)"),
            model_version=self.model_version,
            feature_count=self.metadata.get("feature_count", 32),
            feature_names=self.metadata.get("feature_names", self.extractor.feature_names),
            test_metrics=self.metadata.get("test_metrics", {}),
            training_timestamp=self.metadata.get("training_timestamp", "2026-09-15T00:00:00Z")
        )

    def get_health(self) -> EmailHealthResponse:
        """Readiness check for the email detection engine."""
        return EmailHealthResponse(
            status="ok" if self.is_ready else "degraded",
            model_loaded=self.is_ready,
            feature_count=self.extractor.feature_count,
            version="1.0.0"
        )
