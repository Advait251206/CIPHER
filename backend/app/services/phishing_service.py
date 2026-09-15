"""
CIPHER Phishing Detection Service
End-to-end orchestration service integrating feature extraction, local ML inference,
heuristic rule analysis, risk synthesis, and event auditing.
"""

import os
import json
import urllib.parse
import ipaddress
import contextlib
from typing import Dict, Any, Optional

from app.ml.feature_extractor import FeatureExtractor
from app.ml.predictor import Predictor
from app.detection.heuristic_engine import HeuristicEngine
from app.detection.threat_scorer import ThreatScorer
from app.services.explanation_service import ExplanationService
from app.services.event_service import EventService
from app.schemas.phishing import PhishingAnalyzeRequest, PhishingAnalyzeResponse


class PhishingService:
    """Core detection engine orchestrator."""

    # Load trusted domains once at startup
    TRUSTED_DOMAINS = {
        'wikipedia.org', 'google.com', 'github.com', 'microsoft.com',
        'apple.com', 'amazon.com', 'cloudflare.com', 'mozilla.org',
        'stackoverflow.com', 'linkedin.com', 'youtube.com', 'twitter.com',
        'facebook.com', 'instagram.com', 'netflix.com', 'reddit.com',
        'bing.com', 'yahoo.com', 'zoom.us', 'office.com', 'live.com'
    }
    
    _trusted_file = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'trusted_domains.json')
    if os.path.exists(_trusted_file):
        try:
            with open(_trusted_file, 'r') as _f:
                TRUSTED_DOMAINS.update(json.load(_f))
        except Exception:
            pass

    def __init__(
        self,
        extractor: Optional[FeatureExtractor] = None,
        predictor: Optional[Predictor] = None,
        heuristic_engine: Optional[HeuristicEngine] = None,
        threat_scorer: Optional[ThreatScorer] = None,
        explanation_service: Optional[ExplanationService] = None,
        event_service: Optional[EventService] = None
    ):
        self.extractor = extractor or FeatureExtractor()
        self.predictor = predictor or Predictor()
        self.heuristic_engine = heuristic_engine or HeuristicEngine()
        self.threat_scorer = threat_scorer or ThreatScorer()
        self.explanation_service = explanation_service or ExplanationService()
        self.event_service = event_service or EventService()

    @staticmethod
    def _extract_safe_domain(url: str) -> str:
        """Extracts sanitized domain name, excluding private query parameters or paths."""
        try:
            url_to_parse = url if "://" in url else f"http://{url}"
            parsed = urllib.parse.urlparse(url_to_parse)
            netloc = parsed.netloc or parsed.path.split('/')[0]
            domain = netloc.split(':')[0].lower()
            return domain if domain else "unknown-domain"
        except Exception:
            return "unparseable-domain"

    def analyze_url(self, request: PhishingAnalyzeRequest) -> PhishingAnalyzeResponse:
        """
        Executes end-to-end phishing threat analysis.
        Fails safely if ML or dependencies are unavailable without returning fake data.
        """
        raw_url = request.url
        
        safe_domain = self._extract_safe_domain(raw_url)
        
        is_trusted = False
        
        # 1. Check strict whitelist matches (top domains)
        if any(safe_domain == td or safe_domain.endswith(f".{td}") for td in self.TRUSTED_DOMAINS):
            is_trusted = True
            
        # 2. Check for local/development environments (localhost, 127.0.0.1, private IPs)
        if not is_trusted:
            if safe_domain in ('localhost', '0.0.0.0', '::1'):
                is_trusted = True
            else:
                with contextlib.suppress(ValueError):
                    ip = ipaddress.ip_address(safe_domain)
                    if ip.is_private or ip.is_loopback or ip.is_link_local:
                        is_trusted = True
        
        if is_trusted:
            # Force trusted classification, bypassing ML and heuristics
            classification = "LEGITIMATE"
            risk_score = 0
            severity = "LOW"
            confidence = 1.0
            ml_prob = 0.0
            heuristic_score = 0
            model_version = "cipher-whitelist-v1"
            reasons = ["Domain matches known trusted root domain whitelist"]
            recommendation = "SAFE: Website is a known trusted entity. Proceed normally."
        else:
            # 1. Feature Extraction (Deterministic, pure Python, <1ms)
            try:
                features = self.extractor.extract_features(raw_url)
            except Exception as e:
                raise ValueError(f"Feature extraction failed on provided URL: {str(e)}")
    
            # 2. Local ML Inference
            ml_prob, model_version = self.predictor.predict_phishing_probability(features)
    
            # 3. Independent Heuristic Analysis
            heuristic_result = self.heuristic_engine.analyze_url(raw_url)
            heuristic_score = heuristic_result["heuristic_score"]
            heuristic_reasons = heuristic_result["reasons"]
    
            # 4. Threat Scoring & Decision Synthesis
            risk_score, severity, classification, confidence = self.threat_scorer.calculate_risk(
                ml_phishing_prob=ml_prob,
                heuristic_score=heuristic_score
            )
    
            # 5. User-Facing Recommendation
            recommendation = self.threat_scorer.get_recommendation(severity, classification)
    
            # 6. Explanation Generation
            reasons = self.explanation_service.generate_explanations(
                features=features,
                heuristic_reasons=heuristic_reasons,
                ml_prob=ml_prob,
                classification=classification
            )

        # 7. Privacy-Preserving Event Persistence
        # Extracts only domain hostname - NEVER logs query string or potential auth tokens
        safe_domain = self._extract_safe_domain(raw_url)
        event_id = None
        try:
            event_id = self.event_service.record_scan_event(
                domain=safe_domain,
                classification=classification,
                risk_score=risk_score,
                confidence=confidence,
                severity=severity,
                ml_score=ml_prob,
                heuristic_score=heuristic_score,
                reasons=reasons,
                recommendation=recommendation,
                model_version=model_version,
                source=request.source or "api"
            )
        except Exception as e:
            # Event logging failure should not abort analysis response, but should be noted
            pass

        return PhishingAnalyzeResponse(
            classification=classification,
            risk_score=risk_score,
            severity=severity,
            confidence=confidence,
            ml_score=ml_prob,
            heuristic_score=heuristic_score,
            reasons=reasons,
            recommendation=recommendation,
            model_version=model_version,
            event_id=event_id
        )
