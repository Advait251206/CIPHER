"""
CIPHER Email Analysis Schemas
Pydantic schemas for structured email threat inspection requests, comprehensive responses,
and model metadata telemetry.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


MAX_BODY_CHARS = 500_000  # 500 KB character limit protects against pathological payloads


class EmailAnalyzeRequest(BaseModel):
    """Structured email inspection payload."""
    sender: Optional[str] = Field(default="", description="Sender header line, e.g. 'Security <support@example.com>'")
    recipient: Optional[str] = Field(default="", description="Recipient address, e.g. 'user@company.com'")
    subject: Optional[str] = Field(default="", description="Email subject line")
    body: Optional[str] = Field(default="", description="Email body content in plain text or HTML")
    urls: Optional[List[str]] = Field(default=None, description="Optional pre-extracted URLs; if omitted, automatically parsed from body/subject")

    @field_validator("body")
    @classmethod
    def validate_body_length(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > MAX_BODY_CHARS:
            raise ValueError(f"Email body exceeds maximum allowable length ({MAX_BODY_CHARS:,} characters).")
        return v

    @field_validator("subject")
    @classmethod
    def validate_subject_length(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > 10_000:
            raise ValueError("Email subject exceeds maximum allowable length (10,000 characters).")
        return v


class EmailUrlAnalysisResult(BaseModel):
    """Detailed verdict for an individual embedded URL inspected by the URL detector."""
    url: str
    classification: str
    risk_score: int
    severity: str
    confidence: float
    reasons: List[str]


class EmailAnalyzeResponse(BaseModel):
    """Complete unified risk assessment for an analyzed email."""
    classification: str = Field(description="'LEGITIMATE' | 'SUSPICIOUS' | 'MALICIOUS_EMAIL'")
    risk_score: int = Field(ge=0, le=100, description="Calibrated risk score (0-100)")
    severity: str = Field(description="'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'")
    confidence: float = Field(ge=0.0, le=1.0, description="Model prediction confidence")
    evidence: List[str] = Field(description="Actionable, feature-grounded detection rationale")
    recommendation: str = Field(description="SOC operational response recommendation")
    urls_analyzed: List[EmailUrlAnalysisResult] = Field(default_factory=list, description="Per-URL inspection outcomes")
    features: Dict[str, float] = Field(default_factory=dict, description="Extracted 32 email feature values")
    event_id: Optional[str] = Field(default=None, description="Unique security event ID in unified audit store")
    model_version: str = Field(default="cipher-email-rf-v1")
    timestamp: str


class EmailModelInfoResponse(BaseModel):
    """Email model metadata and held-out benchmark statistics."""
    model_name: str
    model_version: str
    feature_count: int
    feature_names: List[str]
    test_metrics: Dict[str, Any]
    training_timestamp: str


class EmailHealthResponse(BaseModel):
    """Readiness probe response for email detection subsystem."""
    status: str = "ok"
    model_loaded: bool
    feature_count: int
    version: str = "1.0.0"
