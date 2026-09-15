"""
CIPHER Email Phishing API Router
Exposes email threat analysis, text inspection, model evaluation telemetry,
and health readiness probes for local clients and the CIPHER Browser Guard extension.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.schemas.email import (
    EmailAnalyzeRequest,
    EmailAnalyzeResponse,
    EmailModelInfoResponse,
    EmailHealthResponse
)
from app.services.email_service import EmailService

router = APIRouter(prefix="/email", tags=["Email Phishing Analysis"])

# Service singleton
_email_service: Optional[EmailService] = None


def get_email_service() -> EmailService:
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service


class QuickTextAnalyzeRequest(BaseModel):
    text: str = Field(..., max_length=500_000, description="Raw email text (subject + body)")
    sender: Optional[str] = Field(default="", max_length=1000, description="Optional sender header line")


@router.post(
    "/analyze",
    response_model=EmailAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Email for Phishing and Fraud Threats",
    description="Extracts 32 lexical, behavioral, HTML, and sender features, executes local ML inference, inspects embedded URLs, queries threat intelligence IOCs, and returns a unified risk assessment."
)
def analyze_email(request: EmailAnalyzeRequest):
    service = get_email_service()
    if not service.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CIPHER Email ML model is not loaded or unavailable."
        )

    try:
        return service.analyze_email(request)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email analysis encountered an unexpected error: {str(e)}"
        )


@router.post(
    "/analyze-text",
    response_model=EmailAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Quick Raw Text Email Analysis",
    description="Convenience endpoint for inspecting plain email text or clipboard content."
)
def analyze_email_text(request: QuickTextAnalyzeRequest):
    service = get_email_service()
    if not service.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CIPHER Email ML model is not loaded or unavailable."
        )

    try:
        structured_req = EmailAnalyzeRequest(
            subject="",
            body=request.text,
            sender=request.sender or ""
        )
        return service.analyze_email(structured_req)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email text analysis encountered an unexpected error: {str(e)}"
        )


@router.get(
    "/model",
    response_model=EmailModelInfoResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Email Model Metadata & Benchmark Metrics",
    description="Returns model architecture, feature names, held-out test evaluation benchmarks, and training date."
)
def get_email_model_info():
    service = get_email_service()
    return service.get_model_info()


@router.get(
    "/health",
    response_model=EmailHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Email Phishing Subsystem Health Probe",
    description="Readiness probe returning model load status and feature count."
)
def get_email_health():
    service = get_email_service()
    return service.get_health()
