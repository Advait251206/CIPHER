"""
CIPHER Phishing Detection API Router
Exposes the core URL inspection endpoint for web extensions and local clients.
"""

from fastapi import APIRouter, HTTPException, status
from app.schemas.phishing import PhishingAnalyzeRequest, PhishingAnalyzeResponse
from app.services.phishing_service import PhishingService
from app.ml.model_loader import ModelLoader

router = APIRouter(prefix="/phishing", tags=["Phishing Analysis"])
phishing_service = PhishingService()


@router.post(
    "/analyze",
    response_model=PhishingAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze URL for Phishing Threats",
    description="Extracts 15 lexical/structural features, executes local ML inference, runs heuristic security engine, and returns unified risk assessment."
)
def analyze_phishing_url(request: PhishingAnalyzeRequest):
    loader = ModelLoader()
    if not loader.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CIPHER ML model is not loaded or unavailable. Please run train_phishing_model.py first."
        )

    try:
        response = phishing_service.analyze_url(request)
        return response
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Phishing analysis encountered an unexpected error: {str(e)}"
        )
