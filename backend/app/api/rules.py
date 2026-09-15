"""
CIPHER Deterministic Rule Engine API Router
Provides REST endpoints to inspect, configure, and evaluate heuristic and signature rules.
"""

from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, status

from app.rules.models import (
    RulesListResponse,
    RuleDetailResponse,
    RuleToggleResponse,
    RuleEvaluateResponse
)
from app.rules.engine import get_rule_engine
from app.rules import config

router = APIRouter(tags=["Heuristic & Signature Rules"])


@router.get("/rules", response_model=RulesListResponse, summary="List All Heuristic and Signature Rules")
def list_rules(
    category: Optional[str] = Query(default=None, description="Filter by attack category (PORT_SCAN, DOS, etc.)"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    enabled_only: bool = Query(default=False, description="Filter only enabled rules")
):
    """
    Retrieves all registered deterministic heuristic and signature rules.
    """
    engine = get_rule_engine()
    all_rules = engine.list_rules()

    filtered = []
    for r in all_rules:
        if enabled_only and not r.enabled:
            continue
        if category and r.category.upper() != category.upper():
            continue
        if severity and r.severity.upper() != severity.upper():
            continue
        filtered.append(r.to_item())

    enabled_count = sum(1 for r in all_rules if r.enabled)
    return RulesListResponse(
        total_rules=len(filtered),
        enabled_count=enabled_count,
        rules=filtered
    )


@router.get("/rules/{rule_id}", response_model=RuleDetailResponse, summary="Get Rule Details by ID")
def get_rule(rule_id: str):
    """
    Retrieves metadata, configuration, and thresholds for a specific deterministic rule.
    """
    engine = get_rule_engine()
    rule = engine.get_rule(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' was not found in the engine registry."
        )

    thresholds = {
        "PORT_SCAN_THRESHOLD": config.PORT_SCAN_THRESHOLD,
        "PORT_SCAN_WINDOW_SECONDS": config.PORT_SCAN_WINDOW_SECONDS,
        "BRUTE_FORCE_THRESHOLD": config.BRUTE_FORCE_THRESHOLD,
        "BRUTE_FORCE_WINDOW_SECONDS": config.BRUTE_FORCE_WINDOW_SECONDS,
        "DOS_PACKET_RATE_THRESHOLD": config.DOS_PACKET_RATE_THRESHOLD,
        "DOS_BYTE_RATE_THRESHOLD": config.DOS_BYTE_RATE_THRESHOLD,
        "DDOS_SOURCES_THRESHOLD": config.DDOS_SOURCES_THRESHOLD,
        "DDOS_WINDOW_SECONDS": config.DDOS_WINDOW_SECONDS
    }

    return RuleDetailResponse(
        rule=rule.to_item(),
        thresholds=thresholds
    )


@router.post("/rules/{rule_id}/enable", response_model=RuleToggleResponse, summary="Enable a Rule")
def enable_rule(rule_id: str):
    """Enables a disabled heuristic or signature rule."""
    engine = get_rule_engine()
    success = engine.set_rule_enabled(rule_id, True)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' not found."
        )
    return RuleToggleResponse(
        rule_id=rule_id,
        enabled=True,
        message=f"Rule '{rule_id}' successfully enabled."
    )


@router.post("/rules/{rule_id}/disable", response_model=RuleToggleResponse, summary="Disable a Rule")
def disable_rule(rule_id: str):
    """Disables an active heuristic or signature rule."""
    engine = get_rule_engine()
    success = engine.set_rule_enabled(rule_id, False)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id}' not found."
        )
    return RuleToggleResponse(
        rule_id=rule_id,
        enabled=False,
        message=f"Rule '{rule_id}' successfully disabled."
    )


@router.post("/rules/evaluate", response_model=RuleEvaluateResponse, summary="Directly Evaluate Event Against Active Rules")
def evaluate_event(event_payload: Dict[str, Any]):
    """
    Direct endpoint to test a security event or flow against all enabled rules.
    Returns matched rules with evidence-based explanations.
    """
    engine = get_rule_engine()
    matches = engine.evaluate(event_payload)
    total_evaluated = len([r for r in engine.list_rules() if r.enabled])
    return RuleEvaluateResponse(
        total_evaluated=total_evaluated,
        total_matched=len(matches),
        matches=matches
    )
