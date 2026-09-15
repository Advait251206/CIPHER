"""
CIPHER Rule and Match Data Models
Defines structured rule representations, match results, and REST API schemas.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class RuleMatch(BaseModel):
    """Structured result of an individual rule match against an event."""
    rule_id: str
    name: str
    category: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    matched: bool = True
    explanation: str
    recommendation: str
    weight: int = Field(default=40, ge=0, le=100)


class RuleItem(BaseModel):
    """Metadata and definition of a deterministic heuristic or signature rule."""
    rule_id: str
    name: str
    description: str
    category: str
    severity: str
    enabled: bool = True
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    tags: List[str] = Field(default_factory=list)
    recommendation: str
    weight: int = Field(default=40, ge=0, le=100)
    target_event_type: str = "NETWORK"  # "NETWORK", "PHISHING", "ALL"


class BaseRule:
    """Abstract base class for all deterministic heuristic and signature rules."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        category: str,
        severity: str,
        confidence: float = 1.0,
        tags: Optional[List[str]] = None,
        weight: int = 40,
        recommendation: str = "",
        target_event_type: str = "NETWORK",
        enabled: bool = True
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.category = category
        self.severity = severity
        self.confidence = max(0.0, min(1.0, float(confidence)))
        self.tags = tags or []
        self.weight = max(0, min(100, int(weight)))
        self.recommendation = recommendation
        self.target_event_type = target_event_type.upper()
        self.enabled = enabled

    def evaluate(self, event: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Optional[RuleMatch]:
        """
        Evaluates the rule against the event.
        Returns a RuleMatch if condition holds, None otherwise.
        Must NOT mutate the input event.
        """
        raise NotImplementedError

    def to_item(self) -> RuleItem:
        return RuleItem(
            rule_id=self.rule_id,
            name=self.name,
            description=self.description,
            category=self.category,
            severity=self.severity,
            enabled=self.enabled,
            confidence=self.confidence,
            tags=self.tags,
            recommendation=self.recommendation,
            weight=self.weight,
            target_event_type=self.target_event_type
        )


class RulesListResponse(BaseModel):
    """Response schema listing registered rules."""
    total_rules: int
    enabled_count: int
    rules: List[RuleItem]


class RuleDetailResponse(BaseModel):
    """Detailed response schema for a single rule."""
    rule: RuleItem
    thresholds: Dict[str, Any] = Field(default_factory=dict)


class RuleToggleResponse(BaseModel):
    """Response schema after toggling a rule's enabled status."""
    rule_id: str
    enabled: bool
    message: str


class RuleEvaluateResponse(BaseModel):
    """Response schema for direct rule evaluation."""
    total_evaluated: int
    total_matched: int
    matches: List[RuleMatch]
