"""
CIPHER Threat Intelligence Models
Defines Pydantic data schemas, request/response models, and validation logic for IOCs.
"""

import re
import ipaddress
import urllib.parse
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator

from app.threat_intel.config import (
    ALLOWED_IOC_TYPES,
    ALLOWED_SEVERITIES,
    IOC_DEFAULT_CONFIDENCE
)


class IOCType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH = "HASH"


class IOCSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IOCItem(BaseModel):
    """Full database representation of an Indicator of Compromise."""
    ioc_id: str
    ioc_type: str
    indicator: str
    indicator_normalized: str
    source: str = "LOCAL_ADMIN"
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    severity: str = "HIGH"
    category: str = "MALICIOUS_IP"
    description: Optional[str] = None
    first_seen: str
    last_seen: str
    expires_at: Optional[str] = None
    enabled: bool = True
    tags: List[str] = Field(default_factory=list)
    created_at: str


class IOCCreateRequest(BaseModel):
    """Schema for adding a new IOC indicator."""
    ioc_type: str
    indicator: str
    source: str = "LOCAL_ADMIN"
    confidence: float = Field(default=IOC_DEFAULT_CONFIDENCE, ge=0.0, le=1.0)
    severity: str = "HIGH"
    category: Optional[str] = None
    description: Optional[str] = None
    expires_at: Optional[str] = None
    enabled: bool = True
    tags: List[str] = Field(default_factory=list)

    @field_validator("ioc_type")
    @classmethod
    def validate_ioc_type(cls, v: str) -> str:
        clean = (v or "").strip().upper()
        if clean not in ALLOWED_IOC_TYPES:
            raise ValueError(f"Invalid ioc_type '{v}'. Allowed types: {sorted(list(ALLOWED_IOC_TYPES))}")
        return clean

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        clean = (v or "").strip().upper()
        if clean not in ALLOWED_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Allowed: {sorted(list(ALLOWED_SEVERITIES))}")
        return clean

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, float(v)))

    @field_validator("indicator")
    @classmethod
    def validate_indicator_raw(cls, v: str) -> str:
        s = (v or "").strip()
        if not s:
            raise ValueError("Indicator string cannot be empty.")
        if len(s) > 2048:
            raise ValueError("Indicator exceeds maximum supported length (2048 characters).")
        return s

    @model_validator(mode="after")
    def validate_indicator_format(self) -> "IOCCreateRequest":
        t = self.ioc_type
        ind = self.indicator.strip()

        if t == "IP":
            try:
                ipaddress.ip_address(ind)
            except ValueError:
                raise ValueError(f"Indicator '{ind}' is not a valid IPv4 or IPv6 address.")

        elif t == "DOMAIN":
            clean_dom = ind.lower()
            if "://" in clean_dom:
                raise ValueError(f"Domain indicator '{ind}' should not include URI scheme (use type URL instead).")
            if "/" in clean_dom or ":" in clean_dom or " " in clean_dom:
                raise ValueError(f"Indicator '{ind}' is not a valid hostname or domain.")
            # Basic FQDN check
            domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'
            if not re.match(domain_pattern, clean_dom.rstrip(".")) and clean_dom not in ("localhost", "local"):
                raise ValueError(f"Indicator '{ind}' does not match a valid domain name format.")

        elif t == "URL":
            if not (ind.startswith("http://") or ind.startswith("https://")):
                raise ValueError(f"URL indicator '{ind}' must start with http:// or https://")
            parsed = urllib.parse.urlparse(ind)
            if not parsed.netloc:
                raise ValueError(f"URL indicator '{ind}' lacks a valid domain/host.")

        elif t == "HASH":
            clean_hash = ind.lower()
            if not re.match(r'^[a-f0-9]+$', clean_hash):
                raise ValueError(f"Hash indicator '{ind}' must contain valid hexadecimal characters.")
            if len(clean_hash) not in (32, 40, 64):
                raise ValueError(f"Hash indicator '{ind}' must be 32 (MD5), 40 (SHA-1), or 64 (SHA-256) hex characters.")

        # Default category if omitted
        if not self.category:
            defaults = {
                "IP": "MALICIOUS_IP",
                "DOMAIN": "SUSPICIOUS_DOMAIN",
                "URL": "PHISHING_URL",
                "HASH": "MALWARE_HASH"
            }
            self.category = defaults.get(t, "THREAT_IOC")

        return self


class IOCMatch(BaseModel):
    """Structured result of an IOC match against observed event metadata."""
    ioc_id: str
    indicator: str
    ioc_type: str
    source: str
    confidence: float
    severity: str
    category: str
    explanation: str
    matched_field: str


class IOCListResponse(BaseModel):
    """Schema for listing registered IOCs."""
    total_returned: int
    total_matching: int
    iocs: List[IOCItem]


class IOCDetailResponse(BaseModel):
    """Schema for single IOC retrieval."""
    ioc: IOCItem


class IOCToggleResponse(BaseModel):
    """Schema for enable/disable toggle actions."""
    ioc_id: str
    enabled: bool
    message: str


class IOCCheckRequest(BaseModel):
    """Direct indicator check query."""
    indicator: str
    ioc_type: Optional[str] = None


class IOCCheckResponse(BaseModel):
    """Direct indicator check result."""
    matched: bool
    matches: List[IOCMatch] = Field(default_factory=list)


class IOCImportRequest(BaseModel):
    """JSON bulk import schema."""
    iocs: List[IOCCreateRequest]


class IOCImportResponse(BaseModel):
    """Summary of bulk import operation."""
    total_submitted: int
    imported_count: int
    rejected_count: int
    errors: List[Dict[str, Any]] = Field(default_factory=list)
