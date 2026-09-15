"""
CIPHER Threat Intelligence Configuration
Defines local-first IOC thresholds, cache bounds, and safe synthetic demo indicators.
Zero external network connectivity; all data remains strictly local.
"""

import os
from typing import List, Dict, Any

# In-memory lookup cache bounds
IOC_CACHE_MAX_ENTRIES: int = int(os.getenv("CIPHER_IOC_CACHE_MAX_ENTRIES", 5000))

# Default confidence for newly created local IOCs
IOC_DEFAULT_CONFIDENCE: float = float(os.getenv("CIPHER_IOC_DEFAULT_CONFIDENCE", 0.85))

# Maximum batch size for local CSV/JSON imports
IOC_MAX_BULK_IMPORT: int = int(os.getenv("CIPHER_IOC_MAX_BULK_IMPORT", 1000))

# Explicit flag to load synthetic demo IOCs (strictly defaults to False to prevent polluting production DB)
CIPHER_LOAD_DEMO_IOCS: bool = os.getenv("CIPHER_LOAD_DEMO_IOCS", "false").lower() in ("true", "1", "yes")

# Allowed IOC Types and Severities
ALLOWED_IOC_TYPES = {"IP", "DOMAIN", "URL", "HASH"}
ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

# =============================================================================
# Synthetic Demo IOC Dataset (Safe Test Indicators)
# Uses RFC 5737 documentation IPs, RFC 3849 IPv6, and .test pseudo-domains.
# NEVER uses real malicious infrastructure.
# =============================================================================
DEMO_IOC_DATASET: List[Dict[str, Any]] = [
    {
        "ioc_id": "IOC-DEMO-001",
        "ioc_type": "IP",
        "indicator": "203.0.113.10",
        "source": "CIPHER_DEMO",
        "confidence": 0.95,
        "severity": "CRITICAL",
        "category": "C2",
        "description": "Synthetic C2 server indicator (RFC 5737 TEST-NET-3). Used for testing network IOC correlation.",
        "tags": ["demo", "synthetic", "c2", "ipv4"]
    },
    {
        "ioc_id": "IOC-DEMO-002",
        "ioc_type": "IP",
        "indicator": "198.51.100.25",
        "source": "CIPHER_DEMO",
        "confidence": 0.90,
        "severity": "HIGH",
        "category": "BOTNET",
        "description": "Synthetic botnet controller endpoint (RFC 5737 TEST-NET-2).",
        "tags": ["demo", "synthetic", "botnet", "ipv4"]
    },
    {
        "ioc_id": "IOC-DEMO-003",
        "ioc_type": "IP",
        "indicator": "192.0.2.100",
        "source": "CIPHER_DEMO",
        "confidence": 0.80,
        "severity": "MEDIUM",
        "category": "SCANNER",
        "description": "Synthetic reconnaissance scanner IP (RFC 5737 TEST-NET-1).",
        "tags": ["demo", "synthetic", "recon", "ipv4"]
    },
    {
        "ioc_id": "IOC-DEMO-004",
        "ioc_type": "IP",
        "indicator": "2001:db8::10",
        "source": "CIPHER_DEMO",
        "confidence": 0.85,
        "severity": "HIGH",
        "category": "C2",
        "description": "Synthetic IPv6 malicious gateway (RFC 3849 Documentation Prefix).",
        "tags": ["demo", "synthetic", "ipv6"]
    },
    {
        "ioc_id": "IOC-DEMO-005",
        "ioc_type": "DOMAIN",
        "indicator": "example-threat.test",
        "source": "CIPHER_DEMO",
        "confidence": 0.95,
        "severity": "CRITICAL",
        "category": "PHISHING",
        "description": "Synthetic phishing credential collection domain (.test reserved TLD).",
        "tags": ["demo", "synthetic", "phishing", "domain"]
    },
    {
        "ioc_id": "IOC-DEMO-006",
        "ioc_type": "DOMAIN",
        "indicator": "c2-beacon-simulation.test",
        "source": "CIPHER_DEMO",
        "confidence": 0.90,
        "severity": "HIGH",
        "category": "C2",
        "description": "Synthetic command-and-control communication domain (.test reserved TLD).",
        "tags": ["demo", "synthetic", "c2", "domain"]
    },
    {
        "ioc_id": "IOC-DEMO-007",
        "ioc_type": "URL",
        "indicator": "http://example-threat.test/login/secure-verify",
        "source": "CIPHER_DEMO",
        "confidence": 0.95,
        "severity": "CRITICAL",
        "category": "PHISHING",
        "description": "Synthetic high-confidence credential harvest landing URL.",
        "tags": ["demo", "synthetic", "phishing", "url"]
    },
    {
        "ioc_id": "IOC-DEMO-008",
        "ioc_type": "HASH",
        "indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "source": "CIPHER_DEMO",
        "confidence": 0.75,
        "severity": "MEDIUM",
        "category": "MALWARE",
        "description": "Synthetic test payload hash (SHA-256 of empty string).",
        "tags": ["demo", "synthetic", "hash", "sha256"]
    }
]
